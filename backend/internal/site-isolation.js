// "Standorte untereinander" (site-to-site isolation) — DB, apply and API layer.
// Pure logic (nft text, verdicts, warnings) lives in site-isolation-rules.js.
//
// Apply: build the nft script for the dedicated table `inet floppyguard_sites`
// from the stored pairs + the current links, `nft -c -f` (dry run) then
// `nft -f` (one atomic transaction: on any failure the previous table stays
// exactly as it was), then persist the script to
// /etc/nftables.d/floppyguard-sites.nft (SITE_ISOLATION_NFT_FILE).
// Triggered on backend start, after every pair change, and (debounced) from
// syncAgentConfigs — which every WireGuard link/network mutation and the 5-min
// reconciler call — so new or removed networks of an isolated site are picked up
// automatically. An unchanged script is not re-applied as long as the table is
// still present (a `flush ruleset` elsewhere is healed on the next trigger).
//
// Hub reboot / nftables.service restart: the table survives a BACKEND restart
// (it lives in the kernel), but `systemctl restart nftables` or a reboot runs
// /etc/nftables.conf, which starts with `flush ruleset`. The table only comes
// back at boot if that file ends with
//     include "/etc/nftables.d/floppyguard-sites.nft"
// (after its own tables). The persisted script begins with `table … {}` +
// `delete table …`, so it is valid right after `flush ruleset`. Without the
// include the sites are NOT separated between boot and the backend's start-up
// apply; overview() reports that as warning `boot-include-missing`.
//
// Fail-safe: a missing/unreadable view of the links never lifts a separation.
// Tunnel /32s fall back to the last known ones when the live status is missing,
// a link that vanished keeps its last sets for one more apply, and when stored
// pairs exist but NONE of them resolves to current site links the previous table
// is kept (error `links-unresolved`).
//
// Foreign drops: rules someone added by hand to other forward chains (e.g. the
// pre-FloppyGuard `ip saddr @site_x ip daddr @site_y drop` in inet filter) are
// read from `nft -j list ruleset` and reported (warning `manual-drop`,
// `manual_pairs`, tester verdict), so the app never shows a pair as open while
// the hub drops it.

import { execFile as execFileCb } from "node:child_process";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import error from "../lib/error.js";
import { wireguard as logger } from "../logger.js";
import Agent from "../models/agent.js";
import AuditLog from "../models/audit-log.js";
import SiteIsolation from "../models/site_isolation.js";
import { canonicalCidr } from "./agent-ingress-rules.js";
import internalAuditLog from "./audit-log.js";
import {
	bootIncludesFile,
	buildSiteIsolationNft,
	isSiteLink,
	manualDropVerdict,
	manualSitePairs,
	normalizePair,
	parseChainCounters,
	parseForeignForwardDrops,
	planSiteIsolation,
	routeWarnings,
	SITE_CHAIN,
	SITE_TABLE,
	sanitizePairs,
	scriptHash,
	siteIsolationVerdict,
	siteNetworks,
} from "./site-isolation-rules.js";
import { setSiteIsolationTrigger } from "./site-isolation-trigger.js";
import internalWireGuard from "./wireguard.js";

const OBJECT_TYPE = "site-isolation";
const NFT_TIMEOUT_MS = 15 * 1000;
const DEBOUNCE_MS = 2 * 1000;
/** Applies a vanished link keeps its last sets (one reconciler cycle). */
const HOLD_APPLIES = 1;
export const PERSIST_PATH = () => process.env.SITE_ISOLATION_NFT_FILE || "/etc/nftables.d/floppyguard-sites.nft";
export const BOOT_CONF_PATH = () => process.env.SITE_ISOLATION_BOOT_CONF || "/etc/nftables.conf";
const NFT_BIN = () => process.env.NFT_BIN || "nft";

/** Warning codes produced by the applier (not by a fresh plan in overview()). */
const APPLIER_WARNING_CODES = new Set(["persist-failed", "link-missing-held"]);

const execFileP = promisify(execFileCb);

const parseJsonList = (raw) => {
	if (Array.isArray(raw)) return raw;
	if (!raw) return null;
	try {
		const v = JSON.parse(raw);
		return Array.isArray(v) ? v : null;
	} catch {
		return null;
	}
};

/**
 * Link loader with a fail-safe tunnel cache. Returns links in one shape:
 * { id, name, type, importedNetworks, tunnelAddresses, active }.
 * The metadata store is authoritative for ids, names, types and networks (it
 * survives a downed interface); the live status adds tunnel /32s, online state,
 * the effective type of untyped peers and peers without metadata. A corrupt or
 * unreadable store THROWS — applying with an empty link list would silently lift
 * every isolation.
 *
 * Tunnel /32s exist only in the live status. When it is unavailable (throws,
 * `available: false`, wg0 not up yet at boot) or a known link is missing from it,
 * the last tunnel addresses seen for that link are used instead of [] — a
 * transient read error must not drop 10.10.0.x/32 out of a site's set.
 */
export function createLinkLoader(deps = {}) {
	const d = {
		readMetadataStore: () => internalWireGuard.readMetadataStore(),
		getStatus: () => internalWireGuard.getStatus(),
		log: logger,
		...deps,
	};
	const tunnelCache = new Map();
	return async function loadLinks() {
		const metadata = await d.readMetadataStore();
		let status = null;
		try {
			status = await d.getStatus();
		} catch (err) {
			d.log.warn(
				`Site isolation: WireGuard status unavailable (${err.message}) — last known tunnel addresses used`,
			);
		}
		const statusOk = Boolean(status?.available);
		const live = new Map((statusOk ? status.links || [] : []).map((l) => [l.id, l]));
		const tunnelOf = (id, l) => {
			if (l) {
				const t = l.tunnelAddresses || [];
				tunnelCache.set(id, t);
				return t;
			}
			return tunnelCache.get(id) || [];
		};
		const out = [];
		for (const [id, m] of Object.entries(metadata.links || {})) {
			const l = live.get(id);
			live.delete(id);
			out.push({
				id,
				name: m?.name || l?.name || id,
				type: m?.type || l?.type || null,
				importedNetworks: m?.importedNetworks?.length ? m.importedNetworks : l?.importedNetworks || [],
				tunnelAddresses: tunnelOf(id, l),
				active: Boolean(l?.active),
			});
		}
		for (const l of live.values()) {
			out.push({
				id: l.id,
				name: l.name || l.id,
				type: l.type || null,
				importedNetworks: l.importedNetworks || [],
				tunnelAddresses: tunnelOf(l.id, l),
				active: Boolean(l.active),
			});
		}
		return out;
	};
}

export const loadLinks = createLinkLoader();

export async function loadPairs(trx) {
	const rows = await SiteIsolation.query(trx).orderBy("id");
	return rows.map((r) => ({ id: r.id, ...normalizePair(r.link_a, r.link_b) }));
}

const pairKey = (p) => `${p.a}|${p.b}`;

/**
 * Applier with injectable IO (tests pass a fake execFile / fs / input loader).
 * apply() calls are serialized; it never throws — the outcome is in the returned
 * state ({ ok, changed, hash, at, error, error_code, warnings, applied_pairs }).
 */
export function createSiteIsolationApplier(deps = {}) {
	const d = {
		execFile: (file, args) => execFileP(file, args, { timeout: NFT_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024 }),
		fs: fsp,
		tmpDir: os.tmpdir(),
		persistPath: PERSIST_PATH,
		nftBin: NFT_BIN,
		loadInput: async () => ({ pairs: await loadPairs(), links: await loadLinks() }),
		log: logger,
		now: () => Math.floor(Date.now() / 1000),
		...deps,
	};
	const state = {
		hash: null,
		script: null,
		at: null,
		error: null,
		error_code: null,
		error_at: null,
		planWarnings: [],
		heldWarnings: [],
		persistError: null,
		pairs: 0,
		appliedPairs: [],
		persisted: null,
	};
	// last applied version of every link that had a set — used to hold a vanished link
	const lastLinks = new Map();
	const missingStreak = new Map();
	let chain = Promise.resolve();

	const nft = (args) => d.execFile(d.nftBin(), args);
	const errText = (err) =>
		String(err?.stderr || err?.message || err)
			.trim()
			.slice(0, 2000);

	async function persist(script) {
		const target = d.persistPath();
		await d.fs.mkdir(path.dirname(target), { recursive: true });
		const tmp = `${target}.tmp-${process.pid}`;
		await d.fs.writeFile(tmp, script, { encoding: "utf8", mode: 0o644 });
		await d.fs.rename(tmp, target);
		return target;
	}

	/** Write the boot copy; a failure is a warning (the live table is right) and is retried on every apply. */
	async function persistReported(script) {
		try {
			state.persisted = await persist(script);
			state.persistError = null;
		} catch (err) {
			state.persisted = null;
			state.persistError = errText(err);
			d.log.warn(`Site isolation: could not persist ${d.persistPath()}: ${state.persistError}`);
		}
	}

	function fail(code, message) {
		state.error = message;
		state.error_code = code;
		state.error_at = d.now();
		return { ok: false, changed: false, ...snapshot() };
	}

	/**
	 * Links as the plan should see them: a link referenced by a stored pair that is
	 * gone from the input keeps its last applied version for HOLD_APPLIES applies.
	 */
	function withHeldLinks(input) {
		const present = new Set(input.links.map((l) => l.id));
		const ids = new Set(input.pairs.flatMap((p) => [p.a, p.b]));
		const held = [];
		const warnings = [];
		for (const id of ids) {
			if (present.has(id)) {
				missingStreak.delete(id);
				continue;
			}
			const n = (missingStreak.get(id) || 0) + 1;
			missingStreak.set(id, n);
			const last = lastLinks.get(id);
			if (last && n <= HOLD_APPLIES) {
				held.push(last);
				warnings.push({
					code: "link-missing-held",
					link_id: id,
					name: last.name,
					message: `${last.name} ist nicht mehr auffindbar — die Trennung bleibt vorerst mit den letzten bekannten Netzen bestehen`,
				});
			}
		}
		for (const id of [...missingStreak.keys()]) if (!ids.has(id)) missingStreak.delete(id);
		return { links: [...input.links, ...held], warnings };
	}

	async function applyOnce({ force = false } = {}) {
		let input;
		let script;
		let plan;
		let heldWarnings;
		try {
			const raw = await d.loadInput();
			const held = withHeldLinks(raw);
			heldWarnings = held.warnings;
			input = { pairs: raw.pairs, links: held.links };
			plan = planSiteIsolation(input);
			script = buildSiteIsolationNft(input);
		} catch (err) {
			// Without a trustworthy view of the links the table is left as it is.
			const res = fail("input", `Eingaben nicht lesbar: ${errText(err)}`);
			d.log.error(`Site isolation: not applied, previous table kept — ${state.error}`);
			return res;
		}
		// Fail closed: stored pairs, but none resolves to current site links (empty
		// or missing metadata store, links re-created under new keys …). Applying
		// would lift every separation on a pure input problem — keep the old table.
		if (input.pairs.length) {
			const byId = new Map(input.links.map((l) => [l.id, l]));
			const unresolved = input.pairs.filter((p) => ![p.a, p.b].every((id) => isSiteLink(byId.get(id))));
			if (!input.links.some(isSiteLink) || unresolved.length === input.pairs.length) {
				state.planWarnings = plan.warnings;
				state.heldWarnings = heldWarnings;
				const res = fail(
					"links-unresolved",
					"Keine gespeicherte Trennung passt zu einer vorhandenen Standort-Verbindung (WireGuard-Metadaten leer oder Verbindungen neu angelegt) — die bisherigen Regeln bleiben aktiv",
				);
				d.log.error(`Site isolation: not applied, previous table kept — ${state.error}`);
				return res;
			}
		}
		const hash = scriptHash(script);
		state.planWarnings = plan.warnings;
		state.heldWarnings = heldWarnings;
		if (!force && hash === state.hash && !state.error) {
			try {
				await nft(["list", "table", "inet", SITE_TABLE]);
				// the boot copy may still be stale from an earlier failed write
				if (!state.persisted) await persistReported(script);
				return { ok: true, changed: false, ...snapshot() };
			} catch {
				d.log.warn(`Site isolation: table inet ${SITE_TABLE} vanished (ruleset flushed?) — re-applying`);
			}
		}
		let dir = null;
		try {
			dir = await d.fs.mkdtemp(path.join(d.tmpDir, "fg-sites-"));
			const file = path.join(dir, "sites.nft");
			await d.fs.writeFile(file, script, { encoding: "utf8", mode: 0o600 });
			await nft(["-c", "-f", file]);
			await nft(["-f", file]);
		} catch (err) {
			const res = fail("nft", errText(err));
			d.log.error(`Site isolation: nft rejected the ruleset, previous table kept — ${state.error}`);
			return res;
		} finally {
			if (dir) await d.fs.rm(dir, { recursive: true, force: true }).catch(() => {});
		}
		const changed = hash !== state.hash;
		state.hash = hash;
		state.script = script;
		state.at = d.now();
		state.error = null;
		state.error_code = null;
		state.error_at = null;
		state.pairs = plan.pairs.length;
		state.appliedPairs = plan.pairs.map(pairKey);
		const byId = new Map(input.links.map((l) => [l.id, l]));
		lastLinks.clear();
		for (const id of plan.sites.keys()) if (byId.has(id)) lastLinks.set(id, byId.get(id));
		await persistReported(script);
		if (changed) {
			d.log.info(`Site isolation applied: ${plan.pairs.length} pair(s), ${plan.sites.size} site set(s)`);
		}
		for (const w of [...plan.warnings, ...heldWarnings]) d.log.warn(`Site isolation: ${w.message}`);
		return { ok: true, changed, ...snapshot() };
	}

	function warnings() {
		const out = [...state.planWarnings, ...state.heldWarnings];
		if (state.persistError) {
			out.push({
				code: "persist-failed",
				message: `Regeln aktiv, aber ${d.persistPath()} konnte nicht geschrieben werden: ${state.persistError}`,
			});
		}
		return out;
	}

	function snapshot() {
		return {
			hash: state.hash,
			at: state.at,
			error: state.error,
			error_code: state.error_code,
			error_at: state.error_at,
			warnings: warnings(),
			pairs: state.pairs,
			applied_pairs: [...state.appliedPairs],
			persisted: state.persisted,
		};
	}

	function apply(opts) {
		const p = chain.then(() => applyOnce(opts));
		chain = p.catch(() => {});
		return p;
	}

	/**
	 * Drop counters per "setA>setB" from the live chain, and whether the table is
	 * there at all (false also when nft is unavailable).
	 */
	async function counters() {
		try {
			const { stdout } = await nft(["-j", "list", "chain", "inet", SITE_TABLE, SITE_CHAIN]);
			return { present: true, map: parseChainCounters(stdout) };
		} catch {
			return { present: false, map: new Map() };
		}
	}

	/** Drop rules in OTHER forward chains (see header); null when the ruleset is not readable. */
	async function foreignDrops() {
		try {
			const { stdout } = await nft(["-j", "list", "ruleset"]);
			return parseForeignForwardDrops(stdout);
		} catch {
			return null;
		}
	}

	return { apply, state: snapshot, counters, foreignDrops };
}

const applier = createSiteIsolationApplier();
let scheduled = null;
let started = false;

function schedule(reason) {
	if (!started || scheduled) return;
	scheduled = setTimeout(() => {
		scheduled = null;
		applier.apply().then((res) => {
			if (!res.ok) logger.warn(`Site isolation re-apply (${reason || "trigger"}) failed: ${res.error}`);
		});
	}, DEBOUNCE_MS);
	scheduled.unref?.();
}

let replaceLock = Promise.resolve();
const withReplaceLock = (fn) => {
	const next = replaceLock.then(fn, fn);
	replaceLock = next.catch(() => {});
	return next;
};

/** Is the boot include in place? null = config not readable (no warning then). */
async function bootIncludeOk() {
	try {
		const text = await fsp.readFile(BOOT_CONF_PATH(), "utf8");
		return bootIncludesFile(text, PERSIST_PATH());
	} catch {
		return null;
	}
}

/** Last pair change from the audit log: { at, by } or null. */
async function lastChange() {
	try {
		const row = await AuditLog.query()
			.where("object_type", OBJECT_TYPE)
			.orderBy("created_on", "DESC")
			.orderBy("id", "DESC")
			.withGraphFetched("user")
			.first();
		if (!row) return null;
		const t = new Date(row.created_on).getTime();
		return {
			at: Number.isFinite(t) ? Math.floor(t / 1000) : null,
			by: row.user?.name || row.user?.nickname || row.user?.email || null,
		};
	} catch (err) {
		logger.warn(`Site isolation: last change not readable: ${err.message}`);
		return null;
	}
}

const internalSiteIsolation = {
	/** Server entrypoint: apply once now and re-apply whenever syncAgentConfigs runs. */
	start() {
		if (process.env.SITE_ISOLATION_DISABLED === "true") {
			logger.info("Site isolation disabled by SITE_ISOLATION_DISABLED=true");
			return Promise.resolve(null);
		}
		started = true;
		setSiteIsolationTrigger(schedule);
		return applier.apply({ force: true }).then((res) => {
			if (!res.ok) logger.error(`Site isolation start-up apply failed: ${res.error}`);
			return res;
		});
	},

	apply(opts) {
		return applier.apply(opts);
	},

	/** GET /api/site-isolation */
	async overview() {
		const [links, pairs] = await Promise.all([loadLinks(), loadPairs()]);
		const byId = new Map(links.map((l) => [l.id, l]));
		const sites = links
			.filter(isSiteLink)
			.map((l) => ({
				link_id: l.id,
				name: l.name,
				networks: siteNetworks({ importedNetworks: l.importedNetworks }).nets,
				tunnel: siteNetworks({ tunnelAddresses: l.tunnelAddresses }).nets,
				online: Boolean(l.active),
			}))
			.sort((a, b) => a.name.localeCompare(b.name, "de"));
		const plan = planSiteIsolation({ pairs, links });
		const [table, drops, includeOk, changed] = await Promise.all([
			applier.counters(),
			applier.foreignDrops(),
			bootIncludeOk(),
			lastChange(),
		]);
		const agents = (
			await Agent.query()
				.where("is_deleted", 0)
				.whereNotNull("wg_link_name")
				.select("id", "name", "wg_link_name", "allowed_networks", "allowed_sites")
		).map((a) => ({
			id: a.id,
			name: a.name,
			wg_link_name: a.wg_link_name,
			allowed_networks: parseJsonList(a.allowed_networks),
			allowed_sites: parseJsonList(a.allowed_sites),
		}));
		const st = applier.state();
		// Enforced = the pair is in the table the hub actually runs: part of the last
		// SUCCESSFUL apply (a failed apply keeps that previous table) and the table
		// still exists. A pair stored after the last success, or a vanished table,
		// is not enforced.
		const applied = new Set(table.present ? st.applied_pairs : []);
		const outPairs = pairs.map((p) => {
			const A = plan.sites.get(p.a);
			const B = plan.sites.get(p.b);
			const ab = A && B ? table.map.get(`${A.set}>${B.set}`) : null;
			const ba = A && B ? table.map.get(`${B.set}>${A.set}`) : null;
			return {
				id: p.id,
				link_a: p.a,
				link_b: p.b,
				name_a: byId.get(p.a)?.name ?? null,
				name_b: byId.get(p.b)?.name ?? null,
				enforced: applied.has(pairKey(p)),
				dropped:
					ab || ba
						? {
								packets: (ab?.packets || 0) + (ba?.packets || 0),
								bytes: (ab?.bytes || 0) + (ba?.bytes || 0),
							}
						: null,
			};
		});
		const manualPairs = drops ? manualSitePairs({ drops, sites }) : [];
		const warnings = [
			...plan.warnings,
			...st.warnings.filter((w) => APPLIER_WARNING_CODES.has(w.code)),
			...routeWarnings({ pairs: plan.pairs, links, agents }),
		];
		if (drops?.length) {
			warnings.push({
				code: "manual-drop",
				rules: drops.map((r) => ({
					family: r.family,
					table: r.table,
					chain: r.chain,
					comment: r.comment,
					src_set: r.src_set,
					dst_set: r.dst_set,
				})),
				message: `Am Hub gibt es zusätzliche, manuell gesetzte Sperren außerhalb von FloppyGuard (${[
					...new Set(drops.map((r) => `${r.family} ${r.table} ${r.chain}`)),
				].join(", ")})`,
			});
		}
		if (includeOk === false && plan.pairs.length) {
			warnings.push({
				code: "boot-include-missing",
				file: PERSIST_PATH(),
				message: `${BOOT_CONF_PATH()} lädt ${PERSIST_PATH()} nicht — nach einem Neustart des Hubs greift die Trennung erst wieder, wenn FloppyGuard läuft`,
			});
		}
		return {
			sites,
			pairs: outPairs,
			manual_pairs: manualPairs,
			applied: {
				hash: st.hash,
				at: st.at,
				error: st.error,
				error_code: st.error_code,
				error_at: st.error_at,
				file: st.persisted,
				table_present: table.present,
			},
			last_change: changed,
			warnings,
		};
	},

	/** PUT /api/site-isolation — replace the full pair set, then apply. */
	async replace(access, body) {
		await withReplaceLock(async () => {
			const links = await loadLinks();
			const clean = sanitizePairs(body?.pairs, links);
			const nameOf = (id) => links.find((l) => l.id === id)?.name || id;
			const label = (p) => `${nameOf(p.a)} <-> ${nameOf(p.b)}`;
			const before = await SiteIsolation.transaction(async (trx) => {
				const prev = await loadPairs(trx);
				await SiteIsolation.query(trx).delete();
				for (const p of clean) await SiteIsolation.query(trx).insert({ link_a: p.a, link_b: p.b });
				return prev;
			});
			const prevKeys = new Set(before.map(pairKey));
			const nextKeys = new Set(clean.map(pairKey));
			const added = clean.filter((p) => !prevKeys.has(pairKey(p))).map(label);
			const removed = before.filter((p) => !nextKeys.has(pairKey(p))).map(label);
			if (added.length || removed.length) {
				try {
					await internalAuditLog.add(access, {
						action: "updated",
						object_type: OBJECT_TYPE,
						object_id: 0,
						meta: { added, removed, pairs: clean.length },
					});
				} catch (err) {
					logger.warn(`site isolation audit log failed: ${err.message}`);
				}
			}
			await applier.apply({ force: true });
		});
		return this.overview();
	},

	/** POST /api/site-isolation/test {source, destination} — read-only verdict. */
	async test(body) {
		const b = body || {};
		const src = canonicalCidr(b.source);
		if (!src) throw new error.ValidationError("source: invalid IPv4 address/CIDR");
		const dst = canonicalCidr(b.destination);
		if (!dst) throw new error.ValidationError("destination: invalid IPv4 address/CIDR");
		return this.verdict(src, dst);
	},

	/**
	 * Verdict for one flow against the STORED pairs (what the hub enforces once
	 * applied) + whether the last apply succeeded. When no pair blocks the flow,
	 * foreign drop rules in other forward chains are checked as well (`manual`).
	 * Used by the Freigaben tester.
	 */
	async verdict(src, dst) {
		const [links, pairs] = await Promise.all([loadLinks(), loadPairs()]);
		const v = siteIsolationVerdict({ pairs, links, src, dst });
		const st = applier.state();
		const out = { ...v, applied: !st.error && Boolean(st.hash), error: st.error };
		if (v.blocked) return out;
		const drops = await applier.foreignDrops();
		const m = drops ? manualDropVerdict({ drops, src, dst }) : { blocked: false, partial: false };
		if (m.blocked) return { blocked: true, partial: false, manual: m.rule, applied: true, error: null };
		if (m.partial && !v.partial) return { ...out, partial: true, manual: m.rule };
		return out;
	},
};

export default internalSiteIsolation;
