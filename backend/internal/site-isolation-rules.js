// Pure helpers for "Standorte untereinander" (site-to-site isolation on the hub).
// No DB / IO here, so everything that decides what lands in the hub's nftables
// is unit-testable.
//
// Model: a pair {a, b} of site links (ids "wg0:<pubkey>", stable across renames)
// means "these two sites must NOT reach each other" — both directions, every
// protocol, established flows included. No pairs = everything allowed (the
// behaviour before this feature).
//
// Enforcement: a DEDICATED nftables table `inet floppyguard_sites` with one
// interval set per involved site (its importedNetworks + its tunnel /32s) and a
// base chain on the forward hook at priority `filter - 10`, i.e. BEFORE the
// hub's own `inet filter` forward chain. Policy accept: the table only ever
// drops the isolated pairs, everything else continues to the hub's normal
// forward rules. A packet dropped here is final (nftables drop verdicts are
// absolute across base chains).
//
// Atomic replace: the script starts with `table inet floppyguard_sites {}` (create
// if missing) + `delete table inet floppyguard_sites` + the full definition. nft -f
// runs a file as ONE transaction, so either the new table is in place or the old
// one stays untouched. The script never touches any other table.
//
// Empty pair list: the table is still created, with empty chain (policy accept).
// This keeps a single code path, makes the boot include file always valid and a
// "no isolation" state visible in `nft list ruleset` instead of a vanished table.

import { createHash } from "node:crypto";
import error from "../lib/error.js";
import { canonicalCidr, cidrContains, echoValue as echo } from "./agent-ingress-rules.js";

export const SITE_TABLE = "floppyguard_sites";
export const SITE_CHAIN = "forward";
/** Link types that count as a site (a LAN behind the peer). Client links never do. */
export const SITE_LINK_TYPES = new Set(["site-to-site", "hub-link"]);
export const MAX_PAIRS = 200;
const LINK_ID_RE = /^wg\d{1,3}:[A-Za-z0-9+/=]{1,64}$/;
const NAME_MAX = 48;

const ipInt = (cidr) => {
	const [addr] = cidr.split("/");
	return addr.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
};
const prefixOf = (cidr) => Number(cidr.split("/")[1]);

/** Two canonical CIDRs share at least one address. */
export function cidrOverlaps(x, y) {
	return cidrContains(x, y) || cidrContains(y, x);
}

/**
 * Link name for an nft comment: ASCII only (umlauts transliterated), no quotes,
 * backslashes, newlines or other control characters, clipped. Pure.
 */
export function sanitizeCommentText(value, max = NAME_MAX) {
	const translit = { ä: "ae", ö: "oe", ü: "ue", Ä: "Ae", Ö: "Oe", Ü: "Ue", ß: "ss" };
	const s = String(value ?? "")
		.replace(/[äöüÄÖÜß]/g, (c) => translit[c])
		.normalize("NFKD")
		.replace(/[^A-Za-z0-9 ._()+:<>-]/g, " ")
		.replace(/\s+/g, " ")
		.trim();
	return s.slice(0, max).trim() || "site";
}

/** Stable nft set name for a link id (does not change on rename). */
export function siteSetName(linkId) {
	return `site_${createHash("sha256").update(String(linkId)).digest("hex").slice(0, 10)}`;
}

/** Normalized pair key: a < b. */
export function normalizePair(a, b) {
	return a < b ? { a, b } : { a: b, b: a };
}

export const isSiteLink = (l) => Boolean(l) && SITE_LINK_TYPES.has(l.type);

/**
 * Networks of one site for the set: canonical importedNetworks plus the tunnel
 * /32 addresses, deduplicated, CIDRs inside another entry removed (an nft
 * interval set rejects overlapping elements), sorted by address. A /0 is never
 * taken (it would isolate the site from everything) and is reported.
 * → { nets: string[], skipped: [{ value, reason }] }  Pure.
 */
export function siteNetworks(link) {
	const skipped = [];
	const raw = [];
	for (const v of link?.importedNetworks || []) {
		// The table is IPv4-only (ipv4_addr sets, `ip saddr`): an IPv6 network is
		// valid but NOT covered — reported as such, not as "invalid".
		if (String(v ?? "").includes(":")) {
			skipped.push({ value: echo(v), reason: "ipv6-unsupported" });
			continue;
		}
		const c = canonicalCidr(v);
		if (!c) {
			skipped.push({ value: echo(v), reason: "invalid" });
			continue;
		}
		if (prefixOf(c) === 0) {
			skipped.push({ value: c, reason: "default-route" });
			continue;
		}
		raw.push(c);
	}
	for (const v of link?.tunnelAddresses || []) {
		const s = String(v ?? "");
		const c = canonicalCidr(s.includes("/") ? s : `${s}/32`);
		if (c?.endsWith("/32")) raw.push(c);
		else if (s) skipped.push({ value: echo(v), reason: "invalid" });
	}
	const uniq = [...new Set(raw)];
	const nets = uniq
		.filter((n) => !uniq.some((o) => o !== n && cidrContains(o, n)))
		.sort((x, y) => ipInt(x) - ipInt(y) || prefixOf(x) - prefixOf(y));
	return { nets, skipped };
}

/**
 * Validate a full pair list from the API against the current links.
 * Each entry {link_a, link_b}: both well-formed link ids, different, existing and
 * of a site type. Duplicates (also reversed) collapse. Throws ValidationError.
 * → [{ a, b }] normalized (a < b), sorted. Pure.
 */
export function sanitizePairs(input, links) {
	if (!Array.isArray(input)) throw new error.ValidationError("pairs must be an array of {link_a, link_b}");
	if (input.length > MAX_PAIRS) throw new error.ValidationError(`pairs: at most ${MAX_PAIRS} entries`);
	const byId = new Map((links || []).map((l) => [l.id, l]));
	const seen = new Map();
	input.forEach((p, i) => {
		const a = typeof p?.link_a === "string" ? p.link_a.trim() : "";
		const b = typeof p?.link_b === "string" ? p.link_b.trim() : "";
		for (const [field, v] of [
			["link_a", a],
			["link_b", b],
		]) {
			if (!LINK_ID_RE.test(v))
				throw new error.ValidationError(`pairs[${i}].${field}: invalid link id ${echo(v)}`);
			const l = byId.get(v);
			if (!l) throw new error.ValidationError(`pairs[${i}].${field}: unknown link ${echo(v)}`);
			if (!isSiteLink(l))
				throw new error.ValidationError(
					`pairs[${i}].${field}: ${echo(l.name || v)} is not a site-to-site link`,
				);
		}
		if (a === b) throw new error.ValidationError(`pairs[${i}]: a site cannot be isolated from itself`);
		const n = normalizePair(a, b);
		seen.set(`${n.a}|${n.b}`, n);
	});
	return [...seen.values()].sort((x, y) => (x.a === y.a ? (x.b < y.b ? -1 : 1) : x.a < y.a ? -1 : 1));
}

/**
 * What the table will contain: per pair the two sites' nets, and warnings for
 * pairs that cannot be enforced (link gone, no networks) or look suspicious
 * (overlapping networks, skipped entries). Pure.
 *
 * → { sites: Map(linkId → { id, name, set, nets }), pairs: [{ a, b }], warnings: [] }
 */
export function planSiteIsolation({ pairs = [], links = [] }) {
	const byId = new Map(links.map((l) => [l.id, l]));
	const sites = new Map();
	const warnings = [];
	const effective = [];
	const siteFor = (id) => {
		if (sites.has(id)) return sites.get(id);
		const l = byId.get(id);
		const { nets, skipped } = siteNetworks(l);
		for (const s of skipped) {
			warnings.push({
				code: "network-skipped",
				link_id: id,
				name: l.name || id,
				value: s.value,
				reason: s.reason,
				message:
					s.reason === "default-route"
						? `${l.name || id}: Standardroute ${s.value} wird für die Trennung ignoriert`
						: s.reason === "ipv6-unsupported"
							? `${l.name || id}: IPv6-Netz ${s.value} wird von der Standort-Trennung nicht erfasst`
							: `${l.name || id}: ungültiges Netz ${s.value} wird ignoriert`,
			});
		}
		const site = { id, name: l.name || id, set: siteSetName(id), nets };
		sites.set(id, site);
		return site;
	};
	for (const p of pairs) {
		const missing = [p.a, p.b].filter((id) => !byId.has(id));
		if (missing.length) {
			for (const id of missing) {
				warnings.push({
					code: "link-missing",
					link_id: id,
					pair: { a: p.a, b: p.b },
					message: `Standort ${id} existiert nicht mehr — diese Trennung wird übersprungen`,
				});
			}
			continue;
		}
		const notSite = [p.a, p.b].filter((id) => !isSiteLink(byId.get(id)));
		if (notSite.length) {
			for (const id of notSite) {
				warnings.push({
					code: "link-not-site",
					link_id: id,
					pair: { a: p.a, b: p.b },
					message: `${byId.get(id).name || id} ist kein Standort-Link mehr — diese Trennung wird übersprungen`,
				});
			}
			continue;
		}
		const A = siteFor(p.a);
		const B = siteFor(p.b);
		const empty = [A, B].filter((s) => !s.nets.length);
		if (empty.length) {
			for (const s of empty) {
				warnings.push({
					code: "no-networks",
					link_id: s.id,
					pair: { a: p.a, b: p.b },
					message: `${s.name} hat keine Netze — die Trennung zu ${s === A ? B.name : A.name} greift nicht`,
				});
			}
			continue;
		}
		const overlap = A.nets.filter((x) => B.nets.some((y) => cidrOverlaps(x, y)));
		if (overlap.length) {
			warnings.push({
				code: "overlap",
				pair: { a: p.a, b: p.b },
				networks: overlap,
				message: `${A.name} und ${B.name} haben überlappende Netze (${overlap.join(", ")}) — Verkehr darin wird ebenfalls verworfen`,
			});
		}
		effective.push({ a: p.a, b: p.b });
	}
	// Only sites of an enforced pair get a set.
	const used = new Set(effective.flatMap((p) => [p.a, p.b]));
	for (const id of [...sites.keys()]) if (!used.has(id)) sites.delete(id);
	return { sites, pairs: effective, warnings };
}

/**
 * The nft script for the dedicated table (see header). Deterministic for the
 * same input (golden-testable, hash-stable). Never emits anything outside
 * `inet floppyguard_sites`. Pure.
 */
export function buildSiteIsolationNft({ pairs = [], links = [] }) {
	const plan = planSiteIsolation({ pairs, links });
	const out = [
		"#!/usr/sbin/nft -f",
		"# Managed by FloppyGuard - Standorte untereinander (site isolation). Do not edit:",
		"# the backend replaces this table atomically on every change.",
		`table inet ${SITE_TABLE} {}`,
		`delete table inet ${SITE_TABLE}`,
		`table inet ${SITE_TABLE} {`,
	];
	const ordered = [...plan.sites.values()].sort((x, y) => (x.set < y.set ? -1 : 1));
	for (const s of ordered) {
		for (const n of s.nets) {
			if (canonicalCidr(n) !== n) throw new Error(`site isolation: refusing non-canonical CIDR ${echo(n)}`);
		}
		out.push(
			`\tset ${s.set} {`,
			"\t\ttype ipv4_addr",
			"\t\tflags interval",
			`\t\tcomment "${sanitizeCommentText(s.name)}"`,
			`\t\telements = { ${s.nets.join(", ")} }`,
			"\t}",
		);
	}
	out.push(`\tchain ${SITE_CHAIN} {`, "\t\ttype filter hook forward priority filter - 10; policy accept;");
	for (const p of plan.pairs) {
		const A = plan.sites.get(p.a);
		const B = plan.sites.get(p.b);
		for (const [x, y] of [
			[A, B],
			[B, A],
		]) {
			const c = sanitizeCommentText(
				`Standort-Trennung ${sanitizeCommentText(x.name, 40)} -> ${sanitizeCommentText(y.name, 40)}`,
				100,
			);
			out.push(`\t\tip saddr @${x.set} ip daddr @${y.set} counter drop comment "${c}"`);
		}
	}
	out.push("\t}", "}", "");
	return out.join("\n");
}

/** sha256 of the script (what "applied" compares). */
export function scriptHash(script) {
	return createHash("sha256").update(String(script)).digest("hex");
}

/**
 * Would the hub drop src → dst because of an isolation pair? src/dst are IPv4
 * hosts or CIDRs. `blocked` = the whole src range lies in one site's set and the
 * whole dst range in the other's. `partial` = the ranges only overlap the sets
 * (some addresses blocked). Pure.
 * → { blocked, partial, pair?: { a, b, name_a, name_b, direction: "a-to-b"|"b-to-a" } }
 */
export function siteIsolationVerdict({ pairs = [], links = [], src, dst }) {
	const s = canonicalCidr(src);
	const d = canonicalCidr(dst);
	if (!s || !d) return { blocked: false, partial: false };
	const plan = planSiteIsolation({ pairs, links });
	const inSet = (site, c) => site.nets.some((n) => cidrContains(n, c));
	const touches = (site, c) => site.nets.some((n) => cidrOverlaps(n, c));
	let partial = null;
	for (const p of plan.pairs) {
		const A = plan.sites.get(p.a);
		const B = plan.sites.get(p.b);
		const ref = (direction) => ({ a: p.a, b: p.b, name_a: A.name, name_b: B.name, direction });
		if (inSet(A, s) && inSet(B, d)) return { blocked: true, partial: false, pair: ref("a-to-b") };
		if (inSet(B, s) && inSet(A, d)) return { blocked: true, partial: false, pair: ref("b-to-a") };
		if (!partial && touches(A, s) && touches(B, d)) partial = ref("a-to-b");
		if (!partial && touches(B, s) && touches(A, d)) partial = ref("b-to-a");
	}
	return partial ? { blocked: false, partial: true, pair: partial } : { blocked: false, partial: false };
}

/**
 * Agents that still route a network of a site their own site is isolated from:
 * the route exists on the agent, but the hub drops the traffic. Routed set per
 * agent follows the ACL priority of syncAgentConfigs: allowed_networks >
 * allowed_sites > full mesh. Pure.
 *
 * agents: [{ id, name, wg_link_name, allowed_networks: string[]|null, allowed_sites: string[]|null }]
 * → [{ code: "route-dropped", agent_id, agent_name, link_id, other_link_id, other_name, networks, via, message }]
 */
export function routeWarnings({ pairs = [], links = [], agents = [] }) {
	const byId = new Map(links.map((l) => [l.id, l]));
	const nameCount = new Map();
	for (const l of links) nameCount.set(l.name, (nameCount.get(l.name) || 0) + 1);
	const out = [];
	for (const agent of agents) {
		if (!agent?.wg_link_name || nameCount.get(agent.wg_link_name) !== 1) continue;
		const own = links.find((l) => l.name === agent.wg_link_name);
		if (!isSiteLink(own)) continue;
		for (const p of pairs) {
			const otherId = p.a === own.id ? p.b : p.b === own.id ? p.a : null;
			const other = otherId ? byId.get(otherId) : null;
			if (!other || !isSiteLink(other)) continue;
			const otherNets = (other.importedNetworks || []).map(canonicalCidr).filter(Boolean);
			let nets = [];
			let via;
			if (Array.isArray(agent.allowed_networks) && agent.allowed_networks.length) {
				via = "allowed_networks";
				nets = agent.allowed_networks
					.map(canonicalCidr)
					.filter((n) => n && otherNets.some((o) => cidrOverlaps(o, n)));
			} else if (Array.isArray(agent.allowed_sites) && agent.allowed_sites.length) {
				via = "allowed_sites";
				nets = agent.allowed_sites.includes(other.name) ? otherNets : [];
			} else {
				via = "full-mesh";
				nets = otherNets;
			}
			nets = [...new Set(nets)];
			if (!nets.length) continue;
			out.push({
				code: "route-dropped",
				agent_id: agent.id,
				agent_name: agent.name,
				link_id: own.id,
				other_link_id: other.id,
				other_name: other.name,
				networks: nets,
				via,
				message: `${agent.name}: Route zu ${other.name} (${nets.join(", ")}) vorhanden, wird am Hub verworfen`,
			});
		}
	}
	return out;
}

/**
 * Drop counters per pair from `nft -j list chain inet floppyguard_sites forward`.
 * Matches each rule by its saddr/daddr set names. Pure; tolerant of bad input.
 * → Map("setA>setB" → { packets, bytes })
 */
export function parseChainCounters(jsonText) {
	const out = new Map();
	let doc;
	try {
		doc = JSON.parse(jsonText);
	} catch {
		return out;
	}
	for (const item of doc?.nftables || []) {
		const expr = item?.rule?.expr;
		if (!Array.isArray(expr)) continue;
		let saddr = null;
		let daddr = null;
		let counter = null;
		for (const e of expr) {
			const m = e?.match;
			const field = m?.left?.payload?.field;
			const right = m?.right;
			if (typeof right === "string" && right.startsWith("@")) {
				if (field === "saddr") saddr = right.slice(1);
				if (field === "daddr") daddr = right.slice(1);
			}
			if (e?.counter) counter = e.counter;
		}
		if (saddr && daddr && counter) {
			out.set(`${saddr}>${daddr}`, { packets: Number(counter.packets) || 0, bytes: Number(counter.bytes) || 0 });
		}
	}
	return out;
}

// ── foreign (manual) drops in other forward chains ───────────────────────────
//
// FloppyGuard only owns `inet floppyguard_sites`. Drop rules someone added by hand
// to another forward-hooked chain (e.g. `ip saddr @site_x ip daddr @site_y drop`
// in `inet filter forward`) also separate sites — and a drop in ANY base chain on
// the hook is final. The app must not claim "nicht getrennt" while such a rule
// drops the traffic, so they are read from `nft -j list ruleset` and reported.

/** One nft JSON address expression → canonical IPv4 CIDRs, or null when not understood. */
export function nftAddrToCidrs(value, sets) {
	if (typeof value === "string") {
		if (value.startsWith("@")) return sets?.get(value.slice(1)) ?? null;
		const c = canonicalCidr(value.includes("/") ? value : `${value}/32`);
		return c ? [c] : null;
	}
	if (value?.prefix) {
		const c = canonicalCidr(`${value.prefix.addr}/${value.prefix.len}`);
		return c ? [c] : null;
	}
	if (Array.isArray(value?.set)) {
		const out = [];
		for (const e of value.set) {
			const r = nftAddrToCidrs(e, sets);
			if (!r) return null;
			out.push(...r);
		}
		return out;
	}
	if (value?.elem !== undefined) return nftAddrToCidrs(value.elem.val ?? value.elem, sets);
	return null;
}

/**
 * Drop/reject rules with an `ip saddr` AND an `ip daddr` match in forward-hooked
 * base chains of every table EXCEPT floppyguard_sites. Set references are resolved
 * to their elements (null = not resolvable, e.g. ranges). `extra` = the rule has
 * further conditions (ports, interfaces …), so it only drops part of the traffic.
 * Pure; tolerant of bad input (→ []).
 * → [{ family, table, chain, handle, comment, src_set, dst_set, src, dst, extra }]
 */
export function parseForeignForwardDrops(jsonText) {
	let doc;
	try {
		doc = typeof jsonText === "string" ? JSON.parse(jsonText) : jsonText;
	} catch {
		return [];
	}
	const items = Array.isArray(doc?.nftables) ? doc.nftables : [];
	const key = (o, name) => `${o.family}|${o.table}|${name}`;
	const forwardChains = new Set();
	const sets = new Map();
	for (const it of items) {
		const c = it?.chain;
		if (c?.hook === "forward" && !(c.family === "inet" && c.table === SITE_TABLE)) {
			forwardChains.add(key(c, c.name));
		}
		const s = it?.set;
		if (s?.name && s.type === "ipv4_addr") {
			const elems = Array.isArray(s.elem) ? s.elem : [];
			const cidrs = [];
			let ok = true;
			for (const e of elems) {
				const r = nftAddrToCidrs(e, null);
				if (!r) ok = false;
				else cidrs.push(...r);
			}
			sets.set(key(s, s.name), ok ? cidrs : null);
		}
	}
	const out = [];
	for (const it of items) {
		const r = it?.rule;
		if (!r || !forwardChains.has(key(r, r.chain)) || !Array.isArray(r.expr)) continue;
		const isDrop = r.expr.some((e) => e && ("drop" in e || "reject" in e));
		if (!isDrop) continue;
		const tableSets = new Map(
			[...sets].filter(([k]) => k.startsWith(`${r.family}|${r.table}|`)).map(([k, v]) => [k.split("|")[2], v]),
		);
		let src;
		let dst;
		let srcSet = null;
		let dstSet = null;
		let extra = false;
		for (const e of r.expr) {
			if (!e || typeof e !== "object") continue;
			if (e.match) {
				const field = e.match.left?.payload?.field;
				const proto = e.match.left?.payload?.protocol;
				const op = e.match.op;
				if (proto === "ip" && (field === "saddr" || field === "daddr") && (op === "==" || op === "in")) {
					const right = e.match.right;
					const name = typeof right === "string" && right.startsWith("@") ? right.slice(1) : null;
					const cidrs = nftAddrToCidrs(right, tableSets);
					if (field === "saddr") {
						src = cidrs;
						srcSet = name;
					} else {
						dst = cidrs;
						dstSet = name;
					}
				} else {
					extra = true;
				}
				continue;
			}
			if ("counter" in e || "drop" in e || "reject" in e || "log" in e || "limit" in e) continue;
			extra = true;
		}
		if (src === undefined || dst === undefined) continue;
		out.push({
			family: r.family,
			table: r.table,
			chain: r.chain,
			handle: r.handle ?? null,
			comment: typeof r.comment === "string" ? r.comment.slice(0, 120) : null,
			src_set: srcSet,
			dst_set: dstSet,
			src: src ?? null,
			dst: dst ?? null,
			extra,
		});
	}
	return out;
}

const anyOverlap = (xs, ys) => xs.some((x) => ys.some((y) => cidrOverlaps(x, y)));

/**
 * Site pairs that a foreign drop rule separates (fully or partly), from the site
 * nets (imported + tunnel). Unresolvable rule addresses are ignored here (they
 * still show up as a manual-drop warning). Pure.
 * sites: [{ link_id, name, networks, tunnel }]
 * → [{ link_a, link_b, rules: [{ family, table, chain, comment }] }] (link_a < link_b)
 */
export function manualSitePairs({ drops = [], sites = [] }) {
	const nets = (s) => [...(s.networks || []), ...(s.tunnel || [])];
	const out = new Map();
	for (let i = 0; i < sites.length; i++) {
		for (let j = i + 1; j < sites.length; j++) {
			const A = nets(sites[i]);
			const B = nets(sites[j]);
			const hits = drops.filter(
				(d) =>
					d.src &&
					d.dst &&
					((anyOverlap(d.src, A) && anyOverlap(d.dst, B)) || (anyOverlap(d.src, B) && anyOverlap(d.dst, A))),
			);
			if (!hits.length) continue;
			const n = normalizePair(sites[i].link_id, sites[j].link_id);
			out.set(`${n.a}|${n.b}`, {
				link_a: n.a,
				link_b: n.b,
				rules: hits.map((d) => ({ family: d.family, table: d.table, chain: d.chain, comment: d.comment })),
			});
		}
	}
	return [...out.values()];
}

/**
 * Would a foreign drop rule drop src → dst? Same semantics as
 * siteIsolationVerdict (blocked = whole ranges inside, partial = overlap).
 * Rules with extra conditions only ever count as partial. Pure.
 */
export function manualDropVerdict({ drops = [], src, dst }) {
	const s = canonicalCidr(src);
	const d = canonicalCidr(dst);
	if (!s || !d) return { blocked: false, partial: false };
	let partial = null;
	for (const r of drops) {
		if (!r.src || !r.dst) continue;
		const ref = { family: r.family, table: r.table, chain: r.chain, comment: r.comment };
		const full = r.src.some((n) => cidrContains(n, s)) && r.dst.some((n) => cidrContains(n, d));
		if (full && !r.extra) return { blocked: true, partial: false, rule: ref };
		if (!partial && anyOverlap(r.src, [s]) && anyOverlap(r.dst, [d])) partial = ref;
	}
	return partial ? { blocked: false, partial: true, rule: partial } : { blocked: false, partial: false };
}

/**
 * Does an nftables boot config load the persisted table file? True for an
 * uncommented `include "<file>"` or an include glob that matches its directory
 * (e.g. "/etc/nftables.d/*.nft"). Pure.
 */
export function bootIncludesFile(confText, file) {
	const dir = file.slice(0, file.lastIndexOf("/") + 1);
	const base = file.slice(dir.length);
	for (const raw of String(confText ?? "").split("\n")) {
		const line = raw.replace(/#.*/, "").trim();
		const m = line.match(/^include\s+"([^"]+)"/);
		if (!m) continue;
		const inc = m[1];
		if (inc === file) return true;
		if (inc.startsWith(dir) && inc.slice(dir.length).includes("*")) {
			const re = new RegExp(
				`^${inc
					.slice(dir.length)
					.replace(/[.+?^${}()|[\]\\]/g, "\\$&")
					.replace(/\*/g, "[^/]*")}$`,
			);
			if (re.test(base)) return true;
		}
	}
	return false;
}
