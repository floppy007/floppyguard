// Pure helpers behind the "Freigaben" comfort API: the catalog of known sources
// and destinations for one agent (pickers, wizards), the flow tester, the
// "unused rule" candidates and the bulk create/disable validation. No DB / IO
// here — agent-ingress.js collects the data and hands it in.
//
// Wire format note: every list is an ARRAY of objects. CIDRs and link ids never
// appear as object keys, because the frontend camelizes response keys deeply.

import error from "../lib/error.js";
import {
	canonicalCidr,
	cidrContains,
	echoValue as echo,
	hostIp,
	isHubSourced,
	parseJsonArray,
	ruleCovers,
	sanitizeIngressRule,
	tunnelAddressEntries,
	upstreamCovered,
} from "./agent-ingress-rules.js";

/** Common port sets for the rule editor ([] = all ports). */
export const PORT_PRESETS = [
	{
		id: "web",
		ports: [
			{ proto: "tcp", port: "80" },
			{ proto: "tcp", port: "443" },
		],
	},
	{ id: "ssh", ports: [{ proto: "tcp", port: "22" }] },
	{ id: "smb", ports: [{ proto: "tcp", port: "445" }] },
	{
		id: "ldap",
		ports: [
			{ proto: "tcp", port: "389" },
			{ proto: "tcp", port: "636" },
		],
	},
	{ id: "rdp", ports: [{ proto: "tcp", port: "3389" }] },
	{
		id: "dns",
		ports: [
			{ proto: "tcp", port: "53" },
			{ proto: "udp", port: "53" },
		],
	},
	{ id: "proxmox", ports: [{ proto: "tcp", port: "8006" }] },
	{ id: "pbs", ports: [{ proto: "tcp", port: "8007" }] },
	{ id: "all", ports: [] },
];

export const STALE_RULE_SECONDS = 30 * 24 * 3600;
export const MAX_BULK_RULES = 100;
export const MAX_BULK_DISABLE = 500;

const UPSTREAM_KIND_ORDER = ["proxy-host", "stream", "manual", "hub-egress"];
const DEST_GROUP = { "proxy-host": 0, stream: 0, manual: 0, "hub-egress": 0, service: 1, network: 2 };

const uniq = (list) => [...new Set(list)];
const byLabel = (a, b) => String(a.label).localeCompare(String(b.label));
const portKey = (p) => `${p.proto}/${p.port}`;

function mergePorts(into, add) {
	for (const p of add) {
		if (!into.some((q) => portKey(q) === portKey(p))) into.push(p);
	}
	return into;
}

const sortPorts = (ports) =>
	[...ports].sort((a, b) => a.proto.localeCompare(b.proto) || Number(a.port) - Number(b.port));

/**
 * Unix seconds from a DB timestamp: integer seconds, milliseconds, a numeric
 * string or a date string. null when unparseable.
 */
export function toUnixSeconds(value) {
	if (value === null || value === undefined || value === "") return null;
	if (typeof value === "number" || /^\d+$/.test(String(value))) {
		const n = Number(value);
		if (!Number.isFinite(n) || n <= 0) return null;
		return n > 1e12 ? Math.floor(n / 1000) : Math.floor(n);
	}
	const ms = value instanceof Date ? value.getTime() : Date.parse(String(value));
	return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}

/** Subnets of the Address lines of a wg conf ("Address = 10.10.0.1/24" → "10.10.0.0/24"). */
export function tunnelSubnets(confText) {
	const out = [];
	for (const p of tunnelAddressEntries(confText)) {
		if (!p.includes("/")) continue;
		const c = canonicalCidr(p);
		if (c && !c.endsWith("/32") && !out.includes(c)) out.push(c);
	}
	return out;
}

/**
 * Upstreams behind the agent grouped by host: one destination entry per IP (or
 * CIDR for an egress flow to a whole net). `covered` = every upstream of that
 * host is covered by an enabled rule from its hub source (egress flows with an
 * own source use that one). Pure.
 */
export function upstreamDestinations(behind, { rules = [], hubHosts = [] } = {}) {
	const groups = new Map();
	for (const u of behind || []) {
		const cidr = canonicalCidr(u?.host);
		if (!cidr) continue;
		if (!groups.has(cidr)) groups.set(cidr, []);
		groups.get(cidr).push(u);
	}
	const out = [];
	for (const [cidr, list] of groups) {
		const rank = (u) => {
			const i = UPSTREAM_KIND_ORDER.indexOf(u.kind);
			return i < 0 ? UPSTREAM_KIND_ORDER.length : i;
		};
		const ordered = [...list].sort((a, b) => rank(a) - rank(b));
		const names = uniq(
			ordered.flatMap((u) =>
				u.kind === "proxy-host"
					? String(u.label || "")
							.split(",")
							.map((s) => s.trim())
					: [String(u.label || "").trim()],
			),
		).filter(Boolean);
		const ports = [];
		for (const u of ordered) {
			if (u.port) mergePorts(ports, [{ proto: u.proto || "tcp", port: String(u.port) }]);
		}
		const covered = ordered.every((u) => upstreamCovered(u, rules, hubHosts));
		const entry = {
			id: `host:${hostIp(cidr)}`,
			kind: ordered[0].kind,
			label: names[0] || hostIp(cidr),
			names,
			cidrs: [cidr],
			ports: sortPorts(ports),
			// The ports the hub's upstreams use. `ports` may later grow by the ports
			// of discovered services on the same host (display only): a proxy rule
			// must not open those.
			upstream_ports: sortPorts(ports),
			enabled: ordered.some((u) => Boolean(u.enabled)),
			covered,
		};
		if (ordered.some((u) => !u.port)) entry.hint = "no-port";
		out.push(entry);
	}
	return out;
}

/**
 * Services the agent discovered ({name, url}) as destination entries, one per
 * IPv4 host. With `ownNets` (array) only hosts inside one of them are kept;
 * ownNets null = no filter. Port = URL port or the scheme default. Pure.
 */
export function serviceDestinations(services, ownNets, { agentId = 0 } = {}) {
	const list = parseJsonArray(services);
	if (!list.length) return [];
	const byIp = new Map();
	const out = [];
	list.forEach((svc, i) => {
		if (!svc || typeof svc.url !== "string") return;
		let url;
		try {
			url = new URL(svc.url);
		} catch {
			return;
		}
		const host = url.hostname;
		if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return;
		const cidr = canonicalCidr(host);
		if (!cidr) return;
		if (Array.isArray(ownNets) && !ownNets.some((n) => cidrContains(n, cidr))) return;
		const port = url.port || (url.protocol === "https:" ? "443" : url.protocol === "http:" ? "80" : "");
		if (!port) return;
		const name = String(svc.name || host).trim() || host;
		const p = { proto: "tcp", port: String(Number(port)) };
		const existing = byIp.get(cidr);
		if (existing) {
			if (!existing.names.includes(name)) existing.names.push(name);
			mergePorts(existing.ports, [p]);
			return;
		}
		const entry = {
			id: `service:${agentId}:${i}`,
			kind: "service",
			label: name,
			names: [name],
			cidrs: [cidr],
			ports: [p],
		};
		byIp.set(cidr, entry);
		out.push(entry);
	});
	for (const e of out) e.ports = sortPorts(e.ports);
	return out;
}

/**
 * Catalog of known sources/destinations for one agent. Pure.
 *
 * ctx = {
 *   agent: { id, name, ingress_mode, services },
 *   site: { linkId, ownNets } | null,          // agentSiteLink result
 *   links: [{ id, name, type, importedNetworks, tunnelAddresses, active }],
 *   linkAgents: [{ link_id, preserve_lan_source_ip }], // agents bound to links
 *   hubNets, hubHosts, tunnelNets,             // hub-connected nets, hub /32s, tunnel subnets
 *   iface,                                     // hub interface of the agent's link
 *   egressFlows, clients, behind, rules, now,
 * }
 */
export function buildCatalog(ctx) {
	const {
		agent,
		site = null,
		links = [],
		linkAgents = [],
		hubNets = [],
		hubHosts = [],
		tunnelNets = [],
		iface = "wg0",
		egressFlows = [],
		clients = [],
		behind = [],
		rules = [],
		applied = null,
		now = Math.floor(Date.now() / 1000),
	} = ctx;
	const linkFound = Boolean(site);
	const inHub = (n) => hubNets.some((h) => cidrContains(h, n));
	const ownNets = site ? site.ownNets || [] : [];
	const ownNoHub = ownNets.filter((n) => !inHub(n));
	const linkById = new Map(links.map((l) => [l.id, l]));

	// ── sources ──
	const sources = [];
	const hubEntry = {
		id: "hub",
		kind: "hub",
		label: "hub",
		cidrs: uniq(hubHosts.map(canonicalCidr).filter(Boolean)),
		hint: "snat-hub-lan",
	};
	const hubNames = [];
	const egressSources = [];
	for (const f of egressFlows) {
		if (!f?.source) continue;
		const c = canonicalCidr(f.source);
		if (!c) continue;
		egressSources.push({ id: `egress:${f.id}`, kind: "hub-egress", label: f.label, cidrs: [c] });
	}
	const siteSources = [];
	for (const l of links) {
		if (!l?.id || l.type === "client" || (site && l.id === site.linkId)) continue;
		const nets = uniq((l.importedNetworks || []).map(canonicalCidr).filter(Boolean));
		const ownNetsOfLink = nets.filter((n) => !inHub(n));
		if (nets.length && !ownNetsOfLink.length) {
			// Everything behind this site is on a hub-connected net: its traffic
			// reaches the agent SNATed as the hub address.
			hubNames.push(l.name);
			continue;
		}
		const tunnel = uniq(
			(l.tunnelAddresses || [])
				.map((c) => canonicalCidr(String(c).includes("/") ? c : `${c}/32`))
				.filter((c) => c?.endsWith("/32")),
		);
		if (!ownNetsOfLink.length && !tunnel.length) continue;
		const siteId = `site:${l.id}`;
		const bound = linkAgents.filter((a) => a.link_id === l.id);
		const entry = {
			id: siteId,
			kind: "site",
			label: l.name,
			cidrs: [...ownNetsOfLink, ...tunnel],
			online: Boolean(l.active),
		};
		if (bound.length && bound.every((a) => a.preserve_lan_source_ip !== true && a.preserve_lan_source_ip !== 1)) {
			entry.hint = "masquerade";
		}
		siteSources.push(entry);
		for (const n of ownNetsOfLink) {
			siteSources.push({
				id: `site-net:${l.id}:${n}`,
				kind: "site-net",
				label: n,
				cidrs: [n],
				parent: siteId,
				online: Boolean(l.active),
			});
		}
	}
	if (hubNames.length) hubEntry.names = uniq(hubNames);
	if (hubEntry.cidrs.length) sources.push(hubEntry);
	sources.push(...egressSources);
	if (linkFound) sources.push(...siteSources);
	for (const c of clients) {
		if (site && c.id === site.linkId) continue; // the agent's own (inferred-client) site link
		const l = linkById.get(c.id);
		sources.push({
			id: `client:${c.id}`,
			kind: "client",
			label: c.label,
			cidrs: uniq(c.hosts || []),
			...(l ? { online: Boolean(l.active) } : {}),
		});
	}
	tunnelNets.forEach((n, i) => {
		sources.push({ id: i ? `tunnel:${iface}:${i}` : `tunnel:${iface}`, kind: "tunnel", label: n, cidrs: [n] });
	});

	// ── destinations ──
	let destinations;
	if (linkFound) {
		const ups = upstreamDestinations(behind, { rules, hubHosts });
		for (const s of serviceDestinations(agent?.services, ownNoHub, { agentId: agent?.id })) {
			const host = ups.find((u) => u.cidrs[0] === s.cidrs[0]);
			if (host) {
				host.names = uniq([...host.names, ...s.names]);
				host.ports = sortPorts(mergePorts([...host.ports], s.ports));
			} else {
				ups.push(s);
			}
		}
		for (const n of ownNoHub) ups.push({ id: `net:${n}`, kind: "network", label: n, cidrs: [n] });
		destinations = ups;
	} else {
		destinations = serviceDestinations(agent?.services, null, { agentId: agent?.id });
	}
	destinations.sort((a, b) => (DEST_GROUP[a.kind] ?? 3) - (DEST_GROUP[b.kind] ?? 3) || byLabel(a, b));

	const hubSrcs = [...hubEntry.cidrs, ...egressSources.flatMap((e) => e.cidrs)];
	const site_ = site ? linkById.get(site.linkId) : null;
	return {
		agent_id: agent?.id,
		agent_name: agent?.name,
		ingress_mode: agent?.ingress_mode || "open",
		link_found: linkFound,
		site: site ? { link_id: site.linkId, name: site_?.name ?? site.linkId, networks: [...ownNets] } : null,
		sources,
		destinations,
		port_presets: PORT_PRESETS.map((p) => ({ id: p.id, ports: p.ports.map((x) => ({ ...x })) })),
		prune_candidates: pruneCandidates({
			rules,
			behind,
			hubSrcs,
			mode: agent?.ingress_mode || "open",
			now,
			linkFound,
			appliedState: applied?.state ?? null,
		}),
	};
}

/** Newest reference time of a rule: last hit, creation, (re-)arming. null = none known. */
export function ruleReferenceTime(r) {
	const refs = [toUnixSeconds(r.last_hit_at), toUnixSeconds(r.created_on), toUnixSeconds(r.armed_on)].filter(
		(v) => v !== null,
	);
	return refs.length ? Math.max(...refs) : null;
}

/**
 * Enabled rules without a new connection for 30 days that no upstream behind the
 * agent needs — the one-click "switch off unused" offer, so deliberately narrow:
 *   - only while the agent confirmed the current ruleset (appliedState
 *     "applied"): an agent that is offline, too old or failed reports no
 *     counters, so "no hits" means nothing there;
 *   - only rules armed (switched on / targets changed) more than 30 days ago;
 *   - only HUB-sourced rules (every source inside a hub / egress address).
 *     Rules for VPN clients, other sites or tunnel ranges are often break-glass
 *     access (admin laptop → iDRAC) that is quiet for months but still needed,
 *     and no upstream list can tell; they are never offered.
 * Counters only count NEW connections, so a long-lived session stays invisible
 * either way — the UI says so. In restricted mode at least one enabled rule
 * always stays (the newest is dropped from the list when all would qualify). Pure.
 */
export function pruneCandidates({
	rules = [],
	behind = [],
	hubSrcs = [],
	mode = "open",
	now = Math.floor(Date.now() / 1000),
	linkFound = true,
	appliedState = null,
}) {
	if (!linkFound || appliedState !== "applied") return [];
	const enabled = rules.filter((r) => r.enabled);
	const out = [];
	for (const r of enabled) {
		if (!isHubSourced(r, hubSrcs)) continue;
		const ref = ruleReferenceTime(r);
		if (ref === null || now - ref <= STALE_RULE_SECONDS) continue;
		// armed_on = when the rule last started to matter (falls back to creation)
		const armed = toUnixSeconds(r.armed_on) ?? toUnixSeconds(r.created_on);
		if (armed === null || now - armed <= STALE_RULE_SECONDS) continue;
		const needed = behind.some((u) =>
			[...hubSrcs, ...(u.source ? [u.source] : [])].some((h) =>
				ruleCovers(r, { src: h, dst: u.host, port: u.port ?? null, proto: u.proto || "tcp" }),
			),
		);
		if (needed) continue;
		out.push({ rule: r, ref });
	}
	if (mode === "restricted" && out.length && out.length === enabled.length) {
		let newest = 0;
		out.forEach((c, i) => {
			if (c.ref > out[newest].ref) newest = i;
		});
		out.splice(newest, 1);
	}
	return out.map(({ rule }) => ({
		id: rule.id,
		name: rule.name,
		last_hit_at: rule.last_hit_at ?? null,
		reason: "no-hits-30d",
	}));
}

/** Validate a tester query → { src, dst, port: number|null, proto }. */
export function sanitizeFlowQuery(body) {
	const b = body || {};
	const src = canonicalCidr(b.source);
	if (!src) throw new error.ValidationError(`source: invalid IPv4 address/CIDR: ${echo(b.source)}`);
	const dst = canonicalCidr(b.destination);
	if (!dst) throw new error.ValidationError(`destination: invalid IPv4 address/CIDR: ${echo(b.destination)}`);
	let port = null;
	if (b.port !== undefined && b.port !== null && b.port !== "") {
		const n =
			typeof b.port === "number" ? b.port : /^\d{1,5}$/.test(String(b.port).trim()) ? Number(b.port) : Number.NaN;
		if (!Number.isInteger(n) || n < 1 || n > 65535) {
			throw new error.ValidationError(`port: invalid port ${echo(b.port)}`);
		}
		port = n;
	}
	const proto = b.proto === undefined || b.proto === null || b.proto === "" ? "tcp" : String(b.proto).toLowerCase();
	if (proto !== "tcp" && proto !== "udp") throw new error.ValidationError(`proto: invalid protocol ${echo(proto)}`);
	return { src, dst, port, proto };
}

const ruleRef = (r) => (r ? { id: r.id, name: r.name } : null);

/**
 * What this agent's FG_IN does with one flow (src → dst:port/proto). Pure.
 * Rule order = ascending id (the line iptables hits first, whose counter rises).
 *
 * `isolation` = siteIsolationVerdict result for the flow (or null). The hub's
 * site isolation drops the flow BEFORE it ever reaches the agent, so a blocked
 * verdict wins over every Freigabe (reason "site-isolation", pair attached).
 */
export function evaluateFlow({
	mode = "open",
	rules = [],
	ownNets = [],
	hubNets = [],
	src,
	dst,
	port = null,
	proto = "tcp",
	applied = null,
	isolation = null,
}) {
	const notes = ["established-return", "forward-only"];
	if (applied && applied.state !== "applied") notes.push("not-applied");
	const base = { mode, matched_rules: [], disabled_match: null, port_unknown: false, notes };
	if (isolation?.blocked) {
		if (isolation.applied === false) notes.push("site-isolation-not-applied");
		return {
			...base,
			allowed: false,
			filtered: true,
			reason: "site-isolation",
			rule: null,
			site_isolation: isolation.pair || null,
			// blocked by a drop rule set by hand outside FloppyGuard (no pair)
			site_isolation_manual: isolation.manual || null,
		};
	}
	if (isolation?.partial) notes.push("site-isolation-partial");
	if (!ownNets.some((n) => cidrContains(n, dst)) || hubNets.some((n) => cidrContains(n, dst))) {
		return { ...base, allowed: null, filtered: false, reason: "not-via-agent", rule: null };
	}
	if (ownNets.some((n) => cidrContains(n, src))) {
		return { ...base, allowed: null, filtered: false, reason: "same-site", rule: null };
	}
	const flow = { src, dst, port: port ?? null, proto };
	const sorted = [...rules].sort((a, b) => a.id - b.id);
	const matches = sorted.filter((r) => ruleCovers(r, flow));
	const disabled = sorted.find((r) => !r.enabled && ruleCovers({ ...r, enabled: true }, flow));
	const portUnknown =
		(port === null || port === undefined) &&
		!matches.length &&
		sorted.some((r) => r.enabled && r.ports.length && ruleCovers({ ...r, ports: [] }, flow));
	const out = {
		...base,
		matched_rules: matches.map(ruleRef),
		disabled_match: ruleRef(disabled),
		port_unknown: portUnknown,
	};
	const first = matches[0] || null;
	if (mode !== "restricted")
		return { ...out, allowed: true, filtered: false, reason: "open-mode", rule: ruleRef(first) };
	if (first) return { ...out, allowed: true, filtered: true, reason: "rule", rule: ruleRef(first) };
	return { ...out, allowed: false, filtered: true, reason: "no-rule", rule: null };
}

/**
 * Validate a bulk create body's rule list: 1..MAX_BULK_RULES entries, each one
 * through sanitizeIngressRule; the first bad entry fails the whole batch with
 * its index in the message ("rules[3]: sources must not be empty").
 */
export function sanitizeBulkList(list) {
	if (!Array.isArray(list) || list.length < 1 || list.length > MAX_BULK_RULES) {
		throw new error.ValidationError(`rules must be an array of 1 to ${MAX_BULK_RULES} Freigaben`);
	}
	return list.map((d, i) => {
		try {
			return sanitizeIngressRule(d);
		} catch (err) {
			if (err instanceof error.ValidationError) {
				throw new error.ValidationError(`rules[${i}]: ${err.message}`, err);
			}
			throw err;
		}
	});
}

const targetKey = (r) =>
	JSON.stringify([
		[...(r.sources || [])].map(canonicalCidr).sort(),
		[...(r.destinations || [])].map(canonicalCidr).sort(),
		[...(r.ports || [])].map(portKey).sort(),
	]);

/**
 * Split sanitized bulk entries into new rules, rules to switch back on and
 * duplicates. Targets = sources, destinations and ports (as sets).
 *   - same targets as an ENABLED existing rule or an earlier entry → skipped
 *   - same targets as a DISABLED existing rule (typically switched off by hand
 *     or by "switch off unused") → that rule is re-enabled instead: skipping it
 *     would report success while the traffic stays dropped
 * Pure.
 * → { create: [{ index, rule }], reenable: [{ index, rule_id }],
 *     skipped: [{ index, reason: "duplicate", rule_id }] }
 */
export function bulkDedupe(existing, clean) {
	const enabledByKey = new Map();
	const disabledByKey = new Map();
	for (const r of existing || []) {
		const k = targetKey(r);
		const into = r.enabled ? enabledByKey : disabledByKey;
		if (!into.has(k)) into.set(k, r.id ?? null);
	}
	const seen = new Map(enabledByKey);
	const create = [];
	const reenable = [];
	const skipped = [];
	(clean || []).forEach((rule, index) => {
		const k = targetKey(rule);
		if (seen.has(k)) {
			skipped.push({ index, reason: "duplicate", rule_id: seen.get(k) });
			return;
		}
		if (disabledByKey.has(k) && disabledByKey.get(k) !== null) {
			const ruleId = disabledByKey.get(k);
			reenable.push({ index, rule_id: ruleId });
			seen.set(k, ruleId);
			return;
		}
		seen.set(k, null);
		create.push({ index, rule });
	});
	return { create, reenable, skipped };
}

/** Validate a bulk-disable id list: 1..MAX_BULK_DISABLE positive integers, deduplicated. */
export function sanitizeRuleIds(value) {
	if (!Array.isArray(value) || value.length < 1 || value.length > MAX_BULK_DISABLE) {
		throw new error.ValidationError(`rule_ids must be an array of 1 to ${MAX_BULK_DISABLE} ids`);
	}
	const out = [];
	for (const v of value) {
		const n = typeof v === "number" ? v : /^\d+$/.test(String(v)) ? Number(v) : Number.NaN;
		if (!Number.isInteger(n) || n < 1) throw new error.ValidationError(`rule_ids: invalid id ${echo(v)}`);
		if (!out.includes(n)) out.push(n);
	}
	return out;
}
