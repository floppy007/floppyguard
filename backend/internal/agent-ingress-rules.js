// Pure helpers for per-agent ingress filtering ("Freigaben"). No DB / IO here so
// everything that decides what lands in the agent's iptables is unit-testable.
//
// Model: an agent with ingress_mode "restricted" filters all traffic that ARRIVES
// through its WireGuard interface (from the hub or other sites) against an allow
// list. The agent applies the generated ruleset as its own chain FG_IN (atomic
// iptables-restore --noflush, jump at FORWARD position 1). Restricted semantics:
// ACCEPT RELATED,ESTABLISHED, ACCEPT per (source × destination × port), DROP for
// `-i <iface>` at the end.
// Mode "open" with rules is observation only: the rule lines end in RETURN (hit
// counters still work), established/related traffic RETURNs at the top (so it
// skips the rule walk and the counters mean "new flows" in both modes), and there
// is neither an ACCEPT nor a final DROP, so the chain never overrides the
// gateway's own FORWARD rules.
//
// Scope: FG_IN hangs in FORWARD only. It filters traffic routed THROUGH the
// gateway into its LAN — not connections to services on the gateway itself
// (INPUT), which stay governed by the gateway's own firewall.

import { createHash } from "node:crypto";
import error from "../lib/error.js";

export const INGRESS_CHAIN = "FG_IN";
export const INGRESS_MODES = new Set(["open", "restricted"]);
export const INGRESS_PROTOS = new Set(["tcp", "udp"]);

export const MAX_RULES_PER_AGENT = 500;
export const isWgIface = (name) => /^wg\d{1,3}$/.test(String(name ?? ""));
/** "wgN:<pubkey>" -> [iface, pubkey] or null when there is no colon. */
export function splitLinkId(id) {
	const s = String(id);
	const i = s.indexOf(":");
	return i < 0 ? null : [s.slice(0, i), s.slice(i + 1)];
}
export const pubKey8 = (pub) => String(pub).slice(0, 8);
const MAX_LIST = 64;
// Every rule expands to sources × destinations × ports iptables lines. The whole
// ruleset travels in each /agent/config poll and is parsed on the agent, so cap
// the expansion per rule and per agent (an absurd 64×64×64 rule would be 262k
// lines / ~28 MB, built synchronously on every poll).
export const MAX_LINES_PER_RULE = 256;
export const MAX_LINES_TOTAL = 4000;
const NAME_MAX = 100;
const NOTE_MAX = 255;

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function ipToInt(ip) {
	const m = IPV4_RE.exec(ip);
	if (!m) return null;
	const o = m.slice(1, 5).map(Number);
	if (o.some((x) => x > 255)) return null;
	return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
}

function intToIp(n) {
	return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

/**
 * Canonicalize an IPv4 host or CIDR to "a.b.c.d/p" with host bits masked off.
 * "10.0.0.1" → "10.0.0.1/32", "192.168.1.7/24" → "192.168.1.0/24".
 * Returns null for anything that is not a clean IPv4 host/CIDR.
 */
export function canonicalCidr(value) {
	const s = String(value ?? "").trim();
	if (!s) return null;
	const [addr, prefixStr, extra] = s.split("/");
	if (extra !== undefined) return null;
	const ipInt = ipToInt(addr);
	if (ipInt === null) return null;
	let prefix = 32;
	if (prefixStr !== undefined) {
		if (!/^\d{1,2}$/.test(prefixStr)) return null;
		prefix = Number(prefixStr);
		if (prefix > 32) return null;
	}
	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	return `${intToIp((ipInt & mask) >>> 0)}/${prefix}`;
}

/** True when CIDR `inner` lies completely inside CIDR `outer` (both canonical-able). */
export function cidrContains(outer, inner) {
	const o = canonicalCidr(outer);
	const i = canonicalCidr(inner);
	if (!o || !i) return false;
	const [oAddr, oP] = o.split("/");
	const [iAddr, iP] = i.split("/");
	if (Number(iP) < Number(oP)) return false;
	const p = Number(oP);
	const mask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
	return (ipToInt(iAddr) & mask) >>> 0 === (ipToInt(oAddr) & mask) >>> 0;
}

/** A request value echoed in an error message, clipped (the message goes to the client and the log). */
export const echoValue = (v) => {
	const s = String(v ?? "");
	return s.length > 64 ? `${s.slice(0, 64)}…` : s;
};

function sanitizeCidrList(input, field, { allowEmpty }) {
	const value = input === null || typeof input === "undefined" ? [] : input;
	if (!Array.isArray(value)) {
		throw new error.ValidationError(`${field} must be an array of IPv4 addresses/CIDRs`);
	}
	if (value.length > MAX_LIST) {
		throw new error.ValidationError(`${field}: at most ${MAX_LIST} entries`);
	}
	const out = [];
	for (const raw of value) {
		const c = canonicalCidr(raw);
		if (!c) throw new error.ValidationError(`${field} contains invalid IPv4 address/CIDR: ${echoValue(raw)}`);
		if (!out.includes(c)) out.push(c);
	}
	if (!allowEmpty && out.length === 0) {
		throw new error.ValidationError(`${field} must not be empty`);
	}
	return out;
}

function sanitizePorts(value) {
	if (value === null || typeof value === "undefined") return [];
	if (!Array.isArray(value)) throw new error.ValidationError("ports must be an array");
	if (value.length > MAX_LIST) throw new error.ValidationError(`ports: at most ${MAX_LIST} entries`);
	const out = [];
	for (const raw of value) {
		const proto = String(raw?.proto ?? "tcp").toLowerCase();
		if (!INGRESS_PROTOS.has(proto)) throw new error.ValidationError(`ports: invalid protocol ${echoValue(proto)}`);
		const portStr = String(raw?.port ?? "").trim();
		const m = /^(\d{1,5})(?:[:-](\d{1,5}))?$/.exec(portStr);
		if (!m) throw new error.ValidationError(`ports: invalid port ${echoValue(portStr)}`);
		const from = Number(m[1]);
		const to = m[2] !== undefined ? Number(m[2]) : from;
		if (from < 1 || to > 65535 || to < from)
			throw new error.ValidationError(`ports: invalid port ${echoValue(portStr)}`);
		const port = from === to ? String(from) : `${from}:${to}`;
		if (!out.some((p) => p.proto === proto && p.port === port)) out.push({ proto, port });
	}
	return out;
}

function cleanText(value, max) {
	return (
		String(value ?? "")
			// biome-ignore lint/suspicious/noControlCharactersInRegex: strip control chars from user text
			.replace(/[\u0000-\u001f\u007f]/g, " ")
			.trim()
			.slice(0, max)
	);
}

/**
 * Validate + normalize a rule payload from the API. Returns the DB-shaped patch
 * (JSON columns as arrays; the caller stringifies). `partial` allows updates
 * that omit fields.
 */
export function sanitizeIngressRule(data, { partial = false } = {}) {
	const d = data || {};
	const out = {};
	if (!partial || typeof d.name !== "undefined") {
		const name = cleanText(d.name, NAME_MAX);
		if (!name) throw new error.ValidationError("name is required");
		out.name = name;
	}
	if (!partial || typeof d.sources !== "undefined") {
		out.sources = sanitizeCidrList(d.sources, "sources", { allowEmpty: false });
	}
	if (!partial || typeof d.destinations !== "undefined") {
		out.destinations = sanitizeCidrList(d.destinations, "destinations", { allowEmpty: true });
	}
	if (!partial || typeof d.ports !== "undefined") {
		out.ports = sanitizePorts(d.ports);
	}
	if (!partial || typeof d.enabled !== "undefined") {
		out.enabled = d.enabled === undefined ? true : Boolean(d.enabled) && d.enabled !== "false" && d.enabled !== 0;
	}
	if (!partial || typeof d.note !== "undefined") {
		out.note = cleanText(d.note, NOTE_MAX) || null;
	}
	if (!partial) assertRuleLineCount(out);
	return out;
}

/** Number of iptables lines one rule expands to (sources × destinations × ports). */
export function ruleLineCount(rule) {
	const n = (list) => Math.max(1, Array.isArray(list) ? list.length : 0);
	return (Array.isArray(rule?.sources) ? rule.sources.length : 0) * n(rule?.destinations) * n(rule?.ports);
}

/** Reject a rule whose expansion exceeds MAX_LINES_PER_RULE. */
export function assertRuleLineCount(rule) {
	const lines = ruleLineCount(rule);
	if (lines > MAX_LINES_PER_RULE) {
		throw new error.ValidationError(
			`Freigabe ergibt ${lines} Filterzeilen (Quellen × Ziele × Ports), erlaubt sind höchstens ${MAX_LINES_PER_RULE} – bitte aufteilen oder zusammenfassen`,
		);
	}
}

/**
 * Reject a ruleset whose ENABLED rules expand to more than MAX_LINES_TOTAL lines
 * in total. Checked on save (create/update/mode change, enabling a direct link):
 * buildIngressRestore enforces the same cap, and a ruleset it cannot build never
 * reaches the agent. `ifaceCount` = hub interface + enabled direct links — every
 * rule line is emitted once per interface.
 */
export function assertTotalLineCount(rules, ifaceCount = 1) {
	const total =
		(rules || []).filter((r) => r?.enabled !== false).reduce((n, r) => n + ruleLineCount(r), 0) *
		Math.max(1, ifaceCount);
	if (total > MAX_LINES_TOTAL) {
		throw new error.ValidationError(
			`Die aktiven Freigaben ergeben zusammen ${total} Filterzeilen, erlaubt sind höchstens ${MAX_LINES_TOTAL} – bitte Freigaben zusammenfassen oder deaktivieren`,
		);
	}
}

export function sanitizeIngressMode(mode) {
	const m = String(mode ?? "").trim();
	if (!INGRESS_MODES.has(m))
		throw new error.ValidationError(`ingress_mode must be one of: ${[...INGRESS_MODES].join(", ")}`);
	return m;
}

/** JSON array column -> array. Arrays pass through; empty, non-string, non-array or invalid JSON -> fallback. */
export const parseJsonArray = (raw, fallback = []) => {
	if (Array.isArray(raw)) return raw;
	if (typeof raw !== "string" || !raw) return fallback;
	try {
		const v = JSON.parse(raw);
		return Array.isArray(v) ? v : fallback;
	} catch {
		return fallback;
	}
};

/** DB row → API object (JSON columns parsed, bools normalized). */
export function rowToRule(row) {
	return {
		id: row.id,
		agent_id: row.agent_id,
		name: row.name,
		sources: parseJsonArray(row.sources),
		destinations: parseJsonArray(row.destinations),
		ports: parseJsonArray(row.ports),
		enabled: Boolean(row.enabled),
		note: row.note ?? null,
		hit_packets: Number(row.hit_packets || 0),
		last_hit_at: row.last_hit_at ? Number(row.last_hit_at) : null,
		created_on: row.created_on,
		modified_on: row.modified_on,
		armed_on: row.armed_on ? Number(row.armed_on) : null,
	};
}

/**
 * Pure: the armed_on patch for an update. A rule is (re-)armed — its "no new
 * connection" window starts over — when it is switched on or its targets
 * change (as sets — reordering does not re-arm); a rename or note edit keeps the reference.
 *
 * @param {Object} existing  API-shaped rule (rowToRule) before the update
 * @param {Object} clean     sanitized partial patch
 * @param {number} now       unix seconds
 * @returns {{armed_on?: number}}
 */
/** Order-insensitive key of a sources/destinations/ports list (entries are already canonical). */
const listKey = (list) =>
	JSON.stringify([...(list || [])].map((v) => (typeof v === "string" ? v : `${v.proto}/${v.port}`)).sort());

export function armedOnPatch(existing, clean, now) {
	const switchedOn = clean.enabled === true && !existing.enabled;
	const targetsChanged = ["sources", "destinations", "ports"].some(
		(f) => typeof clean[f] !== "undefined" && listKey(clean[f]) !== listKey(existing[f]),
	);
	return switchedOn || targetsChanged ? { armed_on: now } : {};
}

/**
 * Build the iptables-restore payload for one agent, or null when the agent needs
 * no filter at all (mode "open" without rules — zero footprint on the agent).
 *
 * Traffic arriving through the agent's direct links (`directIfaces`, fgd<id>,
 * see agent-direct-link-rules.js) is filtered exactly like traffic from the hub:
 * every rule line and the final DROP are repeated per interface. Without direct
 * links the text (and its hash) is unchanged.
 *
 * @param {{ingress_mode: string, iface: string, directIfaces?: string[]}} agent  iface = sanitized WG interface
 * @param {Array} rules  API-shaped rules (rowToRule)
 * @returns {{text: string, hash: string, ruleCount: number}|null}
 */
export function buildIngressRestore({ ingress_mode, iface, directIfaces = [] }, rules) {
	const mode = INGRESS_MODES.has(ingress_mode) ? ingress_mode : "open";
	const active = (rules || []).filter((r) => r.enabled).sort((a, b) => a.id - b.id);
	if (mode === "open" && active.length === 0) return null;
	if (!isWgIface(iface)) throw new Error(`invalid wg interface: ${iface}`);
	for (const d of directIfaces) {
		if (!/^fgd\d{1,4}$/.test(String(d))) throw new Error(`invalid direct interface: ${d}`);
	}
	const ifaces = [iface, ...directIfaces];
	if (active.length > MAX_RULES_PER_AGENT) throw new Error("too many ingress rules");

	const restricted = mode === "restricted";
	// Open mode = observation only (see header): RETURN instead of ACCEPT, the
	// conntrack shortcut RETURNs (non-terminal), no final DROP.
	const target = restricted ? "ACCEPT" : "RETURN";
	const lines = ["*filter", `:${INGRESS_CHAIN} - [0:0]`];
	lines.push(`-A ${INGRESS_CHAIN} -m conntrack --ctstate RELATED,ESTABLISHED -j ${target}`);
	let ruleCount = 0;
	for (const rule of active) {
		if (!Number.isInteger(rule.id) || rule.id < 1) throw new Error("rule without id");
		const sources = (rule.sources || []).map(canonicalCidr);
		// An invalid destination must never degrade to "any destination": only an
		// explicitly EMPTY list means any.
		const destList = (rule.destinations || []).map(canonicalCidr);
		if (!sources.length || sources.some((s) => !s) || destList.some((d) => !d)) {
			throw new Error(`rule ${rule.id}: bad CIDR`);
		}
		const dests = destList.length ? destList : [null];
		const ports = rule.ports?.length ? rule.ports : [null];
		for (const src of sources) {
			for (const dst of dests) {
				for (const p of ports) {
					for (const inIface of ifaces) {
						let l = `-A ${INGRESS_CHAIN} -s ${src}`;
						if (dst) l += ` -d ${dst}`;
						l += ` -i ${inIface}`;
						if (p) {
							if (!INGRESS_PROTOS.has(p.proto) || !/^\d{1,5}(:\d{1,5})?$/.test(p.port)) {
								throw new Error(`rule ${rule.id}: bad port`);
							}
							l += ` -p ${p.proto} -m ${p.proto} --dport ${p.port}`;
						}
						l += ` -m comment --comment "fg:${rule.id}" -j ${target}`;
						lines.push(l);
						ruleCount++;
						if (ruleCount > MAX_LINES_TOTAL) throw new Error(`more than ${MAX_LINES_TOTAL} ingress lines`);
					}
				}
			}
		}
	}
	if (restricted) for (const inIface of ifaces) lines.push(`-A ${INGRESS_CHAIN} -i ${inIface} -j DROP`);
	lines.push("COMMIT");
	const text = `${lines.join("\n")}\n`;
	return { text, hash: createHash("sha256").update(text).digest("hex"), ruleCount };
}

/**
 * Parse counters from `iptables -L FG_IN -v -x -n` style input the agent sends:
 * { "<ruleId>": packets }. Hostile input is clamped; returns Map<id, packets>.
 */
export function sanitizeIngressCounters(value) {
	const out = new Map();
	if (!value || typeof value !== "object" || Array.isArray(value)) return out;
	let n = 0;
	for (const [k, v] of Object.entries(value)) {
		if (++n > MAX_RULES_PER_AGENT) break;
		const id = Number(k);
		const packets = Number(v);
		if (!Number.isInteger(id) || id < 1) continue;
		if (!Number.isFinite(packets) || packets < 0) continue;
		out.set(id, Math.min(Math.floor(packets), Number.MAX_SAFE_INTEGER));
	}
	return out;
}

/**
 * Decide the new hit bookkeeping for one rule from a counter sample.
 * Counters reset when the chain is rebuilt, so a lower value means "reset" and
 * the sample itself is the delta.
 */
export function nextHitState({ hit_packets, last_hit_at }, packets, now) {
	const prev = Number(hit_packets || 0);
	const delta = packets >= prev ? packets - prev : packets;
	return { hit_packets: packets, last_hit_at: delta > 0 ? now : last_hit_at || null };
}

/** True when an enabled rule lets `srcIp` reach `dstIp:port/proto`. */
export function ruleCovers(rule, { src, dst, port, proto = "tcp" }) {
	if (!rule.enabled) return false;
	if (!rule.sources.some((s) => cidrContains(s, src))) return false;
	if (rule.destinations.length && !rule.destinations.some((d) => cidrContains(d, dst))) return false;
	if (!rule.ports.length) return true;
	// Unknown port ("any port" egress flow) is only covered by a rule without a
	// port list — a port-restricted rule would drop the other ports.
	if (port === null || port === undefined) return false;
	return rule.ports.some((p) => {
		if (p.proto !== proto) return false;
		const [a, b] = p.port.split(":").map(Number);
		return port >= a && port <= (b ?? a);
	});
}

/**
 * True when EVERY source of the rule lies inside one of `hubSrcs` (hub tunnel
 * /32s + egress-flow sources). A broad source that merely contains the hub
 * (10.10.0.0/24, 0.0.0.0/0) is NOT hub-sourced. Does not look at `enabled`.
 */
export function isHubSourced(rule, hubSrcs) {
	return (
		Array.isArray(rule?.sources) &&
		rule.sources.length > 0 &&
		rule.sources.every((s) => hubSrcs.some((h) => cidrContains(h, s)))
	);
}

/**
 * True when upstream `u` ({host, port, proto, source?}) is reachable through an
 * enabled rule from its hub source: an egress flow may name its own source
 * (SNAT address), everything else arrives from one of the hub tunnel hosts.
 */
export function upstreamCovered(u, rules, hubHosts) {
	const srcs = u.source ? [u.source] : hubHosts || [];
	return srcs.some((src) =>
		(rules || []).some((r) => ruleCovers(r, { src, dst: u.host, port: u.port ?? null, proto: u.proto || "tcp" })),
	);
}

/** Trimmed entries of all `Address =` lines of a wg conf, in file order. */
export function tunnelAddressEntries(confText) {
	const out = [];
	for (const m of String(confText || "").matchAll(/^\s*Address\s*=\s*(.+)$/gim)) {
		for (const part of m[1].split(",")) {
			const p = part.trim();
			if (p) out.push(p);
		}
	}
	return out;
}

/** Host part of a tunnel Address line ("Address = 10.10.0.1/24" → "10.10.0.1/32"). */
export function hubTunnelHosts(confText) {
	const hosts = [];
	for (const p of tunnelAddressEntries(confText)) {
		const ip = p.split("/")[0];
		if (ipToInt(ip) !== null) hosts.push(`${ip}/32`);
	}
	return hosts;
}

/** "10.0.0.1/32" → "10.0.0.1"; any other CIDR is returned unchanged. */
export const hostIp = (cidr) => String(cidr).replace(/\/32$/, "");
