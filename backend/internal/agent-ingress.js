// Per-agent ingress filtering ("Freigaben") — DB + API layer.
// Pure rule logic lives in agent-ingress-rules.js.

import { Resolver } from "node:dns/promises";
import { readdir, readFile } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import path from "node:path";
import error from "../lib/error.js";
import { wireguard as logger } from "../logger.js";
import Agent from "../models/agent.js";
import AgentIngressRule from "../models/agent_ingress_rule.js";
import ProxyHost from "../models/proxy_host.js";
import Stream from "../models/stream.js";
import {
	buildCatalog,
	bulkDedupe,
	evaluateFlow,
	sanitizeBulkList,
	sanitizeFlowQuery,
	sanitizeRuleIds,
	tunnelSubnets,
} from "./agent-ingress-catalog.js";
import {
	assertRuleLineCount,
	assertTotalLineCount,
	buildIngressRestore,
	canonicalCidr,
	cidrContains,
	hostIp,
	hubTunnelHosts,
	isHubSourced,
	isWgIface,
	MAX_RULES_PER_AGENT,
	nextHitState,
	parseJsonArray,
	pubKey8,
	rowToRule,
	armedOnPatch,
	sanitizeIngressCounters,
	sanitizeIngressMode,
	sanitizeIngressRule,
	splitLinkId,
	upstreamCovered,
} from "./agent-ingress-rules.js";
import internalDirectLink from "./agent-direct-link.js";
import internalAuditLog from "./audit-log.js";
import internalSiteIsolation from "./site-isolation.js";
import internalWireGuard from "./wireguard.js";

const OBJECT_TYPE = "agent-ingress";
const nowSeconds = () => Math.floor(Date.now() / 1000);

// Hand-written nginx server blocks next to the FloppyGuard-managed ones (e.g.
// sso/webmail). They proxy into site LANs too, so the Prüfung must see them.
const MANUAL_CONF_DIR = () => process.env.NGINX_MANUAL_CONF_DIR || "/etc/nginx/conf.d";
const MANUAL_CONF_RE = /^zz-[\w.-]+\.conf$/;
const DNS_TIMEOUT_MS = 1500;
const DNS_CACHE_MS = 60 * 1000;
const DNS_CACHE_MAX = 500;
// Hub-originated egress through the hub's SNAT/tunnel address (e.g. Mailcow on a
// hub-side CT → DC for SOGo-LDAP) uses no proxy host or stream, so it cannot be
// derived from them. Listed here it takes part in the Prüfung like an upstream:
// [{ "name": "Mailcow SOGo -> DC", "destination": "10.3.10.5", "port": 636,
//    "proto": "tcp", "source": "10.10.0.1" }]   (source optional = hub address)
const HUB_EGRESS_FLOWS_PATH = () => process.env.HUB_EGRESS_FLOWS_PATH || "/data/hub-egress-flows.json";
const HOSTS_FILE = () => process.env.HOSTS_FILE || "/etc/hosts";

/**
 * Upstreams of one hand-written nginx conf: every `proxy_pass http(s)://host[:port]`
 * plus NPM-style `set $server "host"` / `set $port N`. Pure (text in, list out).
 */
export function parseManualConfUpstreams(text, file) {
	const out = [];
	const src = String(text || "").replace(/#[^\n]*/g, "");
	const label = /\bserver_name\s+([^;]+);/.exec(src)?.[1]?.trim().split(/\s+/)[0] || file;
	const seen = new Set();
	// nginx connects to the scheme's default port when proxy_pass names none.
	const schemePort = (scheme) => ({ http: 80, https: 443 })[String(scheme || "").toLowerCase()] || null;
	const add = (host, port, scheme) => {
		const h = String(host || "")
			.trim()
			.replace(/^\[|\]$/g, "");
		if (!h || h.startsWith("$") || h.startsWith("unix:")) return;
		const p = Number(port) || schemePort(scheme);
		const key = `${h}:${p}`;
		if (seen.has(key)) return;
		seen.add(key);
		out.push({ kind: "manual", id: file, label, host: h, port: p, proto: "tcp", enabled: true });
	};
	for (const m of src.matchAll(/\bproxy_pass\s+(https?):\/\/([^\s:/;]+|\[[^\]]+\])(?::(\d+))?/g)) {
		add(m[2], m[3], m[1]);
	}
	const server = /\bset\s+\$server\s+"?([^";\s]+)"?\s*;/.exec(src)?.[1];
	if (server) {
		add(
			server,
			/\bset\s+\$port\s+"?(\d+)"?\s*;/.exec(src)?.[1],
			/\bset\s+\$forward_scheme\s+"?(https?)"?\s*;/.exec(src)?.[1],
		);
	}
	return out;
}

/**
 * Upstreams of one proxy host: forward_host/port, each custom location, and any
 * proxy_pass written into the host's or a location's advanced_config (those
 * cross the site agent just the same).
 */
export function proxyHostUpstreams(p) {
	const out = [];
	const names = parseJsonArray(p.domain_names, typeof p.domain_names === "string" ? [p.domain_names] : []);
	const hostLabel = names.join(", ");
	const enabled = Boolean(p.enabled);
	const fromAdvanced = (text, label) => {
		if (!text) return;
		for (const u of parseManualConfUpstreams(text, label)) {
			out.push({ ...u, kind: "proxy-host", id: p.id, label, enabled });
		}
	};
	out.push({
		kind: "proxy-host",
		id: p.id,
		label: hostLabel,
		host: p.forward_host,
		port: Number(p.forward_port) || null,
		proto: "tcp",
		enabled,
	});
	fromAdvanced(p.advanced_config, hostLabel);
	for (const loc of parseJsonArray(p.locations)) {
		const label = `${hostLabel} ${loc?.path || ""}`.trim();
		fromAdvanced(loc?.advanced_config, label);
		if (!loc?.forward_host) continue;
		// forward_host of a location may carry a path ("10.0.0.5/api")
		const host = String(loc.forward_host).split("/")[0].trim();
		if (!host) continue;
		out.push({
			kind: "proxy-host",
			id: p.id,
			label,
			host,
			port: Number(loc.forward_port) || null,
			proto: "tcp",
			enabled,
		});
	}
	return out;
}

/**
 * One-click rule for a missing upstream: limited to the upstream's port (nginx /
 * the stream only ever connects there) — an empty list would open every port of
 * the target to the hub source, which also carries the Hetzner-LAN SNAT
 * (MASQUERADE of 10.10.10.0/24 to the hub's tunnel address). An upstream without
 * a known port (a `proxy_pass $var` without scheme/port, an "any port" egress
 * flow) or without a known hub source address gets NO suggestion (null): the
 * admin has to write the rule by hand with the port(s) actually used.
 */
export function upstreamSuggestion(u, srcs) {
	if (!u.port || !srcs?.length) return null;
	return {
		name: `${u.kind === "hub-egress" ? "Hub" : "Proxy"} ${u.label}`.slice(0, 100),
		sources: srcs.slice(0, 1),
		destinations: [canonicalCidr(u.host)],
		ports: [{ proto: u.proto || "tcp", port: String(u.port) }],
	};
}

/**
 * Hub-sourced rules that are broader than the proxy traffic needs. The hub's
 * tunnel address also carries every Hetzner-LAN host (MASQUERADE of the hub LAN
 * to that address), so a hub-source rule lets Mailcow, the webserver CT, ... in
 * as well. Reported:
 *   all-ports    — no port list: every port of the destinations is open
 *   unused-ports — port entries no upstream behind the agent uses
 * `hubSrcs` = hub tunnel /32s + egress-flow sources; a rule counts as hub-sourced
 * when EVERY source lies inside one of them. `behind` = upstreams in the site. Pure.
 */
export function broadHubRules(rules, hubSrcs, behind) {
	const out = [];
	for (const r of rules) {
		if (!r.enabled || !isHubSourced(r, hubSrcs)) continue;
		const inDest = (u) =>
			canonicalCidr(u.host) && (!r.destinations.length || r.destinations.some((d) => cidrContains(d, u.host)));
		if (!r.ports.length) {
			out.push({ id: r.id, name: r.name, reason: "all-ports", ports: [] });
			continue;
		}
		const unused = r.ports.filter((p) => {
			const [a, b] = String(p.port).split(":").map(Number);
			return !behind.some(
				(u) => inDest(u) && (u.proto || "tcp") === p.proto && u.port && u.port >= a && u.port <= (b ?? a),
			);
		});
		if (unused.length) {
			out.push({
				id: r.id,
				name: r.name,
				reason: "unused-ports",
				ports: unused.map((p) => `${p.port}/${p.proto}`),
			});
		}
	}
	return out;
}

/**
 * The site link an agent is bound to, as [linkId, ownNets] — by the EFFECTIVE
 * status name/networks (generated name, AllowedIPs fallback; the UI binds agents
 * by that name), excluding only explicitly-typed clients (an untyped single-LAN
 * wg0 site is "client" by heuristic only). Falls back to raw metadata when the
 * live status is unavailable. null = no such link.
 */
export function agentSiteLink(linkName, { statusLinks = null, metaLinks = [] } = {}) {
	if (Array.isArray(statusLinks)) {
		const l = resolveBoundStatusLink(linkName, statusLinks);
		return l && !(l.type === "client" && l.typeExplicit !== false)
			? [l.id, (l.importedNetworks || []).map(canonicalCidr).filter(Boolean)]
			: null;
	}
	const entry = metaLinks.find(([, l]) => l.name === linkName && l.type !== "client");
	return entry ? [entry[0], (entry[1].importedNetworks || []).map(canonicalCidr).filter(Boolean)] : null;
}

const isGeneratedLinkName = (l) =>
	Boolean(l?.peerPublicKey) && l.name === `${l.type}-${String(l.peerPublicKey).slice(0, 8)}`;

/**
 * The status link an agent's wg_link_name refers to. A link without a stored
 * name is shown as `${type}-${pubkey8}`, and its type is INFERRED from the
 * AllowedIPs — a site that goes from one to two routed networks changes from
 * "client-…" to "hub-link-…", which used to orphan the binding. A generated
 * name therefore also matches by its public-key prefix, as long as exactly one
 * still-unnamed link carries it (a link that got a real name since then had
 * its bindings moved by the rename cascade). Pure.
 */
export function resolveBoundStatusLink(linkName, statusLinks) {
	const links = Array.isArray(statusLinks) ? statusLinks : [];
	const exact = links.find((x) => x.name === linkName);
	if (exact) return exact;
	const m = /^(.+)-([A-Za-z0-9+/]{8})$/.exec(String(linkName || ""));
	if (!m) return null;
	const byKey = links.filter((x) => isGeneratedLinkName(x) && String(x.peerPublicKey).startsWith(m[2]));
	return byKey.length === 1 ? byKey[0] : null;
}

/**
 * Why an agent's bound link is not usable as a site (for the check): the link
 * exists but is typed "client" (link_hint "typed-client"), or nothing matches
 * ("not-found"). Pure.
 */
export function boundLinkMissingHint(linkName, statusLinks) {
	if (!Array.isArray(statusLinks)) return { reason: "not-found" };
	const l = resolveBoundStatusLink(linkName, statusLinks);
	if (l && l.type === "client" && l.typeExplicit !== false) {
		return { reason: "typed-client", link_id: l.id, link_name: l.name };
	}
	return { reason: "not-found" };
}

async function manualConfUpstreams() {
	const dir = MANUAL_CONF_DIR();
	let files = [];
	try {
		files = (await readdir(dir)).filter((f) => MANUAL_CONF_RE.test(f)).sort();
	} catch {
		return [];
	}
	const out = [];
	for (const f of files) {
		try {
			out.push(...parseManualConfUpstreams(await readFile(path.join(dir, f), "utf8"), f));
		} catch {
			// unreadable conf: skip, the check is advisory
		}
	}
	return out;
}

/**
 * Hub egress flows from HUB_EGRESS_FLOWS_PATH (see above) as upstream entries.
 * Pure: JSON text in, list out; invalid entries are skipped.
 */
export function parseHubEgressFlows(text) {
	let list;
	try {
		list = JSON.parse(String(text || "[]"));
	} catch {
		return [];
	}
	if (!Array.isArray(list)) return [];
	const out = [];
	list.slice(0, 200).forEach((f, i) => {
		const host = canonicalCidr(f?.destination);
		if (!host) return;
		const proto = String(f?.proto || "tcp").toLowerCase();
		if (proto !== "tcp" && proto !== "udp") return;
		const port = Number(f?.port);
		const source = f?.source ? canonicalCidr(f.source) : null;
		if (f?.source && !source) return;
		out.push({
			kind: "hub-egress",
			id: `egress-${i + 1}`,
			label: String(f?.name || `Hub-Egress ${i + 1}`).slice(0, 100),
			// single host stays a plain IP like the other upstreams
			host: hostIp(host),
			port: Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null,
			proto,
			enabled: f?.enabled !== false,
			...(source ? { source } : {}),
		});
	});
	return out;
}

/**
 * Networks directly connected to the hub on non-WireGuard interfaces, from an
 * os.networkInterfaces()-shaped object. The hub reaches these on the LAN itself,
 * never through a site agent — even when a site link also imports them (e.g.
 * PVE-Hetzner importing the hub's own 10.10.10.0/24). Pure.
 */
export function hubConnectedNets(ifaces) {
	const out = [];
	for (const [name, addrs] of Object.entries(ifaces || {})) {
		if (/^wg\d/.test(name) || name === "lo") continue;
		for (const a of addrs || []) {
			if (a?.family !== "IPv4" && a?.family !== 4) continue;
			if (a.internal) continue;
			const net = canonicalCidr(a.cidr || "");
			if (net && !out.includes(net)) out.push(net);
		}
	}
	return out;
}

/** /32 AllowedIPs of one [Peer] (by PublicKey) in a wg conf text. Pure. */
export function peerTunnelHosts(confText, publicKey) {
	const hosts = [];
	let inPeer = false;
	let key = null;
	let allowed = [];
	const flush = () => {
		if (inPeer && key === publicKey) hosts.push(...allowed);
	};
	for (const raw of String(confText || "").split(/\r?\n/)) {
		const t = raw.trim();
		if (t.startsWith("[")) {
			flush();
			inPeer = t === "[Peer]";
			key = null;
			allowed = [];
			continue;
		}
		const m = /^(\w+)\s*=\s*(.*)$/.exec(t);
		if (!m || !inPeer) continue;
		if (m[1] === "PublicKey") key = m[2].trim();
		if (m[1] === "AllowedIPs") {
			for (const part of m[2].split(",")) {
				const c = canonicalCidr(part.trim());
				if (c?.endsWith("/32")) allowed.push(c);
			}
		}
	}
	flush();
	return [...new Set(hosts)];
}

/**
 * VPN clients from the live WireGuard status, with the EFFECTIVE link type (an
 * untyped /32 peer is inferred as client there, as in assertPeerConfigAllowed)
 * and the networks the client can actually reach:
 *   - fullTunnel → everything (0.0.0.0/0),
 *   - importedNetworks set → exactly those,
 *   - otherwise (typical road warrior, createPeer/generatePeerConfig give it every
 *     network the hub serves on that interface) → the interface's tunnel subnets
 *     plus every exported/imported network of the other links on that interface.
 * Tunnel hosts are the peer's live /32 AllowedIPs. Pure.
 */
export function vpnClientsFromStatus(status) {
	const links = status?.links || [];
	const ifaceAddrs = new Map((status?.interfaces || []).map((i) => [i.name, i.addresses || []]));
	const clients = [];
	for (const l of links) {
		if (l?.type !== "client" || !l.id) continue;
		const hosts = [
			...new Set(
				[...(l.allowedIps || []), ...(l.tunnelAddresses || [])]
					.map((c) => canonicalCidr(String(c).includes("/") ? c : `${c}/32`))
					.filter((c) => c?.endsWith("/32")),
			),
		];
		if (!hosts.length) continue;
		let nets;
		if (l.fullTunnel) {
			nets = ["0.0.0.0/0"];
		} else if ((l.importedNetworks || []).length) {
			nets = l.importedNetworks;
		} else {
			nets = [
				...(ifaceAddrs.get(l.interfaceName) || []),
				...links
					.filter((o) => o.id !== l.id && o.interfaceName === l.interfaceName)
					.flatMap((o) => [
						...(o.exportedNetworks || []),
						...(o.type === "client" ? [] : o.importedNetworks || []),
					]),
			];
		}
		nets = [...new Set(nets.map(canonicalCidr).filter(Boolean))].filter((n) => !n.endsWith("/32"));
		if (!nets.length) continue;
		const parts = splitLinkId(l.id);
		clients.push({ id: l.id, label: l.name || pubKey8(parts ? parts[1] : String(l.id)), hosts, nets });
	}
	return clients;
}

/**
 * Road-warrior clients reach a site LAN hub-wg0 → wg0 WITHOUT SNAT, so they arrive
 * with their own tunnel address — no hub-sourced rule covers them. For each client
 * tunnel host and each client network that overlaps the agent's own nets, report a
 * gap when no enabled rule has that client as source and overlaps that network as
 * destination (a port- or host-restricted rule counts as deliberate). Pure.
 * clients: [{ id, label, hosts: ["10.10.0.4/32"], nets: ["192.168.60.0/24"] }]
 */
export function clientIngressGaps(clients, ownNets, rules) {
	const gaps = [];
	for (const c of clients || []) {
		for (const net of c.nets || []) {
			for (const own of ownNets) {
				let dst = null;
				if (cidrContains(own, net)) dst = canonicalCidr(net);
				else if (cidrContains(net, own)) dst = canonicalCidr(own);
				if (!dst) continue;
				for (const host of c.hosts || []) {
					const covered = rules.some(
						(r) =>
							r.enabled &&
							r.sources.some((s) => cidrContains(s, host)) &&
							(!r.destinations.length ||
								r.destinations.some((d) => cidrContains(d, dst) || cidrContains(dst, d))),
					);
					if (covered) continue;
					const ip = hostIp(host);
					gaps.push({
						kind: "vpn-client",
						id: `${c.id}|${dst}`,
						label: `${c.label} (${ip})`,
						host: dst,
						port: null,
						proto: "tcp",
						enabled: true,
						suggestion: {
							name: `VPN-Client ${c.label}`.slice(0, 100),
							sources: [`${ip}/32`],
							destinations: [dst],
							ports: [],
						},
					});
				}
			}
		}
	}
	return gaps;
}

async function hubEgressFlows() {
	try {
		return parseHubEgressFlows(await readFile(HUB_EGRESS_FLOWS_PATH(), "utf8"));
	} catch {
		return []; // no file = no hub egress flows configured
	}
}

/** IPv4 entries of an /etc/hosts text → Map<lowercased name, ip>. Pure. */
export function parseHostsFile(text) {
	const map = new Map();
	for (const raw of String(text || "").split(/\r?\n/)) {
		const parts = raw.replace(/#.*/, "").trim().split(/\s+/);
		if (parts.length < 2 || parts[0].includes("/") || !canonicalCidr(parts[0])) continue;
		for (const name of parts.slice(1)) {
			const key = name.toLowerCase();
			if (!map.has(key)) map.set(key, parts[0]);
		}
	}
	return map;
}

// Module-level caches: the Prüfung runs on every page/modal open.
const dnsCache = new Map(); // host → { ip, at }
let hostsCache = { at: 0, map: new Map() };
// c-ares based (network only): unlike dns.lookup it does not occupy a libuv
// threadpool slot, and the timeout really ends the query.
const resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });

async function hostsMap() {
	if (Date.now() - hostsCache.at < DNS_CACHE_MS) return hostsCache.map;
	let map = new Map();
	try {
		map = parseHostsFile(await readFile(HOSTS_FILE(), "utf8"));
	} catch {
		// no hosts file: DNS only
	}
	hostsCache = { at: Date.now(), map };
	return map;
}

/** Resolve a DNS-name upstream to IPv4 (/etc/hosts, then DNS with timeout); null when it does not resolve. */
async function resolveUpstreamHost(host) {
	const key = String(host).toLowerCase();
	const hit = dnsCache.get(key);
	if (hit && Date.now() - hit.at < DNS_CACHE_MS) return hit.ip;
	let ip = (await hostsMap()).get(key) || null;
	if (!ip) {
		try {
			ip = (await resolver.resolve4(key)).find((a) => canonicalCidr(a)) || null;
		} catch {
			ip = null;
		}
	}
	if (dnsCache.size >= DNS_CACHE_MAX) dnsCache.clear();
	dnsCache.set(key, { ip, at: Date.now() });
	return ip;
}

/**
 * What the agent last reported as applied vs. what the hub wants it to run.
 * state: applied | pending (not confirmed yet) | failed (agent reported an
 * error) | unknown (agent never reported — script older than this feature).
 */
// An agent polls every 30 s. Without a heartbeat for this long, a ruleset it has
// not confirmed yet is reported as "offline" instead of "pending" — it will not
// be applied until the agent is back, and the UI must not poll for it forever.
export const AGENT_OFFLINE_AFTER_S = 5 * 60;

export function ingressAppliedState({
	desiredHash,
	appliedHash,
	error: err,
	buildError,
	lastSeen = undefined,
	now = nowSeconds(),
}) {
	const applied = appliedHash || null;
	const desired = desiredHash ?? null;
	// The hub cannot build the ruleset at all: the agent keeps its old one.
	if (buildError) {
		return {
			state: "failed",
			applied_hash: applied,
			desired_hash: null,
			error: `Regelsatz kann nicht erzeugt werden: ${buildError}`,
		};
	}
	let state;
	if (applied === null) state = desired === "NONE" ? "applied" : "unknown";
	// An agent error wins over matching hashes: a failed self-heal re-apply keeps
	// the old applied hash while FG_IN is gone or incomplete.
	else if (err) state = "failed";
	else if (desired !== null && applied === desired) state = "applied";
	else state = "pending";
	// lastSeen undefined = caller did not pass it (keep "pending"); null/0 = never seen.
	if (
		state === "pending" &&
		lastSeen !== undefined &&
		(!lastSeen || now - Number(lastSeen) > AGENT_OFFLINE_AFTER_S)
	) {
		state = "offline";
	}
	return { state, applied_hash: applied, desired_hash: desired, error: err || null };
}

/** Interfaces FG_IN filters: the hub interface + every enabled direct link. */
const ifaceCountOf = async (agentId) => 1 + (await internalDirectLink.ifacesFor(agentId)).length;

const ifaceOf = (agent) => (isWgIface(agent?.wg_interface) ? agent.wg_interface : "wg0");

async function loadAgent(agentId) {
	const agent = await Agent.query().where("id", agentId).where("is_deleted", 0).first();
	if (!agent) throw new error.ItemNotFoundError(agentId);
	return agent;
}

/** The agent row locked for the rest of the transaction (current mode included). */
async function lockAgent(agentId, trx) {
	const locked = await Agent.query(trx).where("id", agentId).where("is_deleted", 0).forUpdate().first();
	if (!locked) throw new error.ItemNotFoundError(agentId);
	return locked;
}

async function loadRules(agentId, trx = undefined) {
	const rows = await AgentIngressRule.query(trx).where("agent_id", agentId).orderBy("id", "asc");
	return rows.map(rowToRule);
}

function toDbPatch(clean) {
	const patch = { ...clean };
	for (const f of ["sources", "destinations", "ports"]) {
		if (typeof patch[f] !== "undefined") patch[f] = JSON.stringify(patch[f]);
	}
	return patch;
}

async function audit(access, action, agent, meta) {
	if (!access) return; // internal callers (import script) log via logger only
	try {
		await internalAuditLog.add(access, {
			action,
			object_type: OBJECT_TYPE,
			object_id: agent.id,
			meta: { agent: agent.name, ...meta },
		});
	} catch (err) {
		logger.warn(`ingress audit log failed: ${err.message}`);
	}
}

// A restricted agent with zero active rules would drop everything arriving via
// its tunnel (except established return traffic). Refuse that state instead of
// silently cutting a site off.
function assertNotEmptyRestricted(mode, rules) {
	if (mode === "restricted" && !rules.some((r) => r.enabled)) {
		throw new error.ValidationError(
			"Mindestens eine aktive Freigabe ist nötig, solange der Agent auf „nur Freigaben“ steht",
		);
	}
}

/**
 * Rule totals for the proxy check, so list views show "n active rules" without
 * loading every agent's full ingress state (N+1).
 */
export function ingressRuleCounts(rules) {
	return { rule_count: rules.length, active_rule_count: rules.filter((r) => r.enabled).length };
}

/** True when a partial rule update can enlarge the generated ruleset. */
export function updateCanGrow(clean) {
	return ["sources", "destinations", "ports"].some((f) => typeof clean[f] !== "undefined") || clean.enabled === true;
}

// Proxy check and catalog read the same upstreams / WireGuard state. The
// /ingress page asks for the check plus one catalog per agent card at once, so
// CONCURRENT requests share one in-flight collection. Nothing is kept once it
// settles: a request after a link rename/delete or a proxy host change must
// see the new state (the UI refetches right after such a mutation).
const memo = (fn) => {
	let inFlight = null;
	return () => {
		if (inFlight) return inFlight;
		const promise = fn();
		inFlight = promise;
		const clear = () => {
			if (inFlight === promise) inFlight = null;
		};
		promise.then(clear, clear);
		return promise;
	};
};

/**
 * Every upstream the hub connects to: proxy hosts (incl. custom locations and
 * advanced_config), streams, the hand-written zz-*.conf server blocks and the
 * configured hub egress flows; DNS-name upstreams resolved to IPv4.
 * → { upstreams, unchecked (names that do not resolve), egressFlows }
 * Callers must not mutate the returned objects (shared by concurrent callers).
 */
const collectUpstreams = memo(async () => {
	const proxies = await ProxyHost.query()
		.where("is_deleted", 0)
		.select("id", "domain_names", "forward_host", "forward_port", "enabled", "locations", "advanced_config");
	const streams = await Stream.query()
		.where("is_deleted", 0)
		.select(
			"id",
			"incoming_port",
			"forwarding_host",
			"forwarding_port",
			"tcp_forwarding",
			"udp_forwarding",
			"enabled",
		);

	const upstreams = [];
	for (const p of proxies) upstreams.push(...proxyHostUpstreams(p));
	for (const s of streams) {
		for (const proto of ["tcp", "udp"]) {
			if (!s[`${proto}_forwarding`]) continue;
			upstreams.push({
				kind: "stream",
				id: s.id,
				label: `Port ${s.incoming_port}/${proto}`,
				host: s.forwarding_host,
				port: Number(s.forwarding_port) || null,
				proto,
				enabled: Boolean(s.enabled),
			});
		}
	}

	upstreams.push(...(await manualConfUpstreams()));
	const egressFlows = await hubEgressFlows();
	upstreams.push(...egressFlows);

	// DNS-name upstreams: resolve (short timeout, in parallel, cached) so they can
	// be attributed to a site; names that do not resolve are reported as not
	// checkable instead of silently disappearing from the check.
	const names = [...new Set(upstreams.filter((u) => u.host && !canonicalCidr(u.host)).map((u) => u.host))];
	const resolved = new Map(await Promise.all(names.map(async (h) => [h, await resolveUpstreamHost(h)])));
	const unchecked = [];
	for (const u of upstreams) {
		if (!u.host || canonicalCidr(u.host)) continue;
		const ip = resolved.get(u.host);
		if (ip) {
			u.hostname = u.host;
			u.host = ip;
		} else if (u.enabled) {
			unchecked.push({ kind: u.kind, id: u.id, label: u.label, host: u.host, port: u.port, proto: u.proto });
		}
	}
	return { upstreams, unchecked, egressFlows };
});

/**
 * WireGuard view shared by check and catalog:
 *   metadataLinks — [id, meta] entries of the metadata store
 *   wgStatus      — live status (null when unavailable)
 *   statusLinks   — live links, or null without a live status
 *   hubNets       — networks the hub is directly connected to
 *   clients       — VPN clients with tunnel hosts and reachable nets
 *   confTextFor / hubHostsFor — wg conf text / hub tunnel /32s per interface
 */
const wgContext = memo(async () => {
	const metadata = await internalWireGuard.readMetadataStore();
	const metadataLinks = Object.entries(metadata.links || {});

	const confCache = new Map();
	const confTextFor = async (ifaceName) => {
		if (!isWgIface(ifaceName)) return "";
		if (!confCache.has(ifaceName)) {
			const dir = process.env.WG_CONF_DIR || "/etc/wireguard";
			let text = "";
			try {
				text = await readFile(path.join(dir, `${ifaceName}.conf`), "utf8");
			} catch {
				text = "";
			}
			confCache.set(ifaceName, text);
		}
		return confCache.get(ifaceName);
	};
	const hubHostsFor = async (ifaceName) => hubTunnelHosts(await confTextFor(ifaceName));

	// Upstreams on a network the hub is directly connected to never pass a site
	// agent, even when that site's link imports the network too.
	const hubNets = hubConnectedNets(networkInterfaces());

	// VPN clients with their tunnel addresses and reachable networks — from the
	// live status (effective type, road warriors without importedNetworks and
	// full-tunnel clients included). Without the live status, fall back to the
	// typed metadata entries that name their networks explicitly.
	let clients = [];
	let wgStatus = null;
	try {
		wgStatus = await internalWireGuard.getStatus();
	} catch (err) {
		logger.warn(`Ingress check: WireGuard status unavailable (${err.message}) — VPN clients from metadata only`);
	}
	if (wgStatus?.available) {
		clients = vpnClientsFromStatus(wgStatus);
	} else {
		for (const [id, l] of metadataLinks) {
			if (l.type !== "client") continue;
			const parts = splitLinkId(id);
			if (!parts) continue;
			const [iface, pub] = parts;
			const hosts = peerTunnelHosts(await confTextFor(iface), pub);
			const nets = l.fullTunnel ? ["0.0.0.0/0"] : (l.importedNetworks || []).map(canonicalCidr).filter(Boolean);
			if (hosts.length && nets.length) clients.push({ id, label: l.name || pubKey8(pub), hosts, nets });
		}
	}
	return {
		metadataLinks,
		wgStatus,
		statusLinks: wgStatus?.available ? wgStatus.links || [] : null,
		hubNets,
		clients,
		confTextFor,
		hubHostsFor,
	};
});

/** Upstreams inside the agent's own site nets that do not sit on a hub-connected net. */
const upstreamsBehind = (upstreams, ownNets, hubNets) =>
	upstreams.filter(
		(u) =>
			canonicalCidr(u.host) &&
			ownNets.some((n) => cidrContains(n, u.host)) &&
			!hubNets.some((n) => cidrContains(n, u.host)),
	);

/**
 * Links in one shape for the catalog — live status, or the metadata store with
 * the tunnel /32s from the wg conf when the status is unavailable.
 */
async function catalogLinks(ctx) {
	if (ctx.statusLinks) {
		return ctx.statusLinks.map((l) => ({
			id: l.id,
			name: l.name,
			type: l.type,
			importedNetworks: l.importedNetworks || [],
			tunnelAddresses: l.tunnelAddresses || [],
			active: Boolean(l.active),
		}));
	}
	const out = [];
	for (const [id, l] of ctx.metadataLinks) {
		const parts = splitLinkId(id);
		const tunnel = parts ? peerTunnelHosts(await ctx.confTextFor(parts[0]), parts[1]) : [];
		out.push({
			id,
			name: l.name || id,
			type: l.type,
			importedNetworks: l.importedNetworks || [],
			tunnelAddresses: tunnel,
			active: false,
		});
	}
	return out;
}

/** The link an agent is bound to (by name, like agentSiteLink), any type. */
function boundLinkId(linkName, ctx) {
	if (!linkName) return null;
	if (ctx.statusLinks) return resolveBoundStatusLink(linkName, ctx.statusLinks)?.id ?? null;
	return ctx.metadataLinks.find(([, l]) => l.name === linkName)?.[0] ?? null;
}

const internalAgentIngress = {
	async list(agentId) {
		const agent = await loadAgent(agentId);
		const rules = await loadRules(agent.id);
		return {
			agent_id: agent.id,
			ingress_mode: agent.ingress_mode || "open",
			rules,
			applied: await this.appliedFor(agent, rules),
		};
	},

	/**
	 * Applied-vs-desired filter state of one agent (see ingressAppliedState).
	 * `rules` = the agent's already loaded rules (null = load them).
	 */
	async appliedFor(agent, rules = null) {
		let desiredHash = null;
		let buildError = null;
		try {
			desiredHash = (await this.payloadFor(agent, rules))?.hash ?? "NONE";
		} catch (err) {
			buildError = err.message || String(err);
		}
		return ingressAppliedState({
			desiredHash,
			appliedHash: agent.ingress_applied_hash,
			error: agent.ingress_error,
			buildError,
			lastSeen: agent.last_seen ?? null,
		});
	},

	// create / update / delete / setMode / createBulk / disableBulk all check the
	// ruleset against the agent's mode and size caps and then write. Each runs in
	// a transaction with the agent row locked (SELECT … FOR UPDATE) and re-reads
	// mode + rules under that lock, so two concurrent changes (e.g. a bulk-disable
	// and a single disable, a switch to restricted, or two creates near the line
	// cap) cannot both pass a check — no restricted agent without an active rule,
	// no ruleset beyond MAX_RULES_PER_AGENT / MAX_LINES_TOTAL.

	async create(access, agentId, data) {
		const agent = await loadAgent(agentId);
		const clean = sanitizeIngressRule(data);
		const rule = await AgentIngressRule.transaction(async (trx) => {
			await lockAgent(agent.id, trx);
			const existing = await loadRules(agent.id, trx);
			if (existing.length >= MAX_RULES_PER_AGENT)
				throw new error.ValidationError(`Maximal ${MAX_RULES_PER_AGENT} Freigaben pro Agent`);
			assertTotalLineCount([...existing, clean], await ifaceCountOf(agent.id));
			const row = await AgentIngressRule.query(trx).insertAndFetch({
				...toDbPatch(clean),
				agent_id: agent.id,
				armed_on: nowSeconds(),
			});
			return rowToRule(row);
		});
		await audit(access, "created", agent, { name: rule.name, rule: rule.id });
		return rule;
	},

	async update(access, agentId, ruleId, data) {
		const agent = await loadAgent(agentId);
		const clean = sanitizeIngressRule(data, { partial: true });
		const rule = await AgentIngressRule.transaction(async (trx) => {
			const locked = await lockAgent(agent.id, trx);
			const all = await loadRules(agent.id, trx);
			const existing = all.find((r) => r.id === ruleId);
			if (!existing) throw new error.ItemNotFoundError(ruleId);
			const merged = { ...existing, ...clean };
			const rules = all.map((r) => (r.id === ruleId ? merged : r));
			// Size caps only when the patch can grow the ruleset (targets changed or the
			// rule switched on). Disabling or renaming an oversized rule saved before the
			// caps existed must stay possible — that is how an admin gets out of it.
			if (updateCanGrow(clean)) {
				assertRuleLineCount(merged);
				assertTotalLineCount(rules, await ifaceCountOf(agent.id));
			}
			assertNotEmptyRestricted(locked.ingress_mode, rules);
			const row = await AgentIngressRule.query(trx).patchAndFetchById(ruleId, {
				...toDbPatch(clean),
				...armedOnPatch(existing, clean, nowSeconds()),
			});
			return rowToRule(row);
		});
		await audit(access, "updated", agent, { name: rule.name, rule: rule.id });
		return rule;
	},

	async delete(access, agentId, ruleId) {
		const agent = await loadAgent(agentId);
		const existing = await AgentIngressRule.transaction(async (trx) => {
			const locked = await lockAgent(agent.id, trx);
			const all = await loadRules(agent.id, trx);
			const row = all.find((r) => r.id === ruleId);
			if (!row) throw new error.ItemNotFoundError(ruleId);
			assertNotEmptyRestricted(
				locked.ingress_mode,
				all.filter((r) => r.id !== ruleId),
			);
			await AgentIngressRule.query(trx).deleteById(ruleId);
			return row;
		});
		await audit(access, "deleted", agent, { name: existing.name, rule: existing.id });
		return { deleted: true };
	},

	async setMode(access, agentId, mode) {
		const agent = await loadAgent(agentId);
		const m = sanitizeIngressMode(mode);
		await AgentIngressRule.transaction(async (trx) => {
			await lockAgent(agent.id, trx);
			const rules = await loadRules(agent.id, trx);
			assertNotEmptyRestricted(m, rules);
			// Never switch into a mode whose ruleset cannot be built (the agent would
			// silently keep its old filter).
			assertTotalLineCount(rules, await ifaceCountOf(agent.id));
			await Agent.query(trx).patch({ ingress_mode: m }).where("id", agent.id);
		});
		await audit(access, "updated", agent, { name: `Modus: ${m}`, ingress_mode: m });
		return this.list(agent.id);
	},

	/**
	 * What the agent receives in /api/agent/config — null = no filter at all.
	 * `rules` = the agent's already loaded rules (null = load them).
	 */
	async payloadFor(agent, rules = null) {
		const built = buildIngressRestore(
			{
				ingress_mode: agent.ingress_mode || "open",
				iface: ifaceOf(agent),
				directIfaces: await internalDirectLink.ifacesFor(agent.id),
			},
			rules ?? (await loadRules(agent.id)),
		);
		return built ? { hash: built.hash, rules: built.text } : null;
	},

	async preview(agentId) {
		const agent = await loadAgent(agentId);
		const built = buildIngressRestore(
			{
				ingress_mode: agent.ingress_mode || "open",
				iface: ifaceOf(agent),
				directIfaces: await internalDirectLink.ifacesFor(agent.id),
			},
			await loadRules(agent.id),
		);
		return {
			agent_id: agent.id,
			ingress_mode: agent.ingress_mode || "open",
			iface: ifaceOf(agent),
			rules_text: built ? built.text : null,
			rule_count: built ? built.ruleCount : 0,
			hash: built ? built.hash : null,
		};
	},

	/** Heartbeat hook: store hit counters the agent reports per rule. */
	async recordCounters(agent, raw) {
		const counters = sanitizeIngressCounters(raw);
		if (!counters.size) return;
		const rows = await AgentIngressRule.query()
			.where("agent_id", agent.id)
			.whereIn("id", [...counters.keys()]);
		const now = nowSeconds();
		const knex = AgentIngressRule.knex();
		for (const row of rows) {
			const next = nextHitState(row, counters.get(row.id), now);
			if (Number(row.hit_packets || 0) === next.hit_packets && (row.last_hit_at || null) === next.last_hit_at)
				continue;
			// Plain knex update: counter bookkeeping must not bump modified_on.
			await knex("agent_ingress_rule").where("id", row.id).update(next);
		}
	},

	/**
	 * Known sources/destinations of one agent for pickers and wizards (see
	 * buildCatalog): other sites, VPN clients, the hub, upstreams and services
	 * inside the agent's site, port presets and rules that look unused.
	 */
	async catalog(agentId) {
		const agent = await loadAgent(agentId);
		const [ctx, { upstreams, egressFlows }] = await Promise.all([wgContext(), collectUpstreams()]);
		const site = agentSiteLink(agent.wg_link_name, { statusLinks: ctx.statusLinks, metaLinks: ctx.metadataLinks });
		const iface = site ? (splitLinkId(site[0])?.[0] ?? ifaceOf(agent)) : ifaceOf(agent);
		const ownNets = site ? site[1] : [];
		const rules = await loadRules(agent.id);
		const others = await Agent.query()
			.where("is_deleted", 0)
			.whereNotNull("wg_link_name")
			.select("id", "wg_link_name", "preserve_lan_source_ip");
		const linkAgents = others
			.map((a) => ({
				link_id: boundLinkId(a.wg_link_name, ctx),
				preserve_lan_source_ip: a.preserve_lan_source_ip,
			}))
			.filter((a) => a.link_id);
		const applied = await this.appliedFor(agent, rules);
		return buildCatalog({
			agent,
			site: site ? { linkId: site[0], ownNets } : null,
			links: await catalogLinks(ctx),
			linkAgents,
			hubNets: ctx.hubNets,
			hubHosts: await ctx.hubHostsFor(iface),
			tunnelNets: tunnelSubnets(await ctx.confTextFor(iface)),
			iface,
			egressFlows,
			clients: ctx.clients,
			behind: site ? upstreamsBehind(upstreams, ownNets, ctx.hubNets) : [],
			rules,
			applied,
			now: nowSeconds(),
		});
	},

	/** Read-only: what this agent's filter does with one flow (see evaluateFlow). */
	async testFlow(agentId, body) {
		const agent = await loadAgent(agentId);
		const q = sanitizeFlowQuery(body);
		const ctx = await wgContext();
		const site = agentSiteLink(agent.wg_link_name, { statusLinks: ctx.statusLinks, metaLinks: ctx.metadataLinks });
		const rules = await loadRules(agent.id);
		const applied = await this.appliedFor(agent, rules);
		// Hub-side site isolation is checked first: it drops the flow at the hub,
		// before any agent filter sees it. A failing lookup must not break the
		// tester — it then reports the Freigaben view only, with a note.
		let isolation = null;
		try {
			isolation = await internalSiteIsolation.verdict(q.src, q.dst);
		} catch (err) {
			logger.warn(`Ingress test: site isolation lookup failed: ${err.message}`);
		}
		if (!site && isolation?.blocked) {
			return {
				...evaluateFlow({ mode: agent.ingress_mode || "open", ...q, applied, isolation }),
				link_found: false,
			};
		}
		if (!site) {
			// Without its site the agent's networks are unknown: every query would
			// read "not via this agent", hiding the real cause (missing/renamed link).
			return {
				mode: agent.ingress_mode || "open",
				allowed: null,
				filtered: false,
				reason: "link-not-found",
				rule: null,
				matched_rules: [],
				disabled_match: null,
				port_unknown: false,
				notes: [
					...(applied.state !== "applied" ? ["not-applied"] : []),
					...(!isolation ? ["site-isolation-unknown"] : isolation.partial ? ["site-isolation-partial"] : []),
				],
				link_found: false,
			};
		}
		const result = evaluateFlow({
			mode: agent.ingress_mode || "open",
			rules,
			ownNets: site[1],
			hubNets: ctx.hubNets,
			...q,
			applied,
			isolation,
		});
		if (!isolation) result.notes = [...result.notes, "site-isolation-unknown"];
		return { ...result, link_found: true };
	},

	/**
	 * Create several rules at once (wizards, "create missing rules"). All entries
	 * are validated before the DB is touched. An entry whose targets equal an
	 * enabled rule or an earlier entry is skipped; one that equals a DISABLED rule
	 * switches that rule back on (re-armed) instead — skipping it would report
	 * success while a restricted agent keeps dropping the traffic. One
	 * transaction with the agent row locked, one audit entry per kind of change.
	 * → { created: [rule], reenabled: [rule], skipped: [{ index, reason, rule_id }] }
	 */
	async createBulk(access, agentId, list) {
		const agent = await loadAgent(agentId);
		const clean = sanitizeBulkList(list);
		const armedOn = nowSeconds();
		const { created, reenabled, skipped } = await AgentIngressRule.transaction(async (trx) => {
			await lockAgent(agent.id, trx);
			const existing = await loadRules(agent.id, trx);
			const { create, reenable, skipped } = bulkDedupe(existing, clean);
			const fresh = create.map((c) => c.rule);
			const reIds = reenable.map((r) => r.rule_id);
			if (existing.length + fresh.length > MAX_RULES_PER_AGENT)
				throw new error.ValidationError(`Maximal ${MAX_RULES_PER_AGENT} Freigaben pro Agent`);
			const after = existing.map((r) => (reIds.includes(r.id) ? { ...r, enabled: true } : r));
			assertTotalLineCount([...after, ...fresh], await ifaceCountOf(agent.id));
			const out = [];
			for (const rule of fresh) {
				const row = await AgentIngressRule.query(trx).insertAndFetch({
					...toDbPatch(rule),
					agent_id: agent.id,
					armed_on: armedOn,
				});
				out.push(rowToRule(row));
			}
			const back = [];
			if (reIds.length) {
				await AgentIngressRule.query(trx)
					.patch({ enabled: true, armed_on: armedOn })
					.where("agent_id", agent.id)
					.whereIn("id", reIds);
				back.push(...(await loadRules(agent.id, trx)).filter((r) => reIds.includes(r.id)));
			}
			return { created: out, reenabled: back, skipped };
		});
		if (created.length) {
			await audit(access, "created", agent, {
				name: `Sammelanlage ${created.length} Freigaben`,
				rules: created.map((r) => r.id),
				count: created.length,
			});
		}
		if (reenabled.length) {
			await audit(access, "updated", agent, {
				name: `${reenabled.length} Freigaben wieder eingeschaltet`,
				rules: reenabled.map((r) => r.id),
				count: reenabled.length,
			});
		}
		return { created, reenabled, skipped };
	},

	/**
	 * Switch several rules off at once ("Ungenutzte Freigaben abschalten"). Every
	 * id must belong to the agent; a restricted agent keeps at least one active
	 * rule. With `prune` (the one-click action) every id must still be a prune
	 * candidate of the catalog right now — the list the admin confirmed may be
	 * stale, and the server-side rules for candidates (applied ruleset, hub
	 * sources only, 30 days armed) must hold. Disabling does not arm a rule, so
	 * armed_on stays.
	 */
	async disableBulk(access, agentId, ids, { prune = false } = {}) {
		const agent = await loadAgent(agentId);
		const ruleIds = sanitizeRuleIds(ids);
		if (prune) {
			const allowed = new Set(((await this.catalog(agent.id)).prune_candidates || []).map((c) => c.id));
			const refused = ruleIds.find((id) => !allowed.has(id));
			if (refused !== undefined) {
				throw new error.ValidationError(
					`Freigabe ${refused} ist kein Kandidat (mehr) für „ungenutzt abschalten“ – Liste neu laden`,
				);
			}
		}
		await AgentIngressRule.transaction(async (trx) => {
			const locked = await lockAgent(agent.id, trx);
			const rules = await loadRules(agent.id, trx);
			const missing = ruleIds.find((id) => !rules.some((r) => r.id === id));
			if (missing) throw new error.ItemNotFoundError(missing);
			const after = rules.map((r) => (ruleIds.includes(r.id) ? { ...r, enabled: false } : r));
			assertNotEmptyRestricted(locked.ingress_mode, after);
			await AgentIngressRule.query(trx)
				.patch({ enabled: false })
				.where("agent_id", agent.id)
				.whereIn("id", ruleIds);
		});
		await audit(access, "updated", agent, { name: `${ruleIds.length} Freigaben abgeschaltet`, rules: ruleIds });
		return { disabled: ruleIds };
	},

	/**
	 * Cross-check proxy hosts / streams against the ingress rules of the agent
	 * whose site hosts their upstream. Returns per-agent:
	 *   missing — enabled upstreams that a restricted agent would DROP (→ 504 at the hub)
	 *   missing_disabled — the same for switched-off proxy hosts/streams (info only)
	 *   unchecked — upstreams given by a DNS name that does not resolve (not checkable)
	 *   unusedHubRules — rules from a hub address whose targets no upstream uses
	 *   broadHubRules — hub-sourced rules without a port list / with ports no
	 *     upstream uses (the hub source also carries the Hetzner-LAN SNAT)
	 *   applied — whether the agent confirmed the current ruleset
	 *   rule_count / active_rule_count — the agent's rules (all / enabled)
	 * Upstreams come from proxy hosts (incl. custom locations), streams, the
	 * hand-written zz-*.conf server blocks and the configured hub egress flows
	 * (HUB_EGRESS_FLOWS_PATH — hub-originated traffic through the SNAT address).
	 */
	async proxyCheck() {
		const agents = await Agent.query().where("is_deleted", 0).whereNotNull("wg_link_name");
		const [
			{ upstreams, unchecked, egressFlows },
			{ metadataLinks: links, statusLinks, hubNets, clients, hubHostsFor },
		] = await Promise.all([collectUpstreams(), wgContext()]);
		// One query for every agent's rules instead of two per agent (N+1).
		const rulesByAgent = new Map(agents.map((a) => [a.id, []]));
		if (agents.length) {
			const rows = await AgentIngressRule.query()
				.whereIn(
					"agent_id",
					agents.map((a) => a.id),
				)
				.orderBy("id", "asc");
			for (const row of rows) rulesByAgent.get(row.agent_id)?.push(rowToRule(row));
		}

		const egressSources = egressFlows.map((f) => f.source).filter(Boolean);
		const result = [];
		for (const agent of agents) {
			const mode = agent.ingress_mode || "open";
			const site = agentSiteLink(agent.wg_link_name, { statusLinks, metaLinks: links });
			if (!site) {
				// Bound to a link that does not exist (renamed/deleted): report it
				// instead of silently dropping the agent from the check.
				const hint = boundLinkMissingHint(agent.wg_link_name, statusLinks);
				result.push({
					agent_id: agent.id,
					agent_name: agent.name,
					ingress_mode: mode,
					link_found: false,
					link_hint: hint.reason,
					...(hint.link_name ? { link_hint_name: hint.link_name } : {}),
					wg_link_name: agent.wg_link_name,
					hub_sources: [],
					hub_egress_flows: egressFlows.length,
					missing: [],
					missing_disabled: [],
					unchecked: [],
					unused_hub_rules: [],
					broad_hub_rules: [],
					...ingressRuleCounts(rulesByAgent.get(agent.id) ?? []),
					applied: await this.appliedFor(agent, rulesByAgent.get(agent.id) ?? []),
				});
				continue;
			}
			const [linkId, ownNets] = site;
			const hubHosts = await hubHostsFor(splitLinkId(linkId)?.[0] ?? "");
			// Empty = wg conf unreadable or without Address line: only upstreams with
			// their own egress source are checkable (see link_hint "hub-source-unknown").
			const hubKnown = hubHosts.length > 0;
			const rules = rulesByAgent.get(agent.id) ?? [];

			const behind = upstreamsBehind(upstreams, ownNets, hubNets);
			const missing = [];
			const missingDisabled = [];
			for (const u of behind) {
				if (!u.source && !hubKnown) continue; // hub address unknown: not checkable
				// A hub egress flow may name its own source (SNAT address); everything
				// else arrives from the hub's tunnel address.
				const srcs = u.source ? [u.source] : hubHosts;
				const covered = upstreamCovered(u, rules, hubHosts);
				if (!covered && !u.enabled) {
					// Switched off on purpose: no traffic, no 504 — info only, no warning
					missingDisabled.push(u);
				} else if (!covered) {
					// suggestion null = no known port: no one-click rule (see upstreamSuggestion)
					missing.push({
						...u,
						suggestion: upstreamSuggestion(u, srcs),
					});
				}
			}

			// Client traffic is only dropped (and so only reported) while restricted.
			if (mode === "restricted") {
				const ownNoHub = ownNets.filter((n) => !hubNets.some((h) => cidrContains(h, n)));
				// An untyped single-LAN site is inferred as "client" too — never a gap against itself.
				missing.push(
					...clientIngressGaps(
						clients.filter((c) => c.id !== linkId),
						ownNoHub,
						rules,
					),
				);
			}

			// Hub-sourced = EVERY source lies inside a hub/egress address. A broad
			// source that merely contains the hub (10.10.0.0/24, 0.0.0.0/0) also serves
			// VPN clients / other sites, whose targets no proxy host shows.
			const hubSrcs = [...hubHosts, ...egressSources];
			const unusedHubRules = rules
				.filter((r) => r.enabled && r.destinations.length && isHubSourced(r, hubSrcs))
				.map((r) => ({
					id: r.id,
					name: r.name,
					unused: r.destinations.filter((d) => !behind.some((u) => cidrContains(d, u.host))),
				}))
				.filter((r) => r.unused.length);
			const broad = broadHubRules(rules, hubSrcs, behind);

			result.push({
				agent_id: agent.id,
				agent_name: agent.name,
				ingress_mode: mode,
				link_found: true,
				...(hubKnown ? {} : { link_hint: "hub-source-unknown" }),
				hub_sources: hubHosts,
				hub_egress_flows: egressFlows.length,
				missing,
				missing_disabled: missingDisabled,
				unchecked: mode === "restricted" ? unchecked : [],
				unused_hub_rules: unusedHubRules,
				broad_hub_rules: broad,
				...ingressRuleCounts(rules),
				applied: await this.appliedFor(agent, rules),
			});
		}
		return result;
	},
};

export default internalAgentIngress;
