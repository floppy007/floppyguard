// Pure helpers for direct links ("Direktverbindungen"): a WireGuard tunnel
// between two site agents that carries their site-to-site traffic directly,
// with the hub as the automatic fallback. No DB / IO here.
//
// Model: side A listens (fixed public IP / port forward on its router), side B
// dials A's endpoint. Each side runs its own interface fgd<id> (never wgN — a
// gateway may run foreign wgN tunnels, e.g. a road-warrior VPN on wg1) with
// `Table = off`. The partner's networks go into routing table
// DIRECT_TABLE_BASE + id, looked up by an `ip rule` at DIRECT_RULE_PREF before
// the main table. The agent fills that table only while the link is healthy
// (handshake + ping), so on failure the main-table hub routes on wgN take over
// without the hub routes ever being touched — and with no direct link nothing on
// the gateway changes at all.
//
// NAT stays as on the hub tunnel (phase 1): the tunnel /30 is MASQUERADEd into
// the LAN like the hub tunnel subnet, and a side whose hub traffic leaves NATed
// (e.g. a blanket `-o wg0 -j MASQUERADE` from another tool) sets nat_<side> so
// its LAN sources also leave the direct tunnel NATed — the effective sender
// addresses seen by firewalls, RADIUS and AD stay the same on both paths.
//
// Private keys never leave the agent: each side generates its key on first use
// and reports only the public key in its heartbeat; the partner's config is
// complete once both keys are known.

import { createHash } from "node:crypto";
import error from "../lib/error.js";
import { cidrContains } from "./agent-ingress-rules.js";

export const DIRECT_TABLE_BASE = 52000;
export const DIRECT_RULE_PREF = 31000;
export const MAX_DIRECT_LINK_ID = 9999;
export const DIRECT_KEEPALIVE_S = 25;
export const DIRECT_PATHS = new Set(["direct", "hub"]);

export const directIface = (id) => `fgd${id}`;
export const isDirectIface = (name) => /^fgd\d{1,4}$/.test(String(name ?? ""));
export const directTable = (id) => DIRECT_TABLE_BASE + Number(id);

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
// RFC 1123 host name: labels of letters/digits/hyphens, no leading/trailing
// hyphen. Ends up in the wg-quick config (not a shell), still kept strict.
const HOSTNAME_RE =
	/^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const WG_PUBKEY_RE = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;

const ipToInt = (ip) => ip.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
const intToIp = (n) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join(".");

export const isIpv4Literal = (v) => {
	const m = String(v ?? "").match(IPV4_RE);
	return Boolean(m) && m.slice(1).every((o) => Number(o) <= 255);
};

export const isWgPublicKey = (v) => typeof v === "string" && WG_PUBKEY_RE.test(v);

const isPrivateIpv4Net = (cidr) => ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].some((p) => cidrContains(p, cidr));

/**
 * Canonical /30 of a direct link, or null. Host bits must be zero (the input is
 * what the admin typed — silently masking "10.10.9.1/30" would hide a typo).
 */
export function canonicalTunnelSubnet(value) {
	const m = String(value ?? "")
		.trim()
		.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/30$/);
	if (!m || !isIpv4Literal(m[1])) return null;
	const n = ipToInt(m[1]);
	if (n % 4 !== 0) return null;
	const cidr = `${m[1]}/30`;
	return isPrivateIpv4Net(cidr) ? cidr : null;
}

/** { a, b } tunnel addresses of a /30: A = network+1, B = network+2. */
export function tunnelAddresses(tunnelSubnet) {
	const n = ipToInt(tunnelSubnet.split("/")[0]);
	return { a: intToIp(n + 1), b: intToIp(n + 2) };
}

const bool = (v) => v === true || v === 1 || v === "1" || v === "true";

/**
 * Validate admin input for create (partial=false) or update (partial=true).
 * Returns only the fields present (update) with canonical values.
 *
 * @throws {error.ValidationError}
 */
export function sanitizeDirectLinkInput(body, { partial = false } = {}) {
	const b = body && typeof body === "object" ? body : {};
	const out = {};
	const has = (k) => typeof b[k] !== "undefined";
	const need = (k) => {
		if (!partial && !has(k)) throw new error.ValidationError(`${k} is required`);
		return has(k);
	};

	if (need("name")) {
		const name = typeof b.name === "string" ? b.name.trim() : "";
		// biome-ignore lint/suspicious/noControlCharactersInRegex: reject control characters in a display name
		if (!name || name.length > 64 || /[\u0000-\u001f\u007f]/.test(name)) {
			throw new error.ValidationError("name must be 1-64 characters");
		}
		out.name = name;
	}
	for (const k of ["agent_a_id", "agent_b_id"]) {
		if (need(k)) {
			const n = Number(b[k]);
			if (!Number.isInteger(n) || n < 1) throw new error.ValidationError(`${k} must be an agent id`);
			out[k] = n;
		}
	}
	if (has("agent_a_id") && has("agent_b_id") && out.agent_a_id === out.agent_b_id) {
		throw new error.ValidationError("a direct link needs two different agents");
	}
	if (need("listen_port")) {
		const p = Number(b.listen_port);
		if (!Number.isInteger(p) || p < 1024 || p > 65535) {
			throw new error.ValidationError("listen_port must be 1024-65535");
		}
		out.listen_port = p;
	}
	if (need("endpoint_host")) {
		const h = typeof b.endpoint_host === "string" ? b.endpoint_host.trim().toLowerCase() : "";
		const looksNumeric = /^[\d.]+$/.test(h);
		if (!h || (looksNumeric ? !isIpv4Literal(h) : !HOSTNAME_RE.test(h))) {
			throw new error.ValidationError("endpoint_host must be a public IPv4 address or a host name");
		}
		out.endpoint_host = h;
	}
	if (need("tunnel_subnet")) {
		const t = canonicalTunnelSubnet(b.tunnel_subnet);
		if (!t) {
			throw new error.ValidationError("tunnel_subnet must be a private /30 network address (e.g. 10.10.9.0/30)");
		}
		out.tunnel_subnet = t;
	}
	if (has("mtu")) {
		if (b.mtu === null || b.mtu === "") out.mtu = null;
		else {
			const m = Number(b.mtu);
			if (!Number.isInteger(m) || m < 1280 || m > 1500) throw new error.ValidationError("mtu must be 1280-1500");
			out.mtu = m;
		}
	}
	for (const k of ["enabled", "nat_a", "nat_b"]) {
		if (has(k)) out[k] = bool(b[k]);
		else if (!partial) out[k] = false;
	}
	return out;
}

/**
 * Cross-checks of a complete link against the rest of the mesh (pure):
 * - both agents bound to (unambiguous) site links, not road-warrior clients;
 * - the two sites are not separated ("Standorte untereinander") — the hub's
 *   isolation does not apply on a direct path;
 * - the /30 overlaps no site network, no agent tunnel subnet, no other link;
 * - the agent pair has no second link.
 *
 * @param {object} link  sanitized complete link (incl. id when updating)
 * @param {{agents: Map<number, object>, siteLinkIdOf: (agent) => string|null,
 *   isolated: (idA: string, idB: string) => boolean, siteNets: string[],
 *   agentTunnelSubnets: string[], others: object[]}} ctx
 * All checks only apply to an ENABLED link: a link that became invalid later
 * (sites separated, agent deleted, a new site net over its /30) must stay
 * editable and switchable off — its payload is inactive anyway.
 *
 * @throws {error.ValidationError}
 */
export function assertDirectLinkFits(link, ctx) {
	if (!link.enabled) return;
	const a = ctx.agents.get(link.agent_a_id);
	const b = ctx.agents.get(link.agent_b_id);
	if (!a || !b) throw new error.ValidationError("both agents must exist");
	const la = ctx.siteLinkIdOf(a);
	const lb = ctx.siteLinkIdOf(b);
	if (!la || !lb) {
		throw new error.ValidationError(
			"both agents must be bound to a site link (Standort-Verbindung) — road-warrior clients cannot have direct links",
		);
	}
	if (la === lb) throw new error.ValidationError("both agents belong to the same site");
	if (ctx.isolated(la, lb)) {
		throw new error.ValidationError(
			"these sites are separated („Standorte untereinander“) — the separation only applies on the hub, a direct link would bypass it",
		);
	}
	if (natRestrictedConflict(link, a, b)) {
		throw new error.ValidationError(
			"a side with „nur Freigaben“ cannot take a partner that masquerades into the direct tunnel: its Freigaben match the partner's hub address, on the direct path the traffic would arrive from the transfer net and be dropped",
		);
	}
	const t = link.tunnel_subnet;
	const nets = [...ctx.siteNets, ...ctx.agentTunnelSubnets];
	const clash = nets.find((n) => cidrContains(n, t) || cidrContains(t, n));
	if (clash) throw new error.ValidationError(`tunnel_subnet ${t} overlaps ${clash}`);
	// The tunnel's own UDP must never be routed into the per-link table.
	if (isIpv4Literal(link.endpoint_host)) {
		const inside = nets.find((n) => cidrContains(n, `${link.endpoint_host}/32`));
		if (inside) throw new error.ValidationError(`endpoint_host ${link.endpoint_host} lies inside ${inside}`);
	}
	for (const o of ctx.others) {
		if (o.id === link.id) continue;
		if (cidrContains(o.tunnel_subnet, t) || cidrContains(t, o.tunnel_subnet)) {
			throw new error.ValidationError(`tunnel_subnet ${t} is already used by direct link "${o.name}"`);
		}
		const samePair =
			(o.agent_a_id === link.agent_a_id && o.agent_b_id === link.agent_b_id) ||
			(o.agent_a_id === link.agent_b_id && o.agent_b_id === link.agent_a_id);
		if (samePair) throw new error.ValidationError(`these agents already have direct link "${o.name}"`);
		if (o.agent_a_id === link.agent_a_id && o.listen_port === link.listen_port) {
			throw new error.ValidationError(
				`listen_port ${link.listen_port} is already used on this agent by "${o.name}"`,
			);
		}
	}
}

/**
 * A restricted side (FG_IN "nur Freigaben") whose partner masquerades into the
 * direct tunnel: the partner's traffic arrives from its /30 address instead of
 * its hub address, so the Freigaben written for the hub path drop it while the
 * health ping (INPUT) still succeeds. Such a link must not be active.
 */
export function natRestrictedConflict(link, agentA, agentB) {
	const restricted = (x) => (x?.ingress_mode || "open") === "restricted";
	return Boolean((restricted(agentA) && link.nat_b) || (restricted(agentB) && link.nat_a));
}

const assertCidr = (n) => {
	if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(n)) throw new Error(`Invalid CIDR: ${n}`);
};

/**
 * PostUp/PostDown for one side. Idempotent (`-C … || -A …`) because wg-quick
 * may re-run them; the interface name is baked in (no %i), like buildHubPostUp.
 * rp_filter goes loose on the direct AND the hub interface: while the two sides
 * disagree on the path (one already back on the hub), a reply may arrive on the
 * other tunnel than its route points to, which strict rp_filter would drop.
 */
export function buildDirectHooks({ iface, hubIface, tunnelSubnet, nat }) {
	if (!isDirectIface(iface)) throw new Error(`invalid direct interface: ${iface}`);
	if (!/^wg\d{1,3}$/.test(hubIface)) throw new Error(`invalid hub interface: ${hubIface}`);
	assertCidr(tunnelSubnet);
	const rules = [
		[`FORWARD -i ${iface} -j ACCEPT`, ""],
		[`FORWARD -o ${iface} -j ACCEPT`, ""],
		// tunnel /30 sources into the LAN: same as the hub tunnel subnet on wgN
		[`POSTROUTING ! -o ${iface} -s ${tunnelSubnet} -j MASQUERADE`, "-t nat "],
	];
	if (nat) rules.push([`POSTROUTING -o ${iface} -j MASQUERADE`, "-t nat "]);
	const up = [
		"sysctl -w net.ipv4.ip_forward=1",
		`sysctl -w net.ipv4.conf.${iface}.rp_filter=2`,
		// wg-quick runs the hook under set -e: a missing hub interface (wg0 not up
		// yet at boot) must not abort bringing the direct link up
		`[ ! -e /proc/sys/net/ipv4/conf/${hubIface} ] || sysctl -w net.ipv4.conf.${hubIface}.rp_filter=2`,
		...rules.map(([r, t]) => `iptables ${t}-C ${r} 2>/dev/null || iptables ${t}-A ${r}`),
	];
	const down = rules.map(([r, t]) => `iptables ${t}-D ${r} 2>/dev/null || true`);
	return { postUp: up.join("; "), postDown: down.join("; ") };
}

/**
 * wg-quick config of one side WITHOUT PrivateKey (the agent inserts its own).
 * null while the partner's public key is not known yet.
 */
export function buildDirectConfig({ link, side, hubIface, peerPublicKey, peerNets, mtu }) {
	if (!isWgPublicKey(peerPublicKey)) return null;
	const iface = directIface(link.id);
	const addrs = tunnelAddresses(link.tunnel_subnet);
	const own = side === "a" ? addrs.a : addrs.b;
	const nat = side === "a" ? link.nat_a : link.nat_b;
	const { postUp, postDown } = buildDirectHooks({ iface, hubIface, tunnelSubnet: link.tunnel_subnet, nat });
	for (const n of peerNets) assertCidr(n);
	const lines = ["[Interface]", `Address = ${own}/30`];
	if (side === "a") lines.push(`ListenPort = ${link.listen_port}`);
	if (mtu) lines.push(`MTU = ${mtu}`);
	lines.push("Table = off", `PostUp = ${postUp}`, `PostDown = ${postDown}`, "", "[Peer]");
	lines.push(`PublicKey = ${peerPublicKey}`);
	lines.push(`AllowedIPs = ${[link.tunnel_subnet, ...peerNets].join(", ")}`);
	if (side === "b") lines.push(`Endpoint = ${link.endpoint_host}:${link.listen_port}`);
	lines.push(`PersistentKeepalive = ${DIRECT_KEEPALIVE_S}`);
	return `${lines.join("\n")}\n`;
}

/**
 * Networks the agent routes through the direct link: exactly those of its
 * hub-side reach (otherSiteNets — ACL-filtered, own-site-stripped, same
 * computation as the hub peer's AllowedIPs) that the partner site exports.
 * Unlike on the hub path, a partner SUPERNET of an own net (e.g. 10.0.0.0/8 over
 * an own 10.3.10.0/24) must go too: the per-link table is consulted before the
 * main table, so longest-prefix match against the own routes no longer applies
 * and the own site (or the hub tunnel) would be pulled into the direct tunnel.
 * `ownNets` = own site nets + the agent's hub tunnel subnet. Sorted, deduped.
 */
export function directPeerNets(otherSiteNets, partnerNets, ownNets = []) {
	const partner = new Set(partnerNets || []);
	const clashes = (n) => ownNets.some((o) => cidrContains(n, o) || cidrContains(o, n));
	return [...new Set((otherSiteNets || []).filter((n) => partner.has(n) && !clashes(n)))].sort();
}

/**
 * One entry of the agent's `direct_links` payload.
 * Disabled / isolated / incomplete links are sent as `enabled: false`, so the
 * agent tears the tunnel down but keeps its key.
 */
export function directPayloadEntry({ link, side, hubIface, peerPublicKey, peerNets, active }) {
	const base = { id: link.id, iface: directIface(link.id), table: directTable(link.id) };
	if (!active) return { ...base, enabled: false };
	const config = buildDirectConfig({ link, side, hubIface, peerPublicKey, peerNets, mtu: link.mtu });
	const addrs = tunnelAddresses(link.tunnel_subnet);
	return {
		...base,
		enabled: true,
		peer_ip: side === "a" ? addrs.b : addrs.a,
		routes: peerNets,
		// a host name endpoint is re-resolved by the agent while the handshake is stale
		endpoint:
			side === "b" && !isIpv4Literal(link.endpoint_host) ? `${link.endpoint_host}:${link.listen_port}` : null,
		config_text: config,
		config_hash: config ? createHash("sha256").update(config).digest("hex") : null,
	};
}

/**
 * Sanitize the `direct_links` status object of a heartbeat:
 * { "<linkId>": { public_key, up, path, handshake_age, rtt_ms, error } }.
 * Only ids in `allowedIds` (links this agent is a side of) are kept.
 *
 * @returns {Map<number, {public_key: string|null, status: object}>}
 */
export function sanitizeDirectStatus(raw, allowedIds) {
	const out = new Map();
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
	for (const [k, v] of Object.entries(raw)) {
		const id = Number(k);
		if (!Number.isInteger(id) || !allowedIds.has(id) || !v || typeof v !== "object") continue;
		const age = Number(v.handshake_age);
		const rtt = Number(v.rtt_ms);
		out.set(id, {
			public_key: isWgPublicKey(v.public_key) ? v.public_key : null,
			status: {
				up: v.up === true,
				path: DIRECT_PATHS.has(v.path) ? v.path : "hub",
				handshake_age: Number.isInteger(age) && age >= 0 && age < 10 ** 9 ? age : null,
				rtt_ms:
					v.rtt_ms !== null && Number.isFinite(rtt) && rtt >= 0 && rtt < 100000
						? Math.round(rtt * 10) / 10
						: null,
				error:
					String(v.error ?? "")
						.replace(/\p{Cc}/gu, " ")
						.trim()
						.slice(0, 255) || null,
			},
		});
	}
	return out;
}
