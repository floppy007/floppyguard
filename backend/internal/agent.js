import { execFile } from "node:child_process";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { createConnection } from "node:net";
import error from "../lib/error.js";
import { wireguard as logger } from "../logger.js";
import Agent from "../models/agent.js";
import Setting from "../models/setting.js";
import internalWireGuard, { canonicalizeIpv4Network, withWriteLock } from "./wireguard.js";

/**
 * Generate a random hex token of `byteLength` bytes (returns 2*byteLength hex chars).
 *
 * @param {number} byteLength
 * @returns {string}
 */
const randomToken = (byteLength = 32) => randomBytes(byteLength).toString("hex");

/**
 * Compute SHA-256 hex digest of a string. Returns null if input is falsy.
 *
 * @param {string|null|undefined} text
 * @returns {string|null}
 */
const hashConfig = (text) => {
	if (!text) return null;
	return createHash("sha256").update(text).digest("hex");
};

const AGENT_SCRIPT_VERSION = "1.3.23";

/** Setting key holding the hub URLs propagated to agents. */
const AGENT_HUB_URL_SETTING = "agent-hub-url";

/**
 * Validate that a URL is safe to write into config.env via sed and to use as a
 * shell-interpolated curl target on the agent. Rejects anything that isn't a
 * plain http(s) URL — same threat model as getInstallScript's URL guard.
 *
 * @param {string|null|undefined} url
 * @returns {string|null}  the URL if valid, otherwise null
 */
function sanitizeHubUrl(url) {
	if (!url || typeof url !== "string") return null;
	const trimmed = url.trim().replace(/\/+$/, "");
	if (!trimmed) return null;
	try {
		const parsed = new URL(trimmed);
		if (!["http:", "https:"].includes(parsed.protocol)) return null;
	} catch {
		return null;
	}
	// config.env writes use sed with `|` delimiter and bash double quotes; curl
	// interpolates the value unquoted-safe. Reject shell/sed metacharacters.
	if (/[$`\\;|&(){}<>!#"'\s]/.test(trimmed)) return null;
	return trimmed;
}

// UniFi credential fields are interpolated into config.env (UNIFI_PASS="...")
// which is `source`d as ROOT on the agent. A value with a quote, newline,
// backtick, $ or backslash can close the assignment and inject env/shell — at
// minimum it corrupts the PRIMARY_URL/FALLBACK_URL lines below it and silently
// blackholes the agent's hub connection. Validate before storage (mirrors how
// sanitizeHubUrl / sanitizeAclNetworks guard their own sinks).
const UNIFI_UNSAFE_RE = /["$`\\\r\n]/;
function sanitizeUnifiFields(data, patch) {
	if (typeof data.unifi_url !== "undefined") {
		if (data.unifi_url === null || data.unifi_url === "") {
			patch.unifi_url = null;
		} else {
			const u = sanitizeHubUrl(data.unifi_url);
			if (!u) throw new error.ValidationError("unifi_url must be a valid http(s) URL without shell metacharacters");
			patch.unifi_url = u;
		}
	}
	for (const f of ["unifi_user", "unifi_pass", "unifi_site"]) {
		if (typeof data[f] === "undefined") continue;
		if (data[f] === null || data[f] === "") {
			patch[f] = f === "unifi_site" ? "default" : null;
			continue;
		}
		const s = String(data[f]);
		if (UNIFI_UNSAFE_RE.test(s)) {
			throw new error.ValidationError(`${f} contains characters not allowed in config.env (quotes, newline, backtick, $ or backslash)`);
		}
		patch[f] = s;
	}
}

// `mode` and `wg_interface` are interpolated into the same root-sourced
// config.env heredoc (AGENT_MODE="..." / WG_INTERFACE="...") in
// getInstallScript — the JS template substitutes the value BEFORE the
// single-quoted heredoc is written, so a quote+newline closes the assignment
// and injects arbitrary lines, exactly the sink sanitizeUnifiFields guards.
// wg_interface additionally flows into `wg-quick up "$iface"` and the path
// /etc/wireguard/$iface.conf on the agent. Whitelist both before storage.
const VALID_AGENT_MODES = ["native", "unifi"];
// Mirrors VALID_IFACE_NAME in wireguard.js.
const VALID_WG_INTERFACE_RE = /^wg\d{1,3}$/;
function sanitizeAgentMode(mode) {
	const m = mode || "native";
	if (!VALID_AGENT_MODES.includes(m)) {
		throw new error.ValidationError(`mode must be one of: ${VALID_AGENT_MODES.join(", ")}`);
	}
	return m;
}
function sanitizeWgInterface(name) {
	const n = name || "wg0";
	if (typeof n !== "string" || !VALID_WG_INTERFACE_RE.test(n)) {
		throw new error.ValidationError('wg_interface must match wg<number>, e.g. "wg0"');
	}
	return n;
}

/**
 * Resolve the hub URLs to advertise to agents. Source of truth: the
 * `agent-hub-url` setting (value = public/fallback URL, meta.primary = internal
 * primary URL), with env-var fallback. Returns null fields when unset so the
 * agent keeps whatever it already has baked in (never overwrites with empty).
 *
 * @returns {Promise<{ primaryUrl: string|null, fallbackUrl: string|null }>}
 */
async function getAgentHubUrls() {
	let primary = null;
	let fallback = null;
	try {
		const row = await Setting.query().where("id", AGENT_HUB_URL_SETTING).first();
		if (row) {
			fallback = sanitizeHubUrl(row.value);
			primary = sanitizeHubUrl(row.meta?.primary);
		}
	} catch {
		// Setting table not available — fall through to env.
	}
	primary = primary || sanitizeHubUrl(process.env.AGENT_HUB_PRIMARY_URL);
	fallback = fallback || sanitizeHubUrl(process.env.AGENT_HUB_FALLBACK_URL);
	return { primaryUrl: primary, fallbackUrl: fallback };
}

/**
 * Compute HMAC-SHA256 of the script using the agent_token as key.
 * The agent verifies this signature before accepting a self-update.
 *
 * @param {string} script
 * @param {string} agentToken
 * @returns {string}
 */
const signScript = (script, agentToken) =>
	createHmac("sha256", agentToken).update(script).digest("hex");

/**
 * Parse agent.services JSON string into array. Returns [] on failure.
 * @param {Object} agent
 * @returns {Object}
 */
const parseAgentServices = (agent) => {
	if (!agent.services) {
		agent.services = [];
	} else if (typeof agent.services === "string") {
		try {
			agent.services = JSON.parse(agent.services);
		} catch {
			agent.services = [];
		}
	}
	// ACL columns are stored as JSON strings — hand them to the API as arrays
	// (or null when unset) so the frontend can edit them without re-parsing.
	for (const field of ["allowed_sites", "allowed_networks"]) {
		if (typeof agent[field] === "string") {
			try {
				agent[field] = JSON.parse(agent[field]);
			} catch {
				agent[field] = null;
			}
		}
	}
	return agent;
};

// Heartbeat `services` come straight from the remote agent's POST body and are
// rendered in the admin UI as clickable links (<a href={svc.url}>{svc.name}</a>).
// A compromised agent (or anyone holding an agent_token) must not be able to
// store javascript: URLs, phishing targets on exotic schemes, or unbounded
// payloads. Keep only entries with a string name and a plain http(s) URL;
// drop everything else. (scanAllAgentServices derives its URLs server-side
// and doesn't need this.)
const MAX_AGENT_SERVICES = 50;
const sanitizeAgentServices = (value) => {
	if (!Array.isArray(value)) return [];
	const out = [];
	for (const entry of value) {
		if (out.length >= MAX_AGENT_SERVICES) break;
		if (!entry || typeof entry !== "object") continue;
		if (typeof entry.name !== "string" || typeof entry.url !== "string") continue;
		const name = entry.name.trim().slice(0, 100);
		const url = entry.url.trim().slice(0, 255);
		if (!name || !url) continue;
		try {
			const parsed = new URL(url);
			if (!["http:", "https:"].includes(parsed.protocol)) continue;
		} catch {
			continue;
		}
		out.push({ name, url });
	}
	return out;
};

// Known port → default label
const KNOWN_PORTS = [
	{ port: 8080, label: "Web UI" },
	{ port: 8443, label: "Web UI", https: true },
	{ port: 9000, label: "Portainer" },
	{ port: 9443, label: "Portainer", https: true },
	{ port: 8888, label: "Management UI" },
	{ port: 3000, label: "Grafana" },
	{ port: 9090, label: "Prometheus" },
	{ port: 1880, label: "Node-RED" },
	{ port: 10000, label: "Webmin" },
	{ port: 8000, label: "Web UI" },
];

/**
 * Check if a TCP port is open on a host. Resolves true/false in ~1s.
 */
const tcpProbe = (host, port) =>
	new Promise((resolve) => {
		const sock = createConnection({ host, port, timeout: 1000 });
		sock.once("connect", () => {
			sock.destroy();
			resolve(true);
		});
		sock.once("timeout", () => {
			sock.destroy();
			resolve(false);
		});
		sock.once("error", () => resolve(false));
	});

/**
 * Try to fetch the <title> from a URL. Returns null on failure.
 */
/**
 * Fetch a URL via curl (handles self-signed certs, redirects, timeouts reliably).
 * Returns { title, finalUrl } or null on failure/404.
 */
const fetchTitle = (url) =>
	new Promise((resolve) => {
		const args = [
			"-skL",
			"--max-time", "4",
			"--write-out", "\n__FINALURL__%{url_effective}",
			url,
		];
		execFile("curl", args, { timeout: 5000 }, (err, stdout) => {
			if (err) {
				resolve(null);
				return;
			}
			const sep = stdout.lastIndexOf("\n__FINALURL__");
			const body = sep >= 0 ? stdout.slice(0, sep) : stdout;
			const finalUrl = sep >= 0 ? stdout.slice(sep + 13).trim() : url;
			if (!body.includes("<title") || /not found|404/i.test(body.slice(0, 200))) {
				resolve(null);
				return;
			}
			const m = body.match(/<title[^>]*>([^<]{1,80})<\/title>/i);
			resolve({ title: m ? m[1].trim() : null, finalUrl });
		});
	});

/**
 * Strict CIDR validation — prevents shell injection via malicious network values.
 * Only allows valid IPv4 CIDR notation (e.g. "192.168.1.0/24").
 */
const CIDR_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
function assertCIDR(value) {
	if (!CIDR_RE.test(value)) {
		throw new Error(`Invalid CIDR: ${value}`);
	}
}

/**
 * Validate an agent's allowed_networks ACL on input. Each entry flows into
 * syncAgentConfigs → buildHubPostUp (`ip route add <net> dev wgN`, run as root
 * on the agent), so a non-CIDR value must be rejected before storage — relying
 * on the assertCIDR sink alone lets a poisoned value silently break config sync
 * for every agent on the next metadata apply. See [[project_wg_network_validation]].
 *
 * @param {unknown} value  array of CIDR strings, or null/undefined
 * @returns {string[]|null}  trimmed, deduped CIDR list, or null
 * @throws {error.ValidationError} on a non-array or any invalid CIDR entry
 */
function sanitizeAclNetworks(value) {
	if (value === null || typeof value === "undefined") return null;
	if (!Array.isArray(value)) {
		throw new error.ValidationError("allowed_networks must be an array of CIDRs or null");
	}
	const nets = Array.from(new Set(value.map((n) => String(n || "").trim()).filter(Boolean)));
	// Empty after filtering = "no per-network restriction" (full mesh), same as
	// null — the UI shows a cleared ACL as "All". Never store "[]", which
	// syncAgentConfigs would read as an explicit "allow nothing" list.
	if (nets.length === 0) return null;
	for (const net of nets) {
		// CIDR_RE is shape-only — it accepts garbage like 999.0.0.0/99 (which would
		// break `ip route add` and take the agent's tunnel down). Validate octet and
		// prefix ranges strictly here.
		if (!CIDR_RE.test(net)) {
			throw new error.ValidationError(`allowed_networks contains invalid CIDR: ${net}`);
		}
		const [addr, prefixStr] = net.split("/");
		const prefix = Number(prefixStr);
		if (prefix > 32 || addr.split(".").some((octet) => Number(octet) > 255)) {
			throw new error.ValidationError(`allowed_networks contains invalid CIDR: ${net}`);
		}
		// A /0 prefix in a per-agent ACL becomes `ip route add <default>` on the
		// agent (run as root), hijacking its routing and locking the box out. The
		// hub routes specific subnets, never the whole internet. Reject ANY /0 —
		// not just the literal "0.0.0.0/0" (0.0.0.0/00, 00.00.00.00/0 alias it).
		if (prefix === 0) {
			throw new error.ValidationError(`allowed_networks must not contain a /0 route (${net} would hijack the agent's default route)`);
		}
	}
	// Canonicalize to network address (mask host bits) so an ACL entry compares
	// equal to the exported site nets in _computeOtherSiteNets — otherwise
	// "192.168.10.0/24" vs a host-bits "192.168.10.1/24" would drop the net.
	return Array.from(new Set(nets.map((n) => canonicalizeIpv4Network(n) || n)));
}

/**
 * Coerce an agent's allowed_sites ACL (link-name whitelist) to trimmed,
 * non-empty strings. Compared against link names only — never shell-interpolated
 * — so no CIDR validation is required.
 *
 * @param {unknown} value  array of link names, or null/undefined
 * @returns {string[]|null}
 */
function sanitizeAclSites(value) {
	if (value === null || typeof value === "undefined") return null;
	if (!Array.isArray(value)) return null;
	const sites = value.map((s) => String(s || "").trim()).filter(Boolean);
	// Empty = no restriction (full mesh), same as null — never store "[]".
	return sites.length ? sites : null;
}

/**
 * Build hub-managed PostUp/PostDown rules from the config's tunnel subnet.
 * %i is replaced by wg-quick with the interface name at runtime.
 *
 * @param {string} tunnelSubnet  e.g. "10.10.0.0/24"
 * @param {string[]} remoteSiteNets  networks from other sites that need MASQUERADE
 *   when exiting through the local LAN (e.g. ["192.168.111.0/24", "192.168.112.0/24"])
 */
function buildHubPostUp(tunnelSubnet, remoteSiteNets = [], peerNets = []) {
	assertCIDR(tunnelSubnet);
	let rules = `sysctl -w net.ipv4.ip_forward=1; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING ! -o %i -s ${tunnelSubnet} -j MASQUERADE`;
	for (const net of remoteSiteNets) {
		assertCIDR(net);
		rules += `; iptables -t nat -A POSTROUTING ! -o %i -s ${net} -j MASQUERADE`;
	}
	for (const net of peerNets) {
		assertCIDR(net);
		rules += `; ip route add ${net} dev %i 2>/dev/null || true`;
	}
	return rules;
}
function buildHubPostDown(tunnelSubnet, remoteSiteNets = [], peerNets = []) {
	assertCIDR(tunnelSubnet);
	let rules = `iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING ! -o %i -s ${tunnelSubnet} -j MASQUERADE`;
	for (const net of remoteSiteNets) {
		assertCIDR(net);
		rules += `; iptables -t nat -D POSTROUTING ! -o %i -s ${net} -j MASQUERADE`;
	}
	for (const net of peerNets) {
		assertCIDR(net);
		rules += `; ip route del ${net} dev %i 2>/dev/null || true`;
	}
	return rules;
}

/**
 * Extract the tunnel subnet from an Address line (e.g. "10.10.0.5/24" -> "10.10.0.0/24").
 * Falls back to "10.10.0.0/24" if not parseable.
 */
function deriveTunnelSubnet(configText) {
	const m = (configText || "").match(/^\s*Address\s*=\s*([\d.]+)\/([\d]+)/im);
	if (!m) return "10.10.0.0/24";
	const parts = m[1].split(".");
	const mask = Number.parseInt(m[2], 10);
	if (mask <= 8) return `${parts[0]}.0.0.0/${mask}`;
	if (mask <= 16) return `${parts[0]}.${parts[1]}.0.0/${mask}`;
	// For /32 host addresses, derive the enclosing /24 (the tunnel subnet)
	if (mask > 24) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
	return `${parts[0]}.${parts[1]}.${parts[2]}.0/${mask}`;
}

/**
 * @param {string} configText  raw wg-quick config
 * @param {string[]} remoteSiteNets  networks from other sites needing LAN MASQUERADE
 */
function normalizeAgentConfig(configText, remoteSiteNets = []) {
	if (!configText) return configText;
	const lines = configText.split(/\r?\n/);
	const out = [];
	let inInterface = false;
	let hasTable = false;

	// Single pass: detect Table, mask PrivateKey, strip PostUp/PostDown
	for (const raw of lines) {
		const t = raw.trim();
		if (t === "[Interface]") inInterface = true;
		else if (t.startsWith("[")) inInterface = false;

		if (inInterface && t.startsWith("Table")) {
			hasTable = true;
		}

		// Mask PrivateKey for DB storage
		if (inInterface && t.startsWith("PrivateKey") && !t.includes("(hidden)")) {
			out.push("PrivateKey = (hidden)");
			continue;
		}

		// Strip all PostUp/PostDown — hub regenerates them
		if (t.startsWith("PostUp") || t.startsWith("PostDown")) continue;

		out.push(raw);
	}

	// Derive tunnel subnet from Address field
	const tunnelSubnet = deriveTunnelSubnet(configText);

	// Insert Table = off + hub-managed PostUp/PostDown before first [Peer]
	const peerIdx = out.findIndex((l) => l.trim() === "[Peer]");
	const insertAt = peerIdx > 0 ? peerIdx : out.length;

	const toInsert = [];
	if (!hasTable) toInsert.push("Table = off");
	const peerNets = _parseHubPeerAllowedIPs(configText).filter(
		(c) => !c.endsWith("/32") && !c.endsWith("/128"),
	);
	toInsert.push(`PostUp = ${buildHubPostUp(tunnelSubnet, remoteSiteNets, peerNets)}`);
	toInsert.push(`PostDown = ${buildHubPostDown(tunnelSubnet, remoteSiteNets, peerNets)}`);

	out.splice(insertAt, 0, ...toInsert);

	return out.join("\n");
}

/**
 * Extract the first Address IP from a wg-quick config string.
 * e.g. "Address = 10.10.0.2/32" → "10.10.0.2"
 */
const extractWgIp = (configText) => {
	if (!configText) return null;
	const m = configText.match(/^\s*Address\s*=\s*([\d.]+)/im);
	return m ? m[1] : null;
};

/**
 * Scan known management ports on `ip` and return [{name, url}].
 */
const scanIp = async (ip) => {
	const found = [];
	const seenUrls = new Set();

	for (const { port, label, https: useHttps } of KNOWN_PORTS) {
		const open = await tcpProbe(ip, port);
		if (!open) continue;
		const scheme = useHttps ? "https" : "http";
		const probeUrl = `${scheme}://${ip}:${port}`;
		const result = await fetchTitle(probeUrl);
		if (result === null) continue;
		// Store the clean base URL (scheme + host + port), not the redirect destination path
		const parsed = new URL(result.finalUrl || probeUrl);
		const storeUrl = `${parsed.protocol}//${parsed.hostname}:${parsed.port || (parsed.protocol === "https:" ? "443" : "80")}`;
		const key = storeUrl;
		if (seenUrls.has(key)) continue;
		seenUrls.add(key);
		seenUrls.add(probeUrl.replace(/\/$/, ""));
		const name = result.title ?? label;
		found.push({ name, url: storeUrl });
	}
	return found;
};

/**
 * Extract a dotted-decimal IP from a string (e.g. agent name "VM-Docker (192.168.10.7)").
 * Returns null if none found.
 */
const extractIpFromText = (text) => {
	if (!text) return null;
	const m = text.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
	return m ? m[1] : null;
};

/**
 * True only for a syntactically valid RFC1918 private IPv4 address
 * (10/8, 172.16/12, 192.168/16). The service-discovery scanner derives its
 * target from agent-controlled heartbeat input (hostname/lan_ip), so an
 * agent_token holder must not be able to point the hub's TCP probe + curl at
 * loopback, link-local (169.254 cloud metadata), or arbitrary public hosts —
 * an SSRF the agent could not otherwise reach from the hub's network position.
 */
const isPrivateIpv4 = (ip) => {
	if (typeof ip !== "string") return false;
	const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (!m) return false;
	const octets = m.slice(1, 5).map(Number);
	if (octets.some((n) => n > 255)) return false;
	const [a, b] = octets;
	if (a === 10) return true;
	if (a === 172 && b >= 16 && b <= 31) return true;
	if (a === 192 && b === 168) return true;
	return false;
};

/**
 * Scan all active agents and update their services field.
 * Called on startup and once daily.
 */
const scanAllAgentServices = async () => {
	const agents = await Agent.query().where("is_deleted", 0).where("status", "active");
	for (const agent of agents) {
		// Prefer LAN IP (from hostname or name) — browser-clickable.
		// Only use WireGuard IP as fallback if no LAN IP found.
		const lanIp = extractIpFromText(agent.hostname) || extractIpFromText(agent.name);
		const wgIp = extractWgIp(agent.config_text);
		// Defense-in-depth SSRF guard: lanIp is derived from agent-controlled
		// heartbeat input (hostname/lan_ip), so only ever probe/curl an RFC1918
		// private target — never loopback, link-local (cloud metadata), or a
		// public host on the hub's (more privileged) network. Prefer the LAN IP,
		// fall back to the WireGuard IP, drop anything non-private.
		const target = [lanIp, wgIp].find((ip) => isPrivateIpv4(ip));
		const scanIps = target ? [target] : [];
		if (scanIps.length === 0) continue;
		try {
			// Scan all candidate IPs, merge results (prefer LAN IP URLs)
			const services = [];
			for (const ip of scanIps) {
				const found = await scanIp(ip);
				for (const svc of found) {
					if (!services.some((s) => s.url === svc.url)) {
						services.push(svc);
					}
				}
			}
			await Agent.query().patchAndFetchById(agent.id, {
				services: JSON.stringify(services),
			});
		} catch {
			// ignore per-agent errors
		}
	}
};

const RECONCILE_INTERVAL_MS = 5 * 60 * 1000;

// Background timers (service scan + config reconciler) are started explicitly by
// the server entrypoint via internalAgent.startBackgroundTasks(), NOT on module
// import — so importing agent.js in tests/CLI scripts never schedules timers (which
// otherwise made `node --test --test-force-exit` truncate non-deterministically).
function startBackgroundTasks() {
	// Service scan: once on startup (after a short delay) then once a day.
	setTimeout(() => {
		scanAllAgentServices().catch(() => {});
		setInterval(() => scanAllAgentServices().catch(() => {}), 24 * 60 * 60 * 1000);
	}, 5000);

	// Defense-in-depth reconciler. getConfig serves the STORED config_text, so every
	// agent depends on syncAgentConfigs having written it. If any mutation path ever
	// forgets to trigger a resync (the class of bug that left deleted nets routed),
	// the agent silently freezes on a stale config. Periodically recompute so a missed
	// trigger self-heals — and warn so it stops being silent. Read + resync under the
	// same write lock as every store mutation, so the reconciler can never read a
	// pre-delete snapshot and write a stale config over a correct one.
	setTimeout(() => {
		const reconcile = () =>
			withWriteLock(async () => {
				const metadata = await internalWireGuard.readMetadataStore();
				const res = await internalAgent.syncAgentConfigs(metadata);
				const changed = Array.isArray(res) ? res.filter((r) => r.changed) : [];
				// An endpoint-ONLY rewrite (hub-domain propagation) is expected, not a
				// missed trigger — separate it so a fleet-wide domain move doesn't drown
				// out the genuine network/ACL drift this warning exists to surface.
				const endpointOnly = changed.filter((r) => r.endpointChanged && !r.allowedChanged);
				const drift = changed.filter((r) => !(r.endpointChanged && !r.allowedChanged));
				if (drift.length) {
					logger.warn(
						`Agent reconciler: ${drift.length} stale agent config(s) resynced (a mutation path missed its trigger): ${drift.map((r) => r.name).join(", ")}`,
					);
				}
				if (endpointOnly.length) {
					logger.info(
						`Agent reconciler: propagated hub endpoint to ${endpointOnly.length} agent(s): ${endpointOnly.map((r) => r.name).join(", ")}`,
					);
				}
			}).catch((err) => logger.debug(`Agent reconciler skipped: ${err.message}`));
		setInterval(reconcile, RECONCILE_INTERVAL_MS);
	}, 60 * 1000);
}

/**
 * Build the agent loop script (the bash daemon that runs on the remote machine).
 *
 * @param {string} mode  "native" or "unifi"
 * @returns {string}  Complete bash script starting with #!/bin/bash
 */
function buildLoopScript(mode) {
	// ── apply_config function: mode-specific ──────────────────────────────────────
	// native: write wg-quick config file and apply via wg syncconf / wg-quick
	// unifi:  push peer config to UniFi Network Application API
	const applyFunctionNative = `\
# Ensure kernel ip routes exist for all non-host AllowedIPs on a WireGuard interface.
# wg syncconf updates WireGuard peer tables but does NOT touch the kernel routing table.
# This must be called after syncconf and also once on startup to recover from missed syncs.
# Also removes stale wg routes for networks no longer in AllowedIPs.

# True (exit 0) if CIDR $1 overlaps any whitespace-separated CIDR in $2.
# An exact string match misses a more-specific or supernet overlap, so a remote
# 192.168.1.128/25 advertised over a locally-connected 192.168.1.0/24 would get a
# wg route and hijack half the local LAN ("switch hijack"). Real containment test.
_net_overlaps() {
  python3 - "$1" "$2" <<'PYEOF' 2>/dev/null
import sys, ipaddress
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
except Exception:
    sys.exit(1)
for p in sys.argv[2].split():
    try:
        if net.overlaps(ipaddress.ip_network(p, strict=False)):
            sys.exit(0)
    except Exception:
        pass
sys.exit(1)
PYEOF
}

sync_routes() {
  local iface="$1"
  ip link show "$iface" > /dev/null 2>&1 || return 0
  local wg_nets
  wg_nets=$(wg show "$iface" allowed-ips 2>/dev/null | awk '{for(i=2;i<=NF;i++) print $i}' || echo "")

  # Collect networks that are directly connected on physical interfaces — never override these
  local phys_nets
  phys_nets=$(ip -4 route show type unicast 2>/dev/null | grep -v "dev $iface" | grep ' dev ' | awk '{print $1}' | grep '/' || echo "")

  # Remove stale wg routes: routes pointing at our wg interface that are no longer in AllowedIPs
  local current_wg_routes
  current_wg_routes=$(ip -4 route show dev "$iface" 2>/dev/null | awk '{print $1}' | grep '/' || echo "")
  if [ -n "$current_wg_routes" ]; then
    while IFS= read -r existing; do
      [ -z "$existing" ] && continue
      case "$existing" in */32|*/128) continue ;; esac
      if ! echo "$wg_nets" | grep -qxF "$existing"; then
        ip route del "$existing" dev "$iface" 2>/dev/null && log "Removed stale route $existing dev $iface" || true
      fi
    done <<< "$current_wg_routes"
  fi

  [ -z "$wg_nets" ] && return 0
  while IFS= read -r net; do
    [ -z "$net" ] && continue
    case "$net" in */32|*/128|0.0.0.0/0|::/0) continue ;; esac
    # Skip networks that overlap a locally-connected physical interface net — a
    # more-specific wg route would hijack part of the local LAN. grep is a fast
    # path for the exact case; _net_overlaps catches subnet/supernet overlaps too.
    if echo "$phys_nets" | grep -qxF "$net" || _net_overlaps "$net" "$phys_nets"; then
      log "Skipping route $net dev $iface — overlaps a physical interface net"
      continue
    fi
    ip route add "$net" dev "$iface" 2>/dev/null && log "Added route $net dev $iface" || true
  done <<< "$wg_nets"
}

apply_config() {
  local cfg="$1" iface="$2"
  printf '%s' "$cfg" > /tmp/fg_new_wg.conf
  local old_conf="/etc/wireguard/$iface.conf"

  # ── Preserve local PrivateKey when hub sends "(hidden)" ──
  if grep -q 'PrivateKey = (hidden)' /tmp/fg_new_wg.conf && [ -f "$old_conf" ]; then
    local real_key
    real_key=$(grep '^PrivateKey' "$old_conf" | head -1 | sed 's/^PrivateKey *= *//')
    if [ -n "$real_key" ] && [ "$real_key" != "(hidden)" ]; then
      python3 -c "
import sys
key=sys.argv[1]
with open('/tmp/fg_new_wg.conf','r') as f: c=f.read()
with open('/tmp/fg_new_wg.conf','w') as f: f.write(c.replace('PrivateKey = (hidden)','PrivateKey = '+key,1))
" "$real_key"
    fi
  fi

  if ip link show "$iface" > /dev/null 2>&1; then
    # ── Apply PostUp/PostDown changes from hub ──
    local old_postup="" old_postdown="" new_postup="" new_postdown=""
    [ -f "$old_conf" ] && old_postup=$(grep '^PostUp' "$old_conf" | sed 's/^PostUp *= *//' || true)
    [ -f "$old_conf" ] && old_postdown=$(grep '^PostDown' "$old_conf" | sed 's/^PostDown *= *//' || true)
    new_postup=$(grep '^PostUp' /tmp/fg_new_wg.conf | sed 's/^PostUp *= *//' || true)
    if [ "$old_postup" != "$new_postup" ]; then
      # PostUp/PostDown carry the wg-quick placeholder %i. wg-quick substitutes it
      # for the real interface, but here we eval the strings ourselves, so %i must
      # be replaced with $iface first — otherwise every "iptables ... -o %i" /
      # "ip ... dev %i" matches no interface and silently fails (2>/dev/null), and
      # the agent never adds/removes MASQUERADE+FORWARD rules (only sync_routes,
      # which uses $iface, kept routes correct — MASQUERADE leaked on every removal).
      if [ -n "$old_postdown" ]; then
        log "Running old PostDown before applying new rules..."
        eval "$(printf '%s' "$old_postdown" | sed "s/%i/$iface/g")" 2>/dev/null || true
      fi
      if [ -n "$new_postup" ]; then
        log "Applying new PostUp rules from hub..."
        eval "$(printf '%s' "$new_postup" | sed "s/%i/$iface/g")" 2>/dev/null || true
      fi
    fi
    wg syncconf "$iface" <(wg-quick strip /tmp/fg_new_wg.conf 2>/dev/null || grep -vE "^(Address|PostUp|PostDown|DNS|MTU|Table|PreUp|PreDown)[[:space:]]*=" /tmp/fg_new_wg.conf)
    # wg syncconf sometimes silently ignores AllowedIPs changes for existing peers.
    # Force-set AllowedIPs per peer from the new config to ensure they match.
    while IFS= read -r line; do
      local pk ai
      pk=$(echo "$line" | awk '{print $1}')
      ai=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf "%s,", $i}' | sed 's/,$//')
      [ -z "$pk" ] || [ -z "$ai" ] && continue
      wg set "$iface" peer "$pk" allowed-ips "$ai" 2>/dev/null || true
    done < <(wg-quick strip /tmp/fg_new_wg.conf 2>/dev/null | awk '$1=="[Peer]"{pk="";ai=""} $1=="PublicKey"{pk=$3} $1=="AllowedIPs"{ai="";for(i=3;i<=NF;i++)ai=ai $i} pk && ai{print pk, ai; pk=""; ai=""}')
    cp /tmp/fg_new_wg.conf "/etc/wireguard/$iface.conf"
    sync_routes "$iface"
    log "Applied config update to $iface (syncconf + AllowedIPs force-set, no downtime)"
  else
    cp /tmp/fg_new_wg.conf "/etc/wireguard/$iface.conf"
    wg-quick up "$iface" && log "Brought up $iface with new config"
  fi
}

# Sync routes once at agent startup to recover any routes missed by previous syncconf calls
sync_routes "$WG_INTERFACE"`;

	// For UniFi mode, config_text is a JSON blob:
	// { "server_public_key": "...", "endpoint": "host:port",
	//   "local_address": "10.x.x.x/32", "allowed_ips": ["..."],
	//   "persistent_keepalive": 25, "private_key": "..." }
	// The agent authenticates with UniFi controller and creates/updates the
	// WireGuard VPN client entry. It also adds firewall rules for the allowed_ips.
	const applyFunctionUnifi = `\
# UniFi helper: authenticate and get session cookie
unifi_login() {
  curl -sk -c /tmp/fg_unifi_cookie -b /tmp/fg_unifi_cookie \\
    -X POST -H "Content-Type: application/json" \\
    -d "{\\"username\\":\\"$UNIFI_USER\\",\\"password\\":\\"$UNIFI_PASS\\"}" \\
    "$UNIFI_URL/api/auth/login" > /dev/null 2>&1
}

# UniFi helper: find existing VPN client by name, returns ID or empty
unifi_find_vpn() {
  local name="$1"
  curl -sk -b /tmp/fg_unifi_cookie \\
    "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/vpnclient" 2>/dev/null |
    python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('data', [])
for item in items:
    if item.get('name') == sys.argv[1]:
        print(item.get('_id',''))
        sys.exit(0)
" "$name" 2>/dev/null || echo ""
}

apply_config() {
  local cfg="$1"  # JSON blob from FloppyGuard
  # Parse peer config from JSON
  SERVER_PUB=$(python3 -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('server_public_key',''))" "$cfg" 2>/dev/null || echo "")
  ENDPOINT=$(python3   -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('endpoint',''))" "$cfg" 2>/dev/null || echo "")
  LOCAL_ADDR=$(python3 -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('local_address',''))" "$cfg" 2>/dev/null || echo "")
  PRIV_KEY=$(python3   -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('private_key',''))" "$cfg" 2>/dev/null || echo "")
  ALLOWED=$(python3    -c "import sys,json; d=json.loads(sys.argv[1]); print(','.join(d.get('allowed_ips',[])))" "$cfg" 2>/dev/null || echo "")
  KEEPALIVE=$(python3  -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('persistent_keepalive',25))" "$cfg" 2>/dev/null || echo "25")

  if [ -z "$SERVER_PUB" ] || [ -z "$ENDPOINT" ]; then
    log "UniFi apply: missing server_public_key or endpoint in config, skipping"
    return 1
  fi

  unifi_login

  local payload
  payload=$(python3 -c "
import json, sys
d = {
  'name': 'FloppyGuard',
  'vpn_type': 'wireguard-client',
  'private_key': sys.argv[1],
  'server_public_key': sys.argv[2],
  'server_address': sys.argv[3],
  'local_wg_address': sys.argv[4],
  'allowed_ips': sys.argv[5].split(',') if sys.argv[5] else [],
  'persistent_keepalive': int(sys.argv[6]),
  'enabled': bool(sys.argv[5])
}
print(json.dumps(d))
" "$PRIV_KEY" "$SERVER_PUB" "$ENDPOINT" "$LOCAL_ADDR" "$ALLOWED" "$KEEPALIVE" 2>/dev/null)

  # Check if a FloppyGuard VPN entry already exists
  VPN_ID=$(unifi_find_vpn "FloppyGuard")

  if [ -n "$VPN_ID" ]; then
    # Update existing entry
    curl -sk -b /tmp/fg_unifi_cookie -X PUT \\
      -H "Content-Type: application/json" \\
      -d "$payload" \\
      "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/vpnclient/$VPN_ID" > /dev/null 2>&1 && \\
      log "Updated UniFi WireGuard VPN client (id: $VPN_ID)" || \\
      log "Warning: UniFi VPN update failed"
  else
    # Create new entry
    curl -sk -b /tmp/fg_unifi_cookie -X POST \\
      -H "Content-Type: application/json" \\
      -d "$payload" \\
      "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/vpnclient" > /dev/null 2>&1 && \\
      log "Created UniFi WireGuard VPN client" || \\
      log "Warning: UniFi VPN create failed"
  fi

  # Add firewall rules for each allowed_ip network (traffic policy: accept on WAN_IN)
  # This ensures return traffic from the WireGuard networks is allowed through the firewall
  if [ -n "$ALLOWED" ]; then
    IFS=',' read -ra NETS <<< "$ALLOWED"
    for net in "\${NETS[@]}"; do
      net=$(echo "$net" | tr -d ' ')
      # Check if rule already exists
      EXISTING_RULE=$(curl -sk -b /tmp/fg_unifi_cookie \\
        "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/firewallrule" 2>/dev/null |
        python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('data', [])
for item in items:
    if item.get('name') == 'FG-WG-' + sys.argv[1]:
        print(item.get('_id',''))
        sys.exit(0)
" "$net" 2>/dev/null || echo "")

      if [ -z "$EXISTING_RULE" ]; then
        FW_PAYLOAD=$(python3 -c "
import json, sys
d = {
  'name': 'FG-WG-' + sys.argv[1],
  'ruleset': 'WAN_IN',
  'rule_index': 4100,
  'action': 'accept',
  'enabled': True,
  'protocol': 'all',
  'src_firewallgroup_ids': [],
  'dst_firewallgroup_ids': [],
  'src_address': sys.argv[1],
  'dst_address': '',
  'state_new': True,
  'state_established': True,
  'state_related': True,
  'icmp_typename': ''
}
print(json.dumps(d))
" "$net" 2>/dev/null)
        curl -sk -b /tmp/fg_unifi_cookie -X POST \\
          -H "Content-Type: application/json" \\
          -d "$FW_PAYLOAD" \\
          "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/firewallrule" > /dev/null 2>&1 && \\
          log "Added firewall rule for WireGuard network $net" || \\
          log "Warning: firewall rule for $net could not be added"
      fi
    done
  fi

  # Remove stale FG-WG-* firewall rules for networks no longer in allowed_ips.
  # The VPN client's allowed_ips is replaced wholesale on each apply, but the
  # firewall rules were only ever added — without this, a removed network leaves
  # its accept-on-WAN_IN rule lingering forever (over-permissive cruft that
  # accumulates). Mirrors the native sync_routes stale-route reconciler.
  curl -sk -b /tmp/fg_unifi_cookie \\
    "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/firewallrule" 2>/dev/null |
    python3 -c "
import sys, json
data = json.load(sys.stdin)
keep = set(n for n in sys.argv[1].split(',') if n)
for item in data.get('data', []):
    name = item.get('name', '')
    if name.startswith('FG-WG-') and name[6:] not in keep:
        print(item.get('_id', ''))
" "$ALLOWED" 2>/dev/null | while read -r stale_id; do
      [ -z "$stale_id" ] && continue
      curl -sk -b /tmp/fg_unifi_cookie -X DELETE \\
        "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/firewallrule/$stale_id" > /dev/null 2>&1 && \\
        log "Removed stale FloppyGuard firewall rule $stale_id" || true
    done
}`;

	const applyFunction = mode === "unifi" ? applyFunctionUnifi : applyFunctionNative;

	// For UniFi mode, config applies using JSON; no wg_interface needed in apply call
	const applyCallNative = `apply_config "$CFG" "$IFACE"`;
	const applyCallUnifi = `apply_config "$CFG"`;
	const applyCall = mode === "unifi" ? applyCallUnifi : applyCallNative;

	return `#!/bin/bash
set -euo pipefail
source /etc/floppyguard-agent/config.env
# Default the UniFi vars so a unifi-built script self-updated onto a native
# agent's config.env (which never had them written) does not abort under set -u
# and crash-loop via systemd. Missing creds just fail unifi_login gracefully.
: "\${UNIFI_URL:=}"
: "\${UNIFI_USER:=}"
: "\${UNIFI_PASS:=}"
: "\${UNIFI_SITE:=default}"

SCRIPT_VERSION="${AGENT_SCRIPT_VERSION}"
HASH_FILE="/var/lib/floppyguard-agent/last_hash"
mkdir -p /var/lib/floppyguard-agent

log() { echo "[$(date -Iseconds)] floppyguard-agent[$AGENT_MODE]: $*" >&2; }
reach() { curl -sf --max-time 5 "$1/api" > /dev/null 2>&1; }
get_server() {
  if reach "$PRIMARY_URL"; then echo "$PRIMARY_URL"; return; fi
  if reach "$FALLBACK_URL"; then echo "$FALLBACK_URL"; return; fi
  echo ""
}
rotate_token() {
  local new_token="$1"
  FGTOKEN="$new_token"
  sed -i "s|^FGTOKEN=.*|FGTOKEN=\\"$new_token\\"|" /etc/floppyguard-agent/config.env
  log "Token rotated to permanent agent_token"
}
# Adopt hub URLs pushed by the server so a hub domain change reaches every agent
# that can still reach the hub on at least one of its current URLs. Only updates
# on a non-empty, changed value — never wipes a working URL with an empty one.
# Replace KEY="..." in config.env, or append it if the line doesn't exist yet
# (older agents may predate a given key — sed alone would silently no-op).
upsert_env() {
  local key="$1" val="$2"
  if grep -q "^$key=" /etc/floppyguard-agent/config.env; then
    sed -i "s|^$key=.*|$key=\\"$val\\"|" /etc/floppyguard-agent/config.env
  else
    printf '%s="%s"\\n' "$key" "$val" >> /etc/floppyguard-agent/config.env
  fi
}
update_server_urls() {
  local new_primary="$1" new_fallback="$2"
  # Only adopt a server-advertised URL once it actually answers. A typo in the hub
  # setting would otherwise brick every agent — it can't reach the hub to fetch a
  # corrected URL. Verify reachability before persisting; keep the working one until
  # the new one is live (eventually consistent across the domain move).
  if [ -n "$new_primary" ] && [ "$new_primary" != "$PRIMARY_URL" ] && reach "$new_primary"; then
    PRIMARY_URL="$new_primary"
    upsert_env PRIMARY_URL "$new_primary"
    log "Primary URL updated from hub to $new_primary"
  fi
  if [ -n "$new_fallback" ] && [ "$new_fallback" != "$FALLBACK_URL" ] && reach "$new_fallback"; then
    FALLBACK_URL="$new_fallback"
    upsert_env FALLBACK_URL "$new_fallback"
    log "Fallback URL updated from hub to $new_fallback"
  fi
}

${applyFunction}

# ── Service discovery ────────────────────────────────────────────────────────
# port:scheme:fallback_name  (https ports use https scheme)
SCAN_PORTS="80:http:Web 443:https:Web 3000:http:Grafana 8080:http:UniFi Network 8443:https:UniFi Network 8888:http:Management UI 9000:http:Portainer 9443:https:Portainer 9090:http:Prometheus 1880:http:Node-RED 10000:http:Webmin 8000:http:Web UI"

SERVICES_JSON="[]"
SERVICES_SCAN_INTERVAL=86400  # scan once a day
LAST_SCAN=0
# Register-retry backoff: /api/agent/register is IP-rate-limited (10/15min) and
# the limiter is shared across agents behind the same NAT, so retrying every poll
# would exhaust the bucket and block legitimate registrations. Retry at most once
# per REGISTER_RETRY_INTERVAL seconds.
LAST_REG_ATTEMPT=0
REGISTER_RETRY_INTERVAL=300

scan_services() {
  # Use only LAN IP (default route src) — browser-clickable, not WireGuard IP
  local host_ip
  host_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \\K\\S+' | head -1 || true)
  [ -z "$host_ip" ] && { log "Service scan: no LAN IP found, skipping"; return; }

  local found="[]"
  for entry in $SCAN_PORTS; do
    local port scheme fallback_name
    port=$(echo "$entry" | cut -d: -f1)
    scheme=$(echo "$entry" | cut -d: -f2)
    fallback_name=$(echo "$entry" | cut -d: -f3- | tr ':' ' ')
    # Quick TCP check via curl timeout
    code=$(curl -sk --max-time 2 -o /dev/null -w "%{http_code}" "$scheme://$host_ip:$port/" 2>/dev/null || echo "000")
    [ "$code" = "000" ] && continue
    # Fetch page title — skip if empty or 404-like
    title=$(curl -skL --max-time 4 "$scheme://$host_ip:$port/" 2>/dev/null \\
      | grep -oP '(?<=<title>)[^<]+' | head -1 | tr -d '\\r\\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-60 || true)
    [ -z "$title" ] && continue
    echo "$title" | grep -qiE '^(404|not found|error|default page)' && continue
    url="$scheme://$host_ip:$port"
    found=$(python3 -c "
import sys, json
arr = json.loads(sys.argv[1])
url, name = sys.argv[2], sys.argv[3]
if not any(s['url'] == url for s in arr):
    arr.append({'name': name, 'url': url})
print(json.dumps(arr))
" "$found" "$url" "$title" 2>/dev/null || echo "$found")
  done
  SERVICES_JSON="$found"
  log "Service scan: $(echo "$found" | python3 -c 'import sys,json; a=json.load(sys.stdin); print(len(a))' 2>/dev/null || echo 0) services found on $host_ip"
}

while true; do
  # Periodic service scan
  NOW=$(date +%s)
  if [ $((NOW - LAST_SCAN)) -ge $SERVICES_SCAN_INTERVAL ]; then
    scan_services
    LAST_SCAN=$(date +%s)
  fi

  SERVER=$(get_server)
  if [ -n "$SERVER" ]; then
    RESPONSE=$(curl -sf --max-time 10 \\
      -H "Authorization: Bearer $FGTOKEN" \\
      "$SERVER/api/agent/config" 2>/dev/null) || true

    # ── Register-retry: /config rejected us but the hub is reachable. The initial
    # install registration may never have completed (FGTOKEN is still the
    # reg_token). Try exchanging it; harmless no-op if FGTOKEN is already a valid
    # agent_token (the hub rejects and returns no agent_token).
    if [ -z "$RESPONSE" ] && [ $((NOW - LAST_REG_ATTEMPT)) -ge $REGISTER_RETRY_INTERVAL ]; then
      LAST_REG_ATTEMPT=$NOW
      REG=$(curl -sf --max-time 10 -X POST -H "Content-Type: application/json" \\
        -d "{\\"reg_token\\":\\"$FGTOKEN\\"}" "$SERVER/api/agent/register" 2>/dev/null) || true
      if [ -n "$REG" ]; then
        RETRY_TOKEN=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('agent_token') or '')" "$REG" 2>/dev/null || echo "")
        if [ -n "$RETRY_TOKEN" ]; then
          rotate_token "$RETRY_TOKEN"
          log "Recovered registration on poll"
          RESPONSE=$(curl -sf --max-time 10 \\
            -H "Authorization: Bearer $FGTOKEN" \\
            "$SERVER/api/agent/config" 2>/dev/null) || true
        fi
      fi
    fi

    if [ -n "$RESPONSE" ]; then
      NEW_HASH=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('config_hash') or '')" "$RESPONSE" 2>/dev/null || echo "")
      CURRENT_HASH=$(cat "$HASH_FILE" 2>/dev/null || echo "")
      NEW_TOKEN=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('agent_token') or '')" "$RESPONSE" 2>/dev/null || echo "")

      [ -n "$NEW_TOKEN" ] && [ "$NEW_TOKEN" != "$FGTOKEN" ] && rotate_token "$NEW_TOKEN"

      # ── Hub-URL propagation: adopt server-advertised URLs ──────────────────────
      NEW_PRIMARY=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('primary_url') or '')" "$RESPONSE" 2>/dev/null || echo "")
      NEW_FALLBACK=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('fallback_url') or '')" "$RESPONSE" 2>/dev/null || echo "")
      update_server_urls "$NEW_PRIMARY" "$NEW_FALLBACK"

      # ── Script self-update FIRST (before config apply) ─────────────────────────
      # Must run before config apply so agents get bug fixes (like PrivateKey
      # preservation) before attempting to apply a new config.
      SCRIPT_VERSION_SERVER=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('script_version') or '')" "$RESPONSE" 2>/dev/null || echo "")
      if [ -n "$SCRIPT_VERSION_SERVER" ] && [ "$SCRIPT_VERSION_SERVER" != "$SCRIPT_VERSION" ]; then
        log "Script update available ($SCRIPT_VERSION → $SCRIPT_VERSION_SERVER), downloading..."
        HEADERS_FILE=$(mktemp /tmp/fg_headers.XXXXXX)
        NEW_SCRIPT=$(curl -sf --max-time 30 -D "$HEADERS_FILE" \\
          -H "Authorization: Bearer $FGTOKEN" \\
          "$SERVER/api/agent/loop-script" 2>/dev/null) || NEW_SCRIPT=""
        SERVER_SIG=$(grep -i '^X-Script-Signature:' "$HEADERS_FILE" 2>/dev/null | sed 's/^[^:]*: *//' | tr -d '\\r\\n' || echo "")
        rm -f "$HEADERS_FILE"
        if [ -n "$NEW_SCRIPT" ] && echo "$NEW_SCRIPT" | head -1 | grep -q '^#!'; then
          LOCAL_SIG=$(printf '%s' "$NEW_SCRIPT" | openssl dgst -sha256 -hmac "$FGTOKEN" 2>/dev/null | awk '{print $NF}')
          if [ -n "$SERVER_SIG" ] && [ "$LOCAL_SIG" = "$SERVER_SIG" ]; then
            printf '%s\\n' "$NEW_SCRIPT" > /tmp/fg_loop_update
            chmod +x /tmp/fg_loop_update
            cp /tmp/fg_loop_update /usr/local/sbin/floppyguard-agent
            rm -f /tmp/fg_loop_update
            log "Script updated to version $SCRIPT_VERSION_SERVER (signature verified), restarting..."
            exec /usr/local/sbin/floppyguard-agent
          else
            log "Script signature verification failed, rejecting update (expected=$SERVER_SIG got=$LOCAL_SIG)"
          fi
        else
          log "Script update download failed or invalid, skipping"
        fi
      fi

      if [ -n "$NEW_HASH" ] && [ "$NEW_HASH" != "$CURRENT_HASH" ]; then
        CFG=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('config_text') or '')" "$RESPONSE" 2>/dev/null || echo "")
        IFACE=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('wg_interface','wg0'))" "$RESPONSE" 2>/dev/null || echo "wg0")
        if [ -n "$CFG" ]; then
          ${applyCall}
          echo "$NEW_HASH" > "$HASH_FILE"
        fi
      fi

      # ── Upload local config if server has none ──────────────────────────────────
      if [ -z "$NEW_HASH" ]; then
        IFACE=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('wg_interface','wg0'))" "$RESPONSE" 2>/dev/null || echo "wg0")
        CONF_FILE="/etc/wireguard/$IFACE.conf"
        if [ -f "$CONF_FILE" ]; then
          LOCAL_CFG=$(cat "$CONF_FILE" 2>/dev/null | sed 's/PrivateKey = .*/PrivateKey = (hidden)/')
          if [ -n "$LOCAL_CFG" ]; then
            UPLOAD=$(python3 -c "import sys,json; print(json.dumps({'config_text': sys.argv[1]}))" "$LOCAL_CFG" 2>/dev/null || echo "")
            if [ -n "$UPLOAD" ]; then
              curl -sf --max-time 10 -X POST \\
                -H "Authorization: Bearer $FGTOKEN" \\
                -H "Content-Type: application/json" \\
                -d "$UPLOAD" \\
                "$SERVER/api/agent/upload-config" > /dev/null 2>&1 && \\
                log "Uploaded local $IFACE config to hub" || true
            fi
          fi
        fi
      fi

      MY_HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "")
      MY_LAN_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \\K\\S+' | head -1 || echo "")
      HEARTBEAT=$(python3 -c "
import sys, json
print(json.dumps({'hash': sys.argv[1], 'server': sys.argv[2], 'services': json.loads(sys.argv[3]), 'hostname': sys.argv[4], 'lan_ip': sys.argv[5], 'script_version': sys.argv[6]}))
" "$NEW_HASH" "$SERVER" "$SERVICES_JSON" "$MY_HOSTNAME" "$MY_LAN_IP" "$SCRIPT_VERSION" 2>/dev/null || echo "{\\"hash\\":\\"$NEW_HASH\\",\\"server\\":\\"$SERVER\\"}")

      curl -sf --max-time 5 -X POST \\
        -H "Authorization: Bearer $FGTOKEN" \\
        -H "Content-Type: application/json" \\
        -d "$HEARTBEAT" \\
        "$SERVER/api/agent/heartbeat" > /dev/null 2>&1 || true
    fi
  else
    log "No server reachable (primary: $PRIMARY_URL, fallback: $FALLBACK_URL)"
  fi
  sleep "$POLL_INTERVAL"
done`;
}

const internalAgent = {
	// Start background timers (service scan + config reconciler). Called once by the
	// server entrypoint (index.js), never on import — keeps tests/CLI timer-free.
	startBackgroundTasks,

	// ─── Admin methods (JWT-authenticated) ──────────────────────────────────────

	/**
	 * Returns all non-deleted agents (without agent_token for security).
	 *
	 * @returns {Promise<Agent[]>}
	 */
	async getAll() {
		const agents = await Agent.query()
			.where("is_deleted", 0)
			.select(
				"id",
				"name",
				"hostname",
				"wg_interface",
				"config_text",
				"config_hash",
				"mgmt_url",
				"services",
				"wg_link_name",
				"reg_token",
				"last_seen",
				"status",
				"agent_version",
				"allowed_sites",
				"allowed_networks",
				"last_server_url",
				"created_on",
				"modified_on",
			)
			.orderBy("created_on", "asc");
		return agents.map(parseAgentServices);
	},

	/**
	 * Returns a single agent by id (without agent_token).
	 *
	 * @param {number} id
	 * @returns {Promise<Agent>}
	 */
	async getById(id) {
		const agent = await Agent.query()
			.where("id", id)
			.where("is_deleted", 0)
			.select(
				"id",
				"name",
				"hostname",
				"wg_interface",
				"config_text",
				"config_hash",
				"mgmt_url",
				"services",
				"wg_link_name",
				"reg_token",
				"last_seen",
				"status",
				"agent_version",
				"allowed_sites",
				"allowed_networks",
				"last_server_url",
				"created_on",
				"modified_on",
			)
			.first();

		if (!agent) {
			throw new error.ItemNotFoundError(id);
		}

		return parseAgentServices(agent);
	},

	/**
	 * Creates a new agent with a fresh reg_token. Returns the full record
	 * including reg_token (shown once).
	 *
	 * @param {Object} data
	 * @returns {Promise<Agent>}
	 */
	async create(data) {
		if (data.wg_link_name) {
			const metadata = await internalWireGuard.readMetadataStore();
			const matches = Object.values(metadata.links || {}).filter((l) => l.name === data.wg_link_name);
			if (matches.length > 1) {
				throw new error.ValidationError(
					`wg_link_name "${data.wg_link_name}" matches ${matches.length} links — resolve duplicate link names before assigning`,
				);
			}
		}

		const reg_token = randomToken(32);
		const config_hash = hashConfig(data.config_text);

		const unifi = {};
		sanitizeUnifiFields(data, unifi);

		const agent = await Agent.query().insertAndFetch({
			name: data.name,
			mode: sanitizeAgentMode(data.mode),
			reg_token,
			agent_token: null,
			hostname: data.hostname || null,
			wg_interface: sanitizeWgInterface(data.wg_interface),
			config_text: data.config_text || null,
			config_hash,
			mgmt_url: data.mgmt_url || null,
			wg_link_name: data.wg_link_name || null,
			unifi_url: unifi.unifi_url ?? null,
			unifi_user: unifi.unifi_user ?? null,
			unifi_pass: unifi.unifi_pass ?? null,
			unifi_site: unifi.unifi_site ?? "default",
			last_seen: null,
			status: "pending",
			is_deleted: false,
		});

		return agent;
	},

	/**
	 * Updates name, wg_interface, and/or config_text. Recalculates config_hash
	 * when config_text changes.
	 *
	 * @param {number}  id
	 * @param {Object}  data
	 * @returns {Promise<Agent>}
	 */
	async update(id, data) {
		const existing = await Agent.query().where("id", id).where("is_deleted", 0).first();

		if (!existing) {
			throw new error.ItemNotFoundError(id);
		}

		if (data.wg_link_name && data.wg_link_name !== existing.wg_link_name) {
			const metadata = await internalWireGuard.readMetadataStore();
			const matches = Object.values(metadata.links || {}).filter((l) => l.name === data.wg_link_name);
			if (matches.length > 1) {
				throw new error.ValidationError(
					`wg_link_name "${data.wg_link_name}" matches ${matches.length} links — resolve duplicate link names before assigning`,
				);
			}
		}

		const patch = {};

		if (typeof data.name !== "undefined") {
			patch.name = data.name;
		}
		if (typeof data.wg_interface !== "undefined") {
			patch.wg_interface = sanitizeWgInterface(data.wg_interface);
		}
		if (typeof data.mode !== "undefined") patch.mode = sanitizeAgentMode(data.mode);
		if (typeof data.config_text !== "undefined") {
			patch.config_text = data.config_text;
			patch.config_hash = hashConfig(data.config_text);
		}
		if (typeof data.mgmt_url !== "undefined") patch.mgmt_url = data.mgmt_url || null;
		if (typeof data.wg_link_name !== "undefined") patch.wg_link_name = data.wg_link_name || null;
		sanitizeUnifiFields(data, patch);
		if (typeof data.allowed_sites !== "undefined") {
			const sites = sanitizeAclSites(data.allowed_sites);
			patch.allowed_sites = sites ? JSON.stringify(sites) : null;
		}
		if (typeof data.allowed_networks !== "undefined") {
			const nets = sanitizeAclNetworks(data.allowed_networks);
			patch.allowed_networks = nets ? JSON.stringify(nets) : null;
		}

		// Detect changes that alter which networks belong in this agent's hub-peer
		// AllowedIPs, so the pushed config_text must be resynced. ACL changes AND
		// wg_link_name (rebinding to another link flips ownNets→otherSiteNets entirely).
		const needsResync =
			(typeof patch.allowed_networks !== "undefined" && patch.allowed_networks !== existing.allowed_networks) ||
			(typeof patch.allowed_sites !== "undefined" && patch.allowed_sites !== existing.allowed_sites) ||
			(typeof patch.wg_link_name !== "undefined" && patch.wg_link_name !== existing.wg_link_name);

		await Agent.query().patchAndFetchById(id, patch);

		// Propagate the change into config_text so the agent picks it up on its next
		// poll. Best-effort: never fail the update if the sync hiccups.
		if (needsResync) {
			try {
				// Read-recompute-write must be atomic w.r.t. concurrent peer
				// mutations. syncAgentConfigs rewrites EVERY agent's stored config
				// from the metadata snapshot, so an unlocked read could grab a
				// pre-delete snapshot and land last, re-advertising a just-removed
				// network fleet-wide (re-granting revoked cross-site access). Hold
				// the same write lock every other syncAgentConfigs caller takes
				// (createPeer/deletePeer/reconciler).
				await withWriteLock(async () => {
					const metadata = await internalWireGuard.readMetadataStore();
					await this.syncAgentConfigs(metadata);
				});
			} catch (err) {
				// Sync is best-effort; the next metadata apply will reconcile. Log it
				// so a poisoned sibling ACL (which makes syncAgentConfigs throw) is
				// visible instead of silently leaving config_text stale.
				logger.error(`Agent ${id}: ACL updated but config sync failed — ${err.message}`);
			}
		}

		return this.getById(id);
	},

	/**
	 * Cascade a link rename to agent bindings. Agents reference a link by its
	 * MUTABLE name — `wg_link_name` (column) and `allowed_sites` (whitelist). A
	 * rename without this migration silently orphans every bound agent: it gets
	 * skipped on every later sync ("no-link-or-config") and freezes on its last
	 * config, so future add/remove never reach it.
	 *
	 * @param {string} oldName
	 * @param {string} newName
	 * @returns {Promise<{wgLinkName:number, allowedSites:number}>}
	 */
	async renameLinkBinding(oldName, newName) {
		if (!oldName || !newName || oldName === newName) return { wgLinkName: 0, allowedSites: 0 };
		// MySQL's default collation is case-insensitive, but link names are matched
		// case-sensitively everywhere else (linksByName, the allowed_sites cascade
		// below). Re-filter the WHERE result to EXACT case so an "office"-bound agent
		// is not silently rebound by an unrelated "Office"→… rename.
		let wgLinkName = 0;
		const bound = await Agent.query().where("wg_link_name", oldName);
		for (const a of bound) {
			if (a.wg_link_name !== oldName) continue; // case-insensitive WHERE over-matched
			await Agent.query().patchAndFetchById(a.id, { wg_link_name: newName });
			wgLinkName++;
		}
		let allowedSites = 0;
		const agents = await Agent.query().where("is_deleted", 0).whereNotNull("allowed_sites");
		for (const a of agents) {
			let sites;
			try {
				sites = JSON.parse(a.allowed_sites);
			} catch {
				continue;
			}
			if (!Array.isArray(sites) || !sites.includes(oldName)) continue;
			const next = sites.map((s) => (s === oldName ? newName : s));
			await Agent.query().patchAndFetchById(a.id, { allowed_sites: JSON.stringify(next) });
			allowedSites++;
		}
		if (wgLinkName || allowedSites) {
			logger.info(`Link rename "${oldName}" → "${newName}": migrated ${wgLinkName} wg_link_name + ${allowedSites} allowed_sites binding(s)`);
		}
		return { wgLinkName, allowedSites };
	},

	/**
	 * Soft-deletes an agent.
	 *
	 * @param {number} id
	 * @returns {Promise<boolean>}
	 */
	async delete(id) {
		const existing = await Agent.query().where("id", id).where("is_deleted", 0).first();

		if (!existing) {
			throw new error.ItemNotFoundError(id);
		}

		await Agent.query().patchAndFetchById(id, { is_deleted: true });
		return true;
	},

	/**
	 * Generates a fresh reg_token for an existing agent so it can be reinstalled.
	 * Clears agent_token and resets status to pending.
	 *
	 * @param {number} id
	 * @returns {Promise<{ reg_token: string }>}
	 */
	async resetToken(id) {
		const existing = await Agent.query().where("id", id).where("is_deleted", 0).first();

		if (!existing) {
			throw new error.ItemNotFoundError(id);
		}

		const reg_token = randomToken(32);
		await Agent.query().patchAndFetchById(id, {
			reg_token,
			agent_token: null,
			status: "pending",
		});

		return this.getById(id);
	},

	/**
	 * Returns a bash install script for the agent as a plain-text string.
	 *
	 * @param {number} id
	 * @param {string} publicUrl   e.g. "https://proxy.example.com"
	 * @param {string} tunnelUrl   e.g. "http://10.8.0.1:3300"
	 * @returns {Promise<string>}
	 */
	async getInstallScript(id, publicUrl, tunnelUrl) {
		// publicUrl/tunnelUrl are interpolated into DOUBLE-QUOTED config.env lines that
		// are `source`d as root by the agent loop. Use the same strict validator as the
		// hub-URL propagation sink (sanitizeHubUrl) — the old inline guard missed `"`
		// and whitespace, so `https://a/x" <cmd>"` broke out of the quotes and executed
		// <cmd> as root. Reassign to the sanitized (trimmed) value actually emitted.
		let cleanPublic = publicUrl;
		let cleanTunnel = tunnelUrl;
		if (publicUrl) {
			cleanPublic = sanitizeHubUrl(publicUrl);
			if (!cleanPublic) throw new error.ValidationError("public_url must be a valid http(s) URL without shell metacharacters");
		}
		if (tunnelUrl) {
			cleanTunnel = sanitizeHubUrl(tunnelUrl);
			if (!cleanTunnel) throw new error.ValidationError("tunnel_url must be a valid http(s) URL without shell metacharacters");
		}

		const agent = await Agent.query().where("id", id).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.ItemNotFoundError(id);
		}

		const regToken = agent.reg_token || "";
		// Re-validate at the sink: these are interpolated into the root-sourced
		// config.env heredoc below, so a poisoned row (pre-validation data) must
		// never reach it. create()/update() enforce the same whitelist on write.
		const wgInterface = sanitizeWgInterface(agent.wg_interface);
		const mode = sanitizeAgentMode(agent.mode);
		// Re-validate the UniFi fields at the sink too: they are interpolated raw
		// into the same root-sourced config.env heredoc (UNIFI_PASS="...") and a
		// legacy row written before sanitizeUnifiFields existed (pre-v1.3.21) may
		// carry a quote/newline/$/backtick that closes the assignment and injects
		// shell as root. sanitizeUnifiFields throws on such a poisoned row.
		const unifiPatch = {};
		sanitizeUnifiFields(agent, unifiPatch);
		const unifiUrl = unifiPatch.unifi_url || "";
		const unifiUser = unifiPatch.unifi_user || "";
		const unifiPass = unifiPatch.unifi_pass || "";
		const unifiSite = unifiPatch.unifi_site || "default";

		// Extra env vars for UniFi mode
		const unifiEnvLines =
			mode === "unifi"
				? `UNIFI_URL="${unifiUrl}"\nUNIFI_USER="${unifiUser}"\nUNIFI_PASS="${unifiPass}"\nUNIFI_SITE="${unifiSite}"\n`
				: "";

		const loopScript = buildLoopScript(mode);

		const installScript = `#!/bin/bash
set -euo pipefail

echo "[floppyguard-agent] Installing FloppyGuard agent (mode: ${mode}, ID: ${id})..."

# ── 1. Directories ──────────────────────────────────────────────────────────────
mkdir -p /etc/floppyguard-agent /var/lib/floppyguard-agent

# ── 2. config.env ───────────────────────────────────────────────────────────────
cat > /etc/floppyguard-agent/config.env << 'ENVEOF'
FGTOKEN="${regToken}"
PRIMARY_URL="${cleanTunnel}"
FALLBACK_URL="${cleanPublic}"
FGAGENT_ID="${id}"
AGENT_MODE="${mode}"
WG_INTERFACE="${wgInterface}"
POLL_INTERVAL=30
${unifiEnvLines}ENVEOF
chmod 600 /etc/floppyguard-agent/config.env

# ── 3. Initial registration ─────────────────────────────────────────────────────
echo "[floppyguard-agent] Registering with FloppyGuard..."
REGISTER_RESPONSE=$(curl -sf --max-time 15 \\
  -X POST -H "Content-Type: application/json" \\
  -d '{"reg_token":"${regToken}"}' \\
  "${cleanPublic}/api/agent/register" 2>/dev/null) || true

if [ -n "$REGISTER_RESPONSE" ]; then
  AGENT_TOKEN=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('agent_token',''))" "$REGISTER_RESPONSE" 2>/dev/null || echo "")
  if [ -n "$AGENT_TOKEN" ]; then
    sed -i "s|^FGTOKEN=.*|FGTOKEN=\\"$AGENT_TOKEN\\"|" /etc/floppyguard-agent/config.env
    echo "[floppyguard-agent] Registration successful."
  else
    echo "[floppyguard-agent] Warning: no agent_token in response; will retry on first poll."
  fi
else
  echo "[floppyguard-agent] Warning: registration unreachable; will retry on first poll."
fi

# ── 4. Agent loop script ────────────────────────────────────────────────────────
cat > /usr/local/sbin/floppyguard-agent << 'SCRIPTEOF'
${loopScript}
SCRIPTEOF
chmod +x /usr/local/sbin/floppyguard-agent

# ── 5. Systemd unit ─────────────────────────────────────────────────────────────
cat > /etc/systemd/system/floppyguard-agent.service << 'UNITEOF'
[Unit]
Description=FloppyGuard Remote Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/floppyguard-agent
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=floppyguard-agent

[Install]
WantedBy=multi-user.target
UNITEOF

# ── 6. Enable + start ───────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now floppyguard-agent

echo ""
echo "[floppyguard-agent] Done. Mode: ${mode}"
echo "[floppyguard-agent]   systemctl status floppyguard-agent"
echo "[floppyguard-agent]   journalctl -u floppyguard-agent -f"
`;

		return installScript;
	},

	/**
	 * Same as getInstallScript but looks up the agent by reg_token (no JWT needed).
	 *
	 * @param {string} regToken
	 * @param {string} publicUrl
	 * @param {string} tunnelUrl
	 * @returns {Promise<string>}
	 */
	async getInstallScriptByToken(regToken, publicUrl, tunnelUrl) {
		const agent = await Agent.query().where("reg_token", regToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid registration token", "error.auth");
		}

		return this.getInstallScript(agent.id, publicUrl, tunnelUrl);
	},

	// ─── Agent methods (agent-token-authenticated) ──────────────────────────────

	/**
	 * Exchanges a reg_token for a permanent agent_token. Idempotent: a repeat
	 * register with the same reg_token returns the already-issued agent_token,
	 * so a lost HTTP response doesn't brick the agent (the loop's register-retry
	 * resends the same reg_token). The reg_token is only retired once the agent
	 * proves receipt by authenticating with the agent_token (see getConfig), or
	 * via an admin resetToken().
	 * Returns { agent_token, config_hash }.
	 *
	 * @param {string} regToken
	 * @returns {Promise<{ agent_token: string, config_hash: string|null }>}
	 */
	async register(regToken) {
		const agent = await Agent.query().where("reg_token", regToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid registration token", "error.auth");
		}

		let agent_token = agent.agent_token;
		if (!agent_token) {
			agent_token = randomToken(32);
			await Agent.query().patchAndFetchById(agent.id, {
				agent_token,
				status: "active",
			});
		}

		return {
			agent_token,
			agent_id: agent.id,
			config_hash: agent.config_hash || null,
		};
	},

	/**
	 * Returns config for the agent identified by agent_token.
	 *
	 * @param {string} agentToken
	 * @returns {Promise<{ config_text: string|null, config_hash: string|null, wg_interface: string, poll_interval: number }>}
	 */
	async getConfig(agentToken) {
		const agent = await Agent.query().where("agent_token", agentToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid agent token", "error.auth");
		}

		// The agent has proven receipt of its agent_token, so the registration
		// exchange is complete — retire the single-use reg_token now. register()
		// keeps it valid until this point so a lost register response can be
		// recovered by the loop's register-retry instead of bricking the agent.
		if (agent.reg_token) {
			await Agent.query().patchAndFetchById(agent.id, { reg_token: null });
		}

		const { primaryUrl, fallbackUrl } = await getAgentHubUrls();

		return {
			config_text: agent.config_text || null,
			config_hash: agent.config_hash || null,
			wg_interface: agent.wg_interface || "wg0",
			poll_interval: 30,
			script_version: AGENT_SCRIPT_VERSION,
			// Hub-URL propagation: agents rewrite their config.env when these differ
			// from what they have, so a hub domain change reaches every agent that
			// can still reach the hub on at least one of its current URLs.
			primary_url: primaryUrl,
			fallback_url: fallbackUrl,
		};
	},

	/**
	 * Returns the loop script for the agent identified by agent_token.
	 *
	 * @param {string} agentToken
	 * @returns {Promise<string>}
	 */
	async getLoopScript(agentToken) {
		const agent = await Agent.query().where("agent_token", agentToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid agent token", "error.auth");
		}

		const script = buildLoopScript(agent.mode || "native");
		const signature = signScript(script, agentToken);
		return { script, signature };
	},

	/**
	 * Updates last_seen and status for the agent.
	 *
	 * @param {string} agentToken
	 * @param {Object} data  — { hash, server }
	 * @returns {Promise<{ ok: boolean }>}
	 */
	async heartbeat(agentToken, data) {
		const agent = await Agent.query().where("agent_token", agentToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid agent token", "error.auth");
		}

		const patch = {
			last_seen: Math.floor(Date.now() / 1000),
			status: "active",
		};

		if (data?.hostname) {
			// hostname/lan_ip are agent-controlled (the route applies no schema
			// validation) and feed the service-discovery scanner via
			// extractIpFromText. Strip control chars, only append lan_ip when it is
			// a syntactically valid RFC1918 private IPv4 (so a hostile value can't
			// point the hub's scan at loopback/link-local/public hosts), and clamp
			// to the column width (255) so an oversized value can't throw a MySQL
			// strict-mode "Data too long" that 500s the heartbeat.
			// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional control-char strip of agent-supplied hostname
			const host = String(data.hostname).replace(/[\u0000-\u001f\u007f]/g, "").trim();
			const lanIp = isPrivateIpv4(data.lan_ip) ? ` (${data.lan_ip})` : "";
			patch.hostname = `${host}${lanIp}`.slice(0, 255);
		}

		if (data && Array.isArray(data.services)) {
			patch.services = JSON.stringify(sanitizeAgentServices(data.services));
		}

		if (data?.script_version) {
			// Clamp to the agent_version column width (32) — untrusted input under
			// MySQL strict mode would otherwise throw "Data too long" and 500 the
			// heartbeat, freezing this agent's last_seen/status.
			patch.agent_version = String(data.script_version).slice(0, 32);
		}

		if (data?.server) {
			// Untrusted display-only value: which hub URL the agent reached us on.
			// Clamp length and strip control chars; never used in a shell/sed sink.
			patch.last_server_url = String(data.server).replace(/\s+/g, "").slice(0, 255);
		}

		await Agent.query().patchAndFetchById(agent.id, patch);

		return { ok: true };
	},

	/**
	 * Accepts a config_text upload from an agent. Only stores it if the server
	 * has no config_text for this agent yet (prevents agents from overwriting
	 * server-managed configs).
	 *
	 * @param {string} agentToken
	 * @param {Object} data  — { config_text: string }
	 * @returns {Promise<{ ok: boolean, stored: boolean }>}
	 */
	async uploadConfig(agentToken, data) {
		const agent = await Agent.query().where("agent_token", agentToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid agent token", "error.auth");
		}

		if (agent.config_text) {
			return { ok: true, stored: false, reason: "config-already-exists" };
		}

		if (!data?.config_text?.trim()) {
			return { ok: true, stored: false, reason: "empty-config" };
		}

		let finalConfig = normalizeAgentConfig(data.config_text);
		if (!agent.wg_link_name) {
			// syncAgentConfigs only reconciles agents WITH a wg_link_name (whereNotNull),
			// so an unbound agent's uploaded conf is never re-derived. If it still lists
			// long-removed site networks, the hub would store and re-serve them forever
			// (reinfection). Strip the hub-peer AllowedIPs down to the tunnel subnet +
			// /32 host routes so an unbound agent can't pin stale site nets.
			const tunnelSubnet = deriveTunnelSubnet(finalConfig);
			const hostRoutes = _parseHubPeerAllowedIPs(finalConfig).filter((c) => c.endsWith("/32") || c.endsWith("/128"));
			const safe = [...new Set([tunnelSubnet, ...hostRoutes])].sort();
			finalConfig = normalizeAgentConfig(_rewriteHubPeerAllowedIPs(finalConfig, safe));
		}
		const config_hash = hashConfig(finalConfig);
		await Agent.query().patchAndFetchById(agent.id, {
			config_text: finalConfig,
			config_hash,
		});

		logger.info(`Agent ${agent.name} (id=${agent.id}) uploaded initial config (normalized)`);
		return { ok: true, stored: true };
	},

	/**
	 * Syncs the hub-peer AllowedIPs in each agent's config_text from WireGuard metadata.
	 *
	 * For every agent that has a wg_link_name:
	 *   - Find the matching link in metadata by name
	 *   - Compute new AllowedIPs for the hub peer:
	 *       = (WG-specific entries currently in the config, i.e. not tracked by any link's importedNetworks)
	 *       + (importedNetworks of ALL OTHER links except this agent's own link)
	 *   - If AllowedIPs changed: update config_text + config_hash in DB
	 *
	 * Agents pick up the change automatically on their next poll (every 30 s).
	 *
	 * @param {Object} metadata  — { interfaces, links } from wireguard-metadata.json
	 * @returns {Promise<Array<{ agentId: number, name: string, changed: boolean, newAllowedIPs?: string[] }>>}
	 */
	async syncAgentConfigs(metadata) {
		const agents = await Agent.query().where("is_deleted", 0).whereNotNull("wg_link_name");

		// Detect duplicate link names — if two links share a name, any agent with that
		// wg_link_name is ambiguous and must not receive a potentially wrong config update.
		const nameCount = new Map();
		for (const linkMeta of Object.values(metadata.links || {})) {
			if (linkMeta.name) nameCount.set(linkMeta.name, (nameCount.get(linkMeta.name) || 0) + 1);
		}
		const ambiguousLinkNames = new Set([...nameCount.entries()].filter(([, c]) => c > 1).map(([n]) => n));

		// Index links by name → linkMeta (only for unambiguous names)
		const linksByName = new Map();
		for (const linkMeta of Object.values(metadata.links || {})) {
			if (linkMeta.name && !ambiguousLinkNames.has(linkMeta.name)) {
				linksByName.set(linkMeta.name, linkMeta);
			}
		}

		// The networks that actually live behind the mesh — used to identify "site
		// networks". Only site-to-site links contribute; client links (road-warrior
		// phone/laptop) are excluded (see _collectSiteNetworks for why).
		const allSiteNets = _collectSiteNetworks(metadata.links);

		const results = [];

		for (const agent of agents) {
			// Per-agent isolation: one poisoned link (e.g. an IPv6/host-bits CIDR that
			// trips assertCIDR deep in normalizeAgentConfig) must NOT abort the whole
			// loop and leave every later agent un-resynced. Skip the bad one, keep going.
			try {
				results.push(await _syncOneAgent(agent, { linksByName, allSiteNets, ambiguousLinkNames }));
			} catch (err) {
				logger.error(`syncAgentConfigs: agent ${agent.name} (id=${agent.id}) failed — skipping, other agents unaffected: ${err.message}`);
				results.push({ agentId: agent.id, name: agent.name, changed: false, error: err.message });
			}
		}

		return results;
	},
};

/**
 * Returns the AllowedIPs of the hub peer (first [Peer] section) from a wg-quick config string.
 */
function _parseHubPeerAllowedIPs(configText) {
	let inPeer = false;
	for (const raw of configText.split(/\r?\n/)) {
		const t = raw.trim();
		if (t === "[Peer]") {
			inPeer = true;
			continue;
		}
		if (t.startsWith("[")) {
			inPeer = false;
			continue;
		}
		if (inPeer && t.startsWith("AllowedIPs")) {
			return t
				.slice(t.indexOf("=") + 1)
				.trim()
				.split(",")
				.map((s) => s.trim())
				.filter(Boolean);
		}
	}
	return [];
}

/**
 * Rewrites the AllowedIPs of the first [Peer] section in a wg-quick config string.
 */
function _rewriteHubPeerAllowedIPs(configText, newAllowedIPs) {
	let inPeer = false;
	let replaced = false;
	return configText
		.split(/\r?\n/)
		.map((raw) => {
			const t = raw.trim();
			if (t === "[Peer]") {
				inPeer = true;
				return raw;
			}
			if (t.startsWith("[")) {
				inPeer = false;
				return raw;
			}
			if (inPeer && !replaced && t.startsWith("AllowedIPs")) {
				replaced = true;
				return `AllowedIPs = ${newAllowedIPs.join(", ")}`;
			}
			return raw;
		})
		.join("\n");
}

/**
 * Rewrite the hub [Peer] Endpoint host to the current hub host (WG_HUB_HOST),
 * keeping the existing port. The hub is authoritative for the endpoint just like
 * it is for AllowedIPs, so a hub-domain change (e.g. floppyguard.comnic.de →
 * proxy.comnic.de) propagates to every agent on its next poll instead of leaving
 * the endpoint baked at install time. That stale-endpoint gap is the recurring
 * "tunnel dead after reboot / domain move" class (PVE 2026-06-07, Floppy+Daniel
 * 2026-06-19). Only the host is swapped — the port is preserved, and a line
 * without a trailing :port is left untouched (nothing safe to rewrite).
 *
 * @param {string} configText
 * @param {string} hubHost  e.g. "proxy.comnic.de" (from resolveHubHost())
 * @returns {string}
 */
function _rewriteHubPeerEndpoint(configText, hubHost) {
	if (!configText || !hubHost) return configText;
	let peerIdx = 0;
	let inPeer = false;
	let replaced = false;
	return configText
		.split(/\r?\n/)
		.map((raw) => {
			const t = raw.trim();
			if (t === "[Peer]") {
				peerIdx += 1;
				inPeer = true;
				return raw;
			}
			if (t.startsWith("[")) {
				inPeer = false;
				return raw;
			}
			// Only the hub peer = the FIRST [Peer]. Scoping to peerIdx === 1 (not just
			// a global "replaced" flag) is essential: a port-less or absent hub Endpoint
			// must NOT fall through and clobber a LATER peer's endpoint in a multi-peer
			// (relay/site-to-site) config. Endpoint is optional, so we cannot rely on it
			// always matching the way AllowedIPs does.
			if (inPeer && peerIdx === 1 && !replaced && t.startsWith("Endpoint")) {
				// Endpoint = <host> : <port> [# comment]. Tolerate whitespace around the
				// colon and an optional trailing comment (wg accepts both, and a baked
				// config may carry them); the host group is comment-free. A port-less
				// endpoint does not match and is left untouched.
				const m = t.match(/^Endpoint\s*=\s*([^#]*?)\s*:\s*(\d+)\s*(#.*)?$/);
				if (m) {
					replaced = true;
					const host = m[1];
					const comment = m[3] ? ` ${m[3]}` : "";
					// Don't DOWNGRADE a deliberately-pinned IP literal to a (possibly
					// dual-stack) DNS name — that could re-introduce the AAAA black-hole.
					// But DO rewrite IP→IP when the hub itself moved to a new IP: a real
					// server migration must still propagate to IP-pinned agents.
					const isIp = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith("[");
					if (isIp(host) && !isIp(hubHost)) return raw;
					// Same host (case-insensitive — DNS is) must not flip the hash and
					// needlessly bounce wg0.
					if (host.toLowerCase() === hubHost.toLowerCase()) return raw;
					return `Endpoint = ${hubHost}:${m[2]}${comment}`;
				}
			}
			return raw;
		})
		.join("\n");
}

/**
 * Parses the allowed_sites JSON column. Returns a Set of link names,
 * or null if the field is empty/unset (meaning full-mesh, all sites allowed).
 */
function _parseAllowedSites(raw) {
	if (!raw) return null;
	try {
		const parsed = JSON.parse(raw);
		if (!Array.isArray(parsed) || parsed.length === 0) return null;
		return new Set(parsed.map((s) => String(s).trim()).filter(Boolean));
	} catch {
		return null;
	}
}

/**
 * Collects the set of LAN networks that actually exist behind the mesh — the
 * networks gateways should route to each other.
 *
 * Only site-to-site links contribute. A client link (road-warrior phone/laptop)
 * exports no LAN (exportedNetworks: []), and its importedNetworks is a *reach
 * list* (which sites the client wants to talk to), NOT networks that live behind
 * it. Folding client reach-lists into this set made the hub re-advertise a
 * network to every gateway as long as ANY client still listed it — so removing a
 * subnet from its real site did nothing while a phone still wanted to reach it.
 * Links with no `type` default to site (included) to stay safe on older metadata.
 *
 * @param {Object} links  metadata.links keyed by id
 * @returns {Set<string>} site network CIDRs
 */
function _collectSiteNetworks(links) {
	return new Set(
		Object.values(links || {})
			.filter((l) => l.type !== "client")
			.flatMap((l) => l.importedNetworks || []),
	);
}

/**
 * Recompute and persist one agent's hub-peer config. Extracted from the
 * syncAgentConfigs loop so each agent can be wrapped in its own try/catch — a
 * single failing agent (e.g. an IPv6 net that trips the IPv4-only assertCIDR)
 * must not abort the whole fleet sync. Returns the per-agent result; throws only
 * on a genuine error, which the caller isolates.
 */
async function _syncOneAgent(agent, { linksByName, allSiteNets, ambiguousLinkNames }) {
	if (ambiguousLinkNames.has(agent.wg_link_name)) {
		return { agentId: agent.id, name: agent.name, changed: false, reason: "ambiguous-link-name" };
	}
	const linkMeta = linksByName.get(agent.wg_link_name);
	if (!linkMeta || !agent.config_text) {
		return { agentId: agent.id, name: agent.name, changed: false, reason: "no-link-or-config" };
	}

	// Networks belonging to THIS agent's own site (don't route these through hub)
	const ownNets = new Set(linkMeta.importedNetworks || []);

	// Network access control: allowed_networks > allowed_sites > full-mesh.
	const allowedNetworks = _parseAllowedSites(agent.allowed_networks);
	const allowedSites = _parseAllowedSites(agent.allowed_sites);
	const { nets: otherSiteNets, orphans } = _computeOtherSiteNets({
		allowedNetworks,
		allowedSites,
		allSiteNets,
		ownNets,
		linksByName,
	});
	if (orphans.length) {
		logger.warn(
			`Agent ${agent.name} (id=${agent.id}): allowed_networks references net(s) no site exports anymore: ${orphans.join(", ")}`,
		);
	}

	const currentAllowedIPs = _parseHubPeerAllowedIPs(agent.config_text);
	// The tunnel subnet must ALWAYS remain in AllowedIPs or the tunnel collapses.
	const agentTunnelSubnet = deriveTunnelSubnet(agent.config_text);
	const newAllowedIPs = _computeHubPeerAllowedIPs(agentTunnelSubnet, otherSiteNets);
	const newSorted = newAllowedIPs.join(",");
	const currentSorted = [...currentAllowedIPs].sort().join(",");

	const masqueradeNets = otherSiteNets.filter((n) => !ownNets.has(n));
	masqueradeNets.sort();

	// Hub is authoritative for the [Peer] Endpoint too — rewrite it from
	// WG_HUB_HOST so a hub-domain change reaches every agent's baked config on
	// the next poll (the stale-endpoint-after-reboot class, see
	// _rewriteHubPeerEndpoint). Use configuredHubHost(), NOT resolveHubHost():
	// when WG_HUB_HOST is unset/malformed the latter falls back to the OS hostname
	// ("vpn-hub-comnic") or a whitespace/newline-poisoned value. Since this runs on
	// EVERY sync for EVERY agent, baking such a value would black-hole the whole
	// fleet — so without a clean, explicit WG_HUB_HOST we leave endpoints untouched.
	const hubHost = internalWireGuard.configuredHubHost();
	const allowedRewritten =
		newSorted !== currentSorted ? _rewriteHubPeerAllowedIPs(agent.config_text, newAllowedIPs) : agent.config_text;
	const rewritten = _rewriteHubPeerEndpoint(allowedRewritten, hubHost);
	const endpointChanged = rewritten !== allowedRewritten;
	const allowedChanged = newSorted !== currentSorted;
	const newConfigText = normalizeAgentConfig(rewritten, masqueradeNets);
	const newHash = hashConfig(newConfigText);

	if (newHash === agent.config_hash) {
		return { agentId: agent.id, name: agent.name, changed: false };
	}

	await Agent.query().patchAndFetchById(agent.id, { config_text: newConfigText, config_hash: newHash });
	return { agentId: agent.id, name: agent.name, changed: true, newAllowedIPs, masqueradeNets, endpointChanged, allowedChanged };
}

/**
 * Computes the set of OTHER-site networks an agent may route, applying the
 * deny-by-default ACL priority: allowed_networks > allowed_sites > full-mesh.
 *
 * - allowed_networks: intersect the explicit ACL with the LIVE exported site nets
 *   (allSiteNets). A CIDR no site exports anymore (subnet removed, or a typo) is
 *   dropped — otherwise it stays in AllowedIPs/route/MASQUERADE while the hub no
 *   longer routes it (silent blackhole that never self-prunes). Such entries are
 *   returned as `orphans` so the caller can surface them.
 * - allowed_sites: a whitelist of SITE-link names. Client (road-warrior) links are
 *   skipped — a whitelisted client must not grant site reach via its reach-list.
 * - neither: full mesh (all site nets except own).
 *
 * @returns {{nets: string[], orphans: string[]}}
 */
function _computeOtherSiteNets({ allowedNetworks, allowedSites, allSiteNets, ownNets, linksByName }) {
	if (allowedNetworks) {
		const nets = [...allowedNetworks].filter((n) => !ownNets.has(n) && allSiteNets.has(n));
		const orphans = [...allowedNetworks].filter((n) => !ownNets.has(n) && !allSiteNets.has(n));
		return { nets, orphans };
	}
	const nets = [...allSiteNets].filter((n) => {
		if (ownNets.has(n)) return false;
		if (!allowedSites) return true; // no whitelist = full mesh
		for (const [, lm] of linksByName) {
			if (lm.type !== "client" && allowedSites.has(lm.name) && (lm.importedNetworks || []).includes(n)) return true;
		}
		return false;
	});
	return { nets, orphans: [] };
}

/**
 * Computes the authoritative AllowedIPs for an agent's hub peer.
 *
 * The hub is the single source of truth: an agent may reach exactly the tunnel
 * subnet plus the networks it is allowed to route (otherSiteNets — already
 * ACL-filtered and own-site-stripped by the caller). A network removed from a
 * link drops out of otherSiteNets and is therefore absent here, which is what
 * makes a removal propagate to remote agents. We deliberately do not merge in
 * the agent's current AllowedIPs: a removed network is indistinguishable from a
 * hand-added route, so preserving "unknown" entries made removals permanently
 * sticky.
 *
 * @param {string} agentTunnelSubnet  — e.g. "10.10.0.0/24" (always kept)
 * @param {string[]} otherSiteNets    — networks this agent is allowed to reach
 * @returns {string[]} deduped, sorted AllowedIPs
 */
function _computeHubPeerAllowedIPs(agentTunnelSubnet, otherSiteNets) {
	return [...new Set([agentTunnelSubnet, ...otherSiteNets])].sort();
}

export default internalAgent;

// Exported for unit testing only
export const _testExports = {
	buildHubPostUp,
	buildHubPostDown,
	deriveTunnelSubnet,
	normalizeAgentConfig,
	_parseHubPeerAllowedIPs,
	_rewriteHubPeerAllowedIPs,
	_rewriteHubPeerEndpoint,
	_computeHubPeerAllowedIPs,
	_collectSiteNetworks,
	_computeOtherSiteNets,
	sanitizeUnifiFields,
	sanitizeAgentMode,
	sanitizeWgInterface,
	sanitizeAgentServices,
	_parseAllowedSites,
	assertCIDR,
	sanitizeHubUrl,
	buildLoopScript,
	AGENT_SCRIPT_VERSION,
	sanitizeAclNetworks,
	sanitizeAclSites,
};
