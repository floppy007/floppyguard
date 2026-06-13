import { execFile, execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { hostname, networkInterfaces } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import error from "../lib/error.js";
import { wireguard as logger } from "../logger.js";

const execFileAsync = promisify(execFile);

// ── Module-level mutex for serializing write operations ─────────────────────
// Node.js is single-threaded but async operations interleave. This mutex
// ensures that createPeer, deletePeer, and metadata writes don't overlap,
// preventing race conditions (duplicate tunnel IPs, lost metadata patches).
let _writeLock = Promise.resolve();
function withWriteLock(fn) {
	const next = _writeLock.then(fn, fn);
	_writeLock = next.catch(() => {});
	return next;
}

// Serialize every read-modify-write of the metadata store under the SAME mutex as
// createPeer/applyMetadataPatch. Without this, deletePeer/updateLinkMetadata/etc.
// did an unlocked read→mutate→write (whole-file overwrite): a concurrent save read
// the pre-delete file, merged, and wrote its copy back — resurrecting a
// just-deleted link, which syncAgentConfigs then re-advertised fleet-wide. Returns
// the freshly-written store snapshot; do live wg + syncAgentConfigs OUTSIDE the
// lock (they don't take it). NOT re-entrant — never call from inside withWriteLock.
async function mutateMetadataStore(mutator) {
	return withWriteLock(async () => {
		const store = await readMetadataStore();
		await mutator(store);
		await writeMetadataStore(store);
		return store;
	});
}

// Reject renaming a link onto a name another link already holds. Two links sharing
// a name make every bound agent resolve to 'ambiguous-link-name' in syncAgentConfigs
// and freezes BOTH silently. Call inside the store mutator (throws before write).
function assertUniqueLinkName(store, linkId, newName, oldName) {
	if (!newName || newName === oldName) return;
	for (const [id, l] of Object.entries(store.links || {})) {
		if (id !== linkId && l && l.name === newName) {
			throw new error.ValidationError(`A link named "${newName}" already exists — choose a unique name`);
		}
	}
}

/**
 * Derive a WireGuard public key from a private key using stdin piping.
 * Avoids shell interpolation entirely — no command injection possible.
 */
function derivePublicKey(privateKey) {
	return execFileSync(getWireGuardBin(), ["pubkey"], {
		input: `${privateKey}\n`,
		encoding: "utf8",
	}).trim();
}

const ACTIVE_HANDSHAKE_WINDOW = 180;
const LINK_TYPES = new Set(["client", "site-to-site", "hub-link", "imported", "unknown"]);
const INTERFACE_ROLES = new Set(["client-hub", "site-to-site", "hub-link", "auxiliary", "unknown"]);
const MANAGEMENT_MODES = new Set(["local", "imported", "unknown"]);
const REMOTE_MANAGEMENT_MODES = new Set(["none", "ssh", "agent", "unknown"]);
const RETURN_PATH_MODES = new Set(["auto", "routed", "static-route", "nat", "unknown"]);

const getWireGuardConfDir = () => process.env.WG_CONF_DIR || "/etc/wireguard";
const getWireGuardBin = () => process.env.WG_BIN || "wg";
const getIpBin = () => process.env.IP_BIN || "ip";

/** Resolve hub hostname for peer/agent configs: WG_HUB_HOST env > OS hostname */
function resolveHubHost() {
	return process.env.WG_HUB_HOST || hostname() || "<server-ip>";
}
const getMetadataFile = () =>
	process.env.WG_METADATA_FILE || path.resolve(process.cwd(), ".local-data", "wireguard-metadata.json");

async function pathExists(targetPath) {
	try {
		await fs.access(targetPath);
		return true;
	} catch {
		return false;
	}
}

async function readText(targetPath) {
	try {
		return await fs.readFile(targetPath, "utf8");
	} catch {
		return "";
	}
}

async function readNumber(targetPath) {
	const value = await readText(targetPath);
	const parsed = Number.parseInt(value.trim(), 10);
	return Number.isFinite(parsed) ? parsed : 0;
}

async function readMetadataStore() {
	let raw;
	try {
		raw = await fs.readFile(getMetadataFile(), "utf8");
	} catch (err) {
		// Only a missing file is a legitimate empty store (first run). Any OTHER read
		// error (EACCES/EMFILE/…) MUST NOT be swallowed into an empty store: every
		// mutation path does read→mutate→write of the whole file, so returning {} here
		// would let the next mutation persist an empty store over real data and
		// permanently wipe all link/interface metadata. Surface it so the mutation
		// aborts instead.
		if (err.code === "ENOENT") return { interfaces: {}, links: {} };
		throw err;
	}
	let parsed;
	try {
		parsed = JSON.parse(raw);
	} catch (err) {
		// A corrupt/truncated store (e.g. a crash mid-write) must throw, not silently
		// become {} — same data-loss reasoning as above.
		throw new Error(`WireGuard metadata store at ${getMetadataFile()} is corrupt: ${err.message}`);
	}
	return {
		interfaces: parsed.interfaces || {},
		links: parsed.links || {},
	};
}

async function writeMetadataStore(store) {
	const metadataFile = getMetadataFile();
	await fs.mkdir(path.dirname(metadataFile), { recursive: true });
	// Write atomically: a partial fs.writeFile (crash/power loss mid-write) would
	// leave truncated JSON that readMetadataStore now refuses to parse. Write to a
	// temp file then rename (atomic on the same filesystem) so the live file is
	// always either the old or the new complete document, never a truncated one.
	const tmpFile = `${metadataFile}.tmp`;
	await fs.writeFile(tmpFile, `${JSON.stringify(store, null, 2)}\n`, "utf8");
	await fs.rename(tmpFile, metadataFile);
}

function mergeMetadataEntry(current = {}, patch = {}) {
	const merged = { ...current, ...patch };
	for (const [key, value] of Object.entries(merged)) {
		if (value === undefined) delete merged[key];
	}
	return merged;
}

function mergeMetadataStorePatch(store = {}, patch = {}) {
	const nextStore = {
		interfaces: { ...(store.interfaces || {}) },
		links: { ...(store.links || {}) },
	};

	for (const [name, value] of Object.entries(patch.interfaces || {})) {
		nextStore.interfaces[name] = mergeMetadataEntry(
			nextStore.interfaces[name] || {},
			sanitizeInterfaceMetadataPatch(value),
		);
	}

	for (const [id, value] of Object.entries(patch.links || {})) {
		nextStore.links[id] = mergeMetadataEntry(nextStore.links[id] || {}, sanitizeLinkMetadataPatch(value));
	}

	return nextStore;
}

async function backupMetadataStore(store = null) {
	const currentStore = store || (await readMetadataStore());
	const metadataFile = getMetadataFile();
	await fs.mkdir(path.dirname(metadataFile), { recursive: true });
	const stamp = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
	const backupPath = `${metadataFile}.${stamp}.bak`;
	await fs.writeFile(backupPath, `${JSON.stringify(currentStore, null, 2)}\n`, "utf8");
	return backupPath;
}

async function applyMetadataPatch(patch = {}) {
	return withWriteLock(async () => {
		const store = await readMetadataStore();
		const nextStore = mergeMetadataStorePatch(store, patch);
		await writeMetadataStore(nextStore);
		return nextStore;
	});
}

// Replace the ENTIRE metadata store under the module write lock. Used by backup
// restore: a raw writeMetadataStore outside the lock loses to the exact race the
// mutateMetadataStore comment describes — a concurrent locked read-modify-write
// that read the pre-restore store writes its copy back afterwards, silently
// wiping the restore. Returns the freshly-written store snapshot.
async function replaceMetadataStore(store = {}) {
	return withWriteLock(async () => {
		const nextStore = {
			interfaces: store.interfaces || {},
			links: store.links || {},
		};
		await writeMetadataStore(nextStore);
		return nextStore;
	});
}

function sanitizeStringArray(value) {
	if (!Array.isArray(value)) return [];
	return Array.from(new Set(value.map((item) => String(item || "").trim()).filter(Boolean)));
}

// Network values (importedNetworks / exportedNetworks / routeTargets) flow into
// `ip route add <net> dev wgN` shell strings that are written to wg-quick
// PostUp/PostDown lines and executed as root. A value like "10.0.0.0/24; <cmd>"
// would be command injection. Validate every entry as a clean IPv4/IPv6 address
// or CIDR and drop anything else — the character set alone (digits, hex, ":", ".",
// "/") makes shell metacharacters impossible.
const IPV4_NET_RE = /^(?:\d{1,3}\.){3}\d{1,3}(?:\/(?:\d|[12]\d|3[0-2]))?$/;
const IPV6_NET_RE = /^[0-9a-fA-F:]+(?:\/(?:\d|[1-9]\d|1[01]\d|12[0-8]))?$/;

function isValidNetwork(value) {
	const v = String(value || "").trim();
	if (!v) return false;
	if (IPV4_NET_RE.test(v)) {
		return v
			.split("/")[0]
			.split(".")
			.every((octet) => Number(octet) <= 255);
	}
	// IPv6 must contain a colon and only hex/colon characters (plus optional prefix).
	return v.includes(":") && IPV6_NET_RE.test(v);
}

// Strict validator for an interface [Interface] Address. The raw value is written
// verbatim into a wg-quick conf and the interface is activated with `wg-quick up`,
// which executes any PostUp/PostDown directives in that conf AS ROOT. A value with
// an embedded newline could smuggle in an attacker-controlled `PostUp = <cmd>` line
// (String.trim() strips only leading/trailing whitespace, not interior newlines),
// so reject anything that isn't a single clean IPv4/IPv6 HOST address WITH a prefix
// and no whitespace. Unlike sanitizeNetworkArray we keep the host bits — an
// interface address like 10.20.0.1/24 is a host, not a masked network.
const IPV4_HOST_CIDR_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
function isValidInterfaceAddress(value) {
	const v = String(value || "").trim();
	if (!v || /\s/.test(v)) return false;
	const m = IPV4_HOST_CIDR_RE.exec(v);
	if (m) {
		return [m[1], m[2], m[3], m[4]].every((o) => Number(o) <= 255) && Number(m[5]) <= 32;
	}
	// IPv6 host with a MANDATORY prefix: hex + colons only (no shell metacharacters).
	return v.includes(":") && v.includes("/") && IPV6_NET_RE.test(v);
}

// A link/peer name is written verbatim as a `# <name>` comment line into a wg-quick
// conf; an embedded newline could smuggle an attacker-controlled `[Interface]` /
// `PostUp = <cmd>` line that wg-quick executes AS ROOT on the next `wg-quick up`.
// String.trim() in the route strips only leading/trailing whitespace, not interior
// newlines — so mirror the interface-address guard above and reject control characters.
// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional control-char guard
const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f]/;
function isSafeLinkName(value) {
	return !CONTROL_CHARS_RE.test(String(value ?? ""));
}
// Belt-and-suspenders companion: strip control characters from a name before it is
// persisted or rendered, so a malicious value can never reach a conf via any path.
// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional control-char guard
const CONTROL_CHARS_GLOBAL_RE = /[\u0000-\u001f\u007f]/g;
function stripLinkNameControlChars(value) {
	return String(value).replace(CONTROL_CHARS_GLOBAL_RE, "");
}

// Canonicalize an IPv4 CIDR to its network address (host bits masked off), e.g.
// "192.168.10.1/24" → "192.168.10.0/24". Returns null for anything that isn't a
// valid IPv4 CIDR with a prefix — including IPv6: the mesh routes IPv4 SITE
// networks only (forwarding IPv6 into local LANs is out of scope). This does NOT
// affect the hub/app being reachable over IPv6 (that's a proxy/endpoint concern,
// not a routed site network). Canonicalizing also fixes the host-bits-vs-network
// mismatch that made an allowed_networks ACL drop a net it should keep.
function canonicalizeIpv4Network(value) {
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(String(value || "").trim());
	if (!m) return null;
	const a = Number(m[1]);
	const b = Number(m[2]);
	const c = Number(m[3]);
	const d = Number(m[4]);
	const p = Number(m[5]);
	if (a > 255 || b > 255 || c > 255 || d > 255 || p > 32) return null;
	const ipInt = ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;
	const mask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
	const net = (ipInt & mask) >>> 0;
	return `${(net >>> 24) & 0xff}.${(net >>> 16) & 0xff}.${(net >>> 8) & 0xff}.${net & 0xff}/${p}`;
}

function sanitizeNetworkArray(value) {
	if (!Array.isArray(value)) return [];
	const out = [];
	for (const item of value) {
		const canon = canonicalizeIpv4Network(item);
		if (canon) out.push(canon);
	}
	return Array.from(new Set(out));
}

function sanitizeInterfaceMetadata(input = {}) {
	const role = input.role ? String(input.role) : undefined;
	const managementMode = input.managementMode ? String(input.managementMode) : undefined;
	return {
		role: normalizeInterfaceRole(role),
		managementMode: MANAGEMENT_MODES.has(managementMode) ? managementMode : undefined,
		exportedNetworks: sanitizeNetworkArray(input.exportedNetworks),
		importedNetworks: sanitizeNetworkArray(input.importedNetworks),
		routeTargets: sanitizeNetworkArray(input.routeTargets),
		notes: sanitizeStringArray(input.notes),
	};
}

function sanitizeInterfaceMetadataPatch(input = {}) {
	const sanitized = {};
	if (Object.hasOwn(input, "role"))
		sanitized.role = normalizeInterfaceRole(input.role ? String(input.role) : undefined);
	if (Object.hasOwn(input, "managementMode"))
		sanitized.managementMode = MANAGEMENT_MODES.has(input.managementMode ? String(input.managementMode) : undefined)
			? String(input.managementMode)
			: undefined;
	if (Object.hasOwn(input, "exportedNetworks"))
		sanitized.exportedNetworks = sanitizeNetworkArray(input.exportedNetworks);
	if (Object.hasOwn(input, "importedNetworks"))
		sanitized.importedNetworks = sanitizeNetworkArray(input.importedNetworks);
	if (Object.hasOwn(input, "routeTargets")) sanitized.routeTargets = sanitizeNetworkArray(input.routeTargets);
	if (Object.hasOwn(input, "notes")) sanitized.notes = sanitizeStringArray(input.notes);
	if (Object.hasOwn(input, "dns")) sanitized.dns = sanitizeStringArray(input.dns);
	return sanitized;
}

function sanitizeLinkMetadata(input = {}) {
	const type = input.type ? String(input.type) : undefined;
	const returnPathMode = input.returnPathMode ? String(input.returnPathMode) : undefined;
	const remoteManagementMode = input.remoteManagementMode ? String(input.remoteManagementMode) : undefined;
	return {
		name: input.name ? stripLinkNameControlChars(input.name) : undefined,
		type: normalizeLinkType(type),
		exportedNetworks: sanitizeNetworkArray(input.exportedNetworks),
		importedNetworks: sanitizeNetworkArray(input.importedNetworks),
		returnPathMode: RETURN_PATH_MODES.has(returnPathMode) ? returnPathMode : undefined,
		remoteManagementMode: REMOTE_MANAGEMENT_MODES.has(remoteManagementMode) ? remoteManagementMode : undefined,
		planIntent: input.planIntent ? String(input.planIntent) : undefined,
		planState: input.planState ? String(input.planState) : undefined,
		notes: sanitizeStringArray(input.notes),
	};
}

function sanitizeLinkMetadataPatch(input = {}) {
	const sanitized = {};
	if (Object.hasOwn(input, "name")) sanitized.name = input.name ? stripLinkNameControlChars(input.name) : undefined;
	if (Object.hasOwn(input, "type")) sanitized.type = normalizeLinkType(input.type ? String(input.type) : undefined);
	if (Object.hasOwn(input, "exportedNetworks"))
		sanitized.exportedNetworks = sanitizeNetworkArray(input.exportedNetworks);
	if (Object.hasOwn(input, "importedNetworks"))
		sanitized.importedNetworks = sanitizeNetworkArray(input.importedNetworks);
	if (Object.hasOwn(input, "returnPathMode"))
		sanitized.returnPathMode = RETURN_PATH_MODES.has(
			input.returnPathMode ? String(input.returnPathMode) : undefined,
		)
			? String(input.returnPathMode)
			: undefined;
	if (Object.hasOwn(input, "remoteManagementMode"))
		sanitized.remoteManagementMode = REMOTE_MANAGEMENT_MODES.has(
			input.remoteManagementMode ? String(input.remoteManagementMode) : undefined,
		)
			? String(input.remoteManagementMode)
			: undefined;
	if (Object.hasOwn(input, "planIntent"))
		sanitized.planIntent = input.planIntent ? String(input.planIntent) : undefined;
	if (Object.hasOwn(input, "planState")) sanitized.planState = input.planState ? String(input.planState) : undefined;
	if (Object.hasOwn(input, "dns")) sanitized.dns = sanitizeStringArray(input.dns);
	if (Object.hasOwn(input, "fullTunnel")) sanitized.fullTunnel = Boolean(input.fullTunnel);
	if (Object.hasOwn(input, "platform"))
		sanitized.platform = ["desktop", "mobile"].includes(input.platform) ? input.platform : undefined;
	if (Object.hasOwn(input, "notes")) sanitized.notes = sanitizeStringArray(input.notes);
	return sanitized;
}

function normalizeLinkType(type) {
	if (!type) return undefined;
	if (type === "site-link") return "site-to-site";
	return LINK_TYPES.has(type) ? type : undefined;
}

function normalizeInterfaceRole(role) {
	if (!role) return undefined;
	if (role === "site-link") return "site-to-site";
	return INTERFACE_ROLES.has(role) ? role : undefined;
}

async function updateInterfaceMetadata(interfaceName, patch) {
	const store = await mutateMetadataStore((s) => {
		s.interfaces[interfaceName] = mergeMetadataEntry(
			s.interfaces[interfaceName] || {},
			sanitizeInterfaceMetadataPatch(patch),
		);
	});
	return store.interfaces[interfaceName];
}

async function updateLinkMetadata(linkId, patch) {
	const sanitized = sanitizeLinkMetadataPatch(patch);
	let oldName;
	const store = await mutateMetadataStore((s) => {
		oldName = s.links[linkId]?.name;
		assertUniqueLinkName(s, linkId, sanitized.name, oldName);
		s.links[linkId] = mergeMetadataEntry(s.links[linkId] || {}, sanitized);
	});
	// The patch may change AllowedIPs/DNS/full-tunnel/platform; drop cached peer configs
	// so a prior Download/QR cache isn't re-served stale on the next download.
	clearPeerConfigCache();
	// Agents bind to a link by its (mutable) name via wg_link_name / allowed_sites.
	// A rename without cascading those columns silently orphans every bound agent.
	if (Object.hasOwn(sanitized, "name") && sanitized.name && oldName && sanitized.name !== oldName) {
		try {
			const { default: internalAgent } = await import("./agent.js");
			await internalAgent.renameLinkBinding(oldName, sanitized.name);
		} catch (err) {
			logger.error(`Link rename cascade ${oldName}→${sanitized.name} failed: ${err.message}`);
		}
	}
	return store.links[linkId];
}

function parseConfig(confText) {
	const result = { addresses: [], listenPort: null, privateKeyPresent: false, peers: [] };
	let section = "";
	let currentPeer = null;
	for (const rawLine of confText.split(/\r?\n/)) {
		const line = rawLine.trim();
		if (!line || line.startsWith("#")) continue;
		if (line === "[Interface]") {
			section = "interface";
			currentPeer = null;
			continue;
		}
		if (line === "[Peer]") {
			section = "peer";
			currentPeer = {};
			result.peers.push(currentPeer);
			continue;
		}
		if (!line.includes("=")) continue;
		const [key, value] = line.split("=", 2).map((part) => part.trim());
		if (section === "interface") {
			if (key === "Address")
				result.addresses = value
					.split(",")
					.map((part) => part.trim())
					.filter(Boolean);
			if (key === "ListenPort") {
				const parsed = Number.parseInt(value, 10);
				result.listenPort = Number.isFinite(parsed) ? parsed : null;
			}
			if (key === "PrivateKey") result.privateKeyPresent = Boolean(value);
		}
		if (section === "peer" && currentPeer) currentPeer[key] = value;
	}
	return result;
}

async function getDump() {
	try {
		const { stdout } = await execFileAsync(getWireGuardBin(), ["show", "all", "dump"]);
		return stdout;
	} catch (err) {
		logger.debug(`wg show all dump failed: ${err.message}`);
		return "";
	}
}

function parseDump(stdout) {
	const now = Math.floor(Date.now() / 1000);
	const byInterface = new Map();
	for (const rawLine of stdout.split(/\r?\n/)) {
		const line = rawLine.trim();
		if (!line) continue;
		const parts = line.split("\t");
		const iface = parts[0];
		if (!iface) continue;
		if (parts.length === 5) {
			byInterface.set(iface, {
				active: true,
				name: iface,
				publicKey: parts[2] || null,
				listenPort: parts[3] ? Number.parseInt(parts[3], 10) || null : null,
				peers: [],
				peerCount: 0,
				activePeerCount: 0,
				rxBytes: 0,
				txBytes: 0,
			});
			continue;
		}
		const existing = byInterface.get(iface) || {
			active: true,
			name: iface,
			publicKey: null,
			listenPort: null,
			peers: [],
			peerCount: 0,
			activePeerCount: 0,
			rxBytes: 0,
			txBytes: 0,
		};
		const latestHandshake = Number.parseInt(parts[5] || "0", 10) || 0;
		const rxBytes = Number.parseInt(parts[6] || "0", 10) || 0;
		const txBytes = Number.parseInt(parts[7] || "0", 10) || 0;
		const isActive = latestHandshake > 0 && now - latestHandshake < ACTIVE_HANDSHAKE_WINDOW;
		existing.peers.push({
			publicKey: parts[1] || null,
			endpoint: parts[3] || null,
			allowedIps: (parts[4] || "")
				.split(",")
				.map((part) => part.trim())
				.filter(Boolean),
			latestHandshake,
			rxBytes,
			txBytes,
			isActive,
		});
		existing.peerCount += 1;
		existing.activePeerCount += isActive ? 1 : 0;
		existing.rxBytes += rxBytes;
		existing.txBytes += txBytes;
		byInterface.set(iface, existing);
	}
	return byInterface;
}

function dedupe(values) {
	return Array.from(new Set(values.filter(Boolean)));
}

function isPrivateNetwork(target) {
	return (
		target.startsWith("10.") ||
		target.startsWith("192.168.") ||
		/^172\.(1[6-9]|2\d|3[0-1])\./u.test(target) ||
		target.startsWith("fd") ||
		target.startsWith("fc")
	);
}

function isHostRoute(target) {
	return /\/32$/u.test(target) || /\/128$/u.test(target);
}

function classifyLinkType(allowedIps, ifaceName) {
	const privateNetworks = allowedIps.filter((entry) => isPrivateNetwork(entry));
	const networkRoutes = privateNetworks.filter((entry) => !isHostRoute(entry));
	const hostRoutes = privateNetworks.filter((entry) => isHostRoute(entry));
	// On wg0 (hub), peers with at most 1 network route are considered clients
	// (they bring their own subnet but don't act as site-to-site links)
	if (ifaceName === "wg0" && networkRoutes.length <= 1) return "client";
	if (networkRoutes.length >= 2) return "hub-link";
	if (networkRoutes.length >= 1) return "site-to-site";
	if (hostRoutes.length > 0) return "client";
	return ifaceName === "wg0" ? "client" : "unknown";
}

function inferInterfaceRole(name, peers) {
	if (name === "wg0") return "client-hub";
	const linkTypes = peers.map((peer) => classifyLinkType(peer.allowedIps || [], name));
	if (linkTypes.includes("hub-link")) return "hub-link";
	if (linkTypes.includes("site-to-site")) return "site-to-site";
	if (peers.length > 0) return "auxiliary";
	return "unknown";
}

function buildLinkRecord(ifaceName, peer, index, metadata = {}) {
	const importedNetworks = metadata.importedNetworks?.length
		? metadata.importedNetworks
		: dedupe((peer.allowedIps || []).filter((entry) => isPrivateNetwork(entry) && !isHostRoute(entry)));
	const tunnelAddresses = dedupe((peer.allowedIps || []).filter((entry) => isHostRoute(entry)));
	const type = normalizeLinkType(metadata.type) || classifyLinkType(peer.allowedIps || [], ifaceName);
	const warnings = [];
	const nextActions = [];
	if (!peer.endpoint) warnings.push("remote-endpoint-missing");
	if (importedNetworks.length > 0) nextActions.push("verify-return-path");
	if (type === "hub-link" || type === "site-to-site") nextActions.push("model-exported-networks");
	if (!REMOTE_MANAGEMENT_MODES.has(metadata.remoteManagementMode)) nextActions.push("define-remote-management-mode");
	return {
		id: `${ifaceName}:${peer.publicKey || index}`,
		interfaceName: ifaceName,
		type,
		name: metadata.name || (peer.publicKey ? `${type}-${peer.publicKey.slice(0, 8)}` : `${type}-${index + 1}`),
		peerPublicKey: peer.publicKey || null,
		remoteEndpoint: peer.endpoint || null,
		allowedIps: peer.allowedIps || [],
		tunnelAddresses,
		exportedNetworks: metadata.exportedNetworks || [],
		importedNetworks,
		latestHandshake: peer.latestHandshake || 0,
		rxBytes: peer.rxBytes || 0,
		txBytes: peer.txBytes || 0,
		active: Boolean(peer.isActive),
		hasMetadata: Boolean(Object.keys(metadata).length),
		returnPathMode: RETURN_PATH_MODES.has(metadata.returnPathMode)
			? metadata.returnPathMode
			: importedNetworks.length
				? "unknown"
				: "routed",
		remoteManagementMode: REMOTE_MANAGEMENT_MODES.has(metadata.remoteManagementMode)
			? metadata.remoteManagementMode
			: "none",
		platform: metadata.platform || null,
		dns: metadata.dns || [],
		fullTunnel: Boolean(metadata.fullTunnel),
		planIntent: metadata.planIntent || type,
		planState: metadata.planState || null,
		notes: metadata.notes || [],
		warnings,
		nextActions,
	};
}

async function getRoutes() {
	try {
		const { stdout } = await execFileAsync(getIpBin(), ["route", "show"]);
		const parsed = stdout
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter(Boolean)
			.map((line) => {
				const devMatch = line.match(/\bdev\s+(\S+)/u);
				const viaMatch = line.match(/\bvia\s+(\S+)/u);
				const destination = line.split(/\s+/u)[0] || "";
				return { destination, device: devMatch?.[1] || null, via: viaMatch?.[1] || null, raw: line };
			});
		const wireguard = parsed.filter((route) => route.device?.startsWith("wg"));
		const privateRoutes = parsed.filter(
			(route) => route.destination !== "default" && isPrivateNetwork(route.destination),
		);
		return { all: parsed, wireguard, privateRoutes };
	} catch (err) {
		logger.debug(`ip route show failed: ${err.message}`);
		return { all: [], wireguard: [], privateRoutes: [] };
	}
}

async function getInterfaceStatus(name, dumpByInterface, metadataStore) {
	const confPath = path.join(getWireGuardConfDir(), `${name}.conf`);
	const configText = await readText(confPath);
	const parsedConfig = parseConfig(configText);
	const dump = dumpByInterface.get(name);
	const statsBase = `/sys/class/net/${name}/statistics`;
	const configPeerNetworks = dedupe(
		parsedConfig.peers.flatMap((peer) =>
			String(peer.AllowedIPs || "")
				.split(",")
				.map((part) => part.trim())
				.filter(Boolean),
		),
	);
	const peers = dump?.peers ?? [];
	const metadata = metadataStore.interfaces[name] || {};
	const role = normalizeInterfaceRole(metadata.role) || inferInterfaceRole(name, peers);
	const importedNetworks = metadata.importedNetworks?.length
		? metadata.importedNetworks
		: dedupe(
				peers.flatMap((peer) =>
					(peer.allowedIps || []).filter((entry) => isPrivateNetwork(entry) && !isHostRoute(entry)),
				),
			);
	const routeTargets = metadata.routeTargets?.length
		? metadata.routeTargets
		: dedupe(peers.flatMap((peer) => peer.allowedIps || []));
	const active = Boolean(dump?.active);
	return {
		name,
		isHub: name === "wg0",
		role,
		managementMode: MANAGEMENT_MODES.has(metadata.managementMode) ? metadata.managementMode : "local",
		configPath: confPath,
		configExists: Boolean(configText),
		active,
		addresses: parsedConfig.addresses,
		listenPort: dump?.listenPort ?? parsedConfig.listenPort,
		publicKey: dump?.publicKey ?? null,
		peerCount: dump?.peerCount ?? parsedConfig.peers.length,
		activePeerCount: dump?.activePeerCount ?? 0,
		rxBytes: await readNumber(path.join(statsBase, "rx_bytes")),
		txBytes: await readNumber(path.join(statsBase, "tx_bytes")),
		privateKeyPresent: parsedConfig.privateKeyPresent,
		peerNetworks: configPeerNetworks,
		importedNetworks,
		exportedNetworks: metadata.exportedNetworks || [],
		dns: metadata.dns || [],
		routeTargets,
		health: active ? "healthy" : "inactive",
		notes: metadata.notes?.length
			? metadata.notes
			: importedNetworks.length
				? [`${importedNetworks.length} imported network(s) detected`]
				: [],
		peers,
	};
}

async function listConfigNames() {
	try {
		const entries = await fs.readdir(getWireGuardConfDir(), { withFileTypes: true });
		return entries
			.filter((entry) => entry.isFile() && entry.name.endsWith(".conf"))
			.map((entry) => entry.name.replace(/\.conf$/u, ""))
			.sort((left, right) => left.localeCompare(right));
	} catch {
		return [];
	}
}

function buildTopology(interfaces, links) {
	return {
		exportedNetworks: dedupe([
			...interfaces.flatMap((item) => item.exportedNetworks || []),
			...links.flatMap((item) => item.exportedNetworks || []),
		]),
		importedNetworks: dedupe([
			...interfaces.flatMap((item) => item.importedNetworks || []),
			...links.flatMap((item) => item.importedNetworks || []),
		]),
		siteLinks: links.filter((item) => item.type === "site-to-site").map((item) => item.id),
		clientLinks: links.filter((item) => item.type === "client").map((item) => item.id),
		hubLinks: links.filter((item) => item.type === "hub-link").map((item) => item.id),
	};
}

function buildRouteAnalysis(routes, topology) {
	const wireguardDestinations = new Set(routes.wireguard.map((route) => route.destination));
	const staticRouteDestinations = new Set(
		routes.privateRoutes
			.filter((route) => !String(route.device || "").startsWith("wg"))
			.map((route) => route.destination),
	);
	const missingReturnRoutes = topology.importedNetworks
		.filter((network) => !wireguardDestinations.has(network) && !staticRouteDestinations.has(network))
		.map((network) => ({ network, reason: "network-not-found-in-live-routes" }));
	const natCandidates = topology.importedNetworks
		.filter((network) => !wireguardDestinations.has(network) && !staticRouteDestinations.has(network))
		.map((network) => ({ network, reason: "return-path-unclear" }));
	const staticRoutes = routes.privateRoutes.filter((route) => !String(route.device || "").startsWith("wg"));
	const splitTunnelCandidates = dedupe([
		...topology.importedNetworks,
		...staticRoutes.map((route) => route.destination),
	]);
	return {
		all: routes.all,
		wireguard: routes.wireguard,
		privateRoutes: routes.privateRoutes,
		staticRoutes,
		missingReturnRoutes,
		natCandidates,
		conflicts: [],
		splitTunnelCandidates,
		observations: [
			...(missingReturnRoutes.length
				? ["Some imported networks are not visible as live WireGuard routes yet"]
				: []),
			...(staticRoutes.length
				? ["Static private routes exist outside WireGuard and may affect reachability decisions"]
				: []),
		],
	};
}

function getMissingImportedNetworks(link, routeAnalysis) {
	const missing = new Set((routeAnalysis.missingReturnRoutes || []).map((item) => item.network));
	return (link.importedNetworks || []).filter((network) => missing.has(network));
}

function getNatCandidateNetworks(link, routeAnalysis) {
	const candidates = new Set((routeAnalysis.natCandidates || []).map((item) => item.network));
	return (link.importedNetworks || []).filter((network) => candidates.has(network));
}

function inferPlanState(link, missingImportedNetworks, natCandidateNetworks) {
	const readinessChecks = [
		Boolean(link.planIntent && link.planIntent !== "unknown"),
		(link.exportedNetworks || []).length > 0,
		(link.importedNetworks || []).length > 0,
		Boolean(link.remoteManagementMode && !["none", "unknown"].includes(link.remoteManagementMode)),
		Boolean(link.returnPathMode && !["auto", "unknown"].includes(link.returnPathMode)),
		missingImportedNetworks.length === 0,
		natCandidateNetworks.length === 0,
	];
	const completed = readinessChecks.filter(Boolean).length;
	if (completed <= 2) return "discover";
	if (completed <= 4) return "shape";
	if (completed <= 6) return "validate";
	return "ready";
}

function enrichLinkRecord(link, routeAnalysis) {
	const warnings = [...(link.warnings || [])];
	const nextActions = [...(link.nextActions || [])];
	const missingImportedNetworks = getMissingImportedNetworks(link, routeAnalysis);
	const natCandidateNetworks = getNatCandidateNetworks(link, routeAnalysis);

	if (!link.remoteEndpoint) warnings.push("remote-endpoint-missing");
	if (missingImportedNetworks.length) {
		warnings.push("imported-network-missing-live-route");
		nextActions.push("fix-return-path");
	}
	if (natCandidateNetworks.length && ["auto", "unknown"].includes(link.returnPathMode)) {
		warnings.push("nat-likely-needed");
		nextActions.push("decide-nat-or-static-route");
	}
	if (["site-to-site", "hub-link"].includes(link.type) && !link.exportedNetworks.length) {
		warnings.push("exported-networks-missing");
		nextActions.push("model-exported-networks");
	}
	if ((link.importedNetworks || []).length && ["auto", "unknown"].includes(link.returnPathMode)) {
		warnings.push("return-path-mode-undefined");
		nextActions.push("define-return-path-mode");
	}
	if (["none", "unknown"].includes(link.remoteManagementMode) && link.type !== "client") {
		warnings.push("remote-management-mode-undefined");
		nextActions.push("define-remote-management-mode");
	}
	if (!link.active && (link.importedNetworks.length || link.exportedNetworks.length) && link.type !== "client") {
		warnings.push("link-not-currently-active");
		nextActions.push("verify-live-tunnel-state");
	}

	return {
		...link,
		warnings: dedupe(warnings),
		nextActions: dedupe(nextActions),
		planState: link.planState || inferPlanState(link, missingImportedNetworks, natCandidateNetworks),
	};
}

function enrichInterfaceStatus(item, links) {
	const relatedLinks = links.filter((link) => link.interfaceName === item.name);
	const warningCount = relatedLinks.filter((link) => link.warnings.length > 0).length;
	const importedNetworks = item.importedNetworks || [];
	const notes = [...(item.notes || [])];

	if (!item.configExists) notes.push("config file missing");
	if (!item.privateKeyPresent && item.configExists) notes.push("private key missing from config");
	if (!item.active && importedNetworks.length) notes.push("inactive interface with imported networks");
	if (warningCount > 0) notes.push(`${warningCount} link(s) on this interface need review`);

	let health = "healthy";
	if (!item.active && (item.peerCount > 0 || importedNetworks.length > 0)) {
		health = "warning";
	} else if (!item.active) {
		health = "inactive";
	} else if (warningCount > 0 || !item.configExists || !item.privateKeyPresent) {
		health = "warning";
	}

	return {
		...item,
		health,
		notes: dedupe(notes),
	};
}

function deriveGlobalNextActions(interfaces, links, routeAnalysis) {
	const actions = [
		...(routeAnalysis.missingReturnRoutes?.length ? ["fix-return-path"] : []),
		...(routeAnalysis.natCandidates?.length ? ["review-nat-requirements"] : []),
		...interfaces.flatMap((item) => (item.health === "warning" ? ["review-interface-health"] : [])),
		...links.flatMap((link) => link.nextActions || []),
	];
	return dedupe(actions);
}

function deriveGlobalWarnings(interfaces, routeAnalysis) {
	const warnings = [
		...(routeAnalysis.missingReturnRoutes?.length
			? ["Imported networks exist without matching live WireGuard route entries"]
			: []),
		...(routeAnalysis.natCandidates?.length
			? ["Some imported networks may still require NAT or explicit return-path handling"]
			: []),
		...interfaces.flatMap((item) => (item.health === "warning" ? [`Interface ${item.name} needs review`] : [])),
	];
	return dedupe(warnings);
}

function buildCapabilities() {
	return {
		mode: "metadata-write",
		supports: {
			peerCrud: false,
			interfaceCrud: false,
			configDownload: false,
			shareLinks: false,
			wizardPlanning: true,
			remoteSsh: false,
			remoteAgent: false,
			metadataCrud: true,
		},
	};
}

// NOTE: this performs a conf read-modify-write and live `wg set` and MUST run under
// the module write lock (withWriteLock) so it can't interleave with createPeer's
// locked appendFile and silently drop a freshly-added [Peer] block. The sole caller
// (generatePeerConfig) wraps the call in withWriteLock; never call it unlocked.
async function _rotatePeerPublicKey(ifaceName, oldPubKey, newPubKey, peerAllowedIps) {
	const confPath = path.join(getWireGuardConfDir(), `${ifaceName}.conf`);
	let confText;
	try {
		confText = await fs.readFile(confPath, "utf8");
	} catch {
		return false;
	}

	// Rewrite conf: swap old PublicKey for new one in the matching [Peer] block
	const lines = confText.split(/\r?\n/);
	let inPeer = false;
	let swapped = false;
	const out = [];
	for (const rawLine of lines) {
		const t = rawLine.trim();
		if (t === "[Peer]") {
			inPeer = true;
			out.push(rawLine);
			continue;
		}
		if (t.startsWith("[")) {
			inPeer = false;
			out.push(rawLine);
			continue;
		}
		if (inPeer && !swapped && t.startsWith("PublicKey")) {
			const currentKey = t.slice(t.indexOf("=") + 1).trim();
			if (currentKey === oldPubKey) {
				out.push(`PublicKey = ${newPubKey}`);
				swapped = true;
				continue;
			}
		}
		out.push(rawLine);
	}

	if (!swapped) return false;

	await fs.writeFile(confPath, out.join("\n"), "utf8");
	const wgBin = getWireGuardBin();
	try {
		await execFileAsync(wgBin, ["set", ifaceName, "peer", oldPubKey, "remove"]);
	} catch (err) {
		logger.debug(`Failed to remove old peer ${oldPubKey.slice(0, 8)}… from ${ifaceName}: ${err.message}`);
	}
	try {
		const args = ["set", ifaceName, "peer", newPubKey];
		if (peerAllowedIps.length > 0) args.push("allowed-ips", peerAllowedIps.join(","));
		await execFileAsync(wgBin, args);
	} catch (err) {
		logger.debug(`Failed to add rotated peer ${newPubKey.slice(0, 8)}… on ${ifaceName}: ${err.message}`);
	}
	return true;
}

// generatePeerConfig generates a fresh keypair and rotates the hub-side peer key on
// every call (the hub only stores the public key, so it cannot re-emit the original
// private key). The WireGuard page offers BOTH "Download config" and "Show QR" for
// the same link without refetching, so two calls would otherwise: (a) 404 the second
// call because rotation changed the link id (linkId embeds the pubkey), (b) silently
// sever a just-provisioned device on the second rotation, or (c) hand out two keys
// where only the last works. Cache the generated material briefly, keyed by BOTH the
// id the caller passed AND the post-rotation id, so back-to-back Download+QR (in any
// order) and repeat downloads return identical material and rotate exactly once.
const _peerConfigCache = new Map(); // linkId -> { result, expires }
// In-flight de-duplication: the result cache is only written at the very END of
// generation (after getStatus + genkey + the locked key rotation). Two genuinely
// concurrent requests for the same linkId (e.g. Download config + open QR fired
// together) would both miss the result cache, both rotate the hub-side key, and the
// SECOND would serve a config whose public key the hub never registered (a dead config
// cached for the whole TTL). Sharing a single in-flight promise per linkId makes them
// rotate exactly once and return identical, registered material.
const _peerConfigInFlight = new Map(); // linkId -> Promise<result>
const PEER_CONFIG_CACHE_TTL_MS = 120_000;

function _getCachedPeerConfig(linkId) {
	const entry = _peerConfigCache.get(linkId);
	if (!entry) return null;
	if (entry.expires <= Date.now()) {
		_peerConfigCache.delete(linkId);
		return null;
	}
	return entry.result;
}

// Drop every cached peer config. Must be called by any path that mutates the link
// metadata fields a cached config is built from (importedNetworks/dns/fullTunnel/
// platform), so the next Download/QR regenerates instead of serving a stale config.
// The cache Map is module-private, so external mutators (e.g. wireguard-plan.js's
// applyMetadata/restoreMetadataBackup) invalidate through this exported helper.
function clearPeerConfigCache() {
	_peerConfigCache.clear();
}

async function generatePeerConfig(linkId) {
	const cached = _getCachedPeerConfig(linkId);
	if (cached) return cached;

	// Coalesce overlapping requests for the same link onto one execution so the
	// hub-side key is rotated exactly once (see _peerConfigInFlight above).
	const inFlight = _peerConfigInFlight.get(linkId);
	if (inFlight) return inFlight;

	const promise = _generatePeerConfigUncached(linkId);
	_peerConfigInFlight.set(linkId, promise);
	try {
		return await promise;
	} finally {
		_peerConfigInFlight.delete(linkId);
	}
}

async function _generatePeerConfigUncached(linkId) {
	const status = await getStatus();
	if (!status.available) {
		throw new Error("WireGuard is not available");
	}

	const link = (status.links || []).find((l) => l.id === linkId);
	if (!link) {
		throw new Error(`Link not found: ${linkId}`);
	}

	const iface = status.interfaces.find((i) => i.name === link.interfaceName);
	const hubPublicKey = iface?.publicKey ?? null;
	const hubListenPort = iface?.listenPort ?? 51820;

	const tunnelAddress = link.tunnelAddresses[0] ?? null;

	// Build AllowedIPs: for road warriors (no importedNetworks), collect all
	// exportedNetworks from OTHER peers so the client can reach remote sites.
	let allowedIps;
	if (link.importedNetworks.length > 0) {
		allowedIps = link.importedNetworks;
	} else {
		const otherLinks = (status.links || []).filter((l) => l.id !== linkId && l.interfaceName === link.interfaceName);
		const otherNets = otherLinks.flatMap((l) => l.exportedNetworks || []);
		const tunnelSubnets = iface?.addresses ?? [];
		allowedIps = [...new Set([...tunnelSubnets, ...otherNets])];
	}

	// Generate a fresh WireGuard keypair for this peer
	// Note: wg pubkey hangs when piped via Node.js child_process stdin on this system;
	// use shell pipe instead.
	const wgBin = getWireGuardBin();
	const { stdout: privKeyRaw } = await execFileAsync(wgBin, ["genkey"]);
	const privateKey = privKeyRaw.trim();
	const newPubKey = derivePublicKey(privateKey);

	// Rotate the peer's public key on the hub
	const oldPubKey = link.peerPublicKey;
	let rotated = false;
	if (oldPubKey && oldPubKey !== newPubKey) {
		// Serialize the conf RMW + live wg set under the write lock so it can't
		// interleave with a concurrent createPeer's locked appendFile (which would
		// otherwise lose the new peer block from the conf).
		rotated = await withWriteLock(() =>
			_rotatePeerPublicKey(link.interfaceName, oldPubKey, newPubKey, link.allowedIps || []),
		);
		if (rotated) {
			// Rename the link in the metadata store (ID is based on pubkey) — locked RMW
			const newLinkId = `${link.interfaceName}:${newPubKey}`;
			await mutateMetadataStore((s) => {
				if (s.links[linkId]) {
					s.links[newLinkId] = s.links[linkId];
					delete s.links[linkId];
				}
			});
		}
	}

	const filename = `${link.name || link.id}.conf`.replace(/[^\w.-]/g, "_");

	const lines = [
		`# WireGuard peer config — ${link.name || link.id}`,
		"# Generated by FloppyGuard",
		"",
		"[Interface]",
		`PrivateKey = ${privateKey}`,
		`# PublicKey = ${newPubKey}  # (registered on hub — do not share)`,
	];

	if (tunnelAddress) {
		lines.push(`Address = ${tunnelAddress}`);
	}

	// DNS: link-level > interface-level > env fallback
	// Use the new link ID only if key rotation actually succeeded
	const effectiveLinkId = rotated ? `${link.interfaceName}:${newPubKey}` : linkId;
	const store = await readMetadataStore();
	const ifaceMeta = store.interfaces[link.interfaceName] || {};
	const linkMeta = store.links[effectiveLinkId] || store.links[linkId] || {};
	const dnsServers = linkMeta.dns?.length
		? linkMeta.dns
		: ifaceMeta.dns?.length
			? ifaceMeta.dns
			: process.env.WG_DNS
				? process.env.WG_DNS.split(",").map((s) => s.trim())
				: [];
	if (dnsServers.length > 0) {
		lines.push(`DNS = ${dnsServers.join(", ")}`);
	}

	// Full tunnel: route all traffic through VPN
	// Desktop (Windows/Linux/Mac): /1-split avoids replacing default route → no routing loop
	// Mobile (iOS/Android): 0.0.0.0/0 signals the OS to treat it as a VPN tunnel
	const isFullTunnel = Boolean(linkMeta.fullTunnel);
	const isMobile = linkMeta.platform === "mobile";
	const fullTunnelIPs = isMobile ? ["0.0.0.0/0", "::/0"] : ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];
	const finalAllowedIps = isFullTunnel ? fullTunnelIPs : allowedIps;

	lines.push("", "[Peer]", `# Hub interface: ${link.interfaceName}`);

	if (hubPublicKey) {
		lines.push(`PublicKey = ${hubPublicKey}`);
	}

	const hubHost = resolveHubHost();
	lines.push(
		`Endpoint = ${hubHost}:${hubListenPort}`,
		`AllowedIPs = ${finalAllowedIps.join(", ") || "0.0.0.0/0"}`,
		"PersistentKeepalive = 25",
	);

	const result = { filename, content: `${lines.join("\n")}\n`, publicKey: newPubKey };

	// Cache under the id the caller passed AND the post-rotation id so a follow-up
	// Download/QR with either id returns the SAME material without rotating again.
	const expires = Date.now() + PEER_CONFIG_CACHE_TTL_MS;
	_peerConfigCache.set(linkId, { result, expires });
	if (rotated) _peerConfigCache.set(`${link.interfaceName}:${newPubKey}`, { result, expires });

	return result;
}

async function generatePeerConfigQr(linkId) {
	const { content } = await generatePeerConfig(linkId);
	const QRCode = (await import("qrcode")).default;
	const png = await QRCode.toBuffer(content, { type: "png", errorCorrectionLevel: "L" });
	return png;
}

async function getStatus() {
	_ensureBandwidthPolling();
	const metadataStore = await readMetadataStore();
	const wireGuardConfDir = getWireGuardConfDir();
	const wireGuardBin = getWireGuardBin();
	const ipBin = getIpBin();
	const available = await pathExists(wireGuardConfDir);
	if (!available) {
		return {
			available: false,
			mode: "metadata-write",
			hub: null,
			interfaces: [],
			links: [],
			routes: {
				all: [],
				wireguard: [],
				privateRoutes: [],
				staticRoutes: [],
				missingReturnRoutes: [],
				natCandidates: [],
				conflicts: [],
				splitTunnelCandidates: [],
				observations: [],
			},
			topology: { exportedNetworks: [], importedNetworks: [], siteLinks: [], clientLinks: [], hubLinks: [] },
			capabilities: buildCapabilities(),
			summary: null,
			metadata: metadataStore,
			warnings: [`WireGuard config directory is not available at ${wireGuardConfDir}`],
			nextActions: ["mount-wireguard-config-directory"],
		};
	}

	const dumpByInterface = parseDump(await getDump());
	const configNames = await listConfigNames();
	const interfaceNames = Array.from(new Set([...configNames, ...dumpByInterface.keys()])).sort((a, b) =>
		a.localeCompare(b),
	);
	const interfaceStatuses = await Promise.all(
		interfaceNames.map((name) => getInterfaceStatus(name, dumpByInterface, metadataStore)),
	);
	const rawLinks = interfaceStatuses.flatMap((item) =>
		item.peers.map((peer, index) =>
			buildLinkRecord(
				item.name,
				peer,
				index,
				metadataStore.links[`${item.name}:${peer.publicKey || index}`] || {},
			),
		),
	);
	const routes = await getRoutes();
	const topology = buildTopology(interfaceStatuses, rawLinks);
	const routeAnalysis = buildRouteAnalysis(routes, topology);
	const links = rawLinks.map((link) => enrichLinkRecord(link, routeAnalysis));
	const interfaces = interfaceStatuses.map((item) => enrichInterfaceStatus(item, links));
	const hub = interfaces.find((item) => item.name === "wg0") || null;
	const warnings = deriveGlobalWarnings(interfaces, routeAnalysis);

	// ── AllowedIPs conflict detection ─────────────────────────────────────────
	// When two or more peers claim the same subnet in AllowedIPs, WireGuard
	// silently assigns it to the last peer processed — breaking routing for
	// all others.  Detect this and warn prominently.
	const subnetToPeers = new Map(); // subnet → [{linkId, name}]
	for (const link of links) {
		for (const cidr of link.allowedIps || []) {
			if (isHostRoute(cidr)) continue; // /32 and /128 tunnel IPs are expected per-peer
			if (!subnetToPeers.has(cidr)) subnetToPeers.set(cidr, []);
			subnetToPeers.get(cidr).push({ id: link.id, name: link.name });
		}
	}
	for (const [subnet, claimants] of subnetToPeers) {
		if (claimants.length > 1) {
			const peerNames = claimants.map((c) => c.name);
			warnings.push({
				code: "allowedips-conflict",
				subnet,
				peers: peerNames,
				message: `Subnet ${subnet} claimed by multiple peers - only one peer can route this subnet`,
			});
		}
	}

	const nextActions = deriveGlobalNextActions(interfaces, links, routeAnalysis);
	const totalPeers = interfaces.reduce((sum, item) => sum + item.peerCount, 0);
	const activePeers = interfaces.reduce((sum, item) => sum + item.activePeerCount, 0);
	const totalRxBytes = interfaces.reduce((sum, item) => sum + item.rxBytes, 0);
	const totalTxBytes = interfaces.reduce((sum, item) => sum + item.txBytes, 0);
	const peerNetworks = dedupe(interfaces.flatMap((item) => item.peerNetworks));

	if (!(await pathExists("/sys/class/net")))
		warnings.push("/sys/class/net is not mounted; traffic counters are unavailable");
	if (!dumpByInterface.size)
		warnings.push(`No live output from "${wireGuardBin} show all dump"; data may be config-only`);
	if (!routes.all.length) warnings.push(`No route data from "${ipBin} route show"; gateway summary is incomplete`);
	if (!interfaces.length)
		warnings.push("No WireGuard interfaces were discovered from config files or live runtime data");

	return {
		available: true,
		mode: "metadata-write",
		hub,
		interfaces,
		links,
		routes: routeAnalysis,
		topology,
		capabilities: buildCapabilities(),
		metadata: metadataStore,
		summary: {
			interfaceCount: interfaces.length,
			activeInterfaceCount: interfaces.filter((item) => item.active).length,
			totalPeers,
			activePeers,
			totalRxBytes,
			totalTxBytes,
			peerNetworkCount: peerNetworks.length,
			wireguardRouteCount: routes.wireguard.length,
			privateRouteCount: routes.privateRoutes.length,
			linkCount: links.length,
			siteLinkCount: topology.siteLinks.length,
			hubLinkCount: topology.hubLinks.length,
			clientLinkCount: topology.clientLinks.length,
		},
		warnings,
		nextActions,
	};
}

// ─── Hub wg0.conf sync ───────────────────────────────────────────────────────
//
// Keeps /etc/wireguard/<iface>.conf in sync with the metadata store.
// Called automatically after applyMetadata when importedNetworks change.
//
// Per peer:
//   AllowedIPs = <existing /32+/128 tunnel IPs> + <metadata importedNetworks>
// Peers without a metadata entry are left unchanged.
// PostUp/PostDown ip-route lines are rebuilt from the union of all effective AllowedIPs.

/**
 * Discover non-WireGuard network interfaces that carry private IPv4 subnets.
 * Returns an array of { name, address, netmask, cidr } for each qualifying address.
 * Used to auto-generate MASQUERADE rules so wg0-sourced traffic can exit via
 * physical interfaces (e.g. eth1 for a LAN behind the hub).
 */
function _getPrivatePhysicalInterfaces() {
	const nics = networkInterfaces();
	const result = [];
	for (const [name, addrs] of Object.entries(nics)) {
		if (name.startsWith("wg") || name === "lo") continue;
		for (const addr of addrs || []) {
			if (addr.family !== "IPv4" || addr.internal) continue;
			if (!isPrivateNetwork(addr.address)) continue;
			// Derive CIDR from netmask prefix length
			const prefix = addr.cidr ? addr.cidr : `${addr.address}/${addr.netmask}`;
			result.push({ name, address: addr.address, cidr: prefix });
		}
	}
	return result;
}

function _parsePeersFromConf(lines) {
	const peers = new Map(); // pubkey → current AllowedIPs string[]
	let inPeer = false;
	let currentPubKey = null;
	let currentAllowedIPs = [];

	const flush = () => {
		if (inPeer && currentPubKey) peers.set(currentPubKey, [...currentAllowedIPs]);
	};

	for (const rawLine of lines) {
		const trimmed = rawLine.trim();
		if (trimmed === "[Peer]") {
			flush();
			inPeer = true;
			currentPubKey = null;
			currentAllowedIPs = [];
			continue;
		}
		if (trimmed.startsWith("[")) {
			flush();
			inPeer = false;
			currentPubKey = null;
			continue;
		}
		if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
		const eqIdx = trimmed.indexOf("=");
		const k = trimmed.slice(0, eqIdx).trim();
		const v = trimmed.slice(eqIdx + 1).trim();
		if (inPeer) {
			if (k === "PublicKey") currentPubKey = v;
			if (k === "AllowedIPs")
				currentAllowedIPs = v
					.split(",")
					.map((s) => s.trim())
					.filter(Boolean);
		}
	}
	flush();
	return peers;
}

function _buildPeerUpdates(peerMap, linksMeta, ifaceName) {
	const updates = new Map(); // pubkey → new AllowedIPs[]
	for (const [pubkey, currentCIDRs] of peerMap) {
		const meta = linksMeta[`${ifaceName}:${pubkey}`];
		if (!meta) continue; // unmanaged peer — leave unchanged
		const hostRoutes = currentCIDRs.filter((c) => c.endsWith("/32") || c.endsWith("/128"));

		// Client peers only get their tunnel IP on the hub side.
		// Their importedNetworks define what the CLIENT can reach (goes into the
		// downloaded client config), not what the hub routes toward them.
		// Only an EXPLICITLY-typed client is reduced to host routes. An untyped link
		// (legacy / imported / plan-created) must NOT be degraded to client by the
		// ≤1-route heuristic of classifyLinkType — that strips a real single-subnet
		// site from the hub peer while _collectSiteNetworks (agent-side) keeps
		// advertising it to every other agent (split-brain). Untyped defaults to site,
		// matching _collectSiteNetworks.
		if (normalizeLinkType(meta.type) === "client") {
			const newIPs = [...new Set(hostRoutes)];
			if ([...newIPs].sort().join(",") !== [...currentCIDRs].sort().join(",")) {
				updates.set(pubkey, newIPs);
			}
			continue;
		}

		const imported = (meta.importedNetworks || []).filter((c) => !c.endsWith("/32") && !c.endsWith("/128"));
		// Hub authoritative on full removal: only fall back to the conf's current
		// non-host CIDRs when the metadata has NO importedNetworks key at all
		// (legacy / hand-maintained peer). An explicit empty array means "all site
		// networks revoked" and must drop the subnet — falling back to currentNonHost
		// there re-injected the just-removed net and made REMOVE never propagate
		// hub-side (sibling of the fixed agent-side _computeHubPeerAllowedIPs bug).
		const currentNonHost = currentCIDRs.filter((c) => !c.endsWith("/32") && !c.endsWith("/128"));
		const effectiveNets = Object.hasOwn(meta, "importedNetworks") ? imported : currentNonHost;
		const newIPs = [...new Set([...hostRoutes, ...effectiveNets])];
		if ([...newIPs].sort().join(",") !== [...currentCIDRs].sort().join(",")) {
			updates.set(pubkey, newIPs);
		}
	}
	return updates;
}

function _rewriteHubConf(lines, ifaceName, peerUpdates, allRouteNets, masqueradeIfaces = []) {
	let inPeer = false;
	let currentPubKey = null;
	const out = [];
	for (const rawLine of lines) {
		const t = rawLine.trim();
		if (t === "[Peer]") {
			inPeer = true;
			currentPubKey = null;
			out.push(rawLine);
			continue;
		}
		if (t.startsWith("[")) {
			inPeer = false;
			currentPubKey = null;
			out.push(rawLine);
			continue;
		}
		if (inPeer && t.startsWith("PublicKey")) {
			currentPubKey = t.slice(t.indexOf("=") + 1).trim();
			out.push(rawLine);
			continue;
		}
		if (inPeer && t.startsWith("AllowedIPs") && currentPubKey && peerUpdates.has(currentPubKey)) {
			out.push(`AllowedIPs = ${peerUpdates.get(currentPubKey).join(", ")}`);
			continue;
		}
		if (!inPeer && (t.startsWith("PostUp") || t.startsWith("PostDown"))) {
			const isUp = t.startsWith("PostUp");
			const key = isUp ? "PostUp" : "PostDown";
			const verb = isUp ? "add" : "del";
			const iptVerb = isUp ? "-A" : "-D";
			const value = rawLine.slice(rawLine.indexOf("=") + 1).trim();
			const routeRe = new RegExp(`^ip route (?:add|del) \\S+ dev ${ifaceName}`);
			const masqRe = /^iptables -t nat -[AD] POSTROUTING (?:-[os] \S+ ){2}-j MASQUERADE$/;
			const nonRoute = value
				.split(";")
				.map((s) => s.trim())
				.filter((p) => p && !routeRe.test(p) && !masqRe.test(p));
			const routeCmds = [...allRouteNets]
				.sort()
				.map((net) => `ip route ${verb} ${net} dev ${ifaceName} 2>/dev/null || true`);
			// Auto-MASQUERADE: for each physical interface with a private IP,
			// ensure wg-sourced traffic going out that interface gets NATed.
			const masqCmds = [];
			for (const nic of masqueradeIfaces) {
				masqCmds.push(`iptables -t nat ${iptVerb} POSTROUTING -o ${nic.name} -s ${nic.cidr} -j MASQUERADE`);
			}
			out.push(`${key} = ${[...nonRoute, ...routeCmds, ...masqCmds].join("; ")}`);
			continue;
		}
		out.push(rawLine);
	}

	// If no PostUp/PostDown existed in the original config, inject them before the first [Peer]
	const hasPostUp = lines.some((l) => l.trim().startsWith("PostUp"));
	if (!hasPostUp && (allRouteNets.size > 0 || masqueradeIfaces.length > 0)) {
		const routeUpCmds = [...allRouteNets].sort().map((net) => `ip route add ${net} dev ${ifaceName} 2>/dev/null || true`);
		const routeDownCmds = [...allRouteNets].sort().map((net) => `ip route del ${net} dev ${ifaceName} 2>/dev/null || true`);
		const masqUpCmds = masqueradeIfaces.map((nic) => `iptables -t nat -A POSTROUTING -o ${nic.name} -s ${nic.cidr} -j MASQUERADE`);
		const masqDownCmds = masqueradeIfaces.map((nic) => `iptables -t nat -D POSTROUTING -o ${nic.name} -s ${nic.cidr} -j MASQUERADE 2>/dev/null || true`);
		const postUp = [...routeUpCmds, ...masqUpCmds].join("; ");
		const postDown = [...routeDownCmds, ...masqDownCmds].join("; ");
		// Insert before the first [Peer] line
		const peerIdx = out.findIndex((l) => l.trim() === "[Peer]");
		const insertAt = peerIdx > 0 ? peerIdx : out.length;
		const newLines = [];
		if (postUp) newLines.push(`PostUp = ${postUp}`);
		if (postDown) newLines.push(`PostDown = ${postDown}`);
		out.splice(insertAt, 0, ...newLines);
	}

	return out.join("\n");
}

/**
 * Remove a [Peer] block (and its preceding comment line) from a wg-quick conf.
 * Returns the rewritten config text.
 */
function _removePeerFromConf(confText, targetPubKey) {
	const lines = confText.split(/\r?\n/);
	const out = [];
	let inPeer = false;
	let skipBlock = false;
	let currentPubKey = null;
	// Buffer lines within a [Peer] block until we know the PublicKey
	let peerBuffer = [];

	const flushBuffer = (skip) => {
		if (!skip) {
			// If the line before [Peer] is a comment, it was already pushed to out.
			// We need to remove it if we're skipping this block.
			out.push(...peerBuffer);
		} else {
			// Remove preceding comment line(s) that belong to this peer
			while (out.length > 0 && out[out.length - 1].trim().startsWith("#")) {
				out.pop();
			}
			// Also remove trailing blank lines before the comment
			while (out.length > 0 && out[out.length - 1].trim() === "") {
				out.pop();
			}
		}
		peerBuffer = [];
	};

	for (const rawLine of lines) {
		const t = rawLine.trim();
		if (t === "[Peer]") {
			if (inPeer) flushBuffer(skipBlock);
			inPeer = true;
			skipBlock = false;
			currentPubKey = null;
			peerBuffer = [rawLine];
			continue;
		}
		if (t.startsWith("[") && t !== "[Peer]") {
			if (inPeer) flushBuffer(skipBlock);
			inPeer = false;
			skipBlock = false;
			out.push(rawLine);
			continue;
		}
		if (inPeer) {
			peerBuffer.push(rawLine);
			if (t.startsWith("PublicKey")) {
				currentPubKey = t.slice(t.indexOf("=") + 1).trim();
				if (currentPubKey === targetPubKey) skipBlock = true;
			}
			continue;
		}
		out.push(rawLine);
	}
	// Flush last peer block
	if (inPeer) flushBuffer(skipBlock);

	// Clean up trailing blank lines
	while (out.length > 0 && out[out.length - 1].trim() === "") {
		out.pop();
	}
	return `${out.join("\n")}\n`;
}

/**
 * Delete a WireGuard peer from the live interface, config file, and metadata.
 * @param {string} linkId - Format: "ifaceName:publicKey"
 */
async function deletePeer(linkId) {
	if (!linkId?.includes(":")) {
		throw new Error("Invalid linkId format — expected ifaceName:publicKey");
	}

	const colonIdx = linkId.indexOf(":");
	const ifaceName = linkId.slice(0, colonIdx);
	const publicKey = linkId.slice(colonIdx + 1);

	if (!ifaceName || !publicKey) {
		throw new Error("Invalid linkId — interface name and public key are required");
	}

	const status = await getStatus();
	if (!status.available) throw new Error("WireGuard is not available");

	const iface = status.interfaces.find((i) => i.name === ifaceName);
	if (!iface) throw new Error(`Interface ${ifaceName} not found`);

	const link = status.links.find((l) => l.id === linkId);
	if (!link) throw new Error(`Link not found: ${linkId}`);

	// ── Backup metadata before any changes ──
	await backupMetadataStore();

	// ── Remove from live interface ──
	const wgBin = getWireGuardBin();
	try {
		await execFileAsync(wgBin, ["set", ifaceName, "peer", publicKey, "remove"]);
	} catch (err) {
		logger.debug(`Peer ${publicKey.slice(0, 8)}… not active on ${ifaceName}, skipping live removal: ${err.message}`);
	}

	// ── Remove from config file (locked RMW — serialize with createPeer's locked
	// appendFile so a concurrent create can't have its [Peer] block read out here
	// and clobbered by this writeFile). ──
	const confPath = path.join(getWireGuardConfDir(), `${ifaceName}.conf`);
	try {
		await withWriteLock(async () => {
			const confText = await fs.readFile(confPath, "utf8");
			const newConf = _removePeerFromConf(confText, publicKey);
			await fs.writeFile(confPath, newConf, "utf8");
		});
	} catch (err) {
		logger.warn(`Could not update conf for ${ifaceName} during peer deletion: ${err.message}`);
	}

	// ── Remove exclusive routes ──
	const peerNonHostNets = (link.allowedIps || []).filter((cidr) => !cidr.endsWith("/32") && !cidr.endsWith("/128"));
	if (peerNonHostNets.length > 0) {
		// Collect all other peers' non-host networks
		const otherNets = new Set();
		for (const otherLink of status.links) {
			if (otherLink.id === linkId) continue;
			for (const cidr of otherLink.allowedIps || []) {
				if (!cidr.endsWith("/32") && !cidr.endsWith("/128")) otherNets.add(cidr);
			}
		}
		const ipBin = getIpBin();
		for (const net of peerNonHostNets) {
			if (!otherNets.has(net)) {
				try {
					await execFileAsync(ipBin, ["route", "del", net, "dev", ifaceName]);
				} catch (err) {
					logger.debug(`Route del ${net} dev ${ifaceName}: ${err.message}`);
				}
			}
		}
	}

	// ── Remove metadata (locked RMW — else a concurrent save resurrects the link) ──
	const store = await mutateMetadataStore((s) => {
		delete s.links[linkId];
	});

	// Drop any cached peer config for the removed link so it can't be re-served.
	_peerConfigCache.clear();

	// ── Rebuild the hub conf so the deleted net's PostUp `ip route add <net> dev wg0`
	// line is removed. Without this it survives in wg0.conf and a later wg-quick
	// restart/reboot re-creates the route to a net no peer serves (blackhole). ──
	let hubSync;
	try {
		hubSync = await syncHubConf(store, ifaceName);
	} catch (err) {
		logger.error(`Hub conf sync after deletePeer (${linkId}) failed: ${err.message}`);
		hubSync = { error: err.message };
	}

	// ── Resync agents so the deleted site's networks drop out of every OTHER
	// agent's AllowedIPs + PostUp route + MASQUERADE. Without this, syncAgentConfigs
	// never recomputes, config_hash stays unchanged, the 30s poll is a no-op, and
	// the removed LAN stays routed (blackholed) on every mesh agent forever. ──
	let agentSync;
	try {
		// Run the agent resync under the write lock on FRESHLY-read metadata so a
		// concurrent mutation's sync (built from an older snapshot) can never land
		// last and overwrite this delete with a stale config that re-advertises the
		// removed network fleet-wide. Mirrors the locked reconciler in agent.js.
		agentSync = await withWriteLock(async () => {
			const { default: internalAgent } = await import("./agent.js");
			const fresh = await readMetadataStore();
			return internalAgent.syncAgentConfigs(fresh);
		});
	} catch (err) {
		logger.error(`Agent config sync after deletePeer (${linkId}) failed: ${err.message}`);
		agentSync = { error: err.message };
	}

	return { deleted: true, linkId, hubSync, agentSync };
}

/**
 * Update a WireGuard peer's config-level properties (AllowedIPs).
 * Updates metadata, rewrites conf, and applies live via wg set + route sync.
 * @param {string} linkId - Format: "ifaceName:publicKey"
 * @param {object} changes - { importedNetworks?: string[] }
 */
async function updatePeer(linkId, changes = {}) {
	if (!linkId?.includes(":")) {
		throw new Error("Invalid linkId format — expected ifaceName:publicKey");
	}

	const colonIdx = linkId.indexOf(":");
	const ifaceName = linkId.slice(0, colonIdx);
	const publicKey = linkId.slice(colonIdx + 1);

	if (!ifaceName || !publicKey) {
		throw new Error("Invalid linkId — interface name and public key are required");
	}

	const status = await getStatus();
	if (!status.available) throw new Error("WireGuard is not available");

	const iface = status.interfaces.find((i) => i.name === ifaceName);
	if (!iface) throw new Error(`Interface ${ifaceName} not found`);

	const link = status.links.find((l) => l.id === linkId);
	if (!link) throw new Error(`Link not found: ${linkId}`);

	// ── AllowedIPs conflict check for importedNetworks changes ──
	// Skip for client links: importedNetworks is a reach list, not hub-side routing, so
	// it cannot conflict (mirrors createPeer and the /metadata + plan-preview checks).
	if (changes.importedNetworks !== undefined) {
		const effectiveType = changes.type ?? link.type;
		if (effectiveType !== "client") {
			const newNets = sanitizeNetworkArray(changes.importedNetworks);
			const otherLinks = status.links.filter((l) => l.id !== linkId);
			const conflicts = checkAllowedIPsConflicts(newNets, otherLinks);
			if (conflicts.length > 0) {
				const details = conflicts.map((c) => `${c.subnet} already claimed by ${c.peer}`).join("; ");
				throw new Error(`AllowedIPs conflict: ${details}`);
			}
		}
	}

	// ── Backup metadata ──
	await backupMetadataStore();

	// ── Update metadata with new values ──
	const metadataPatch = {};
	if (changes.importedNetworks !== undefined) {
		metadataPatch.importedNetworks = sanitizeNetworkArray(changes.importedNetworks);
	}
	if (changes.name !== undefined) {
		metadataPatch.name = changes.name ? stripLinkNameControlChars(changes.name) : undefined;
	}
	if (changes.type !== undefined) {
		metadataPatch.type = normalizeLinkType(changes.type);
	}
	if (changes.dns !== undefined) {
		metadataPatch.dns = sanitizeStringArray(changes.dns);
	}
	if (changes.fullTunnel !== undefined) {
		metadataPatch.fullTunnel = Boolean(changes.fullTunnel);
	}
	if (changes.platform !== undefined) {
		metadataPatch.platform = ["desktop", "mobile"].includes(changes.platform) ? changes.platform : undefined;
	}

	let oldName;
	const store = await mutateMetadataStore((s) => {
		oldName = s.links[linkId]?.name;
		assertUniqueLinkName(s, linkId, metadataPatch.name, oldName);
		s.links[linkId] = mergeMetadataEntry(s.links[linkId] || {}, metadataPatch);
	});

	// Drop any cached peer configs — the link's AllowedIPs/DNS may have changed and a
	// stale cached config must not be re-served on the next download/QR.
	_peerConfigCache.clear();

	// Cascade a rename to agent bindings so renamed links don't orphan their agents.
	if (metadataPatch.name && oldName && metadataPatch.name !== oldName) {
		try {
			const { default: internalAgent } = await import("./agent.js");
			await internalAgent.renameLinkBinding(oldName, metadataPatch.name);
		} catch (err) {
			logger.error(`Link rename cascade ${oldName}→${metadataPatch.name} failed: ${err.message}`);
		}
	}

	// ── Sync hub conf (rewrites AllowedIPs in conf + live wg set + routes) ──
	const hubSync = await syncHubConf(store, ifaceName);

	// ── Sync agent configs (push updated AllowedIPs to remote agents) ──
	let agentSync;
	try {
		// Locked + fresh-read so a concurrent mutation's older-snapshot sync can't
		// land last and clobber this update (see deletePeer for the full rationale).
		agentSync = await withWriteLock(async () => {
			const { default: internalAgent } = await import("./agent.js");
			const fresh = await readMetadataStore();
			return internalAgent.syncAgentConfigs(fresh);
		});
	} catch (err) {
		// Surface, don't swallow: a poisoned sibling link (e.g. an IPv6/prefixless
		// net that passes isValidNetwork but trips assertCIDR) throws here and
		// leaves EVERY agent's config stale. Log at error and report it so the
		// admin sees the update didn't propagate, matching agent.js update().
		logger.error(`Agent config sync after updatePeer (${linkId}) failed: ${err.message}`);
		agentSync = { error: err.message };
	}

	return { updated: true, linkId, hubSync, agentSync };
}

// Public entry point: serialize the whole conf read-modify-write under the module
// write lock so it can't interleave with createPeer's locked appendFile (which would
// otherwise lose a freshly-added [Peer] block from the conf — see mutex note above).
// createPeer already holds the lock, so it calls _syncHubConfCore directly instead.
async function syncHubConf(metadata, ifaceName = "wg0") {
	return withWriteLock(() => _syncHubConfCore(metadata, ifaceName));
}

async function _syncHubConfCore(metadata, ifaceName = "wg0") {
	const confPath = path.join(getWireGuardConfDir(), `${ifaceName}.conf`);
	let confText;
	try {
		confText = await fs.readFile(confPath, "utf8");
	} catch {
		return { synced: false, reason: "no-conf-file" };
	}

	const lines = confText.split(/\r?\n/);
	const peerMap = _parsePeersFromConf(lines);
	const peerUpdates = _buildPeerUpdates(peerMap, metadata.links || {}, ifaceName);

	// Also detect live-vs-conf drift: if conf has AllowedIPs that differ from
	// the running interface, force a wg set even if metadata didn't change.
	let liveDump;
	try {
		liveDump = parseDump(await getDump());
	} catch (err) {
		logger.debug(`Live dump for sync failed: ${err.message}`);
		liveDump = new Map();
	}
	const liveIface = liveDump.get(ifaceName);
	if (liveIface) {
		for (const [pubkey, confCIDRs] of peerMap) {
			if (peerUpdates.has(pubkey)) continue; // already scheduled for update
			const livePeer = liveIface.peers.find((p) => p.publicKey === pubkey);
			if (!livePeer) continue;
			const liveIPs = [...(livePeer.allowedIps || [])].sort().join(",");
			const confIPs = [...confCIDRs].sort().join(",");
			if (liveIPs !== confIPs) {
				peerUpdates.set(pubkey, confCIDRs);
			}
		}
	}

	// NOTE: do NOT early-return when peerUpdates is empty. The live route
	// reconciliation (add missing + prune stale) below must still run so a route
	// whose `ip route del` transiently failed on the removing change gets pruned on
	// the next sync, even though there is no AllowedIPs delta then. Only the conf
	// rewrite + `wg set` are gated on peerUpdates.size.

	// All non-/32 networks across all peers (effective values after updates)
	const allRouteNets = new Set();
	for (const [pubkey, currentCIDRs] of peerMap) {
		const effective = peerUpdates.has(pubkey) ? peerUpdates.get(pubkey) : currentCIDRs;
		for (const cidr of effective) {
			// Sink-side guard: these values are interpolated into `ip route add <net>`
			// shell strings executed as root. Drop anything that isn't a clean
			// IPv4/IPv6 CIDR, even if it was already persisted in an existing conf.
			if (!cidr.endsWith("/32") && !cidr.endsWith("/128") && isValidNetwork(cidr)) allRouteNets.add(cidr);
		}
	}

	// Exclude networks already directly connected on physical interfaces —
	// adding a wg0 route for these would override the local LAN route.
	const physNetsForExclusion = _getPrivatePhysicalInterfaces();
	for (const nic of physNetsForExclusion) {
		if (allRouteNets.has(nic.cidr)) {
			allRouteNets.delete(nic.cidr);
		}
	}

	// Discover physical interfaces with private IPs for auto-MASQUERADE.
	// wg0 peers that route traffic to subnets reachable via eth1/ens* etc.
	// need MASQUERADE so return packets find their way back through the tunnel.
	const physicalIfaces = _getPrivatePhysicalInterfaces();
	// Derive the WireGuard tunnel subnet from the Address line (e.g. 10.10.0.0/24)
	const addrLine = lines.find((l) => /^\s*Address\s*=/i.test(l));
	let tunnelSubnet = "10.10.0.0/24";
	if (addrLine) {
		const am = addrLine.match(/(\d+\.\d+\.\d+)\.\d+\/(\d+)/);
		if (am) {
			const mask = Number.parseInt(am[2], 10);
			tunnelSubnet = `${am[1]}.0/${mask > 24 ? 24 : mask}`;
		}
	}
	// Build a deduplicated list: one entry per (nicName, nicCidr) pair.
	// For each physical interface we need TWO MASQUERADE rules:
	//   1. -s <nic.cidr> -o <nic.name>  (traffic from the physical subnet itself)
	//   2. -s <tunnelSubnet> -o <nic.name> (WG peers reaching hosts on that LAN)
	const masqueradeIfaces = [];
	const seenMasq = new Set();
	for (const nic of physicalIfaces) {
		const key1 = `${nic.name}:${nic.cidr}`;
		if (!seenMasq.has(key1)) {
			seenMasq.add(key1);
			masqueradeIfaces.push(nic);
		}
		const key2 = `${nic.name}:${tunnelSubnet}`;
		if (!seenMasq.has(key2)) {
			seenMasq.add(key2);
			masqueradeIfaces.push({ name: nic.name, address: nic.address, cidr: tunnelSubnet });
		}
	}

	const wgBin = getWireGuardBin();
	const ipBin = getIpBin();
	const changes = [];

	// Rewrite the conf whenever its content would change — NOT only when a peer's
	// AllowedIPs changed. A newly-added site peer adds routes (PostUp `ip route add`
	// + MASQUERADE) without any AllowedIPs delta, so gating the rewrite on
	// peerUpdates.size left those PostUp lines out of the conf: the live route was
	// added below but every wg-quick restart/reboot dropped it again. Diff the rebuilt
	// conf against the normalized on-disk text and write only on a real change.
	const normalizedOriginal = lines.join("\n");
	const newText = _rewriteHubConf(lines, ifaceName, peerUpdates, allRouteNets, masqueradeIfaces);
	if (newText !== normalizedOriginal) {
		await fs.writeFile(confPath, newText, "utf8");
	}

	// Live `wg set` is still gated on an actual AllowedIPs change — only peers whose
	// cryptokey routing changed need re-applying.
	if (peerUpdates.size) {
		for (const [pubkey, newIPs] of peerUpdates) {
			try {
				await execFileAsync(wgBin, ["set", ifaceName, "peer", pubkey, "allowed-ips", newIPs.join(",")]);
				changes.push({ peer: `${pubkey.slice(0, 8)}…`, allowedIPs: newIPs });
			} catch (err) {
				logger.debug(`wg set peer ${pubkey.slice(0, 8)}… skipped (not connected): ${err.message}`);
			}
		}
	}

	// Add any newly required routes live, and PRUNE stale ones. With `Table = off`
	// wg-quick manages no routes, so a route added for a now-removed net survives
	// `wg set allowed-ips` shrinking and keeps blackholing traffic until a manual
	// wg-quick restart. Mirror the agent-side sync_routes reconciler: delete wg0
	// routes whose net is no longer in any peer's effective AllowedIPs. Never touch
	// the kernel-connected tunnel route (proto kernel) or host (/32,/128) routes.
	try {
		const { stdout } = await execFileAsync(ipBin, ["route", "show", "dev", ifaceName]);
		const routeLines = stdout
			.split("\n")
			.map((l) => l.trim())
			.filter(Boolean);
		const existing = new Set(routeLines.map((l) => l.split(/\s/)[0]).filter(Boolean));
		for (const net of allRouteNets) {
			if (!existing.has(net)) {
				try {
					await execFileAsync(ipBin, ["route", "add", net, "dev", ifaceName]);
				} catch (err) {
					logger.debug(`Route add ${net} dev ${ifaceName}: ${err.message}`);
				}
			}
		}
		for (const line of routeLines) {
			const prefix = line.split(/\s/)[0];
			if (!prefix?.includes("/")) continue;
			if (prefix.endsWith("/32") || prefix.endsWith("/128")) continue;
			if (line.includes("proto kernel")) continue; // connected tunnel/LAN route
			if (prefix === tunnelSubnet) continue;
			if (allRouteNets.has(prefix)) continue; // still routed
			try {
				await execFileAsync(ipBin, ["route", "del", prefix, "dev", ifaceName]);
				changes.push({ routeRemoved: prefix });
			} catch (err) {
				logger.debug(`Stale route del ${prefix} dev ${ifaceName}: ${err.message}`);
			}
		}
	} catch (err) {
		logger.debug(`Route lookup for ${ifaceName} failed: ${err.message}`);
	}

	return { synced: true, changes };
}

// ─── Bandwidth ring buffer ────────────────────────────────────────────────────
// Polls `wg show all dump` every BW_POLL_INTERVAL ms, computes per-peer
// RX/TX byte deltas and stores up to BW_HISTORY_SIZE rate samples per peer.

const BW_HISTORY_SIZE = 60; // samples (= 10 min at 10 s interval)
const BW_POLL_INTERVAL = 10_000; // ms

/** Map<peerKey, Array<{ts: number, rx: number, tx: number}>> — rates in bytes/s */
const _bwHistory = new Map();
/** Map<peerKey, {ts: number, rxBytes: number, txBytes: number}> — previous raw counters */
let _bwPrev = null;

async function _pollBandwidth() {
	try {
		const now = Date.now();
		const dump = parseDump(await getDump());
		const snap = new Map();
		for (const [iface, data] of dump) {
			for (const peer of data.peers) {
				if (!peer.publicKey) continue;
				const key = `${iface}:${peer.publicKey}`;
				snap.set(key, { ts: now, rxBytes: peer.rxBytes, txBytes: peer.txBytes });
			}
		}
		if (_bwPrev) {
			const dt = (now - _bwPrev.get("__ts__")) / 1000 || BW_POLL_INTERVAL / 1000;
			for (const [key, curr] of snap) {
				if (key === "__ts__") continue;
				const prev = _bwPrev.get(key);
				if (!prev) continue;
				const rx = Math.max(0, curr.rxBytes - prev.rxBytes) / dt;
				const tx = Math.max(0, curr.txBytes - prev.txBytes) / dt;
				const history = _bwHistory.get(key) ?? [];
				history.push({ ts: now, rx: Math.round(rx), tx: Math.round(tx) });
				if (history.length > BW_HISTORY_SIZE) history.shift();
				_bwHistory.set(key, history);
			}
		}
		snap.set("__ts__", now);
		_bwPrev = snap;
	} catch (err) {
		logger.debug(`Bandwidth poll error: ${err.message}`);
	}
}

// Lazy-initialize bandwidth polling on first getBandwidth() or getStatus() call,
// not at module import — avoids unnecessary `wg show` calls when WireGuard is not installed.
let _bwTimer = null;
function _ensureBandwidthPolling() {
	if (_bwTimer) return;
	_pollBandwidth();
	_bwTimer = setInterval(_pollBandwidth, BW_POLL_INTERVAL);
	if (typeof _bwTimer.unref === "function") _bwTimer.unref();
}

/**
 * Returns the bandwidth ring buffer, annotated with link names from metadata.
 * Each entry: { id, name, history: [{ts, rx, tx}] }
 */
async function getBandwidth() {
	_ensureBandwidthPolling();
	const metadataStore = await readMetadataStore();
	const result = [];
	for (const [key, history] of _bwHistory) {
		const linkMeta = metadataStore.links?.[key] ?? {};
		result.push({ id: key, name: linkMeta.name || key, history });
	}
	// Sort by most recently active (last sample tx+rx descending)
	result.sort((a, b) => {
		const lastA = a.history.at(-1);
		const lastB = b.history.at(-1);
		return (lastB?.rx ?? 0) + (lastB?.tx ?? 0) - ((lastA?.rx ?? 0) + (lastA?.tx ?? 0));
	});
	return result;
}

/**
 * Check if any of the proposed subnets conflict with existing links' AllowedIPs.
 * Returns an array of { subnet, peer } for each conflict found.
 */
function checkAllowedIPsConflicts(proposedNets, existingLinks) {
	if (!proposedNets?.length) return [];
	const conflicts = [];
	for (const net of proposedNets) {
		if (isHostRoute(net)) continue;
		for (const link of existingLinks) {
			const linkNets = (link.allowedIps || []).filter((ip) => !isHostRoute(ip));
			if (linkNets.includes(net)) {
				conflicts.push({ subnet: net, peer: link.name || link.id });
			}
		}
	}
	return conflicts;
}

export {
	_buildPeerUpdates,
	canonicalizeIpv4Network,
	isValidInterfaceAddress,
	withWriteLock,
	buildLinkRecord,
	buildRouteAnalysis,
	buildTopology,
	classifyLinkType,
	clearPeerConfigCache,
	dedupe,
	deriveGlobalNextActions,
	deriveGlobalWarnings,
	enrichInterfaceStatus,
	enrichLinkRecord,
	getMetadataFile,
	getMissingImportedNetworks,
	getNatCandidateNetworks,
	inferInterfaceRole,
	inferPlanState,
	mergeMetadataEntry,
	mergeMetadataStorePatch,
	normalizeInterfaceRole,
	normalizeLinkType,
	sanitizeInterfaceMetadata,
	sanitizeInterfaceMetadataPatch,
	sanitizeLinkMetadata,
	sanitizeLinkMetadataPatch,
	syncHubConf,
};

/**
 * Create a new WireGuard interface with generated keypair and config file.
 * @param {object} opts
 * @param {string} [opts.name] - Interface name (auto-assigned if omitted: wg2, wg3, …)
 * @param {string} opts.address - Tunnel address with mask, e.g. "10.20.0.1/24"
 * @param {number} [opts.listenPort] - UDP listen port (auto-assigned if omitted)
 * @param {string} [opts.role] - Interface role hint for metadata
 */
const VALID_IFACE_NAME = /^wg\d{1,3}$/;

async function createInterface({ name, address, listenPort, role } = {}) {
	if (!address?.trim()) throw new Error("Address is required (e.g. 10.20.0.1/24)");
	// This value is written verbatim into the wg-quick conf and activated with
	// `wg-quick up`, which runs PostUp/PostDown as root. Reject anything that isn't a
	// single clean IPv4/IPv6 host+prefix so a newline can't inject a PostUp command.
	if (!isValidInterfaceAddress(address)) {
		throw new Error("Invalid address — expected a single IPv4/IPv6 host with prefix, e.g. 10.20.0.1/24");
	}

	const confDir = getWireGuardConfDir();
	const wgBin = getWireGuardBin();

	// Serialize the name/port auto-allocation + conf write + bring-up under the module
	// write lock. Without it two concurrent create-interface calls (double-submit, or
	// two admins) both read the same listConfigNames()/port snapshot before either
	// writes, pick the same wgN + 51820, writeFile the same conf (last writer wins), and
	// the loser's `wg-quick up` fails — its catch then unlink()s the conf the WINNER is
	// now running from, leaving metadata that references an interface with no conf file.
	// mutateMetadataStore (below) takes this same lock and is NOT re-entrant, so it stays
	// outside this block.
	let publicKey;
	await withWriteLock(async () => {
		// ── Auto-assign interface name if not provided ──
		if (!name) {
			const existing = await listConfigNames();
			for (let i = 0; i < 100; i++) {
				const candidate = `wg${i}`;
				if (!existing.includes(candidate)) {
					name = candidate;
					break;
				}
			}
			if (!name) throw new Error("No free interface name available");
		}

		if (!VALID_IFACE_NAME.test(name)) {
			throw new Error(`Invalid interface name "${name}" — must match wgN (e.g. wg0, wg1)`);
		}

		const confPath = path.join(confDir, `${name}.conf`);
		if (await pathExists(confPath)) {
			throw new Error(`Interface ${name} already exists`);
		}

		// ── Auto-assign listen port if not provided ──
		if (!listenPort) {
			const existing = await listConfigNames();
			const usedPorts = new Set();
			for (const n of existing) {
				const conf = parseConfig(await readText(path.join(confDir, `${n}.conf`)));
				if (conf.listenPort) usedPorts.add(conf.listenPort);
			}
			for (let port = 51820; port < 51920; port++) {
				if (!usedPorts.has(port)) {
					listenPort = port;
					break;
				}
			}
			if (!listenPort) throw new Error("No free listen port available");
		}

		// ── Generate keypair ──
		const { stdout: privKeyRaw } = await execFileAsync(wgBin, ["genkey"]);
		const privateKey = privKeyRaw.trim();
		publicKey = derivePublicKey(privateKey);

		// ── Write config file ──
		const confLines = [
			"[Interface]",
			`Address = ${address.trim()}`,
			`ListenPort = ${listenPort}`,
			`PrivateKey = ${privateKey}`,
			"Table = off",
			`PostUp = iptables -A FORWARD -i ${name} -j ACCEPT; iptables -A FORWARD -o ${name} -j ACCEPT`,
			`PostDown = iptables -D FORWARD -i ${name} -j ACCEPT; iptables -D FORWARD -o ${name} -j ACCEPT`,
			"",
		];
		await fs.writeFile(confPath, confLines.join("\n"), "utf8");

		// ── Bring interface up ──
		try {
			await execFileAsync("wg-quick", ["up", name]);
		} catch (err) {
			// Clean up conf if wg-quick fails
			await fs.unlink(confPath).catch(() => {});
			throw new Error(`Failed to bring up ${name}: ${err.message}`);
		}

		// ── Enable on boot ──
		try {
			await execFileAsync("systemctl", ["enable", `wg-quick@${name}`]);
		} catch (err) {
			logger.warn(`Failed to enable wg-quick@${name} on boot: ${err.message}`);
		}
	});

	// ── Write metadata (locked RMW) ──
	await mutateMetadataStore((s) => {
		s.interfaces[name] = sanitizeInterfaceMetadataPatch({
			role: role || "auxiliary",
			managementMode: "local",
		});
	});

	return {
		created: true,
		name,
		address: address.trim(),
		listenPort,
		publicKey,
	};
}

/**
 * Delete a WireGuard interface: bring it down, remove config, clean metadata.
 * @param {string} name - Interface name (e.g. "wg1")
 */
async function deleteInterface(rawName) {
	if (!rawName?.trim()) throw new Error("Interface name is required");
	const name = rawName.trim();

	if (!VALID_IFACE_NAME.test(name)) {
		throw new Error(`Invalid interface name "${name}" — must match wgN (e.g. wg0, wg1)`);
	}
	if (name === "wg0") throw new Error("Cannot delete the primary hub interface wg0");

	const confDir = getWireGuardConfDir();
	const confPath = path.join(confDir, `${name}.conf`);

	if (!(await pathExists(confPath))) {
		throw new Error(`Interface ${name} not found — no config file at ${confPath}`);
	}

	// ── Backup metadata ──
	await backupMetadataStore();

	// ── Bring interface down ──
	try {
		await execFileAsync("wg-quick", ["down", name]);
	} catch (err) {
		logger.debug(`wg-quick down ${name}: ${err.message}`);
	}

	// ── Disable on boot ──
	try {
		await execFileAsync("systemctl", ["disable", `wg-quick@${name}`]);
	} catch (err) {
		logger.debug(`systemctl disable wg-quick@${name}: ${err.message}`);
	}

	// ── Remove config file ──
	await fs.unlink(confPath);

	// ── Clean metadata — remove interface + all its links (locked RMW) ──
	await mutateMetadataStore((s) => {
		delete s.interfaces[name];
		for (const linkId of Object.keys(s.links)) {
			if (linkId.startsWith(`${name}:`)) {
				delete s.links[linkId];
			}
		}
	});

	// Drop any cached peer configs for the removed interface's links.
	_peerConfigCache.clear();

	// ── Resync agents: a deleted interface's site networks feed allSiteNets
	// cross-interface, so every mesh agent (including those on OTHER interfaces)
	// must recompute or it keeps routing the now-dead LANs (AllowedIPs + route +
	// MASQUERADE) forever. ──
	let agentSync;
	try {
		// Locked + fresh-read so a concurrent mutation's older-snapshot sync can't
		// land last and clobber this delete (see deletePeer for the full rationale).
		agentSync = await withWriteLock(async () => {
			const { default: internalAgent } = await import("./agent.js");
			const fresh = await readMetadataStore();
			return internalAgent.syncAgentConfigs(fresh);
		});
	} catch (err) {
		logger.error(`Agent config sync after deleteInterface (${name}) failed: ${err.message}`);
		agentSync = { error: err.message };
	}

	return { deleted: true, name, agentSync };
}

/**
 * Create a new WireGuard peer on the hub interface.
 * Generates a keypair, assigns the next free tunnel IP, adds the peer to the
 * live interface and config file, writes metadata, and returns the client config.
 */
async function createPeer({ name, type, dns, fullTunnel, platform, importedNetworks, ifaceName = "wg0" }) {
	// Reject control characters (incl. newlines) in the name BEFORE any side effects:
	// it is written verbatim as a `# <name>` comment line into the wg-quick conf, so a
	// newline could inject a root-executed PostUp (see isSafeLinkName).
	if (name != null && !isSafeLinkName(name)) {
		throw new Error("Invalid name — control characters (including newlines) are not allowed");
	}
	return withWriteLock(async () => {
	const status = await getStatus();
	if (!status.available) throw new Error("WireGuard is not available");

	const iface = status.interfaces.find((i) => i.name === ifaceName);
	if (!iface) throw new Error(`Interface ${ifaceName} not found`);

	// ── Find next free tunnel IP ──
	// Compute the host range from the hub's ACTUAL prefix instead of assuming /24.
	// Hardcoding /24 (scan .2-.254 of the first three octets) handed out addresses
	// OUTSIDE a longer prefix's subnet (e.g. 10.10.0.130/25, past the /25 broadcast),
	// which the hub — running `Table = off` with only the connected tunnel route —
	// cannot reach, and wrongly capped shorter prefixes at 253 hosts.
	const hubAddr = (iface.addresses[0] || "10.10.0.1/24").split("/");
	const hubIp = hubAddr[0];
	const mask = hubAddr[1] || "24";
	const prefix = Number.parseInt(mask, 10);
	const octets = hubIp.split(".").map(Number);
	if (
		octets.length !== 4 ||
		octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255) ||
		!Number.isInteger(prefix) ||
		prefix < 0 ||
		prefix > 32
	) {
		throw new Error(`Interface ${ifaceName} has an invalid address: ${iface.addresses[0]}`);
	}
	const hubInt = ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
	const maskBits = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	const network = (hubInt & maskBits) >>> 0;
	const broadcast = (network | (~maskBits >>> 0)) >>> 0;
	const intToIp = (n) => `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
	const usedIPs = new Set();
	// Hub's own IP
	usedIPs.add(hubIp);
	// All existing peer tunnel IPs
	for (const link of status.links) {
		for (const addr of link.tunnelAddresses) {
			usedIPs.add(addr.replace(/\/\d+$/, ""));
		}
	}
	let nextIP = null;
	// Iterate host addresses strictly inside the subnet, excluding network + broadcast.
	for (let host = network + 1; host < broadcast; host++) {
		const candidate = intToIp(host >>> 0);
		if (usedIPs.has(candidate)) continue;
		nextIP = candidate;
		break;
	}
	if (!nextIP) throw new Error("No free tunnel IPs available in subnet");

	const tunnelAddress = `${nextIP}/${mask}`;
	const peerAllowedIP = `${nextIP}/32`;

	// ── Generate keypair ──
	const wgBin = getWireGuardBin();
	const { stdout: privKeyRaw } = await execFileAsync(wgBin, ["genkey"]);
	const privateKey = privKeyRaw.trim();
	const publicKey = derivePublicKey(privateKey);

	// ── Compute AllowedIPs for hub side ──
	// Client peers only get their tunnel IP on the hub side — importedNetworks
	// define what the client can reach (downloaded config), not hub routing.
	const hubAllowedIPs = [peerAllowedIP];
	const importedNets = sanitizeNetworkArray(importedNetworks);
	const isClientType = (type || "client") === "client";
	if (importedNets.length && !isClientType) hubAllowedIPs.push(...importedNets);

	// ── AllowedIPs conflict check ──
	// Skip for client/road-warrior links: their importedNetworks are a REACH list
	// (which existing sites they want to talk to), deliberately NOT added to
	// hubAllowedIPs (see the !isClientType guard above), so there is no cryptokey-routing
	// conflict. The other conflict checks (routes/wireguard.js /metadata and
	// wireguard-plan.js) likewise exempt clients; createPeer must too or selecting any
	// existing site to reach falsely throws "AllowedIPs conflict".
	if (!isClientType) {
		const conflicts = checkAllowedIPsConflicts(importedNets, status.links);
		if (conflicts.length > 0) {
			const details = conflicts.map((c) => `${c.subnet} already claimed by ${c.peer}`).join("; ");
			throw new Error(`AllowedIPs conflict: ${details}`);
		}
	}

	// ── Reject duplicate link names BEFORE any conf/live side effects. Two links
	// sharing a name make every bound agent resolve to ambiguous-link-name in
	// syncAgentConfigs and silently freeze BOTH. The update paths already guard this
	// via assertUniqueLinkName; createPeer must too. ──
	const desiredName = name ? String(name) : undefined;
	assertUniqueLinkName(
		{ links: Object.fromEntries((status.links || []).map((l) => [l.id, l])) },
		`${ifaceName}:${publicKey}`,
		desiredName,
	);

	// ── Write config file FIRST (safe to fail without side effects) ──
	const confPath = path.join(getWireGuardConfDir(), `${ifaceName}.conf`);
	const peerBlock = [
		"",
		`# ${stripLinkNameControlChars(name || "new-peer")}`,
		"[Peer]",
		`PublicKey = ${publicKey}`,
		`AllowedIPs = ${hubAllowedIPs.join(", ")}`,
		"",
	].join("\n");
	await fs.appendFile(confPath, peerBlock, "utf8");

	// ── Add peer to live interface (rollback conf on failure) ──
	try {
		await execFileAsync(wgBin, ["set", ifaceName, "peer", publicKey, "allowed-ips", hubAllowedIPs.join(",")]);
	} catch (err) {
		// Rollback: remove the peer block we just appended
		const conf = await fs.readFile(confPath, "utf8");
		const cleaned = conf.replace(peerBlock, "");
		await fs.writeFile(confPath, cleaned, "utf8");
		throw new Error(`Failed to add peer to live interface: ${err.message}`);
	}

	// ── Write metadata ──
	const linkId = `${ifaceName}:${publicKey}`;
	const store = await readMetadataStore();
	const ifaceMeta = store.interfaces[ifaceName] || {};
	store.links[linkId] = sanitizeLinkMetadataPatch({
		name: name || undefined,
		type: type || "client",
		importedNetworks: importedNets,
		dns: (dns || []).filter(Boolean),
		fullTunnel: Boolean(fullTunnel),
		platform: platform || undefined,
	});
	await writeMetadataStore(store);

	// ── Site peers: reconcile the hub conf so the new site's networks get a kernel
	// route + persisted PostUp `ip route add`. createPeer only set cryptokey routing
	// (wg set allowed-ips); with `Table = off` the hub has no kernel route to the new
	// LAN until syncHubConf runs, and without the PostUp rewrite the route is dropped
	// on every wg-quick restart. We already hold the write lock, so call the unlocked
	// core directly (the wrapper would deadlock). No-op for client peers. ──
	if (importedNets.length && !isClientType) {
		try {
			await _syncHubConfCore(store, ifaceName);
		} catch (err) {
			logger.error(`Hub conf sync after createPeer (${linkId}) failed: ${err.message}`);
		}
	}

	// Resync existing agents so a newly-added site's networks reach them on the next
	// poll, not only at the 5-min reconciler. No-op for client peers (no site nets).
	try {
		const { default: internalAgent } = await import("./agent.js");
		await internalAgent.syncAgentConfigs(store);
	} catch (err) {
		logger.error(`Agent config sync after createPeer (${linkId}) failed: ${err.message}`);
	}

	// ── Build client config ──
	const hubPublicKey = iface.publicKey;
	const hubListenPort = iface.listenPort || 51820;
	const hubHost = resolveHubHost();

	// DNS: link > interface > env
	const dnsServers = (dns || []).length
		? dns
		: ifaceMeta.dns?.length
			? ifaceMeta.dns
			: process.env.WG_DNS
				? process.env.WG_DNS.split(",").map((s) => s.trim())
				: [];

	const isFullTunnel = Boolean(fullTunnel);
	const isMobilePlatform = platform === "mobile";
	const fullTunnelIPs = isMobilePlatform ? ["0.0.0.0/0", "::/0"] : ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];
	// For road warriors (no importedNetworks), include all networks exported by other peers
	let clientBaseIPs;
	if (importedNets.length) {
		clientBaseIPs = importedNets;
	} else {
		const otherLinks = (status.links || []).filter((l) => l.interfaceName === ifaceName);
		const otherNets = otherLinks.flatMap((l) => l.exportedNetworks || []);
		clientBaseIPs = [...new Set([...(iface.addresses || []), ...otherNets])];
	}
	const clientAllowedIPs = isFullTunnel ? fullTunnelIPs : clientBaseIPs;

	const configLines = [
		`# WireGuard peer config — ${name || linkId}`,
		"# Generated by FloppyGuard",
		"",
		"[Interface]",
		`PrivateKey = ${privateKey}`,
		`Address = ${tunnelAddress}`,
	];
	if (dnsServers.length) configLines.push(`DNS = ${dnsServers.join(", ")}`);
	configLines.push(
		"",
		"[Peer]",
		`PublicKey = ${hubPublicKey}`,
		`Endpoint = ${hubHost}:${hubListenPort}`,
		`AllowedIPs = ${clientAllowedIPs.join(", ") || "0.0.0.0/0"}`,
		"PersistentKeepalive = 25",
	);

	const filename = `${name || "peer"}.conf`.replace(/[^\w.-]/g, "_");
	const content = `${configLines.join("\n")}\n`;

	return { linkId, publicKey, tunnelAddress, filename, content };
	}); // end withWriteLock
}

export default {
	applyMetadataPatch,
	backupMetadataStore,
	clearPeerConfigCache,
	createInterface,
	createPeer,
	deleteInterface,
	deletePeer,
	generatePeerConfig,
	updatePeer,
	generatePeerConfigQr,
	getBandwidth,
	getStatus,
	readMetadataStore,
	replaceMetadataStore,
	syncHubConf,
	updateInterfaceMetadata,
	updateLinkMetadata,
	writeMetadataStore,
};
