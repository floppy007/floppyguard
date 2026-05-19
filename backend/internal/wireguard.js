import { execFile, execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { networkInterfaces } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
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
	try {
		const raw = await fs.readFile(getMetadataFile(), "utf8");
		const parsed = JSON.parse(raw);
		return {
			interfaces: parsed.interfaces || {},
			links: parsed.links || {},
		};
	} catch {
		return { interfaces: {}, links: {} };
	}
}

async function writeMetadataStore(store) {
	const metadataFile = getMetadataFile();
	await fs.mkdir(path.dirname(metadataFile), { recursive: true });
	await fs.writeFile(metadataFile, `${JSON.stringify(store, null, 2)}\n`, "utf8");
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

function sanitizeStringArray(value) {
	if (!Array.isArray(value)) return [];
	return Array.from(new Set(value.map((item) => String(item || "").trim()).filter(Boolean)));
}

function sanitizeInterfaceMetadata(input = {}) {
	const role = input.role ? String(input.role) : undefined;
	const managementMode = input.managementMode ? String(input.managementMode) : undefined;
	return {
		role: normalizeInterfaceRole(role),
		managementMode: MANAGEMENT_MODES.has(managementMode) ? managementMode : undefined,
		exportedNetworks: sanitizeStringArray(input.exportedNetworks),
		importedNetworks: sanitizeStringArray(input.importedNetworks),
		routeTargets: sanitizeStringArray(input.routeTargets),
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
		sanitized.exportedNetworks = sanitizeStringArray(input.exportedNetworks);
	if (Object.hasOwn(input, "importedNetworks"))
		sanitized.importedNetworks = sanitizeStringArray(input.importedNetworks);
	if (Object.hasOwn(input, "routeTargets")) sanitized.routeTargets = sanitizeStringArray(input.routeTargets);
	if (Object.hasOwn(input, "notes")) sanitized.notes = sanitizeStringArray(input.notes);
	if (Object.hasOwn(input, "dns")) sanitized.dns = sanitizeStringArray(input.dns);
	return sanitized;
}

function sanitizeLinkMetadata(input = {}) {
	const type = input.type ? String(input.type) : undefined;
	const returnPathMode = input.returnPathMode ? String(input.returnPathMode) : undefined;
	const remoteManagementMode = input.remoteManagementMode ? String(input.remoteManagementMode) : undefined;
	return {
		name: input.name ? String(input.name) : undefined,
		type: normalizeLinkType(type),
		exportedNetworks: sanitizeStringArray(input.exportedNetworks),
		importedNetworks: sanitizeStringArray(input.importedNetworks),
		returnPathMode: RETURN_PATH_MODES.has(returnPathMode) ? returnPathMode : undefined,
		remoteManagementMode: REMOTE_MANAGEMENT_MODES.has(remoteManagementMode) ? remoteManagementMode : undefined,
		planIntent: input.planIntent ? String(input.planIntent) : undefined,
		planState: input.planState ? String(input.planState) : undefined,
		notes: sanitizeStringArray(input.notes),
	};
}

function sanitizeLinkMetadataPatch(input = {}) {
	const sanitized = {};
	if (Object.hasOwn(input, "name")) sanitized.name = input.name ? String(input.name) : undefined;
	if (Object.hasOwn(input, "type")) sanitized.type = normalizeLinkType(input.type ? String(input.type) : undefined);
	if (Object.hasOwn(input, "exportedNetworks"))
		sanitized.exportedNetworks = sanitizeStringArray(input.exportedNetworks);
	if (Object.hasOwn(input, "importedNetworks"))
		sanitized.importedNetworks = sanitizeStringArray(input.importedNetworks);
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
	const store = await readMetadataStore();
	store.interfaces[interfaceName] = mergeMetadataEntry(
		store.interfaces[interfaceName] || {},
		sanitizeInterfaceMetadataPatch(patch),
	);
	await writeMetadataStore(store);
	return store.interfaces[interfaceName];
}

async function updateLinkMetadata(linkId, patch) {
	const store = await readMetadataStore();
	store.links[linkId] = mergeMetadataEntry(store.links[linkId] || {}, sanitizeLinkMetadataPatch(patch));
	await writeMetadataStore(store);
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

async function generatePeerConfig(linkId) {
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

	const allowedIps = link.importedNetworks.length > 0 ? link.importedNetworks : (iface?.addresses ?? []);

	// Generate a fresh WireGuard keypair for this peer
	// Note: wg pubkey hangs when piped via Node.js child_process stdin on this system;
	// use shell pipe instead.
	const wgBin = getWireGuardBin();
	const { stdout: privKeyRaw } = await execFileAsync(wgBin, ["genkey"]);
	const privateKey = privKeyRaw.trim();
	const newPubKey = derivePublicKey(privateKey);

	// Rotate the peer's public key on the hub
	const oldPubKey = link.peerPublicKey;
	if (oldPubKey && oldPubKey !== newPubKey) {
		const rotated = await _rotatePeerPublicKey(link.interfaceName, oldPubKey, newPubKey, link.allowedIps || []);
		if (rotated) {
			// Rename the link in the metadata store (ID is based on pubkey)
			const store = await readMetadataStore();
			const newLinkId = `${link.interfaceName}:${newPubKey}`;
			if (store.links[linkId]) {
				store.links[newLinkId] = store.links[linkId];
				delete store.links[linkId];
				await writeMetadataStore(store);
			}
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
	// After key rotation the link ID changes; use the new ID to find metadata
	const effectiveLinkId = (oldPubKey && oldPubKey !== newPubKey) ? `${link.interfaceName}:${newPubKey}` : linkId;
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

	const hubHost = process.env.WG_HUB_HOST || "<server-ip>";
	lines.push(
		`Endpoint = ${hubHost}:${hubListenPort}`,
		`AllowedIPs = ${finalAllowedIps.join(", ") || "0.0.0.0/0"}`,
		"PersistentKeepalive = 25",
	);

	return { filename, content: `${lines.join("\n")}\n`, publicKey: newPubKey };
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
		const linkType = normalizeLinkType(meta.type) || classifyLinkType(currentCIDRs, ifaceName);
		if (linkType === "client") {
			const newIPs = [...new Set(hostRoutes)];
			if ([...newIPs].sort().join(",") !== [...currentCIDRs].sort().join(",")) {
				updates.set(pubkey, newIPs);
			}
			continue;
		}

		const imported = (meta.importedNetworks || []).filter((c) => !c.endsWith("/32") && !c.endsWith("/128"));
		// If metadata has no importedNetworks, preserve existing non-host CIDRs from conf
		// to avoid stripping AllowedIPs that were set manually or by a previous sync.
		const currentNonHost = currentCIDRs.filter((c) => !c.endsWith("/32") && !c.endsWith("/128"));
		const effectiveNets = imported.length > 0 ? imported : currentNonHost;
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
			const masqRe = /^iptables -t nat -[AD] POSTROUTING -o \S+ -s \S+ -j MASQUERADE$/;
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

	// ── Remove from config file ──
	const confPath = path.join(getWireGuardConfDir(), `${ifaceName}.conf`);
	try {
		const confText = await fs.readFile(confPath, "utf8");
		const newConf = _removePeerFromConf(confText, publicKey);
		await fs.writeFile(confPath, newConf, "utf8");
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

	// ── Remove metadata ──
	const store = await readMetadataStore();
	delete store.links[linkId];
	await writeMetadataStore(store);

	return { deleted: true, linkId };
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
	if (changes.importedNetworks !== undefined) {
		const newNets = sanitizeStringArray(changes.importedNetworks);
		const otherLinks = status.links.filter((l) => l.id !== linkId);
		const conflicts = checkAllowedIPsConflicts(newNets, otherLinks);
		if (conflicts.length > 0) {
			const details = conflicts.map((c) => `${c.subnet} already claimed by ${c.peer}`).join("; ");
			throw new Error(`AllowedIPs conflict: ${details}`);
		}
	}

	// ── Backup metadata ──
	await backupMetadataStore();

	// ── Update metadata with new values ──
	const metadataPatch = {};
	if (changes.importedNetworks !== undefined) {
		metadataPatch.importedNetworks = sanitizeStringArray(changes.importedNetworks);
	}
	if (changes.name !== undefined) {
		metadataPatch.name = changes.name ? String(changes.name) : undefined;
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

	const store = await readMetadataStore();
	store.links[linkId] = mergeMetadataEntry(store.links[linkId] || {}, metadataPatch);
	await writeMetadataStore(store);

	// ── Sync hub conf (rewrites AllowedIPs in conf + live wg set + routes) ──
	const hubSync = await syncHubConf(store, ifaceName);

	// ── Sync agent configs (push updated AllowedIPs to remote agents) ──
	let agentSync;
	try {
		const { default: internalAgent } = await import("./agent.js");
		agentSync = await internalAgent.syncAgentConfigs(store);
	} catch (err) {
		logger.debug(`Agent config sync after updatePeer skipped: ${err.message}`);
	}

	return { updated: true, linkId, hubSync, agentSync };
}

async function syncHubConf(metadata, ifaceName = "wg0") {
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

	if (!peerUpdates.size) return { synced: true, changes: [] };

	// All non-/32 networks across all peers (effective values after updates)
	const allRouteNets = new Set();
	for (const [pubkey, currentCIDRs] of peerMap) {
		const effective = peerUpdates.has(pubkey) ? peerUpdates.get(pubkey) : currentCIDRs;
		for (const cidr of effective) {
			if (!cidr.endsWith("/32") && !cidr.endsWith("/128")) allRouteNets.add(cidr);
		}
	}

	// Discover physical interfaces with private IPs for auto-MASQUERADE.
	// wg0 peers that route traffic to subnets reachable via eth1/ens* etc.
	// need MASQUERADE so return packets find their way back through the tunnel.
	const physicalIfaces = _getPrivatePhysicalInterfaces();
	// Build a deduplicated list: one entry per (nicName, nicCidr) pair.
	// The CIDR used is the interface's own subnet (covers all wg traffic
	// destined for that physical network).
	const masqueradeIfaces = [];
	const seenMasq = new Set();
	for (const nic of physicalIfaces) {
		const key = `${nic.name}:${nic.cidr}`;
		if (!seenMasq.has(key)) {
			seenMasq.add(key);
			masqueradeIfaces.push(nic);
		}
	}

	const newText = _rewriteHubConf(lines, ifaceName, peerUpdates, allRouteNets, masqueradeIfaces);
	await fs.writeFile(confPath, newText, "utf8");

	const wgBin = getWireGuardBin();
	const ipBin = getIpBin();
	const changes = [];

	for (const [pubkey, newIPs] of peerUpdates) {
		try {
			await execFileAsync(wgBin, ["set", ifaceName, "peer", pubkey, "allowed-ips", newIPs.join(",")]);
			changes.push({ peer: `${pubkey.slice(0, 8)}…`, allowedIPs: newIPs });
		} catch (err) {
			logger.debug(`wg set peer ${pubkey.slice(0, 8)}… skipped (not connected): ${err.message}`);
		}
	}

	// Add any newly required routes live
	try {
		const { stdout } = await execFileAsync(ipBin, ["route", "show", "dev", ifaceName]);
		const existing = new Set(
			stdout
				.split("\n")
				.map((l) => l.split(/\s/)[0])
				.filter(Boolean),
		);
		for (const net of allRouteNets) {
			if (!existing.has(net)) {
				try {
					await execFileAsync(ipBin, ["route", "add", net, "dev", ifaceName]);
				} catch (err) {
					logger.debug(`Route add ${net} dev ${ifaceName}: ${err.message}`);
				}
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
	buildLinkRecord,
	buildRouteAnalysis,
	buildTopology,
	classifyLinkType,
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

	const confDir = getWireGuardConfDir();
	const wgBin = getWireGuardBin();

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
	const publicKey = derivePublicKey(privateKey);

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

	// ── Write metadata ──
	const store = await readMetadataStore();
	store.interfaces[name] = sanitizeInterfaceMetadataPatch({
		role: role || "auxiliary",
		managementMode: "local",
	});
	await writeMetadataStore(store);

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

	// ── Clean metadata — remove interface + all its links ──
	const store = await readMetadataStore();
	delete store.interfaces[name];
	for (const linkId of Object.keys(store.links)) {
		if (linkId.startsWith(`${name}:`)) {
			delete store.links[linkId];
		}
	}
	await writeMetadataStore(store);

	return { deleted: true, name };
}

/**
 * Create a new WireGuard peer on the hub interface.
 * Generates a keypair, assigns the next free tunnel IP, adds the peer to the
 * live interface and config file, writes metadata, and returns the client config.
 */
async function createPeer({ name, type, dns, fullTunnel, platform, importedNetworks, ifaceName = "wg0" }) {
	return withWriteLock(async () => {
	const status = await getStatus();
	if (!status.available) throw new Error("WireGuard is not available");

	const iface = status.interfaces.find((i) => i.name === ifaceName);
	if (!iface) throw new Error(`Interface ${ifaceName} not found`);

	// ── Find next free tunnel IP ──
	const hubAddr = (iface.addresses[0] || "10.10.0.1/24").split("/");
	const basePrefix = hubAddr[0].split(".").slice(0, 3).join(".");
	const mask = hubAddr[1] || "24";
	const usedIPs = new Set();
	// Hub's own IP
	usedIPs.add(hubAddr[0]);
	// All existing peer tunnel IPs
	for (const link of status.links) {
		for (const addr of link.tunnelAddresses) {
			usedIPs.add(addr.replace(/\/\d+$/, ""));
		}
	}
	let nextIP = null;
	for (let i = 2; i < 255; i++) {
		const candidate = `${basePrefix}.${i}`;
		if (!usedIPs.has(candidate)) {
			nextIP = candidate;
			break;
		}
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
	const importedNets = (importedNetworks || []).filter(Boolean);
	const isClientType = (type || "client") === "client";
	if (importedNets.length && !isClientType) hubAllowedIPs.push(...importedNets);

	// ── AllowedIPs conflict check ──
	const conflicts = checkAllowedIPsConflicts(importedNets, status.links);
	if (conflicts.length > 0) {
		const details = conflicts.map((c) => `${c.subnet} already claimed by ${c.peer}`).join("; ");
		throw new Error(`AllowedIPs conflict: ${details}`);
	}

	// ── Write config file FIRST (safe to fail without side effects) ──
	const confPath = path.join(getWireGuardConfDir(), `${ifaceName}.conf`);
	const peerBlock = [
		"",
		`# ${name || "new-peer"}`,
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

	// ── Build client config ──
	const hubPublicKey = iface.publicKey;
	const hubListenPort = iface.listenPort || 51820;
	const hubHost = process.env.WG_HUB_HOST || "<server-ip>";

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
	const clientAllowedIPs = isFullTunnel ? fullTunnelIPs : importedNets.length ? importedNets : iface.addresses || [];

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
	syncHubConf,
	updateInterfaceMetadata,
	updateLinkMetadata,
	writeMetadataStore,
};
