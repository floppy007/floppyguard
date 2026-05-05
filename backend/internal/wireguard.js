import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const ACTIVE_HANDSHAKE_WINDOW = 180;
const LINK_TYPES = new Set(["client", "site-to-site", "hub-link", "imported", "unknown"]);
const INTERFACE_ROLES = new Set(["client-hub", "site-to-site", "hub-link", "auxiliary", "unknown"]);
const MANAGEMENT_MODES = new Set(["local", "imported", "unknown"]);
const REMOTE_MANAGEMENT_MODES = new Set(["none", "ssh", "agent", "unknown"]);
const RETURN_PATH_MODES = new Set(["auto", "routed", "static-route", "nat", "unknown"]);

const getWireGuardConfDir = () => process.env.WG_CONF_DIR || "/etc/wireguard";
const getWireGuardBin = () => process.env.WG_BIN || "wg";
const getIpBin = () => process.env.IP_BIN || "ip";
const getMetadataFile = () => process.env.WG_METADATA_FILE || path.resolve(process.cwd(), ".local-data", "wireguard-metadata.json");

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
		nextStore.interfaces[name] = mergeMetadataEntry(nextStore.interfaces[name] || {}, sanitizeInterfaceMetadataPatch(value));
	}

	for (const [id, value] of Object.entries(patch.links || {})) {
		nextStore.links[id] = mergeMetadataEntry(nextStore.links[id] || {}, sanitizeLinkMetadataPatch(value));
	}

	return nextStore;
}

async function backupMetadataStore(store = null) {
	const currentStore = store || await readMetadataStore();
	const metadataFile = getMetadataFile();
	await fs.mkdir(path.dirname(metadataFile), { recursive: true });
	const stamp = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
	const backupPath = `${metadataFile}.${stamp}.bak`;
	await fs.writeFile(backupPath, `${JSON.stringify(currentStore, null, 2)}\n`, "utf8");
	return backupPath;
}

async function applyMetadataPatch(patch = {}) {
	const store = await readMetadataStore();
	const nextStore = mergeMetadataStorePatch(store, patch);
	await writeMetadataStore(nextStore);
	return nextStore;
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
	if (Object.hasOwn(input, "role")) sanitized.role = normalizeInterfaceRole(input.role ? String(input.role) : undefined);
	if (Object.hasOwn(input, "managementMode")) sanitized.managementMode = MANAGEMENT_MODES.has(input.managementMode ? String(input.managementMode) : undefined) ? String(input.managementMode) : undefined;
	if (Object.hasOwn(input, "exportedNetworks")) sanitized.exportedNetworks = sanitizeStringArray(input.exportedNetworks);
	if (Object.hasOwn(input, "importedNetworks")) sanitized.importedNetworks = sanitizeStringArray(input.importedNetworks);
	if (Object.hasOwn(input, "routeTargets")) sanitized.routeTargets = sanitizeStringArray(input.routeTargets);
	if (Object.hasOwn(input, "notes")) sanitized.notes = sanitizeStringArray(input.notes);
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
	if (Object.hasOwn(input, "exportedNetworks")) sanitized.exportedNetworks = sanitizeStringArray(input.exportedNetworks);
	if (Object.hasOwn(input, "importedNetworks")) sanitized.importedNetworks = sanitizeStringArray(input.importedNetworks);
	if (Object.hasOwn(input, "returnPathMode")) sanitized.returnPathMode = RETURN_PATH_MODES.has(input.returnPathMode ? String(input.returnPathMode) : undefined) ? String(input.returnPathMode) : undefined;
	if (Object.hasOwn(input, "remoteManagementMode")) sanitized.remoteManagementMode = REMOTE_MANAGEMENT_MODES.has(input.remoteManagementMode ? String(input.remoteManagementMode) : undefined) ? String(input.remoteManagementMode) : undefined;
	if (Object.hasOwn(input, "planIntent")) sanitized.planIntent = input.planIntent ? String(input.planIntent) : undefined;
	if (Object.hasOwn(input, "planState")) sanitized.planState = input.planState ? String(input.planState) : undefined;
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
	store.interfaces[interfaceName] = mergeMetadataEntry(store.interfaces[interfaceName] || {}, sanitizeInterfaceMetadataPatch(patch));
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
			if (key === "Address") result.addresses = value.split(",").map((part) => part.trim()).filter(Boolean);
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
	} catch {
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
			allowedIps: (parts[4] || "").split(",").map((part) => part.trim()).filter(Boolean),
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
	return target.startsWith("10.") || target.startsWith("192.168.") || /^172\.(1[6-9]|2\d|3[0-1])\./u.test(target) || target.startsWith("fd") || target.startsWith("fc");
}

function isHostRoute(target) {
	return /\/32$/u.test(target) || /\/128$/u.test(target);
}

function classifyLinkType(allowedIps, ifaceName) {
	const privateNetworks = allowedIps.filter((entry) => isPrivateNetwork(entry));
	const networkRoutes = privateNetworks.filter((entry) => !isHostRoute(entry));
	const hostRoutes = privateNetworks.filter((entry) => isHostRoute(entry));
	if (ifaceName === "wg0" && networkRoutes.length <= 1) return "client";
	if (ifaceName === "wg0" && networkRoutes.length === 0 && hostRoutes.length <= 2) return "client";
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
		returnPathMode: RETURN_PATH_MODES.has(metadata.returnPathMode) ? metadata.returnPathMode : (importedNetworks.length ? "unknown" : "routed"),
		remoteManagementMode: REMOTE_MANAGEMENT_MODES.has(metadata.remoteManagementMode) ? metadata.remoteManagementMode : "none",
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
		const privateRoutes = parsed.filter((route) => route.destination !== "default" && isPrivateNetwork(route.destination));
		return { all: parsed, wireguard, privateRoutes };
	} catch {
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
		parsedConfig.peers.flatMap((peer) => String(peer.AllowedIPs || "").split(",").map((part) => part.trim()).filter(Boolean)),
	);
	const peers = dump?.peers ?? [];
	const metadata = metadataStore.interfaces[name] || {};
	const role = normalizeInterfaceRole(metadata.role) || inferInterfaceRole(name, peers);
	const importedNetworks = metadata.importedNetworks?.length
		? metadata.importedNetworks
		: dedupe(peers.flatMap((peer) => (peer.allowedIps || []).filter((entry) => isPrivateNetwork(entry) && !isHostRoute(entry))));
	const routeTargets = metadata.routeTargets?.length ? metadata.routeTargets : dedupe(peers.flatMap((peer) => peer.allowedIps || []));
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
		notes: metadata.notes?.length ? metadata.notes : (importedNetworks.length ? [`${importedNetworks.length} imported network(s) detected`] : []),
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
		exportedNetworks: dedupe([...interfaces.flatMap((item) => item.exportedNetworks || []), ...links.flatMap((item) => item.exportedNetworks || [])]),
		importedNetworks: dedupe([...interfaces.flatMap((item) => item.importedNetworks || []), ...links.flatMap((item) => item.importedNetworks || [])]),
		siteLinks: links.filter((item) => item.type === "site-to-site").map((item) => item.id),
		clientLinks: links.filter((item) => item.type === "client").map((item) => item.id),
		hubLinks: links.filter((item) => item.type === "hub-link").map((item) => item.id),
	};
}

function buildRouteAnalysis(routes, topology) {
	const wireguardDestinations = new Set(routes.wireguard.map((route) => route.destination));
	const staticRouteDestinations = new Set(routes.privateRoutes.filter((route) => !String(route.device || "").startsWith("wg")).map((route) => route.destination));
	const missingReturnRoutes = topology.importedNetworks
		.filter((network) => !wireguardDestinations.has(network) && !staticRouteDestinations.has(network))
		.map((network) => ({ network, reason: "network-not-found-in-live-routes" }));
	const natCandidates = topology.importedNetworks
		.filter((network) => !wireguardDestinations.has(network) && !staticRouteDestinations.has(network))
		.map((network) => ({ network, reason: "return-path-unclear" }));
	const staticRoutes = routes.privateRoutes.filter((route) => !String(route.device || "").startsWith("wg"));
	const splitTunnelCandidates = dedupe([...topology.importedNetworks, ...staticRoutes.map((route) => route.destination)]);
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
			...(missingReturnRoutes.length ? ["Some imported networks are not visible as live WireGuard routes yet"] : []),
			...(staticRoutes.length ? ["Static private routes exist outside WireGuard and may affect reachability decisions"] : []),
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
	if (["none", "unknown"].includes(link.remoteManagementMode)) {
		warnings.push("remote-management-mode-undefined");
		nextActions.push("define-remote-management-mode");
	}
	if (!link.active && (link.importedNetworks.length || link.exportedNetworks.length)) {
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
		...interfaces.flatMap((item) => item.health === "warning" ? ["review-interface-health"] : []),
		...links.flatMap((link) => link.nextActions || []),
	];
	return dedupe(actions);
}

function deriveGlobalWarnings(interfaces, routeAnalysis) {
	const warnings = [
		...(routeAnalysis.missingReturnRoutes?.length ? ["Imported networks exist without matching live WireGuard route entries"] : []),
		...(routeAnalysis.natCandidates?.length ? ["Some imported networks may still require NAT or explicit return-path handling"] : []),
		...interfaces.flatMap((item) => item.health === "warning" ? [`Interface ${item.name} needs review`] : []),
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
		if (t === "[Peer]") { inPeer = true; out.push(rawLine); continue; }
		if (t.startsWith("[")) { inPeer = false; out.push(rawLine); continue; }
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
	try { await execFileAsync(wgBin, ["set", ifaceName, "peer", oldPubKey, "remove"]); } catch { /* not active */ }
	try {
		const args = ["set", ifaceName, "peer", newPubKey];
		if (peerAllowedIps.length > 0) args.push("allowed-ips", peerAllowedIps.join(","));
		await execFileAsync(wgBin, args);
	} catch { /* ignore */ }
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

	const allowedIps = link.importedNetworks.length > 0
		? link.importedNetworks
		: (iface?.addresses ?? []);

	// Generate a fresh WireGuard keypair for this peer
	// Note: wg pubkey hangs when piped via Node.js child_process stdin on this system;
	// use shell pipe instead.
	const wgBin = getWireGuardBin();
	const { stdout: privKeyRaw } = await execFileAsync(wgBin, ["genkey"]);
	const privateKey = privKeyRaw.trim();
	const { execSync } = await import("node:child_process");
	const newPubKey = execSync(`printf '%s\\n' ${JSON.stringify(privateKey)} | ${wgBin} pubkey`).toString().trim();

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

	lines.push(
		"",
		"[Peer]",
		`# Hub interface: ${link.interfaceName}`,
	);

	if (hubPublicKey) {
		lines.push(`PublicKey = ${hubPublicKey}`);
	}

	const hubHost = process.env.WG_HUB_HOST || "<server-ip>";
	lines.push(
		`Endpoint = ${hubHost}:${hubListenPort}`,
		`AllowedIPs = ${allowedIps.join(", ") || "0.0.0.0/0"}`,
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
			routes: { all: [], wireguard: [], privateRoutes: [], staticRoutes: [], missingReturnRoutes: [], natCandidates: [], conflicts: [], splitTunnelCandidates: [], observations: [] },
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
	const interfaceNames = Array.from(new Set([...configNames, ...dumpByInterface.keys()])).sort((a, b) => a.localeCompare(b));
	const interfaceStatuses = await Promise.all(interfaceNames.map((name) => getInterfaceStatus(name, dumpByInterface, metadataStore)));
	const rawLinks = interfaceStatuses.flatMap((item) => item.peers.map((peer, index) => buildLinkRecord(item.name, peer, index, metadataStore.links[`${item.name}:${peer.publicKey || index}`] || {})));
	const routes = await getRoutes();
	const topology = buildTopology(interfaceStatuses, rawLinks);
	const routeAnalysis = buildRouteAnalysis(routes, topology);
	const links = rawLinks.map((link) => enrichLinkRecord(link, routeAnalysis));
	const interfaces = interfaceStatuses.map((item) => enrichInterfaceStatus(item, links));
	const hub = interfaces.find((item) => item.name === "wg0") || null;
	const warnings = deriveGlobalWarnings(interfaces, routeAnalysis);
	const nextActions = deriveGlobalNextActions(interfaces, links, routeAnalysis);
	const totalPeers = interfaces.reduce((sum, item) => sum + item.peerCount, 0);
	const activePeers = interfaces.reduce((sum, item) => sum + item.activePeerCount, 0);
	const totalRxBytes = interfaces.reduce((sum, item) => sum + item.rxBytes, 0);
	const totalTxBytes = interfaces.reduce((sum, item) => sum + item.txBytes, 0);
	const peerNetworks = dedupe(interfaces.flatMap((item) => item.peerNetworks));

	if (!(await pathExists("/sys/class/net"))) warnings.push("/sys/class/net is not mounted; traffic counters are unavailable");
	if (!dumpByInterface.size) warnings.push(`No live output from "${wireGuardBin} show all dump"; data may be config-only`);
	if (!routes.all.length) warnings.push(`No route data from "${ipBin} route show"; gateway summary is incomplete`);
	if (!interfaces.length) warnings.push("No WireGuard interfaces were discovered from config files or live runtime data");

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
		if (trimmed === "[Peer]") { flush(); inPeer = true; currentPubKey = null; currentAllowedIPs = []; continue; }
		if (trimmed.startsWith("[")) { flush(); inPeer = false; currentPubKey = null; continue; }
		if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
		const eqIdx = trimmed.indexOf("=");
		const k = trimmed.slice(0, eqIdx).trim();
		const v = trimmed.slice(eqIdx + 1).trim();
		if (inPeer) {
			if (k === "PublicKey") currentPubKey = v;
			if (k === "AllowedIPs") currentAllowedIPs = v.split(",").map((s) => s.trim()).filter(Boolean);
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
		const imported = (meta.importedNetworks || []).filter((c) => !c.endsWith("/32") && !c.endsWith("/128"));
		const newIPs = [...new Set([...hostRoutes, ...imported])];
		if ([...newIPs].sort().join(",") !== [...currentCIDRs].sort().join(",")) {
			updates.set(pubkey, newIPs);
		}
	}
	return updates;
}

function _rewriteHubConf(lines, ifaceName, peerUpdates, allRouteNets) {
	let inPeer = false;
	let currentPubKey = null;
	const out = [];
	for (const rawLine of lines) {
		const t = rawLine.trim();
		if (t === "[Peer]") { inPeer = true; currentPubKey = null; out.push(rawLine); continue; }
		if (t.startsWith("[")) { inPeer = false; currentPubKey = null; out.push(rawLine); continue; }
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
			const value = rawLine.slice(rawLine.indexOf("=") + 1).trim();
			const routeRe = new RegExp(`^ip route (?:add|del) \\S+ dev ${ifaceName}`);
			const nonRoute = value.split(";").map((s) => s.trim()).filter((p) => p && !routeRe.test(p));
			const routeCmds = [...allRouteNets].sort().map((net) => `ip route ${verb} ${net} dev ${ifaceName} 2>/dev/null || true`);
			out.push(`${key} = ${[...nonRoute, ...routeCmds].join("; ")}`);
			continue;
		}
		out.push(rawLine);
	}
	return out.join("\n");
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

	if (!peerUpdates.size) return { synced: true, changes: [] };

	// All non-/32 networks across all peers (effective values after updates)
	const allRouteNets = new Set();
	for (const [pubkey, currentCIDRs] of peerMap) {
		const effective = peerUpdates.has(pubkey) ? peerUpdates.get(pubkey) : currentCIDRs;
		for (const cidr of effective) {
			if (!cidr.endsWith("/32") && !cidr.endsWith("/128")) allRouteNets.add(cidr);
		}
	}

	const newText = _rewriteHubConf(lines, ifaceName, peerUpdates, allRouteNets);
	await fs.writeFile(confPath, newText, "utf8");

	const wgBin = getWireGuardBin();
	const ipBin = getIpBin();
	const changes = [];

	for (const [pubkey, newIPs] of peerUpdates) {
		try {
			await execFileAsync(wgBin, ["set", ifaceName, "peer", pubkey, "allowed-ips", newIPs.join(",")]);
			changes.push({ peer: `${pubkey.slice(0, 8)}…`, allowedIPs: newIPs });
		} catch {
			// peer not currently connected — conf is updated, live apply skipped
		}
	}

	// Add any newly required routes live
	try {
		const { stdout } = await execFileAsync(ipBin, ["route", "show", "dev", ifaceName]);
		const existing = new Set(stdout.split("\n").map((l) => l.split(/\s/)[0]).filter(Boolean));
		for (const net of allRouteNets) {
			if (!existing.has(net)) {
				try { await execFileAsync(ipBin, ["route", "add", net, "dev", ifaceName]); } catch { /* already exists */ }
			}
		}
	} catch { /* ignore route lookup failures */ }

	return { synced: true, changes };
}

export {
	buildLinkRecord,
	buildRouteAnalysis,
	buildTopology,
	classifyLinkType,
	deriveGlobalNextActions,
	deriveGlobalWarnings,
	enrichInterfaceStatus,
	enrichLinkRecord,
	getNatCandidateNetworks,
	getMissingImportedNetworks,
	inferInterfaceRole,
	inferPlanState,
	normalizeInterfaceRole,
	normalizeLinkType,
	mergeMetadataStorePatch,
	sanitizeInterfaceMetadata,
	sanitizeInterfaceMetadataPatch,
	sanitizeLinkMetadata,
	sanitizeLinkMetadataPatch,
	syncHubConf,
};

export default {
	applyMetadataPatch,
	backupMetadataStore,
	generatePeerConfig,
	generatePeerConfigQr,
	getStatus,
	readMetadataStore,
	syncHubConf,
	updateInterfaceMetadata,
	updateLinkMetadata,
	writeMetadataStore,
};
