import internalWireGuard, {
	buildRouteAnalysis,
	buildTopology,
	deriveGlobalNextActions,
	deriveGlobalWarnings,
	enrichInterfaceStatus,
	enrichLinkRecord,
	sanitizeInterfaceMetadataPatch,
	sanitizeLinkMetadataPatch,
} from "./wireguard.js";
import { promises as fs } from "node:fs";
import path from "node:path";

function dedupe(values) {
	return Array.from(new Set((values || []).filter(Boolean)));
}

function getMetadataFile() {
	return process.env.WG_METADATA_FILE || path.resolve(process.cwd(), ".local-data", "wireguard-metadata.json");
}

function getApplyAuditFile() {
	return process.env.WG_APPLY_AUDIT_FILE || `${getMetadataFile()}.apply-audit.json`;
}

function isEqual(left, right) {
	return JSON.stringify(left) === JSON.stringify(right);
}

function normalizePatch(patch = {}) {
	const interfaces = Object.fromEntries(
		Object.entries(patch.interfaces || {})
			.map(([name, value]) => [name, sanitizeInterfaceMetadataPatch(value)])
			.filter(([, value]) => Object.keys(value).length > 0),
	);
	const links = Object.fromEntries(
		Object.entries(patch.links || {})
			.map(([id, value]) => [id, sanitizeLinkMetadataPatch(value)])
			.filter(([, value]) => Object.keys(value).length > 0),
	);

	return { interfaces, links };
}

function mergeMetadata(current = {}, patch = {}) {
	const merged = { ...current, ...patch };
	for (const [key, value] of Object.entries(merged)) {
		if (value === undefined) delete merged[key];
	}
	return merged;
}

function buildDiffEntries(currentEntries, patchedEntries, kind) {
	return Object.entries(patchedEntries).flatMap(([id, patch]) => {
		const before = currentEntries[id] || {};

		const after = mergeMetadata(before, patch);
		const changedFields = Object.keys(after).filter((field) => !isEqual(before[field], after[field]));
		if (!changedFields.length) return [];

		return [{
			id,
			kind,
			changedFields,
			before,
			after,
		}];
	});
}

function buildProjectedInterface(item, metadata) {
	return {
		...item,
		role: metadata.role || item.role || "unknown",
		managementMode: metadata.managementMode || item.managementMode || "unknown",
		importedNetworks: metadata.importedNetworks?.length ? metadata.importedNetworks : (item.importedNetworks || []),
		exportedNetworks: metadata.exportedNetworks || item.exportedNetworks || [],
		routeTargets: metadata.routeTargets?.length ? metadata.routeTargets : (item.routeTargets || []),
		notes: metadata.notes?.length ? metadata.notes : (item.notes || []),
	};
}

function buildProjectedLink(link, metadata) {
	return {
		...link,
		type: metadata.type || link.type || "unknown",
		name: metadata.name || link.name,
		exportedNetworks: metadata.exportedNetworks || link.exportedNetworks || [],
		importedNetworks: metadata.importedNetworks?.length ? metadata.importedNetworks : (link.importedNetworks || []),
		returnPathMode: metadata.returnPathMode || link.returnPathMode || "unknown",
		remoteManagementMode: metadata.remoteManagementMode || link.remoteManagementMode || "unknown",
		planIntent: metadata.planIntent || link.planIntent || metadata.type || link.type || "unknown",
		planState: metadata.planState || null,
		notes: metadata.notes?.length ? metadata.notes : (link.notes || []),
		hasMetadata: Object.keys(metadata).length > 0,
		warnings: [],
		nextActions: [],
	};
}

function buildSummary(interfaces, links, topology, routeAnalysis) {
	return {
		interfaceCount: interfaces.length,
		activeInterfaceCount: interfaces.filter((item) => item.active).length,
		totalPeers: interfaces.reduce((sum, item) => sum + (item.peerCount || 0), 0),
		activePeers: interfaces.reduce((sum, item) => sum + (item.activePeerCount || 0), 0),
		totalRxBytes: interfaces.reduce((sum, item) => sum + (item.rxBytes || 0), 0),
		totalTxBytes: interfaces.reduce((sum, item) => sum + (item.txBytes || 0), 0),
		peerNetworkCount: dedupe(interfaces.flatMap((item) => item.peerNetworks || [])).length,
		wireguardRouteCount: routeAnalysis.wireguard.length,
		privateRouteCount: routeAnalysis.privateRoutes.length,
		linkCount: links.length,
		siteLinkCount: topology.siteLinks.length,
		hubLinkCount: topology.hubLinks.length,
		clientLinkCount: topology.clientLinks.length,
	};
}

function classifyChangeScope(diff) {
	const fields = dedupe([
		...diff.interfaces.flatMap((item) => item.changedFields),
		...diff.links.flatMap((item) => item.changedFields),
	]);
	const configRelevantFields = new Set([
		"type",
		"importedNetworks",
		"exportedNetworks",
		"returnPathMode",
		"remoteManagementMode",
		"planIntent",
		"planState",
		"role",
		"managementMode",
		"routeTargets",
	]);

	if (!fields.length) return "none";
	if (fields.some((field) => configRelevantFields.has(field))) return "metadata-with-config-intent";
	return "metadata-only";
}

function buildApplyContract({ errors, warnings, nextActions, normalizedPatch, diff }) {
	const changedFieldCount = diff.interfaces.reduce((sum, item) => sum + item.changedFields.length, 0)
		+ diff.links.reduce((sum, item) => sum + item.changedFields.length, 0);
	const changeScope = classifyChangeScope(diff);
	const blockedBy = dedupe([
		...errors.map((item) => `error:${item}`),
		// warnings are informational only in metadata-write mode — no live config is written
	]);
	const canApply = blockedBy.length === 0 && changedFieldCount > 0;
	const requiresBackup = changeScope !== "none" && changedFieldCount > 0;

	return {
		canApply,
		blockedBy,
		requiresBackup,
		changeScope,
		changeCount: changedFieldCount,
		applyMode: "metadata-preview",
		requiresLiveConfigWrite: false,
		recommendedSteps: dedupe([
			...(requiresBackup ? ["create-backup-before-apply"] : []),
			...(changeScope === "metadata-with-config-intent" ? ["implement-write-layer-before-apply"] : []),
			...nextActions.slice(0, 5),
		]),
	};
}

function summarizeApplyBlockers(apply) {
	if (!apply.blockedBy.length) return "apply-not-allowed";
	return `Apply blocked: ${apply.blockedBy.join(", ")}`;
}

function buildPatchSummary(patch) {
	return {
		interfaceTargets: Object.keys(patch.interfaces || {}),
		linkTargets: Object.keys(patch.links || {}),
	};
}

async function readApplyAudit() {
	try {
		const raw = await fs.readFile(getApplyAuditFile(), "utf8");
		const parsed = JSON.parse(raw);
		return Array.isArray(parsed) ? parsed : [];
	} catch {
		return [];
	}
}

async function writeApplyAudit(entries) {
	const auditFile = getApplyAuditFile();
	await fs.mkdir(path.dirname(auditFile), { recursive: true });
	await fs.writeFile(auditFile, `${JSON.stringify(entries, null, 2)}\n`, "utf8");
}

async function appendApplyAudit(entry) {
	const entries = await readApplyAudit();
	entries.unshift(entry);
	await writeApplyAudit(entries.slice(0, 25));
	return entry;
}

async function listMetadataBackups() {
	const metadataFile = getMetadataFile();
	const directory = path.dirname(metadataFile);
	const baseName = path.basename(metadataFile);
	try {
		const entries = await fs.readdir(directory, { withFileTypes: true });
		const backupNames = entries
			.filter((entry) => entry.isFile() && entry.name.startsWith(`${baseName}.`) && entry.name.endsWith(".bak"))
			.map((entry) => entry.name)
			.sort((left, right) => right.localeCompare(left));
		return backupNames.map((name) => ({
			path: path.join(directory, name),
			fileName: name,
		}));
	} catch {
		return [];
	}
}

function buildPlanPreview(status, patch = {}) {
	const normalizedPatch = normalizePatch(patch);
	const currentMetadata = status.metadata || { interfaces: {}, links: {} };
	const errors = [];

	for (const name of Object.keys(normalizedPatch.interfaces)) {
		if (!(status.interfaces || []).some((item) => item.name === name)) {
			errors.push(`Unknown interface "${name}"`);
		}
	}

	for (const id of Object.keys(normalizedPatch.links)) {
		if (!(status.links || []).some((item) => item.id === id)) {
			errors.push(`Unknown link "${id}"`);
		}
	}

	const nextMetadata = {
		interfaces: { ...currentMetadata.interfaces },
		links: { ...currentMetadata.links },
	};

	for (const [name, value] of Object.entries(normalizedPatch.interfaces)) {
		nextMetadata.interfaces[name] = mergeMetadata(currentMetadata.interfaces[name] || {}, value);
	}

	for (const [id, value] of Object.entries(normalizedPatch.links)) {
		nextMetadata.links[id] = mergeMetadata(currentMetadata.links[id] || {}, value);
	}

	const projectedInterfacesBase = (status.interfaces || []).map((item) => buildProjectedInterface(item, nextMetadata.interfaces[item.name] || {}));
	const projectedLinksBase = (status.links || []).map((item) => buildProjectedLink(item, nextMetadata.links[item.id] || {}));
	const topology = buildTopology(projectedInterfacesBase, projectedLinksBase);
	const routeAnalysis = buildRouteAnalysis(
		{
			all: status.routes?.all || [],
			wireguard: status.routes?.wireguard || [],
			privateRoutes: status.routes?.privateRoutes || [],
		},
		topology,
	);
	const links = projectedLinksBase.map((item) => enrichLinkRecord(item, routeAnalysis));
	const interfaces = projectedInterfacesBase.map((item) => enrichInterfaceStatus(item, links));
	const warnings = dedupe([
		...deriveGlobalWarnings(interfaces, routeAnalysis),
		"Preview only applies metadata; live WireGuard config is unchanged",
	]);
	const nextActions = dedupe([
		...deriveGlobalNextActions(interfaces, links, routeAnalysis),
		...(errors.length ? ["resolve-preview-errors"] : []),
	]);
	const diff = {
		interfaces: buildDiffEntries(currentMetadata.interfaces || {}, normalizedPatch.interfaces || {}, "interface"),
		links: buildDiffEntries(currentMetadata.links || {}, normalizedPatch.links || {}, "link"),
	};
	const apply = buildApplyContract({ errors, warnings, nextActions, normalizedPatch, diff });

	return {
		mode: status.mode || "metadata-write",
		appliesLiveConfig: false,
		valid: errors.length === 0,
		errors,
		warnings,
		nextActions,
		apply,
		patch: normalizedPatch,
		diff,
		projected: {
			interfaces,
			links,
			topology,
			routes: routeAnalysis,
			summary: buildSummary(interfaces, links, topology, routeAnalysis),
			warnings,
			nextActions,
		},
	};
}

async function previewPlan(patch = {}) {
	const status = await internalWireGuard.getStatus();
	return buildPlanPreview(status, patch);
}

async function applyMetadata(patch = {}) {
	const preview = await previewPlan(patch);
	if (!preview.valid) {
		const err = new Error(`Preview invalid: ${preview.errors.join(", ")}`);
		err.code = "preview-invalid";
		err.preview = preview;
		throw err;
	}
	if (!preview.apply.canApply) {
		const err = new Error(summarizeApplyBlockers(preview.apply));
		err.code = "apply-blocked";
		err.preview = preview;
		throw err;
	}

	const currentMetadata = (await internalWireGuard.getStatus()).metadata || { interfaces: {}, links: {} };
	const backupPath = await internalWireGuard.backupMetadataStore(currentMetadata);
	const metadata = await internalWireGuard.applyMetadataPatch(preview.patch);
	const status = await internalWireGuard.getStatus();
	const auditEntry = await appendApplyAudit({
		at: new Date().toISOString(),
		backupPath,
		changeScope: preview.apply.changeScope,
		changeCount: preview.apply.changeCount,
		patchSummary: buildPatchSummary(preview.patch),
	});

	return {
		applied: true,
		backupPath,
		auditEntry,
		apply: preview.apply,
		metadata,
		status,
	};
}

async function restoreMetadataBackup(backupPath) {
	const backups = await listMetadataBackups();
	const selectedBackup = backups.find((item) => item.path === backupPath);
	if (!selectedBackup) {
		const err = new Error(`Unknown metadata backup: ${backupPath}`);
		err.code = "restore-invalid-backup";
		throw err;
	}

	const restoreSourceRaw = await fs.readFile(selectedBackup.path, "utf8");
	const restoreSource = JSON.parse(restoreSourceRaw);
	const currentMetadata = (await internalWireGuard.getStatus()).metadata || { interfaces: {}, links: {} };
	const preRestoreBackupPath = await internalWireGuard.backupMetadataStore(currentMetadata);
	await internalWireGuard.writeMetadataStore({
		interfaces: restoreSource.interfaces || {},
		links: restoreSource.links || {},
	});
	const status = await internalWireGuard.getStatus();
	const auditEntry = await appendApplyAudit({
		at: new Date().toISOString(),
		backupPath: preRestoreBackupPath,
		changeScope: "metadata-only",
		changeCount: 0,
		patchSummary: {
			interfaceTargets: Object.keys((restoreSource.interfaces || {})),
			linkTargets: Object.keys((restoreSource.links || {})),
		},
		action: "restore-backup",
		restoredFrom: selectedBackup.path,
	});

	return {
		restored: true,
		restoredFrom: selectedBackup.path,
		backupPath: preRestoreBackupPath,
		auditEntry,
		metadata: status.metadata || { interfaces: {}, links: {} },
		status,
	};
}

async function getApplyState() {
	const [backups, recentApplies] = await Promise.all([
		listMetadataBackups(),
		readApplyAudit(),
	]);

	return {
		backups,
		recentApplies,
		lastApply: recentApplies[0] || null,
	};
}

export {
	buildPlanPreview,
	buildApplyContract,
	classifyChangeScope,
	normalizePatch,
};

export default {
	applyMetadata,
	getApplyState,
	previewPlan,
	restoreMetadataBackup,
};
