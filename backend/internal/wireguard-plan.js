import { promises as fs } from "node:fs";
import path from "node:path";
import { wireguard as logger } from "../logger.js";
import internalWireGuard, {
	buildRouteAnalysis,
	buildSummary,
	buildTopology,
	cascadeLinkRenames,
	clearPeerConfigCache,
	dedupe,
	deriveGlobalNextActions,
	deriveGlobalWarnings,
	enrichInterfaceStatus,
	enrichLinkRecord,
	findLinkNetworkConflicts,
	getMetadataFile,
	mergeMetadataEntry,
	sanitizeInterfaceMetadataPatch,
	sanitizeLinkMetadataPatch,
	syncAgentConfigsLocked,
	syncAllHubConfs,
	withWriteLock,
} from "./wireguard.js";

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

// Re-export mergeMetadataEntry as mergeMetadata for local usage
const mergeMetadata = mergeMetadataEntry;

function buildDiffEntries(currentEntries, patchedEntries, kind) {
	return Object.entries(patchedEntries).flatMap(([id, patch]) => {
		const before = currentEntries[id] || {};

		const after = mergeMetadata(before, patch);
		// Union of keys: a patch that clears a field is sanitized to `undefined` and
		// mergeMetadata deletes the key, so the removal only shows up in `before`.
		const fields = new Set([...Object.keys(before), ...Object.keys(after)]);
		const changedFields = [...fields].filter((field) => !isEqual(before[field], after[field]));
		if (!changedFields.length) return [];

		return [
			{
				id,
				kind,
				changedFields,
				before,
				after,
			},
		];
	});
}

function buildProjectedInterface(item, metadata) {
	return {
		...item,
		role: metadata.role || item.role || "unknown",
		managementMode: metadata.managementMode || item.managementMode || "unknown",
		importedNetworks: Object.hasOwn(metadata, "importedNetworks")
			? metadata.importedNetworks
			: item.importedNetworks || [],
		exportedNetworks: metadata.exportedNetworks || item.exportedNetworks || [],
		routeTargets: Object.hasOwn(metadata, "routeTargets") ? metadata.routeTargets : item.routeTargets || [],
		notes: Object.hasOwn(metadata, "notes") ? metadata.notes : item.notes || [],
	};
}

function buildProjectedLink(link, metadata) {
	const type = metadata.type || link.type || "unknown";
	return {
		...link,
		type,
		// No stored name → buildLinkRecord falls back to the generated `${type}-${pubkey8}`
		// after the write, so a cleared name must project THAT, not the old live name
		// (which would trip the duplicate check when another link takes it over).
		name: metadata.name || (link.peerPublicKey ? `${type}-${link.peerPublicKey.slice(0, 8)}` : link.name),
		exportedNetworks: metadata.exportedNetworks || link.exportedNetworks || [],
		// hasOwn, not `?.length`: an explicit [] revokes every net (same rule as
		// _buildPeerUpdates); only an ABSENT key keeps the live (conf-derived) nets.
		importedNetworks: Object.hasOwn(metadata, "importedNetworks")
			? metadata.importedNetworks
			: link.importedNetworks || [],
		returnPathMode: metadata.returnPathMode || link.returnPathMode || "unknown",
		remoteManagementMode: metadata.remoteManagementMode || link.remoteManagementMode || "unknown",
		planIntent: metadata.planIntent || link.planIntent || metadata.type || link.type || "unknown",
		planState: metadata.planState || null,
		notes: Object.hasOwn(metadata, "notes") ? metadata.notes : link.notes || [],
		hasMetadata: Object.keys(metadata).length > 0,
		warnings: [],
		nextActions: [],
	};
}

function classifyChangeScope(diff) {
	const fields = dedupe([
		...diff.interfaces.flatMap((item) => item.changedFields),
		...diff.links.flatMap((item) => item.changedFields),
	]);
	const configRelevantFields = new Set([
		"name",
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

function buildApplyContract({ errors, nextActions, diff }) {
	const changedFieldCount =
		diff.interfaces.reduce((sum, item) => sum + item.changedFields.length, 0) +
		diff.links.reduce((sum, item) => sum + item.changedFields.length, 0);
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
	let raw;
	try {
		raw = await fs.readFile(getApplyAuditFile(), "utf8");
	} catch (err) {
		if (err.code !== "ENOENT") {
			logger.warn(`Apply audit ${getApplyAuditFile()} unreadable (${err.message}); starting fresh`);
		}
		return [];
	}
	try {
		const parsed = JSON.parse(raw);
		return Array.isArray(parsed) ? parsed : [];
	} catch (err) {
		// Advisory history only — never fail an already-persisted apply over it.
		logger.warn(`Apply audit ${getApplyAuditFile()} is corrupt (${err.message}); starting fresh`);
		return [];
	}
}

async function writeApplyAudit(entries) {
	const auditFile = getApplyAuditFile();
	await fs.mkdir(path.dirname(auditFile), { recursive: true });
	// tmp + rename, same as writeMetadataStore: never leave a truncated file behind.
	const tmpFile = `${auditFile}.tmp`;
	await fs.writeFile(tmpFile, `${JSON.stringify(entries, null, 2)}\n`, "utf8");
	await fs.rename(tmpFile, auditFile);
}

// Under the module write lock: both callers (applyMetadata, restoreMetadataBackup)
// call this after their own locked sections have returned, so this cannot nest/deadlock.
async function appendApplyAudit(entry) {
	return withWriteLock(async () => {
		const entries = await readApplyAudit();
		entries.unshift(entry);
		await writeApplyAudit(entries.slice(0, 25));
		return entry;
	});
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

	const projectedInterfacesBase = (status.interfaces || []).map((item) =>
		buildProjectedInterface(item, nextMetadata.interfaces[item.name] || {}),
	);
	const projectedLinksBase = (status.links || []).map((item) =>
		buildProjectedLink(item, nextMetadata.links[item.id] || {}),
	);

	// Validate that link names are unique — duplicate names cause silent agent misconfiguration
	// because syncAgentConfigs indexes links by name and last-writer wins
	{
		const seenNames = new Map(); // name → first link id
		const duplicateNames = new Set();
		for (const link of projectedLinksBase) {
			if (link.name) {
				if (seenNames.has(link.name)) {
					duplicateNames.add(link.name);
				} else {
					seenNames.set(link.name, link.id);
				}
			}
		}
		for (const name of duplicateNames) {
			errors.push(`Duplicate link name "${name}" — link names must be unique for agent assignment`);
		}
	}

	// Validate AllowedIPs conflicts — two non-client peers claiming the same subnet
	// causes WireGuard to silently assign it to only one peer, breaking routing.
	// CIDR overlap, not string equality: a /16 over another site's /24 steals the
	// overlapping part the same way (longest-prefix routing at the hub).
	{
		const byId = Object.fromEntries(projectedLinksBase.map((l) => [l.id, l]));
		for (const c of findLinkNetworkConflicts(byId)) {
			errors.push(`Subnet conflict: ${c} — only one peer can route a subnet`);
		}
	}

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
	const apply = buildApplyContract({ errors, nextActions, diff });

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

/**
 * Link renames between two metadata stores: [{oldName, newName}] for every link
 * id whose EFFECTIVE name changed. `fallbackNames` ({linkId: name}, from the live
 * status before the write) supplies the old name of a link whose name came only
 * from the conf / was generated and never stood in the metadata store — agents
 * bind to that name just the same. `afterNames` ({linkId: name}, from the live
 * status AFTER the write) supplies the effective new name when the new store
 * entry has no name of its own (the link falls back to its conf/generated name,
 * and bindings must follow it there instead of being left on the old name).
 */
function diffLinkRenames(before, after, fallbackNames = {}, afterNames = {}) {
	const renames = [];
	for (const [id, next] of Object.entries(after?.links || {})) {
		const oldName = before?.links?.[id]?.name || fallbackNames?.[id];
		const newName = next?.name || afterNames?.[id];
		if (oldName && newName && oldName !== newName) renames.push({ oldName, newName });
	}
	return renames;
}

/** {linkId: name} of the live status links (fallback names for diffLinkRenames). */
function statusLinkNames(status) {
	return Object.fromEntries((status?.links || []).filter((l) => l?.id && l?.name).map((l) => [l.id, l.name]));
}

/**
 * Shared tail of every metadata write (apply, restore, PUT /metadata):
 * drop cached peer configs, cascade link renames to agent bindings, then
 * (optionally) resync hub confs + agent config_text with the error shaping
 * the audit log and UI expect. Returns the post-sync status.
 */
async function finishMetadataWrite({ previous, written, statusBefore, syncConfig }) {
	// The write may have changed link AllowedIPs/DNS/full-tunnel/platform; invalidate
	// cached peer configs so a prior Download/QR isn't re-served stale.
	clearPeerConfigCache();
	// One snapshot after the write, reused for rename fallback names and the
	// conf-sync interface list (cascadeLinkRenames only touches agent bindings).
	const statusAfterWrite = await internalWireGuard.getStatus();
	// Agents bind to a link by its (mutable) name: cascade renames BEFORE the resync.
	const renameCascade = await cascadeLinkRenames(
		diffLinkRenames(previous, written, statusLinkNames(statusBefore), statusLinkNames(statusAfterWrite)),
	);
	let hubSync = null;
	let agentSync = null;
	if (syncConfig) {
		try {
			hubSync = await syncAllHubConfs((statusAfterWrite.interfaces || []).map((i) => i.name));
		} catch (err) {
			hubSync = { synced: false, reason: err.message };
		}
		try {
			// Locked + fresh-read (see syncAgentConfigsLocked): a concurrent mutation's
			// older-snapshot sync can never land last and re-advertise a removed network.
			agentSync = await syncAgentConfigsLocked();
		} catch (err) {
			agentSync = { error: err.message };
		}
	}
	const status = await internalWireGuard.getStatus();
	return { renameCascade, hubSync, agentSync, status };
}

async function previewPlan(patch = {}) {
	const status = await internalWireGuard.getStatus();
	return buildPlanPreview(status, patch);
}

async function applyMetadata(patch = {}) {
	const statusBefore = await internalWireGuard.getStatus();
	const preview = buildPlanPreview(statusBefore, patch);
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

	const currentMetadata = statusBefore.metadata || { interfaces: {}, links: {} };
	const backupPath = await internalWireGuard.backupMetadataStore(currentMetadata);
	// previous = the store read under the same write lock as the patch (no window
	// for a concurrent write between diff base and patch).
	const { store: metadata, previous: storeBefore } = await internalWireGuard.applyMetadataPatch(preview.patch, {
		withPrevious: true,
	});
	// Sync ALL WG interfaces' conf files + agent config_text from the new metadata
	// (config-relevant changes only) so the live config never drifts from the UI.
	const { renameCascade, hubSync, agentSync, status } = await finishMetadataWrite({
		previous: storeBefore,
		written: metadata,
		statusBefore,
		syncConfig: preview.apply.changeScope === "metadata-with-config-intent",
	});
	const auditEntry = await appendApplyAudit({
		at: new Date().toISOString(),
		backupPath,
		changeScope: preview.apply.changeScope,
		changeCount: preview.apply.changeCount,
		patchSummary: buildPatchSummary(preview.patch),
		hubSync,
	});

	return {
		applied: true,
		backupPath,
		auditEntry,
		apply: preview.apply,
		hubSync,
		agentSync,
		renameCascade,
		metadata,
		status,
	};
}

// Identity fields a link may have gained AFTER the backup was taken. When the
// backup entry lacks one (or has an empty name), the current value is kept:
// dropping a name would make the link fall back to its conf/generated name and
// leave agents bound via wg_link_name / allowed_sites on "no-link-or-config";
// dropping type/importedNetworks would silently reclassify the link or change
// its routed nets. Every other field is restored from the backup as before.
const RESTORE_KEEP_IF_MISSING = ["name", "type", "importedNetworks"];
function mergeRestoredLink(current, backupEntry) {
	const merged = { ...(backupEntry || {}) };
	if (!current) return merged;
	for (const key of RESTORE_KEEP_IF_MISSING) {
		const missing = key === "name" ? !merged.name : !Object.hasOwn(merged, key);
		if (missing && Object.hasOwn(current, key) && current[key] !== undefined && current[key] !== "") {
			merged[key] = current[key];
		}
	}
	return merged;
}

// Merge a metadata backup into the live store, but only for links/interfaces that
// exist LIVE right now. A wholesale replace let an old backup resurrect ghost links
// (deleted peers, other interfaces — counted as sites by the agent sync, shrinking
// every agent's routes to their nets), wipe the metadata of links added since, and
// cascade stale names into agent bindings. Live entries the backup lacks keep their
// current metadata; backup entries with no live counterpart are skipped. Non-live
// entries already in the current store are left untouched.
function mergeBackupIntoLive(current, backup, liveLinkIds, liveInterfaceNames) {
	const cur = current || {};
	const bak = backup || {};
	const store = {
		interfaces: { ...(cur.interfaces || {}) },
		links: { ...(cur.links || {}) },
	};
	const restoredLinks = [];
	const keptLinks = [];
	const skippedLinks = [];
	const bakLinks = bak.links || {};
	for (const id of liveLinkIds) {
		if (Object.hasOwn(bakLinks, id)) {
			store.links[id] = mergeRestoredLink(store.links[id], bakLinks[id]);
			restoredLinks.push(id);
		} else {
			keptLinks.push(id);
		}
	}
	for (const id of Object.keys(bakLinks)) {
		if (!liveLinkIds.has(id)) skippedLinks.push(id);
	}
	const skippedInterfaces = [];
	for (const [name, value] of Object.entries(bak.interfaces || {})) {
		if (liveInterfaceNames.has(name)) store.interfaces[name] = value;
		else skippedInterfaces.push(name);
	}
	return { store, restoredLinks, keptLinks, skippedLinks, skippedInterfaces };
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
	let restoreSource;
	try {
		restoreSource = JSON.parse(restoreSourceRaw);
	} catch (parseErr) {
		// A truncated/corrupt .bak (crash mid-write, manual edit) must be a client-visible
		// 400 with the file name, not a SyntaxError → 500 "Internal Error".
		const err = new Error(
			`Metadata backup ${path.basename(selectedBackup.path)} is corrupt and cannot be restored: ${parseErr.message}`,
		);
		err.code = "restore-invalid-backup";
		throw err;
	}
	const statusBefore = await internalWireGuard.getStatus();
	if (!statusBefore.available) {
		const err = new Error("WireGuard is not available — cannot match the backup against live peers");
		err.code = "restore-unavailable";
		throw err;
	}
	const liveLinkIds = new Set((statusBefore.links || []).map((l) => l.id));
	const liveInterfaceNames = new Set((statusBefore.interfaces || []).map((i) => i.name));
	const currentMetadata = statusBefore.metadata || { interfaces: {}, links: {} };
	const preRestoreBackupPath = await internalWireGuard.backupMetadataStore(currentMetadata);
	// Merge (only live ids, see mergeBackupIntoLive) and write under the module
	// write lock: a raw writeMetadataStore here could be silently overwritten by a
	// concurrent locked read-modify-write that read the pre-restore store (the
	// lost-update race mutateMetadataStore guards against), wiping the restore.
	// previous = the store read under that lock.
	let mergeInfo = null;
	const { store: restoredMetadata, previous: storeBefore } = await internalWireGuard.replaceMetadataStore(
		(current) => {
			mergeInfo = mergeBackupIntoLive(current, restoreSource, liveLinkIds, liveInterfaceNames);
			return mergeInfo.store;
		},
		{ withPrevious: true },
	);
	if (mergeInfo.skippedLinks.length || mergeInfo.keptLinks.length) {
		logger.warn(
			`Metadata restore from ${path.basename(selectedBackup.path)}: skipped ${mergeInfo.skippedLinks.length} non-live link(s), kept current metadata for ${mergeInfo.keptLinks.length} live link(s) missing from the backup`,
		);
	}
	// Always resync hub conf for every interface plus agent config_text from the
	// restored metadata (mirrors applyMetadata's config-intent path). Without this,
	// wg0.conf AllowedIPs/PostUp, live wg peers, kernel routes, and agent configs would
	// keep reflecting the pre-restore state even though the UI reports the rollback
	// applied. The backup may also carry other link names — those cascade too.
	const { renameCascade, hubSync, agentSync, status } = await finishMetadataWrite({
		previous: storeBefore,
		written: restoredMetadata,
		statusBefore,
		syncConfig: true,
	});
	const auditEntry = await appendApplyAudit({
		at: new Date().toISOString(),
		backupPath: preRestoreBackupPath,
		changeScope: "metadata-with-config-intent",
		changeCount: 0,
		patchSummary: {
			interfaceTargets: Object.keys(restoreSource.interfaces || {}).filter((n) => liveInterfaceNames.has(n)),
			linkTargets: mergeInfo.restoredLinks,
		},
		action: "restore-backup",
		restoredFrom: selectedBackup.path,
		hubSync,
	});

	return {
		restored: true,
		restoredFrom: selectedBackup.path,
		backupPath: preRestoreBackupPath,
		auditEntry,
		hubSync,
		agentSync,
		renameCascade,
		restoredLinks: mergeInfo.restoredLinks,
		keptLinks: mergeInfo.keptLinks,
		skippedLinks: mergeInfo.skippedLinks,
		skippedInterfaces: mergeInfo.skippedInterfaces,
		metadata: status.metadata || { interfaces: {}, links: {} },
		status,
	};
}

async function getApplyState() {
	const [backups, recentApplies] = await Promise.all([listMetadataBackups(), readApplyAudit()]);

	return {
		backups,
		recentApplies,
		lastApply: recentApplies[0] || null,
	};
}

export {
	buildApplyContract,
	buildPlanPreview,
	cascadeLinkRenames,
	classifyChangeScope,
	diffLinkRenames,
	finishMetadataWrite,
	mergeBackupIntoLive,
	normalizePatch,
	statusLinkNames,
};

export default {
	applyMetadata,
	getApplyState,
	previewPlan,
	restoreMetadataBackup,
};
