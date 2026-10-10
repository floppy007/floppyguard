import type { WireGuardHubSyncResult, WireGuardRenameCascade, WireGuardRestoreMetadataResponse } from "src/api/backend";

/**
 * Failed steps of the link-rename cascade (agent bindings follow a renamed link).
 * A failure leaves bound agents on the old or a temporary name — they freeze.
 */
export function renameCascadeProblems(cascade: WireGuardRenameCascade | null | undefined): string[] {
	if (!cascade?.errors?.length) return [];
	const out = cascade.errors.map((e) => `${e.from} → ${e.to}: ${e.error}`);
	if (cascade.rolledBack) out.push("rolled back");
	return out;
}

/**
 * Problems of the live sync after a metadata restore. hubSync is keyed by
 * interface (or a single failure object), agentSync may be a fleet-wide error.
 * Per-agent failures come as {changed: false, error}; skips as {reason}.
 */
export function restoreSyncProblems(
	data: Pick<WireGuardRestoreMetadataResponse, "hubSync" | "agentSync"> &
		Partial<Pick<WireGuardRestoreMetadataResponse, "renameCascade">>,
): {
	hub: string[];
	agentError: string | null;
	agentsSkipped: string[];
	agentsFailed: string[];
	renameErrors: string[];
} {
	const hub: string[] = [];
	const hubSync = data.hubSync;
	if (hubSync && typeof (hubSync as WireGuardHubSyncResult).synced === "boolean") {
		const single = hubSync as WireGuardHubSyncResult;
		if (!single.synced) hub.push(single.reason ?? "?");
	} else if (hubSync) {
		for (const [iface, res] of Object.entries(hubSync as Record<string, WireGuardHubSyncResult>)) {
			if (res && res.synced === false) hub.push(`${iface}: ${res.reason ?? "?"}`);
		}
	}
	const agentSync = data.agentSync;
	const agentError = agentSync && !Array.isArray(agentSync) ? agentSync.error || "?" : null;
	const agentsFailed = Array.isArray(agentSync)
		? agentSync.filter((a) => a.error).map((a) => `${a.name} (${a.error})`)
		: [];
	const agentsSkipped = Array.isArray(agentSync)
		? agentSync.filter((a) => !a.changed && !a.error && a.reason).map((a) => `${a.name} (${a.reason})`)
		: [];
	return { hub, agentError, agentsSkipped, agentsFailed, renameErrors: renameCascadeProblems(data.renameCascade) };
}

/** Number of hub peers changed by a live sync (per-interface map or a single result). */
export function hubChangeCount(
	hubSync: Record<string, WireGuardHubSyncResult> | WireGuardHubSyncResult | null | undefined,
): number {
	if (!hubSync) return 0;
	if (typeof (hubSync as WireGuardHubSyncResult).synced === "boolean") {
		return (hubSync as WireGuardHubSyncResult).changes?.length ?? 0;
	}
	return Object.values(hubSync as Record<string, WireGuardHubSyncResult>).reduce(
		(sum, res) => sum + (res?.changes?.length ?? 0),
		0,
	);
}
