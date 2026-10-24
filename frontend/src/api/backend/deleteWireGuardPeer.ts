import * as api from "./base";

/** One agent bound to a link that a link/interface delete would remove too. */
export interface BoundAgentCheck {
	id: number;
	name: string;
	linkName: string;
	/** Why the agent cannot be deleted now (null = deletable). */
	blocked: string | null;
	/** A forced delete would be accepted (agent offline for good). */
	forceable: boolean;
}

export interface BoundAgentDeleteOptions {
	deleteBoundAgents?: boolean;
	forceAgentIds?: number[];
	dryRun?: boolean;
}

export interface BoundAgentDeleteResult {
	deleted: number[];
	errors: { id: number; name: string; error: string }[];
}

export interface DeleteWireGuardPeerRequest extends BoundAgentDeleteOptions {
	linkId: string;
}

export interface DeleteWireGuardPeerResponse {
	deleted?: boolean;
	dryRun?: boolean;
	linkId: string;
	/** dryRun: the check per bound agent; otherwise the cascade result. */
	agents?: BoundAgentCheck[] | BoundAgentDeleteResult;
}

export async function deleteWireGuardPeer(data: DeleteWireGuardPeerRequest): Promise<DeleteWireGuardPeerResponse> {
	// rawBody: backend deleteOptions() reads camelCase dryRun/deleteBoundAgents/forceAgentIds
	return api.post({ url: "wireguard/delete-peer", data, rawBody: true }) as Promise<DeleteWireGuardPeerResponse>;
}

/**
 * Delete a link/interface together with its bound agents as ONE backend
 * operation: a dry run checks every bound agent first (a refused agent that is
 * offline for good is offered for a forced delete via `confirmForce`); nothing is
 * removed while one of them still refuses. The backend deletes the agents only
 * after the peer/interface is gone and re-checks everything itself.
 */
export async function deleteWithBoundAgents(
	call: (opts: BoundAgentDeleteOptions) => Promise<{ agents?: BoundAgentCheck[] | BoundAgentDeleteResult }>,
	confirmForce: (agent: BoundAgentCheck) => boolean,
): Promise<void> {
	const check = await call({ dryRun: true });
	const agents = Array.isArray(check.agents) ? check.agents : [];
	const forceAgentIds: number[] = [];
	for (const a of agents) {
		if (!a.blocked) continue;
		if (!a.forceable || !confirmForce(a)) throw new Error(`${a.name}: ${a.blocked}`);
		forceAgentIds.push(a.id);
	}
	const res = await call({ deleteBoundAgents: agents.length > 0, forceAgentIds });
	const result = res.agents && !Array.isArray(res.agents) ? res.agents : null;
	if (result?.errors?.length) {
		throw new Error(result.errors.map((e) => `${e.name}: ${e.error}`).join("; "));
	}
}
