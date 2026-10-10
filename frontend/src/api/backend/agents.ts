import { del, get, post, put } from "./base";
import type { Agent, AgentCreateData, AgentUpdateData } from "./models";

export function getAgents(): Promise<Agent[]> {
	return get({ url: "agents" }) as Promise<Agent[]>;
}

export function createAgent(data: AgentCreateData): Promise<Agent> {
	return post({ url: "agents", data }) as Promise<Agent>;
}

export function updateAgent(id: number, data: AgentUpdateData): Promise<Agent> {
	return put({ url: `agents/${id}`, data }) as Promise<Agent>;
}

export function deleteAgent(id: number, force = false): Promise<void> {
	return del({ url: `agents/${id}`, params: force ? { force: "1" } : undefined }) as Promise<void>;
}

/** Mirrors FORCE_DELETE_OFFLINE_S in backend/internal/agent.js. */
export const AGENT_FORCE_DELETE_OFFLINE_S = 60 * 60;

/** Backend refusal from assertIngressTornDown (the Freigaben filter may still run). */
const INGRESS_GUARD_RE = /als gesetzt meldet/;
/** Backend ItemNotFoundError ("Not Found - <id>"): the agent is already deleted. */
const NOT_FOUND_RE = /^Not Found( - \d+)?$/;

export const isAgentGone = (agent: Pick<Agent, "lastSeen">, now = Date.now() / 1000): boolean =>
	!agent.lastSeen || now - agent.lastSeen >= AGENT_FORCE_DELETE_OFFLINE_S;

/**
 * Delete an agent; when the backend refuses because the Freigaben filter is not
 * confirmed as torn down and the agent is gone (offline for good — it can never
 * confirm), ask a second time (`confirmForce`) and force the delete.
 * An agent the backend no longer knows counts as deleted, so retrying a
 * half-done link/interface delete does not fail on it again.
 */
export async function deleteAgentGuarded(
	agent: Pick<Agent, "id" | "lastSeen">,
	confirmForce: () => boolean,
): Promise<void> {
	try {
		await deleteAgent(agent.id);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		if (NOT_FOUND_RE.test(msg)) return;
		if (!INGRESS_GUARD_RE.test(msg) || !isAgentGone(agent) || !confirmForce()) throw err;
		await deleteAgent(agent.id, true);
	}
}

export function resetAgentToken(id: number): Promise<Agent> {
	return post({ url: `agents/${id}/reset-token`, data: {} }) as Promise<Agent>;
}

export function buildInstallOneliner(regToken: string, publicUrl: string, tunnelUrl: string): string {
	const url = `${publicUrl}/api/agent/install?reg_token=${encodeURIComponent(regToken)}&public_url=${encodeURIComponent(publicUrl)}&tunnel_url=${encodeURIComponent(tunnelUrl)}`;
	return `curl -fsSL "${url}" | bash`;
}
