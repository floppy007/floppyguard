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

export function deleteAgent(id: number): Promise<void> {
	return del({ url: `agents/${id}` }) as Promise<void>;
}

export function resetAgentToken(id: number): Promise<Agent> {
	return post({ url: `agents/${id}/reset-token`, data: {} }) as Promise<Agent>;
}

export function buildInstallOneliner(regToken: string, publicUrl: string, tunnelUrl: string): string {
	const url = `${publicUrl}/api/agent/install?reg_token=${encodeURIComponent(regToken)}&public_url=${encodeURIComponent(publicUrl)}&tunnel_url=${encodeURIComponent(tunnelUrl)}`;
	return `curl -fsSL "${url}" | bash`;
}
