import { del, get, post, put } from "./base";
import type {
	AgentIngressBulkResult,
	AgentIngressCatalog,
	AgentIngressCheck,
	AgentIngressMode,
	AgentIngressPreview,
	AgentIngressRule,
	AgentIngressRuleData,
	AgentIngressState,
	AgentIngressTestRequest,
	AgentIngressTestResult,
} from "./models";

export function getAgentIngress(agentId: number): Promise<AgentIngressState> {
	return get({ url: `agents/${agentId}/ingress` }) as Promise<AgentIngressState>;
}

export function setAgentIngressMode(agentId: number, ingressMode: AgentIngressMode): Promise<AgentIngressState> {
	return put({ url: `agents/${agentId}/ingress`, data: { ingressMode } }) as Promise<AgentIngressState>;
}

export function getAgentIngressPreview(agentId: number): Promise<AgentIngressPreview> {
	return get({ url: `agents/${agentId}/ingress/preview` }) as Promise<AgentIngressPreview>;
}

export function createAgentIngressRule(agentId: number, data: AgentIngressRuleData): Promise<AgentIngressRule> {
	return post({ url: `agents/${agentId}/ingress/rules`, data }) as Promise<AgentIngressRule>;
}

export function updateAgentIngressRule(
	agentId: number,
	ruleId: number,
	data: Partial<AgentIngressRuleData>,
): Promise<AgentIngressRule> {
	return put({ url: `agents/${agentId}/ingress/rules/${ruleId}`, data }) as Promise<AgentIngressRule>;
}

export function deleteAgentIngressRule(agentId: number, ruleId: number): Promise<{ deleted: boolean }> {
	return del({ url: `agents/${agentId}/ingress/rules/${ruleId}` }) as Promise<{ deleted: boolean }>;
}

export function getAgentIngressCheck(): Promise<AgentIngressCheck[]> {
	return get({ url: "agent-ingress/check" }) as Promise<AgentIngressCheck[]>;
}

export function getAgentIngressCatalog(agentId: number): Promise<AgentIngressCatalog> {
	return get({ url: `agents/${agentId}/ingress/catalog` }) as Promise<AgentIngressCatalog>;
}

/** Read-only: what the agent's filter does with one flow. */
export function testAgentIngress(agentId: number, data: AgentIngressTestRequest): Promise<AgentIngressTestResult> {
	return post({ url: `agents/${agentId}/ingress/test`, data }) as Promise<AgentIngressTestResult>;
}

/** Create several rules at once; duplicates of existing rules are skipped by the backend. */
export function createAgentIngressRulesBulk(
	agentId: number,
	rules: AgentIngressRuleData[],
): Promise<AgentIngressBulkResult> {
	return post({ url: `agents/${agentId}/ingress/rules/bulk`, data: { rules } }) as Promise<AgentIngressBulkResult>;
}

/**
 * Switch several rules off. prune = the "switch off unused" action: the backend
 * re-checks every id against its current prune candidates.
 */
export function disableAgentIngressRules(
	agentId: number,
	ruleIds: number[],
	{ prune = false }: { prune?: boolean } = {},
): Promise<{ disabled: number[] }> {
	return post({
		url: `agents/${agentId}/ingress/rules/bulk-disable`,
		data: prune ? { ruleIds, prune: true } : { ruleIds },
	}) as Promise<{
		disabled: number[];
	}>;
}
