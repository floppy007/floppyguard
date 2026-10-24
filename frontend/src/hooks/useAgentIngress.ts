import { type QueryClient, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	type AgentIngressBulkResult,
	type AgentIngressCatalog,
	type AgentIngressCheck,
	type AgentIngressMode,
	type AgentIngressPreview,
	type AgentIngressRuleData,
	type AgentIngressState,
	type AgentIngressTestRequest,
	type AgentIngressTestResult,
	createAgentIngressRule,
	createAgentIngressRulesBulk,
	disableAgentIngressRules,
	getAgentIngress,
	getAgentIngressCatalog,
	getAgentIngressCheck,
	getAgentIngressPreview,
	setAgentIngressMode,
	testAgentIngress,
	updateAgentIngressRule,
} from "src/api/backend";

/**
 * The agent confirms a new ruleset with its next heartbeat (~30 s). While a
 * ruleset is still "pending", poll so the "not yet confirmed" hint clears on its
 * own — but only for a bounded window per query (PENDING_POLL_WINDOW_MS from the
 * last change, or from when "pending" was first seen). An agent that never
 * confirms (offline, not upgraded) must not keep the expensive Prüfung query
 * (/agent-ingress/check: all hosts, streams, confs, DNS) running every 10 s for
 * as long as the page is open; the backend reports such agents as "offline".
 */
export const PENDING_POLL_MS = 10 * 1000;
export const PENDING_POLL_WINDOW_MS = 3 * 60 * 1000;

// queryHash → start of the current pending poll window
const pendingWindows = new Map<string, number>();

/** Start a fresh poll window for every ingress query (after a mutation). */
export const resetIngressPollWindows = () => pendingWindows.clear();

export const ingressPendingInterval = (
	data: AgentIngressState | AgentIngressCheck[] | undefined,
	key = "default",
	now = Date.now(),
): number | false => {
	const list = data ? (Array.isArray(data) ? data : [data]) : [];
	if (!list.some((entry) => entry?.applied?.state === "pending")) {
		pendingWindows.delete(key);
		return false;
	}
	const since = pendingWindows.get(key) ?? now;
	pendingWindows.set(key, since);
	return now - since < PENDING_POLL_WINDOW_MS ? PENDING_POLL_MS : false;
};

/**
 * Everything an ingress mutation can change: rules, generated ruleset, cross-check and the agent list (mode).
 * Returns the refetch promise: mutations return it from onSuccess so they stay
 * pending until the (slow) Prüfung has refreshed — otherwise its stale "missing"
 * row re-enables "Freigabe anlegen" and a second click creates a duplicate rule.
 */
const invalidateAgentIngress = (queryClient: QueryClient) => {
	resetIngressPollWindows();
	return Promise.all([
		queryClient.invalidateQueries({ queryKey: ["agent-ingress"] }),
		queryClient.invalidateQueries({ queryKey: ["agent-ingress-preview"] }),
		queryClient.invalidateQueries({ queryKey: ["agent-ingress-check"] }),
		// covered flags and prune candidates change with every rule mutation
		queryClient.invalidateQueries({ queryKey: ["agent-ingress-catalog"] }),
		queryClient.invalidateQueries({ queryKey: ["agents"] }),
	]);
};

const useAgentIngress = (agentId: number, options = {}) => {
	return useQuery<AgentIngressState, Error>({
		queryKey: ["agent-ingress", agentId],
		queryFn: () => getAgentIngress(agentId),
		staleTime: 15 * 1000,
		refetchInterval: (query) => ingressPendingInterval(query.state.data, query.queryHash),
		...options,
	});
};

/**
 * Enabled-rule count of one agent. Normally from the shared check (no full
 * ingress fetch per agent, N+1), but the check only lists agents bound to a
 * WireGuard link: for an unbound agent (or an older backend without the count)
 * fall back to its own ingress state once the check has settled.
 */
const useAgentIngressActiveRules = (agentId: number, fromCheck: number | null, checkSettled: boolean) => {
	const fallback = useAgentIngress(agentId, { enabled: checkSettled && fromCheck === null });
	if (fromCheck !== null) return fromCheck;
	return fallback.data ? fallback.data.rules.filter((r) => r.enabled).length : null;
};

const useAgentIngressPreview = (agentId: number, options = {}) => {
	return useQuery<AgentIngressPreview, Error>({
		queryKey: ["agent-ingress-preview", agentId],
		queryFn: () => getAgentIngressPreview(agentId),
		...options,
	});
};

const useAgentIngressCheck = (options = {}) => {
	return useQuery<AgentIngressCheck[], Error>({
		queryKey: ["agent-ingress-check"],
		queryFn: getAgentIngressCheck,
		staleTime: 30 * 1000,
		refetchInterval: (query) => ingressPendingInterval(query.state.data, query.queryHash),
		...options,
	});
};

const useSetAgentIngressMode = (agentId: number) => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (mode: AgentIngressMode) => setAgentIngressMode(agentId, mode),
		onSuccess: () => invalidateAgentIngress(queryClient),
	});
};

const useCreateAgentIngressRule = (agentId: number) => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (data: AgentIngressRuleData) => createAgentIngressRule(agentId, data),
		onSuccess: () => invalidateAgentIngress(queryClient),
	});
};

const useUpdateAgentIngressRule = (agentId: number) => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: ({ ruleId, data }: { ruleId: number; data: Partial<AgentIngressRuleData> }) =>
			updateAgentIngressRule(agentId, ruleId, data),
		onSuccess: () => invalidateAgentIngress(queryClient),
	});
};

/**
 * Known sources/destinations, port presets and prune candidates (pickers,
 * wizards). No retry: a backend without the endpoint (404) or a failing
 * WireGuard view must degrade to the plain form at once.
 */
const useAgentIngressCatalog = (agentId: number, options = {}) => {
	return useQuery<AgentIngressCatalog, Error>({
		queryKey: ["agent-ingress-catalog", agentId],
		queryFn: () => getAgentIngressCatalog(agentId),
		staleTime: 60 * 1000,
		retry: false,
		...options,
	});
};

/** Flow tester — read-only, invalidates nothing. */
const useTestAgentIngress = (agentId: number) => {
	return useMutation<AgentIngressTestResult, Error, AgentIngressTestRequest>({
		mutationFn: (data: AgentIngressTestRequest) => testAgentIngress(agentId, data),
	});
};

const useCreateAgentIngressRulesBulk = (agentId: number) => {
	const queryClient = useQueryClient();
	return useMutation<AgentIngressBulkResult, Error, AgentIngressRuleData[]>({
		mutationFn: (rules: AgentIngressRuleData[]) => createAgentIngressRulesBulk(agentId, rules),
		onSuccess: () => invalidateAgentIngress(queryClient),
	});
};

/** prune: the "switch off unused" action (ids re-checked by the backend) */
const useDisableAgentIngressRules = (agentId: number, { prune = false }: { prune?: boolean } = {}) => {
	const queryClient = useQueryClient();
	return useMutation<{ disabled: number[] }, Error, number[]>({
		mutationFn: (ruleIds: number[]) => disableAgentIngressRules(agentId, ruleIds, { prune }),
		onSuccess: () => invalidateAgentIngress(queryClient),
	});
};

export {
	invalidateAgentIngress,
	useAgentIngress,
	useAgentIngressActiveRules,
	useAgentIngressCatalog,
	useAgentIngressCheck,
	useAgentIngressPreview,
	useCreateAgentIngressRule,
	useCreateAgentIngressRulesBulk,
	useDisableAgentIngressRules,
	useSetAgentIngressMode,
	useTestAgentIngress,
	useUpdateAgentIngressRule,
};
