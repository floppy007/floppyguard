import type { QueryClient } from "@tanstack/react-query";

// Not re-exported from ./index: index.test.tsx mocks the src/hooks barrel with a fixed factory.

/** Every query the WireGuard page derives from the hub config / wg state. */
export const WG_QUERY_KEYS = ["wireguard-status", "wireguard-bandwidth", "wireguard-apply-state"] as const;

/** Keys an agent-affecting change (delete link/interface, restore, apply) must also refresh. */
export const WG_AGENT_QUERY_KEYS = ["agents", "agent-ingress-check"] as const;

/** Key arrays for DeleteConfirmModal's `invalidations` prop (agent queries only). */
export const agentInvalidations = (): string[][] => WG_AGENT_QUERY_KEYS.map((k) => [k]);

/** Key arrays for DeleteConfirmModal's `invalidations` prop. */
export const wireGuardInvalidations = (opts: { agents?: boolean } = {}): string[][] => [
	...WG_QUERY_KEYS.map((k) => [k]),
	...(opts.agents ? agentInvalidations() : []),
];

export const invalidateWireGuard = (queryClient: QueryClient, opts: { agents?: boolean } = {}) => {
	for (const key of wireGuardInvalidations(opts)) {
		queryClient.invalidateQueries({ queryKey: key });
	}
};
