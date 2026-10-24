import { IconShieldLock } from "@tabler/icons-react";
import type { Agent } from "src/api/backend";
import { ingressUnusedCount, ingressWarningCount, ti as t } from "src/components/AgentIngress";
import { useAgentIngressActiveRules, useAgentIngressCheck } from "src/hooks";
import { showAgentIngressModal } from "src/modals";

/** Compact "Freigaben" line in the agent panel; details live in AgentIngressModal. */
export function AgentIngressSummary({ agent }: { agent: Agent }) {
	// One shared check for every agent panel instead of a full ingress fetch each (N+1)
	const check = useAgentIngressCheck();
	const entry = check.data?.find((c) => c.agentId === agent.id);

	const mode = entry?.ingressMode ?? agent.ingressMode ?? "open";
	const restricted = mode === "restricted";
	// unbound agents are not in the check: their count comes from their own rules
	const activeRules = useAgentIngressActiveRules(agent.id, entry?.activeRuleCount ?? null, check.isSuccess);
	const warnings = entry ? ingressWarningCount(entry) : null;
	const unused = entry ? ingressUnusedCount(entry) : 0;
	// Missing upstreams only break traffic while the filter is active
	const missingWhileRestricted = restricted && (warnings ?? 0) > 0;

	return (
		<div className="mb-3 d-flex align-items-center gap-2 flex-wrap">
			<span className="small text-secondary">
				<IconShieldLock size={14} className="me-1" />
				{t("title")}
			</span>
			<span className={`badge ${restricted ? "bg-green-lt text-green" : "bg-secondary-lt"}`}>
				{t(restricted ? "badge.restricted" : "badge.open")}
			</span>
			{activeRules !== null && <span className="small">{t("summary.rules", { count: activeRules })}</span>}
			{warnings !== null && warnings > 0 && (
				<span className={`badge ${missingWhileRestricted ? "bg-red-lt text-red" : "bg-yellow-lt text-yellow"}`}>
					{t("summary.warnings", { count: warnings })}
				</span>
			)}
			{unused > 0 && <span className="badge bg-secondary-lt">{t("summary.unused", { count: unused })}</span>}
			<button
				type="button"
				className="btn btn-sm btn-link p-0 small"
				onClick={() => showAgentIngressModal(agent.id, agent.name)}
			>
				{t("manage")}
			</button>
		</div>
	);
}
