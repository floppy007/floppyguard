import { useState } from "react";
import type { AgentIngressRuleData } from "src/api/backend";
import { useCreateAgentIngressRulesBulk } from "src/hooks";
import { bulkResultInfo, bulkResultRuleId, errMessage } from "../utils";

/**
 * Save the rules of a wizard — always through the bulk endpoint, also for a
 * single rule: it skips exact duplicates and switches a matching disabled rule
 * back on, so rerunning a wizard never creates the same rule twice. onDone
 * receives the info line for the panel and the rule to highlight.
 */
export function useWizardSave(agentId: number, onDone: (info?: string, ruleId?: number | null) => void) {
	const createBulk = useCreateAgentIngressRulesBulk(agentId);
	const [error, setError] = useState<string | null>(null);
	const pending = createBulk.isPending;

	const save = (rules: AgentIngressRuleData[]) => {
		if (pending || rules.length === 0) return;
		setError(null);
		createBulk.mutate(rules, {
			onSuccess: (res) => onDone(bulkResultInfo(res), bulkResultRuleId(res)),
			onError: (err: unknown) => setError(errMessage(err)),
		});
	};

	return { save, pending, error };
}
