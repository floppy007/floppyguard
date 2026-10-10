import type { AgentIngressCatalog, AgentIngressRuleData } from "src/api/backend";
import { isBroadRule, lineCount, MAX_RULE_LINES } from "../catalog";
import { RuleSentence } from "../RuleSentence";
import { ti } from "../utils";

interface Props {
	rules: AgentIngressRuleData[];
	catalog?: AgentIngressCatalog | null;
}

/** Last wizard step: one sentence per rule to be created, line count, broad-rule warning. */
export function RulePreviewList({ rules, catalog }: Props) {
	const lines = rules.reduce((n, r) => n + lineCount(r), 0);
	const tooMany = rules.some((r) => lineCount(r) > MAX_RULE_LINES);
	const broad = rules.some(isBroadRule);
	return (
		<div data-testid="ingress-wizard-preview">
			<div className="small text-secondary mb-2">{ti("wizard.preview")}</div>
			<ul className="list-unstyled small mb-2">
				{rules.map((r) => (
					<li key={`${r.name}-${r.sources.join(",")}-${r.destinations.join(",")}`} className="mb-1">
						<span className="badge bg-secondary-lt text-secondary fw-normal me-2">{r.name}</span>
						<RuleSentence rule={r} catalog={catalog} withSource />
					</li>
				))}
			</ul>
			<div className={`small ${tooMany ? "text-danger" : "text-secondary"}`}>
				{ti("wizard.lines", { count: lines })}
				{tooMany && ` — ${ti("wizard.too-many", { max: MAX_RULE_LINES })}`}
			</div>
			{broad && (
				<div className="alert d-block alert-warning py-2 px-3 small mt-2 mb-0" data-testid="ingress-wizard-broad">
					{ti("wizard.broad")}
				</div>
			)}
		</div>
	);
}

/** Whether the preview allows saving (every rule within the per-rule line cap). */
export const previewSavable = (rules: AgentIngressRuleData[]) =>
	rules.length > 0 && rules.every((r) => lineCount(r) <= MAX_RULE_LINES && r.sources.length > 0);
