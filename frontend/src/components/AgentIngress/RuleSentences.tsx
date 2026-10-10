import type { AgentIngressCatalog, AgentIngressCatalogKind, AgentIngressRule } from "src/api/backend";
import { groupRulesBySource, shortCidr, type SourceGroupKind } from "./catalog";
import { KindIcon } from "./CatalogPicker";
import { RuleSentence } from "./RuleSentence";
import { HitCell, ingressRuleDomId, RuleButtons, RuleToggle, useRuleRowActions } from "./RulesTable";
import { isLegacyNote, ti } from "./utils";

const GROUP_ICON: Record<SourceGroupKind, AgentIngressCatalogKind | "other"> = {
	hub: "hub",
	site: "site",
	client: "client",
	other: "other",
};

interface Props {
	agentId: number;
	rules: AgentIngressRule[];
	catalog?: AgentIngressCatalog | null;
	onEdit: (rule: AgentIngressRule) => void;
	onError: (msg: string | null) => void;
	highlightId?: number | null;
}

/**
 * Default rule view: one card per source ("Hinderlich Office"), one sentence
 * per rule ("may access Ops-Server (10.3.10.25) – all ports"). Without a
 * catalog the raw CIDRs serve as names.
 */
export function AgentIngressRuleSentences({ agentId, rules, catalog, onEdit, onError, highlightId }: Props) {
	const { onToggle, onDelete, togglePending } = useRuleRowActions(agentId, onError);

	if (rules.length === 0) {
		return <div className="text-secondary small mb-3">{ti("empty")}</div>;
	}

	const groups = groupRulesBySource(rules, catalog);

	return (
		<div className="mb-3 d-flex flex-column gap-2" data-testid="ingress-sentences">
			{groups.map((g) => (
				<div key={g.key} className="card card-sm" data-testid="ingress-source-group">
					<div className="card-header py-2 px-3 d-flex flex-wrap align-items-center gap-2">
						<KindIcon kind={GROUP_ICON[g.kind]} size={16} />
						<span className="fw-medium">{g.label}</span>
						<span className="small font-monospace text-secondary d-none d-md-inline text-break">
							{g.cidrs.map(shortCidr).join(", ")}
						</span>
						<span className="badge bg-secondary-lt ms-auto">
							{ti("sentence.active-count", {
								active: g.rules.filter((r) => r.enabled).length,
								count: g.rules.length,
							})}
						</span>
					</div>
					<div className="list-group list-group-flush">
						{g.rules.map((rule) => (
							<div
								key={rule.id}
								id={ingressRuleDomId(agentId, rule.id)}
								className={[
									"list-group-item py-2 px-3 small",
									rule.enabled ? "" : "text-secondary",
									highlightId === rule.id ? "bg-primary-lt" : "",
								]
									.filter(Boolean)
									.join(" ")}
							>
								<div className="d-flex flex-wrap align-items-center gap-2">
									<RuleSentence rule={rule} catalog={catalog} className="text-break" />
									<span className="badge bg-secondary-lt text-secondary fw-normal">{rule.name}</span>
									{isLegacyNote(rule.note) && (
										<span className="badge bg-warning-lt text-warning">{ti("legacy")}</span>
									)}
									{!rule.enabled && <span className="badge bg-secondary-lt">{ti("sentence.off")}</span>}
									<HitCell rule={rule} />
									<div className="ms-auto d-flex align-items-center gap-1">
										<RuleToggle rule={rule} disabled={togglePending} onToggle={onToggle} />
										<RuleButtons rule={rule} onEdit={onEdit} onDelete={onDelete} />
									</div>
								</div>
								{rule.note && <div className="text-secondary small mt-1">{rule.note}</div>}
							</div>
						))}
					</div>
				</div>
			))}
		</div>
	);
}
