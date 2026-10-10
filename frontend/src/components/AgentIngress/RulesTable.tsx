import { IconInfoCircle, IconPencil, IconTrash } from "@tabler/icons-react";
import { type AgentIngressCatalog, type AgentIngressRule, deleteAgentIngressRule } from "src/api/backend";
import { useUpdateAgentIngressRule } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { showDeleteConfirmModal } from "src/modals/DeleteConfirmModal";
import { labelsForCidrs } from "./catalog";
import { errMessage, formatPorts, INGRESS_INVALIDATIONS, isLegacyNote, isStaleRule, relativeTime, ti } from "./utils";

export function HitCell({ rule }: { rule: AgentIngressRule }) {
	// Hits count NEW connections only, so "no new connection" is a hint (info
	// icon), not a warning: a rule carrying only long-lived flows looks idle.
	const stale = isStaleRule(rule);
	const label = rule.lastHitAt === null ? ti("hit.never") : ti("hit.last", { ago: relativeTime(rule.lastHitAt) });
	return (
		<span
			className="text-secondary"
			data-stale={stale ? "true" : undefined}
			title={`${ti("hit.packets", { count: rule.hitPackets ?? 0 })}${stale ? ` — ${ti("hit.stale")}` : ""}`}
		>
			{stale && <IconInfoCircle size={14} className="me-1" />}
			{label}
		</span>
	);
}

/** DOM id of a rule row (sentence or table) — the tester scrolls to it. */
export const ingressRuleDomId = (agentId: number, ruleId: number) => `ingress-rule-${agentId}-${ruleId}`;

/** Toggle / delete shared by the table and the sentence view. */
export function useRuleRowActions(agentId: number, onError: (msg: string | null) => void) {
	const updateRule = useUpdateAgentIngressRule(agentId);
	const onToggle = (rule: AgentIngressRule, enabled: boolean) => {
		onError(null);
		updateRule.mutate({ ruleId: rule.id, data: { enabled } }, { onError: (err) => onError(errMessage(err)) });
	};
	const onDelete = (rule: AgentIngressRule) =>
		showDeleteConfirmModal({
			title: ti("delete-title"),
			onConfirm: async () => {
				await deleteAgentIngressRule(agentId, rule.id);
			},
			invalidations: INGRESS_INVALIDATIONS,
			children: ti("delete-confirm", { name: rule.name }),
		});
	return { onToggle, onDelete, togglePending: updateRule.isPending };
}

/** Active switch of one rule (same aria-label in both views). */
export function RuleToggle({
	rule,
	disabled,
	onToggle,
}: {
	rule: AgentIngressRule;
	disabled: boolean;
	onToggle: (rule: AgentIngressRule, enabled: boolean) => void;
}) {
	return (
		<div className="form-check form-switch mb-0">
			<input
				className="form-check-input"
				type="checkbox"
				role="switch"
				aria-checked={rule.enabled}
				aria-label={ti("toggle-label", { name: rule.name })}
				checked={rule.enabled}
				disabled={disabled}
				onChange={(e) => onToggle(rule, e.target.checked)}
			/>
		</div>
	);
}

/** Edit / delete buttons of one rule. */
export function RuleButtons({
	rule,
	onEdit,
	onDelete,
}: {
	rule: AgentIngressRule;
	onEdit: (rule: AgentIngressRule) => void;
	onDelete: (rule: AgentIngressRule) => void;
}) {
	return (
		<>
			<button
				type="button"
				className="btn btn-sm btn-ghost-secondary p-1"
				title={intl.formatMessage({ id: "action.edit" })}
				aria-label={`${intl.formatMessage({ id: "action.edit" })} ${rule.name}`}
				data-ingress-edit={rule.id}
				onClick={() => onEdit(rule)}
			>
				<IconPencil size={16} aria-hidden />
			</button>
			<button
				type="button"
				className="btn btn-sm btn-ghost-danger p-1"
				title={intl.formatMessage({ id: "action.delete" })}
				aria-label={`${intl.formatMessage({ id: "action.delete" })} ${rule.name}`}
				onClick={() => onDelete(rule)}
			>
				<IconTrash size={16} aria-hidden />
			</button>
		</>
	);
}

interface Props {
	agentId: number;
	rules: AgentIngressRule[];
	onEdit: (rule: AgentIngressRule) => void;
	onError: (msg: string | null) => void;
	/** names for the CIDRs (title tooltips) */
	catalog?: AgentIngressCatalog | null;
	/** rule to highlight briefly (tester "go to rule") */
	highlightId?: number | null;
}

/** Rule list with hit info, active toggle, edit and delete. */
export function AgentIngressRulesTable({ agentId, rules, onEdit, onError, catalog, highlightId }: Props) {
	const { onToggle, onDelete, togglePending } = useRuleRowActions(agentId, onError);
	const all = ti("all");

	if (rules.length === 0) {
		return <div className="text-secondary small mb-3">{ti("empty")}</div>;
	}

	const names = (cidrs: string[], kind: "sources" | "destinations") =>
		catalog && cidrs.length ? labelsForCidrs(cidrs, catalog[kind], catalog).join(", ") : undefined;

	return (
		<div className="table-responsive mb-3">
			<table className="table table-sm table-vcenter card-table small mb-0">
				<thead>
					<tr>
						<th>{ti("col.name")}</th>
						<th>{ti("col.sources")}</th>
						<th>{ti("col.destinations")}</th>
						<th>{ti("col.ports")}</th>
						<th>{ti("col.hits")}</th>
						<th>{ti("col.active")}</th>
						<th />
					</tr>
				</thead>
				<tbody>
					{rules.map((rule) => (
						<tr
							key={rule.id}
							id={ingressRuleDomId(agentId, rule.id)}
							className={
								[rule.enabled ? "" : "text-secondary", highlightId === rule.id ? "bg-primary-lt" : ""]
									.filter(Boolean)
									.join(" ") || undefined
							}
						>
							<td>
								<div className="fw-medium">
									{rule.name}
									{isLegacyNote(rule.note) && (
										<span className="badge bg-warning-lt text-warning ms-2">{ti("legacy")}</span>
									)}
								</div>
								{rule.note && <div className="text-secondary small">{rule.note}</div>}
							</td>
							<td className="font-monospace" title={names(rule.sources, "sources")}>
								{rule.sources.join(", ")}
							</td>
							<td className="font-monospace" title={names(rule.destinations, "destinations")}>
								{rule.destinations.length ? rule.destinations.join(", ") : all}
							</td>
							<td className="font-monospace">{rule.ports.length ? formatPorts(rule.ports) : all}</td>
							<td>
								<HitCell rule={rule} />
							</td>
							<td>
								<RuleToggle rule={rule} disabled={togglePending} onToggle={onToggle} />
							</td>
							<td className="text-end text-nowrap">
								<RuleButtons rule={rule} onEdit={onEdit} onDelete={onDelete} />
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}
