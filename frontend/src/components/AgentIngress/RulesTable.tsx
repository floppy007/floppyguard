import { IconDotsVertical, IconInfoCircle, IconPencil, IconTrash } from "@tabler/icons-react";
import { type AgentIngressCatalog, type AgentIngressRule, deleteAgentIngressRule } from "src/api/backend";
import { useQueryClient } from "@tanstack/react-query";
import { invalidateAgentIngress, useUpdateAgentIngressRule } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { POPPER_FIXED } from "src/modules/Dropdown";
import { showDeleteConfirmModal } from "src/modals/DeleteConfirmModal";
import { labelsForCidrs } from "./catalog";
import { errMessage, formatPorts, isLegacyNote, isStaleRule, relativeTime, ti } from "./utils";

/** Hit info: "zuletzt: vor 2 Stunden" / "noch kein Treffer"; packets and the stale hint in the tooltip. */
export function HitCell({ rule }: { rule: AgentIngressRule }) {
	// Hits count NEW connections only, so "no new connection" is a hint (info
	// icon), not a warning: a rule carrying only long-lived flows looks idle.
	const stale = isStaleRule(rule);
	const label = rule.lastHitAt === null ? ti("hit.never") : ti("hit.short", { ago: relativeTime(rule.lastHitAt) });
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

/** DOM id of a rule row in the Freigaben list — the tester scrolls to it. */
export const ingressRuleDomId = (agentId: number, ruleId: number) => `ingress-rule-${agentId}-${ruleId}`;

/** DOM id of the same rule in the raw table (tab Technik) — distinct, both can be mounted. */
export const rawRuleDomId = (agentId: number, ruleId: number) => `${ingressRuleDomId(agentId, ruleId)}-raw`;

/** Toggle / delete shared by the table and the sentence view. */
export function useRuleRowActions(agentId: number, onError: (msg: string | null) => void) {
	const updateRule = useUpdateAgentIngressRule(agentId);
	const queryClient = useQueryClient();
	const onToggle = (rule: AgentIngressRule, enabled: boolean) => {
		onError(null);
		updateRule.mutate({ ruleId: rule.id, data: { enabled } }, { onError: (err) => onError(errMessage(err)) });
	};
	const onDelete = (rule: AgentIngressRule) =>
		showDeleteConfirmModal({
			title: ti("delete-title"),
			onConfirm: async () => {
				await deleteAgentIngressRule(agentId, rule.id);
				// same refresh as every other ingress mutation (incl. a fresh pending poll window)
				await invalidateAgentIngress(queryClient);
			},
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

/**
 * Kebab menu of one rule: Bearbeiten, Löschen. The toggle carries
 * data-ingress-edit so the focus returns to it when the edit form closes.
 */
export function RuleMenu({
	rule,
	onEdit,
	onDelete,
}: {
	rule: AgentIngressRule;
	onEdit: (rule: AgentIngressRule) => void;
	onDelete: (rule: AgentIngressRule) => void;
}) {
	const edit = intl.formatMessage({ id: "action.edit" });
	const del = intl.formatMessage({ id: "action.delete" });
	return (
		<div className="dropdown">
			<button
				type="button"
				className="btn btn-sm btn-ghost-secondary btn-icon"
				data-bs-toggle="dropdown"
				data-bs-popper-config={POPPER_FIXED}
				aria-expanded="false"
				aria-haspopup="menu"
				aria-label={ti("row.menu", { name: rule.name })}
				title={ti("row.menu", { name: rule.name })}
				data-ingress-edit={rule.id}
			>
				<IconDotsVertical size={16} aria-hidden />
			</button>
			<div className="dropdown-menu dropdown-menu-end" role="menu">
				<button
					type="button"
					role="menuitem"
					className="dropdown-item"
					aria-label={`${edit} ${rule.name}`}
					onClick={() => onEdit(rule)}
				>
					<IconPencil size={16} className="me-2" aria-hidden />
					{edit}
				</button>
				<div className="dropdown-divider" />
				<button
					type="button"
					role="menuitem"
					className="dropdown-item text-danger"
					aria-label={`${del} ${rule.name}`}
					onClick={() => onDelete(rule)}
				>
					<IconTrash size={16} className="me-2" aria-hidden />
					{del}
				</button>
			</div>
		</div>
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

/** Raw rule table (tab Technik): CIDRs, ports, hit counters, active toggle, edit and delete. */
export function AgentIngressRulesTable({ agentId, rules, onEdit, onError, catalog, highlightId }: Props) {
	const { onToggle, onDelete, togglePending } = useRuleRowActions(agentId, onError);
	const all = ti("all");

	if (rules.length === 0) {
		return <div className="text-secondary small mb-3">{ti("empty")}</div>;
	}

	const names = (cidrs: string[], kind: "sources" | "destinations") =>
		catalog && cidrs.length ? labelsForCidrs(cidrs, catalog[kind], catalog).join(", ") : undefined;

	return (
		<div className="table-responsive border rounded">
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
							id={rawRuleDomId(agentId, rule.id)}
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
							<td className="text-nowrap">
								<HitCell rule={rule} />
								<div className="text-secondary">
									{ti("hit.packets", { count: rule.hitPackets ?? 0 })}
								</div>
							</td>
							<td>
								<RuleToggle rule={rule} disabled={togglePending} onToggle={onToggle} />
							</td>
							<td className="text-end">
								<RuleMenu rule={rule} onEdit={onEdit} onDelete={onDelete} />
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}
