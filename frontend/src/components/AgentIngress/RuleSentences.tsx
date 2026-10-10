import { IconArrowRight, IconChevronDown, IconChevronRight } from "@tabler/icons-react";
import { type ReactNode, useEffect, useState } from "react";
import type { AgentIngressCatalog, AgentIngressCatalogKind, AgentIngressRule } from "src/api/backend";
import { describeRule, groupRulesBySource, shortCidr, type SourceGroupKind } from "./catalog";
import { KindIcon } from "./CatalogPicker";
import { MAX_INLINE_TARGETS } from "./RuleSentence";
import { HitCell, ingressRuleDomId, RuleMenu, RuleToggle, useRuleRowActions } from "./RulesTable";
import { isLegacyNote, ti } from "./utils";

const GROUP_ICON: Record<SourceGroupKind, AgentIngressCatalogKind | "other"> = {
	hub: "hub",
	site: "site",
	client: "client",
	other: "other",
};

/** At most this many port chips, the rest as "+N". */
const MAX_PORT_CHIPS = 4;

/** Targets of one rule as readable names ("Nextcloud (192.168.60.22)") plus port chips. */
export function RuleTargets({
	rule,
	catalog,
}: {
	rule: Pick<AgentIngressRule, "sources" | "destinations" | "ports">;
	catalog?: AgentIngressCatalog | null;
}) {
	const d = describeRule(rule, catalog);
	const inline = d.targets.slice(0, MAX_INLINE_TARGETS);
	const more = d.targets.slice(MAX_INLINE_TARGETS);
	const targets: ReactNode[] = [];
	if (d.anyTarget) {
		targets.push(<strong key="any">{ti("row.anything")}</strong>);
	} else {
		inline.forEach((t, i) => {
			if (i > 0) targets.push(", ");
			targets.push(<strong key={`t-${i}`}>{t}</strong>);
		});
		if (more.length) {
			targets.push(" ");
			targets.push(
				<span key="more" className="text-decoration-underline" title={more.join(", ")}>
					{ti("sentence.more", { count: more.length })}
					<span className="visually-hidden">: {more.join(", ")}</span>
				</span>,
			);
		}
	}
	const ports = rule.ports.map((p) => `${p.proto}/${p.port}`);
	const shownPorts = ports.slice(0, MAX_PORT_CHIPS);
	const hiddenPorts = ports.slice(MAX_PORT_CHIPS);
	return (
		<span className="d-inline-flex flex-wrap align-items-center gap-1" data-testid="ingress-rule-targets">
			<IconArrowRight size={14} className="text-secondary flex-shrink-0" aria-hidden />
			<span className="text-break me-1">{targets}</span>
			{ports.length === 0 ? (
				<span className="badge bg-secondary-lt text-secondary fw-normal">{ti("sentence.all-ports")}</span>
			) : (
				<>
					{shownPorts.map((p) => (
						<span key={p} className="badge bg-secondary-lt text-secondary fw-normal font-monospace">
							{p}
						</span>
					))}
					{hiddenPorts.length > 0 && (
						<span className="badge bg-secondary-lt text-secondary fw-normal" title={hiddenPorts.join(", ")}>
							+{hiddenPorts.length}
							<span className="visually-hidden">: {hiddenPorts.join(", ")}</span>
						</span>
					)}
				</>
			)}
		</span>
	);
}

interface Props {
	agentId: number;
	rules: AgentIngressRule[];
	catalog?: AgentIngressCatalog | null;
	onEdit: (rule: AgentIngressRule) => void;
	onError: (msg: string | null) => void;
	highlightId?: number | null;
}

/**
 * Default rule view: one collapsible section per source ("Hinderlich Office"),
 * one compact row per rule — targets by name, port chips, last hit, active
 * switch and a menu. Without a catalog the raw CIDRs serve as names.
 */
export function AgentIngressRuleSentences({ agentId, rules, catalog, onEdit, onError, highlightId }: Props) {
	const { onToggle, onDelete, togglePending } = useRuleRowActions(agentId, onError);
	const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
	const groups = groupRulesBySource(rules, catalog);
	// The group a highlight targets (tester "go to rule", a rule just created)
	// opens for good — it must not snap shut when the highlight fades.
	const highlightGroup = highlightId == null ? null : (groups.find((g) => g.rules.some((r) => r.id === highlightId))?.key ?? null);
	useEffect(() => {
		if (highlightGroup === null) return;
		setCollapsed((prev) => {
			if (!prev.has(highlightGroup)) return prev;
			const next = new Set(prev);
			next.delete(highlightGroup);
			return next;
		});
	}, [highlightGroup]);

	if (rules.length === 0) return null;

	const toggleGroup = (key: string) =>
		setCollapsed((prev) => {
			const next = new Set(prev);
			if (next.has(key)) next.delete(key);
			else next.add(key);
			return next;
		});

	return (
		<div className="d-flex flex-column gap-3" data-testid="ingress-sentences">
			{groups.map((g) => {
				// open at once while highlighted; the effect above then keeps it open
				const open = !collapsed.has(g.key) || g.key === highlightGroup;
				const bodyId = `ingress-${agentId}-group-${g.key.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
				return (
					<section key={g.key} className="border rounded" data-testid="ingress-source-group">
						<button
							type="button"
							className="btn btn-ghost-secondary w-100 justify-content-start text-start text-body gap-2 px-3 py-2 rounded-0 border-0"
							aria-expanded={open}
							aria-controls={bodyId}
							onClick={() => toggleGroup(g.key)}
						>
							{open ? (
								<IconChevronDown size={16} className="text-secondary flex-shrink-0" aria-hidden />
							) : (
								<IconChevronRight size={16} className="text-secondary flex-shrink-0" aria-hidden />
							)}
							<KindIcon kind={GROUP_ICON[g.kind]} size={16} />
							<span className="fw-medium text-truncate" data-testid="ingress-group-label">
								{g.label}
							</span>
							<span
								className="small font-monospace text-secondary fw-normal text-truncate"
								style={{ minWidth: 0 }}
								data-testid="ingress-group-cidrs"
							>
								{g.cidrs.map(shortCidr).join(", ")}
							</span>
							<span className="small text-secondary fw-normal ms-auto text-nowrap">
								{ti("sentence.active-count", {
									active: g.rules.filter((r) => r.enabled).length,
									count: g.rules.length,
								})}
							</span>
						</button>
						{open && (
							<div id={bodyId} className="list-group list-group-flush border-top">
								{g.rules.map((rule) => (
									<div
										key={rule.id}
										id={ingressRuleDomId(agentId, rule.id)}
										className={[
											"list-group-item py-2 px-3",
											rule.enabled ? "" : "text-secondary",
											highlightId === rule.id ? "bg-primary-lt" : "",
										]
											.filter(Boolean)
											.join(" ")}
									>
										{/* same grid for every row: content left, hits/switch/menu right (below on phones) */}
										<div className="ingress-rule-row" data-testid="ingress-rule-row">
											<div className="ingress-rule-main">
												<RuleTargets rule={rule} catalog={catalog} />
												<div className="small text-secondary mt-1 d-flex flex-wrap align-items-center gap-1">
													<span className="text-break">{rule.name}</span>
													{isLegacyNote(rule.note) && (
														<span className="badge bg-warning-lt text-warning">{ti("legacy")}</span>
													)}
													{!rule.enabled && (
														<span className="badge bg-secondary-lt">{ti("sentence.off")}</span>
													)}
												</div>
												{rule.note && <div className="small text-secondary">{rule.note}</div>}
											</div>
											<div className="ingress-rule-side" data-testid="ingress-rule-side">
												<span className="ingress-rule-hit small text-nowrap">
													<HitCell rule={rule} />
												</span>
												<RuleToggle rule={rule} disabled={togglePending} onToggle={onToggle} />
												<RuleMenu rule={rule} onEdit={onEdit} onDelete={onDelete} />
											</div>
										</div>
									</div>
								))}
							</div>
						)}
					</section>
				);
			})}
		</div>
	);
}
