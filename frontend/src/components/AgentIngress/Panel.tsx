import { IconPlus } from "@tabler/icons-react";
import { useEffect, useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import type { AgentIngressApplied, AgentIngressMode, AgentIngressRule } from "src/api/backend";
import { useAgentIngress, useAgentIngressCatalog, useAgentIngressCheck, useSetAgentIngressMode } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { POPPER_FIXED } from "src/modules/Dropdown";
import { AgentIngressCheckList } from "./CheckList";
import { ComfortActions } from "./ComfortActions";
import { IngressTester } from "./IngressTester";
import { AgentIngressRuleForm } from "./RuleForm";
import { AgentIngressRuleSentences } from "./RuleSentences";
import { AgentIngressRulesPreview } from "./RulesPreview";
import { AgentIngressRulesTable, ingressRuleDomId } from "./RulesTable";
import { errMessage, ti } from "./utils";
import { PublishProxyWizard, SiteAccessWizard, SiteFullAccessWizard } from "./wizards";

type Editing = "new" | number | "wizard:proxy" | "wizard:site" | "wizard:full" | null;
export type IngressView = "sentences" | "table";

const VIEW_KEY = "fg.ingress.view";

const readView = (): IngressView => {
	try {
		return window.localStorage.getItem(VIEW_KEY) === "table" ? "table" : "sentences";
	} catch {
		return "sentences";
	}
};

const writeView = (view: IngressView) => {
	try {
		window.localStorage.setItem(VIEW_KEY, view);
	} catch {
		// storage blocked (private window): the choice just is not remembered
	}
};

const WIZARDS = ["proxy", "site", "full"] as const;

/**
 * Whether the agent confirmed the ruleset the hub wants it to run (reported in
 * its heartbeat). Only shown when something is off — a rejected filter must not
 * look active.
 */
function AppliedState({ applied, mode }: { applied: AgentIngressApplied | undefined; mode: AgentIngressMode }) {
	if (!applied || applied.state === "applied") return null;
	const severe =
		mode === "restricted" &&
		(applied.state === "failed" || applied.state === "unknown" || applied.state === "offline");
	const variant = applied.state === "failed" || severe ? "danger" : "warning";
	return (
		<Alert variant={variant} className="py-2 px-3 small" data-testid="ingress-applied-state">
			{ti(`applied.${applied.state}`)}
			{applied.error && <span className="font-monospace ms-1">({applied.error})</span>}
		</Alert>
	);
}

/**
 * Full "Freigaben" editor for one agent: mode switch, rule table + form,
 * Prüfung and generated-rules preview. Used by AgentIngressModal and the
 * Freigaben page.
 */
export function AgentIngressPanel({ agentId }: { agentId: number }) {
	const ingress = useAgentIngress(agentId);
	const checkQuery = useAgentIngressCheck();
	const catalogQuery = useAgentIngressCatalog(agentId);
	const setMode = useSetAgentIngressMode(agentId);
	// Only the id: the form must always see the current rule from the query, not
	// a snapshot from when "edit" was clicked.
	const [editing, setEditing] = useState<Editing>(null);
	const [error, setError] = useState<string | null>(null);
	const [info, setInfo] = useState<string | null>(null);
	const [view, setViewState] = useState<IngressView>(readView);
	const [highlight, setHighlight] = useState<number | null>(null);
	const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
	// "Add" button of the toolbar (unmounted while a form/wizard is open): focus
	// goes back there when the form/wizard closes, or to the edited rule's button.
	const addRef = useRef<HTMLButtonElement>(null);
	const prevEditing = useRef<Editing>(null);
	const focusAfterClose = useRef<number | null>(null);

	useEffect(
		() => () => {
			if (highlightTimer.current) clearTimeout(highlightTimer.current);
		},
		[],
	);

	useEffect(() => {
		const prev = prevEditing.current;
		prevEditing.current = editing;
		if (prev === null || editing !== null) return;
		const target = focusAfterClose.current ?? (typeof prev === "number" ? prev : null);
		focusAfterClose.current = null;
		const editButton =
			target !== null
				? document
						.getElementById(ingressRuleDomId(agentId, target))
						?.querySelector<HTMLButtonElement>("button[data-ingress-edit]")
				: null;
		(editButton ?? addRef.current)?.focus();
	}, [editing, agentId]);

	if (ingress.isLoading) {
		return <div className="text-secondary small">{intl.formatMessage({ id: "loading" })}</div>;
	}
	if (ingress.error || !ingress.data) {
		return <div className="text-danger small">{ingress.error?.message}</div>;
	}

	const mode: AgentIngressMode = ingress.data.ingressMode ?? "open";
	const rules = ingress.data.rules ?? [];
	const check = checkQuery.data?.find((c) => c.agentId === agentId);
	const editingRule: AgentIngressRule | null =
		typeof editing === "number" ? (rules.find((r) => r.id === editing) ?? null) : null;
	// A rule deleted meanwhile simply closes its form
	const formOpen = editing === "new" || editingRule !== null;
	const wizardOpen = typeof editing === "string" && editing.startsWith("wizard:");
	// The catalog is optional: a failing / missing endpoint (old backend) keeps the plain form
	const catalog = catalogQuery.data ?? null;
	const wizardsAvailable = !!catalog && catalog.linkFound !== false;

	const setView = (next: IngressView) => {
		setViewState(next);
		writeView(next);
	};

	const focusRule = (ruleId: number) => {
		const el = document.getElementById(ingressRuleDomId(agentId, ruleId));
		el?.scrollIntoView?.({ behavior: "smooth", block: "center" });
		setHighlight(ruleId);
		if (highlightTimer.current) clearTimeout(highlightTimer.current);
		highlightTimer.current = setTimeout(() => setHighlight(null), 2000);
	};

	/** Close form/wizard; `ruleId` = the rule it created (highlighted, gets the focus). */
	const closeEditor = (msg?: string, ruleId?: number | null) => {
		if (typeof ruleId === "number") focusAfterClose.current = ruleId;
		setEditing(null);
		if (msg) setInfo(msg);
		if (typeof ruleId === "number") {
			// after the rules refetch rendered the new row
			setTimeout(() => focusRule(ruleId), 50);
		}
	};

	const open = (next: Editing) => {
		setInfo(null);
		setEditing(next);
	};

	const onModeChange = (next: AgentIngressMode) => {
		if (next === mode || setMode.isPending) return;
		// Restricted drops everything without a matching rule — can cut a site off
		if (next === "restricted" && !window.confirm(ti("confirm-restricted"))) return;
		setError(null);
		setMode.mutate(next, { onError: (err) => setError(errMessage(err)) });
	};

	return (
		<div>
			<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible>
				{error}
			</Alert>

			<fieldset className="mb-3" disabled={setMode.isPending}>
				<legend className="form-label small mb-1">{ti("mode")}</legend>
				{(["open", "restricted"] as const).map((m) => (
					<div key={m} className="form-check form-check-inline">
						<input
							id={`ingress-mode-${agentId}-${m}`}
							className="form-check-input"
							type="radio"
							name={`ingress-mode-${agentId}`}
							checked={mode === m}
							onChange={() => onModeChange(m)}
						/>
						<label className="form-check-label small" htmlFor={`ingress-mode-${agentId}-${m}`}>
							{ti(`mode.${m}`)}
						</label>
					</div>
				))}
			</fieldset>

			{mode === "open" && rules.some((r) => r.enabled) && (
				<Alert variant="info" className="py-2 px-3 small" data-testid="ingress-open-hint">
					{ti("open-hint")}
				</Alert>
			)}

			<AppliedState applied={ingress.data.applied} mode={mode} />

			<div className="d-flex flex-wrap align-items-center gap-2 mb-2">
				<div className="fw-medium small text-uppercase text-secondary me-auto">{ti("rules")}</div>
				{!formOpen && !wizardOpen && (
					<>
						{wizardsAvailable ? (
							// Guided first: the wizards let you choose instead of type; the
							// free form is the expert path at the end of the menu.
							<div className="dropdown">
								<button
									ref={addRef}
									type="button"
									className="btn btn-sm btn-primary dropdown-toggle"
									data-bs-toggle="dropdown"
									data-bs-popper-config={POPPER_FIXED}
									aria-expanded="false"
									aria-haspopup="menu"
								>
									<IconPlus size={14} className="me-1" aria-hidden />
									{ti("add")}
								</button>
								<div className="dropdown-menu" role="menu">
									<h6 className="dropdown-header">{ti("add.guided")}</h6>
									{WIZARDS.map((w) => (
										<button
											key={w}
											type="button"
											role="menuitem"
											className="dropdown-item"
											onClick={() => open(`wizard:${w}`)}
										>
											{ti(`wizard.${w}.title`)}
										</button>
									))}
									<div className="dropdown-divider" />
									<button
										type="button"
										role="menuitem"
										className="dropdown-item"
										onClick={() => open("new")}
									>
										{ti("add.expert")}
									</button>
								</div>
							</div>
						) : (
							<button ref={addRef} type="button" className="btn btn-sm btn-primary" onClick={() => open("new")}>
								<IconPlus size={14} className="me-1" aria-hidden />
								{ti("add")}
							</button>
						)}
						<ComfortActions
							agentId={agentId}
							mode={mode}
							rules={rules}
							check={check}
							catalog={catalog}
							onError={setError}
							onInfo={setInfo}
						/>
					</>
				)}
				<fieldset className="btn-group btn-group-sm" aria-label={ti("view.label")}>
					{(["sentences", "table"] as const).map((v) => (
						<button
							key={v}
							type="button"
							className={`btn ${view === v ? "btn-secondary" : "btn-outline-secondary"}`}
							aria-pressed={view === v}
							onClick={() => setView(v)}
						>
							{ti(`view.${v}`)}
						</button>
					))}
				</fieldset>
			</div>

			{catalogQuery.isError && (
				<div className="small text-secondary mb-2" data-testid="ingress-catalog-unavailable">
					{ti("catalog.unavailable")}
				</div>
			)}

			<Alert variant="success" show={!!info} onClose={() => setInfo(null)} dismissible className="py-2 px-3 small">
				{info}
			</Alert>

			{formOpen && (
				<AgentIngressRuleForm
					key={editingRule ? editingRule.id : "new"}
					agentId={agentId}
					rule={editingRule}
					catalog={catalog}
					onDone={(created) =>
						closeEditor(created ? ti("result.created-one", { name: created.name }) : undefined, created?.id)
					}
				/>
			)}

			{catalog && editing === "wizard:proxy" && (
				<PublishProxyWizard agentId={agentId} catalog={catalog} onDone={closeEditor} />
			)}
			{catalog && editing === "wizard:site" && (
				<SiteAccessWizard agentId={agentId} catalog={catalog} onDone={closeEditor} />
			)}
			{catalog && editing === "wizard:full" && (
				<SiteFullAccessWizard agentId={agentId} catalog={catalog} onDone={closeEditor} />
			)}

			{view === "sentences" ? (
				<AgentIngressRuleSentences
					agentId={agentId}
					rules={rules}
					catalog={catalog}
					onEdit={(rule) => setEditing(rule.id)}
					onError={setError}
					highlightId={highlight}
				/>
			) : (
				<AgentIngressRulesTable
					agentId={agentId}
					rules={rules}
					catalog={catalog}
					onEdit={(rule) => setEditing(rule.id)}
					onError={setError}
					highlightId={highlight}
				/>
			)}

			<IngressTester agentId={agentId} catalog={catalog} onFocusRule={focusRule} />

			<AgentIngressCheckList
				agentId={agentId}
				mode={mode}
				check={check}
				isLoading={checkQuery.isLoading}
				error={checkQuery.error}
				onError={setError}
			/>

			<AgentIngressRulesPreview agentId={agentId} />
		</div>
	);
}
