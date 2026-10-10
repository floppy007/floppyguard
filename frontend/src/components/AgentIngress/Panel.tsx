import { IconLock, IconLockOpen, IconPlus, IconShieldCheck, IconShieldLock, IconShieldX } from "@tabler/icons-react";
import { type KeyboardEvent, type ReactNode, type Ref, useEffect, useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Link } from "react-router-dom";
import type {
	AgentIngressApplied,
	AgentIngressCatalog,
	AgentIngressMode,
	AgentIngressRule,
} from "src/api/backend";
import {
	useAgentIngress,
	useAgentIngressCatalog,
	useAgentIngressCheck,
	useSetAgentIngressMode,
	useSiteIsolation,
} from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { POPPER_FIXED } from "src/modules/Dropdown";
import { AgentIngressCheckList } from "./CheckList";
import { MissingProxyAction, PruneAction } from "./ComfortActions";
import { IngressTester } from "./IngressTester";
import { AgentIngressRuleForm } from "./RuleForm";
import { AgentIngressRuleSentences } from "./RuleSentences";
import { ingressRuleDomId } from "./RulesTable";
import { isolatedSiteNamesFor, SITE_ISOLATION_ANCHOR } from "./SiteIsolation";
import { AgentIngressTechTab } from "./TechTab";
import { errMessage, ingressWarningCount, ti } from "./utils";
import { PublishProxyWizard, SiteAccessWizard, SiteFullAccessWizard } from "./wizards";

type Editing = "new" | number | "wizard:proxy" | "wizard:site" | "wizard:full" | null;
export type IngressTab = "rules" | "check" | "tech";

const TABS: IngressTab[] = ["rules", "check", "tech"];
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
		<Alert variant={variant} className="d-block py-2 px-3 small mb-0" data-testid="ingress-applied-state">
			{ti(`applied.${applied.state}`)}
			{applied.error && <span className="font-monospace ms-1">({applied.error})</span>}
		</Alert>
	);
}

interface BannerProps {
	agentId: number;
	mode: AgentIngressMode;
	activeRules: number;
	hasEnabledRules: boolean;
	networks: string[];
	/** proxy targets the filter drops (restricted only) */
	dropped: number;
	/** sites this one is cut off from at the hub ("Trennung zwischen Standorten"), independent of the mode */
	isolatedFrom: string[];
	pending: boolean;
	heading?: ReactNode;
	onModeChange: (mode: AgentIngressMode) => void;
	onShowCheck: () => void;
}

/**
 * Status card of the site's ingress filter (at the site's gateway): on or off,
 * what that means, and the one switch to change it. The hub-side separation
 * between sites is a separate layer; it is named here as its own line so an
 * "off" filter never reads as "everything gets in".
 */
function StatusBanner({
	agentId,
	mode,
	activeRules,
	hasEnabledRules,
	networks,
	dropped,
	isolatedFrom,
	pending,
	heading,
	onModeChange,
	onShowCheck,
}: BannerProps) {
	const restricted = mode === "restricted";
	// Filter on without a single active rule: everything from the tunnel is
	// dropped — the most dangerous state must not look like the safe one.
	const blocked = restricted && activeRules === 0;
	const titleId = `ingress-${agentId}-status`;
	const tone = blocked ? "red" : restricted ? "green" : "secondary";
	return (
		<section
			className="card"
			aria-labelledby={titleId}
			data-testid="ingress-banner"
			data-mode={mode}
			data-blocked={blocked ? "true" : undefined}
		>
			<div className={`card-status-start bg-${tone}`} />
			{heading && <div className="card-header">{heading}</div>}
			<div className="card-body d-flex flex-column flex-sm-row align-items-sm-start gap-3">
				<div className="d-flex align-items-start gap-3 flex-fill" style={{ minWidth: 0 }}>
				<span className={`avatar flex-shrink-0 bg-${tone}-lt text-${tone}`} aria-hidden>
					{blocked ? <IconShieldX /> : restricted ? <IconShieldCheck /> : <IconLockOpen />}
				</span>
				<div className="flex-fill" style={{ minWidth: 0 }}>
					<div className="fw-bold" id={titleId}>
						{ti(restricted ? "banner.title-on" : "banner.title-off")}
					</div>
					<div className="small text-secondary mb-1" data-testid="ingress-banner-explain">
						{ti("banner.explain")}
					</div>
					{blocked ? (
						<div className="text-danger fw-medium" data-testid="ingress-banner-blocked">
							{ti("banner.restricted-none")}
						</div>
					) : (
						<div className="text-secondary" data-testid="ingress-banner-text">
							{restricted
								? ti("banner.restricted", { count: activeRules })
								: isolatedFrom.length > 0
									? ti("banner.open-except", { sites: isolatedFrom.join(", ") })
									: ti("banner.open")}
						</div>
					)}
					{!restricted && hasEnabledRules && (
						<div className="small text-secondary mt-1" data-testid="ingress-open-hint">
							{ti("open-hint")}
						</div>
					)}
					{networks.length > 0 && (
						<div className="d-flex flex-wrap align-items-center gap-1 mt-2 small">
							<span className="text-secondary me-1">{ti("banner.networks")}</span>
							{networks.map((n) => (
								<span key={n} className="badge bg-secondary-lt text-secondary fw-normal font-monospace">
									{n}
								</span>
							))}
						</div>
					)}
					{isolatedFrom.length > 0 && (
						<div
							className="small mt-2 text-red d-flex align-items-start gap-1"
							data-testid="ingress-banner-isolated"
						>
							<IconLock size={14} className="flex-shrink-0 mt-1" aria-hidden />
							<span>
								{ti("banner.isolated-from", { sites: isolatedFrom.join(", ") })}{" "}
								<Link
									to={`/ingress#${SITE_ISOLATION_ANCHOR}`}
									className="text-secondary"
									data-testid="ingress-banner-isolated-link"
								>
									{ti("banner.isolated-hint")}
								</Link>
							</span>
						</div>
					)}
					{restricted && dropped > 0 && (
						<div className="small mt-2 text-danger" data-testid="ingress-banner-dropped">
							{ti("list.warnings", { count: dropped })}.{" "}
							<button
								type="button"
								className="btn btn-link p-0 border-0 align-baseline"
								style={{ minHeight: 0, fontSize: "inherit", lineHeight: "inherit" }}
								onClick={onShowCheck}
							>
								{ti("banner.to-check")}
							</button>
						</div>
					)}
				</div>
				</div>
				<button
					type="button"
					className={`btn btn-sm flex-shrink-0 align-self-start ${restricted ? "btn-outline-secondary" : "btn-outline-primary"}`}
					disabled={pending}
					onClick={() => onModeChange(restricted ? "open" : "restricted")}
					data-testid="ingress-mode-toggle"
				>
					{restricted ? (
						<IconLockOpen size={16} className="me-1" aria-hidden />
					) : (
						<IconShieldLock size={16} className="me-1" aria-hidden />
					)}
					{restricted ? ti("banner.turn-off") : ti("banner.turn-on")}
				</button>
			</div>
		</section>
	);
}

/** The one primary action: "Neue Freigabe" — the 3 wizards plus the free form (or the form alone without catalog). */
function NewRuleButton({
	wizards,
	onOpen,
	buttonRef,
}: {
	wizards: boolean;
	onOpen: (next: Editing) => void;
	buttonRef: Ref<HTMLButtonElement>;
}) {
	if (!wizards) {
		return (
			<button ref={buttonRef} type="button" className="btn btn-primary" onClick={() => onOpen("new")}>
				<IconPlus size={16} className="me-1" aria-hidden />
				{ti("new")}
			</button>
		);
	}
	return (
		// Guided first: the wizards let you choose instead of type; the free form
		// is the expert path at the end of the menu.
		<div className="dropdown">
			<button
				ref={buttonRef}
				type="button"
				className="btn btn-primary dropdown-toggle"
				data-bs-toggle="dropdown"
				data-bs-popper-config={POPPER_FIXED}
				aria-expanded="false"
				aria-haspopup="menu"
			>
				<IconPlus size={16} className="me-1" aria-hidden />
				{ti("new")}
			</button>
			<div className="dropdown-menu dropdown-menu-end" role="menu">
				<h6 className="dropdown-header">{ti("add.guided")}</h6>
				{WIZARDS.map((w) => (
					<button
						key={w}
						type="button"
						role="menuitem"
						className="dropdown-item"
						onClick={() => onOpen(`wizard:${w}`)}
					>
						{ti(`wizard.${w}.title`)}
					</button>
				))}
				<div className="dropdown-divider" />
				<button type="button" role="menuitem" className="dropdown-item" onClick={() => onOpen("new")}>
					{ti("add.expert")}
				</button>
			</div>
		</div>
	);
}

interface Props {
	agentId: number;
	/** card header of the status banner (agent name on the page; the dialog title has it already) */
	heading?: ReactNode;
	/** rare destructive actions (remove the agent), shown at the end of the Technik tab */
	dangerZone?: ReactNode;
	/** the agent's WireGuard link name: finds the site in the hub separation when the catalog has no link id */
	linkName?: string | null;
}

/**
 * "Freigaben" of one agent: status banner with the filter switch, then tabs
 * Freigaben (rules by source, wizards, form) | Prüfen (tester, proxy check) |
 * Technik (raw table, generated rules). Used by the Freigaben page and the
 * agent dialog.
 */
export function AgentIngressDetail({ agentId, heading, dangerZone, linkName }: Props) {
	const ingress = useAgentIngress(agentId);
	const checkQuery = useAgentIngressCheck();
	const catalogQuery = useAgentIngressCatalog(agentId);
	const setMode = useSetAgentIngressMode(agentId);
	// optional: an older backend without the endpoint simply shows no isolation line
	const isolation = useSiteIsolation();
	const [tab, setTabState] = useState<IngressTab>("rules");
	// tabs once opened stay mounted (hidden): the tester keeps its input and result
	const [visited, setVisited] = useState<Set<IngressTab>>(() => new Set<IngressTab>(["rules"]));
	// Only the id: the form must always see the current rule from the query, not
	// a snapshot from when "edit" was clicked.
	const [editing, setEditing] = useState<Editing>(null);
	const [error, setError] = useState<string | null>(null);
	const [info, setInfo] = useState<string | null>(null);
	const [highlight, setHighlight] = useState<number | null>(null);
	const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
	// "Neue Freigabe" (unmounted while a form/wizard is open): focus goes back
	// there when the form/wizard closes, or to the edited rule's menu button.
	const addRef = useRef<HTMLButtonElement>(null);
	const prevEditing = useRef<Editing>(null);
	const focusAfterClose = useRef<number | null>(null);
	const tabRefs = useRef<Partial<Record<IngressTab, HTMLButtonElement | null>>>({});

	useEffect(
		() => () => {
			for (const t of timers.current) clearTimeout(t);
		},
		[],
	);

	useEffect(() => {
		const prev = prevEditing.current;
		prevEditing.current = editing;
		if (prev === null || editing !== null) return;
		const target = focusAfterClose.current ?? (typeof prev === "number" ? prev : null);
		focusAfterClose.current = null;
		const menuButton =
			target !== null
				? document
						.getElementById(ingressRuleDomId(agentId, target))
						?.querySelector<HTMLButtonElement>("button[data-ingress-edit]")
				: null;
		(menuButton ?? addRef.current)?.focus();
	}, [editing, agentId]);

	const later = (fn: () => void, ms: number) => {
		timers.current.push(setTimeout(fn, ms));
	};

	if (ingress.isLoading) {
		return <div className="text-secondary small">{intl.formatMessage({ id: "loading" })}</div>;
	}
	if (ingress.error || !ingress.data) {
		return <div className="text-danger small">{ingress.error?.message}</div>;
	}

	const mode: AgentIngressMode = ingress.data.ingressMode ?? "open";
	const restricted = mode === "restricted";
	const rules = ingress.data.rules ?? [];
	const activeRules = rules.filter((r) => r.enabled).length;
	const check = checkQuery.data?.find((c) => c.agentId === agentId);
	const dropped = restricted ? ingressWarningCount(check) : 0;
	const editingRule: AgentIngressRule | null =
		typeof editing === "number" ? (rules.find((r) => r.id === editing) ?? null) : null;
	// A rule deleted meanwhile simply closes its form
	const formOpen = editing === "new" || editingRule !== null;
	const wizardOpen = typeof editing === "string" && editing.startsWith("wizard:");
	// The catalog is optional: a failing / missing endpoint (old backend) keeps the plain form
	const catalog: AgentIngressCatalog | null = catalogQuery.data ?? null;
	const wizardsAvailable = !!catalog && catalog.linkFound !== false;

	const setTab = (next: IngressTab) => {
		setTabState(next);
		setVisited((prev) => (prev.has(next) ? prev : new Set(prev).add(next)));
	};

	const focusRule = (ruleId: number) => {
		setTab("rules");
		setHighlight(ruleId);
		// after the Freigaben tab rendered (and opened the rule's section)
		later(() => {
			document.getElementById(ingressRuleDomId(agentId, ruleId))?.scrollIntoView?.({
				behavior: "smooth",
				block: "center",
			});
		}, 50);
		later(() => setHighlight((h) => (h === ruleId ? null : h)), 2000);
	};

	/** Close form/wizard; `ruleId` = the rule it created (highlighted, gets the focus). */
	const closeEditor = (msg?: string, ruleId?: number | null) => {
		if (typeof ruleId === "number") focusAfterClose.current = ruleId;
		setEditing(null);
		if (msg) setInfo(msg);
		if (typeof ruleId === "number") focusRule(ruleId);
	};

	const open = (next: Editing) => {
		setInfo(null);
		setEditing(next);
		setTab("rules");
	};

	const onModeChange = (next: AgentIngressMode) => {
		if (next === mode || setMode.isPending) return;
		// Restricted drops everything without a matching rule — can cut a site off;
		// open lets everything in again.
		if (!window.confirm(ti(next === "restricted" ? "confirm-restricted" : "confirm-open"))) return;
		setError(null);
		setMode.mutate(next, { onError: (err) => setError(errMessage(err)) });
	};

	const onTabKey = (e: KeyboardEvent, current: IngressTab) => {
		const i = TABS.indexOf(current);
		let next: IngressTab | null = null;
		if (e.key === "ArrowRight") next = TABS[(i + 1) % TABS.length];
		else if (e.key === "ArrowLeft") next = TABS[(i + TABS.length - 1) % TABS.length];
		else if (e.key === "Home") next = TABS[0];
		else if (e.key === "End") next = TABS[TABS.length - 1];
		if (!next) return;
		e.preventDefault();
		setTab(next);
		tabRefs.current[next]?.focus();
	};

	const tabId = (t: IngressTab) => `ingress-${agentId}-tab-${t}`;
	const panelId = (t: IngressTab) => `ingress-${agentId}-panel-${t}`;
	const tabLabel = (t: IngressTab): ReactNode => {
		if (t === "rules") return ti("tab.rules", { count: rules.length });
		if (t === "check")
			return (
				<>
					{ti("tab.check")}
					{dropped > 0 && (
						<span className="badge bg-red text-red-fg ms-2" data-testid="ingress-tab-check-badge">
							{dropped}
						</span>
					)}
				</>
			);
		return ti("tab.tech");
	};

	const showNewButton = !formOpen && !wizardOpen;
	const newButton = <NewRuleButton wizards={wizardsAvailable} onOpen={open} buttonRef={addRef} />;

	const rulesTab = (
		<div className="d-flex flex-column gap-3">
			{rules.length > 0 && showNewButton && (
				<div className="d-flex flex-wrap align-items-center gap-2">
					<span className="text-secondary me-auto">
						{ti("sentence.active-count", { active: activeRules, count: rules.length })}
					</span>
					<PruneAction
						agentId={agentId}
						mode={mode}
						rules={rules}
						catalog={catalog}
						onError={setError}
						onInfo={setInfo}
					/>
					{newButton}
				</div>
			)}

			{catalogQuery.isError && (
				<div className="small text-secondary" data-testid="ingress-catalog-unavailable">
					{ti("catalog.unavailable")}
				</div>
			)}

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

			{rules.length === 0 ? (
				showNewButton && (
					<div className="text-center py-4 px-2" data-testid="ingress-empty">
						<span className="avatar avatar-lg bg-primary-lt text-primary mb-3" aria-hidden>
							<IconShieldLock />
						</span>
						<h3 className="h4 mb-2">{ti("empty.title")}</h3>
						<p className="text-secondary mx-auto mb-3" style={{ maxWidth: "36rem" }}>
							{ti(restricted ? "empty.text-restricted" : "empty.text")}
						</p>
						<div className="d-inline-flex">{newButton}</div>
					</div>
				)
			) : (
				<AgentIngressRuleSentences
					agentId={agentId}
					rules={rules}
					catalog={catalog}
					onEdit={(rule) => open(rule.id)}
					onError={setError}
					highlightId={highlight}
				/>
			)}
		</div>
	);

	const checkTab = (
		// The tester ("does X reach Y?") comes first; the reverse-proxy comparison
		// (where banner and tab badge point, with its one-click fix) below it.
		<div className="d-flex flex-column gap-4">
			<IngressTester agentId={agentId} catalog={catalog} onFocusRule={focusRule} />
			<hr className="my-0" />
			<AgentIngressCheckList
				agentId={agentId}
				mode={mode}
				check={check}
				isLoading={checkQuery.isLoading}
				error={checkQuery.error}
				onError={setError}
				actions={
					<MissingProxyAction
						agentId={agentId}
						mode={mode}
						check={check}
						onError={setError}
						onInfo={setInfo}
					/>
				}
			/>
		</div>
	);

	const panels: Record<IngressTab, () => ReactNode> = {
		rules: () => rulesTab,
		check: () => checkTab,
		tech: () => (
			<AgentIngressTechTab
				agentId={agentId}
				mode={mode}
				rules={rules}
				applied={ingress.data?.applied}
				check={check}
				catalog={catalog}
				onEdit={(rule) => open(rule.id)}
				onError={setError}
				dangerZone={dangerZone}
			/>
		),
	};

	return (
		<div className="d-flex flex-column gap-3" data-testid={`ingress-detail-${agentId}`}>
			<StatusBanner
				agentId={agentId}
				mode={mode}
				activeRules={activeRules}
				hasEnabledRules={activeRules > 0}
				networks={catalog?.site?.networks ?? []}
				dropped={dropped}
				isolatedFrom={isolatedSiteNamesFor(isolation.data, catalog?.site?.linkId, linkName)}
				pending={setMode.isPending}
				heading={heading}
				onModeChange={onModeChange}
				onShowCheck={() => setTab("check")}
			/>

			<AppliedState applied={ingress.data.applied} mode={mode} />

			<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible className="mb-0">
				{error}
			</Alert>
			<Alert variant="success" show={!!info} onClose={() => setInfo(null)} dismissible className="py-2 px-3 mb-0">
				{info}
			</Alert>

			<div className="card">
				<div className="card-header ingress-tabs-header">
					<div
						className="nav nav-tabs card-header-tabs flex-nowrap ingress-tablist"
						role="tablist"
						aria-label={ti("tabs.label")}
					>
						{TABS.map((t) => (
							<button
								key={t}
								ref={(el) => {
									tabRefs.current[t] = el;
								}}
								type="button"
								role="tab"
								id={tabId(t)}
								className={`nav-link text-nowrap flex-shrink-0${tab === t ? " active" : ""}`}
								aria-selected={tab === t}
								aria-controls={panelId(t)}
								tabIndex={tab === t ? 0 : -1}
								onClick={() => setTab(t)}
								onKeyDown={(e) => onTabKey(e, t)}
							>
								{tabLabel(t)}
							</button>
						))}
					</div>
				</div>
				<div className="card-body">
					{TABS.filter((t) => visited.has(t) || t === tab).map((t) => (
						<div
							key={t}
							id={panelId(t)}
							role="tabpanel"
							aria-labelledby={tabId(t)}
							hidden={t !== tab}
							data-testid={`ingress-panel-${t}`}
						>
							{panels[t]()}
						</div>
					))}
				</div>
			</div>
		</div>
	);
}
