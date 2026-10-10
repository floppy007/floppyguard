import { IconLock } from "@tabler/icons-react";
import { useEffect } from "react";
import Alert from "react-bootstrap/Alert";
import { useSearchParams } from "react-router-dom";
import { type Agent, deleteAgentGuarded } from "src/api/backend";
import { HasPermission, LoadingPage } from "src/components";
import {
	AgentIngressDetail,
	buildIngressAgentEntries,
	type IngressAgentEntry,
	ingressAgentFromParam,
	ingressAgentSubName,
	ingressSiteName,
	isIngressAppliedProblem,
	isolatedSiteNamesFor,
	pickDefaultIngressAgent,
	SiteIsolationCard,
	ti,
} from "src/components/AgentIngress";
import { useAgentIngress, useAgentIngressCheck, useAgents, useSiteIsolation } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { showDeleteConfirmModal } from "src/modals";
import { ADMIN, VIEW } from "src/modules/Permissions";

const statusBadge: Record<Agent["status"], string> = {
	active: "bg-green-lt text-green",
	pending: "bg-yellow-lt text-yellow",
	error: "bg-red-lt text-red",
};

function ModeBadge({ mode }: { mode: IngressAgentEntry["mode"] }) {
	return mode === "restricted" ? (
		<span className="badge bg-green-lt text-green">{ti("badge.restricted")}</span>
	) : (
		<span className="badge bg-secondary-lt text-secondary">{ti("badge.open")}</span>
	);
}

/**
 * Lock badge: the hub separates this site from others ("Trennung zwischen
 * Standorten") — shown next to the ingress filter state, which is a different layer.
 */
function IsolatedBadge({ sites }: { sites: string[] }) {
	if (sites.length === 0) return null;
	const label = ti("list.isolated", { sites: sites.join(", ") });
	return (
		<span
			className="badge bg-red-lt text-red d-inline-flex align-items-center gap-1 text-truncate"
			style={{ maxWidth: "100%" }}
			title={label}
			data-testid="ingress-list-isolated"
		>
			<IconLock size={12} className="flex-shrink-0" aria-hidden />
			<span className="text-truncate" style={{ lineHeight: 1.4, paddingBottom: "1px" }}>
				{label}
			</span>
		</span>
	);
}

/** Agent status in the user's language ("pending" → "Wartet auf Verbindung"). */
const agentStatusLabel = (status: Agent["status"]) => ti(`agent-status.${status}`);

/** Short badge when a restricted agent's ruleset is not confirmed as running (failed / offline / unknown). */
function AppliedBadge({ entry }: { entry: IngressAgentEntry }) {
	if (!isIngressAppliedProblem(entry)) return null;
	return (
		<span className="badge bg-red-lt text-red" data-testid="ingress-list-applied">
			{ti(`applied.${entry.applied}-short`)}
		</span>
	);
}

/**
 * Rare, destructive: revoke this site's agent. Lives at the end of the Technik
 * tab — the only place for an orphaned agent whose WireGuard link is gone (the
 * WireGuard page offers delete only per existing link).
 */
function AgentDangerZone({ agent, linkMissing }: { agent: Agent; linkMissing: boolean }) {
	const titleId = `ingress-${agent.id}-danger`;
	return (
		<section
			className="border border-danger-subtle rounded p-3"
			aria-labelledby={titleId}
			data-testid="ingress-danger-zone"
		>
			<h3 className="h4 mb-1 text-danger" id={titleId}>
				{ti("danger.title")}
			</h3>
			<p className="text-secondary small mb-3">{ti("danger.text")}</p>
			{linkMissing && (
				<p className="small mb-3" data-testid="ingress-danger-orphan">
					{ti("danger.orphan")}
				</p>
			)}
			<button
				type="button"
				className="btn btn-sm btn-outline-danger"
				data-testid={`ingress-agent-delete-${agent.id}`}
				onClick={() =>
					showDeleteConfirmModal({
						title: intl.formatMessage({ id: "wireguard.agent.delete-title" }),
						onConfirm: async () => {
							// Gateway gone for good: second confirmation, then forced delete.
							await deleteAgentGuarded(agent, () =>
								window.confirm(
									intl.formatMessage({ id: "wireguard.agent.delete-force-confirm" }, { name: agent.name }),
								),
							);
						},
						invalidations: [["agents"], ["agent-ingress-check"]],
						children: intl.formatMessage({ id: "wireguard.agent.delete-confirm" }, { name: agent.name }),
					})
				}
			>
				{intl.formatMessage({ id: "wireguard.agent.delete" })}
			</button>
		</section>
	);
}

/** Red dot + count: proxy targets a restricted agent drops. */
function WarningDot({ count }: { count: number }) {
	if (count <= 0) return null;
	const label = ti("list.warnings", { count });
	return (
		<span className="d-inline-flex align-items-center gap-1 text-red small" title={label} data-testid="ingress-list-warning">
			<span className="status-dot status-dot-animated status-red" aria-hidden />
			<span aria-hidden>{count}</span>
			<span className="visually-hidden">{label}</span>
		</span>
	);
}

function AgentListItem({
	entry,
	selected,
	isolatedFrom,
	onSelect,
}: {
	entry: IngressAgentEntry;
	selected: boolean;
	/** sites the hub separates this one from */
	isolatedFrom: string[];
	onSelect: (id: number) => void;
}) {
	const ingress = useAgentIngress(entry.agent.id);
	const active = ingress.data ? ingress.data.rules.filter((r) => r.enabled).length : null;
	const subName = ingressAgentSubName(entry.agent);
	return (
		<button
			type="button"
			className={`list-group-item list-group-item-action py-2 px-3${selected ? " active" : ""}`}
			aria-current={selected ? "true" : undefined}
			onClick={() => onSelect(entry.agent.id)}
			data-testid={`ingress-agent-${entry.agent.id}`}
		>
			<div className="d-flex align-items-center gap-2">
				<span className="fw-medium text-truncate me-auto" data-testid="ingress-list-site">
					{ingressSiteName(entry.agent)}
				</span>
				<WarningDot count={entry.warnings} />
			</div>
			{subName && (
				<div className="small text-secondary text-truncate" data-testid="ingress-list-agent">
					{subName}
				</div>
			)}
			<div className="d-flex align-items-center flex-wrap gap-2 mt-1 small">
				<ModeBadge mode={entry.mode} />
				<AppliedBadge entry={entry} />
				{active !== null && <span className="text-secondary">{ti("summary.rules", { count: active })}</span>}
			</div>
			{isolatedFrom.length > 0 && (
				<div className="d-flex mt-1 small" style={{ minWidth: 0 }}>
					<IsolatedBadge sites={isolatedFrom} />
				</div>
			)}
		</button>
	);
}

/** Page content without the permission wrapper (rendered directly in tests). */
export function IngressPageContent() {
	const agents = useAgents();
	const check = useAgentIngressCheck();
	// optional (older backend: no endpoint) — only adds the "getrennt von" hints
	const isolation = useSiteIsolation();
	const [params, setParams] = useSearchParams();

	const entries = buildIngressAgentEntries(agents.data ?? [], check.data);
	const fromUrl = ingressAgentFromParam(entries, params.get("agent"));
	// The default depends on mode, missing targets and applied state — all of
	// which the user's own actions change. Once resolved it is pinned in the URL,
	// so a refetch never swaps the site (and remounts the detail) under the user.
	const selectedId = fromUrl ?? pickDefaultIngressAgent(entries);
	const selected = entries.find((e) => e.agent.id === selectedId) ?? null;
	const restrictedCount = entries.filter((e) => e.mode === "restricted").length;
	const isolatedFrom = (e: IngressAgentEntry) => isolatedSiteNamesFor(isolation.data, null, e.agent.wgLinkName);

	const select = (id: number) => {
		const next = new URLSearchParams(params);
		next.set("agent", String(id));
		setParams(next, { replace: true });
	};

	const pinId = agents.isSuccess && fromUrl === null ? selectedId : null;
	// once pinned, fromUrl is set and pinId is null: re-runs (new setParams identity) are no-ops
	useEffect(() => {
		if (pinId === null) return;
		setParams(
			(prev) => {
				const next = new URLSearchParams(prev);
				next.set("agent", String(pinId));
				return next;
			},
			{ replace: true },
		);
	}, [pinId, setParams]);

	if (agents.isLoading) {
		return <LoadingPage />;
	}
	if (agents.isError) {
		return (
			<Alert variant="danger">{agents.error?.message || ti("error.unknown")}</Alert>
		);
	}

	const selectedCheck = selected ? check.data?.find((c) => c.agentId === selected.agent.id) : undefined;

	return (
		<div className="platform-page">
			{/* the sidebar links WireGuard; no extra header action competes with "Neue Freigabe" */}
			<div className="platform-page-header">
				<div>
					<h1 className="platform-title">{ti("page.title")}</h1>
					<p className="platform-subtitle">{ti("page.lead")}</p>
				</div>
			</div>

			{check.error && <Alert variant="warning">{check.error.message}</Alert>}

			{/* hub-wide, above the per-site view: which sites may reach each other at all */}
			<SiteIsolationCard />

			{entries.length === 0 ? (
				<div className="text-secondary">{ti("page.no-agents")}</div>
			) : (
				<div className="d-flex flex-column flex-lg-row align-items-lg-start gap-3 gap-lg-4">
					{/* master: list on wide screens, a select above the detail on narrow ones */}
					<div className="d-lg-none">
						<label className="form-label" htmlFor="ingress-agent-select">
							{ti("page.select")}
						</label>
						<select
							id="ingress-agent-select"
							className="form-select"
							value={selectedId ?? ""}
							onChange={(e) => select(Number(e.target.value))}
							data-testid="ingress-agent-select"
						>
							{entries.map((e) => (
								<option key={e.agent.id} value={e.agent.id}>
									{[
										ingressSiteName(e.agent),
										ingressAgentSubName(e.agent) ? `(${ingressAgentSubName(e.agent)})` : null,
										ti(e.mode === "restricted" ? "badge.restricted" : "badge.open"),
										isIngressAppliedProblem(e) ? ti(`applied.${e.applied}-short`) : null,
										e.warnings > 0 ? ti("list.warnings", { count: e.warnings }) : null,
										isolatedFrom(e).length > 0
											? ti("list.isolated", { sites: isolatedFrom(e).join(", ") })
											: null,
									]
										.filter(Boolean)
										.join(" · ")}
								</option>
							))}
						</select>
					</div>
					<nav
						className="d-none d-lg-block flex-shrink-0"
						style={{ width: 280 }}
						aria-labelledby="ingress-sites-title"
					>
						<div className="d-flex align-items-baseline justify-content-between gap-2 mb-2">
							<h2 className="h4 mb-0" id="ingress-sites-title">
								{ti("page.sites")}
							</h2>
							<span className="small text-secondary" data-testid="ingress-sites-summary">
								{ti("page.sites-summary", {
									restricted: restrictedCount,
									open: entries.length - restrictedCount,
								})}
							</span>
						</div>
						<div className="list-group" data-testid="ingress-agent-list">
							{entries.map((e) => (
								<AgentListItem
									key={e.agent.id}
									entry={e}
									selected={e.agent.id === selectedId}
									isolatedFrom={isolatedFrom(e)}
									onSelect={select}
								/>
							))}
						</div>
					</nav>
					<div className="flex-fill" style={{ minWidth: 0 }}>
						{selected && (
							<AgentIngressDetail
								key={selected.agent.id}
								agentId={selected.agent.id}
								linkName={selected.agent.wgLinkName}
								dangerZone={
									<AgentDangerZone agent={selected.agent} linkMissing={selectedCheck?.linkFound === false} />
								}
								heading={
									<div className="w-100" style={{ minWidth: 0 }}>
										<div className="d-flex flex-wrap align-items-center gap-2">
											<h2 className="h3 mb-0 text-break">{ingressSiteName(selected.agent)}</h2>
											{selected.agent.status !== "active" && (
												<span className={`badge ${statusBadge[selected.agent.status] ?? "bg-secondary-lt"}`}>
													{agentStatusLabel(selected.agent.status)}
												</span>
											)}
										</div>
										{ingressAgentSubName(selected.agent) && (
											<div className="small text-secondary text-break" data-testid="ingress-detail-agent">
												{ingressAgentSubName(selected.agent)}
											</div>
										)}
									</div>
								}
							/>
						)}
					</div>
				</div>
			)}
		</div>
	);
}

const Ingress = () => (
	<HasPermission section={ADMIN} permission={VIEW} pageLoading loadingNoLogo>
		<IngressPageContent />
	</HasPermission>
);

export default Ingress;
