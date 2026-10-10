import { IconAlertTriangle, IconLockOpen, IconShieldLock } from "@tabler/icons-react";
import type { ReactNode } from "react";
import Alert from "react-bootstrap/Alert";
import { Link } from "react-router-dom";
import { type Agent, type AgentIngressCheck, deleteAgentGuarded } from "src/api/backend";
import { HasPermission, LoadingPage } from "src/components";
import { AgentIngressPanel, ingressWarningCount, ti } from "src/components/AgentIngress";
import { useAgentIngressCheck, useAgents } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { showDeleteConfirmModal } from "src/modals";
import { ADMIN, VIEW } from "src/modules/Permissions";

const statusBadge: Record<Agent["status"], string> = {
	active: "bg-green-lt text-green",
	pending: "bg-yellow-lt text-yellow",
	error: "bg-red-lt text-red",
};

function StatCard({ icon, color, label, value }: { icon: ReactNode; color: string; label: string; value: number }) {
	return (
		<div className="col-sm-6 col-xl-4">
			<div className="card card-sm h-100 platform-stat-card">
				<div className="card-body d-flex align-items-center gap-3">
					<span className={`bg-${color} text-white avatar`}>{icon}</span>
					<div>
						<div className="text-secondary">{label}</div>
						<div className="platform-stat-value">{value}</div>
					</div>
				</div>
			</div>
		</div>
	);
}

function AgentCard({ agent, check }: { agent: Agent; check: AgentIngressCheck | undefined }) {
	const mode = check?.ingressMode ?? agent.ingressMode ?? "open";
	const restricted = mode === "restricted";
	const missing = ingressWarningCount(check);

	return (
		<div className="card platform-elevated-card" data-testid={`ingress-agent-${agent.id}`}>
			<div className="card-header d-flex align-items-center gap-2 flex-wrap">
				<h3 className="card-title m-0">{agent.name}</h3>
				<span className={`badge ${statusBadge[agent.status] ?? "bg-secondary-lt"}`}>{agent.status}</span>
				<span className={`badge ${restricted ? "bg-green-lt text-green" : "bg-secondary-lt"}`}>
					{ti(`mode.${mode}-short`)}
				</span>
				{missing > 0 && (
					<span className={`badge ${restricted ? "bg-red-lt text-red" : "bg-yellow-lt text-yellow"}`}>
						{ti("summary.warnings", { count: missing })}
					</span>
				)}
				{check?.applied && check.applied.state !== "applied" && (
					<span
						className={`badge ${check.applied.state === "failed" || restricted ? "bg-red-lt text-red" : "bg-yellow-lt text-yellow"}`}
					>
						{ti(`applied.${check.applied.state}-short`)}
					</span>
				)}
				{agent.wgLinkName && agent.wgLinkName !== agent.name && (
					<span className="small text-secondary ms-auto">{agent.wgLinkName}</span>
				)}
				{/* Revoke an agent whose site is gone (its link may already be deleted) */}
				<button
					type="button"
					className={`btn btn-sm btn-outline-danger py-0 px-2${agent.wgLinkName && agent.wgLinkName !== agent.name ? "" : " ms-auto"}`}
					data-testid={`ingress-agent-delete-${agent.id}`}
					onClick={() =>
						showDeleteConfirmModal({
							title: intl.formatMessage({ id: "wireguard.agent.delete-title" }),
							onConfirm: async () => {
								// Gateway gone for good: second confirmation, then forced delete.
								await deleteAgentGuarded(agent, () =>
									window.confirm(
										intl.formatMessage(
											{ id: "wireguard.agent.delete-force-confirm" },
											{ name: agent.name },
										),
									),
								);
							},
							invalidations: [["agents"], ["agent-ingress-check"]],
							children: intl.formatMessage(
								{ id: "wireguard.agent.delete-confirm" },
								{ name: agent.name },
							),
						})
					}
				>
					{intl.formatMessage({ id: "wireguard.agent.delete" })}
				</button>
			</div>
			<div className="card-body">
				<AgentIngressPanel agentId={agent.id} />
			</div>
		</div>
	);
}

/** Page content without the permission wrapper (rendered directly in tests). */
export function IngressPageContent() {
	const agents = useAgents();
	const check = useAgentIngressCheck();

	if (agents.isLoading) {
		return <LoadingPage />;
	}
	if (agents.isError) {
		return <Alert variant="danger">{agents.error?.message || "Unknown error"}</Alert>;
	}

	const list = [...(agents.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));
	const checkFor = (id: number) => check.data?.find((c) => c.agentId === id);
	const modeOf = (a: Agent) => checkFor(a.id)?.ingressMode ?? a.ingressMode ?? "open";
	const restrictedCount = list.filter((a) => modeOf(a) === "restricted").length;
	// Missing upstreams only break traffic on restricted agents
	const warningCount = list
		.filter((a) => modeOf(a) === "restricted")
		.reduce((sum, a) => sum + ingressWarningCount(checkFor(a.id)), 0);

	return (
		<div className="platform-page">
			<div className="platform-page-header">
				<div>
					<div className="platform-kicker">{intl.formatMessage({ id: "wireguard.page.kicker" })}</div>
					<h1 className="platform-title">{ti("title")}</h1>
					<p className="platform-subtitle">{ti("explain")}</p>
				</div>
				<div className="d-flex align-items-center gap-2">
					<Link to="/wireguard" className="btn btn-sm btn-outline-secondary">
						WireGuard
					</Link>
				</div>
			</div>

			<div className="row row-cards mb-4">
				<StatCard
					icon={<IconShieldLock />}
					color="green"
					label={ti("page.stat.restricted")}
					value={restrictedCount}
				/>
				<StatCard
					icon={<IconLockOpen />}
					color="secondary"
					label={ti("page.stat.open")}
					value={list.length - restrictedCount}
				/>
				<StatCard
					icon={<IconAlertTriangle />}
					color={warningCount > 0 ? "red" : "secondary"}
					label={ti("page.stat.warnings")}
					value={warningCount}
				/>
			</div>

			{check.error && <Alert variant="warning">{check.error.message}</Alert>}

			{list.length === 0 ? (
				<div className="text-secondary">{ti("page.no-agents")}</div>
			) : (
				<div className="d-flex flex-column gap-3">
					{list.map((agent) => (
						<AgentCard key={agent.id} agent={agent} check={checkFor(agent.id)} />
					))}
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
