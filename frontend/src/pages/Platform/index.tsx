import {
	IconBolt,
	IconChecklist,
	IconPlugConnected,
	IconRoute,
	IconShield,
	IconShieldHalfFilled,
	IconStack2,
	IconTopologyStar3,
} from "@tabler/icons-react";
import { useNavigate } from "react-router-dom";
import { useHostReport, useWireGuardStatus, useFail2BanStatus, useUnbanIp } from "src/hooks";
import type { WireGuardLink } from "src/api/backend";
import { intl } from "src/locale/IntlProvider";

const KNOWN_NEXT_ACTIONS = new Set([
	"verify-return-path", "model-exported-networks", "define-remote-management-mode",
	"fix-return-path", "decide-nat-or-static-route", "define-return-path-mode",
	"verify-live-tunnel-state", "mount-wireguard-config-directory",
]);
const fmtNextAction = (a: string) =>
	KNOWN_NEXT_ACTIONS.has(a) ? intl.formatMessage({ id: `wireguard.next.${a}` }) : a;

const getPlanBadge = (link: WireGuardLink) => {
	switch (link.planState) {
		case "ready": return { labelId: "platform.plan.ready", className: "bg-green-lt text-green" };
		case "validate": return { labelId: "platform.plan.validate", className: "bg-yellow-lt text-yellow" };
		case "shape": return { labelId: "platform.plan.shaping", className: "bg-blue-lt text-blue" };
		case "discover": return { labelId: "platform.plan.discover", className: "bg-secondary-lt text-secondary" };
		default: return { labelId: "platform.plan.unplanned", className: "bg-secondary-lt text-secondary" };
	}
};


const getLinkTypeBadge = (link: WireGuardLink) => {
	switch (link.type) {
		case "client": return { labelId: "platform.link-type.client", className: "bg-green-lt text-green" };
		case "site-to-site": return { labelId: "platform.link-type.site", className: "bg-blue-lt text-blue" };
		case "hub-link": return { labelId: "platform.link-type.hub", className: "bg-cyan-lt text-cyan" };
		default: return { labelId: "platform.link-type.other", className: "bg-secondary-lt text-secondary" };
	}
};

const Platform = () => {
	const navigate = useNavigate();
	const { data: hostReport } = useHostReport();
	const { data: wireguard } = useWireGuardStatus();
	const { data: fail2ban, isLoading: f2bLoading } = useFail2BanStatus();
	const unban = useUnbanIp();
	const summary = wireguard?.summary;
	const hub = wireguard?.hub;
	const links = wireguard?.links?.slice(0, 4) || [];
	const nextActions = wireguard?.nextActions?.slice(0, 4) || [];
	const capabilities = wireguard?.capabilities;
	const missingReturnRoutes = wireguard?.routes.missingReturnRoutes || [];
	const natCandidates = wireguard?.routes.natCandidates || [];
	const observations = wireguard?.routes.observations || [];
	const readinessCounts = {
		ready: links.filter((link) => link.planState === "ready").length,
		validate: links.filter((link) => link.planState === "validate").length,
		shape: links.filter((link) => link.planState === "shape").length,
		discover: links.filter((link) => !link.planState || link.planState === "discover").length,
	};

	return (
		<div className="platform-page">
			<section className="platform-hero card">
				<div className="card-body p-4 p-md-5">
					<div className="row align-items-center g-4">
						<div className="col-lg-8">
							<div className="platform-kicker">{intl.formatMessage({ id: "platform.hero.kicker" })}</div>
							<h1 className="platform-title">FloppyGuard</h1>
							<p className="platform-subtitle mb-4 fs-4">
								{intl.formatMessage({ id: "platform.hero.subtitle" })}
							</p>
							<div className="platform-actions">
								<button className="btn btn-primary" type="button" onClick={() => navigate("/wireguard")}>
									{intl.formatMessage({ id: "platform.btn.open-wireguard" })}
								</button>
								<button className="btn btn-outline-primary" type="button" onClick={() => navigate("/gateway")}>
									{intl.formatMessage({ id: "platform.btn.open-gateway" })}
								</button>
								<button className="btn btn-outline-secondary" type="button" onClick={() => navigate("/nginx/proxy")}>
									{intl.formatMessage({ id: "platform.btn.open-proxy" })}
								</button>
							</div>
						</div>
						<div className="col-lg-4">
							<div className="platform-status-grid">
								<div className="platform-status-chip">
									<span className="badge bg-green-lt text-green">live</span>
									<div>Host WireGuard stays untouched</div>
								</div>
								<div className="platform-status-chip">
									<span className="badge bg-green-lt text-green">live</span>
									<div>Current live proxy stack stays untouched</div>
								</div>
								<div className="platform-status-chip">
									<span className={`badge ${capabilities?.supports.metadataCrud ? "bg-blue-lt text-blue" : "bg-secondary-lt text-secondary"}`}>
										{capabilities?.supports.metadataCrud ? "metadata-write" : "read-only"}
									</span>
									<div>Fork persists planning metadata but does not write live configs.</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</section>

			<section className="row row-cards">
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-green text-white avatar"><IconBolt /></span>
							<div>
								<div className="text-secondary">Proxy Hosts</div>
								<div className="platform-stat-value">{hostReport?.proxy || 0}</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-blue text-white avatar"><IconShieldHalfFilled /></span>
							<div>
								<div className="text-secondary">Interfaces</div>
								<div className="platform-stat-value">{summary?.activeInterfaceCount || 0} / {summary?.interfaceCount || 0}</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-yellow text-white avatar"><IconPlugConnected /></span>
							<div>
								<div className="text-secondary">Active Peers</div>
								<div className="platform-stat-value">{summary?.activePeers || 0} / {summary?.totalPeers || 0}</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-cyan text-white avatar"><IconTopologyStar3 /></span>
							<div>
								<div className="text-secondary">{intl.formatMessage({ id: "platform.stat.logical-links" })}</div>
								<div className="platform-stat-value">{summary?.linkCount || 0}</div>
							</div>
						</div>
					</div>
				</div>
			</section>

			<section className="row row-cards">
				<div className="col-lg-5">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title d-flex align-items-center gap-2"><IconStack2 size={18} /> {intl.formatMessage({ id: "platform.cap.title" })}</h3>
						</div>
						<div className="card-body d-flex flex-column gap-3">
							<div className="platform-module">
								<div className="fw-bold">Proxy Core</div>
								<div className="text-secondary small">Hosts, redirects, streams, certificates and users remain the operational base.</div>
							</div>
							<div className="platform-module">
								<div className="fw-bold">WireGuard Runtime</div>
								<div className="text-secondary small">Interfaces, peers, routes, links and topology are already modeled inside the fork.</div>
							</div>
							<div className="platform-module">
								<div className="fw-bold">Planning Layer</div>
								<div className="text-secondary small">
									{capabilities?.supports.wizardPlanning ? "Planner and metadata persistence are available." : "Planner support is not active yet."}
								</div>
							</div>
							<div className="platform-module">
								<div className="fw-bold">Write Layer</div>
								<div className="text-secondary small">
									{capabilities?.supports.peerCrud ? "Peer CRUD is available." : "Peer CRUD and host writes are still intentionally blocked."}
								</div>
							</div>
							<div className="platform-module">
								<div className="fw-bold">Remote Apply</div>
								<div className="text-secondary small">
									{capabilities?.supports.remoteSsh || capabilities?.supports.remoteAgent ? "Remote apply is partially available." : "SSH and agent-based apply are not enabled yet."}
								</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-lg-7">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title d-flex align-items-center gap-2"><IconChecklist size={18} /> {intl.formatMessage({ id: "platform.link-readiness.title" })}</h3>
						</div>
						<div className="card-body">
							<div className="d-flex gap-2 flex-wrap mb-3">
								<span className="badge bg-green-lt text-green">ready {readinessCounts.ready}</span>
								<span className="badge bg-yellow-lt text-yellow">validate {readinessCounts.validate}</span>
								<span className="badge bg-blue-lt text-blue">shape {readinessCounts.shape}</span>
								<span className="badge bg-secondary-lt text-secondary">discover {readinessCounts.discover}</span>
								<span className="badge bg-emerald-lt text-emerald">client {summary?.clientLinkCount || 0}</span>
								<span className="badge bg-indigo-lt text-indigo">site {summary?.siteLinkCount || 0}</span>
								<span className="badge bg-cyan-lt text-cyan">hub {summary?.hubLinkCount || 0}</span>
							</div>
							<div className="d-flex flex-column gap-2">
								{links.length ? links.map((link) => {
									const planBadge = getPlanBadge(link);
									const typeBadge = getLinkTypeBadge(link);
									return (
										<div key={link.id} className="platform-list-item">
											<div className="d-flex justify-content-between align-items-start gap-2 flex-wrap">
												<div className="fw-medium">{link.name}</div>
												<div className="d-flex gap-1 flex-wrap">
													<span className={`badge ${typeBadge.className}`}>{intl.formatMessage({ id: typeBadge.labelId })}</span>
													<span className={`badge ${planBadge.className}`}>{intl.formatMessage({ id: planBadge.labelId })}</span>
												</div>
											</div>
											<div className="text-secondary small">{link.interfaceName}{link.remoteEndpoint ? ` · ${link.remoteEndpoint}` : ""}</div>
										</div>
									);
								}) : <div className="text-secondary small">{intl.formatMessage({ id: "platform.no-links" })}</div>}
							</div>
						</div>
					</div>
				</div>
			</section>

			<section className="row row-cards">
				<div className="col-lg-6">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title d-flex align-items-center gap-2"><IconRoute size={18} /> {intl.formatMessage({ id: "platform.gateway-snapshot.title" })}</h3>
						</div>
						<div className="card-body d-flex flex-column gap-3">
							<div>
								<div className="text-secondary small mb-1">{intl.formatMessage({ id: "platform.hub-interface" })}</div>
								<div className="fw-bold">{hub?.name || "—"}</div>
								<div className="text-secondary small">{hub?.addresses?.join(", ") || intl.formatMessage({ id: "platform.no-addresses" })}</div>
							</div>
							<div className="d-flex flex-wrap gap-2">
								<span className="badge bg-blue-lt text-blue">WG routes: {summary?.wireguardRouteCount || 0}</span>
								<span className="badge bg-azure-lt text-azure">Private routes: {summary?.privateRouteCount || 0}</span>
								<span className="badge bg-yellow-lt text-yellow">Peer networks: {summary?.peerNetworkCount || 0}</span>
							</div>
							{nextActions.length > 0 && (
								<div className="small text-secondary d-flex flex-column gap-1">
									{nextActions.map((a) => <span key={a}>• {fmtNextAction(a)}</span>)}
								</div>
							)}
						</div>
					</div>
				</div>
				<div className="col-lg-6">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title">{intl.formatMessage({ id: "platform.runtime-risks.title" })}</h3>
						</div>
						<div className="card-body d-flex flex-column gap-3">
							<div className="platform-source">
								<div className="fw-bold">{intl.formatMessage({ id: "platform.missing-return.title" })}</div>
								<div className="text-secondary small">{missingReturnRoutes.length ? intl.formatMessage({ id: "platform.missing-return.some" }, { count: missingReturnRoutes.length }) : intl.formatMessage({ id: "platform.missing-return.none" })}</div>
							</div>
							<div className="platform-source">
								<div className="fw-bold">{intl.formatMessage({ id: "platform.nat-candidates.title" })}</div>
								<div className="text-secondary small">{natCandidates.length ? intl.formatMessage({ id: "platform.nat-candidates.some" }, { count: natCandidates.length }) : intl.formatMessage({ id: "platform.nat-candidates.none" })}</div>
							</div>
							<div className="platform-source">
								<div className="fw-bold">{intl.formatMessage({ id: "platform.write-cap.title" })}</div>
								<div className="text-secondary small">{capabilities?.supports.peerCrud ? "Live write actions are enabled." : "Live peer and interface writes are still disabled."}</div>
							</div>
							<div className="platform-source">
								<div className="fw-bold">{intl.formatMessage({ id: "platform.observations.title" })}</div>
								<div className="text-secondary small">
									{observations.length ? observations.slice(0, 3).join(" ") : intl.formatMessage({ id: "platform.observations.none" })}
								</div>
							</div>
						</div>
					</div>
				</div>
			</section>

			<section className="row row-cards">
				<div className="col-12">
					<div className="card platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title d-flex align-items-center gap-2">
								<IconShield size={18} /> Fail2Ban
							</h3>
							<div className="card-options">
								{fail2ban?.available && (
									<span className="badge bg-green-lt text-green">{intl.formatMessage({ id: "f2b.active" })}</span>
								)}
							</div>
						</div>
						<div className="card-body p-0">
							{f2bLoading && <div className="p-3 text-secondary small">{intl.formatMessage({ id: "f2b.loading" })}</div>}
							{!f2bLoading && !fail2ban?.available && (
								<div className="p-3 text-secondary small">{intl.formatMessage({ id: "f2b.unavailable" })}</div>
							)}
							{fail2ban?.available && fail2ban.jails.length === 0 && (
								<div className="p-3 text-secondary small">{intl.formatMessage({ id: "f2b.no-jails" })}</div>
							)}
							{fail2ban?.available && fail2ban.jails.length > 0 && (
								<table className="table table-vcenter card-table">
									<thead>
										<tr>
											<th>{intl.formatMessage({ id: "f2b.col-jail" })}</th>
											<th className="text-end">{intl.formatMessage({ id: "f2b.col-failed" })}</th>
											<th className="text-end">{intl.formatMessage({ id: "f2b.col-banned" })}</th>
											<th>{intl.formatMessage({ id: "f2b.col-banned-ips" })}</th>
										</tr>
									</thead>
									<tbody>
										{fail2ban.jails.map((jail) => (
											<tr key={jail.name}>
												<td className="fw-medium">{jail.name}</td>
												<td className="text-end">
													<span className={jail.currentlyFailed > 0 ? "text-warning" : "text-secondary"}>
														{jail.currentlyFailed}
													</span>
													<span className="text-secondary"> / {jail.totalFailed}</span>
												</td>
												<td className="text-end">
													<span className={jail.currentlyBanned > 0 ? "text-danger fw-bold" : "text-secondary"}>
														{jail.currentlyBanned}
													</span>
													<span className="text-secondary"> / {jail.totalBanned}</span>
												</td>
												<td>
													<div className="d-flex flex-wrap gap-1">
														{jail.bannedIps.length === 0 && (
															<span className="text-secondary small">—</span>
														)}
														{jail.bannedIps.map((ip) => (
															<span key={ip} className="badge bg-red-lt text-red d-flex align-items-center gap-1">
																{ip}
																<button
																	type="button"
																	className="btn-close btn-close-sm ms-1"
																	style={{ fontSize: "0.6rem" }}
																	title={intl.formatMessage({ id: "f2b.unban" })}
																	disabled={unban.isPending}
																	onClick={() => unban.mutate({ jail: jail.name, ip })}
																/>
															</span>
														))}
													</div>
												</td>
											</tr>
										))}
									</tbody>
								</table>
							)}
						</div>
					</div>
				</div>
			</section>
		</div>
	);
};

export default Platform;
