import {
	IconArrowDown,
	IconArrowRight,
	IconArrowsCross,
	IconArrowUp,
	IconBolt,
	IconBoltOff,
	IconDisc,
	IconPlugConnected,
	IconRoute,
	IconShield,
	IconShieldHalfFilled,
	IconTopologyStar3,
} from "@tabler/icons-react";
import { useNavigate } from "react-router-dom";
import { HasPermission } from "src/components";
import { useHostReport, useWireGuardStatus, useFail2BanStatus, useUnbanIp } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { DEAD_HOSTS, PROXY_HOSTS, REDIRECTION_HOSTS, STREAMS, VIEW } from "src/modules/Permissions";

const KNOWN_NEXT_ACTIONS = new Set([
	"verify-return-path", "model-exported-networks", "define-remote-management-mode",
	"fix-return-path", "decide-nat-or-static-route", "define-return-path-mode",
	"verify-live-tunnel-state", "mount-wireguard-config-directory",
]);
const fmtNextAction = (a: string) =>
	KNOWN_NEXT_ACTIONS.has(a) ? intl.formatMessage({ id: `wireguard.next.${a}` }) : a;

const byteFmt = (value?: number) => {
	const bytes = Number(value) || 0;
	if (bytes < 1024) return `${bytes} B`;
	const units = ["KB", "MB", "GB", "TB"];
	let current = bytes;
	let idx = -1;
	do {
		current /= 1024;
		idx += 1;
	} while (current >= 1024 && idx < units.length - 1);
	return `${current < 10 ? current.toFixed(2) : current < 100 ? current.toFixed(1) : Math.round(current)} ${units[idx]}`;
};

const Dashboard = () => {
	const { data: hostReport } = useHostReport();
	const { data: wireguard } = useWireGuardStatus();
	const { data: fail2ban, isLoading: f2bLoading } = useFail2BanStatus();
	const unban = useUnbanIp();
	const navigate = useNavigate();
	const wgSummary = wireguard?.summary;
	const hub = wireguard?.hub;
	const routePreview = wireguard?.routes.wireguard.slice(0, 5) || [];
	const nextActions = wireguard?.nextActions?.slice(0, 4) || [];
	const links = wireguard?.links?.slice(0, 4) || [];
	const missingReturnRoutes = wireguard?.routes.missingReturnRoutes || [];
	const natCandidates = wireguard?.routes.natCandidates || [];

	return (
		<div className="platform-page">

			{/* Top stat cards */}
			<div className="row row-deck row-cards">
				<HasPermission section={PROXY_HOSTS} permission={VIEW} hideError>
					<div className="col-sm-6 col-xl-3">
						<a
							href="/nginx/proxy"
							className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
							onClick={(e) => { e.preventDefault(); navigate("/nginx/proxy"); }}
						>
							<div className="card-body">
								<div className="d-flex align-items-center gap-3">
									<span className="bg-green text-white avatar"><IconBolt /></span>
									<div>
										<div className="text-secondary">Proxy Hosts</div>
										<div className="platform-stat-value">{hostReport?.proxy || 0}</div>
									</div>
								</div>
							</div>
						</a>
					</div>
				</HasPermission>
				<div className="col-sm-6 col-xl-3">
					<a
						href="/wireguard"
						className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
						onClick={(e) => { e.preventDefault(); navigate("/wireguard"); }}
					>
						<div className="card-body">
							<div className="d-flex align-items-center gap-3">
								<span className="bg-blue text-white avatar"><IconShieldHalfFilled /></span>
								<div>
									<div className="text-secondary">WireGuard Interfaces</div>
									<div className="platform-stat-value">{wgSummary?.activeInterfaceCount || 0} / {wgSummary?.interfaceCount || 0}</div>
								</div>
							</div>
						</div>
					</a>
				</div>
				<div className="col-sm-6 col-xl-3">
					<a
						href="/wireguard"
						className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
						onClick={(e) => { e.preventDefault(); navigate("/wireguard"); }}
					>
						<div className="card-body">
							<div className="d-flex align-items-center gap-3">
								<span className="bg-yellow text-white avatar"><IconPlugConnected /></span>
								<div>
									<div className="text-secondary">Active Peers</div>
									<div className="platform-stat-value">{wgSummary?.activePeers || 0} / {wgSummary?.totalPeers || 0}</div>
								</div>
							</div>
						</div>
					</a>
				</div>
				<div className="col-sm-6 col-xl-3">
					<a
						href="/wireguard"
						className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
						onClick={(e) => { e.preventDefault(); navigate("/wireguard"); }}
					>
						<div className="card-body">
							<div className="d-flex align-items-center gap-3">
								<span className="bg-cyan text-white avatar"><IconTopologyStar3 /></span>
								<div>
									<div className="text-secondary">{intl.formatMessage({ id: "dashboard.stat.logical-links" })}</div>
									<div className="platform-stat-value">{wgSummary?.linkCount || 0}</div>
								</div>
							</div>
						</div>
					</a>
				</div>
			</div>

			{/* Gateway overview + link preview */}
			<div className="row row-cards">
				<div className="col-lg-7">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title d-flex align-items-center gap-2"><IconRoute size={18} /> {intl.formatMessage({ id: "dashboard.gateway-overview" })}</h3>
							<div className="card-options">
								<a href="/gateway" className="btn btn-sm btn-ghost-secondary" onClick={(e) => { e.preventDefault(); navigate("/gateway"); }}>
									{intl.formatMessage({ id: "dashboard.view-routing" })} <IconArrowRight size={14} />
								</a>
							</div>
						</div>
						<div className="card-body">
							<div className="row row-cards">
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">{intl.formatMessage({ id: "dashboard.hub-interface" })}</div>
										<div className="fw-bold mb-1">{hub?.name || "—"}</div>
										<div className="small text-secondary">
											{hub?.addresses?.length ? hub.addresses.join(", ") : intl.formatMessage({ id: "dashboard.no-addresses" })}
										</div>
									</div>
								</div>
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">{intl.formatMessage({ id: "dashboard.total-traffic" })}</div>
										<div className="fw-bold mb-1">{byteFmt(wgSummary?.totalRxBytes)} / {byteFmt(wgSummary?.totalTxBytes)}</div>
										<div className="small text-secondary">
											{wgSummary?.peerNetworkCount || 0} peer networks · {wgSummary?.privateRouteCount || 0} private routes
										</div>
									</div>
								</div>
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">{intl.formatMessage({ id: "dashboard.topology" })}</div>
										<div className="fw-bold mb-1">{wgSummary?.siteLinkCount || 0} site · {wgSummary?.hubLinkCount || 0} hub · {wgSummary?.clientLinkCount || 0} client</div>
										<div className="small text-secondary">
											{missingReturnRoutes.length > 0 && <span className="text-warning">{intl.formatMessage({ id: "dashboard.missing-return-hint" }, { count: missingReturnRoutes.length })} · </span>}
											{natCandidates.length > 0 && <span className="text-warning">{intl.formatMessage({ id: "dashboard.nat-candidate-hint" }, { count: natCandidates.length })} · </span>}
											{missingReturnRoutes.length === 0 && natCandidates.length === 0 && <span>{intl.formatMessage({ id: "dashboard.no-route-risks" })} · </span>}
											<span>{intl.formatMessage({ id: "dashboard.wg-routes" }, { count: wgSummary?.wireguardRouteCount || 0 })}</span>
										</div>
									</div>
								</div>
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">{intl.formatMessage({ id: "dashboard.next-steps" })}</div>
										<div className="small text-secondary d-flex flex-column gap-1">
											{nextActions.length ? nextActions.map((a) => <span key={a}>• {fmtNextAction(a)}</span>) : <span>{intl.formatMessage({ id: "dashboard.no-hints" })}</span>}
										</div>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-lg-5">
					<div className="card h-100 platform-table-card">
						<div className="card-header">
							<h3 className="card-title">{intl.formatMessage({ id: "dashboard.link-preview" })}</h3>
							<div className="card-options">
								<a href="/traffic" className="btn btn-sm btn-ghost-secondary" onClick={(e) => { e.preventDefault(); navigate("/traffic"); }}>
									{intl.formatMessage({ id: "dashboard.view-traffic" })} <IconArrowRight size={14} />
								</a>
							</div>
						</div>
						<div className="list-group list-group-flush">
							{(() => {
								const maxBytes = links.length ? Math.max(...links.map((l) => Math.max(l.rxBytes || 0, l.txBytes || 0)), 1) : 1;
								return links.length ? links.map((link) => (
									<div key={link.id} className="list-group-item py-2">
										<div className="d-flex align-items-center justify-content-between mb-1">
											<span className="fw-medium" style={{ fontSize: "0.85rem" }}>{link.name || link.id}</span>
											<span className={`badge ${link.active ? "bg-success-lt text-success" : "bg-secondary-lt text-secondary"}`} style={{ fontSize: "0.65rem" }}>
												{link.active ? "●" : "○"} {link.type || "—"}
											</span>
										</div>
										<div style={{ display: "flex", gap: 4, alignItems: "center" }}>
											<IconArrowDown size={10} className="text-success" style={{ flexShrink: 0 }} />
											<div style={{ flex: 1, height: 4, borderRadius: 2, background: "var(--tblr-border-color)", overflow: "hidden" }}>
												<div style={{ width: `${Math.max(2, Math.round(((link.rxBytes || 0) / maxBytes) * 100))}%`, height: "100%", background: "var(--tblr-success)", borderRadius: 2 }} />
											</div>
											<IconArrowUp size={10} className="text-primary" style={{ flexShrink: 0 }} />
											<div style={{ flex: 1, height: 4, borderRadius: 2, background: "var(--tblr-border-color)", overflow: "hidden" }}>
												<div style={{ width: `${Math.max(2, Math.round(((link.txBytes || 0) / maxBytes) * 100))}%`, height: "100%", background: "var(--tblr-primary)", borderRadius: 2 }} />
											</div>
											<span className="text-secondary" style={{ fontSize: "0.65rem", minWidth: 60, textAlign: "right" }}>
												{byteFmt(link.rxBytes)} / {byteFmt(link.txBytes)}
											</span>
										</div>
									</div>
								)) : routePreview.length ? routePreview.map((route) => (
									<div key={route.raw} className="list-group-item">
										<div className="fw-medium">{route.destination}</div>
										<div className="text-secondary small">
											dev {route.device || "?"}{route.via ? ` via ${route.via}` : ""}
										</div>
									</div>
								)) : (
									<div className="list-group-item text-secondary small">{intl.formatMessage({ id: "dashboard.no-links" })}</div>
								);
							})()}
						</div>
					</div>
				</div>
			</div>

			{/* Secondary host stats */}
			<div className="row row-deck row-cards">
				<HasPermission section={REDIRECTION_HOSTS} permission={VIEW} hideError>
					<div className="col-sm-6 col-lg-3">
						<a
							href="/nginx/redirection"
							className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
							onClick={(e) => { e.preventDefault(); navigate("/nginx/redirection"); }}
						>
							<div className="card-body">
								<div className="d-flex align-items-center gap-3">
									<span className="bg-yellow text-white avatar"><IconArrowsCross /></span>
									<div>
										<div className="text-secondary">Redirection Hosts</div>
										<div className="platform-stat-value">{hostReport?.redirection || 0}</div>
									</div>
								</div>
							</div>
						</a>
					</div>
				</HasPermission>
				<HasPermission section={STREAMS} permission={VIEW} hideError>
					<div className="col-sm-6 col-lg-3">
						<a
							href="/nginx/stream"
							className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
							onClick={(e) => { e.preventDefault(); navigate("/nginx/stream"); }}
						>
							<div className="card-body">
								<div className="d-flex align-items-center gap-3">
									<span className="bg-blue text-white avatar"><IconDisc /></span>
									<div>
										<div className="text-secondary">Streams</div>
										<div className="platform-stat-value">{hostReport?.stream || 0}</div>
									</div>
								</div>
							</div>
						</a>
					</div>
				</HasPermission>
				<HasPermission section={DEAD_HOSTS} permission={VIEW} hideError>
					<div className="col-sm-6 col-lg-3">
						<a
							href="/nginx/404"
							className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
							onClick={(e) => { e.preventDefault(); navigate("/nginx/404"); }}
						>
							<div className="card-body">
								<div className="d-flex align-items-center gap-3">
									<span className="bg-red text-white avatar"><IconBoltOff /></span>
									<div>
										<div className="text-secondary">Dead Hosts</div>
										<div className="platform-stat-value">{hostReport?.dead || 0}</div>
									</div>
								</div>
							</div>
						</a>
					</div>
				</HasPermission>
			</div>

			{/* Fail2Ban */}
			<div className="row row-cards">
				<div className="col-12">
					<div className="card platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title d-flex align-items-center gap-2">
								<IconShield size={18} /> Fail2Ban
							</h3>
							<div className="card-options">
								{fail2ban?.available && <span className="badge bg-green-lt text-green">{intl.formatMessage({ id: "f2b.active" })}</span>}
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
														{jail.bannedIps.length === 0 && <span className="text-secondary small">—</span>}
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
			</div>

		</div>
	);
};

export default Dashboard;
