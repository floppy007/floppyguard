import {
	IconArrowsCross,
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
import { DEAD_HOSTS, PROXY_HOSTS, REDIRECTION_HOSTS, STREAMS, VIEW } from "src/modules/Permissions";

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
									<div className="text-secondary">Logical Links</div>
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
							<h3 className="card-title d-flex align-items-center gap-2"><IconRoute size={18} /> Gateway Overview</h3>
						</div>
						<div className="card-body">
							<div className="row row-cards">
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">Hub Interface</div>
										<div className="fw-bold mb-1">{hub?.name || "—"}</div>
										<div className="small text-secondary">
											{hub?.addresses?.length ? hub.addresses.join(", ") : "No addresses reported"}
										</div>
									</div>
								</div>
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">Total Traffic</div>
										<div className="fw-bold mb-1">{byteFmt(wgSummary?.totalRxBytes)} / {byteFmt(wgSummary?.totalTxBytes)}</div>
										<div className="small text-secondary">
											{wgSummary?.peerNetworkCount || 0} peer networks · {wgSummary?.privateRouteCount || 0} private routes
										</div>
									</div>
								</div>
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">Topology</div>
										<div className="fw-bold mb-1">{wgSummary?.siteLinkCount || 0} site · {wgSummary?.hubLinkCount || 0} hub · {wgSummary?.clientLinkCount || 0} client</div>
										<div className="small text-secondary">
											{missingReturnRoutes.length > 0 && <span className="text-warning">{missingReturnRoutes.length} missing return route(s) · </span>}
											{natCandidates.length > 0 && <span className="text-warning">{natCandidates.length} NAT candidate(s) · </span>}
											{missingReturnRoutes.length === 0 && natCandidates.length === 0 && <span>No route risks detected · </span>}
											<span>{wgSummary?.wireguardRouteCount || 0} WG routes</span>
										</div>
									</div>
								</div>
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">Next Steps</div>
										<div className="small text-secondary d-flex flex-column gap-1">
											{nextActions.length ? nextActions.map((item) => <span key={item}>• {item}</span>) : <span>No immediate hints from runtime.</span>}
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
							<h3 className="card-title">Link Preview</h3>
						</div>
						<div className="list-group list-group-flush">
							{links.length ? links.map((link) => (
								<div key={link.id} className="list-group-item">
									<div className="fw-medium">{link.name}</div>
									<div className="text-secondary small">
										{link.type} on {link.interfaceName}{link.remoteEndpoint ? ` · ${link.remoteEndpoint}` : ""}
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
								<div className="list-group-item text-secondary small">No WireGuard routes available.</div>
							)}
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
								{fail2ban?.available && <span className="badge bg-green-lt text-green">aktiv</span>}
							</div>
						</div>
						<div className="card-body p-0">
							{f2bLoading && <div className="p-3 text-secondary small">Lade…</div>}
							{!f2bLoading && !fail2ban?.available && (
								<div className="p-3 text-secondary small">fail2ban nicht verfügbar.</div>
							)}
							{fail2ban?.available && fail2ban.jails.length === 0 && (
								<div className="p-3 text-secondary small">Keine Jails konfiguriert.</div>
							)}
							{fail2ban?.available && fail2ban.jails.length > 0 && (
								<table className="table table-vcenter card-table">
									<thead>
										<tr>
											<th>Jail</th>
											<th className="text-end">Fehlversuche</th>
											<th className="text-end">Gesperrt</th>
											<th>Gesperrte IPs</th>
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
																	title="Entsperren"
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
