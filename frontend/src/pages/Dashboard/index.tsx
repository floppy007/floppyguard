import {
	IconArrowDown,
	IconArrowRight,
	IconArrowUp,
	IconRoute,
	IconShield,
	IconShieldHalfFilled,
} from "@tabler/icons-react";
import { useNavigate } from "react-router-dom";
import type { PeerBandwidth } from "src/api/backend";
import { DonutGauge, HasPermission, PeerSparkline } from "src/components";
import { useFail2BanStatus, useHostReport, useUnbanIp, useWireGuardBandwidth, useWireGuardStatus } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { DEAD_HOSTS, PROXY_HOSTS, REDIRECTION_HOSTS, STREAMS, VIEW } from "src/modules/Permissions";

const KNOWN_NEXT_ACTIONS = new Set([
	"verify-return-path",
	"model-exported-networks",
	"define-remote-management-mode",
	"fix-return-path",
	"decide-nat-or-static-route",
	"define-return-path-mode",
	"verify-live-tunnel-state",
	"mount-wireguard-config-directory",
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

const PEER_COLORS = ["#4299e1", "#48bb78", "#ed8936", "#a78bfa", "#f687b3", "#38b2ac"];

const rateFmt = (bps: number) => {
	if (bps < 1024) return `${bps} B/s`;
	if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`;
	return `${(bps / 1024 / 1024).toFixed(2)} MB/s`;
};

const timeAgo = (ts: number) => {
	if (!ts) return "—";
	const s = Math.floor(Date.now() / 1000) - ts;
	if (s < 60) return `${s}s ago`;
	if (s < 3600) return `${Math.floor(s / 60)}m ago`;
	return `${Math.floor(s / 3600)}h ago`;
};

function MiniChart({ peers, mode }: { peers: PeerBandwidth[]; mode: "rx" | "tx" }) {
	const W = 600;
	const H = 140;
	const N = 60;
	const PAD = { t: 6, r: 8, b: 18, l: 42 };
	const IW = W - PAD.l - PAD.r;
	const IH = H - PAD.t - PAD.b;
	const allVals = peers.flatMap((p) => p.history.map((s) => (mode === "rx" ? s.rx : s.tx)));
	const yMax = Math.max(...allVals, 1024) * 1.2;

	const toD = (peer: PeerBandwidth, fill: boolean) => {
		if (!peer.history.length) return "";
		// Pad history with zeros on the left so data is always right-aligned (= "now")
		const padded =
			peer.history.length < N
				? [...Array(N - peer.history.length).fill({ rx: 0, tx: 0 }), ...peer.history]
				: peer.history.slice(-N);
		const pts = padded.map((s, i) => {
			const x = PAD.l + (i / (N - 1)) * IW;
			const v = mode === "rx" ? s.rx : s.tx;
			const y = PAD.t + IH - (v / yMax) * IH;
			return `${x.toFixed(1)},${y.toFixed(1)}`;
		});
		if (fill) {
			const lastX = (PAD.l + ((padded.length - 1) / (N - 1)) * IW).toFixed(1);
			return `M ${pts.join(" L ")} L ${lastX},${(PAD.t + IH).toFixed(1)} L ${PAD.l},${(PAD.t + IH).toFixed(1)} Z`;
		}
		return `M ${pts.join(" L ")}`;
	};

	const ticks = [0, 0.5, 1].map((f) => ({ y: PAD.t + IH * (1 - f), label: rateFmt(Math.round(yMax * f)) }));

	return (
		<>
			<svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: H, display: "block" }}>
				<title>bandwidth</title>
				<defs>
					{peers.map((_, idx) => {
						const c = PEER_COLORS[idx % PEER_COLORS.length];
						return (
							<linearGradient key={idx} id={`dg-${mode}-${idx}`} x1="0" y1="0" x2="0" y2="1">
								<stop offset="0%" stopColor={c} stopOpacity="0.2" />
								<stop offset="100%" stopColor={c} stopOpacity="0" />
							</linearGradient>
						);
					})}
				</defs>
				{ticks.map(({ y, label }) => (
					<g key={label}>
						<line
							x1={PAD.l}
							y1={y}
							x2={W - PAD.r}
							y2={y}
							stroke="currentColor"
							strokeOpacity="0.06"
							strokeWidth={1}
						/>
						<text
							x={PAD.l - 3}
							y={y + 3.5}
							textAnchor="end"
							fontSize={8}
							fill="currentColor"
							fillOpacity="0.35"
							fontFamily="monospace"
						>
							{label}
						</text>
					</g>
				))}
				{peers.map((p, idx) => {
					const c = PEER_COLORS[idx % PEER_COLORS.length];
					const areaD = toD(p, true);
					const lineD = toD(p, false);
					if (!lineD) return null;
					return (
						<g key={p.id}>
							<path d={areaD} fill={`url(#dg-${mode}-${idx})`} />
							<path
								d={lineD}
								fill="none"
								stroke={c}
								strokeWidth={1.6}
								strokeLinejoin="round"
								strokeLinecap="round"
							/>
						</g>
					);
				})}
				<text x={PAD.l} y={H - 2} fontSize={8} fill="currentColor" fillOpacity="0.3" fontFamily="monospace">
					-10m
				</text>
				<text
					x={W - PAD.r}
					y={H - 2}
					fontSize={8}
					fill="currentColor"
					fillOpacity="0.3"
					fontFamily="monospace"
					textAnchor="end"
				>
					now
				</text>
			</svg>
			<div className="d-flex flex-wrap gap-3" style={{ padding: "0.4rem 0 0" }}>
				{peers.map((p, idx) => {
					const c = PEER_COLORS[idx % PEER_COLORS.length];
					const lastVal =
						p.history.length > 0
							? mode === "rx"
								? p.history[p.history.length - 1].rx
								: p.history[p.history.length - 1].tx
							: 0;
					return (
						<div key={p.id} className="d-flex align-items-center gap-1">
							<svg width={18} height={3} style={{ flexShrink: 0 }}>
								<rect width={18} height={3} rx={1.5} fill={c} />
							</svg>
							<span style={{ fontSize: "0.75rem" }}>{p.name}</span>
							<span className="text-secondary" style={{ fontSize: "0.7rem", fontFamily: "monospace" }}>
								{rateFmt(lastVal)}
							</span>
						</div>
					);
				})}
			</div>
		</>
	);
}

const Dashboard = () => {
	const { data: hostReport } = useHostReport();
	const { data: wireguard } = useWireGuardStatus();
	const { data: bw = [] } = useWireGuardBandwidth();
	const { data: fail2ban, isLoading: f2bLoading } = useFail2BanStatus();
	const unban = useUnbanIp();
	const navigate = useNavigate();

	const hasHistory = bw.some((p) => p.history.length > 0);
	const wgSummary = wireguard?.summary;
	const hub = wireguard?.hub;
	const nextActions = wireguard?.nextActions?.slice(0, 4) || [];
	const links = wireguard?.links || [];
	const missingReturnRoutes = wireguard?.routes.missingReturnRoutes || [];
	const natCandidates = wireguard?.routes.natCandidates || [];

	const proxyActive = hostReport?.proxy || 0;
	const proxyTotal = proxyActive + (hostReport?.dead || 0);
	const peersActive = wgSummary?.activePeers || 0;
	const peersTotal = wgSummary?.totalPeers || 0;
	const ifaceActive = wgSummary?.activeInterfaceCount || 0;
	const ifaceTotal = wgSummary?.interfaceCount || 0;

	return (
		<div className="platform-page">
			{/* ═══ Stat cards with donut gauges ═══ */}
			<div className="row row-deck row-cards">
				<HasPermission section={PROXY_HOSTS} permission={VIEW} hideError>
					<div className="col-sm-6 col-xl-3">
						<a
							href="/nginx/proxy"
							className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
							onClick={(e) => {
								e.preventDefault();
								navigate("/nginx/proxy");
							}}
						>
							<div className="card-body">
								<div className="platform-stat-donut">
									<DonutGauge value={proxyActive} max={proxyTotal || 1} color="var(--tblr-green)" />
									<div>
										<div
											className="text-secondary"
											style={{
												fontSize: "0.72rem",
												fontWeight: 600,
												textTransform: "uppercase",
												letterSpacing: "0.04em",
											}}
										>
											Proxy Hosts
										</div>
										<div className="platform-stat-value">
											{proxyActive}{" "}
											<span
												className="text-secondary"
												style={{ fontSize: "0.8rem", fontWeight: 400 }}
											>
												/ {proxyTotal}
											</span>
										</div>
										<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
											{proxyActive} active · {hostReport?.dead || 0} disabled
										</div>
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
						onClick={(e) => {
							e.preventDefault();
							navigate("/wireguard");
						}}
					>
						<div className="card-body">
							<div className="platform-stat-donut">
								<DonutGauge
									value={ifaceActive}
									max={ifaceTotal || 1}
									color="var(--tblr-primary)"
									liveDot={ifaceActive > 0}
								/>
								<div>
									<div
										className="text-secondary"
										style={{
											fontSize: "0.72rem",
											fontWeight: 600,
											textTransform: "uppercase",
											letterSpacing: "0.04em",
										}}
									>
										WG Interfaces
									</div>
									<div className="platform-stat-value">
										{ifaceActive}{" "}
										<span
											className="text-secondary"
											style={{ fontSize: "0.8rem", fontWeight: 400 }}
										>
											/ {ifaceTotal}
										</span>
									</div>
									<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
										{hub?.name || "—"} active
									</div>
								</div>
							</div>
						</div>
					</a>
				</div>
				<div className="col-sm-6 col-xl-3">
					<a
						href="/wireguard"
						className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
						onClick={(e) => {
							e.preventDefault();
							navigate("/wireguard");
						}}
					>
						<div className="card-body">
							<div className="platform-stat-donut">
								<DonutGauge value={peersActive} max={peersTotal || 1} color="var(--tblr-purple)" />
								<div>
									<div
										className="text-secondary"
										style={{
											fontSize: "0.72rem",
											fontWeight: 600,
											textTransform: "uppercase",
											letterSpacing: "0.04em",
										}}
									>
										Active Peers
									</div>
									<div className="platform-stat-value">
										{peersActive}{" "}
										<span
											className="text-secondary"
											style={{ fontSize: "0.8rem", fontWeight: 400 }}
										>
											/ {peersTotal}
										</span>
									</div>
									<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
										{peersTotal - peersActive} peer idle
									</div>
								</div>
							</div>
						</div>
					</a>
				</div>
				<div className="col-sm-6 col-xl-3">
					<a
						href="/wireguard"
						className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
						onClick={(e) => {
							e.preventDefault();
							navigate("/wireguard");
						}}
					>
						<div className="card-body">
							<div className="platform-stat-donut">
								<DonutGauge
									value={wgSummary?.linkCount || 0}
									max={wgSummary?.linkCount || 1}
									color="var(--tblr-green)"
									liveDot={(wgSummary?.linkCount || 0) > 0}
								/>
								<div>
									<div
										className="text-secondary"
										style={{
											fontSize: "0.72rem",
											fontWeight: 600,
											textTransform: "uppercase",
											letterSpacing: "0.04em",
										}}
									>
										{intl.formatMessage({ id: "dashboard.stat.logical-links" })}
									</div>
									<div className="platform-stat-value">{wgSummary?.linkCount || 0}</div>
									<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
										{wgSummary?.siteLinkCount || 0} site · {wgSummary?.clientLinkCount || 0} client
									</div>
								</div>
							</div>
						</div>
					</a>
				</div>
			</div>

			{/* ═══ Gateway overview + Peer connections with sparklines ═══ */}
			<div className="row row-cards">
				<div className="col-lg-7">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title d-flex align-items-center gap-2">
								<IconRoute size={18} /> {intl.formatMessage({ id: "dashboard.gateway-overview" })}
							</h3>
							<div className="card-options">
								<a
									href="/gateway"
									className="btn btn-sm btn-ghost-secondary"
									onClick={(e) => {
										e.preventDefault();
										navigate("/gateway");
									}}
								>
									{intl.formatMessage({ id: "dashboard.view-routing" })} <IconArrowRight size={14} />
								</a>
							</div>
						</div>
						<div className="card-body">
							<div className="row row-cards">
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">
											{intl.formatMessage({ id: "dashboard.hub-interface" })}
										</div>
										<div className="fw-bold mb-1">{hub?.name || "—"}</div>
										<div className="small text-secondary">
											{hub?.addresses?.length
												? hub.addresses.join(", ")
												: intl.formatMessage({ id: "dashboard.no-addresses" })}
										</div>
									</div>
								</div>
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">
											{intl.formatMessage({ id: "dashboard.total-traffic" })}
										</div>
										<div className="fw-bold mb-1">
											{byteFmt(wgSummary?.totalRxBytes)} / {byteFmt(wgSummary?.totalTxBytes)}
										</div>
										<div className="small text-secondary">
											{wgSummary?.peerNetworkCount || 0} peer networks ·{" "}
											{wgSummary?.privateRouteCount || 0} private routes
										</div>
									</div>
								</div>
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">
											{intl.formatMessage({ id: "dashboard.topology" })}
										</div>
										<div className="fw-bold mb-1">
											{wgSummary?.siteLinkCount || 0} site · {wgSummary?.hubLinkCount || 0} hub ·{" "}
											{wgSummary?.clientLinkCount || 0} client
										</div>
										<div className="small text-secondary">
											{missingReturnRoutes.length > 0 && (
												<span className="text-warning">
													{intl.formatMessage(
														{ id: "dashboard.missing-return-hint" },
														{ count: missingReturnRoutes.length },
													)}{" "}
													·{" "}
												</span>
											)}
											{natCandidates.length > 0 && (
												<span className="text-warning">
													{intl.formatMessage(
														{ id: "dashboard.nat-candidate-hint" },
														{ count: natCandidates.length },
													)}{" "}
													·{" "}
												</span>
											)}
											{missingReturnRoutes.length === 0 && natCandidates.length === 0 && (
												<span>{intl.formatMessage({ id: "dashboard.no-route-risks" })} · </span>
											)}
											<span>
												{intl.formatMessage(
													{ id: "dashboard.wg-routes" },
													{ count: wgSummary?.wireguardRouteCount || 0 },
												)}
											</span>
										</div>
									</div>
								</div>
								<div className="col-sm-6">
									<div className="platform-inline-panel h-100">
										<div className="text-secondary small mb-1">
											{intl.formatMessage({ id: "dashboard.next-steps" })}
										</div>
										<div className="small text-secondary d-flex flex-column gap-1">
											{nextActions.length ? (
												nextActions.map((a) => <span key={a}>• {fmtNextAction(a)}</span>)
											) : (
												<span>{intl.formatMessage({ id: "dashboard.no-hints" })}</span>
											)}
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
							<h3 className="card-title d-flex align-items-center gap-2">
								<IconShieldHalfFilled size={16} />
								{intl.formatMessage({ id: "dashboard.link-preview" })}
								{links.some((l) => l.active) && (
									<span
										className="status-dot status-green status-dot-animated"
										style={{ width: 5, height: 5 }}
									/>
								)}
							</h3>
							<div className="card-options">
								<a
									href="/traffic"
									className="btn btn-sm btn-ghost-secondary"
									onClick={(e) => {
										e.preventDefault();
										navigate("/traffic");
									}}
								>
									{intl.formatMessage({ id: "dashboard.view-traffic" })} <IconArrowRight size={14} />
								</a>
							</div>
						</div>
						<div style={{ maxHeight: 280, overflowY: "auto" }}>
							{(() => {
								if (!links.length) {
									return (
										<div className="p-3 text-secondary small">
											{intl.formatMessage({ id: "dashboard.no-links" })}
										</div>
									);
								}

								// Map bandwidth history to links
								const bwMap = new Map(bw.map((p) => [p.id, p]));

								return links.map((link) => {
									const isActive =
										link.active &&
										link.latestHandshake > 0 &&
										Date.now() / 1000 - link.latestHandshake < 180;
									const peerBw = bwMap.get(link.id);
									const sparkData = peerBw?.history.map((s) => s.rx + s.tx) || [];
									const color = isActive
										? PEER_COLORS[links.indexOf(link) % PEER_COLORS.length]
										: "var(--tblr-secondary)";

									return (
										<div key={link.id} className="platform-peer-row">
											<div className="d-flex align-items-center justify-content-between mb-1">
												<div>
													<span className="fw-medium" style={{ fontSize: "0.85rem" }}>
														{link.name || link.id}
													</span>
													<div className="text-secondary" style={{ fontSize: "0.7rem" }}>
														{link.type || "—"} · {link.interfaceName} · handshake{" "}
														{timeAgo(link.latestHandshake)}
													</div>
												</div>
												<span
													className={`badge ${isActive ? "bg-success-lt text-success" : "bg-secondary-lt text-secondary"}`}
													style={{ fontSize: "0.65rem" }}
												>
													{isActive ? "●" : "○"} {isActive ? "Active" : "Idle"}
												</span>
											</div>
											<div className="platform-peer-bottom">
												<div className="platform-peer-spark">
													<PeerSparkline data={sparkData} color={color} height={32} />
												</div>
												<div className="platform-peer-stats">
													<div style={{ textAlign: "right" }}>
														<div className="platform-peer-stat-dir text-success">↓ RX</div>
														<div className="platform-peer-stat-val">
															{byteFmt(link.rxBytes)}
														</div>
													</div>
													<div style={{ textAlign: "right" }}>
														<div className="platform-peer-stat-dir text-primary">↑ TX</div>
														<div className="platform-peer-stat-val">
															{byteFmt(link.txBytes)}
														</div>
													</div>
												</div>
											</div>
										</div>
									);
								});
							})()}
						</div>
					</div>
				</div>
			</div>

			{/* ═══ Live bandwidth charts ═══ */}
			{hasHistory && (
				<div className="row row-cards">
					<div className="col-lg-6">
						<div className="card platform-elevated-card">
							<div className="card-header">
								<h3 className="card-title d-flex align-items-center gap-2">
									<IconArrowDown size={14} className="text-success" />
									{intl.formatMessage({ id: "traffic.chart-rx" })}
								</h3>
								<div className="card-options">
									<span
										className="text-secondary"
										style={{ fontSize: "0.72rem", fontFamily: "monospace" }}
									>
										{rateFmt(
											bw.reduce((s, p) => s + (p.history[p.history.length - 1]?.rx ?? 0), 0),
										)}
									</span>
								</div>
							</div>
							<div className="card-body pt-1 pb-2">
								<MiniChart peers={bw.slice(0, 4)} mode="rx" />
							</div>
						</div>
					</div>
					<div className="col-lg-6">
						<div className="card platform-elevated-card">
							<div className="card-header">
								<h3 className="card-title d-flex align-items-center gap-2">
									<IconArrowUp size={14} className="text-primary" />
									{intl.formatMessage({ id: "traffic.chart-tx" })}
								</h3>
								<div className="card-options">
									<span
										className="text-secondary"
										style={{ fontSize: "0.72rem", fontFamily: "monospace" }}
									>
										{rateFmt(
											bw.reduce((s, p) => s + (p.history[p.history.length - 1]?.tx ?? 0), 0),
										)}
									</span>
								</div>
							</div>
							<div className="card-body pt-1 pb-2">
								<MiniChart peers={bw.slice(0, 4)} mode="tx" />
							</div>
						</div>
					</div>
				</div>
			)}

			{/* ═══ Secondary host stats with donut gauges ═══ */}
			<div className="row row-deck row-cards">
				<HasPermission section={REDIRECTION_HOSTS} permission={VIEW} hideError>
					<div className="col-sm-6 col-lg-4">
						<a
							href="/nginx/redirection"
							className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
							onClick={(e) => {
								e.preventDefault();
								navigate("/nginx/redirection");
							}}
						>
							<div className="card-body">
								<div className="platform-stat-donut">
									<DonutGauge
										value={hostReport?.redirection || 0}
										max={hostReport?.redirection || 1}
										color="var(--tblr-yellow)"
										label={String(hostReport?.redirection || 0)}
									/>
									<div>
										<div
											className="text-secondary"
											style={{
												fontSize: "0.72rem",
												fontWeight: 600,
												textTransform: "uppercase",
												letterSpacing: "0.04em",
											}}
										>
											Redirections
										</div>
										<div className="platform-stat-value" style={{ fontSize: "1.15rem" }}>
											{hostReport?.redirection || 0} active
										</div>
										<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
											All operational
										</div>
									</div>
								</div>
							</div>
						</a>
					</div>
				</HasPermission>
				<HasPermission section={STREAMS} permission={VIEW} hideError>
					<div className="col-sm-6 col-lg-4">
						<a
							href="/nginx/stream"
							className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
							onClick={(e) => {
								e.preventDefault();
								navigate("/nginx/stream");
							}}
						>
							<div className="card-body">
								<div className="platform-stat-donut">
									<DonutGauge
										value={hostReport?.stream || 0}
										max={hostReport?.stream || 1}
										color="var(--tblr-azure)"
										label={String(hostReport?.stream || 0)}
									/>
									<div>
										<div
											className="text-secondary"
											style={{
												fontSize: "0.72rem",
												fontWeight: 600,
												textTransform: "uppercase",
												letterSpacing: "0.04em",
											}}
										>
											Streams
										</div>
										<div className="platform-stat-value" style={{ fontSize: "1.15rem" }}>
											{hostReport?.stream || 0} active
										</div>
										<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
											TCP forwarding
										</div>
									</div>
								</div>
							</div>
						</a>
					</div>
				</HasPermission>
				<HasPermission section={DEAD_HOSTS} permission={VIEW} hideError>
					<div className="col-sm-6 col-lg-4">
						<a
							href="/nginx/404"
							className="card card-sm card-link card-link-pop platform-stat-card platform-card-link"
							onClick={(e) => {
								e.preventDefault();
								navigate("/nginx/404");
							}}
						>
							<div className="card-body">
								<div className="platform-stat-donut">
									<DonutGauge
										value={hostReport?.dead || 0}
										max={hostReport?.dead || 1}
										color="var(--tblr-red)"
										label={String(hostReport?.dead || 0)}
									/>
									<div>
										<div
											className="text-secondary"
											style={{
												fontSize: "0.72rem",
												fontWeight: 600,
												textTransform: "uppercase",
												letterSpacing: "0.04em",
											}}
										>
											Dead Hosts
										</div>
										<div className="platform-stat-value" style={{ fontSize: "1.15rem" }}>
											{hostReport?.dead || 0} blocked
										</div>
										<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
											Serving 410 Gone
										</div>
									</div>
								</div>
							</div>
						</a>
					</div>
				</HasPermission>
			</div>

			{/* ═══ Fail2Ban ═══ */}
			<div className="row row-cards">
				<div className="col-12">
					<div className="card platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title d-flex align-items-center gap-2">
								<IconShield size={18} /> Fail2Ban
							</h3>
							<div className="card-options">
								{fail2ban?.available && (
									<span className="badge bg-green-lt text-green">
										{intl.formatMessage({ id: "f2b.active" })}
									</span>
								)}
							</div>
						</div>
						<div className="card-body p-0">
							{f2bLoading && (
								<div className="p-3 text-secondary small">
									{intl.formatMessage({ id: "f2b.loading" })}
								</div>
							)}
							{!f2bLoading && !fail2ban?.available && (
								<div className="p-3 text-secondary small">
									{intl.formatMessage({ id: "f2b.unavailable" })}
								</div>
							)}
							{fail2ban?.available && fail2ban.jails.length === 0 && (
								<div className="p-3 text-secondary small">
									{intl.formatMessage({ id: "f2b.no-jails" })}
								</div>
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
													<span
														className={
															jail.currentlyFailed > 0 ? "text-warning" : "text-secondary"
														}
													>
														{jail.currentlyFailed}
													</span>
													<span className="text-secondary"> / {jail.totalFailed}</span>
												</td>
												<td className="text-end">
													<span
														className={
															jail.currentlyBanned > 0
																? "text-danger fw-bold"
																: "text-secondary"
														}
													>
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
															<span
																key={ip}
																className="badge bg-red-lt text-red d-flex align-items-center gap-1"
															>
																{ip}
																<button
																	type="button"
																	className="btn-close btn-close-sm ms-1"
																	style={{ fontSize: "0.6rem" }}
																	title={intl.formatMessage({ id: "f2b.unban" })}
																	disabled={unban.isPending}
																	onClick={() =>
																		unban.mutate({ jail: jail.name, ip })
																	}
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
