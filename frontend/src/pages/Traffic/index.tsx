import { IconArrowDown, IconArrowRight, IconArrowUp, IconCircle, IconCircleCheck } from "@tabler/icons-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import type { BandwidthRange, PeerBandwidth } from "src/api/backend";
import { DonutGauge, PeerSparkline } from "src/components";
import { useWireGuardBandwidth, useWireGuardStatus } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { relativeTime } from "src/modules/relativeTime";
import { getLinkTypeBadge } from "src/pages/WireGuard/linkLabels";
import { byteFmt, rateFmt } from "src/pages/WireGuard/topology";
import { currentRates, isLinkActive, PEER_COLORS, peerColorMap, sortByVolume } from "./bandwidth";

// ─── XY Line Chart ─────────────────────────────────────────────────────────

interface ChartProps {
	peers: PeerBandwidth[];
	colors: Map<string, string>;
	mode: "rx" | "tx";
	range: BandwidthRange;
	height?: number;
}

const RANGE_DURATION_MS: Record<BandwidthRange, number> = {
	live: 10 * 60 * 1000,
	"24h": 24 * 60 * 60 * 1000,
	"30d": 30 * 24 * 60 * 60 * 1000,
	"12m": 365 * 24 * 60 * 60 * 1000,
};

function formatTimeTick(timestamp: number, range: BandwidthRange, position: number) {
	if (range === "live") {
		if (position === 1) return intl.formatMessage({ id: "traffic.tick-now" });
		return intl.formatMessage({ id: "traffic.tick-minutes" }, { count: Math.round((1 - position) * 10) });
	}

	const options: Intl.DateTimeFormatOptions =
		range === "24h"
			? { hour: "2-digit", minute: "2-digit" }
			: range === "30d"
				? { day: "2-digit", month: "short" }
				: { month: "short" };
	return new Intl.DateTimeFormat(undefined, options).format(new Date(timestamp));
}

function LineChart({ peers, colors, mode, range, height = 180 }: ChartProps) {
	const W = 600;
	const H = height;
	const PAD = { top: 8, right: 12, bottom: 24, left: 52 };
	const innerW = W - PAD.left - PAD.right;
	const innerH = H - PAD.top - PAD.bottom;
	const endTime = Date.now();
	const startTime = endTime - RANGE_DURATION_MS[range];

	const visibleSamples = (peer: PeerBandwidth) =>
		peer.history.filter((sample) => sample.ts >= startTime && sample.ts <= endTime);
	const allValues = peers.flatMap((peer) =>
		visibleSamples(peer).map((sample) => (mode === "rx" ? sample.rx : sample.tx)),
	);
	const rawMax = allValues.length ? Math.max(...allValues) : 0;
	const yMax = rawMax < 1024 ? 1024 : rawMax * 1.15;

	const plotPoints = (peer: PeerBandwidth) =>
		visibleSamples(peer).map((sample) => {
			const x = PAD.left + ((sample.ts - startTime) / (endTime - startTime)) * innerW;
			const value = mode === "rx" ? sample.rx : sample.tx;
			const y = PAD.top + innerH - (value / yMax) * innerH;
			return { x, y };
		});

	const toPath = (points: Array<{ x: number; y: number }>) => {
		if (!points.length) return "";
		return `M ${points.map(({ x, y }) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" L ")}`;
	};

	const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => ({
		y: PAD.top + innerH * (1 - f),
		label: rateFmt(Math.round(yMax * f)),
	}));

	const xTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => ({
		x: PAD.left + f * innerW,
		label: formatTimeTick(startTime + f * (endTime - startTime), range, f),
	}));

	return (
		<svg
			viewBox={`0 0 ${W} ${H}`}
			style={{ width: "100%", height: H, display: "block" }}
			aria-label={`${mode === "rx" ? "Received" : "Sent"} bandwidth over time`}
		>
			{yTicks.map(({ y, label }) => (
				<g key={label}>
					<line
						x1={PAD.left}
						y1={y}
						x2={W - PAD.right}
						y2={y}
						stroke="var(--tblr-border-color)"
						strokeWidth={1}
						strokeDasharray="3,3"
					/>
					<text x={PAD.left - 4} y={y + 4} textAnchor="end" fontSize={9} fill="var(--tblr-secondary)">
						{label}
					</text>
				</g>
			))}

			{xTicks.map(({ x, label }, index) => (
				<text
					key={`${label}-${index}`}
					x={x}
					y={H - 4}
					textAnchor="middle"
					fontSize={9}
					fill="var(--tblr-secondary)"
				>
					{label}
				</text>
			))}

			{peers.map((peer) => {
				const points = plotPoints(peer);
				const d = toPath(points);
				if (!d) return null;
				const color = colors.get(peer.id) ?? PEER_COLORS[0];
				const first = points[0];
				const last = points[points.length - 1];
				return (
					<g key={peer.id}>
						<path
							d={`${d} L ${last.x.toFixed(1)},${PAD.top + innerH} L ${first.x.toFixed(1)},${PAD.top + innerH} Z`}
							fill={color}
							fillOpacity={0.1}
						/>
						<path
							d={d}
							fill="none"
							stroke={color}
							strokeWidth={1.8}
							strokeLinejoin="round"
							strokeLinecap="round"
						/>
						<circle cx={last.x} cy={last.y} r={3} fill={color} />
					</g>
				);
			})}

			<line
				x1={PAD.left}
				y1={PAD.top + innerH}
				x2={W - PAD.right}
				y2={PAD.top + innerH}
				stroke="var(--tblr-border-color)"
				strokeWidth={1}
			/>
		</svg>
	);
}

// ─── Legend ────────────────────────────────────────────────────────────────

function Legend({ peers, colors }: { peers: PeerBandwidth[]; colors: Map<string, string> }) {
	return (
		<div className="d-flex flex-wrap gap-3 mb-2">
			{peers.map((peer) => (
				<div key={peer.id} className="d-flex align-items-center gap-1">
					<svg width={20} height={3} style={{ flexShrink: 0 }}>
						<rect width={20} height={3} rx={1.5} fill={colors.get(peer.id) ?? PEER_COLORS[0]} />
					</svg>
					<span style={{ fontSize: "0.78rem" }}>{peer.name}</span>
					{peer.history.length > 0 && (
						<span className="text-secondary" style={{ fontSize: "0.72rem" }}>
							↓ {rateFmt(peer.history[peer.history.length - 1]?.rx ?? 0)} ↑{" "}
							{rateFmt(peer.history[peer.history.length - 1]?.tx ?? 0)}
						</span>
					)}
				</div>
			))}
		</div>
	);
}

// ─── Main page ─────────────────────────────────────────────────────────────

const Traffic = () => {
	const navigate = useNavigate();
	const [range, setRange] = useState<BandwidthRange>("live");
	const { data: bw = [], isLoading: bwLoading, dataUpdatedAt } = useWireGuardBandwidth(range);
	// "Current" rates always come from the live series (same query as range=live).
	// The last history bucket is an average (12m: today's) and includes peers long gone.
	const { data: liveBw = [] } = useWireGuardBandwidth("live");
	const { data: wg } = useWireGuardStatus();

	const links = wg?.links ?? [];
	const now = Date.now() / 1000;
	const totalRx = links.reduce((s, l) => s + (l.rxBytes || 0), 0);
	const totalTx = links.reduce((s, l) => s + (l.txBytes || 0), 0);
	const activeLinks = links.filter((l) => isLinkActive(l, now)).length;

	const { rx: currentRxRate, tx: currentTxRate } = currentRates(liveBw);

	// Rank by volume over the whole window in every range: the live API orders by
	// the newest sample only, which reshuffled the top 6 on every 10 s poll.
	const chartPeers = sortByVolume(bw).slice(0, 6);
	const peerColors = peerColorMap(
		links.map((l) => l.id),
		chartPeers.map((p) => p.id),
	);
	const hasHistory = chartPeers.some((p) => p.history.length > 0);

	// Map bandwidth history to link IDs for sparklines
	const bwMap = new Map(bw.map((p) => [p.id, p]));

	return (
		<div className="platform-page">
			<div className="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
				<h2 className="mb-0">{intl.formatMessage({ id: "traffic" })}</h2>
				<div className="btn-group" role="group" aria-label="Traffic history range">
					{(["live", "24h", "30d", "12m"] as BandwidthRange[]).map((value) => (
						<button
							key={value}
							type="button"
							className={`btn btn-sm ${range === value ? "btn-primary" : "btn-outline-primary"}`}
							onClick={() => setRange(value)}
						>
							{{ live: "Live", "24h": "24 h", "30d": "30 d", "12m": "12 m" }[value]}
						</button>
					))}
				</div>
			</div>
			{/* ═══ Stat cards with donut gauges ═══ */}
			<div className="row row-deck row-cards mb-3">
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm platform-stat-card">
						<div className="card-body">
							<div className="platform-stat-donut">
								<DonutGauge
									value={currentRxRate}
									max={currentRxRate + currentTxRate || 1}
									color="var(--tblr-green)"
									label="RX"
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
										{intl.formatMessage({ id: "traffic.current-rx" })}
									</div>
									<div className="fw-bold" style={{ fontSize: "1.1rem" }}>
										{rateFmt(currentRxRate)}
									</div>
									<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
										{byteFmt(totalRx)} {intl.formatMessage({ id: "traffic.total" })}
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm platform-stat-card">
						<div className="card-body">
							<div className="platform-stat-donut">
								<DonutGauge
									value={currentTxRate}
									max={currentRxRate + currentTxRate || 1}
									color="var(--tblr-primary)"
									label="TX"
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
										{intl.formatMessage({ id: "traffic.current-tx" })}
									</div>
									<div className="fw-bold" style={{ fontSize: "1.1rem" }}>
										{rateFmt(currentTxRate)}
									</div>
									<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
										{byteFmt(totalTx)} {intl.formatMessage({ id: "traffic.total" })}
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm platform-stat-card">
						<div className="card-body">
							<div className="platform-stat-donut">
								<DonutGauge value={activeLinks} max={links.length || 1} color="var(--tblr-green)" />
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
										{intl.formatMessage({ id: "traffic.active-links" })}
									</div>
									<div className="fw-bold" style={{ fontSize: "1.1rem" }}>
										{activeLinks} / {links.length}
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm platform-stat-card">
						<div className="card-body">
							<div className="platform-stat-donut">
								<DonutGauge
									value={1}
									max={1}
									color="var(--tblr-azure)"
									liveDot={currentRxRate + currentTxRate > 0}
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
										{intl.formatMessage({ id: "traffic.combined-rate" })}
									</div>
									<div className="fw-bold" style={{ fontSize: "1.1rem" }}>
										{rateFmt(currentRxRate + currentTxRate)}
									</div>
									<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
										{liveBw.length} {intl.formatMessage({ id: "traffic.peers" })}
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>

			{/* ═══ Bandwidth charts ═══ */}
			<div className="row row-cards mb-3">
				<div className="col-lg-6">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header d-flex align-items-center justify-content-between">
							<div>
								<h3 className="card-title mb-0 d-flex align-items-center gap-2">
									<IconArrowDown size={16} className="text-success" />
									{intl.formatMessage({ id: "traffic.chart-rx" })}
								</h3>
								<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
									{intl.formatMessage({ id: `traffic.range-subtitle.${range}` })}
								</div>
							</div>
							{dataUpdatedAt > 0 && (
								<span className="text-secondary" style={{ fontSize: "0.72rem" }}>
									{new Date(dataUpdatedAt).toLocaleTimeString()}
								</span>
							)}
						</div>
						<div className="card-body pt-2">
							{bwLoading && (
								<div className="text-secondary small py-4 text-center">
									{intl.formatMessage({ id: "traffic.warming-up" })}
								</div>
							)}
							{!bwLoading && !hasHistory && (
								<div className="text-secondary small py-4 text-center">
									{intl.formatMessage({ id: "traffic.warming-up" })}
								</div>
							)}
							{!bwLoading && hasHistory && (
								<>
									<Legend peers={chartPeers} colors={peerColors} />
									<LineChart peers={chartPeers} colors={peerColors} mode="rx" range={range} />
								</>
							)}
						</div>
					</div>
				</div>

				<div className="col-lg-6">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header d-flex align-items-center justify-content-between">
							<div>
								<h3 className="card-title mb-0 d-flex align-items-center gap-2">
									<IconArrowUp size={16} className="text-primary" />
									{intl.formatMessage({ id: "traffic.chart-tx" })}
								</h3>
								<div className="text-secondary" style={{ fontSize: "0.72rem" }}>
									{intl.formatMessage({ id: `traffic.range-subtitle.${range}` })}
								</div>
							</div>
							{dataUpdatedAt > 0 && (
								<span className="text-secondary" style={{ fontSize: "0.72rem" }}>
									{new Date(dataUpdatedAt).toLocaleTimeString()}
								</span>
							)}
						</div>
						<div className="card-body pt-2">
							{bwLoading && (
								<div className="text-secondary small py-4 text-center">
									{intl.formatMessage({ id: "traffic.warming-up" })}
								</div>
							)}
							{!bwLoading && !hasHistory && (
								<div className="text-secondary small py-4 text-center">
									{intl.formatMessage({ id: "traffic.warming-up" })}
								</div>
							)}
							{!bwLoading && hasHistory && (
								<>
									<Legend peers={chartPeers} colors={peerColors} />
									<LineChart peers={chartPeers} colors={peerColors} mode="tx" range={range} />
								</>
							)}
						</div>
					</div>
				</div>
			</div>

			{/* ═══ Per-peer detail table with sparklines ═══ */}
			<div className="card platform-elevated-card">
				<div className="card-header d-flex align-items-center justify-content-between">
					<h3 className="card-title mb-0">{intl.formatMessage({ id: "traffic.table-title" })}</h3>
					<a
						href="/gateway"
						className="btn btn-sm btn-ghost-secondary"
						onClick={(e) => {
							e.preventDefault();
							navigate("/gateway");
						}}
					>
						{intl.formatMessage({ id: "traffic.routing-details" })} <IconArrowRight size={14} />
					</a>
				</div>
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>{intl.formatMessage({ id: "traffic.col-peer" })}</th>
								<th>{intl.formatMessage({ id: "traffic.col-type" })}</th>
								<th style={{ minWidth: 120 }}>{intl.formatMessage({ id: "traffic.col-activity" })}</th>
								<th className="text-end">
									<IconArrowDown size={11} className="text-success me-1" />
									{intl.formatMessage({ id: "traffic.col-rx" })}
								</th>
								<th className="text-end">
									<IconArrowUp size={11} className="text-primary me-1" />
									{intl.formatMessage({ id: "traffic.col-tx" })}
								</th>
								<th>{intl.formatMessage({ id: "traffic.col-handshake" })}</th>
								<th>{intl.formatMessage({ id: "traffic.col-status" })}</th>
							</tr>
						</thead>
						<tbody>
							{links.length === 0 && (
								<tr>
									<td colSpan={7} className="text-secondary text-center small py-4">
										{intl.formatMessage({ id: "traffic.no-links" })}
									</td>
								</tr>
							)}
							{[...links]
								.sort((a, b) => b.rxBytes + b.txBytes - (a.rxBytes + a.txBytes))
								.map((link) => {
									const isActive = isLinkActive(link, now);
									const typeBadge = getLinkTypeBadge(link);
									const peerBw = bwMap.get(link.id);
									const sparkData = peerBw?.history.map((s) => s.rx + s.tx) || [];
									const color = isActive
										? (peerColors.get(link.id) ?? PEER_COLORS[0])
										: "var(--tblr-secondary)";

									return (
										<tr key={link.id}>
											<td>
												<div className="d-flex align-items-center gap-2">
													{isActive ? (
														<IconCircleCheck
															size={14}
															className="text-success flex-shrink-0"
														/>
													) : (
														<IconCircle
															size={14}
															className="text-secondary flex-shrink-0"
														/>
													)}
													<div>
														<div className="fw-medium">{link.name || link.id}</div>
														<div className="text-secondary" style={{ fontSize: "0.75rem" }}>
															{link.interfaceName}
														</div>
													</div>
												</div>
											</td>
											<td>
												<span className={`badge ${typeBadge.className}`}>
													{intl.formatMessage({ id: typeBadge.labelId })}
												</span>
											</td>
											<td>
												<PeerSparkline data={sparkData} color={color} height={24} />
											</td>
											<td className="text-end font-monospace">{byteFmt(link.rxBytes)}</td>
											<td className="text-end font-monospace">{byteFmt(link.txBytes)}</td>
											<td className="text-secondary">
												{link.latestHandshake ? relativeTime(link.latestHandshake) : "—"}
											</td>
											<td>
												{isActive ? (
													<span className="badge bg-success-lt text-success">
														{intl.formatMessage({ id: "traffic.status-active" })}
													</span>
												) : (
													<span className="badge bg-secondary-lt text-secondary">
														{intl.formatMessage({ id: "traffic.status-idle" })}
													</span>
												)}
											</td>
										</tr>
									);
								})}
						</tbody>
					</table>
				</div>
			</div>
		</div>
	);
};

export default Traffic;
