import {
	IconArrowDown,
	IconArrowUp,
	IconCircle,
	IconCircleCheck,
	IconRefresh,
	IconWifi,
} from "@tabler/icons-react";
import { useWireGuardStatus } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import type { WireGuardLink } from "src/api/backend";

const byteFmt = (value?: number) => {
	const bytes = Number(value) || 0;
	if (bytes === 0) return "0 B";
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

const timeAgo = (ts: number) => {
	if (!ts) return intl.formatMessage({ id: "traffic.never" });
	const diff = Math.floor(Date.now() / 1000) - ts;
	if (diff < 60) return `${diff}s`;
	if (diff < 3600) return `${Math.floor(diff / 60)}m`;
	if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
	return `${Math.floor(diff / 86400)}d`;
};

interface BarProps {
	value: number;
	max: number;
	color: string;
}

function HorizBar({ value, max, color }: BarProps) {
	const pct = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
	return (
		<div style={{ display: "flex", alignItems: "center", gap: 6 }}>
			<div
				style={{
					flex: 1,
					height: 6,
					borderRadius: 3,
					background: "var(--tblr-border-color)",
					overflow: "hidden",
				}}
			>
				<div
					style={{
						width: `${pct}%`,
						height: "100%",
						borderRadius: 3,
						background: color,
						transition: "width 0.4s ease",
					}}
				/>
			</div>
			<span style={{ fontSize: "0.7rem", color: "var(--tblr-secondary)", minWidth: 52, textAlign: "right" }}>
				{byteFmt(value)}
			</span>
		</div>
	);
}

function MiniSparkline({ points, color }: { points: number[]; color: string }) {
	if (!points.length) return null;
	const max = Math.max(...points, 1);
	const w = 80;
	const h = 28;
	const step = w / Math.max(points.length - 1, 1);
	const coords = points.map((v, i) => `${i * step},${h - (v / max) * h}`).join(" ");
	return (
		<svg width={w} height={h} style={{ display: "block" }}>
			<title>traffic</title>
			<polyline points={coords} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" />
		</svg>
	);
}

function LinkRow({ link, maxBytes }: { link: WireGuardLink; maxBytes: number }) {
	const linkName = link.name || link.id;
	const isActive = link.active && link.latestHandshake > 0 && Date.now() / 1000 - link.latestHandshake < 180;

	return (
		<div className="card mb-2">
			<div className="card-body py-3">
				<div className="row align-items-center g-3">
					{/* Name + status */}
					<div className="col-md-3">
						<div className="d-flex align-items-center gap-2">
							{isActive ? (
								<IconCircleCheck size={16} className="text-success" />
							) : (
								<IconCircle size={16} className="text-secondary" />
							)}
							<div>
								<div className="fw-medium" style={{ fontSize: "0.875rem" }}>{linkName}</div>
								<div className="text-secondary" style={{ fontSize: "0.75rem" }}>
									{link.interfaceName}
									{link.type ? ` · ${link.type}` : ""}
								</div>
							</div>
						</div>
					</div>

					{/* RX bar */}
					<div className="col-md-4">
						<div className="d-flex align-items-center gap-1 mb-1">
							<IconArrowDown size={11} className="text-success" />
							<span style={{ fontSize: "0.7rem", color: "var(--tblr-secondary)" }}>
								{intl.formatMessage({ id: "traffic.rx" })}
							</span>
						</div>
						<HorizBar value={link.rxBytes} max={maxBytes} color="var(--tblr-success)" />
					</div>

					{/* TX bar */}
					<div className="col-md-4">
						<div className="d-flex align-items-center gap-1 mb-1">
							<IconArrowUp size={11} className="text-primary" />
							<span style={{ fontSize: "0.7rem", color: "var(--tblr-secondary)" }}>
								{intl.formatMessage({ id: "traffic.tx" })}
							</span>
						</div>
						<HorizBar value={link.txBytes} max={maxBytes} color="var(--tblr-primary)" />
					</div>

					{/* Handshake */}
					<div className="col-md-1 text-end">
						<div className="text-secondary" style={{ fontSize: "0.7rem" }}>
							{intl.formatMessage({ id: "traffic.handshake" })}
						</div>
						<div
							style={{ fontSize: "0.8rem" }}
							className={isActive ? "text-success fw-medium" : "text-secondary"}
						>
							{timeAgo(link.latestHandshake)}
						</div>
					</div>
				</div>
			</div>
		</div>
	);
}

const Traffic = () => {
	const { data: wireguard, isLoading, dataUpdatedAt, refetch } = useWireGuardStatus();
	const links: WireGuardLink[] = wireguard?.links ?? [];

	const sortedLinks = [...links].sort((a, b) => (b.rxBytes + b.txBytes) - (a.rxBytes + a.txBytes));
	const maxBytes = sortedLinks.length ? Math.max(...sortedLinks.map((l) => Math.max(l.rxBytes, l.txBytes)), 1) : 1;

	const totalRx = links.reduce((s, l) => s + (l.rxBytes || 0), 0);
	const totalTx = links.reduce((s, l) => s + (l.txBytes || 0), 0);
	const activeLinks = links.filter((l) => l.active && l.latestHandshake > 0 && Date.now() / 1000 - l.latestHandshake < 180).length;

	// mock sparkline demo points (tunnel up-time simulation)
	const demoPoints = [12, 18, 14, 22, 30, 25, 28, 35, 40, 38, 42, 50];

	return (
		<div className="platform-page">
			{/* Summary stat cards */}
			<div className="row row-deck row-cards mb-3">
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm">
						<div className="card-body">
							<div className="d-flex align-items-center gap-3">
								<span className="bg-success text-white avatar"><IconArrowDown /></span>
								<div>
									<div className="text-secondary" style={{ fontSize: "0.8rem" }}>
										{intl.formatMessage({ id: "traffic.total-rx" })}
									</div>
									<div className="fw-bold" style={{ fontSize: "1.2rem" }}>{byteFmt(totalRx)}</div>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm">
						<div className="card-body">
							<div className="d-flex align-items-center gap-3">
								<span className="bg-primary text-white avatar"><IconArrowUp /></span>
								<div>
									<div className="text-secondary" style={{ fontSize: "0.8rem" }}>
										{intl.formatMessage({ id: "traffic.total-tx" })}
									</div>
									<div className="fw-bold" style={{ fontSize: "1.2rem" }}>{byteFmt(totalTx)}</div>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm">
						<div className="card-body">
							<div className="d-flex align-items-center gap-3">
								<span className="bg-green text-white avatar"><IconWifi /></span>
								<div>
									<div className="text-secondary" style={{ fontSize: "0.8rem" }}>
										{intl.formatMessage({ id: "traffic.active-links" })}
									</div>
									<div className="fw-bold" style={{ fontSize: "1.2rem" }}>
										{activeLinks} / {links.length}
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm">
						<div className="card-body">
							<div className="d-flex align-items-center gap-3">
								<MiniSparkline points={demoPoints} color="var(--tblr-cyan)" />
								<div>
									<div className="text-secondary" style={{ fontSize: "0.8rem" }}>
										{intl.formatMessage({ id: "traffic.combined" })}
									</div>
									<div className="fw-bold" style={{ fontSize: "1.2rem" }}>{byteFmt(totalRx + totalTx)}</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>

			{/* Per-peer bandwidth bars */}
			<div className="card">
				<div className="card-header d-flex align-items-center justify-content-between">
					<h3 className="card-title mb-0">
						{intl.formatMessage({ id: "traffic.per-peer-title" })}
					</h3>
					<div className="d-flex align-items-center gap-2">
						{dataUpdatedAt > 0 && (
							<span className="text-secondary" style={{ fontSize: "0.75rem" }}>
								{intl.formatMessage({ id: "traffic.updated" }, { time: new Date(dataUpdatedAt).toLocaleTimeString() })}
							</span>
						)}
						<button
							type="button"
							className="btn btn-sm btn-outline-secondary"
							onClick={() => refetch()}
							disabled={isLoading}
						>
							<IconRefresh size={14} />
						</button>
					</div>
				</div>
				<div className="card-body">
					{isLoading && (
						<div className="text-secondary small py-3 text-center">
							{intl.formatMessage({ id: "traffic.loading" })}
						</div>
					)}
					{!isLoading && sortedLinks.length === 0 && (
						<div className="text-secondary small py-3 text-center">
							{intl.formatMessage({ id: "traffic.no-links" })}
						</div>
					)}
					{!isLoading && sortedLinks.map((link) => (
						<LinkRow key={link.id} link={link} maxBytes={maxBytes} />
					))}
				</div>
			</div>

			{/* Detailed table */}
			{!isLoading && sortedLinks.length > 0 && (
				<div className="card mt-3">
					<div className="card-header">
						<h3 className="card-title mb-0">
							{intl.formatMessage({ id: "traffic.table-title" })}
						</h3>
					</div>
					<div className="table-responsive">
						<table className="table table-vcenter card-table">
							<thead>
								<tr>
									<th>{intl.formatMessage({ id: "traffic.col-peer" })}</th>
									<th>{intl.formatMessage({ id: "traffic.col-type" })}</th>
									<th>{intl.formatMessage({ id: "traffic.col-iface" })}</th>
									<th className="text-end">
										<IconArrowDown size={12} className="text-success me-1" />
										{intl.formatMessage({ id: "traffic.col-rx" })}
									</th>
									<th className="text-end">
										<IconArrowUp size={12} className="text-primary me-1" />
										{intl.formatMessage({ id: "traffic.col-tx" })}
									</th>
									<th>{intl.formatMessage({ id: "traffic.col-handshake" })}</th>
									<th>{intl.formatMessage({ id: "traffic.col-status" })}</th>
								</tr>
							</thead>
							<tbody>
								{sortedLinks.map((link) => {
									const isActive = link.active && link.latestHandshake > 0 && Date.now() / 1000 - link.latestHandshake < 180;
									return (
										<tr key={link.id}>
											<td className="fw-medium">{link.name || link.id}</td>
											<td>
												<span className={`badge ${
													link.type === "client" ? "bg-green-lt text-green" :
													link.type === "site-to-site" ? "bg-blue-lt text-blue" :
													link.type === "hub-link" ? "bg-cyan-lt text-cyan" :
													"bg-secondary-lt text-secondary"
												}`}>
													{link.type || "—"}
												</span>
											</td>
											<td className="text-secondary">{link.interfaceName}</td>
											<td className="text-end font-monospace">{byteFmt(link.rxBytes)}</td>
											<td className="text-end font-monospace">{byteFmt(link.txBytes)}</td>
											<td className="text-secondary">
												{link.latestHandshake ? timeAgo(link.latestHandshake) : "—"}
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
			)}
		</div>
	);
};

export default Traffic;
