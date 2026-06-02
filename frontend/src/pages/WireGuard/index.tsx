import { IconPlugConnected, IconPlus, IconRoute, IconShieldHalfFilled, IconTopologyStar3 } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import type {
	Agent,
	WireGuardApplyMetadataResponse,
	WireGuardInterface,
	WireGuardInterfaceRole,
	WireGuardLink,
	WireGuardLinkType,
	WireGuardManagementMode,
	WireGuardMetadataPatch,
	WireGuardPlanPreviewResponse,
	WireGuardRemoteManagementMode,
	WireGuardReturnPathMode,
	WireGuardRouteHint,
} from "src/api/backend";
import {
	buildInstallOneliner,
	createWireGuardInterface,
	deleteWireGuardInterface,
	deleteWireGuardPeer,
	downloadWireGuardLinkConfig,
	resetAgentToken,
} from "src/api/backend";
import { Loading } from "src/components";
import {
	useAgents,
	useApplyWireGuardMetadata,
	useCreateAgent,
	useCreateWireGuardPeer,
	usePreviewWireGuardPlan,
	useRestoreWireGuardMetadata,
	useSetSetting,
	useSetting,
	useUpdateAgent,
	useWireGuardApplyState,
	useWireGuardStatus,
} from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { showDeleteConfirmModal, showWireGuardQrModal } from "src/modals";
import styles from "./index.module.css";

// ── Utilities ──────────────────────────────────────────────────────────────────

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

const KNOWN_WARNINGS = new Set([
	"remote-endpoint-missing",
	"imported-network-missing-live-route",
	"nat-likely-needed",
	"exported-networks-missing",
	"return-path-mode-undefined",
	"remote-management-mode-undefined",
	"link-not-currently-active",
	"allowedips-conflict",
]);

const fmtWarning = (w: string) => (KNOWN_WARNINGS.has(w) ? intl.formatMessage({ id: `wireguard.warning.${w}` }) : w);

// Structured warning from the backend (e.g. allowedips-conflict)
type StructuredWarning = { code: string; subnet: string; peers: string[]; message: string };
const isStructuredWarning = (w: unknown): w is StructuredWarning =>
	typeof w === "object" && w !== null && "code" in w;

const fmtGlobalWarning = (w: string | StructuredWarning): string => {
	if (isStructuredWarning(w)) {
		if (w.code === "allowedips-conflict") {
			return intl.formatMessage(
				{ id: "wireguard.warning.allowedips-conflict" },
				{ subnet: w.subnet, peers: w.peers.join(", ") },
			);
		}
		return w.message;
	}
	return fmtWarning(w);
};

const byteFmt = (value?: number) => {
	const bytes = Number(value) || 0;
	if (bytes < 1024) return `${bytes} B`;
	const units = ["KB", "MB", "GB", "TB"];
	let v = bytes;
	let i = -1;
	do {
		v /= 1024;
		i++;
	} while (v >= 1024 && i < 3);
	return `${v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
};

const shortKey = (value?: string | null) => (value ? `${value.slice(0, 8)}…` : "—");
const splitCsv = (value: string) =>
	value
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);

const parseMgmt = (v: string): WireGuardRemoteManagementMode =>
	(["none", "ssh", "agent"] as const).includes(v as never) ? (v as WireGuardRemoteManagementMode) : "unknown";
const parseReturn = (v: string): WireGuardReturnPathMode =>
	(["auto", "static-route", "nat", "routed"] as const).includes(v as never)
		? (v as WireGuardReturnPathMode)
		: "unknown";
const parseIfaceRole = (v: string): WireGuardInterfaceRole =>
	(["client-hub", "site-to-site", "hub-link", "auxiliary", "unknown"] as const).includes(v as never)
		? (v as WireGuardInterfaceRole)
		: "unknown";
const parseIfaceMgmt = (v: string): WireGuardManagementMode =>
	(["local", "imported", "unknown"] as const).includes(v as never) ? (v as WireGuardManagementMode) : "unknown";

const timeAgo = (ts: number) => {
	if (!ts) return intl.formatMessage({ id: "wireguard.time.never" });
	const s = Math.floor(Date.now() / 1000 - ts);
	if (s < 60) return `${s}s ago`;
	if (s < 3600) return `${Math.floor(s / 60)}m ago`;
	return `${Math.floor(s / 3600)}h ago`;
};

const typeBadge = (type: WireGuardLink["type"]) => {
	switch (type) {
		case "site-to-site":
			return { label: "site-to-site", cls: "bg-indigo-lt text-indigo" };
		case "hub-link":
			return { label: "hub-link", cls: "bg-cyan-lt text-cyan" };
		case "client":
			return { label: "client", cls: "bg-emerald-lt text-emerald" };
		default:
			return { label: type || "unknown", cls: "bg-secondary-lt text-secondary" };
	}
};

const planBadge = (state?: string | null) => {
	switch (state) {
		case "ready":
			return { label: intl.formatMessage({ id: "wireguard.plan.ready" }), cls: "bg-green-lt text-green" };
		case "validate":
			return { label: intl.formatMessage({ id: "wireguard.plan.check" }), cls: "bg-yellow-lt text-yellow" };
		case "shape":
			return { label: intl.formatMessage({ id: "wireguard.plan.design" }), cls: "bg-blue-lt text-blue" };
		default:
			return {
				label: intl.formatMessage({ id: "wireguard.plan.unplanned" }),
				cls: "bg-secondary-lt text-secondary",
			};
	}
};

const ifaceHealthBadge = (health?: string) => {
	switch (health) {
		case "healthy":
			return "bg-green-lt text-green";
		case "warning":
			return "bg-yellow-lt text-yellow";
		default:
			return "bg-secondary-lt text-secondary";
	}
};

const hasRouteHint = (link: WireGuardLink, hints: WireGuardRouteHint[]) =>
	hints.some((h) => link.importedNetworks.includes(h.network));

// ── Apply sync result banner ────────────────────────────────────────────────────

function ApplySyncResult({ data }: { data: WireGuardApplyMetadataResponse }) {
	const { hubSync, agentSync, apply } = data;
	if (apply.changeScope !== "metadata-with-config-intent") {
		return (
			<div className="alert alert-success mt-2 mb-0 py-2 small">
				{intl.formatMessage({ id: "wireguard.apply.saved" })}
			</div>
		);
	}
	const hubOk = hubSync?.synced !== false;
	const agentChanges = agentSync?.filter((a) => a.changed) ?? [];
	const agentErrors = agentSync?.filter((a) => !a.changed && a.reason) ?? [];
	const noChange = intl.formatMessage({ id: "wireguard.apply.no-change" });
	return (
		<div className={`alert mt-2 mb-0 py-2 small ${hubOk ? "alert-success" : "alert-warning"}`}>
			<div className="fw-medium">{intl.formatMessage({ id: "wireguard.apply.saved-live" })}</div>
			<div className="mt-1">
				<span className="me-3">
					{intl.formatMessage({ id: "wireguard.apply.hub-config" })}{" "}
					{hubOk
						? `✓ ${hubSync?.changes?.length ? `(${intl.formatMessage({ id: "wireguard.apply.peers-updated" }, { count: hubSync.changes.length })})` : `(${noChange})`}`
						: `⚠ ${hubSync?.reason ?? intl.formatMessage({ id: "notification.error" })}`}
				</span>
				{agentSync && (
					<span>
						{intl.formatMessage({ id: "wireguard.apply.agents" })}{" "}
						{agentChanges.length > 0 ? `✓ ${agentChanges.map((a) => a.name).join(", ")}` : noChange}
						{agentErrors.length > 0 &&
							` · ⚠ ${agentErrors.map((a) => a.name).join(", ")} ${intl.formatMessage({ id: "wireguard.apply.skipped" })}`}
					</span>
				)}
			</div>
		</div>
	);
}

// ── Topology Map ───────────────────────────────────────────────────────────────

type TopoPos = { x: number; y: number };

function computePositions(links: WireGuardLink[], W: number, H: number): Record<string, TopoPos> {
	const cx = W / 2;
	const cy = H * 0.44; // hub slightly above centre so bottom nodes have room for labels
	const R = Math.min(W, H) * 0.36;

	// Angle arcs per type (degrees, 0=right, 90=bottom)
	const arcs: Record<string, [number, number]> = {
		"site-to-site": [-140, -40],
		"hub-link": [-40, 40],
		client: [60, 160],
		imported: [160, 220],
		unknown: [160, 220],
	};

	const byType: Record<string, WireGuardLink[]> = {};
	for (const link of links) {
		const t = link.type || "unknown";
		if (!byType[t]) byType[t] = [];
		byType[t].push(link);
	}

	const positions: Record<string, TopoPos> = {};
	for (const [type, tLinks] of Object.entries(byType)) {
		const [start, end] = arcs[type] ?? arcs.unknown;
		tLinks.forEach((link, i) => {
			const t = tLinks.length === 1 ? 0.5 : i / (tLinks.length - 1);
			const deg = start + t * (end - start);
			const rad = (deg * Math.PI) / 180;
			positions[link.id] = { x: cx + R * Math.cos(rad), y: cy + R * Math.sin(rad) };
		});
	}
	return positions;
}

const TOPO_TYPE_META = [
	{
		type: "site-to-site",
		labelId: "wireguard.topo.site-to-site",
		color: "#6366f1",
		badgeCls: "bg-indigo-lt text-indigo",
	},
	{ type: "hub-link", labelId: "wireguard.topo.hub-link", color: "#06b6d4", badgeCls: "bg-cyan-lt text-cyan" },
	{ type: "client", labelId: "wireguard.topo.client", color: "#10b981", badgeCls: "bg-emerald-lt text-emerald" },
] as const;

function TopologyMap({ links, interfaces }: { links: WireGuardLink[]; interfaces: WireGuardInterface[] }) {
	const W = 900;
	const H = 460; // tall enough so bottom nodes + their network labels never clip
	const cx = W / 2;
	const cy = H * 0.44; // must match computePositions
	const positions = computePositions(links, W, H);

	const typeColorMap: Record<string, string> = {
		"site-to-site": "#6366f1",
		"hub-link": "#06b6d4",
		client: "#10b981",
		unclassified: "#94a3b8",
	};

	const activeLinkCount = links.filter((l) => l.active).length;

	return (
		<div className={styles.topologyContainer}>
			{/* Map SVG */}
			<svg viewBox={`0 0 ${W} ${H}`} className={styles.topologySvg} preserveAspectRatio="xMidYMid meet">
				{/* Connection lines */}
				{links.map((link) => {
					const pos = positions[link.id];
					if (!pos) return null;
					const color = typeColorMap[link.type] || "#94a3b8";
					return (
						<line
							key={`line-${link.id}`}
							x1={cx}
							y1={cy}
							x2={pos.x}
							y2={pos.y}
							stroke={color}
							strokeWidth={link.active ? 2.5 : 1.5}
							strokeOpacity={link.active ? 0.7 : 0.2}
							strokeDasharray={link.active ? undefined : "7 5"}
						/>
					);
				})}

				{/* Central hub node */}
				<circle
					cx={cx}
					cy={cy}
					r={30}
					fill="var(--tblr-primary)"
					fillOpacity={0.1}
					stroke="var(--tblr-primary)"
					strokeWidth={2}
				/>
				<text
					x={cx}
					y={cy - 7}
					textAnchor="middle"
					dominantBaseline="middle"
					className={styles.topoHubLabel}
					fontSize="12"
				>
					{intl.formatMessage({ id: "wireguard.topo.this" })}
				</text>
				<text
					x={cx}
					y={cy + 8}
					textAnchor="middle"
					dominantBaseline="middle"
					className={styles.topoHubLabel}
					fontSize="12"
				>
					{intl.formatMessage({ id: "wireguard.topo.hub" })}
				</text>

				{/* Interface labels near center */}
				{interfaces.slice(0, 4).map((iface, i) => {
					const angle = ((i / Math.max(interfaces.length - 1, 1)) * 180 - 90) * (Math.PI / 180);
					const lx = cx + 50 * Math.cos(angle);
					const ly = cy + 50 * Math.sin(angle);
					return (
						<text
							key={iface.name}
							x={lx}
							y={ly}
							textAnchor="middle"
							dominantBaseline="middle"
							fontSize="9"
							fill="var(--tblr-secondary)"
							opacity="0.7"
						>
							{iface.name}
						</text>
					);
				})}

				{/* Link nodes */}
				{links.map((link) => {
					const pos = positions[link.id];
					if (!pos) return null;
					const color = typeColorMap[link.type] || "#94a3b8";
					const displayName = link.name.length > 16 ? `${link.name.slice(0, 15)}…` : link.name;

					// Determine label direction: above node if in upper half, below if in lower half
					const inUpperHalf = pos.y < cy;
					const labelY = inUpperHalf ? pos.y - 28 : pos.y + 28;
					const trafficY = inUpperHalf ? pos.y - 40 : pos.y + 40;

					// Networks to show: exported first, then imported as fallback (max 3 total)
					const nets = [
						...link.exportedNetworks.map((n) => ({ n, kind: "ex" as const })),
						...link.importedNetworks
							.slice(0, Math.max(0, 3 - link.exportedNetworks.length))
							.map((n) => ({ n, kind: "im" as const })),
					].slice(0, 3);
					const netDir = inUpperHalf ? -1 : 1;
					const netBaseY = inUpperHalf ? labelY - 12 : trafficY + 12;

					return (
						<g key={`node-${link.id}`}>
							<circle
								cx={pos.x}
								cy={pos.y}
								r={18}
								fill={link.active ? color : "var(--tblr-bg-surface)"}
								fillOpacity={link.active ? 0.15 : 1}
								stroke={color}
								strokeWidth={link.active ? 2 : 1.5}
								strokeOpacity={link.active ? 0.9 : 0.35}
							/>
							{/* Active pulse dot */}
							{link.active && <circle cx={pos.x + 13} cy={pos.y - 13} r={5} fill="#22c55e" />}
							{/* Node label — link name */}
							<text
								x={pos.x}
								y={labelY}
								textAnchor="middle"
								dominantBaseline="middle"
								fontSize="10"
								className={styles.topoLabel}
							>
								{displayName}
							</text>
							{/* Traffic indicator */}
							{link.active && (link.rxBytes > 0 || link.txBytes > 0) && (
								<text
									x={pos.x}
									y={trafficY}
									textAnchor="middle"
									dominantBaseline="middle"
									fontSize="8"
									fill="var(--tblr-secondary)"
								>
									{byteFmt(link.rxBytes + link.txBytes)}
								</text>
							)}
							{/* Network labels */}
							{nets.map(({ n, kind }, ni) => (
								<text
									key={`net-${ni}`}
									x={pos.x}
									y={netBaseY + ni * 11 * netDir}
									textAnchor="middle"
									dominantBaseline="middle"
									fontSize="8"
									fill={kind === "ex" ? color : "#94a3b8"}
									opacity="0.85"
								>
									{n}
								</text>
							))}
						</g>
					);
				})}
			</svg>

			{/* Legend bar */}
			<div className={styles.topoLegend}>
				<div className={styles.topoLegendItems}>
					{TOPO_TYPE_META.map(({ type, labelId, color }) => {
						const count = links.filter((l) => l.type === type).length;
						return (
							<div key={type} className={styles.topoLegendItem}>
								<svg width="28" height="12" style={{ flexShrink: 0 }}>
									<line x1="0" y1="6" x2="28" y2="6" stroke={color} strokeWidth="2.5" />
									<circle
										cx="14"
										cy="6"
										r="5"
										fill={color}
										fillOpacity="0.15"
										stroke={color}
										strokeWidth="1.5"
									/>
								</svg>
								<span className={styles.topoLegendLabel}>{intl.formatMessage({ id: labelId })}</span>
								<span className={styles.topoLegendCount}>{count}</span>
							</div>
						);
					})}
					<div className={styles.topoLegendItem}>
						<svg width="28" height="12" style={{ flexShrink: 0 }}>
							<line
								x1="0"
								y1="6"
								x2="28"
								y2="6"
								stroke="#94a3b8"
								strokeWidth="1.5"
								strokeDasharray="5 3"
							/>
						</svg>
						<span className={styles.topoLegendLabel}>
							{intl.formatMessage({ id: "wireguard.topo.legend-inactive" })}
						</span>
					</div>
					<div className={styles.topoLegendItem}>
						<svg width="12" height="12" style={{ flexShrink: 0 }}>
							<circle cx="6" cy="6" r="5" fill="#22c55e" />
						</svg>
						<span className={styles.topoLegendLabel}>
							{intl.formatMessage({ id: "wireguard.topo.legend-active" })}
						</span>
						<span className={styles.topoLegendCount}>
							{activeLinkCount} / {links.length}
						</span>
					</div>
					<div
						className={styles.topoLegendItem}
						style={{ marginLeft: "auto", opacity: 0.55, fontSize: "0.75rem" }}
					>
						<span style={{ color: typeColorMap["site-to-site"] }}>■</span>&nbsp;
						{intl.formatMessage({ id: "wireguard.topo.legend-exported" })}&nbsp;&nbsp;
						<span style={{ color: typeColorMap.unclassified }}>■</span>&nbsp;
						{intl.formatMessage({ id: "wireguard.topo.legend-imported" })}
					</div>
				</div>
			</div>
		</div>
	);
}

// ── Preview Result ─────────────────────────────────────────────────────────────

function PreviewResult({ preview, current }: { preview: WireGuardPlanPreviewResponse; current: boolean }) {
	const cls = !current ? "bg-yellow-lt text-yellow" : preview.valid ? "bg-green-lt text-green" : "bg-red-lt text-red";
	const label = !current
		? intl.formatMessage({ id: "wireguard.preview.outdated" })
		: preview.valid
			? intl.formatMessage({ id: "wireguard.preview.valid" })
			: intl.formatMessage({ id: "notification.error" });
	return (
		<div className="border rounded p-3 mt-3">
			<span className={`badge ${cls} mb-2`}>{label}</span>
			{preview.errors.map((e) => (
				<div key={e} className="small text-danger">
					✗ {e}
				</div>
			))}
			{preview.warnings.slice(0, 3).map((w) => (
				<div key={w} className="small text-warning">
					⚠ {fmtWarning(w)}
				</div>
			))}
			{preview.apply.canApply && current && (
				<div className="small text-success mt-1">
					{intl.formatMessage({ id: "wireguard.preview.ready-metadata" })}
				</div>
			)}
			{!preview.apply.canApply && preview.apply.blockedBy.length > 0 && (
				<div className="small text-danger mt-1">
					{intl.formatMessage({ id: "wireguard.preview.blocked" })} {preview.apply.blockedBy[0]}
				</div>
			)}
			{preview.apply.changeScope === "metadata-with-config-intent" && (
				<div className="small text-warning mt-1">
					{intl.formatMessage({ id: "wireguard.preview.config-intent-change" })}
				</div>
			)}
		</div>
	);
}

// ── Agent Section ──────────────────────────────────────────────────────────────

function AgentSection({ link, agents }: { link: WireGuardLink; agents: Agent[] }) {
	const existingAgent =
		agents.find((a) => a.wgLinkName === link.name) ??
		agents.find((a) => a.name === link.name) ??
		agents.find((a) =>
			link.tunnelAddresses.some((addr) => {
				const ip = addr.replace(/\/\d+$/, "");
				return (a.hostname ?? "").includes(ip) || a.name.includes(ip);
			}),
		);
	const createAgent = useCreateAgent();
	const updateAgent = useUpdateAgent();
	const hubSetting = useSetting("agent-hub-url");
	const setSetting = useSetSetting();
	const [hubUrlEdit, setHubUrlEdit] = useState<{ primary: string; fallback: string } | null>(null);

	const [publicUrl, setPublicUrl] = useState(() => window.location.origin);
	const [tunnelUrl, setTunnelUrl] = useState(() => {
		const ip = (link.tunnelAddresses || [])[0]?.replace(/\/\d+$/, "");
		return ip ? `http://${ip}:3300` : "";
	});
	const [copied, setCopied] = useState(false);
	const [activeAgent, setActiveAgent] = useState<Agent | null>(existingAgent ?? null);
	const [mgmtUrlEdit, setMgmtUrlEdit] = useState<string | null>(null);
	const [aclEdit, setAclEdit] = useState<string | null>(null);
	const [showReinstall, setShowReinstall] = useState(false);
	const [resetLoading, setResetLoading] = useState(false);
	const agentCreateAttempted = useRef(false);

	// Auto-create agent if none exists for this link
	useEffect(() => {
		if (!existingAgent && !activeAgent && !agentCreateAttempted.current) {
			agentCreateAttempted.current = true;
			createAgent.mutate(
				{
					name: link.name,
					mode: "native",
					wgInterface: link.interfaceName,
					wgLinkName: link.name,
				},
				{ onSuccess: setActiveAgent },
			);
		}
	}, [existingAgent, activeAgent, link.interfaceName, link.name, createAgent.mutate]);

	const handleCopy = (text: string) => {
		navigator.clipboard.writeText(text).catch(() => {});
		setCopied(true);
		setTimeout(() => setCopied(false), 2000);
	};

	const handleResetToken = async (agentId: number) => {
		setResetLoading(true);
		try {
			const updated = await resetAgentToken(agentId);
			setActiveAgent(updated);
			setShowReinstall(true);
		} finally {
			setResetLoading(false);
		}
	};

	const handleSaveMgmtUrl = (agentId: number) => {
		if (mgmtUrlEdit === null) return;
		updateAgent.mutate(
			{
				id: agentId,
				data: { mgmtUrl: mgmtUrlEdit.trim() || undefined },
			},
			{
				onSuccess: (updated) => {
					setActiveAgent(updated);
					setMgmtUrlEdit(null);
				},
			},
		);
	};

	const handleSaveAcl = (agentId: number) => {
		if (aclEdit === null) return;
		const networks = splitCsv(aclEdit);
		updateAgent.mutate(
			{ id: agentId, data: { allowedNetworks: networks } },
			{
				onSuccess: (updated) => {
					setActiveAgent(updated);
					setAclEdit(null);
				},
			},
		);
	};

	// Mirror backend sanitizeHubUrl: http(s) only, no shell/sed metacharacters.
	// Empty is allowed (clears that URL). Blocks Save on junk the backend would
	// silently reject, so the admin gets feedback instead of a no-op.
	const isValidHubUrl = (v: string) => {
		const t = v.trim();
		if (!t) return true;
		return /^https?:\/\/[^\s"'$`\\;|&(){}<>!#]+$/.test(t);
	};
	const hubUrlInvalid =
		hubUrlEdit !== null && (!isValidHubUrl(hubUrlEdit.primary) || !isValidHubUrl(hubUrlEdit.fallback));

	const handleSaveHubUrl = () => {
		if (hubUrlEdit === null || hubUrlInvalid) return;
		setSetting.mutate(
			{
				id: "agent-hub-url",
				value: hubUrlEdit.fallback.trim(),
				meta: { primary: hubUrlEdit.primary.trim() },
			},
			{ onSuccess: () => setHubUrlEdit(null) },
		);
	};

	// Use the resolved agent (either pre-existing or just created)
	const agent = activeAgent ?? existingAgent ?? null;

	return (
		<div className={styles.inlineSection}>
			<div className="fw-medium mb-3 small text-uppercase text-secondary">Agent — {link.name}</div>

			{/* Hub address — GLOBAL setting propagated to every agent on next poll */}
			<div className="mb-3 p-2 rounded" style={{ background: "rgba(128,128,128,0.06)" }}>
				{hubUrlEdit === null ? (
					<div className="d-flex align-items-center gap-2 flex-wrap small">
						<span className="text-secondary">{intl.formatMessage({ id: "wireguard.agent.hub-url" })}</span>
						<code>{hubSetting.data?.meta?.primary || "—"}</code>
						<span className="text-secondary">/</span>
						<code>{hubSetting.data?.value || "—"}</code>
						<button
							type="button"
							className="btn btn-sm btn-link p-0 small"
							onClick={() =>
								setHubUrlEdit({
									primary: hubSetting.data?.meta?.primary ?? "",
									fallback: hubSetting.data?.value ?? "",
								})
							}
						>
							{intl.formatMessage({ id: "wireguard.agent.change" })}
						</button>
					</div>
				) : (
					<div className="d-flex flex-column gap-2">
						<input
							type="url"
							className="form-control form-control-sm"
							style={{ maxWidth: 360 }}
							value={hubUrlEdit.primary}
							onChange={(e) => setHubUrlEdit({ ...hubUrlEdit, primary: e.target.value })}
							placeholder="http://10.10.0.1:3300"
						/>
						<input
							type="url"
							className="form-control form-control-sm"
							style={{ maxWidth: 360 }}
							value={hubUrlEdit.fallback}
							onChange={(e) => setHubUrlEdit({ ...hubUrlEdit, fallback: e.target.value })}
							placeholder="https://proxy.comnic.de"
						/>
						<div className="d-flex gap-2 align-items-center">
							<button
								type="button"
								className="btn btn-sm btn-primary"
								disabled={setSetting.isPending || hubUrlInvalid}
								onClick={handleSaveHubUrl}
							>
								{intl.formatMessage({ id: "save" })}
							</button>
							<button
								type="button"
								className="btn btn-sm btn-outline-secondary"
								onClick={() => setHubUrlEdit(null)}
							>
								{intl.formatMessage({ id: "cancel" })}
							</button>
							{hubUrlInvalid && (
								<span className="small text-danger">
									{intl.formatMessage({ id: "wireguard.agent.hub-url-invalid" })}
								</span>
							)}
						</div>
					</div>
				)}
				<div className="form-text small">{intl.formatMessage({ id: "wireguard.agent.hub-url-hint" })}</div>
			</div>

			{!agent && (
				<div className="text-secondary small">
					{createAgent.isPending
						? intl.formatMessage({ id: "wireguard.agent.creating" })
						: intl.formatMessage({ id: "wireguard.agent.not-found" })}
				</div>
			)}

			{agent && (
				<>
					{/* Status row — only shown when active */}
					{agent.status === "active" && (
						<div className="d-flex flex-wrap gap-3 mb-3">
							<div className="small">
								<span className="text-secondary me-1">
									{intl.formatMessage({ id: "wireguard.agent.host" })}
								</span>
								{agent.hostname ?? "—"}
							</div>
							{agent.lastSeen && (
								<div className="small">
									<span className="text-secondary me-1">
										{intl.formatMessage({ id: "wireguard.agent.last-seen" })}
									</span>
									{timeAgo(agent.lastSeen)}
								</div>
							)}
							{agent.agentVersion && (
								<div className="small">
									<span className="text-secondary me-1">
										{intl.formatMessage({ id: "wireguard.agent.version" })}
									</span>
									v{agent.agentVersion}
								</div>
							)}
							{agent.services && agent.services.length > 0
								? agent.services.map((svc) => (
										<div key={svc.url} className="small">
											<a
												href={svc.url}
												target="_blank"
												rel="noopener noreferrer"
												className="btn btn-sm btn-outline-success py-0 px-2"
											>
												{svc.name} ↗
											</a>
										</div>
									))
								: agent.mgmtUrl && (
										<div className="small">
											<a
												href={agent.mgmtUrl}
												target="_blank"
												rel="noopener noreferrer"
												className="btn btn-sm btn-outline-success py-0 px-2"
											>
												{intl.formatMessage({ id: "action.open" })} ↗
											</a>
										</div>
									)}
						</div>
					)}

					{/* Pending: show install hint */}
					{agent.status === "pending" && (
						<div className="alert alert-warning py-2 px-3 small mb-3">
							{intl.formatMessage({ id: "wireguard.agent.not-installed" })}
						</div>
					)}

					{/* Management URL — only show when a URL is actually set */}
					{agent.status === "active" && agent.mgmtUrl && (
						<div className="mb-3">
							{mgmtUrlEdit === null ? (
								<div className="d-flex align-items-center gap-2">
									<span className="small text-secondary">
										{intl.formatMessage({ id: "wireguard.agent.mgmt-url" })}
									</span>
									<span className="small">{agent.mgmtUrl}</span>
									<button
										type="button"
										className="btn btn-sm btn-link p-0 small"
										onClick={() => setMgmtUrlEdit(agent.mgmtUrl ?? "")}
									>
										{intl.formatMessage({ id: "wireguard.agent.change" })}
									</button>
								</div>
							) : (
								<div className="d-flex align-items-center gap-2">
									<input
										type="url"
										className="form-control form-control-sm"
										style={{ maxWidth: 320 }}
										value={mgmtUrlEdit}
										onChange={(e) => setMgmtUrlEdit(e.target.value)}
										placeholder="http://192.168.10.7:8080"
									/>
									<button
										type="button"
										className="btn btn-sm btn-primary"
										disabled={updateAgent.isPending}
										onClick={() => handleSaveMgmtUrl(agent.id)}
									>
										{intl.formatMessage({ id: "save" })}
									</button>
									<button
										type="button"
										className="btn btn-sm btn-outline-secondary"
										onClick={() => setMgmtUrlEdit(null)}
									>
										{intl.formatMessage({ id: "cancel" })}
									</button>
								</div>
							)}
						</div>
					)}

					{/* Network ACL — which remote subnets this agent may reach via the hub */}
					{agent.status === "active" && (
						<div className="mb-3">
							{aclEdit === null ? (
								<div className="d-flex align-items-center gap-2 flex-wrap">
									<span className="small text-secondary">
										{intl.formatMessage({ id: "wireguard.agent.allowed-networks" })}
									</span>
									<span className="small">
										{agent.allowedNetworks && agent.allowedNetworks.length > 0
											? agent.allowedNetworks.join(", ")
											: intl.formatMessage({ id: "wireguard.agent.allowed-networks-all" })}
									</span>
									<button
										type="button"
										className="btn btn-sm btn-link p-0 small"
										onClick={() => setAclEdit((agent.allowedNetworks ?? []).join(", "))}
									>
										{intl.formatMessage({ id: "wireguard.agent.change" })}
									</button>
								</div>
							) : (
								<div className="d-flex align-items-start gap-2 flex-wrap">
									<input
										type="text"
										className="form-control form-control-sm"
										style={{ maxWidth: 360 }}
										value={aclEdit}
										onChange={(e) => setAclEdit(e.target.value)}
										placeholder="192.168.10.0/24, 192.168.11.0/24"
									/>
									<button
										type="button"
										className="btn btn-sm btn-primary"
										disabled={updateAgent.isPending}
										onClick={() => handleSaveAcl(agent.id)}
									>
										{intl.formatMessage({ id: "save" })}
									</button>
									<button
										type="button"
										className="btn btn-sm btn-outline-secondary"
										onClick={() => setAclEdit(null)}
									>
										{intl.formatMessage({ id: "cancel" })}
									</button>
								</div>
							)}
							<div className="form-text small">
								{intl.formatMessage({ id: "wireguard.agent.allowed-networks-hint" })}
							</div>
						</div>
					)}

					{/* Reinstall toggle — only shown when active */}
					{agent.status === "active" && !showReinstall && (
						<button
							type="button"
							className="btn btn-sm btn-outline-secondary mb-2"
							disabled={resetLoading}
							onClick={() => handleResetToken(agent.id)}
						>
							{resetLoading
								? intl.formatMessage({ id: "wireguard.agent.renewing-token" })
								: intl.formatMessage({ id: "wireguard.agent.reinstall" })}
						</button>
					)}

					{/* Install one-liner — always shown when pending, toggled when active */}
					{(agent.status !== "active" || showReinstall) &&
						(() => {
							const regToken = agent.regToken;
							const oneliner =
								regToken && publicUrl.trim() && tunnelUrl.trim()
									? buildInstallOneliner(regToken, publicUrl.trim(), tunnelUrl.trim())
									: null;
							return (
								<>
									<div className="row g-2 mb-2">
										<div className="col-md-6">
											<label className="form-label mb-1 small">
												{intl.formatMessage({ id: "wireguard.agent.public-url-label" })}
												<input
													type="url"
													className="form-control form-control-sm"
													value={publicUrl}
													onChange={(e) => setPublicUrl(e.target.value)}
													placeholder="https://hub.example.com"
												/>
											</label>
										</div>
										<div className="col-md-6">
											<label className="form-label mb-1 small">
												{intl.formatMessage({ id: "wireguard.agent.tunnel-url-label" })}
												<input
													type="url"
													className="form-control form-control-sm"
													value={tunnelUrl}
													onChange={(e) => setTunnelUrl(e.target.value)}
													placeholder="http://10.10.0.1:3300"
												/>
											</label>
										</div>
									</div>
									{oneliner ? (
										<div className="d-flex align-items-center gap-2">
											<code
												className="flex-grow-1 text-truncate small bg-dark text-white px-2 py-1 rounded"
											>
												{oneliner}
											</code>
											<button
												className="btn btn-sm btn-outline-secondary flex-shrink-0"
												type="button"
												onClick={() => handleCopy(oneliner)}
											>
												{copied
													? intl.formatMessage({ id: "wireguard.agent.copied" })
													: intl.formatMessage({ id: "wireguard.agent.copy" })}
											</button>
											{agent.status === "active" && (
												<button
													className="btn btn-sm btn-ghost-secondary flex-shrink-0"
													type="button"
													onClick={() => setShowReinstall(false)}
												>
													{intl.formatMessage({ id: "action.close" })}
												</button>
											)}
										</div>
									) : (
										<div className="text-secondary small">
											{intl.formatMessage({ id: "wireguard.agent.no-token" })}
										</div>
									)}
								</>
							);
						})()}
				</>
			)}
		</div>
	);
}

// ── Link Card ──────────────────────────────────────────────────────────────────

interface EnhancedInterface extends WireGuardInterface {
	exportedNetworks: string[];
	importedNetworks: string[];
	routeTargets: string[];
	notes: string[];
}

interface LinkCardProps {
	link: WireGuardLink;
	missingReturnRoutes: WireGuardRouteHint[];
	natCandidates: WireGuardRouteHint[];
	planningInterfaces: EnhancedInterface[];
	agents: Agent[];
}

function LinkCard({ link, missingReturnRoutes, natCandidates, planningInterfaces, agents }: LinkCardProps) {
	const [editorOpen, setEditorOpen] = useState(false);
	const [plannerOpen, setPlannerOpen] = useState(false);
	const [agentOpen, setAgentOpen] = useState(false);
	const [downloading, setDownloading] = useState(false);

	// Editor state
	const [draftName, setDraftName] = useState("");
	const [draftImported, setDraftImported] = useState("");
	const [draftExported, setDraftExported] = useState("");
	const [draftMgmt, setDraftMgmt] = useState<WireGuardRemoteManagementMode>("none");
	const [draftReturn, setDraftReturn] = useState<WireGuardReturnPathMode>("auto");
	const [draftDns, setDraftDns] = useState("");
	const [draftFullTunnel, setDraftFullTunnel] = useState(false);
	const [draftType, setDraftType] = useState<WireGuardLinkType>("client");
	const [draftPlatform, setDraftPlatform] = useState<"desktop" | "mobile">("desktop");
	// Planner state
	const [planExported, setPlanExported] = useState("");
	const [planImported, setPlanImported] = useState("");
	const [planReturn, setPlanReturn] = useState<WireGuardReturnPathMode>("auto");
	const [planMgmt, setPlanMgmt] = useState<WireGuardRemoteManagementMode>("none");
	const [planIntent, setPlanIntent] = useState("unknown");

	const applyMetadata = useApplyWireGuardMetadata();

	const tb = typeBadge(link.type);
	const pb = planBadge(link.planState);
	const missingReturn = hasRouteHint(link, missingReturnRoutes);
	const natCandidate = hasRouteHint(link, natCandidates);

	// Match agent by wgLinkName first, then by name, then by tunnel IP
	const matchedAgent =
		agents.find((a) => a.wgLinkName === link.name) ??
		agents.find((a) => a.name === link.name) ??
		agents.find((a) =>
			link.tunnelAddresses.some((addr) => {
				const ip = addr.replace(/\/\d+$/, "");
				return (a.hostname ?? "").includes(ip) || a.name.includes(ip);
			}),
		);
	const agentServices = matchedAgent?.status === "active" ? (matchedAgent.services ?? []) : [];

	const openEditor = () => {
		setDraftName(link.name);
		setDraftImported(link.importedNetworks.join(", "));
		setDraftExported(link.exportedNetworks.join(", "));
		setDraftMgmt(link.remoteManagementMode || "none");
		setDraftReturn(link.returnPathMode || "auto");
		setDraftDns((link.dns || []).join(", "));
		setDraftFullTunnel(Boolean(link.fullTunnel));
		setDraftType(link.type);
		setDraftPlatform(link.platform || "desktop");
		setEditorOpen(true);
		setPlannerOpen(false);
	};

	const openPlanner = () => {
		const iface = planningInterfaces.find((i) => i.name === link.interfaceName);
		setPlanExported(
			(link.exportedNetworks.length ? link.exportedNetworks : (iface?.exportedNetworks ?? [])).join(", "),
		);
		setPlanImported(link.importedNetworks.join(", "));
		setPlanReturn(link.returnPathMode || "auto");
		setPlanMgmt(link.remoteManagementMode || "none");
		setPlanIntent(link.planIntent || link.type || "unknown");
		setPlannerOpen(true);
		setEditorOpen(false);
	};

	// Only include fields that actually changed — avoids triggering metadata-with-config-intent
	// for unchanged config-relevant fields whose stored value is simply undefined (default).
	const editorLinkPatch: Record<string, unknown> = {};
	const trimmedName = draftName.trim();
	if (trimmedName !== (link.name || "")) editorLinkPatch.name = trimmedName || undefined;
	const draftImportedArr = splitCsv(draftImported);
	if (draftImportedArr.join(",") !== (link.importedNetworks || []).join(","))
		editorLinkPatch.importedNetworks = draftImportedArr;
	const draftExportedArr = splitCsv(draftExported);
	if (draftExportedArr.join(",") !== (link.exportedNetworks || []).join(","))
		editorLinkPatch.exportedNetworks = draftExportedArr;
	if (draftMgmt !== (link.remoteManagementMode || "none")) editorLinkPatch.remoteManagementMode = draftMgmt;
	if (draftReturn !== (link.returnPathMode || "auto")) editorLinkPatch.returnPathMode = draftReturn;
	const draftDnsArr = splitCsv(draftDns);
	if (draftDnsArr.join(",") !== (link.dns || []).join(",")) editorLinkPatch.dns = draftDnsArr;
	if (draftFullTunnel !== Boolean(link.fullTunnel)) editorLinkPatch.fullTunnel = draftFullTunnel;
	if (draftType !== link.type) editorLinkPatch.type = draftType;
	if (draftPlatform !== (link.platform || "desktop")) editorLinkPatch.platform = draftPlatform;

	const editorPatch: WireGuardMetadataPatch = {
		links: { [link.id]: editorLinkPatch },
	};
	const plannerPatch: WireGuardMetadataPatch = {
		links: {
			[link.id]: {
				type: planIntent as WireGuardLink["type"],
				exportedNetworks: splitCsv(planExported),
				importedNetworks: splitCsv(planImported),
				returnPathMode: planReturn,
				remoteManagementMode: planMgmt,
				planIntent,
			},
		},
	};
	return (
		<div className={`card ${styles.linkCard}`}>
			{/* Card header */}
			<div className="card-header d-flex align-items-center gap-3">
				<div className="flex-grow-1 overflow-hidden">
					<div className="fw-bold text-truncate">{link.name}</div>
					<div className="text-secondary small text-truncate">
						{link.interfaceName} ·{" "}
						{link.remoteEndpoint || intl.formatMessage({ id: "wireguard.link.endpoint-unknown" })} ·{" "}
						{intl.formatMessage({ id: "wireguard.link.last-handshake" })} {timeAgo(link.latestHandshake)}
					</div>
				</div>
				<div className="d-flex align-items-center gap-2 flex-shrink-0">
					<span className={`badge ${tb.cls}`}>{tb.label}</span>
					<span
						className={`badge ${link.active ? "bg-green-lt text-green" : "bg-secondary-lt text-secondary"}`}
					>
						{link.active
							? intl.formatMessage({ id: "wireguard.link.active" })
							: intl.formatMessage({ id: "wireguard.link.inactive" })}
					</span>
					<span className={`badge ${pb.cls}`}>{pb.label}</span>
					{link.platform && (
						<span className="badge bg-azure-lt text-azure">
							{link.platform === "mobile" ? "Mobile" : "Desktop"}
						</span>
					)}
					{missingReturn && (
						<span className="badge bg-red-lt text-red">
							{intl.formatMessage({ id: "wireguard.link.missing-return" })}
						</span>
					)}
					{natCandidate && (
						<span className="badge bg-yellow-lt text-yellow">
							{intl.formatMessage({ id: "wireguard.link.nat-candidate" })}
						</span>
					)}
				</div>
			</div>

			{/* Card body */}
			<div className="card-body py-2">
				<div className="d-flex flex-wrap gap-4 mb-2">
					<div className="small">
						<span className="text-secondary me-1">
							{intl.formatMessage({ id: "wireguard.link.traffic" })}
						</span>
						{byteFmt(link.rxBytes)} rx / {byteFmt(link.txBytes)} tx
					</div>
					<div className="small">
						<span className="text-secondary me-1">
							{intl.formatMessage({ id: "wireguard.link.return-path" })}
						</span>
						{link.returnPathMode}
					</div>
					<div className="small">
						<span className="text-secondary me-1">
							{intl.formatMessage({ id: "wireguard.link.management" })}
						</span>
						{link.remoteManagementMode}
					</div>
					{link.tunnelAddresses.length > 0 && (
						<div className="small">
							<span className="text-secondary me-1">
								{intl.formatMessage({ id: "wireguard.link.tunnel" })}
							</span>
							{link.tunnelAddresses.join(", ")}
						</div>
					)}
				</div>

				{link.exportedNetworks.length > 0 && (
					<div className="d-flex flex-wrap gap-1 align-items-center mb-1">
						<span className="text-secondary small me-1">
							{intl.formatMessage({ id: "wireguard.link.export" })}
						</span>
						{link.exportedNetworks.map((n) => (
							<span key={n} className="badge bg-azure-lt text-azure">
								{n}
							</span>
						))}
					</div>
				)}
				{link.importedNetworks.length > 0 && (
					<div className="d-flex flex-wrap gap-1 align-items-center mb-1">
						<span className="text-secondary small me-1">
							{intl.formatMessage({ id: "wireguard.link.import" })}
						</span>
						{link.importedNetworks.map((n) => (
							<span key={n} className="badge bg-blue-lt text-blue">
								{n}
							</span>
						))}
					</div>
				)}
				{link.warnings.length > 0 && (
					<div className="mt-2">
						{link.warnings.slice(0, 2).map((w) => (
							<div key={w} className="small text-warning">
								⚠ {fmtWarning(w)}
							</div>
						))}
					</div>
				)}

				{matchedAgent?.status === "active" && matchedAgent.agentVersion && (
					<div className="d-flex flex-wrap gap-2 align-items-center mt-2">
						<span className="badge bg-secondary-lt" title={intl.formatMessage({ id: "wireguard.agent.version" })}>
							Agent v{matchedAgent.agentVersion}
						</span>
					</div>
				)}

				{agentServices.length > 0 && (
					<div className="d-flex flex-wrap gap-1 align-items-center mt-2 mb-1">
						<span className="text-secondary small me-1">
							{intl.formatMessage({ id: "wireguard.link.apps" })}
						</span>
						{agentServices.map((svc) => (
							<a
								key={svc.url}
								href={svc.url}
								target="_blank"
								rel="noopener noreferrer"
								className="btn btn-sm btn-outline-success"
								title={svc.url}
							>
								{svc.name} ↗
							</a>
						))}
					</div>
				)}

				<div className="d-flex gap-2 mt-3">
					<button
						className={`btn btn-sm ${editorOpen ? "btn-primary" : "btn-outline-primary"}`}
						type="button"
						onClick={() => {
							if (editorOpen) {
								setEditorOpen(false);
							} else {
								openEditor();
							}
						}}
					>
						{editorOpen
							? intl.formatMessage({ id: "wireguard.link.close-editor" })
							: intl.formatMessage({ id: "wireguard.link.edit-metadata" })}
					</button>
					<button
						className={`btn btn-sm ${plannerOpen ? "btn-secondary" : "btn-outline-secondary"}`}
						type="button"
						onClick={() => {
							if (plannerOpen) {
								setPlannerOpen(false);
							} else {
								openPlanner();
							}
						}}
					>
						{plannerOpen
							? intl.formatMessage({ id: "wireguard.link.close-planner" })
							: intl.formatMessage({ id: "wireguard.link.plan-link" })}
					</button>
					{link.remoteManagementMode === "agent" && (
						<button
							className={`btn btn-sm ${agentOpen ? "btn-purple" : "btn-outline-purple"}`}
							type="button"
							onClick={() => setAgentOpen((v) => !v)}
						>
							{agentOpen ? intl.formatMessage({ id: "wireguard.link.close-agent" }) : "Agent"}
						</button>
					)}
					<button
						className="btn btn-sm btn-outline-secondary ms-auto"
						type="button"
						disabled={downloading}
						onClick={async () => {
							setDownloading(true);
							try {
								const filename = `${(link.name || link.id).replace(/[^\w.-]/g, "_")}.conf`;
								await downloadWireGuardLinkConfig(link.id, filename);
							} finally {
								setDownloading(false);
							}
						}}
					>
						{downloading ? "…" : intl.formatMessage({ id: "wireguard.link.download-config" })}
					</button>
					<button
						className="btn btn-sm btn-outline-secondary"
						type="button"
						onClick={() => showWireGuardQrModal(link.id, link.name || link.id)}
					>
						{intl.formatMessage({ id: "wireguard.link.show-qr" })}
					</button>
					<button
						className="btn btn-sm btn-outline-danger"
						type="button"
						onClick={() =>
							showDeleteConfirmModal({
								title: intl.formatMessage({ id: "wireguard.link.delete-title" }),
								onConfirm: async () => {
									await deleteWireGuardPeer({ linkId: link.id });
								},
								invalidations: [
									["wireguard-status"],
									["wireguard-metadata"],
									["wireguard-bandwidth"],
									["wireguard-apply-state"],
								],
								children: intl.formatMessage(
									{ id: "wireguard.link.delete-confirm" },
									{ name: link.name || link.id },
								),
							})
						}
					>
						{intl.formatMessage({ id: "wireguard.link.delete" })}
					</button>
				</div>
			</div>

			{/* Agent section */}
			{agentOpen && link.remoteManagementMode === "agent" && <AgentSection link={link} agents={agents} />}

			{/* Inline metadata editor */}
			{editorOpen && (
				<div className={styles.inlineSection}>
					<div className="fw-medium mb-3 small text-uppercase text-secondary">
						{intl.formatMessage({ id: "wireguard.link.metadata-editor" })} — {link.name}
					</div>
					<div className="row g-3">
						<div className="col-12">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.link.display-name" })}
								<input
									type="text"
									className="form-control"
									value={draftName}
									onChange={(e) => setDraftName(e.target.value)}
									placeholder={link.id}
								/>
								<div className="form-hint">
									{intl.formatMessage({ id: "wireguard.link.display-name-hint" })}
								</div>
							</label>
						</div>
						<div className="col-md-4">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.link.imported-networks" })}
								<textarea
									className="form-control"
									rows={3}
									value={draftImported}
									onChange={(e) => setDraftImported(e.target.value)}
									placeholder="192.168.10.0/24, ..."
								/>
								<div className="form-hint">
									{intl.formatMessage({ id: "wireguard.link.imported-networks-hint" })}
								</div>
							</label>
						</div>
						<div className="col-md-4">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.link.exported-networks" })}
								<textarea
									className="form-control"
									rows={3}
									value={draftExported}
									onChange={(e) => setDraftExported(e.target.value)}
									placeholder="192.168.10.0/24, ..."
								/>
								<div className="form-hint">
									{intl.formatMessage({ id: "wireguard.link.exported-networks-hint" })}
								</div>
							</label>
						</div>
						<div className="col-md-4">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.create.type" })}
								<select
									className="form-select"
									value={draftType}
									onChange={(e) => setDraftType(e.target.value as WireGuardLinkType)}
								>
									<option value="client">Client</option>
									<option value="site-to-site">Site-to-Site</option>
									<option value="hub-link">Hub-Link</option>
								</select>
							</label>
						</div>
						<div className="col-md-4">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.link.remote-management" })}
								<select
									className="form-select"
									value={draftMgmt}
									onChange={(e) => setDraftMgmt(parseMgmt(e.target.value))}
								>
									<option value="none">
										{intl.formatMessage({ id: "wireguard.link.mgmt-none" })}
									</option>
									<option value="ssh">ssh</option>
									<option value="agent">agent</option>
								</select>
							</label>
						</div>
						<div className="col-md-4">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.link.return-mode" })}
								<select
									className="form-select"
									value={draftReturn}
									onChange={(e) => setDraftReturn(parseReturn(e.target.value))}
								>
									<option value="auto">auto</option>
									<option value="static-route">static-route</option>
									<option value="nat">nat</option>
								</select>
							</label>
						</div>
						<div className="col-md-4">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.field.dns" })}
								<input
									type="text"
									className="form-control"
									value={draftDns}
									onChange={(e) => setDraftDns(e.target.value)}
									placeholder="10.10.0.1, 1.1.1.1"
								/>
							</label>
						</div>
						{draftType === "client" && (
							<div className="col-md-4">
								<label className="form-label">
									{intl.formatMessage({ id: "wireguard.create.platform" })}
									<select
										className="form-select"
										value={draftPlatform}
										onChange={(e) => setDraftPlatform(e.target.value as "desktop" | "mobile")}
									>
										<option value="desktop">{intl.formatMessage({ id: "wireguard.create.platform-desktop" })}</option>
										<option value="mobile">{intl.formatMessage({ id: "wireguard.create.platform-mobile" })}</option>
									</select>
								</label>
							</div>
						)}
						{draftType === "client" && (
							<div className="col-md-4 d-flex align-items-end pb-1">
								<label className="form-check form-switch">
									<input
										type="checkbox"
										className="form-check-input"
										checked={draftFullTunnel}
										onChange={(e) => setDraftFullTunnel(e.target.checked)}
									/>
									<span className="form-check-label">{intl.formatMessage({ id: "wireguard.field.full-tunnel" })}</span>
								</label>
							</div>
						)}
					</div>
					<div className="d-flex gap-2 mt-3">
						<button
							className="btn btn-sm btn-primary"
							type="button"
							disabled={applyMetadata.isPending || Object.keys(editorLinkPatch).length === 0}
							onClick={() => {
								applyMetadata.mutate(editorPatch, {
									onSuccess: () => setEditorOpen(false),
								});
							}}
						>
							{applyMetadata.isPending
								? intl.formatMessage({ id: "wireguard.iface.saving" })
								: intl.formatMessage({ id: "save" })}
						</button>
						<button
							className="btn btn-sm btn-ghost-secondary"
							type="button"
							onClick={() => setEditorOpen(false)}
						>
							{intl.formatMessage({ id: "cancel" })}
						</button>
					</div>
					{applyMetadata.isSuccess && applyMetadata.data && <ApplySyncResult data={applyMetadata.data} />}
					{applyMetadata.isError && (
						<div className="alert alert-danger mt-2 mb-0 py-2 small">
							{intl.formatMessage({ id: "wireguard.link.save-failed" })}
						</div>
					)}
				</div>
			)}

			{/* Inline link planner */}
			{plannerOpen && (
				<div className={styles.inlineSection}>
					<div className="fw-medium mb-3 small text-uppercase text-secondary">
						{intl.formatMessage({ id: "wireguard.link.planner" })} — {link.name}
					</div>
					<div className="row g-3">
						<div className="col-md-3">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.link.connection-type" })}
								<select
									className="form-select"
									value={planIntent}
									onChange={(e) => setPlanIntent(e.target.value)}
								>
									{["site-to-site", "hub-link", "client", "imported", "unknown"].map((o) => (
										<option key={o} value={o}>
											{o}
										</option>
									))}
								</select>
							</label>
						</div>
						<div className="col-md-3">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.link.export-local-networks" })}
								<textarea
									className="form-control"
									rows={3}
									value={planExported}
									onChange={(e) => setPlanExported(e.target.value)}
									placeholder="192.168.10.0/24, ..."
								/>
							</label>
						</div>
						<div className="col-md-3">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.link.import-remote-networks" })}
								<textarea
									className="form-control"
									rows={3}
									value={planImported}
									onChange={(e) => setPlanImported(e.target.value)}
									placeholder="192.168.200.0/24, ..."
								/>
							</label>
						</div>
						<div className="col-md-3">
							<label className="form-label">
								{intl.formatMessage({ id: "wireguard.link.return-mode" })}
								<select
									className="form-select"
									value={planReturn}
									onChange={(e) => setPlanReturn(parseReturn(e.target.value))}
								>
									<option value="auto">auto</option>
									<option value="static-route">static-route</option>
									<option value="nat">nat</option>
								</select>
							</label>
							<label className="form-label mt-2">
								{intl.formatMessage({ id: "wireguard.link.remote-management" })}
								<select
									className="form-select"
									value={planMgmt}
									onChange={(e) => setPlanMgmt(parseMgmt(e.target.value))}
								>
									<option value="none">
										{intl.formatMessage({ id: "wireguard.link.mgmt-none" })}
									</option>
									<option value="ssh">ssh</option>
									<option value="agent">agent</option>
								</select>
							</label>
						</div>
					</div>
					<div className="d-flex gap-2 mt-3">
						<button
							className="btn btn-sm btn-primary"
							type="button"
							disabled={applyMetadata.isPending}
							onClick={() => {
								applyMetadata.mutate(plannerPatch, {
									onSuccess: () => {
										setPlannerOpen(false);
										if (planMgmt === "agent") setAgentOpen(true);
									},
								});
							}}
						>
							{applyMetadata.isPending
								? intl.formatMessage({ id: "wireguard.iface.saving" })
								: intl.formatMessage({ id: "wireguard.link.save-plan" })}
						</button>
						<button
							className="btn btn-sm btn-ghost-secondary"
							type="button"
							onClick={() => setPlannerOpen(false)}
						>
							{intl.formatMessage({ id: "cancel" })}
						</button>
					</div>
					{applyMetadata.isSuccess && applyMetadata.data && <ApplySyncResult data={applyMetadata.data} />}
				</div>
			)}
		</div>
	);
}

// ── Interface Card ─────────────────────────────────────────────────────────────

function InterfaceCard({ iface, allLinks }: { iface: EnhancedInterface; allLinks: WireGuardLink[] }) {
	const [editorOpen, setEditorOpen] = useState(false);
	const [draftRole, setDraftRole] = useState<WireGuardInterfaceRole>("unknown");
	const [draftMgmt, setDraftMgmt] = useState<WireGuardManagementMode>("local");
	const [draftExported, setDraftExported] = useState("");
	const [draftImported, setDraftImported] = useState("");
	const [draftRouteTargets, setDraftRouteTargets] = useState("");
	const [draftDns, setDraftDns] = useState("");
	const [draftNotes, setDraftNotes] = useState("");
	const [preview, setPreview] = useState<WireGuardPlanPreviewResponse | null>(null);
	const [previewKey, setPreviewKey] = useState("");

	const applyMetadata = useApplyWireGuardMetadata();
	const previewPlan = usePreviewWireGuardPlan();

	const ifaceLinks = allLinks.filter((l) => l.interfaceName === iface.name);

	const openEditor = () => {
		setDraftRole(iface.role || "unknown");
		setDraftMgmt(iface.managementMode || "local");
		setDraftExported(iface.exportedNetworks.join(", "));
		setDraftImported(iface.importedNetworks.join(", "));
		setDraftRouteTargets(iface.routeTargets.join(", "));
		setDraftDns((iface.dns || []).join(", "));
		setDraftNotes(iface.notes.join(", "));
		setPreview(null);
		setPreviewKey("");
		setEditorOpen(true);
	};

	const patch: WireGuardMetadataPatch = {
		interfaces: {
			[iface.name]: {
				role: draftRole,
				managementMode: draftMgmt,
				exportedNetworks: splitCsv(draftExported),
				importedNetworks: splitCsv(draftImported),
				routeTargets: splitCsv(draftRouteTargets),
				dns: splitCsv(draftDns),
				notes: splitCsv(draftNotes),
			},
		},
	};
	const patchKey = JSON.stringify(patch);
	const previewCurrent = Boolean(preview && previewKey === patchKey);

	return (
		<div className={styles.ifaceCard} style={{ display: "flex", flexDirection: "column" }}>
			<div className={styles.ifaceCardHeader}>
				<div>
					<div className="fw-bold">{iface.name}</div>
					<div className="text-secondary small">
						{iface.addresses.join(", ") || intl.formatMessage({ id: "wireguard.iface.no-addresses" })}
					</div>
				</div>
				<div className="d-flex gap-1 align-items-center">
					<span
						className={`badge ${iface.active ? "bg-green-lt text-green" : "bg-secondary-lt text-secondary"}`}
					>
						{iface.active
							? intl.formatMessage({ id: "wireguard.link.active" })
							: intl.formatMessage({ id: "wireguard.link.inactive" })}
					</span>
					<span className={`badge ${ifaceHealthBadge(iface.health)}`}>
						{iface.health || intl.formatMessage({ id: "wireguard.iface.unknown" })}
					</span>
					<span className="badge bg-secondary-lt text-secondary">
						{iface.role || intl.formatMessage({ id: "wireguard.iface.unknown" })}
					</span>
				</div>
			</div>

			<div className={styles.ifaceCardBody} style={{ flex: 1, display: "flex", flexDirection: "column", gap: "0.5rem" }}>
				<div className="small">
					<span className="text-secondary me-1">
						{intl.formatMessage({ id: "wireguard.iface.peers" })}
					</span>
					{iface.activePeerCount} {intl.formatMessage({ id: "wireguard.link.active" })} / {iface.peerCount}
				</div>
				<div className="small">
					<span className="text-secondary me-1">
						{intl.formatMessage({ id: "wireguard.link.traffic" })}
					</span>
					{byteFmt(iface.rxBytes)} rx / {byteFmt(iface.txBytes)} tx
				</div>
				<div className="small">
					<span className="text-secondary me-1">Port</span>
					{iface.listenPort || "—"}
				</div>
				<div className="small text-truncate">
					<span className="text-secondary me-1">{intl.formatMessage({ id: "wireguard.iface.key" })}</span>
					{shortKey(iface.publicKey)}
				</div>
				<div className="small">
					<span className="text-secondary me-1">
						{intl.formatMessage({ id: "wireguard.link.export" })}
					</span>
					{iface.exportedNetworks.length > 0
						? iface.exportedNetworks.slice(0, 4).map((n) => (
								<span key={n} className="badge bg-azure-lt text-azure me-1">
									{n}
								</span>
							))
						: "—"}
				</div>
				<div className="small">
					<span className="text-secondary me-1">
						{intl.formatMessage({ id: "wireguard.tab.links" })}
					</span>
					{ifaceLinks.length > 0
						? ifaceLinks.map((l) => (
								<span key={l.id} className={`badge ${typeBadge(l.type).cls} me-1`}>
									{l.name}
								</span>
							))
						: "—"}
				</div>
			</div>

			<div className="d-flex gap-2 px-3 pb-3">
				<button
					className="btn btn-sm btn-outline-primary"
					type="button"
					onClick={() => {
						if (editorOpen) {
							setEditorOpen(false);
						} else {
							openEditor();
						}
					}}
				>
					{editorOpen
						? intl.formatMessage({ id: "action.close" })
						: intl.formatMessage({ id: "action.edit" })}
				</button>
				{!iface.isHub && (
					<button
						className="btn btn-sm btn-outline-danger"
						type="button"
						onClick={() =>
							showDeleteConfirmModal({
								title: intl.formatMessage({ id: "wireguard.iface.delete-title" }),
								onConfirm: async () => {
									await deleteWireGuardInterface({ name: iface.name });
								},
								invalidations: [
									["wireguard-status"],
									["wireguard-metadata"],
									["wireguard-bandwidth"],
								],
								children: intl.formatMessage(
									{ id: "wireguard.iface.delete-confirm" },
									{ name: iface.name },
								),
							})
						}
					>
						{intl.formatMessage({ id: "wireguard.link.delete" })}
					</button>
				)}
			</div>

			{editorOpen && (
				<div className={styles.inlineSection}>
					<div className={styles.editorHeader}>
						<span className={styles.editorTitle}>
							{intl.formatMessage({ id: "wireguard.iface.editor-title" })} — {iface.name}
						</span>
						<div className="d-flex gap-2">
							<button
								className="btn btn-sm btn-outline-primary"
								type="button"
								disabled={previewPlan.isPending}
								onClick={() => {
									previewPlan.mutate(patch, {
										onSuccess: (result) => {
											setPreview(result);
											setPreviewKey(patchKey);
										},
									});
								}}
							>
								{previewPlan.isPending
									? intl.formatMessage({ id: "wireguard.iface.preview-loading" })
									: intl.formatMessage({ id: "wireguard.iface.preview" })}
							</button>
							<button
								className="btn btn-sm btn-primary"
								type="button"
								disabled={
									applyMetadata.isPending || !preview?.valid || !preview.apply.canApply || !previewCurrent
								}
								onClick={() => {
									applyMetadata.mutate(patch, {
										onSuccess: () => {
											setEditorOpen(false);
											setPreview(null);
										},
									});
								}}
							>
								{applyMetadata.isPending
									? intl.formatMessage({ id: "wireguard.iface.saving" })
									: intl.formatMessage({ id: "save" })}
							</button>
							<button
								className="btn btn-sm btn-ghost-secondary"
								type="button"
								onClick={() => setEditorOpen(false)}
							>
								{intl.formatMessage({ id: "cancel" })}
							</button>
						</div>
					</div>

					<div className={styles.editorGrid}>
						<div className={styles.editorGroupWide}>
							<div className={styles.editorGroupLabel}>
								{intl.formatMessage({ id: "wireguard.iface.role" })} &amp; {intl.formatMessage({ id: "wireguard.link.management" })}
							</div>
							<div className="d-flex gap-3">
								<div style={{ flex: 1 }}>
									<label className="form-label small text-secondary mb-1">
										{intl.formatMessage({ id: "wireguard.iface.role" })}
									</label>
									<select
										className="form-select form-select-sm"
										value={draftRole}
										onChange={(e) => setDraftRole(parseIfaceRole(e.target.value))}
									>
										{(["client-hub", "site-to-site", "hub-link", "auxiliary", "unknown"] as const).map(
											(o) => (
												<option key={o} value={o}>
													{o}
												</option>
											),
										)}
									</select>
								</div>
								<div style={{ flex: 1 }}>
									<label className="form-label small text-secondary mb-1">
										{intl.formatMessage({ id: "wireguard.link.management" })}
									</label>
									<select
										className="form-select form-select-sm"
										value={draftMgmt}
										onChange={(e) => setDraftMgmt(parseIfaceMgmt(e.target.value))}
									>
										{(["local", "imported", "unknown"] as const).map((o) => (
											<option key={o} value={o}>
												{o}
											</option>
										))}
									</select>
								</div>
							</div>
						</div>

						<div className={styles.editorGroupWide}>
							<div className={styles.editorGroupLabel}>
								{intl.formatMessage({ id: "wireguard.link.exported-networks" })} / {intl.formatMessage({ id: "wireguard.link.imported-networks" })}
							</div>
							<div className="d-flex gap-3">
								<div style={{ flex: 1 }}>
									<label className="form-label small text-secondary mb-1">
										{intl.formatMessage({ id: "wireguard.link.export" })}
									</label>
									<textarea
										className="form-control form-control-sm font-monospace"
										rows={4}
										value={draftExported}
										onChange={(e) => setDraftExported(e.target.value)}
										placeholder="192.168.10.0/24, ..."
									/>
								</div>
								<div style={{ flex: 1 }}>
									<label className="form-label small text-secondary mb-1">
										{intl.formatMessage({ id: "wireguard.link.import" })}
									</label>
									<textarea
										className="form-control form-control-sm font-monospace"
										rows={4}
										value={draftImported}
										onChange={(e) => setDraftImported(e.target.value)}
										placeholder="10.10.10.0/24, ..."
									/>
								</div>
							</div>
						</div>

						<div className={styles.editorGroupWide}>
							<div className={styles.editorGroupLabel}>
								{intl.formatMessage({ id: "wireguard.iface.route-targets" })} &amp; DNS
							</div>
							<div className="d-flex gap-3">
								<div style={{ flex: 2 }}>
									<label className="form-label small text-secondary mb-1">
										{intl.formatMessage({ id: "wireguard.iface.route-targets" })}
									</label>
									<textarea
										className="form-control form-control-sm font-monospace"
										rows={2}
										value={draftRouteTargets}
										onChange={(e) => setDraftRouteTargets(e.target.value)}
										placeholder={intl.formatMessage({ id: "wireguard.iface.placeholder-routes" })}
									/>
								</div>
								<div style={{ flex: 1 }}>
									<label className="form-label small text-secondary mb-1">DNS</label>
									<textarea
										className="form-control form-control-sm font-monospace"
										rows={2}
										value={draftDns}
										onChange={(e) => setDraftDns(e.target.value)}
										placeholder="10.10.0.1, 1.1.1.1"
									/>
								</div>
							</div>
						</div>

						<div className={styles.editorGroupWide}>
							<div className={styles.editorGroupLabel}>
								{intl.formatMessage({ id: "wireguard.iface.notes" })}
							</div>
							<textarea
								className="form-control form-control-sm"
								rows={2}
								value={draftNotes}
								onChange={(e) => setDraftNotes(e.target.value)}
								placeholder={intl.formatMessage({ id: "wireguard.iface.placeholder-notes" })}
							/>
						</div>
					</div>

					{preview && <PreviewResult preview={preview} current={previewCurrent} />}
					{applyMetadata.isSuccess && applyMetadata.data && <ApplySyncResult data={applyMetadata.data} />}
					{applyMetadata.isError && (
						<div className="alert alert-danger mt-2 mb-0 py-2 small">
							{intl.formatMessage({ id: "wireguard.iface.save-failed" })}
						</div>
					)}
				</div>
			)}
		</div>
	);
}

// ── Routing Matrix ─────────────────────────────────────────────────────────────

// ── Create Interface Form ──────────────────────────────────────────────────────

function CreateInterfaceForm() {
	const [open, setOpen] = useState(false);
	const [name, setName] = useState("");
	const [address, setAddress] = useState("");
	const [listenPort, setListenPort] = useState("");
	const [pending, setPending] = useState(false);
	const [result, setResult] = useState<{ name: string; publicKey: string } | null>(null);
	const [error, setError] = useState("");
	const queryClient = useQueryClient();

	const onSubmit = async () => {
		setPending(true);
		setError("");
		try {
			const res = await createWireGuardInterface({
				name: name.trim() || undefined,
				address: address.trim(),
				listenPort: listenPort ? Number(listenPort) : undefined,
			});
			setResult(res);
			queryClient.invalidateQueries({ queryKey: ["wireguard-status"] });
			queryClient.invalidateQueries({ queryKey: ["wireguard-metadata"] });
		} catch (err: any) {
			setError(err?.message || "Failed to create interface");
		}
		setPending(false);
	};

	if (!open) {
		return (
			<button className="btn btn-sm btn-outline-primary mt-3" type="button" onClick={() => setOpen(true)}>
				<IconPlus size={14} className="me-1" />
				{intl.formatMessage({ id: "wireguard.iface.create" })}
			</button>
		);
	}

	if (result) {
		return (
			<div className="card mt-3">
				<div className="card-body">
					<div className="alert alert-success mb-2 py-2 small">
						{intl.formatMessage({ id: "wireguard.iface.created" }, { name: result.name })}
					</div>
					<div className="small text-secondary mb-2">
						{intl.formatMessage({ id: "wireguard.iface.public-key" })} <code>{result.publicKey}</code>
					</div>
					<button
						className="btn btn-sm btn-outline-secondary"
						type="button"
						onClick={() => {
							setOpen(false);
							setResult(null);
							setName("");
							setAddress("");
							setListenPort("");
						}}
					>
						{intl.formatMessage({ id: "action.close" })}
					</button>
				</div>
			</div>
		);
	}

	return (
		<div className="card mt-3">
			<div className="card-body">
				<div className="fw-medium mb-3 small text-uppercase text-secondary">
					{intl.formatMessage({ id: "wireguard.iface.create" })}
				</div>
				{error && <div className="alert alert-danger mb-2 py-2 small">{error}</div>}
				<div className="row g-3">
					<div className="col-md-3">
						<label className="form-label">
							{intl.formatMessage({ id: "wireguard.iface.name" })}
							<input
								type="text"
								className="form-control"
								value={name}
								onChange={(e) => setName(e.target.value)}
								placeholder="wg2"
							/>
						</label>
						<div className="form-text">{intl.formatMessage({ id: "wireguard.iface.name-hint" })}</div>
					</div>
					<div className="col-md-3">
						<label className="form-label">
							{intl.formatMessage({ id: "wireguard.iface.address" })}
							<input
								type="text"
								className="form-control"
								value={address}
								onChange={(e) => setAddress(e.target.value)}
								placeholder="10.20.0.1/24"
							/>
						</label>
					</div>
					<div className="col-md-3">
						<label className="form-label">
							{intl.formatMessage({ id: "wireguard.iface.port" })}
							<input
								type="number"
								className="form-control"
								value={listenPort}
								onChange={(e) => setListenPort(e.target.value)}
								placeholder={intl.formatMessage({ id: "wireguard.iface.port-hint" })}
							/>
						</label>
					</div>
				</div>
				<div className="d-flex gap-2 mt-3">
					<button
						className="btn btn-sm btn-primary"
						type="button"
						disabled={pending || !address.trim()}
						onClick={onSubmit}
					>
						{pending ? "…" : intl.formatMessage({ id: "wireguard.iface.create" })}
					</button>
					<button className="btn btn-sm btn-ghost-secondary" type="button" onClick={() => setOpen(false)}>
						{intl.formatMessage({ id: "cancel" })}
					</button>
				</div>
			</div>
		</div>
	);
}

function RoutingMatrix({ links }: { links: WireGuardLink[] }) {
	const allNetworks = Array.from(new Set(links.flatMap((l) => l.exportedNetworks))).sort();

	if (allNetworks.length === 0) {
		return (
			<div className="card">
				<div className="card-header">
					<h3 className="card-title">{intl.formatMessage({ id: "wireguard.routing.matrix-title" })}</h3>
				</div>
				<div className="card-body text-secondary small">
					{intl.formatMessage({ id: "wireguard.routing.matrix-no-networks" })}
				</div>
			</div>
		);
	}

	return (
		<div className="card">
			<div className="card-header">
				<h3 className="card-title">{intl.formatMessage({ id: "wireguard.routing.matrix-title" })}</h3>
				<span className="text-secondary small ms-2">
					{intl.formatMessage({ id: "wireguard.routing.matrix-hint" })}
				</span>
			</div>
			<div className="table-responsive">
				<table className="table table-vcenter card-table">
					<thead>
						<tr>
							<th>{intl.formatMessage({ id: "wireguard.routing.col-peer" })}</th>
							{allNetworks.map((net) => (
								<th key={net} className="text-center text-secondary small fw-normal">
									{net}
								</th>
							))}
						</tr>
					</thead>
					<tbody>
						{links.map((link) => (
							<tr key={link.id}>
								<td className="fw-medium">{link.name || link.id}</td>
								{allNetworks.map((net) => {
									const exports = link.exportedNetworks.includes(net);
									const imports = link.importedNetworks.includes(net);
									return (
										<td key={net} className="text-center">
											{exports ? (
												<span className="badge bg-azure-lt text-azure">
													{intl.formatMessage({ id: "wireguard.routing.matrix-exports" })}
												</span>
											) : imports ? (
												<span className="text-green fw-medium">✓</span>
											) : (
												<span className="text-secondary">—</span>
											)}
										</td>
									);
								})}
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</div>
	);
}

// ── Main Component ─────────────────────────────────────────────────────────────

type Tab = "overview" | "links" | "interfaces" | "routing";

const WireGuard = () => {
	const { data, isLoading, isError, error } = useWireGuardStatus();
	const applyState = useWireGuardApplyState();
	const restoreMetadata = useRestoreWireGuardMetadata();
	const agentsQuery = useAgents();
	const createPeer = useCreateWireGuardPeer();
	const [activeTab, setActiveTab] = useState<Tab>("overview");
	const [createOpen, setCreateOpen] = useState(false);
	const [newName, setNewName] = useState("");
	const [newType, setNewType] = useState<"client" | "site-to-site" | "hub-link">("client");
	const [newDns, setNewDns] = useState("");
	const [newFullTunnel, setNewFullTunnel] = useState(false);
	const [newPlatform, setNewPlatform] = useState<"desktop" | "mobile">("desktop");
	const [newImported, setNewImported] = useState("");
	const [newIfaceName, setNewIfaceName] = useState("wg0");
	const [createResult, setCreateResult] = useState<{
		filename: string;
		content: string;
		tunnelAddress: string;
	} | null>(null);

	if (isLoading) return <Loading />;
	if (isError)
		return (
			<div className="alert alert-danger">
				{intl.formatMessage({ id: "wireguard.status.load-error" }, { error: error.message })}
			</div>
		);
	if (!data?.available || !data.summary) {
		return (
			<div className="platform-page">
				<div className="platform-page-header">
					<div>
						<div className="platform-kicker">{intl.formatMessage({ id: "wireguard.page.kicker" })}</div>
						<h1 className="platform-title">WireGuard</h1>
					</div>
				</div>
				<div className="alert alert-warning">{intl.formatMessage({ id: "wireguard.status.unavailable" })}</div>
			</div>
		);
	}

	const summary = data.summary;
	const hub = data.hub;
	const links = data.links || [];
	const interfaces = data.interfaces;
	const missingReturnRoutes = data.routes?.missingReturnRoutes || [];
	const natCandidates = data.routes?.natCandidates || [];
	const nextActions = data.nextActions || [];
	const globalWarnings = (data.warnings || []) as (string | StructuredWarning)[];
	const conflictWarnings = globalWarnings.filter(
		(w) => isStructuredWarning(w) && w.code === "allowedips-conflict",
	) as StructuredWarning[];
	const activePeers = interfaces
		.flatMap((iface) => iface.peers.map((peer) => ({ ...peer, iface: iface.name })))
		.filter((peer) => peer.isActive);
	const backups = applyState.data?.backups || [];

	const planningInterfaces: EnhancedInterface[] = interfaces.map((iface) => ({
		...iface,
		exportedNetworks: iface.exportedNetworks ?? iface.peerNetworks ?? [],
		importedNetworks: iface.importedNetworks ?? [],
		routeTargets: iface.routeTargets ?? [],
		notes: iface.notes ?? [],
	}));

	const groupedLinks = {
		site: links.filter((l) => l.type === "site-to-site"),
		hub: links.filter((l) => l.type === "hub-link"),
		client: links.filter((l) => l.type === "client"),
		other: links.filter((l) => !["site-to-site", "hub-link", "client"].includes(l.type)),
	};

	const agents = agentsQuery.data ?? [];
	const linkCardProps = { missingReturnRoutes, natCandidates, planningInterfaces, agents };

	const renderLinks = (items: WireGuardLink[], label: string, badgeCls: string) => {
		if (items.length === 0) return null;
		return (
			<div className="mb-4">
				<div className="d-flex align-items-center gap-2 mb-3">
					<h3 className="m-0" style={{ fontSize: "1rem", fontWeight: 600 }}>
						{label}
					</h3>
					<span className={`badge ${badgeCls}`}>{items.length}</span>
				</div>
				<div className="d-flex flex-column gap-3">
					{items.map((link) => (
						<LinkCard key={link.id} link={link} {...linkCardProps} />
					))}
				</div>
			</div>
		);
	};

	return (
		<div className="platform-page">
			<div className="platform-page-header">
				<div>
					<div className="platform-kicker">{intl.formatMessage({ id: "wireguard.page.kicker" })}</div>
					<h1 className="platform-title">WireGuard</h1>
				</div>
				<div className="d-flex align-items-center gap-2">
					{interfaces.length > 1 ? (
						<select
							className="form-select form-select-sm"
							style={{ width: "auto" }}
							value={newIfaceName}
							onChange={(e) => setNewIfaceName(e.target.value)}
						>
							{interfaces.map((i) => (
								<option key={i.name} value={i.name}>
									{i.name}
								</option>
							))}
						</select>
					) : (
						<div className="text-secondary small">
							{hub?.name || intl.formatMessage({ id: "wireguard.hub.unknown" })}
						</div>
					)}
					<button
						type="button"
						className="btn btn-primary btn-sm d-flex align-items-center gap-1"
						onClick={() => {
							setCreateOpen(!createOpen);
							setCreateResult(null);
						}}
					>
						<IconPlus size={16} />
						{intl.formatMessage({ id: "wireguard.create.button" })}
					</button>
				</div>
			</div>

			{/* ── Create Tunnel Form ── */}
			{createOpen && (
				<div className="card platform-elevated-card">
					<div className="card-header">
						<h3 className="card-title">{intl.formatMessage({ id: "wireguard.create.title" })}</h3>
					</div>
					<div className="card-body">
						{createResult ? (
							<div>
								<div className="alert alert-success mb-3">
									{intl.formatMessage({ id: "wireguard.create.success" }, { name: newName, ip: createResult.tunnelAddress })}
								</div>
								<div className="mb-3">
									<label className="form-label fw-bold">Client-Config zum Download:</label>
									<pre
										className="bg-dark text-light p-3 rounded"
										style={{ fontSize: "0.78rem", maxHeight: 300, overflow: "auto" }}
									>
										{createResult.content}
									</pre>
								</div>
								<div className="d-flex gap-2">
									<button
										type="button"
										className="btn btn-sm btn-primary"
										onClick={() => {
											const blob = new Blob([createResult.content], { type: "text/plain" });
											const url = URL.createObjectURL(blob);
											const a = document.createElement("a");
											a.href = url;
											a.download = createResult.filename;
											a.click();
											URL.revokeObjectURL(url);
										}}
									>
										{intl.formatMessage({ id: "wireguard.create.download" })}
									</button>
									<button
										type="button"
										className="btn btn-sm btn-ghost-secondary"
										onClick={() => {
											setCreateOpen(false);
											setCreateResult(null);
											setNewName("");
											setNewDns("");
											setNewImported("");
											setNewFullTunnel(false);
										}}
									>
										{intl.formatMessage({ id: "wireguard.create.close" })}
									</button>
								</div>
							</div>
						) : (
							<div className="row g-4">
								<div className="col-md-3">
									<label className="form-label mb-1">{intl.formatMessage({ id: "wireguard.create.name" })}</label>
									<input
										type="text"
										className="form-control"
										value={newName}
										onChange={(e) => setNewName(e.target.value)}
										placeholder={intl.formatMessage({ id: "wireguard.create.name-placeholder" })}
									/>
								</div>
								<div className="col-md-3">
									<label className="form-label mb-1">{intl.formatMessage({ id: "wireguard.create.type" })}</label>
									<select
										className="form-select"
										value={newType}
										onChange={(e) => setNewType(e.target.value as typeof newType)}
									>
										<option value="client">Client</option>
										<option value="site-to-site">Site-to-Site</option>
										<option value="hub-link">Hub-Link</option>
									</select>
								</div>
								<div className="col-md-3">
									<label className="form-label mb-1">{intl.formatMessage({ id: "wireguard.create.interface" })}</label>
									<select
										className="form-select"
										value={newIfaceName}
										onChange={(e) => setNewIfaceName(e.target.value)}
									>
										{interfaces.map((i) => (
											<option key={i.name} value={i.name}>
												{i.name} ({i.addresses.join(", ")})
											</option>
										))}
									</select>
								</div>
								<div className="col-md-3">
									<label className="form-label mb-1">{intl.formatMessage({ id: "wireguard.create.dns" })}</label>
									<input
										type="text"
										className="form-control"
										value={newDns}
										onChange={(e) => setNewDns(e.target.value)}
										placeholder="10.10.0.1, 1.1.1.1"
									/>
								</div>
								{newType === "client" && (
									<div className="col-md-3">
										<label className="form-label mb-1">{intl.formatMessage({ id: "wireguard.create.platform" })}</label>
										<select
											className="form-select"
											value={newPlatform}
											onChange={(e) => setNewPlatform(e.target.value as "desktop" | "mobile")}
										>
											<option value="desktop">{intl.formatMessage({ id: "wireguard.create.platform-desktop" })}</option>
											<option value="mobile">{intl.formatMessage({ id: "wireguard.create.platform-mobile" })}</option>
										</select>
									</div>
								)}
								{newType === "client" && (
									<div className="col-md-3 d-flex align-items-center" style={{ paddingTop: "0.25rem" }}>
										<label className="form-check form-switch mb-0">
											<input
												type="checkbox"
												className="form-check-input"
												checked={newFullTunnel}
												onChange={(e) => setNewFullTunnel(e.target.checked)}
											/>
											<span className="form-check-label">{intl.formatMessage({ id: "wireguard.create.full-tunnel" })}</span>
										</label>
									</div>
								)}
								{!newFullTunnel && (
									<div className="col-12">
										<label className="form-label mb-1">{intl.formatMessage({ id: "wireguard.create.allowed-ips" })}</label>
										<div className="row g-2 mb-1">
											{(() => {
												const selectedNets = new Set(splitCsv(newImported));
												const toggleNet = (net: string) => {
													const nets = new Set(splitCsv(newImported));
													if (nets.has(net)) nets.delete(net);
													else nets.add(net);
													setNewImported([...nets].join(", "));
												};
												const toggleSite = (siteNets: string[]) => {
													const nets = new Set(splitCsv(newImported));
													const allSelected = siteNets.every((n) => nets.has(n));
													for (const n of siteNets) {
														if (allSelected) nets.delete(n);
														else nets.add(n);
													}
													setNewImported([...nets].join(", "));
												};
												// Group networks by site (exclude clients — they consume networks, not provide them)
												const sites = links
													.filter((l) => l.type !== "client" && l.importedNetworks.length > 0)
													.map((l) => ({ name: l.name, nets: l.importedNetworks }));
												return sites.map((site) => (
													<div key={site.name} className="col-md-4">
														<div className="card card-sm">
															<div className="card-body py-2 px-3">
																<label className="form-check mb-1">
																	<input
																		type="checkbox"
																		className="form-check-input"
																		checked={site.nets.every((n) => selectedNets.has(n))}
																		onChange={() => toggleSite(site.nets)}
																	/>
																	<span className="form-check-label fw-bold small">{site.name}</span>
																</label>
																{site.nets.map((net) => (
																	<label key={net} className="form-check ms-3">
																		<input
																			type="checkbox"
																			className="form-check-input"
																			checked={selectedNets.has(net)}
																			onChange={() => toggleNet(net)}
																		/>
																		<span className="form-check-label small text-secondary">{net}</span>
																	</label>
																))}
															</div>
														</div>
													</div>
												));
											})()}
										</div>
										<input
											type="text"
											className="form-control form-control-sm mt-1"
											value={newImported}
											onChange={(e) => setNewImported(e.target.value)}
											placeholder="10.10.0.0/24, 192.168.10.0/24"
										/>
										<div className="form-hint mt-1">{intl.formatMessage({ id: "wireguard.create.allowed-ips-hint" })}</div>
									</div>
								)}
								<div className="col-12">
									<div className="d-flex gap-2">
										<button
											type="button"
											className="btn btn-sm btn-primary"
											disabled={!newName.trim() || createPeer.isPending}
											onClick={() => {
												createPeer.mutate(
													{
														name: newName.trim(),
														type: newType,
														dns: newDns
															? newDns
																	.split(",")
																	.map((s) => s.trim())
																	.filter(Boolean)
															: [],
														fullTunnel: newFullTunnel,
														platform: newPlatform,
														importedNetworks: newImported
															? newImported
																	.split(",")
																	.map((s) => s.trim())
																	.filter(Boolean)
															: [],
														ifaceName: newIfaceName,
													},
													{ onSuccess: setCreateResult },
												);
											}}
										>
											{createPeer.isPending ? intl.formatMessage({ id: "wireguard.create.pending" }) : intl.formatMessage({ id: "wireguard.create.submit" })}
										</button>
										<button
											type="button"
											className="btn btn-sm btn-ghost-secondary"
											onClick={() => setCreateOpen(false)}
										>
											{intl.formatMessage({ id: "wireguard.create.cancel" })}
										</button>
									</div>
									{createPeer.isError && (
										<div className="alert alert-danger mt-2 mb-0">
											{createPeer.error?.message || intl.formatMessage({ id: "wireguard.create.error" })}
										</div>
									)}
								</div>
							</div>
						)}
					</div>
				</div>
			)}

			{/* Stat cards */}
			<div className="row row-deck row-cards my-4">
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-blue text-white avatar">
								<IconShieldHalfFilled />
							</span>
							<div>
								<div className="text-secondary">
									{intl.formatMessage({ id: "wireguard.tab.interfaces" })}
								</div>
								<div className="platform-stat-value">
									{summary.activeInterfaceCount} / {summary.interfaceCount}
								</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-green text-white avatar">
								<IconPlugConnected />
							</span>
							<div>
								<div className="text-secondary">
									{intl.formatMessage({ id: "wireguard.stats.active-peers" })}
								</div>
								<div className="platform-stat-value">
									{summary.activePeers} / {summary.totalPeers}
								</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-yellow text-white avatar">
								<IconRoute />
							</span>
							<div>
								<div className="text-secondary">
									{intl.formatMessage({ id: "wireguard.stats.gateway-routes" })}
								</div>
								<div className="platform-stat-value">{summary.wireguardRouteCount}</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-cyan text-white avatar">
								<IconTopologyStar3 />
							</span>
							<div>
								<div className="text-secondary">
									{intl.formatMessage({ id: "wireguard.tab.links" })}
								</div>
								<div className="platform-stat-value">{summary.linkCount}</div>
							</div>
						</div>
					</div>
				</div>
			</div>

			{/* Tabs */}
			<div className={styles.tabs}>
				{(["overview", "links", "interfaces", "routing"] as const).map((tab) => (
					<button
						key={tab}
						type="button"
						className={`${styles.tab} ${activeTab === tab ? styles.tabActive : ""}`}
						onClick={() => setActiveTab(tab)}
					>
						{
							{
								overview: intl.formatMessage({ id: "wireguard.tab.overview" }),
								links: intl.formatMessage({ id: "wireguard.tab.links" }),
								interfaces: intl.formatMessage({ id: "wireguard.tab.interfaces" }),
								routing: intl.formatMessage({ id: "wireguard.tab.routing" }),
							}[tab]
						}
						{tab === "links" && links.length > 0 && (
							<span className="badge bg-secondary-lt text-secondary ms-2" style={{ fontSize: "0.7rem" }}>
								{links.length}
							</span>
						)}
						{tab === "routing" && (missingReturnRoutes.length > 0 || natCandidates.length > 0) && (
							<span className="badge bg-yellow-lt text-yellow ms-2" style={{ fontSize: "0.7rem" }}>
								{missingReturnRoutes.length + natCandidates.length}
							</span>
						)}
					</button>
				))}
			</div>

			{/* ── Overview ── */}
			{activeTab === "overview" && (
				<div>
					<div className="card mb-4">
						<div className="card-header">
							<h3 className="card-title">
								{intl.formatMessage({ id: "wireguard.overview.topology-title" })}
							</h3>
							<div className="card-options">
								<div className="d-flex gap-2">
									<span className="badge bg-emerald-lt text-emerald">
										client {summary.clientLinkCount}
									</span>
									<span className="badge bg-indigo-lt text-indigo">site {summary.siteLinkCount}</span>
									<span className="badge bg-cyan-lt text-cyan">hub {summary.hubLinkCount}</span>
								</div>
							</div>
						</div>
						<div className="card-body p-0">
							{links.length > 0 ? (
								<TopologyMap links={links} interfaces={interfaces} />
							) : (
								<div className="p-4 text-secondary small">
									{intl.formatMessage({ id: "wireguard.overview.no-links" })}
								</div>
							)}
						</div>
					</div>

					{conflictWarnings.length > 0 && (
						<div className="alert alert-danger mb-4 py-3">
							<div className="fw-bold mb-2">AllowedIPs Conflict</div>
							{conflictWarnings.map((w) => (
								<div key={w.subnet} className="small mb-1">
									{fmtGlobalWarning(w)}
								</div>
							))}
						</div>
					)}

					<div className="row row-cards mb-4">
						{nextActions.length > 0 && (
							<div className="col-md-6">
								<div className="card h-100">
									<div className="card-header">
										<h3 className="card-title">
											{intl.formatMessage({ id: "wireguard.overview.next-actions-title" })}
										</h3>
									</div>
									<div className="card-body">
										<div className="d-flex flex-column gap-2">
											{nextActions.slice(0, 8).map((action) => (
												<div key={action} className="small text-secondary">
													• {fmtNextAction(action)}
												</div>
											))}
										</div>
									</div>
								</div>
							</div>
						)}

						<div className={nextActions.length > 0 ? "col-md-6" : "col-12"}>
							<div className="card h-100">
								<div className="card-header">
									<h3 className="card-title">
										{intl.formatMessage({ id: "wireguard.overview.backups-title" })}
									</h3>
								</div>
								<div className="card-body">
									{backups.length === 0 && (
										<div className="text-secondary small">
											{intl.formatMessage({ id: "wireguard.overview.no-backups" })}
										</div>
									)}
									<div className="d-flex flex-column gap-2">
										{backups.slice(0, 5).map((item) => (
											<div
												key={item.path}
												className="d-flex justify-content-between align-items-center gap-2"
											>
												<span className="small text-secondary">{item.fileName}</span>
												<button
													className="btn btn-sm btn-outline-warning"
													type="button"
													disabled={restoreMetadata.isPending}
													onClick={() => {
														restoreMetadata.mutate(item.path);
													}}
												>
													{restoreMetadata.isPending
														? intl.formatMessage({
																id: "wireguard.overview.restore-loading",
															})
														: intl.formatMessage({ id: "wireguard.overview.restore" })}
												</button>
											</div>
										))}
									</div>
									{restoreMetadata.isSuccess && (
										<div className="alert alert-warning mt-3 mb-0 py-2 small">
											{intl.formatMessage({ id: "wireguard.overview.restore-success" })}
										</div>
									)}
									{restoreMetadata.isError && (
										<div className="alert alert-danger mt-3 mb-0 py-2 small">
											{intl.formatMessage({ id: "wireguard.overview.restore-failed" })}
										</div>
									)}
								</div>
							</div>
						</div>
					</div>
				</div>
			)}

			{/* ── Links ── */}
			{activeTab === "links" && (
				<div>
					{links.length === 0 && (
						<div className="alert alert-secondary">
							{intl.formatMessage({ id: "wireguard.links.no-links" })}
						</div>
					)}
					{renderLinks(groupedLinks.site, intl.formatMessage({ id: "wireguard.links.site-to-site" }), "bg-indigo-lt text-indigo")}
					{renderLinks(
						groupedLinks.hub,
						intl.formatMessage({ id: "wireguard.links.hub-links" }),
						"bg-cyan-lt text-cyan",
					)}
					{renderLinks(
						groupedLinks.client,
						intl.formatMessage({ id: "wireguard.links.clients" }),
						"bg-emerald-lt text-emerald",
					)}
					{renderLinks(
						groupedLinks.other,
						intl.formatMessage({ id: "wireguard.links.unclassified" }),
						"bg-secondary-lt text-secondary",
					)}
				</div>
			)}

			{/* ── Interfaces ── */}
			{activeTab === "interfaces" && (
				<div>
					<div className={styles.ifaceGrid}>
						{planningInterfaces.map((iface) => (
							<InterfaceCard key={iface.name} iface={iface} allLinks={links} />
						))}
					</div>
					{planningInterfaces.length === 0 && (
						<div className="alert alert-secondary">
							{intl.formatMessage({ id: "wireguard.interfaces.none" })}
						</div>
					)}
					<CreateInterfaceForm />
				</div>
			)}

			{/* ── Routing ── */}
			{activeTab === "routing" && (
				<div className="row row-cards">
					<div className="col-md-6">
						<div className="card">
							<div className="card-header">
								<h3 className="card-title">
									{intl.formatMessage({ id: "wireguard.routing.missing-return-title" })}
								</h3>
								{missingReturnRoutes.length > 0 && (
									<span className="badge bg-red-lt text-red ms-2">{missingReturnRoutes.length}</span>
								)}
							</div>
							<div className="card-body">
								{missingReturnRoutes.length === 0 ? (
									<div className="text-secondary small">
										{intl.formatMessage({ id: "wireguard.routing.no-missing-return" })}
									</div>
								) : (
									<div className="d-flex flex-column gap-3">
										{missingReturnRoutes.map((hint) => (
											<div key={`${hint.network}-${hint.reason}`}>
												<div className="fw-medium small">{hint.network}</div>
												<div className="text-secondary small">{hint.reason}</div>
											</div>
										))}
									</div>
								)}
							</div>
						</div>
					</div>

					<div className="col-md-6">
						<div className="card">
							<div className="card-header">
								<h3 className="card-title">
									{intl.formatMessage({ id: "wireguard.routing.nat-candidates-title" })}
								</h3>
								{natCandidates.length > 0 && (
									<span className="badge bg-yellow-lt text-yellow ms-2">{natCandidates.length}</span>
								)}
							</div>
							<div className="card-body">
								{natCandidates.length === 0 ? (
									<div className="text-secondary small">
										{intl.formatMessage({ id: "wireguard.routing.no-nat-candidates" })}
									</div>
								) : (
									<div className="d-flex flex-column gap-3">
										{natCandidates.map((hint) => (
											<div key={`${hint.network}-${hint.reason}`}>
												<div className="fw-medium small">{hint.network}</div>
												<div className="text-secondary small">{hint.reason}</div>
											</div>
										))}
									</div>
								)}
							</div>
						</div>
					</div>

					<div className="col-12">
						<div className="card platform-table-card">
							<div className="card-header">
								<h3 className="card-title">
									{intl.formatMessage({ id: "wireguard.stats.active-peers" })}
								</h3>
								<span className="badge bg-green-lt text-green ms-2">{activePeers.length}</span>
							</div>
							<div className="table-responsive">
								<table className={`table table-vcenter card-table ${styles.peerTable}`}>
									<thead>
										<tr>
											<th>{intl.formatMessage({ id: "wireguard.routing.col-interface" })}</th>
											<th>{intl.formatMessage({ id: "wireguard.link.display-name" })}</th>
											<th>{intl.formatMessage({ id: "wireguard.routing.col-public-key" })}</th>
											<th>{intl.formatMessage({ id: "wireguard.routing.col-endpoint" })}</th>
											<th>{intl.formatMessage({ id: "wireguard.routing.col-allowed-ips" })}</th>
											<th>{intl.formatMessage({ id: "wireguard.link.traffic" })}</th>
											<th>
												{intl.formatMessage({ id: "wireguard.routing.col-last-handshake" })}
											</th>
										</tr>
									</thead>
									<tbody>
										{activePeers.length === 0 ? (
											<tr>
												<td colSpan={7} className="text-secondary">
													{intl.formatMessage({ id: "wireguard.routing.no-active-peers" })}
												</td>
											</tr>
										) : (
											activePeers.map((peer) => (
												<tr key={`${peer.iface}-${peer.publicKey}`}>
													<td>{peer.iface}</td>
													<td>
														{links.find(
															(l) =>
																l.peerPublicKey === peer.publicKey &&
																l.interfaceName === peer.iface,
														)?.name || <span className="text-secondary">—</span>}
													</td>
													<td className="text-secondary">{shortKey(peer.publicKey)}</td>
													<td>
														{peer.endpoint || <span className="text-secondary">—</span>}
													</td>
													<td>
														{peer.allowedIps.length > 0 ? (
															<div className="d-flex flex-wrap gap-1">
																{peer.allowedIps.map((ip) => (
																	<span
																		key={ip}
																		className="badge bg-secondary-lt text-secondary"
																	>
																		{ip}
																	</span>
																))}
															</div>
														) : (
															<span className="text-secondary">—</span>
														)}
													</td>
													<td>
														{byteFmt(peer.rxBytes)} / {byteFmt(peer.txBytes)}
													</td>
													<td className="text-secondary">{timeAgo(peer.latestHandshake)}</td>
												</tr>
											))
										)}
									</tbody>
								</table>
							</div>
						</div>
					</div>

					<div className="col-12">
						<RoutingMatrix links={links} />
					</div>
				</div>
			)}
		</div>
	);
};

export default WireGuard;
