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
	WireGuardMetadataLinkPatch,
	WireGuardMetadataPatch,
	WireGuardPlanPreviewResponse,
	WireGuardRemoteManagementMode,
	WireGuardRestoreMetadataResponse,
	WireGuardReturnPathMode,
	WireGuardRouteHint,
	WireGuardStructuredWarning,
} from "src/api/backend";
import {
	buildInstallOneliner,
	createWireGuardInterface,
	deleteAgentGuarded,
	deleteWireGuardInterface,
	deleteWireGuardPeer,
	deleteWithBoundAgents,
	downloadWireGuardLinkConfig,
	resetAgentToken,
	saveBlob,
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
import { agentInvalidations, invalidateWireGuard, wireGuardInvalidations } from "src/hooks/wireguardKeys";
import { intl } from "src/locale/IntlProvider";
import { showDeleteConfirmModal, showWireGuardQrModal } from "src/modals";
import { AgentIngressSummary } from "./AgentIngressSummary";
import styles from "./index.module.css";
import { fmtNextAction, fmtWarning, getLinkTypeBadge, getPlanBadge } from "./linkLabels";
import { hubChangeCount, renameCascadeProblems, restoreSyncProblems } from "./restoreSync";
import { TopologyMap } from "./TopologyMap";
import { agoFmt, byteFmt, matchLinkAgent } from "./topology";

// ── Utilities ──────────────────────────────────────────────────────────────────

// Structured warning from the backend (e.g. allowedips-conflict)
const isStructuredWarning = (w: string | WireGuardStructuredWarning): w is WireGuardStructuredWarning =>
	typeof w === "object" && w !== null && "code" in w;

const isConflictWarning = (w: string | WireGuardStructuredWarning): w is WireGuardStructuredWarning =>
	isStructuredWarning(w) && w.code === "allowedips-conflict";

const fmtGlobalWarning = (w: string | WireGuardStructuredWarning): string => {
	if (isConflictWarning(w)) {
		return intl.formatMessage(
			{ id: "wireguard.warning.allowedips-conflict" },
			{ subnet: w.subnet, peers: w.peers.join(", ") },
		);
	}
	if (isStructuredWarning(w)) return w.message;
	return fmtWarning(w);
};

const shortKey = (value?: string | null) => (value ? `${value.slice(0, 8)}…` : "—");
const splitCsv = (value: string) =>
	value
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
// Free-text lists (interface notes) may contain commas — one entry per line instead.
const splitLines = (value: string) =>
	value
		.split(/\r?\n/)
		.map((s) => s.trim())
		.filter(Boolean);
// Both sides normalised through splitCsv so whitespace/empty entries never produce a spurious patch.
const csvChanged = (draft: string, base: readonly string[] | string | undefined) =>
	splitCsv(draft).join(",") !== splitCsv(Array.isArray(base) ? base.join(",") : ((base as string) ?? "")).join(",");

// Agent-reported service URLs cross a trust boundary (heartbeat payload from
// the remote box) — only render plain http(s) URLs as clickable links.
const isSafeServiceUrl = (url: string) => /^https?:\/\//i.test(url);

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

/** "never" (localized) or the same short age the topology map shows ("40 s", "6 min", "3 h", "2 d"). */
const timeAgo = (ts: number) =>
	ts ? agoFmt(Date.now() / 1000 - ts) : intl.formatMessage({ id: "wireguard.time.never" });

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

/** Error alert for a failed mutation (title + raw backend message). */
function MutationError({
	error,
	titleId,
	testId,
}: {
	error: Error | null | undefined;
	titleId: string;
	testId?: string;
}) {
	return (
		<div className="alert alert-danger mt-2 mb-0 py-2 small" data-testid={testId}>
			{intl.formatMessage({ id: titleId })}
			{error?.message && <div className="font-monospace mt-1">{error.message}</div>}
		</div>
	);
}

// ── Apply sync result banner ────────────────────────────────────────────────────

function ApplySyncResult({ data, onDismiss }: { data: WireGuardApplyMetadataResponse; onDismiss?: () => void }) {
	const { apply } = data;
	const dismiss = onDismiss ? (
		<button
			type="button"
			className="btn-close float-end"
			aria-label={intl.formatMessage({ id: "action.close" })}
			onClick={onDismiss}
		/>
	) : null;
	if (apply.changeScope !== "metadata-with-config-intent") {
		const renameOnly = renameCascadeProblems(data.renameCascade);
		return (
			<div
				className={`alert mt-2 mb-0 py-2 small ${renameOnly.length ? "alert-warning" : "alert-success"}`}
				data-testid="wireguard-apply-result"
			>
				{dismiss}
				{intl.formatMessage({ id: "wireguard.apply.saved" })}
				{renameOnly.length > 0 && (
					<div className="mt-1">
						⚠ {intl.formatMessage({ id: "wireguard.apply.rename-failed" })} {renameOnly.join("; ")}
					</div>
				)}
			</div>
		);
	}
	const { hub, agentError, agentsSkipped, agentsFailed, renameErrors } = restoreSyncProblems(data);
	const hubChanges = hubChangeCount(data.hubSync);
	const agentChanges = Array.isArray(data.agentSync) ? data.agentSync.filter((a) => a.changed) : [];
	const error = intl.formatMessage({ id: "notification.error" });
	const noChange = intl.formatMessage({ id: "wireguard.apply.no-change" });
	const ok = !hub.length && !agentError && !agentsFailed.length && !renameErrors.length;
	return (
		<div
			className={`alert mt-2 mb-0 py-2 small ${ok ? "alert-success" : "alert-warning"}`}
			data-testid="wireguard-apply-result"
		>
			{dismiss}
			<div className="fw-medium">{intl.formatMessage({ id: "wireguard.apply.saved-live" })}</div>
			<div className="mt-1">
				<span className="me-3">
					{intl.formatMessage({ id: "wireguard.apply.hub-config" })}{" "}
					{hub.length === 0
						? `✓ (${hubChanges ? intl.formatMessage({ id: "wireguard.apply.peers-updated" }, { count: hubChanges }) : noChange})`
						: `⚠ ${error}: ${hub.join("; ")}`}
				</span>
				{data.agentSync && (
					<span>
						{intl.formatMessage({ id: "wireguard.apply.agents" })}{" "}
						{agentError
							? `⚠ ${error}: ${agentError}`
							: agentChanges.length > 0
								? `✓ ${agentChanges.map((a) => a.name).join(", ")}`
								: noChange}
						{agentsSkipped.length > 0 &&
							` · ⚠ ${agentsSkipped.join(", ")} ${intl.formatMessage({ id: "wireguard.apply.skipped" })}`}
						{agentsFailed.length > 0 && ` · ⚠ ${error}: ${agentsFailed.join(", ")}`}
					</span>
				)}
			</div>
			{renameErrors.length > 0 && (
				<div className="mt-1">
					⚠ {intl.formatMessage({ id: "wireguard.apply.rename-failed" })} {renameErrors.join("; ")}
				</div>
			)}
		</div>
	);
}

function RestoreSyncResult({ data }: { data: WireGuardRestoreMetadataResponse }) {
	const { hub, agentError, agentsSkipped, agentsFailed, renameErrors } = restoreSyncProblems(data);
	const ok =
		hub.length === 0 &&
		!agentError &&
		agentsSkipped.length === 0 &&
		agentsFailed.length === 0 &&
		renameErrors.length === 0;
	const error = intl.formatMessage({ id: "notification.error" });
	return (
		<div
			className={`alert mt-3 mb-0 py-2 small ${ok ? "alert-success" : "alert-warning"}`}
			data-testid="wireguard-restore-result"
		>
			<div className="fw-medium">{intl.formatMessage({ id: "wireguard.overview.restore-success" })}</div>
			{hub.length > 0 && (
				<div className="mt-1">
					{intl.formatMessage({ id: "wireguard.apply.hub-config" })} ⚠ {error}: {hub.join("; ")}
				</div>
			)}
			{agentError && (
				<div className="mt-1">
					{intl.formatMessage({ id: "wireguard.apply.agents" })} ⚠ {error}: {agentError}
				</div>
			)}
			{agentsFailed.length > 0 && (
				<div className="mt-1">
					{intl.formatMessage({ id: "wireguard.apply.agents" })} ⚠ {error}: {agentsFailed.join(", ")}
				</div>
			)}
			{agentsSkipped.length > 0 && (
				<div className="mt-1">
					{intl.formatMessage({ id: "wireguard.apply.agents" })} ⚠ {agentsSkipped.join(", ")}{" "}
					{intl.formatMessage({ id: "wireguard.apply.skipped" })}
				</div>
			)}
			{renameErrors.length > 0 && (
				<div className="mt-1">
					⚠ {intl.formatMessage({ id: "wireguard.apply.rename-failed" })} {renameErrors.join("; ")}
				</div>
			)}
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

/** Clipboard fallback for non-secure contexts: select a temporary textarea and execCommand("copy"). */
function copyTextFallback(text: string): boolean {
	const area = document.createElement("textarea");
	area.value = text;
	area.setAttribute("readonly", "");
	area.style.position = "fixed";
	area.style.opacity = "0";
	document.body.appendChild(area);
	area.select();
	let ok = false;
	try {
		ok = document.execCommand("copy");
	} catch {
		ok = false;
	}
	document.body.removeChild(area);
	return ok;
}

/** Hub-side tunnel URL for the installer: the hub's own address on the link's interface (IPv6 bracketed). */
export function hubTunnelUrl(address: string | undefined): string {
	const ip = (address ?? "").trim().replace(/\/\d+$/, "");
	if (!ip) return "";
	return ip.includes(":") ? `http://[${ip}]:3300` : `http://${ip}:3300`;
}

/** Second confirmation before a forced delete of an agent that is offline for good. */
const confirmForceAgent = (name: string) =>
	window.confirm(intl.formatMessage({ id: "wireguard.agent.delete-force-confirm" }, { name }));

/**
 * Delete confirm for a link/interface whose bound agents are removed with it
 * (see deleteWithBoundAgents). `boundAgents` is only for the confirmation text.
 */
function confirmDeleteWithBoundAgents({
	titleId,
	confirmTextId,
	name,
	boundAgents,
	call,
}: {
	titleId: string;
	confirmTextId: string;
	name: string;
	boundAgents: { name: string }[];
	call: Parameters<typeof deleteWithBoundAgents>[0];
}) {
	showDeleteConfirmModal({
		title: intl.formatMessage({ id: titleId }),
		onConfirm: () => deleteWithBoundAgents(call, (a) => confirmForceAgent(a.name)),
		invalidations: wireGuardInvalidations({ agents: true }),
		children: (
			<>
				{intl.formatMessage({ id: confirmTextId }, { name })}
				{boundAgents.length > 0 && (
					<div className="mt-2">
						{intl.formatMessage(
							{ id: "wireguard.link.delete-agent-note" },
							{ agent: boundAgents.map((a) => a.name).join(", ") },
						)}
					</div>
				)}
			</>
		),
	});
}

function AgentSection({
	link,
	agents,
	allLinks,
	agentsReady,
	hubAddress,
}: {
	link: WireGuardLink;
	agents: Agent[];
	/** every link (for matching generated link names by public-key prefix) */
	allLinks?: WireGuardLink[];
	agentsReady: boolean;
	/** The hub's own address on link.interfaceName (not the peer's tunnel IP). */
	hubAddress?: string;
}) {
	const existingAgent = matchLinkAgent(link, agents, allLinks);
	const createAgent = useCreateAgent();
	const updateAgent = useUpdateAgent();
	const queryClient = useQueryClient();

	// PRIMARY_URL is the HUB as seen through the tunnel — link.tunnelAddresses are
	// the gateway's own /32s. Default: the agent-hub-url setting's primary, else the
	// hub's address on this interface. null = not edited, so the default follows the
	// setting once it has loaded.
	const hubSetting = useSetting("agent-hub-url");
	// public_url = the agent's FALLBACK_URL (internet path): the backend accepts
	// https only. Default: the setting's public URL, else this page's origin — but
	// only when https (an admin UI opened as http://<hub>:81 must not leak into it).
	const defaultPublicUrl =
		[hubSetting.data?.value, window.location.origin]
			.map((u) => (typeof u === "string" ? u.trim() : ""))
			.find((u) => /^https:\/\//i.test(u)) ?? "";
	const [publicUrlEdit, setPublicUrl] = useState<string | null>(null);
	const publicUrl = publicUrlEdit ?? defaultPublicUrl;
	const settingPrimary = hubSetting.data?.meta?.primary;
	const defaultTunnelUrl = (typeof settingPrimary === "string" && settingPrimary.trim()) || hubTunnelUrl(hubAddress);
	const [tunnelUrlEdit, setTunnelUrl] = useState<string | null>(null);
	const tunnelUrl = tunnelUrlEdit ?? defaultTunnelUrl;
	const [copied, setCopied] = useState(false);
	// Only the id is pinned; the agent itself always comes from the (polled) agents
	// query so status/last-seen/version update while the panel is open. lastKnown
	// bridges the moment between a mutation and the refetched list.
	const [activeAgentId, setActiveAgentId] = useState<number | null>(existingAgent?.id ?? null);
	const [lastKnown, setLastKnown] = useState<Agent | null>(null);
	const setActiveAgent = (updated: Agent) => {
		setActiveAgentId(updated.id);
		setLastKnown(updated);
	};
	const [mgmtUrlEdit, setMgmtUrlEdit] = useState<string | null>(null);
	const [aclEdit, setAclEdit] = useState<string | null>(null);
	// updateAgent is shared by the mgmt-URL editor, the ACL editor and the LAN
	// switch: remember which control fired it so its error shows only there.
	const [updateSource, setUpdateSource] = useState<"mgmt" | "acl" | "lan" | null>(null);
	const [showReinstall, setShowReinstall] = useState(false);
	const [resetLoading, setResetLoading] = useState(false);
	const [resetError, setResetError] = useState<string | null>(null);
	const agentCreateAttempted = useRef(false);

	const runCreateAgent = () => {
		agentCreateAttempted.current = true;
		createAgent.mutate(
			{
				name: link.name,
				mode: "native",
				wgInterface: link.interfaceName,
				wgLinkName: link.name,
			},
			{
				onSuccess: (created) => {
					setActiveAgentId(created.id);
					setLastKnown(created);
				},
			},
		);
	};

	// Auto-create agent if none exists for this link. Only once the agents query
	// has actually resolved — while it is in flight (or errored) the list is just
	// a placeholder [] and creating here would duplicate an existing agent.
	// A failure is shown below with a retry button (the ref blocks auto-retries).
	// biome-ignore lint/correctness/useExhaustiveDependencies: runCreateAgent only reads link name/interface (listed)
	useEffect(() => {
		if (agentsReady && !existingAgent && activeAgentId === null && !agentCreateAttempted.current) {
			runCreateAgent();
		}
	}, [agentsReady, existingAgent, activeAgentId, link.interfaceName, link.name, createAgent.mutate]);

	const handleDeleteAgent = (target: Agent) => {
		showDeleteConfirmModal({
			title: intl.formatMessage({ id: "wireguard.agent.delete-title" }),
			onConfirm: async () => {
				await deleteAgentGuarded(target, () => confirmForceAgent(target.name));
				// Stay "not found" afterwards — no silent re-create; the retry button creates a fresh agent.
				agentCreateAttempted.current = true;
				setActiveAgentId(null);
				setLastKnown(null);
			},
			invalidations: agentInvalidations(),
			children: intl.formatMessage({ id: "wireguard.agent.delete-confirm" }, { name: target.name }),
		});
	};

	const handleCopy = (text: string) => {
		const done = () => {
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		};
		// navigator.clipboard only exists in a secure context (not on http://<hub>:81)
		if (navigator.clipboard?.writeText) {
			navigator.clipboard.writeText(text).then(done, () => {
				if (copyTextFallback(text)) done();
			});
		} else if (copyTextFallback(text)) {
			done();
		}
	};

	const handleResetToken = async (agentId: number) => {
		// Rotating the token locks the running agent out at once (it re-registers
		// only via the new installer) — config/route/Freigaben updates stop.
		if (!window.confirm(intl.formatMessage({ id: "wireguard.agent.reinstall-confirm" }, { name: link.name }))) {
			return;
		}
		setResetLoading(true);
		setResetError(null);
		try {
			const updated = await resetAgentToken(agentId);
			setActiveAgent(updated);
			setShowReinstall(true);
			queryClient.invalidateQueries({ queryKey: ["agents"] });
		} catch (err) {
			setResetError(err instanceof Error ? err.message : String(err));
		} finally {
			setResetLoading(false);
		}
	};

	const handleSaveMgmtUrl = (agentId: number) => {
		if (mgmtUrlEdit === null) return;
		setUpdateSource("mgmt");
		updateAgent.mutate(
			{
				id: agentId,
				// null (not undefined) so the key survives JSON.stringify and an
				// emptied field actually clears mgmt_url on the backend
				data: { mgmtUrl: mgmtUrlEdit.trim() || null },
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
		setUpdateSource("acl");
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

	const handleTogglePreserveLan = (agentId: number, value: boolean) => {
		setUpdateSource("lan");
		updateAgent.mutate(
			{ id: agentId, data: { preserveLanSourceIp: value } },
			{ onSuccess: (updated) => setActiveAgent(updated) },
		);
	};

	// Use the resolved agent (either pre-existing or just created)
	const agent =
		(activeAgentId !== null
			? (agents.find((a) => a.id === activeAgentId) ?? (lastKnown?.id === activeAgentId ? lastKnown : null))
			: null) ??
		existingAgent ??
		null;
	const safeServices = (agent?.services ?? []).filter((svc) => isSafeServiceUrl(svc.url));

	return (
		<div className={styles.inlineSection}>
			<div className="fw-medium mb-3 small text-uppercase text-secondary">
				{intl.formatMessage({ id: "wireguard.link.agent" })} — {link.name}
			</div>

			{!agent && (
				<div className="text-secondary small">
					{createAgent.isPending
						? intl.formatMessage({ id: "wireguard.agent.creating" })
						: intl.formatMessage({ id: "wireguard.agent.not-found" })}
					{createAgent.isError && (
						<div className="text-danger mt-1" data-testid="agent-create-error">
							{intl.formatMessage(
								{ id: "wireguard.agent.create-failed" },
								{ error: createAgent.error?.message ?? "" },
							)}
						</div>
					)}
					{/* after a failed create or a delete — never before the first auto-create ran */}
					{!createAgent.isPending && agentsReady && !existingAgent && agentCreateAttempted.current && (
						<button
							type="button"
							className="btn btn-sm btn-outline-primary mt-2 d-block"
							onClick={runCreateAgent}
						>
							{intl.formatMessage({ id: "wireguard.agent.retry" })}
						</button>
					)}
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
							{agent.configError ? (
								<div className="small">
									<span className="badge bg-red-lt text-red" title={agent.configError}>
										{intl.formatMessage({ id: "wireguard.agent.config-failed" })}
									</span>
								</div>
							) : (
								agent.configAppliedHash &&
								agent.configHash &&
								agent.configAppliedHash !== agent.configHash && (
									<div className="small">
										<span className="badge bg-yellow-lt text-yellow">
											{intl.formatMessage({ id: "wireguard.agent.config-pending" })}
										</span>
									</div>
								)
							)}
							{safeServices.length > 0
								? safeServices.map((svc) => (
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
										onClick={() => {
											updateAgent.reset();
											setMgmtUrlEdit(agent.mgmtUrl ?? "");
										}}
									>
										{intl.formatMessage({ id: "wireguard.agent.change" })}
									</button>
								</div>
							) : (
								<div className="d-flex align-items-center gap-2 flex-wrap">
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
									{updateAgent.isError && updateSource === "mgmt" && (
										<span className="small text-danger">{updateAgent.error?.message}</span>
									)}
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
										onClick={() => {
											updateAgent.reset();
											setAclEdit((agent.allowedNetworks ?? []).join(", "));
										}}
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
									{updateAgent.isError && updateSource === "acl" && (
										<span className="small text-danger">{updateAgent.error?.message}</span>
									)}
								</div>
							)}
							<div className="form-text small">
								{intl.formatMessage({ id: "wireguard.agent.allowed-networks-hint" })}
							</div>
						</div>
					)}

					{/* Ingress filter ("Freigaben") — details in AgentIngressModal */}
					{agent.status === "active" && <AgentIngressSummary agent={agent} />}

					{/* Preserve real client IP into the local LAN (no MASQUERADE) */}
					{agent.status === "active" && (
						<div className="mb-3">
							<div className="form-check form-switch">
								<input
									className="form-check-input"
									type="checkbox"
									role="switch"
									aria-checked={agent.preserveLanSourceIp}
									id={`preserve-lan-${agent.id}`}
									checked={agent.preserveLanSourceIp}
									disabled={updateAgent.isPending}
									onChange={(e) => handleTogglePreserveLan(agent.id, e.target.checked)}
								/>
								<label className="form-check-label small" htmlFor={`preserve-lan-${agent.id}`}>
									{intl.formatMessage({ id: "wireguard.agent.preserve-lan" })}
								</label>
							</div>
							<div className="form-text small">
								{intl.formatMessage({ id: "wireguard.agent.preserve-lan-hint" })}
							</div>
							{updateAgent.isError && updateSource === "lan" && (
								<div className="small text-danger">{updateAgent.error?.message}</div>
							)}
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
					{resetError && <div className="small text-danger mb-2">{resetError}</div>}

					{/* Revoke: deletes the agent (token invalid at once) */}
					<button
						type="button"
						className={`btn btn-sm btn-outline-danger mb-2${agent.status === "active" && !showReinstall ? " ms-2" : " d-block"}`}
						onClick={() => handleDeleteAgent(agent)}
					>
						{intl.formatMessage({ id: "wireguard.agent.delete" })}
					</button>

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
											<code className="flex-grow-1 text-truncate small bg-dark text-white px-2 py-1 rounded">
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
	/** every link (agent matching by public-key prefix needs them) */
	allLinks: WireGuardLink[];
	missingReturnRoutes: WireGuardRouteHint[];
	natCandidates: WireGuardRouteHint[];
	planningInterfaces: EnhancedInterface[];
	agents: Agent[];
	agentsReady: boolean;
}

function LinkCard({
	link,
	allLinks,
	missingReturnRoutes,
	natCandidates,
	planningInterfaces,
	agents,
	agentsReady,
}: LinkCardProps) {
	const [editorOpen, setEditorOpen] = useState(false);
	const [plannerOpen, setPlannerOpen] = useState(false);
	const [agentOpen, setAgentOpen] = useState(false);
	const [downloading, setDownloading] = useState(false);
	const [downloadError, setDownloadError] = useState<string | null>(null);
	// Download/QR generate a NEW key pair and rotate the hub-side key. Only valid
	// for road-warrior clients — on a site/agent link the gateway keeps its own
	// key and would be cut off at once (the backend refuses those with 409).
	// An untyped peer is "client" only by the ≤1-route heuristic — if it carries a
	// LAN it is most likely a single-subnet site, so require an explicit type then.
	const canProvisionConfig =
		link.type === "client" &&
		(link.typeExplicit !== false || link.allowedIps.every((c) => /\/(32|128)$/.test(c))) &&
		link.remoteManagementMode !== "agent" &&
		!agents.some((a) => a.wgLinkName === link.name);
	const queryClient = useQueryClient();
	const confirmKeyRotation = () =>
		window.confirm(intl.formatMessage({ id: "wireguard.link.rotate-confirm" }, { name: link.name || link.id }));
	// The rotated key changes the link id (iface:newPubKey) — refresh so later
	// edits/deletes don't target the old id.
	const invalidateAfterRotation = () => invalidateWireGuard(queryClient);

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
	// The link as it was when the editor opened. The patch diffs against this, not
	// against the live `link` (re-polled every 15 s): a field changed underneath an
	// open editor (other admin, restore, rename cascade) must not be reverted.
	const [editorBase, setEditorBase] = useState<WireGuardLink | null>(null);
	// Planner state
	const [planExported, setPlanExported] = useState("");
	const [planImported, setPlanImported] = useState("");
	const [planReturn, setPlanReturn] = useState<WireGuardReturnPathMode>("auto");
	const [planMgmt, setPlanMgmt] = useState<WireGuardRemoteManagementMode>("none");
	const [planIntent, setPlanIntent] = useState("unknown");
	// Same idea as editorBase: the planner patch diffs against the link as it was when the planner opened.
	const [plannerBase, setPlannerBase] = useState<WireGuardLink | null>(null);

	const applyMetadata = useApplyWireGuardMetadata();

	const tb = getLinkTypeBadge(link);
	const pb = getPlanBadge(link);
	const missingReturn = hasRouteHint(link, missingReturnRoutes);
	const natCandidate = hasRouteHint(link, natCandidates);

	// Same matching as the topology map: wgLinkName, generated name by key prefix, name, tunnel IP
	const matchedAgent = matchLinkAgent(link, agents, allLinks);
	const agentServices =
		matchedAgent?.status === "active"
			? (matchedAgent.services ?? []).filter((svc) => isSafeServiceUrl(svc.url))
			: [];

	const openEditor = () => {
		setEditorBase(link);
		setDraftName(link.name);
		setDraftImported(link.importedNetworks.join(", "));
		setDraftExported(link.exportedNetworks.join(", "));
		setDraftMgmt(link.remoteManagementMode || "none");
		setDraftReturn(link.returnPathMode || "auto");
		setDraftDns((link.dns || []).join(", "));
		setDraftFullTunnel(Boolean(link.fullTunnel));
		setDraftType(link.type);
		setDraftPlatform(link.platform || "desktop");
		applyMetadata.reset();
		setEditorOpen(true);
		setPlannerOpen(false);
	};

	const openPlanner = () => {
		setPlannerBase(link);
		const iface = planningInterfaces.find((i) => i.name === link.interfaceName);
		setPlanExported(
			(link.exportedNetworks.length ? link.exportedNetworks : (iface?.exportedNetworks ?? [])).join(", "),
		);
		setPlanImported(link.importedNetworks.join(", "));
		setPlanReturn(link.returnPathMode || "auto");
		setPlanMgmt(link.remoteManagementMode || "none");
		setPlanIntent(link.planIntent || link.type || "unknown");
		applyMetadata.reset();
		setPlannerOpen(true);
		setEditorOpen(false);
	};

	// Only include fields that actually changed — avoids triggering metadata-with-config-intent
	// for unchanged config-relevant fields whose stored value is simply undefined (default).
	const base = editorBase ?? link;
	const editorLinkPatch: WireGuardMetadataLinkPatch = {};
	const trimmedName = draftName.trim();
	// Cleared name: send "" (JSON drops undefined, which made clearing a silent no-op);
	// the backend sanitizes "" to a removal and falls back to the generated name.
	if (trimmedName !== (base.name || "")) editorLinkPatch.name = trimmedName;
	if (csvChanged(draftImported, base.importedNetworks)) editorLinkPatch.importedNetworks = splitCsv(draftImported);
	if (csvChanged(draftExported, base.exportedNetworks)) editorLinkPatch.exportedNetworks = splitCsv(draftExported);
	if (draftMgmt !== (base.remoteManagementMode || "none")) editorLinkPatch.remoteManagementMode = draftMgmt;
	if (draftReturn !== (base.returnPathMode || "auto")) editorLinkPatch.returnPathMode = draftReturn;
	if (csvChanged(draftDns, base.dns)) editorLinkPatch.dns = splitCsv(draftDns);
	// Client-only fields, mirroring the create form: a link re-typed away from client must not keep a
	// stale full tunnel (would put 0.0.0.0/1 into its downloaded config) or a Desktop/Mobile badge.
	const effectiveFullTunnel = draftType === "client" && draftFullTunnel;
	if (effectiveFullTunnel !== Boolean(base.fullTunnel)) editorLinkPatch.fullTunnel = effectiveFullTunnel;
	if (draftType !== base.type) editorLinkPatch.type = draftType;
	if (draftType === "client") {
		if (draftPlatform !== (base.platform || "desktop")) editorLinkPatch.platform = draftPlatform;
	} else if (base.platform) {
		// JSON drops undefined keys, so null is what actually clears the stored value server-side
		editorLinkPatch.platform = null;
	}

	const editorPatch: WireGuardMetadataPatch = {
		links: { [link.id]: editorLinkPatch },
	};
	// Planner: same changed-fields-only rule as the editor. Sending all six fields unconditionally
	// stored derived defaults (type, auto/none) and forced a config-intent apply on an untouched save.
	const pBase = plannerBase ?? link;
	const plannerLinkPatch: WireGuardMetadataLinkPatch = {};
	if (planIntent !== (pBase.planIntent || pBase.type || "unknown")) {
		plannerLinkPatch.planIntent = planIntent;
		if (planIntent !== pBase.type) plannerLinkPatch.type = planIntent as WireGuardLink["type"];
	}
	if (csvChanged(planExported, pBase.exportedNetworks)) plannerLinkPatch.exportedNetworks = splitCsv(planExported);
	if (csvChanged(planImported, pBase.importedNetworks)) plannerLinkPatch.importedNetworks = splitCsv(planImported);
	if (planReturn !== (pBase.returnPathMode || "auto")) plannerLinkPatch.returnPathMode = planReturn;
	if (planMgmt !== (pBase.remoteManagementMode || "none")) plannerLinkPatch.remoteManagementMode = planMgmt;
	const plannerPatch: WireGuardMetadataPatch = {
		links: { [link.id]: plannerLinkPatch },
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
					<span className={`badge ${tb.className}`}>{intl.formatMessage({ id: tb.labelId })}</span>
					<span
						className={`badge ${link.active ? "bg-green-lt text-green" : "bg-secondary-lt text-secondary"}`}
					>
						{link.active
							? intl.formatMessage({ id: "wireguard.link.active" })
							: intl.formatMessage({ id: "wireguard.link.inactive" })}
					</span>
					<span className={`badge ${pb.className}`}>{intl.formatMessage({ id: pb.labelId })}</span>
					{link.type === "client" && link.platform && (
						<span className="badge bg-azure-lt text-azure">
							{intl.formatMessage({
								id:
									link.platform === "mobile"
										? "wireguard.link.platform-mobile"
										: "wireguard.link.platform-desktop",
							})}
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
						<span
							className="badge bg-secondary-lt"
							title={intl.formatMessage({ id: "wireguard.agent.version" })}
						>
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
							{agentOpen
								? intl.formatMessage({ id: "wireguard.link.close-agent" })
								: intl.formatMessage({ id: "wireguard.link.agent" })}
						</button>
					)}
					{canProvisionConfig && (
						<button
							className="btn btn-sm btn-outline-secondary ms-auto"
							type="button"
							disabled={downloading}
							onClick={async () => {
								if (!confirmKeyRotation()) return;
								setDownloading(true);
								setDownloadError(null);
								try {
									const filename = `${(link.name || link.id).replace(/[^\w.-]/g, "_")}.conf`;
									await downloadWireGuardLinkConfig(link.id, filename);
									invalidateAfterRotation();
								} catch (err) {
									setDownloadError(err instanceof Error ? err.message : String(err));
								} finally {
									setDownloading(false);
								}
							}}
						>
							{downloading ? "…" : intl.formatMessage({ id: "wireguard.link.download-config" })}
						</button>
					)}
					{canProvisionConfig && (
						<button
							className="btn btn-sm btn-outline-secondary"
							type="button"
							onClick={() => {
								if (!confirmKeyRotation()) return;
								showWireGuardQrModal(link.id, link.name || link.id, invalidateAfterRotation);
							}}
						>
							{intl.formatMessage({ id: "wireguard.link.show-qr" })}
						</button>
					)}
					<button
						className={`btn btn-sm btn-outline-danger${canProvisionConfig ? "" : " ms-auto"}`}
						type="button"
						onClick={() => {
							// An agent bound to this link would outlive it with a valid token and be
							// inherited by a later link of the same name. The backend deletes it
							// together with the peer as one operation: every bound agent is checked
							// first (nothing is removed while one refuses, e.g. Freigaben filter
							// still active), the agents are deleted only after the peer is gone.
							// This list is only for the confirmation text.
							const boundAgents = agents.filter((a) => a.wgLinkName === link.name);
							confirmDeleteWithBoundAgents({
								titleId: "wireguard.link.delete-title",
								confirmTextId: "wireguard.link.delete-confirm",
								name: link.name || link.id,
								boundAgents,
								call: (opts) => deleteWireGuardPeer({ linkId: link.id, ...opts }),
							});
						}}
					>
						{intl.formatMessage({ id: "wireguard.link.delete" })}
					</button>
				</div>
				{downloadError && <div className="small text-danger mt-2">{downloadError}</div>}
			</div>

			{/* Agent section */}
			{agentOpen && link.remoteManagementMode === "agent" && (
				<AgentSection
					link={link}
					agents={agents}
					allLinks={allLinks}
					agentsReady={agentsReady}
					hubAddress={planningInterfaces.find((i) => i.name === link.interfaceName)?.addresses[0]}
				/>
			)}

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
									{/* 'unknown'/'imported' links show their real state instead of "Client" */}
									{!["client", "site-to-site", "hub-link"].includes(draftType) && (
										<option value={draftType} disabled>
											{draftType}
										</option>
									)}
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
									{draftMgmt === "unknown" && (
										<option value="unknown" disabled>
											unknown
										</option>
									)}
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
									{draftReturn === "unknown" && (
										<option value="unknown" disabled>
											unknown
										</option>
									)}
									<option value="auto">auto</option>
									<option value="routed">routed</option>
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
										<option value="desktop">
											{intl.formatMessage({ id: "wireguard.create.platform-desktop" })}
										</option>
										<option value="mobile">
											{intl.formatMessage({ id: "wireguard.create.platform-mobile" })}
										</option>
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
									<span className="form-check-label">
										{intl.formatMessage({ id: "wireguard.field.full-tunnel" })}
									</span>
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
					{applyMetadata.isError && (
						<MutationError error={applyMetadata.error} titleId="wireguard.link.save-failed" />
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
									{planReturn === "unknown" && (
										<option value="unknown" disabled>
											unknown
										</option>
									)}
									<option value="auto">auto</option>
									<option value="routed">routed</option>
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
									{planMgmt === "unknown" && (
										<option value="unknown" disabled>
											unknown
										</option>
									)}
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
							disabled={applyMetadata.isPending || Object.keys(plannerLinkPatch).length === 0}
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
					{applyMetadata.isError && (
						<MutationError
							error={applyMetadata.error}
							titleId="wireguard.link.save-failed"
							testId="planner-save-error"
						/>
					)}
				</div>
			)}

			{/* Save result stays visible after the editor/planner closed on success */}
			{!editorOpen && !plannerOpen && applyMetadata.isSuccess && applyMetadata.data && (
				<div className="px-3 pb-3">
					<ApplySyncResult data={applyMetadata.data} onDismiss={() => applyMetadata.reset()} />
				</div>
			)}
		</div>
	);
}

// ── Interface Card ─────────────────────────────────────────────────────────────

function InterfaceCard({
	iface,
	allLinks,
	agents,
}: {
	iface: EnhancedInterface;
	allLinks: WireGuardLink[];
	agents: Agent[];
}) {
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
	// Values pre-filled when the editor opened. Many are derived by the backend
	// (importedNetworks/routeTargets from peers, auto/health notes) — sending them
	// unchanged would store them as metadata and freeze the live derivation, so
	// the patch only carries fields the admin actually changed.
	const [editorBase, setEditorBase] = useState<Record<string, string> | null>(null);

	const openEditor = () => {
		setEditorBase({
			role: iface.role || "unknown",
			managementMode: iface.managementMode || "local",
			exportedNetworks: iface.exportedNetworks.join(", "),
			importedNetworks: iface.importedNetworks.join(", "),
			routeTargets: iface.routeTargets.join(", "),
			dns: (iface.dns || []).join(", "),
			notes: iface.notes.join("\n"),
		});
		setDraftRole(iface.role || "unknown");
		setDraftMgmt(iface.managementMode || "local");
		setDraftExported(iface.exportedNetworks.join(", "));
		setDraftImported(iface.importedNetworks.join(", "));
		setDraftRouteTargets(iface.routeTargets.join(", "));
		setDraftDns((iface.dns || []).join(", "));
		setDraftNotes(iface.notes.join("\n"));
		setPreview(null);
		setPreviewKey("");
		applyMetadata.reset();
		setEditorOpen(true);
	};

	const ifacePatch: Record<string, unknown> = {};
	if (editorBase) {
		if (draftRole !== editorBase.role) ifacePatch.role = draftRole;
		if (draftMgmt !== editorBase.managementMode) ifacePatch.managementMode = draftMgmt;
		if (csvChanged(draftExported, editorBase.exportedNetworks))
			ifacePatch.exportedNetworks = splitCsv(draftExported);
		if (csvChanged(draftImported, editorBase.importedNetworks))
			ifacePatch.importedNetworks = splitCsv(draftImported);
		if (csvChanged(draftRouteTargets, editorBase.routeTargets))
			ifacePatch.routeTargets = splitCsv(draftRouteTargets);
		if (csvChanged(draftDns, editorBase.dns)) ifacePatch.dns = splitCsv(draftDns);
		// Notes are free text (may contain commas) — one note per line.
		if (splitLines(draftNotes).join("\n") !== splitLines(editorBase.notes ?? "").join("\n"))
			ifacePatch.notes = splitLines(draftNotes);
	}
	const patch: WireGuardMetadataPatch = {
		interfaces: { [iface.name]: ifacePatch },
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

			<div
				className={styles.ifaceCardBody}
				style={{ flex: 1, display: "flex", flexDirection: "column", gap: "0.5rem" }}
			>
				<div className="small">
					<span className="text-secondary me-1">{intl.formatMessage({ id: "wireguard.iface.peers" })}</span>
					{iface.activePeerCount} {intl.formatMessage({ id: "wireguard.link.active" })} / {iface.peerCount}
				</div>
				<div className="small">
					<span className="text-secondary me-1">{intl.formatMessage({ id: "wireguard.link.traffic" })}</span>
					{byteFmt(iface.rxBytes)} rx / {byteFmt(iface.txBytes)} tx
				</div>
				<div className="small">
					<span className="text-secondary me-1">{intl.formatMessage({ id: "wireguard.iface.port" })}</span>
					{iface.listenPort || "—"}
				</div>
				<div className="small text-truncate">
					<span className="text-secondary me-1">{intl.formatMessage({ id: "wireguard.iface.key" })}</span>
					{shortKey(iface.publicKey)}
				</div>
				<div className="small">
					<span className="text-secondary me-1">{intl.formatMessage({ id: "wireguard.link.export" })}</span>
					{iface.exportedNetworks.length > 0
						? iface.exportedNetworks.slice(0, 4).map((n) => (
								<span key={n} className="badge bg-azure-lt text-azure me-1">
									{n}
								</span>
							))
						: "—"}
				</div>
				<div className="small">
					<span className="text-secondary me-1">{intl.formatMessage({ id: "wireguard.tab.links" })}</span>
					{ifaceLinks.length > 0
						? ifaceLinks.map((l) => (
								<span key={l.id} className={`badge ${getLinkTypeBadge(l).className} me-1`}>
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
						onClick={() => {
							// Same as the link delete: the backend deletes the agents bound to this
							// interface's links together with it (checked first, deleted after).
							// Agent.wgInterface is the gateway-side interface, so bind by link name
							// only — and skip a name another interface still uses. This list is
							// only for the confirmation text.
							const ifaceLinkNames = new Set(ifaceLinks.map((l) => l.name));
							const otherLinkNames = new Set(
								allLinks.filter((l) => l.interfaceName !== iface.name).map((l) => l.name),
							);
							const boundAgents = agents.filter(
								(a) =>
									!!a.wgLinkName &&
									ifaceLinkNames.has(a.wgLinkName) &&
									!otherLinkNames.has(a.wgLinkName),
							);
							confirmDeleteWithBoundAgents({
								titleId: "wireguard.iface.delete-title",
								confirmTextId: "wireguard.iface.delete-confirm",
								name: iface.name,
								boundAgents,
								call: (opts) => deleteWireGuardInterface({ name: iface.name, ...opts }),
							});
						}}
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
									applyMetadata.isPending ||
									!preview?.valid ||
									!preview.apply.canApply ||
									!previewCurrent ||
									Object.keys(ifacePatch).length === 0
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
								{intl.formatMessage({ id: "wireguard.iface.role" })} &amp;{" "}
								{intl.formatMessage({ id: "wireguard.link.management" })}
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
										{(
											["client-hub", "site-to-site", "hub-link", "auxiliary", "unknown"] as const
										).map((o) => (
											<option key={o} value={o}>
												{o}
											</option>
										))}
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
								{intl.formatMessage({ id: "wireguard.link.exported-networks" })} /{" "}
								{intl.formatMessage({ id: "wireguard.link.imported-networks" })}
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
								rows={3}
								value={draftNotes}
								onChange={(e) => setDraftNotes(e.target.value)}
								placeholder={intl.formatMessage({ id: "wireguard.iface.placeholder-notes" })}
							/>
						</div>
					</div>

					{previewPlan.isError && (
						<MutationError
							error={previewPlan.error}
							titleId="wireguard.iface.preview-failed"
							testId="iface-preview-error"
						/>
					)}
					{preview && <PreviewResult preview={preview} current={previewCurrent} />}
					{applyMetadata.isError && (
						<MutationError error={applyMetadata.error} titleId="wireguard.iface.save-failed" />
					)}
				</div>
			)}
			{!editorOpen && applyMetadata.isSuccess && applyMetadata.data && (
				<div className="px-3 pb-3">
					<ApplySyncResult data={applyMetadata.data} onDismiss={() => applyMetadata.reset()} />
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
			invalidateWireGuard(queryClient);
		} catch (err: any) {
			setError(err?.message || intl.formatMessage({ id: "wireguard.create.error" }));
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

// Global hub-address editor — the agent-hub-url setting applies to every agent,
// so it lives once at the page level (not per link). Agents adopt these URLs on
// their next poll (reach-verified) when the hub domain moves.
function HubUrlEditor() {
	const hubSetting = useSetting("agent-hub-url");
	const setSetting = useSetSetting();
	const [edit, setEdit] = useState<{ primary: string; fallback: string } | null>(null);

	const isValidHubUrl = (v: string) => {
		const t = v.trim();
		if (!t) return true;
		return /^https?:\/\/[^\s"'$`\\;|&(){}<>!#]+$/.test(t);
	};
	const invalid = edit !== null && (!isValidHubUrl(edit.primary) || !isValidHubUrl(edit.fallback));

	const save = () => {
		if (edit === null || invalid) return;
		setSetting.mutate(
			{ id: "agent-hub-url", value: edit.fallback.trim(), meta: { primary: edit.primary.trim() } },
			{ onSuccess: () => setEdit(null) },
		);
	};

	return (
		<div className="card platform-elevated-card mb-4">
			<div className="card-body py-2 px-3">
				{edit === null ? (
					<div className="d-flex align-items-center gap-2 flex-wrap small">
						<span className="text-secondary text-uppercase fw-medium">
							{intl.formatMessage({ id: "wireguard.agent.hub-url" })}
						</span>
						<code>{hubSetting.data?.meta?.primary || "—"}</code>
						<span className="text-secondary">/</span>
						<code>{hubSetting.data?.value || "—"}</code>
						<button
							type="button"
							className="btn btn-sm btn-link p-0 small"
							onClick={() => {
								setSetting.reset();
								setEdit({
									primary: hubSetting.data?.meta?.primary ?? "",
									fallback: hubSetting.data?.value ?? "",
								});
							}}
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
							value={edit.primary}
							onChange={(e) => setEdit({ ...edit, primary: e.target.value })}
							placeholder="http://10.10.0.1:3300"
						/>
						<input
							type="url"
							className="form-control form-control-sm"
							style={{ maxWidth: 360 }}
							value={edit.fallback}
							onChange={(e) => setEdit({ ...edit, fallback: e.target.value })}
							placeholder="https://proxy.comnic.de"
						/>
						<div className="d-flex gap-2 align-items-center">
							<button
								type="button"
								className="btn btn-sm btn-primary"
								disabled={setSetting.isPending || invalid}
								onClick={save}
							>
								{intl.formatMessage({ id: "save" })}
							</button>
							<button
								type="button"
								className="btn btn-sm btn-outline-secondary"
								onClick={() => setEdit(null)}
							>
								{intl.formatMessage({ id: "cancel" })}
							</button>
							{invalid && (
								<span className="small text-danger">
									{intl.formatMessage({ id: "wireguard.agent.hub-url-invalid" })}
								</span>
							)}
							{!invalid && setSetting.isError && (
								<span className="small text-danger">{setSetting.error?.message}</span>
							)}
						</div>
					</div>
				)}
				<div className="form-text small mt-1">{intl.formatMessage({ id: "wireguard.agent.hub-url-hint" })}</div>
			</div>
		</div>
	);
}

const WireGuard = () => {
	const { data, isLoading, isError, error } = useWireGuardStatus();
	const applyState = useWireGuardApplyState();
	const restoreMetadata = useRestoreWireGuardMetadata();
	// Keep the shared agents query fresh while the page is open: fast while an
	// install is pending (the panel switches to "active" by itself), otherwise at
	// a steady cadence so the topology map's online/offline state (lastSeen vs.
	// AGENT_OFFLINE_AFTER_S) does not flip every agent to "offline" after 5
	// minutes without a reload.
	const agentsQuery = useAgents({
		refetchInterval: (query: { state: { data?: Agent[] } }) => {
			const list = query.state.data;
			if (!list?.length) return false;
			return list.some((a) => a.status === "pending") ? 10_000 : 60_000;
		},
	});
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
	// Only block when there is nothing to show: a failed background refetch keeps
	// the last data, and unmounting would throw away open editors and drafts.
	if (isError && !data)
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
	const globalWarnings = data.warnings || [];
	const conflictWarnings = globalWarnings.filter(isConflictWarning);
	// Operational backend warnings (no live wg dump, /sys/class/net missing, …)
	const generalWarnings = globalWarnings.filter((w) => !isConflictWarning(w));
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
	const linkCardProps = {
		allLinks: links,
		missingReturnRoutes,
		natCandidates,
		planningInterfaces,
		agents,
		agentsReady: agentsQuery.isSuccess,
	};

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
			{isError && (
				<div className="alert alert-warning" data-testid="wireguard-refetch-error">
					{intl.formatMessage({ id: "wireguard.status.load-error" }, { error: error?.message ?? "" })}
				</div>
			)}
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
									{intl.formatMessage(
										{ id: "wireguard.create.success" },
										{ name: newName, ip: createResult.tunnelAddress },
									)}
								</div>
								<div className="mb-3">
									<label className="form-label fw-bold">
										{intl.formatMessage({ id: "wireguard.create.client-config-label" })}
									</label>
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
											saveBlob(
												new Blob([createResult.content], { type: "text/plain" }),
												createResult.filename,
											);
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
									<label className="form-label mb-1">
										{intl.formatMessage({ id: "wireguard.create.name" })}
									</label>
									<input
										type="text"
										className="form-control"
										value={newName}
										onChange={(e) => setNewName(e.target.value)}
										placeholder={intl.formatMessage({ id: "wireguard.create.name-placeholder" })}
									/>
								</div>
								<div className="col-md-3">
									<label className="form-label mb-1">
										{intl.formatMessage({ id: "wireguard.create.type" })}
									</label>
									<select
										className="form-select"
										value={newType}
										onChange={(e) => {
											const type = e.target.value as typeof newType;
											setNewType(type);
											// Full-tunnel only exists for clients; a hidden "on" would be sent for a site
											if (type !== "client") setNewFullTunnel(false);
										}}
									>
										<option value="client">Client</option>
										<option value="site-to-site">Site-to-Site</option>
										<option value="hub-link">Hub-Link</option>
									</select>
								</div>
								<div className="col-md-3">
									<label className="form-label mb-1">
										{intl.formatMessage({ id: "wireguard.create.interface" })}
									</label>
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
									<label className="form-label mb-1">
										{intl.formatMessage({ id: "wireguard.create.dns" })}
									</label>
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
										<label className="form-label mb-1">
											{intl.formatMessage({ id: "wireguard.create.platform" })}
										</label>
										<select
											className="form-select"
											value={newPlatform}
											onChange={(e) => setNewPlatform(e.target.value as "desktop" | "mobile")}
										>
											<option value="desktop">
												{intl.formatMessage({ id: "wireguard.create.platform-desktop" })}
											</option>
											<option value="mobile">
												{intl.formatMessage({ id: "wireguard.create.platform-mobile" })}
											</option>
										</select>
									</div>
								)}
								{newType === "client" && (
									<div
										className="col-md-3 d-flex align-items-center"
										style={{ paddingTop: "0.25rem" }}
									>
										<label className="form-check form-switch mb-0">
											<input
												type="checkbox"
												className="form-check-input"
												checked={newFullTunnel}
												onChange={(e) => setNewFullTunnel(e.target.checked)}
											/>
											<span className="form-check-label">
												{intl.formatMessage({ id: "wireguard.create.full-tunnel" })}
											</span>
										</label>
									</div>
								)}
								{!(newType === "client" && newFullTunnel) && (
									<div className="col-12">
										<label className="form-label mb-1">
											{intl.formatMessage({
												id:
													newType === "client"
														? "wireguard.create.allowed-ips"
														: "wireguard.create.site-networks",
											})}
										</label>
										{/* Picking other sites' networks only makes sense for a client — for a
										    site/hub link they are already claimed and the backend rejects them. */}
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
												const sites = (newType === "client" ? links : [])
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
																		checked={site.nets.every((n) =>
																			selectedNets.has(n),
																		)}
																		onChange={() => toggleSite(site.nets)}
																	/>
																	<span className="form-check-label fw-bold small">
																		{site.name}
																	</span>
																</label>
																{site.nets.map((net) => (
																	<label key={net} className="form-check ms-3">
																		<input
																			type="checkbox"
																			className="form-check-input"
																			checked={selectedNets.has(net)}
																			onChange={() => toggleNet(net)}
																		/>
																		<span className="form-check-label small text-secondary">
																			{net}
																		</span>
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
										<div className="form-hint mt-1">
											{intl.formatMessage({
												id:
													newType === "client"
														? "wireguard.create.allowed-ips-hint"
														: "wireguard.create.site-networks-hint",
											})}
										</div>
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
														dns: splitCsv(newDns),
														fullTunnel: newType === "client" && newFullTunnel,
														// Client-only, like fullTunnel: a site link must not carry a Desktop badge
														platform: newType === "client" ? newPlatform : undefined,
														// Hidden while full tunnel is on (see the picker guard above): don't persist a reach list the config ignores
														importedNetworks:
															newType === "client" && newFullTunnel
																? []
																: splitCsv(newImported),
														ifaceName: newIfaceName,
													},
													{ onSuccess: setCreateResult },
												);
											}}
										>
											{createPeer.isPending
												? intl.formatMessage({ id: "wireguard.create.pending" })
												: intl.formatMessage({ id: "wireguard.create.submit" })}
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
											{createPeer.error?.message ||
												intl.formatMessage({ id: "wireguard.create.error" })}
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
					<HubUrlEditor />
					<div className="card mb-4">
						<div className="card-header">
							<h3 className="card-title">
								{intl.formatMessage({ id: "wireguard.overview.topology-title" })}
							</h3>
							<div className="card-options">
								<div className="d-flex gap-2">
									<span className="badge bg-emerald-lt text-emerald">
										{intl.formatMessage({ id: "platform.link-type.client" })}{" "}
										{summary.clientLinkCount}
									</span>
									<span className="badge bg-indigo-lt text-indigo">
										{intl.formatMessage({ id: "platform.link-type.site" })} {summary.siteLinkCount}
									</span>
									<span className="badge bg-cyan-lt text-cyan">
										{intl.formatMessage({ id: "platform.link-type.hub" })} {summary.hubLinkCount}
									</span>
								</div>
							</div>
						</div>
						<div className="card-body p-0">
							{links.length > 0 ? (
								<TopologyMap
									links={links}
									interfaces={interfaces}
									agents={agentsQuery.data ?? []}
									onShowMore={() => setActiveTab("links")}
								/>
							) : (
								<div className="p-4 text-secondary small">
									{intl.formatMessage({ id: "wireguard.overview.no-links" })}
								</div>
							)}
						</div>
					</div>

					{conflictWarnings.length > 0 && (
						<div className="alert alert-danger mb-4 py-3">
							<div className="fw-bold mb-2">
								{intl.formatMessage({ id: "wireguard.overview.allowedips-conflict" })}
							</div>
							{conflictWarnings.map((w) => (
								<div key={w.subnet} className="small mb-1">
									{fmtGlobalWarning(w)}
								</div>
							))}
						</div>
					)}

					{generalWarnings.length > 0 && (
						<div className="alert alert-warning mb-4 py-3">
							{generalWarnings.map((w) => (
								<div key={typeof w === "string" ? w : `${w.code}-${w.subnet}`} className="small mb-1">
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
													onClick={() =>
														// Rewrites hub + every agent config live — never on a single click
														showDeleteConfirmModal({
															title: intl.formatMessage({
																id: "wireguard.overview.restore-confirm-title",
															}),
															confirmLabel: intl.formatMessage({
																id: "wireguard.overview.restore",
															}),
															onConfirm: async () => {
																await restoreMetadata.mutateAsync(item.path);
															},
															children: intl.formatMessage(
																{ id: "wireguard.overview.restore-confirm" },
																{ file: item.fileName },
															),
														})
													}
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
									{restoreMetadata.isSuccess && restoreMetadata.data && (
										<RestoreSyncResult data={restoreMetadata.data} />
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
					{renderLinks(
						groupedLinks.site,
						intl.formatMessage({ id: "wireguard.links.site-to-site" }),
						"bg-indigo-lt text-indigo",
					)}
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
							<InterfaceCard key={iface.name} iface={iface} allLinks={links} agents={agents} />
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
