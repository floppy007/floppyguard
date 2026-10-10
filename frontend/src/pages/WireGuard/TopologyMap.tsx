import {
	IconArrowsExchange,
	IconBuilding,
	IconCpu,
	IconDeviceLaptop,
	IconNetwork,
	IconShieldLock,
	IconTopologyStar3,
	IconUsers,
} from "@tabler/icons-react";
import cn from "classnames";
import { type CSSProperties, useEffect, useRef, useState } from "react";
import type { Agent, WireGuardInterface, WireGuardLink } from "src/api/backend";
import { intl } from "src/locale/IntlProvider";
import s from "./TopologyMap.module.css";
import {
	type AgentState,
	agentState,
	agoFmt,
	bindAgents,
	byteFmt,
	clientDevice,
	type DisplayStatus,
	displayStatus,
	edgeMidpoint,
	edgePath,
	type LayoutNode,
	type LinkRate,
	layout,
	linkStatus,
	MAP_H,
	MAP_W,
	type NodeKind,
	nodeKind,
	nowSeconds,
	type Point,
	rateFmt,
	rateWidth,
	useLinkRates,
} from "./topology";

/** Width of an element in px, live (ResizeObserver); undefined until measured / without the API. */
function useElementWidth<T extends HTMLElement>() {
	const ref = useRef<T>(null);
	const [width, setWidth] = useState<number | undefined>(undefined);
	useEffect(() => {
		const el = ref.current;
		if (!el || typeof ResizeObserver === "undefined") return;
		const update = () => {
			const w = el.getBoundingClientRect().width;
			setWidth(w > 0 ? Math.round(w) : undefined);
		};
		update();
		const ro = new ResizeObserver(update);
		ro.observe(el);
		return () => ro.disconnect();
	}, []);
	return { ref, width };
}

/** Above this many bytes/s an online edge shows the animated flow overlay */
const FLOW_MIN_RATE = 1024;

const t = (id: string, values?: Record<string, string | number>) =>
	intl.formatMessage({ id: `wireguard.topo.${id}` }, values);

const pos = (p: Point): CSSProperties => ({ left: `${(p.x / MAP_W) * 100}%`, top: `${(p.y / MAP_H) * 100}%` });

const KIND_LABEL: Record<NodeKind, string> = {
	site: "site-to-site",
	"hub-link": "hub-link",
	client: "client",
	other: "site-to-site",
};

function kindLabel(link: WireGuardLink, kind: NodeKind) {
	if (kind === "other") return link.type;
	return t(KIND_LABEL[kind]);
}

function KindIcon({ link, kind, size = 16 }: { link?: WireGuardLink; kind: NodeKind; size?: number }) {
	if (kind === "site") return <IconBuilding size={size} aria-hidden />;
	if (kind === "hub-link") return <IconArrowsExchange size={size} aria-hidden />;
	if (kind === "client") {
		const Device = link ? clientDevice(link) : IconDeviceLaptop;
		return <Device size={size} aria-hidden />;
	}
	return <IconNetwork size={size} aria-hidden />;
}

function statusText(link: WireGuardLink, status: DisplayStatus, now: number) {
	if (status === "never") return t("status.never");
	const label = t(`status.${status}`);
	if (!link.latestHandshake) return label;
	return t("status.ago", { status: label, ago: agoFmt(now - link.latestHandshake) });
}

function rateDominant(rate?: LinkRate) {
	if (!rate || rate.rxRate === null || rate.txRate === null) return null;
	return Math.max(rate.rxRate, rate.txRate);
}

function edgeLabel(rate?: LinkRate) {
	const dom = rateDominant(rate);
	if (!rate || dom === null || dom <= FLOW_MIN_RATE) {
		// Nothing transferred yet: no label at all instead of "Σ 0 B".
		if (!rate?.total) return { text: "", muted: true };
		return { text: t("rate.total", { value: byteFmt(rate.total) }), muted: true };
	}
	return {
		text: `${t("rate.down", { value: rateFmt(rate.rxRate ?? 0) })} · ${t("rate.up", { value: rateFmt(rate.txRate ?? 0) })}`,
		muted: false,
	};
}

// ── Hub ────────────────────────────────────────────────────────────────────────

function HubCard({
	interfaces,
	online,
	total,
	style,
}: {
	interfaces: WireGuardInterface[];
	online: number;
	total: number;
	style: CSSProperties;
}) {
	const hubIfaces = interfaces.filter((i) => i.isHub);
	const shown = (hubIfaces.length ? hubIfaces : interfaces).slice(0, 3);
	const rx = interfaces.reduce((sum, i) => sum + (Number(i.rxBytes) || 0), 0);
	const tx = interfaces.reduce((sum, i) => sum + (Number(i.txBytes) || 0), 0);
	const title = `${t("this")} ${t("hub")}`;
	return (
		<div className={s.hub} style={style} role="group" aria-label={title}>
			<div className={s.nodeHead}>
				<span className={cn(s.avatar, s.hubAvatar)}>
					<IconTopologyStar3 size={18} aria-hidden />
				</span>
				<span className={s.hubName}>{title}</span>
			</div>
			{shown.length > 0 && (
				<div className={s.chips} title={t("hub.interfaces")}>
					{shown.map((i) => (
						<span key={i.name} className={cn(s.chip, !i.active && s.chipOff)}>
							{i.addresses[0] ? `${i.name} · ${i.addresses[0]}` : i.name}
						</span>
					))}
				</div>
			)}
			<div className={s.hubStats}>
				<span>{t("rate.down", { value: byteFmt(rx) })}</span>
				<span>{t("rate.up", { value: byteFmt(tx) })}</span>
			</div>
			<div className={s.hubOnline}>{t("hub.online", { online, total })}</div>
		</div>
	);
}

// ── Nodes ──────────────────────────────────────────────────────────────────────

function NodeCard({
	link,
	kind,
	status,
	agent,
	now,
	style,
}: {
	link: WireGuardLink;
	kind: NodeKind;
	status: DisplayStatus;
	agent?: Agent;
	now: number;
	style: CSSProperties;
}) {
	const statusLabel = statusText(link, status, now);
	const nets = link.importedNetworks ?? [];
	const aState: AgentState | null = agent ? agentState(agent, now) : null;
	const restricted = agent?.ingressMode === "restricted";

	const aria = [t("aria.node", { name: link.name, type: kindLabel(link, kind), status: t(`status.${status}`) })];
	if (link.latestHandshake) aria.push(t("aria.handshake", { ago: agoFmt(now - link.latestHandshake) }));
	if (agent && aState) aria.push(`${t("node.agent", { name: agent.name })}: ${t(`node.agent-state.${aState}`)}`);
	if (restricted) aria.push(t("node.restricted"));

	return (
		<div
			className={cn(s.node, s[`kind-${kind}`], s[`st-${status}`])}
			style={style}
			role="group"
			aria-label={aria.join(", ")}
		>
			<div className={s.nodeHead}>
				<span className={s.avatar}>
					<KindIcon link={link} kind={kind} />
				</span>
				<span className={s.nodeName} title={link.name}>
					{link.name}
				</span>
			</div>
			<div className={s.nodeStatus}>
				<span className={cn(s.dot, s[`dot-${status}`])} aria-hidden />
				<span className={s.statusText}>{statusLabel}</span>
			</div>
			{(nets.length > 0 || agent) && (
				<div className={s.chips}>
					{nets.length > 0 && (
						<span className={s.chip} title={nets.join("\n")}>
							<IconNetwork size={12} aria-hidden />
							<span className={s.chipLabel}>{t("node.networks", { count: nets.length })}</span>
							<span className={s.chipShort}>{nets.length}</span>
						</span>
					)}
					{agent && aState && (
						<span
							className={cn(s.chip, s.agentChip, s[`agent-${aState}`])}
							title={`${t("node.agent", { name: agent.name })} · ${t(`node.agent-state.${aState}`)}`}
						>
							<IconCpu size={12} aria-hidden />
							<span className={s.chipLabel}>{agent.name}</span>
						</span>
					)}
					{restricted && (
						<span className={cn(s.chip, s.shieldChip)} title={t("node.restricted")}>
							<IconShieldLock size={12} aria-hidden />
						</span>
					)}
				</div>
			)}
		</div>
	);
}

function MoreCard({ count, style, onClick }: { count: number; style: CSSProperties; onClick?: () => void }) {
	const label = t("node.more", { count });
	const content = (
		<div className={s.nodeHead}>
			<span className={s.avatar}>
				<IconUsers size={16} aria-hidden />
			</span>
			<span className={s.nodeName}>{label}</span>
		</div>
	);
	return onClick ? (
		<button type="button" className={cn(s.node, s["kind-client"], s.more)} style={style} onClick={onClick}>
			{content}
		</button>
	) : (
		<div className={cn(s.node, s["kind-client"], s.more)} style={style} role="group" aria-label={label}>
			{content}
		</div>
	);
}

// ── Legend ─────────────────────────────────────────────────────────────────────

function LineSample({ className }: { className: string }) {
	return (
		<svg width="28" height="10" className={s.lineSample} aria-hidden>
			<path d="M 1 5 L 27 5" className={cn(s.edge, s["type-site"], className)} />
		</svg>
	);
}

function Legend({ counts, online, total }: { counts: Record<NodeKind, number>; online: number; total: number }) {
	return (
		<figcaption className={s.legend}>
			{(["site", "hub-link", "client"] as const).map((kind) => (
				<span key={kind} className={cn(s.legendItem, s[`kind-${kind}`])}>
					<span className={s.legendIcon}>
						<KindIcon kind={kind} size={14} />
					</span>
					{t(KIND_LABEL[kind])}
					<span className={s.legendCount}>{counts[kind]}</span>
				</span>
			))}
			<span className={s.legendSep} aria-hidden />
			{(["online", "stale", "offline"] as const).map((st) => (
				<span key={st} className={s.legendItem}>
					<span className={cn(s.dot, s[`dot-${st}`])} aria-hidden />
					{t(`status.${st}`)}
				</span>
			))}
			{counts.client > 0 && (
				// road warriors are usually disconnected: their hollow grey dot is not "offline"
				<span className={s.legendItem}>
					<span className={cn(s.dot, s["dot-idle"])} aria-hidden />
					{t("legend.client-idle")}
				</span>
			)}
			<span className={s.legendSep} aria-hidden />
			<span className={s.legendItem}>
				<svg width="28" height="10" className={s.lineSample} aria-hidden>
					<path d="M 1 5 L 27 5" className={cn(s.edge, s["type-site"], s["edge-online"])} />
					<path d="M 1 5 L 27 5" className={cn(s.edge, s["type-site"], s.flow)} />
				</svg>
				{t("legend.flow")}
			</span>
			<span className={s.legendItem}>
				<LineSample className={s["edge-online"]} />
				{t("legend.idle")}
			</span>
			<span className={s.legendItem}>
				<LineSample className={s["edge-stale"]} />
				{t("legend.stale")}
			</span>
			<span className={s.legendItem}>
				<LineSample className={s["edge-offline"]} />
				{t("legend.offline")}
			</span>
			<span className={s.legendSep} aria-hidden />
			<span className={s.legendItem}>
				<IconCpu size={14} aria-hidden />
				{t("legend.agent")}
			</span>
			<span className={s.legendItem}>
				<IconShieldLock size={14} aria-hidden />
				{t("legend.restricted")}
			</span>
			<span className={cn(s.legendItem, s.legendTotal)}>
				<span className={s.legendCount}>{t("hub.online", { online, total })}</span>
			</span>
		</figcaption>
	);
}

// ── Map ────────────────────────────────────────────────────────────────────────

type Props = {
	links: WireGuardLink[];
	interfaces: WireGuardInterface[];
	agents: Agent[];
	/** Target of the "+N more" clients node (e.g. switch to the links tab) */
	onShowMore?: () => void;
};

type LinkNode = Extract<LayoutNode, { link: WireGuardLink }>;

export function TopologyMap({ links, interfaces, agents, onShowMore }: Props) {
	const now = nowSeconds();
	const rates = useLinkRates(links);
	const { ref: mapRef, width } = useElementWidth<HTMLElement>();
	const { hub, nodes, stacked } = layout(links, width ? { width } : undefined);
	const bound = bindAgents(links, agents);

	const counts: Record<NodeKind, number> = { site: 0, "hub-link": 0, client: 0, other: 0 };
	let online = 0;
	for (const link of links) {
		counts[nodeKind(link)]++;
		if (linkStatus(link, now) === "online") online++;
	}

	const linkNodes = nodes.filter((n): n is LinkNode => n.kind !== "more");
	const moreNode = nodes.find((n) => n.kind === "more");
	const upper = linkNodes.filter((n) => n.kind !== "client");
	const lower = linkNodes.filter((n) => n.kind === "client");

	const edges = linkNodes.map((n) => {
		const status = displayStatus(n.link, now);
		const rate = rates.get(n.link.id);
		const dom = rateDominant(rate);
		const flowing = status === "online" && dom !== null && dom > FLOW_MIN_RATE;
		return {
			key: n.key,
			d: edgePath(hub, n),
			mid: edgeMidpoint(hub, n),
			status,
			kind: n.kind,
			flowing,
			reverse: flowing && (rate?.rxRate ?? 0) > (rate?.txRate ?? 0),
			width: rateWidth(flowing ? dom : null),
			label: edgeLabel(rate),
		};
	});
	if (moreNode) {
		edges.push({
			key: moreNode.key,
			d: edgePath(hub, moreNode),
			mid: edgeMidpoint(hub, moreNode),
			status: "idle",
			kind: "client",
			flowing: false,
			reverse: false,
			width: 1.5,
			label: { text: "", muted: true },
		});
	}

	const renderNode = (n: LinkNode) => (
		<NodeCard
			key={n.key}
			link={n.link}
			kind={n.kind}
			status={displayStatus(n.link, now)}
			agent={bound.get(n.link.id)}
			now={now}
			style={pos(n)}
		/>
	);

	const sites = counts.site + counts["hub-link"] + counts.other;
	return (
		<figure
			ref={mapRef}
			className={cn(s.map, stacked && s.stacked)}
			aria-label={t("aria.map", { sites, clients: counts.client, online })}
			data-layout={stacked ? "stacked" : "map"}
		>
			<div className={s.canvas}>
				<svg
					className={s.edges}
					viewBox={`0 0 ${MAP_W} ${MAP_H}`}
					preserveAspectRatio="none"
					aria-hidden
					focusable="false"
				>
					{edges.map((e) => (
						<g key={e.key}>
							<path
								d={e.d}
								className={cn(s.edge, s[`edge-${e.status}`], s[`type-${e.kind}`])}
								vectorEffect="non-scaling-stroke"
								style={{ strokeWidth: e.width }}
							/>
							{e.flowing && (
								<path
									d={e.d}
									className={cn(s.edge, s.flow, e.reverse && s.flowReverse, s[`type-${e.kind}`])}
									vectorEffect="non-scaling-stroke"
									style={{ strokeWidth: e.width }}
								/>
							)}
						</g>
					))}
				</svg>
				{edges
					.filter((e) => e.label.text)
					.map((e) => (
						<span
							key={`label-${e.key}`}
							className={cn(s.edgeLabel, e.label.muted && s.edgeLabelMuted)}
							style={pos(e.mid)}
							aria-hidden
						>
							{e.label.text}
						</span>
					))}
				<HubCard interfaces={interfaces} online={online} total={links.length} style={pos(hub)} />
				{upper.length > 0 && (
					<div className={cn(s.section, s.sectionSites)}>
						<div className={s.sectionTitle}>{t("section.sites")}</div>
						{upper.map(renderNode)}
					</div>
				)}
				{(lower.length > 0 || moreNode) && (
					<div className={cn(s.section, s.sectionClients)}>
						<div className={s.sectionTitle}>{t("section.clients")}</div>
						{lower.map(renderNode)}
						{moreNode?.kind === "more" && (
							<MoreCard count={moreNode.more} style={pos(moreNode)} onClick={onShowMore} />
						)}
					</div>
				)}
			</div>
			<Legend counts={counts} online={online} total={links.length} />
		</figure>
	);
}

export default TopologyMap;
