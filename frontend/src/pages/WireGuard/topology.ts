import { IconDeviceLaptop, IconDeviceMobile } from "@tabler/icons-react";
import { useMemo, useRef } from "react";
import type { Agent, WireGuardLink } from "src/api/backend";

// Pure helpers for the WireGuard topology map (TopologyMap.tsx). Times are
// unix seconds, like latestHandshake / lastSeen from the backend.

/** Mirrors ACTIVE_HANDSHAKE_WINDOW in backend/internal/wireguard.js */
export const ACTIVE_HANDSHAKE_WINDOW_S = 180;
/** Past this a handshake is no longer "stale" but "offline" */
export const STALE_HANDSHAKE_S = 15 * 60;
/** Mirrors AGENT_OFFLINE_AFTER_S in the backend */
export const AGENT_OFFLINE_AFTER_S = 300;

export const MAP_W = 1000;
export const MAP_H = 560;
const RX = 400;
const RY = 210;
/** Inner radius factor of staggered (every second) nodes (tried together with one that just clears a card height) */
const STAGGER_INNER = 0.62;
/** Arc ends (degrees from the horizontal): upper and lower arc end cards must not touch each other */
const ARC_END = 12;
/** Above this many clients, show CLIENT_VISIBLE and a "+N" node (fewer when they do not fit) */
const CLIENT_LIMIT = 10;
const CLIENT_VISIBLE = 9;
/** Max spacing between neighbours as a fraction of the arc (keeps few nodes together) */
const MAX_STEP = 0.2;

// Rendered sizes in px (TopologyMap.module.css): the layout checks real card
// boxes for overlap, because cards do not scale with the canvas.
export const CARD_W = 148;
/** .node width in a container ≤ 900 px */
export const CARD_W_NARROW = 120;
/** tallest node card (name, status, chips row) */
export const CARD_H = 78;
export const HUB_W = 184;
export const HUB_H = 104;
const CARD_GAP = 6;
/** At or below this container width the CSS stacks the cards anyway (no map). */
export const STACK_BELOW = 640;

/** Canvas size in px for a container width (aspect-ratio 16/9, height clamped 360–640 like the CSS). */
export const canvasSize = (width: number) => ({ w: width, h: Math.min(640, Math.max(360, (width * 9) / 16)) });
export const cardWidthFor = (width: number) => (width <= 900 ? CARD_W_NARROW : CARD_W);

export type LinkStatus = "online" | "stale" | "offline" | "never";
export type DisplayStatus = LinkStatus | "idle";
export type NodeKind = "site" | "hub-link" | "client" | "other";
export type AgentState = "online" | "offline" | "pending" | "error";
export type Point = { x: number; y: number };

export const nowSeconds = () => Math.floor(Date.now() / 1000);

export const byteFmt = (value?: number) => {
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

/** Bytes per second, e.g. "1.20 MB/s" */
export const rateFmt = (value: number) => `${byteFmt(Math.round(value))}/s`;

/** Short age, e.g. "40 s", "6 min", "3 h", "2 d" */
export const agoFmt = (seconds: number) => {
	const s = Math.max(0, Math.floor(seconds));
	if (s < 60) return `${s} s`;
	if (s < 3600) return `${Math.floor(s / 60)} min`;
	if (s < 86400) return `${Math.floor(s / 3600)} h`;
	return `${Math.floor(s / 86400)} d`;
};

export function linkStatus(link: Pick<WireGuardLink, "active" | "latestHandshake">, now: number): LinkStatus {
	if (link.active) return "online";
	const hs = Number(link.latestHandshake) || 0;
	if (!hs) return "never";
	const age = now - hs;
	if (age < ACTIVE_HANDSHAKE_WINDOW_S) return "online";
	if (age <= STALE_HANDSHAKE_S) return "stale";
	return "offline";
}

export function nodeKind(link: Pick<WireGuardLink, "type">): NodeKind {
	switch (link.type) {
		case "site-to-site":
			return "site";
		case "hub-link":
			return "hub-link";
		case "client":
			return "client";
		default:
			return "other";
	}
}

/** Road warriors are usually disconnected: their offline/never is neutral, not red. */
export function displayStatus(link: WireGuardLink, now: number): DisplayStatus {
	const st = linkStatus(link, now);
	if (nodeKind(link) === "client" && (st === "offline" || st === "never")) return "idle";
	return st;
}

export function clientDevice(link: Pick<WireGuardLink, "platform">) {
	return link.platform === "mobile" ? IconDeviceMobile : IconDeviceLaptop;
}

type LinkRef = Pick<WireGuardLink, "name" | "type" | "peerPublicKey" | "tunnelAddresses">;
type AgentRef = Pick<Agent, "name" | "hostname" | "wgLinkName" | "lastSeen">;

/** A link shown under its generated name `${type}-${pubkey8}` (no stored name). */
const isGeneratedLinkName = (l: LinkRef) => !!l.peerPublicKey && l.name === `${l.type}-${l.peerPublicKey.slice(0, 8)}`;

const newestSeen = <A extends AgentRef>(list: A[]): A | undefined =>
	list.reduce<A | undefined>((best, a) => (!best || (a.lastSeen ?? 0) > (best.lastSeen ?? 0) ? a : best), undefined);

/**
 * The agent of one link — the same matching for link cards and the topology
 * map, mirroring the backend's resolveBoundStatusLink:
 *   1. agent.wgLinkName === link.name (most recently seen wins);
 *   2. a generated name ("client-AbCd1234") by its public-key prefix: the type
 *      part is inferred from AllowedIPs and changes (client-… → hub-link-…),
 *      so the stored binding may carry the old prefix. Only when exactly one
 *      unnamed link carries that key prefix and no link has the stored name;
 *   3. agent name === link name;
 *   4. the link's tunnel IP in the agent's hostname or name.
 * Steps 3–4 only consider agents not bound to another existing link.
 */
export function matchLinkAgent<A extends AgentRef>(
	link: LinkRef,
	agents: A[],
	allLinks: LinkRef[] = [link],
): A | undefined {
	const exact = newestSeen(agents.filter((a) => !!a.wgLinkName && a.wgLinkName === link.name));
	if (exact) return exact;
	const linkNames = new Set(allLinks.map((l) => l.name));
	if (isGeneratedLinkName(link)) {
		const byKey = agents.filter((a) => {
			const m = /^(.+)-([A-Za-z0-9+/]{8})$/.exec(a.wgLinkName ?? "");
			if (!m || linkNames.has(a.wgLinkName ?? "") || !link.peerPublicKey?.startsWith(m[2])) return false;
			return allLinks.filter((l) => isGeneratedLinkName(l) && l.peerPublicKey?.startsWith(m[2])).length === 1;
		});
		const k = newestSeen(byKey);
		if (k) return k;
	}
	const unbound = agents.filter((a) => !a.wgLinkName || !linkNames.has(a.wgLinkName));
	return (
		unbound.find((a) => a.name === link.name) ??
		unbound.find((a) =>
			link.tunnelAddresses.some((addr) => {
				const ip = addr.replace(/\/\d+$/, "");
				return !!ip && ((a.hostname ?? "").includes(ip) || a.name.includes(ip));
			}),
		)
	);
}

/** Agent per link id (see matchLinkAgent). */
export function bindAgents(links: WireGuardLink[], agents: Agent[]): Map<string, Agent> {
	const out = new Map<string, Agent>();
	for (const link of links) {
		const agent = matchLinkAgent(link, agents, links);
		if (agent) out.set(link.id, agent);
	}
	return out;
}

export function agentState(agent: Pick<Agent, "status" | "lastSeen">, now: number): AgentState {
	if (agent.status === "error") return "error";
	if (agent.status === "pending") return "pending";
	if (!agent.lastSeen || now - agent.lastSeen > AGENT_OFFLINE_AFTER_S) return "offline";
	return "online";
}

// ── Layout ─────────────────────────────────────────────────────────────────────

export type LayoutNode =
	| { key: string; kind: NodeKind; link: WireGuardLink; x: number; y: number }
	| { key: string; kind: "more"; more: number; x: number; y: number };

/**
 * stacked: the cards do not fit on the map without overlapping at this width —
 * render the stacked grid (as on narrow screens) instead.
 */
export type Layout = { hub: Point; nodes: LayoutNode[]; stacked: boolean };

const byName = (a: WireGuardLink, b: WireGuardLink) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id);

const deg = (d: number) => (d * Math.PI) / 180;

/**
 * Parametric angles (degrees) for `count` nodes on the ellipse arc
 * [startDeg, endDeg], spaced by arc length so neighbours keep the same
 * distance where the ellipse bends. Few nodes stay grouped around the middle.
 */
function arcAngles(
	count: number,
	startDeg: number,
	endDeg: number,
	rx: number,
	ry: number,
	stepFrac: number = count === 1 ? 0 : Math.min(1 / (count - 1), MAX_STEP),
): number[] {
	if (count <= 0) return [];
	const steps = 360;
	const cum = [0];
	let px = rx * Math.cos(deg(startDeg));
	let py = ry * Math.sin(deg(startDeg));
	for (let i = 1; i <= steps; i++) {
		const a = deg(startDeg + ((endDeg - startDeg) * i) / steps);
		const x = rx * Math.cos(a);
		const y = ry * Math.sin(a);
		cum.push(cum[i - 1] + Math.hypot(x - px, y - py));
		px = x;
		py = y;
	}
	const total = cum[steps];
	const step = count === 1 ? 0 : stepFrac;
	const out: number[] = [];
	for (let i = 0; i < count; i++) {
		const target = (0.5 + (i - (count - 1) / 2) * step) * total;
		let j = 1;
		while (j < steps && cum[j] < target) j++;
		const seg = cum[j] - cum[j - 1] || 1;
		const frac = Math.min(1, Math.max(0, (target - cum[j - 1]) / seg));
		out.push(startDeg + ((endDeg - startDeg) * (j - 1 + frac)) / steps);
	}
	return out;
}

/** stepFrac: spacing as a fraction of the arc; stagger: radius factor of every second node; scale: radii factor */
type ArcVariant = { stepFrac?: number; stagger?: number; scale?: number };

function placeArc(
	count: number,
	startDeg: number,
	endDeg: number,
	hub: Point,
	rx: number,
	ry: number,
	{ stepFrac, stagger = 1, scale = 1 }: ArcVariant = {},
): Point[] {
	const sx = rx * scale;
	const sy = ry * scale;
	return arcAngles(count, startDeg, endDeg, sx, sy, stepFrac).map((a, i) => {
		const k = i % 2 === 1 ? stagger : 1;
		return { x: hub.x + k * sx * Math.cos(deg(a)), y: hub.y + k * sy * Math.sin(deg(a)) };
	});
}

type Box = { x0: number; y0: number; x1: number; y1: number };

const boxAt = (c: Point, w: number, h: number): Box => ({
	x0: c.x - w / 2 - CARD_GAP / 2,
	y0: c.y - h / 2 - CARD_GAP / 2,
	x1: c.x + w / 2 + CARD_GAP / 2,
	y1: c.y + h / 2 + CARD_GAP / 2,
});

const overlaps = (a: Box, b: Box) => a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;

/**
 * Arc placements from tight to loose: few nodes grouped around the middle,
 * then spread over the whole arc, then alternating radii (staggered rows).
 */
function arcVariants(count: number, ryPx: number): ArcVariant[] {
	if (count <= 1) return [{}];
	const full = 1 / (count - 1);
	const compact = Math.min(full, MAX_STEP);
	const steps = [0, 0.25, 0.5, 0.75, 1].map((t) => compact + (full - compact) * t);
	const uniq = [...new Set(steps.map((v) => Math.round(v * 1e6) / 1e6))];
	const out: ArcVariant[] = uniq.map((stepFrac) => ({ stepFrac }));
	// then wider radii (up to the canvas edge) and staggered rows: the inner row
	// either at STAGGER_INNER or just one card height (+gap) further in
	for (const scale of [1, 1.12]) {
		const clearing = Math.round((1 - (CARD_H + CARD_GAP + 2) / (ryPx * scale)) * 100) / 100;
		const staggers = [...new Set([clearing, STAGGER_INNER])].filter((k) => k >= 0.4 && k < 1).sort((a, b) => b - a);
		if (scale !== 1) out.push(...uniq.map((stepFrac) => ({ stepFrac, scale })));
		for (const stagger of staggers) out.push(...uniq.map((stepFrac) => ({ stepFrac, stagger, scale })));
	}
	return out;
}

/**
 * Node positions in viewBox units: hub in the centre, sites and hub-links on
 * the upper arc, clients on the lower arc, anything else on the sides.
 * Deterministic: the order inside an arc is by name, so polls don't reshuffle.
 *
 * `width` = the container width in px. Cards keep their pixel size while the
 * canvas scales, so every placement is checked as real card boxes: the arc
 * spreads out and staggers until no two cards (nor a card and the hub) overlap;
 * clients collapse into "+N" further when needed. When the sites still do not
 * fit, `stacked` asks for the stacked grid instead of overlapping cards.
 */
export function layout(links: WireGuardLink[], { width = MAP_W }: { width?: number } = {}): Layout {
	const hub = { x: MAP_W / 2, y: MAP_H / 2 };
	const rx = RX;
	const ry = RY;
	const upper: WireGuardLink[] = [];
	const lower: WireGuardLink[] = [];
	const other: WireGuardLink[] = [];
	for (const link of links) {
		const kind = nodeKind(link);
		if (kind === "site" || kind === "hub-link") upper.push(link);
		else if (kind === "client") lower.push(link);
		else other.push(link);
	}
	upper.sort(byName);
	lower.sort(byName);
	other.sort(byName);

	const px = canvasSize(width);
	const cw = cardWidthFor(width);
	const toPx = (p: Point): Point => ({ x: (p.x / MAP_W) * px.w, y: (p.y / MAP_H) * px.h });
	const ryPx = (ry / MAP_H) * px.h;
	const placed: Box[] = [boxAt(toPx(hub), HUB_W, HUB_H)];
	let stacked = width <= STACK_BELOW;
	const fits = (pts: Point[]) => {
		const boxes = pts.map((p) => boxAt(toPx(p), cw, CARD_H));
		const inside = boxes.every(
			(b) => b.x0 >= -CARD_GAP && b.y0 >= -CARD_GAP && b.x1 <= px.w + CARD_GAP && b.y1 <= px.h + CARD_GAP,
		);
		if (!inside) return false;
		for (let i = 0; i < boxes.length; i++) {
			if (placed.some((p) => overlaps(p, boxes[i]))) return false;
			for (let j = i + 1; j < boxes.length; j++) if (overlaps(boxes[i], boxes[j])) return false;
		}
		return true;
	};
	/** First arc placement without overlaps; null when none fits. Accepted boxes join `placed`. */
	const placeFitting = (count: number, startDeg: number, endDeg: number): Point[] | null => {
		for (const v of arcVariants(count, ryPx)) {
			const pts = placeArc(count, startDeg, endDeg, hub, rx, ry, v);
			if (fits(pts)) {
				placed.push(...pts.map((p) => boxAt(toPx(p), cw, CARD_H)));
				return pts;
			}
		}
		return null;
	};
	/** Like placeFitting, falling back to the loosest variant (marks the layout stacked). */
	const place = (count: number, startDeg: number, endDeg: number): Point[] => {
		const pts = placeFitting(count, startDeg, endDeg);
		if (pts) return pts;
		stacked = true;
		const variants = arcVariants(count, ryPx);
		return placeArc(count, startDeg, endDeg, hub, rx, ry, variants[variants.length - 1]);
	};

	const nodes: LayoutNode[] = [];

	// Sides first (few, around the equator): the arcs then keep clear of them.
	const right = other.filter((_, i) => i % 2 === 0);
	const left = other.filter((_, i) => i % 2 === 1);
	place(right.length, -10, 10).forEach((p, i) => {
		nodes.push({ key: right[i].id, kind: "other", link: right[i], ...p });
	});
	place(left.length, 190, 170).forEach((p, i) => {
		nodes.push({ key: left[i].id, kind: "other", link: left[i], ...p });
	});

	// side nodes sit around the equator: the arcs then end higher / lower
	const arcEnd = other.length ? ARC_END + 16 : ARC_END;
	place(upper.length, -180 + arcEnd, -arcEnd).forEach((p, i) => {
		nodes.push({ key: upper[i].id, kind: nodeKind(upper[i]), link: upper[i], ...p });
	});

	// Lower arc runs left to right (168° → 12°) so the name order reads naturally.
	// All clients when they fit (up to CLIENT_LIMIT), else fewer + a "+N" node.
	// In the stacked grid (narrow, or sites that did not fit) the plain limit applies.
	const legacyShown = lower.length > CLIENT_LIMIT ? CLIENT_VISIBLE : lower.length;
	let shownCount = legacyShown;
	let lowerPts: Point[] | null = null;
	if (!stacked) {
		const candidates: number[] = [];
		if (lower.length <= CLIENT_LIMIT) candidates.push(lower.length);
		for (let v = Math.min(lower.length - 1, CLIENT_VISIBLE); v >= 1; v--) candidates.push(v);
		for (const v of candidates) {
			lowerPts = placeFitting(v + (v < lower.length ? 1 : 0), 180 - arcEnd, arcEnd);
			if (lowerPts) {
				shownCount = v;
				break;
			}
		}
	}
	if (!lowerPts) {
		shownCount = legacyShown;
		lowerPts = place(shownCount + (shownCount < lower.length ? 1 : 0), 180 - arcEnd, arcEnd);
	}
	const pts = lowerPts;
	const shown = lower.slice(0, shownCount);
	shown.forEach((link, i) => {
		nodes.push({ key: link.id, kind: "client", link, ...pts[i] });
	});
	if (shownCount < lower.length) {
		nodes.push({
			key: "more:clients",
			kind: "more",
			more: lower.length - shownCount,
			...pts[shownCount],
		});
	}
	return { hub, nodes, stacked };
}

// ── Edges ──────────────────────────────────────────────────────────────────────

/** Control point: the midpoint pushed perpendicular by 6 % of the length. */
export function edgeControl(hub: Point, node: Point): Point {
	const dx = node.x - hub.x;
	const dy = node.y - hub.y;
	const len = Math.hypot(dx, dy) || 1;
	const off = 0.06 * len;
	return { x: (hub.x + node.x) / 2 - (dy / len) * off, y: (hub.y + node.y) / 2 + (dx / len) * off };
}

/** Quadratic Bézier from the hub to a node with a slight curve. */
export function edgePath(hub: Point, node: Point): string {
	const c = edgeControl(hub, node);
	const r = (n: number) => Math.round(n * 10) / 10;
	return `M ${r(hub.x)} ${r(hub.y)} Q ${r(c.x)} ${r(c.y)} ${r(node.x)} ${r(node.y)}`;
}

/** Point on the curve at t = 0.5 (where the edge label sits). */
export function edgeMidpoint(hub: Point, node: Point): Point {
	const c = edgeControl(hub, node);
	return { x: 0.25 * hub.x + 0.5 * c.x + 0.25 * node.x, y: 0.25 * hub.y + 0.5 * c.y + 0.25 * node.y };
}

/** Stroke width 1.5–4 px on a log scale from 1 KB/s to 100 MB/s. */
export function rateWidth(rate: number | null | undefined): number {
	if (!rate || rate <= 1024) return 1.5;
	const t = (Math.log10(rate) - Math.log10(1024)) / (Math.log10(100 * 1024 * 1024) - Math.log10(1024));
	return Math.round((1.5 + 2.5 * Math.min(1, Math.max(0, t))) * 100) / 100;
}

// ── Transfer rates ─────────────────────────────────────────────────────────────

export type RateSample = { rx: number; tx: number; at: number };
export type LinkRate = { rxRate: number | null; txRate: number | null; total: number };

/**
 * Bytes/s since the previous sample (at = ms). No previous sample, a counter
 * that went down (interface restart) or no elapsed time → null rates.
 */
export function computeRates(
	prev: Map<string, RateSample>,
	links: WireGuardLink[],
	at: number,
): { rates: Map<string, LinkRate>; samples: Map<string, RateSample> } {
	const rates = new Map<string, LinkRate>();
	const samples = new Map<string, RateSample>();
	for (const link of links) {
		const rx = Number(link.rxBytes) || 0;
		const tx = Number(link.txBytes) || 0;
		const p = prev.get(link.id);
		const dt = p ? (at - p.at) / 1000 : 0;
		const valid = p && dt > 0 && rx >= p.rx && tx >= p.tx;
		rates.set(link.id, {
			rxRate: valid ? (rx - p.rx) / dt : null,
			txRate: valid ? (tx - p.tx) / dt : null,
			total: rx + tx,
		});
		samples.set(link.id, { rx, tx, at });
	}
	return { rates, samples };
}

/** Per-link transfer rates between polls (the status query refetches every 15 s). */
export function useLinkRates(links: WireGuardLink[]): Map<string, LinkRate> {
	const samples = useRef(new Map<string, RateSample>());
	// Cache per links array so a repeated render (StrictMode) doesn't take a second sample.
	const cache = useRef(new WeakMap<WireGuardLink[], Map<string, LinkRate>>());
	return useMemo(() => {
		const hit = cache.current.get(links);
		if (hit) return hit;
		const res = computeRates(samples.current, links, Date.now());
		samples.current = res.samples;
		cache.current.set(links, res.rates);
		return res.rates;
	}, [links]);
}
