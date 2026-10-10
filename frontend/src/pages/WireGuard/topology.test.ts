import { IconDeviceLaptop, IconDeviceMobile } from "@tabler/icons-react";
import type { Agent, WireGuardLink } from "src/api/backend";
import { describe, expect, it } from "vitest";
import {
	agentState,
	agoFmt,
	bindAgents,
	byteFmt,
	CARD_H,
	canvasSize,
	cardWidthFor,
	HUB_H,
	HUB_W,
	clientDevice,
	computeRates,
	displayStatus,
	edgeMidpoint,
	edgePath,
	layout,
	type Layout,
	linkStatus,
	MAP_H,
	MAP_W,
	matchLinkAgent,
	nodeKind,
	rateWidth,
} from "./topology";

const NOW = 1_800_000_000;

const mkLink = (over: Partial<WireGuardLink> = {}): WireGuardLink => ({
	id: `wg0:${over.name ?? "x"}`,
	interfaceName: "wg0",
	type: "site-to-site",
	name: "x",
	peerPublicKey: null,
	remoteEndpoint: null,
	allowedIps: [],
	tunnelAddresses: [],
	exportedNetworks: [],
	importedNetworks: [],
	latestHandshake: 0,
	rxBytes: 0,
	txBytes: 0,
	active: false,
	hasMetadata: true,
	returnPathMode: "unknown",
	remoteManagementMode: "unknown",
	warnings: [],
	nextActions: [],
	...over,
});

const mkAgent = (over: Partial<Agent> = {}): Agent => ({
	id: 1,
	name: "agent",
	mode: "native",
	hostname: null,
	wgInterface: "wg0",
	configText: null,
	configHash: null,
	lastSeen: NOW,
	status: "active",
	createdOn: 0,
	modifiedOn: 0,
	mgmtUrl: null,
	wgLinkName: null,
	agentVersion: null,
	services: [],
	allowedNetworks: null,
	allowedSites: null,
	preserveLanSourceIp: true,
	...over,
});

describe("linkStatus", () => {
	it("follows the handshake age boundaries", () => {
		const at = (age: number) => linkStatus(mkLink({ latestHandshake: NOW - age }), NOW);
		expect(at(179)).toBe("online");
		expect(at(181)).toBe("stale");
		expect(at(15 * 60)).toBe("stale");
		expect(at(15 * 60 + 1)).toBe("offline");
		expect(linkStatus(mkLink({ latestHandshake: 0 }), NOW)).toBe("never");
	});

	it("trusts the backend active flag", () => {
		expect(linkStatus(mkLink({ active: true, latestHandshake: NOW - 500 }), NOW)).toBe("online");
	});
});

describe("displayStatus", () => {
	it("shows offline/never clients as neutral idle", () => {
		expect(displayStatus(mkLink({ type: "client", latestHandshake: NOW - 3600 }), NOW)).toBe("idle");
		expect(displayStatus(mkLink({ type: "client" }), NOW)).toBe("idle");
		expect(displayStatus(mkLink({ type: "client", latestHandshake: NOW - 300 }), NOW)).toBe("stale");
		expect(displayStatus(mkLink({ type: "site-to-site", latestHandshake: NOW - 3600 }), NOW)).toBe("offline");
		expect(displayStatus(mkLink({ type: "hub-link" }), NOW)).toBe("never");
	});
});

describe("nodeKind / clientDevice", () => {
	it("maps link types", () => {
		expect(nodeKind(mkLink({ type: "site-to-site" }))).toBe("site");
		expect(nodeKind(mkLink({ type: "hub-link" }))).toBe("hub-link");
		expect(nodeKind(mkLink({ type: "client" }))).toBe("client");
		expect(nodeKind(mkLink({ type: "unknown" }))).toBe("other");
		expect(clientDevice(mkLink({ platform: "mobile" }))).toBe(IconDeviceMobile);
		expect(clientDevice(mkLink({ platform: "desktop" }))).toBe(IconDeviceLaptop);
		expect(clientDevice(mkLink({}))).toBe(IconDeviceLaptop);
	});
});

describe("bindAgents / agentState", () => {
	it("binds agents by link name", () => {
		const links = [
			mkLink({ name: "Hinderlich Office" }),
			mkLink({ name: "Daniel Home" }),
			mkLink({ name: "solo" }),
		];
		const agents = [
			mkAgent({ id: 1, name: "a1", wgLinkName: "Hinderlich Office" }),
			mkAgent({ id: 2, name: "a2", wgLinkName: "Daniel Home" }),
			mkAgent({ id: 3, name: "a3", wgLinkName: null }),
		];
		const map = bindAgents(links, agents);
		expect(map.get("wg0:Hinderlich Office")?.id).toBe(1);
		expect(map.get("wg0:Daniel Home")?.id).toBe(2);
		expect(map.has("wg0:solo")).toBe(false);
	});

	it("matches a generated link name by its public-key prefix, like the link cards", () => {
		const key = "AbCd1234efgh5678ijkl9012mnop3456qrst7890uvw=";
		// the binding was made while the link showed as "client-AbCd1234"; with a
		// second routed network it is shown as "hub-link-AbCd1234" now
		const link = mkLink({ name: "hub-link-AbCd1234", type: "hub-link", peerPublicKey: key });
		const other = mkLink({ name: "Daniel Home" });
		const agents = [mkAgent({ id: 7, name: "gw", wgLinkName: "client-AbCd1234" })];
		expect(bindAgents([link, other], agents).get(link.id)?.id).toBe(7);
		expect(matchLinkAgent(link, agents, [link, other])?.id).toBe(7);
		// two unnamed links with that prefix: ambiguous, no match
		const twin = mkLink({ name: "client-AbCd1234", type: "client", peerPublicKey: `${key.slice(0, 8)}zz` });
		expect(matchLinkAgent(link, agents, [link, twin])?.id).toBeUndefined();
	});

	it("falls back to agent name and tunnel IP for agents without a binding", () => {
		const link = mkLink({ name: "Office", tunnelAddresses: ["10.10.0.7/32"] });
		expect(bindAgents([link], [mkAgent({ id: 3, name: "Office" })]).get(link.id)?.id).toBe(3);
		expect(bindAgents([link], [mkAgent({ id: 4, name: "gw", hostname: "gw-10.10.0.7" })]).get(link.id)?.id).toBe(4);
		// bound to another existing link: not stolen by the name fallback
		const daniel = mkLink({ name: "Daniel Home" });
		expect(
			bindAgents([link, daniel], [mkAgent({ id: 5, name: "Office", wgLinkName: "Daniel Home" })]).get(link.id),
		).toBeUndefined();
	});

	it("derives the agent state like the backend", () => {
		expect(agentState(mkAgent({ lastSeen: NOW - 300 }), NOW)).toBe("online");
		expect(agentState(mkAgent({ lastSeen: NOW - 301 }), NOW)).toBe("offline");
		expect(agentState(mkAgent({ lastSeen: null }), NOW)).toBe("offline");
		expect(agentState(mkAgent({ status: "pending", lastSeen: null }), NOW)).toBe("pending");
		expect(agentState(mkAgent({ status: "error" }), NOW)).toBe("error");
	});
});

describe("layout", () => {
	const CARD_W = 148;
	const sites = ["Hinderlich Office", "Daniel Home", "PVE-Hetzner", "VM-Docker", "Site E", "Site F"].map((name) =>
		mkLink({ name, type: "site-to-site" }),
	);
	const clients = ["laptop", "phone"].map((name) => mkLink({ name, type: "client" }));

	it("is deterministic and centres the hub", () => {
		const a = layout([...sites, ...clients]);
		const b = layout([...clients].reverse().concat([...sites].reverse()));
		expect(a.hub).toEqual({ x: MAP_W / 2, y: MAP_H / 2 });
		expect(a.nodes.map((n) => [n.key, Math.round(n.x), Math.round(n.y)])).toEqual(
			b.nodes.map((n) => [n.key, Math.round(n.x), Math.round(n.y)]),
		);
	});

	it("puts sites above and clients below the hub", () => {
		const { hub, nodes } = layout([...sites, ...clients]);
		for (const n of nodes) {
			if (n.kind === "site") expect(n.y).toBeLessThan(hub.y);
			if (n.kind === "client") expect(n.y).toBeGreaterThan(hub.y);
		}
	});

	/** Pairs of overlapping card boxes (hub included) in px at a container width. */
	const overlapsAt = (l: Layout, width: number) => {
		const px = canvasSize(width);
		const cw = cardWidthFor(width);
		const box = (x: number, y: number, w: number, h: number) => {
			const cx = (x / MAP_W) * px.w;
			const cy = (y / MAP_H) * px.h;
			return { x0: cx - w / 2, x1: cx + w / 2, y0: cy - h / 2, y1: cy + h / 2 };
		};
		const boxes = [
			{ key: "hub", ...box(l.hub.x, l.hub.y, HUB_W, HUB_H) },
			...l.nodes.map((n) => ({ key: n.key, ...box(n.x, n.y, cw, CARD_H) })),
		];
		const out: string[] = [];
		for (let i = 0; i < boxes.length; i++) {
			for (let j = i + 1; j < boxes.length; j++) {
				const a = boxes[i];
				const b = boxes[j];
				if (a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1) out.push(`${a.key}/${b.key}`);
			}
		}
		return out;
	};

	it("keeps the cards of 6 sites + 2 clients apart on the map", () => {
		const l = layout([...sites, ...clients], { width: 1000 });
		expect(l.nodes).toHaveLength(8);
		expect(l.stacked).toBe(false);
		expect(overlapsAt(l, 1000)).toEqual([]);
		// node centres keep at least a card width apart horizontally or a card height vertically
		for (let i = 0; i < l.nodes.length; i++) {
			for (let j = i + 1; j < l.nodes.length; j++) {
				const a = l.nodes[i];
				const b = l.nodes[j];
				expect(Math.abs(a.x - b.x) >= CARD_W || Math.abs(a.y - b.y) >= CARD_H).toBe(true);
			}
		}
	});

	it("never overlaps cards: spreads, staggers, collapses clients or stacks", () => {
		const manySites = Array.from({ length: 8 }, (_, i) => mkLink({ name: `site${i}`, type: "site-to-site" }));
		const tenClients = Array.from({ length: 10 }, (_, i) =>
			mkLink({ name: `c${String(i).padStart(2, "0")}`, type: "client" }),
		);
		for (const width of [700, 1100]) {
			for (const set of [tenClients, manySites, [...manySites, ...tenClients], [...sites.slice(0, 5)]]) {
				const l = layout(set, { width });
				// stacked = CSS grid, no absolute positions — nothing can overlap there
				if (!l.stacked) expect(overlapsAt(l, width), `${set.length} links at ${width}px`).toEqual([]);
			}
		}
		// the common cases stay a map
		expect(layout(tenClients, { width: 1100 }).stacked).toBe(false);
		expect(layout(manySites, { width: 1100 }).stacked).toBe(false);
		expect(layout(sites.slice(0, 5), { width: 700 }).stacked).toBe(false);
		// too many sites for a narrow map → stacked grid instead of overlapping cards
		expect(layout(manySites, { width: 700 }).stacked).toBe(true);
	});

	it("keeps nodes inside the canvas", () => {
		const many = Array.from({ length: 14 }, (_, i) => mkLink({ name: `s${i}`, type: "site-to-site" }));
		for (const n of layout(many).nodes) {
			expect(n.x).toBeGreaterThan(0);
			expect(n.x).toBeLessThan(MAP_W);
			expect(n.y).toBeGreaterThan(0);
			expect(n.y).toBeLessThan(MAP_H);
		}
	});

	it("collapses more than 10 clients into 9 + a '+N' node, fewer when the map is too small", () => {
		const many = Array.from({ length: 13 }, (_, i) =>
			mkLink({ name: `c${String(i).padStart(2, "0")}`, type: "client" }),
		);
		const moreOf = (l: Layout) => {
			const more = l.nodes.find((n) => n.kind === "more");
			return more && "more" in more ? more.more : 0;
		};
		// narrow (stacked grid): the plain 9 + "+N" rule
		const narrow = layout(many, { width: 600 });
		expect(narrow.stacked).toBe(true);
		expect(narrow.nodes).toHaveLength(10);
		expect(moreOf(narrow)).toBe(4);
		expect(layout(many.slice(0, 10), { width: 600 }).nodes.some((n) => n.kind === "more")).toBe(false);
		// on a map only as many as fit, the rest in "+N" — every client is counted
		for (const width of [700, 1000, 1400]) {
			const l = layout(many, { width });
			const shown = l.nodes.filter((n) => n.kind === "client").length;
			expect(shown + moreOf(l)).toBe(13);
			expect(shown).toBeLessThanOrEqual(9);
			expect(overlapsAt(l, width)).toEqual([]);
		}
	});
});

describe("edges", () => {
	it("draws a slightly curved quadratic Bézier", () => {
		const hub = { x: 500, y: 280 };
		const node = { x: 500, y: 80 };
		expect(edgePath(hub, node)).toMatch(/^M 500 280 Q [\d.]+ 180 500 80$/);
		const mid = edgeMidpoint(hub, node);
		expect(mid.y).toBeCloseTo(180);
		expect(mid.x).not.toBeCloseTo(500);
	});

	it("scales the stroke width on a log scale", () => {
		expect(rateWidth(null)).toBe(1.5);
		expect(rateWidth(500)).toBe(1.5);
		expect(rateWidth(100 * 1024 * 1024)).toBe(4);
		expect(rateWidth(1e12)).toBe(4);
		const mid = rateWidth(1024 * 1024);
		expect(mid).toBeGreaterThan(1.5);
		expect(mid).toBeLessThan(4);
	});
});

describe("computeRates", () => {
	it("computes bytes per second between samples", () => {
		const l1 = mkLink({ name: "a", rxBytes: 1000, txBytes: 2000 });
		const first = computeRates(new Map(), [l1], 0);
		expect(first.rates.get(l1.id)).toEqual({ rxRate: null, txRate: null, total: 3000 });
		const l2 = { ...l1, rxBytes: 16000, txBytes: 2000 };
		const second = computeRates(first.samples, [l2], 15000);
		expect(second.rates.get(l1.id)).toEqual({ rxRate: 1000, txRate: 0, total: 18000 });
	});

	it("returns null after a counter reset", () => {
		const l1 = mkLink({ name: "a", rxBytes: 50_000, txBytes: 50_000 });
		const first = computeRates(new Map(), [l1], 0);
		const reset = computeRates(first.samples, [{ ...l1, rxBytes: 10, txBytes: 60_000 }], 15000);
		expect(reset.rates.get(l1.id)).toEqual({ rxRate: null, txRate: null, total: 60_010 });
	});
});

describe("formatters", () => {
	it("formats bytes and ages", () => {
		expect(byteFmt(512)).toBe("512 B");
		expect(byteFmt(1536)).toBe("1.50 KB");
		expect(agoFmt(40)).toBe("40 s");
		expect(agoFmt(6 * 60)).toBe("6 min");
		expect(agoFmt(3 * 3600)).toBe("3 h");
	});
});
