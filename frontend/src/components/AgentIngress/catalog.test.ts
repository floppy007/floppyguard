import type { AgentIngressCatalog, AgentIngressPortPreset, AgentIngressRule } from "src/api/backend";
import { describe, expect, it } from "vitest";
import {
	collapseCidrs,
	describeRule,
	entryById,
	entryLabel,
	expandEntries,
	flatEntries,
	groupRulesBySource,
	labelForCidr,
	lineCount,
	portsToPresetSelection,
	pruneSelection,
	ruleForSiteAccess,
	ruleForSiteFull,
	ruleForUpstream,
	selectionToPorts,
	targetsFromValue,
} from "./catalog";

const presets: AgentIngressPortPreset[] = [
	{
		id: "web",
		ports: [
			{ proto: "tcp", port: "80" },
			{ proto: "tcp", port: "443" },
		],
	},
	{ id: "ssh", ports: [{ proto: "tcp", port: "22" }] },
	{
		id: "dns",
		ports: [
			{ proto: "tcp", port: "53" },
			{ proto: "udp", port: "53" },
		],
	},
	{ id: "all", ports: [] },
];

const catalogFixture: AgentIngressCatalog = {
	agentId: 1,
	agentName: "VM-Docker",
	ingressMode: "restricted",
	linkFound: true,
	site: { linkId: "wg0:FH", name: "Floppy Home", networks: ["10.3.10.0/24"] },
	sources: [
		{ id: "hub", kind: "hub", label: "hub", cidrs: ["10.10.0.1/32"], hint: "snat-hub-lan" },
		{ id: "egress:mail", kind: "hub-egress", label: "Mailcow LDAP", cidrs: ["10.10.0.6/32"] },
		{
			id: "site:wg0:H",
			kind: "site",
			label: "Hinderlich Office",
			cidrs: ["192.168.200.0/24", "10.4.10.0/24", "10.10.0.5/32"],
			online: true,
		},
		{
			id: "site-net:wg0:H:192.168.200.0/24",
			kind: "site-net",
			label: "192.168.200.0/24",
			cidrs: ["192.168.200.0/24"],
			parent: "site:wg0:H",
		},
		{
			id: "site-net:wg0:H:10.4.10.0/24",
			kind: "site-net",
			label: "10.4.10.0/24",
			cidrs: ["10.4.10.0/24"],
			parent: "site:wg0:H",
		},
		{ id: "site:wg0:D", kind: "site", label: "Daniel Home", cidrs: ["192.168.111.0/24"] },
		{ id: "client:wg0:N", kind: "client", label: "Notebook Flo", cidrs: ["10.10.0.20/32"] },
		{ id: "tunnel:wg0", kind: "tunnel", label: "10.10.0.0/24", cidrs: ["10.10.0.0/24"] },
	],
	destinations: [
		{
			id: "host:10.3.10.25",
			kind: "proxy-host",
			label: "Ops-Server",
			names: ["Ops-Server", "ops.example.com"],
			cidrs: ["10.3.10.25/32"],
			ports: [{ proto: "tcp", port: "443" }],
			enabled: true,
			covered: false,
		},
		{
			id: "host:10.3.10.6",
			kind: "hub-egress",
			label: "Mailcow LDAP",
			names: ["Mailcow LDAP"],
			cidrs: ["10.3.10.6/32"],
			ports: [{ proto: "tcp", port: "636" }],
			enabled: true,
			covered: false,
		},
		{
			id: "host:10.3.10.30",
			kind: "manual",
			label: "var.example.com",
			names: ["var.example.com"],
			cidrs: ["10.3.10.30/32"],
			ports: [],
			enabled: true,
			covered: false,
			hint: "no-port",
		},
		{
			id: "service:1:0",
			kind: "service",
			label: "Unraid",
			names: ["Unraid"],
			cidrs: ["10.3.10.12/32"],
			ports: [{ proto: "tcp", port: "80" }],
		},
		{ id: "net:10.3.10.0/24", kind: "network", label: "10.3.10.0/24", cidrs: ["10.3.10.0/24"] },
	],
	portPresets: presets,
	pruneCandidates: [],
};

const cat = catalogFixture;
const byId = (id: string) => {
	const e = entryById(cat).get(id);
	if (!e) throw new Error(id);
	return e;
};

const rule = (over: Partial<AgentIngressRule>): AgentIngressRule => ({
	id: 1,
	agentId: 1,
	name: "r",
	sources: [],
	destinations: [],
	ports: [],
	enabled: true,
	note: null,
	hitPackets: 0,
	lastHitAt: null,
	createdOn: 1_000,
	modifiedOn: 1_000,
	...over,
});

describe("catalog labels", () => {
	it("indexes entries", () => {
		expect(flatEntries(cat)).toHaveLength(cat.sources.length + cat.destinations.length);
		expect(flatEntries(undefined)).toEqual([]);
		expect(byId("hub").kind).toBe("hub");
	});

	it("labelForCidr: exact matches by priority, lone hosts inside a network, raw otherwise", () => {
		expect(labelForCidr("10.3.10.25", cat)).toBe("Ops-Server (10.3.10.25)");
		expect(labelForCidr("10.3.10.12/32", cat)).toBe("Unraid (10.3.10.12)");
		expect(labelForCidr("192.168.200.0/24", cat)).toBe("Hinderlich Office · 192.168.200.0/24");
		expect(labelForCidr("192.168.111.0/24", cat)).toBe("Daniel Home");
		expect(labelForCidr("10.10.0.20", cat)).toBe("Notebook Flo");
		expect(labelForCidr("10.10.0.1/32", cat)).toBe("Reverse proxy (hub)");
		expect(labelForCidr("10.3.10.0/24", cat)).toBe("Floppy Home · 10.3.10.0/24");
		expect(labelForCidr("10.3.10.77", cat)).toBe("10.3.10.77 (Floppy Home)");
		expect(labelForCidr("192.168.200.9", cat)).toBe("192.168.200.9 (Hinderlich Office)");
		expect(labelForCidr("8.8.8.8/32", cat)).toBe("8.8.8.8");
		expect(labelForCidr("10.3.10.25", undefined)).toBe("10.3.10.25");
	});

	it("entryLabel names sites, tunnel and hub", () => {
		expect(entryLabel(byId("site:wg0:H"), cat)).toBe("Hinderlich Office (3 networks)");
		expect(entryLabel(byId("tunnel:wg0"), cat)).toBe("All VPN participants (10.10.0.0/24)");
		expect(entryLabel(byId("hub"), cat)).toBe("Reverse proxy (hub)");
		expect(entryLabel(byId("egress:mail"), cat)).toBe("Mailcow LDAP");
	});

	it("collapseCidrs prefers whole entries, larger first, and keeps the rest", () => {
		const full = collapseCidrs(["10.10.0.5", "192.168.200.0/24", "10.4.10.0/24", "1.2.3.4"], cat.sources);
		expect(full.entries.map((e) => e.id)).toEqual(["site:wg0:H"]);
		expect(full.rest).toEqual(["1.2.3.4"]);
		const part = collapseCidrs(["192.168.200.0/24", "10.3.10.25"], cat.sources);
		expect(part.entries.map((e) => e.id)).toEqual(["site-net:wg0:H:192.168.200.0/24"]);
		expect(part.rest).toEqual(["10.3.10.25"]);
		expect(collapseCidrs(["10.0.0.1", "10.0.0.1/32"], [])).toEqual({ entries: [], rest: ["10.0.0.1"] });
	});

	it("describeRule resolves names; without catalog raw CIDRs", () => {
		const r = rule({
			sources: ["10.10.0.1"],
			destinations: ["10.3.10.25", "10.3.10.12"],
			ports: [{ proto: "tcp", port: "443" }],
		});
		expect(describeRule(r, cat)).toEqual({
			sourceLabel: "Reverse proxy (hub)",
			sourceKey: "10.10.0.1/32",
			targets: ["Ops-Server (10.3.10.25)", "Unraid (10.3.10.12)"],
			anyTarget: false,
			portsText: "ports tcp/443",
		});
		expect(describeRule({ ...r, destinations: [], ports: [] }, null)).toMatchObject({
			sourceLabel: "10.10.0.1",
			anyTarget: true,
			portsText: "all ports",
		});
	});

	it("groupRulesBySource: hub first, sites A→Z, clients, others", () => {
		const rules = [
			rule({ id: 1, sources: ["8.8.8.8"] }),
			rule({ id: 2, sources: ["10.10.0.20"] }),
			rule({ id: 3, sources: ["192.168.200.0/24"] }),
			rule({ id: 4, sources: ["192.168.111.0/24"] }),
			rule({ id: 5, sources: ["10.10.0.1/32"] }),
			rule({ id: 6, sources: ["10.10.0.1"], enabled: false }),
		];
		const groups = groupRulesBySource(rules, cat);
		expect(groups.map((g) => g.label)).toEqual([
			"Reverse proxy (hub)",
			"Daniel Home",
			"Hinderlich Office · 192.168.200.0/24",
			"Notebook Flo",
			"8.8.8.8",
		]);
		expect(groups[0].rules.map((r) => r.id)).toEqual([5, 6]);
		expect(groups[0].key).toBe("10.10.0.1/32");
	});

	it("targetsFromValue and expandEntries", () => {
		expect(targetsFromValue("10.3.10.25, 9.9.9.9", cat.destinations, cat)).toEqual([
			{ label: "Ops-Server (10.3.10.25)", cidrs: ["10.3.10.25/32"] },
			{ label: "9.9.9.9", cidrs: ["9.9.9.9/32"] },
		]);
		const expanded = expandEntries(cat.sources, cat);
		// the site's nets already have entries: only its tunnel address is split off
		expect(expanded.filter((e) => e.id.startsWith("site:wg0:H#")).map((e) => e.cidrs)).toEqual([
			["10.10.0.5/32"],
		]);
		expect(expanded.every((e) => e.cidrs.length === 1)).toBe(true);
	});
});

describe("ports", () => {
	it("maps ports to presets and back", () => {
		expect(portsToPresetSelection([], presets)).toEqual({ presetIds: ["all"], custom: "" });
		expect(
			portsToPresetSelection(
				[
					{ proto: "tcp", port: "443" },
					{ proto: "tcp", port: "80" },
					{ proto: "tcp", port: "8443" },
				],
				presets,
			),
		).toEqual({ presetIds: ["web"], custom: "tcp/8443" });
		expect(selectionToPorts(["web"], "udp/51820, bogus", presets)).toEqual([
			{ proto: "tcp", port: "80" },
			{ proto: "tcp", port: "443" },
			{ proto: "udp", port: "51820" },
		]);
		expect(selectionToPorts(["all", "web"], "tcp/22", presets)).toEqual([]);
		expect(selectionToPorts(["ssh"], "tcp/22", presets)).toEqual([{ proto: "tcp", port: "22" }]);
	});
});

describe("wizard factories", () => {
	it("ruleForUpstream mirrors the backend suggestion", () => {
		const hub = byId("hub");
		expect(ruleForUpstream(byId("host:10.3.10.25"), hub)).toEqual({
			name: "Proxy Ops-Server",
			sources: ["10.10.0.1/32"],
			destinations: ["10.3.10.25/32"],
			ports: [{ proto: "tcp", port: "443" }],
			enabled: true,
		});
		// egress flows use their own source
		expect(ruleForUpstream(byId("host:10.3.10.6"), hub, [byId("egress:mail")])).toMatchObject({
			name: "Hub Mailcow LDAP",
			sources: ["10.10.0.6/32"],
		});
		expect(ruleForUpstream(byId("host:10.3.10.30"), hub)).toBeNull();
		expect(ruleForUpstream(byId("host:10.3.10.25"), null)).toBeNull();
	});

	it("site access and full access rules", () => {
		const site = { label: "Hinderlich Office", cidrs: ["192.168.200.0/24"] };
		const r = ruleForSiteAccess(
			site,
			[
				{ label: "Ops-Server", cidrs: ["10.3.10.25/32"] },
				{ label: "Unraid", cidrs: ["10.3.10.12/32"] },
			],
			[{ proto: "tcp", port: "22" }],
		);
		expect(r).toEqual({
			name: "Hinderlich Office → Ops-Server +1",
			sources: ["192.168.200.0/24"],
			destinations: ["10.3.10.25/32", "10.3.10.12/32"],
			ports: [{ proto: "tcp", port: "22" }],
			enabled: true,
		});
		expect(ruleForSiteFull(site)).toEqual({
			name: "Hinderlich Office – full access",
			sources: ["192.168.200.0/24"],
			destinations: [],
			ports: [],
			enabled: true,
		});
	});

	it("lineCount mirrors ruleLineCount", () => {
		expect(lineCount({ sources: ["a", "b"], destinations: [], ports: [] })).toBe(2);
		expect(
			lineCount({
				sources: ["a", "b"],
				destinations: ["c", "d", "e"],
				ports: [
					{ proto: "tcp", port: "1" },
					{ proto: "tcp", port: "2" },
				],
			}),
		).toBe(12);
		expect(lineCount({ sources: [], destinations: ["c"], ports: [] })).toBe(0);
	});

	it("pruneSelection never switches off the last enabled rule in restricted mode", () => {
		const rules = [
			rule({ id: 1, createdOn: 100 }),
			rule({ id: 2, createdOn: 300 }),
			rule({ id: 3, createdOn: 200, enabled: false }),
		];
		const cands = [
			{ id: 1, name: "a", lastHitAt: null, reason: "no-hits-30d" as const },
			{ id: 2, name: "b", lastHitAt: null, reason: "no-hits-30d" as const },
			{ id: 3, name: "c", lastHitAt: null, reason: "no-hits-30d" as const },
		];
		// restricted: candidates cover every enabled rule → the newest (2) stays
		expect(pruneSelection(cands, rules, "restricted").map((c) => c.id)).toEqual([1]);
		// open: everything may go; disabled / unknown ids never
		expect(pruneSelection(cands, rules, "open").map((c) => c.id)).toEqual([1, 2]);
		expect(pruneSelection([cands[0]], rules, "restricted").map((c) => c.id)).toEqual([1]);
		expect(pruneSelection([cands[1]], [rules[1]], "restricted")).toEqual([]);
	});
});
