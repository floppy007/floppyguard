import assert from "node:assert/strict";
import test from "node:test";
import {
	buildCatalog,
	bulkDedupe,
	evaluateFlow,
	PORT_PRESETS,
	pruneCandidates,
	sanitizeBulkList,
	sanitizeFlowQuery,
	sanitizeRuleIds,
	serviceDestinations,
	toUnixSeconds,
	tunnelSubnets,
	upstreamDestinations,
} from "./agent-ingress-catalog.js";

const DAY = 24 * 3600;
const NOW = 1_800_000_000;

const rule = (over = {}) => ({
	id: 1,
	name: "r",
	sources: ["10.10.0.1/32"],
	destinations: ["192.168.60.22/32"],
	ports: [],
	enabled: true,
	last_hit_at: null,
	created_on: NOW - 60 * DAY,
	armed_on: null,
	...over,
});

const up = (over = {}) => ({
	kind: "proxy-host",
	id: 1,
	label: "nextcloud.example.de",
	host: "192.168.60.22",
	port: 443,
	proto: "tcp",
	enabled: true,
	...over,
});

const OWN = "wg0:own";
const links = [
	{
		id: OWN,
		name: "Floppy Home",
		type: "hub-link",
		importedNetworks: ["192.168.60.0/24", "192.168.11.0/24"],
		tunnelAddresses: ["10.10.0.2/32"],
		active: true,
	},
	{
		id: "wg0:hinderlich",
		name: "Hinderlich Office",
		type: "hub-link",
		importedNetworks: ["192.168.200.0/24", "192.168.210.0/24"],
		tunnelAddresses: ["10.10.0.7/32"],
		active: true,
	},
	{
		id: "wg0:hetzner",
		name: "PVE-Hetzner",
		type: "site-to-site",
		importedNetworks: ["10.10.10.0/24"],
		tunnelAddresses: ["10.10.0.9/32"],
		active: false,
	},
	{
		id: "wg0:phone",
		name: "iPhone",
		type: "client",
		importedNetworks: [],
		tunnelAddresses: ["10.10.0.3/32"],
		active: false,
	},
];

const baseCtx = (over = {}) => ({
	agent: {
		id: 1,
		name: "VM-Docker",
		ingress_mode: "restricted",
		services: JSON.stringify([
			{ name: "Nextcloud", url: "https://192.168.60.22/" },
			{ name: "Portainer", url: "http://192.168.60.5:9000" },
			{ name: "Fremd", url: "http://172.16.0.1:80" },
			{ name: "Name", url: "http://nas.local:5000" },
		]),
	},
	site: { linkId: OWN, ownNets: ["192.168.60.0/24", "192.168.11.0/24", "10.10.10.0/24"] },
	links,
	linkAgents: [
		{ link_id: OWN, preserve_lan_source_ip: false },
		{ link_id: "wg0:hinderlich", preserve_lan_source_ip: false },
	],
	hubNets: ["10.10.10.0/24"],
	hubHosts: ["10.10.0.1/32"],
	tunnelNets: ["10.10.0.0/24"],
	iface: "wg0",
	egressFlows: [
		{ kind: "hub-egress", id: "egress-1", label: "Mailcow -> DC", host: "192.168.11.5", port: 636, proto: "tcp" },
		{
			kind: "hub-egress",
			id: "egress-2",
			label: "SNAT flow",
			host: "192.168.11.5",
			port: 389,
			proto: "tcp",
			source: "10.10.0.6/32",
		},
	],
	clients: [{ id: "wg0:phone", label: "iPhone", hosts: ["10.10.0.3/32"], nets: ["192.168.60.0/24"] }],
	behind: [up(), up({ id: 2, label: "cloud.example.de, files.example.de", port: 8443 })],
	rules: [rule()],
	now: NOW,
	...over,
});

// ─── buildCatalog ────────────────────────────────────────────────────────────

test("buildCatalog: own site excluded, hub-connected site folded into the hub entry", () => {
	const c = buildCatalog(baseCtx());
	assert.equal(c.link_found, true);
	assert.deepEqual(c.site, {
		link_id: OWN,
		name: "Floppy Home",
		networks: ["192.168.60.0/24", "192.168.11.0/24", "10.10.10.0/24"],
	});
	const ids = c.sources.map((s) => s.id);
	assert.ok(!ids.includes(`site:${OWN}`));
	assert.ok(!ids.includes("site:wg0:hetzner"));
	assert.equal(ids[0], "hub");
	const hub = c.sources[0];
	assert.deepEqual(hub.cidrs, ["10.10.0.1/32"]);
	assert.equal(hub.hint, "snat-hub-lan");
	assert.deepEqual(hub.names, ["PVE-Hetzner"]);
	// egress flow with its own source right after the hub
	assert.deepEqual(c.sources[1], {
		id: "egress:egress-2",
		kind: "hub-egress",
		label: "SNAT flow",
		cidrs: ["10.10.0.6/32"],
	});
	const site = c.sources.find((s) => s.id === "site:wg0:hinderlich");
	assert.deepEqual(site.cidrs, ["192.168.200.0/24", "192.168.210.0/24", "10.10.0.7/32"]);
	assert.equal(site.hint, "masquerade");
	assert.equal(site.online, true);
	const nets = c.sources.filter((s) => s.parent === "site:wg0:hinderlich");
	assert.deepEqual(
		nets.map((n) => [n.kind, n.cidrs[0]]),
		[
			["site-net", "192.168.200.0/24"],
			["site-net", "192.168.210.0/24"],
		],
	);
});

test("buildCatalog: masquerade hint only without preserve_lan_source_ip", () => {
	const c = buildCatalog(baseCtx({ linkAgents: [{ link_id: "wg0:hinderlich", preserve_lan_source_ip: true }] }));
	assert.equal(c.sources.find((s) => s.id === "site:wg0:hinderlich").hint, undefined);
	const none = buildCatalog(baseCtx({ linkAgents: [] }));
	assert.equal(none.sources.find((s) => s.id === "site:wg0:hinderlich").hint, undefined);
});

test("buildCatalog: client /32 and tunnel subnet sources", () => {
	const c = buildCatalog(baseCtx());
	const client = c.sources.find((s) => s.kind === "client");
	assert.deepEqual(client, {
		id: "client:wg0:phone",
		kind: "client",
		label: "iPhone",
		cidrs: ["10.10.0.3/32"],
		online: false,
	});
	const tunnel = c.sources.at(-1);
	assert.deepEqual(tunnel, { id: "tunnel:wg0", kind: "tunnel", label: "10.10.0.0/24", cidrs: ["10.10.0.0/24"] });
	// order: hub, egress, sites, clients, tunnel
	assert.deepEqual(
		[...new Set(c.sources.map((s) => (s.kind === "site-net" ? "site" : s.kind)))],
		["hub", "hub-egress", "site", "client", "tunnel"],
	);
});

test("buildCatalog: upstreams grouped by host, services merged, foreign services dropped", () => {
	const c = buildCatalog(baseCtx());
	const host = c.destinations.find((d) => d.id === "host:192.168.60.22");
	assert.equal(host.kind, "proxy-host");
	assert.equal(host.label, "nextcloud.example.de");
	assert.deepEqual(host.names, ["nextcloud.example.de", "cloud.example.de", "files.example.de", "Nextcloud"]);
	assert.deepEqual(host.cidrs, ["192.168.60.22/32"]);
	assert.deepEqual(host.ports, [
		{ proto: "tcp", port: "443" },
		{ proto: "tcp", port: "8443" },
	]);
	assert.equal(host.covered, true);
	assert.equal(host.enabled, true);
	// exactly one entry for that IP
	assert.equal(c.destinations.filter((d) => d.cidrs[0] === "192.168.60.22/32").length, 1);
	const svc = c.destinations.find((d) => d.kind === "service");
	assert.equal(svc.label, "Portainer");
	assert.deepEqual(svc.ports, [{ proto: "tcp", port: "9000" }]);
	assert.ok(!c.destinations.some((d) => d.label === "Fremd" || d.label === "Name"));
	// networks: own nets without hub-connected ones, sorted last
	assert.deepEqual(
		c.destinations.filter((d) => d.kind === "network").map((d) => d.label),
		["192.168.11.0/24", "192.168.60.0/24"],
	);
	assert.deepEqual(
		c.destinations.map((d) => d.kind),
		["proxy-host", "service", "network", "network"],
	);
});

test("buildCatalog: service ports are shown on the host but kept out of upstream_ports", () => {
	const c = buildCatalog(
		baseCtx({
			agent: {
				id: 1,
				name: "VM-Docker",
				ingress_mode: "restricted",
				services: [{ name: "Jellyfin admin", url: "http://192.168.60.22:8096" }],
			},
		}),
	);
	const host = c.destinations.find((d) => d.id === "host:192.168.60.22");
	assert.deepEqual(
		host.ports.map((p) => p.port),
		["443", "8096", "8443"],
	);
	// a proxy rule built from the catalog must only open what the proxy uses
	assert.deepEqual(
		host.upstream_ports.map((p) => p.port),
		["443", "8443"],
	);
});

test("buildCatalog: arrays only — no CIDR or link id used as an object key", () => {
	const c = buildCatalog(baseCtx());
	const walk = (v) => {
		if (Array.isArray(v)) return v.forEach(walk);
		if (v && typeof v === "object") {
			for (const [k, x] of Object.entries(v)) {
				assert.match(k, /^[a-z_]+$/i, `bad key ${k}`);
				walk(x);
			}
		}
	};
	walk(c);
	assert.ok(Array.isArray(c.port_presets) && c.port_presets.length === PORT_PRESETS.length);
});

test("buildCatalog: link missing → no sites, services without own-net filter, no prune", () => {
	const c = buildCatalog(baseCtx({ site: null, rules: [rule({ id: 9, destinations: ["192.168.99.1/32"] })] }));
	assert.equal(c.link_found, false);
	assert.equal(c.site, null);
	assert.ok(!c.sources.some((s) => s.kind === "site" || s.kind === "site-net"));
	assert.ok(c.sources.some((s) => s.kind === "client"));
	assert.ok(c.sources.some((s) => s.kind === "tunnel"));
	assert.deepEqual(
		c.destinations.map((d) => d.label),
		["Fremd", "Nextcloud", "Portainer"],
	);
	assert.ok(c.destinations.every((d) => d.kind === "service"));
	assert.deepEqual(c.prune_candidates, []);
});

test("upstreamDestinations: kind priority, no-port hint, coverage per upstream", () => {
	const list = upstreamDestinations(
		[
			up({ kind: "stream", label: "Port 2222/tcp", host: "192.168.11.9", port: 22 }),
			up({ kind: "manual", label: "sso.example.de", host: "192.168.11.9", port: null, enabled: false }),
			up({ kind: "proxy-host", label: "nas.example.de", host: "192.168.11.9", port: 5000, enabled: false }),
		],
		{
			rules: [rule({ destinations: ["192.168.11.9/32"], ports: [{ proto: "tcp", port: "22" }] })],
			hubHosts: ["10.10.0.1/32"],
		},
	);
	assert.equal(list.length, 1);
	const [e] = list;
	assert.equal(e.kind, "proxy-host");
	assert.equal(e.label, "nas.example.de");
	assert.deepEqual(e.names, ["nas.example.de", "Port 2222/tcp", "sso.example.de"]);
	assert.equal(e.hint, "no-port");
	assert.equal(e.enabled, true);
	assert.equal(e.covered, false);
	const all = upstreamDestinations([up({ port: 443 }), up({ port: 80 })], {
		rules: [rule({ ports: [] })],
		hubHosts: ["10.10.0.1/32"],
	});
	assert.equal(all[0].covered, true);
	assert.deepEqual(all[0].ports, [
		{ proto: "tcp", port: "80" },
		{ proto: "tcp", port: "443" },
	]);
});

test("serviceDestinations: scheme ports, own-net filter, same IP merged", () => {
	const s = serviceDestinations(
		[
			{ name: "A", url: "http://192.168.60.5" },
			{ name: "B", url: "https://192.168.60.5:8443/x" },
			{ name: "C", url: "https://192.168.61.1" },
			{ name: "bad", url: "not a url" },
			null,
		],
		["192.168.60.0/24"],
		{ agentId: 4 },
	);
	assert.deepEqual(s, [
		{
			id: "service:4:0",
			kind: "service",
			label: "A",
			names: ["A", "B"],
			cidrs: ["192.168.60.5/32"],
			ports: [
				{ proto: "tcp", port: "80" },
				{ proto: "tcp", port: "8443" },
			],
		},
	]);
	assert.equal(serviceDestinations([{ name: "C", url: "https://192.168.61.1" }], null).length, 1);
	assert.deepEqual(serviceDestinations("garbage", null), []);
});

test("tunnelSubnets / toUnixSeconds", () => {
	assert.deepEqual(tunnelSubnets("[Interface]\nAddress = 10.10.0.1/24, 10.20.0.1\nListenPort = 51820\n"), [
		"10.10.0.0/24",
	]);
	assert.equal(toUnixSeconds(1700000000), 1700000000);
	assert.equal(toUnixSeconds("1700000000"), 1700000000);
	assert.equal(toUnixSeconds(1700000000123), 1700000000);
	assert.equal(toUnixSeconds("2023-11-14T22:13:20.000Z"), 1700000000);
	assert.equal(toUnixSeconds(null), null);
	assert.equal(toUnixSeconds("nope"), null);
});

// ─── evaluateFlow ────────────────────────────────────────────────────────────

const flow = (over = {}) => ({
	mode: "restricted",
	rules: [],
	ownNets: ["192.168.60.0/24", "10.10.10.0/24"],
	hubNets: ["10.10.10.0/24"],
	src: "10.10.0.1/32",
	dst: "192.168.60.22/32",
	port: 443,
	proto: "tcp",
	applied: { state: "applied" },
	...over,
});

test("evaluateFlow: not-via-agent and same-site", () => {
	const outside = evaluateFlow(flow({ dst: "172.16.0.1/32" }));
	assert.equal(outside.reason, "not-via-agent");
	assert.equal(outside.allowed, null);
	assert.equal(outside.filtered, false);
	assert.equal(evaluateFlow(flow({ dst: "10.10.10.5/32" })).reason, "not-via-agent");
	const same = evaluateFlow(flow({ src: "192.168.60.0/24" }));
	assert.equal(same.reason, "same-site");
	assert.equal(same.allowed, null);
	assert.deepEqual(same.notes, ["established-return", "forward-only"]);
});

test("evaluateFlow: restricted rule / no-rule, first match by id", () => {
	const rules = [
		rule({ id: 7, name: "seven", ports: [{ proto: "tcp", port: "443" }] }),
		rule({ id: 3, name: "three" }),
		rule({ id: 5, name: "off", enabled: false }),
	];
	const r = evaluateFlow(flow({ rules }));
	assert.equal(r.allowed, true);
	assert.equal(r.filtered, true);
	assert.equal(r.reason, "rule");
	assert.deepEqual(r.rule, { id: 3, name: "three" });
	assert.deepEqual(r.matched_rules, [
		{ id: 3, name: "three" },
		{ id: 7, name: "seven" },
	]);
	assert.deepEqual(r.disabled_match, { id: 5, name: "off" });
	const no = evaluateFlow(flow({ rules, src: "10.10.0.4/32" }));
	assert.equal(no.allowed, false);
	assert.equal(no.filtered, true);
	assert.equal(no.reason, "no-rule");
	assert.equal(no.rule, null);
});

test("evaluateFlow: open mode observes, not-applied note", () => {
	const r = evaluateFlow(flow({ mode: "open", rules: [rule({ id: 2 })], applied: { state: "pending" } }));
	assert.equal(r.allowed, true);
	assert.equal(r.filtered, false);
	assert.equal(r.reason, "open-mode");
	assert.deepEqual(r.rule, { id: 2, name: "r" });
	assert.deepEqual(r.notes, ["established-return", "forward-only", "not-applied"]);
	assert.equal(evaluateFlow(flow({ mode: "open" })).rule, null);
});

test("evaluateFlow: port_unknown when only port-restricted rules would match", () => {
	const rules = [rule({ ports: [{ proto: "tcp", port: "443" }] })];
	const r = evaluateFlow(flow({ rules, port: null }));
	assert.equal(r.port_unknown, true);
	assert.equal(r.reason, "no-rule");
	assert.equal(evaluateFlow(flow({ rules })).port_unknown, false);
	assert.equal(evaluateFlow(flow({ rules: [rule()], port: null })).port_unknown, false);
});

test("evaluateFlow: source net must lie inside the rule source", () => {
	const r = evaluateFlow(flow({ rules: [rule({ sources: ["192.168.200.0/24"] })], src: "192.168.200.0/24" }));
	assert.equal(r.reason, "rule");
	const wider = evaluateFlow(flow({ rules: [rule({ sources: ["192.168.200.15/32"] })], src: "192.168.200.0/24" }));
	assert.equal(wider.reason, "no-rule");
});

// ─── pruneCandidates ─────────────────────────────────────────────────────────

test("pruneCandidates: 30 days without hits and no upstream needs it", () => {
	const rules = [
		rule({ id: 1, name: "old unused", destinations: ["192.168.60.99/32"] }),
		rule({ id: 2, name: "old but needed" }),
		rule({ id: 3, name: "fresh hit", destinations: ["192.168.60.98/32"], last_hit_at: NOW - 2 * DAY }),
		rule({ id: 4, name: "fresh armed", destinations: ["192.168.60.97/32"], armed_on: NOW - DAY }),
		rule({ id: 5, name: "disabled", destinations: ["192.168.60.96/32"], enabled: false }),
		rule({ id: 6, name: "young", destinations: ["192.168.60.95/32"], created_on: NOW - 10 * DAY }),
	];
	const out = pruneCandidates({
		rules,
		behind: [up()],
		hubSrcs: ["10.10.0.1/32"],
		mode: "open",
		now: NOW,
		appliedState: "applied",
	});
	assert.deepEqual(out, [{ id: 1, name: "old unused", last_hit_at: null, reason: "no-hits-30d" }]);
});

test("pruneCandidates: only hub-sourced rules of an agent that applied its ruleset", () => {
	const rules = [
		rule({ id: 1, name: "hub old", destinations: ["192.168.60.99/32"] }),
		// break-glass access of a VPN client / another site / the tunnel: never offered
		rule({ id: 2, name: "admin laptop -> iDRAC", sources: ["10.10.0.3/32"], destinations: ["192.168.11.241/32"] }),
		rule({ id: 3, name: "site -> DC", sources: ["192.168.200.0/24"], destinations: ["192.168.11.5/32"] }),
		rule({ id: 4, name: "tunnel", sources: ["10.10.0.0/24"], destinations: [] }),
		// hub plus a client source: not hub-only
		rule({ id: 5, name: "mixed", sources: ["10.10.0.1/32", "10.10.0.3/32"], destinations: ["192.168.60.98/32"] }),
		// armed 10 days ago (switched back on), old creation → still too young
		rule({ id: 6, name: "re-armed", destinations: ["192.168.60.97/32"], armed_on: NOW - 10 * DAY }),
	];
	const args = { rules, behind: [], hubSrcs: ["10.10.0.1/32"], mode: "open", now: NOW };
	assert.deepEqual(
		pruneCandidates({ ...args, appliedState: "applied" }).map((c) => c.id),
		[1],
	);
	// no counters from an agent that did not confirm its ruleset: nothing to judge
	for (const state of ["pending", "failed", "offline", "unknown", null]) {
		assert.deepEqual(pruneCandidates({ ...args, appliedState: state }), [], String(state));
	}
});

test("buildCatalog: prune candidates only with an applied ruleset", () => {
	// restricted agent: the needed rule 1 (→ Nextcloud) stays, 7 is unused
	const rules = [rule({ id: 1 }), rule({ id: 7, destinations: ["192.168.60.99/32"] })];
	assert.deepEqual(
		buildCatalog(baseCtx({ rules, applied: { state: "applied" } })).prune_candidates.map((c) => c.id),
		[7],
	);
	assert.deepEqual(buildCatalog(baseCtx({ rules, applied: { state: "offline" } })).prune_candidates, []);
	assert.deepEqual(buildCatalog(baseCtx({ rules })).prune_candidates, []);
});

test("pruneCandidates: egress flow source counts, date-string created_on parsed", () => {
	const rules = [
		rule({
			id: 1,
			sources: ["10.10.0.6/32"],
			destinations: ["192.168.11.5/32"],
			created_on: new Date((NOW - 90 * DAY) * 1000).toISOString(),
		}),
		rule({
			id: 2,
			destinations: ["192.168.60.99/32"],
			created_on: new Date((NOW - 90 * DAY) * 1000).toISOString(),
		}),
	];
	const behind = [up({ kind: "hub-egress", host: "192.168.11.5", port: 389, source: "10.10.0.6/32" })];
	const out = pruneCandidates({
		rules,
		behind,
		hubSrcs: ["10.10.0.1/32", "10.10.0.6/32"],
		mode: "open",
		now: NOW,
		appliedState: "applied",
	});
	assert.deepEqual(
		out.map((c) => c.id),
		[2],
	);
});

test("pruneCandidates: restricted keeps the newest rule, link missing → []", () => {
	const rules = [
		rule({ id: 1, destinations: ["192.168.60.99/32"], last_hit_at: NOW - 40 * DAY }),
		rule({ id: 2, destinations: ["192.168.60.98/32"], last_hit_at: NOW - 35 * DAY }),
		rule({ id: 3, destinations: ["192.168.60.97/32"], last_hit_at: NOW - 50 * DAY }),
	];
	const base = { rules, behind: [], hubSrcs: ["10.10.0.1/32"], now: NOW, appliedState: "applied" };
	const r = pruneCandidates({ ...base, mode: "restricted" });
	assert.deepEqual(
		r.map((c) => c.id),
		[1, 3],
	);
	const o = pruneCandidates({ ...base, mode: "open" });
	assert.equal(o.length, 3);
	assert.deepEqual(pruneCandidates({ ...base, mode: "open", linkFound: false }), []);
});

// ─── sanitizeFlowQuery ───────────────────────────────────────────────────────

test("sanitizeFlowQuery normalizes and validates", () => {
	assert.deepEqual(sanitizeFlowQuery({ source: "192.168.200.15", destination: "10.3.10.25", port: 443 }), {
		src: "192.168.200.15/32",
		dst: "10.3.10.25/32",
		port: 443,
		proto: "tcp",
	});
	assert.deepEqual(
		sanitizeFlowQuery({ source: "192.168.200.7/24", destination: "10.3.10.25", proto: "UDP", port: "53" }),
		{
			src: "192.168.200.0/24",
			dst: "10.3.10.25/32",
			port: 53,
			proto: "udp",
		},
	);
	assert.equal(sanitizeFlowQuery({ source: "1.2.3.4", destination: "5.6.7.8", port: "" }).port, null);
	for (const bad of [
		{ source: "x", destination: "10.0.0.1" },
		{ source: "10.0.0.1" },
		{ source: "10.0.0.1", destination: "10.0.0.2", port: 0 },
		{ source: "10.0.0.1", destination: "10.0.0.2", port: 70000 },
		{ source: "10.0.0.1", destination: "10.0.0.2", port: 1.5 },
		{ source: "10.0.0.1", destination: "10.0.0.2", port: "80-90" },
		{ source: "10.0.0.1", destination: "10.0.0.2", proto: "icmp" },
		null,
	]) {
		assert.throws(() => sanitizeFlowQuery(bad), { status: 400 }, JSON.stringify(bad));
	}
});

// ─── bulk ────────────────────────────────────────────────────────────────────

test("sanitizeBulkList: 1..100 entries, index in the error message", () => {
	const ok = sanitizeBulkList([{ name: "a", sources: ["10.10.0.1"], destinations: [], ports: [] }]);
	assert.deepEqual(ok[0].sources, ["10.10.0.1/32"]);
	assert.throws(() => sanitizeBulkList([]), { status: 400 });
	assert.throws(() => sanitizeBulkList("x"), { status: 400 });
	assert.throws(() => sanitizeBulkList(undefined), { status: 400 });
	const many = Array.from({ length: 101 }, (_, i) => ({ name: `r${i}`, sources: ["10.0.0.1"] }));
	assert.throws(() => sanitizeBulkList(many), { status: 400 });
	assert.throws(
		() =>
			sanitizeBulkList([
				{ name: "a", sources: ["10.10.0.1"] },
				{ name: "b", sources: ["10.10.0.1"] },
				{ name: "c", sources: [] },
			]),
		(err) => err.status === 400 && err.message.startsWith("rules[2]: ") && /sources/.test(err.message),
	);
});

test("bulkDedupe: equal target sets against existing rules and earlier entries", () => {
	const existing = [
		rule({
			id: 11,
			sources: ["10.10.0.1/32", "10.10.0.7/32"],
			destinations: ["192.168.60.22/32"],
			ports: [
				{ proto: "tcp", port: "443" },
				{ proto: "tcp", port: "80" },
			],
		}),
	];
	const clean = [
		// same sets in a different order → duplicate of 11
		{
			name: "x",
			sources: ["10.10.0.7/32", "10.10.0.1/32"],
			destinations: ["192.168.60.22/32"],
			ports: [
				{ proto: "tcp", port: "80" },
				{ proto: "tcp", port: "443" },
			],
		},
		{ name: "new", sources: ["10.10.0.1/32"], destinations: [], ports: [] },
		{ name: "again", sources: ["10.10.0.1/32"], destinations: [], ports: [] },
		{ name: "other port", sources: ["10.10.0.1/32"], destinations: [], ports: [{ proto: "udp", port: "53" }] },
	];
	const { create, skipped, reenable } = bulkDedupe(existing, clean);
	assert.deepEqual(
		create.map((c) => [c.index, c.rule.name]),
		[
			[1, "new"],
			[3, "other port"],
		],
	);
	assert.deepEqual(skipped, [
		{ index: 0, reason: "duplicate", rule_id: 11 },
		{ index: 2, reason: "duplicate", rule_id: null },
	]);
	assert.deepEqual(reenable, []);
});

test("bulkDedupe: a switched-off rule with the same targets is re-enabled, not skipped", () => {
	const target = { sources: ["10.10.0.1/32"], destinations: ["192.168.60.9/32"], ports: [{ proto: "tcp", port: "443" }] };
	const existing = [rule({ id: 21, ...target, enabled: false })];
	const { create, skipped, reenable } = bulkDedupe(existing, [
		{ name: "Proxy cloud", ...target },
		{ name: "Proxy cloud again", ...target },
	]);
	assert.deepEqual(create, []);
	assert.deepEqual(reenable, [{ index: 0, rule_id: 21 }]);
	assert.deepEqual(skipped, [{ index: 1, reason: "duplicate", rule_id: 21 }]);
	// an enabled twin wins over a disabled one: nothing to switch on
	const both = bulkDedupe([rule({ id: 22, ...target }), rule({ id: 21, ...target, enabled: false })], [
		{ name: "x", ...target },
	]);
	assert.deepEqual(both.reenable, []);
	assert.deepEqual(both.skipped, [{ index: 0, reason: "duplicate", rule_id: 22 }]);
});

test("validation errors echo at most 64 characters of the request value", () => {
	const huge = "x".repeat(50_000);
	for (const body of [
		{ source: huge, destination: "10.0.0.1" },
		{ source: "10.0.0.1", destination: huge },
		{ source: "10.0.0.1", destination: "10.0.0.2", port: huge },
		{ source: "10.0.0.1", destination: "10.0.0.2", proto: huge },
	]) {
		assert.throws(
			() => sanitizeFlowQuery(body),
			(err) => err.status === 400 && err.message.length < 140,
		);
	}
	assert.throws(
		() => sanitizeBulkList([{ name: "a", sources: [huge] }]),
		(err) => err.status === 400 && err.message.length < 160,
	);
	assert.throws(
		() => sanitizeBulkList([{ name: "a", sources: ["10.0.0.1"], ports: [{ proto: "tcp", port: huge }] }]),
		(err) => err.status === 400 && err.message.length < 160,
	);
	assert.throws(
		() => sanitizeRuleIds([huge]),
		(err) => err.status === 400 && err.message.length < 140,
	);
});

test("sanitizeRuleIds: positive integers, deduped, 1..500", () => {
	assert.deepEqual(sanitizeRuleIds([3, "4", 3]), [3, 4]);
	assert.throws(() => sanitizeRuleIds([]), { status: 400 });
	assert.throws(() => sanitizeRuleIds([0]), { status: 400 });
	assert.throws(() => sanitizeRuleIds(["1; drop"]), { status: 400 });
	assert.throws(() => sanitizeRuleIds(Array.from({ length: 501 }, (_, i) => i + 1)), { status: 400 });
});

test("PORT_PRESETS cover the documented sets", () => {
	const byId = Object.fromEntries(PORT_PRESETS.map((p) => [p.id, p.ports.map((x) => `${x.port}/${x.proto}`)]));
	assert.deepEqual(byId, {
		web: ["80/tcp", "443/tcp"],
		ssh: ["22/tcp"],
		smb: ["445/tcp"],
		ldap: ["389/tcp", "636/tcp"],
		rdp: ["3389/tcp"],
		dns: ["53/tcp", "53/udp"],
		proxmox: ["8006/tcp"],
		pbs: ["8007/tcp"],
		all: [],
	});
});
