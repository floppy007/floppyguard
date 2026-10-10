import assert from "node:assert/strict";
import test from "node:test";
import {
	bootIncludesFile,
	buildSiteIsolationNft,
	manualDropVerdict,
	manualSitePairs,
	normalizePair,
	parseChainCounters,
	parseForeignForwardDrops,
	planSiteIsolation,
	routeWarnings,
	sanitizeCommentText,
	sanitizePairs,
	scriptHash,
	siteIsolationVerdict,
	siteNetworks,
	siteSetName,
} from "./site-isolation-rules.js";

const H = "wg0:88I9yCmRuMLXDyUxAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const D = "wg0:FPfjO8lOu0b5+foyAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const F = "wg0:3/5dhEQsF68H43gPAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const C = "wg0:+Wz1P+1VjpU8+OQaAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

const links = () => [
	{
		id: H,
		name: "Hinderlich Office",
		type: "site-to-site",
		importedNetworks: [
			"192.168.200.0/24",
			"192.168.210.0/24",
			"192.168.220.0/24",
			"192.168.240.0/24",
			"10.4.0.0/16",
			"10.3.20.0/24",
		],
		tunnelAddresses: ["10.10.0.7/32"],
		active: true,
	},
	{
		id: D,
		name: "Daniel Home",
		type: "site-to-site",
		importedNetworks: ["192.168.111.0/24", "192.168.112.0/24"],
		tunnelAddresses: ["10.10.0.5/32"],
		active: true,
	},
	{
		id: F,
		name: "Floppy Home",
		type: "site-to-site",
		importedNetworks: ["192.168.11.0/24", "10.3.10.0/24"],
		tunnelAddresses: ["10.10.0.2/32"],
		active: false,
	},
	{
		id: C,
		name: "iPhone Floppy",
		type: "client",
		importedNetworks: ["10.10.0.0/24", "192.168.11.0/24"],
		tunnelAddresses: ["10.10.0.9/32"],
		active: true,
	},
];

test("siteNetworks: canonical, deduped, contained entries removed, sorted, tunnel /32 added", () => {
	const r = siteNetworks({
		importedNetworks: ["10.4.1.7/16", "10.4.0.0/16", "10.4.3.0/24", "192.168.1.0/24", "bogus", "0.0.0.0/0"],
		tunnelAddresses: ["10.10.0.7", "10.10.0.7/32"],
	});
	assert.deepEqual(r.nets, ["10.4.0.0/16", "10.10.0.7/32", "192.168.1.0/24"]);
	assert.deepEqual(
		r.skipped.map((s) => s.reason),
		["invalid", "default-route"],
	);
});

test("buildSiteIsolationNft: golden text for Hinderlich <-> Daniel", () => {
	const sH = siteSetName(H);
	const sD = siteSetName(D);
	const [first, second] = sH < sD ? [sH, sD] : [sD, sH];
	const sets = {
		[sH]: [
			`\tset ${sH} {`,
			"\t\ttype ipv4_addr",
			"\t\tflags interval",
			'\t\tcomment "Hinderlich Office"',
			"\t\telements = { 10.3.20.0/24, 10.4.0.0/16, 10.10.0.7/32, 192.168.200.0/24, 192.168.210.0/24, 192.168.220.0/24, 192.168.240.0/24 }",
			"\t}",
		],
		[sD]: [
			`\tset ${sD} {`,
			"\t\ttype ipv4_addr",
			"\t\tflags interval",
			'\t\tcomment "Daniel Home"',
			"\t\telements = { 10.10.0.5/32, 192.168.111.0/24, 192.168.112.0/24 }",
			"\t}",
		],
	};
	const expected = [
		"#!/usr/sbin/nft -f",
		"# Managed by FloppyGuard - Standorte untereinander (site isolation). Do not edit:",
		"# the backend replaces this table atomically on every change.",
		"table inet floppyguard_sites {}",
		"delete table inet floppyguard_sites",
		"table inet floppyguard_sites {",
		...sets[first],
		...sets[second],
		"\tchain forward {",
		"\t\ttype filter hook forward priority filter - 10; policy accept;",
		...(() => {
			const p = normalizePair(H, D);
			const A = p.a === H ? [sH, "Hinderlich Office"] : [sD, "Daniel Home"];
			const B = p.b === H ? [sH, "Hinderlich Office"] : [sD, "Daniel Home"];
			return [
				`\t\tip saddr @${A[0]} ip daddr @${B[0]} counter drop comment "Standort-Trennung ${A[1]} -> ${B[1]}"`,
				`\t\tip saddr @${B[0]} ip daddr @${A[0]} counter drop comment "Standort-Trennung ${B[1]} -> ${A[1]}"`,
			];
		})(),
		"\t}",
		"}",
		"",
	].join("\n");
	const script = buildSiteIsolationNft({ pairs: [normalizePair(H, D)], links: links() });
	assert.equal(script, expected);
	// deterministic → stable hash
	assert.equal(
		scriptHash(script),
		scriptHash(buildSiteIsolationNft({ pairs: [normalizePair(D, H)], links: links().reverse() })),
	);
	// never touches another table
	for (const line of script.split("\n")) {
		if (/^(table|delete|flush|add)\b/.test(line)) assert.match(line, /inet floppyguard_sites\b/);
	}
	assert.doesNotMatch(script, /flush ruleset/);
});

test("buildSiteIsolationNft: no pairs → empty accept chain, no sets", () => {
	const script = buildSiteIsolationNft({ pairs: [], links: links() });
	assert.doesNotMatch(script, /\bset site_/);
	assert.doesNotMatch(script, /drop/);
	assert.match(script, /chain forward \{\n\t\ttype filter hook forward priority filter - 10; policy accept;\n\t\}/);
});

test("buildSiteIsolationNft: link names are sanitized in comments", () => {
	const l = links();
	l[0].name = 'Evil"; flush ruleset; #\nÄußere Höhe';
	const script = buildSiteIsolationNft({ pairs: [normalizePair(H, D)], links: l });
	assert.doesNotMatch(script, /flush ruleset;/);
	for (const line of script.split("\n").filter((x) => x.includes("comment"))) {
		assert.match(line, /comment "[^"\\\n]*"$/);
	}
	assert.match(script, /Aeussere Hoehe/);
	assert.equal(sanitizeCommentText('a"b\\c\nd'), "a b c d");
	assert.equal(sanitizeCommentText(""), "site");
});

test("planSiteIsolation: missing link, client link and empty site are skipped with warnings", () => {
	const l = links();
	l[2].importedNetworks = [];
	l[2].tunnelAddresses = [];
	const gone = "wg0:GONEGONEGONEGONEGONEGONEGONEGONEGONEGONEGONE=";
	const plan = planSiteIsolation({
		pairs: [normalizePair(H, gone), normalizePair(H, C), normalizePair(H, F), normalizePair(H, D)],
		links: l,
	});
	assert.deepEqual(plan.pairs, [normalizePair(H, D)]);
	assert.deepEqual(
		plan.warnings.map((w) => w.code),
		["link-missing", "link-not-site", "no-networks"],
	);
	assert.deepEqual([...plan.sites.keys()].sort(), [D, H].sort());
	// the script stays valid without the skipped pairs
	const script = buildSiteIsolationNft({ pairs: plan.pairs, links: l });
	assert.equal((script.match(/counter drop/g) || []).length, 2);
});

test("planSiteIsolation: overlapping site networks warn", () => {
	const l = links();
	l[1].importedNetworks = ["10.4.5.0/24"];
	const plan = planSiteIsolation({ pairs: [normalizePair(H, D)], links: l });
	assert.equal(plan.warnings[0].code, "overlap");
	assert.deepEqual(plan.warnings[0].networks, ["10.4.0.0/16"]);
});

test("sanitizePairs: validates, normalizes and dedupes", () => {
	const out = sanitizePairs(
		[
			{ link_a: H, link_b: D },
			{ link_a: D, link_b: H },
			{ link_a: F, link_b: H },
		],
		links(),
	);
	assert.deepEqual(
		out,
		[normalizePair(F, H), normalizePair(H, D)].sort((x, y) => (x.a < y.a ? -1 : 1)),
	);
	assert.deepEqual(sanitizePairs([], links()), []);
});

test("sanitizePairs: rejects a==b, unknown link, client link, malformed id, non-array", () => {
	assert.throws(() => sanitizePairs([{ link_a: H, link_b: H }], links()), /cannot be isolated from itself/);
	assert.throws(() => sanitizePairs([{ link_a: H, link_b: "wg0:UNKNOWNUNKNOWNUNKNOWN=" }], links()), /unknown link/);
	assert.throws(() => sanitizePairs([{ link_a: H, link_b: C }], links()), /not a site-to-site link/);
	assert.throws(() => sanitizePairs([{ link_a: 'wg0:x"; drop', link_b: D }], links()), /invalid link id/);
	assert.throws(() => sanitizePairs([{ link_a: H }], links()), /link_b: invalid link id/);
	assert.throws(() => sanitizePairs("nope", links()), /must be an array/);
});

test("buildSiteIsolationNft: invalid networks are skipped with a warning, never emitted", () => {
	const l = links();
	l[1].importedNetworks = ["192.168.111.300/24"];
	const plan = planSiteIsolation({ pairs: [normalizePair(H, D)], links: l });
	assert.ok(plan.warnings.some((w) => w.code === "network-skipped" && w.reason === "invalid"));
	// D still has its tunnel /32 → still enforced, bad net not emitted
	const script = buildSiteIsolationNft({ pairs: [normalizePair(H, D)], links: l });
	assert.doesNotMatch(script, /300/);
});

test("siteIsolationVerdict: blocked both directions, allowed elsewhere, partial for wider ranges", () => {
	const pairs = [normalizePair(H, D)];
	const v1 = siteIsolationVerdict({ pairs, links: links(), src: "192.168.210.15", dst: "192.168.111.5" });
	assert.equal(v1.blocked, true);
	const norm = normalizePair(H, D);
	assert.equal(v1.pair.direction, norm.a === H ? "a-to-b" : "b-to-a");
	assert.deepEqual([v1.pair.a, v1.pair.b], [norm.a, norm.b]);
	const v2 = siteIsolationVerdict({ pairs, links: links(), src: "10.10.0.5", dst: "10.4.7.1" });
	assert.equal(v2.blocked, true);
	const v3 = siteIsolationVerdict({ pairs, links: links(), src: "192.168.210.15", dst: "192.168.11.5" });
	assert.deepEqual(v3, { blocked: false, partial: false });
	const v4 = siteIsolationVerdict({ pairs, links: links(), src: "192.168.0.0/16", dst: "192.168.111.5" });
	assert.equal(v4.blocked, false);
	assert.equal(v4.partial, true);
	assert.deepEqual(siteIsolationVerdict({ pairs: [], links: links(), src: "192.168.210.1", dst: "192.168.111.1" }), {
		blocked: false,
		partial: false,
	});
	assert.deepEqual(siteIsolationVerdict({ pairs, links: links(), src: "x", dst: "192.168.111.1" }), {
		blocked: false,
		partial: false,
	});
});

test("routeWarnings: full mesh, allowed_sites and allowed_networks", () => {
	const pairs = [normalizePair(H, D)];
	const agents = [
		{
			id: 1,
			name: "gw-hinderlich",
			wg_link_name: "Hinderlich Office",
			allowed_networks: null,
			allowed_sites: null,
		},
		{
			id: 2,
			name: "gw-daniel",
			wg_link_name: "Daniel Home",
			allowed_networks: ["192.168.11.0/24"],
			allowed_sites: null,
		},
		{
			id: 3,
			name: "gw-daniel-2",
			wg_link_name: "Daniel Home",
			allowed_networks: ["192.168.210.0/24"],
			allowed_sites: null,
		},
		{
			id: 4,
			name: "gw-floppy",
			wg_link_name: "Floppy Home",
			allowed_networks: null,
			allowed_sites: ["Daniel Home"],
		},
	];
	const w = routeWarnings({ pairs, links: links(), agents });
	assert.deepEqual(
		w.map((x) => [x.agent_id, x.via, x.networks]),
		[
			[1, "full-mesh", ["192.168.111.0/24", "192.168.112.0/24"]],
			[3, "allowed_networks", ["192.168.210.0/24"]],
		],
	);
	assert.match(w[0].message, /vorhanden, wird am Hub verworfen/);
});

test("parseChainCounters: maps set pair to counters, tolerates junk", () => {
	const json = JSON.stringify({
		nftables: [
			{ metainfo: {} },
			{ chain: { name: "forward" } },
			{
				rule: {
					expr: [
						{
							match: {
								op: "==",
								left: { payload: { protocol: "ip", field: "saddr" } },
								right: "@site_a",
							},
						},
						{
							match: {
								op: "==",
								left: { payload: { protocol: "ip", field: "daddr" } },
								right: "@site_b",
							},
						},
						{ counter: { packets: 3, bytes: 180 } },
						{ drop: null },
					],
				},
			},
		],
	});
	assert.deepEqual([...parseChainCounters(json)], [["site_a>site_b", { packets: 3, bytes: 180 }]]);
	assert.equal(parseChainCounters("not json").size, 0);
});

// ── IPv6, foreign drops, boot include ────────────────────────────────────────

test("siteNetworks: IPv6 networks are reported as ipv6-unsupported, not invalid", () => {
	const r = siteNetworks({ importedNetworks: ["2a00:6020:1000::/56", "192.168.210.0/24"] });
	assert.deepEqual(r.nets, ["192.168.210.0/24"]);
	assert.deepEqual(r.skipped, [{ value: "2a00:6020:1000::/56", reason: "ipv6-unsupported" }]);
	const l = links();
	l[0].importedNetworks = [...l[0].importedNetworks, "2a00:6020:1000::/56"];
	const plan = planSiteIsolation({ pairs: [normalizePair(H, D)], links: l });
	const w = plan.warnings.find((x) => x.code === "network-skipped");
	assert.equal(w.reason, "ipv6-unsupported");
	assert.match(w.message, /IPv6-Netz .* nicht erfasst/);
	assert.doesNotMatch(w.message, /ungültig/);
});

// Trimmed `nft -j list ruleset` of the hub on 10.10.26 (manual rules in inet filter).
const LIVE_RULESET = JSON.stringify({
	nftables: [
		{ metainfo: { version: "1.0.6", json_schema_version: 1 } },
		{ table: { family: "inet", name: "filter", handle: 1 } },
		{
			set: {
				family: "inet",
				name: "site_hinderlich",
				table: "filter",
				type: "ipv4_addr",
				flags: ["interval"],
				elem: [
					{ prefix: { addr: "10.3.20.0", len: 24 } },
					{ prefix: { addr: "10.4.0.0", len: 16 } },
					"10.10.0.7",
					{ prefix: { addr: "192.168.200.0", len: 24 } },
					{ prefix: { addr: "192.168.210.0", len: 24 } },
					{ prefix: { addr: "192.168.220.0", len: 24 } },
					{ prefix: { addr: "192.168.240.0", len: 24 } },
				],
			},
		},
		{
			set: {
				family: "inet",
				name: "site_daniel",
				table: "filter",
				type: "ipv4_addr",
				flags: ["interval"],
				elem: [
					"10.10.0.5",
					{ prefix: { addr: "192.168.111.0", len: 24 } },
					{ prefix: { addr: "192.168.112.0", len: 24 } },
				],
			},
		},
		{
			chain: {
				family: "inet",
				table: "filter",
				name: "forward",
				handle: 2,
				type: "filter",
				hook: "forward",
				prio: 0,
				policy: "drop",
			},
		},
		{
			rule: {
				family: "inet",
				table: "filter",
				chain: "forward",
				handle: 22,
				comment: "Standort-Trennung Hinderlich zu Daniel",
				expr: [
					{
						match: {
							op: "==",
							left: { payload: { protocol: "ip", field: "saddr" } },
							right: "@site_hinderlich",
						},
					},
					{
						match: {
							op: "==",
							left: { payload: { protocol: "ip", field: "daddr" } },
							right: "@site_daniel",
						},
					},
					{ counter: { packets: 0, bytes: 0 } },
					{ drop: null },
				],
			},
		},
		{
			rule: {
				family: "inet",
				table: "filter",
				chain: "forward",
				handle: 24,
				expr: [{ match: { op: "==", left: { meta: { key: "iifname" } }, right: "wg0" } }, { accept: null }],
			},
		},
		{
			chain: {
				family: "ip",
				table: "filter",
				name: "FORWARD",
				hook: "forward",
				type: "filter",
				prio: 0,
				policy: "accept",
			},
		},
		{
			rule: {
				family: "ip",
				table: "filter",
				chain: "FORWARD",
				handle: 9,
				expr: [
					{
						match: {
							op: "==",
							left: { payload: { protocol: "ip", field: "saddr" } },
							right: { prefix: { addr: "192.168.11.0", len: 24 } },
						},
					},
					{ match: { op: "==", left: { payload: { protocol: "ip", field: "daddr" } }, right: "10.3.10.5" } },
					{ match: { op: "==", left: { payload: { protocol: "tcp", field: "dport" } }, right: 22 } },
					{ counter: { packets: 0, bytes: 0 } },
					{ drop: null },
				],
			},
		},
		// only a saddr match: not a site separation, ignored
		{
			rule: {
				family: "ip",
				table: "filter",
				chain: "FORWARD",
				handle: 10,
				expr: [
					{ match: { op: "==", left: { payload: { protocol: "ip", field: "saddr" } }, right: "1.2.3.4" } },
					{ drop: null },
				],
			},
		},
		// FloppyGuard's own table is never "foreign"
		{ chain: { family: "inet", table: "floppyguard_sites", name: "forward", hook: "forward", prio: -10 } },
		{
			rule: {
				family: "inet",
				table: "floppyguard_sites",
				chain: "forward",
				expr: [
					{ match: { op: "==", left: { payload: { protocol: "ip", field: "saddr" } }, right: "@site_x" } },
					{ match: { op: "==", left: { payload: { protocol: "ip", field: "daddr" } }, right: "@site_y" } },
					{ drop: null },
				],
			},
		},
		// a drop in a non-forward chain is irrelevant
		{ chain: { family: "inet", table: "filter", name: "input", hook: "input", prio: 0 } },
		{
			rule: {
				family: "inet",
				table: "filter",
				chain: "input",
				expr: [
					{
						match: {
							op: "==",
							left: { payload: { protocol: "ip", field: "saddr" } },
							right: "@site_daniel",
						},
					},
					{
						match: {
							op: "==",
							left: { payload: { protocol: "ip", field: "daddr" } },
							right: "@site_hinderlich",
						},
					},
					{ drop: null },
				],
			},
		},
	],
});

test("parseForeignForwardDrops: finds the manual inet filter rule with resolved sets, skips own table", () => {
	const drops = parseForeignForwardDrops(LIVE_RULESET);
	assert.equal(drops.length, 2);
	const [manual, ipt] = drops;
	assert.equal(manual.table, "filter");
	assert.equal(manual.chain, "forward");
	assert.equal(manual.src_set, "site_hinderlich");
	assert.equal(manual.dst_set, "site_daniel");
	assert.ok(manual.src.includes("10.10.0.7/32"));
	assert.ok(manual.dst.includes("192.168.111.0/24"));
	assert.equal(manual.extra, false);
	assert.equal(ipt.family, "ip");
	assert.deepEqual(ipt.src, ["192.168.11.0/24"]);
	assert.deepEqual(ipt.dst, ["10.3.10.5/32"]);
	assert.equal(ipt.extra, true);
	assert.deepEqual(parseForeignForwardDrops("not json"), []);
	assert.deepEqual(parseForeignForwardDrops('{"nftables":[]}'), []);
});

test("manualSitePairs + manualDropVerdict: manual rule separates Hinderlich <-> Daniel only", () => {
	const drops = parseForeignForwardDrops(LIVE_RULESET);
	const sites = links()
		.filter((l) => l.type === "site-to-site")
		.map((l) => ({ link_id: l.id, name: l.name, networks: l.importedNetworks, tunnel: l.tunnelAddresses }));
	const mp = manualSitePairs({ drops, sites });
	const n = normalizePair(H, D);
	assert.ok(mp.some((p) => p.link_a === n.a && p.link_b === n.b));
	assert.equal(
		mp.find((p) => p.link_a === n.a && p.link_b === n.b).rules[0].comment,
		"Standort-Trennung Hinderlich zu Daniel",
	);
	// the ip filter rule (Floppy Home → .10.5 ssh) touches no other site pair
	assert.equal(mp.filter((p) => [p.link_a, p.link_b].includes(F)).length, 0);

	const v = manualDropVerdict({ drops, src: "192.168.210.15", dst: "192.168.111.5" });
	assert.equal(v.blocked, true);
	assert.equal(v.rule.table, "filter");
	// one-directional manual rule: reverse is not blocked by THIS fixture
	assert.equal(manualDropVerdict({ drops, src: "192.168.111.5", dst: "192.168.210.15" }).blocked, false);
	// rule with extra conditions (port) is partial only
	const p = manualDropVerdict({ drops, src: "192.168.11.4", dst: "10.3.10.5" });
	assert.equal(p.blocked, false);
	assert.equal(p.partial, true);
	assert.deepEqual(manualDropVerdict({ drops, src: "192.168.11.4", dst: "192.168.111.5" }), {
		blocked: false,
		partial: false,
	});
});

test("bootIncludesFile: exact include, glob include, commented include", () => {
	const f = "/etc/nftables.d/floppyguard-sites.nft";
	assert.equal(
		bootIncludesFile('flush ruleset\ntable inet filter {}\ninclude "/etc/nftables.d/floppyguard-sites.nft"\n', f),
		true,
	);
	assert.equal(bootIncludesFile('include "/etc/nftables.d/*.nft"', f), true);
	assert.equal(bootIncludesFile('include "/etc/nftables.d/*.conf"', f), false);
	assert.equal(bootIncludesFile('# include "/etc/nftables.d/floppyguard-sites.nft"', f), false);
	assert.equal(bootIncludesFile("flush ruleset\n", f), false);
	assert.equal(bootIncludesFile(null, f), false);
});
