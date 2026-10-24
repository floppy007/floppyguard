import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { _testExports } from "./agent.js";
import {
	armedOnPatch,
	buildIngressRestore,
	canonicalCidr,
	cidrContains,
	hubTunnelHosts,
	isHubSourced,
	isWgIface,
	nextHitState,
	pubKey8,
	splitLinkId,
	ruleCovers,
	tunnelAddressEntries,
	upstreamCovered,
	sanitizeIngressCounters,
	sanitizeIngressMode,
	sanitizeIngressRule,
	MAX_LINES_PER_RULE,
	ruleLineCount,
} from "./agent-ingress-rules.js";

const rule = (over = {}) => ({
	id: 1,
	name: "r",
	sources: ["10.10.0.1/32"],
	destinations: ["192.168.60.22/32"],
	ports: [],
	enabled: true,
	...over,
});

// ─── CIDR helpers ────────────────────────────────────────────────────────────

test("canonicalCidr normalizes hosts and masks host bits", () => {
	assert.equal(canonicalCidr("10.0.0.1"), "10.0.0.1/32");
	assert.equal(canonicalCidr(" 192.168.1.7/24 "), "192.168.1.0/24");
	assert.equal(canonicalCidr("0.0.0.0/0"), "0.0.0.0/0");
	for (const bad of ["", "10.0.0.300", "10.0.0.1/33", "10.0.0.1/24/1", "a.b.c.d", "10.0.0.1; rm", "::1", null]) {
		assert.equal(canonicalCidr(bad), null, String(bad));
	}
});

test("cidrContains handles hosts, subnets and supernets", () => {
	assert.ok(cidrContains("10.3.10.0/24", "10.3.10.25"));
	assert.ok(cidrContains("10.4.0.0/16", "10.4.30.0/24"));
	assert.ok(!cidrContains("10.4.30.0/24", "10.4.0.0/16"));
	assert.ok(!cidrContains("192.168.60.0/24", "192.168.61.1"));
	assert.ok(cidrContains("0.0.0.0/0", "8.8.8.8"));
});

// ─── sanitizeIngressRule ─────────────────────────────────────────────────────

test("sanitizeIngressRule normalizes lists and ports", () => {
	const r = sanitizeIngressRule({
		name: "  Proxy\nNextcloud ",
		sources: ["10.10.0.1", "10.10.0.1/32"],
		destinations: ["192.168.60.22"],
		ports: [{ proto: "TCP", port: "443" }, { port: "8000-8010" }, { proto: "tcp", port: "443" }],
	});
	assert.equal(r.name, "Proxy Nextcloud");
	assert.deepEqual(r.sources, ["10.10.0.1/32"]);
	assert.deepEqual(r.destinations, ["192.168.60.22/32"]);
	assert.deepEqual(r.ports, [
		{ proto: "tcp", port: "443" },
		{ proto: "tcp", port: "8000:8010" },
	]);
	assert.equal(r.enabled, true);
	assert.equal(r.note, null);
});

test("sanitizeIngressRule rejects bad input instead of widening it", () => {
	assert.throws(() => sanitizeIngressRule({ name: "x", sources: [] }), /sources/);
	assert.throws(() => sanitizeIngressRule({ name: "", sources: ["10.0.0.1"] }), /name/);
	assert.throws(
		() => sanitizeIngressRule({ name: "x", sources: ["10.0.0.1"], destinations: ["nope"] }),
		/destinations/,
	);
	assert.throws(() =>
		sanitizeIngressRule({ name: "x", sources: ["10.0.0.1"], ports: [{ proto: "icmp", port: "1" }] }),
	);
	assert.throws(() => sanitizeIngressRule({ name: "x", sources: ["10.0.0.1"], ports: [{ port: "0" }] }));
	assert.throws(() => sanitizeIngressRule({ name: "x", sources: ["10.0.0.1"], ports: [{ port: "90:80" }] }));
	assert.throws(() => sanitizeIngressRule({ name: "x", sources: "10.0.0.1" }));
});

test("sanitizeIngressRule partial only touches given fields", () => {
	assert.deepEqual(sanitizeIngressRule({ enabled: false }, { partial: true }), { enabled: false });
});

test("sanitizeIngressMode accepts only open/restricted", () => {
	assert.equal(sanitizeIngressMode("restricted"), "restricted");
	assert.throws(() => sanitizeIngressMode("closed"));
});

// ─── buildIngressRestore ─────────────────────────────────────────────────────

test("open agent without rules gets no filter at all (zero footprint)", () => {
	assert.equal(buildIngressRestore({ ingress_mode: "open", iface: "wg0" }, []), null);
	assert.equal(buildIngressRestore({ ingress_mode: "open", iface: "wg0" }, [rule({ enabled: false })]), null);
});

test("restricted ruleset: established first, DROP last, comments carry rule ids", () => {
	const b = buildIngressRestore({ ingress_mode: "restricted", iface: "wg0" }, [
		rule({ id: 7, ports: [{ proto: "tcp", port: "443" }] }),
		rule({ id: 3, sources: ["192.168.111.0/24"], destinations: [] }),
		rule({ id: 9, enabled: false }),
	]);
	const lines = b.text.trim().split("\n");
	assert.equal(lines[0], "*filter");
	assert.equal(lines[1], ":FG_IN - [0:0]");
	assert.equal(lines[2], "-A FG_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
	assert.equal(lines[3], '-A FG_IN -s 192.168.111.0/24 -i wg0 -m comment --comment "fg:3" -j ACCEPT');
	assert.equal(
		lines[4],
		'-A FG_IN -s 10.10.0.1/32 -d 192.168.60.22/32 -i wg0 -p tcp -m tcp --dport 443 -m comment --comment "fg:7" -j ACCEPT',
	);
	assert.equal(lines[5], "-A FG_IN -i wg0 -j DROP");
	assert.equal(lines[6], "COMMIT");
	assert.equal(b.ruleCount, 2);
	assert.match(b.hash, /^[0-9a-f]{64}$/);
});

test("open mode with rules has no DROP", () => {
	const b = buildIngressRestore({ ingress_mode: "open", iface: "wg0" }, [rule()]);
	assert.ok(!b.text.includes("-j DROP"));
});

test("open mode with rules is observation only (RETURN, conntrack shortcut RETURNs)", () => {
	const b = buildIngressRestore({ ingress_mode: "open", iface: "wg0" }, [rule()]);
	const rules = b.text.split("\n").filter((l) => l.startsWith("-A "));
	assert.equal(rules.length, 2);
	// established traffic skips the rule walk, non-terminal
	assert.equal(rules[0], "-A FG_IN -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN");
	assert.match(rules[1], / -j RETURN$/);
	assert.ok(!b.text.includes("-j ACCEPT"));
	assert.equal(b.ruleCount, 1);
});

test("rule expansion is capped per rule and per agent", () => {
	const many = (n, f) => Array.from({ length: n }, (_, i) => f(i));
	const big = {
		name: "big",
		sources: many(17, (i) => `10.0.${i}.0/24`),
		destinations: many(16, (i) => `192.168.${i}.1`),
		ports: [],
	};
	assert.equal(ruleLineCount(big), 17 * 16);
	assert.throws(() => sanitizeIngressRule(big), /höchstens/);
	assert.doesNotThrow(() => sanitizeIngressRule({ ...big, sources: big.sources.slice(0, 16) }));
	assert.equal(ruleLineCount({ sources: ["1.1.1.1"], destinations: [], ports: [] }), 1);
	// global cap: 20 rules × 256 lines > 4000
	const rules = many(20, (i) => ({
		...rule({ id: i + 1 }),
		sources: many(16, (j) => `10.${i}.${j}.0/24`),
		destinations: many(16, (j) => `192.168.${j}.1`),
	}));
	assert.equal(ruleLineCount(rules[0]), MAX_LINES_PER_RULE);
	assert.throws(() => buildIngressRestore({ ingress_mode: "restricted", iface: "wg0" }, rules), /ingress lines/);
});

test("an invalid destination never degrades to 'any destination'", () => {
	assert.throws(() =>
		buildIngressRestore({ ingress_mode: "restricted", iface: "wg0" }, [rule({ destinations: ["999.1.1.1/32"] })]),
	);
	assert.throws(() => buildIngressRestore({ ingress_mode: "restricted", iface: "wg0" }, [rule({ sources: [] })]));
});

test("interface name is validated (no injection via wg_interface)", () => {
	assert.throws(() => buildIngressRestore({ ingress_mode: "restricted", iface: "wg0 -j ACCEPT" }, [rule()]));
});

test("hash is stable and changes with content", () => {
	const a = buildIngressRestore({ ingress_mode: "restricted", iface: "wg0" }, [rule()]);
	const b = buildIngressRestore({ ingress_mode: "restricted", iface: "wg0" }, [rule()]);
	const c = buildIngressRestore({ ingress_mode: "restricted", iface: "wg0" }, [
		rule({ destinations: ["192.168.60.8"] }),
	]);
	assert.equal(a.hash, b.hash);
	assert.notEqual(a.hash, c.hash);
});

// ─── counters / hits ─────────────────────────────────────────────────────────

test("sanitizeIngressCounters drops hostile values", () => {
	const m = sanitizeIngressCounters({ 1: 5, 2: -1, x: 3, 4: "7", 5: Number.POSITIVE_INFINITY, 0: 1 });
	assert.deepEqual(
		[...m.entries()],
		[
			[1, 5],
			[4, 7],
		],
	);
	assert.equal(sanitizeIngressCounters([1, 2]).size, 0);
	assert.equal(sanitizeIngressCounters("x").size, 0);
});

test("nextHitState: growth = hit, unchanged = no hit, reset counts as delta", () => {
	assert.deepEqual(nextHitState({ hit_packets: 10, last_hit_at: 5 }, 12, 100), { hit_packets: 12, last_hit_at: 100 });
	assert.deepEqual(nextHitState({ hit_packets: 10, last_hit_at: 5 }, 10, 100), { hit_packets: 10, last_hit_at: 5 });
	assert.deepEqual(nextHitState({ hit_packets: 10, last_hit_at: 5 }, 3, 100), { hit_packets: 3, last_hit_at: 100 });
	assert.deepEqual(nextHitState({ hit_packets: 10, last_hit_at: null }, 0, 100), {
		hit_packets: 0,
		last_hit_at: null,
	});
});

// ─── proxy coupling ──────────────────────────────────────────────────────────

test("ruleCovers respects source, destination, ports and enabled", () => {
	const r = rule({ ports: [{ proto: "tcp", port: "8000:8010" }] });
	assert.ok(ruleCovers(r, { src: "10.10.0.1/32", dst: "192.168.60.22", port: 8005 }));
	assert.ok(!ruleCovers(r, { src: "10.10.0.1/32", dst: "192.168.60.22", port: 443 }));
	assert.ok(!ruleCovers(r, { src: "10.10.0.1/32", dst: "192.168.60.22", port: 8005, proto: "udp" }));
	assert.ok(!ruleCovers(r, { src: "10.10.0.9/32", dst: "192.168.60.22", port: 8005 }));
	assert.ok(!ruleCovers({ ...r, enabled: false }, { src: "10.10.0.1/32", dst: "192.168.60.22", port: 8005 }));
	assert.ok(ruleCovers(rule({ destinations: [] }), { src: "10.10.0.1/32", dst: "10.3.10.25", port: 22 }));
});

test("hubTunnelHosts extracts host addresses of the hub interface", () => {
	assert.deepEqual(hubTunnelHosts("[Interface]\nAddress = 10.10.0.1/24, 10.20.0.1/24\nListenPort = 51820"), [
		"10.10.0.1/32",
		"10.20.0.1/32",
	]);
	assert.deepEqual(hubTunnelHosts(""), []);
});

// ─── agent loop script ───────────────────────────────────────────────────────

test("agent loop script ships the ingress functions and is valid bash", () => {
	const script = _testExports.buildLoopScript();
	for (const fn of [
		"apply_ingress()",
		"remove_ingress()",
		"ensure_ingress_jump()",
		"ingress_selfheal()",
		"dedupe_iface_rules()",
	]) {
		assert.ok(script.includes(fn), fn);
	}
	assert.ok(script.includes("'ingress_counters': json.loads(sys.argv[7])"));
	assert.ok(!script.includes("rstrip('\n')"), "template literal must not turn \\n into a real newline in python");
	const r = spawnSync("bash", ["-n"], { input: script });
	assert.equal(r.status, 0, r.stderr?.toString());
});

// Pinned on purpose: since agent script 1.5.0 an "open" agent WITH rules only
// observes (RETURN everywhere, no ACCEPT, no DROP). In 1.4.0 the same input
// ACCEPTed matching flows at FORWARD position 1. Any change to this output changes
// live gateway behaviour fleet-wide and must be a deliberate, release-noted step.
test("open-mode output is pinned: RETURN only, no ACCEPT, no DROP", () => {
	const b = buildIngressRestore({ ingress_mode: "open", iface: "wg0" }, [
		rule({ id: 7, ports: [{ proto: "tcp", port: "443" }] }),
		rule({ id: 3, sources: ["192.168.111.0/24"], destinations: [] }),
	]);
	assert.equal(
		b.text,
		[
			"*filter",
			":FG_IN - [0:0]",
			"-A FG_IN -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
			'-A FG_IN -s 192.168.111.0/24 -i wg0 -m comment --comment "fg:3" -j RETURN',
			'-A FG_IN -s 10.10.0.1/32 -d 192.168.60.22/32 -i wg0 -p tcp -m tcp --dport 443 -m comment --comment "fg:7" -j RETURN',
			"COMMIT",
			"",
		].join("\n"),
	);
	assert.ok(!/-j (ACCEPT|DROP)\b/.test(b.text));
});

test("armedOnPatch re-arms on switch-on or target change, not on rename/note edit", () => {
	const existing = {
		enabled: true,
		sources: ["10.0.0.0/24"],
		destinations: [],
		ports: [{ proto: "tcp", port: "389" }],
	};
	assert.deepEqual(armedOnPatch(existing, { name: "neu", note: "x" }, 100), {});
	assert.deepEqual(armedOnPatch(existing, { enabled: true }, 100), {}, "already on");
	assert.deepEqual(armedOnPatch(existing, { sources: ["10.0.0.0/24"] }, 100), {}, "same targets");
	assert.deepEqual(armedOnPatch(existing, { ports: [{ proto: "tcp", port: "636" }] }, 100), { armed_on: 100 });
	assert.deepEqual(armedOnPatch(existing, { destinations: ["10.1.0.5/32"] }, 100), { armed_on: 100 });
	assert.deepEqual(armedOnPatch({ ...existing, enabled: false }, { enabled: true }, 100), { armed_on: 100 });
	assert.deepEqual(armedOnPatch(existing, { enabled: false }, 100), {});
	const existing2 = {
		enabled: true,
		sources: ["10.0.0.0/24", "10.1.0.0/24"],
		destinations: [],
		ports: [
			{ proto: "tcp", port: "636" },
			{ proto: "tcp", port: "389" },
		],
	};
	assert.deepEqual(armedOnPatch(existing2, { sources: ["10.1.0.0/24", "10.0.0.0/24"] }, 100), {}, "reorder only");
	assert.deepEqual(
		armedOnPatch(
			existing2,
			{
				ports: [
					{ proto: "tcp", port: "389" },
					{ proto: "tcp", port: "636" },
				],
			},
			100,
		),
		{},
		"ports reorder only",
	);
	assert.deepEqual(armedOnPatch(existing2, { sources: ["10.1.0.0/24"] }, 100), { armed_on: 100 }, "subset re-arms");
});

test("self-update shebang check uses no pipe (large scripts must not SIGPIPE under pipefail)", () => {
	const script = _testExports.buildLoopScript();
	assert.ok(
		!script.includes('echo "$NEW_SCRIPT" | head'),
		"piping the downloaded script into head races with SIGPIPE",
	);
	assert.ok(script.includes('[[ "$NEW_SCRIPT" == "#!"* ]]'));
});

// ─── shared predicates (proxyCheck / catalog) ────────────────────────────────

test("upstreamCovered uses u.source when set, else the hub hosts; null port vs port list", () => {
	const r = rule({
		sources: ["10.10.0.1/32"],
		destinations: ["10.3.10.5/32"],
		ports: [{ proto: "tcp", port: "443" }],
	});
	const hub = ["10.10.0.1/32"];
	assert.equal(upstreamCovered({ host: "10.3.10.5", port: 443, proto: "tcp" }, [r], hub), true);
	// an egress flow with its own SNAT source is checked against that source only
	assert.equal(
		upstreamCovered({ host: "10.3.10.5", port: 443, proto: "tcp", source: "10.10.0.9/32" }, [r], hub),
		false,
	);
	const own = rule({ sources: ["10.10.0.9/32"], destinations: [], ports: [] });
	assert.equal(upstreamCovered({ host: "10.3.10.5", port: 443, source: "10.10.0.9/32" }, [own], hub), true);
	// unknown port: a port-restricted rule does not cover it, undefined counts as unknown too
	assert.equal(upstreamCovered({ host: "10.3.10.5", port: null, proto: "tcp" }, [r], hub), false);
	assert.equal(upstreamCovered({ host: "10.3.10.5" }, [r], hub), false);
	// proto missing defaults to tcp
	assert.equal(upstreamCovered({ host: "10.3.10.5", port: 443 }, [r], hub), true);
	assert.equal(upstreamCovered({ host: "10.3.10.5", port: 443 }, [r], undefined), false);
});

test("isHubSourced: every source inside a hub address, broad sources are not", () => {
	const hub = ["10.10.0.1/32", "10.10.0.7/32"];
	assert.equal(isHubSourced(rule({ sources: ["10.10.0.1/32"] }), hub), true);
	assert.equal(isHubSourced(rule({ sources: ["10.10.0.1/32", "10.10.0.7/32"] }), hub), true);
	assert.equal(isHubSourced(rule({ sources: ["10.10.0.1/32", "10.4.0.0/16"] }), hub), false);
	assert.equal(isHubSourced(rule({ sources: ["10.10.0.0/24"] }), hub), false);
	assert.equal(isHubSourced(rule({ sources: [] }), hub), false);
	assert.equal(isHubSourced({}, hub), false);
});

test("tunnelAddressEntries splits every Address line in file order", () => {
	assert.deepEqual(tunnelAddressEntries("Address = 10.10.0.1/24, 10.20.0.1\n"), ["10.10.0.1/24", "10.20.0.1"]);
	assert.deepEqual(tunnelAddressEntries("[Interface]\naddress=10.1.0.1/24\n\nAddress = ,\n"), ["10.1.0.1/24"]);
	assert.deepEqual(tunnelAddressEntries(null), []);
});

test("link id helpers: splitLinkId / isWgIface / pubKey8", () => {
	assert.deepEqual(splitLinkId("wg0:abc:def="), ["wg0", "abc:def="]);
	assert.equal(splitLinkId("nocolon"), null);
	assert.equal(isWgIface("wg12"), true);
	for (const bad of ["wg", "wg1234", "eth0", "wg0\n", null, undefined]) assert.equal(isWgIface(bad), false);
	assert.equal(pubKey8("ABCDEFGHIJ"), "ABCDEFGH");
});
