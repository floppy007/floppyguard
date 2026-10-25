import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
	assertDirectLinkFits,
	buildDirectConfig,
	buildDirectHooks,
	canonicalTunnelSubnet,
	directPayloadEntry,
	directPeerNets,
	isDirectIface,
	sanitizeDirectLinkInput,
	sanitizeDirectStatus,
	tunnelAddresses,
} from "./agent-direct-link-rules.js";
import { buildIngressRestore } from "./agent-ingress-rules.js";
import { _testExports as agentExports } from "./agent.js";

const KEY_A = "uA8nRdrRr628qLIa2mkciZ/jfFT3SOzyxAWSafp2UzY=";
const KEY_B = "88I9yCmRuMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxA=";

const link = (over = {}) => ({
	id: 1,
	name: "Floppy ↔ Hinderlich",
	agent_a_id: 2,
	agent_b_id: 1,
	listen_port: 51830,
	endpoint_host: "203.0.113.10",
	tunnel_subnet: "10.10.9.0/30",
	mtu: 1300,
	enabled: true,
	nat_a: false,
	nat_b: true,
	...over,
});

test("tunnel subnet: private /30 network address only", () => {
	assert.equal(canonicalTunnelSubnet("10.10.9.0/30"), "10.10.9.0/30");
	assert.equal(canonicalTunnelSubnet(" 192.168.250.4/30 "), "192.168.250.4/30");
	assert.equal(canonicalTunnelSubnet("10.10.9.1/30"), null, "host bits set");
	assert.equal(canonicalTunnelSubnet("10.10.9.0/29"), null);
	assert.equal(canonicalTunnelSubnet("8.8.8.0/30"), null, "public");
	assert.equal(canonicalTunnelSubnet("10.10.9.0/30; reboot"), null);
	assert.deepEqual(tunnelAddresses("10.10.9.0/30"), { a: "10.10.9.1", b: "10.10.9.2" });
	assert.deepEqual(tunnelAddresses("10.10.9.252/30"), { a: "10.10.9.253", b: "10.10.9.254" });
});

test("input validation", () => {
	const ok = sanitizeDirectLinkInput({ ...link(), id: undefined });
	assert.equal(ok.endpoint_host, "203.0.113.10");
	assert.equal(ok.nat_b, true);
	assert.equal(
		sanitizeDirectLinkInput({ ...link(), endpoint_host: "Daniel.DynDNS.example" }).endpoint_host,
		"daniel.dyndns.example",
	);
	for (const bad of [
		{ endpoint_host: "1.2.3.4:51820" },
		{ endpoint_host: "a b" },
		{ endpoint_host: "host\nPostUp = rm -rf /" },
		{ endpoint_host: "999.1.1.1" },
		{ listen_port: 80 },
		{ listen_port: "51830x" },
		{ agent_b_id: 2 },
		{ tunnel_subnet: "10.10.9.0/24" },
		{ mtu: 9000 },
		{ name: "" },
	]) {
		assert.throws(() => sanitizeDirectLinkInput({ ...link(), ...bad }), /must|needs|required/, JSON.stringify(bad));
	}
	assert.throws(() => sanitizeDirectLinkInput({ name: "x" }), /required/);
	assert.deepEqual(sanitizeDirectLinkInput({ enabled: "true" }, { partial: true }), { enabled: true });
	assert.deepEqual(sanitizeDirectLinkInput({ mtu: null }, { partial: true }), { mtu: null });
});

const fitsCtx = (over = {}) => ({
	agents: new Map([
		[1, { id: 1, wg_link_name: "Floppy Home" }],
		[2, { id: 2, wg_link_name: "Hinderlich Office" }],
		[5, { id: 5, wg_link_name: "Daniel Home" }],
		[6, { id: 6, wg_link_name: "PVE-Hetzner" }],
		[9, { id: 9, wg_link_name: "iPhone" }],
	]),
	siteLinkIdOf: (a) =>
		({ "Floppy Home": "wg0:F", "Hinderlich Office": "wg0:H", "Daniel Home": "wg0:D", "PVE-Hetzner": "wg0:P" })[
			a.wg_link_name
		] ?? null,
	isolated: (x, y) => [x, y].sort().join("|") === "wg0:D|wg0:H",
	siteNets: ["192.168.20.0/24", "192.168.200.0/24", "10.4.0.0/16"],
	agentTunnelSubnets: ["10.10.0.0/24"],
	others: [],
	...over,
});

test("mesh checks: separated sites, clients, overlaps, duplicates", () => {
	assert.doesNotThrow(() => assertDirectLinkFits(link(), fitsCtx()));
	assert.throws(() => assertDirectLinkFits(link({ agent_a_id: 5, agent_b_id: 2 }), fitsCtx()), /separated/);
	assert.throws(() => assertDirectLinkFits(link({ agent_a_id: 9 }), fitsCtx()), /site link/);
	assert.throws(() => assertDirectLinkFits(link({ agent_a_id: 77 }), fitsCtx()), /exist/);
	assert.throws(
		() => assertDirectLinkFits(link({ tunnel_subnet: "10.10.0.4/30" }), fitsCtx()),
		/overlaps 10\.10\.0\.0\/24/,
	);
	assert.throws(
		() => assertDirectLinkFits(link({ tunnel_subnet: "10.4.9.0/30" }), fitsCtx()),
		/overlaps 10\.4\.0\.0\/16/,
	);
	const other = { ...link({ id: 2, name: "x", tunnel_subnet: "10.10.9.4/30" }) };
	assert.throws(() => assertDirectLinkFits(link(), fitsCtx({ others: [other] })), /already have/);
	assert.throws(
		() =>
			assertDirectLinkFits(
				link({ tunnel_subnet: "10.10.9.4/30", agent_a_id: 1, agent_b_id: 5 }),
				fitsCtx({ others: [other] }),
			),
		/already used/,
	);
	assert.throws(
		() =>
			assertDirectLinkFits(link({ agent_b_id: 6, tunnel_subnet: "10.10.9.8/30" }), fitsCtx({ others: [other] })),
		/listen_port/,
	);
	// updating the same row does not clash with itself
	assert.doesNotThrow(() => assertDirectLinkFits(link(), fitsCtx({ others: [link()] })));
});

test("hooks: idempotent, interface baked in, NAT only where asked", () => {
	const h = buildDirectHooks({ iface: "fgd1", hubIface: "wg0", tunnelSubnet: "10.10.9.0/30", nat: true });
	assert.ok(!h.postUp.includes("%i"));
	assert.match(
		h.postUp,
		/iptables -C FORWARD -i fgd1 -j ACCEPT 2>\/dev\/null \|\| iptables -A FORWARD -i fgd1 -j ACCEPT/,
	);
	assert.match(h.postUp, /-t nat -A POSTROUTING ! -o fgd1 -s 10\.10\.9\.0\/30 -j MASQUERADE/);
	assert.match(h.postUp, /-t nat -A POSTROUTING -o fgd1 -j MASQUERADE/);
	assert.match(h.postUp, /net\.ipv4\.conf\.fgd1\.rp_filter=2.*net\.ipv4\.conf\.wg0\.rp_filter=2/);
	assert.match(h.postDown, /-t nat -D POSTROUTING -o fgd1 -j MASQUERADE/);
	const noNat = buildDirectHooks({ iface: "fgd1", hubIface: "wg0", tunnelSubnet: "10.10.9.0/30", nat: false });
	assert.ok(!/-o fgd1 -j MASQUERADE/.test(noNat.postUp));
	// never a wgN name (a gateway may run foreign wg tunnels, e.g. wg1)
	assert.throws(() => buildDirectHooks({ iface: "wg1", hubIface: "wg0", tunnelSubnet: "10.10.9.0/30" }));
	assert.throws(() => buildDirectHooks({ iface: "fgd1", hubIface: "wg0;x", tunnelSubnet: "10.10.9.0/30" }));
	assert.equal(isDirectIface("fgd12"), true);
	assert.equal(isDirectIface("wg1"), false);
});

test("config: A listens, B dials, no PrivateKey, partner nets only", () => {
	const nets = ["192.168.200.0/24", "10.4.0.0/16"];
	const a = buildDirectConfig({
		link: link(),
		side: "a",
		hubIface: "wg0",
		peerPublicKey: KEY_A,
		peerNets: nets,
		mtu: 1300,
	});
	assert.match(a, /^\[Interface\]\nAddress = 10\.10\.9\.1\/30\nListenPort = 51830\nMTU = 1300\nTable = off\n/);
	assert.ok(!/Endpoint/.test(a));
	assert.ok(!/PrivateKey/.test(a));
	assert.match(a, /AllowedIPs = 10\.10\.9\.0\/30, 192\.168\.200\.0\/24, 10\.4\.0\.0\/16/);
	const b = buildDirectConfig({
		link: link(),
		side: "b",
		hubIface: "wg0",
		peerPublicKey: KEY_A,
		peerNets: [],
		mtu: null,
	});
	assert.match(b, /Address = 10\.10\.9\.2\/30/);
	assert.ok(!/ListenPort/.test(b));
	assert.match(b, /Endpoint = 203\.0\.113\.10:51830\nPersistentKeepalive = 25/);
	// side b NATs (nat_b), side a does not
	assert.match(b, /-o fgd1 -j MASQUERADE/);
	assert.ok(!/-o fgd1 -j MASQUERADE/.test(a));
	// no partner key yet → no config
	assert.equal(
		buildDirectConfig({ link: link(), side: "b", hubIface: "wg0", peerPublicKey: null, peerNets: [] }),
		null,
	);
	assert.equal(
		buildDirectConfig({ link: link(), side: "b", hubIface: "wg0", peerPublicKey: "x", peerNets: [] }),
		null,
	);
	assert.throws(() =>
		buildDirectConfig({
			link: link(),
			side: "a",
			hubIface: "wg0",
			peerPublicKey: KEY_A,
			peerNets: ["1.2.3.0/24; x"],
		}),
	);
});

test("peer nets = hub-side reach restricted to the partner site", () => {
	// Hinderlich's ACL reaches Floppy's .11/.20/.50/.60 + 10.3.10, PVE's 10.10.10 — not Floppy's 10.3.60
	const hinderlichReach = [
		"10.10.10.0/24",
		"192.168.60.0/24",
		"192.168.11.0/24",
		"10.3.10.0/24",
		"192.168.20.0/24",
		"192.168.50.0/24",
	];
	const floppyNets = [
		"192.168.11.0/24",
		"192.168.20.0/24",
		"192.168.60.0/24",
		"10.3.10.0/24",
		"10.3.60.0/24",
		"192.168.50.0/24",
	];
	assert.deepEqual(directPeerNets(hinderlichReach, floppyNets), [
		"10.3.10.0/24",
		"192.168.11.0/24",
		"192.168.20.0/24",
		"192.168.50.0/24",
		"192.168.60.0/24",
	]);
	assert.deepEqual(directPeerNets([], floppyNets), []);
});

test("payload entry: disabled carries no config, enabled is hash-protected", () => {
	const off = directPayloadEntry({
		link: link(),
		side: "a",
		hubIface: "wg0",
		peerPublicKey: KEY_B,
		peerNets: [],
		active: false,
	});
	assert.deepEqual(off, { id: 1, iface: "fgd1", table: 52001, enabled: false });
	const on = directPayloadEntry({
		link: link(),
		side: "b",
		hubIface: "wg0",
		peerPublicKey: KEY_A,
		peerNets: ["192.168.200.0/24"],
		active: true,
	});
	assert.equal(on.enabled, true);
	assert.equal(on.peer_ip, "10.10.9.1");
	assert.deepEqual(on.routes, ["192.168.200.0/24"]);
	assert.equal(on.endpoint, null, "IP literal endpoint needs no re-resolution");
	assert.equal(on.config_hash, createHash("sha256").update(on.config_text).digest("hex"));
	const dyn = directPayloadEntry({
		link: link({ endpoint_host: "daniel.example.org" }),
		side: "b",
		hubIface: "wg0",
		peerPublicKey: KEY_A,
		peerNets: [],
		active: true,
	});
	assert.equal(dyn.endpoint, "daniel.example.org:51830");
	const waiting = directPayloadEntry({
		link: link(),
		side: "a",
		hubIface: "wg0",
		peerPublicKey: null,
		peerNets: [],
		active: true,
	});
	assert.equal(waiting.config_text, null);
	assert.equal(waiting.config_hash, null);
});

test("heartbeat status: only own links, strict shapes", () => {
	const m = sanitizeDirectStatus(
		{
			1: { public_key: KEY_A, up: true, path: "direct", handshake_age: 12, rtt_ms: 7.345, error: "x\ny" },
			2: { public_key: "evil", path: "sideways", handshake_age: -1, rtt_ms: "a" },
			3: { public_key: KEY_A },
			__proto__: { x: 1 },
		},
		new Set([1, 2]),
	);
	assert.deepEqual([...m.keys()], [1, 2]);
	assert.deepEqual(m.get(1), {
		public_key: KEY_A,
		status: { up: true, path: "direct", handshake_age: 12, rtt_ms: 7.3, error: "x y" },
	});
	assert.deepEqual(m.get(2), {
		public_key: null,
		status: { up: false, path: "hub", handshake_age: null, rtt_ms: null, error: null },
	});
	assert.equal(sanitizeDirectStatus([1], new Set([1])).size, 0);
	assert.equal(sanitizeDirectStatus(null, new Set([1])).size, 0);
});

test("FG_IN covers direct interfaces like the hub interface; unchanged without them", () => {
	const rules = [{ id: 1, enabled: true, sources: ["192.168.200.0/24"], destinations: [], ports: [] }];
	const plain = buildIngressRestore({ ingress_mode: "restricted", iface: "wg0" }, rules);
	const same = buildIngressRestore({ ingress_mode: "restricted", iface: "wg0", directIfaces: [] }, rules);
	assert.equal(plain.hash, same.hash, "no direct links → identical ruleset");
	const withDirect = buildIngressRestore({ ingress_mode: "restricted", iface: "wg0", directIfaces: ["fgd1"] }, rules);
	assert.match(withDirect.text, /-A FG_IN -s 192\.168\.200\.0\/24 -i fgd1 -m comment --comment "fg:1" -j ACCEPT/);
	assert.match(withDirect.text, /-A FG_IN -i wg0 -j DROP\n-A FG_IN -i fgd1 -j DROP\nCOMMIT/);
	assert.throws(() =>
		buildIngressRestore({ ingress_mode: "restricted", iface: "wg0", directIfaces: ["eth0"] }, rules),
	);
});

test("agent script: direct links are optional, health-checked and never touch the hub routes", () => {
	const s = agentExports.buildLoopScript();
	assert.ok(s.includes('direct_wait "$POLL_INTERVAL"'));
	assert.ok(!/\n {2}sleep "\$POLL_INTERVAL"\n/.test(s), "plain sleep replaced by the health-checking wait");
	// direct step runs after the ingress step and before the heartbeat
	const ing = s.indexOf('INGRESS_APPLIED=$(cat "$INGRESS_RUN_HASH"');
	const dir = s.indexOf("direct_step || true");
	const hb = s.indexOf("HEARTBEAT=$(python3");
	assert.ok(ing > 0 && dir > ing && hb > dir);
	// routes go into the per-link table only; main-table hub routes stay untouched
	assert.ok(s.includes('ip route replace "$net" dev "$iface" table "$table"'));
	assert.ok(s.includes("ip rule add pref $DIRECT_RULE_PREF lookup"));
	assert.ok(!/ip route (add|replace|del) "\$net" dev "\$iface" metric/.test(s));
	// the ingress guard and the key handling
	assert.ok(s.includes("direct_ingress_ok"));
	assert.ok(s.includes("wg genkey"));
	assert.ok(s.includes("'direct_links': json.loads(sys.argv[12])"));
	// no echo|head style pipes in the new code (SIGPIPE under pipefail)
	const block = s.slice(s.indexOf('DIRECT_DIR="/var/lib'), s.indexOf("# ── Service discovery"));
	assert.ok(!/\| *head/.test(block));
	assert.ok(!/\| *grep -q/.test(block));
});

test("audit fixes: supernets of own nets stay off the direct path; disabled links stay editable; line cap per interface", async () => {
	// a partner 10.0.0.0/8 would win over the own 10.3.10.0/24 in the per-link table (consulted before main)
	assert.deepEqual(
		directPeerNets(
			["10.0.0.0/8", "192.168.200.0/24"],
			["10.0.0.0/8", "192.168.200.0/24"],
			["10.3.10.0/24", "10.10.0.0/24"],
		),
		["192.168.200.0/24"],
	);
	// separated sites / missing agent: an enabled link is refused, a disabled one can still be saved (Rückweg)
	assert.throws(() => assertDirectLinkFits(link({ agent_a_id: 5, agent_b_id: 2 }), fitsCtx()), /separated/);
	assert.doesNotThrow(() => assertDirectLinkFits(link({ agent_a_id: 5, agent_b_id: 2, enabled: false }), fitsCtx()));
	assert.doesNotThrow(() => assertDirectLinkFits(link({ agent_a_id: 77, enabled: false }), fitsCtx()));
	const { assertTotalLineCount, MAX_LINES_TOTAL } = await import("./agent-ingress-rules.js");
	const sources = Array.from({ length: 50 }, (_, i) => `10.20.${i}.0/24`);
	const rules = Array.from({ length: Math.ceil(MAX_LINES_TOTAL / 50 / 2) + 1 }, (_, i) => ({
		id: i + 1,
		enabled: true,
		sources,
		destinations: [],
		ports: [],
	}));
	assert.doesNotThrow(() => assertTotalLineCount(rules, 1));
	assert.throws(() => assertTotalLineCount(rules, 2), /Filterzeilen/);
});

test("second audit: restricted side vs partner NAT, endpoint inside a mesh net, disabled links skip all checks", async () => {
	const { natRestrictedConflict } = await import("./agent-direct-link-rules.js");
	const restricted = { ingress_mode: "restricted" };
	const open = { ingress_mode: "open" };
	// live setup: Hinderlich (A, open, no NAT) <-> Floppy (B, restricted, NAT) is fine
	assert.equal(natRestrictedConflict(link({ nat_a: false, nat_b: true }), open, restricted), false);
	assert.equal(natRestrictedConflict(link({ nat_a: true, nat_b: false }), open, restricted), true);
	assert.equal(natRestrictedConflict(link({ nat_a: false, nat_b: true }), restricted, open), true);
	const ctx = fitsCtx();
	ctx.agents.get(1).ingress_mode = "restricted";
	assert.throws(() => assertDirectLinkFits(link({ nat_a: true }), ctx), /nur Freigaben/);
	assert.throws(() => assertDirectLinkFits(link({ endpoint_host: "192.168.200.9" }), fitsCtx()), /lies inside/);
	// disabled: even a /30 that collides with a newer site net can be saved (switch off)
	assert.doesNotThrow(() =>
		assertDirectLinkFits(
			link({ enabled: false, tunnel_subnet: "10.4.9.0/30" }),
			fitsCtx({ others: [link({ id: 2 })] }),
		),
	);
});

test("agent script: in-place peer update stages <iface>.conf and refuses an empty strip", () => {
	const s = agentExports.buildLoopScript();
	assert.ok(s.includes('stage="$DIRECT_DIR/stage/$2.conf"'));
	assert.ok(!s.includes("conf.new"));
	assert.ok(s.includes('*PrivateKey*"[Peer]"*PublicKey*)'));
	assert.ok(s.includes("WG_ENDPOINT_RESOLUTION_RETRIES=1 wg set"));
});
