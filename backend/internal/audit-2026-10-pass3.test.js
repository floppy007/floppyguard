// Regression tests for the 2026-10 audit pass 3 (agents / WireGuard / Freigaben).
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const { clientIngressGaps, hubConnectedNets, parseManualConfUpstreams, peerTunnelHosts } = await import(
	"./agent-ingress.js"
);
const { ruleCovers } = await import("./agent-ingress-rules.js");
const { _testExports } = await import("./agent.js");
const { bodyFieldNames, describeAgentRequest, describeWireGuardRequest } = await import("./audit-route.js");

const rule = (over = {}) => ({
	id: 1,
	name: "r",
	sources: ["10.10.0.1/32"],
	destinations: ["192.168.60.22/32"],
	ports: [],
	enabled: true,
	...over,
});

describe("Freigaben check: ports", () => {
	it("an upstream without a port is not covered by a port-restricted rule", () => {
		const r = rule({ ports: [{ proto: "tcp", port: "9000" }] });
		assert.equal(ruleCovers(r, { src: "10.10.0.1/32", dst: "192.168.60.22", port: null }), false);
		assert.equal(ruleCovers(rule(), { src: "10.10.0.1/32", dst: "192.168.60.22", port: null }), true);
	});
	it("proxy_pass without a port defaults to the scheme port", () => {
		const conf =
			"server { server_name a.example; location / { proxy_pass https://10.3.10.31; } location /x { proxy_pass http://10.3.10.32/x; } }";
		assert.deepEqual(
			parseManualConfUpstreams(conf, "zz-a.conf").map((u) => [u.host, u.port]),
			[
				["10.3.10.31", 443],
				["10.3.10.32", 80],
			],
		);
		const npm = 'server { set $forward_scheme https; set $server "10.3.60.21"; }';
		assert.deepEqual(
			parseManualConfUpstreams(npm, "zz-b.conf").map((u) => [u.host, u.port]),
			[["10.3.60.21", 443]],
		);
	});
});

describe("Freigaben check: hub-connected nets", () => {
	it("collects non-wg, non-internal IPv4 networks", () => {
		const nets = hubConnectedNets({
			lo: [{ family: "IPv4", internal: true, cidr: "127.0.0.1/8" }],
			eth1: [
				{ family: "IPv4", internal: false, cidr: "10.10.10.106/24" },
				{ family: "IPv6", internal: false, cidr: "fe80::1/64" },
			],
			wg0: [{ family: "IPv4", internal: false, cidr: "10.10.0.1/24" }],
		});
		assert.deepEqual(nets, ["10.10.10.0/24"]);
	});
});

describe("Freigaben check: VPN clients", () => {
	const conf = [
		"[Interface]",
		"Address = 10.10.0.1/24",
		"[Peer]",
		"PublicKey = LAPPI",
		"AllowedIPs = 10.10.0.4/32",
		"[Peer]",
		"PublicKey = SITE",
		"AllowedIPs = 10.10.0.2/32, 192.168.11.0/24",
	].join("\n");
	it("reads the client's tunnel host from the hub conf", () => {
		assert.deepEqual(peerTunnelHosts(conf, "LAPPI"), ["10.10.0.4/32"]);
		assert.deepEqual(peerTunnelHosts(conf, "SITE"), ["10.10.0.2/32"]);
		assert.deepEqual(peerTunnelHosts(conf, "NOPE"), []);
	});
	it("reports client networks behind the agent that no rule covers", () => {
		const clients = [
			{
				id: "wg0:LAPPI",
				label: "Floppy Lappi",
				hosts: ["10.10.0.4/32"],
				nets: ["192.168.60.0/24", "10.10.0.0/24"],
			},
		];
		const own = ["192.168.11.0/24", "192.168.60.0/24"];
		const gaps = clientIngressGaps(clients, own, [rule()]);
		assert.equal(gaps.length, 1);
		assert.equal(gaps[0].kind, "vpn-client");
		assert.equal(gaps[0].host, "192.168.60.0/24");
		assert.deepEqual(gaps[0].suggestion.sources, ["10.10.0.4/32"]);
		assert.deepEqual(gaps[0].suggestion.destinations, ["192.168.60.0/24"]);
		// a rule for the whole tunnel range (or a host inside the net) counts as covered
		assert.equal(clientIngressGaps(clients, own, [rule({ sources: ["10.10.0.0/24"] })]).length, 0);
		assert.equal(
			clientIngressGaps(clients, own, [rule({ sources: ["10.10.0.4/32"], destinations: ["192.168.60.22/32"] })])
				.length,
			0,
		);
		assert.equal(clientIngressGaps(clients, own, [rule({ sources: ["10.10.0.0/24"], enabled: false })]).length, 1);
	});
});

describe("agent admin API", () => {
	it("redacts key lines of config_text", () => {
		const out = _testExports.redactConfigSecrets(
			"[Interface]\nPrivateKey = abc123=\nAddress = 10.10.0.2/32\n[Peer]\nPresharedKey = xyz=\nPublicKey = pub=",
		);
		assert.ok(!out.includes("abc123"));
		assert.ok(!out.includes("xyz="));
		assert.ok(out.includes("PrivateKey = (hidden)"));
		assert.ok(out.includes("PublicKey = pub="));
		assert.equal(_testExports.redactConfigSecrets(null), null);
	});
});

describe("agent loop script", () => {
	const script = _testExports.buildLoopScript();
	it("never puts the agent token on a command line", () => {
		assert.ok(!/Bearer \$FGTOKEN/.test(script.replace(/printf 'header = "Authorization: Bearer %s[^\n]*/, "")));
		assert.ok(!script.includes('-hmac "$FGTOKEN"'));
		assert.ok(!/sed[^\n]*\$new_token/.test(script));
		assert.ok(script.includes("curl -K -"));
	});
	it("installs a self-update atomically", () => {
		assert.ok(!script.includes('cp "$LOOP_UPDATE" /usr/local/sbin/floppyguard-agent'));
		assert.ok(script.includes('bash -n "$AGENT_NEW" && mv -f "$AGENT_NEW" "$AGENT_BIN"'));
	});
	it("reports the applied config hash and error in the heartbeat", () => {
		assert.ok(script.includes("'config_applied_hash': sys.argv[10], 'config_error': sys.argv[11]"));
		assert.ok(script.includes('APPLIED_HASH=$(cat "$HASH_FILE"'));
	});
});

describe("audit entries for agent / WireGuard routes", () => {
	it("describes WireGuard mutations and key downloads without values", () => {
		const e = describeWireGuardRequest({
			method: "POST",
			path: "/update-peer",
			query: {},
			body: { linkId: "wg0:abc", changes: { importedNetworks: ["10.0.0.0/24"] } },
		});
		assert.equal(e.action, "updated");
		assert.equal(e.meta.target, "wg0:abc");
		assert.deepEqual(e.meta.fields, ["linkId", "changes"]);
		assert.ok(!JSON.stringify(e).includes("10.0.0.0/24"));
		assert.equal(describeWireGuardRequest({ method: "GET", path: "/status", query: {} }), null);
		assert.equal(describeWireGuardRequest({ method: "POST", path: "/plan-preview", body: {} }), null);
		assert.equal(
			describeWireGuardRequest({ method: "GET", path: "/link-config", query: { link_id: "wg0:x" } }).meta.op,
			"link-config",
		);
		assert.equal(
			describeWireGuardRequest({ method: "DELETE", path: "/peers/wg0%3Ax", body: {} }).action,
			"deleted",
		);
		assert.equal(
			describeWireGuardRequest({ method: "POST", path: "/create-peer", body: { name: "n" } }).action,
			"created",
		);
	});
	it("describes agent admin operations", () => {
		assert.equal(describeAgentRequest({ method: "GET", path: "/agents", params: {} }), null);
		assert.equal(describeAgentRequest({ method: "GET", path: "/agents/3", params: { id: "3" } }), null);
		const put = describeAgentRequest({
			method: "PUT",
			path: "/agents/3",
			params: { id: "3" },
			body: { config_text: "PrivateKey = secret" },
		});
		assert.equal(put.object_id, 3);
		assert.deepEqual(put.meta.fields, ["config_text"]);
		assert.ok(!JSON.stringify(put).includes("secret"));
		assert.equal(
			describeAgentRequest({ method: "POST", path: "/agents/3/reset-token", params: { id: "3" } }).meta.op,
			"reset-token",
		);
		assert.equal(
			describeAgentRequest({ method: "GET", path: "/agents/3/install", params: { id: "3" } }).meta.op,
			"install-script",
		);
		assert.deepEqual(bodyFieldNames(["a"]), []);
	});
});

describe("VPN clients for the ingress check come from the live status (r2-2)", async () => {
	const { vpnClientsFromStatus } = await import("./agent-ingress.js");
	const status = {
		interfaces: [{ name: "wg0", addresses: ["10.10.0.1/24"] }],
		links: [
			// Site link: its LAN is what the hub routes to it.
			{
				id: "wg0:SITE",
				interfaceName: "wg0",
				type: "site-to-site",
				name: "Floppy Home",
				allowedIps: ["10.10.0.2/32", "192.168.60.0/24"],
				importedNetworks: ["192.168.60.0/24"],
				exportedNetworks: [],
			},
			// Road warrior without importedNetworks (inferred client, untyped in metadata).
			{
				id: "wg0:LAPPI",
				interfaceName: "wg0",
				type: "client",
				name: "",
				allowedIps: ["10.10.0.4/32"],
				importedNetworks: [],
				exportedNetworks: [],
			},
			// Full-tunnel phone.
			{
				id: "wg0:PHONE",
				interfaceName: "wg0",
				type: "client",
				name: "Phone",
				allowedIps: ["10.10.0.5/32"],
				importedNetworks: [],
				fullTunnel: true,
			},
		],
	};
	const own = ["192.168.60.0/24"];
	const rule = (over = {}) => ({
		id: 1,
		enabled: true,
		sources: ["10.10.0.1/32"],
		destinations: [],
		ports: [],
		...over,
	});

	it("reports a road warrior without importedNetworks", () => {
		const clients = vpnClientsFromStatus(status);
		const lappi = clients.find((c) => c.id === "wg0:LAPPI");
		assert.ok(lappi, "untyped/road-warrior client is included");
		assert.deepEqual(lappi.hosts, ["10.10.0.4/32"]);
		assert.ok(lappi.nets.includes("192.168.60.0/24"), "reach = every site net the hub serves on wg0");
		const gaps = clientIngressGaps(clients, own, [rule()]);
		assert.ok(gaps.some((g) => g.suggestion.sources[0] === "10.10.0.4/32" && g.host === "192.168.60.0/24"));
	});

	it("reports a full-tunnel client", () => {
		const clients = vpnClientsFromStatus(status);
		const phone = clients.find((c) => c.id === "wg0:PHONE");
		assert.deepEqual(phone.nets, ["0.0.0.0/0"]);
		const gaps = clientIngressGaps(clients, own, [rule()]);
		assert.ok(gaps.some((g) => g.suggestion.sources[0] === "10.10.0.5/32" && g.host === "192.168.60.0/24"));
		// a rule for the client covers it
		const covered = clientIngressGaps([phone], own, [rule({ sources: ["10.10.0.5/32"] })]);
		assert.equal(covered.length, 0);
	});

	it("never lists site links as clients", () => {
		assert.ok(!vpnClientsFromStatus(status).some((c) => c.id === "wg0:SITE"));
	});
});
