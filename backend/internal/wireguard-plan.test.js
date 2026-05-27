import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildApplyContract, buildPlanPreview, classifyChangeScope, normalizePatch } from "./wireguard-plan.js";

async function withPlanEnv(env, suffix, fn) {
	const previous = {
		WG_CONF_DIR: process.env.WG_CONF_DIR,
		WG_BIN: process.env.WG_BIN,
		IP_BIN: process.env.IP_BIN,
		WG_METADATA_FILE: process.env.WG_METADATA_FILE,
	};

	Object.assign(process.env, env);

	try {
		const imported = await import(`./wireguard-plan.js?case=${suffix}`);
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

test("normalizePatch sanitizes incoming preview metadata", () => {
	assert.deepEqual(
		normalizePatch({
			interfaces: {
				wg1: {
					role: "site-link",
					exportedNetworks: ["10.20.0.0/24", "10.20.0.0/24"],
				},
			},
			links: {
				"wg1:site-peer-key": {
					type: "site-link",
					notes: ["review", "review"],
				},
			},
		}),
		{
			interfaces: {
				wg1: {
					role: "site-to-site",
					exportedNetworks: ["10.20.0.0/24"],
				},
			},
			links: {
				"wg1:site-peer-key": {
					type: "site-to-site",
					notes: ["review"],
				},
			},
		},
	);
});

test("buildPlanPreview projects metadata changes into route-aware warnings and diffs", () => {
	const status = {
		available: true,
		mode: "metadata-write",
		metadata: {
			interfaces: {
				wg1: {
					role: "site-to-site",
					managementMode: "imported",
					exportedNetworks: ["10.20.0.0/24"],
				},
			},
			links: {
				"wg1:site-peer-key": {
					type: "site-to-site",
					name: "site-a",
					importedNetworks: ["192.168.200.0/24"],
					exportedNetworks: ["10.20.0.0/24"],
					returnPathMode: "unknown",
					remoteManagementMode: "unknown",
					planIntent: "site-to-site",
				},
			},
		},
		interfaces: [
			{
				name: "wg1",
				active: false,
				configExists: true,
				privateKeyPresent: true,
				peerCount: 1,
				activePeerCount: 0,
				rxBytes: 1,
				txBytes: 2,
				peerNetworks: ["192.168.200.0/24"],
				role: "site-to-site",
				managementMode: "imported",
				importedNetworks: ["192.168.200.0/24"],
				exportedNetworks: ["10.20.0.0/24"],
				routeTargets: ["192.168.200.0/24"],
				notes: [],
			},
		],
		links: [
			{
				id: "wg1:site-peer-key",
				interfaceName: "wg1",
				type: "site-to-site",
				name: "site-a",
				peerPublicKey: "site-peer-key",
				remoteEndpoint: "site.example.com:51820",
				allowedIps: ["192.168.200.0/24"],
				tunnelAddresses: [],
				exportedNetworks: ["10.20.0.0/24"],
				importedNetworks: ["192.168.200.0/24"],
				latestHandshake: 0,
				rxBytes: 1,
				txBytes: 2,
				active: false,
				hasMetadata: true,
				returnPathMode: "unknown",
				remoteManagementMode: "unknown",
				planIntent: "site-to-site",
				planState: null,
				notes: [],
				warnings: [],
				nextActions: [],
			},
		],
		routes: {
			all: [],
			wireguard: [],
			privateRoutes: [],
		},
	};

	const preview = buildPlanPreview(status, {
		interfaces: {
			wg1: {
				exportedNetworks: ["10.30.0.0/24"],
				notes: ["staged update"],
			},
		},
		links: {
			"wg1:site-peer-key": {
				exportedNetworks: ["10.30.0.0/24"],
				returnPathMode: "static-route",
				remoteManagementMode: "ssh",
				planState: "validate",
				notes: ["ready for review"],
			},
		},
	});

	assert.equal(preview.valid, true);
	assert.equal(preview.appliesLiveConfig, false);
	assert.equal(preview.apply.canApply, true);
	assert.equal(preview.apply.requiresBackup, true);
	assert.equal(preview.apply.changeScope, "metadata-with-config-intent");
	assert.equal(preview.apply.blockedBy.length, 0);
	assert.equal(preview.diff.interfaces[0]?.changedFields.includes("exportedNetworks"), true);
	assert.equal(preview.diff.links[0]?.changedFields.includes("returnPathMode"), true);
	assert.match(preview.warnings.join(" "), /live WireGuard config is unchanged/);
	assert.equal(preview.projected.summary.siteLinkCount, 1);
	assert.deepEqual(preview.projected.topology.siteLinks, ["wg1:site-peer-key"]);

	const link = preview.projected.links[0];
	assert.equal(link.returnPathMode, "static-route");
	assert.equal(link.remoteManagementMode, "ssh");
	assert.equal(link.planState, "validate");
	assert.equal(link.warnings.includes("return-path-mode-undefined"), false);
	assert.equal(link.nextActions.includes("define-remote-management-mode"), false);

	const iface = preview.projected.interfaces[0];
	assert.equal(iface.exportedNetworks[0], "10.30.0.0/24");
	assert.equal(iface.notes.includes("staged update"), true);
});

test("classifyChangeScope distinguishes no-op, metadata-only and config-intent changes", () => {
	assert.equal(classifyChangeScope({ interfaces: [], links: [] }), "none");
	assert.equal(classifyChangeScope({ interfaces: [{ changedFields: ["notes"] }], links: [] }), "metadata-only");
	assert.equal(
		classifyChangeScope({ interfaces: [], links: [{ changedFields: ["exportedNetworks"] }] }),
		"metadata-with-config-intent",
	);
});

test("buildApplyContract exposes blockers and backup requirements", () => {
	const apply = buildApplyContract({
		errors: [],
		warnings: ["Imported networks exist without matching live WireGuard route entries"],
		nextActions: ["fix-return-path"],
		normalizedPatch: {
			interfaces: {},
			links: {
				"wg1:site-peer-key": {
					returnPathMode: "static-route",
				},
			},
		},
		diff: {
			interfaces: [],
			links: [
				{
					id: "wg1:site-peer-key",
					kind: "link",
					changedFields: ["returnPathMode"],
					before: { returnPathMode: "unknown" },
					after: { returnPathMode: "static-route" },
				},
			],
		},
	});

	assert.equal(apply.canApply, true);
	assert.equal(apply.requiresBackup, true);
	assert.equal(apply.changeScope, "metadata-with-config-intent");
	assert.deepEqual(apply.blockedBy, []);
	assert.equal(apply.recommendedSteps.includes("create-backup-before-apply"), true);
	assert.equal(apply.recommendedSteps.includes("implement-write-layer-before-apply"), true);
});

test("buildPlanPreview marks unknown targets as invalid preview errors", () => {
	const preview = buildPlanPreview(
		{
			available: true,
			mode: "metadata-write",
			metadata: { interfaces: {}, links: {} },
			interfaces: [],
			links: [],
			routes: { all: [], wireguard: [], privateRoutes: [] },
		},
		{
			interfaces: { wg99: { role: "site-to-site" } },
			links: { "wg99:peer": { type: "client" } },
		},
	);

	assert.equal(preview.valid, false);
	assert.deepEqual(preview.errors, ['Unknown interface "wg99"', 'Unknown link "wg99:peer"']);
	assert.equal(preview.apply.canApply, false);
	assert.equal(preview.apply.blockedBy.includes('error:Unknown interface "wg99"'), true);
	assert.equal(preview.nextActions.includes("resolve-preview-errors"), true);
});

test("applyMetadata writes metadata-only changes and creates a backup", async () => {
	const tempRoot = await mkdtemp(path.join(os.tmpdir(), "wg-plan-apply-"));
	const confDir = path.join(tempRoot, "conf");
	const metadataFile = path.join(tempRoot, "wireguard-metadata.json");
	await mkdir(confDir, { recursive: true });
	await writeFile(
		path.join(confDir, "wg1.conf"),
		`[Interface]
Address = 10.1.0.1/24
PrivateKey = test-private-key
`,
		"utf8",
	);
	await writeFile(
		metadataFile,
		`${JSON.stringify(
			{
				interfaces: {
					wg1: {
						notes: ["old note"],
					},
				},
				links: {},
			},
			null,
			2,
		)}\n`,
		"utf8",
	);

	await withPlanEnv(
		{
			WG_CONF_DIR: confDir,
			WG_BIN: "/bin/false",
			IP_BIN: "/bin/false",
			WG_METADATA_FILE: metadataFile,
		},
		`apply-${Date.now()}`,
		async (planModule) => {
			const result = await planModule.default.applyMetadata({
				interfaces: {
					wg1: {
						notes: ["new note"],
					},
				},
			});

			assert.equal(result.applied, true);
			assert.match(result.backupPath, /\.bak$/);
			assert.equal(result.auditEntry.changeScope, "metadata-only");
			assert.deepEqual(result.auditEntry.patchSummary.interfaceTargets, ["wg1"]);
			const saved = JSON.parse(await readFile(metadataFile, "utf8"));
			assert.deepEqual(saved.interfaces.wg1.notes, ["new note"]);
			const backup = JSON.parse(await readFile(result.backupPath, "utf8"));
			assert.deepEqual(backup.interfaces.wg1.notes, ["old note"]);
			const state = await planModule.default.getApplyState();
			assert.equal(state.backups.length, 1);
			assert.equal(state.lastApply?.backupPath, result.backupPath);
			assert.equal(state.recentApplies.length, 1);
		},
	);
});

test("buildPlanPreview rejects duplicate subnet claims between non-client peers", () => {
	const status = {
		available: true,
		mode: "metadata-write",
		metadata: {
			interfaces: {},
			links: {
				"wg0:peer-a": {
					type: "site-to-site",
					name: "Site-A",
					importedNetworks: ["192.168.10.0/24"],
				},
				"wg0:peer-b": {
					type: "site-to-site",
					name: "Site-B",
					importedNetworks: ["192.168.20.0/24"],
				},
			},
		},
		interfaces: [{
			name: "wg0",
			active: true,
			configExists: true,
			privateKeyPresent: true,
			peerCount: 2,
			activePeerCount: 2,
			rxBytes: 0, txBytes: 0,
			peerNetworks: ["192.168.10.0/24", "192.168.20.0/24"],
			importedNetworks: ["192.168.10.0/24", "192.168.20.0/24"],
			exportedNetworks: [], routeTargets: [], notes: [],
		}],
		links: [
			{ id: "wg0:peer-a", interfaceName: "wg0", type: "site-to-site", name: "Site-A",
			  allowedIps: ["192.168.10.0/24"], tunnelAddresses: [], importedNetworks: ["192.168.10.0/24"],
			  exportedNetworks: [], active: true, hasMetadata: true, warnings: [], nextActions: [], notes: [] },
			{ id: "wg0:peer-b", interfaceName: "wg0", type: "site-to-site", name: "Site-B",
			  allowedIps: ["192.168.20.0/24"], tunnelAddresses: [], importedNetworks: ["192.168.20.0/24"],
			  exportedNetworks: [], active: true, hasMetadata: true, warnings: [], nextActions: [], notes: [] },
		],
		routes: { all: [], wireguard: [], privateRoutes: [] },
	};

	// No conflict: different subnets — preview is valid
	const ok = buildPlanPreview(status, {
		links: { "wg0:peer-a": { importedNetworks: ["192.168.10.0/24", "192.168.30.0/24"] } },
	});
	assert.equal(ok.valid, true, "non-conflicting subnets should be valid");

	// Conflict: peer-b tries to claim peer-a's subnet
	const bad = buildPlanPreview(status, {
		links: { "wg0:peer-b": { importedNetworks: ["192.168.20.0/24", "192.168.10.0/24"] } },
	});
	assert.equal(bad.valid, false, "conflicting subnets should be invalid");
	assert.ok(bad.errors.some((e) => e.includes("192.168.10.0/24")), "error should mention the conflicting subnet");
});

test("restoreMetadataBackup restores a known backup and records restore audit", async () => {
	const tempRoot = await mkdtemp(path.join(os.tmpdir(), "wg-plan-restore-"));
	const confDir = path.join(tempRoot, "conf");
	const metadataFile = path.join(tempRoot, "wireguard-metadata.json");
	await mkdir(confDir, { recursive: true });
	await writeFile(
		path.join(confDir, "wg1.conf"),
		`[Interface]
Address = 10.1.0.1/24
PrivateKey = test-private-key
`,
		"utf8",
	);
	await writeFile(
		metadataFile,
		`${JSON.stringify(
			{
				interfaces: {
					wg1: {
						notes: ["current note"],
					},
				},
				links: {},
			},
			null,
			2,
		)}\n`,
		"utf8",
	);
	const backupPath = `${metadataFile}.2026-04-19T23-00-00-000Z.bak`;
	await writeFile(
		backupPath,
		`${JSON.stringify(
			{
				interfaces: {
					wg1: {
						notes: ["restored note"],
					},
				},
				links: {},
			},
			null,
			2,
		)}\n`,
		"utf8",
	);

	await withPlanEnv(
		{
			WG_CONF_DIR: confDir,
			WG_BIN: "/bin/false",
			IP_BIN: "/bin/false",
			WG_METADATA_FILE: metadataFile,
		},
		`restore-${Date.now()}`,
		async (planModule) => {
			const result = await planModule.default.restoreMetadataBackup(backupPath);
			assert.equal(result.restored, true);
			assert.equal(result.restoredFrom, backupPath);
			assert.equal(result.auditEntry.action, "restore-backup");
			const saved = JSON.parse(await readFile(metadataFile, "utf8"));
			assert.deepEqual(saved.interfaces.wg1.notes, ["restored note"]);
			const state = await planModule.default.getApplyState();
			assert.equal(state.lastApply?.restoredFrom, backupPath);
		},
	);
});
