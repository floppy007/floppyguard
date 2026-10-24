// Round-5 review fixes: bound-agent cascade in deletePeer/deleteInterface,
// network prefix guard (< /8), CIDR-overlap conflict checks (updatePeer type
// change, createPeer, metadata), broad hub-source Freigaben, stable binding of
// generated link names, imported rules armed_on, nginx conf lock coverage.
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

const wg = await import("./wireguard.js");
const {
	_assertBoundAgentCascade,
	_buildPeerUpdates,
	_deleteBoundAgents,
	_planBoundAgentCascade,
	checkAllowedIPsConflicts,
	findLinkNetworkConflicts,
	sanitizeNetworkArray,
} = wg;
const ingress = await import("./agent-ingress.js");
const { broadHubRules, upstreamSuggestion, agentSiteLink, boundLinkMissingHint, resolveBoundStatusLink } = ingress;
const { default: internalAgent } = await import("./agent.js");

// ─── fake WireGuard environment (no real wg/ip, temp conf + metadata) ────────

async function withFakeWg({ conf = {}, metadata, dump }, fn) {
	const root = await mkdtemp(path.join(os.tmpdir(), "fg-r5-"));
	const confDir = path.join(root, "conf");
	const binDir = path.join(root, "bin");
	const metadataFile = path.join(root, "meta.json");
	const wgLog = path.join(root, "wg.log");
	await mkdir(confDir, { recursive: true });
	await mkdir(binDir, { recursive: true });
	for (const [name, text] of Object.entries(conf)) await writeFile(path.join(confDir, `${name}.conf`), text);
	await writeFile(metadataFile, `${JSON.stringify(metadata)}\n`);
	const wgBin = path.join(binDir, "wg");
	await writeFile(
		wgBin,
		`#!/usr/bin/env bash
echo "$*" >> '${wgLog}'
case "$1" in
  show) printf '%b' '${dump.replace(/\n/g, "\\n").replace(/\t/g, "\\t")}' ;;
  genkey) echo "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=" ;;
  pubkey) echo "bmV3cHVia2V5bmV3cHVia2V5bmV3cHVia2V5MTIzNDU=" ;;
esac
`,
	);
	await chmod(wgBin, 0o755);
	const ipBin = path.join(binDir, "ip");
	await writeFile(ipBin, "#!/usr/bin/env bash\nexit 0\n");
	await chmod(ipBin, 0o755);
	const prev = {
		WG_CONF_DIR: process.env.WG_CONF_DIR,
		WG_BIN: process.env.WG_BIN,
		IP_BIN: process.env.IP_BIN,
		WG_METADATA_FILE: process.env.WG_METADATA_FILE,
	};
	Object.assign(process.env, { WG_CONF_DIR: confDir, WG_BIN: wgBin, IP_BIN: ipBin, WG_METADATA_FILE: metadataFile });
	// Never touch the agent table from a unit test: the fleet resync after a
	// delete is stubbed (the bound-agent lookup is injected per test).
	const origSync = internalAgent.syncAgentConfigs;
	internalAgent.syncAgentConfigs = async () => [];
	try {
		const mod = await import(`./wireguard.js?r5=${Date.now()}-${Math.random()}`);
		const log = async () => {
			try {
				return await readFile(wgLog, "utf8");
			} catch {
				return "";
			}
		};
		return await fn({ mod, confDir, metadataFile, log });
	} finally {
		internalAgent.syncAgentConfigs = origSync;
		for (const [k, v] of Object.entries(prev)) {
			if (v === undefined) delete process.env[k];
			else process.env[k] = v;
		}
		await rm(root, { recursive: true, force: true });
	}
}

const HUB_CONF =
	"[Interface]\nAddress = 10.10.0.1/24\nListenPort = 51820\nPrivateKey = hub-priv\n\n" +
	"[Peer]\nPublicKey = site-pk\nAllowedIPs = 10.10.0.5/32, 192.168.77.0/24\n\n" +
	"[Peer]\nPublicKey = phone-pk\nAllowedIPs = 10.10.0.6/32\n";
const HUB_DUMP =
	"wg0\thub-priv\thub-pub\t51820\toff\n" +
	"wg0\tsite-pk\t(none)\t1.2.3.4:51820\t10.10.0.5/32,192.168.77.0/24\t4102444800\t10\t20\t0\n" +
	"wg0\tphone-pk\t(none)\t(none)\t10.10.0.6/32\t0\t0\t0\t0\n";
const META = () => ({
	interfaces: {},
	links: {
		"wg0:site-pk": { name: "site-x", type: "site-to-site", importedNetworks: ["192.168.77.0/24"] },
		"wg0:phone-pk": { name: "phone", type: "client", importedNetworks: ["192.168.0.0/16"] },
	},
});

/** Fake agent module: deleteBlocker per id, delete() calls recorded. */
function fakeAgents(rows, blockers = {}, events = []) {
	return {
		loadAgents: async (names) => rows.filter((r) => names.includes(r.wg_link_name)),
		agentApi: {
			deleteBlocker: async (row, { force }) => (force ? null : (blockers[row.id] ?? null)),
			delete: async (id, opts) => {
				events.push(["agent-delete", id, Boolean(opts?.force)]);
				return true;
			},
		},
	};
}

// ─── cascade helpers ─────────────────────────────────────────────────────────

describe("bound-agent cascade helpers", () => {
	const rows = [
		{ id: 1, name: "gw-a", wg_link_name: "L" },
		{ id: 2, name: "gw-b", wg_link_name: "L" },
	];
	it("refuses without deleteBoundAgents and names the agents", async () => {
		const deps = fakeAgents(rows);
		const plan = await _planBoundAgentCascade(["L"], [], deps);
		assert.equal(plan.length, 2);
		assert.throws(
			() => _assertBoundAgentCascade(plan, false),
			(err) => err.status === 409 && /gw-a/.test(err.message) && /gw-b/.test(err.message),
		);
		assert.doesNotThrow(() => _assertBoundAgentCascade([], false));
	});
	it("refuses the whole cascade when ANY bound agent refuses (checked before anything is deleted)", async () => {
		const deps = fakeAgents(rows, { 2: { reason: "Agent filtert noch", forceable: false } });
		const plan = await _planBoundAgentCascade(["L"], [], deps);
		assert.throws(
			() => _assertBoundAgentCascade(plan, true),
			(err) => err.status === 409 && /Nichts gelöscht/.test(err.message) && /gw-b/.test(err.message),
		);
	});
	it("a confirmed force id clears the blocker of that agent", async () => {
		const deps = fakeAgents(rows, { 2: { reason: "x", forceable: true } });
		const plan = await _planBoundAgentCascade(["L"], [2], deps);
		assert.doesNotThrow(() => _assertBoundAgentCascade(plan, true));
		assert.equal(plan.find((p) => p.id === 2).force, true);
	});
	it("deletes the planned agents, treats Not Found as done and collects other errors", async () => {
		const seen = [];
		const agentApi = {
			delete: async (id, { force }) => {
				seen.push([id, force]);
				if (id === 2) throw new Error("Not Found - 2");
				if (id === 3) throw new Error("db down");
				return true;
			},
		};
		const res = await _deleteBoundAgents(
			[
				{ id: 1, name: "a", force: false },
				{ id: 2, name: "b", force: true },
				{ id: 3, name: "c", force: false },
			],
			{ agentApi },
		);
		assert.deepEqual(seen, [
			[1, false],
			[2, true],
			[3, false],
		]);
		assert.deepEqual(res.deleted, [1, 2]);
		assert.deepEqual(res.errors, [{ id: 3, name: "c", error: "db down" }]);
	});
});

describe("internalAgent.deleteBlocker", () => {
	const now = 2_000_000_000;
	it("blocks a restricted agent; forceable only when offline for an hour", async () => {
		const online = { id: 1, ingress_mode: "restricted", last_seen: now - 60 };
		const gone = { id: 2, ingress_mode: "restricted", last_seen: now - 7200 };
		const b1 = await internalAgent.deleteBlocker(online, { nowS: now });
		assert.match(b1.reason, /offen/);
		assert.equal(b1.forceable, false);
		const b2 = await internalAgent.deleteBlocker(gone, { nowS: now });
		assert.equal(b2.forceable, true);
		assert.equal(await internalAgent.deleteBlocker(gone, { force: true, nowS: now }), null);
		const f1 = await internalAgent.deleteBlocker(online, { force: true, nowS: now });
		assert.match(f1.reason, /nicht gemeldet/);
		assert.equal(f1.forceable, false);
	});
});

// ─── deletePeer / deleteInterface with bound agents ──────────────────────────

describe("deletePeer with bound agents", () => {
	const rows = [{ id: 7, name: "gw-x", wg_link_name: "site-x" }];

	it("refuses (409) while an agent is bound and changes nothing", async () => {
		await withFakeWg(
			{ conf: { wg0: HUB_CONF }, metadata: META(), dump: HUB_DUMP },
			async ({ mod, confDir, metadataFile, log }) => {
				const events = [];
				mod._setBoundAgentCascadeDepsForTests(fakeAgents(rows, {}, events));
				await assert.rejects(
					mod.default.deletePeer("wg0:site-pk"),
					(err) => err.status === 409 && /gw-x/.test(err.message),
				);
				assert.equal(await readFile(path.join(confDir, "wg0.conf"), "utf8"), HUB_CONF);
				assert.ok(JSON.parse(await readFile(metadataFile, "utf8")).links["wg0:site-pk"]);
				assert.ok(!/peer site-pk remove/.test(await log()));
				assert.deepEqual(events, []);
			},
		);
	});

	it("dryRun reports the bound agents and their state without changing anything", async () => {
		await withFakeWg({ conf: { wg0: HUB_CONF }, metadata: META(), dump: HUB_DUMP }, async ({ mod, confDir }) => {
			mod._setBoundAgentCascadeDepsForTests(fakeAgents(rows, { 7: { reason: "Filter aktiv", forceable: true } }));
			const res = await mod.default.deletePeer("wg0:site-pk", { dryRun: true });
			assert.deepEqual(res.agents, [
				{ id: 7, name: "gw-x", linkName: "site-x", blocked: "Filter aktiv", forceable: true },
			]);
			assert.equal(await readFile(path.join(confDir, "wg0.conf"), "utf8"), HUB_CONF);
		});
	});

	it("a refusing agent stops the cascade before the peer is touched", async () => {
		await withFakeWg(
			{ conf: { wg0: HUB_CONF }, metadata: META(), dump: HUB_DUMP },
			async ({ mod, confDir, log }) => {
				const events = [];
				mod._setBoundAgentCascadeDepsForTests(
					fakeAgents(rows, { 7: { reason: "Filter aktiv", forceable: false } }, events),
				);
				await assert.rejects(
					mod.default.deletePeer("wg0:site-pk", { deleteBoundAgents: true }),
					/Nichts gelöscht/,
				);
				assert.equal(await readFile(path.join(confDir, "wg0.conf"), "utf8"), HUB_CONF);
				assert.ok(!/peer site-pk remove/.test(await log()));
				assert.deepEqual(events, []);
			},
		);
	});

	it("cascade: peer removed first, the agent deleted only afterwards", async () => {
		await withFakeWg(
			{ conf: { wg0: HUB_CONF }, metadata: META(), dump: HUB_DUMP },
			async ({ mod, confDir, metadataFile, log }) => {
				const events = [];
				const deps = fakeAgents(rows, {}, events);
				const origDelete = deps.agentApi.delete;
				deps.agentApi.delete = async (id, opts) => {
					// At this point the peer must already be gone from conf, live and metadata.
					assert.ok(!(await readFile(path.join(confDir, "wg0.conf"), "utf8")).includes("site-pk"));
					assert.match(await log(), /set wg0 peer site-pk remove/);
					assert.ok(!JSON.parse(await readFile(metadataFile, "utf8")).links["wg0:site-pk"]);
					return origDelete(id, opts);
				};
				mod._setBoundAgentCascadeDepsForTests(deps);
				const res = await mod.default.deletePeer("wg0:site-pk", { deleteBoundAgents: true });
				assert.equal(res.deleted, true);
				assert.deepEqual(res.agents.deleted, [7]);
				assert.deepEqual(events, [["agent-delete", 7, false]]);
			},
		);
	});

	it("a peer without bound agents is deleted as before", async () => {
		await withFakeWg({ conf: { wg0: HUB_CONF }, metadata: META(), dump: HUB_DUMP }, async ({ mod, confDir }) => {
			mod._setBoundAgentCascadeDepsForTests(fakeAgents([]));
			const res = await mod.default.deletePeer("wg0:phone-pk");
			assert.equal(res.deleted, true);
			assert.ok(!(await readFile(path.join(confDir, "wg0.conf"), "utf8")).includes("phone-pk"));
		});
	});
});

describe("deleteInterface with bound agents", () => {
	const WG7 =
		"[Interface]\nAddress = 10.77.0.1/24\nListenPort = 51877\nPrivateKey = p7\n\n[Peer]\nPublicKey = s7-pk\nAllowedIPs = 10.77.0.2/32\n";
	const meta = () => ({ interfaces: {}, links: { "wg977:s7-pk": { name: "site-7", type: "site-to-site" } } });
	const rows = [{ id: 9, name: "gw-7", wg_link_name: "site-7" }];
	it("refuses while an agent of one of its links is bound and reports it on dryRun", async () => {
		await withFakeWg(
			{ conf: { wg0: HUB_CONF, wg977: WG7 }, metadata: meta(), dump: HUB_DUMP },
			async ({ mod, confDir }) => {
				mod._setBoundAgentCascadeDepsForTests(fakeAgents(rows));
				await assert.rejects(
					mod.default.deleteInterface("wg977"),
					(err) => err.status === 409 && /gw-7/.test(err.message),
				);
				const dry = await mod.default.deleteInterface("wg977", { dryRun: true });
				assert.deepEqual(
					dry.agents.map((a) => a.id),
					[9],
				);
				assert.equal(await readFile(path.join(confDir, "wg977.conf"), "utf8"), WG7);
			},
		);
	});
});

// ─── network prefix guard ────────────────────────────────────────────────────

describe("network lists reject prefixes shorter than /8", () => {
	it("rejects /0, /1 and /7, accepts /8 and longer", () => {
		for (const bad of ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/7"]) {
			assert.throws(() => sanitizeNetworkArray([bad]), /nicht erlaubt/, bad);
		}
		assert.deepEqual(sanitizeNetworkArray(["10.0.0.0/8", "192.168.1.5/24"]), ["10.0.0.0/8", "192.168.1.0/24"]);
	});
	it("_buildPeerUpdates never puts a stored short prefix on the hub peer", () => {
		const peerMap = new Map([["PK", ["10.10.0.5/32", "192.168.5.0/24"]]]);
		const updates = _buildPeerUpdates(
			peerMap,
			{ "wg0:PK": { type: "site-to-site", importedNetworks: ["0.0.0.0/1", "128.0.0.0/1", "192.168.5.0/24"] } },
			"wg0",
		);
		assert.ok(!updates.has("PK"), "only the /24 survives — unchanged");
		const u2 = _buildPeerUpdates(peerMap, { "wg0:PK": { importedNetworks: ["0.0.0.0/0"] } }, "wg0");
		assert.deepEqual(u2.get("PK"), ["10.10.0.5/32"]);
	});
	it("createPeer and updatePeer reject a split default route before any change", async () => {
		await withFakeWg(
			{ conf: { wg0: HUB_CONF }, metadata: META(), dump: HUB_DUMP },
			async ({ mod, confDir, metadataFile }) => {
				await assert.rejects(
					mod.default.createPeer({
						name: "evil",
						type: "site-to-site",
						importedNetworks: ["0.0.0.0/1", "128.0.0.0/1"],
					}),
					/nicht erlaubt/,
				);
				await assert.rejects(
					mod.default.updatePeer("wg0:site-pk", { importedNetworks: ["0.0.0.0/1"] }),
					/nicht erlaubt/,
				);
				assert.equal(await readFile(path.join(confDir, "wg0.conf"), "utf8"), HUB_CONF);
				assert.deepEqual(JSON.parse(await readFile(metadataFile, "utf8")), META());
			},
		);
	});
});

// ─── CIDR-overlap conflict checks ────────────────────────────────────────────

describe("site network conflicts by CIDR overlap", () => {
	it("checkAllowedIPsConflicts finds supernets and subnets, not only equal strings", () => {
		const links = [{ name: "B", allowedIps: ["10.10.0.5/32", "192.168.20.0/24"] }];
		assert.equal(checkAllowedIPsConflicts(["192.168.0.0/16"], links).length, 1);
		assert.equal(checkAllowedIPsConflicts(["192.168.20.128/25"], links).length, 1);
		assert.equal(checkAllowedIPsConflicts(["192.168.20.0/24"], links).length, 1);
		assert.equal(checkAllowedIPsConflicts(["192.168.21.0/24"], links).length, 0);
	});
	it("findLinkNetworkConflicts skips clients and only reports pairs with a changed link", () => {
		const links = {
			a: { name: "A", type: "site-to-site", importedNetworks: ["10.4.0.0/16"] },
			b: { name: "B", importedNetworks: ["10.4.20.0/24"] },
			c: { name: "C", type: "client", importedNetworks: ["10.0.0.0/8"] },
			d: { name: "D", type: "site-to-site", importedNetworks: ["192.168.1.0/24"] },
		};
		assert.equal(findLinkNetworkConflicts(links).length, 1);
		assert.equal(findLinkNetworkConflicts(links, ["d"]).length, 0);
		assert.match(findLinkNetworkConflicts(links, ["b"])[0], /overlaps/);
	});
	it("updatePeer: retyping a client whose reach list covers another site's subnet throws", async () => {
		await withFakeWg(
			{ conf: { wg0: HUB_CONF }, metadata: META(), dump: HUB_DUMP },
			async ({ mod, confDir, metadataFile }) => {
				await assert.rejects(
					mod.default.updatePeer("wg0:phone-pk", { type: "site-to-site" }),
					(e) => e.public === true && e.status === 409 && /AllowedIPs conflict/.test(e.message),
				);
				// a site whose new networks overlap another site's subnet throws too
				await assert.rejects(
					mod.default.updatePeer("wg0:phone-pk", {
						type: "site-to-site",
						importedNetworks: ["192.168.77.128/25"],
					}),
					/AllowedIPs conflict/,
				);
				assert.equal(await readFile(path.join(confDir, "wg0.conf"), "utf8"), HUB_CONF);
				assert.deepEqual(JSON.parse(await readFile(metadataFile, "utf8")), META());
			},
		);
	});
	it("updatePeer rejects an invalid type/platform instead of silently clearing the stored one", async () => {
		await withFakeWg(
			{ conf: { wg0: HUB_CONF }, metadata: META(), dump: HUB_DUMP },
			async ({ mod, metadataFile }) => {
				await assert.rejects(
					mod.default.updatePeer("wg0:phone-pk", { type: "clients" }),
					(e) => e.public === true && e.status === 400 && /Invalid type/.test(e.message),
				);
				await assert.rejects(
					mod.default.updatePeer("wg0:phone-pk", { platform: "tablet" }),
					(e) => e.public === true && e.status === 400 && /Invalid platform/.test(e.message),
				);
				const stored = JSON.parse(await readFile(metadataFile, "utf8"));
				assert.equal(stored.links["wg0:phone-pk"].type, "client");
			},
		);
	});
	it("createPeer: a new site overlapping an existing site's subnet throws", async () => {
		await withFakeWg({ conf: { wg0: HUB_CONF }, metadata: META(), dump: HUB_DUMP }, async ({ mod, confDir }) => {
			await assert.rejects(
				mod.default.createPeer({ name: "s2", type: "site-to-site", importedNetworks: ["192.168.0.0/16"] }),
				(e) => e.public === true && e.status === 409 && /AllowedIPs conflict/.test(e.message),
			);
			assert.equal(await readFile(path.join(confDir, "wg0.conf"), "utf8"), HUB_CONF);
		});
	});
	it("createInterface: an invalid address is a public 400, not an Internal Error", async () => {
		await withFakeWg({ conf: { wg0: HUB_CONF }, metadata: META(), dump: HUB_DUMP }, async ({ mod }) => {
			await assert.rejects(
				mod.default.createInterface({ address: "10.20.0.1" }),
				(e) => e.public === true && e.status === 400 && /Invalid address/.test(e.message),
			);
		});
	});
});

// ─── Freigaben check: broad hub rules, port-less upstreams ───────────────────

describe("Freigaben check: hub-source rules", () => {
	const rule = (id, extra) => ({
		id,
		name: `r${id}`,
		enabled: true,
		sources: ["10.10.0.1/32"],
		destinations: [],
		ports: [],
		...extra,
	});
	const behind = [{ host: "10.3.10.26", port: 10100, proto: "tcp" }];
	it("flags hub-source rules without ports and with ports no upstream uses", () => {
		const out = broadHubRules(
			[
				rule(1, { destinations: ["10.3.10.26/32"] }),
				rule(2, { destinations: ["10.3.10.26/32"], ports: [{ proto: "tcp", port: "10100" }] }),
				rule(3, {
					destinations: ["10.3.10.26/32"],
					ports: [
						{ proto: "tcp", port: "22" },
						{ proto: "tcp", port: "10000:10200" },
					],
				}),
				rule(4, { sources: ["192.168.11.0/24"] }), // not hub-sourced
				rule(5, { enabled: false }),
			],
			["10.10.0.1/32"],
			behind,
		);
		assert.deepEqual(out, [
			{ id: 1, name: "r1", reason: "all-ports", ports: [] },
			{ id: 3, name: "r3", reason: "unused-ports", ports: ["22/tcp"] },
		]);
	});
	it("no one-click suggestion without a known hub source (unreadable wg conf)", () => {
		assert.equal(
			upstreamSuggestion({ kind: "proxy-host", label: "x", host: "10.3.10.5", port: 443, proto: "tcp" }, []),
			null,
		);
	});
	it("no one-click suggestion for an upstream without a known port", () => {
		assert.equal(
			upstreamSuggestion({ kind: "manual", label: "x", host: "10.3.10.5", port: null, proto: "tcp" }, [
				"10.10.0.1/32",
			]),
			null,
		);
	});
});

describe("Freigaben check: binding to a generated link name", () => {
	const links = [
		{
			id: "wg0:ABCDEFGHxyz",
			name: "hub-link-ABCDEFGH",
			type: "hub-link",
			typeExplicit: false,
			peerPublicKey: "ABCDEFGHxyz",
			importedNetworks: ["192.168.5.0/24", "192.168.6.0/24"],
		},
		{
			id: "wg0:QQQQQQQQxyz",
			name: "Office",
			type: "client",
			typeExplicit: true,
			peerPublicKey: "QQQQQQQQxyz",
			importedNetworks: ["10.9.0.0/24"],
		},
	];
	it("still finds the link when its inferred type (and so its generated name) changed", () => {
		assert.equal(resolveBoundStatusLink("client-ABCDEFGH", links)?.id, "wg0:ABCDEFGHxyz");
		assert.deepEqual(agentSiteLink("client-ABCDEFGH", { statusLinks: links }), [
			"wg0:ABCDEFGHxyz",
			["192.168.5.0/24", "192.168.6.0/24"],
		]);
		// a real (stored) name never matches by key prefix
		assert.equal(resolveBoundStatusLink("client-QQQQQQQQ", links), null);
	});
	it("reports a link typed as client instead of 'not found'", () => {
		assert.deepEqual(boundLinkMissingHint("Office", links), {
			reason: "typed-client",
			link_id: "wg0:QQQQQQQQxyz",
			link_name: "Office",
		});
		assert.deepEqual(boundLinkMissingHint("gone", links), { reason: "not-found" });
	});
});

// ─── nginx: every conf mutation runs under the config lock ───────────────────

describe("nginx conf lock coverage", () => {
	it("deleteConfig waits for a running configure() of the same host", async () => {
		const { default: internalNginx, _testExports } = await import("./nginx.js");
		const order = [];
		let release;
		const gate = new Promise((r) => {
			release = r;
		});
		const holder = _testExports.withConfigLock(async () => {
			order.push("configure-start");
			await gate;
			order.push("configure-end");
		});
		const fs = await import("node:fs");
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fg-r5-nginx-"));
		const origName = internalNginx.getConfigName;
		internalNginx.getConfigName = (_t, id) => path.join(dir, `${id}.conf`);
		try {
			fs.writeFileSync(path.join(dir, "5.conf"), "server {}\n");
			const del = internalNginx.deleteConfig("proxy_host", { id: 5 }).then(() => order.push("delete"));
			await new Promise((r) => setTimeout(r, 20));
			assert.ok(fs.existsSync(path.join(dir, "5.conf")), "delete must wait for the lock");
			release();
			await Promise.all([holder, del]);
			assert.deepEqual(order, ["configure-start", "configure-end", "delete"]);
			assert.ok(!fs.existsSync(path.join(dir, "5.conf")));
		} finally {
			internalNginx.getConfigName = origName;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
	it("backupConfig picks up a conf stashed as <conf>.disabled", async () => {
		const { default: internalNginx } = await import("./nginx.js");
		const fs = await import("node:fs");
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fg-r5-nginx-"));
		const origName = internalNginx.getConfigName;
		internalNginx.getConfigName = (_t, id) => path.join(dir, `${id}.conf`);
		try {
			fs.writeFileSync(path.join(dir, "6.conf"), "server { stashed }\n");
			assert.equal(await internalNginx.stashConfig("proxy_host", { id: 6 }), true);
			assert.ok(fs.existsSync(path.join(dir, "6.conf.disabled")));
			assert.equal(await internalNginx.backupConfig("proxy_host", { id: 6 }), true);
			assert.equal(fs.readFileSync(path.join(dir, "6.conf.bak"), "utf8"), "server { stashed }\n");
			assert.ok(!fs.existsSync(path.join(dir, "6.conf.disabled")));
			assert.equal(await internalNginx.backupConfig("proxy_host", { id: 99 }), false);
		} finally {
			internalNginx.getConfigName = origName;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

// ─── create() checks the caps under the agent row lock ───────────────────────

describe("ingress create", () => {
	it("locks the agent row before re-reading rules and inserting (armed_on set)", async () => {
		const { default: AgentIngressRule } = await import("../models/agent_ingress_rule.js");
		const { default: Agent } = await import("../models/agent.js");
		const calls = [];
		const inserted = [];
		const origRule = { query: AgentIngressRule.query, transaction: AgentIngressRule.transaction };
		const origAgent = Agent.query;
		const TRX = { trx: true };
		const agentRow = { id: 3, name: "gw", ingress_mode: "open", is_deleted: 0 };
		const chain = (kind, trx) => {
			const q = {
				where: () => q,
				forUpdate: () => {
					calls.push(`${kind}.forUpdate:${trx === TRX}`);
					return q;
				},
				orderBy: async () => {
					calls.push(`${kind}.loadRules:${trx === TRX}`);
					return [];
				},
				first: async () => agentRow,
				insertAndFetch: async (row) => {
					calls.push(`${kind}.insert:${trx === TRX}`);
					inserted.push(row);
					return { id: inserted.length, ...row };
				},
			};
			return q;
		};
		Agent.query = (trx) => chain("agent", trx);
		AgentIngressRule.query = (trx) => chain("rule", trx);
		AgentIngressRule.transaction = async (fn) => fn(TRX);
		try {
			const before = Math.floor(Date.now() / 1000);
			// access null = internal caller (no audit-log write)
			const rule = await ingress.default.create(null, 3, {
				name: "Psono",
				sources: ["10.10.0.1"],
				destinations: ["10.3.10.26"],
			});
			assert.equal(rule.name, "Psono");
			assert.deepEqual(calls, ["agent.forUpdate:true", "rule.loadRules:true", "rule.insert:true"]);
			assert.ok(Number.isInteger(inserted[0].armed_on) && inserted[0].armed_on >= before, "armed_on set");
		} finally {
			AgentIngressRule.query = origRule.query;
			AgentIngressRule.transaction = origRule.transaction;
			Agent.query = origAgent;
		}
	});
});

// ─── testFlow without a site link keeps the isolation notes ──────────────────

describe("ingress testFlow (link not found)", () => {
	it("reports site-isolation-partial / -unknown like the bound branch", async () => {
		const { default: AgentIngressRule } = await import("../models/agent_ingress_rule.js");
		const { default: Agent } = await import("../models/agent.js");
		const { default: siteIsolation } = await import("./site-isolation.js");
		const { default: wgInternal } = await import("./wireguard.js");
		const orig = {
			agent: Agent.query,
			rule: AgentIngressRule.query,
			verdict: siteIsolation.verdict,
			meta: wgInternal.readMetadataStore,
			status: wgInternal.getStatus,
		};
		const chain = (result) => {
			const q = { where: () => q, orderBy: async () => [], first: async () => result };
			return q;
		};
		Agent.query = () =>
			chain({ id: 3, name: "gw", ingress_mode: "open", is_deleted: 0, wg_link_name: "renamed", last_seen: null });
		AgentIngressRule.query = () => chain(null);
		wgInternal.readMetadataStore = async () => ({ links: {} });
		wgInternal.getStatus = async () => {
			throw new Error("wg down");
		};
		const body = { source: "10.4.0.5", destination: "10.3.10.5", port: 443, proto: "tcp" };
		try {
			siteIsolation.verdict = async () => ({ blocked: false, partial: true });
			const partial = await ingress.default.testFlow(3, body);
			assert.equal(partial.reason, "link-not-found");
			assert.ok(partial.notes.includes("site-isolation-partial"));
			assert.ok(!partial.notes.includes("site-isolation-unknown"));

			siteIsolation.verdict = async () => {
				throw new Error("db down");
			};
			const unknown = await ingress.default.testFlow(3, body);
			assert.equal(unknown.reason, "link-not-found");
			assert.ok(unknown.notes.includes("site-isolation-unknown"));
		} finally {
			Agent.query = orig.agent;
			AgentIngressRule.query = orig.rule;
			siteIsolation.verdict = orig.verdict;
			wgInternal.readMetadataStore = orig.meta;
			wgInternal.getStatus = orig.status;
		}
	});
});
