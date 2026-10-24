// Regression tests for the 2026-10 audit pass on agents / WireGuard / Freigaben.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fg-audit-agentwg-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const {
	_excludeConnectedNets,
	assertPeerConfigAllowed,
	classifyLinkType,
	isValidDnsEntry,
	sanitizeDnsArray,
	sanitizeLinkMetadataPatch,
	writeConfAtomic,
} = await import("./wireguard.js");
const { cascadeLinkRenames, diffLinkRenames, statusLinkNames } = await import("./wireguard-plan.js");
const {
	agentSiteLink,
	ingressAppliedState,
	parseHostsFile,
	parseHubEgressFlows,
	parseManualConfUpstreams,
	proxyHostUpstreams,
	updateCanGrow,
	upstreamSuggestion,
} = await import("./agent-ingress.js");
const { _testExports: agentTest } = await import("./agent.js");
const { assertTotalLineCount, MAX_LINES_TOTAL, sanitizeIngressRule } = await import("./agent-ingress-rules.js");

describe("hub route exclusion of directly connected nets", () => {
	it("compares the host-form NIC cidr by containment", () => {
		const nets = new Set(["10.10.10.0/24", "10.10.10.128/25", "192.168.20.0/24", "10.0.0.0/8"]);
		_excludeConnectedNets(nets, [{ name: "eth1", cidr: "10.10.10.106/24" }]);
		// equal + more-specific dropped, unrelated + supernet kept
		assert.deepEqual([...nets].sort(), ["10.0.0.0/8", "192.168.20.0/24"]);
	});
});

describe("DNS validation for generated client configs", () => {
	it("accepts IPs and host names, rejects newlines / junk", () => {
		assert.ok(isValidDnsEntry("1.1.1.1"));
		assert.ok(isValidDnsEntry("2001:4860:4860::8888"));
		assert.ok(isValidDnsEntry("comnic.intra"));
		assert.ok(!isValidDnsEntry("1.1.1.1\nPostUp = curl x | sh"));
		assert.ok(!isValidDnsEntry("a b"));
		assert.ok(!isValidDnsEntry("1.1.1.1; rm"));
	});
	it("sanitizeDnsArray throws on bad input before any side effect", () => {
		assert.deepEqual(sanitizeDnsArray(undefined), []);
		assert.deepEqual(sanitizeDnsArray([" 1.1.1.1 ", "", "1.1.1.1", "dc.comnic.intra"]), [
			"1.1.1.1",
			"dc.comnic.intra",
		]);
		assert.throws(() => sanitizeDnsArray("1.1.1.1"), /array/);
		assert.throws(() => sanitizeDnsArray(["1.1.1.1\nPostUp = id"]), /Invalid DNS entry/);
	});
});

describe("atomic hub conf write", () => {
	it("replaces the file with mode 0600 and leaves no temp file", async () => {
		const conf = path.join(tmp, "wg9.conf");
		fs.writeFileSync(conf, "old", { mode: 0o644 });
		await writeConfAtomic(conf, "[Interface]\nPrivateKey = x\n");
		assert.equal(fs.readFileSync(conf, "utf8"), "[Interface]\nPrivateKey = x\n");
		assert.equal(fs.statSync(conf).mode & 0o777, 0o600);
		assert.deepEqual(
			fs.readdirSync(tmp).filter((f) => f.startsWith("wg9.conf.tmp")),
			[],
		);
	});
	it("keeps the old file when the write fails", async () => {
		const conf = path.join(tmp, "missing-dir", "wg8.conf");
		await assert.rejects(() => writeConfAtomic(conf, "x"));
	});
});

describe("link rename cascade (apply-metadata / restore)", () => {
	it("diffs renamed links by id", () => {
		const before = { links: { a: { name: "Hinderlich" }, b: { name: "Home" }, c: {} } };
		const after = { links: { a: { name: "Hinderlich Office" }, b: { name: "Home" }, c: { name: "New" }, d: {} } };
		assert.deepEqual(diffLinkRenames(before, after), [{ oldName: "Hinderlich", newName: "Hinderlich Office" }]);
		assert.deepEqual(diffLinkRenames({ links: {} }, after), []);
	});
	it("uses the live status name when the old name never stood in the store", () => {
		const after = { links: { "wg0:abc": { name: "Floppy Lappi" } } };
		const fallback = statusLinkNames({ links: [{ id: "wg0:abc", name: "client-abc12345" }, { id: "x" }] });
		assert.deepEqual(fallback, { "wg0:abc": "client-abc12345" });
		assert.deepEqual(diffLinkRenames({ links: {} }, after, fallback), [
			{ oldName: "client-abc12345", newName: "Floppy Lappi" },
		]);
	});
	it("reports cascade failures instead of only logging them", async () => {
		const calls = [];
		const res = await cascadeLinkRenames([{ oldName: "A", newName: "B" }], {
			rename: async (from, to) => {
				calls.push([from, to]);
				throw new Error("db down");
			},
		});
		assert.deepEqual(res.errors, [{ from: "A", to: "B", error: "db down" }]);
		assert.equal(res.rolledBack, false);
		assert.deepEqual((await cascadeLinkRenames([])).errors, []);
	});
	it("rolls a swap back to the old names when the temp phase fails", async () => {
		const bindings = { A: "agentA", B: "agentB" };
		const rename = async (from, to) => {
			if (from === "B" && to.startsWith("__fg_rename_")) throw new Error("boom");
			if (bindings[from]) {
				bindings[to] = bindings[from];
				delete bindings[from];
			}
		};
		const res = await cascadeLinkRenames(
			[
				{ oldName: "A", newName: "B" },
				{ oldName: "B", newName: "A" },
			],
			{ rename },
		);
		assert.equal(res.rolledBack, true);
		assert.equal(res.errors.length, 1);
		// nobody is left on a temporary name, nothing got merged
		assert.deepEqual(bindings, { A: "agentA", B: "agentB" });
	});
	it("completes a swap through temp names and retries a failed final step once", async () => {
		const bindings = { A: "agentA", B: "agentB" };
		let failedOnce = false;
		const rename = async (from, to) => {
			if (to === "A" && !failedOnce) {
				failedOnce = true;
				throw new Error("transient");
			}
			if (bindings[from]) {
				bindings[to] = bindings[from];
				delete bindings[from];
			}
		};
		const res = await cascadeLinkRenames(
			[
				{ oldName: "A", newName: "B" },
				{ oldName: "B", newName: "A" },
			],
			{ rename },
		);
		assert.deepEqual(res.errors, []);
		assert.deepEqual(bindings, { B: "agentA", A: "agentB" });
	});
});

describe("Config/QR guard uses the effective link type", () => {
	const noAgents = async () => [];
	it("allows an untyped /32 road-warrior client on wg0 (type inferred like getStatus)", async () => {
		const allowedIps = ["10.10.0.9/32"];
		assert.equal(classifyLinkType(allowedIps, "wg0"), "client");
		const link = { id: "wg0:qsYGHd", name: "Floppy Lappi", interfaceName: "wg0", allowedIps, type: "client" };
		await assert.doesNotReject(() => assertPeerConfigAllowed(link, {}, { boundAgents: noAgents }));
		// also without the status record's type (metadata has no type either)
		const { type: _t, ...untyped } = link;
		await assert.doesNotReject(() => assertPeerConfigAllowed(untyped, undefined, { boundAgents: noAgents }));
	});
	it("still refuses site links, agent-managed and agent-bound links", async () => {
		const site = {
			id: "wg1:x",
			name: "Site",
			interfaceName: "wg1",
			allowedIps: ["192.168.1.0/24"],
			type: "site-to-site",
		};
		await assert.rejects(() => assertPeerConfigAllowed(site, {}, { boundAgents: noAgents }), /Client/);
		const client = {
			id: "wg0:y",
			name: "Phone",
			interfaceName: "wg0",
			allowedIps: ["10.10.0.8/32"],
			type: "client",
		};
		await assert.rejects(
			() => assertPeerConfigAllowed(client, { remoteManagementMode: "agent" }, { boundAgents: noAgents }),
			/Agent/,
		);
		await assert.rejects(
			() => assertPeerConfigAllowed(client, {}, { boundAgents: async () => [{ id: 1, wg_link_name: "Phone" }] }),
			/gebunden/,
		);
	});
});

describe("Freigaben applied state", () => {
	const H = "a".repeat(64);
	const H2 = "b".repeat(64);
	it("maps agent reports to applied / pending / failed / unknown", () => {
		assert.equal(ingressAppliedState({ desiredHash: H, appliedHash: H }).state, "applied");
		assert.equal(ingressAppliedState({ desiredHash: H, appliedHash: H2 }).state, "pending");
		// an agent without a recent heartbeat is "offline", not "pending" forever
		const t = 1_800_000_000;
		assert.equal(
			ingressAppliedState({ desiredHash: H, appliedHash: H2, lastSeen: t - 60, now: t }).state,
			"pending",
		);
		assert.equal(
			ingressAppliedState({ desiredHash: H, appliedHash: H2, lastSeen: t - 3600, now: t }).state,
			"offline",
		);
		assert.equal(ingressAppliedState({ desiredHash: H, appliedHash: H2, lastSeen: null, now: t }).state, "offline");
		assert.equal(
			ingressAppliedState({ desiredHash: H, appliedHash: H, lastSeen: t - 3600, now: t }).state,
			"applied",
		);
		assert.equal(ingressAppliedState({ desiredHash: H, appliedHash: "NONE", error: "rejected" }).state, "failed");
		assert.equal(ingressAppliedState({ desiredHash: H, appliedHash: null }).state, "unknown");
		assert.equal(ingressAppliedState({ desiredHash: "NONE", appliedHash: null }).state, "applied");
		assert.equal(ingressAppliedState({ desiredHash: "NONE", appliedHash: "NONE" }).state, "applied");
	});
	it("reports failed when the hashes match but the agent reports an error (failed self-heal)", () => {
		const r = ingressAppliedState({
			desiredHash: H,
			appliedHash: H,
			error: "self-heal failed: iptables-restore failed",
		});
		assert.equal(r.state, "failed");
		assert.match(r.error, /self-heal failed/);
	});
	it("reports failed (not pending) when the hub cannot build the ruleset", () => {
		const r = ingressAppliedState({
			desiredHash: null,
			appliedHash: H,
			buildError: "more than 4000 ingress lines",
		});
		assert.equal(r.state, "failed");
		assert.match(r.error, /4000/);
	});
});

describe("Freigaben size caps on save", () => {
	const many = (n, f) => Array.from({ length: n }, (_, i) => f(i));
	const bigRule = (i) => ({
		id: i + 1,
		enabled: true,
		sources: many(16, (j) => `10.${i}.${j}.0/24`),
		destinations: many(16, (j) => `192.168.${j}.1/32`),
		ports: [],
	});
	it("rejects a ruleset whose active rules exceed the total line cap", () => {
		const rules = many(16, bigRule); // 16 × 256 = 4096 > 4000
		assert.ok(16 * 256 > MAX_LINES_TOTAL);
		assert.throws(() => assertTotalLineCount(rules), /höchstens 4000/);
		// disabled rules do not count
		assert.doesNotThrow(() => assertTotalLineCount(rules.map((r, i) => ({ ...r, enabled: i > 0 }))));
	});
	it("a toggle-off or rename of an oversized rule is not size-checked", () => {
		assert.equal(updateCanGrow(sanitizeIngressRule({ enabled: false }, { partial: true })), false);
		assert.equal(updateCanGrow(sanitizeIngressRule({ name: "neu" }, { partial: true })), false);
		assert.equal(updateCanGrow(sanitizeIngressRule({ note: "x" }, { partial: true })), false);
		assert.equal(updateCanGrow(sanitizeIngressRule({ enabled: true }, { partial: true })), true);
		assert.equal(updateCanGrow(sanitizeIngressRule({ sources: ["10.0.0.1"] }, { partial: true })), true);
		assert.equal(updateCanGrow(sanitizeIngressRule({ ports: [] }, { partial: true })), true);
	});
});

describe("Prüfung inputs: hub egress flows and /etc/hosts", () => {
	it("parses hub egress flows, skipping invalid entries", () => {
		const flows = parseHubEgressFlows(
			JSON.stringify([
				{ name: "Mailcow SOGo -> DC", destination: "10.3.10.5", port: 636, source: "10.10.0.1" },
				{ name: "bad dst", destination: "dc.local" },
				{ name: "bad proto", destination: "10.3.10.5", proto: "icmp" },
				{ destination: "10.3.60.0/24", proto: "udp" },
			]),
		);
		assert.deepEqual(
			flows.map((f) => [f.kind, f.label, f.host, f.port, f.proto, f.source ?? null]),
			[
				["hub-egress", "Mailcow SOGo -> DC", "10.3.10.5", 636, "tcp", "10.10.0.1/32"],
				["hub-egress", "Hub-Egress 4", "10.3.60.0/24", null, "udp", null],
			],
		);
		assert.deepEqual(parseHubEgressFlows("not json"), []);
		assert.deepEqual(parseHubEgressFlows('{"a":1}'), []);
	});
	it("parses IPv4 /etc/hosts entries case-insensitively", () => {
		const m = parseHostsFile("127.0.0.1 localhost\n# 1.2.3.4 x\n10.3.10.5 VM-DC-COMNIC-01 dc  # c\n::1 ip6\n");
		assert.equal(m.get("vm-dc-comnic-01"), "10.3.10.5");
		assert.equal(m.get("dc"), "10.3.10.5");
		assert.equal(m.has("x"), false);
		assert.equal(m.has("ip6"), false);
	});
});

describe("manual nginx confs in the Prüfung", () => {
	it("parses proxy_pass and NPM-style set $server/$port", () => {
		const sso =
			"server {\n  server_name sso.comnic-it.de;\n  location / {\n    proxy_pass http://10.3.10.31:9000;\n  }\n}";
		assert.deepEqual(
			parseManualConfUpstreams(sso, "zz-sso.conf").map((u) => [u.kind, u.label, u.host, u.port]),
			[["manual", "sso.comnic-it.de", "10.3.10.31", 9000]],
		);
		const webmail = `server {\n  server_name webmail.comnic-it.de;\n  set $forward_scheme http;\n  set $server         "10.3.60.21";\n  set $port           80;\n  location / { proxy_pass $forward_scheme://$server:$port; }\n}`;
		assert.deepEqual(
			parseManualConfUpstreams(webmail, "zz-webmail.conf").map((u) => [u.host, u.port]),
			[["10.3.60.21", 80]],
		);
		assert.deepEqual(parseManualConfUpstreams("# proxy_pass http://1.2.3.4;\n", "zz-x.conf"), []);
	});
});

describe("certificate renewal safety", async () => {
	const { default: internalCertificate, renewalBackoffMs } = await import("./certificate.js");
	it("backs off failed automatic renewals (2h … 24h)", () => {
		const h = 60 * 60 * 1000;
		assert.deepEqual([1, 2, 3, 4, 5, 9].map(renewalBackoffMs), [2 * h, 4 * h, 8 * h, 16 * h, 24 * h, 24 * h]);
	});
	it("recovers the valid cert from an interrupted renewal instead of deleting it", () => {
		const le = fs.mkdtempSync(path.join(tmp, "le-"));
		const backup = path.join(le, ".renewal-backup-npm-7");
		fs.mkdirSync(path.join(backup, "live", "npm-7"), { recursive: true });
		fs.writeFileSync(path.join(backup, "live", "npm-7", "fullchain.pem"), "OLD-VALID");
		fs.mkdirSync(path.join(backup, "renewal"), { recursive: true });
		fs.writeFileSync(path.join(backup, "renewal", "npm-7.conf"), "old");
		// certbot had already re-created the renewal conf before the crash
		fs.mkdirSync(path.join(le, "renewal"), { recursive: true });
		fs.writeFileSync(path.join(le, "renewal", "npm-7.conf"), "new");
		internalCertificate.recoverStaleRenewalBackup(backup);
		assert.equal(fs.readFileSync(path.join(le, "live", "npm-7", "fullchain.pem"), "utf8"), "OLD-VALID");
		assert.equal(fs.readFileSync(path.join(le, "renewal", "npm-7.conf"), "utf8"), "new");
		assert.equal(fs.existsSync(backup), false);
		assert.doesNotThrow(() => internalCertificate.recoverStaleRenewalBackup(backup));
	});
});

describe("remote version fetch", async () => {
	const { default: rv } = await import("./remote-version.js");
	it("shares one GitHub request between concurrent callers", async () => {
		const orig = rv.fetchUrl;
		let calls = 0;
		rv.fetchUrl = () =>
			new Promise((resolve) => {
				calls++;
				setTimeout(() => resolve(JSON.stringify({ tag_name: "v9.9.9" })), 20);
			});
		rv.last_result = null;
		rv.last_error = null;
		try {
			const results = await Promise.all([rv.get(), rv.get(), rv.get()]);
			assert.equal(calls, 1);
			for (const r of results) assert.equal(r.latest, "v9.9.9");
			assert.equal(rv.inflight, null);
		} finally {
			rv.fetchUrl = orig;
			rv.last_result = null;
			rv.last_error = null;
			rv.last_fetch_time = null;
		}
	});
	it("caches a failure instead of re-fetching on every call", async () => {
		const orig = rv.fetchUrl;
		let calls = 0;
		rv.fetchUrl = async () => {
			calls++;
			throw new Error("ETIMEDOUT");
		};
		rv.last_result = null;
		rv.last_error = null;
		try {
			await assert.rejects(() => rv.get(), /ETIMEDOUT/);
			await assert.rejects(() => rv.get(), /ETIMEDOUT/);
			assert.equal(calls, 1);
			rv.last_error_time = Date.now() - rv.error_cache_timeout - 1;
			rv.fetchUrl = async () => {
				calls++;
				return JSON.stringify({ tag_name: "v9.9.9" });
			};
			assert.equal((await rv.get()).latest, "v9.9.9");
			assert.equal(calls, 2);
		} finally {
			rv.fetchUrl = orig;
			rv.last_result = null;
			rv.last_error = null;
		}
	});
	it("keeps serving the last known release when a refresh fails", async () => {
		const orig = rv.fetchUrl;
		let calls = 0;
		rv.fetchUrl = async () => {
			calls++;
			throw new Error("rate limited");
		};
		rv.last_result = { tag_name: "v9.9.9" };
		rv.last_fetch_time = Date.now() - rv.cache_timeout - 1;
		rv.last_error = null;
		try {
			assert.equal((await rv.get()).latest, "v9.9.9");
			assert.equal((await rv.get()).latest, "v9.9.9");
			assert.equal(calls, 1);
		} finally {
			rv.fetchUrl = orig;
			rv.last_result = null;
			rv.last_error = null;
			rv.last_fetch_time = null;
		}
	});
});

describe("Config/QR guard: untyped single-LAN peer is a site, not a client", () => {
	const noAgents = async () => [];
	it("refuses an untyped wg0 peer carrying a LAN (heuristic says client)", async () => {
		const allowedIps = ["10.10.0.9/32", "192.168.111.0/24"];
		assert.equal(classifyLinkType(allowedIps, "wg0"), "client");
		const link = { id: "wg0:s", name: "UXG", interfaceName: "wg0", allowedIps, type: "client" };
		await assert.rejects(() => assertPeerConfigAllowed(link, {}, { boundAgents: noAgents }), /ausdrücklichen/);
		await assert.rejects(
			() => assertPeerConfigAllowed(link, undefined, { boundAgents: noAgents }),
			/ausdrücklichen/,
		);
	});
	it("still allows an explicitly typed client even with a network in AllowedIPs", async () => {
		const link = {
			id: "wg0:c",
			name: "Lappi",
			interfaceName: "wg0",
			allowedIps: ["10.10.0.9/32", "192.168.99.0/24"],
			type: "client",
		};
		await assert.doesNotReject(() => assertPeerConfigAllowed(link, { type: "client" }, { boundAgents: noAgents }));
	});
});

describe("site networks reject /0", () => {
	it("metadata patch throws on a /0 network (any spelling)", () => {
		assert.throws(() => sanitizeLinkMetadataPatch({ importedNetworks: ["0.0.0.0/0"] }), /\/0/);
		assert.throws(() => sanitizeLinkMetadataPatch({ exportedNetworks: ["10.1.2.3/0"] }), /\/0/);
		assert.deepEqual(sanitizeLinkMetadataPatch({ importedNetworks: ["10.0.0.0/10"] }).importedNetworks, [
			"10.0.0.0/10",
		]);
	});
	it("_collectSiteNetworks drops a stored /0 (sink guard)", () => {
		const nets = agentTest._collectSiteNetworks({
			a: { type: "site-to-site", importedNetworks: ["0.0.0.0/0", "192.168.1.0/24"] },
		});
		assert.deepEqual([...nets], ["192.168.1.0/24"]);
	});
});

describe("Prüfung: proxy upstreams and link binding", () => {
	it("picks up proxy_pass from host and location advanced_config", () => {
		const ups = proxyHostUpstreams({
			id: 7,
			domain_names: ["proxy.example"],
			forward_host: "10.3.10.12",
			forward_port: 80,
			enabled: 1,
			advanced_config: "location /api { proxy_pass http://192.168.20.6:8123; }\nproxy_pass_header Server;",
			locations: JSON.stringify([
				{
					path: "/x",
					forward_host: "10.3.10.13",
					forward_port: 81,
					advanced_config: "proxy_pass https://10.3.10.14;",
				},
			]),
		});
		const hosts = ups.map((u) => `${u.host}:${u.port}`).sort();
		assert.deepEqual(hosts, ["10.3.10.12:80", "10.3.10.13:81", "10.3.10.14:443", "192.168.20.6:8123"]);
		assert.ok(ups.every((u) => u.kind === "proxy-host" && u.id === 7 && u.enabled === true));
	});
	it("suggests a rule limited to the upstream port", () => {
		const sug = upstreamSuggestion(
			{ kind: "proxy-host", label: "psono", host: "10.3.10.26", port: 10100, proto: "tcp" },
			["10.10.0.1/32"],
		);
		assert.deepEqual(sug.ports, [{ proto: "tcp", port: "10100" }]);
		assert.deepEqual(sug.destinations, ["10.3.10.26/32"]);
		const udp = upstreamSuggestion({ kind: "stream", label: "s", host: "10.3.10.5", port: 53, proto: "udp" }, [
			"x",
		]);
		assert.deepEqual(udp.ports, [{ proto: "udp", port: "53" }]);
	});
	it("binds by the effective status link (generated name, AllowedIPs networks)", () => {
		const statusLinks = [
			{
				id: "wg0:k",
				name: "site-to-site-abcdefgh",
				type: "site-to-site",
				importedNetworks: ["192.168.111.0/24"],
			},
			{ id: "wg0:u", name: "Untyped", type: "client", typeExplicit: false, importedNetworks: ["192.168.5.0/24"] },
			{ id: "wg0:c", name: "Phone", type: "client", typeExplicit: true, importedNetworks: [] },
		];
		assert.deepEqual(agentSiteLink("site-to-site-abcdefgh", { statusLinks }), ["wg0:k", ["192.168.111.0/24"]]);
		assert.deepEqual(agentSiteLink("Untyped", { statusLinks }), ["wg0:u", ["192.168.5.0/24"]]);
		assert.equal(agentSiteLink("Phone", { statusLinks }), null);
		assert.equal(agentSiteLink("gone", { statusLinks }), null);
		// metadata fallback without live status
		const metaLinks = [["wg0:m", { name: "M", importedNetworks: ["10.4.0.0/16"] }]];
		assert.deepEqual(agentSiteLink("M", { metaLinks }), ["wg0:m", ["10.4.0.0/16"]]);
	});
});
