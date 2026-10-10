// Round-4 review fixes: forced agent delete, https-only fallback hub URL,
// uploadConfig resync, and the agent-side reinstall token pickup.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

const { default: internalAgent, _testExports } = await import("./agent.js");
const { default: Agent } = await import("../models/agent.js");
const { default: internalWireGuard, withWriteLock } = await import("./wireguard.js");
const { describeAgentRequest } = await import("./audit-route.js");
const { assertForceDeleteAllowed, sanitizeFallbackHubUrl, buildLoopScript } = _testExports;

const script = buildLoopScript();

/** Cut one bash function definition `name() { … }` out of the loop script. */
function bashFn(name) {
	const start = script.indexOf(`\n${name}() {`);
	assert.ok(start >= 0, `${name}() not found`);
	const end = script.indexOf("\n}\n", start);
	return script.slice(start + 1, end + 3);
}

function runBash(body, env = {}) {
	const r = spawnSync("bash", ["-c", body], { encoding: "utf8", env: { PATH: process.env.PATH, ...env } });
	return { code: r.status, out: (r.stdout || "").trim(), err: r.stderr || "" };
}

describe("forced agent delete", () => {
	const now = 2_000_000_000;
	it("refuses while the agent still reports in", () => {
		assert.throws(() => assertForceDeleteAllowed({ last_seen: now - 60 }, now), /nicht gemeldet/);
		assert.throws(() => assertForceDeleteAllowed({ last_seen: now - 3599 }, now));
	});
	it("allows an agent that is offline for an hour or never reported", () => {
		assert.doesNotThrow(() => assertForceDeleteAllowed({ last_seen: now - 3600 }, now));
		assert.doesNotThrow(() => assertForceDeleteAllowed({ last_seen: null }, now));
		assert.doesNotThrow(() => assertForceDeleteAllowed({}, now));
	});
	it("is audited as force-delete", () => {
		const base = { method: "DELETE", path: "/agents/7", params: { id: "7" }, body: undefined };
		assert.equal(describeAgentRequest({ ...base, query: { force: "1" } }).meta.op, "force-delete");
		assert.equal(describeAgentRequest({ ...base, query: {} }).meta.op, "delete");
	});
	it("delete(force) skips the Freigaben guard for an offline agent and revokes its tokens", async () => {
		const row = { id: 7, name: "gone", ingress_mode: "restricted", last_seen: 1, agent_token: "a".repeat(64) };
		const patches = [];
		const orig = Agent.query;
		const { default: AgentIngressRule } = await import("../models/agent_ingress_rule.js");
		const origRule = AgentIngressRule.query;
		const q = {
			where() {
				return q;
			},
			first: async () => row,
			patchAndFetchById: async (_id, p) => {
				patches.push(p);
				return { ...row, ...p };
			},
			delete: async () => 0,
		};
		Agent.query = () => q;
		AgentIngressRule.query = () => q;
		try {
			// without force: refused (restricted filter, gateway cannot confirm)
			await assert.rejects(() => internalAgent.delete(7), /offen/);
			assert.equal(patches.length, 0);
			assert.equal(await internalAgent.delete(7, { force: true }), true);
			assert.deepEqual(patches, [{ is_deleted: true, agent_token: null, reg_token: null }]);
			// still online → force refused
			row.last_seen = Math.floor(Date.now() / 1000);
			await assert.rejects(() => internalAgent.delete(7, { force: true }), /nicht gemeldet/);
		} finally {
			Agent.query = orig;
			AgentIngressRule.query = origRule;
		}
	});
});

describe("fallback hub URL is https only", () => {
	it("sanitizeFallbackHubUrl", () => {
		assert.equal(sanitizeFallbackHubUrl("https://proxy.example.com/"), "https://proxy.example.com");
		assert.equal(sanitizeFallbackHubUrl("http://hub.example.com:81"), null);
		assert.equal(sanitizeFallbackHubUrl('https://a/"$(id)"'), null);
	});
	it("getInstallScript rejects a plain-http public_url", async () => {
		await assert.rejects(
			() => internalAgent.getInstallScript(1, "http://10.10.10.106:81", "http://10.10.0.1:3300"),
			/public_url must be an https:\/\/ URL/,
		);
	});
	it("agent get_server uses a plain-http fallback only through the tunnel", () => {
		const harness = (route, fallback, getent = 'getent() { echo "203.0.113.5 STREAM hub"; }') =>
			runBash(
				[
					"reach() { return 0; }",
					getent,
					`ip() { echo "203.0.113.5 ${route} src 192.0.2.2 uid 0"; }`,
					bashFn("via_tunnel"),
					bashFn("get_server"),
					`PRIMARY_URL="http://10.10.0.1:3300"`,
					`FALLBACK_URL="${fallback}"`,
					"get_server",
				].join("\n"),
			).out;
		// tunnel down (routes via the LAN): neither plain-http URL is used
		assert.equal(harness("via 192.0.2.1 dev eth0", "http://hub.example.com:81"), "");
		// https fallback is fine without the tunnel
		assert.equal(harness("via 192.0.2.1 dev eth0", "https://hub.example.com"), "https://hub.example.com");
		// tunnel up: the primary wins
		assert.equal(harness("dev wg0", "https://hub.example.com"), "http://10.10.0.1:3300");
		// an IPv4-literal primary needs no NSS lookup (getent can fail for literals)
		assert.equal(harness("dev wg0", "https://hub.example.com", "getent() { return 2; }"), "http://10.10.0.1:3300");
	});
});

describe("agent reinstall token pickup (FILE_TOKEN)", () => {
	const startMarker = '    if [ -z "$RESPONSE" ]; then\n      FILE_TOKEN=';
	const start = script.indexOf(startMarker);
	const end = script.indexOf("\n    fi\n", start);
	const block = script.slice(start, end + 7);

	const run = (fileLine, current) => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fg-filetoken-"));
		const env = path.join(dir, "config.env");
		fs.writeFileSync(env, `PRIMARY_URL="http://x"\n${fileLine}\nFGAGENT_ID="1"\n`);
		try {
			return runBash(
				[
					"log() { echo \"LOG $*\" >&2; }",
					// the hub accepts only the new token
					'fg_curl() { [ "$FGTOKEN" = "newtoken" ] && echo "{\\"ok\\":1}"; }',
					`FGTOKEN="${current}"`,
					'SERVER="http://hub"',
					'RESPONSE=""',
					block.replaceAll("/etc/floppyguard-agent/config.env", env),
					'echo "$FGTOKEN|$RESPONSE"',
				].join("\n"),
			);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	};

	it("block is present", () => {
		assert.ok(start > 0 && end > start);
		assert.ok(block.includes("Adopted agent token from config.env"));
	});
	it("adopts a new token written by a reinstall and polls again", () => {
		const r = run('FGTOKEN="newtoken"', "revoked");
		assert.equal(r.out, 'newtoken|{"ok":1}');
		assert.match(r.err, /Adopted agent token/);
	});
	it("keeps the running token when the file holds the same one", () => {
		const r = run('FGTOKEN="revoked"', "revoked");
		assert.equal(r.out, "revoked|");
		assert.doesNotMatch(r.err, /Adopted/);
	});
	it("ignores a token line with shell metacharacters", () => {
		const r = run('FGTOKEN="new$(touch /tmp/fg-pwned)"', "revoked");
		assert.equal(r.out, "revoked|");
	});
});

describe("uploadConfig resync", () => {
	const TOKEN = "b".repeat(64);
	const CONF = [
		"[Interface]",
		"PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=",
		"Address = 10.10.0.5/24",
		"",
		"[Peer]",
		"PublicKey = aHVicHVia2V5aHVicHVia2V5aHVicHVia2V5aHViMDA=",
		"Endpoint = hub.example.com:51820",
		"AllowedIPs = 10.10.0.0/24",
		"",
	].join("\n");

	it("a bound agent resyncs under the write lock and stays stored when the sync throws", async () => {
		const row = { id: 9, name: "site", wg_link_name: "Site", wg_interface: "wg0", config_text: null };
		const patches = [];
		const order = [];
		const orig = {
			query: Agent.query,
			sync: internalAgent.syncAgentConfigs,
			read: internalWireGuard.readMetadataStore,
		};
		const q = {
			where() {
				return q;
			},
			first: async () => row,
			patchAndFetchById: async (_id, p) => {
				patches.push(p);
				return { ...row, ...p };
			},
		};
		Agent.query = () => q;
		internalWireGuard.readMetadataStore = async () => ({ links: [] });
		let competing;
		internalAgent.syncAgentConfigs = async (metadata) => {
			order.push("sync-start");
			assert.deepEqual(metadata, { links: [] });
			// Another writer queued now must wait until this sync is done.
			competing = withWriteLock(async () => order.push("other-writer"));
			await new Promise((r) => setTimeout(r, 20));
			order.push("sync-end");
			throw new Error("sync exploded");
		};
		try {
			const res = await internalAgent.uploadConfig(TOKEN, { config_text: CONF });
			await competing;
			assert.deepEqual(res, { ok: true, stored: true });
			assert.equal(patches.length, 1);
			assert.ok(patches[0].config_text.includes("[Interface]"));
			assert.deepEqual(order, ["sync-start", "sync-end", "other-writer"]);
		} finally {
			Agent.query = orig.query;
			internalAgent.syncAgentConfigs = orig.sync;
			internalWireGuard.readMetadataStore = orig.read;
		}
	});

	it("an unbound agent is stored without a resync", async () => {
		const row = { id: 10, name: "solo", wg_link_name: null, wg_interface: "wg0", config_text: null };
		const orig = { query: Agent.query, sync: internalAgent.syncAgentConfigs };
		let synced = false;
		const q = {
			where() {
				return q;
			},
			first: async () => row,
			patchAndFetchById: async (_id, p) => ({ ...row, ...p }),
		};
		Agent.query = () => q;
		internalAgent.syncAgentConfigs = async () => {
			synced = true;
		};
		try {
			const res = await internalAgent.uploadConfig(TOKEN, { config_text: CONF });
			assert.deepEqual(res, { ok: true, stored: true });
			assert.equal(synced, false);
		} finally {
			Agent.query = orig.query;
			internalAgent.syncAgentConfigs = orig.sync;
		}
	});
});
