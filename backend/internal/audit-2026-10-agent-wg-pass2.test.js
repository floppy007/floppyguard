// Regression tests for the 2026-10 audit pass 2 on agents / WireGuard.
import assert from "node:assert/strict";
import fs from "node:fs";
import { describe, it } from "node:test";

const { _rewriteRotatedPeer } = await import("./wireguard.js");
const { _testExports } = await import("./agent.js");
const { assertNoConfigText, assertIngressTornDown, buildLoopScript } = _testExports;

const OLD = "OLDkeyOLDkeyOLDkeyOLDkeyOLDkeyOLDkeyOLDkey0=";
const NEW = "NEWkeyNEWkeyNEWkeyNEWkeyNEWkeyNEWkeyNEWkey0=";
const OTHER = "OTHkeyOTHkeyOTHkeyOTHkeyOTHkeyOTHkeyOTHkey0=";

describe("peer key rotation drops the rotated peer's PresharedKey", () => {
	const conf = [
		"[Interface]",
		"PrivateKey = hub",
		"",
		"# Laptop",
		"[Peer]",
		"PresharedKey = psk-laptop=",
		`PublicKey = ${OLD}`,
		"AllowedIPs = 10.10.0.3/32",
		"",
		"[Peer]",
		`PublicKey = ${OTHER}`,
		"PresharedKey = psk-other=",
		"AllowedIPs = 10.10.0.4/32",
	].join("\n");

	it("swaps the key and removes only that block's PSK", () => {
		const { text, swapped } = _rewriteRotatedPeer(conf, OLD, NEW);
		assert.equal(swapped, true);
		assert.ok(text.includes(`PublicKey = ${NEW}`));
		assert.ok(!text.includes(OLD));
		assert.ok(!text.includes("psk-laptop"));
		assert.ok(text.includes("PresharedKey = psk-other="), "other peers keep their PSK");
		assert.ok(text.includes("AllowedIPs = 10.10.0.3/32"));
		assert.ok(text.includes("# Laptop"));
	});

	it("leaves the conf untouched when the key is not found", () => {
		const { text, swapped } = _rewriteRotatedPeer(conf, "missing=", NEW);
		assert.equal(swapped, false);
		assert.equal(text, conf);
	});
});

describe("admin API cannot set config_text", () => {
	it("rejects config_text, accepts everything else", () => {
		assert.throws(() => assertNoConfigText({ config_text: "[Interface]\nPreUp = id" }), /config_text/);
		assert.throws(() => assertNoConfigText({ config_text: null }), /config_text/);
		assert.doesNotThrow(() => assertNoConfigText({ name: "x", wg_interface: "wg1" }));
		assert.doesNotThrow(() => assertNoConfigText(undefined));
	});
});

describe("agent delete guard for the Freigaben filter", () => {
	it("refuses restricted mode", () => {
		assert.throws(
			() => assertIngressTornDown({ ingress_mode: "restricted" }, { state: "applied", applied_hash: "a".repeat(64) }),
			/offen/,
		);
	});
	it("refuses open mode not yet applied by the agent", () => {
		assert.throws(() =>
			assertIngressTornDown({ ingress_mode: "open" }, { state: "pending", applied_hash: "a".repeat(64) }),
		);
		assert.throws(() =>
			assertIngressTornDown({ ingress_mode: "open" }, { state: "offline", applied_hash: "b".repeat(64) }),
		);
	});
	it("allows open mode that is applied, or an agent without filter", () => {
		assert.doesNotThrow(() =>
			assertIngressTornDown({ ingress_mode: "open" }, { state: "applied", applied_hash: "a".repeat(64) }),
		);
		assert.doesNotThrow(() => assertIngressTornDown({ ingress_mode: "open" }, { state: "pending", applied_hash: "NONE" }));
		assert.doesNotThrow(() => assertIngressTornDown({}, { state: "unknown", applied_hash: null }));
	});
});

describe("agent loop script hardening", () => {
	const script = buildLoopScript();

	it("uses the plaintext primary URL only through the tunnel", () => {
		assert.match(script, /if via_tunnel "\$PRIMARY_URL" && reach "\$PRIMARY_URL"; then/);
		assert.match(script, / dev \(wg\[0-9\]\+\|lo\) /);
	});

	it("never rotates the token from a /config reply", () => {
		assert.ok(!script.includes("resp_get agent_token"));
	});

	it("validates wg_interface and pushed hub URLs", () => {
		assert.ok(script.includes(`grep -qE '^wg[0-9]{1,3}$'`));
		assert.ok(script.includes("valid_hub_url"));
	});

	it("picks up a token written by a reinstall", () => {
		assert.ok(script.includes("Adopted agent token from config.env"));
	});

	it("install script restarts an already running agent", () => {
		const src = fs.readFileSync(new URL("./agent.js", import.meta.url), "utf8");
		assert.ok(!src.includes("systemctl enable --now floppyguard-agent"));
		assert.ok(src.includes("systemctl restart floppyguard-agent"));
	});
});
