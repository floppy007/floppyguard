import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "oidc-settings-"));
process.env.OIDC_CONFIG_PATH = path.join(dir, "oidc.json");
const { default: settings, validate } = await import("./oidc-settings.js");

const valid = {
	enabled: true,
	label: "Mit Firmenkonto anmelden",
	issuer: "https://sso.example.com/application/o/fg/",
	client_id: "abc",
	client_secret: "s3cret",
	redirect_uri: "https://proxy.example.com/api/oidc/callback",
	required_group: "Admins",
	groups_claim: "groups",
	scopes: "openid profile email",
	expiry: "1d",
};

describe("oidc-settings", () => {
	before(() => fs.rmSync(process.env.OIDC_CONFIG_PATH, { force: true }));
	after(() => fs.rmSync(dir, { recursive: true, force: true }));

	it("returns defaults without a file and never exposes the secret", () => {
		const s = settings.get();
		assert.equal(s.enabled, false);
		assert.equal(s.label, "Mit Firmenkonto anmelden");
		assert.equal(s.has_client_secret, false);
		assert.equal("client_secret" in s, false);
	});

	it("saves, strips trailing slash, writes 0600, keeps secret when omitted", () => {
		const first = settings.save(valid);
		assert.equal(first.settings.issuer, "https://sso.example.com/application/o/fg");
		assert.equal(first.settings.has_client_secret, true);
		assert.equal(fs.statSync(process.env.OIDC_CONFIG_PATH).mode & 0o777, 0o600);

		const second = settings.save({ ...valid, client_secret: "", label: "SSO" });
		assert.deepEqual(second.changed, ["label"]);
		const raw = JSON.parse(fs.readFileSync(process.env.OIDC_CONFIG_PATH, "utf8"));
		assert.equal(raw.client_secret, "s3cret");
	});

	it("rejects control characters, non-https and incomplete activation", () => {
		assert.throws(() => validate({ ...valid, label: "a\nb" }, {}), /Steuerzeichen/);
		assert.throws(() => validate({ ...valid, issuer: "http://evil.example.com" }, {}), /https/);
		assert.throws(() => validate({ ...valid, redirect_uri: "https://x.example.com/other" }, {}), /callback/);
		assert.throws(() => validate({ ...valid, scopes: "profile email" }, {}), /openid/);
		assert.throws(() => validate({ ...valid, expiry: "1d; rm" }, {}), /Gültigkeitsdauer/);
		assert.throws(() => validate({ ...valid, client_secret: "", required_group: "" }, {}), /Zum Aktivieren fehlen/);
	});

	it("allows saving a disabled, incomplete draft", () => {
		const out = validate({ enabled: false, issuer: "" }, {});
		assert.equal(out.enabled, false);
	});
});
