import assert from "node:assert/strict";
import test from "node:test";
import { REDACTED, redactSecrets, stripHostMetaSecrets } from "../lib/redact-secrets.js";

test("redactSecrets masks DNS credentials, keys and passwords at any depth", () => {
	const input = {
		domain_names: ["a.example"],
		meta: { dns_challenge: true, dns_provider: "cloudflare", dns_provider_credentials: "dns_cloudflare_api_token=abc" },
		certificate: { meta: { certificate_key: "-----BEGIN PRIVATE KEY-----" } },
		items: [{ username: "u", password: "p" }, { username: "v", password: "" }],
	};
	const out = redactSecrets(input);
	assert.equal(out.meta.dns_provider_credentials, REDACTED);
	assert.equal(out.meta.dns_provider, "cloudflare");
	assert.equal(out.certificate.meta.certificate_key, REDACTED);
	assert.equal(out.items[0].password, REDACTED);
	assert.equal(out.items[0].username, "u");
	assert.equal(out.items[1].password, "");
	// input untouched
	assert.equal(input.meta.dns_provider_credentials, "dns_cloudflare_api_token=abc");
	assert.equal(input.items[0].password, "p");
});

test("redactSecrets keeps flags like password_changed and handles primitives", () => {
	assert.deepEqual(redactSecrets({ password_changed: true, name: "x" }), { password_changed: true, name: "x" });
	assert.equal(redactSecrets(null), null);
	assert.equal(redactSecrets("s"), "s");
	assert.deepEqual(redactSecrets([1, { secret: "x" }]), [1, { secret: REDACTED }]);
});

test("redactSecrets uses toJSON of model-like objects", () => {
	const model = { toJSON: () => ({ meta: { dns_provider_credentials: "t" } }) };
	assert.equal(redactSecrets(model).meta.dns_provider_credentials, REDACTED);
});

test("stripHostMetaSecrets drops DNS credentials only", () => {
	const meta = { dns_challenge: true, dns_provider: "cloudflare", dns_provider_credentials: "x", geo_filter: true };
	assert.deepEqual(stripHostMetaSecrets(meta), { dns_challenge: true, dns_provider: "cloudflare", geo_filter: true });
	const clean = { geo_filter: true };
	assert.equal(stripHostMetaSecrets(clean), clean);
	assert.equal(stripHostMetaSecrets(undefined), undefined);
});
