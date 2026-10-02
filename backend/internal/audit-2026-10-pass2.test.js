// Regression tests for the second 2026-10 audit pass (SSO expiry units,
// Cloudflare DNS meta, Route53 credentials, hostname regex, live bandwidth).
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fg-audit2-"));
process.env.DATA_DIR = tmp;
process.env.OIDC_CONFIG_PATH = path.join(tmp, "oidc.json");

const { expirySeconds, validate } = await import("./oidc-settings.js");
const { normalizeRoute53Credentials, credentialsFileContent } = await import("../lib/route53-credentials.js");
const { default: cloudflareDns } = await import("./cloudflare-dns.js");
const { default: internalCertificate } = await import("./certificate.js");

after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const here = path.dirname(new URL(import.meta.url).pathname);
const readSchema = (name) => JSON.parse(fs.readFileSync(path.join(here, "../schema/components", name), "utf8"));

describe("SSO expiry", () => {
	it("computes the lifetime in seconds", () => {
		assert.equal(expirySeconds("8h"), 8 * 3600);
		assert.equal(expirySeconds("1d"), 86400);
		assert.equal(expirySeconds("2w"), 14 * 86400);
		assert.equal(expirySeconds("30m"), 1800);
		assert.equal(expirySeconds("1y"), 365 * 86400);
	});

	it("rejects units that moment and jsonwebtoken read differently", () => {
		assert.equal(expirySeconds("1M"), null);
		assert.equal(expirySeconds("1Q"), null);
		assert.equal(expirySeconds("10s"), null);
		assert.equal(expirySeconds("2y"), null); // over the one-year cap
		assert.equal(expirySeconds(undefined), null);
	});

	it("validation refuses 1M and 1Q", () => {
		for (const expiry of ["1M", "1Q"]) {
			assert.throws(() => validate({ expiry }, {}), /Gültigkeitsdauer/);
		}
		assert.equal(validate({ expiry: "12h" }, {}).expiry, "12h");
	});
});

describe("Cloudflare DNS meta", () => {
	it("drops client-supplied record ids and status fields", () => {
		const out = cloudflareDns.sanitizeMeta(
			{
				cloudflareDns: {
					enabled: true,
					proxied: false,
					records: { "a.example.com|A": { id: "../../other/dns_records/x" } },
					status: "synced",
					error: null,
					syncedAt: "x",
				},
			},
			undefined,
		);
		assert.deepEqual(out.cloudflareDns, { enabled: true, proxied: false });
	});

	it("keeps the server-side records of the stored host", () => {
		const stored = { cloudflare_dns: { enabled: true, records: { "a.example.com|A": { id: "a".repeat(32) } } } };
		const out = cloudflareDns.sanitizeMeta(
			{ cloudflare_dns: { enabled: true, records: { "a.example.com|A": { id: "b".repeat(32) } } } },
			stored,
		);
		assert.equal(out.cloudflare_dns.records["a.example.com|A"].id, "a".repeat(32));
	});

	it("gives the server-wide token only to admins", async () => {
		const host = { id: 1, domain_names: ["a.example.com"], certificate_id: 0 };
		const prev = process.env.CLOUDFLARE_API_TOKEN;
		process.env.CLOUDFLARE_API_TOKEN = "global-token";
		try {
			assert.equal(await cloudflareDns._getToken(host, { userId: 1, isAdmin: true }), "global-token");
			assert.equal(await cloudflareDns._getToken(host, { userId: 2, isAdmin: false }), null);
			assert.equal(await cloudflareDns._getToken(host, undefined), null);
		} finally {
			if (prev === undefined) delete process.env.CLOUDFLARE_API_TOKEN;
			else process.env.CLOUDFLARE_API_TOKEN = prev;
		}
	});
});

describe("Route53 credentials", () => {
	const valid = "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

	it("accepts the documented template", () => {
		assert.equal(normalizeRoute53Credentials(valid), `${valid}\n`);
		assert.equal(
			normalizeRoute53Credentials("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\r\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n"),
			`${valid}\n`,
		);
	});

	it("rejects credential_process and other keys or sections", () => {
		assert.throws(() => normalizeRoute53Credentials(`${valid}\ncredential_process = /bin/sh -c id`), /not allowed/);
		assert.throws(() => normalizeRoute53Credentials(`[profile x]\n${valid}`), /default/);
		assert.throws(() => normalizeRoute53Credentials("[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE"), /need/);
		assert.throws(() => normalizeRoute53Credentials(`${valid}\nregion=us-east-1; touch /tmp/x`), /invalid value/);
	});

	it("passes other providers through unchanged", () => {
		assert.equal(credentialsFileContent("cloudflare", "dns_cloudflare_api_token = x"), "dns_cloudflare_api_token = x");
		assert.throws(() => credentialsFileContent("route53", "credential_process=id"));
	});

	it("does not read an AWS config file and leaves process.env alone", () => {
		const before = process.env.AWS_CONFIG_FILE;
		const { opts } = internalCertificate.getAdditionalCertbotArgs(7, "route53");
		assert.equal(opts.env.AWS_CONFIG_FILE, "/dev/null");
		assert.match(opts.env.AWS_SHARED_CREDENTIALS_FILE, /credentials-7$/);
		assert.equal(process.env.AWS_CONFIG_FILE, before);
		assert.notEqual(opts.env, process.env);
	});
});

describe("hostname patterns", () => {
	const patterns = [
		["redirection", readSchema("redirection-host-object.json").properties.forward_domain_name],
		["stream", readSchema("stream-object.json").properties.forwarding_host.anyOf[0]],
	];
	for (const [name, schema] of patterns) {
		it(`${name}: runs in linear time and has a length cap`, () => {
			const re = new RegExp(schema.pattern, "u");
			assert.ok(schema.maxLength > 0);
			const start = Date.now();
			assert.equal(re.test(`${"a".repeat(5000)}.`), false);
			assert.ok(Date.now() - start < 100);
			assert.equal(re.test("example.com"), true);
			assert.equal(re.test("a;b"), false);
			assert.equal(re.test("a}b"), false);
			assert.equal(re.test("a..b"), false);
		});
	}
});
