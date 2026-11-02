import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fg-cloudflare-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));
process.env.FG_CLOUDFLARE_CONFIG = path.join(tmp, "cloudflare.json");
delete process.env.CLOUDFLARE_API_TOKEN;
delete process.env.CLOUDFLARE_DNS_IPV4;
delete process.env.CLOUDFLARE_DNS_IPV6;

const { default: settings, validate, recordAddresses } = await import("./cloudflare-settings.js");
const { default: cloudflareDns } = await import("./cloudflare-dns.js");
const { default: utils } = await import("../lib/utils.js");
const { default: certificateModel } = await import("../models/certificate.js");

const TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-xy";
const ZONE = "a".repeat(32);
const ID = (c) => c.repeat(32);

describe("cloudflare settings", () => {
	it("validate: Token-Format, Token bleibt ohne Eingabe, clear_token löscht", () => {
		assert.throws(() => validate({ api_token: "kurz" }), /Format/);
		assert.throws(() => validate({ api_token: `${TOKEN}\nx` }), /Format/);
		const v = validate({ api_token: ` ${TOKEN} ` });
		assert.equal(v.api_token, TOKEN);
		assert.equal(validate({}, v).api_token, TOKEN);
		assert.equal(validate({ api_token: "" }, v).api_token, TOKEN);
		assert.equal(validate({ clear_token: true }, v).api_token, "");
	});

	it("validate: nur öffentliche, gültige Adressen; Vorgaben", () => {
		assert.throws(() => validate({ ipv4: "10.0.0.1" }), /öffentliche/);
		assert.throws(() => validate({ ipv4: "1.2.3" }), /IPv4/);
		assert.throws(() => validate({ ipv6: "fd00::1" }), /öffentliche/);
		assert.throws(() => validate({ ipv6: "2001:db8::1%eth0" }), /IPv6/);
		const v = validate({ ipv4: "95.216.66.221", ipv6: "2a01:4f9::1" });
		assert.equal(v.ipv4, "95.216.66.221");
		assert.equal(v.auto_new_hosts, true);
		assert.equal(v.proxied_default, false);
		assert.equal(v.allow_all_users, false);
	});

	it("recordAddresses: eingetragene Adressen ersetzen die Erkennung komplett", () => {
		assert.deepEqual(recordAddresses({ ipv4: "95.216.66.221", ipv6: "" }), ["95.216.66.221"]);
		process.env.CLOUDFLARE_DNS_IPV6 = "2a01:4f9::1";
		try {
			assert.deepEqual(recordAddresses({ ipv4: "", ipv6: "" }), ["2a01:4f9::1"]);
		} finally {
			delete process.env.CLOUDFLARE_DNS_IPV6;
		}
	});

	it("get gibt den Token nie heraus, nur die letzten vier Zeichen", () => {
		const { settings: out } = settings.save({ api_token: TOKEN });
		assert.equal(out.api_token, undefined);
		assert.equal(out.has_token, true);
		assert.equal(out.token_hint, "9_-xy".slice(-4));
		assert.doesNotMatch(JSON.stringify(settings.get()), new RegExp(TOKEN));
		assert.equal(fs.statSync(process.env.FG_CLOUDFLARE_CONFIG).mode & 0o777, 0o600);
	});

	it("status: Vorgaben nur, wenn der Benutzer den Hauptschlüssel nutzen darf", () => {
		settings.save({ api_token: TOKEN, auto_new_hosts: true, proxied_default: true });
		assert.deepEqual(settings.status({ isAdmin: true }), {
			configured: true,
			available: true,
			auto_new_hosts: true,
			proxied_default: true,
		});
		assert.equal(settings.status({ isAdmin: false }).available, false);
		assert.equal(settings.status({ isAdmin: false }).auto_new_hosts, false);
		settings.save({ allow_all_users: true });
		assert.equal(settings.status({ isAdmin: false }).available, true);
	});

	it("getToken: Hauptschlüssel für Admins, für andere nur mit Freigabe", async () => {
		settings.save({ api_token: TOKEN, allow_all_users: false });
		const host = { certificate_id: 0 };
		assert.equal(await cloudflareDns._getToken(host, { userId: 1, isAdmin: true }), TOKEN);
		assert.equal(await cloudflareDns._getToken(host, { userId: 2, isAdmin: false }), null);
		settings.save({ allow_all_users: true });
		assert.equal(await cloudflareDns._getToken(host, { userId: 2, isAdmin: false }), TOKEN);
		settings.save({ clear_token: true, allow_all_users: false });
	});

	it("getToken: Token des eigenen Cloudflare-DNS-Zertifikats hat Vorrang vor dem Hauptschlüssel", async (t) => {
		settings.save({ api_token: TOKEN, allow_all_users: false });
		const cert = {
			id: 5,
			owner_user_id: 2,
			is_deleted: 0,
			meta: { dns_provider: "cloudflare", dns_provider_credentials: "dns_cloudflare_api_token = cert-token" },
		};
		t.mock.method(certificateModel, "query", () => ({ findById: async () => cert }));
		const host = { certificate_id: 5 };
		assert.equal(await cloudflareDns._getToken(host, { userId: 1, isAdmin: true }), "cert-token");
		assert.equal(await cloudflareDns._getToken(host, { userId: 2, isAdmin: false }), "cert-token");
		// fremdes Zertifikat, kein Admin, kein freigegebener Hauptschlüssel → nichts
		assert.equal(await cloudflareDns._getToken(host, { userId: 3, isAdmin: false }), null);
		settings.save({ clear_token: true });
	});
});

/** Cloudflare-API-Attrappe: Zonen nach Name, Records nach ID. */
const mockApi = (t, records) => {
	const calls = [];
	t.mock.method(globalThis, "fetch", async (url, opts = {}) => {
		const u = new URL(url);
		const method = opts.method || "GET";
		calls.push(`${method} ${u.pathname}`);
		let result;
		if (u.pathname === "/client/v4/zones") result = [{ id: ZONE, name: u.searchParams.get("name") }];
		else {
			const m = u.pathname.match(/dns_records\/([0-9a-f]{32})$/);
			if (m && method === "DELETE") {
				delete records[m[1]];
				result = { id: m[1] };
			} else if (m && method === "PUT") {
				result = { ...JSON.parse(opts.body), id: m[1] };
				records[m[1]] = result;
			} else if (m) {
				if (!records[m[1]]) return { ok: false, status: 404, json: async () => ({ success: false, errors: [] }) };
				result = records[m[1]];
			} else if (u.pathname.endsWith("/dns_records")) {
				const name = u.searchParams.get("name");
				const type = u.searchParams.get("type");
				result = Object.values(records).filter((r) => r.name === name && r.type === type);
			}
		}
		return { ok: true, status: 200, json: async () => ({ success: true, result }) };
	});
	return calls;
};

describe("cloudflare record cleanup", () => {
	const managed = (id, name) => ({ id, name, type: "A", content: "1.2.3.4", comment: "Managed by FloppyGuard" });

	it("löscht nur eigene Records, behält gehaltene IDs und Namen; doppelte (verstümmelte) Schlüssel nur einmal", async (t) => {
		const store = {
			[ID("1")]: managed(ID("1"), "old.example.com"),
			[ID("2")]: managed(ID("2"), "keep.example.com"),
			[ID("3")]: { ...managed(ID("3"), "manual.example.com"), comment: "von Hand" },
		};
		const calls = mockApi(t, store);
		const failed = await cloudflareDns._removeRecords(
			"tok",
			{
				"old.example.com|A": { id: ID("1"), zone: "example.com" },
				"old.example.com|a": { id: ID("1"), zone: "example.com" },
				"keep.example.com|A": { id: ID("2"), zone: "example.com" },
				"manual.example.com|A": { id: ID("3"), zone: "example.com" },
			},
			new Set([ID("2")]),
		);
		assert.deepEqual(failed, {});
		assert.deepEqual(Object.keys(store).sort(), [ID("2"), ID("3")]);
		assert.equal(calls.filter((c) => c.startsWith("DELETE")).length, 1);
	});

	it("löscht keinen Record, dessen Name noch zum Host gehört", async (t) => {
		const store = { [ID("4")]: managed(ID("4"), "app.example.com") };
		mockApi(t, store);
		await cloudflareDns._removeRecords(
			"tok",
			{ "app.example.com|AAAA": { id: ID("4"), zone: "example.com" } },
			new Set(),
			new Set(["app.example.com"]),
		);
		assert.ok(store[ID("4")]);
	});
});

const renderProxyHost = async (meta) => {
	const template = fs.readFileSync(new URL("../templates/proxy_host.conf", import.meta.url), "utf8");
	return utils.getRenderEngine().parseAndRender(template, {
		id: 7, domain_names: ["app.example.com"], forward_scheme: "http", forward_host: "10.0.0.5",
		forward_port: 80, advanced_config: "", locations: [], use_default_location: true, ipv6: false,
		enabled: 1, meta,
	});
};

describe("proxy_host.conf Cloudflare real IP", () => {
	it("CF-Connecting-IP nur bei aktivem Cloudflare-Proxy, vor dem Länder-Filter", async () => {
		const on = await renderProxyHost({ cloudflare_dns: { enabled: true, proxied: true }, geo_filter: true });
		assert.match(on, /real_ip_header CF-Connecting-IP;/);
		assert.match(on, /include conf\.d\/include\/ip_ranges_cloudflare\[\.\]conf;/);
		assert.ok(on.indexOf("CF-Connecting-IP") < on.indexOf("$fg_geo_deny"));
		assert.match(await renderProxyHost({ cloudflareDns: { enabled: true, proxied: true } }), /CF-Connecting-IP/);
		assert.doesNotMatch(await renderProxyHost({ cloudflare_dns: { enabled: true, proxied: false } }), /CF-Connecting-IP/);
		assert.doesNotMatch(await renderProxyHost({ cloudflare_dns: { enabled: false, proxied: true } }), /CF-Connecting-IP/);
		assert.doesNotMatch(await renderProxyHost({}), /CF-Connecting-IP/);
	});
});
