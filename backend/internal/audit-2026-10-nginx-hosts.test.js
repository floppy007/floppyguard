// Regression tests for the nginx-hosts findings of audit pass 3: DNS credentials
// in renew() responses, access-list passwords via proxy hosts, htpasswd build,
// a failed reload after issuance, ip_ranges validation and create(certificate "new").
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fg-audit-nginx-hosts-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

process.env.NPM_LETSENCRYPT_ROOT = path.join(tmp, "le");
process.env.NPM_CERTBOT_CONFIG_DIR = path.join(tmp, "etc-le");
process.env.DATA_DIR = tmp;

const { default: errs } = await import("../lib/error.js");
const { default: utils } = await import("../lib/utils.js");
const { default: internalCertificate } = await import("./certificate.js");
const { default: certificateModel } = await import("../models/certificate.js");
const { default: userModel } = await import("../models/user.js");
const { default: accessListModel } = await import("../models/access_list.js");
const { default: proxyHostModel } = await import("../models/proxy_host.js");
const { default: internalNginx } = await import("./nginx.js");
const { default: internalAuditLog } = await import("./audit-log.js");
const { default: internalHost } = await import("./host.js");
const { default: internalAccessList } = await import("./access-list.js");
const { default: internalProxyHost } = await import("./proxy-host.js");
const { default: cloudflareDns } = await import("./cloudflare-dns.js");

describe("certificate renew()", () => {
	it("never returns or audit-logs meta.dns_provider_credentials", async (t) => {
		t.mock.method(internalCertificate, "get", async () => ({
			id: 5,
			provider: "letsencrypt",
			meta: { dns_challenge: true },
		}));
		t.mock.method(internalCertificate, "renewLetsEncryptSslWithDnsChallenge", async () => {});
		t.mock.method(internalCertificate, "getCertificateInfoFromFile", async () => ({
			dates: { from: 1790000000, to: 1797000000 },
		}));
		t.mock.method(certificateModel, "query", () => ({
			patchAndFetchById: async (id, patch) => ({
				id,
				is_deleted: 0,
				meta: { dns_provider: "cloudflare", dns_provider_credentials: "secret" },
				...patch,
			}),
		}));
		const audit = t.mock.method(internalAuditLog, "add", async () => {});
		t.mock.method(internalNginx, "reload", async () => {});
		const res = await internalCertificate.renew({ can: async () => true }, { id: 5 });
		assert.equal(res.meta.dns_provider_credentials, undefined);
		assert.equal(res.meta.dns_provider, "cloudflare");
		assert.equal(audit.mock.calls[0].arguments[1].meta.meta.dns_provider_credentials, undefined);
	});
});

describe("certificate create() (HTTP challenge)", () => {
	it("keeps the row when nginx reload fails after certbot succeeded", async (t) => {
		const deleted = [];
		t.mock.method(certificateModel, "query", () => ({
			insertAndFetch: async (data) => ({ id: 11, meta: {}, ...data }),
			deleteById: async (id) => deleted.push(id),
			patchAndFetchById: async (id, patch) => ({ id, meta: {}, ...patch }),
		}));
		const userQb = {
			where: () => userQb,
			andWhere: () => userQb,
			first: async () => ({ id: 1, email: "a@example.com" }),
		};
		t.mock.method(userModel, "query", () => userQb);
		t.mock.method(globalThis, "setTimeout", (fn) => fn());
		t.mock.method(internalHost, "getHostsWithDomains", async () => ({ total_count: 0 }));
		t.mock.method(internalCertificate, "disableInUseHosts", async () => {});
		t.mock.method(internalCertificate, "enableInUseHosts", async () => []);
		t.mock.method(internalNginx, "generateLetsEncryptRequestConfig", async () => {});
		t.mock.method(internalNginx, "deleteLetsEncryptRequestConfig", async () => {});
		t.mock.method(internalCertificate, "requestLetsEncryptSsl", async () => {});
		t.mock.method(internalCertificate, "getCertificateInfoFromFile", async () => ({
			dates: { from: 1790000000, to: 1797000000 },
		}));
		t.mock.method(internalCertificate, "addCreatedAuditLog", async () => {});
		let reloads = 0;
		t.mock.method(internalNginx, "reload", async () => {
			reloads++;
			// 1st: activate the challenge conf; 2nd: after re-enabling the hosts
			if (reloads === 2) throw new Error("nginx -t failed (unrelated host)");
		});
		internalCertificate.reloadPending = false;
		try {
			const access = { can: async () => true, token: { getUserId: () => 1 } };
			const res = await internalCertificate.create(access, {
				provider: "letsencrypt",
				domain_names: ["a.example.com"],
				meta: {},
			});
			assert.equal(res.id, 11);
			assert.deepEqual(deleted, []);
			assert.equal(internalCertificate.reloadPending, true);
		} finally {
			internalCertificate.reloadPending = false;
		}
	});
});

describe("access-list passwords via proxy hosts", () => {
	it("cleanRowAccessListPasswords blanks nested item passwords", () => {
		const row = { id: 1, access_list: { items: [{ username: "u", password: "secret" }], clients: [] } };
		internalHost.cleanRowAccessListPasswords(row);
		assert.equal(row.access_list.items[0].password, "");
		assert.doesNotThrow(() => internalHost.cleanRowAccessListPasswords({ id: 2, access_list: null }));
	});

	it("maskItems uses a constant hint and masks proxy_hosts[].access_list too", () => {
		const list = {
			items: [{ username: "u", password: "abcdef" }],
			proxy_hosts: [{ id: 3, access_list: { items: [{ username: "u", password: "abcdef" }] } }],
		};
		internalAccessList.maskItems(list);
		assert.equal(list.items[0].hint, "********");
		assert.equal(list.items[0].password, "");
		assert.equal(list.proxy_hosts[0].access_list.items[0].password, "");
	});

	it("assertAccessListAccess rejects a foreign list and allows 0", async (t) => {
		const qb = {
			where: () => qb,
			andWhere: () => qb,
			first: () => qb,
			// biome-ignore lint/suspicious/noThenProperty: mimics the awaitable query builder
			then: (resolve, reject) => Promise.resolve(undefined).then(resolve, reject),
		};
		t.mock.method(accessListModel, "query", () => qb);
		const access = { can: async () => ({ permission_visibility: "user" }), token: { getUserId: () => 2 } };
		await assert.rejects(
			() => internalHost.assertAccessListAccess(access, 5),
			(err) => err instanceof errs.ValidationError && /not accessible/.test(err.message),
		);
		await internalHost.assertAccessListAccess(access, 0);
		await assert.rejects(() => internalHost.assertAccessListAccess(access, "x"), errs.ValidationError);
	});

	it("proxy-host update checks a changed access_list_id before writing", async (t) => {
		t.mock.method(internalNginx, "assertSafeHostFields", () => {});
		t.mock.method(internalHost, "assertHostnamesFree", async () => {});
		t.mock.method(internalProxyHost, "get", async () => ({ id: 1, access_list_id: 0, meta: {} }));
		t.mock.method(internalHost, "assertAccessListAccess", async () => {
			throw new errs.ValidationError("Access list not found or not accessible");
		});
		const write = t.mock.method(proxyHostModel, "query", () => {
			throw new Error("proxy host must not be written");
		});
		const access = { can: async () => ({ permission_visibility: "user" }), token: { getUserId: () => 2 } };
		await assert.rejects(() => internalProxyHost.update(access, { id: 1, access_list_id: 5 }), /not accessible/);
		assert.equal(write.mock.callCount(), 0);
	});
});

describe("access-list build()", () => {
	const list = (items) => ({ id: 77, name: "t", items });

	it("passes '--' before the password and writes the file once", async (t) => {
		const file = path.join(tmp, "htpasswd-ok");
		t.mock.method(internalAccessList, "getFilename", () => file);
		const calls = [];
		t.mock.method(utils, "execFile", async (cmd, args) => {
			calls.push([cmd, ...args]);
			return `$apr1$hash-${args.at(-1)}`;
		});
		await internalAccessList.build(
			list([
				{ username: "a", password: "-1" },
				{ username: "b", password: "" },
				{ username: "c", password: "pw" },
			]),
		);
		assert.deepEqual(calls[0], ["openssl", "passwd", "-apr1", "--", "-1"]);
		assert.equal(fs.readFileSync(file, "utf8"), "a:$apr1$hash--1\nc:$apr1$hash-pw\n");
	});

	it("keeps the previous file when hashing fails", async (t) => {
		const file = path.join(tmp, "htpasswd-fail");
		fs.writeFileSync(file, "old:$apr1$x\n");
		t.mock.method(internalAccessList, "getFilename", () => file);
		t.mock.method(utils, "execFile", async (_cmd, args) => {
			if (args.at(-1) === "bad") throw new Error("openssl failed");
			return "$apr1$ok";
		});
		await assert.rejects(() =>
			internalAccessList.build(
				list([
					{ username: "a", password: "good" },
					{ username: "b", password: "bad" },
				]),
			),
		);
		assert.equal(fs.readFileSync(file, "utf8"), "old:$apr1$x\n");
	});
});

describe("proxy-host create() with certificate_id 'new'", () => {
	it("links the cert directly: one configure, no update(), no 'updated' audit", async (t) => {
		t.mock.method(internalNginx, "assertSafeHostFields", () => {});
		t.mock.method(internalHost, "assertHostnamesFree", async () => {});
		const patches = [];
		const qb = {
			insertAndFetch: async (data) => ({ id: 9, ...data }),
			where: () => qb,
			patch: async (p) => {
				patches.push(p);
				return 1;
			},
		};
		t.mock.method(proxyHostModel, "query", () => qb);
		t.mock.method(internalCertificate, "createQuickCertificate", async () => ({ id: 42 }));
		const update = t.mock.method(internalProxyHost, "update", async () => {
			throw new Error("update() must not be called");
		});
		t.mock.method(internalProxyHost, "get", async () => ({ id: 9, certificate_id: 42, meta: {} }));
		const configure = t.mock.method(internalNginx, "configure", async () => ({ nginx_online: true }));
		t.mock.method(cloudflareDns, "resolveActor", async () => null);
		t.mock.method(cloudflareDns, "syncProxyHost", async (row) => row);
		const audit = t.mock.method(internalAuditLog, "add", async () => {});
		const access = { can: async () => true, token: { getUserId: () => 1 } };
		const res = await internalProxyHost.create(access, {
			domain_names: ["n.example.com"],
			forward_host: "10.0.0.1",
			certificate_id: "new",
			meta: {},
		});
		assert.equal(res.id, 9);
		assert.deepEqual(patches, [{ certificate_id: 42 }]);
		assert.equal(update.mock.callCount(), 0);
		assert.equal(configure.mock.callCount(), 1);
		assert.deepEqual(
			audit.mock.calls.map((c) => c.arguments[1].action),
			["created"],
		);
	});
});
