// Regression tests for four audit findings that were implemented late:
// stale renewal backups, renew() vs. a failing nginx reload, and request
// timeouts for the Cloudflare API and the remote-version check.
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fg-audit-skipped-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const root = path.join(tmp, "le");
const etc = path.join(tmp, "etc-le");
process.env.NPM_LETSENCRYPT_ROOT = root;
process.env.NPM_CERTBOT_CONFIG_DIR = etc;
process.env.DATA_DIR = tmp;

const { default: internalCertificate } = await import("./certificate.js");
const { default: certificateModel } = await import("../models/certificate.js");
const { default: internalNginx } = await import("./nginx.js");
const { default: internalAuditLog } = await import("./audit-log.js");
const { default: cloudflareDns } = await import("./cloudflare-dns.js");
const { default: remoteVersion } = await import("./remote-version.js");

const write = (p, content) => {
	fs.mkdirSync(path.dirname(p), { recursive: true });
	fs.writeFileSync(p, content);
};

describe("stale renewal backup", () => {
	it("restores a missing live dir from the backup instead of deleting it", () => {
		fs.rmSync(root, { recursive: true, force: true });
		fs.rmSync(etc, { recursive: true, force: true });
		fs.mkdirSync(etc, { recursive: true });
		const backupDir = path.join(root, ".renewal-backup-npm-9");
		write(path.join(backupDir, "live", "npm-9", "fullchain.pem"), "OLD-VALID");
		fs.mkdirSync(path.join(root, "live"), { recursive: true });

		const backup = internalCertificate.backupCertDirsForRenewal(9, root, etc);
		// The recovered live dir is moved aside again by THIS renewal's backup …
		assert.deepEqual(backup.entries, ["live/npm-9"]);
		assert.equal(fs.readFileSync(path.join(backupDir, "live", "npm-9", "fullchain.pem"), "utf8"), "OLD-VALID");
		// … and comes back on a failed renewal.
		internalCertificate.restoreCertDirsBackup(backup);
		assert.equal(fs.readFileSync(path.join(root, "live", "npm-9", "fullchain.pem"), "utf8"), "OLD-VALID");
		assert.equal(fs.existsSync(backupDir), false);
	});

	it("initTimer recovers interrupted renewals before the first run", (t) => {
		fs.rmSync(root, { recursive: true, force: true });
		write(path.join(root, ".renewal-backup-npm-4", "live", "npm-4", "fullchain.pem"), "OLD-VALID");
		const order = [];
		t.mock.method(internalCertificate, "processExpiringHosts", () => order.push("process"));
		const orig = internalCertificate.recoverAllStaleRenewalBackups;
		t.mock.method(internalCertificate, "recoverAllStaleRenewalBackups", () => {
			order.push("recover");
			orig();
		});
		internalCertificate.initTimer();
		clearInterval(internalCertificate.interval);
		internalCertificate.interval = null;
		assert.deepEqual(order, ["recover", "process"]);
		assert.equal(fs.readFileSync(path.join(root, "live", "npm-4", "fullchain.pem"), "utf8"), "OLD-VALID");
		assert.equal(fs.existsSync(path.join(root, ".renewal-backup-npm-4")), false);
	});
});

describe("renew() with a failing nginx reload", () => {
	it("records the new expiry before the reload and still reports the failure", async (t) => {
		const order = [];
		const access = { can: async () => true };
		t.mock.method(internalCertificate, "get", async () => ({
			id: 5,
			provider: "letsencrypt",
			meta: {},
			domain_names: ["a.example.com"],
		}));
		t.mock.method(internalCertificate, "renewLetsEncryptSsl", async () => order.push("certbot"));
		t.mock.method(internalCertificate, "getCertificateInfoFromFile", async () => ({
			dates: { from: 1790000000, to: 1797000000 },
		}));
		t.mock.method(certificateModel, "query", () => ({
			patchAndFetchById: async (id, patch) => {
				order.push("patch");
				return { id, ...patch };
			},
		}));
		t.mock.method(internalAuditLog, "add", async () => order.push("audit"));
		t.mock.method(internalNginx, "reload", async () => {
			order.push("reload");
			throw new Error("nginx -t failed");
		});
		await assert.rejects(() => internalCertificate.renew(access, { id: 5 }), /nginx -t failed/);
		assert.deepEqual(order, ["certbot", "patch", "audit", "reload"]);
	});
});

describe("Cloudflare API request", () => {
	it("sends a timeout signal and reports a non-JSON response clearly", async (t) => {
		let seen;
		t.mock.method(globalThis, "fetch", async (_url, options) => {
			seen = options;
			return {
				ok: false,
				status: 502,
				json: async () => {
					throw new SyntaxError("Unexpected token <");
				},
			};
		});
		await assert.rejects(() => cloudflareDns._api("tok", "/zones"), /HTTP 502, no JSON response/);
		assert.ok(seen.signal instanceof AbortSignal);
		assert.equal(seen.headers.Authorization, "Bearer tok");
	});

	it("aborts a hanging request", async (t) => {
		t.mock.method(
			globalThis,
			"fetch",
			(_url, options) =>
				new Promise((_resolve, reject) => {
					options.signal.addEventListener("abort", () => reject(options.signal.reason));
				}),
		);
		// AbortSignal.timeout() timers are unref'd; a ref'd timer keeps the test alive
		const controller = new AbortController();
		setTimeout(() => controller.abort(new DOMException("timed out", "TimeoutError")), 50);
		await assert.rejects(() => cloudflareDns._api("tok", "/zones", { signal: controller.signal }), {
			name: "TimeoutError",
		});
	});
});

describe("remote version fetch timeout", () => {
	it("gives up on a server that never answers", async () => {
		const sockets = [];
		const server = net.createServer((socket) => sockets.push(socket));
		await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
		const orig = remoteVersion.fetch_timeout;
		remoteVersion.fetch_timeout = 200;
		try {
			await assert.rejects(
				() => remoteVersion.fetchUrl(`https://127.0.0.1:${server.address().port}/`),
				/timed out/,
			);
		} finally {
			remoteVersion.fetch_timeout = orig;
			for (const s of sockets) s.destroy();
			server.close();
		}
	});
});
