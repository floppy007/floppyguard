// Regression tests: certificate renewal must never take the live cert away
// from nginx, and must not let certbot fork the lineage into npm-<id>-0001.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, beforeEach, describe, it } from "node:test";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fg-cert-renewal-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

// Hub layout: letsencryptRoot holds live/ + archive/ (+ a stale renewal/),
// certbot's config dir symlinks live/ + archive/ into it but has its OWN renewal/.
const root = path.join(tmp, "opt-le");
const etc = path.join(tmp, "etc-le");
process.env.NPM_LETSENCRYPT_ROOT = root;
process.env.NPM_CERTBOT_CONFIG_DIR = etc;

const { default: utils } = await import("../lib/utils.js");
const {
	default: internalCertificate,
	credentialsLocationFor,
	removeStaleCredentialsFiles,
} = await import("./certificate.js");

const write = (p, content) => {
	fs.mkdirSync(path.dirname(p), { recursive: true });
	fs.writeFileSync(p, content);
};

const setupLineage = ({ live = true, etcConf = true } = {}) => {
	fs.rmSync(root, { recursive: true, force: true });
	fs.rmSync(etc, { recursive: true, force: true });
	fs.mkdirSync(path.join(root, "live"), { recursive: true });
	fs.mkdirSync(path.join(root, "archive"), { recursive: true });
	fs.mkdirSync(etc, { recursive: true });
	fs.symlinkSync(path.join(root, "live"), path.join(etc, "live"));
	fs.symlinkSync(path.join(root, "archive"), path.join(etc, "archive"));
	write(path.join(root, "renewal", "npm-7.conf"), "stale");
	if (etcConf) write(path.join(etc, "renewal", "npm-7.conf"), "current");
	if (live) {
		write(path.join(root, "archive", "npm-7", "fullchain1.pem"), "OLD-VALID");
		fs.mkdirSync(path.join(root, "live", "npm-7"), { recursive: true });
		fs.symlinkSync("../../archive/npm-7/fullchain1.pem", path.join(root, "live", "npm-7", "fullchain.pem"));
	}
};

describe("certificate renewal in place", () => {
	const origExec = utils.execFile;
	after(() => {
		utils.execFile = origExec;
	});
	beforeEach(() => {
		utils.execFile = origExec;
	});

	it("renews an intact lineage without moving the live cert aside", async () => {
		setupLineage();
		assert.equal(internalCertificate.lineageIsIntact(7), true);
		let seenDuringRun = null;
		utils.execFile = async () => {
			seenDuringRun = fs.existsSync(path.join(etc, "live", "npm-7", "fullchain.pem"));
			return "ok";
		};
		assert.equal(await internalCertificate.runCertbotRenewal(7, [], {}), "ok");
		assert.equal(seenDuringRun, true);
		assert.equal(fs.readFileSync(path.join(etc, "renewal", "npm-7.conf"), "utf8"), "current");
		assert.equal(fs.existsSync(path.join(root, ".renewal-backup-npm-7")), false);
	});

	it("keeps the old cert when certbot fails on an intact lineage", async () => {
		setupLineage();
		utils.execFile = async () => {
			throw new Error("dns timeout");
		};
		await assert.rejects(() => internalCertificate.runCertbotRenewal(7, [], {}), /dns timeout/);
		assert.equal(fs.readFileSync(path.join(root, "live", "npm-7", "fullchain.pem"), "utf8"), "OLD-VALID");
	});

	it("moves certbot's own renewal conf aside for a broken lineage", async () => {
		setupLineage({ live: false });
		assert.equal(internalCertificate.lineageIsIntact(7), false);
		let confDuringRun = null;
		utils.execFile = async () => {
			confDuringRun = fs.existsSync(path.join(etc, "renewal", "npm-7.conf"));
			write(path.join(root, "archive", "npm-7", "fullchain1.pem"), "NEW");
			fs.mkdirSync(path.join(root, "live", "npm-7"), { recursive: true });
			fs.symlinkSync("../../archive/npm-7/fullchain1.pem", path.join(root, "live", "npm-7", "fullchain.pem"));
			write(path.join(etc, "renewal", "npm-7.conf"), "fresh");
			return "ok";
		};
		await internalCertificate.runCertbotRenewal(7, [], {});
		assert.equal(confDuringRun, false);
		assert.equal(fs.readFileSync(path.join(etc, "renewal", "npm-7.conf"), "utf8"), "fresh");
		assert.equal(fs.existsSync(path.join(root, ".renewal-backup-npm-7")), false);
	});

	it("restores the backup when certbot exits 0 but wrote a versioned lineage", async () => {
		setupLineage({ etcConf: true, live: true });
		// live present but certbot's conf missing → broken; simulate the old trap
		fs.rmSync(path.join(etc, "renewal", "npm-7.conf"));
		utils.execFile = async () => {
			fs.mkdirSync(path.join(root, "live", "npm-7-0001"), { recursive: true });
			write(path.join(etc, "renewal", "npm-7-0001.conf"), "forked");
			return "ok";
		};
		await assert.rejects(() => internalCertificate.runCertbotRenewal(7, [], {}), /did not write live\/npm-7/);
		assert.equal(fs.readFileSync(path.join(root, "live", "npm-7", "fullchain.pem"), "utf8"), "OLD-VALID");
		assert.equal(fs.readFileSync(path.join(root, "renewal", "npm-7.conf"), "utf8"), "stale");
		assert.equal(fs.existsSync(path.join(root, ".renewal-backup-npm-7")), false);
	});

	it("recovers a certbot-renewal entry from an interrupted backup", () => {
		setupLineage({ etcConf: false });
		const backup = path.join(root, ".renewal-backup-npm-7");
		write(path.join(backup, "certbot-renewal", "npm-7.conf"), "current");
		internalCertificate.recoverStaleRenewalBackup(backup);
		assert.equal(fs.readFileSync(path.join(etc, "renewal", "npm-7.conf"), "utf8"), "current");
		assert.equal(fs.existsSync(backup), false);
	});

	it("replaces a half-created live dir (dangling links) with the backed-up certificate", () => {
		setupLineage({ live: false });
		// the interrupted renewal had moved the valid lineage aside …
		const backup = path.join(root, ".renewal-backup-npm-7");
		write(path.join(backup, "archive", "npm-7", "fullchain3.pem"), "OLD-VALID");
		fs.mkdirSync(path.join(backup, "live", "npm-7"), { recursive: true });
		fs.symlinkSync("../../archive/npm-7/fullchain3.pem", path.join(backup, "live", "npm-7", "fullchain.pem"));
		// … and certbot crashed after creating a new archive + live dir without a cert
		fs.mkdirSync(path.join(root, "archive", "npm-7"), { recursive: true });
		fs.mkdirSync(path.join(root, "live", "npm-7"), { recursive: true });
		fs.symlinkSync("../../archive/npm-7/fullchain1.pem", path.join(root, "live", "npm-7", "fullchain.pem"));
		internalCertificate.recoverStaleRenewalBackup(backup);
		assert.equal(fs.readFileSync(path.join(root, "live", "npm-7", "fullchain.pem"), "utf8"), "OLD-VALID");
		assert.equal(fs.existsSync(backup), false);
	});

	it("keeps a usable live dir certbot already completed", () => {
		setupLineage({ live: true });
		const backup = path.join(root, ".renewal-backup-npm-7");
		write(path.join(backup, "archive", "npm-7", "fullchain3.pem"), "OLDER");
		fs.mkdirSync(path.join(backup, "live", "npm-7"), { recursive: true });
		fs.symlinkSync("../../archive/npm-7/fullchain3.pem", path.join(backup, "live", "npm-7", "fullchain.pem"));
		internalCertificate.recoverStaleRenewalBackup(backup);
		assert.equal(fs.readFileSync(path.join(root, "live", "npm-7", "fullchain.pem"), "utf8"), "OLD-VALID");
		assert.equal(fs.existsSync(backup), false);
	});
});

describe("nginx reload after a renewal", () => {
	it("retries a failed reload on the timer until it succeeds", async () => {
		const { default: internalNginx } = await import("./nginx.js");
		const orig = internalNginx.reload;
		let calls = 0;
		let fail = true;
		internalNginx.reload = async () => {
			calls++;
			if (fail) throw new Error("nginx -t failed");
		};
		try {
			internalCertificate.reloadPending = true;
			await internalCertificate.retryPendingReload();
			assert.equal(internalCertificate.reloadPending, true);
			fail = false;
			await internalCertificate.retryPendingReload();
			assert.equal(internalCertificate.reloadPending, false);
			// nothing pending → no reload
			await internalCertificate.retryPendingReload();
			assert.equal(calls, 2);
		} finally {
			internalNginx.reload = orig;
			internalCertificate.reloadPending = false;
		}
	});
});

describe("certbot argument builder", () => {
	const origExecFile = utils.execFile;
	const origExec = utils.exec;
	after(() => {
		utils.execFile = origExecFile;
		utils.exec = origExec;
	});
	beforeEach(() => {
		utils.execFile = origExecFile;
		utils.exec = origExec;
	});

	const cert = { id: 7, domain_names: ["a.example"], meta: { key_type: "ecdsa" } };
	const capture = (result = "ok") => {
		const seen = { args: null };
		utils.execFile = async (_cmd, args) => {
			seen.args = args;
			if (result instanceof Error) throw result;
			return result;
		};
		return seen;
	};
	const pairIn = (args, a, b) => args.some((v, i) => v === a && args[i + 1] === b);

	it("renewLetsEncryptSsl builds a webroot --force-renewal run without -m", async () => {
		setupLineage();
		const seen = capture();
		await internalCertificate.renewLetsEncryptSsl(cert);
		const args = seen.args;
		assert.equal(args[0], "certonly");
		assert.ok(args.includes("--force-renewal"));
		assert.ok(pairIn(args, "--cert-name", "npm-7"));
		assert.ok(pairIn(args, "--authenticator", "webroot"));
		assert.ok(args.includes("--non-interactive"));
		assert.ok(pairIn(args, "--key-type", "ecdsa"));
		assert.ok(pairIn(args, "--preferred-challenges", "http"));
		assert.ok(!args.includes("-m"));
	});

	it("requestLetsEncryptSsl passes the email and no --force-renewal", async () => {
		const seen = capture();
		await internalCertificate.requestLetsEncryptSsl(cert, "me@example");
		assert.ok(pairIn(seen.args, "-m", "me@example"));
		assert.ok(!seen.args.includes("--force-renewal"));
		assert.ok(pairIn(seen.args, "--domains", "a.example"));
	});

	describe("DNS challenge renewal", () => {
		let certificateModel;
		let origQuery;
		const dnsCert = { id: 7, domain_names: ["a.example"], meta: { dns_provider: "duckdns" } };
		const credFile = path.join(root, "credentials", "credentials-7");

		beforeEach(async () => {
			({ default: certificateModel } = await import("../models/certificate.js"));
			origQuery = certificateModel.query;
			certificateModel.query = () => ({
				findById: async () => ({ meta: { dns_provider_credentials: "dns_duckdns_token = x" } }),
			});
		});
		after(() => {
			if (certificateModel) certificateModel.query = origQuery;
		});

		it("builds the plugin args; the 0600 credentials file only exists during the run", async () => {
			setupLineage();
			utils.exec = async () => "";
			const seen = { args: null, mode: null, content: null };
			utils.execFile = async (_cmd, args) => {
				seen.args = args;
				seen.mode = fs.statSync(credFile).mode & 0o777;
				seen.content = fs.readFileSync(credFile, "utf8");
				return "ok";
			};
			try {
				await internalCertificate.renewLetsEncryptSslWithDnsChallenge(dnsCert);
			} finally {
				certificateModel.query = origQuery;
			}
			const args = seen.args;
			assert.ok(args.includes("--force-renewal"));
			assert.ok(pairIn(args, "--cert-name", "npm-7"));
			assert.ok(args.includes("--dns-duckdns"));
			assert.ok(pairIn(args, "--dns-duckdns-credentials", credFile));
			assert.ok(args.includes("--dns-duckdns-no-txt-restore"));
			assert.ok(pairIn(args, "--preferred-challenges", "dns"));
			assert.ok(!args.includes("--authenticator"));
			assert.ok(!args.includes("--non-interactive"));
			assert.equal(seen.mode, 0o600);
			assert.match(seen.content, /dns_duckdns_token = x/);
			assert.equal(fs.existsSync(credFile), false);
			assert.deepEqual(
				fs.readdirSync(path.dirname(credFile)).filter((f) => f.endsWith(".tmp")),
				[],
			);
		});

		it("writes the credentials at the path the renewal conf references", async () => {
			setupLineage();
			// certbot's renewal dir differs from letsencryptRoot (hub layout)
			const etcCred = path.join(etc, "credentials", "credentials-7");
			write(path.join(etc, "renewal", "npm-7.conf"), `[renewalparams]\ndns_duckdns_credentials = ${etcCred}\n`);
			utils.exec = async () => "";
			let existed = null;
			const seen = { args: null };
			utils.execFile = async (_cmd, args) => {
				seen.args = args;
				existed = fs.existsSync(etcCred);
				return "ok";
			};
			try {
				await internalCertificate.renewLetsEncryptSslWithDnsChallenge(dnsCert);
			} finally {
				certificateModel.query = origQuery;
			}
			assert.equal(existed, true);
			assert.ok(pairIn(seen.args, "--dns-duckdns-credentials", etcCred));
			assert.equal(fs.existsSync(etcCred), false);
		});

		it("ignores a renewal conf credentials path outside the credentials dirs", () => {
			setupLineage();
			write(path.join(etc, "renewal", "npm-7.conf"), "dns_duckdns_credentials = /tmp/evil/credentials-7\n");
			assert.equal(credentialsLocationFor(7), credFile);
			const other = path.join(root, "credentials", "credentials-8");
			write(path.join(etc, "renewal", "npm-7.conf"), `dns_duckdns_credentials = ${other}\n`);
			assert.equal(credentialsLocationFor(7), credFile);
		});

		it("concurrent runs of one certificate keep the file until the last one ends", async () => {
			setupLineage();
			utils.exec = async () => "";
			const releases = [];
			const seenFile = [];
			utils.execFile = async () => {
				seenFile.push(fs.existsSync(credFile));
				await new Promise((resolve) => releases.push(resolve));
				// still there for this run, even if the other one already finished
				seenFile.push(fs.existsSync(credFile));
				return "ok";
			};
			try {
				const a = internalCertificate.renewLetsEncryptSslWithDnsChallenge(dnsCert);
				const b = internalCertificate.renewLetsEncryptSslWithDnsChallenge(dnsCert);
				while (releases.length < 2) await new Promise((resolve) => setTimeout(resolve, 5));
				// the stale-file cleanup must not touch a file in use
				assert.equal(await removeStaleCredentialsFiles(), 0);
				releases[0]();
				await a;
				assert.equal(fs.existsSync(credFile), true);
				releases[1]();
				await b;
			} finally {
				certificateModel.query = origQuery;
			}
			assert.deepEqual(seenFile, [true, true, true, true]);
			assert.equal(fs.existsSync(credFile), false);
		});

		it("route53 points AWS_SHARED_CREDENTIALS_FILE at the per-run file", async () => {
			setupLineage();
			utils.exec = async () => "";
			const seen = { env: null, content: null };
			utils.execFile = async (_cmd, _args, opts) => {
				seen.env = opts.env;
				seen.content = fs.readFileSync(opts.env.AWS_SHARED_CREDENTIALS_FILE, "utf8");
				return "ok";
			};
			certificateModel.query = () => ({
				findById: async () => ({
					meta: {
						dns_provider_credentials:
							"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
					},
				}),
			});
			try {
				await internalCertificate.renewLetsEncryptSslWithDnsChallenge({
					id: 7,
					domain_names: ["a.example"],
					meta: { dns_provider: "route53" },
				});
			} finally {
				certificateModel.query = origQuery;
			}
			assert.equal(seen.env.AWS_SHARED_CREDENTIALS_FILE, credFile);
			assert.match(seen.content, /aws_access_key_id\s*=\s*AKIAIOSFODNN7EXAMPLE/);
			assert.equal(fs.existsSync(credFile), false);
		});

		it("requestLetsEncryptSslWithDnsChallenge removes the credentials after a successful run", async () => {
			setupLineage();
			utils.exec = async () => "";
			let existed = null;
			utils.execFile = async () => {
				existed = fs.existsSync(credFile);
				return "ok";
			};
			await internalCertificate.requestLetsEncryptSslWithDnsChallenge(
				{ ...dnsCert, meta: { ...dnsCert.meta, dns_provider_credentials: "dns_duckdns_token = x" } },
				"me@example",
			);
			assert.equal(existed, true);
			assert.equal(fs.existsSync(credFile), false);
		});

		it("removes the credentials file when certbot fails", async () => {
			setupLineage();
			utils.exec = async () => "";
			capture(new Error("dns timeout"));
			try {
				await assert.rejects(
					() => internalCertificate.renewLetsEncryptSslWithDnsChallenge(dnsCert),
					/dns timeout/,
				);
			} finally {
				certificateModel.query = origQuery;
			}
			assert.equal(fs.existsSync(credFile), false);
		});
	});
});

describe("stale DNS credentials cleanup", () => {
	let certificateModel;
	let origQuery;
	// id → certificate row the mocked DB returns (none: no row)
	let rows = {};
	beforeEach(async () => {
		({ default: certificateModel } = await import("../models/certificate.js"));
		origQuery = certificateModel.query;
		rows = {};
		certificateModel.query = () => ({ findById: async (id) => rows[id] });
	});
	after(() => {
		if (certificateModel) certificateModel.query = origQuery;
	});
	const restore = () => {
		certificateModel.query = origQuery;
	};

	it("removes credentials-<id> files from both credentials dirs, nothing else", async () => {
		const files = [
			path.join(root, "credentials", "credentials-82"),
			path.join(root, "credentials", "credentials-115"),
			path.join(etc, "credentials", "credentials-82"),
		];
		const keep = [path.join(root, "credentials", "other.ini"), path.join(etc, "credentials", "credentials-x")];
		for (const f of [...files, ...keep]) write(f, "secret");
		rows[82] = { meta: { dns_challenge: true, dns_provider_credentials: "dns_duckdns_token = x" } };
		try {
			assert.equal(await removeStaleCredentialsFiles(), 3);
		} finally {
			restore();
		}
		for (const f of files) assert.equal(fs.existsSync(f), false, f);
		for (const f of keep) assert.equal(fs.existsSync(f), true, f);
	});

	it("keeps a legacy file that is the only copy of a DNS certificate's credentials", async () => {
		const only = [path.join(root, "credentials", "credentials-90"), path.join(etc, "credentials", "credentials-90")];
		const deleted = path.join(root, "credentials", "credentials-91");
		const httpCert = path.join(root, "credentials", "credentials-92");
		for (const f of [...only, deleted, httpCert]) write(f, "secret");
		rows[90] = { is_deleted: 0, meta: { dns_challenge: true, dns_provider: "duckdns" } };
		rows[91] = { is_deleted: 1, meta: { dns_challenge: true, dns_provider: "duckdns" } };
		rows[92] = { is_deleted: 0, meta: {} };
		try {
			assert.equal(await removeStaleCredentialsFiles(), 2);
		} finally {
			restore();
		}
		for (const f of only) assert.equal(fs.existsSync(f), true, f);
		assert.equal(fs.existsSync(deleted), false);
		assert.equal(fs.existsSync(httpCert), false);
		for (const f of only) fs.rmSync(f);
	});

	it("keeps the file when the certificate lookup fails", async () => {
		const f = path.join(root, "credentials", "credentials-93");
		write(f, "secret");
		certificateModel.query = () => ({
			findById: async () => {
				throw new Error("db down");
			},
		});
		try {
			assert.equal(await removeStaleCredentialsFiles(), 0);
		} finally {
			restore();
		}
		assert.equal(fs.existsSync(f), true);
		fs.rmSync(f);
	});

	it("removes leftover temp files of an interrupted credentials write", async () => {
		const tmpFiles = [
			path.join(root, "credentials", "credentials-94.1234.1.tmp"),
			path.join(etc, "credentials", "credentials-95.99.7.tmp"),
		];
		const keep = path.join(root, "credentials", "credentials-94.x.tmp");
		for (const f of [...tmpFiles, keep]) write(f, "secret");
		// a temp file is never the only copy, even when the row has none stored
		rows[94] = { meta: { dns_challenge: true, dns_provider: "duckdns" } };
		try {
			assert.equal(await removeStaleCredentialsFiles(), 2);
		} finally {
			restore();
		}
		for (const f of tmpFiles) assert.equal(fs.existsSync(f), false, f);
		assert.equal(fs.existsSync(keep), true);
		fs.rmSync(keep);
	});

	it("tolerates missing credentials dirs", async () => {
		fs.rmSync(path.join(root, "credentials"), { recursive: true, force: true });
		fs.rmSync(path.join(etc, "credentials"), { recursive: true, force: true });
		try {
			assert.equal(await removeStaleCredentialsFiles(), 0);
		} finally {
			restore();
		}
	});
});

describe("certificate download zip", () => {
	it("writes the zip with mode 0600", async () => {
		const dir = fs.mkdtempSync(path.join(tmp, "zip-"));
		const src = path.join(dir, "privkey.pem");
		fs.writeFileSync(src, "KEY");
		const out = path.join(dir, "out.zip");
		await internalCertificate.zipFiles([src], out);
		assert.equal(fs.statSync(out).mode & 0o777, 0o600);
	});
});
