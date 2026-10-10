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
const { default: internalCertificate } = await import("./certificate.js");

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
