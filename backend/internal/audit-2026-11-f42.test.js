// F-42 security baseline: TOTP single use, 2FA failure limits.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { generate, generateSecret } from "otplib";
import TokenModel from "../models/token.js";

const { default: internal2fa } = await import("./2fa.js");
const { default: internalToken, twoFactorFailures } = await import("./token.js");
const { default: authModel } = await import("../models/auth.js");

const nowSec = () => Math.floor(Date.now() / 1000);

function stubQuery(row, patches = []) {
	const qb = {
		where: () => qb,
		andWhere: () => qb,
		forUpdate: () => qb,
		first: async () => row,
		patch: async (d) => {
			patches.push(d);
			return 1;
		},
	};
	return qb;
}

describe("F-42 TOTP replay", () => {
	it("accepts a code once and rejects the same time step afterwards", async (t) => {
		const secret = generateSecret();
		const code = await generate({ secret });
		const state = { id: 9, user_id: 3, type: "password", meta: { totp_enabled: true, totp_secret: secret } };
		const patches = [];
		t.mock.method(internal2fa, "getUserPasswordAuth", async () => state);
		t.mock.method(authModel, "transaction", async (cb) => cb({}));
		t.mock.method(authModel, "query", () => stubQuery(state, patches));

		assert.equal(await internal2fa.verifyForLogin(3, code), true);
		assert.equal(patches.length, 1);
		const step = patches[0].meta.totp_last_step;
		assert.ok(Number.isFinite(step), "matched time step is stored");
		assert.equal(patches[0].meta.totp_secret, secret, "other meta is kept");

		state.meta = patches[0].meta;
		assert.equal(await internal2fa.verifyForLogin(3, code), false, "replayed code is refused");
		assert.equal(patches.length, 1);
	});
});

describe("F-42 2FA failure limits", () => {
	it("voids a challenge after 5 wrong codes without checking further codes", async (t) => {
		twoFactorFailures.reset();
		const challenge = await TokenModel().create({ iss: "api", attrs: { id: 11 }, scope: ["2fa-challenge"], expiresIn: "5m" });
		t.mock.method(authModel, "query", () => stubQuery({ id: 1, meta: { password_changed_at: nowSec() - 3600 } }));
		const verify = t.mock.method(internal2fa, "verifyForLogin", async () => false);
		for (let i = 0; i < 5; i++) {
			await assert.rejects(internalToken.verify2FA(challenge.token, "000000"), /verification code/);
		}
		assert.equal(verify.mock.callCount(), 5);
		await assert.rejects(internalToken.verify2FA(challenge.token, "000000"), /challenge token/);
		assert.equal(verify.mock.callCount(), 5, "blocked challenge does not test codes any more");
	});

	it("limits wrong codes per account across fresh challenges", async (t) => {
		twoFactorFailures.reset();
		t.mock.method(authModel, "query", () => stubQuery({ id: 1, meta: { password_changed_at: nowSec() - 3600 } }));
		const verify = t.mock.method(internal2fa, "verifyForLogin", async () => false);
		for (let i = 0; i < 10; i++) {
			const c = await TokenModel().create({ iss: "api", attrs: { id: 12 }, scope: ["2fa-challenge"], expiresIn: "5m" });
			await assert.rejects(internalToken.verify2FA(c.token, "000000"));
		}
		const c = await TokenModel().create({ iss: "api", attrs: { id: 12 }, scope: ["2fa-challenge"], expiresIn: "5m" });
		await assert.rejects(internalToken.verify2FA(c.token, "000000"), /challenge token/);
		assert.equal(verify.mock.callCount(), 10);
		twoFactorFailures.reset();
	});
});

describe("F-42 host guards", async () => {
	const { default: internalHost } = await import("./host.js");
	const fs = await import("node:fs");
	const os = await import("node:os");
	const path = await import("node:path");

	it("reads server_name entries of hand-written zz-*.conf blocks", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fg-zz-"));
		try {
			fs.writeFileSync(path.join(dir, "zz-sso.conf"), "server {\n  server_name sso.example.com Alt.Example.com; # c\n  # server_name commented.example;\n}\n");
			fs.writeFileSync(path.join(dir, "floppyguard.conf"), "server { server_name _; }\n");
			fs.writeFileSync(path.join(dir, "zz-re.conf"), "server { server_name ~^re\\.example$; }\n");
			const names = internalHost.handConfigServerNames(dir);
			assert.deepEqual([...names].sort(), ["alt.example.com", "sso.example.com"]);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	const admin = { can: async () => true };
	const user = {
		can: async (p) => {
			if (p === "auditlog:list") throw new Error("denied");
			return true;
		},
	};

	it("lets only admins add or change advanced_config", async () => {
		await assert.rejects(internalHost.assertAdvancedConfigAllowed(user, { advanced_config: "return 200;" }, null), (e) => e.status === 403);
		await assert.rejects(
			internalHost.assertAdvancedConfigAllowed(user, { locations: [{ path: "/", advanced_config: "x;" }] }, { locations: [] }),
			(e) => e.status === 403,
		);
		await internalHost.assertAdvancedConfigAllowed(admin, { advanced_config: "return 200;" }, null);
	});

	it("allows non-admins to keep or clear existing advanced_config", async () => {
		const row = { advanced_config: "x;", locations: [{ path: "/", advanced_config: "y;" }] };
		await internalHost.assertAdvancedConfigAllowed(user, { advanced_config: "x;", locations: row.locations }, row);
		await internalHost.assertAdvancedConfigAllowed(user, { advanced_config: "" }, row);
		await internalHost.assertAdvancedConfigAllowed(user, { domain_names: ["a.example"] }, row);
	});
});

describe("F-42 access list API view", async () => {
	const { default: internalAccessList } = await import("./access-list.js");
	it("masks passwords and drops certificate meta of expanded proxy hosts", () => {
		const row = {
			items: [{ username: "u", password: "p" }],
			proxy_hosts: [
				{
					id: 1,
					certificate: { id: 2, provider: "other", meta: { certificate_key: "KEY", dns_provider_credentials: "T" } },
					access_list: { items: [{ username: "u", password: "p" }] },
				},
			],
		};
		const out = internalAccessList.toPublic(row);
		assert.equal(out.items[0].password, "");
		assert.deepEqual(out.proxy_hosts[0].certificate.meta, {});
		assert.equal(out.proxy_hosts[0].certificate.provider, "other");
		assert.notEqual(out.proxy_hosts[0].access_list.items[0].password, "p");
	});
});
