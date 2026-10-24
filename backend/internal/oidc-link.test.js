// Regression tests: an SSO login must not take over another existing account
// by e-mail (stored sub mismatch, local password account, unverified e-mail).
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const { ssoLinkRefusal } = await import("./oidc.js");

describe("ssoLinkRefusal", () => {
	it("accepts the identity the account is already bound to", () => {
		assert.equal(ssoLinkRefusal({ storedSub: "abc", hasPassword: true, claims: { sub: "abc" } }), null);
	});
	it("rejects a different identity on a bound account", () => {
		assert.match(ssoLinkRefusal({ storedSub: "abc", hasPassword: false, claims: { sub: "evil" } }), /andere/);
	});
	it("never auto-links an unbound account that has a local password", () => {
		assert.match(ssoLinkRefusal({ storedSub: undefined, hasPassword: true, claims: { sub: "x" } }), /Passwort/);
	});
	it("rejects linking when the provider marks the e-mail unverified", () => {
		assert.match(
			ssoLinkRefusal({ storedSub: "", hasPassword: false, claims: { sub: "x", email_verified: false } }),
			/bestätigt/,
		);
	});
	it("links an unbound SSO-only account", () => {
		assert.equal(ssoLinkRefusal({ storedSub: "", hasPassword: false, claims: { sub: "x" } }), null);
		assert.equal(
			ssoLinkRefusal({ storedSub: "", hasPassword: false, claims: { sub: "x", email_verified: true } }),
			null,
		);
	});
});

// ─── ensureUser DB path (mocked models) + audit trail ────────────────────────

const { default: internalOidc } = await import("./oidc.js");
const { default: authModel } = await import("../models/auth.js");
const { default: userModel } = await import("../models/user.js");
const { default: userPermissionModel } = await import("../models/user_permission.js");
const { default: internalAuditLog } = await import("./audit-log.js");

// Minimal in-memory stand-in for the objection query builder calls ensureUser/markSso make.
function fakeTable(rows) {
	let nextId = rows.reduce((m, r) => Math.max(m, r.id), 0) + 1;
	return () => {
		const conds = [];
		let patchData = null;
		const match = () => rows.filter((r) => conds.every(([k, v]) => r[k] === v));
		const qb = {
			where(k, v) {
				conds.push([k, v]);
				return qb;
			},
			andWhere(k, v) {
				conds.push([k, v]);
				return qb;
			},
			first: async () => match()[0],
			patch(d) {
				patchData = d;
				return qb;
			},
			insert: async (d) => {
				const row = { id: nextId++, is_deleted: 0, ...d };
				rows.push(row);
				return row;
			},
			insertAndFetch: async (d) => qb.insert(d),
			// biome-ignore lint/suspicious/noThenProperty: mimics the awaitable query builder
			then(resolve, reject) {
				try {
					if (patchData) {
						const hit = match();
						for (const r of hit) Object.assign(r, patchData);
						resolve(hit.length);
					} else {
						resolve(match());
					}
				} catch (err) {
					reject(err);
				}
			},
		};
		return qb;
	};
}

async function withFakeDb({ users = [], auth = [] }, fn) {
	const orig = {
		auth: authModel.query,
		user: userModel.query,
		perm: userPermissionModel.query,
		add: internalAuditLog.add,
	};
	const audit = [];
	authModel.query = fakeTable(auth);
	userModel.query = fakeTable(users);
	userPermissionModel.query = fakeTable([]);
	internalAuditLog.add = async (_access, data) => {
		audit.push(data);
	};
	try {
		await fn({ users, auth, audit });
	} finally {
		authModel.query = orig.auth;
		userModel.query = orig.user;
		userPermissionModel.query = orig.perm;
		internalAuditLog.add = orig.add;
	}
}

const adminUser = (over = {}) => ({ id: 1, email: "a@x.de", roles: ["admin"], is_disabled: 0, is_deleted: 0, ...over });
const oidcRow = (userId, sub) => ({
	id: 10 + userId,
	user_id: userId,
	type: "oidc",
	secret: "",
	is_deleted: 0,
	meta: { sub },
});

describe("ensureUser (DB path)", () => {
	it("keeps a bound account when the provider e-mail changed, and audits the login", async () => {
		await withFakeDb({ users: [adminUser()], auth: [oidcRow(1, "S1")] }, async ({ users, auth, audit }) => {
			const u = await internalOidc.ensureUser("new@x.de", { sub: "S1", email: "new@x.de" });
			assert.equal(u.id, 1);
			assert.equal(users.length, 1, "no second account");
			assert.equal(auth.find((r) => r.type === "oidc").meta.sub, "S1", "sub unchanged");
			assert.deepEqual(
				audit.map((a) => a.action),
				["sso-login"],
			);
			assert.equal(audit[0].meta.sub, "S1");
			assert.ok(!JSON.stringify(audit).match(/token|secret/i), "no tokens in the audit entry");
		});
	});

	it("refuses a different identity for a bound account, audits it, keeps the binding", async () => {
		await withFakeDb({ users: [adminUser()], auth: [oidcRow(1, "S1")] }, async ({ auth, audit }) => {
			await assert.rejects(internalOidc.ensureUser("a@x.de", { sub: "EVIL", email: "a@x.de" }), (err) => {
				assert.equal(err.reason, "linked");
				return true;
			});
			assert.equal(auth.find((r) => r.type === "oidc").meta.sub, "S1", "markSso did not overwrite the sub");
			assert.equal(audit.length, 1);
			assert.equal(audit[0].action, "sso-refused");
			assert.equal(audit[0].object_id, 1);
			assert.equal(audit[0].meta.sub, "EVIL");
			assert.match(audit[0].meta.reason, /andere Anbieter-Identität/);
		});
	});

	it("refuses to auto-link an account with a local password", async () => {
		const pw = { id: 20, user_id: 1, type: "password", secret: "$2b$hash", is_deleted: 0, meta: {} };
		await withFakeDb({ users: [adminUser()], auth: [pw] }, async ({ auth, audit }) => {
			await assert.rejects(
				internalOidc.ensureUser("a@x.de", { sub: "S9", email: "a@x.de" }),
				/nicht freigegeben/,
			);
			assert.ok(!auth.some((r) => r.type === "oidc"), "no oidc binding created");
			assert.equal(audit[0].action, "sso-refused");
			assert.match(audit[0].meta.reason, /Passwort/);
		});
	});

	it("refuses linking when email_verified=false", async () => {
		await withFakeDb({ users: [adminUser()], auth: [] }, async ({ auth, audit }) => {
			await assert.rejects(
				internalOidc.ensureUser("a@x.de", { sub: "S9", email: "a@x.de", email_verified: false }),
				/nicht freigegeben/,
			);
			assert.equal(auth.length, 0);
			assert.match(audit[0].meta.reason, /bestätigt/);
		});
	});

	it("creates a new SSO account and audits creation + login", async () => {
		await withFakeDb({ users: [], auth: [] }, async ({ users, auth, audit }) => {
			const u = await internalOidc.ensureUser("n@x.de", { sub: "S5", email: "n@x.de", name: "N" });
			assert.equal(users.length, 1);
			assert.deepEqual(u.roles, ["admin"]);
			assert.equal(auth[0].meta.sub, "S5");
			assert.deepEqual(
				audit.map((a) => a.action),
				["created", "sso-login"],
			);
		});
	});
});

describe("ensureUser e-mail race", () => {
	it("two concurrent first SSO logins with the same e-mail create exactly one account", async () => {
		await withFakeDb({ users: [], auth: [] }, async ({ users }) => {
			const [a, b] = await Promise.all([
				internalOidc.ensureUser("race@x.de", { sub: "R1", email: "race@x.de" }),
				internalOidc.ensureUser("race@x.de", { sub: "R1", email: "race@x.de" }),
			]);
			assert.equal(users.length, 1, "one account only");
			assert.equal(a.id, b.id);
		});
	});
});
