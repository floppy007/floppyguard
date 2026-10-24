// Regression tests for internal/user.js: e-mail uniqueness under concurrent
// writes (no unique index on user.email) and the own-password-change check.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import bcrypt from "bcrypt";

const { default: internalUser } = await import("./user.js");
const { default: authModel } = await import("../models/auth.js");
const { default: userModel } = await import("../models/user.js");
const { default: userPermissionModel } = await import("../models/user_permission.js");
const { default: internalAuditLog } = await import("./audit-log.js");

// In-memory stand-in for the query builder calls create()/update()/setPassword() make.
// Supports where(k, v) and where(k, op, v) with "=" / "!=".
function fakeTable(rows) {
	let nextId = rows.reduce((m, r) => Math.max(m, r.id), 0) + 1;
	return () => {
		const conds = [];
		let patchData = null;
		const match = () => rows.filter((r) => conds.every(([k, op, v]) => (op === "!=" ? r[k] !== v : r[k] === v)));
		const cond = (k, a, b) => {
			conds.push(b === undefined ? [k, "=", a] : [k, a, b]);
			return qb;
		};
		const qb = {
			where: cond,
			andWhere: cond,
			first() {
				// Thenable that still accepts .where() after .first(), like isEmailAvailable() chains it
				const res = { where: cond };
				// biome-ignore lint/suspicious/noThenProperty: mimics the awaitable query builder
				res.then = (ok, fail) => Promise.resolve(match()[0]).then(ok, fail);
				return res;
			},
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

function withFakeDb(t, { users = [], auth = [] }) {
	t.mock.method(userModel, "query", fakeTable(users));
	t.mock.method(authModel, "query", fakeTable(auth));
	t.mock.method(userPermissionModel, "query", fakeTable([]));
	t.mock.method(internalAuditLog, "add", async () => true);
	t.mock.method(internalUser, "get", async (_access, data) => users.find((u) => u.id === data.id));
	return { users, auth };
}

const access = (userId = 1) => ({ can: async () => true, token: { getUserId: () => userId } });

describe("internalUser e-mail race", () => {
	it("two concurrent create() calls with one e-mail persist exactly one user", async (t) => {
		const { users } = withFakeDb(t, {});
		const mk = () => internalUser.create(access(), { name: "N", nickname: "N", email: "Dup@x.de", roles: [] });
		const results = await Promise.allSettled([mk(), mk()]);
		assert.equal(users.length, 1);
		assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
		const rejected = results.find((r) => r.status === "rejected");
		assert.match(rejected.reason.message, /already in use/);
	});

	it("two concurrent update() calls to the same new e-mail leave only one holder", async (t) => {
		const { users } = withFakeDb(t, {
			users: [
				{ id: 1, email: "a@x.de", roles: ["admin"], is_deleted: 0 },
				{ id: 2, email: "b@x.de", roles: [], is_deleted: 0 },
			],
		});
		// Requester (id 1) is admin, so the privileged-field check passes
		const results = await Promise.allSettled([
			internalUser.update(access(1), { id: 1, email: "c@x.de" }),
			internalUser.update(access(1), { id: 2, email: "c@x.de" }),
		]);
		assert.equal(users.filter((u) => u.email === "c@x.de").length, 1);
		assert.equal(results.filter((r) => r.status === "rejected").length, 1);
	});
});

describe("setPassword own-change check", () => {
	it("rejects a wrong current password with the login error contract", async (t) => {
		const secret = await bcrypt.hash("correct-horse", 4);
		const { auth } = withFakeDb(t, {
			users: [{ id: 1, email: "a@x.de", roles: ["admin"], is_deleted: 0 }],
			auth: [{ id: 5, user_id: 1, type: "password", secret, is_deleted: 0, meta: {} }],
		});
		auth[0].verifyPassword = (p) => bcrypt.compare(p, secret);
		await assert.rejects(
			internalUser.setPassword(access(1), {
				id: 1,
				type: "password",
				current: "wrong-pass",
				secret: "newpass123",
			}),
			(err) => err.message === "Invalid email or password" && err.message_i18n === "error.invalid-auth",
		);
		assert.equal(auth[0].secret, secret, "password unchanged");
	});

	it("rejects an SSO-only account (no password row) with the same error", async (t) => {
		withFakeDb(t, { users: [{ id: 1, email: "a@x.de", roles: ["admin"], is_deleted: 0 }] });
		await assert.rejects(
			internalUser.setPassword(access(1), {
				id: 1,
				type: "password",
				current: "whatever1",
				secret: "newpass123",
			}),
			(err) => err.message === "Invalid email or password" && err.status === 400,
		);
	});
});
