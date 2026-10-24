import assert from "node:assert/strict";
import { test } from "node:test";
import Access from "../lib/access.js";
import errs from "../lib/error.js";
import { parseDatePeriod } from "../lib/helpers.js";
import userIdFromMe from "../lib/express/user-id-from-me.js";
import TokenModel from "../models/token.js";

test("access.can() denial rejects with a 403 PermissionError, not undefined", async () => {
	const access = new Access(null);
	await assert.rejects(
		access.can("auditlog:list"),
		(err) =>
			err instanceof errs.PermissionError &&
			err.status === 403 &&
			err.public === true &&
			err.message === "Permission Denied",
	);
});

test("access.can() with an unknown permission is still a 403", async () => {
	const access = new Access(null);
	await assert.rejects(access.can("nope:nothing"), (err) => err.status === 403);
});

test("parseDatePeriod rejects multi-line and non-string expressions", () => {
	assert.equal(parseDatePeriod("1d\njunk"), null);
	assert.equal(parseDatePeriod("junk\n1d"), null);
	assert.equal(parseDatePeriod(["1d"]), null);
	assert.ok(parseDatePeriod("1d"));
});

test("user-id-from-me denies /users/me without a token instead of throwing", () => {
	const req = { params: { user_id: "me" } };
	const res = { locals: { access: { token: TokenModel() } } };
	let passed;
	assert.doesNotThrow(() =>
		userIdFromMe(req, res, (err) => {
			passed = err;
		}),
	);
	assert.ok(passed);
	assert.equal(passed.status, 403);
});

test("user-id-from-me parses numeric ids", () => {
	const req = { params: { user_id: "12" } };
	let passed = "unset";
	userIdFromMe(req, { locals: {} }, (err) => {
		passed = err;
	});
	assert.equal(passed, undefined);
	assert.equal(req.params.user_id, 12);
});

test("setPermissions never writes the route-injected user id into the permission row", async () => {
	const { default: internalUser } = await import("./user.js");
	const { default: userPermissionModel } = await import("../models/user_permission.js");
	const { default: internalAuditLog } = await import("./audit-log.js");
	const origGet = internalUser.get;
	const origQuery = userPermissionModel.query;
	const origAdd = internalAuditLog.add;
	const writes = [];
	internalUser.get = async () => ({ id: 7, name: "u" });
	internalAuditLog.add = async () => true;
	try {
		for (const existing of [{ id: 3, user_id: 7 }, undefined]) {
			userPermissionModel.query = () => ({
				where: () => ({
					first: async () => existing,
					patchAndFetchById: async (id, data) => {
						writes.push({ id, data });
						return data;
					},
				}),
				insertAndFetch: async (data) => {
					writes.push({ data });
					return data;
				},
			});
			await internalUser.setPermissions({ can: async () => true }, { id: 7, visibility: "all" });
		}
	} finally {
		internalUser.get = origGet;
		userPermissionModel.query = origQuery;
		internalAuditLog.add = origAdd;
	}
	assert.equal(writes.length, 2);
	assert.equal(writes[0].id, 3);
	for (const w of writes) {
		assert.equal(Object.hasOwn(w.data, "id"), false);
		assert.equal(w.data.user_id, 7);
		assert.equal(w.data.visibility, "all");
	}
});

// ─── access lists: optional items, partial PUT, htpasswd usernames ───────────

const withAccessListMocks = async (t, fn) => {
	const { default: internalAccessList } = await import("./access-list.js");
	const { default: accessListModel } = await import("../models/access_list.js");
	const { default: accessListClientModel } = await import("../models/access_list_client.js");
	const { default: internalAuditLog } = await import("./audit-log.js");
	const { default: internalNginx } = await import("./nginx.js");
	const patches = [];
	const inserts = [];
	t.mock.method(accessListModel, "query", () => ({
		insertAndFetch: async (row) => {
			inserts.push(row);
			return { id: 9, ...row };
		},
		where: () => ({ patch: async (p) => patches.push(p) }),
	}));
	t.mock.method(accessListClientModel, "query", () => ({ insert: async () => true }));
	t.mock.method(internalAccessList, "get", async () => ({ id: 9, items: [], clients: [], proxy_host_count: 0 }));
	t.mock.method(internalAccessList, "build", async () => true);
	t.mock.method(internalAuditLog, "add", async () => true);
	t.mock.method(internalNginx, "reload", async () => true);
	const access = { can: async () => ({ permission_visibility: "all" }), token: { getUserId: () => 1 } };
	await fn({ internalAccessList, access, patches, inserts });
};

test("access-list create without items does not throw after inserting the row", async (t) => {
	await withAccessListMocks(t, async ({ internalAccessList, access, inserts }) => {
		const res = await internalAccessList.create(access, {
			name: "x",
			clients: [{ directive: "allow", address: "10.0.0.1" }],
		});
		assert.equal(res.id, 9);
		assert.equal(inserts.length, 1);
	});
});

test("access-list update patches satisfy_any / pass_auth without a name", async (t) => {
	await withAccessListMocks(t, async ({ internalAccessList, access, patches }) => {
		await internalAccessList.update(access, { id: 9, satisfy_any: false });
		assert.deepEqual(patches, [{ satisfy_any: false }]);
		await internalAccessList.update(access, { id: 9, pass_auth: true });
		assert.deepEqual(patches[1], { pass_auth: true });
	});
});

test("access-list rejects htpasswd-breaking usernames before any write", async (t) => {
	await withAccessListMocks(t, async ({ internalAccessList, access, inserts, patches }) => {
		for (const username of ["alice:x", "bob\nmallory:$apr1$x", "carol\r"]) {
			await assert.rejects(
				() => internalAccessList.create(access, { name: "x", items: [{ username, password: "pw" }] }),
				(err) => err instanceof errs.ValidationError && /Invalid username/.test(err.message),
			);
			await assert.rejects(
				() => internalAccessList.update(access, { id: 9, name: "x", items: [{ username, password: "pw" }] }),
				(err) => err instanceof errs.ValidationError,
			);
		}
		assert.equal(inserts.length, 0);
		assert.equal(patches.length, 0);
	});
});

// ─── token failures: 400 vs 401, NaN user ids, audit of impersonation/2FA/settings ───

test("Token.load() wraps non-expiry JWT errors into a public AuthError", async () => {
	await assert.rejects(
		TokenModel().load("x"),
		(err) =>
			err instanceof errs.AuthError &&
			err.public === true &&
			err.status === 400 &&
			err.message === "Invalid token" &&
			err.message_i18n === undefined,
	);
});

test("jwtdecode answers a garbage token with a public 401", async () => {
	const { default: jwtdecode } = await import("../lib/express/jwt-decode.js");
	let passed;
	await jwtdecode()({}, { locals: { token: "garbage" } }, (err) => {
		passed = err;
	});
	assert.ok(passed);
	assert.equal(passed.status, 401);
	assert.equal(passed.public, true);
});

test("access.can() for a token whose user is gone is a 401, not a 403", async (t) => {
	const { default: userModel } = await import("../models/user.js");
	const signed = await TokenModel().create({ iss: "api", attrs: { id: 987654 }, scope: ["user"], expiresIn: "5m" });
	const qb = {
		where: () => qb,
		andWhere: () => qb,
		allowGraph: () => qb,
		withGraphFetched: () => qb,
		first: async () => undefined,
	};
	t.mock.method(userModel, "query", () => qb);
	const access = new Access(signed.token);
	await access.load();
	await assert.rejects(access.can("users:get", 987654), (err) => err.status === 401 && err.public === true);
});

test("require-admin passes a 401 through instead of re-wrapping it as 403", async () => {
	const { default: requireAdmin } = await import("../lib/express/require-admin.js");
	const unauthorized = new errs.UnauthorizedError("User cannot be loaded for Token");
	let passed;
	await requireAdmin()(
		{},
		{
			locals: {
				access: {
					can: async () => {
						throw unauthorized;
					},
				},
			},
		},
		(err) => {
			passed = err;
		},
	);
	assert.equal(passed, unauthorized);
	await requireAdmin()(
		{},
		{
			locals: {
				access: {
					can: async () => {
						throw new Error("nope");
					},
				},
			},
		},
		(err) => {
			passed = err;
		},
	);
	assert.equal(passed.status, 403);
});

for (const bad of ["abc", "0", "-3"]) {
	test(`user-id-from-me rejects user id ${JSON.stringify(bad)} with a 400`, () => {
		const req = { params: { user_id: bad } };
		let passed;
		userIdFromMe(req, { locals: {} }, (err) => {
			passed = err;
		});
		assert.ok(passed);
		assert.equal(passed.status, 400);
		assert.equal(req.params.user_id, bad);
	});
}

test("loginAs writes a login-as audit entry before minting the token", async (t) => {
	const { default: internalUser } = await import("./user.js");
	const { default: internalAuditLog } = await import("./audit-log.js");
	const calls = [];
	t.mock.method(internalUser, "get", async () => ({ id: 5, name: "Bob", email: "bob@example.com" }));
	t.mock.method(internalAuditLog, "add", async (_access, entry) => {
		calls.push(entry);
		return true;
	});
	const out = await internalUser.loginAs({ can: async () => true }, { id: 5 });
	assert.equal(out.user.id, 5);
	assert.equal(calls.length, 1);
	assert.equal(calls[0].action, "login-as");
	assert.equal(calls[0].object_type, "user");
	assert.equal(calls[0].object_id, 5);
});

test("2FA disable is audited without secrets", async (t) => {
	const { default: internal2fa } = await import("./2fa.js");
	const { default: internalUser } = await import("./user.js");
	const { default: internalAuditLog } = await import("./audit-log.js");
	const { default: authModel } = await import("../models/auth.js");
	const { generateSecret, generate } = await import("otplib");
	const secret = generateSecret();
	const code = await generate({ secret });
	const calls = [];
	t.mock.method(internalUser, "get", async () => ({ id: 5, name: "Bob" }));
	t.mock.method(internal2fa, "getUserPasswordAuth", async () => ({
		id: 1,
		meta: { totp_enabled: true, totp_secret: secret, backup_codes: ["h"] },
	}));
	const qb = { where: () => qb, andWhere: () => qb, patch: async () => 1 };
	t.mock.method(authModel, "query", () => qb);
	t.mock.method(internalAuditLog, "add", async (_access, entry) => {
		calls.push(entry);
		return true;
	});
	await internal2fa.disable({ can: async () => true }, 5, code);
	assert.equal(calls.length, 1);
	assert.deepEqual(calls[0].meta, { name: "Bob", totp: "disabled" });
	assert.ok(!JSON.stringify(calls[0]).includes(secret));
});

test("2FA login: a wrong 6-digit code does not fall through to bcrypt backup-code compares", async (t) => {
	const { default: internal2fa } = await import("./2fa.js");
	const { default: bcrypt } = await import("bcrypt");
	const { generateSecret } = await import("otplib");
	t.mock.method(internal2fa, "getUserPasswordAuth", async () => ({
		id: 1,
		meta: { totp_secret: generateSecret(), backup_codes: ["a", "b", "c"] },
	}));
	const compare = t.mock.method(bcrypt, "compare", async () => false);
	assert.equal(await internal2fa.verifyForLogin(5, "000000"), false);
	assert.equal(await internal2fa.verifyForLogin(5, "1234567"), false);
	assert.equal(compare.mock.callCount(), 0);
	assert.equal(await internal2fa.verifyForLogin(5, "ABCDEF12"), false);
	assert.equal(compare.mock.callCount(), 3);
});

test("error handler maps objection's ValidationError (statusCode) to a public 400", async () => {
	const { ValidationError } = await import("objection");
	const { default: app } = await import("../app.js");
	const stack = app.router?.stack ?? app._router.stack;
	const handler = stack[stack.length - 1].handle;
	let status;
	let body;
	const res = {
		status(s) {
			status = s;
			return this;
		},
		send(b) {
			body = b;
		},
	};
	handler(new ValidationError({ type: "RelationExpression", message: "unknown relation foo" }), {}, res, () => {});
	assert.equal(status, 400);
	assert.equal(body.error.message, "unknown relation foo");
});

test("PUT /settings/:id writes one audit entry with field names only", async (t) => {
	const { EventEmitter } = await import("node:events");
	const { default: settingsRouter } = await import("../routes/settings.js");
	const { default: internalAuditLog } = await import("./audit-log.js");
	const calls = [];
	t.mock.method(internalAuditLog, "add", async (_access, entry) => {
		calls.push(entry);
		return true;
	});
	const route = settingsRouter.stack.find((l) => l.route?.path === "/:setting_id").route;
	// [options, jwtdecode, audit, get, put]: the audit middleware is the second `.all`
	const allLayers = route.stack.filter((l) => l.method === undefined || l.method === "_all");
	const audit = allLayers[1].handle;
	const res = Object.assign(new EventEmitter(), { statusCode: 200, locals: { access: { token: {} } } });
	const req = {
		method: "PUT",
		path: "/default-site",
		params: { setting_id: "default-site" },
		query: {},
		body: { value: "redirect", meta: { redirect: "https://evil.example/x", html: "<b>secret</b>" } },
	};
	audit(req, res, () => {});
	res.emit("finish");
	await new Promise((r) => setImmediate(r));
	assert.equal(calls.length, 1);
	assert.equal(calls[0].object_type, "setting");
	assert.deepEqual(calls[0].meta, {
		name: "default-site",
		fields: ["value", "meta"],
		metaFields: ["redirect", "html"],
	});
	const text = JSON.stringify(calls[0]);
	assert.ok(!text.includes("evil.example") && !text.includes("secret"));
});
