// Regressions for auth/2FA: server-rendered 2FA setup QR, token revocation on password
// change (upstream #5836), login-as for disabled users, TOTP disable code in the body,
// and the error handler's fallback code. No test reaches the real database.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import Ajv from "ajv/dist/2020.js";
import Access from "../lib/access.js";
import errs from "../lib/error.js";
import requireAdmin from "../lib/express/require-admin.js";
import TokenModel from "../models/token.js";

const { default: internal2fa } = await import("./2fa.js");
const { default: internalToken } = await import("./token.js");
const { default: internalUser } = await import("./user.js");
const { default: internalAuditLog } = await import("./audit-log.js");
const { default: authModel } = await import("../models/auth.js");
const { default: userModel } = await import("../models/user.js");
const { getCompiledSchema, getValidationSchema } = await import("../schema/index.js");

const nowSec = () => Math.floor(Date.now() / 1000);

/** Query builder stub: every chain method returns itself, first() resolves `row`, patch() records. */
function stubQuery(row, patches = []) {
	const qb = {
		where: () => qb,
		andWhere: () => qb,
		select: () => qb,
		allowGraph: () => qb,
		withGraphFetched: () => qb,
		first: async () => row,
		patch: async (d) => {
			patches.push(d);
			return 1;
		},
		insert: async (d) => {
			patches.push(d);
			return d;
		},
	};
	return qb;
}

const allowAll = (userId = 1) => ({ can: async () => true, token: { getUserId: () => userId } });

describe("2FA setup QR", () => {
	it("returns a server-rendered PNG data URL that matches the response schema", async (t) => {
		t.mock.method(internalUser, "get", async () => ({ id: 1, email: "a@x.de" }));
		const patches = [];
		t.mock.method(authModel, "query", () => stubQuery({ id: 5, user_id: 1, type: "password", meta: {} }, patches));

		const res = await internal2fa.startSetup(allowAll(), 1);

		assert.match(res.qr_data_url, /^data:image\/png;base64,[A-Za-z0-9+/=]+$/);
		const png = Buffer.from(res.qr_data_url.split(",")[1], "base64");
		assert.deepEqual([...png.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
		assert.match(res.otpauth_url, /^otpauth:\/\/totp\//);
		assert.equal(patches[0].meta.totp_pending_secret, res.secret);

		const schema = (await getCompiledSchema()).paths["/users/{userID}/2fa"].post.responses["200"].content[
			"application/json"
		].schema;
		const validate = new Ajv({ strict: false }).compile(schema);
		assert.ok(validate(res), JSON.stringify(validate.errors));
	});
});

describe("token revocation after a password change", () => {
	const loadAccess = async (t, { iat, meta, noPasswordRow = false }) => {
		const signed = await TokenModel().create({ iss: "api", attrs: { id: 7 }, scope: ["user"], expiresIn: "5m" });
		t.mock.method(userModel, "query", () => stubQuery({ id: 7, roles: ["admin"], permissions: {} }));
		t.mock.method(authModel, "query", () =>
			stubQuery(noPasswordRow ? undefined : { id: 1, user_id: 7, type: "password", meta }),
		);
		const access = new Access(signed.token);
		const data = await access.load();
		// jsonwebtoken stamps iat itself; move it to the second under test
		if (iat !== undefined) data.iat = iat;
		return access;
	};

	it("rejects a token issued before password_changed_at with a 401", async (t) => {
		const access = await loadAccess(t, { iat: nowSec() - 60, meta: { password_changed_at: nowSec() } });
		await assert.rejects(
			access.can("users:get", 7),
			(err) => err instanceof errs.TokenRevokedError && err.status === 401 && err.public === true,
		);
	});

	it("keeps a token issued in the same second as the change or later", async (t) => {
		const changed = nowSec() - 10;
		const access = await loadAccess(t, { iat: changed, meta: { password_changed_at: changed } });
		assert.ok(await access.can("users:get", 7));
	});

	it("leaves accounts without the marker (or SSO-only) alone", async (t) => {
		const access = await loadAccess(t, { iat: 1, meta: {} });
		assert.ok(await access.can("users:get", 7));
		const sso = await loadAccess(t, { iat: 1, noPasswordRow: true });
		assert.ok(await sso.can("users:get", 7));
	});

	it("requireAdmin passes a revoked token through as 401 instead of a 403", async (t) => {
		const access = await loadAccess(t, { iat: nowSec() - 60, meta: { password_changed_at: nowSec() } });
		let passed;
		await requireAdmin()({}, { locals: { access } }, (err) => {
			passed = err;
		});
		assert.ok(passed instanceof errs.TokenRevokedError);
		assert.equal(passed.status, 401);

		// a real permission failure still maps to the generic 403
		const denied = { can: async () => Promise.reject(new errs.PermissionError("nope")) };
		await requireAdmin()({}, { locals: { access: denied } }, (err) => {
			passed = err;
		});
		assert.ok(passed instanceof errs.PermissionError);
		assert.equal(passed.status, 403);
	});

	it("refuses to refresh a revoked token", async (t) => {
		t.mock.method(userModel, "query", () => stubQuery({ id: 7 }));
		t.mock.method(authModel, "query", () => stubQuery({ id: 1, meta: { password_changed_at: nowSec() } }));
		const access = {
			token: {
				getUserId: () => 7,
				hasScope: (s) => s === "user",
				get: (k) => ({ attrs: { id: 7 }, scope: ["user"], iat: nowSec() - 3600 })[k],
			},
		};
		await assert.rejects(internalToken.getFreshToken(access, {}), (err) => err.status === 401);

		// a token minted after the change still refreshes (also covers SSO-session tokens)
		access.token.get = (k) => ({ attrs: { id: 7, sso_exp: nowSec() + 600 }, scope: ["user"], iat: nowSec() })[k];
		const fresh = await internalToken.getFreshToken(access, {});
		assert.equal(fresh.token.split(".").length, 3);
	});

	it("voids a 2FA challenge issued before the change", async (t) => {
		const challenge = await TokenModel().create({
			iss: "api",
			attrs: { id: 7 },
			scope: ["2fa-challenge"],
			expiresIn: "5m",
		});
		t.mock.method(authModel, "query", () => stubQuery({ id: 1, meta: { password_changed_at: nowSec() + 5 } }));
		const verify = t.mock.method(internal2fa, "verifyForLogin", async () => true);
		await assert.rejects(internalToken.verify2FA(challenge.token, "123456"), /challenge token/);
		assert.equal(verify.mock.callCount(), 0, "no code is checked (or backup code burnt) for a void challenge");
	});

	it("setPassword stamps password_changed_at and keeps the rest of meta (2FA)", async (t) => {
		t.mock.method(internalUser, "get", async () => ({ id: 2, name: "B" }));
		t.mock.method(internalAuditLog, "add", async () => true);
		const patches = [];
		t.mock.method(authModel, "query", () =>
			stubQuery({ id: 9, user_id: 2, type: "password", meta: { totp_enabled: true, totp_secret: "S" } }, patches),
		);
		const before = nowSec();
		await internalUser.setPassword(allowAll(1), { id: 2, type: "password", secret: "newpass123" });
		const { meta } = patches[0];
		assert.equal(meta.totp_enabled, true);
		assert.equal(meta.totp_secret, "S");
		assert.ok(meta.password_changed_at >= before && meta.password_changed_at <= nowSec());
	});

	it("setPassword stamps the marker on a newly created password row", async (t) => {
		t.mock.method(internalUser, "get", async () => ({ id: 2, name: "B" }));
		t.mock.method(internalAuditLog, "add", async () => true);
		const patches = [];
		t.mock.method(authModel, "query", () => stubQuery(undefined, patches));
		await internalUser.setPassword(allowAll(1), { id: 2, type: "password", secret: "newpass123" });
		assert.equal(typeof patches[0].meta.password_changed_at, "number");
	});
});

describe("loginAs", () => {
	it("refuses a disabled user and issues no token", async (t) => {
		t.mock.method(internalUser, "get", async () => ({ id: 3, name: "C", is_disabled: true }));
		const audit = t.mock.method(internalAuditLog, "add", async () => true);
		const mint = t.mock.method(internalToken, "getTokenFromUser", async () => ({ token: "x" }));
		await assert.rejects(internalUser.loginAs(allowAll(1), { id: 3 }), (err) => err.status === 400);
		assert.equal(mint.mock.callCount(), 0);
		assert.equal(audit.mock.callCount(), 0);
	});

	it("still works for an active user", async (t) => {
		t.mock.method(internalUser, "get", async () => ({ id: 3, name: "C", is_disabled: false }));
		t.mock.method(internalAuditLog, "add", async () => true);
		const res = await internalUser.loginAs(allowAll(1), { id: 3 });
		assert.equal(res.user.id, 3);
		assert.equal(res.token.split(".").length, 3);
	});
});

describe("DELETE /users/:id/2fa", () => {
	const deleteHandler = async () => {
		const { default: router } = await import("../routes/users.js");
		const layer = router.stack.find((l) => l.route?.path === "/:user_id/2fa");
		const handlers = layer.route.stack.filter((l) => l.method === "delete");
		return handlers[handlers.length - 1].handle;
	};
	const run = async (handler, req) => {
		let sent;
		let error;
		const res = {
			locals: { access: allowAll(1) },
			status() {
				return this;
			},
			send(b) {
				sent = b;
			},
		};
		await handler({ method: "delete", path: "/1/2fa", params: { user_id: 1 }, query: {}, ...req }, res, (e) => {
			error = e;
		});
		return { sent, error };
	};

	it("reads the code from the JSON body", async (t) => {
		await getCompiledSchema();
		const disable = t.mock.method(internal2fa, "disable", async () => undefined);
		const { sent, error } = await run(await deleteHandler(), { body: { code: "123456" } });
		assert.equal(error, undefined);
		assert.equal(sent, true);
		assert.equal(disable.mock.calls[0].arguments[2], "123456");
	});

	it("validates the body against the schema", async (t) => {
		await getCompiledSchema();
		const disable = t.mock.method(internal2fa, "disable", async () => undefined);
		const { error } = await run(await deleteHandler(), { body: { code: "12" } });
		assert.equal(error.status, 400);
		assert.equal(disable.mock.callCount(), 0);
		assert.ok(getValidationSchema("/users/{userID}/2fa", "delete"));
	});

	it("rejects a request without any code", async (t) => {
		await getCompiledSchema();
		t.mock.method(internal2fa, "disable", async () => undefined);
		const { error } = await run(await deleteHandler(), { body: {} });
		assert.equal(error.status, 400);
	});
});

describe("error handler", () => {
	it("falls back to code 500 for errors without a status", async () => {
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
		handler(new Error("boom"), {}, res, () => {});
		assert.equal(status, 500);
		assert.equal(body.error.code, 500);
		assert.equal(body.error.message, "Internal Error");
	});
});
