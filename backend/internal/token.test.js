// Regression: refreshing an SSO token (attrs.sso_exp) threw
// "expiry.getTime is not a function" because parseDatePeriod returns a moment.
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const { default: internalToken } = await import("./token.js");
const { default: userModel } = await import("../models/user.js");
const { default: authModel } = await import("../models/auth.js");

function fakeAccess(attrs, iat = Math.floor(Date.now() / 1000)) {
	return {
		token: {
			getUserId: () => 7,
			hasScope: (s) => s === "user",
			get: (k) => (k === "attrs" ? attrs : k === "scope" ? ["user"] : k === "iat" ? iat : undefined),
		},
	};
}

// Password row lookup of assertTokenNotRevoked(); never reach the real database
function mockAuth(t, meta = {}) {
	const qb = { where: () => qb, andWhere: () => qb, first: async () => ({ id: 1, user_id: 7, meta }) };
	t.mock.method(authModel, "query", () => qb);
}

function mockUser(t) {
	const qb = {
		select: () => qb,
		where: () => qb,
		andWhere: () => qb,
		first: async () => ({ id: 7 }),
	};
	t.mock.method(userModel, "query", () => qb);
	mockAuth(t);
}

describe("getFreshToken with sso_exp", () => {
	it("caps the fresh token at the SSO session end", async (t) => {
		mockUser(t);
		const ssoExp = Math.floor(Date.now() / 1000) + 600; // 10 min left, below "1d"
		const res = await internalToken.getFreshToken(fakeAccess({ sso_exp: ssoExp }), {});
		assert.equal(new Date(res.expires).getTime(), ssoExp * 1000);
		assert.equal(res.token.split(".").length, 3);
	});

	it("keeps the requested expiry when the SSO session lasts longer", async (t) => {
		mockUser(t);
		const ssoExp = Math.floor(Date.now() / 1000) + 3 * 86400;
		const res = await internalToken.getFreshToken(fakeAccess({ sso_exp: ssoExp }), { expiry: "1h" });
		const ms = new Date(res.expires).getTime() - Date.now();
		assert.ok(ms > 3500 * 1000 && ms <= 3600 * 1000, `unexpected expiry ${res.expires}`);
	});

	it("rejects a refresh once the SSO session has ended", async (t) => {
		mockUser(t);
		const ssoExp = Math.floor(Date.now() / 1000) - 1;
		await assert.rejects(
			() => internalToken.getFreshToken(fakeAccess({ sso_exp: ssoExp }), {}),
			/SSO session expired/,
		);
	});
});

describe("getFreshToken for a deleted/disabled user", () => {
	it("answers 401 so the SPA logs the user out", async (t) => {
		const qb = { select: () => qb, where: () => qb, andWhere: () => qb, first: async () => undefined };
		t.mock.method(userModel, "query", () => qb);
		await assert.rejects(internalToken.getFreshToken(fakeAccess({}), {}), (err) => err.status === 401);
	});
});

// Regression: an unknown e-mail returned immediately while a known one ran bcrypt
// (cost 13), so the response time revealed which e-mails are registered.
describe("getTokenFromEmail timing pad", () => {
	it("runs one bcrypt compare for an unknown e-mail and returns the i18n login error", async (t) => {
		const bcrypt = (await import("bcrypt")).default;
		const qb = { where: () => qb, andWhere: () => qb, first: async () => undefined };
		t.mock.method(userModel, "query", () => qb);
		const compare = t.mock.method(bcrypt, "compare", async () => false);
		await assert.rejects(
			internalToken.getTokenFromEmail({ identity: "nobody@x.de", secret: "pw" }),
			(err) => err.message === "Invalid email or password" && err.message_i18n === "error.invalid-auth",
		);
		assert.equal(compare.mock.callCount(), 1);
	});
});
