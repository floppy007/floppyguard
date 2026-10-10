// Regression: refreshing an SSO token (attrs.sso_exp) threw
// "expiry.getTime is not a function" because parseDatePeriod returns a moment.
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const { default: internalToken } = await import("./token.js");
const { default: userModel } = await import("../models/user.js");

function fakeAccess(attrs) {
	return {
		token: {
			getUserId: () => 7,
			hasScope: (s) => s === "user",
			get: (k) => (k === "attrs" ? attrs : k === "scope" ? ["user"] : undefined),
		},
	};
}

function mockUser(t) {
	const qb = {
		select: () => qb,
		where: () => qb,
		andWhere: () => qb,
		first: async () => ({ id: 7 }),
	};
	t.mock.method(userModel, "query", () => qb);
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
		await assert.rejects(() => internalToken.getFreshToken(fakeAccess({ sso_exp: ssoExp }), {}), /SSO session expired/);
	});
});
