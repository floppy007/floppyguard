import { afterEach, describe, expect, it } from "vitest";
import AuthStore, { TOKEN_KEY } from "./AuthStore";

describe("AuthStore.isTopTokenExpired", () => {
	afterEach(() => localStorage.clear());

	it("checks only the top token and never drops tokens", () => {
		const now = Date.parse("2026-10-10T12:00:00Z");
		const stack = [
			{ token: "admin", expires: "2026-10-11T12:00:00Z" },
			{ token: "login-as", expires: "2026-10-10T13:00:00Z" },
		];
		localStorage.setItem(TOKEN_KEY, JSON.stringify(stack));
		expect(AuthStore.isTopTokenExpired(now)).toBe(false);
		expect(AuthStore.isTopTokenExpired(Date.parse("2026-10-10T14:00:00Z"))).toBe(true);
		expect(AuthStore.count()).toBe(2);
	});

	it("treats a missing token as expired", () => {
		expect(AuthStore.isTopTokenExpired()).toBe(true);
	});
});
