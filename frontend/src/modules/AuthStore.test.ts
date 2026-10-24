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

describe("AuthStore.hasActiveToken", () => {
	afterEach(() => localStorage.clear());

	it("strips expired tokens from the top down and stops at the first valid one", () => {
		const future = new Date(Date.now() + 3600_000).toISOString();
		const past = new Date(Date.now() - 3600_000).toISOString();
		const stack = [
			{ token: "old-expired", expires: past },
			{ token: "admin", expires: future },
			{ token: "login-as-1", expires: past },
			{ token: "login-as-2", expires: past },
		];
		localStorage.setItem(TOKEN_KEY, JSON.stringify(stack));
		expect(AuthStore.hasActiveToken()).toBe(true);
		expect(JSON.parse(localStorage.getItem(TOKEN_KEY) ?? "[]").map((t: any) => t.token)).toEqual([
			"old-expired",
			"admin",
		]);
	});

	it("empties the stack when every token has expired", () => {
		const past = new Date(Date.now() - 3600_000).toISOString();
		localStorage.setItem(TOKEN_KEY, JSON.stringify([{ token: "a", expires: past }]));
		expect(AuthStore.hasActiveToken()).toBe(false);
		expect(localStorage.getItem(TOKEN_KEY)).toBe("[]");
	});

	it("returns false without touching storage when there are no tokens", () => {
		expect(AuthStore.hasActiveToken()).toBe(false);
		expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
	});
});
