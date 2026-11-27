import { describe, expect, it } from "vitest";
import { safeReturnTarget } from "./returnTarget";

describe("safeReturnTarget", () => {
	it("keeps own paths with query", () => {
		expect(safeReturnTarget("/nginx/proxy", "?q=1")).toBe("/nginx/proxy?q=1");
	});
	it("maps /login to dashboard", () => {
		expect(safeReturnTarget("/login", "?x")).toBe("/");
	});
	it("rejects protocol-relative and backslash targets", () => {
		expect(safeReturnTarget("//evil.example/", "")).toBe("/");
		expect(safeReturnTarget("/\\evil.example", "")).toBe("/");
		expect(safeReturnTarget("/a\\b", "")).toBe("/");
		expect(safeReturnTarget("/a\tb", "")).toBe("/");
		expect(safeReturnTarget("evil", "")).toBe("/");
	});
});
