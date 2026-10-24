import { afterEach, describe, expect, it, vi } from "vitest";
import { safeLocal } from "./safeStorage";

describe("safeLocal", () => {
	afterEach(() => {
		vi.restoreAllMocks();
		localStorage.clear();
	});

	it("reads, writes and removes like localStorage", () => {
		safeLocal.set("k", "v");
		expect(safeLocal.get("k")).toBe("v");
		safeLocal.remove("k");
		expect(safeLocal.get("k")).toBeNull();
	});

	it("degrades to nothing remembered when storage throws", () => {
		// Blocked site data makes even the window.localStorage accessor throw.
		vi.spyOn(window, "localStorage", "get").mockImplementation(() => {
			throw new DOMException("blocked", "SecurityError");
		});
		expect(() => safeLocal.set("k", "v")).not.toThrow();
		expect(safeLocal.get("k")).toBeNull();
		expect(() => safeLocal.remove("k")).not.toThrow();
	});
});
