import { afterEach, describe, expect, it, vi } from "vitest";
import { isChunkLoadError, reloadForNewBundle } from "./ChunkReload";

describe("ChunkReload", () => {
	afterEach(() => {
		vi.restoreAllMocks();
		window.sessionStorage.clear();
	});

	it("recognises failed dynamic imports only", () => {
		expect(
			isChunkLoadError(new TypeError("Failed to fetch dynamically imported module: /assets/Traffic-x.js")),
		).toBe(true);
		expect(isChunkLoadError(new TypeError("Importing a module script failed."))).toBe(true);
		expect(isChunkLoadError(new Error("Cannot read properties of undefined"))).toBe(false);
	});

	it("reloads once, then not again within the guard window", () => {
		const reload = vi.fn();
		vi.spyOn(window, "location", "get").mockReturnValue({ ...window.location, reload } as Location);
		expect(reloadForNewBundle(1_000_000)).toBe(true);
		expect(reloadForNewBundle(1_005_000)).toBe(false);
		expect(reloadForNewBundle(1_100_000)).toBe(true);
		expect(reload).toHaveBeenCalledTimes(2);
	});
});
