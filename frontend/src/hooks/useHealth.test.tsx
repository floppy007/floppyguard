import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const getHealth = vi.hoisted(() => vi.fn());
vi.mock("src/api/backend", async (importOriginal) => ({
	...(await importOriginal<typeof import("src/api/backend")>()),
	getHealth,
}));

const { HEALTH_CACHE_KEY, useHealth } = await import("./useHealth");

const wrapper = ({ children }: { children: ReactNode }) => (
	<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
		{children}
	</QueryClientProvider>
);

describe("useHealth localStorage cache", () => {
	beforeEach(() => {
		localStorage.clear();
		getHealth.mockResolvedValue({ status: "OK", version: { major: 2 } });
	});
	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("does not touch localStorage on every render", async () => {
		const getItem = vi.spyOn(Storage.prototype, "getItem");
		const setItem = vi.spyOn(Storage.prototype, "setItem");
		const { result, rerender } = renderHook(() => useHealth(), { wrapper });
		await waitFor(() => expect(result.current.isSuccess).toBe(true));
		const reads = getItem.mock.calls.filter(([k]) => k === HEALTH_CACHE_KEY).length;
		const writes = setItem.mock.calls.filter(([k]) => k === HEALTH_CACHE_KEY).length;
		for (let i = 0; i < 5; i++) rerender();
		expect(getItem.mock.calls.filter(([k]) => k === HEALTH_CACHE_KEY).length).toBe(reads);
		expect(setItem.mock.calls.filter(([k]) => k === HEALTH_CACHE_KEY).length).toBe(writes);
		expect(writes).toBe(1);
		expect(JSON.parse(localStorage.getItem(HEALTH_CACHE_KEY) as string).data.status).toBe("OK");
	});

	it("serves a fresh cached value as initial data and keeps its timestamp", async () => {
		const updatedAt = Date.now() - 5000;
		localStorage.setItem(HEALTH_CACHE_KEY, JSON.stringify({ data: { status: "CACHED" }, updatedAt }));
		getHealth.mockReturnValue(new Promise(() => {}));
		const { result } = renderHook(() => useHealth(), { wrapper });
		expect(result.current.data).toEqual({ status: "CACHED" });
		expect(result.current.dataUpdatedAt).toBe(updatedAt);
		expect(JSON.parse(localStorage.getItem(HEALTH_CACHE_KEY) as string).updatedAt).toBe(updatedAt);
	});

	it("survives a blocked localStorage", async () => {
		vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
			throw new DOMException("blocked", "SecurityError");
		});
		const { result } = renderHook(() => useHealth(), { wrapper });
		await waitFor(() => expect(result.current.isSuccess).toBe(true));
	});
});
