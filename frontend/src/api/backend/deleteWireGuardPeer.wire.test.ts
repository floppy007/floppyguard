import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Exercises the real ./base wire format: backend deleteOptions() reads camelCase keys only.
vi.mock("src/modules/AuthStore", () => ({ default: { token: { token: "t" }, clear: vi.fn() } }));

const { deleteWireGuardPeer } = await import("./deleteWireGuardPeer");
const { deleteWireGuardInterface } = await import("./deleteWireGuardInterface");
const { fetchBlob } = await import("./base");

const jsonResponse = (body: unknown, status = 200) =>
	new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("WireGuard delete wire format", () => {
	let fetchMock: ReturnType<typeof vi.fn>;
	beforeEach(() => {
		fetchMock = vi.fn(async () => jsonResponse({ deleted: true }));
		vi.stubGlobal("fetch", fetchMock);
	});
	afterEach(() => vi.unstubAllGlobals());

	it("sends delete-peer options in camelCase", async () => {
		await deleteWireGuardPeer({ linkId: "wg0:abc", dryRun: true });
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/api/wireguard/delete-peer");
		expect(JSON.parse(init.body)).toEqual({ linkId: "wg0:abc", dryRun: true });
	});

	it("sends delete-interface options in camelCase", async () => {
		await deleteWireGuardInterface({ name: "wg0", deleteBoundAgents: true, forceAgentIds: [3] });
		expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
			name: "wg0",
			deleteBoundAgents: true,
			forceAgentIds: [3],
		});
	});
});

describe("fetchBlob", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("surfaces the backend error message instead of a bare HTTP status", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => jsonResponse({ error: { code: 409, message: "Agent bound to this link" } }, 409)),
		);
		await expect(fetchBlob({ url: "wireguard/link-config", params: { linkId: "x" } })).rejects.toThrow(
			"Agent bound to this link",
		);
	});
});
