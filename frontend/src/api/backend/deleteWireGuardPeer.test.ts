import { describe, expect, it, vi } from "vitest";

vi.mock("./base", () => ({ del: vi.fn(), get: vi.fn(), post: vi.fn(), put: vi.fn() }));

const { deleteWithBoundAgents } = await import("./deleteWireGuardPeer");

const agent = (id: number, blocked: string | null, forceable = false) => ({
	id,
	name: `gw-${id}`,
	linkName: "L",
	blocked,
	forceable,
});

describe("deleteWithBoundAgents", () => {
	it("dry-runs first, then deletes the link together with its agents in one call", async () => {
		const call = vi
			.fn()
			.mockResolvedValueOnce({ agents: [agent(1, null)] })
			.mockResolvedValueOnce({ agents: { deleted: [1], errors: [] } });
		await deleteWithBoundAgents(call, () => true);
		expect(call.mock.calls).toEqual([[{ dryRun: true }], [{ deleteBoundAgents: true, forceAgentIds: [] }]]);
	});

	it("deletes nothing when one bound agent refuses and cannot be forced", async () => {
		const call = vi.fn().mockResolvedValueOnce({ agents: [agent(1, null), agent(2, "Filter aktiv")] });
		const confirm = vi.fn(() => true);
		await expect(deleteWithBoundAgents(call, confirm)).rejects.toThrow(/gw-2: Filter aktiv/);
		expect(call).toHaveBeenCalledTimes(1);
		expect(confirm).not.toHaveBeenCalled();
	});

	it("forces a gone agent only after confirmation", async () => {
		const call = vi
			.fn()
			.mockResolvedValueOnce({ agents: [agent(3, "Filter aktiv", true)] })
			.mockResolvedValueOnce({ agents: { deleted: [3], errors: [] } });
		await deleteWithBoundAgents(call, () => true);
		expect(call.mock.calls[1][0]).toEqual({ deleteBoundAgents: true, forceAgentIds: [3] });

		const declined = vi.fn().mockResolvedValueOnce({ agents: [agent(3, "Filter aktiv", true)] });
		await expect(deleteWithBoundAgents(declined, () => false)).rejects.toThrow(/Filter aktiv/);
		expect(declined).toHaveBeenCalledTimes(1);
	});

	it("without bound agents it is a plain delete; agent errors after the delete are surfaced", async () => {
		const call = vi.fn().mockResolvedValueOnce({ agents: [] }).mockResolvedValueOnce({ deleted: true });
		await deleteWithBoundAgents(call, () => true);
		expect(call.mock.calls[1][0]).toEqual({ deleteBoundAgents: false, forceAgentIds: [] });

		const failing = vi
			.fn()
			.mockResolvedValueOnce({ agents: [agent(4, null)] })
			.mockResolvedValueOnce({ agents: { deleted: [], errors: [{ id: 4, name: "gw-4", error: "db down" }] } });
		await expect(deleteWithBoundAgents(failing, () => true)).rejects.toThrow(/gw-4: db down/);
	});
});
