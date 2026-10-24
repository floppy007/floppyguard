import { beforeEach, describe, expect, it, vi } from "vitest";

const del = vi.fn();
vi.mock("./base", () => ({ del: (...args: unknown[]) => del(...args), get: vi.fn(), post: vi.fn(), put: vi.fn() }));

const { deleteAgentGuarded, isAgentGone, AGENT_FORCE_DELETE_OFFLINE_S } = await import("./agents");
const { hostNginxError } = await import("src/components/Table/Formatter/HostStatusFormatter");

const GUARD =
	"Agent filtert noch („nur Freigaben“): erst auf „offen“ umstellen und warten, bis der Agent den Filter als gesetzt meldet";
const now = () => Math.floor(Date.now() / 1000);

describe("deleteAgentGuarded", () => {
	beforeEach(() => del.mockReset());

	it("deletes normally without asking twice", async () => {
		del.mockResolvedValueOnce({ deleted: true });
		const confirm = vi.fn(() => true);
		await deleteAgentGuarded({ id: 3, lastSeen: now() }, confirm);
		expect(del).toHaveBeenCalledTimes(1);
		expect(del.mock.calls[0][0]).toEqual({ url: "agents/3", params: undefined });
		expect(confirm).not.toHaveBeenCalled();
	});

	it("forces the delete of a gone agent after a second confirmation", async () => {
		del.mockRejectedValueOnce(new Error(GUARD)).mockResolvedValueOnce({ deleted: true });
		const confirm = vi.fn(() => true);
		await deleteAgentGuarded({ id: 4, lastSeen: now() - AGENT_FORCE_DELETE_OFFLINE_S - 5 }, confirm);
		expect(confirm).toHaveBeenCalledTimes(1);
		expect(del.mock.calls[1][0]).toEqual({ url: "agents/4", params: { force: "1" } });
	});

	it("does not force when the admin declines", async () => {
		del.mockRejectedValueOnce(new Error(GUARD));
		await expect(deleteAgentGuarded({ id: 5, lastSeen: null }, () => false)).rejects.toThrow(/als gesetzt/);
		expect(del).toHaveBeenCalledTimes(1);
	});

	it("does not force an agent that still reports in", async () => {
		del.mockRejectedValueOnce(new Error(GUARD));
		const confirm = vi.fn(() => true);
		await expect(deleteAgentGuarded({ id: 5, lastSeen: now() }, confirm)).rejects.toThrow(/als gesetzt/);
		expect(confirm).not.toHaveBeenCalled();
		expect(del).toHaveBeenCalledTimes(1);
	});

	it("treats an already-deleted agent as deleted (retry of a half-done delete)", async () => {
		del.mockRejectedValueOnce(new Error("Not Found - 5"));
		const confirm = vi.fn(() => true);
		await deleteAgentGuarded({ id: 5, lastSeen: null }, confirm);
		expect(confirm).not.toHaveBeenCalled();
		expect(del).toHaveBeenCalledTimes(1);
	});

	it("does not force on any other error", async () => {
		del.mockRejectedValueOnce(new Error("HTTP 502 Bad Gateway"));
		const confirm = vi.fn(() => true);
		await expect(deleteAgentGuarded({ id: 5, lastSeen: null }, confirm)).rejects.toThrow(/502/);
		expect(confirm).not.toHaveBeenCalled();
		expect(del).toHaveBeenCalledTimes(1);
	});

	it("isAgentGone", () => {
		expect(isAgentGone({ lastSeen: null })).toBe(true);
		expect(isAgentGone({ lastSeen: now() - 10 })).toBe(false);
	});
});

describe("hostNginxError", () => {
	it("reads nginx_err from camelized or raw meta", () => {
		expect(hostNginxError({ nginxErr: "bad", nginxOnline: true })).toBe("bad");
		expect(hostNginxError({ nginx_err: "bad" })).toBe("bad");
		expect(hostNginxError({ nginxErr: null })).toBeNull();
		expect(hostNginxError(undefined)).toBeNull();
	});
});
