import { describe, expect, it } from "vitest";
import { hubChangeCount, renameCascadeProblems, restoreSyncProblems } from "./restoreSync";

describe("restoreSyncProblems", () => {
	it("is empty when hub and agents synced", () => {
		expect(
			restoreSyncProblems({
				hubSync: { wg0: { synced: true, changes: [] } },
				agentSync: [{ agentId: 1, name: "site-a", changed: true }],
			}),
		).toEqual({ hub: [], agentError: null, agentsSkipped: [], agentsFailed: [], renameErrors: [] });
	});

	it("reports per-interface and whole-hub failures", () => {
		expect(
			restoreSyncProblems({
				hubSync: { wg0: { synced: true }, wg1: { synced: false, reason: "wg syncconf failed" } },
				agentSync: null,
			}).hub,
		).toEqual(["wg1: wg syncconf failed"]);
		expect(
			restoreSyncProblems({ hubSync: { synced: false, reason: "getStatus failed" }, agentSync: null }).hub,
		).toEqual(["getStatus failed"]);
	});

	it("reports a fleet-wide agent error and skipped agents", () => {
		expect(restoreSyncProblems({ hubSync: null, agentSync: { error: "db down" } }).agentError).toBe("db down");
		expect(
			restoreSyncProblems({
				hubSync: null,
				agentSync: [
					{ agentId: 1, name: "site-a", changed: false, reason: "no link" },
					{ agentId: 2, name: "site-b", changed: false },
				],
			}).agentsSkipped,
		).toEqual(["site-a (no link)"]);
	});

	it("reports a per-agent sync failure ({changed:false, error}) as failed, not as success", () => {
		const r = restoreSyncProblems({
			hubSync: null,
			agentSync: [
				{ agentId: 1, name: "site-a", changed: false, error: "assertCIDR: bad net" },
				{ agentId: 2, name: "site-b", changed: true },
			],
		});
		expect(r.agentsFailed).toEqual(["site-a (assertCIDR: bad net)"]);
		expect(r.agentsSkipped).toEqual([]);
	});

	it("reports failed link-rename cascade steps", () => {
		expect(renameCascadeProblems(null)).toEqual([]);
		expect(renameCascadeProblems({ renames: [], errors: [], rolledBack: false })).toEqual([]);
		const r = restoreSyncProblems({
			hubSync: null,
			agentSync: null,
			renameCascade: {
				renames: [{ oldName: "A", newName: "B" }],
				errors: [{ from: "A", to: "B", error: "db down" }],
				rolledBack: false,
			},
		});
		expect(r.renameErrors).toEqual(["A → B: db down"]);
	});

	it("counts hub peer changes across the per-interface map", () => {
		expect(hubChangeCount(null)).toBe(0);
		expect(hubChangeCount({ synced: false, reason: "getStatus failed" })).toBe(0);
		expect(
			hubChangeCount({
				wg0: { synced: true, changes: [{ peer: "a", allowedIPs: [] }] },
				wg1: {
					synced: true,
					changes: [
						{ peer: "b", allowedIPs: [] },
						{ peer: "c", allowedIPs: [] },
					],
				},
				wg2: { synced: false, reason: "no-conf-file" },
			}),
		).toBe(3);
	});
});
