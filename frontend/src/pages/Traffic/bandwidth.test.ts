import type { PeerBandwidth } from "src/api/backend";
import { bandwidthRefreshMs } from "src/hooks/useWireGuardBandwidth";
import { describe, expect, it } from "vitest";
import { PEER_COLORS, currentRates, isLinkActive, peerColorMap, sortByVolume } from "./bandwidth";

const peer = (id: string, samples: Array<[number, number]>): PeerBandwidth => ({
	id,
	name: id,
	history: samples.map(([rx, tx], i) => ({ ts: i, rx, tx })),
});

describe("traffic bandwidth helpers", () => {
	it("sums the newest sample of each peer", () => {
		expect(
			currentRates([
				peer("a", [
					[1, 2],
					[10, 20],
				]),
				peer("b", [[5, 5]]),
				peer("c", []),
			]),
		).toEqual({
			rx: 15,
			tx: 25,
		});
	});

	it("sorts peers by total volume without mutating the input", () => {
		const input = [peer("small", [[1, 1]]), peer("big", [[100, 100]]), peer("mid", [[10, 10]])];
		expect(sortByVolume(input).map((p) => p.id)).toEqual(["big", "mid", "small"]);
		expect(input[0].id).toBe("small");
	});

	it("gives each peer a colour that does not depend on its rank", () => {
		const a = peerColorMap(["b", "a", "c", "a"]);
		const b = peerColorMap(["c", "b", "a"]);
		expect(a.get("a")).toBe(PEER_COLORS[0]);
		expect(a.get("b")).toBe(PEER_COLORS[1]);
		expect([...a.entries()]).toEqual([...b.entries()]);
	});

	it("keeps link colours independent of history-only ids and range", () => {
		const links = ["l1", "l2", "l3", "l4", "l5", "l6"];
		const live = peerColorMap(links, ["l1", "l2", "l3", "l4"]);
		// 30d range: a deleted peer "gone" is still in the history and charted
		const month = peerColorMap(links, ["gone", "l1", "l2", "l3", "l4", "l5"]);
		for (const id of links) expect(month.get(id)).toBe(live.get(id));
		const shown = ["gone", "l1", "l2", "l3", "l4", "l5"].map((id) => month.get(id));
		expect(new Set(shown).size).toBe(shown.length);
	});

	it("never repeats a colour among the charted peers, even with more links than colours", () => {
		const links = Array.from({ length: PEER_COLORS.length + 3 }, (_, i) => `p${String(i).padStart(2, "0")}`);
		const shown = [links[0], links[PEER_COLORS.length], links[1], links[PEER_COLORS.length + 1], "x", "y"];
		const m = peerColorMap(links, shown);
		const colors = shown.map((id) => m.get(id));
		expect(new Set(colors).size).toBe(shown.length);
		// the first id keeps its base colour
		expect(m.get(links[0])).toBe(PEER_COLORS[0]);
	});

	it("polls history ranges far less often than live", () => {
		expect(bandwidthRefreshMs("live")).toBe(10_000);
		expect(bandwidthRefreshMs("24h")).toBeGreaterThanOrEqual(60_000);
		expect(bandwidthRefreshMs("30d")).toBeGreaterThan(bandwidthRefreshMs("24h"));
		expect(bandwidthRefreshMs("12m")).toBeGreaterThan(bandwidthRefreshMs("30d"));
	});
});

describe("isLinkActive", () => {
	const now = 1_000_000;
	it("is true for an active link with a fresh handshake", () => {
		expect(isLinkActive({ active: true, latestHandshake: now - 10 }, now)).toBe(true);
	});
	it("is false for an active link whose handshake is past the window (stale poll data)", () => {
		expect(isLinkActive({ active: true, latestHandshake: now - 200 }, now)).toBe(false);
	});
	it("is false for an inactive link even with a fresh handshake", () => {
		expect(isLinkActive({ active: false, latestHandshake: now - 10 }, now)).toBe(false);
	});
	it("is false without any handshake", () => {
		expect(isLinkActive({ active: true, latestHandshake: 0 }, now)).toBe(false);
	});
});
