import type { DirectLinkSideStatus } from "src/api/backend";
import { describe, expect, it } from "vitest";
import { directEdge, directEdgeRtt, directEdgeState } from "./topology";

const side = (over: Partial<DirectLinkSideStatus> = {}): DirectLinkSideStatus => ({
	publicKeyKnown: true,
	seen: 1,
	stale: false,
	up: true,
	path: "direct",
	handshakeAge: 20,
	rttMs: 61,
	...over,
});

describe("directEdgeState", () => {
	it("is direct when both sides are up and direct", () => {
		expect(directEdgeState({ enabled: true, blocked: null, statusA: side(), statusB: side() })).toBe("direct");
	});
	it("is partly when only one side is direct", () => {
		expect(directEdgeState({ enabled: true, blocked: null, statusA: side(), statusB: side({ path: "hub" }) })).toBe(
			"partly",
		);
	});
	it("is hub when both sides report in but none routes direct", () => {
		expect(
			directEdgeState({
				enabled: true,
				blocked: null,
				statusA: side({ path: "hub" }),
				statusB: side({ path: "hub" }),
			}),
		).toBe("hub");
		// a stale or down side is "waiting" (same as the badge on the Freigaben page)
		expect(
			directEdgeState({
				enabled: true,
				blocked: null,
				statusA: side({ stale: true }),
				statusB: side({ up: false }),
			}),
		).toBe("waiting");
	});
	it("is off when disabled, blocked when blocked, waiting while a side has no key / is stale / down", () => {
		expect(directEdgeState({ enabled: false, blocked: null, statusA: side(), statusB: side() })).toBe("off");
		expect(directEdgeState({ enabled: true, blocked: "sites-isolated", statusA: side(), statusB: side() })).toBe(
			"blocked",
		);
		expect(
			directEdgeState({
				enabled: true,
				blocked: null,
				statusA: side({ publicKeyKnown: false }),
				statusB: side(),
			}),
		).toBe("waiting");
	});
	it("takes the round-trip time only from a side on the direct path", () => {
		expect(directEdgeRtt({ statusA: side({ path: "hub", rttMs: 5 }), statusB: side({ rttMs: 61 }) })).toBe(61);
		expect(directEdgeRtt({ statusA: side({ path: "hub" }), statusB: side({ path: "hub" }) })).toBe(null);
	});
});

describe("directEdge", () => {
	it("bends away from the hub and starts/ends at the two cards", () => {
		const hub = { x: 500, y: 280 };
		const { d, mid } = directEdge({ x: 200, y: 100 }, { x: 800, y: 100 }, hub);
		expect(d.startsWith("M 200 100 Q")).toBe(true);
		expect(d.endsWith("800 100")).toBe(true);
		// both cards above the hub → the curve's middle lies further up than the straight line
		expect(mid.y).toBeLessThan(100);
		expect(mid.x).toBeCloseTo(500);
	});
});
