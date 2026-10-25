import type { DirectLinkSideStatus } from "src/api/backend";
import { describe, expect, it } from "vitest";
import { directEdge, directEdgeState } from "./topology";

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
	it("is hub when no side is direct (stale counts as not direct)", () => {
		expect(
			directEdgeState({
				enabled: true,
				blocked: null,
				statusA: side({ stale: true }),
				statusB: side({ up: false }),
			}),
		).toBe("hub");
	});
	it("is off when disabled or blocked", () => {
		expect(directEdgeState({ enabled: false, blocked: null, statusA: side(), statusB: side() })).toBe("off");
		expect(directEdgeState({ enabled: true, blocked: "sites-isolated", statusA: side(), statusB: side() })).toBe(
			"off",
		);
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
