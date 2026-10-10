import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { PeerSparkline } from "./PeerSparkline";

describe("PeerSparkline", () => {
	afterEach(() => cleanup());

	it("draws a single sample as a flat line instead of NaN paths", () => {
		const { container } = render(<PeerSparkline data={[2048]} />);
		const paths = Array.from(container.querySelectorAll("path")).map((p) => p.getAttribute("d") ?? "");
		expect(paths).toHaveLength(2);
		for (const d of paths) expect(d).not.toContain("NaN");
		// spans the full width
		expect(paths[1]).toMatch(/^M 0\.0,[\d.]+ L 200\.0,[\d.]+$/);
	});

	it("still draws several samples across the width", () => {
		const { container } = render(<PeerSparkline data={[0, 1024, 4096]} />);
		const line = container.querySelectorAll("path")[1].getAttribute("d") ?? "";
		expect(line).not.toContain("NaN");
		expect(line.startsWith("M 0.0,")).toBe(true);
		expect(line).toContain("L 200.0,");
	});
});
