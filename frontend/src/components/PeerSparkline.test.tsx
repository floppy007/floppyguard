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

describe("PeerSparkline gradient id", () => {
	afterEach(() => cleanup());

	it("keeps the same gradient id across re-renders", () => {
		const { container, rerender } = render(<PeerSparkline data={[0, 1024]} />);
		const first = container.querySelector("linearGradient")?.getAttribute("id");
		rerender(<PeerSparkline data={[0, 1024, 2048]} />);
		const second = container.querySelector("linearGradient")?.getAttribute("id");
		expect(first).toBeTruthy();
		expect(second).toBe(first);
		expect(container.querySelector("path")?.getAttribute("fill")).toBe(`url(#${first})`);
	});
});
