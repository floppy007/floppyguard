import { describe, expect, it } from "vitest";
import { relativeTime, relativeTimeOrDash } from "./relativeTime";

describe("relativeTime", () => {
	it("goes past hours into days", () => {
		const now = 1_000_000_000;
		expect(relativeTime(now - 7 * 86400, now)).toMatch(/7 days ago/);
	});

	it("never formats the future", () => {
		expect(relativeTime(2000, 1000)).toMatch(/now/);
	});

	it("relativeTimeOrDash shows a dash without a timestamp", () => {
		expect(relativeTimeOrDash(0)).toBe("—");
		expect(relativeTimeOrDash(null)).toBe("—");
		expect(relativeTimeOrDash(undefined)).toBe("—");
	});
});
