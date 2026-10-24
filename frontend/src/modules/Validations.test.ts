import { describe, expect, it } from "vitest";
import { validateDomains } from "./Validations";

describe("validateDomains", () => {
	it("allows exactly maxDomains entries", () => {
		expect(validateDomains(false, 2)(["a.com", "b.com"])).toBeUndefined();
	});

	it("rejects more than maxDomains entries", () => {
		expect(validateDomains(false, 2)(["a.com", "b.com", "c.com"])).toBeTypeOf("string");
	});

	it("has no cap without maxDomains", () => {
		expect(validateDomains(false)(["a.com", "b.com", "c.com"])).toBeUndefined();
	});
});
