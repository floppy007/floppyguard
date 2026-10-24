// Proxy check (agent-ingress.js): totals the list views use instead of one
// full ingress fetch per agent.
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const { ingressRuleCounts } = await import("./agent-ingress.js");

describe("Freigaben check: rule counts", () => {
	it("counts all and enabled rules", () => {
		const rules = [{ enabled: true }, { enabled: false }, { enabled: true }];
		assert.deepEqual(ingressRuleCounts(rules), { rule_count: 3, active_rule_count: 2 });
	});

	it("is zero for an agent without rules", () => {
		assert.deepEqual(ingressRuleCounts([]), { rule_count: 0, active_rule_count: 0 });
	});
});
