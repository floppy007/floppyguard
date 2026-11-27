import { describe, expect, it } from "vitest";
import { buildInstallOneliner } from "./agents";

describe("buildInstallOneliner", () => {
	it("sends the registration token as header, not in the URL", () => {
		const cmd = buildInstallOneliner("ab12", "https://hub.example.com", "http://10.10.0.1:81");
		expect(cmd).toBe(
			'curl -fsSL -H "X-Reg-Token: ab12" "https://hub.example.com/api/agent/install?public_url=https%3A%2F%2Fhub.example.com&tunnel_url=http%3A%2F%2F10.10.0.1%3A81" | bash',
		);
		expect(cmd).not.toContain("reg_token=");
	});
});
