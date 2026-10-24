import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Exercises the real ./base wire format for the 2FA endpoints.
vi.mock("src/modules/AuthStore", () => ({ default: { token: { token: "t" }, clear: vi.fn() } }));

const { disable2FA, start2FASetup } = await import("./twoFactor");
const { del } = await import("./base");

const jsonResponse = (body: unknown, status = 200) =>
	new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("2FA wire format", () => {
	let fetchMock: ReturnType<typeof vi.fn>;
	beforeEach(() => {
		fetchMock = vi.fn(async () => jsonResponse(true));
		vi.stubGlobal("fetch", fetchMock);
	});
	afterEach(() => vi.unstubAllGlobals());

	it("sends the disable code in the DELETE body, not the URL", async () => {
		await disable2FA("me", "123456");
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/api/users/me/2fa");
		expect(url).not.toContain("123456");
		expect(init.method).toBe("DELETE");
		expect(init.headers["Content-Type"]).toBe("application/json");
		expect(JSON.parse(init.body)).toEqual({ code: "123456" });
	});

	it("keeps body-less DELETEs unchanged", async () => {
		await del({ url: "users/5" });
		const [, init] = fetchMock.mock.calls[0];
		expect(init.body).toBeUndefined();
		expect(init.headers["Content-Type"]).toBeUndefined();
	});

	it("camelizes qr_data_url from the setup response", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse({ secret: "S", otpauth_url: "otpauth://totp/x", qr_data_url: "data:image/png;base64,AA==" }),
		);
		const res = await start2FASetup("me");
		expect(res.qrDataUrl).toBe("data:image/png;base64,AA==");
	});
});
