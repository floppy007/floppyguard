import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import EasyModal from "ez-modal-react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
	get2FAStatus: vi.fn(),
	start2FASetup: vi.fn(),
}));
vi.mock("src/api/backend", async (importOriginal) => ({
	...(await importOriginal<typeof import("src/api/backend")>()),
	...api,
}));

const { showTwoFactorModal } = await import("./TwoFactorModal");

const PNG = "data:image/png;base64,iVBORw0KGgo=";

const openSetup = async (qrDataUrl: string) => {
	api.get2FAStatus.mockResolvedValue({ enabled: false, backupCodesRemaining: 0 });
	api.start2FASetup.mockResolvedValue({ secret: "JBSWY3DPEHPK3PXP", otpauthUrl: "otpauth://totp/x", qrDataUrl });
	render(<EasyModal.Provider />);
	act(() => showTwoFactorModal("me"));
	// status step: "Enable 2FA" (not the header's close button)
	const start = await screen.findByRole("button", { name: /2FA aktivieren|Enable Two-Factor/i });
	await act(async () => fireEvent.click(start));
	await screen.findByDisplayValue("JBSWY3DPEHPK3PXP");
};

describe("TwoFactorModal setup QR", () => {
	beforeEach(() => vi.clearAllMocks());
	afterEach(() => cleanup());

	it("renders the backend-rendered QR data URL", async () => {
		await openSetup(PNG);
		const img = screen.getByAltText("QR Code") as HTMLImageElement;
		expect(img.getAttribute("src")).toBe(PNG);
	});

	it("never renders a non-data URL (e.g. a third-party QR service)", async () => {
		await openSetup("https://api.qrserver.com/v1/create-qr-code/?data=otpauth%3A%2F%2Ftotp");
		expect(screen.queryByAltText("QR Code")).toBeNull();
		expect(document.querySelector("img[src^='http']")).toBeNull();
	});
});
