import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import EasyModal from "ez-modal-react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({ updateAuth: vi.fn() }));
vi.mock("src/api/backend", async (importOriginal) => ({
	...(await importOriginal<typeof import("src/api/backend")>()),
	...api,
}));

const auth = vi.hoisted(() => ({ logout: vi.fn() }));
vi.mock("src/context", async (importOriginal) => ({
	...(await importOriginal<typeof import("src/context")>()),
	useAuthState: () => ({ authenticated: true, login: vi.fn(), loginAs: vi.fn(), logout: auth.logout }),
}));

const notify = vi.hoisted(() => ({ showSuccess: vi.fn() }));
vi.mock("src/notifications", async (importOriginal) => ({
	...(await importOriginal<typeof import("src/notifications")>()),
	...notify,
}));

const { showChangePasswordModal } = await import("./ChangePasswordModal");

const submit = async () => {
	render(<EasyModal.Provider />);
	act(() => showChangePasswordModal("me"));
	const current = await screen.findByPlaceholderText(/Current Password|Aktuelles Passwort/i);
	fireEvent.change(current, { target: { value: "oldpass123" } });
	fireEvent.change(screen.getByPlaceholderText(/^(New Password|Neues Passwor)/i), {
		target: { value: "newpass123" },
	});
	fireEvent.change(screen.getByPlaceholderText(/Confirm Password|Passwort bestätigen/i), {
		target: { value: "newpass123" },
	});
	await act(async () => fireEvent.submit(current.closest("form") as HTMLFormElement));
};

describe("ChangePasswordModal own password", () => {
	beforeEach(() => vi.clearAllMocks());
	afterEach(() => cleanup());

	it("logs the session out with an explanation after a successful change (old token is revoked)", async () => {
		api.updateAuth.mockResolvedValue(true);
		await submit();
		await waitFor(() => expect(auth.logout).toHaveBeenCalledTimes(1));
		expect(api.updateAuth).toHaveBeenCalledWith("me", "newpass123", "oldpass123");
		expect(notify.showSuccess).toHaveBeenCalledTimes(1);
	});

	it("stays logged in and shows the error when the change fails", async () => {
		api.updateAuth.mockRejectedValue(new Error("Invalid password"));
		await submit();
		await screen.findByText("Invalid password");
		expect(auth.logout).not.toHaveBeenCalled();
		expect(notify.showSuccess).not.toHaveBeenCalled();
	});
});
