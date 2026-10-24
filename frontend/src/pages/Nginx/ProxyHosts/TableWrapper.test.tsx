import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import TableWrapper from "./TableWrapper";

const hostsMock = vi.fn();
const toggleMock = vi.fn();
const showErrorMock = vi.fn();
const showSuccessMock = vi.fn();
const tableProps: { current: any } = { current: null };

vi.mock("src/hooks", () => ({ useProxyHosts: () => hostsMock() }));
vi.mock("src/api/backend", () => ({
	deleteProxyHost: vi.fn(),
	toggleProxyHost: (...args: unknown[]) => toggleMock(...args),
}));
vi.mock("src/notifications", () => ({
	showError: (...args: unknown[]) => showErrorMock(...args),
	showObjectSuccess: (...args: unknown[]) => showSuccessMock(...args),
}));
vi.mock("src/modals", () => ({
	showDeleteConfirmModal: vi.fn(),
	showHelpModal: vi.fn(),
	showProxyHostModal: vi.fn(),
}));
vi.mock("src/components", () => ({
	Button: ({ children, onClick }: any) => (
		<button type="button" onClick={onClick}>
			{children}
		</button>
	),
	HasPermission: ({ children }: any) => <>{children}</>,
	LoadingPage: () => null,
}));
vi.mock("src/locale", () => ({ T: ({ id }: { id: string }) => <>{id}</> }));
vi.mock("./Table", () => ({
	default: (props: any) => {
		tableProps.current = props;
		return null;
	},
}));

const host = (id: number, domain: string) => ({
	id,
	domainNames: [domain],
	forwardHost: "10.0.0.1",
	forwardPort: 80,
	enabled: true,
});

const renderWrapper = () => {
	const queryClient = new QueryClient();
	const invalidate = vi.spyOn(queryClient, "invalidateQueries");
	const utils = render(
		<QueryClientProvider client={queryClient}>
			<TableWrapper />
		</QueryClientProvider>,
	);
	return { ...utils, queryClient, invalidate };
};

describe("ProxyHosts TableWrapper", () => {
	beforeEach(() => {
		hostsMock.mockReset();
		toggleMock.mockReset();
		showErrorMock.mockReset();
		showSuccessMock.mockReset();
		tableProps.current = null;
	});
	afterEach(() => cleanup());

	it("shows an error and refetches when toggling fails", async () => {
		hostsMock.mockReturnValue({ isLoading: false, isError: false, data: [host(1, "a.example")] });
		toggleMock.mockRejectedValue(new Error("Permission denied"));
		const { invalidate } = renderWrapper();

		await act(async () => {
			await tableProps.current.onDisableToggle(1, false);
		});

		expect(showErrorMock).toHaveBeenCalledWith("Permission denied");
		expect(showSuccessMock).not.toHaveBeenCalled();
		expect(invalidate).toHaveBeenCalledWith({ queryKey: ["proxy-hosts"] });
		expect(invalidate).toHaveBeenCalledWith({ queryKey: ["proxy-host", 1] });
	});

	it("drops a stale search filter once the list is empty", () => {
		hostsMock.mockReturnValue({ isLoading: false, isError: false, data: [host(1, "a.example")] });
		const { rerender, queryClient } = renderWrapper();
		fireEvent.change(screen.getByRole("textbox"), { target: { value: "a.ex" } });
		expect(tableProps.current.isFiltered).toBe(true);

		hostsMock.mockReturnValue({ isLoading: false, isError: false, data: [] });
		rerender(
			<QueryClientProvider client={queryClient}>
				<TableWrapper />
			</QueryClientProvider>,
		);
		// not filtered any more, so EmptyData renders its add button again
		expect(tableProps.current.isFiltered).toBe(false);
	});
});
