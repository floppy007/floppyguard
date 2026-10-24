import { cleanup, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { changeLocale } from "src/locale/IntlProvider";
import { afterEach, describe, expect, it, vi } from "vitest";
import Dashboard from "./index";

vi.mock("src/hooks", () => ({
	useCheckVersion: () => ({ data: undefined }),
	useFail2BanStatus: () => ({ data: { available: false, jails: [] }, isLoading: false }),
	useHostReport: () => ({ data: { proxy: 3, redirection: 2, stream: 1, dead: 4 } }),
	useProxyHosts: () => ({ data: undefined }),
	useUnbanIp: () => ({ mutate: vi.fn(), isPending: false, isError: false }),
	useUser: () => ({ data: { roles: ["admin"], permissions: {} } }),
	useWireGuardBandwidth: () => ({ data: [] }),
	useWireGuardStatus: () => ({
		data: {
			hub: { name: "wg0", addresses: ["10.10.0.1/24"] },
			summary: {
				activePeers: 1,
				totalPeers: 2,
				interfaceCount: 1,
				activeInterfaceCount: 1,
				linkCount: 3,
				siteLinkCount: 2,
				hubLinkCount: 0,
				clientLinkCount: 1,
				peerNetworkCount: 1,
				privateRouteCount: 5,
				wireguardRouteCount: 2,
				totalRxBytes: 0,
				totalTxBytes: 0,
			},
			nextActions: [],
			links: [
				{
					id: "wg0:pk",
					name: "Site A",
					type: "site-to-site",
					interfaceName: "wg0",
					latestHandshake: null,
					rxBytes: 0,
					txBytes: 0,
				},
			],
			routes: { missingReturnRoutes: [], natCandidates: [] },
		},
	}),
}));

vi.mock("src/components", () => ({
	HasPermission: ({ children }: { children: ReactNode }) => <>{children}</>,
	DonutGauge: () => null,
	PeerSparkline: () => null,
}));

afterEach(() => {
	cleanup();
	changeLocale("en");
});

const renderDashboard = () =>
	render(
		<MemoryRouter>
			<Dashboard />
		</MemoryRouter>,
	);

describe("Dashboard", () => {
	it("renders the stat cards from locale keys (no hard-coded English)", () => {
		changeLocale("de");
		renderDashboard();
		const text = document.body.textContent ?? "";
		expect(text).toContain("Aktive Peers");
		expect(text).toContain("wg0 aktiv");
		expect(text).toContain("2 Site · 1 Client");
		expect(text).toContain("1 Peer-Netz · 5 private Routen");
		expect(text).toContain("2 Site · 0 Hub · 1 Client");
		expect(text).toContain("TCP-Weiterleitung");
		expect(text).toContain("Alle in Betrieb");
		expect(screen.getByText("Redirection Hosts")).toBeTruthy();
		for (const english of [
			"Active Peers",
			"All operational",
			"TCP forwarding",
			"peer networks",
			"private routes",
		]) {
			expect(text).not.toContain(english);
		}
	});

	it("keeps the English wording", () => {
		renderDashboard();
		const text = document.body.textContent ?? "";
		expect(text).toContain("Active Peers");
		expect(text).toContain("1 peer network · 5 private routes");
		expect(text).toContain("2 site · 0 hub · 1 client");
		expect(text).toContain("site-to-site · wg0 · handshake");
		expect(text).toContain("404 Not Found");
	});
});
