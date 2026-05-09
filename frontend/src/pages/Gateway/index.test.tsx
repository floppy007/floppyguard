import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Gateway from "./index";

const statusMock = vi.fn();

vi.mock("src/hooks", () => ({
	useWireGuardStatus: () => statusMock(),
}));

const buildStatus = () => ({
	available: true,
	mode: "metadata-write" as const,
	hub: null,
	interfaces: [],
	links: [
		{
			id: "wg1:site-peer-key",
			interfaceName: "wg1",
			type: "site-to-site" as const,
			name: "site-a",
			peerPublicKey: "site-peer-key",
			remoteEndpoint: null,
			allowedIps: ["192.168.200.0/24"],
			tunnelAddresses: [],
			exportedNetworks: [],
			importedNetworks: ["192.168.200.0/24"],
			latestHandshake: 0,
			rxBytes: 1,
			txBytes: 2,
			active: false,
			hasMetadata: true,
			returnPathMode: "unknown" as const,
			remoteManagementMode: "unknown" as const,
			planIntent: "site-to-site",
			planState: "validate",
			notes: [],
			warnings: ["nat-likely-needed", "return-path-mode-undefined"],
			nextActions: ["define-return-path-mode", "review-nat-requirements"],
		},
	],
	routes: {
		all: [],
		wireguard: [],
		privateRoutes: [],
		staticRoutes: [],
		missingReturnRoutes: [{ network: "192.168.200.0/24", reason: "network-not-found-in-live-routes" }],
		natCandidates: [{ network: "192.168.200.0/24", reason: "return-path-unclear" }],
		conflicts: [],
		splitTunnelCandidates: [],
		observations: ["Some imported networks are not visible as live WireGuard routes yet"],
	},
	topology: {
		exportedNetworks: [],
		importedNetworks: ["192.168.200.0/24"],
		siteLinks: ["wg1:site-peer-key"],
		clientLinks: [],
		hubLinks: [],
	},
	capabilities: undefined,
	summary: {
		interfaceCount: 1,
		activeInterfaceCount: 0,
		totalPeers: 1,
		activePeers: 0,
		totalRxBytes: 1,
		totalTxBytes: 2,
		peerNetworkCount: 1,
		wireguardRouteCount: 0,
		privateRouteCount: 0,
		linkCount: 1,
		siteLinkCount: 1,
		hubLinkCount: 0,
		clientLinkCount: 0,
	},
	warnings: ["Interface wg1 needs review"],
	nextActions: ["define-return-path-mode"],
});

describe("Gateway page", () => {
	beforeEach(() => {
		statusMock.mockReturnValue({
			data: buildStatus(),
			isLoading: false,
			isError: false,
			error: null,
		});
	});

	it("renders link warnings and next actions", () => {
		render(<Gateway />);
		expect(screen.getByText(/NAT likely needed/)).toBeTruthy();
		expect(screen.getByText(/Define return path mode/)).toBeTruthy();
	});

	it("renders reachability badge derived from route hints", () => {
		render(<Gateway />);
		expect(screen.getAllByText("Return path missing").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Validate").length).toBeGreaterThan(0);
	});
});
