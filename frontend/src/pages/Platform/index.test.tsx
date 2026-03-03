import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Platform from "./index";

const hostReportMock = vi.fn();
const statusMock = vi.fn();
const navigateMock = vi.fn();

vi.mock("src/hooks", () => ({
	useHostReport: () => hostReportMock(),
	useWireGuardStatus: () => statusMock(),
}));

vi.mock("react-router-dom", async () => {
	const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
	return {
		...actual,
		useNavigate: () => navigateMock,
	};
});

const buildStatus = () => ({
	available: true,
	mode: "metadata-write" as const,
	hub: {
		name: "wg0",
		addresses: ["10.0.0.1/24"],
	},
	interfaces: [],
	links: [
		{
			id: "wg0:peer-public-key",
			interfaceName: "wg0",
			type: "client" as const,
			name: "road-warrior",
			peerPublicKey: "peer-public-key",
			remoteEndpoint: "peer.example.com:51820",
			allowedIps: ["192.168.50.0/24"],
			tunnelAddresses: [],
			exportedNetworks: [],
			importedNetworks: ["192.168.50.0/24"],
			latestHandshake: 1000,
			rxBytes: 10,
			txBytes: 20,
			active: true,
			hasMetadata: false,
			returnPathMode: "routed" as const,
			remoteManagementMode: "none" as const,
			planIntent: "client",
			planState: "ready",
			notes: [],
			warnings: [],
			nextActions: [],
		},
		{
			id: "wg1:site-peer-key",
			interfaceName: "wg1",
			type: "site-to-site" as const,
			name: "site-a",
			peerPublicKey: "site-peer-key",
			remoteEndpoint: null,
			allowedIps: ["192.168.200.0/24"],
			tunnelAddresses: [],
			exportedNetworks: ["10.20.0.0/24"],
			importedNetworks: ["192.168.200.0/24"],
			latestHandshake: 0,
			rxBytes: 1,
			txBytes: 2,
			active: false,
			hasMetadata: true,
			returnPathMode: "static-route" as const,
			remoteManagementMode: "ssh" as const,
			planIntent: "site-to-site",
			planState: "validate",
			notes: [],
			warnings: ["imported-network-missing-live-route"],
			nextActions: ["fix-return-path"],
		},
	],
	routes: {
		all: [],
		wireguard: [],
		privateRoutes: [],
		staticRoutes: [],
		missingReturnRoutes: [{ network: "192.168.200.0/24", reason: "network-not-found-in-live-routes" }],
		natCandidates: [],
		conflicts: [],
		splitTunnelCandidates: [],
		observations: [],
	},
	topology: {
		exportedNetworks: ["10.20.0.0/24"],
		importedNetworks: ["192.168.50.0/24", "192.168.200.0/24"],
		siteLinks: ["wg1:site-peer-key"],
		clientLinks: ["wg0:peer-public-key"],
		hubLinks: [],
	},
	capabilities: {
		mode: "metadata-write" as const,
		supports: {
			peerCrud: false,
			interfaceCrud: false,
			configDownload: false,
			shareLinks: false,
			wizardPlanning: true,
			metadataCrud: true,
			remoteSsh: false,
			remoteAgent: false,
		},
	},
	summary: {
		interfaceCount: 2,
		activeInterfaceCount: 1,
		totalPeers: 2,
		activePeers: 1,
		totalRxBytes: 11,
		totalTxBytes: 22,
		peerNetworkCount: 2,
		wireguardRouteCount: 0,
		privateRouteCount: 0,
		linkCount: 2,
		siteLinkCount: 1,
		hubLinkCount: 0,
		clientLinkCount: 1,
	},
	warnings: ["Interface wg1 needs review"],
	nextActions: ["fix-return-path"],
});

describe("Platform page", () => {
	beforeEach(() => {
		hostReportMock.mockReturnValue({ data: { proxy: 3 } });
		statusMock.mockReturnValue({ data: buildStatus() });
	});

	it("renders mixed client and site links with their respective runtime labels", () => {
		render(<Platform />);
		expect(screen.getByText("road-warrior")).toBeTruthy();
		expect(screen.getByText("site-a")).toBeTruthy();
		expect(screen.getByText(/client · wg0 · peer\.example\.com:51820/)).toBeTruthy();
		expect(screen.getByText(/site-to-site · wg1/)).toBeTruthy();
		expect(screen.getByText("client 1")).toBeTruthy();
		expect(screen.getByText("site 1")).toBeTruthy();
		expect(screen.getByText("hub 0")).toBeTruthy();
		expect(screen.getAllByText("Ready").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Validate").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Client").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Site").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Return path missing").length).toBeGreaterThan(0);
	});
});
