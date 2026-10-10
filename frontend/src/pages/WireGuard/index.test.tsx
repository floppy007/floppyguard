import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import EasyModal from "ez-modal-react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import WireGuard, { hubTunnelUrl } from "./index";

const createWrapper = () => {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	return ({ children }: { children: ReactNode }) => (
		<QueryClientProvider client={queryClient}>
			<EasyModal.Provider>{children}</EasyModal.Provider>
		</QueryClientProvider>
	);
};

const statusMock = vi.fn();
const applyMetadataMock = vi.fn();
const applyStateMock = vi.fn();
const restoreMetadataMock = vi.fn();
const previewPlanMock = vi.fn();
const agentsMock = vi.fn();
const createAgentMock = vi.fn();
const updateAgentMock = vi.fn();
const createPeerMock = vi.fn();

vi.mock("src/hooks", () => ({
	useWireGuardStatus: () => statusMock(),
	useApplyWireGuardMetadata: () => applyMetadataMock(),
	useWireGuardApplyState: () => applyStateMock(),
	useRestoreWireGuardMetadata: () => restoreMetadataMock(),
	usePreviewWireGuardPlan: () => previewPlanMock(),
	useAgents: () => agentsMock(),
	useAgentIngress: () => ({ data: undefined, isLoading: false, error: null }),
	useAgentIngressCheck: () => ({ data: undefined, isLoading: false, error: null }),
	useCreateAgent: () => createAgentMock(),
	useUpdateAgent: () => updateAgentMock(),
	useCreateWireGuardPeer: () => createPeerMock(),
	useSetting: () => ({ data: { value: "https://proxy.comnic.de", meta: { primary: "http://10.10.0.1:3300" } } }),
	useSetSetting: () => ({ mutate: vi.fn(), isPending: false, isError: false, error: null, reset: vi.fn() }),
}));

const buildStatus = () => ({
	available: true,
	mode: "metadata-write" as const,
	hub: {
		name: "wg0",
		isHub: true,
		configPath: "/etc/wireguard/wg0.conf",
		configExists: true,
		active: true,
		addresses: ["10.0.0.1/24"],
		listenPort: 51820,
		publicKey: "hub-public-key",
		peerCount: 1,
		activePeerCount: 1,
		rxBytes: 100,
		txBytes: 200,
		privateKeyPresent: true,
		peerNetworks: ["192.168.50.0/24"],
		role: "client-hub" as const,
		managementMode: "local" as const,
		importedNetworks: ["192.168.50.0/24"],
		exportedNetworks: ["10.10.0.0/24"],
		routeTargets: ["192.168.50.0/24"],
		health: "healthy" as const,
		notes: ["hub ready"],
		peers: [
			{
				publicKey: "peer-public-key",
				endpoint: "peer.example.com:51820",
				allowedIps: ["192.168.50.0/24"],
				latestHandshake: 1000,
				rxBytes: 10,
				txBytes: 20,
				isActive: true,
			},
		],
	},
	interfaces: [
		{
			name: "wg0",
			isHub: true,
			configPath: "/etc/wireguard/wg0.conf",
			configExists: true,
			active: true,
			addresses: ["10.0.0.1/24"],
			listenPort: 51820,
			publicKey: "hub-public-key",
			peerCount: 1,
			activePeerCount: 1,
			rxBytes: 100,
			txBytes: 200,
			privateKeyPresent: true,
			peerNetworks: ["192.168.50.0/24"],
			role: "client-hub" as const,
			managementMode: "local" as const,
			importedNetworks: ["192.168.50.0/24"],
			exportedNetworks: ["10.10.0.0/24"],
			routeTargets: ["192.168.50.0/24"],
			health: "healthy" as const,
			notes: ["hub ready"],
			peers: [
				{
					publicKey: "peer-public-key",
					endpoint: "peer.example.com:51820",
					allowedIps: ["192.168.50.0/24"],
					latestHandshake: 1000,
					rxBytes: 10,
					txBytes: 20,
					isActive: true,
				},
			],
		},
		{
			name: "wg1",
			isHub: false,
			configPath: "/etc/wireguard/wg1.conf",
			configExists: true,
			active: true,
			addresses: ["10.1.0.1/24"],
			listenPort: 51821,
			publicKey: "site-public-key",
			peerCount: 1,
			activePeerCount: 0,
			rxBytes: 50,
			txBytes: 75,
			privateKeyPresent: true,
			peerNetworks: ["192.168.200.0/24"],
			role: "site-to-site" as const,
			managementMode: "imported" as const,
			importedNetworks: ["192.168.200.0/24"],
			exportedNetworks: [],
			routeTargets: ["192.168.200.0/24"],
			health: "warning" as const,
			notes: ["1 link(s) on this interface need review", "inactive interface with imported networks"],
			peers: [
				{
					publicKey: "site-peer-key",
					endpoint: null,
					allowedIps: ["192.168.200.0/24"],
					latestHandshake: 0,
					rxBytes: 1,
					txBytes: 2,
					isActive: false,
				},
			],
		},
	],
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
			planState: "shape",
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
		observations: [],
	},
	topology: {
		exportedNetworks: ["10.10.0.0/24"],
		importedNetworks: ["192.168.200.0/24"],
		siteLinks: ["wg1:site-peer-key"],
		clientLinks: [],
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
		activeInterfaceCount: 2,
		totalPeers: 2,
		activePeers: 1,
		totalRxBytes: 150,
		totalTxBytes: 275,
		peerNetworkCount: 2,
		wireguardRouteCount: 0,
		privateRouteCount: 0,
		linkCount: 1,
		siteLinkCount: 1,
		hubLinkCount: 0,
		clientLinkCount: 0,
	},
	warnings: ["Interface wg1 needs review"],
	nextActions: ["define-return-path-mode", "review-nat-requirements"],
});

const buildLinkPreviewResponse = () => ({
	mode: "metadata-write" as const,
	appliesLiveConfig: false as const,
	valid: true,
	errors: [],
	warnings: ["Preview only applies metadata; live WireGuard config is unchanged"],
	nextActions: ["fix-return-path"],
	apply: {
		canApply: false,
		blockedBy: ["write-layer-not-implemented"],
		requiresBackup: true,
		changeScope: "metadata-with-config-intent" as const,
		changeCount: 2,
		applyMode: "metadata-preview" as const,
		requiresLiveConfigWrite: false as const,
		recommendedSteps: ["create-backup-before-apply", "implement-write-layer-before-apply"],
	},
	patch: {
		links: {
			"wg1:site-peer-key": {
				type: "site-to-site" as const,
				exportedNetworks: ["10.10.0.0/24"],
				importedNetworks: ["192.168.200.0/24"],
				returnPathMode: "static-route" as const,
				remoteManagementMode: "ssh" as const,
				planIntent: "site-to-site",
				planState: "validate",
			},
		},
	},
	diff: {
		interfaces: [],
		links: [
			{
				id: "wg1:site-peer-key",
				kind: "link" as const,
				changedFields: ["exportedNetworks", "returnPathMode"],
				before: { exportedNetworks: [], returnPathMode: "unknown" },
				after: { exportedNetworks: ["10.10.0.0/24"], returnPathMode: "static-route" },
			},
		],
	},
	projected: {
		interfaces: buildStatus().interfaces,
		links: [
			{
				...buildStatus().links[0],
				exportedNetworks: ["10.10.0.0/24"],
				returnPathMode: "static-route",
				remoteManagementMode: "ssh",
				planState: "validate",
			},
		],
		topology: buildStatus().topology,
		routes: buildStatus().routes,
		summary: buildStatus().summary,
		warnings: ["Preview only applies metadata; live WireGuard config is unchanged"],
		nextActions: ["fix-return-path"],
	},
});

const buildInterfacePreviewResponse = () => ({
	mode: "metadata-write" as const,
	appliesLiveConfig: false as const,
	valid: true,
	errors: [],
	warnings: ["Preview only applies metadata; live WireGuard config is unchanged"],
	nextActions: ["review-interface-health"],
	apply: {
		canApply: false,
		blockedBy: ["write-layer-not-implemented"],
		requiresBackup: true,
		changeScope: "metadata-with-config-intent" as const,
		changeCount: 2,
		applyMode: "metadata-preview" as const,
		requiresLiveConfigWrite: false as const,
		recommendedSteps: ["create-backup-before-apply", "implement-write-layer-before-apply"],
	},
	patch: {
		interfaces: {
			wg1: {
				role: "site-to-site" as const,
				managementMode: "imported" as const,
				exportedNetworks: ["10.20.0.0/24"],
				importedNetworks: ["192.168.200.0/24"],
				routeTargets: ["192.168.200.0/24"],
				notes: ["reviewed interface"],
			},
		},
	},
	diff: {
		interfaces: [
			{
				id: "wg1",
				kind: "interface" as const,
				changedFields: ["exportedNetworks", "notes"],
				before: {
					exportedNetworks: [],
					notes: ["1 link(s) on this interface need review", "inactive interface with imported networks"],
				},
				after: { exportedNetworks: ["10.20.0.0/24"], notes: ["reviewed interface"] },
			},
		],
		links: [],
	},
	projected: {
		interfaces: [
			{
				...buildStatus().interfaces[1],
				exportedNetworks: ["10.20.0.0/24"],
				notes: ["reviewed interface"],
				managementMode: "imported" as const,
			},
		],
		links: buildStatus().links,
		topology: buildStatus().topology,
		routes: buildStatus().routes,
		summary: buildStatus().summary,
		warnings: ["Preview only applies metadata; live WireGuard config is unchanged"],
		nextActions: ["review-interface-health"],
	},
});

const buildMetadataOnlyInterfacePreviewResponse = () => ({
	mode: "metadata-write" as const,
	appliesLiveConfig: false as const,
	valid: true,
	errors: [],
	warnings: ["Preview only applies metadata; live WireGuard config is unchanged"],
	nextActions: [],
	apply: {
		canApply: true,
		blockedBy: [],
		requiresBackup: true,
		changeScope: "metadata-only" as const,
		changeCount: 1,
		applyMode: "metadata-preview" as const,
		requiresLiveConfigWrite: false as const,
		recommendedSteps: ["create-backup-before-apply"],
	},
	patch: {
		interfaces: {
			wg1: {
				notes: ["reviewed interface"],
			},
		},
	},
	diff: {
		interfaces: [
			{
				id: "wg1",
				kind: "interface" as const,
				changedFields: ["notes"],
				before: {
					notes: ["1 link(s) on this interface need review", "inactive interface with imported networks"],
				},
				after: { notes: ["reviewed interface"] },
			},
		],
		links: [],
	},
	projected: {
		interfaces: [{ ...buildStatus().interfaces[1], notes: ["reviewed interface"] }],
		links: buildStatus().links,
		topology: buildStatus().topology,
		routes: buildStatus().routes,
		summary: buildStatus().summary,
		warnings: ["Preview only applies metadata; live WireGuard config is unchanged"],
		nextActions: [],
	},
});

describe("WireGuard page", () => {
	afterEach(() => {
		cleanup();
	});

	beforeEach(() => {
		statusMock.mockReturnValue({
			data: buildStatus(),
			isLoading: false,
			isError: false,
			error: null,
		});
		applyMetadataMock.mockReturnValue({
			mutateAsync: vi.fn(),
			mutate: vi.fn(),
			isPending: false,
			isSuccess: false,
			isError: false,
			data: null,
			reset: vi.fn(),
		});
		applyStateMock.mockReturnValue({
			data: {
				backups: [
					{
						path: "/tmp/wireguard-metadata.json.2026-04-19-a.bak",
						fileName: "wireguard-metadata.json.2026-04-19-a.bak",
					},
				],
				recentApplies: [],
				lastApply: null,
			},
			isError: false,
		});
		restoreMetadataMock.mockReturnValue({
			mutateAsync: vi.fn(),
			mutate: vi.fn(),
			isPending: false,
			isSuccess: false,
			isError: false,
			data: null,
			reset: vi.fn(),
		});
		previewPlanMock.mockReturnValue({
			mutateAsync: vi.fn().mockResolvedValue(buildLinkPreviewResponse()),
			mutate: vi.fn(),
			isPending: false,
			isError: false,
		});
		agentsMock.mockReturnValue({
			data: [],
			isLoading: false,
			isError: false,
			isSuccess: true,
			error: null,
		});
		createAgentMock.mockReturnValue({
			mutate: vi.fn(),
			mutateAsync: vi.fn(),
			isPending: false,
		});
		updateAgentMock.mockReturnValue({
			mutate: vi.fn(),
			mutateAsync: vi.fn(),
			isPending: false,
			isError: false,
			error: null,
			reset: vi.fn(),
		});
		createPeerMock.mockReturnValue({
			mutateAsync: vi.fn(),
			isPending: false,
		});
	});

	it("renders link warnings and next actions from runtime status", () => {
		render(<WireGuard />, { wrapper: createWrapper() });
		// Next actions are on the overview tab (default) — translated via intl
		expect(screen.getByText(/Define return path mode/)).toBeTruthy();
		// "review-nat-requirements" is not in KNOWN_NEXT_ACTIONS, rendered with "• " prefix
		expect(screen.getByText(/review-nat-requirements/)).toBeTruthy();
		// Switch to Links tab to see link warnings
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		// Warnings are rendered with ⚠ prefix and translated text
		expect(screen.getByText(/NAT likely needed/)).toBeTruthy();
		expect(screen.getByText(/Return path mode not set/)).toBeTruthy();
	});

	it("hides Download/QR on site links (they would rotate the gateway's key)", () => {
		render(<WireGuard />, { wrapper: createWrapper() });
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		expect(screen.getByText(/NAT likely needed/)).toBeTruthy();
		expect(screen.queryByRole("button", { name: "Download Config" })).toBeNull();
		expect(screen.queryByRole("button", { name: "Show QR" })).toBeNull();
	});

	it("renders interface health and notes", () => {
		render(<WireGuard />, { wrapper: createWrapper() });
		// Switch to Interfaces tab (use getAllByRole since multiple elements may match)
		fireEvent.click(screen.getAllByRole("button", { name: /Interfaces/ })[0]);
		// Health badge renders the health value directly
		expect(screen.getAllByText("warning").length).toBeGreaterThan(0);
		// Interface names are displayed
		expect(screen.getAllByText("wg1").length).toBeGreaterThan(0);
		// Open editor for wg1 (second interface) to see its notes in the textarea
		const editButtons = screen.getAllByRole("button", { name: "Edit" });
		fireEvent.click(editButtons[editButtons.length - 1]);
		// Notes textarea has comma-joined notes as value
		expect(
			screen.getAllByDisplayValue(
				"1 link(s) on this interface need review, inactive interface with imported networks",
			).length,
		).toBeGreaterThan(0);
		// Switch back to Overview tab for backups
		fireEvent.click(screen.getAllByRole("button", { name: /Overview/ })[0]);
		// Backup section is visible with a Restore button
		expect(screen.getAllByText("Metadata Backups").length).toBeGreaterThan(0);
		expect(screen.getAllByRole("button", { name: "Restore" }).length).toBeGreaterThan(0);
	});

	it("shows selected planner with link details", async () => {
		render(<WireGuard />, { wrapper: createWrapper() });
		// Switch to Links tab to see link cards
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		// Open the planner for the link
		fireEvent.click(screen.getAllByRole("button", { name: "Plan link" })[0]);
		// The planner section title includes the link name
		expect(await screen.findByText(/Link Planner/i)).toBeTruthy();
		// The planner form has connection type, network fields
		expect(screen.getByText(/Connection type/i)).toBeTruthy();
	});

	it("saves planner changes via apply metadata", async () => {
		const applyMutation = vi.fn();
		applyMetadataMock.mockReturnValue({
			mutateAsync: vi.fn(),
			mutate: applyMutation,
			isPending: false,
			isSuccess: false,
			isError: false,
			data: null,
			reset: vi.fn(),
		});

		render(<WireGuard />, { wrapper: createWrapper() });
		// Switch to Links tab
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		// Open planner
		fireEvent.click(screen.getAllByRole("button", { name: "Plan link" })[0]);
		// Click the save plan button
		fireEvent.click(screen.getByRole("button", { name: "Save plan" }));
		await waitFor(() => expect(applyMutation).toHaveBeenCalledTimes(1));
	});

	it("shows the apply result outside the closed editor, incl. per-interface hub and fleet sync failures", () => {
		const reset = vi.fn();
		applyMetadataMock.mockReturnValue({
			mutateAsync: vi.fn(),
			mutate: vi.fn(),
			isPending: false,
			isSuccess: true,
			isError: false,
			reset,
			data: {
				applied: true,
				apply: { changeScope: "metadata-with-config-intent" },
				hubSync: { wg0: { synced: false, reason: "no-conf-file" } },
				agentSync: { error: "fleet sync exploded" },
			},
		});

		render(<WireGuard />, { wrapper: createWrapper() });
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		const result = screen.getAllByTestId("wireguard-apply-result")[0];
		expect(result.className).toContain("alert-warning");
		expect(result.textContent).toContain("wg0: no-conf-file");
		expect(result.textContent).toContain("fleet sync exploded");
		// opening the editor clears the previous result
		fireEvent.click(screen.getAllByRole("button", { name: "Edit metadata" })[0]);
		expect(reset).toHaveBeenCalled();
	});

	it("saves metadata edits for a link", async () => {
		const applyMutation = vi.fn();
		applyMetadataMock.mockReturnValue({
			mutateAsync: vi.fn(),
			mutate: applyMutation,
			isPending: false,
			isSuccess: false,
			isError: false,
			data: null,
			reset: vi.fn(),
		});

		render(<WireGuard />, { wrapper: createWrapper() });
		// Switch to Links tab
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		// Open the metadata editor
		fireEvent.click(screen.getAllByRole("button", { name: "Edit metadata" })[0]);
		// Change the display name to trigger a dirty patch
		const nameInput = screen.getByDisplayValue("site-a");
		fireEvent.change(nameInput, { target: { value: "site-a-renamed" } });
		// Save
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => expect(applyMutation).toHaveBeenCalledTimes(1));
	});

	it("previews interface edits before saving an interface", async () => {
		const previewData = buildInterfacePreviewResponse();
		previewPlanMock.mockReturnValue({
			mutateAsync: vi.fn().mockResolvedValue(previewData),
			mutate: vi.fn((_, opts) => opts?.onSuccess?.(previewData)),
			isPending: false,
			isError: false,
		});

		render(<WireGuard />, { wrapper: createWrapper() });
		// Switch to Interfaces tab
		fireEvent.click(screen.getAllByRole("button", { name: /Interfaces/ })[0]);
		// Open the interface editor
		fireEvent.click(screen.getAllByRole("button", { name: "Edit" })[0]);
		// Click Preview button
		fireEvent.click(screen.getByRole("button", { name: "Preview" }));
		// PreviewResult shows a "valid" badge since preview.valid is true
		expect(await screen.findByText("valid")).toBeTruthy();
		// Shows the warning from the preview response
		expect(
			await screen.findByText(/Preview only applies metadata; live WireGuard config is unchanged/),
		).toBeTruthy();
		// Shows blocked-by since canApply is false
		expect(await screen.findByText(/Blocked:/)).toBeTruthy();
		expect(await screen.findByText(/write-layer-not-implemented/)).toBeTruthy();
		// Shows config-intent warning
		expect(await screen.findByText(/Config-intent change/)).toBeTruthy();
	});

	it("applies a reviewed metadata-only interface change", async () => {
		const applyMutation = vi.fn();
		applyMetadataMock.mockReturnValue({
			mutateAsync: vi.fn(),
			mutate: applyMutation,
			isPending: false,
			isSuccess: false,
			isError: false,
			data: null,
			reset: vi.fn(),
		});
		const metaPreviewData = buildMetadataOnlyInterfacePreviewResponse();
		previewPlanMock.mockReturnValue({
			mutateAsync: vi.fn().mockResolvedValue(metaPreviewData),
			mutate: vi.fn((_, opts) => opts?.onSuccess?.(metaPreviewData)),
			isPending: false,
			isError: false,
		});

		render(<WireGuard />, { wrapper: createWrapper() });
		// Switch to Interfaces tab
		fireEvent.click(screen.getAllByRole("button", { name: /Interfaces/ })[0]);
		// Open the interface editor
		fireEvent.click(screen.getAllByRole("button", { name: "Edit" })[0]);
		// Edit the notes
		fireEvent.change(screen.getByPlaceholderText("Hub role, check later, ..."), {
			target: { value: "reviewed interface" },
		});
		// Preview the change
		fireEvent.click(screen.getAllByRole("button", { name: "Preview" })[0]);
		// PreviewResult shows valid badge
		expect(await screen.findByText("valid")).toBeTruthy();
		// Since canApply is true, shows ready-to-apply message
		expect(await screen.findByText(/Ready to apply \(metadata only\)/)).toBeTruthy();
		// Save the change
		fireEvent.click(screen.getAllByRole("button", { name: "Save" })[0]);
		expect(applyMutation).toHaveBeenCalledTimes(1);
	});

	it("restores a listed metadata backup", async () => {
		const restoreMutation = vi.fn(async () => {});
		restoreMetadataMock.mockReturnValue({
			mutateAsync: restoreMutation,
			mutate: vi.fn(),
			isPending: false,
			isSuccess: true,
			isError: false,
			data: {
				restored: true,
				restoredFrom: "/tmp/wireguard-metadata.json.2026-04-19-a.bak",
				backupPath: "/tmp/wireguard-metadata.json.2026-04-19-restore.bak",
				auditEntry: {
					at: "2026-04-19T23:10:00.000Z",
					backupPath: "/tmp/wireguard-metadata.json.2026-04-19-restore.bak",
					changeScope: "metadata-only",
					changeCount: 0,
					action: "restore-backup",
					restoredFrom: "/tmp/wireguard-metadata.json.2026-04-19-a.bak",
					patchSummary: {
						interfaceTargets: ["wg1"],
						linkTargets: [],
					},
				},
				hubSync: { wg0: { synced: true } },
				agentSync: { error: "agent sync exploded" },
			},
		});

		render(<WireGuard />, { wrapper: createWrapper() });
		// Overview tab is default — Restore button is visible; it only opens a confirmation
		fireEvent.click(screen.getAllByRole("button", { name: "Restore" })[0]);
		const dialog = await screen.findByRole("dialog");
		expect(dialog.textContent).toContain("wireguard-metadata.json.2026-04-19-a.bak");
		expect(restoreMutation).not.toHaveBeenCalled();
		fireEvent.click(within(dialog).getByRole("button", { name: "Restore" }));
		await waitFor(() =>
			expect(restoreMutation).toHaveBeenCalledWith("/tmp/wireguard-metadata.json.2026-04-19-a.bak"),
		);
		// Success message from intl: "Metadata restored from backup." — plus the failed agent sync
		expect(screen.getAllByText(/Metadata restored from backup/).length).toBeGreaterThan(0);
		expect(screen.getByTestId("wireguard-restore-result").textContent).toContain("agent sync exploded");
	});

	const buildAgentLinkStatus = () => {
		const status = buildStatus();
		return {
			...status,
			links: [{ ...status.links[0], remoteManagementMode: "agent" as const }],
		};
	};

	it("does not auto-create an agent while the agents query has not resolved", () => {
		statusMock.mockReturnValue({ data: buildAgentLinkStatus(), isLoading: false, isError: false, error: null });
		agentsMock.mockReturnValue({ data: undefined, isLoading: true, isError: false, isSuccess: false, error: null });
		const createMutation = vi.fn();
		createAgentMock.mockReturnValue({ mutate: createMutation, mutateAsync: vi.fn(), isPending: false });

		render(<WireGuard />, { wrapper: createWrapper() });
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		fireEvent.click(screen.getByRole("button", { name: "Agent" }));
		expect(createMutation).not.toHaveBeenCalled();
	});

	it("auto-creates an agent once the agents query resolved without a match", async () => {
		statusMock.mockReturnValue({ data: buildAgentLinkStatus(), isLoading: false, isError: false, error: null });
		const createMutation = vi.fn();
		createAgentMock.mockReturnValue({ mutate: createMutation, mutateAsync: vi.fn(), isPending: false });

		render(<WireGuard />, { wrapper: createWrapper() });
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		fireEvent.click(screen.getByRole("button", { name: "Agent" }));
		await waitFor(() => expect(createMutation).toHaveBeenCalledTimes(1));
		expect(createMutation).toHaveBeenCalledWith(
			{ name: "site-a", mode: "native", wgInterface: "wg1", wgLinkName: "site-a" },
			expect.anything(),
		);
	});

	it("diffs the link editor against the values it opened with, not the polled link", async () => {
		const applyMutation = vi.fn();
		applyMetadataMock.mockReturnValue({
			mutateAsync: vi.fn(),
			mutate: applyMutation,
			isPending: false,
			isSuccess: false,
			isError: false,
			data: null,
			reset: vi.fn(),
		});
		const { rerender } = render(<WireGuard />, { wrapper: createWrapper() });
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		fireEvent.click(screen.getAllByRole("button", { name: "Edit metadata" })[0]);
		fireEvent.change(screen.getByDisplayValue("site-a"), { target: { value: "site-a-renamed" } });
		// another admin adds a network while the editor is open; the 15 s poll brings it in
		const polled = buildStatus();
		polled.links = [{ ...polled.links[0], importedNetworks: ["192.168.200.0/24", "10.4.50.0/24"] }];
		statusMock.mockReturnValue({ data: polled, isLoading: false, isError: false, error: null });
		rerender(<WireGuard />);
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => expect(applyMutation).toHaveBeenCalledTimes(1));
		// only the edited field — the stale importedNetworks draft must not revert the new network
		expect(applyMutation.mock.calls[0][0]).toEqual({ links: { "wg1:site-peer-key": { name: "site-a-renamed" } } });
	});

	it("sends only changed interface fields (derived lists/notes are not frozen)", async () => {
		const applyMutation = vi.fn();
		applyMetadataMock.mockReturnValue({
			mutateAsync: vi.fn(),
			mutate: applyMutation,
			isPending: false,
			isSuccess: false,
			isError: false,
			data: null,
			reset: vi.fn(),
		});
		const metaPreviewData = buildMetadataOnlyInterfacePreviewResponse();
		const previewMutate = vi.fn((_, opts) => opts?.onSuccess?.(metaPreviewData));
		previewPlanMock.mockReturnValue({
			mutateAsync: vi.fn().mockResolvedValue(metaPreviewData),
			mutate: previewMutate,
			isPending: false,
			isError: false,
		});
		render(<WireGuard />, { wrapper: createWrapper() });
		fireEvent.click(screen.getAllByRole("button", { name: /Interfaces/ })[0]);
		fireEvent.click(screen.getAllByRole("button", { name: "Edit" })[0]);
		fireEvent.change(screen.getByPlaceholderText("Hub role, check later, ..."), {
			target: { value: "reviewed interface" },
		});
		fireEvent.click(screen.getAllByRole("button", { name: "Preview" })[0]);
		expect(await screen.findByText("valid")).toBeTruthy();
		fireEvent.click(screen.getAllByRole("button", { name: "Save" })[0]);
		expect(applyMutation).toHaveBeenCalledTimes(1);
		expect(applyMutation.mock.calls[0][0]).toEqual({ interfaces: { wg0: { notes: ["reviewed interface"] } } });
	});

	it("shows a failed agent auto-create with the reason and a retry button", async () => {
		statusMock.mockReturnValue({ data: buildAgentLinkStatus(), isLoading: false, isError: false, error: null });
		const createMutation = vi.fn();
		createAgentMock.mockReturnValue({
			mutate: createMutation,
			mutateAsync: vi.fn(),
			isPending: false,
			isError: true,
			error: new Error("resolve duplicate link names"),
		});
		const { rerender } = render(<WireGuard />, { wrapper: createWrapper() });
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		fireEvent.click(screen.getByRole("button", { name: "Agent" }));
		await waitFor(() => expect(createMutation).toHaveBeenCalledTimes(1));
		rerender(<WireGuard />);
		expect(screen.getByTestId("agent-create-error").textContent).toContain("resolve duplicate link names");
		fireEvent.click(screen.getByRole("button", { name: "Retry" }));
		expect(createMutation).toHaveBeenCalledTimes(2);
	});

	it("pre-fills the installer tunnel URL with the hub address, not the gateway's tunnel IP", () => {
		const status = buildAgentLinkStatus();
		const link = { ...status.links[0], tunnelAddresses: ["10.1.0.2/32"] };
		statusMock.mockReturnValue({
			data: { ...status, links: [link] },
			isLoading: false,
			isError: false,
			error: null,
		});
		agentsMock.mockReturnValue({
			data: [
				{
					id: 7,
					name: "site-a",
					wgLinkName: "site-a",
					hostname: null,
					status: "pending",
					regToken: "reg-token",
					services: [],
					allowedNetworks: null,
					allowedSites: null,
				},
			],
			isLoading: false,
			isError: false,
			isSuccess: true,
			error: null,
		});
		render(<WireGuard />, { wrapper: createWrapper() });
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		fireEvent.click(screen.getByRole("button", { name: "Agent" }));
		// from the agent-hub-url setting (mocked: http://10.10.0.1:3300)
		expect(screen.getByDisplayValue("http://10.10.0.1:3300")).toBeTruthy();
		expect(screen.queryByDisplayValue("http://10.1.0.2:3300")).toBeNull();
		expect(screen.getByRole("button", { name: "Delete agent" })).toBeTruthy();
	});

	it("builds the hub tunnel URL from the interface address", () => {
		expect(hubTunnelUrl("10.1.0.1/24")).toBe("http://10.1.0.1:3300");
		expect(hubTunnelUrl("fd00::1/64")).toBe("http://[fd00::1]:3300");
		expect(hubTunnelUrl(undefined)).toBe("");
	});

	it("renders only http(s) agent service URLs as links", () => {
		agentsMock.mockReturnValue({
			data: [
				{
					id: 1,
					name: "site-a",
					wgLinkName: "site-a",
					hostname: "remote-box",
					status: "active",
					agentVersion: "1.3.21",
					mgmtUrl: null,
					services: [
						{ name: "Evil", url: "javascript:alert(1)" },
						{ name: "Good", url: "http://192.168.10.7:8080" },
					],
					allowedNetworks: null,
					allowedSites: null,
				},
			],
			isLoading: false,
			isError: false,
			isSuccess: true,
			error: null,
		});

		render(<WireGuard />, { wrapper: createWrapper() });
		fireEvent.click(screen.getAllByRole("button", { name: /Links/ })[0]);
		// The http service is rendered as a link, the javascript: one is dropped
		expect(screen.getByText(/Good/)).toBeTruthy();
		expect(screen.queryByText(/Evil/)).toBeNull();
	});

	it("renders the topology map with the hub and an online node", () => {
		const status = buildStatus();
		const now = Math.floor(Date.now() / 1000);
		status.links[0] = { ...status.links[0], active: true, latestHandshake: now - 40, rxBytes: 2048, txBytes: 4096 };
		statusMock.mockReturnValue({ data: status, isLoading: false, isError: false, error: null });
		agentsMock.mockReturnValue({
			data: [
				{
					id: 1,
					name: "gw-a",
					wgLinkName: "site-a",
					status: "active",
					lastSeen: now,
					ingressMode: "restricted",
				},
			],
			isLoading: false,
			isError: false,
			isSuccess: true,
			error: null,
		});

		render(<WireGuard />, { wrapper: createWrapper() });
		const map = screen.getByRole("figure", { name: /Topology: 1 sites, 0 clients, 1 online/ });
		expect(within(map).getByText("This Hub")).toBeTruthy();
		const node = within(map).getByRole("group", { name: /^site-a, Site to Site, online/ });
		expect(node.getAttribute("aria-label")).toMatch(/Agent gw-a: online/);
		expect(node.getAttribute("aria-label")).toMatch(/Only released traffic/);
		expect(within(node).getByText("online · 40 s")).toBeTruthy();
		expect(within(map).getAllByText("1/1 online").length).toBeGreaterThan(0);
	});
});
