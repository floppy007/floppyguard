import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import WireGuard from "./index";

const statusMock = vi.fn();
const applyMetadataMock = vi.fn();
const applyStateMock = vi.fn();
const restoreMetadataMock = vi.fn();
const previewPlanMock = vi.fn();

vi.mock("src/hooks", () => ({
	useWireGuardStatus: () => statusMock(),
	useApplyWireGuardMetadata: () => applyMetadataMock(),
	useWireGuardApplyState: () => applyStateMock(),
	useRestoreWireGuardMetadata: () => restoreMetadataMock(),
	usePreviewWireGuardPlan: () => previewPlanMock(),
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
	beforeEach(() => {
		statusMock.mockReturnValue({
			data: buildStatus(),
			isLoading: false,
			isError: false,
			error: null,
		});
		applyMetadataMock.mockReturnValue({
			mutateAsync: vi.fn(),
			isPending: false,
			isSuccess: false,
			isError: false,
			data: null,
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
			isPending: false,
			isSuccess: false,
			isError: false,
			data: null,
		});
		previewPlanMock.mockReturnValue({
			mutateAsync: vi.fn().mockResolvedValue(buildLinkPreviewResponse()),
			isPending: false,
			isError: false,
		});
	});

	it("renders link warnings and next actions from runtime status", () => {
		render(<WireGuard />);
		expect(screen.getByText("warning: nat-likely-needed")).toBeTruthy();
		expect(screen.getByText("next: define-return-path-mode")).toBeTruthy();
	});

	it("renders interface health and notes", () => {
		render(<WireGuard />);
		expect(screen.getAllByText("warning").length).toBeGreaterThan(0);
		expect(screen.getAllByText(/wg1:/).length).toBeGreaterThan(0);
		expect(screen.getAllByText(/1 link\(s\) on this interface need review/).length).toBeGreaterThan(0);
		expect(screen.getAllByText("Apply Runtime").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Backups available: 1").length).toBeGreaterThan(0);
	});

	it("shows selected planner runtime actions", async () => {
		render(<WireGuard />);
		fireEvent.click(screen.getAllByRole("button", { name: "Plan link" })[0]);
		expect(await screen.findByText(/site-a via wg1 to unknown endpoint/)).toBeTruthy();
		expect(await screen.findByText("Site-to-site flow")).toBeTruthy();
		expect(await screen.findByText(/Suggested defaults: return static-route · mgmt ssh/)).toBeTruthy();
		expect((await screen.findAllByText(/runtime action: define-return-path-mode/)).length).toBeGreaterThan(0);
		expect((await screen.findAllByText(/warning: nat-likely-needed/)).length).toBeGreaterThan(0);
	});

	it("previews a planner diff before save", async () => {
		const previewMutation = vi.fn().mockResolvedValue(buildLinkPreviewResponse());
		previewPlanMock.mockReturnValue({
			mutateAsync: previewMutation,
			isPending: false,
			isError: false,
		});

		render(<WireGuard />);
		fireEvent.click(screen.getAllByRole("button", { name: "Plan link" })[0]);
		fireEvent.click(screen.getByRole("button", { name: "Preview plan" }));

		expect(await screen.findByText("Projected plan preview")).toBeTruthy();
		expect(await screen.findByText(/valid preview/)).toBeTruthy();
		expect(await screen.findByText(/Mode: metadata-only preview/)).toBeTruthy();
		expect(await screen.findByText(/Changed fields: exportedNetworks, returnPathMode/)).toBeTruthy();
		expect(await screen.findByText("Apply readiness")).toBeTruthy();
		expect((await screen.findAllByText("Apply status: Config-intent blocked")).length).toBeGreaterThan(0);
		expect(await screen.findByText("Can apply: no")).toBeTruthy();
		expect(await screen.findByText("Change scope: metadata-with-config-intent")).toBeTruthy();
		expect(
			await screen.findByText(/Blocked: this draft crosses into config intent and needs the later write-layer/),
		).toBeTruthy();
	});

	it("previews metadata edits before saving a link", async () => {
		previewPlanMock.mockReturnValue({
			mutateAsync: vi.fn().mockResolvedValue(buildLinkPreviewResponse()),
			isPending: false,
			isError: false,
		});

		render(<WireGuard />);
		fireEvent.click(screen.getAllByRole("button", { name: "Edit metadata" })[0]);
		fireEvent.click(screen.getByRole("button", { name: "Preview metadata" }));

		expect(await screen.findByText("Projected metadata preview")).toBeTruthy();
		expect((await screen.findAllByText("Warnings")).length).toBeGreaterThan(0);
		expect((await screen.findAllByText("Next actions")).length).toBeGreaterThan(0);
		expect(
			await screen.findByText(/Projected link: import 192.168.200.0\/24 · return static-route · mgmt ssh/),
		).toBeTruthy();
		expect((await screen.findAllByText(/Changed fields: exportedNetworks, returnPathMode/)).length).toBeGreaterThan(
			0,
		);
		expect((await screen.findAllByText("Requires backup: yes")).length).toBeGreaterThan(0);
		expect((await screen.findAllByText(/block: write-layer-not-implemented/)).length).toBeGreaterThan(0);
		expect((await screen.findAllByText("Apply status: Config-intent blocked")).length).toBeGreaterThan(0);
		expect((screen.getAllByLabelText("Return path mode")[0] as HTMLSelectElement).className).toContain(
			"border-red",
		);
		expect((screen.getAllByLabelText("Imported networks")[0] as HTMLTextAreaElement).className).toContain(
			"border-red",
		);
		expect(await screen.findByText("Preview changed the return-path mode stored on this link.")).toBeTruthy();
	});

	it("previews interface edits before saving an interface", async () => {
		previewPlanMock.mockReturnValue({
			mutateAsync: vi.fn().mockResolvedValue(buildInterfacePreviewResponse()),
			isPending: false,
			isError: false,
		});

		render(<WireGuard />);
		fireEvent.click(screen.getAllByRole("button", { name: "Edit" })[0]);
		fireEvent.click(screen.getByRole("button", { name: "Preview interface" }));

		expect(await screen.findByText("Projected interface preview")).toBeTruthy();
		expect((await screen.findAllByText("Next actions")).length).toBeGreaterThan(0);
		expect(await screen.findByText(/Changed fields: exportedNetworks, notes/)).toBeTruthy();
		expect((await screen.findAllByText(/step: create-backup-before-apply/)).length).toBeGreaterThan(0);
		expect((screen.getAllByLabelText("Exported networks")[0] as HTMLTextAreaElement).className).toContain(
			"border-red",
		);
		expect(await screen.findByText("Preview changed the interface exported network scope.")).toBeTruthy();
	});

	it("applies a reviewed metadata-only interface change", async () => {
		const applyMutation = vi.fn().mockResolvedValue({
			applied: true,
			backupPath: "/tmp/wireguard-metadata.json.2026-04-19.bak",
		});
		applyMetadataMock.mockReturnValue({
			mutateAsync: applyMutation,
			isPending: false,
			isSuccess: true,
			isError: false,
			data: {
				applied: true,
				backupPath: "/tmp/wireguard-metadata.json.2026-04-19.bak",
				auditEntry: {
					at: "2026-04-19T23:00:00.000Z",
					backupPath: "/tmp/wireguard-metadata.json.2026-04-19.bak",
					changeScope: "metadata-only",
					changeCount: 1,
					patchSummary: {
						interfaceTargets: ["wg1"],
						linkTargets: [],
					},
				},
			},
		});
		previewPlanMock.mockReturnValue({
			mutateAsync: vi.fn().mockResolvedValue(buildMetadataOnlyInterfacePreviewResponse()),
			isPending: false,
			isError: false,
		});

		render(<WireGuard />);
		fireEvent.click(screen.getAllByRole("button", { name: "Edit" })[0]);
		fireEvent.change(screen.getAllByLabelText("Notes")[0], { target: { value: "reviewed interface" } });
		fireEvent.click(screen.getByRole("button", { name: "Preview interface" }));
		expect(await screen.findByText("Apply status: Metadata-only apply ready")).toBeTruthy();
		expect(await screen.findByText("Can apply: yes")).toBeTruthy();
		expect(await screen.findByText("Change scope: metadata-only")).toBeTruthy();
		expect(
			await screen.findByText(/Ready to apply as metadata-only. A backup will be created automatically./),
		).toBeTruthy();
		expect(
			screen.getAllByText(/Reviewed metadata applied with backup \/tmp\/wireguard-metadata.json.2026-04-19.bak/)
				.length,
		).toBeGreaterThan(0);
		fireEvent.click(screen.getByRole("button", { name: "Save reviewed interface" }));
		expect(applyMutation).toHaveBeenCalledTimes(1);
	});

	it("restores a listed metadata backup", async () => {
		const restoreMutation = vi.fn().mockResolvedValue({
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
		});
		restoreMetadataMock.mockReturnValue({
			mutateAsync: restoreMutation,
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
			},
		});

		render(<WireGuard />);
		fireEvent.click(screen.getAllByRole("button", { name: "Restore" })[0]);
		expect(restoreMutation).toHaveBeenCalledWith("/tmp/wireguard-metadata.json.2026-04-19-a.bak");
		expect(
			screen.getAllByText(/Metadata restored from backup \/tmp\/wireguard-metadata.json.2026-04-19-a.bak/).length,
		).toBeGreaterThan(0);
	});
});
