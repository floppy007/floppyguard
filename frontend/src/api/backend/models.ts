export interface AppVersion {
	major: number;
	minor: number;
	revision: number;
}

export interface UserPermissions {
	id?: number;
	createdOn?: string;
	modifiedOn?: string;
	userId?: number;
	visibility: string;
	proxyHosts: string;
	redirectionHosts: string;
	deadHosts: string;
	streams: string;
	accessLists: string;
	certificates: string;
}

export interface User {
	id: number;
	createdOn: string;
	modifiedOn: string;
	isDisabled: boolean;
	email: string;
	name: string;
	nickname: string;
	avatar: string;
	roles: string[];
	permissions?: UserPermissions;
}

export interface AuditLog {
	id: number;
	createdOn: string;
	modifiedOn: string;
	userId: number;
	objectType: string;
	objectId: number;
	action: string;
	meta: Record<string, any>;
	user?: User;
}

export interface AccessList {
	id?: number;
	createdOn?: string;
	modifiedOn?: string;
	ownerUserId: number;
	name: string;
	meta: Record<string, any>;
	satisfyAny: boolean;
	passAuth: boolean;
	proxyHostCount?: number;
	owner?: User;
	items?: AccessListItem[];
	clients?: AccessListClient[];
}

export interface AccessListItem {
	id?: number;
	createdOn?: string;
	modifiedOn?: string;
	accessListId?: number;
	username: string;
	password: string;
	meta?: Record<string, any>;
	hint?: string;
}

export type AccessListClient = {
	id?: number;
	createdOn?: string;
	modifiedOn?: string;
	accessListId?: number;
	address: string;
	directive: "allow" | "deny";
	meta?: Record<string, any>;
};

export interface Certificate {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	provider: string;
	niceName: string;
	domainNames: string[];
	expiresOn: string;
	meta: Record<string, any>;
	owner?: User;
	proxyHosts?: ProxyHost[];
	deadHosts?: DeadHost[];
	redirectionHosts?: RedirectionHost[];
}

export interface ProxyLocation {
	path: string;
	advancedConfig: string;
	forwardScheme: string;
	forwardHost: string;
	forwardPort: number;
}

export interface ProxyHost {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	domainNames: string[];
	forwardScheme: string;
	forwardHost: string;
	forwardPort: number;
	accessListId: number;
	certificateId: number;
	sslForced: boolean;
	cachingEnabled: boolean;
	blockExploits: boolean;
	advancedConfig: string;
	meta: Record<string, any>;
	allowWebsocketUpgrade: boolean;
	http2Support: boolean;
	enabled: boolean;
	locations?: ProxyLocation[];
	hstsEnabled: boolean;
	hstsSubdomains: boolean;
	trustForwardedProto: boolean;
	owner?: User;
	accessList?: AccessList;
	certificate?: Certificate;
}

export interface DeadHost {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	domainNames: string[];
	certificateId: number;
	sslForced: boolean;
	advancedConfig: string;
	meta: Record<string, any>;
	http2Support: boolean;
	enabled: boolean;
	hstsEnabled: boolean;
	hstsSubdomains: boolean;
	owner?: User;
	certificate?: Certificate;
}

export interface RedirectionHost {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	domainNames: string[];
	forwardDomainName: string;
	preservePath: boolean;
	certificateId: number;
	sslForced: boolean;
	blockExploits: boolean;
	advancedConfig: string;
	meta: Record<string, any>;
	http2Support: boolean;
	forwardScheme: string;
	forwardHttpCode: number;
	enabled: boolean;
	hstsEnabled: boolean;
	hstsSubdomains: boolean;
	owner?: User;
	certificate?: Certificate;
}

export interface Stream {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	incomingPort: number;
	forwardingHost: string;
	forwardingPort: number;
	tcpForwarding: boolean;
	udpForwarding: boolean;
	meta: Record<string, any>;
	enabled: boolean;
	certificateId: number;
	owner?: User;
	certificate?: Certificate;
}

export interface Setting {
	id: string;
	name?: string;
	description?: string;
	value: string;
	meta?: Record<string, any>;
}

export interface DNSProvider {
	id: string;
	name: string;
	credentials: string;
}

export interface WireGuardInterface {
	name: string;
	isHub: boolean;
	configPath: string;
	configExists: boolean;
	active: boolean;
	addresses: string[];
	listenPort: number | null;
	publicKey: string | null;
	peerCount: number;
	activePeerCount: number;
	rxBytes: number;
	txBytes: number;
	privateKeyPresent: boolean;
	peerNetworks: string[];
	role?: WireGuardInterfaceRole;
	managementMode?: WireGuardManagementMode;
	importedNetworks?: string[];
	exportedNetworks?: string[];
	routeTargets?: string[];
	health?: "healthy" | "warning" | "inactive";
	dns?: string[];
	notes?: string[];
	peers: WireGuardPeer[];
}

export interface WireGuardPeer {
	publicKey: string | null;
	endpoint: string | null;
	allowedIps: string[];
	latestHandshake: number;
	rxBytes: number;
	txBytes: number;
	isActive: boolean;
}

export type WireGuardInterfaceRole = "client-hub" | "site-to-site" | "hub-link" | "auxiliary" | "unknown";
export type WireGuardManagementMode = "local" | "imported" | "unknown";
export type WireGuardLinkType = "client" | "site-to-site" | "hub-link" | "imported" | "unknown";
export type WireGuardReturnPathMode = "auto" | "routed" | "static-route" | "nat" | "unknown";
export type WireGuardRemoteManagementMode = "none" | "ssh" | "agent" | "unknown";
export type WireGuardRuntimeMode = "metadata-write";

export interface WireGuardLink {
	id: string;
	interfaceName: string;
	type: WireGuardLinkType;
	name: string;
	peerPublicKey: string | null;
	remoteEndpoint: string | null;
	allowedIps: string[];
	tunnelAddresses: string[];
	exportedNetworks: string[];
	importedNetworks: string[];
	latestHandshake: number;
	rxBytes: number;
	txBytes: number;
	active: boolean;
	hasMetadata: boolean;
	returnPathMode: WireGuardReturnPathMode;
	remoteManagementMode: WireGuardRemoteManagementMode;
	platform?: "desktop" | "mobile" | null;
	fullTunnel?: boolean;
	planIntent?: string | null;
	planState?: string | null;
	notes?: string[];
	dns?: string[];
	warnings: string[];
	nextActions: string[];
}

export interface WireGuardRoute {
	destination: string;
	device: string | null;
	via: string | null;
	raw: string;
}

export interface WireGuardRouteHint {
	network: string;
	reason: string;
}

export interface WireGuardSummary {
	interfaceCount: number;
	activeInterfaceCount: number;
	totalPeers: number;
	activePeers: number;
	totalRxBytes: number;
	totalTxBytes: number;
	peerNetworkCount: number;
	wireguardRouteCount: number;
	privateRouteCount: number;
	linkCount: number;
	siteLinkCount: number;
	hubLinkCount: number;
	clientLinkCount: number;
}

export interface WireGuardCapabilities {
	mode: WireGuardRuntimeMode;
	supports: {
		peerCrud: boolean;
		interfaceCrud: boolean;
		configDownload: boolean;
		shareLinks: boolean;
		wizardPlanning: boolean;
		metadataCrud: boolean;
		remoteSsh: boolean;
		remoteAgent: boolean;
	};
}

export interface WireGuardStatus {
	available: boolean;
	mode?: WireGuardRuntimeMode;
	hub: WireGuardInterface | null;
	interfaces: WireGuardInterface[];
	links?: WireGuardLink[];
	routes: {
		all: WireGuardRoute[];
		wireguard: WireGuardRoute[];
		privateRoutes: WireGuardRoute[];
		staticRoutes?: WireGuardRoute[];
		missingReturnRoutes?: WireGuardRouteHint[];
		natCandidates?: WireGuardRouteHint[];
		conflicts?: unknown[];
		splitTunnelCandidates?: string[];
		observations?: string[];
	};
	topology?: {
		exportedNetworks: string[];
		importedNetworks: string[];
		siteLinks: string[];
		clientLinks: string[];
		hubLinks: string[];
	};
	capabilities?: WireGuardCapabilities;
	summary: WireGuardSummary | null;
	warnings: string[];
	nextActions?: string[];
}

export interface WireGuardMetadataLinkPatch {
	importedNetworks?: string[];
	exportedNetworks?: string[];
	type?: WireGuardLinkType;
	name?: string;
	remoteManagementMode?: WireGuardRemoteManagementMode;
	returnPathMode?: WireGuardReturnPathMode;
	planIntent?: string;
	planState?: string;
	dns?: string[];
	fullTunnel?: boolean;
	notes?: string[];
}

export interface WireGuardMetadataInterfacePatch {
	role?: WireGuardInterfaceRole;
	managementMode?: WireGuardManagementMode;
	importedNetworks?: string[];
	exportedNetworks?: string[];
	routeTargets?: string[];
	dns?: string[];
	notes?: string[];
}

export interface WireGuardMetadataPatch {
	interfaces?: Record<string, WireGuardMetadataInterfacePatch>;
	links?: Record<string, WireGuardMetadataLinkPatch>;
}

export interface WireGuardMetadataResponse {
	available: boolean;
	mode: WireGuardRuntimeMode;
	interfaces: Record<string, WireGuardMetadataInterfacePatch>;
	links: Record<string, WireGuardMetadataLinkPatch>;
}

export interface WireGuardMetadataDiffEntry<TPatch> {
	id: string;
	kind: "interface" | "link";
	changedFields: string[];
	before: TPatch;
	after: TPatch;
}

export interface WireGuardPlanPreviewResponse {
	mode: WireGuardRuntimeMode;
	appliesLiveConfig: false;
	valid: boolean;
	errors: string[];
	warnings: string[];
	nextActions: string[];
	apply: {
		canApply: boolean;
		blockedBy: string[];
		requiresBackup: boolean;
		changeScope: "none" | "metadata-only" | "metadata-with-config-intent";
		changeCount: number;
		applyMode: "metadata-preview";
		requiresLiveConfigWrite: false;
		recommendedSteps: string[];
	};
	patch: WireGuardMetadataPatch;
	diff: {
		interfaces: WireGuardMetadataDiffEntry<WireGuardMetadataInterfacePatch>[];
		links: WireGuardMetadataDiffEntry<WireGuardMetadataLinkPatch>[];
	};
	projected: {
		interfaces: WireGuardInterface[];
		links: WireGuardLink[];
		topology: NonNullable<WireGuardStatus["topology"]>;
		routes: WireGuardStatus["routes"];
		summary: NonNullable<WireGuardStatus["summary"]>;
		warnings: string[];
		nextActions: string[];
	};
}

export interface WireGuardHubSyncResult {
	synced: boolean;
	changes?: Array<{ peer: string; allowedIPs: string[] }>;
	reason?: string;
}

export interface WireGuardAgentSyncResult {
	agentId: number;
	name: string;
	changed: boolean;
	newAllowedIPs?: string[];
	reason?: string;
}

export interface WireGuardApplyMetadataResponse {
	applied: true;
	backupPath: string;
	auditEntry: WireGuardApplyAuditEntry;
	apply: WireGuardPlanPreviewResponse["apply"];
	hubSync: WireGuardHubSyncResult | null;
	agentSync: WireGuardAgentSyncResult[] | null;
	metadata: {
		interfaces: Record<string, WireGuardMetadataInterfacePatch>;
		links: Record<string, WireGuardMetadataLinkPatch>;
	};
	status: WireGuardStatus;
}

export interface WireGuardApplyAuditEntry {
	at: string;
	backupPath: string;
	changeScope: "none" | "metadata-only" | "metadata-with-config-intent";
	changeCount: number;
	action?: "restore-backup";
	restoredFrom?: string;
	patchSummary: {
		interfaceTargets: string[];
		linkTargets: string[];
	};
}

export interface WireGuardApplyStateResponse {
	backups: Array<{
		path: string;
		fileName: string;
	}>;
	recentApplies: WireGuardApplyAuditEntry[];
	lastApply: WireGuardApplyAuditEntry | null;
}

export interface WireGuardRestoreMetadataResponse {
	restored: true;
	restoredFrom: string;
	backupPath: string;
	auditEntry: WireGuardApplyAuditEntry;
	metadata: {
		interfaces: Record<string, WireGuardMetadataInterfacePatch>;
		links: Record<string, WireGuardMetadataLinkPatch>;
	};
	status: WireGuardStatus;
}

export type AgentMode = "native" | "unifi";

export interface Agent {
	id: number;
	name: string;
	mode: AgentMode;
	hostname: string | null;
	wgInterface: string;
	configText: string | null;
	configHash: string | null;
	lastSeen: number | null;
	status: "pending" | "active" | "error";
	createdOn: number;
	modifiedOn: number;
	/** reg_token returned on create and while status=pending */
	regToken?: string | null;
	mgmtUrl: string | null;
	wgLinkName: string | null;
	agentVersion: string | null;
	services: Array<{ name: string; url: string }>;
	/** Per-agent network ACL — explicit CIDRs this agent may route (null = no restriction) */
	allowedNetworks: string[] | null;
	/** Per-agent site ACL — link names whose networks are allowed (null = no restriction) */
	allowedSites: string[] | null;
	// UniFi mode fields
	unifiUrl: string | null;
	unifiUser: string | null;
	unifiSite: string | null;
}

export interface AgentCreateData {
	name: string;
	mode?: AgentMode;
	wgInterface?: string;
	configText?: string;
	mgmtUrl?: string;
	wgLinkName?: string;
	// UniFi mode
	unifiUrl?: string;
	unifiUser?: string;
	unifiPass?: string;
	unifiSite?: string;
}

export interface AgentUpdateData {
	name?: string;
	mode?: AgentMode;
	wgInterface?: string;
	configText?: string;
	mgmtUrl?: string;
	/** Per-agent network ACL — explicit CIDRs this agent may route */
	allowedNetworks?: string[];
	/** Per-agent site ACL — link names whose networks are allowed */
	allowedSites?: string[];
	// UniFi mode
	unifiUrl?: string;
	unifiUser?: string;
	unifiPass?: string;
	unifiSite?: string;
}
