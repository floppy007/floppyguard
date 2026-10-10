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
	authSources?: ("local" | "sso")[];
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
	/** type comes from metadata (false = inferred from AllowedIPs) */
	typeExplicit?: boolean;
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
	/** set when this agent's resync threw (other agents unaffected) */
	error?: string;
}

/** Result of carrying agent bindings along with renamed links. */
export interface WireGuardRenameCascade {
	renames: Array<{ oldName: string; newName: string }>;
	errors: Array<{ from: string; to: string; error: string }>;
	/** the temp-name phase of a swap failed and was rolled back to the old names */
	rolledBack: boolean;
}

export interface WireGuardApplyMetadataResponse {
	applied: true;
	backupPath: string;
	auditEntry: WireGuardApplyAuditEntry;
	apply: WireGuardPlanPreviewResponse["apply"];
	hubSync: WireGuardHubSyncResult | null;
	agentSync: WireGuardAgentSyncResult[] | null;
	renameCascade?: WireGuardRenameCascade;
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
	/** Per interface ({ wg0: {...} }), or { synced: false, reason } if the hub sync itself failed */
	hubSync: Record<string, WireGuardHubSyncResult> | WireGuardHubSyncResult | null;
	/** Per agent, or { error } if the fleet sync failed */
	agentSync: WireGuardAgentSyncResult[] | { error: string } | null;
	renameCascade?: WireGuardRenameCascade;
	metadata: {
		interfaces: Record<string, WireGuardMetadataInterfacePatch>;
		links: Record<string, WireGuardMetadataLinkPatch>;
	};
	status: WireGuardStatus;
}

export type AgentMode = "native";

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
	/** Site gateways: exempt the local LAN from MASQUERADE so VPN clients keep their real source IP (needs a return route). Default true. */
	preserveLanSourceIp: boolean;
	/** Ingress filter for traffic arriving through the tunnel into the site LAN */
	ingressMode?: AgentIngressMode;
	/** config_hash the agent reports as actually applied (heartbeat) */
	configAppliedHash?: string | null;
	/** last config apply error reported by the agent */
	configError?: string | null;
}

export interface AgentCreateData {
	name: string;
	mode?: AgentMode;
	wgInterface?: string;
	configText?: string;
	mgmtUrl?: string;
	wgLinkName?: string;
}

export interface AgentUpdateData {
	name?: string;
	mode?: AgentMode;
	wgInterface?: string;
	configText?: string;
	/** null clears the URL (undefined keys are dropped from the JSON body) */
	mgmtUrl?: string | null;
	/** Per-agent network ACL — explicit CIDRs this agent may route */
	allowedNetworks?: string[];
	/** Per-agent site ACL — link names whose networks are allowed */
	allowedSites?: string[];
	/** Site gateways: exempt the local LAN from MASQUERADE so VPN clients keep their real source IP (needs a return route). */
	preserveLanSourceIp?: boolean;
}

// ── Agent ingress filter ("Freigaben") ────────────────────────────────────────

export type AgentIngressMode = "open" | "restricted";

export interface AgentIngressPort {
	proto: "tcp" | "udp";
	/** single port "443" or range "8000:8010" */
	port: string;
}

export interface AgentIngressRule {
	id: number;
	agentId: number;
	name: string;
	/** source CIDRs (at least one) */
	sources: string[];
	/** target CIDRs — [] = any target */
	destinations: string[];
	/** [] = all ports */
	ports: AgentIngressPort[];
	enabled: boolean;
	note: string | null;
	hitPackets: number;
	/** unix seconds, null = never hit */
	lastHitAt: number | null;
	createdOn: number | string;
	modifiedOn: number | string;
	/** unix seconds: last create / switch-on / target change (not rename or note edit) */
	armedOn?: number | null;
}

export interface AgentIngressRuleData {
	name: string;
	sources: string[];
	destinations: string[];
	ports: AgentIngressPort[];
	enabled: boolean;
	note?: string;
}

/** What the agent reported as running vs. what the hub wants (heartbeat). */
export interface AgentIngressApplied {
	state: "applied" | "pending" | "offline" | "failed" | "unknown";
	appliedHash: string | null;
	desiredHash: string | null;
	error: string | null;
}

export interface AgentIngressState {
	agentId: number;
	ingressMode: AgentIngressMode;
	rules: AgentIngressRule[];
	applied?: AgentIngressApplied;
}

export interface AgentIngressPreview {
	agentId: number;
	ingressMode: AgentIngressMode;
	iface: string;
	rulesText: string | null;
	ruleCount: number;
	hash: string | null;
}

export interface AgentIngressMissingUpstream {
	kind: "proxy-host" | "stream" | "manual" | "hub-egress" | "vpn-client";
	id: number | string;
	label: string;
	host: string;
	port: number | null;
	proto: "tcp" | "udp";
	enabled: boolean;
	/** null = upstream without a known port: no one-click rule (would open all ports). */
	suggestion: Pick<AgentIngressRuleData, "name" | "sources" | "destinations" | "ports"> | null;
}

/** Hub-sourced rule broader than the proxy traffic needs (hub source also carries the Hetzner-LAN SNAT). */
export interface AgentIngressBroadHubRule {
	id: number;
	name: string;
	reason: "all-ports" | "unused-ports";
	/** unused-ports: the port entries no upstream uses ("80/tcp", "8000:8100/tcp") */
	ports: string[];
}

export interface AgentIngressCheck {
	agentId: number;
	agentName: string;
	ingressMode: AgentIngressMode;
	/** false = the bound WireGuard link does not exist, nothing was checked */
	linkFound?: boolean;
	/** linkFound=false: "typed-client" = the link exists but is typed client; else "not-found" */
	linkHint?: "typed-client" | "not-found";
	linkHintName?: string;
	wgLinkName?: string;
	hubSources: string[];
	/** number of configured hub egress flows (/data/hub-egress-flows.json) */
	hubEgressFlows?: number;
	missing: AgentIngressMissingUpstream[];
	/** Switched-off proxy hosts/streams a restricted agent would drop — info only. */
	missingDisabled?: Omit<AgentIngressMissingUpstream, "suggestion">[];
	/** Upstreams given by a DNS name that did not resolve — not checkable. */
	unchecked?: Omit<AgentIngressMissingUpstream, "suggestion" | "enabled">[];
	unusedHubRules: Array<{ id: number; name: string; unused: string[] }>;
	broadHubRules?: AgentIngressBroadHubRule[];
	applied?: AgentIngressApplied;
}

/** What a catalog entry stands for (sources: hub … tunnel; destinations: proxy-host … network). */
export type AgentIngressCatalogKind =
	| "hub"
	| "hub-egress"
	| "site"
	| "site-net"
	| "client"
	| "tunnel"
	| "proxy-host"
	| "stream"
	| "manual"
	| "service"
	| "network";

/** One known source or destination of an agent (pickers, wizards, names for CIDRs). */
export interface AgentIngressCatalogEntry {
	/** stable id: "hub", "site:<link>", "site-net:<link>:<cidr>", "client:<link>", "host:<ip>", "net:<cidr>", … */
	id: string;
	kind: AgentIngressCatalogKind;
	/** display name; "hub" for the hub, the CIDR for site-net / network / tunnel entries */
	label: string;
	/** host entries: every name (domains, stream labels, service names), first = main name */
	names?: string[];
	cidrs: string[];
	/** host entries: the ports the upstreams/services use (display) */
	ports?: AgentIngressPort[];
	/**
	 * upstream host entries: only the ports the hub's proxy hosts / streams use —
	 * a proxy rule opens these, never the ports of services found on the host
	 */
	upstreamPorts?: AgentIngressPort[];
	/** host entries: at least one upstream is enabled */
	enabled?: boolean;
	/** host entries: every upstream is already covered by an enabled rule */
	covered?: boolean;
	/** "no-port" (upstream without known port), "masquerade" (site hides LAN IPs), "snat-hub-lan" (hub) */
	hint?: string;
	online?: boolean;
	/** site-net: id of its site entry */
	parent?: string;
}

export interface AgentIngressPortPreset {
	/** web, ssh, smb, ldap, rdp, dns, proxmox, pbs, all */
	id: string;
	/** [] = all ports */
	ports: AgentIngressPort[];
}

/** Enabled rule without a new connection for 30 days that no upstream needs. */
export interface AgentIngressPruneCandidate {
	id: number;
	name: string;
	lastHitAt: number | null;
	reason: "no-hits-30d";
}

export interface AgentIngressCatalog {
	agentId: number;
	agentName: string;
	ingressMode: AgentIngressMode;
	/** false = the bound WireGuard link does not exist: no site, no destinations behind it */
	linkFound: boolean;
	site: { linkId: string; name: string; networks: string[] } | null;
	sources: AgentIngressCatalogEntry[];
	destinations: AgentIngressCatalogEntry[];
	portPresets: AgentIngressPortPreset[];
	pruneCandidates: AgentIngressPruneCandidate[];
}

export interface AgentIngressTestRequest {
	source: string;
	destination: string;
	port?: number | null;
	proto?: "tcp" | "udp";
}

export interface AgentIngressRuleRef {
	id: number;
	name: string;
}

/** What the agent's filter does with one flow (read-only "Darf X auf Y?"). */
export interface AgentIngressTestResult {
	mode: AgentIngressMode;
	/** null = the agent does not decide (not-via-agent / same-site / link-not-found) */
	allowed: boolean | null;
	filtered: boolean;
	/** link-not-found: the agent's bound WireGuard link is missing/renamed — its networks are unknown */
	/** site-isolation: the hub drops the flow before it reaches the agent ("Standorte untereinander") */
	reason: "rule" | "no-rule" | "open-mode" | "not-via-agent" | "same-site" | "link-not-found" | "site-isolation";
	rule: AgentIngressRuleRef | null;
	matchedRules: AgentIngressRuleRef[];
	/** a disabled rule that would match */
	disabledMatch: AgentIngressRuleRef | null;
	/** no port given and only port-restricted rules would match */
	portUnknown: boolean;
	notes: Array<
		| "established-return"
		| "forward-only"
		| "not-applied"
		| "site-isolation-not-applied"
		| "site-isolation-partial"
		| "site-isolation-unknown"
		| string
	>;
	linkFound?: boolean;
	/** reason site-isolation: the blocked pair, direction = which side is the source */
	siteIsolation?: SiteIsolationPairRef | null;
	/** reason site-isolation without a pair: a drop rule set by hand at the hub, outside FloppyGuard */
	siteIsolationManual?: SiteIsolationForeignRule | null;
}

export interface AgentIngressBulkResult {
	created: AgentIngressRule[];
	/** switched-off rules with the same targets, switched back on instead of a duplicate (older backends: absent) */
	reenabled?: AgentIngressRule[];
	skipped: Array<{ index: number; reason: "duplicate"; ruleId: number | null }>;
}

// ── "Standorte untereinander" (hub-side site isolation) ──────────────────────

/** A site-to-site link as the isolation matrix shows it. */
export interface SiteIsolationSite {
	linkId: string;
	name: string;
	/** imported networks behind the site (canonical CIDRs) */
	networks: string[];
	/** tunnel /32s of the site */
	tunnel: string[];
	online: boolean;
}

/** One isolated (blocked) pair; linkA < linkB. */
export interface SiteIsolationPair {
	id: number;
	linkA: string;
	linkB: string;
	/** null = the link no longer exists */
	nameA: string | null;
	nameB: string | null;
	/** false = stored but not in the hub table (link gone, no networks …) */
	enforced: boolean;
	/** drop counters of both directions; null = no counters (not applied / nft unavailable) */
	dropped: { packets: number; bytes: number } | null;
}

export interface SiteIsolationApplied {
	hash: string | null;
	/** unix seconds of the last successful apply */
	at: number | null;
	error: string | null;
	errorAt: number | null;
	/** persisted boot copy (null = not written) */
	file: string | null;
	/** "input" | "nft" | "links-unresolved" (previous table kept); null = no error */
	errorCode?: string | null;
	/** the table exists on the hub right now */
	tablePresent?: boolean;
}

/** A drop rule outside FloppyGuard (another forward chain on the hub). */
export interface SiteIsolationForeignRule {
	family: string;
	table: string;
	chain: string;
	comment: string | null;
	srcSet?: string | null;
	dstSet?: string | null;
}

/** Two sites that a manual hub rule (outside FloppyGuard) separates. */
export interface SiteIsolationManualPair {
	linkA: string;
	linkB: string;
	rules: SiteIsolationForeignRule[];
}

export interface SiteIsolationWarning {
	code:
		| "network-skipped"
		| "link-missing"
		| "link-missing-held"
		| "manual-drop"
		| "boot-include-missing"
		| "link-not-site"
		| "no-networks"
		| "overlap"
		| "persist-failed"
		| "route-dropped"
		| string;
	/** German text from the backend (fallback for codes without a translation) */
	message: string;
	linkId?: string;
	name?: string;
	pair?: { a: string; b: string };
	networks?: string[];
	agentId?: number;
	agentName?: string;
	otherLinkId?: string;
	otherName?: string;
	via?: "allowed_networks" | "allowed_sites" | "full-mesh";
	/** network-skipped: why */
	reason?: "invalid" | "default-route" | "ipv6-unsupported" | string;
	value?: string;
	/** manual-drop: the foreign rules */
	rules?: SiteIsolationForeignRule[];
	/** boot-include-missing: the file the boot config should include */
	file?: string;
}

export interface SiteIsolationOverview {
	sites: SiteIsolationSite[];
	pairs: SiteIsolationPair[];
	applied: SiteIsolationApplied;
	warnings: SiteIsolationWarning[];
	/** pairs separated by manual hub rules outside FloppyGuard (older backends: absent) */
	manualPairs?: SiteIsolationManualPair[];
	/** last change of the pair set (audit log); null = none recorded */
	lastChange?: { at: number | null; by: string | null } | null;
}

/** PUT body entry: the full set replaces the stored pairs. */
export interface SiteIsolationPairInput {
	linkA: string;
	linkB: string;
}

/** Pair reference in a tester verdict. */
export interface SiteIsolationPairRef {
	a: string;
	b: string;
	nameA: string;
	nameB: string;
	direction: "a-to-b" | "b-to-a";
}
