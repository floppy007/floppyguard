import { QueryClient, QueryClientProvider, QueryObserver } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { ThemeProvider } from "src/context";
import { AgentIngressDialog } from "src/modals/AgentIngressModal";
import { IngressPageContent } from "src/pages/Ingress";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	buildIngressAgentEntries,
	ingressAgentSubName,
	ingressSiteName,
	pickDefaultIngressAgent,
	resolveIngressAgent,
} from "./agentList";
import { missingProxySuggestions } from "./ComfortActions";
import { changedRuleData } from "./RuleForm";
import { AgentIngressRuleSentences } from "./RuleSentences";
import {
	ingressPendingInterval,
	invalidateAgentIngress,
	PENDING_POLL_MS,
	PENDING_POLL_WINDOW_MS,
	resetIngressPollWindows,
} from "src/hooks/useAgentIngress";
import {
	bulkResultInfo,
	ingressUnusedCount,
	ingressWarningCount,
	isIpv4OrCidr,
	isStaleRule,
	parsePorts,
	STALE_HIT_SECONDS,
	validateRuleForm,
} from "./utils";

// ── fetch mock (snake_case payloads, like the real backend) ───────────────────

const now = Math.floor(Date.now() / 1000);

const rules = [
	{
		id: 11,
		agent_id: 1,
		name: "Hub -> Nextcloud",
		sources: ["10.10.0.1"],
		destinations: ["192.168.60.22"],
		ports: [{ proto: "tcp", port: "443" }],
		enabled: true,
		note: null,
		hit_packets: 42,
		last_hit_at: now - 120,
		created_on: now,
		modified_on: now,
	},
	{
		id: 12,
		agent_id: 1,
		name: "Office LAN",
		sources: ["192.168.20.0/24"],
		destinations: [],
		ports: [],
		enabled: true,
		note: "Altlast aus VPN_MGR",
		hit_packets: 0,
		last_hit_at: null,
		created_on: now,
		modified_on: now,
	},
];

const suggestion = {
	name: "Proxy cloud.example.com",
	sources: ["10.10.0.1"],
	destinations: ["192.168.60.9"],
	ports: [],
};

const checkPayload = [
	{
		agent_id: 1,
		agent_name: "site-a",
		ingress_mode: "open",
		hub_sources: ["10.10.0.1"],
		missing: [
			{
				kind: "proxy-host",
				id: 7,
				label: "cloud.example.com",
				host: "192.168.60.9",
				port: 443,
				proto: "tcp",
				enabled: true,
				suggestion,
			},
		],
		missing_disabled: [
			{
				kind: "proxy-host",
				id: 21,
				label: "edge.example.com",
				host: "192.168.60.3",
				port: 3010,
				proto: "tcp",
				enabled: false,
			},
		],
		unchecked: [
			{ kind: "manual", id: "zz-nas.conf", label: "nas.example.com", host: "nas.intra", port: 80, proto: "tcp" },
		],
		unused_hub_rules: [{ id: 11, name: "Hub -> Nextcloud", unused: ["192.168.60.22"] }],
	},
];

/** current filter mode per agent (a PUT changes it, like the backend) */
let agentModes: Record<number, "open" | "restricted"> = { 1: "open", 2: "restricted" };
/** status of agent 1 as the API reports it */
let agent1Status = "active";

const agentsPayload = () => [
	{ id: 1, name: "site-a", status: agent1Status, wg_link_name: "site-a", ingress_mode: agentModes[1], services: [] },
	{ id: 2, name: "VM-B (10.0.0.2)", status: "active", wg_link_name: "site-b", ingress_mode: agentModes[2], services: [] },
];

// snake_case like the backend; the API layer camelizes it
const catalogPayload = (agentId: number) => ({
	agent_id: agentId,
	agent_name: agentId === 1 ? "site-a" : "site-b",
	ingress_mode: agentId === 2 ? "restricted" : "open",
	link_found: true,
	site: { link_id: "wg0:A", name: "Site A", networks: ["192.168.60.0/24"] },
	sources: [
		{ id: "hub", kind: "hub", label: "hub", cidrs: ["10.10.0.1/32"], hint: "snat-hub-lan" },
		{ id: "site:wg0:B", kind: "site", label: "Branch", cidrs: ["192.168.20.0/24"], online: true },
	],
	destinations: [
		{
			id: "host:192.168.60.9",
			kind: "proxy-host",
			label: "Cloud",
			names: ["Cloud", "cloud.example.com"],
			cidrs: ["192.168.60.9/32"],
			ports: [{ proto: "tcp", port: "443" }],
			enabled: true,
			covered: false,
		},
		{
			id: "host:192.168.60.22",
			kind: "proxy-host",
			label: "Nextcloud",
			names: ["Nextcloud"],
			cidrs: ["192.168.60.22/32"],
			ports: [{ proto: "tcp", port: "443" }],
			enabled: true,
			covered: true,
		},
		{
			id: "host:192.168.60.30",
			kind: "manual",
			label: "var.example.com",
			names: ["var.example.com"],
			cidrs: ["192.168.60.30/32"],
			ports: [],
			enabled: true,
			covered: false,
			hint: "no-port",
		},
		{ id: "net:192.168.60.0/24", kind: "network", label: "192.168.60.0/24", cidrs: ["192.168.60.0/24"] },
	],
	port_presets: [
		{
			id: "web",
			ports: [
				{ proto: "tcp", port: "80" },
				{ proto: "tcp", port: "443" },
			],
		},
		{ id: "ssh", ports: [{ proto: "tcp", port: "22" }] },
		{ id: "all", ports: [] },
	],
	// agent 2 is restricted with one enabled rule: the UI must never offer to switch it off
	prune_candidates:
		agentId === 1
			? [{ id: 12, name: "Office LAN", last_hit_at: null, reason: "no-hits-30d" }]
			: [{ id: 21, name: "Site B rule", last_hit_at: null, reason: "no-hits-30d" }],
});

const testResult = {
	mode: "restricted",
	allowed: true,
	filtered: true,
	reason: "rule",
	rule: { id: 11, name: "Hub -> Nextcloud" },
	matched_rules: [{ id: 11, name: "Hub -> Nextcloud" }],
	disabled_match: null,
	port_unknown: false,
	notes: ["established-return", "forward-only"],
	link_found: true,
};

/** status of the catalog endpoint (500 = old/failing backend → plain form) */
let catalogStatus = 200;
/** agent whose ingress state has no rules (empty state) */
let emptyAgent: number | null = null;

/** Check entry of the restricted agent 2 with one dropped proxy target. */
const restrictedCheck = {
	agent_id: 2,
	agent_name: "site-b",
	ingress_mode: "restricted",
	hub_sources: ["10.10.0.1"],
	missing: [
		{
			kind: "proxy-host",
			id: 8,
			label: "wiki.example.com",
			host: "192.168.60.40",
			port: 443,
			proto: "tcp",
			enabled: true,
			suggestion: { ...suggestion, name: "Proxy wiki.example.com", destinations: ["192.168.60.40"] },
		},
	],
	unused_hub_rules: [],
};
let extraChecks: object[] = [];
/** backend answer to saving a single rule (POST/PUT): null = success, else the error message (400) */
let ruleSaveError: string | null = null;

type Call = { url: string; method: string; body: any };
let calls: Call[] = [];

const json = (body: unknown, status = 200) =>
	new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
	const url = String(input);
	const method = init?.method ?? "GET";
	const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
	calls.push({ url, method, body });

	if (url === "/api/agents" && method === "GET") return json(agentsPayload());
	if (url === "/api/agent-ingress/check") return json([...checkPayload, ...extraChecks]);
	const m = url.match(/^\/api\/agents\/(\d+)\/ingress(\/.*)?$/);
	if (m) {
		const agentId = Number(m[1]);
		const rest = m[2] ?? "";
		if (rest === "" && method === "GET") {
			return json({
				agent_id: agentId,
				ingress_mode: agentModes[agentId] ?? "open",
				rules:
					agentId === emptyAgent
						? []
						: agentId === 1
							? rules
							: [{ ...rules[0], id: 21, agent_id: 2, name: "Site B rule" }],
				applied:
					agentId === 2
						? {
								state: "failed",
								applied_hash: "NONE",
								desired_hash: "a".repeat(64),
								error: "rules rejected by iptables-restore --test",
							}
						: { state: "applied", applied_hash: "NONE", desired_hash: "NONE", error: null },
			});
		}
		if (rest === "" && method === "PUT") {
			agentModes[agentId] = body.ingress_mode;
			return json({ agent_id: agentId, ingress_mode: body.ingress_mode, rules });
		}
		if (rest === "/preview") {
			return json({ agent_id: agentId, ingress_mode: "open", iface: "wg1", rules_text: null, rule_count: 0 });
		}
		if (rest === "/catalog") {
			return catalogStatus === 200
				? json(catalogPayload(agentId))
				: json({ error: { message: "catalog failed" } }, catalogStatus);
		}
		if (rest === "/test" && method === "POST") return json(testResult);
		if (rest === "/rules/bulk" && method === "POST") {
			return json(
				{
					created: body.rules.map((r: object, i: number) => ({ ...rules[0], ...r, id: 100 + i })),
					skipped: [],
				},
				201,
			);
		}
		if (rest === "/rules/bulk-disable" && method === "POST") return json({ disabled: body.rule_ids });
		if (ruleSaveError && (rest === "/rules" || rest.startsWith("/rules/")) && (method === "POST" || method === "PUT")) {
			return json({ error: { message: ruleSaveError } }, 400);
		}
		if (rest === "/rules" && method === "POST") return json({ ...rules[0], id: 99, ...body }, 201);
		if (rest.startsWith("/rules/") && method === "PUT") return json({ ...rules[0], ...body });
	}
	return json({ error: { message: `unexpected ${method} ${url}` } }, 500);
});

/** Current router location, for asserting ?agent= */
let lastSearch = "";
function LocationProbe() {
	lastSearch = useLocation().search;
	return null;
}

const createWrapper = (initialEntries: string[] = ["/"]) => {
	const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
	return ({ children }: { children: ReactNode }) => (
		<QueryClientProvider client={queryClient}>
			<ThemeProvider>
				<MemoryRouter initialEntries={initialEntries}>
					{children}
					<LocationProbe />
				</MemoryRouter>
			</ThemeProvider>
		</QueryClientProvider>
	);
};

/** Open a tab of the agent detail ("Rules (2)", "Check", "Technical"). */
const openTab = async (name: string | RegExp) => fireEvent.click(await screen.findByRole("tab", { name }));

const confirmMock = vi.fn(() => true);

beforeEach(() => {
	calls = [];
	catalogStatus = 200;
	emptyAgent = null;
	agentModes = { 1: "open", 2: "restricted" };
	agent1Status = "active";
	extraChecks = [];
	ruleSaveError = null;
	lastSearch = "";
	try {
		window.localStorage.clear();
	} catch {
		// no storage
	}
	confirmMock.mockReset();
	// happy-dom has no window.confirm
	Object.defineProperty(window, "confirm", { value: confirmMock, configurable: true, writable: true });
	fetchMock.mockClear();
	vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

// ── Utils ─────────────────────────────────────────────────────────────────────

describe("agent ingress utils", () => {
	it("validates IPv4/CIDR and ports", () => {
		expect(isIpv4OrCidr("192.168.1.0/24")).toBe(true);
		expect(isIpv4OrCidr("10.0.0.1")).toBe(true);
		expect(isIpv4OrCidr("10.0.0.256")).toBe(false);
		expect(isIpv4OrCidr("10.0.0.0/33")).toBe(false);
		expect(parsePorts("tcp/443, udp/53\ntcp/8000-8010")).toEqual({
			ports: [
				{ proto: "tcp", port: "443" },
				{ proto: "udp", port: "53" },
				{ proto: "tcp", port: "8000:8010" },
			],
			invalid: [],
		});
		expect(parsePorts("443, tcp/70000").invalid).toEqual(["443", "tcp/70000"]);
		expect(
			validateRuleForm({ name: "", sources: "", destinations: "x", ports: "", note: "", enabled: true }),
		).toHaveLength(3);
		// nothing chosen is an error, never "all ports"; a derivable name is optional
		expect(
			validateRuleForm(
				{ name: "", sources: "10.0.0.1", destinations: "", ports: null, note: "", enabled: true },
				{ autoName: true },
			),
		).toEqual(["Choose ports or tick “All ports”."]);
	});

	it("flags stale rules from last hit or creation, never disabled ones", () => {
		const now = 2_000_000_000;
		const old = now - STALE_HIT_SECONDS - 60;
		// just created, never hit → not stale
		expect(isStaleRule({ lastHitAt: null, createdOn: now - 5, enabled: true }, now)).toBe(false);
		expect(
			isStaleRule({ lastHitAt: null, createdOn: new Date((now - 5) * 1000).toISOString(), enabled: true }, now),
		).toBe(false);
		// created long ago, never hit → stale
		expect(
			isStaleRule({ lastHitAt: null, createdOn: new Date(old * 1000).toISOString(), enabled: true }, now),
		).toBe(true);
		// old hit → stale, recent hit → fine
		expect(isStaleRule({ lastHitAt: old, createdOn: old, enabled: true }, now)).toBe(true);
		expect(isStaleRule({ lastHitAt: now - 60, createdOn: old, enabled: true }, now)).toBe(false);
		// disabled rules cannot get hits
		expect(isStaleRule({ lastHitAt: null, createdOn: old, enabled: false }, now)).toBe(false);
		// re-enabled just now (modifiedOn bumped) after an old hit → a fresh window
		expect(isStaleRule({ lastHitAt: old, createdOn: old, modifiedOn: now - 60, enabled: true }, now)).toBe(false);
		expect(
			isStaleRule(
				{
					lastHitAt: null,
					createdOn: old,
					modifiedOn: new Date((now - 60) * 1000).toISOString(),
					enabled: true,
				},
				now,
			),
		).toBe(false);
		expect(isStaleRule({ lastHitAt: old, createdOn: old, modifiedOn: old, enabled: true }, now)).toBe(true);
		// armedOn (backend) wins over modifiedOn: a rename/note edit does not reset the window …
		expect(
			isStaleRule({ lastHitAt: old, createdOn: old, modifiedOn: now - 60, armedOn: old, enabled: true }, now),
		).toBe(true);
		// … but switching on / changing targets (armedOn bumped) does
		expect(
			isStaleRule({ lastHitAt: old, createdOn: old, modifiedOn: now - 60, armedOn: now - 60, enabled: true }, now),
		).toBe(false);
	});

	it("invalidateAgentIngress resolves only after the refetch (create stays pending meanwhile)", async () => {
		const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
		let release: () => void = () => {};
		const gate = new Promise<void>((r) => {
			release = r;
		});
		await qc.fetchQuery({ queryKey: ["agent-ingress-check"], queryFn: () => [] });
		// an active observer so invalidation refetches it, with a slow queryFn
		const obs = new QueryObserver(qc, { queryKey: ["agent-ingress-check"], queryFn: () => gate.then(() => [1]) });
		const unsub = obs.subscribe(() => {});
		let done = false;
		const p = invalidateAgentIngress(qc).then(() => {
			done = true;
		});
		await new Promise((r) => setTimeout(r, 20));
		expect(done).toBe(false);
		release();
		await p;
		expect(done).toBe(true);
		unsub();
	});

	it("polls the ingress state only while a ruleset is pending", () => {
		resetIngressPollWindows();
		const applied = (state: "applied" | "pending" | "offline" | "failed" | "unknown") => ({
			state,
			appliedHash: null,
		});
		expect(ingressPendingInterval(undefined)).toBe(false);
		expect(ingressPendingInterval({ applied: applied("pending") } as never)).toBe(PENDING_POLL_MS);
		expect(ingressPendingInterval({ applied: applied("applied") } as never)).toBe(false);
		expect(ingressPendingInterval({ applied: applied("failed") } as never)).toBe(false);
		expect(
			ingressPendingInterval([{ applied: applied("applied") }, { applied: applied("pending") }] as never),
		).toBe(PENDING_POLL_MS);
		expect(ingressPendingInterval([{ applied: applied("applied") }, {}] as never)).toBe(false);
		// an offline agent is not polled at all
		expect(ingressPendingInterval({ applied: applied("offline") } as never)).toBe(false);
	});

	it("stops polling a pending ruleset after a bounded window and restarts it on a change", () => {
		resetIngressPollWindows();
		const pending = [{ applied: { state: "pending", appliedHash: null } }] as never;
		const t0 = 1_000_000;
		expect(ingressPendingInterval(pending, "check", t0)).toBe(PENDING_POLL_MS);
		expect(ingressPendingInterval(pending, "check", t0 + PENDING_POLL_WINDOW_MS - 1)).toBe(PENDING_POLL_MS);
		expect(ingressPendingInterval(pending, "check", t0 + PENDING_POLL_WINDOW_MS)).toBe(false);
		// another query has its own window
		expect(ingressPendingInterval(pending, "agent-1", t0 + PENDING_POLL_WINDOW_MS)).toBe(PENDING_POLL_MS);
		// a mutation (invalidateAgentIngress) opens a new window
		resetIngressPollWindows();
		expect(ingressPendingInterval(pending, "check", t0 + 10 * PENDING_POLL_WINDOW_MS)).toBe(PENDING_POLL_MS);
		// leaving "pending" closes the window
		expect(ingressPendingInterval([] as never, "check", t0)).toBe(false);
	});
});

describe("rule form diff and warning counts", () => {
	const base = { name: "A", sources: "10.0.0.1", destinations: "", ports: "tcp/443", note: "", enabled: true };

	it("sends only the fields the admin changed", () => {
		expect(changedRuleData(base, { ...base, name: "B" })).toEqual({ name: "B" });
		// reformatting the same list is no change
		expect(changedRuleData(base, { ...base, sources: " 10.0.0.1 ", ports: "TCP/443" })).toEqual({});
		expect(changedRuleData(base, { ...base, enabled: false })).toEqual({ enabled: false });
	});

	it("counts only missing upstreams as warnings, unused rules separately", () => {
		const entry = {
			missing: [checkPayload[0].missing[0]] as never[],
			unusedHubRules: [{ id: 1, name: "x", unused: [] }],
		};
		expect(ingressWarningCount(entry)).toBe(1);
		expect(ingressUnusedCount(entry)).toBe(1);
		expect(ingressWarningCount(undefined)).toBe(0);
	});
});

// ── Modal ─────────────────────────────────────────────────────────────────────

describe("AgentIngressDialog", () => {
	const renderDialog = () =>
		render(<AgentIngressDialog agentId={1} agentName="site-a" visible onClose={() => {}} />, {
			wrapper: createWrapper(),
		});

	it("renders the raw rules from the API in the Technical tab", async () => {
		renderDialog();
		// the raw table lives in "Technical", the sentence view is the default
		await openTab("Technical");
		const tech = await screen.findByTestId("ingress-tech");
		const table = within(tech);
		expect(table.getByText("Hub -> Nextcloud")).toBeTruthy();
		expect(table.getByText("Office LAN")).toBeTruthy();
		expect(table.getByText("tcp/443")).toBeTruthy();
		// empty destinations/ports → "all", legacy note badge, never-hit marker, hit counter
		expect(table.getAllByText("all").length).toBe(2);
		expect(table.getByText("Legacy")).toBeTruthy();
		expect(table.getByText("no hit yet")).toBeTruthy();
		expect(table.getByText(/^last: .*ago/)).toBeTruthy();
		expect(table.getByText("42 packets")).toBeTruthy();
		// interface and generated rules (fetched with the tab)
		await waitFor(() => expect(tech.textContent).toContain("wg1"));
		expect(tech.textContent).toContain("No filter active (filter off).");
	});

	it("switching to restricted asks for confirmation and PUTs the mode", async () => {
		confirmMock.mockReturnValue(true);
		renderDialog();
		const banner = await screen.findByTestId("ingress-banner");
		expect(banner.textContent).toContain("Ingress filter at this site: off");
		expect(banner.textContent).toContain("checks traffic that wants to enter this site’s network from the tunnel");
		fireEvent.click(within(banner).getByRole("button", { name: "Turn ingress filter on" }));
		expect(confirmMock).toHaveBeenCalled();
		await waitFor(() => {
			const put = calls.find((c) => c.method === "PUT" && c.url === "/api/agents/1/ingress");
			expect(put?.body).toEqual({ ingress_mode: "restricted" });
		});
	});

	it("does not switch when the confirmation is declined", async () => {
		confirmMock.mockReturnValue(false);
		renderDialog();
		fireEvent.click(await screen.findByRole("button", { name: "Turn ingress filter on" }));
		expect(confirmMock).toHaveBeenCalled();
		expect(calls.some((c) => c.method === "PUT")).toBe(false);
	});

	it("'Create rule' on a missing upstream POSTs the suggestion", async () => {
		renderDialog();
		await openTab("Check");
		expect(await screen.findByText("cloud.example.com")).toBeTruthy();
		expect(screen.getByText(/no proxy host\/stream uses this target/)).toBeTruthy();
		fireEvent.click(screen.getByRole("button", { name: "Create rule" }));
		await waitFor(() => {
			const post = calls.find((c) => c.method === "POST" && c.url === "/api/agents/1/ingress/rules");
			expect(post?.body).toEqual({ ...suggestion, enabled: true });
		});
	});

	it("an upstream without a known port gets no one-click rule; broad hub rules are flagged", async () => {
		const entry = checkPayload[0] as Record<string, unknown> & { missing: unknown[] };
		entry.missing.push({
			kind: "manual",
			id: "zz-var.conf",
			label: "var.example.com",
			host: "192.168.60.30",
			port: null,
			proto: "tcp",
			enabled: true,
			suggestion: null,
		});
		entry.broad_hub_rules = [
			{ id: 31, name: "Hub wide open", reason: "all-ports", ports: [] },
			{ id: 32, name: "Hub extra ports", reason: "unused-ports", ports: ["22/tcp"] },
		];
		try {
			renderDialog();
			await openTab("Check");
			expect(await screen.findByText("var.example.com")).toBeTruthy();
			// only the upstream with a port has the button
			expect(screen.getAllByRole("button", { name: "Create rule" }).length).toBe(1);
			expect(screen.getByTestId("ingress-no-port")).toBeTruthy();
			const broad = screen.getByTestId("ingress-broad-hub-rules");
			expect(broad.textContent).toContain("Hub wide open");
			expect(broad.textContent).toContain("every port of the targets is open");
			expect(broad.textContent).toContain("22/tcp");
		} finally {
			entry.missing.pop();
			delete entry.broad_hub_rules;
		}
	});

	it("disabled upstreams are info only, unresolvable host names are listed as not checkable", async () => {
		renderDialog();
		await openTab("Check");
		expect(await screen.findByText("edge.example.com")).toBeTruthy();
		expect(screen.getByText(/Disabled proxy hosts\/streams without a rule/)).toBeTruthy();
		expect(screen.getByText(/Not checkable/)).toBeTruthy();
		expect(screen.getByText("nas.example.com")).toBeTruthy();
		// only the enabled missing upstream offers "Create rule"
		expect(screen.getAllByRole("button", { name: "Create rule" })).toHaveLength(1);
		// applied state "applied" shows no alert
		expect(screen.queryByTestId("ingress-applied-state")).toBeNull();
	});

	it("a ruleset the agent rejected is shown as not applied", async () => {
		render(<AgentIngressDialog agentId={2} agentName="site-b" visible onClose={() => {}} />, {
			wrapper: createWrapper(),
		});
		const alert = await screen.findByTestId("ingress-applied-state");
		expect(alert.textContent).toContain("did NOT apply");
		expect(alert.textContent).toContain("iptables-restore --test");
	});

	it("toggling a rule PUTs enabled=false", async () => {
		renderDialog();
		fireEvent.click(await screen.findByLabelText("Rule Office LAN active"));
		await waitFor(() => {
			const put = calls.find((c) => c.method === "PUT" && c.url === "/api/agents/1/ingress/rules/12");
			expect(put?.body).toEqual({ enabled: false });
		});
	});

	it("saving an edit form does not undo a toggle made while it was open", async () => {
		renderDialog();
		fireEvent.click(await screen.findByRole("menuitem", { name: "Edit Office LAN" }));
		// toggle the same rule in the table while the form is open
		fireEvent.click(screen.getByLabelText("Rule Office LAN active"));
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT" && c.url === "/api/agents/1/ingress/rules/12")).toBe(true),
		);
		calls = [];
		fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Office LAN 2" } });
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => {
			const put = calls.find((c) => c.method === "PUT" && c.url === "/api/agents/1/ingress/rules/12");
			expect(put?.body).toEqual({ name: "Office LAN 2" });
		});
	});

	it("form validation blocks invalid input without calling the API", async () => {
		// plain text fields (catalog unavailable)
		catalogStatus = 500;
		renderDialog();
		fireEvent.click(await screen.findByRole("button", { name: /New rule/ }));
		fireEvent.change(screen.getByLabelText("Name"), { target: { value: "x" } });
		fireEvent.change(screen.getByLabelText("Sources"), { target: { value: "10.0.0.999" } });
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		expect(await screen.findByText("Invalid IPv4 address/CIDR: 10.0.0.999")).toBeTruthy();
		expect(calls.some((c) => c.method === "POST")).toBe(false);
	});

	it("groups the rules by source as sentences (default view)", async () => {
		renderDialog();
		await waitFor(() => expect(screen.getAllByTestId("ingress-source-group")).toHaveLength(2));
		const [hub, branch] = screen.getAllByTestId("ingress-source-group");
		expect(hub.textContent).toContain("Reverse proxy (hub)");
		expect(hub.textContent).toContain("1 of 1 active");
		const [hubRow] = within(hub).getAllByTestId("ingress-rule-targets");
		expect(hubRow.textContent).toContain("Nextcloud (192.168.60.22)");
		expect(hubRow.textContent).toContain("tcp/443");
		expect(hub.textContent).toContain("Hub -> Nextcloud");
		expect(hub.textContent).toMatch(/last: .*ago/);
		expect(branch.textContent).toContain("Branch");
		expect(branch.textContent).toContain("everything in the site");
		expect(branch.textContent).toContain("all ports");
		expect(branch.textContent).toContain("Legacy");
		expect(branch.textContent).toContain("no hit yet");
		// rows carry the id the tester jumps to
		expect(document.getElementById("ingress-rule-1-12")).toBeTruthy();
		// sections collapse
		const toggle = within(branch).getByRole("button", { expanded: true });
		fireEvent.click(toggle);
		expect(toggle.getAttribute("aria-expanded")).toBe("false");
		expect(document.getElementById("ingress-rule-1-12")).toBeNull();
		expect(document.getElementById("ingress-rule-1-11")).toBeTruthy();
	});

	it("tabs: rules first, the check tab holds tester (first) and proxy check, the technical tab table and preview", async () => {
		renderDialog();
		const rulesTab = await screen.findByRole("tab", { name: "Rules (2)" });
		expect(rulesTab.getAttribute("aria-selected")).toBe("true");
		expect(screen.getByTestId("ingress-sentences")).toBeTruthy();
		expect(screen.queryByTestId("ingress-tester")).toBeNull();
		expect(screen.queryByTestId("ingress-tech")).toBeNull();
		// open agent: no warnings badge on "Check"
		expect(screen.queryByTestId("ingress-tab-check-badge")).toBeNull();

		await openTab("Check");
		const check = screen.getByTestId("ingress-panel-check");
		expect(within(check).getByTestId("ingress-tester")).toBeTruthy();
		expect(within(check).getByTestId("ingress-check")).toBeTruthy();
		// the tester comes first, the reverse-proxy comparison below it;
		// the plain-language heading, no X/Y template
		const sections = [...check.querySelectorAll("section")].map((s) => s.getAttribute("data-testid"));
		expect(sections.indexOf("ingress-tester")).toBe(0);
		expect(sections.indexOf("ingress-check")).toBeGreaterThan(0);
		expect(within(check).getByRole("heading", { name: "Test a connection" })).toBeTruthy();
		// the hub egress footnote (file path, SNAT) is technical detail, not part of the check view
		expect(within(check).queryByTestId("ingress-egress-note")).toBeNull()
		expect(screen.getByTestId("ingress-panel-rules").hidden).toBe(true);

		await openTab("Technical");
		const tech = screen.getByTestId("ingress-panel-tech");
		expect(within(tech).getByRole("table")).toBeTruthy();
		expect(tech.textContent).toContain("Generated rules");
		expect(within(tech).getByTestId("ingress-egress-note").textContent).toContain("hub-egress-flows.json");
		expect(tech.textContent).toContain("Hub's own flows");
		// the rule list stays out of the technical tab
		expect(within(tech).queryByTestId("ingress-sentences")).toBeNull();

		// arrow keys move between tabs
		fireEvent.keyDown(screen.getByRole("tab", { name: "Technical" }), { key: "ArrowRight" });
		expect(screen.getByRole("tab", { name: "Rules (2)" }).getAttribute("aria-selected")).toBe("true");
	});

	it("an agent without rules explains what a rule is and offers 'New rule'", async () => {
		emptyAgent = 1;
		renderDialog();
		const empty = await screen.findByTestId("ingress-empty");
		expect(empty.textContent).toContain("No rules yet");
		expect(empty.textContent).toContain("reverse proxy on the hub");
		expect(within(empty).getByRole("button", { name: /New rule/ })).toBeTruthy();
		expect(screen.getAllByRole("button", { name: /New rule/ })).toHaveLength(1);
		expect(screen.queryByTestId("ingress-sentences")).toBeNull();
	});

	it("filter on without an active rule: red banner and an empty state that says nothing gets through", async () => {
		emptyAgent = 2;
		render(<AgentIngressDialog agentId={2} agentName="site-b" visible onClose={() => {}} />, {
			wrapper: createWrapper(),
		});
		const banner = await screen.findByTestId("ingress-banner");
		expect(banner.getAttribute("data-blocked")).toBe("true");
		expect(banner.querySelector(".card-status-start")?.className).toContain("bg-red");
		expect(within(banner).getByTestId("ingress-banner-blocked").textContent).toContain(
			"no active rule – all traffic from the tunnel is dropped",
		);
		const empty = await screen.findByTestId("ingress-empty");
		expect(empty.textContent).toContain("without a rule nothing gets through");
		expect(empty.textContent).not.toContain("only count hits");
	});

	it("an open agent without rules keeps the calm banner and the 'only count hits' note", async () => {
		emptyAgent = 1;
		renderDialog();
		const banner = await screen.findByTestId("ingress-banner");
		expect(banner.getAttribute("data-blocked")).toBeNull();
		expect(banner.querySelector(".card-status-start")?.className).toContain("bg-secondary");
		expect((await screen.findByTestId("ingress-empty")).textContent).toContain("only count hits");
	});

	it("never offers to delete the agent", async () => {
		renderDialog();
		await screen.findByTestId("ingress-sentences");
		expect(screen.queryByText(/delete agent/i)).toBeNull();
		expect(document.querySelector("[data-testid^='ingress-agent-delete']")).toBeNull();
		// the dialog links to the page with this agent selected
		expect(screen.getByRole("link", { name: /Show all ingress rules/ }).getAttribute("href")).toBe("/ingress?agent=1");
	});

	it("the proxy wizard creates one rule per chosen host via bulk", async () => {
		renderDialog();
		fireEvent.click(await screen.findByRole("menuitem", { name: "Publish a service via the proxy" }));
		const wizard = await screen.findByTestId("ingress-wizard-proxy");
		expect(wizard.textContent).toContain("missing");
		expect(wizard.textContent).toContain("already released");
		// no known port: not selectable
		expect((screen.getByLabelText("var.example.com (192.168.60.30)") as HTMLInputElement).disabled).toBe(true);
		const next = screen.getByRole("button", { name: "Next" }) as HTMLButtonElement;
		expect(next.disabled).toBe(true);
		fireEvent.click(screen.getByLabelText("Cloud (192.168.60.9)"));
		fireEvent.click(screen.getByLabelText("Nextcloud (192.168.60.22)"));
		fireEvent.click(next);
		const preview = await screen.findByTestId("ingress-wizard-preview");
		expect(preview.textContent).toContain("Reverse proxy (hub) may access Cloud (192.168.60.9) – ports tcp/443");
		expect(preview.textContent).toContain("2 filter lines");
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => {
			const post = calls.find((c) => c.method === "POST" && c.url === "/api/agents/1/ingress/rules/bulk");
			expect(post?.body).toEqual({
				rules: [
					{
						name: "Proxy Cloud",
						sources: ["10.10.0.1/32"],
						destinations: ["192.168.60.9/32"],
						ports: [{ proto: "tcp", port: "443" }],
						enabled: true,
					},
					{
						name: "Proxy Nextcloud",
						sources: ["10.10.0.1/32"],
						destinations: ["192.168.60.22/32"],
						ports: [{ proto: "tcp", port: "443" }],
						enabled: true,
					},
				],
			});
		});
		expect(await screen.findByText("2 created, 0 skipped")).toBeTruthy();
		await waitFor(() => expect(screen.queryByTestId("ingress-wizard-proxy")).toBeNull());
	});

	it("the site wizards need explicit choices before saving", async () => {
		renderDialog();
		const pick = (label: string, value: string) => {
			const input = screen.getByLabelText(label);
			fireEvent.change(input, { target: { value } });
			fireEvent.keyDown(input, { key: "Enter", code: "Enter", keyCode: 13 });
		};
		fireEvent.click(await screen.findByRole("menuitem", { name: "A site may access servers" }));
		const next = () => screen.getByRole("button", { name: "Next" }) as HTMLButtonElement;
		expect(next().disabled).toBe(true);
		pick("Site", "Branch");
		fireEvent.click(next());
		expect(next().disabled).toBe(true);
		pick("Servers", "Cloud");
		fireEvent.click(next());
		// nothing preselected: "All ports" must be chosen explicitly
		expect(next().disabled).toBe(true);
		expect((screen.getByLabelText("All ports") as HTMLInputElement).checked).toBe(false);
		fireEvent.click(screen.getByLabelText("Web (80/443)"));
		fireEvent.click(next());
		expect((await screen.findByTestId("ingress-wizard-preview")).textContent).toContain(
			"Branch may access Cloud (192.168.60.9) – ports tcp/80, tcp/443",
		);
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		// one rule goes through the bulk endpoint too (duplicates skipped / re-enabled there)
		await waitFor(() => {
			const post = calls.find((c) => c.method === "POST" && c.url === "/api/agents/1/ingress/rules/bulk");
			expect(post?.body).toEqual({
				rules: [
					{
						name: "Branch → Cloud (192.168.60.9)",
						sources: ["192.168.20.0/24"],
						destinations: ["192.168.60.9/32"],
						ports: [
							{ proto: "tcp", port: "80" },
							{ proto: "tcp", port: "443" },
						],
						enabled: true,
					},
				],
			});
		});
		await waitFor(() => expect(screen.queryByTestId("ingress-wizard-site")).toBeNull());
		// confirmation instead of a silently vanishing wizard
		expect(await screen.findByText("Rule “Branch → Cloud (192.168.60.9)” created.")).toBeTruthy();

		calls = [];
		fireEvent.click(screen.getByRole("menuitem", { name: "A site gets full access" }));
		pick("Site", "Branch");
		fireEvent.click(next());
		expect(screen.getByTestId("ingress-wizard-full-warning")).toBeTruthy();
		const save = screen.getByRole("button", { name: "Save" }) as HTMLButtonElement;
		expect(save.disabled).toBe(true);
		fireEvent.click(screen.getByLabelText("Understood"));
		fireEvent.click(save);
		await waitFor(() => {
			const post = calls.find((c) => c.method === "POST" && c.url === "/api/agents/1/ingress/rules/bulk");
			expect(post?.body).toEqual({
				rules: [
					{
						name: "Branch – full access",
						sources: ["192.168.20.0/24"],
						destinations: [],
						ports: [],
						enabled: true,
					},
				],
			});
		});
	});

	it("the tester posts the flow and shows the verdict with a link to the rule", async () => {
		renderDialog();
		await openTab("Check");
		const pick = (label: string, value: string) => {
			const input = screen.getByLabelText(label);
			fireEvent.change(input, { target: { value } });
			fireEvent.keyDown(input, { key: "Enter", code: "Enter", keyCode: 13 });
		};
		// wait for the catalog-backed pickers
		await waitFor(() => expect(calls.some((c) => c.url === "/api/agents/1/ingress/catalog")).toBe(true));
		pick("Source", "10.10.0.1");
		pick("Destination", "192.168.60.22");
		fireEvent.change(screen.getByLabelText("Port"), { target: { value: "443" } });
		fireEvent.click(screen.getByRole("button", { name: "Check" }));
		await waitFor(() => {
			const post = calls.find((c) => c.method === "POST" && c.url === "/api/agents/1/ingress/test");
			expect(post?.body).toEqual({ source: "10.10.0.1", destination: "192.168.60.22", port: 443, proto: "tcp" });
		});
		const result = await screen.findByTestId("ingress-tester-result");
		expect(result.textContent).toContain("The FloppyGuard filter lets it through");
		expect(result.textContent).toContain("Reverse proxy (hub) → Nextcloud (192.168.60.22):443/tcp");
		expect(result.textContent).not.toMatch(/reachable/i);
		expect(result.className).toContain("alert-success");
		fireEvent.click(screen.getByRole("button", { name: "Go to rule Hub -> Nextcloud" }));
		// back to the rules tab, the rule highlighted
		await waitFor(() => expect(document.getElementById("ingress-rule-1-11")?.className).toContain("bg-primary-lt"));
		expect(screen.getByRole("tab", { name: "Rules (2)" }).getAttribute("aria-selected")).toBe("true");
	});

	it("'release all missing proxy targets' is offered only while restricted and posts the suggestions in bulk", async () => {
		// open agent with a missing target: listed, but no bulk button (it passes anyway)
		renderDialog();
		await openTab("Check");
		expect(await screen.findByText("cloud.example.com")).toBeTruthy();
		expect(screen.queryByTestId("ingress-comfort-missing")).toBeNull();
		expect(screen.queryByTestId("ingress-banner-dropped")).toBeNull();
		cleanup();

		extraChecks = [restrictedCheck];
		confirmMock.mockReturnValue(true);
		render(<AgentIngressDialog agentId={2} agentName="site-b" visible onClose={() => {}} />, {
			wrapper: createWrapper(),
		});
		// banner: filter on, hint link to the check tab; the tab carries the count
		const banner = await screen.findByTestId("ingress-banner");
		expect(banner.textContent).toContain("Ingress filter at this site: on");
		expect(banner.textContent).toContain("1 active rule");
		expect(await within(banner).findByText(/1 proxy target is dropped/)).toBeTruthy();
		expect((await screen.findByTestId("ingress-tab-check-badge")).textContent).toBe("1");
		fireEvent.click(within(banner).getByRole("button", { name: "Show in Check" }));
		expect(screen.getByRole("tab", { name: /^Check/ }).getAttribute("aria-selected")).toBe("true");
		fireEvent.click(await screen.findByRole("button", { name: "Release all missing proxy targets (1)" }));
		expect(confirmMock).toHaveBeenCalled();
		expect(String((confirmMock.mock.calls[0] as unknown[])[0])).toContain("Proxy wiki.example.com");
		await waitFor(() => {
			const post = calls.find((c) => c.method === "POST" && c.url === "/api/agents/2/ingress/rules/bulk");
			expect(post?.body).toEqual({ rules: [{ ...restrictedCheck.missing[0].suggestion, enabled: true }] });
		});
		expect(await screen.findByText("Rule “Proxy wiki.example.com” created.")).toBeTruthy();
	});

	it("turning the filter off asks for confirmation too", async () => {
		confirmMock.mockReturnValue(true);
		render(<AgentIngressDialog agentId={2} agentName="site-b" visible onClose={() => {}} />, {
			wrapper: createWrapper(),
		});
		fireEvent.click(await screen.findByRole("button", { name: "Turn ingress filter off" }));
		expect(String((confirmMock.mock.calls[0] as unknown[])[0])).toContain("Turn the ingress filter off?");
		await waitFor(() => {
			const put = calls.find((c) => c.method === "PUT" && c.url === "/api/agents/2/ingress");
			expect(put?.body).toEqual({ ingress_mode: "open" });
		});
	});

	it("switches off unused rules, but never the last active rule of a restricted agent", async () => {
		confirmMock.mockReturnValue(true);
		renderDialog();
		fireEvent.click(await screen.findByRole("button", { name: "Switch off unused rules (1)" }));
		await waitFor(() => {
			const post = calls.find(
				(c) => c.method === "POST" && c.url === "/api/agents/1/ingress/rules/bulk-disable",
			);
			// prune: the backend re-checks the ids against its current candidates
			expect(post?.body).toEqual({ rule_ids: [12], prune: true });
		});
		expect(await screen.findByText("Switched off 1 rule.")).toBeTruthy();
		cleanup();
		// agent 2: restricted, its only enabled rule is a candidate → no button
		render(<AgentIngressDialog agentId={2} agentName="site-b" visible onClose={() => {}} />, {
			wrapper: createWrapper(),
		});
		await screen.findByText("Site B rule");
		await waitFor(() => expect(calls.some((c) => c.url === "/api/agents/2/ingress/catalog")).toBe(true));
		await new Promise((r) => setTimeout(r, 20));
		expect(screen.queryByTestId("ingress-comfort-prune")).toBeNull();
	});

	it("falls back to the plain text form when the catalog fails", async () => {
		catalogStatus = 500;
		renderDialog();
		expect(await screen.findByTestId("ingress-catalog-unavailable")).toBeTruthy();
		// no assistants without a catalog
		expect(screen.queryByRole("menuitem", { name: "Publish a service via the proxy" })).toBeNull();
		fireEvent.click(screen.getByRole("button", { name: /New rule/ }));
		expect(screen.getByLabelText("Sources").tagName).toBe("TEXTAREA");
		expect(screen.getByLabelText("Targets").tagName).toBe("TEXTAREA");
		// the sentence view still renders, with raw CIDRs
		expect(screen.getAllByTestId("ingress-source-group")[0].textContent).toContain("10.10.0.1");
	});

	it("the rule form uses pickers with a catalog and previews the rule", async () => {
		renderDialog();
		await waitFor(() => expect(calls.some((c) => c.url === "/api/agents/1/ingress/catalog")).toBe(true));
		// the free form is the expert entry at the end of the "Add rule" menu
		fireEvent.click(await screen.findByRole("menuitem", { name: "Own rule (experts)" }));
		await waitFor(() => expect(screen.getByLabelText("Sources").tagName).toBe("INPUT"));
		const src = screen.getByLabelText("Sources");
		fireEvent.change(src, { target: { value: "Branch" } });
		fireEvent.keyDown(src, { key: "Enter", code: "Enter", keyCode: 13 });
		// nothing preselected: a new rule never starts as "all ports"
		expect((screen.getByLabelText("All ports") as HTMLInputElement).checked).toBe(false);
		fireEvent.click(screen.getByLabelText("SSH (22)"));
		expect((screen.getByLabelText("All ports") as HTMLInputElement).checked).toBe(false);
		const preview = await screen.findByTestId("ingress-form-preview");
		expect(preview.textContent).toContain("Branch may access everything in the site – ports tcp/22");
		expect(preview.textContent).toContain("1 filter line");
		fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Branch SSH" } });
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => {
			const post = calls.find((c) => c.method === "POST" && c.url === "/api/agents/1/ingress/rules");
			expect(post?.body).toEqual({
				name: "Branch SSH",
				sources: ["192.168.20.0/24"],
				destinations: [],
				ports: [{ proto: "tcp", port: "22" }],
				enabled: true,
				note: "",
			});
		});
	});
});

describe("editor dialog (rule form and wizards)", () => {
	const onClose = vi.fn();
	const renderDialog = () =>
		render(<AgentIngressDialog agentId={1} agentName="site-a" visible onClose={onClose} />, {
			wrapper: createWrapper(),
		});
	const editor = () => document.querySelector<HTMLElement>(".modal.ingress-editor-modal");
	const writes = () => calls.filter((c) => c.method !== "GET");

	beforeEach(() => onClose.mockReset());

	it("'Edit' opens a dialog with the rule's values; saving PUTs, closes and highlights the rule", async () => {
		renderDialog();
		fireEvent.click(await screen.findByRole("menuitem", { name: "Edit Office LAN" }));
		const dialog = await screen.findByRole("dialog", { name: "Edit rule" });
		expect(dialog.className).toContain("ingress-editor-modal");
		const form = within(dialog);
		expect((form.getByLabelText("Name") as HTMLInputElement).value).toBe("Office LAN");
		expect((form.getByLabelText("Note") as HTMLInputElement).value).toBe("Altlast aus VPN_MGR");
		expect((form.getByLabelText("Active") as HTMLInputElement).checked).toBe(true);
		// footer: Cancel + Save
		expect(form.getByRole("button", { name: "Cancel" })).toBeTruthy();
		fireEvent.change(form.getByLabelText("Name"), { target: { value: "Office LAN 2" } });
		fireEvent.click(form.getByRole("button", { name: "Save" }));
		await waitFor(() => {
			const put = calls.find((c) => c.method === "PUT" && c.url === "/api/agents/1/ingress/rules/12");
			expect(put?.body).toEqual({ name: "Office LAN 2" });
		});
		await waitFor(() => expect(editor()).toBeNull());
		// the edited rule is highlighted in the list, the agent dialog stays open
		await waitFor(() => expect(document.getElementById("ingress-rule-1-12")?.className).toContain("bg-primary-lt"));
		expect(onClose).not.toHaveBeenCalled();
	});

	it("Cancel and Esc close the dialog without a request (Esc only the top dialog)", async () => {
		renderDialog();
		fireEvent.click(await screen.findByRole("menuitem", { name: "Edit Office LAN" }));
		const dialog = await screen.findByRole("dialog", { name: "Edit rule" });
		fireEvent.change(within(dialog).getByLabelText("Name"), { target: { value: "changed" } });
		fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
		await waitFor(() => expect(editor()).toBeNull());
		expect(writes()).toEqual([]);

		fireEvent.click(screen.getByRole("menuitem", { name: "Edit Office LAN" }));
		await screen.findByRole("dialog", { name: "Edit rule" });
		// stacked over the agent dialog: two dialogs, the editor on top
		expect(document.querySelectorAll(".modal").length).toBe(2);
		fireEvent.keyDown(document, { key: "Escape", code: "Escape", keyCode: 27 });
		await waitFor(() => expect(editor()).toBeNull());
		expect(writes()).toEqual([]);
		// the agent dialog itself did not close, and its backdrop is the only one left
		expect(onClose).not.toHaveBeenCalled();
		await waitFor(() => expect(document.querySelectorAll(".modal-backdrop").length).toBe(1));
	});

	it("shows backend errors inside the dialog and keeps it open", async () => {
		ruleSaveError = "Rule overlaps an existing rule";
		renderDialog();
		fireEvent.click(await screen.findByRole("menuitem", { name: "Edit Office LAN" }));
		const dialog = await screen.findByRole("dialog", { name: "Edit rule" });
		fireEvent.change(within(dialog).getByLabelText("Name"), { target: { value: "Office LAN 2" } });
		fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
		expect(await within(dialog).findByText("Rule overlaps an existing rule")).toBeTruthy();
		expect(editor()).not.toBeNull();
	});

	it("'New rule' → own rule opens a dialog that POSTs and closes", async () => {
		renderDialog();
		await waitFor(() => expect(calls.some((c) => c.url === "/api/agents/1/ingress/catalog")).toBe(true));
		fireEvent.click(await screen.findByRole("menuitem", { name: "Own rule (experts)" }));
		const dialog = await screen.findByRole("dialog", { name: "New rule" });
		const form = within(dialog);
		await waitFor(() => expect(form.getByLabelText("Sources").tagName).toBe("INPUT"));
		const src = form.getByLabelText("Sources");
		fireEvent.change(src, { target: { value: "Branch" } });
		fireEvent.keyDown(src, { key: "Enter", code: "Enter", keyCode: 13 });
		fireEvent.click(form.getByLabelText("SSH (22)"));
		fireEvent.change(form.getByLabelText("Name"), { target: { value: "Branch SSH" } });
		fireEvent.click(form.getByRole("button", { name: "Save" }));
		await waitFor(() => {
			const post = calls.find((c) => c.method === "POST" && c.url === "/api/agents/1/ingress/rules");
			expect(post?.body).toMatchObject({ name: "Branch SSH", ports: [{ proto: "tcp", port: "22" }] });
		});
		await waitFor(() => expect(editor()).toBeNull());
		expect(await screen.findByText("Rule “Branch SSH” created.")).toBeTruthy();
	});

	it("each wizard opens in a dialog named after it", async () => {
		renderDialog();
		for (const [name, testId] of [
			["Publish a service via the proxy", "ingress-wizard-proxy"],
			["A site may access servers", "ingress-wizard-site"],
			["A site gets full access", "ingress-wizard-full"],
		]) {
			fireEvent.click(await screen.findByRole("menuitem", { name }));
			const dialog = await screen.findByRole("dialog", { name });
			expect(within(dialog).getByTestId(testId)).toBeTruthy();
			expect(within(dialog).getByRole("button", { name: "Next" })).toBeTruthy();
			fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
			await waitFor(() => expect(editor()).toBeNull());
		}
		expect(writes()).toEqual([]);
	});

	it("works on the page too: 'Edit' opens the dialog instead of an inline form", async () => {
		render(<IngressPageContent />, { wrapper: createWrapper(["/ingress?agent=1"]) });
		const detail = await screen.findByTestId("ingress-detail-1");
		fireEvent.click(await within(detail).findByRole("menuitem", { name: "Edit Hub -> Nextcloud" }));
		const dialog = await screen.findByRole("dialog", { name: "Edit rule" });
		expect(detail.contains(dialog)).toBe(false);
		expect(within(detail).queryByTestId("ingress-form-title")).toBeNull();
		expect((within(dialog).getByLabelText("Name") as HTMLInputElement).value).toBe("Hub -> Nextcloud");
	});
});

describe("rule form ports, names, focus and tester hints", () => {
	const renderDialog = () =>
		render(<AgentIngressDialog agentId={1} agentName="site-a" visible onClose={() => {}} />, {
			wrapper: createWrapper(),
		});
	const pick = (label: string, value: string) => {
		const input = screen.getByLabelText(label);
		fireEvent.change(input, { target: { value } });
		fireEvent.keyDown(input, { key: "Enter", code: "Enter", keyCode: 13 });
	};

	it("unticking ports never turns into 'all ports'; nothing chosen blocks saving", async () => {
		renderDialog();
		fireEvent.click(await screen.findByRole("menuitem", { name: "Own rule (experts)" }));
		await waitFor(() => expect(screen.getByLabelText("Sources").tagName).toBe("INPUT"));
		const all = () => screen.getByLabelText("All ports") as HTMLInputElement;
		const custom = () => document.getElementById("ingress-1-rule-new-ports") as HTMLInputElement;
		// "All ports" can be unticked again (it used to snap back)
		fireEvent.click(all());
		expect(all().checked).toBe(true);
		expect(custom().disabled).toBe(true);
		fireEvent.click(all());
		expect(all().checked).toBe(false);
		expect(custom().disabled).toBe(false);
		// unticking the last preset leaves nothing chosen, not every port
		fireEvent.click(screen.getByLabelText("Web (80/443)"));
		fireEvent.click(screen.getByLabelText("Web (80/443)"));
		expect(all().checked).toBe(false);
		pick("Sources", "Branch");
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		expect(await screen.findByText("Choose ports or tick “All ports”.")).toBeTruthy();
		expect(calls.some((c) => c.method === "POST")).toBe(false);
		// typed custom port; no name typed → named after the sentence
		fireEvent.change(custom(), { target: { value: "tcp/8443" } });
		expect(all().checked).toBe(false);
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => {
			const post = calls.find((c) => c.method === "POST" && c.url === "/api/agents/1/ingress/rules");
			expect(post?.body).toMatchObject({
				name: "Branch → everything in the site",
				sources: ["192.168.20.0/24"],
				destinations: [],
				ports: [{ proto: "tcp", port: "8443" }],
			});
		});
		expect(await screen.findByText("Rule “Branch → everything in the site” created.")).toBeTruthy();
	});

	it("warns under the form preview when a rule is broad", async () => {
		renderDialog();
		fireEvent.click(await screen.findByRole("menuitem", { name: "Own rule (experts)" }));
		await waitFor(() => expect(screen.getByLabelText("Sources").tagName).toBe("INPUT"));
		pick("Sources", "Branch");
		expect(screen.queryByTestId("ingress-form-broad")).toBeNull();
		fireEvent.click(screen.getByLabelText("All ports"));
		expect(screen.getByTestId("ingress-form-broad")).toBeTruthy();
	});

	it("moves focus into the wizard, to each new step and back to the add button", async () => {
		renderDialog();
		fireEvent.click(await screen.findByRole("menuitem", { name: "Publish a service via the proxy" }));
		await screen.findByTestId("ingress-wizard-proxy");
		expect(document.activeElement?.textContent).toBe("Publish a service via the proxy");
		fireEvent.click(screen.getByLabelText("Cloud (192.168.60.9)"));
		fireEvent.click(screen.getByRole("button", { name: "Next" }));
		await waitFor(() =>
			expect(document.activeElement?.getAttribute("data-testid")).toBe("ingress-wizard-step"),
		);
		fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
		await waitFor(() => expect(document.activeElement?.textContent).toContain("New rule"));
		// the free form takes the focus as well
		fireEvent.click(screen.getByRole("menuitem", { name: "Own rule (experts)" }));
		await waitFor(() =>
			expect(document.activeElement?.getAttribute("data-testid")).toBe("ingress-form-title"),
		);
	});

	it("the tester names a missing link binding instead of 'not via this agent'", async () => {
		const saved = { ...testResult };
		Object.assign(testResult, {
			allowed: null,
			filtered: false,
			reason: "link-not-found",
			rule: null,
			matched_rules: [],
			notes: [],
			link_found: false,
		});
		try {
			renderDialog();
			await openTab("Check");
			await waitFor(() => expect(calls.some((c) => c.url === "/api/agents/1/ingress/catalog")).toBe(true));
			pick("Source", "10.10.0.1");
			pick("Destination", "192.168.60.22");
			fireEvent.click(screen.getByRole("button", { name: "Check" }));
			const result = await screen.findByTestId("ingress-tester-result");
			expect(result.textContent).toContain("bound WireGuard link was not found");
			expect(result.className).toContain("alert-warning");
		} finally {
			Object.assign(testResult, saved);
		}
	});

	it("merges missing-target suggestions with the same targets into one rule", () => {
		const sug = (name: string, ports = [{ proto: "tcp", port: "443" }]) => ({
			name,
			sources: ["10.10.0.1"],
			destinations: ["192.168.60.9"],
			ports,
		});
		const check = {
			missing: [
				{ kind: "proxy-host", suggestion: sug("Proxy a.example.com") },
				{ kind: "proxy-host", suggestion: sug("Proxy b.example.com") },
				{ kind: "stream", suggestion: sug("Hub Port 53/tcp", [{ proto: "tcp", port: "53" }]) },
				{ kind: "proxy-host", suggestion: null },
			],
		} as never;
		const out = missingProxySuggestions(check);
		expect(out.map((r) => r.name)).toEqual(["Proxy a.example.com +1", "Hub Port 53/tcp"]);
		expect(out.every((r) => r.enabled)).toBe(true);
	});

	it("reports switched-on rules apart from new ones", () => {
		const r = (id: number, name: string) => ({ id, name }) as never;
		expect(bulkResultInfo({ created: [], reenabled: [r(5, "Proxy cloud")], skipped: [] })).toBe(
			"Rule “Proxy cloud” was switched off and is switched on again.",
		);
		expect(
			bulkResultInfo({
				created: [r(1, "a"), r(2, "b")],
				reenabled: [r(3, "c")],
				skipped: [{ index: 3, reason: "duplicate", ruleId: 9 }],
			}),
		).toBe("2 created, 1 skipped, 1 switched back on");
	});
});

describe("rule sections and highlights", () => {
	const camel = (r: (typeof rules)[number]) =>
		({
			id: r.id,
			agentId: r.agent_id,
			name: r.name,
			sources: r.sources,
			destinations: r.destinations,
			ports: r.ports,
			enabled: r.enabled,
			note: r.note,
			hitPackets: r.hit_packets,
			lastHitAt: r.last_hit_at,
			createdOn: r.created_on,
			modifiedOn: r.modified_on,
		}) as never;

	it("a highlight opens a collapsed section for good (it stays open when the highlight fades)", () => {
		const Wrapper = createWrapper();
		const view = (highlightId: number | null) => (
			<Wrapper>
				<AgentIngressRuleSentences
					agentId={1}
					rules={rules.map(camel)}
					onEdit={() => {}}
					onError={() => {}}
					highlightId={highlightId}
				/>
			</Wrapper>
		);
		const { rerender } = render(view(null));
		const office = screen.getAllByTestId("ingress-source-group").find((g) => g.textContent?.includes("Office LAN"));
		if (!office) throw new Error("no section");
		const toggle = within(office).getByRole("button", { expanded: true });
		fireEvent.click(toggle);
		expect(document.getElementById("ingress-rule-1-12")).toBeNull();
		// tester "go to rule" / new rule: highlighted → open
		rerender(view(12));
		expect(document.getElementById("ingress-rule-1-12")?.className).toContain("bg-primary-lt");
		// highlight cleared after 2 s: the section stays open, the row (focus target) stays mounted
		rerender(view(null));
		expect(document.getElementById("ingress-rule-1-12")).toBeTruthy();
		expect(toggle.getAttribute("aria-expanded")).toBe("true");
	});
});

describe("rule group header and row layout", () => {
	const danielCatalog = {
		agentId: 1,
		agentName: "VM-Docker",
		ingressMode: "restricted",
		linkFound: true,
		site: null,
		sources: [
			{
				id: "site:wg0:D",
				kind: "site",
				label: "Dnaiel Home",
				cidrs: ["192.168.111.0/24", "192.168.112.0/24", "10.10.0.9/32"],
			},
			{ id: "sn:111", kind: "site-net", label: "192.168.111.0/24", cidrs: ["192.168.111.0/24"], parent: "site:wg0:D" },
			{ id: "sn:112", kind: "site-net", label: "192.168.112.0/24", cidrs: ["192.168.112.0/24"], parent: "site:wg0:D" },
		],
		destinations: [],
		portPresets: [],
	} as never;
	const mk = (id: number, name: string, destinations: string[]) =>
		({
			id,
			agentId: 1,
			name,
			sources: ["192.168.111.0/24", "192.168.112.0/24"],
			destinations,
			ports: [],
			enabled: true,
			note: "",
			hitPackets: 0,
			lastHitAt: null,
			createdOn: "",
			modifiedOn: "",
		}) as never;

	it("names a site once with its CIDRs once, and lays out every row alike", () => {
		const Wrapper = createWrapper();
		render(
			<Wrapper>
				<AgentIngressRuleSentences
					agentId={1}
					rules={[
						mk(1, "long", Array.from({ length: 6 }, (_, i) => `10.3.10.${i + 1}`)),
						mk(2, "short", ["10.3.10.25"]),
					]}
					catalog={danielCatalog}
					onEdit={() => {}}
					onError={() => {}}
				/>
			</Wrapper>,
		);
		const [group] = screen.getAllByTestId("ingress-source-group");
		expect(within(group).getByTestId("ingress-group-label").textContent).toBe("Dnaiel Home");
		expect(within(group).getByTestId("ingress-group-cidrs").textContent).toBe("192.168.111.0/24, 192.168.112.0/24");
		expect(group.textContent?.match(/Dnaiel Home/g)).toHaveLength(1);
		// every row: content left, hits + switch + menu in the right column
		const rows = within(group).getAllByTestId("ingress-rule-row");
		expect(rows).toHaveLength(2);
		for (const row of rows) {
			expect(row.className).toBe("ingress-rule-row");
			const side = within(row).getByTestId("ingress-rule-side");
			expect(row.lastElementChild).toBe(side);
			expect(within(side).getByRole("switch")).toBeTruthy();
			expect(side.textContent).toContain("no hit yet");
		}
	});
});

// ── Page ──────────────────────────────────────────────────────────────────────

describe("Ingress page", () => {
	const agent = (id: number, name: string, mode: "open" | "restricted") =>
		({ id, name, ingressMode: mode, status: "active", wgLinkName: name, services: [] }) as never;
	const checkFor = (agentId: number, missing: number) =>
		({ agentId, ingressMode: undefined, missing: Array.from({ length: missing }, () => ({})) }) as never;

	it("sorts restricted agents first, then by name, and counts warnings only while restricted", () => {
		const entries = buildIngressAgentEntries(
			[agent(1, "zeta", "open"), agent(2, "beta", "restricted"), agent(3, "alpha", "open"), agent(4, "gamma", "restricted")],
			[checkFor(3, 2), checkFor(4, 1)],
		);
		expect(entries.map((e) => e.agent.name)).toEqual(["beta", "gamma", "alpha", "zeta"]);
		expect(entries.find((e) => e.agent.id === 4)?.warnings).toBe(1);
		// open agent: missing targets are not dropped, so no warning
		expect(entries.find((e) => e.agent.id === 3)).toMatchObject({ missing: 2, warnings: 0 });
	});

	it("names a site by its WireGuard link, the agent as secondary; falls back to the agent name", () => {
		const docker = { name: "VM-Docker (192.168.11.7)", wgLinkName: "Floppy Home" };
		expect(ingressSiteName(docker)).toBe("Floppy Home");
		expect(ingressAgentSubName(docker)).toBe("VM-Docker (192.168.11.7)");
		const noLink = { name: "VM-Docker (192.168.11.7)", wgLinkName: null };
		expect(ingressSiteName(noLink)).toBe("VM-Docker (192.168.11.7)");
		expect(ingressAgentSubName(noLink)).toBeNull();
		expect(ingressSiteName({ name: "gw", wgLinkName: "  " })).toBe("gw");
		expect(ingressAgentSubName({ name: "Office", wgLinkName: "Office" })).toBeNull();
		// sorted by the displayed (site) name, not the agent name
		const withLink = (id: number, name: string, link: string | null) =>
			({ id, name, ingressMode: "open", status: "active", wgLinkName: link, services: [] }) as never;
		const entries = buildIngressAgentEntries(
			[withLink(1, "a-agent", "Zeta Site"), withLink(2, "z-agent", "Alpha Site"), withLink(3, "Mid", null)],
			[],
		);
		expect(entries.map((e) => ingressSiteName(e.agent))).toEqual(["Alpha Site", "Mid", "Zeta Site"]);
	});

	it("selects the first restricted agent, else the first with warnings, else the first", () => {
		const build = (...a: never[]) => (checks: never[] = []) => buildIngressAgentEntries(a, checks);
		expect(pickDefaultIngressAgent(build(agent(1, "a", "open"), agent(2, "b", "restricted"))())).toBe(2);
		expect(pickDefaultIngressAgent(build(agent(1, "a", "open"), agent(2, "b", "open"))([checkFor(2, 1)]))).toBe(2);
		expect(pickDefaultIngressAgent(build(agent(1, "b", "open"), agent(2, "a", "open"))())).toBe(2);
		expect(pickDefaultIngressAgent([])).toBeNull();
		// a restricted agent whose ruleset failed/offline/unknown beats the other restricted ones
		const failed = { agentId: 3, ingressMode: undefined, missing: [], applied: { state: "offline" } } as never;
		expect(
			pickDefaultIngressAgent(build(agent(2, "a", "restricted"), agent(3, "b", "restricted"))([failed])),
		).toBe(3);
		const pending = { agentId: 3, ingressMode: undefined, missing: [], applied: { state: "pending" } } as never;
		expect(
			pickDefaultIngressAgent(build(agent(2, "a", "restricted"), agent(3, "b", "restricted"))([pending])),
		).toBe(2);
		const entries = build(agent(1, "a", "open"), agent(2, "b", "restricted"))();
		// URL wins when it names an existing agent; unknown or junk ids fall back
		expect(resolveIngressAgent(entries, "1")).toBe(1);
		expect(resolveIngressAgent(entries, "99")).toBe(2);
		expect(resolveIngressAgent(entries, "1abc")).toBe(2);
		expect(resolveIngressAgent(entries, null)).toBe(2);
	});

	it("lists the agents restricted first and opens the restricted one by default and pins it in the URL", async () => {
		render(<IngressPageContent />, { wrapper: createWrapper(["/ingress"]) });
		const list = await screen.findByTestId("ingress-agent-list");
		const items = within(list).getAllByRole("button");
		expect(items.map((b) => b.getAttribute("data-testid"))).toEqual(["ingress-agent-2", "ingress-agent-1"]);
		expect(items[0].getAttribute("aria-current")).toBe("true");
		expect(items[0].textContent).toContain("Ingress filter on");
		expect(items[1].textContent).toContain("Ingress filter off");
		await waitFor(() => expect(items[0].textContent).toContain("1 active rule"));
		expect(screen.getByTestId("ingress-sites-summary").textContent).toBe("1 with ingress filter · 1 without");
		// detail of agent 2 with its name as the banner heading
		const detail = await screen.findByTestId("ingress-detail-2");
		expect(within(detail).getByRole("heading", { name: "site-b" })).toBeTruthy();
		// site (link) name first, the agent name as muted secondary text
		expect(within(detail).getByTestId("ingress-detail-agent").textContent).toBe("VM-B (10.0.0.2)");
		expect(within(items[0]).getByTestId("ingress-list-site").textContent).toBe("site-b");
		expect(within(items[0]).getByTestId("ingress-list-agent").textContent).toBe("VM-B (10.0.0.2)");
		// link name equals the agent name: no repeated secondary line
		expect(within(items[1]).queryByTestId("ingress-list-agent")).toBeNull();
		const option = within(screen.getByTestId("ingress-agent-select")).getByRole("option", { name: /^site-b/ });
		expect(option.textContent).toContain("site-b · (VM-B (10.0.0.2)) · Ingress filter on");
		await waitFor(() => expect(detail.textContent).toContain("Site B rule"));
		expect(screen.queryByTestId("ingress-detail-1")).toBeNull();
		// compact header, no KPI cards, no extra header button
		const h1 = screen.getByRole("heading", { level: 1 });
		expect(h1.textContent).toBe("Access rules");
		expect(h1.className).toContain("platform-title");
		expect(screen.queryByRole("link", { name: "WireGuard" })).toBeNull();
		expect(screen.queryByText(/Agents in/)).toBeNull();
		// the selection is pinned in the URL
		await waitFor(() => expect(lastSearch).toBe("?agent=2"));
	});

	it("delete agent is off the main view, but still reachable at the end of the Technik tab", async () => {
		// orphaned agent: its WireGuard link is gone
		extraChecks = [{ ...restrictedCheck, link_found: false, wg_link_name: "site-b" }];
		render(<IngressPageContent />, { wrapper: createWrapper(["/ingress?agent=2"]) });
		const detail = await screen.findByTestId("ingress-detail-2");
		await waitFor(() => expect(detail.textContent).toContain("Site B rule"));
		expect(within(screen.getByTestId("ingress-banner")).queryByText(/delete agent/i)).toBeNull();
		expect(within(screen.getByTestId("ingress-panel-rules")).queryByText(/delete agent/i)).toBeNull();
		expect(screen.queryByTestId("ingress-agent-delete-2")).toBeNull();
		await openTab("Technical");
		const zone = await within(screen.getByTestId("ingress-panel-tech")).findByTestId("ingress-danger-zone");
		expect(within(zone).getByTestId("ingress-agent-delete-2").textContent).toMatch(/delete agent/i);
		await waitFor(() => expect(within(zone).getByTestId("ingress-danger-orphan")).toBeTruthy());
	});

	it("keeps the chosen site when the filter is switched off (no jump to another default)", async () => {
		confirmMock.mockReturnValue(true);
		render(<IngressPageContent />, { wrapper: createWrapper(["/ingress"]) });
		const banner = await within(await screen.findByTestId("ingress-detail-2")).findByTestId("ingress-banner");
		await waitFor(() => expect(lastSearch).toBe("?agent=2"));
		fireEvent.click(within(banner).getByRole("button", { name: "Turn ingress filter off" }));
		await waitFor(() => expect(agentModes[2]).toBe("open"));
		// agents refetched as open: agent 1 (missing target) would now be the default
		await waitFor(() =>
			expect(within(screen.getByTestId("ingress-agent-2")).queryByText("Ingress filter on")).toBeNull(),
		);
		await waitFor(() => expect(screen.getByTestId("ingress-banner").getAttribute("data-mode")).toBe("open"));
		expect(screen.getByTestId("ingress-detail-2")).toBeTruthy();
		expect(screen.queryByTestId("ingress-detail-1")).toBeNull();
		expect(lastSearch).toBe("?agent=2");
	});

	it("flags a restricted agent whose ruleset is not running in the list and opens it first", async () => {
		extraChecks = [
			{
				...restrictedCheck,
				missing: [],
				applied: { state: "failed", applied_hash: "NONE", desired_hash: "a".repeat(64), error: "x" },
			},
		];
		render(<IngressPageContent />, { wrapper: createWrapper(["/ingress?agent=1"]) });
		const badge = await within(await screen.findByTestId("ingress-agent-2")).findByTestId("ingress-list-applied");
		expect(badge.textContent).toBe("not applied");
		expect(within(screen.getByTestId("ingress-agent-1")).queryByTestId("ingress-list-applied")).toBeNull();
	});

	it("shows the agent status in words, not the raw API value", async () => {
		agent1Status = "pending";
		render(<IngressPageContent />, { wrapper: createWrapper(["/ingress?agent=1"]) });
		const detail = await screen.findByTestId("ingress-detail-1");
		await waitFor(() => expect(detail.textContent).toContain("Waiting for connection"));
		expect(detail.textContent).not.toMatch(/\bpending\b/);
	});

	it("keeps the selection in the URL (?agent=)", async () => {
		render(<IngressPageContent />, { wrapper: createWrapper(["/ingress?agent=1"]) });
		expect(await screen.findByTestId("ingress-detail-1")).toBeTruthy();
		expect((screen.getByTestId("ingress-agent-select") as HTMLSelectElement).value).toBe("1");
		fireEvent.click(screen.getByTestId("ingress-agent-2"));
		expect(await screen.findByTestId("ingress-detail-2")).toBeTruthy();
		expect(lastSearch).toBe("?agent=2");
		// the narrow-screen select switches as well
		fireEvent.change(screen.getByTestId("ingress-agent-select"), { target: { value: "1" } });
		expect(await screen.findByTestId("ingress-detail-1")).toBeTruthy();
		expect(lastSearch).toBe("?agent=1");
	});

	it("shows a warning dot only for restricted agents that drop proxy targets", async () => {
		extraChecks = [restrictedCheck];
		render(<IngressPageContent />, { wrapper: createWrapper(["/ingress"]) });
		await waitFor(() =>
			expect(within(screen.getByTestId("ingress-agent-2")).getByTestId("ingress-list-warning").textContent).toContain(
				"1",
			),
		);
		// agent 1 is open: its missing target is no warning
		expect(within(screen.getByTestId("ingress-agent-1")).queryByTestId("ingress-list-warning")).toBeNull();
	});
});
