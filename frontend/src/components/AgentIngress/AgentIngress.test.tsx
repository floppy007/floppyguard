import { QueryClient, QueryClientProvider, QueryObserver } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "src/context";
import { AgentIngressDialog } from "src/modals/AgentIngressModal";
import { IngressPageContent } from "src/pages/Ingress";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { missingProxySuggestions } from "./ComfortActions";
import { changedRuleData } from "./RuleForm";
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

const agentsPayload = [
	{ id: 1, name: "site-a", status: "active", wg_link_name: "site-a", ingress_mode: "open", services: [] },
	{ id: 2, name: "site-b", status: "active", wg_link_name: "site-b", ingress_mode: "restricted", services: [] },
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

type Call = { url: string; method: string; body: any };
let calls: Call[] = [];

const json = (body: unknown, status = 200) =>
	new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
	const url = String(input);
	const method = init?.method ?? "GET";
	const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
	calls.push({ url, method, body });

	if (url === "/api/agents" && method === "GET") return json(agentsPayload);
	if (url === "/api/agent-ingress/check") return json(checkPayload);
	const m = url.match(/^\/api\/agents\/(\d+)\/ingress(\/.*)?$/);
	if (m) {
		const agentId = Number(m[1]);
		const rest = m[2] ?? "";
		if (rest === "" && method === "GET") {
			return json({
				agent_id: agentId,
				ingress_mode: agentId === 2 ? "restricted" : "open",
				rules: agentId === 1 ? rules : [{ ...rules[0], id: 21, agent_id: 2, name: "Site B rule" }],
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
		if (rest === "/rules" && method === "POST") return json({ ...rules[0], id: 99, ...body }, 201);
		if (rest.startsWith("/rules/") && method === "PUT") return json({ ...rules[0], ...body });
	}
	return json({ error: { message: `unexpected ${method} ${url}` } }, 500);
});

const createWrapper = () => {
	const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
	return ({ children }: { children: ReactNode }) => (
		<QueryClientProvider client={queryClient}>
			<ThemeProvider>
				<MemoryRouter>{children}</MemoryRouter>
			</ThemeProvider>
		</QueryClientProvider>
	);
};

const confirmMock = vi.fn(() => true);

beforeEach(() => {
	calls = [];
	catalogStatus = 200;
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

	it("renders the rules from the API", async () => {
		renderDialog();
		// table view (the sentence view is the default)
		fireEvent.click(await screen.findByRole("button", { name: "Table" }));
		expect(screen.getByRole("button", { name: "Table" }).getAttribute("aria-pressed")).toBe("true");
		// also listed under "unused hub rules" in the check section
		expect((await screen.findAllByText("Hub -> Nextcloud")).length).toBe(2);
		expect(screen.getByText("Office LAN")).toBeTruthy();
		expect(screen.getByText("tcp/443")).toBeTruthy();
		// empty destinations/ports → "all", legacy note badge, never-hit marker
		expect(screen.getAllByText("all").length).toBe(2);
		expect(screen.getByText("Legacy")).toBeTruthy();
		expect(screen.getByText("no hit yet")).toBeTruthy();
		expect(screen.getByText(/^last /)).toBeTruthy();
	});

	it("switching to restricted asks for confirmation and PUTs the mode", async () => {
		confirmMock.mockReturnValue(true);
		renderDialog();
		const radio = await screen.findByLabelText("Rules only (forwarded traffic without a rule is dropped)");
		fireEvent.click(radio);
		expect(confirmMock).toHaveBeenCalled();
		await waitFor(() => {
			const put = calls.find((c) => c.method === "PUT" && c.url === "/api/agents/1/ingress");
			expect(put?.body).toEqual({ ingress_mode: "restricted" });
		});
	});

	it("does not switch when the confirmation is declined", async () => {
		confirmMock.mockReturnValue(false);
		renderDialog();
		fireEvent.click(await screen.findByLabelText("Rules only (forwarded traffic without a rule is dropped)"));
		expect(calls.some((c) => c.method === "PUT")).toBe(false);
	});

	it("'Create rule' on a missing upstream POSTs the suggestion", async () => {
		renderDialog();
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
		fireEvent.click(await screen.findByRole("button", { name: "Edit Office LAN" }));
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
		fireEvent.click(await screen.findByRole("button", { name: /Add rule/ }));
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
		expect(hub.textContent).toContain("may access Nextcloud (192.168.60.22) – ports tcp/443");
		expect(hub.textContent).toContain("Hub -> Nextcloud");
		expect(branch.textContent).toContain("Branch");
		expect(branch.textContent).toContain("may access everything in the site – all ports");
		expect(branch.textContent).toContain("Legacy");
		// rows carry the id the tester jumps to
		expect(document.getElementById("ingress-rule-1-12")).toBeTruthy();
		expect(screen.getByRole("button", { name: "Sentences" }).getAttribute("aria-pressed")).toBe("true");
	});

	it("remembers the chosen view", async () => {
		renderDialog();
		fireEvent.click(await screen.findByRole("button", { name: "Table" }));
		expect(window.localStorage.getItem("fg.ingress.view")).toBe("table");
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
		expect(screen.queryByTestId("ingress-wizard-proxy")).toBeNull();
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
		fireEvent.click(await screen.findByRole("button", { name: /Check a connection/ }));
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
		await waitFor(() => expect(document.getElementById("ingress-rule-1-11")?.className).toContain("bg-primary-lt"));
	});

	it("'release all missing proxy targets' posts the suggestions in bulk", async () => {
		confirmMock.mockReturnValue(true);
		renderDialog();
		fireEvent.click(await screen.findByRole("button", { name: "Release all missing proxy targets (1)" }));
		expect(confirmMock).toHaveBeenCalled();
		expect(String((confirmMock.mock.calls[0] as unknown[])[0])).toContain("Proxy cloud.example.com");
		await waitFor(() => {
			const post = calls.find((c) => c.method === "POST" && c.url === "/api/agents/1/ingress/rules/bulk");
			expect(post?.body).toEqual({ rules: [{ ...suggestion, enabled: true }] });
		});
		expect(await screen.findByText("Rule “Proxy cloud.example.com” created.")).toBeTruthy();
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
		fireEvent.click(screen.getByRole("button", { name: /Add rule/ }));
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
		await waitFor(() => expect(document.activeElement?.textContent).toContain("Add rule"));
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
			fireEvent.click(await screen.findByRole("button", { name: /Check a connection/ }));
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

// ── Page ──────────────────────────────────────────────────────────────────────

describe("Ingress page", () => {
	it("renders one card per agent with its rules and the overview counts", async () => {
		render(<IngressPageContent />, { wrapper: createWrapper() });
		const cardA = await screen.findByTestId("ingress-agent-1");
		const cardB = screen.getByTestId("ingress-agent-2");
		expect(cardA.textContent).toContain("site-a");
		expect(cardB.textContent).toContain("site-b");
		await waitFor(() => expect(cardA.textContent).toContain("Office LAN"));
		await waitFor(() => expect(cardB.textContent).toContain("Site B rule"));
		expect(screen.getByText('Agents in "rules only" mode').parentElement?.textContent).toContain("1");
		expect(screen.getByText("Agents open (no filter)").parentElement?.textContent).toContain("1");
	});
});
