import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import EasyModal from "ez-modal-react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "src/context";
import { IngressPageContent } from "src/pages/Ingress";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IngressTester, siteIsolationPairLabel } from "./IngressTester";
import { AgentIngressDetail } from "./Panel";
import {
	adoptManualPairs,
	isolatedSiteNames,
	nextSitePairs,
	SiteIsolationCard,
	sitePairKey,
	sitePairState,
	siteIsolationNeedsAttention,
} from "./SiteIsolation";

// ── fetch mock (snake_case like the backend; the API layer camelizes) ─────────

const D = "wg0:D";
const F = "wg0:F";
const H = "wg0:H";

const site = (link_id: string, name: string, online = true) => ({
	link_id,
	name,
	networks: ["192.168.1.0/24"],
	tunnel: ["10.10.0.9/32"],
	online,
});

let overview: any;
let putStatus = 200;
let testPayload: any;

const baseOverview = () => ({
	sites: [site(D, "Daniel Home"), site(F, "Floppy Home"), site(H, "Hinderlich Office", false)],
	pairs: [
		{
			id: 1,
			link_a: D,
			link_b: H,
			name_a: "Daniel Home",
			name_b: "Hinderlich Office",
			enforced: true,
			dropped: { packets: 1234, bytes: 99999 },
		},
		// link gone: must never be sent back
		{ id: 2, link_a: "wg0:X", link_b: F, name_a: null, name_b: "Floppy Home", enforced: false, dropped: null },
	],
	applied: {
		hash: "abc",
		at: 1_780_000_000,
		error: null,
		error_at: null,
		error_code: null,
		file: "/etc/nftables.d/floppyguard-sites.nft",
		table_present: true,
	},
	manual_pairs: [],
	last_change: { at: 1_779_000_000, by: "Floppy" },
	warnings: [
		{
			code: "route-dropped",
			agent_id: 7,
			agent_name: "gw-hinderlich",
			link_id: H,
			other_link_id: D,
			other_name: "Daniel Home",
			networks: ["192.168.111.0/24"],
			via: "full-mesh",
			message: "gw-hinderlich: Route zu Daniel Home …",
		},
		{ code: "persist-failed", message: "Regeln aktiv, aber Datei fehlt" },
	],
});

type Call = { url: string; method: string; body: any };
let calls: Call[] = [];

const json = (body: unknown, status = 200) =>
	new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
	const url = String(input);
	const method = init?.method ?? "GET";
	const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
	calls.push({ url, method, body });
	if (url === "/api/site-isolation" && method === "GET") return json(overview);
	if (url === "/api/site-isolation" && method === "PUT") {
		if (putStatus !== 200) return json({ error: { message: "nft rejected" } }, putStatus);
		const names: Record<string, string> = { [D]: "Daniel Home", [F]: "Floppy Home", [H]: "Hinderlich Office" };
		overview = {
			...overview,
			pairs: body.pairs.map((p: any, i: number) => ({
				id: 10 + i,
				...p,
				name_a: names[p.link_a],
				name_b: names[p.link_b],
				enforced: true,
				dropped: null,
			})),
		};
		return json(overview);
	}
	if (url === "/api/agents" && method === "GET") {
		return json([
			{
				id: 1,
				name: "gw-h",
				status: "active",
				wg_link_name: "Hinderlich Office",
				ingress_mode: "open",
				services: [],
			},
		]);
	}
	if (url === "/api/agent-ingress/check") return json([]);
	if (url === "/api/agents/1/ingress") {
		return json({
			agent_id: 1,
			ingress_mode: "open",
			rules: [],
			applied: { state: "applied", applied_hash: "NONE", desired_hash: "NONE", error: null },
		});
	}
	if (url === "/api/agents/1/ingress/catalog") {
		return json({
			agent_id: 1,
			agent_name: "gw-h",
			ingress_mode: "open",
			link_found: true,
			site: { link_id: H, name: "Hinderlich Office", networks: ["192.168.210.0/24"] },
			sources: [],
			destinations: [],
			port_presets: [],
			prune_candidates: [],
		});
	}
	if (url === "/api/agents/1/ingress/test" && method === "POST") return json(testPayload);
	return json({ error: { message: `unexpected ${method} ${url}` } }, 500);
});

const createWrapper = () => {
	const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
	return ({ children }: { children: ReactNode }) => (
		<QueryClientProvider client={queryClient}>
			<ThemeProvider>
				<MemoryRouter initialEntries={["/ingress"]}>
					<EasyModal.Provider>{children}</EasyModal.Provider>
				</MemoryRouter>
			</ThemeProvider>
		</QueryClientProvider>
	);
};

beforeEach(() => {
	calls = [];
	overview = baseOverview();
	putStatus = 200;
	testPayload = null;
	fetchMock.mockClear();
	vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

const cells = () => within(screen.getByTestId("site-isolation-matrix")).getAllByTestId("site-isolation-cell");
const cell = (a: string, b: string) => {
	const found = cells().find((c) => c.getAttribute("data-a") === a && c.getAttribute("data-b") === b);
	if (!found) throw new Error(`no cell ${a} / ${b}`);
	return found;
};
const puts = () => calls.filter((c) => c.method === "PUT" && c.url === "/api/site-isolation");

// ── helpers ───────────────────────────────────────────────────────────────────

describe("site isolation helpers", () => {
	const data = {
		sites: [
			{ linkId: D, name: "Daniel Home", networks: [], tunnel: [], online: true },
			{ linkId: F, name: "Floppy Home", networks: [], tunnel: [], online: true },
			{ linkId: H, name: "Hinderlich Office", networks: [], tunnel: [], online: true },
		],
		pairs: [
			{
				id: 1,
				linkA: D,
				linkB: H,
				nameA: "Daniel Home",
				nameB: "Hinderlich Office",
				enforced: true,
				dropped: null,
			},
			{ id: 2, linkA: "wg0:X", linkB: F, nameA: null, nameB: "Floppy Home", enforced: false, dropped: null },
		],
	};

	it("pair keys are order-independent", () => {
		expect(sitePairKey(H, D)).toBe(sitePairKey(D, H));
	});

	it("builds the full set: adds/removes one pair, normalized, without pairs of vanished links", () => {
		expect(nextSitePairs(data, H, F, true)).toEqual([
			{ linkA: D, linkB: H },
			{ linkA: F, linkB: H },
		]);
		expect(nextSitePairs(data, H, D, false)).toEqual([]);
	});

	it("names the sites a link is isolated from", () => {
		expect(isolatedSiteNames(data, H)).toEqual(["Daniel Home"]);
		expect(isolatedSiteNames(data, F)).toEqual([]);
		expect(isolatedSiteNames(undefined, H)).toEqual([]);
	});

	it("adopts manual pairs into the full set, skipping vanished links", () => {
		const withManual = {
			...data,
			manualPairs: [
				{ linkA: F, linkB: H, rules: [] },
				{ linkA: "wg0:X", linkB: D, rules: [] },
			],
		};
		expect(adoptManualPairs(withManual)).toEqual([
			{ linkA: D, linkB: H },
			{ linkA: F, linkB: H },
		]);
	});

	it("cell state: open, separated, not in effect, separated by hand", () => {
		expect(sitePairState(undefined, false)).toBe("open");
		expect(sitePairState(undefined, true)).toBe("manual");
		expect(sitePairState(data.pairs[0], false)).toBe("blocked");
		expect(sitePairState({ ...data.pairs[0], enforced: false }, true)).toBe("not-enforced");
	});

	it("needs attention on errors, warnings, manual pairs or unenforced pairs only", () => {
		const applied = { hash: "x", at: 1, error: null, errorAt: null, file: null };
		const calm = { ...data, pairs: [data.pairs[0]], applied, warnings: [], manualPairs: [] };
		expect(siteIsolationNeedsAttention(calm)).toBe(false);
		expect(siteIsolationNeedsAttention({ ...calm, applied: { ...applied, error: "x" } })).toBe(true);
		expect(siteIsolationNeedsAttention({ ...calm, warnings: [{ code: "overlap", message: "" }] })).toBe(true);
		expect(siteIsolationNeedsAttention({ ...calm, manualPairs: [{ linkA: D, linkB: H, rules: [] }] })).toBe(true);
		expect(siteIsolationNeedsAttention({ ...calm, pairs: [{ ...data.pairs[0], enforced: false }] })).toBe(true);
	});

	it("labels a tester pair source first", () => {
		const ref = { a: D, b: H, nameA: "Daniel Home", nameB: "Hinderlich Office" };
		expect(siteIsolationPairLabel({ ...ref, direction: "a-to-b" })).toBe("Daniel Home ↔ Hinderlich Office");
		expect(siteIsolationPairLabel({ ...ref, direction: "b-to-a" })).toBe("Hinderlich Office ↔ Daniel Home");
	});
});

// ── card ──────────────────────────────────────────────────────────────────────

describe("SiteIsolationCard", () => {
	const calm = () => {
		overview.warnings = [];
		overview.pairs = [overview.pairs[0]];
	};
	const confirmButton = (name: string) => screen.findByRole("button", { name });

	it("upper triangle only: every pair exactly once, the rest shaded", async () => {
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		await screen.findByTestId("site-isolation-matrix");
		// 3 sites → 3 pairs, one shaded slot (2×2 grid)
		expect(cells()).toHaveLength(3);
		expect(within(screen.getByTestId("site-isolation-matrix")).getAllByTestId("site-isolation-diag")).toHaveLength(
			1,
		);
		const keys = cells().map((c) =>
			sitePairKey(c.getAttribute("data-a") as string, c.getAttribute("data-b") as string),
		);
		expect(new Set(keys).size).toBe(3);
		expect(cell(D, H).getAttribute("data-state")).toBe("blocked");
		expect(cell(D, H).textContent).toContain("separated");
		expect(cell(D, F).getAttribute("data-state")).toBe("open");
		expect(cell(D, F).textContent).toContain("not separated");
		expect(cell(D, F).className).not.toContain("bg-green-lt");
		expect(cell(D, H).getAttribute("aria-label")).toContain("1,234 packets dropped");
		expect(screen.getByTestId("site-isolation-summary").textContent).toBe("1 of 3 site pairs separated");
	});

	it("collapsed to one line when nothing needs attention; Edit opens it", async () => {
		calm();
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		const toggle = await screen.findByTestId("site-isolation-toggle");
		expect(screen.getByTestId("site-isolation").getAttribute("data-expanded")).toBe("false");
		expect(screen.queryByTestId("site-isolation-matrix")).toBeNull();
		expect(screen.getByTestId("site-isolation-summary").textContent).toBe("1 of 3 site pairs separated");
		expect(toggle.textContent).toBe("Edit");
		expect(toggle.getAttribute("aria-expanded")).toBe("false");
		fireEvent.click(toggle);
		expect(await screen.findByTestId("site-isolation-matrix")).toBeTruthy();
		expect(toggle.textContent).toBe("Collapse");
		fireEvent.click(toggle);
		expect(screen.queryByTestId("site-isolation-matrix")).toBeNull();
	});

	it("summary with nothing separated", async () => {
		calm();
		overview.pairs = [];
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		expect((await screen.findByTestId("site-isolation-summary")).textContent).toBe(
			"None of the 3 site pairs separated",
		);
	});

	it("opens by itself on warnings and shows them translated", async () => {
		overview.warnings.push(
			{
				code: "network-skipped",
				link_id: H,
				name: "Hinderlich Office",
				value: "2a00::/56",
				reason: "ipv6-unsupported",
				message: "x",
			},
			{ code: "link-not-site", link_id: F, name: "Floppy Home", message: "x" },
			{ code: "boot-include-missing", file: "/etc/nftables.d/floppyguard-sites.nft", message: "x" },
		);
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		const warnings = await screen.findByTestId("site-isolation-warnings");
		expect(screen.getByTestId("site-isolation").getAttribute("data-expanded")).toBe("true");
		const text = warnings.textContent;
		expect(text).toContain(
			"gw-hinderlich: route to Daniel Home (192.168.111.0/24) is still configured – the hub drops this traffic.",
		);
		expect(text).toContain(
			"The separation is active, but after a hub restart it is only set again once FloppyGuard is running.",
		);
		expect(text).not.toContain("Regeln aktiv");
		expect(text).toContain("Hinderlich Office: the IPv6 network 2a00::/56 is not covered by the site separation");
		expect(text).toContain("Floppy Home is no longer a site link");
		expect(text).toContain(
			"After a hub restart the separation only takes effect again once FloppyGuard is running",
		);
		expect(screen.queryByTestId("site-isolation-error")).toBeNull();
	});

	it("status: green dot + active (time in the tooltip) and the last change with its author", async () => {
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		const status = await screen.findByTestId("site-isolation-status");
		expect(status.getAttribute("data-state")).toBe("applied");
		expect(status.textContent).toContain("active");
		expect(status.getAttribute("title")).toContain("Last applied on the hub:");
		expect(screen.getByTestId("site-isolation-last-change").textContent).toMatch(/^Last changed: .+ by Floppy$/);
	});

	it("reports a failed apply", async () => {
		overview.applied = {
			hash: "abc",
			at: 1_780_000_000,
			error: "Error: Could not process rule",
			error_at: 1_780_000_100,
			error_code: "nft",
			file: null,
		};
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		const error = await screen.findByTestId("site-isolation-error");
		expect(error.textContent).toContain("the hub keeps the previous rules");
		expect(error.textContent).toContain("Error: Could not process rule");
		expect(screen.getByTestId("site-isolation-status").getAttribute("data-state")).toBe("error");
	});

	it("explains a fail-closed apply (links not resolvable) in plain words", async () => {
		overview.applied = { ...overview.applied, error: "Keine …", error_code: "links-unresolved", error_at: 1 };
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		const error = await screen.findByTestId("site-isolation-error");
		expect(error.textContent).toContain("So that nothing is opened by accident, the hub keeps the previous rules.");
	});

	it("an unenforced pair has its own readable cell, no hover needed", async () => {
		overview.pairs[0].enforced = false;
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		await screen.findByTestId("site-isolation-matrix");
		expect(cell(D, H).getAttribute("data-state")).toBe("not-enforced");
		expect(cell(D, H).textContent).toContain("separated – not in effect");
		expect(cell(D, H).className).toContain("bg-yellow-lt");
		expect(cell(D, H).className).not.toContain("bg-red-lt");
	});

	it("separating asks in a dialog with both sites' networks, then PUTs the full set", async () => {
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		await screen.findByTestId("site-isolation-matrix");

		// cancelled: nothing sent
		fireEvent.click(cell(F, H));
		const dialog = await screen.findByTestId("site-isolation-confirm");
		expect(dialog.textContent).toContain(
			"Floppy Home and Hinderlich Office will no longer be able to reach each other – in both directions, immediately; open connections drop as well.",
		);
		expect(dialog.textContent).toContain("Affected:");
		expect(dialog.textContent).toContain("192.168.1.0/24");
		expect(dialog.textContent).toContain("10.10.0.9/32");
		expect(dialog.textContent).toContain("VPN devices (clients) are not affected");
		fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
		await waitFor(() => expect(screen.queryByTestId("site-isolation-confirm")).toBeNull());
		expect(puts()).toHaveLength(0);

		fireEvent.click(cell(F, H));
		const ok = await confirmButton("Separate");
		expect(ok.className).toContain("btn-red");
		fireEvent.click(ok);
		await waitFor(() => expect(puts()).toHaveLength(1));
		// full set, snake_case, the vanished link's pair dropped
		expect(puts()[0].body).toEqual({
			pairs: [
				{ link_a: D, link_b: H },
				{ link_a: F, link_b: H },
			],
		});
		await waitFor(() => expect(cell(F, H).getAttribute("data-state")).toBe("blocked"));
	});

	it("allowing a separated pair asks with the allow text and removes it from the set", async () => {
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		await screen.findByTestId("site-isolation-matrix");
		fireEvent.click(cell(D, H));
		const dialog = await screen.findByTestId("site-isolation-confirm");
		expect(dialog.textContent).toContain(
			"Daniel Home and Hinderlich Office will be able to reach each other again",
		);
		fireEvent.click(await confirmButton("Allow connection again"));
		await waitFor(() => expect(puts()).toHaveLength(1));
		expect(puts()[0].body).toEqual({ pairs: [] });
	});

	it("shows a failed PUT in the card", async () => {
		putStatus = 400;
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		await screen.findByTestId("site-isolation-matrix");
		fireEvent.click(cell(D, F));
		fireEvent.click(await confirmButton("Separate"));
		expect(await screen.findByText("nft rejected")).toBeTruthy();
	});

	it("manual hub rules: own cell state, warning, and taking them over", async () => {
		overview.manual_pairs = [
			{
				link_a: F,
				link_b: H,
				rules: [{ family: "inet", table: "filter", chain: "forward", comment: "Standort-Trennung" }],
			},
		];
		overview.warnings.push({
			code: "manual-drop",
			rules: [{ family: "inet", table: "filter", chain: "forward", comment: "Standort-Trennung" }],
			message: "Am Hub …",
		});
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		await screen.findByTestId("site-isolation-matrix");
		expect(cell(F, H).getAttribute("data-state")).toBe("manual");
		expect(cell(F, H).textContent).toContain("separated by hand");
		expect(screen.getByTestId("site-isolation-warnings").textContent).toContain(
			"The hub has additional blocks set by hand outside FloppyGuard (inet filter forward).",
		);
		fireEvent.click(screen.getByTestId("site-isolation-adopt"));
		// the dialog button (the warning has one with the same name)
		await waitFor(() =>
			expect(screen.getAllByRole("button", { name: "Take over into FloppyGuard" })).toHaveLength(2),
		);
		fireEvent.click(screen.getAllByRole("button", { name: "Take over into FloppyGuard" })[1]);
		await waitFor(() => expect(puts()).toHaveLength(1));
		expect(puts()[0].body).toEqual({
			pairs: [
				{ link_a: D, link_b: H },
				{ link_a: F, link_b: H },
			],
		});
	});

	it("orphaned pairs can be removed from the link-missing warning", async () => {
		overview.warnings.push({ code: "link-missing", link_id: "wg0:X", message: "x" });
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		fireEvent.click(await screen.findByTestId("site-isolation-cleanup"));
		await waitFor(() => expect(puts()).toHaveLength(1));
		expect(puts()[0].body).toEqual({ pairs: [{ link_a: D, link_b: H }] });
	});

	it("narrow screens: one row per pair with a switch (on = not separated)", async () => {
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		const list = await screen.findByTestId("site-isolation-list");
		expect(list.className).toContain("d-md-none");
		expect(screen.getByTestId("site-isolation-matrix").parentElement?.className).toContain("d-none d-md-block");
		const rows = within(list).getAllByTestId("site-isolation-row");
		expect(rows).toHaveLength(3);
		const blockedRow = rows.find((r) => r.textContent?.includes("Daniel Home ↔ Hinderlich Office"));
		expect(blockedRow?.getAttribute("data-state")).toBe("blocked");
		expect(blockedRow?.textContent).toContain("1,234 packets dropped");
		const sw = within(blockedRow as HTMLElement).getByRole("switch") as HTMLInputElement;
		expect(sw.checked).toBe(false);
		expect(within(list).getByLabelText(/Daniel Home ↔ Floppy Home/)).toBeTruthy();

		const openRow = rows.find((r) => r.textContent?.includes("Daniel Home ↔ Floppy Home")) as HTMLElement;
		const openSwitch = within(openRow).getByRole("switch") as HTMLInputElement;
		expect(openSwitch.checked).toBe(true);
		fireEvent.click(openSwitch);
		fireEvent.click(await confirmButton("Separate"));
		await waitFor(() => expect(puts()).toHaveLength(1));
		expect(puts()[0].body).toEqual({
			pairs: [
				{ link_a: D, link_b: F },
				{ link_a: D, link_b: H },
			],
		});
	});

	it("with fewer than two sites there is nothing to separate", async () => {
		overview = { ...overview, sites: [site(D, "Daniel Home")], pairs: [], warnings: [] };
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		expect((await screen.findByTestId("site-isolation-summary")).textContent).toBe("Fewer than two sites");
		fireEvent.click(screen.getByTestId("site-isolation-toggle"));
		expect(await screen.findByTestId("site-isolation-too-few")).toBeTruthy();
		expect(screen.queryByTestId("site-isolation-matrix")).toBeNull();
	});

	it("degrades to a hint when the endpoint is missing", async () => {
		overview = undefined;
		fetchMock.mockImplementationOnce(async () => json({ error: { message: "Not Found" } }, 404));
		render(<SiteIsolationCard />, { wrapper: createWrapper() });
		expect((await screen.findByTestId("site-isolation-unavailable")).textContent).toContain("Not Found");
	});

	it("sits on the Freigaben page above the per-site view", async () => {
		render(<IngressPageContent />, { wrapper: createWrapper() });
		const card = await screen.findByTestId("site-isolation");
		expect(within(card).getByRole("heading", { name: "Sites among each other" })).toBeTruthy();
		const detail = await screen.findByTestId("ingress-detail-1");
		expect(card.compareDocumentPosition(detail) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
	});
});

// ── per-site banner + tester ──────────────────────────────────────────────────

describe("site isolation in the per-site view", () => {
	it("the status banner lists the sites this one is cut off from", async () => {
		render(<AgentIngressDetail agentId={1} />, { wrapper: createWrapper() });
		const line = await screen.findByTestId("ingress-banner-isolated");
		expect(line.textContent).toContain("Separated from: Daniel Home");
		// the hint links to the card (which then opens), no duplicate tooltip
		const link = screen.getByTestId("ingress-banner-isolated-link");
		expect(link.getAttribute("href")).toBe("/ingress#site-isolation");
		expect(link.textContent).toBe("(see “Sites among each other”)");
		expect(line.getAttribute("title")).toBeNull();
	});

	it("no isolation line when the site is not isolated", async () => {
		overview = { ...overview, pairs: [] };
		render(<AgentIngressDetail agentId={1} />, { wrapper: createWrapper() });
		await screen.findByTestId("ingress-banner");
		await waitFor(() => expect(calls.some((c) => c.url === "/api/site-isolation")).toBe(true));
		await waitFor(() => expect(calls.some((c) => c.url === "/api/agents/1/ingress/catalog")).toBe(true));
		expect(screen.queryByTestId("ingress-banner-isolated")).toBeNull();
	});

	it("the tester names the blocked pair when the hub's site isolation drops the flow", async () => {
		testPayload = {
			mode: "open",
			allowed: false,
			filtered: true,
			reason: "site-isolation",
			rule: null,
			matched_rules: [],
			disabled_match: null,
			port_unknown: false,
			notes: ["established-return", "forward-only", "site-isolation-not-applied"],
			site_isolation: { a: D, b: H, name_a: "Daniel Home", name_b: "Hinderlich Office", direction: "b-to-a" },
			link_found: true,
		};
		render(<IngressTester agentId={1} catalog={null} onFocusRule={() => {}} />, { wrapper: createWrapper() });
		const pick = (label: string, value: string) => {
			const input = screen.getByLabelText(label);
			fireEvent.change(input, { target: { value } });
			fireEvent.keyDown(input, { key: "Enter", code: "Enter", keyCode: 13 });
		};
		pick("Source", "192.168.210.5");
		pick("Destination", "192.168.111.10");
		fireEvent.click(screen.getByRole("button", { name: "Check" }));
		const result = await screen.findByTestId("ingress-tester-result");
		expect(result.textContent).toContain("Blocked by site isolation (Hinderlich Office ↔ Daniel Home)");
		expect(result.className).toContain("alert-danger");
		expect(result.textContent).toContain("has not been applied successfully on the hub yet");
	});

	it("the tester names a manual hub rule when no FloppyGuard pair blocks the flow", async () => {
		testPayload = {
			mode: "open",
			allowed: false,
			filtered: true,
			reason: "site-isolation",
			rule: null,
			matched_rules: [],
			disabled_match: null,
			port_unknown: false,
			notes: ["established-return", "forward-only"],
			site_isolation: null,
			site_isolation_manual: {
				family: "inet",
				table: "filter",
				chain: "forward",
				comment: "Standort-Trennung Hinderlich zu Daniel",
			},
			link_found: true,
		};
		render(<IngressTester agentId={1} catalog={null} onFocusRule={() => {}} />, { wrapper: createWrapper() });
		const pick = (label: string, value: string) => {
			const input = screen.getByLabelText(label);
			fireEvent.change(input, { target: { value } });
			fireEvent.keyDown(input, { key: "Enter", code: "Enter", keyCode: 13 });
		};
		pick("Source", "192.168.210.5");
		pick("Destination", "192.168.111.10");
		fireEvent.click(screen.getByRole("button", { name: "Check" }));
		const result = await screen.findByTestId("ingress-tester-result");
		expect(result.textContent).toContain(
			"Dropped on the hub by a block set by hand outside FloppyGuard (Standort-Trennung Hinderlich zu Daniel)",
		);
	});
});
