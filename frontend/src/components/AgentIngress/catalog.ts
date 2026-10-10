import type {
	AgentIngressCatalog,
	AgentIngressCatalogEntry,
	AgentIngressCatalogKind,
	AgentIngressMode,
	AgentIngressPort,
	AgentIngressPortPreset,
	AgentIngressPruneCandidate,
	AgentIngressRule,
	AgentIngressRuleData,
} from "src/api/backend";
import { formatPorts, parsePorts, splitList, ti } from "./utils";

// Pure helpers around the ingress catalog: names for CIDRs, whole entries back
// from CIDR lists, rule sentences, grouping, port presets and the wizard rule
// factories. Everything works without a catalog (raw CIDRs as labels).

/** Catalog entry as the pickers use it; `display` overrides the computed label. */
export type PickerEntry = AgentIngressCatalogEntry & { display?: string };

/** Per-rule cap of the backend (MAX_LINES_PER_RULE). */
export const MAX_RULE_LINES = 256;

/** Destination kinds that stand for one upstream host. */
export const HOST_KINDS: ReadonlySet<AgentIngressCatalogKind> = new Set([
	"proxy-host",
	"stream",
	"manual",
	"service",
	"hub-egress",
]);

// ── IPv4 ─────────────────────────────────────────────────────────────────────

const parseCidr = (value: string): { net: number; bits: number } | null => {
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(String(value).trim());
	if (!m) return null;
	const octets = m.slice(1, 5).map(Number);
	if (octets.some((o) => o > 255)) return null;
	const bits = m[5] === undefined ? 32 : Number(m[5]);
	if (bits > 32) return null;
	const ip = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
	const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
	return { net: (ip & mask) >>> 0, bits };
};

const intToIp = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");

/** "10.0.0.1" → "10.0.0.1/32", "10.0.0.7/24" → "10.0.0.0/24"; invalid input unchanged. */
export const canonCidr = (value: string): string => {
	const p = parseCidr(value);
	return p ? `${intToIp(p.net)}/${p.bits}` : String(value).trim();
};

/** Whether `outer` contains `inner` (both CIDR or IP). */
export const cidrContains = (outer: string, inner: string): boolean => {
	const o = parseCidr(outer);
	const i = parseCidr(inner);
	if (!o || !i || i.bits < o.bits) return false;
	const mask = o.bits === 0 ? 0 : (0xffffffff << (32 - o.bits)) >>> 0;
	return ((i.net & mask) >>> 0) === o.net;
};

/** "10.3.10.25/32" → "10.3.10.25"; networks stay CIDRs. */
export const shortCidr = (cidr: string): string => {
	const c = canonCidr(cidr);
	return c.endsWith("/32") ? c.slice(0, -3) : c;
};

// ── entries ──────────────────────────────────────────────────────────────────

export const flatEntries = (catalog: AgentIngressCatalog | undefined | null): AgentIngressCatalogEntry[] =>
	catalog ? [...(catalog.sources ?? []), ...(catalog.destinations ?? [])] : [];

export const entryById = (catalog: AgentIngressCatalog | undefined | null): Map<string, AgentIngressCatalogEntry> =>
	new Map(flatEntries(catalog).map((e) => [e.id, e]));

/** The hub source entry (hub tunnel address), if any. */
export const hubEntryOf = (catalog: AgentIngressCatalog | undefined | null) =>
	catalog?.sources.find((e) => e.kind === "hub") ?? null;

/**
 * Display name of one entry: hosts "Ops-Server (10.3.10.25)", site nets
 * "Hinderlich Office · 192.168.200.0/24", whole sites with several nets
 * "Hinderlich Office (6 networks)", the hub and the tunnel with i18n names.
 */
export const entryLabel = (entry: PickerEntry, catalog?: AgentIngressCatalog | null): string => {
	if (entry.display) return entry.display;
	switch (entry.kind) {
		case "hub":
			return ti("catalog.hub");
		case "tunnel":
			return ti("catalog.tunnel", { net: entry.cidrs[0] ?? entry.label });
		case "site-net": {
			const parent = entry.parent ? catalog?.sources.find((e) => e.id === entry.parent) : undefined;
			return parent ? `${parent.label} · ${entry.label}` : entry.label;
		}
		case "site":
			return entry.cidrs.length > 1
				? `${entry.label} (${ti("catalog.networks", { count: entry.cidrs.length })})`
				: entry.label;
		case "network":
			return entry.label;
		default:
			// egress flow SOURCES (id "egress:…") are named, not host entries
			if (HOST_KINDS.has(entry.kind) && !entry.id.startsWith("egress:")) {
				return `${entry.names?.[0] ?? entry.label} (${shortCidr(entry.cidrs[0] ?? "")})`;
			}
			return entry.label;
	}
};

// Exact-match priority of labelForCidr (lower wins)
const EXACT_PRIORITY: Record<string, number> = {
	"proxy-host": 0,
	stream: 0,
	manual: 0,
	service: 0,
	"site-net": 1,
	site: 2,
	client: 3,
	hub: 4,
	"hub-egress": 5,
	network: 6,
	tunnel: 7,
};

/** Name of a network that contains a lone address ("Floppy Home"), or null. */
const containerName = (cidr: string, catalog: AgentIngressCatalog): string | null => {
	let best: { bits: number; name: string } | null = null;
	for (const e of flatEntries(catalog)) {
		if (!["site", "site-net", "network", "client", "tunnel"].includes(e.kind)) continue;
		for (const c of e.cidrs) {
			const p = parseCidr(c);
			if (!p || p.bits === 32 || !cidrContains(c, cidr)) continue;
			if (best && best.bits >= p.bits) continue;
			let name: string;
			if (e.kind === "site-net") {
				name = catalog.sources.find((s) => s.id === e.parent)?.label ?? e.label;
			} else if (e.kind === "network") {
				name = catalog.site?.name ?? e.label;
			} else if (e.kind === "tunnel") {
				name = ti("catalog.tunnel", { net: c });
			} else {
				name = e.label;
			}
			best = { bits: p.bits, name };
		}
	}
	return best?.name ?? null;
};

/**
 * Human name for one CIDR. An exact match wins (host > site net > site >
 * client > hub > network); a lone address inside a known network shows as
 * "10.3.10.77 (Floppy Home)"; otherwise the raw CIDR.
 */
export const labelForCidr = (cidr: string, catalog: AgentIngressCatalog | undefined | null): string => {
	const raw = shortCidr(cidr);
	if (!catalog) return raw;
	const c = canonCidr(cidr);
	const exact = flatEntries(catalog)
		.filter((e) => e.cidrs.some((x) => canonCidr(x) === c))
		.sort((a, b) => (EXACT_PRIORITY[a.kind] ?? 9) - (EXACT_PRIORITY[b.kind] ?? 9));
	const hit = exact[0];
	if (hit) {
		if (hit.kind === "site" && hit.cidrs.length > 1) {
			// one address of a site (tunnel /32) – name the site, keep the address visible
			return `${raw} (${hit.label})`;
		}
		if (hit.kind === "client" && hit.cidrs.length > 1) return `${hit.label} (${raw})`;
		if (hit.kind === "network") return `${catalog.site?.name ?? raw} · ${raw}`;
		return entryLabel(hit, catalog);
	}
	if (c.endsWith("/32")) {
		const name = containerName(c, catalog);
		if (name) return `${raw} (${name})`;
	}
	return raw;
};

/**
 * A CIDR list back into whole entries: an entry is chosen when ALL its cidrs
 * are in the list, larger entries first (a full site is one entry, not six
 * site nets). Leftover CIDRs (as given) are returned in `rest`.
 */
export const collapseCidrs = <E extends AgentIngressCatalogEntry>(
	cidrs: string[],
	entries: E[],
): { entries: E[]; rest: string[] } => {
	const list = cidrs.map((c) => ({ raw: c, canon: canonCidr(c) }));
	const index = new Map<string, number>();
	list.forEach((c, i) => {
		if (!index.has(c.canon)) index.set(c.canon, i);
	});
	const claimed = new Set<string>();
	const chosen: Array<{ entry: E; first: number }> = [];
	const seen = new Set<string>();
	const candidates = entries
		.filter((e) => e.cidrs.length > 0)
		.map((e, order) => ({ e, order }))
		.sort((a, b) => b.e.cidrs.length - a.e.cidrs.length || a.order - b.order);
	for (const { e } of candidates) {
		if (seen.has(e.id)) continue;
		const canon = e.cidrs.map(canonCidr);
		if (!canon.every((c) => index.has(c))) continue;
		if (canon.some((c) => claimed.has(c))) continue;
		for (const c of canon) claimed.add(c);
		seen.add(e.id);
		chosen.push({ entry: e, first: Math.min(...canon.map((c) => index.get(c) ?? 0)) });
	}
	chosen.sort((a, b) => a.first - b.first);
	const rest: string[] = [];
	const restSeen = new Set<string>();
	for (const c of list) {
		if (claimed.has(c.canon) || restSeen.has(c.canon)) continue;
		restSeen.add(c.canon);
		rest.push(c.raw);
	}
	return { entries: chosen.map((c) => c.entry), rest };
};

/** Labels for a CIDR list: whole entries first, then the single CIDRs. */
export const labelsForCidrs = (cidrs: string[], entries: PickerEntry[], catalog?: AgentIngressCatalog | null) => {
	if (!catalog) return cidrs.map(shortCidr);
	const { entries: whole, rest } = collapseCidrs(cidrs, entries);
	return [...whole.map((e) => entryLabel(e, catalog)), ...rest.map((c) => labelForCidr(c, catalog))];
};

type RuleLike = Pick<AgentIngressRuleData, "sources" | "destinations" | "ports">;

export const sourceKeyOf = (sources: string[]) => [...new Set(sources.map(canonCidr))].sort().join(",");

export interface RuleDescription {
	sourceLabel: string;
	sourceKey: string;
	targets: string[];
	anyTarget: boolean;
	portsText: string;
}

export const portsText = (ports: AgentIngressPort[]) =>
	ports.length ? ti("sentence.ports", { list: formatPorts(ports) }) : ti("sentence.all-ports");

export const describeRule = (rule: RuleLike, catalog: AgentIngressCatalog | undefined | null): RuleDescription => ({
	sourceLabel: labelsForCidrs(rule.sources, catalog?.sources ?? [], catalog).join(", "),
	sourceKey: sourceKeyOf(rule.sources),
	targets: labelsForCidrs(rule.destinations, catalog?.destinations ?? [], catalog),
	anyTarget: rule.destinations.length === 0,
	portsText: portsText(rule.ports),
});

export type SourceGroupKind = "hub" | "site" | "client" | "other";

export interface RuleGroup<R extends RuleLike = AgentIngressRule> {
	key: string;
	label: string;
	kind: SourceGroupKind;
	cidrs: string[];
	rules: R[];
}

const groupKind = (sources: string[], catalog: AgentIngressCatalog | undefined | null): SourceGroupKind => {
	if (!catalog || !sources.length) return "other";
	const within = (kinds: string[]) =>
		sources.every((s) =>
			catalog.sources.some((e) => kinds.includes(e.kind) && e.cidrs.some((c) => cidrContains(c, s))),
		);
	if (within(["hub", "hub-egress"])) return "hub";
	if (within(["site", "site-net"])) return "site";
	if (within(["client"])) return "client";
	return "other";
};

/** The site (whole-site entry) a source CIDR lies in — via a site or one of its nets. */
const siteOfCidr = (cidr: string, catalog: AgentIngressCatalog): AgentIngressCatalogEntry | null => {
	for (const e of catalog.sources) {
		if (e.kind !== "site" && e.kind !== "site-net") continue;
		if (!e.cidrs.some((c) => cidrContains(c, cidr))) continue;
		const site = e.kind === "site-net" ? catalog.sources.find((s) => s.id === e.parent) : e;
		if (site) return site;
	}
	return null;
};

/**
 * Heading of a rule group: sources inside a site are named by the site only
 * ("Daniel Home", not "Daniel Home · 192.168.111.0/24, Daniel Home · …" — the
 * CIDRs are shown next to it), the rest by their labels; duplicates once.
 */
export const groupLabelOf = (sources: string[], catalog: AgentIngressCatalog | undefined | null): string => {
	if (!catalog) return [...new Set(sources.map(shortCidr))].join(", ");
	const names: string[] = [];
	const rest: string[] = [];
	for (const s of sources) {
		const site = siteOfCidr(s, catalog);
		if (site) names.push(site.label);
		else rest.push(s);
	}
	return [...new Set([...names, ...labelsForCidrs(rest, catalog.sources ?? [], catalog)])].join(", ");
};

const GROUP_ORDER: Record<SourceGroupKind, number> = { hub: 0, site: 1, client: 2, other: 3 };

/** Rules grouped by their (sorted) source list: hub first, then sites A→Z, clients, others. */
export const groupRulesBySource = <R extends RuleLike>(
	rules: R[],
	catalog: AgentIngressCatalog | undefined | null,
): RuleGroup<R>[] => {
	const groups = new Map<string, RuleGroup<R>>();
	for (const rule of rules) {
		const key = sourceKeyOf(rule.sources);
		let g = groups.get(key);
		if (!g) {
			g = {
				key,
				label: groupLabelOf(rule.sources, catalog),
				kind: groupKind(rule.sources, catalog),
				cidrs: [...new Set(rule.sources.map(canonCidr))].sort(),
				rules: [],
			};
			groups.set(key, g);
		}
		g.rules.push(rule);
	}
	return [...groups.values()].sort(
		(a, b) => GROUP_ORDER[a.kind] - GROUP_ORDER[b.kind] || a.label.localeCompare(b.label),
	);
};

// ── ports ────────────────────────────────────────────────────────────────────

const portKey = (p: AgentIngressPort) => `${p.proto}/${p.port}`;

/** Ports → checked presets + the rest as "tcp/8443, udp/51820". [] = "all". */
export const portsToPresetSelection = (
	ports: AgentIngressPort[],
	presets: AgentIngressPortPreset[],
): { presetIds: string[]; custom: string } => {
	if (ports.length === 0) return { presetIds: presets.some((p) => p.id === "all") ? ["all"] : [], custom: "" };
	const keys = new Set(ports.map(portKey));
	const presetIds: string[] = [];
	const used = new Set<string>();
	for (const p of presets) {
		if (!p.ports.length) continue;
		if (p.ports.every((x) => keys.has(portKey(x)))) {
			presetIds.push(p.id);
			for (const x of p.ports) used.add(portKey(x));
		}
	}
	return { presetIds, custom: formatPorts(ports.filter((p) => !used.has(portKey(p)))) };
};

/** Checked presets + custom text → ports ("all" = []). Invalid custom entries are dropped. */
export const selectionToPorts = (
	presetIds: string[],
	custom: string,
	presets: AgentIngressPortPreset[],
): AgentIngressPort[] => {
	if (presetIds.includes("all")) return [];
	const out: AgentIngressPort[] = [];
	const seen = new Set<string>();
	const add = (p: AgentIngressPort) => {
		if (seen.has(portKey(p))) return;
		seen.add(portKey(p));
		out.push({ proto: p.proto, port: p.port });
	};
	for (const id of presetIds) {
		for (const p of presets.find((x) => x.id === id)?.ports ?? []) add(p);
	}
	for (const p of parsePorts(custom).ports) add(p);
	return out;
};

// ── rules ────────────────────────────────────────────────────────────────────

/** Filter lines a rule expands to (mirrors the backend's ruleLineCount). */
export const lineCount = (rule: Partial<RuleLike>): number => {
	const n = (list: unknown[] | undefined) => Math.max(1, Array.isArray(list) ? list.length : 0);
	return (Array.isArray(rule.sources) ? rule.sources.length : 0) * n(rule.destinations) * n(rule.ports);
};

/** Rule opens every port or the whole site. */
export const isBroadRule = (rule: RuleLike) => rule.destinations.length === 0 || rule.ports.length === 0;

const clip = (s: string) => s.slice(0, 100);

/**
 * Rule that lets the hub reach one upstream host (same as the backend's
 * upstreamSuggestion): hub tunnel address (or the egress flow's own source) →
 * host/32 on the ports its upstreams use. null for hosts without a known port.
 */
export const ruleForUpstream = (
	entry: AgentIngressCatalogEntry,
	hubEntry: AgentIngressCatalogEntry | null,
	egressSources: AgentIngressCatalogEntry[] = [],
): AgentIngressRuleData | null => {
	// Only the ports the proxy hosts / streams use: `ports` also lists services
	// the agent found on the host (display), which the hub does not need.
	const ports = entry.upstreamPorts ?? entry.ports ?? [];
	if (entry.hint === "no-port" || !ports.length || !entry.cidrs.length) return null;
	const name = entry.names?.[0] ?? entry.label;
	let sources: string[] = hubEntry?.cidrs.slice(0, 1) ?? [];
	if (entry.kind === "hub-egress") {
		const egress = egressSources.find((e) => e.kind === "hub-egress" && (entry.names ?? []).includes(e.label));
		if (egress) sources = egress.cidrs.slice(0, 1);
	}
	if (!sources.length) return null;
	return {
		name: clip(`${entry.kind === "hub-egress" ? "Hub" : "Proxy"} ${name}`),
		sources,
		destinations: [canonCidr(entry.cidrs[0])],
		ports: ports.map((p) => ({ proto: p.proto, port: p.port })),
		enabled: true,
	};
};

export interface RuleTarget {
	label: string;
	cidrs: string[];
}

/** "<Site> → <first target> +N" on the chosen ports. */
export const ruleForSiteAccess = (
	site: RuleTarget,
	targets: RuleTarget[],
	ports: AgentIngressPort[],
): AgentIngressRuleData => ({
	name: clip(`${site.label} → ${targets[0]?.label ?? ""}${targets.length > 1 ? ` +${targets.length - 1}` : ""}`),
	sources: [...site.cidrs],
	destinations: targets.flatMap((t) => t.cidrs),
	ports: ports.map((p) => ({ proto: p.proto, port: p.port })),
	enabled: true,
});

/**
 * Name for a rule the admin did not name, from its sentence: "Branch → Cloud
 * (192.168.60.9) +1", "Branch → everything in the site". "" without sources.
 */
export const autoRuleName = (rule: RuleLike, catalog: AgentIngressCatalog | undefined | null): string => {
	if (!rule.sources.length) return "";
	const d = describeRule(rule, catalog);
	if (d.anyTarget) return clip(ti("rule-name.anything", { source: d.sourceLabel }));
	return clip(`${d.sourceLabel} → ${d.targets[0] ?? ""}${d.targets.length > 1 ? ` +${d.targets.length - 1}` : ""}`);
};

/** The whole site LAN on every port. */
export const ruleForSiteFull = (site: RuleTarget): AgentIngressRuleData => ({
	name: clip(ti("wizard.full.rule-name", { site: site.label })),
	sources: [...site.cidrs],
	destinations: [],
	ports: [],
	enabled: true,
});

/** Picker value (comma list) → named targets: whole entries, then single CIDRs. */
export const targetsFromValue = (
	value: string,
	entries: PickerEntry[],
	catalog: AgentIngressCatalog | undefined | null,
): RuleTarget[] => {
	const { entries: whole, rest } = collapseCidrs(splitList(value), entries);
	return [
		...whole.map((e) => ({ label: entryLabel(e, catalog), cidrs: e.cidrs.map(canonCidr) })),
		...rest.map((c) => ({ label: labelForCidr(c, catalog), cidrs: [canonCidr(c)] })),
	];
};

const toSec = (v: number | string | null | undefined): number => {
	if (v === null || v === undefined || v === "") return 0;
	if (typeof v === "number") return v > 1e12 ? Math.floor(v / 1000) : v;
	if (/^\d+$/.test(v)) return toSec(Number(v));
	const ms = Date.parse(v);
	return Number.isNaN(ms) ? 0 : Math.floor(ms / 1000);
};

/**
 * Prune candidates the UI may switch off: only enabled rules that still exist;
 * in restricted mode at least one enabled rule always stays (the newest one —
 * last hit / creation / arming — is dropped from the list).
 */
export const pruneSelection = (
	candidates: AgentIngressPruneCandidate[],
	rules: AgentIngressRule[],
	mode: AgentIngressMode,
): AgentIngressPruneCandidate[] => {
	const enabled = rules.filter((r) => r.enabled);
	const list = candidates.filter((c) => enabled.some((r) => r.id === c.id));
	if (mode !== "restricted" || !list.length || list.length < enabled.length) return list;
	const ref = (id: number) => {
		const r = enabled.find((x) => x.id === id);
		return r ? Math.max(r.lastHitAt ?? 0, toSec(r.createdOn), r.armedOn ?? 0) : 0;
	};
	let newest = 0;
	list.forEach((c, i) => {
		const a = ref(c.id);
		const b = ref(list[newest].id);
		if (a > b || (a === b && c.id > list[newest].id)) newest = i;
	});
	return list.filter((_, i) => i !== newest);
};

/**
 * Tester options: every entry with several CIDRs split into one option per CIDR
 * (site nets, client hosts), CIDRs that already have their own entry skipped.
 */
export const expandEntries = (
	entries: AgentIngressCatalogEntry[],
	catalog: AgentIngressCatalog | undefined | null,
): PickerEntry[] => {
	const single = new Set(entries.filter((e) => e.cidrs.length === 1).map((e) => canonCidr(e.cidrs[0])));
	const out: PickerEntry[] = [];
	for (const e of entries) {
		if (e.cidrs.length <= 1) {
			out.push(e);
			continue;
		}
		e.cidrs.forEach((c, i) => {
			if (single.has(canonCidr(c))) return;
			out.push({
				...e,
				id: `${e.id}#${i}`,
				cidrs: [c],
				display: `${e.kind === "hub" ? ti("catalog.hub") : e.label} · ${shortCidr(c)}`,
			});
		});
	}
	return out.map((e) => (e.display ? e : { ...e, display: entryLabel(e, catalog) }));
};
