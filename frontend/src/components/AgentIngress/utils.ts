import type { AgentIngressBulkResult, AgentIngressCheck, AgentIngressPort, AgentIngressRule } from "src/api/backend";
import { intl } from "src/locale/IntlProvider";

/** Rules without a hit for this long get a (muted) warning. */
export const STALE_HIT_SECONDS = 30 * 24 * 3600;

/** Split a comma/semicolon/whitespace/newline separated list. */
export const splitList = (value: string): string[] =>
	value
		.split(/[\s,;]+/)
		.map((s) => s.trim())
		.filter(Boolean);

const IPV4_CIDR = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/;

export const isIpv4OrCidr = (value: string): boolean => {
	const m = IPV4_CIDR.exec(value);
	if (!m) return false;
	const octets = m.slice(1, 5).map(Number);
	if (octets.some((o) => o > 255)) return false;
	if (m[5] !== undefined && Number(m[5]) > 32) return false;
	return true;
};

const PORT_ENTRY = /^(tcp|udp)\/(\d{1,5})(?:[:-](\d{1,5}))?$/i;

/** Parse "tcp/443, udp/53, tcp/8000:8010" → ports; invalid entries are returned separately. */
export const parsePorts = (value: string): { ports: AgentIngressPort[]; invalid: string[] } => {
	const ports: AgentIngressPort[] = [];
	const invalid: string[] = [];
	for (const entry of splitList(value)) {
		const m = PORT_ENTRY.exec(entry);
		if (!m) {
			invalid.push(entry);
			continue;
		}
		const from = Number(m[2]);
		const to = m[3] !== undefined ? Number(m[3]) : from;
		if (from < 1 || to > 65535 || to < from) {
			invalid.push(entry);
			continue;
		}
		ports.push({
			proto: m[1].toLowerCase() as AgentIngressPort["proto"],
			port: m[3] !== undefined ? `${from}:${to}` : `${from}`,
		});
	}
	return { ports, invalid };
};

export const formatPorts = (ports: AgentIngressPort[]): string => ports.map((p) => `${p.proto}/${p.port}`).join(", ");

export const isLegacyNote = (note: string | null | undefined): boolean => /altlast/i.test(note ?? "");

/** createdOn arrives as unix seconds or as a date string; null when unparsable. */
export const toUnixSeconds = (value: number | string | null | undefined): number | null => {
	if (value === null || value === undefined || value === "") return null;
	if (typeof value === "number") return value > 1e12 ? Math.floor(value / 1000) : value;
	if (/^\d+$/.test(value)) return toUnixSeconds(Number(value));
	const ms = Date.parse(value);
	return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
};

/**
 * "No new connection" = enabled and no hit for STALE_HIT_SECONDS, measured from
 * the latest of last hit, creation and armedOn (set by the backend when the
 * rule is switched on or its targets change — a rename or note edit does not
 * restart the window). A disabled rule (which cannot get hits) is never
 * flagged. Hits only count NEW connections, so this is a hint, not proof the
 * rule is unused: long-lived flows (LDAP, IMAP, iSCSI) do not show up.
 * Without armedOn (backend before the migration) modifiedOn is the fallback.
 */
export const isStaleRule = (
	rule: Pick<AgentIngressRule, "lastHitAt" | "createdOn" | "enabled"> &
		Partial<Pick<AgentIngressRule, "modifiedOn" | "armedOn">>,
	now = Date.now() / 1000,
): boolean => {
	if (!rule.enabled) return false;
	const armed = rule.armedOn !== undefined ? (rule.armedOn ?? null) : toUnixSeconds(rule.modifiedOn);
	const refs = [rule.lastHitAt ?? null, toUnixSeconds(rule.createdOn), armed].filter((v): v is number => v !== null);
	if (refs.length === 0) return false;
	const ref = Math.max(...refs);
	return now - ref > STALE_HIT_SECONDS;
};

export { relativeTime } from "src/modules/relativeTime";

export interface RuleFormValues {
	name: string;
	sources: string;
	destinations: string;
	/**
	 * formatPorts text; "" = ALL ports (an explicit choice); null = nothing
	 * chosen yet — never silently treated as "all ports".
	 */
	ports: string | null;
	note: string;
	enabled: boolean;
}

/**
 * Client-side validation; the backend validates again and its message is shown
 * as well. `autoName`: the form derives a name from the rule when none is typed.
 */
export const validateRuleForm = (
	values: RuleFormValues,
	{ autoName = false }: { autoName?: boolean } = {},
): string[] => {
	const errors: string[] = [];
	if (!values.name.trim() && !autoName) {
		errors.push(intl.formatMessage({ id: "wireguard.agent.ingress.err.name-required" }));
	}
	const sources = splitList(values.sources);
	if (sources.length === 0) {
		errors.push(intl.formatMessage({ id: "wireguard.agent.ingress.err.sources-required" }));
	}
	for (const v of [...sources, ...splitList(values.destinations)]) {
		if (!isIpv4OrCidr(v)) {
			errors.push(intl.formatMessage({ id: "wireguard.agent.ingress.err.invalid-cidr" }, { value: v }));
		}
	}
	if (values.ports === null) {
		errors.push(intl.formatMessage({ id: "wireguard.agent.ingress.err.ports-required" }));
	}
	for (const v of parsePorts(values.ports ?? "").invalid) {
		errors.push(intl.formatMessage({ id: "wireguard.agent.ingress.err.invalid-port" }, { value: v }));
	}
	return errors;
};

/**
 * Info line after a bulk create (wizards, "create missing rules"): a single
 * new / switched-on rule by name, otherwise the counts. Switched-on rules are
 * reported separately — they existed but were off.
 */
export const bulkResultInfo = (res: AgentIngressBulkResult | undefined): string => {
	const created = res?.created ?? [];
	const reenabled = res?.reenabled ?? [];
	const skipped = res?.skipped?.length ?? 0;
	if (created.length === 1 && !reenabled.length && !skipped) {
		return ti("result.created-one", { name: created[0].name });
	}
	if (!created.length && reenabled.length === 1 && !skipped) {
		return ti("result.reenabled-one", { name: reenabled[0].name });
	}
	const parts = [ti("wizard.result", { created: created.length, skipped })];
	if (reenabled.length) parts.push(ti("result.reenabled", { count: reenabled.length }));
	return parts.join(", ");
};

/** The rule a bulk result points to (first new, else first switched-on), for highlighting. */
export const bulkResultRuleId = (res: AgentIngressBulkResult | undefined): number | null =>
	res?.created?.[0]?.id ?? res?.reenabled?.[0]?.id ?? null;

/** i18n shortcut for the wireguard.agent.ingress.* namespace */
export const ti = (id: string, values?: Record<string, string | number>) =>
	intl.formatMessage({ id: `wireguard.agent.ingress.${id}` }, values);

/**
 * "Warnungen" = enabled upstreams without a matching rule (the only finding that
 * drops traffic). One helper so the WireGuard agent panel and the Freigaben page
 * show the same number; unused hub rules are a separate, neutral hint.
 */
export const ingressWarningCount = (entry: Pick<AgentIngressCheck, "missing"> | undefined): number =>
	entry?.missing.length ?? 0;

/** Hub rules whose targets no proxy host/stream uses — info only, not a warning. */
export const ingressUnusedCount = (entry: Pick<AgentIngressCheck, "unusedHubRules"> | undefined): number =>
	entry?.unusedHubRules.length ?? 0;

export const errMessage = (err: unknown) => (err instanceof Error ? err.message : String(err));
