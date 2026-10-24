import type { Agent, AgentIngressApplied, AgentIngressCheck, AgentIngressMode } from "src/api/backend";
import { ingressWarningCount } from "./utils";

/** One site/agent in the Freigaben master list. */
export interface IngressAgentEntry {
	agent: Agent;
	mode: AgentIngressMode;
	/** proxy targets without a rule (any mode) */
	missing: number;
	/** missing targets that are actually dropped (restricted only) — the meaningful warning */
	warnings: number;
	/** what the agent reported for its ruleset (from the check); undefined = not known yet */
	applied?: AgentIngressApplied["state"];
	/** enabled rules (from the check); null = not known yet */
	activeRules: number | null;
}

/**
 * Primary label of a site in the Freigaben page: the WireGuard link name
 * ("Floppy Home"), falling back to the agent name when there is none.
 */
export const ingressSiteName = (agent: Pick<Agent, "name" | "wgLinkName">): string =>
	agent.wgLinkName?.trim() || agent.name;

/**
 * Secondary label: the agent name ("VM-Docker (192.168.11.7)") when the site
 * name is the link name — null when it would only repeat the primary label.
 */
export const ingressAgentSubName = (agent: Pick<Agent, "name" | "wgLinkName">): string | null => {
	const site = ingressSiteName(agent);
	return agent.name && agent.name !== site ? agent.name : null;
};

/**
 * A restricted agent whose ruleset is not confirmed as running: rejected,
 * offline or unknown (pending is normal right after a change). Its filter may
 * not be what the page shows.
 */
export const isIngressAppliedProblem = (entry: Pick<IngressAgentEntry, "mode" | "applied">): boolean =>
	entry.mode === "restricted" && !!entry.applied && entry.applied !== "applied" && entry.applied !== "pending";

/** Agents with their mode and warnings; restricted first, then by site name (as displayed). */
export const buildIngressAgentEntries = (
	agents: Agent[],
	checks: AgentIngressCheck[] | undefined,
): IngressAgentEntry[] =>
	agents
		.map((agent) => {
			const check = checks?.find((c) => c.agentId === agent.id);
			const mode: AgentIngressMode = check?.ingressMode ?? agent.ingressMode ?? "open";
			const missing = ingressWarningCount(check);
			return {
				agent,
				mode,
				missing,
				warnings: mode === "restricted" ? missing : 0,
				applied: check?.applied?.state,
				activeRules: check?.activeRuleCount ?? null,
			};
		})
		.sort(
			(a, b) =>
				Number(b.mode === "restricted") - Number(a.mode === "restricted") ||
				ingressSiteName(a.agent).localeCompare(ingressSiteName(b.agent)) ||
				a.agent.name.localeCompare(b.agent.name),
		);

/**
 * Default selection: a restricted agent whose ruleset is not running, else the
 * first restricted agent, else the first with missing targets, else the first.
 */
export const pickDefaultIngressAgent = (entries: IngressAgentEntry[]): number | null =>
	(
		entries.find(isIngressAppliedProblem) ??
		entries.find((e) => e.mode === "restricted") ??
		entries.find((e) => e.missing > 0) ??
		entries[0]
	)?.agent.id ?? null;

/** The agent named by the URL (?agent=<id>), if it exists. */
export const ingressAgentFromParam = (entries: IngressAgentEntry[], param: string | null): number | null => {
	if (param && /^\d+$/.test(param)) {
		const id = Number(param);
		if (entries.some((e) => e.agent.id === id)) return id;
	}
	return null;
};
