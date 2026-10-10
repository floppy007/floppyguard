import type {
	AgentIngressCatalog,
	AgentIngressCheck,
	AgentIngressMode,
	AgentIngressRule,
	AgentIngressRuleData,
} from "src/api/backend";
import { useCreateAgentIngressRulesBulk, useDisableAgentIngressRules } from "src/hooks";
import { canonCidr, pruneSelection } from "./catalog";
import { bulkResultInfo, errMessage, ti } from "./utils";

/** Same target identity as the backend's bulk dedupe: sources, destinations and ports as sets. */
const targetKey = (r: Pick<AgentIngressRuleData, "sources" | "destinations" | "ports">) =>
	JSON.stringify([
		[...new Set(r.sources.map(canonCidr))].sort(),
		[...new Set(r.destinations.map(canonCidr))].sort(),
		[...new Set(r.ports.map((p) => `${p.proto}/${p.port}`))].sort(),
	]);

/**
 * Proxy-target gaps with a one-click rule (client gaps would open all ports: not
 * "proxy targets"). One suggestion per distinct target — several proxy hosts on
 * the same host:port, or a stream's tcp and udp side with the same rule, become
 * ONE rule whose name lists them — so the count and the confirm match what the
 * backend creates.
 */
export const missingProxySuggestions = (check: AgentIngressCheck | undefined): AgentIngressRuleData[] => {
	const byKey = new Map<string, { rule: AgentIngressRuleData; names: string[] }>();
	for (const m of check?.missing ?? []) {
		if (m.kind === "vpn-client" || !m.suggestion) continue;
		const rule = { ...m.suggestion, enabled: true };
		const key = targetKey(rule);
		const hit = byKey.get(key);
		if (!hit) byKey.set(key, { rule, names: [rule.name] });
		else if (!hit.names.includes(rule.name)) hit.names.push(rule.name);
	}
	return [...byKey.values()].map(({ rule, names }) => ({
		...rule,
		name: (names.length > 1 ? `${names[0]} +${names.length - 1}` : names[0]).slice(0, 100),
	}));
};

interface MissingProps {
	agentId: number;
	mode: AgentIngressMode;
	check: AgentIngressCheck | undefined;
	onError: (msg: string | null) => void;
	onInfo: (msg: string | null) => void;
}

/**
 * "Release all missing proxy targets": one bulk create for every proxy target
 * the agent drops. Only offered while the filter is active — in open mode the
 * targets pass anyway.
 */
export function MissingProxyAction({ agentId, mode, check, onError, onInfo }: MissingProps) {
	const bulk = useCreateAgentIngressRulesBulk(agentId);
	const suggestions = mode === "restricted" ? missingProxySuggestions(check) : [];

	if (!suggestions.length) return null;

	const onMissing = () => {
		if (bulk.isPending) return;
		const names = suggestions.map((s) => `• ${s.name}`).join("\n");
		if (!window.confirm(`${ti("comfort.missing-confirm", { count: suggestions.length })}\n\n${names}`)) return;
		onError(null);
		onInfo(null);
		bulk.mutate(suggestions, {
			onSuccess: (res) => onInfo(bulkResultInfo(res)),
			onError: (err) => onError(errMessage(err)),
		});
	};

	return (
		<button
			type="button"
			className="btn btn-sm btn-primary"
			disabled={bulk.isPending}
			onClick={onMissing}
			data-testid="ingress-comfort-missing"
		>
			{ti("comfort.missing", { count: suggestions.length })}
		</button>
	);
}

interface PruneProps {
	agentId: number;
	mode: AgentIngressMode;
	rules: AgentIngressRule[];
	catalog?: AgentIngressCatalog | null;
	onError: (msg: string | null) => void;
	onInfo: (msg: string | null) => void;
}

/** Subtle "switch off unused rules (n)": enabled rules without a new connection for 30 days. */
export function PruneAction({ agentId, mode, rules, catalog, onError, onInfo }: PruneProps) {
	const disable = useDisableAgentIngressRules(agentId, { prune: true });
	const prune = catalog ? pruneSelection(catalog.pruneCandidates ?? [], rules, mode) : [];

	if (!prune.length) return null;

	const onPrune = () => {
		if (disable.isPending) return;
		const names = prune.map((c) => `• ${c.name}`).join("\n");
		if (
			!window.confirm(
				`${ti("comfort.prune-confirm", { count: prune.length })}\n\n${names}\n\n${ti("comfort.prune-hint")}`,
			)
		)
			return;
		onError(null);
		onInfo(null);
		disable.mutate(
			prune.map((c) => c.id),
			{
				onSuccess: (res) => onInfo(ti("comfort.prune-done", { count: res?.disabled?.length ?? prune.length })),
				onError: (err) => onError(errMessage(err)),
			},
		);
	};

	return (
		<button
			type="button"
			className="btn btn-sm btn-ghost-secondary"
			disabled={disable.isPending}
			onClick={onPrune}
			title={ti("comfort.prune-hint")}
			data-testid="ingress-comfort-prune"
		>
			{ti("comfort.prune", { count: prune.length })}
		</button>
	);
}
