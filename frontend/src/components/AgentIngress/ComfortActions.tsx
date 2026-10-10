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

interface Props {
	agentId: number;
	mode: AgentIngressMode;
	rules: AgentIngressRule[];
	check: AgentIngressCheck | undefined;
	catalog?: AgentIngressCatalog | null;
	onError: (msg: string | null) => void;
	onInfo: (msg: string | null) => void;
}

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

/**
 * Toolbar comfort actions: create every missing proxy-target rule at once and
 * switch off hub rules without new connections for 30 days.
 */
export function ComfortActions({ agentId, mode, rules, check, catalog, onError, onInfo }: Props) {
	const bulk = useCreateAgentIngressRulesBulk(agentId);
	const disable = useDisableAgentIngressRules(agentId, { prune: true });
	const suggestions = missingProxySuggestions(check);
	const prune = catalog ? pruneSelection(catalog.pruneCandidates ?? [], rules, mode) : [];
	const busy = bulk.isPending || disable.isPending;

	const onMissing = () => {
		if (busy || !suggestions.length) return;
		const names = suggestions.map((s) => `• ${s.name}`).join("\n");
		if (!window.confirm(`${ti("comfort.missing-confirm", { count: suggestions.length })}\n\n${names}`)) return;
		onError(null);
		onInfo(null);
		bulk.mutate(suggestions, {
			onSuccess: (res) => onInfo(bulkResultInfo(res)),
			onError: (err) => onError(errMessage(err)),
		});
	};

	const onPrune = () => {
		if (busy || !prune.length) return;
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

	if (!suggestions.length && !prune.length) return null;

	return (
		<>
			{suggestions.length > 0 && (
				<button
					type="button"
					className="btn btn-sm btn-outline-danger"
					disabled={busy}
					onClick={onMissing}
					data-testid="ingress-comfort-missing"
				>
					{ti("comfort.missing", { count: suggestions.length })}
				</button>
			)}
			{prune.length > 0 && (
				<button
					type="button"
					className="btn btn-sm btn-outline-secondary"
					disabled={busy}
					onClick={onPrune}
					title={ti("comfort.prune-hint")}
					data-testid="ingress-comfort-prune"
				>
					{ti("comfort.prune", { count: prune.length })}
				</button>
			)}
		</>
	);
}
