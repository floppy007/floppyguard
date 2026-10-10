import type { ReactNode } from "react";
import type {
	AgentIngressApplied,
	AgentIngressCatalog,
	AgentIngressCheck,
	AgentIngressMode,
	AgentIngressRule,
} from "src/api/backend";
import { useAgentIngressPreview } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { AgentIngressRulesTable } from "./RulesTable";
import { ti } from "./utils";

interface Props {
	agentId: number;
	mode: AgentIngressMode;
	rules: AgentIngressRule[];
	applied: AgentIngressApplied | undefined;
	check: AgentIngressCheck | undefined;
	catalog?: AgentIngressCatalog | null;
	onEdit: (rule: AgentIngressRule) => void;
	onError: (msg: string | null) => void;
	/** rare destructive actions (remove the agent), last section of the tab */
	dangerZone?: ReactNode;
}

const shortHash = (hash: string | null | undefined) => (hash && hash !== "NONE" ? hash.slice(0, 12) : "–");

function InfoRow({ label, children }: { label: string; children: ReactNode }) {
	return (
		<>
			<dt className="col-sm-4 col-lg-3 fw-normal text-secondary">{label}</dt>
			<dd className="col-sm-8 col-lg-9 mb-2">{children}</dd>
		</>
	);
}

/**
 * Tab "Technik": interface and mode, the raw rule table with hit counters and
 * the iptables-restore text the agent receives (fetched when the tab opens).
 */
export function AgentIngressTechTab({
	agentId,
	mode,
	rules,
	applied,
	check,
	catalog,
	onEdit,
	onError,
	dangerZone,
}: Props) {
	const preview = useAgentIngressPreview(agentId);
	const id = (part: string) => `ingress-${agentId}-tech-${part}`;

	return (
		<div className="d-flex flex-column gap-4" data-testid="ingress-tech">
			<section aria-labelledby={id("info")}>
				<h3 className="h4 mb-3" id={id("info")}>
					{ti("tech.info")}
				</h3>
				<dl className="row mb-0 small">
					<InfoRow label={ti("tech.mode")}>
						<code>{mode}</code> – {ti(mode === "restricted" ? "badge.restricted" : "badge.open")}
					</InfoRow>
					<InfoRow label={ti("tech.iface")}>
						<code>{preview.data?.iface ?? "…"}</code>
					</InfoRow>
					{check?.wgLinkName && (
						<InfoRow label={ti("tech.link")}>
							<code>{check.wgLinkName}</code>
						</InfoRow>
					)}
					{(check?.hubSources?.length ?? 0) > 0 && (
						<InfoRow label={ti("tech.hub-sources")}>
							<code>{check?.hubSources.join(", ")}</code>
						</InfoRow>
					)}
					{check && (
						// Hub-originated traffic (e.g. Mailcow → DC) via the SNAT/tunnel address uses no
						// proxy host: the proxy check only knows it from the egress-flow list.
						<InfoRow label={ti("tech.egress")}>
							<span data-testid="ingress-egress-note">
								{ti("check.egress-note", { count: check.hubEgressFlows ?? 0 })}
							</span>
						</InfoRow>
					)}
					{applied && (
						<InfoRow label={ti("tech.applied")}>
							{ti(`applied.${applied.state}-short`)}{" "}
							<span className="text-secondary">
								({ti("tech.hashes", {
									desired: shortHash(applied.desiredHash),
									applied: shortHash(applied.appliedHash),
								})})
							</span>
							{applied.error && <div className="font-monospace text-danger">{applied.error}</div>}
						</InfoRow>
					)}
				</dl>
			</section>

			<section aria-labelledby={id("table")}>
				<h3 className="h4 mb-3" id={id("table")}>
					{ti("tech.table")}
				</h3>
				{rules.length ? (
					<AgentIngressRulesTable
						agentId={agentId}
						rules={rules}
						catalog={catalog}
						onEdit={onEdit}
						onError={onError}
					/>
				) : (
					<p className="text-secondary small mb-0">{ti("empty")}</p>
				)}
			</section>

			<section aria-labelledby={id("preview")}>
				<h3 className="h4 mb-1" id={id("preview")}>
					{ti("preview")}
					{preview.data ? ` (${ti("preview.count", { count: preview.data.ruleCount })})` : ""}
				</h3>
				<p className="text-secondary small mb-3">{ti("tech.preview-lead")}</p>
				{preview.isLoading && <div className="text-secondary small">{intl.formatMessage({ id: "loading" })}</div>}
				{preview.error && <div className="text-danger small">{preview.error.message}</div>}
				{preview.data &&
					(preview.data.rulesText ? (
						<pre
							className="small mb-0 p-2 border rounded"
							style={{ maxHeight: 320, overflow: "auto" }}
							data-testid="ingress-preview-text"
						>
							{preview.data.rulesText}
						</pre>
					) : (
						<div className="text-secondary small">{ti("preview.empty")}</div>
					))}
			</section>

			{dangerZone}
		</div>
	);
}
