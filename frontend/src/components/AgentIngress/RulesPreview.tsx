import { useState } from "react";
import { useAgentIngressPreview } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { ti } from "./utils";

/** Collapsible "Erzeugte Regeln": the iptables-restore text the agent receives. Fetched on first expand. */
export function AgentIngressRulesPreview({ agentId }: { agentId: number }) {
	const [open, setOpen] = useState(false);
	const preview = useAgentIngressPreview(agentId, { enabled: open });

	return (
		<div>
			<button
				type="button"
				className="btn btn-sm btn-link p-0 small text-uppercase text-secondary fw-medium"
				aria-expanded={open}
				onClick={() => setOpen((o) => !o)}
			>
				{open ? "▾" : "▸"} {ti("preview")}
				{open && preview.data ? ` (${ti("preview.count", { count: preview.data.ruleCount })})` : ""}
			</button>
			{open && (
				<div className="mt-2">
					{preview.isLoading && (
						<div className="text-secondary small">{intl.formatMessage({ id: "loading" })}</div>
					)}
					{preview.error && <div className="text-danger small">{preview.error.message}</div>}
					{preview.data &&
						(preview.data.rulesText ? (
							<pre className="small mb-0 p-2 border rounded" style={{ maxHeight: 320, overflow: "auto" }}>
								{preview.data.rulesText}
							</pre>
						) : (
							<div className="text-secondary small">{ti("preview.empty")}</div>
						))}
				</div>
			)}
		</div>
	);
}
