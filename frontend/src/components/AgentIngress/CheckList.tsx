import { IconAlertTriangle } from "@tabler/icons-react";
import type { ReactNode } from "react";
import type { AgentIngressCheck, AgentIngressMode } from "src/api/backend";
import { useCreateAgentIngressRule } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { errMessage, ti } from "./utils";

interface Props {
	agentId: number;
	mode: AgentIngressMode;
	check: AgentIngressCheck | undefined;
	isLoading: boolean;
	error: Error | null;
	onError: (msg: string | null) => void;
	/** bulk action shown next to the heading ("release all missing proxy targets") */
	actions?: ReactNode;
}

/**
 * Proxy cross-check (tab Prüfen): proxy hosts / streams whose upstream this agent would drop
 * (prominent while restricted) and hub-sourced rules no upstream uses.
 */
export function AgentIngressCheckList({ agentId, mode, check, isLoading, error, onError, actions }: Props) {
	const createRule = useCreateAgentIngressRule(agentId);
	const restricted = mode === "restricted";

	let body: ReactNode;
	if (isLoading) {
		body = <div className="text-secondary small">{intl.formatMessage({ id: "loading" })}</div>;
	} else if (error) {
		body = <div className="text-danger small">{error.message}</div>;
	} else if (!check) {
		body = <div className="text-secondary small">{ti("check.none")}</div>;
	} else if (check.linkFound === false) {
		body = (
			<div className="alert d-block alert-warning py-2 px-3 small mb-0" data-testid="ingress-link-missing">
				{check.linkHint === "typed-client"
					? ti("check.link-client", { link: check.linkHintName ?? check.wgLinkName ?? "" })
					: ti("check.link-missing", { link: check.wgLinkName ?? "" })}
			</div>
		);
	} else if (
		check.missing.length === 0 &&
		check.unusedHubRules.length === 0 &&
		!check.broadHubRules?.length &&
		!check.missingDisabled?.length &&
		!check.unchecked?.length
	) {
		body = <div className="text-success small">{ti("check.ok")}</div>;
	} else {
		body = (
			<>
				{check.missing.length > 0 && (
					<div className={`alert d-block ${restricted ? "alert-danger" : "alert-info"} py-2 px-3 small mb-2`}>
						<div className="fw-medium mb-2">
							{restricted ? ti("check.missing-restricted") : ti("check.missing-open")}
						</div>
						{check.missing.map((m) => (
							<div
								key={`${m.kind}-${m.id}-${m.proto}-${m.host}-${m.port ?? ""}-${m.label}`}
								className="d-flex align-items-center gap-2 flex-wrap mb-1"
							>
								<span className="badge bg-secondary-lt">{ti(`check.kind.${m.kind}`)}</span>
								<span className="fw-medium">{m.label}</span>
								<span className="font-monospace">
									→ {m.host}
									{m.port ? `:${m.port}` : ""}
									{m.kind === "vpn-client" ? "" : `/${m.proto}`}
								</span>
								{m.suggestion ? (
									<button
										type="button"
										className="btn btn-sm btn-outline-primary py-0 px-2 ms-auto"
										disabled={createRule.isPending}
										onClick={() => {
											const suggestion = m.suggestion;
											if (!suggestion) return;
											onError(null);
											createRule.mutate(
												{ ...suggestion, enabled: true },
												{ onError: (err) => onError(errMessage(err)) },
											);
										}}
									>
										{ti("check.create")}
									</button>
								) : (
									<span className="ms-auto text-secondary" data-testid="ingress-no-port">
										{ti("check.no-port")}
									</span>
								)}
							</div>
						))}
					</div>
				)}
				{(check.unchecked?.length ?? 0) > 0 && (
					<div className="alert d-block alert-warning py-2 px-3 small mb-2">
						<div className="fw-medium mb-1">{ti("check.unchecked")}</div>
						{check.unchecked?.map((u) => (
							<div
								key={`${u.kind}-${u.id}-${u.proto}-${u.host}-${u.port ?? ""}-${u.label}`}
								className="d-flex gap-2 flex-wrap"
							>
								<span className="badge bg-secondary-lt">{ti(`check.kind.${u.kind}`)}</span>
								<span className="fw-medium">{u.label}</span>
								<span className="font-monospace">
									→ {u.host}
									{u.port ? `:${u.port}` : ""}/{u.proto}
								</span>
							</div>
						))}
					</div>
				)}
				{(check.missingDisabled?.length ?? 0) > 0 && (
					<div className="small text-secondary mb-2">
						<div className="mb-1">{ti("check.missing-disabled")}</div>
						{check.missingDisabled?.map((m) => (
							<div
								key={`${m.kind}-${m.id}-${m.proto}-${m.host}-${m.port ?? ""}-${m.label}`}
								className="d-flex gap-2 flex-wrap"
							>
								<span className="badge bg-secondary-lt">{ti(`check.kind.${m.kind}`)}</span>
								<span>{m.label}</span>
								<span className="font-monospace">
									→ {m.host}
									{m.port ? `:${m.port}` : ""}/{m.proto}
								</span>
								<span>({ti("check.disabled")})</span>
							</div>
						))}
					</div>
				)}
				{(check.broadHubRules?.length ?? 0) > 0 && (
					<div
						className="alert d-block alert-warning py-2 px-3 small mb-2"
						data-testid="ingress-broad-hub-rules"
					>
						<div className="fw-medium mb-1">{ti("check.broad")}</div>
						{check.broadHubRules?.map((r) => (
							<div key={r.id} className="d-flex gap-2 flex-wrap">
								<span className="fw-medium">{r.name}</span>
								<span>
									{r.reason === "all-ports"
										? ti("check.broad.all-ports")
										: ti("check.broad.unused-ports", { ports: r.ports.join(", ") })}
								</span>
							</div>
						))}
					</div>
				)}
				{check.unusedHubRules.length > 0 && (
					<div className="small text-secondary">
						{check.unusedHubRules.map((r) => (
							<div key={r.id} className="mb-1">
								<IconAlertTriangle size={14} className="me-1 text-warning" />
								<span className="fw-medium">{r.name}</span>:{" "}
								<span className="font-monospace">{r.unused.join(", ")}</span> — {ti("check.unused")}
							</div>
						))}
					</div>
				)}
			</>
		);
	}

	return (
		<section aria-labelledby={`ingress-${agentId}-check-title`} data-testid="ingress-check">
			<div className="d-flex flex-wrap align-items-start gap-2 mb-3">
				<div className="me-auto">
					<h3 className="h4 mb-1" id={`ingress-${agentId}-check-title`}>
						{ti("check.title")}
					</h3>
					<p className="text-secondary small mb-0">{ti("check.lead")}</p>
				</div>
				{actions}
			</div>
			{body}
		</section>
	);
}
