import { IconChevronDown, IconChevronRight } from "@tabler/icons-react";
import { useState } from "react";
import type { AgentIngressCatalog, AgentIngressTestResult } from "src/api/backend";
import { useTestAgentIngress } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { expandEntries, labelForCidr } from "./catalog";
import { CatalogPicker } from "./CatalogPicker";
import { splitList, ti } from "./utils";

const VARIANT: Record<AgentIngressTestResult["reason"], string> = {
	rule: "success",
	"no-rule": "danger",
	"open-mode": "info",
	"not-via-agent": "secondary",
	"same-site": "secondary",
	"link-not-found": "warning",
};

interface Props {
	agentId: number;
	catalog?: AgentIngressCatalog | null;
	/** jump to a rule row (sentence or table) */
	onFocusRule: (ruleId: number) => void;
}

/**
 * Collapsible "May X reach Y?": asks the backend what this agent's filter does
 * with one flow. The verdict is about the FloppyGuard filter only, never about
 * reachability (routing, host firewalls, services are not checked).
 */
export function IngressTester({ agentId, catalog, onFocusRule }: Props) {
	const [open, setOpen] = useState(false);
	const [source, setSource] = useState("");
	const [destination, setDestination] = useState("");
	const [port, setPort] = useState("");
	const [proto, setProto] = useState<"tcp" | "udp">("tcp");
	const [tested, setTested] = useState<{ src: string; dst: string; port: string; proto: string } | null>(null);
	const test = useTestAgentIngress(agentId);
	const idp = `ingress-${agentId}-tester`;

	const src = splitList(source)[0] ?? "";
	const dst = splitList(destination)[0] ?? "";
	const portNum = port.trim() ? Number(port) : null;
	const portValid = portNum === null || (Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535);
	const canRun = !!src && !!dst && portValid && !test.isPending;

	const run = () => {
		if (!canRun) return;
		setTested({ src, dst, port: port.trim(), proto });
		test.mutate({ source: src, destination: dst, port: portNum, proto });
	};

	const result = test.data;
	const ruleButton = (r: { id: number; name: string }) => (
		<button
			type="button"
			className="btn btn-link p-0 align-baseline fw-medium"
			onClick={() => onFocusRule(r.id)}
			aria-label={ti("tester.go-to-rule", { name: r.name })}
		>
			{r.name}
		</button>
	);

	return (
		<div className="mb-3">
			<button
				type="button"
				className="btn btn-sm btn-link p-0 small text-uppercase text-secondary fw-medium d-inline-flex align-items-center"
				aria-expanded={open}
				aria-controls={`${idp}-body`}
				onClick={() => setOpen((o) => !o)}
			>
				{open ? (
					<IconChevronDown size={14} className="me-1" aria-hidden />
				) : (
					<IconChevronRight size={14} className="me-1" aria-hidden />
				)}
				{ti("tester.title")}
			</button>
			{open && (
				<div id={`${idp}-body`} className="mt-2">
					<div className="row g-2 align-items-end">
						<div className="col-12 col-md">
							<label className="form-label mb-1 small" htmlFor={`${idp}-source`}>
								{ti("tester.source")}
							</label>
							<CatalogPicker
								id={`${idp}-source`}
								value={source}
								onChange={setSource}
								entries={expandEntries(catalog?.sources ?? [], catalog)}
								catalog={catalog}
								multi={false}
								placeholder={ti("picker.placeholder.sources")}
							/>
						</div>
						<div className="col-12 col-md">
							<label className="form-label mb-1 small" htmlFor={`${idp}-destination`}>
								{ti("tester.destination")}
							</label>
							<CatalogPicker
								id={`${idp}-destination`}
								value={destination}
								onChange={setDestination}
								entries={expandEntries(catalog?.destinations ?? [], catalog)}
								catalog={catalog}
								multi={false}
								placeholder={ti("picker.placeholder.destinations-required")}
							/>
						</div>
						<div className="col-6 col-md-2">
							<label className="form-label mb-1 small" htmlFor={`${idp}-port`}>
								{ti("tester.port")}
							</label>
							<input
								id={`${idp}-port`}
								type="number"
								min={1}
								max={65535}
								inputMode="numeric"
								className={`form-control form-control-sm${portValid ? "" : " is-invalid"}`}
								value={port}
								onChange={(e) => setPort(e.target.value)}
							/>
						</div>
						<div className="col-6 col-md-2">
							<label className="form-label mb-1 small" htmlFor={`${idp}-proto`}>
								{ti("tester.proto")}
							</label>
							<select
								id={`${idp}-proto`}
								className="form-select form-select-sm"
								value={proto}
								onChange={(e) => setProto(e.target.value === "udp" ? "udp" : "tcp")}
							>
								<option value="tcp">tcp</option>
								<option value="udp">udp</option>
							</select>
						</div>
						<div className="col-12 col-md-auto">
							<button
								type="button"
								className="btn btn-sm btn-primary w-100"
								disabled={!canRun}
								onClick={run}
							>
								{ti("tester.run")}
							</button>
						</div>
					</div>

					{test.error && <div className="small text-danger mt-2">{test.error.message}</div>}

					{result && tested && result.linkFound === false && result.reason !== "link-not-found" && (
						<div className="alert alert-warning py-2 px-3 small mt-2 mb-0" data-testid="ingress-tester-no-link">
							{ti("tester.reason.link-not-found")}
						</div>
					)}

					{result && tested && (
						<div
							className={`alert alert-${VARIANT[result.reason] ?? "secondary"} py-2 px-3 small mt-2 mb-0`}
							data-testid="ingress-tester-result"
							role="status"
						>
							<div className="fw-medium">
								{result.reason === "rule" && result.rule ? (
									intl.formatMessage(
										{ id: "wireguard.agent.ingress.tester.reason.rule" },
										{ name: ruleButton(result.rule) },
									)
								) : (
									ti(`tester.reason.${result.reason}`)
								)}
							</div>
							{result.reason === "open-mode" && result.rule && (
								<div className="small">
									{intl.formatMessage(
										{ id: "wireguard.agent.ingress.tester.observing-rule" },
										{ name: ruleButton(result.rule) },
									)}
								</div>
							)}
							<div className="small text-secondary mt-1">
								{ti("tester.tested-address", {
									src: labelForCidr(tested.src, catalog),
									dst: labelForCidr(tested.dst, catalog),
									port: tested.port ? `:${tested.port}` : "",
									proto: tested.proto,
								})}
							</div>
							{result.disabledMatch && (
								<div className="small text-secondary">
									{ti("tester.disabled-match", { name: result.disabledMatch.name })}
								</div>
							)}
							{result.portUnknown && (
								<div className="small text-secondary">{ti("tester.port-unknown")}</div>
							)}
							{result.notes
								.filter((n) => ["established-return", "forward-only", "not-applied"].includes(n))
								.map((n) => (
									<div key={n} className="small text-secondary">
										{ti(`tester.note.${n}`)}
									</div>
								))}
						</div>
					)}
				</div>
			)}
		</div>
	);
}
