import { useState } from "react";
import type { AgentIngressCatalog, AgentIngressCatalogEntry, AgentIngressRuleData } from "src/api/backend";
import { entryLabel, hubEntryOf, ruleForUpstream } from "../catalog";
import { KindIcon } from "../CatalogPicker";
import { formatPorts, ti } from "../utils";
import { previewSavable, RulePreviewList } from "./RulePreviewList";
import { useWizardSave } from "./useWizardSave";
import { WizardShell } from "./WizardShell";

const UPSTREAM_KINDS = new Set(["proxy-host", "stream", "manual", "hub-egress"]);

interface Props {
	agentId: number;
	catalog: AgentIngressCatalog;
	onDone: (info?: string, ruleId?: number | null) => void;
}

/** "Publish a service via the proxy": pick upstream hosts, one hub → host rule each. */
export function PublishProxyWizard({ agentId, catalog, onDone }: Props) {
	const [step, setStep] = useState(0);
	const [chosen, setChosen] = useState<string[]>([]);
	const { save, pending, error } = useWizardSave(agentId, onDone);

	const hub = hubEntryOf(catalog);
	const egress = catalog.sources.filter((e) => e.kind === "hub-egress");
	const rank = (e: AgentIngressCatalogEntry) => (e.hint === "no-port" ? 2 : !e.covered && e.enabled ? 0 : 1);
	const hosts = catalog.destinations
		.filter((e) => UPSTREAM_KINDS.has(e.kind) && e.id.startsWith("host:"))
		.sort((a, b) => rank(a) - rank(b) || entryLabel(a, catalog).localeCompare(entryLabel(b, catalog)));

	const rules = hosts
		.filter((e) => chosen.includes(e.id))
		.map((e) => ruleForUpstream(e, hub, egress))
		.filter((r): r is AgentIngressRuleData => r !== null);

	const toggle = (id: string, on: boolean) => setChosen((c) => (on ? [...c, id] : c.filter((x) => x !== id)));

	return (
		<WizardShell
			agentId={agentId}
			wizard="proxy"
			title={ti("wizard.proxy.title")}
			steps={[ti("wizard.proxy.step.hosts"), ti("wizard.proxy.step.preview")]}
			step={step}
			onStep={setStep}
			canNext={rules.length > 0}
			canSave={previewSavable(rules)}
			pending={pending}
			errors={error ? [error] : []}
			onSave={() => save(rules)}
			onCancel={() => onDone()}
		>
			{step === 0 &&
				(hosts.length === 0 ? (
					<div className="text-secondary small">{ti("wizard.proxy.none")}</div>
				) : (
					<div className="d-flex flex-column gap-1">
						{hosts.map((e) => {
							const noPort = e.hint === "no-port";
							const covered = !!e.covered;
							const inputId = `ingress-${agentId}-wizard-proxy-${e.id}`;
							// the ports the rule will open (not the services found on the host)
							const ports = e.upstreamPorts ?? e.ports ?? [];
							return (
								<div
									key={e.id}
									className={`form-check mb-0 small d-flex flex-wrap align-items-center gap-2${covered || noPort ? " text-secondary" : ""}`}
								>
									<input
										id={inputId}
										type="checkbox"
										className="form-check-input mt-0"
										checked={chosen.includes(e.id)}
										disabled={noPort}
										onChange={(ev) => toggle(e.id, ev.target.checked)}
									/>
									<label htmlFor={inputId} className="form-check-label d-flex align-items-center gap-1">
										<KindIcon kind={e.kind} />
										{entryLabel(e, catalog)}
									</label>
									{ports.length > 0 && (
										<span className="font-monospace text-secondary">{formatPorts(ports)}</span>
									)}
									{noPort ? (
										<span className="text-secondary">{ti("check.no-port")}</span>
									) : covered ? (
										<span className="badge bg-secondary-lt">{ti("wizard.covered-badge")}</span>
									) : e.enabled ? (
										<span className="badge bg-red-lt text-red">{ti("wizard.missing-badge")}</span>
									) : null}
									{(e.names?.length ?? 0) > 1 && (
										<span
											className="text-secondary text-truncate"
											style={{ maxWidth: "100%" }}
											title={e.names?.join(", ")}
										>
											{e.names?.slice(1).join(", ")}
										</span>
									)}
								</div>
							);
						})}
					</div>
				))}
			{step === 1 && <RulePreviewList rules={rules} catalog={catalog} />}
		</WizardShell>
	);
}
