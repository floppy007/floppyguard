import { useState } from "react";
import type { AgentIngressCatalog } from "src/api/backend";
import { ruleForSiteAccess, selectionToPorts, targetsFromValue } from "../catalog";
import { CatalogPicker } from "../CatalogPicker";
import { PortPicker } from "../PortPicker";
import { parsePorts, ti } from "../utils";
import { previewSavable, RulePreviewList } from "./RulePreviewList";
import { siteSourceEntries } from "./siteSources";
import { useWizardSave } from "./useWizardSave";
import { WizardShell } from "./WizardShell";

interface Props {
	agentId: number;
	catalog: AgentIngressCatalog;
	onDone: (info?: string, ruleId?: number | null) => void;
}

/** "A site may access servers": site → chosen destinations on chosen ports (nothing preselected). */
export function SiteAccessWizard({ agentId, catalog, onDone }: Props) {
	const [step, setStep] = useState(0);
	const [source, setSource] = useState("");
	const [targets, setTargets] = useState("");
	// null = no port choice yet: "all ports" must be picked explicitly
	const [ports, setPorts] = useState<string | null>(null);
	const { save, pending, error } = useWizardSave(agentId, onDone);
	const idp = `ingress-${agentId}-wizard-site`;

	const sources = siteSourceEntries(catalog);
	const site = targetsFromValue(source, sources, catalog);
	const dests = targetsFromValue(targets, catalog.destinations, catalog);
	const portList = ports === null ? null : selectionToPorts([], ports, []);
	const invalidPorts = ports === null ? [] : parsePorts(ports).invalid;
	const siteTarget =
		site.length > 0 ? { label: site.map((s) => s.label).join(", "), cidrs: site.flatMap((s) => s.cidrs) } : null;
	const rules = siteTarget && dests.length && portList ? [ruleForSiteAccess(siteTarget, dests, portList)] : [];

	const canNext = [siteTarget !== null, dests.length > 0, ports !== null && invalidPorts.length === 0][step] ?? false;

	return (
		<WizardShell
			agentId={agentId}
			wizard="site"
			title={ti("wizard.site.title")}
			steps={[
				ti("wizard.site.step.source"),
				ti("wizard.site.step.targets"),
				ti("wizard.site.step.ports"),
				ti("wizard.site.step.preview"),
			]}
			step={step}
			onStep={setStep}
			canNext={canNext}
			canSave={previewSavable(rules)}
			pending={pending}
			errors={[
				...invalidPorts.map((v) =>
					ti("err.invalid-port", {
						value: v,
					}),
				),
				...(error ? [error] : []),
			]}
			onSave={() => save(rules)}
			onCancel={() => onDone()}
		>
			{step === 0 && (
				<div>
					<label className="form-label mb-1 small" htmlFor={`${idp}-source`}>
						{ti("wizard.site.step.source")}
					</label>
					<CatalogPicker
						id={`${idp}-source`}
						value={source}
						onChange={setSource}
						entries={sources}
						catalog={catalog}
						multi={false}
						placeholder={ti("picker.placeholder.sources")}
					/>
				</div>
			)}
			{step === 1 && (
				<div>
					<label className="form-label mb-1 small" htmlFor={`${idp}-targets`}>
						{ti("wizard.site.step.targets")}
					</label>
					<CatalogPicker
						id={`${idp}-targets`}
						value={targets}
						onChange={setTargets}
						entries={catalog.destinations}
						catalog={catalog}
						placeholder={ti("picker.placeholder.destinations-required")}
					/>
				</div>
			)}
			{step === 2 && (
				<div>
					<div className="form-label mb-1 small" id={`${idp}-ports-label`}>
						{ti("wizard.site.step.ports")}
					</div>
					<PortPicker
						id={`${idp}-ports`}
						value={ports}
						onChange={setPorts}
						presets={catalog.portPresets}
						labelledBy={`${idp}-ports-label`}
					/>
				</div>
			)}
			{step === 3 && <RulePreviewList rules={rules} catalog={catalog} />}
		</WizardShell>
	);
}
