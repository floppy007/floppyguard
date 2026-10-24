import { useState } from "react";
import type { AgentIngressCatalog } from "src/api/backend";
import { ruleForSiteFull, targetsFromValue } from "../catalog";
import { CatalogPicker } from "../CatalogPicker";
import { ti } from "../utils";
import { previewSavable, RulePreviewList } from "./RulePreviewList";
import { siteSourceEntries } from "./siteSources";
import { useWizardSave } from "./useWizardSave";
import { WizardShell } from "./WizardShell";

interface Props {
	agentId: number;
	catalog: AgentIngressCatalog;
	onDone: (info?: string, ruleId?: number | null) => void;
}

/** "A site gets full access": the whole site LAN on every port, after an explicit acknowledgement. */
export function SiteFullAccessWizard({ agentId, catalog, onDone }: Props) {
	const [step, setStep] = useState(0);
	const [source, setSource] = useState("");
	const [ack, setAck] = useState(false);
	const { save, pending, error } = useWizardSave(agentId, onDone);
	const idp = `ingress-${agentId}-wizard-full`;

	const sources = siteSourceEntries(catalog);
	const site = targetsFromValue(source, sources, catalog);
	const rules = site.length
		? [ruleForSiteFull({ label: site.map((s) => s.label).join(", "), cidrs: site.flatMap((s) => s.cidrs) })]
		: [];

	return (
		<WizardShell
			agentId={agentId}
			wizard="full"
			title={ti("wizard.full.title")}
			steps={[ti("wizard.full.step.source"), ti("wizard.full.step.preview")]}
			step={step}
			onStep={setStep}
			canNext={rules.length > 0}
			canSave={ack && previewSavable(rules)}
			pending={pending}
			errors={error ? [error] : []}
			onSave={() => save(rules)}
			onCancel={() => onDone()}
		>
			{step === 0 && (
				<div>
					<label className="form-label mb-1 small" htmlFor={`${idp}-source`}>
						{ti("wizard.full.step.source")}
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
				<>
					<div
						className="alert d-block alert-warning py-2 px-3 small"
						data-testid="ingress-wizard-full-warning"
					>
						{ti("wizard.full.warning", { site: catalog.site?.name ?? catalog.agentName ?? "" })}
					</div>
					<RulePreviewList rules={rules} catalog={catalog} />
					<div className="form-check mt-2 small">
						<input
							id={`${idp}-ack`}
							type="checkbox"
							className="form-check-input"
							checked={ack}
							onChange={(e) => setAck(e.target.checked)}
						/>
						<label className="form-check-label" htmlFor={`${idp}-ack`}>
							{ti("wizard.full.ack")}
						</label>
					</div>
				</>
			)}
		</WizardShell>
	);
}
