import { useEffect, useRef, useState } from "react";
import type { AgentIngressCatalog, AgentIngressRule, AgentIngressRuleData } from "src/api/backend";
import { useCreateAgentIngressRule, useUpdateAgentIngressRule } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { CatalogPicker } from "./CatalogPicker";
import { autoRuleName, isBroadRule, lineCount, MAX_RULE_LINES } from "./catalog";
import { PortPicker } from "./PortPicker";
import { RuleSentence } from "./RuleSentence";
import { formatPorts, parsePorts, type RuleFormValues, splitList, ti, validateRuleForm } from "./utils";

// ports null: a new rule starts with NOTHING chosen — "all ports" is an explicit
// choice, as in the wizards, never the silent default.
const EMPTY_FORM: RuleFormValues = { name: "", sources: "", destinations: "", ports: null, note: "", enabled: true };

const ruleToForm = (rule: AgentIngressRule): RuleFormValues => ({
	name: rule.name,
	sources: rule.sources.join(", "),
	destinations: rule.destinations.join(", "),
	ports: formatPorts(rule.ports),
	note: rule.note ?? "",
	enabled: rule.enabled,
});

/** Plain ports field: an emptied field means "nothing chosen", never "all ports" (that is the checkbox). */
const textPorts = (text: string): string | null => (text.trim() ? text : null);

/** Form → rule data. ports null (nothing chosen) only reaches this after validation refused it. */
const formToData = (values: RuleFormValues): AgentIngressRuleData => ({
	name: values.name.trim(),
	sources: splitList(values.sources),
	destinations: splitList(values.destinations),
	ports: values.ports === null ? [] : parsePorts(values.ports).ports,
	enabled: values.enabled,
	note: values.note.trim(),
});

/**
 * Only the fields the admin changed in the form. An edit must not resend
 * values it merely displayed: the rule may have changed meanwhile (e.g. the
 * table switch disabled it) and a full PUT would silently undo that.
 */
export const changedRuleData = (initial: RuleFormValues, values: RuleFormValues): Partial<AgentIngressRuleData> => {
	const before = formToData(initial);
	const after = formToData(values);
	const out: Partial<AgentIngressRuleData> = {};
	for (const key of Object.keys(after) as Array<keyof AgentIngressRuleData>) {
		if (JSON.stringify(after[key]) !== JSON.stringify(before[key])) {
			(out as Record<string, unknown>)[key] = after[key];
		}
	}
	return out;
};

interface Props {
	agentId: number;
	/** null = create a new rule */
	rule: AgentIngressRule | null;
	/** created: the new rule (create only) — confirmed and highlighted by the panel */
	onDone: (created?: AgentIngressRule) => void;
	/** with a catalog: name pickers and port presets; without (loading, error, old backend): plain text fields */
	catalog?: AgentIngressCatalog | null;
}

/**
 * Add/edit form for one ingress rule ("own rule", for experts — the wizards are
 * the main path). Validates client-side, shows backend errors too. A rule
 * without a typed name is named after its sentence.
 */
export function AgentIngressRuleForm({ agentId, rule, onDone, catalog }: Props) {
	const [initial] = useState<RuleFormValues>(() => (rule ? ruleToForm(rule) : EMPTY_FORM));
	const [values, setValues] = useState<RuleFormValues>(initial);
	const [errors, setErrors] = useState<string[]>([]);
	const createRule = useCreateAgentIngressRule(agentId);
	const updateRule = useUpdateAgentIngressRule(agentId);
	const pending = createRule.isPending || updateRule.isPending;
	const serverError = createRule.error ?? updateRule.error;
	const idPrefix = `ingress-${agentId}-rule-${rule?.id ?? "new"}`;
	const titleRef = useRef<HTMLDivElement>(null);

	// The button that opened the form is gone now: move focus into the form
	useEffect(() => {
		titleRef.current?.focus();
	}, []);

	const set = <K extends keyof RuleFormValues>(key: K, value: RuleFormValues[K]) =>
		setValues((v) => ({ ...v, [key]: value }));

	const draft = formToData(values);
	const derivedName = autoRuleName(draft, catalog);
	const lines = lineCount(draft);
	const tooMany = lines > MAX_RULE_LINES;
	const portsChosen = values.ports !== null;

	const withName = (v: RuleFormValues): RuleFormValues => (v.name.trim() ? v : { ...v, name: derivedName });

	const onSubmit = () => {
		const found = validateRuleForm(values, { autoName: derivedName !== "" });
		if (tooMany) found.push(ti("wizard.too-many", { max: MAX_RULE_LINES }));
		setErrors(found);
		if (found.length) return;
		const final = withName(values);
		if (rule) {
			const data = changedRuleData(initial, final);
			if (Object.keys(data).length === 0) {
				onDone();
				return;
			}
			updateRule.mutate({ ruleId: rule.id, data }, { onSuccess: () => onDone() });
		} else {
			createRule.mutate(formToData(final), { onSuccess: (created) => onDone(created) });
		}
	};

	return (
		<div className="card card-sm mb-3">
			<div className="card-body">
				<div className="fw-medium mb-2" ref={titleRef} tabIndex={-1} data-testid="ingress-form-title">
					{rule ? ti("form.edit-title") : ti("form.add-title")}
				</div>
				<div className="row g-2">
					<div className="col-md-6">
						<label className="form-label mb-1 small" htmlFor={`${idPrefix}-name`}>
							{ti("field.name")}
						</label>
						<input
							id={`${idPrefix}-name`}
							type="text"
							className="form-control form-control-sm"
							value={values.name}
							maxLength={100}
							placeholder={derivedName || undefined}
							aria-describedby={`${idPrefix}-name-hint`}
							onChange={(e) => set("name", e.target.value)}
						/>
						<div id={`${idPrefix}-name-hint`} className="form-text small">
							{ti("field.name-auto-hint")}
						</div>
					</div>
					<div className="col-md-6">
						<label className="form-label mb-1 small" htmlFor={`${idPrefix}-note`}>
							{ti("field.note")}
						</label>
						<input
							id={`${idPrefix}-note`}
							type="text"
							className="form-control form-control-sm"
							value={values.note}
							onChange={(e) => set("note", e.target.value)}
						/>
					</div>
					<div className="col-md-6">
						<label className="form-label mb-1 small" htmlFor={`${idPrefix}-sources`}>
							{ti("field.sources")}
						</label>
						{catalog ? (
							<CatalogPicker
								id={`${idPrefix}-sources`}
								value={values.sources}
								onChange={(v) => set("sources", v)}
								entries={catalog.sources}
								catalog={catalog}
								placeholder={ti("picker.placeholder.sources")}
							/>
						) : (
							<textarea
								id={`${idPrefix}-sources`}
								className="form-control form-control-sm font-monospace"
								rows={2}
								value={values.sources}
								placeholder="10.10.0.1, 192.168.20.0/24"
								onChange={(e) => set("sources", e.target.value)}
							/>
						)}
						<div className="form-text small">{ti("field.sources-hint")}</div>
					</div>
					<div className="col-md-6">
						<label className="form-label mb-1 small" htmlFor={`${idPrefix}-destinations`}>
							{ti("field.destinations")}
						</label>
						{catalog ? (
							<CatalogPicker
								id={`${idPrefix}-destinations`}
								value={values.destinations}
								onChange={(v) => set("destinations", v)}
								entries={catalog.destinations}
								catalog={catalog}
								placeholder={ti("picker.placeholder.destinations")}
							/>
						) : (
							<textarea
								id={`${idPrefix}-destinations`}
								className="form-control form-control-sm font-monospace"
								rows={2}
								value={values.destinations}
								placeholder="192.168.10.7"
								onChange={(e) => set("destinations", e.target.value)}
							/>
						)}
						<div className="form-text small">{ti("field.destinations-hint")}</div>
					</div>
					<div className="col-md-8">
						<label
							className="form-label mb-1 small"
							htmlFor={`${idPrefix}-ports`}
							id={`${idPrefix}-ports-label`}
						>
							{ti("field.ports")}
						</label>
						{catalog ? (
							<PortPicker
								id={`${idPrefix}-ports`}
								value={values.ports}
								onChange={(v) => set("ports", v)}
								presets={catalog.portPresets}
								labelledBy={`${idPrefix}-ports-label`}
							/>
						) : (
							<>
								<input
									id={`${idPrefix}-ports`}
									type="text"
									className="form-control form-control-sm font-monospace"
									value={values.ports ?? ""}
									placeholder="tcp/443, udp/53, tcp/8000:8010"
									disabled={values.ports === ""}
									onChange={(e) => set("ports", textPorts(e.target.value))}
								/>
								<div className="form-check mt-1 mb-0">
									<input
										id={`${idPrefix}-ports-all`}
										type="checkbox"
										className="form-check-input"
										checked={values.ports === ""}
										onChange={(e) => set("ports", e.target.checked ? "" : null)}
									/>
									<label className="form-check-label small" htmlFor={`${idPrefix}-ports-all`}>
										{ti("preset.all")}
									</label>
								</div>
								<div className="form-text small">{ti("field.ports-hint")}</div>
							</>
						)}
					</div>
					<div className="col-md-4 d-flex align-items-center">
						<div className="form-check form-switch mt-md-3">
							<input
								id={`${idPrefix}-enabled`}
								className="form-check-input"
								type="checkbox"
								role="switch"
								aria-checked={values.enabled}
								checked={values.enabled}
								onChange={(e) => set("enabled", e.target.checked)}
							/>
							<label className="form-check-label small" htmlFor={`${idPrefix}-enabled`}>
								{ti("field.enabled")}
							</label>
						</div>
					</div>
				</div>
				{draft.sources.length > 0 && portsChosen && (
					<div className="small mt-2 d-flex flex-wrap gap-2" data-testid="ingress-form-preview">
						<RuleSentence rule={draft} catalog={catalog} withSource />
						<span className={tooMany ? "text-danger" : "text-secondary"}>
							{ti("wizard.lines", { count: lines })}
						</span>
					</div>
				)}
				{draft.sources.length > 0 && portsChosen && isBroadRule(draft) && (
					<div className="alert d-block alert-warning py-2 px-3 small mt-2 mb-0" data-testid="ingress-form-broad">
						{ti("form.broad")}
					</div>
				)}
				{errors.length > 0 && (
					<ul className="small text-danger mt-2 mb-0 ps-3" role="alert">
						{errors.map((e) => (
							<li key={e}>{e}</li>
						))}
					</ul>
				)}
				{serverError && <div className="small text-danger mt-2">{serverError.message}</div>}
				<div className="d-flex gap-2 mt-3">
					<button
						type="button"
						className="btn btn-sm btn-primary"
						disabled={pending || tooMany}
						onClick={onSubmit}
					>
						{intl.formatMessage({ id: "save" })}
					</button>
					<button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => onDone()}>
						{intl.formatMessage({ id: "cancel" })}
					</button>
				</div>
			</div>
		</div>
	);
}
