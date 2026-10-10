import { type ReactNode, useEffect, useRef } from "react";
import { intl } from "src/locale/IntlProvider";
import { ti } from "../utils";

interface Props {
	agentId: number;
	/** wizard id, for DOM ids ("proxy", "site", "full") */
	wizard: string;
	title: string;
	steps: string[];
	/** 0-based current step; the last step is the preview */
	step: number;
	onStep: (step: number) => void;
	/** whether "Next" may leave the current step */
	canNext: boolean;
	/** whether "Save" is allowed on the last step */
	canSave: boolean;
	pending: boolean;
	errors: string[];
	info?: string | null;
	onSave: () => void;
	onCancel: () => void;
	children: ReactNode;
}

/**
 * Inline wizard card (the panel may already sit inside a modal, so no nested
 * modal): step indicator, Back / Next / Save, error area for client and server
 * errors. Focus: the title on open (the menu item that opened it is gone), the
 * step content whenever the step changes (Next/Back swap the content).
 */
export function WizardShell({
	agentId,
	wizard,
	title,
	steps,
	step,
	onStep,
	canNext,
	canSave,
	pending,
	errors,
	info,
	onSave,
	onCancel,
	children,
}: Props) {
	const last = step === steps.length - 1;
	const titleId = `ingress-${agentId}-wizard-${wizard}-title`;
	const stepId = `ingress-${agentId}-wizard-${wizard}-step`;
	const titleRef = useRef<HTMLDivElement>(null);
	const stepRef = useRef<HTMLDivElement>(null);
	const shownStep = useRef(step);

	useEffect(() => {
		titleRef.current?.focus();
	}, []);

	useEffect(() => {
		if (shownStep.current === step) return;
		shownStep.current = step;
		stepRef.current?.focus();
	}, [step]);

	return (
		<section className="card card-sm mb-3" aria-labelledby={titleId} data-testid={`ingress-wizard-${wizard}`}>
			<div className="card-body">
				<div className="fw-medium mb-2" id={titleId} ref={titleRef} tabIndex={-1}>
					{title}
				</div>
				<ol className="steps steps-counter steps-blue my-3 small">
					{steps.map((s, i) => (
						<li
							key={s}
							className={`step-item${i === step ? " active" : ""}`}
							aria-current={i === step ? "step" : undefined}
						>
							{s}
						</li>
					))}
				</ol>
				<div
					ref={stepRef}
					tabIndex={-1}
					id={stepId}
					data-testid="ingress-wizard-step"
				>
					{children}
				</div>
				{errors.length > 0 && (
					<ul className="small text-danger mt-2 mb-0 ps-3" role="alert">
						{errors.map((e) => (
							<li key={e}>{e}</li>
						))}
					</ul>
				)}
				{info && <div className="small text-info mt-2">{info}</div>}
				<div className="d-flex flex-wrap gap-2 mt-3">
					{step > 0 && (
						<button
							type="button"
							className="btn btn-sm btn-outline-secondary"
							disabled={pending}
							onClick={() => onStep(step - 1)}
						>
							{ti("wizard.back")}
						</button>
					)}
					{last ? (
						<button
							type="button"
							className="btn btn-sm btn-primary"
							disabled={pending || !canSave}
							onClick={onSave}
						>
							{intl.formatMessage({ id: "save" })}
						</button>
					) : (
						<button
							type="button"
							className="btn btn-sm btn-primary"
							disabled={!canNext}
							onClick={() => onStep(step + 1)}
						>
							{ti("wizard.next")}
						</button>
					)}
					<button type="button" className="btn btn-sm btn-outline-secondary ms-auto" onClick={onCancel}>
						{intl.formatMessage({ id: "cancel" })}
					</button>
				</div>
			</div>
		</section>
	);
}
