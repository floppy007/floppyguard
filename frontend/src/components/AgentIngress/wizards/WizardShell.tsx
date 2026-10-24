import { type ReactNode, useEffect, useRef } from "react";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
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

/** DOM id of a wizard's title (names the dialog, gets the focus). */
export const ingressWizardTitleId = (agentId: number, wizard: string) => `ingress-${agentId}-wizard-${wizard}-title`;

/**
 * A wizard as the header, body and footer of the panel's editor dialog: step
 * indicator, error area for client and server errors, footer with Cancel and
 * Back / Next / Save. Focus: the title on open, the step content whenever the
 * step changes (Next/Back swap the content).
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
	const titleId = ingressWizardTitleId(agentId, wizard);
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
		<>
			<Modal.Header closeButton>
				<Modal.Title id={titleId} ref={titleRef} tabIndex={-1}>
					{title}
				</Modal.Title>
			</Modal.Header>
			<Modal.Body data-testid={`ingress-wizard-${wizard}`}>
				<ol className="steps steps-counter steps-blue mt-0 mb-3 small">
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
				<div ref={stepRef} tabIndex={-1} id={stepId} data-testid="ingress-wizard-step">
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
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={onCancel}>{intl.formatMessage({ id: "cancel" })}</Button>
				<div className="ms-auto d-flex flex-wrap gap-2">
					{step > 0 && (
						<Button disabled={pending} onClick={() => onStep(step - 1)}>
							{ti("wizard.back")}
						</Button>
					)}
					{last ? (
						<Button
							actionType="primary"
							isLoading={pending}
							disabled={pending || !canSave}
							onClick={onSave}
						>
							{intl.formatMessage({ id: "save" })}
						</Button>
					) : (
						<Button actionType="primary" disabled={!canNext} onClick={() => onStep(step + 1)}>
							{ti("wizard.next")}
						</Button>
					)}
				</div>
			</Modal.Footer>
		</>
	);
}
