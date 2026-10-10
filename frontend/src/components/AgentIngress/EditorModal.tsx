import type { ReactNode } from "react";
import Modal from "react-bootstrap/Modal";

interface Props {
	show: boolean;
	/** id of the title inside (form / wizard header), names the dialog */
	labelledBy?: string;
	/** Esc, backdrop, the header's ✕ — close without saving */
	onHide: () => void;
	/** after the fade-out: the panel drops the content and moves the focus back */
	onExited: () => void;
	children: ReactNode;
}

/**
 * Dialog around the rule form and the wizards (they render header, body and
 * footer themselves, as the other dialogs of the app do). The Freigaben panel
 * renders it, also inside the agent dialog: there it stacks above that dialog
 * (classes ingress-editor-modal / -backdrop lift it), and react-bootstrap only
 * lets the top dialog react to Esc and hold the focus. The panel moves the
 * focus itself (title on open, rule / "Neue Freigabe" on close), hence no
 * restoreFocus.
 */
export function IngressEditorModal({ show, labelledBy, onHide, onExited, children }: Props) {
	const focusTitle = () => {
		if (labelledBy) document.getElementById(labelledBy)?.focus();
	};
	return (
		<Modal
			show={show}
			onHide={onHide}
			onEntered={focusTitle}
			onExited={onExited}
			size="lg"
			scrollable
			fullscreen="sm-down"
			restoreFocus={false}
			className="ingress-editor-modal"
			backdropClassName="ingress-editor-backdrop"
			aria-labelledby={labelledBy}
		>
			{children}
		</Modal>
	);
}
