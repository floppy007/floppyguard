import EasyModal, { type InnerModalProps } from "ez-modal-react";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { AgentIngressPanel, ti } from "src/components/AgentIngress";
import { intl } from "src/locale/IntlProvider";

/** Route of the Freigaben page (the modal lives outside the router, so it links with a plain href). */
export const AGENT_INGRESS_PAGE = "/ingress";

interface DialogProps {
	agentId: number;
	agentName: string;
	visible: boolean;
	onClose: () => void;
}

/** The dialog itself, exported separately so it can be rendered without the EasyModal provider (tests). */
export function AgentIngressDialog({ agentId, agentName, visible, onClose }: DialogProps) {
	return (
		<Modal show={visible} onHide={onClose} size="xl">
			<Modal.Header closeButton>
				<Modal.Title>{ti("modal-title", { name: agentName })}</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<p className="text-secondary small">{ti("explain")}</p>
				<AgentIngressPanel agentId={agentId} />
			</Modal.Body>
			<Modal.Footer>
				<a href={AGENT_INGRESS_PAGE} className="btn btn-link me-auto px-0">
					{ti("open-page")} ↗
				</a>
				<Button type="button" actionType="primary" onClick={onClose}>
					{intl.formatMessage({ id: "action.close" })}
				</Button>
			</Modal.Footer>
		</Modal>
	);
}

interface Props extends InnerModalProps {
	agentId: number;
	agentName: string;
}

const AgentIngressModal = EasyModal.create(({ agentId, agentName, visible, remove }: Props) => (
	<AgentIngressDialog agentId={agentId} agentName={agentName} visible={visible} onClose={remove} />
));

const showAgentIngressModal = (agentId: number, agentName: string) => {
	EasyModal.show(AgentIngressModal, { agentId, agentName });
};

export { showAgentIngressModal };
