import { useQueryClient } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { renewCertificate } from "src/api/backend";
import { Button } from "src/components";
import { T } from "src/locale";
import { showObjectSuccess } from "src/notifications";

interface Props extends InnerModalProps {
	id: number;
}

const showRenewCertificateModal = (id: number) => {
	EasyModal.show(RenewCertificateModal, { id });
};

const RenewCertificateModal = EasyModal.create(({ id, visible, remove }: Props) => {
	const queryClient = useQueryClient();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [isSubmitting, setIsSubmitting] = useState(false);
	// Ref, not state, as the guard: under StrictMode the mount effect runs twice with
	// the same closure and would otherwise POST /renew twice.
	const startedRef = useRef(false);

	useEffect(() => {
		if (startedRef.current) return;
		startedRef.current = true;
		setIsSubmitting(true);

		renewCertificate(id)
			.then(() => {
				showObjectSuccess("certificate", "renewed");
				queryClient.invalidateQueries({ queryKey: ["certificates"] });
				remove();
			})
			.catch((err: any) => {
				setErrorMsg(<T id={err.message} />);
			})
			.finally(() => {
				setIsSubmitting(false);
			});
	}, [id, remove, queryClient]);

	return (
		<Modal show={visible} onHide={isSubmitting ? undefined : remove}>
			<Modal.Header closeButton={!isSubmitting}>
				<Modal.Title>
					<T id="certificate.renew" />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<Alert variant="danger" show={!!errorMsg}>
					{errorMsg}
				</Alert>
				{isSubmitting && !errorMsg ? <p className="text-center mt-3">Please wait ...</p> : null}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={isSubmitting}>
					<T id="action.close" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export { showRenewCertificateModal };
