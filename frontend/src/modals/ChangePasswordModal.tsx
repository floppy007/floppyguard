import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { Form, Formik } from "formik";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { updateAuth } from "src/api/backend";
import { Button, FloatingTextField } from "src/components";
import { useAuthState } from "src/context";
import { intl, T } from "src/locale";
import { validateString } from "src/modules/Validations";
import { showSuccess } from "src/notifications";

const showChangePasswordModal = (id: number | "me") => {
	EasyModal.show(ChangePasswordModal, { id });
};

interface Props extends InnerModalProps {
	id: number | "me";
}
const ChangePasswordModal = EasyModal.create(({ id, visible, remove }: Props) => {
	const [error, setError] = useState<ReactNode | null>(null);
	const [isSubmitting, setIsSubmitting] = useState(false);
	const { logout } = useAuthState();

	const onSubmit = async (values: any, { setSubmitting }: any) => {
		if (values.new !== values.confirm) {
			setError(<T id="error.passwords-must-match" />);
			setSubmitting(false);
			return;
		}

		if (isSubmitting) return;
		setIsSubmitting(true);
		setError(null);

		try {
			await updateAuth(id, values.new, values.current);
		} catch (err: any) {
			setError(<T id={err.message} />);
			setIsSubmitting(false);
			setSubmitting(false);
			return;
		}
		remove();
		if (id === "me") {
			// The backend revokes every token issued before the change, including
			// this session's: log out now with an explanation instead of letting
			// the next request 401 and reload to the login page without one.
			showSuccess(intl.formatMessage({ id: "user.password-changed-relogin" }));
			logout();
		}
	};

	return (
		<Modal show={visible} onHide={remove}>
			<Formik
				initialValues={
					{
						current: "",
						new: "",
						confirm: "",
					} as any
				}
				onSubmit={onSubmit}
			>
				{() => (
					<Form>
						<Modal.Header closeButton>
							<Modal.Title>
								<T id="user.change-password" />
							</Modal.Title>
						</Modal.Header>
						<Modal.Body>
							<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible>
								{error}
							</Alert>
							<div className="mb-3">
								<FloatingTextField
									name="current"
									labelId="user.current-password"
									type="password"
									autoComplete="current-password"
									required
								/>
							</div>
							<div className="mb-3">
								<FloatingTextField
									name="new"
									labelId="user.new-password"
									type="password"
									autoComplete="new-password"
									required
									validate={validateString(8, 100)}
								/>
							</div>
							<div className="mb-3">
								<FloatingTextField
									name="confirm"
									labelId="user.confirm-password"
									type="password"
									autoComplete="new-password"
									required
									validate={validateString(8, 100)}
								/>
							</div>
						</Modal.Body>
						<Modal.Footer>
							<Button onClick={remove} disabled={isSubmitting}>
								<T id="cancel" />
							</Button>
							<Button
								type="submit"
								actionType="primary"
								className="ms-auto"
								isLoading={isSubmitting}
								disabled={isSubmitting}
							>
								<T id="save" />
							</Button>
						</Modal.Footer>
					</Form>
				)}
			</Formik>
		</Modal>
	);
});

export { showChangePasswordModal };
