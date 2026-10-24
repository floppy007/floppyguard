import { useQueryClient } from "@tanstack/react-query";
import { Form, Formik } from "formik";
import { useState } from "react";
import { Alert } from "react-bootstrap";
import { createUser } from "src/api/backend";
import { BrandLogo, Button, FloatingTextField, LocalePicker, Page, ThemeSwitcher } from "src/components";
import { useAuthState } from "src/context";
import { T } from "src/locale";
import { validateEmail, validateString } from "src/modules/Validations";
import styles from "./index.module.css";

interface Payload {
	name: string;
	email: string;
	password: string;
}

export default function Setup() {
	const queryClient = useQueryClient();
	const { login } = useAuthState();
	const [errorMsg, setErrorMsg] = useState<string | null>(null);

	const onSubmit = async (values: Payload, { setSubmitting }: any) => {
		setErrorMsg(null);

		// Set a nickname, which is the first word of the name
		const nickname = values.name.split(" ")[0];

		const { password, ...payload } = {
			...values,
			...{
				nickname,
				auth: {
					type: "password",
					secret: values.password,
				},
			},
		};

		try {
			const user = await createUser(payload, true);
			if (user?.id) {
				try {
					await login(user.email, password);
					// Trigger a Health change
					await queryClient.refetchQueries({ queryKey: ["health"] });
					// window.location.reload();
				} catch (err: any) {
					setErrorMsg(err.message);
				}
			} else {
				setErrorMsg("cannot_create_user");
			}
		} catch (err: any) {
			setErrorMsg(err.message);
		}
		setSubmitting(false);
	};

	return (
		<Page className="page page-center">
			<div className={styles.shell}>
				<div className={styles.helperBtns}>
					<LocalePicker />
					<ThemeSwitcher />
				</div>
				<div className={styles.hero}>
					<BrandLogo className={styles.logo} alt="FloppyGuard Platform" />
					<div className={styles.heroCopy}>
						<div className={styles.kicker}>
							<T id="setup.kicker" />
						</div>
						<h1 className={styles.title}>
							<T id="setup.hero.title" />
						</h1>
						<p className={styles.subtitle}>
							<T id="setup.hero.subtitle" />
						</p>
					</div>
				</div>
				<div className={styles.panel}>
					<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
						{errorMsg}
					</Alert>
					<Formik
						initialValues={
							{
								name: "",
								email: "",
								password: "",
							} as any
						}
						onSubmit={onSubmit}
					>
						{({ isSubmitting }) => (
							<Form>
								<div className={styles.panelHeader}>
									<h2 className={styles.panelTitle}>
										<T id="setup.title" />
									</h2>
									<p className={styles.panelIntro}>
										<T id="setup.preamble" />
									</p>
								</div>
								<div className={styles.panelBody}>
									<div className="mb-3">
										<FloatingTextField
											name="name"
											labelId="user.full-name"
											validate={validateString(1, 50)}
										/>
									</div>
									<div className="mb-3">
										<FloatingTextField
											name="email"
											labelId="email-address"
											type="email"
											validate={validateEmail()}
										/>
									</div>
									<div className="mb-3">
										<FloatingTextField
											name="password"
											labelId="user.new-password"
											type="password"
											autoComplete="new-password"
											validate={validateString(8, 100)}
										/>
									</div>
								</div>
								<div className={styles.footerAction}>
									<Button
										type="submit"
										actionType="primary"
										isLoading={isSubmitting}
										disabled={isSubmitting}
										className="w-100"
									>
										<T id="save" />
									</Button>
								</div>
							</Form>
						)}
					</Formik>
				</div>
			</div>
		</Page>
	);
}
