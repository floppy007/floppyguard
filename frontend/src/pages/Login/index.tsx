import { useState } from "react";
import { Alert } from "react-bootstrap";
import type { HealthResponse } from "src/api/backend";
import { getToken, isTwoFactorChallenge, verify2FA } from "src/api/backend";
import { BrandLogo, LocalePicker, Page, ThemeSwitcher } from "src/components";
import { useHealth } from "src/hooks/useHealth";
import AuthStore from "src/modules/AuthStore";
import styles from "./index.module.css";

export default function Login() {
	const health = useHealth();
	const [identity, setIdentity] = useState("");
	const [secret, setSecret] = useState("");
	const [code, setCode] = useState("");
	const [challengeToken, setChallengeToken] = useState<string | null>(null);
	const [status, setStatus] = useState<string>("");
	const [isSubmitting, setIsSubmitting] = useState(false);

	const getVersion = () => {
		if (!health.data) return "";
		const v = (health.data as unknown as HealthResponse).version;
		return `v${v.major}.${v.minor}.${v.revision}`;
	};

	const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		if (isSubmitting) return;
		setIsSubmitting(true);
		setStatus("");
		try {
			const response = await getToken(identity, secret);
			if (isTwoFactorChallenge(response)) {
				setChallengeToken(response.challengeToken);
				setStatus("Enter the code from your authenticator app.");
				return;
			}
			AuthStore.set(response);
			window.location.assign("/");
		} catch (err: any) {
			setStatus(`Login failed: ${err?.message || "Unexpected error"}`);
		} finally {
			setIsSubmitting(false);
		}
	};

	const handle2FA = async (event: React.FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		if (!challengeToken || isSubmitting) return;
		setIsSubmitting(true);
		setStatus("");
		try {
			const response = await verify2FA(challengeToken, code);
			AuthStore.set(response);
			window.location.assign("/");
		} catch (err: any) {
			setStatus(`2FA failed: ${err?.message || "Unexpected error"}`);
		} finally {
			setIsSubmitting(false);
		}
	};

	return (
		<Page className="page page-center">
			<div className={styles.card}>
				<div className={styles.cardHeader}>
					<BrandLogo className={styles.logo} alt="FloppyGuard" />
					<div className={styles.tools}>
						<LocalePicker />
						<ThemeSwitcher />
					</div>
				</div>

				<div className={styles.cardBody}>
					<h2 className={styles.heading}>{challengeToken ? "Two-factor verification" : "Sign in"}</h2>

					{status ? (
						<Alert
							variant={status.toLowerCase().includes("failed") ? "danger" : "info"}
							className="py-2 px-3 small"
						>
							{status}
						</Alert>
					) : null}

					{!challengeToken ? (
						<form onSubmit={handleLogin}>
							<div className="mb-3">
								<label className="form-label" htmlFor="identity">
									Email
								</label>
								<input
									id="identity"
									type="email"
									className="form-control"
									value={identity}
									onChange={(e) => setIdentity(e.target.value)}
									autoComplete="username"
								/>
							</div>
							<div className="mb-4">
								<label className="form-label" htmlFor="secret">
									Password
								</label>
								<input
									id="secret"
									type="password"
									className="form-control"
									value={secret}
									onChange={(e) => setSecret(e.target.value)}
									autoComplete="current-password"
								/>
							</div>
							<button type="submit" className="btn btn-primary w-100" disabled={isSubmitting}>
								{isSubmitting ? "Signing in…" : "Sign in"}
							</button>
						</form>
					) : (
						<form onSubmit={handle2FA}>
							<div className="mb-4">
								<label className="form-label" htmlFor="code">
									Authenticator code
								</label>
								<input
									id="code"
									className="form-control"
									value={code}
									onChange={(e) => setCode(e.target.value)}
									autoComplete="one-time-code"
								/>
							</div>
							<div className="d-grid gap-2">
								<button type="submit" className="btn btn-primary w-100" disabled={isSubmitting}>
									{isSubmitting ? "Verifying…" : "Verify"}
								</button>
								<button
									type="button"
									className="btn btn-ghost-secondary w-100"
									onClick={() => {
										setChallengeToken(null);
										setCode("");
										setStatus("");
									}}
								>
									Back
								</button>
							</div>
						</form>
					)}
				</div>

				<div className={styles.cardFooter}>{getVersion()}</div>
			</div>
		</Page>
	);
}
