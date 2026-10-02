import { useEffect, useState } from "react";
import { Alert } from "react-bootstrap";
import type { HealthResponse } from "src/api/backend";
import { exchangeOidcLogin, getOidcStatus, getToken, isTwoFactorChallenge, verify2FA } from "src/api/backend";
import { BrandLogo, LocalePicker, Page, ThemeSwitcher } from "src/components";
import { useHealth } from "src/hooks/useHealth";
import { intl } from "src/locale/IntlProvider";
import AuthStore from "src/modules/AuthStore";
import styles from "./index.module.css";

const t = (id: string) => intl.formatMessage({ id });

// Feste Fehlercodes vom Backend (routes/oidc.js). Alles andere wird ignoriert.
const SSO_ERRORS = ["unconfigured", "denied", "invalid", "failed", "expired", "rejected"];
// "group" nutzt den allgemeinen Text von login.sso-error-rejected.
const SSO_REJECT_REASONS = ["disabled", "noemail"];

export default function Login() {
	const health = useHealth();
	const [identity, setIdentity] = useState("");
	const [secret, setSecret] = useState("");
	const [code, setCode] = useState("");
	const [challengeToken, setChallengeToken] = useState<string | null>(null);
	const [status, setStatus] = useState<string>("");
	const [statusIsError, setStatusIsError] = useState(false);
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [ssoLabel, setSsoLabel] = useState<string | null>(null);

	// Rueckweg vom Anbieter. Das Fragment enthaelt nur feste Codes; das Token
	// selbst wird ueber ein HttpOnly-Cookie per POST abgeholt. Tokens oder
	// freier Text aus der URL werden nie uebernommen bzw. angezeigt.
	useEffect(() => {
		const hash = window.location.hash.replace(/^#/, "");
		if (hash) {
			const parsed = new URLSearchParams(hash);
			const ssoDone = parsed.get("sso") === "done";
			const ssoError = parsed.get("sso_error");
			const reason = parsed.get("reason");
			// Fragment entfernen, damit ein Neuladen nichts wiederholt.
			window.history.replaceState(null, "", window.location.pathname);
			if (ssoDone) {
				exchangeOidcLogin()
					.then((response) => {
						AuthStore.set(response);
						window.location.assign("/");
					})
					.catch(() => {
						setStatusIsError(true);
						setStatus(t("login.sso-error-expired"));
					});
			} else if (ssoError && SSO_ERRORS.includes(ssoError)) {
				setStatusIsError(true);
				if (ssoError === "rejected" && reason && SSO_REJECT_REASONS.includes(reason)) {
					setStatus(t(`login.sso-error-rejected-${reason}`));
				} else {
					setStatus(t(`login.sso-error-${ssoError}`));
				}
			}
		}
		getOidcStatus()
			.then((res) => setSsoLabel(res.enabled ? res.label : null))
			.catch(() => setSsoLabel(null));
	}, []);

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
		setStatusIsError(false);
		try {
			const response = await getToken(identity, secret);
			if (isTwoFactorChallenge(response)) {
				setChallengeToken(response.challengeToken);
				setStatus(t("login.2fa-prompt"));
				return;
			}
			AuthStore.set(response);
			window.location.assign("/");
		} catch (err: any) {
			setStatusIsError(true);
			setStatus(intl.formatMessage({ id: "login.error" }, { error: err?.message || "Unexpected error" }));
		} finally {
			setIsSubmitting(false);
		}
	};

	const handle2FA = async (event: React.FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		if (!challengeToken || isSubmitting) return;
		setIsSubmitting(true);
		setStatus("");
		setStatusIsError(false);
		try {
			const response = await verify2FA(challengeToken, code);
			AuthStore.set(response);
			window.location.assign("/");
		} catch (err: any) {
			setStatusIsError(true);
			setStatus(intl.formatMessage({ id: "login.2fa-error" }, { error: err?.message || "Unexpected error" }));
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
					<h2 className={styles.heading}>{challengeToken ? t("login.2fa-title") : t("login.title")}</h2>

					{status ? (
						<Alert variant={statusIsError ? "danger" : "info"} className="py-2 px-3 small">
							{status}
						</Alert>
					) : null}

					{!challengeToken ? (
						<>
							<form onSubmit={handleLogin}>
								<div className="mb-3">
									<label className="form-label" htmlFor="identity">
										{t("login.email")}
									</label>
									<input
										id="identity"
										type="email"
										className="form-control"
										value={identity}
										onChange={(e) => setIdentity(e.target.value)}
										autoComplete="username"
										required
									/>
								</div>
								<div className="mb-4">
									<label className="form-label" htmlFor="secret">
										{t("login.password")}
									</label>
									<input
										id="secret"
										type="password"
										className="form-control"
										value={secret}
										onChange={(e) => setSecret(e.target.value)}
										autoComplete="current-password"
										required
									/>
								</div>
								<button type="submit" className="btn btn-primary w-100" disabled={isSubmitting}>
									{isSubmitting ? t("login.signing-in") : t("login.sign-in")}
								</button>
							</form>

							{ssoLabel ? (
								<>
									<div className={styles.ssoSeparator}>{t("login.sso-or")}</div>
									<a className="btn btn-outline-primary w-100" href="/api/oidc/start">
										{ssoLabel}
									</a>
								</>
							) : null}
						</>
					) : (
						<form onSubmit={handle2FA}>
							<div className="mb-4">
								<label className="form-label" htmlFor="code">
									{t("login.2fa-code")}
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
									{isSubmitting ? t("login.2fa-verifying") : t("login.2fa-verify")}
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
									{t("login.2fa-back")}
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
