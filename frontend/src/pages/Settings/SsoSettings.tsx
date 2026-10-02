import { type FormEvent, useEffect, useState } from "react";
import { Alert } from "react-bootstrap";
import type { OidcSettingsInput } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useOidcSettings, useTestOidcSettings, useUpdateOidcSettings } from "src/hooks";
import { intl, T } from "src/locale";
import { showObjectSuccess } from "src/notifications";

type FormState = Omit<OidcSettingsInput, "clearClientSecret"> & { clientSecret: string };

const EMPTY: FormState = {
	enabled: false,
	label: "",
	issuer: "",
	clientId: "",
	clientSecret: "",
	redirectUri: "",
	requiredGroup: "",
	groupsClaim: "groups",
	scopes: "openid profile email",
	expiry: "1d",
};

const t = (id: string) => intl.formatMessage({ id });

export default function SsoSettings() {
	const { data, isLoading, error } = useOidcSettings();
	const save = useUpdateOidcSettings();
	const test = useTestOidcSettings();
	const [form, setForm] = useState<FormState>(EMPTY);

	useEffect(() => {
		if (data) {
			const { hasClientSecret: _s, configPath: _p, ...rest } = data;
			setForm({ ...EMPTY, ...rest, clientSecret: "" });
		}
	}, [data]);

	const set =
		<K extends keyof FormState>(key: K) =>
		(value: FormState[K]) =>
			setForm((prev) => ({ ...prev, [key]: value }));

	const suggestedRedirect = `${window.location.origin}/api/oidc/callback`;

	const onSubmit = (e: FormEvent) => {
		e.preventDefault();
		test.reset();
		const payload: OidcSettingsInput = { ...form };
		if (!form.clientSecret) {
			delete payload.clientSecret;
		}
		save.mutate(payload, {
			onSuccess: () => {
				setForm((prev) => ({ ...prev, clientSecret: "" }));
				showObjectSuccess("setting", "saved");
			},
		});
	};

	if (isLoading) {
		return (
			<div className="card-body">
				<Loading noLogo />
			</div>
		);
	}

	if (error) {
		return (
			<div className="card-body">
				<Alert variant="danger">{error.message}</Alert>
			</div>
		);
	}

	const text = (
		key: keyof FormState,
		labelId: string,
		opts: { placeholder?: string; hintId?: string; type?: string } = {},
	) => (
		<div className="mb-3">
			<label className="form-label" htmlFor={`sso-${key}`}>
				<T id={labelId} />
			</label>
			<input
				id={`sso-${key}`}
				type={opts.type || "text"}
				className="form-control"
				autoComplete="off"
				spellCheck={false}
				placeholder={opts.placeholder}
				value={String(form[key] ?? "")}
				onChange={(e) => set(key)(e.target.value as never)}
			/>
			{opts.hintId ? (
				<div className="form-hint">
					<T id={opts.hintId} />
				</div>
			) : null}
		</div>
	);

	return (
		<form onSubmit={onSubmit} className="d-flex flex-column flex-fill">
			<div className="card-body">
				<div className="d-flex align-items-start justify-content-between gap-3 flex-wrap mb-4">
					<div>
						<h3 className="card-title mb-1">
							<T id="settings.sso" />
						</h3>
						<div className="text-secondary small">
							<T id="settings.sso.description" />
						</div>
					</div>
					<span className={`badge ${data?.enabled ? "bg-green-lt" : "bg-secondary-lt"}`}>
						<T id={data?.enabled ? "settings.sso.status-active" : "settings.sso.status-inactive"} />
					</span>
				</div>

				{save.error ? (
					<Alert variant="danger" dismissible onClose={() => save.reset()}>
						{save.error.message}
					</Alert>
				) : null}

				<div className="mb-4">
					<label className="form-check form-switch">
						<input
							className="form-check-input"
							type="checkbox"
							checked={form.enabled}
							onChange={(e) => set("enabled")(e.target.checked)}
						/>
						<span className="form-check-label">
							<T id="settings.sso.enabled" />
						</span>
					</label>
					<div className="form-hint">
						<T id="settings.sso.enabled.hint" />
					</div>
				</div>

				<h4 className="subheader mb-2">
					<T id="settings.sso.section.provider" />
				</h4>
				<div className="row">
					<div className="col-lg-12">
						<div className="mb-3">
							<label className="form-label" htmlFor="sso-issuer">
								<T id="settings.sso.issuer" />
							</label>
							<div className="input-group">
								<input
									id="sso-issuer"
									type="url"
									className="form-control"
									autoComplete="off"
									spellCheck={false}
									placeholder="https://sso.example.com/application/o/floppyguard/"
									value={form.issuer}
									onChange={(e) => set("issuer")(e.target.value)}
								/>
								<button
									type="button"
									className="btn"
									disabled={!form.issuer || test.isPending}
									onClick={() => test.mutate(form.issuer)}
								>
									{test.isPending ? <span className="spinner-border spinner-border-sm me-2" /> : null}
									<T id="settings.sso.test" />
								</button>
							</div>
							<div className="form-hint">
								<T id="settings.sso.issuer.hint" />
							</div>
							{test.data ? (
								<Alert variant={test.data.ok ? "success" : "warning"} className="mt-2 mb-0 py-2">
									{test.data.message}
								</Alert>
							) : null}
							{test.error ? (
								<Alert variant="danger" className="mt-2 mb-0 py-2">
									{test.error.message}
								</Alert>
							) : null}
						</div>
					</div>
					<div className="col-lg-6">{text("clientId", "settings.sso.client-id")}</div>
					<div className="col-lg-6">
						{text("clientSecret", "settings.sso.client-secret", {
							type: "password",
							placeholder: data?.hasClientSecret ? t("settings.sso.client-secret.keep") : "",
							hintId: data?.hasClientSecret ? "settings.sso.client-secret.stored" : undefined,
						})}
					</div>
					<div className="col-lg-12">
						<div className="mb-3">
							<label className="form-label" htmlFor="sso-redirectUri">
								<T id="settings.sso.redirect-uri" />
							</label>
							<div className="input-group">
								<input
									id="sso-redirectUri"
									type="url"
									className="form-control"
									autoComplete="off"
									spellCheck={false}
									placeholder={suggestedRedirect}
									value={form.redirectUri}
									onChange={(e) => set("redirectUri")(e.target.value)}
								/>
								<button
									type="button"
									className="btn"
									disabled={form.redirectUri === suggestedRedirect}
									onClick={() => set("redirectUri")(suggestedRedirect)}
								>
									<T id="settings.sso.redirect-uri.use-current" />
								</button>
							</div>
							<div className="form-hint">
								<T id="settings.sso.redirect-uri.hint" />
							</div>
						</div>
					</div>
				</div>

				<h4 className="subheader mt-2 mb-2">
					<T id="settings.sso.section.access" />
				</h4>
				<div className="row">
					<div className="col-lg-6">
						{text("requiredGroup", "settings.sso.required-group", {
							hintId: "settings.sso.required-group.hint",
						})}
					</div>
					<div className="col-lg-6">
						{text("groupsClaim", "settings.sso.groups-claim", { placeholder: "groups" })}
					</div>
					<div className="col-lg-6">
						{text("scopes", "settings.sso.scopes", { placeholder: "openid profile email" })}
					</div>
					<div className="col-lg-6">
						{text("expiry", "settings.sso.expiry", {
							placeholder: "1d",
							hintId: "settings.sso.expiry.hint",
						})}
					</div>
				</div>

				<h4 className="subheader mt-2 mb-2">
					<T id="settings.sso.section.login" />
				</h4>
				{text("label", "settings.sso.label", { placeholder: "Mit Firmenkonto anmelden" })}
				<div className="mb-2">
					<div className="form-label">
						<T id="settings.sso.preview" />
					</div>
					<div className="platform-sso-preview">
						<span className="btn btn-outline-primary w-100" aria-hidden="true">
							{form.label || "Mit Firmenkonto anmelden"}
						</span>
					</div>
				</div>

				<Alert variant="info" className="mt-4 mb-0">
					<T id="settings.sso.security-note" />
				</Alert>
			</div>
			<div className="card-footer bg-transparent mt-auto">
				<div className="btn-list justify-content-end">
					<Button type="submit" actionType="primary" isLoading={save.isPending} disabled={save.isPending}>
						<T id="save" />
					</Button>
				</div>
			</div>
		</form>
	);
}
