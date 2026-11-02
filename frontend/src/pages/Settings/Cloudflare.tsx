import {
	IconBrandCloudflare,
	IconCheck,
	IconExternalLink,
	IconInfoCircle,
	IconKey,
	IconNetwork,
	IconPlugConnected,
	IconSettings,
	IconWorld,
} from "@tabler/icons-react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { Alert } from "react-bootstrap";
import type { CloudflareSettings, CloudflareSettingsInput } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useCloudflare, useTestCloudflare, useUpdateCloudflare } from "src/hooks";
import { intl, T } from "src/locale";
import { showObjectSuccess } from "src/notifications";

const t = (id: string, values?: Record<string, string | number>) => intl.formatMessage({ id }, values);

// Cloudflare-Vorlagen-Link: öffnet „API-Token erstellen“ mit DNS bearbeiten + Zone lesen für alle Zonen
// (https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/)
const TOKEN_TEMPLATE_URL = `https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=${encodeURIComponent(
	JSON.stringify([
		{ key: "dns", type: "edit" },
		{ key: "zone", type: "read" },
	]),
)}&accountId=*&zoneId=all&name=FloppyGuard`;

type Form = Required<Omit<CloudflareSettingsInput, "apiToken">> & { apiToken: string };

const toForm = (d: CloudflareSettings): Form => ({
	ipv4: d.ipv4 || "",
	ipv6: d.ipv6 || "",
	autoNewHosts: d.autoNewHosts,
	proxiedDefault: d.proxiedDefault,
	allowAllUsers: d.allowAllUsers,
	apiToken: "",
	clearToken: false,
});

function Section({ icon, title, hint, children }: { icon: ReactNode; title: string; hint?: string; children: ReactNode }) {
	return (
		<div className="card platform-elevated-card mb-3">
			<div className="card-header">
				<h4 className="card-title mb-0 d-flex align-items-center gap-2">
					{icon}
					<T id={title} />
				</h4>
				{hint ? (
					<span className="ms-auto text-secondary small">
						<T id={hint} />
					</span>
				) : null}
			</div>
			<div className="card-body">{children}</div>
		</div>
	);
}

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
	return (
		<div className="d-flex gap-3 mb-3">
			<span className="avatar avatar-sm rounded-circle bg-orange-lt fw-bold flex-shrink-0">{n}</span>
			<div className="flex-fill">
				<div className="fw-semibold mb-1">
					<T id={title} />
				</div>
				{children}
			</div>
		</div>
	);
}

export default function Cloudflare() {
	const { data, isLoading, error } = useCloudflare();
	const save = useUpdateCloudflare();
	const test = useTestCloudflare();
	const [form, setForm] = useState<Form | null>(null);

	useEffect(() => {
		if (data) setForm(toForm(data));
	}, [data]);

	const initial = useMemo(() => (data ? JSON.stringify(toForm(data)) : ""), [data]);

	if (isLoading || (!form && !error)) {
		return (
			<div className="card-body">
				<Loading noLogo />
			</div>
		);
	}
	if (error || !data || !form) {
		return (
			<div className="card-body">
				<Alert variant="danger">{error?.message || "Unknown error"}</Alert>
			</div>
		);
	}

	const dirty = JSON.stringify(form) !== initial;
	const set = (patch: Partial<Form>) => setForm((f) => (f ? { ...f, ...patch } : f));
	const connected = (data.hasToken && !form.clearToken) || data.envToken;

	const onSave = () => {
		const payload: CloudflareSettingsInput = { ...form };
		if (!form.apiToken.trim()) delete payload.apiToken;
		save.mutate(payload, {
			onSuccess: () => {
				showObjectSuccess("setting", "saved");
				test.reset();
			},
		});
	};

	const detectedHint = (family: "ipv4" | "ipv6") =>
		data.detected[family][0]
			? t("settings.cloudflare.addresses.detected", { address: data.detected[family][0] })
			: t("settings.cloudflare.addresses.none-detected");

	const toggles = [
		["autoNewHosts", "settings.cloudflare.defaults.auto"],
		["proxiedDefault", "settings.cloudflare.defaults.proxied"],
		["allowAllUsers", "settings.cloudflare.defaults.all-users"],
	] as const;

	return (
		<div className="d-flex flex-column flex-fill">
			<div className="card-body">
				<div className="d-flex align-items-start justify-content-between gap-3 flex-wrap mb-4">
					<div>
						<span className="platform-kicker">
							<IconBrandCloudflare size={14} />
							<T id="settings.cloudflare.kicker" />
						</span>
						<h3 className="card-title mt-2 mb-1">
							<T id="settings.cloudflare" />
						</h3>
						<div className="text-secondary" style={{ maxWidth: "62ch" }}>
							<T id="settings.cloudflare.description" />
						</div>
					</div>
					<span className={`badge ${connected ? "bg-green-lt" : "bg-secondary-lt"}`}>
						<T id={connected ? "settings.cloudflare.state.on" : "settings.cloudflare.state.off"} />
					</span>
				</div>

				{save.error ? (
					<Alert variant="danger" dismissible onClose={() => save.reset()}>
						{save.error.message}
					</Alert>
				) : null}

				<Section icon={<IconKey size={18} />} title="settings.cloudflare.token" hint="settings.cloudflare.token.hint">
					<Step n={1} title="settings.cloudflare.step1">
						<a
							href={TOKEN_TEMPLATE_URL}
							target="_blank"
							rel="noopener noreferrer"
							className="btn btn-outline-orange"
						>
							<IconBrandCloudflare size={16} className="me-1" />
							<T id="settings.cloudflare.step1.button" />
							<IconExternalLink size={14} className="ms-1" />
						</a>
						<div className="form-hint mt-2">
							<T id="settings.cloudflare.step1.hint" />
						</div>
						<details className="mt-2 small">
							<summary className="text-secondary" style={{ cursor: "pointer" }}>
								<T id="settings.cloudflare.manual" />
							</summary>
							<ol className="mt-2 mb-0 ps-3 text-secondary">
								<li>
									<T id="settings.cloudflare.manual.1" />
								</li>
								<li>
									<T id="settings.cloudflare.manual.2" />
								</li>
								<li>
									<T id="settings.cloudflare.manual.3" />
								</li>
								<li>
									<T id="settings.cloudflare.manual.4" />
								</li>
							</ol>
						</details>
					</Step>
					<Step n={2} title="settings.cloudflare.step2">
						<div className="d-flex gap-2 flex-wrap align-items-start">
							<input
								id="cf-token"
								type="password"
								className="form-control font-monospace"
								style={{ maxWidth: 420 }}
								autoComplete="off"
								spellCheck={false}
								aria-label={t("settings.cloudflare.step2")}
								placeholder={
									data.hasToken && !form.clearToken
										? t("settings.cloudflare.token.keep", { hint: data.tokenHint })
										: t("settings.cloudflare.token.placeholder")
								}
								value={form.apiToken}
								onChange={(e) => set({ apiToken: e.target.value })}
							/>
							<Button
								type="button"
								isLoading={test.isPending}
								disabled={test.isPending || (!form.apiToken.trim() && !connected)}
								onClick={() => test.mutate(form.apiToken.trim() || undefined)}
							>
								<IconPlugConnected size={16} className="me-1" />
								<T id="settings.cloudflare.test" />
							</Button>
						</div>
						{data.hasToken ? (
							<div className="form-hint d-flex align-items-center gap-2">
								<T
									id={form.clearToken ? "settings.cloudflare.token.cleared" : "settings.cloudflare.token.stored"}
									data={{ hint: data.tokenHint }}
								/>
								<button
									type="button"
									className="btn btn-link btn-sm p-0"
									onClick={() => set({ clearToken: !form.clearToken })}
								>
									<T id={form.clearToken ? "settings.cloudflare.token.undo" : "settings.cloudflare.token.clear"} />
								</button>
							</div>
						) : null}
						{data.envToken && !data.hasToken ? (
							<div className="form-hint">
								<T id="settings.cloudflare.token.env" />
							</div>
						) : null}
						{test.data ? (
							<Alert variant={test.data.ok ? "success" : "danger"} className="mt-3 mb-0 py-2">
								<div className="d-flex align-items-center gap-2">
									{test.data.ok ? <IconCheck size={16} /> : null}
									{test.data.ok ? <T id="settings.cloudflare.test.ok" /> : test.data.message}
								</div>
								{test.data.zones.length ? (
									<div className="geo-chips mt-2">
										{test.data.zones.map((z) => (
											<span key={z} className="geo-chip">
												<IconWorld size={14} className="text-secondary" />
												{z}
											</span>
										))}
									</div>
								) : null}
							</Alert>
						) : null}
						{test.error ? (
							<Alert variant="danger" className="mt-3 mb-0 py-2">
								{test.error.message}
							</Alert>
						) : null}
					</Step>
					<Step n={3} title="settings.cloudflare.step3">
						<div className="text-secondary small">
							<T id="settings.cloudflare.step3.hint" />
						</div>
					</Step>
				</Section>

				<Section
					icon={<IconNetwork size={18} />}
					title="settings.cloudflare.addresses"
					hint="settings.cloudflare.addresses.hint"
				>
					<div className="row g-3">
						{(["ipv4", "ipv6"] as const).map((family) => (
							<div key={family} className="col-md-6">
								<label className="form-label" htmlFor={`cf-${family}`}>
									<T id={`settings.cloudflare.addresses.${family}`} />
								</label>
								<input
									id={`cf-${family}`}
									type="text"
									className="form-control font-monospace"
									autoComplete="off"
									spellCheck={false}
									placeholder={data.detected[family][0] || ""}
									value={form[family]}
									onChange={(e) => set({ [family]: e.target.value.trim() })}
								/>
								<div className="form-hint">{detectedHint(family)}</div>
							</div>
						))}
					</div>
					<div className="form-hint mt-3">
						{data.effectiveAddresses.length ? (
							<T
								id="settings.cloudflare.addresses.effective"
								data={{ addresses: data.effectiveAddresses.join(", ") }}
							/>
						) : (
							<span className="text-danger">
								<T id="settings.cloudflare.addresses.missing" />
							</span>
						)}
					</div>
				</Section>

				<Section icon={<IconSettings size={18} />} title="settings.cloudflare.defaults">
					<div className="list-group list-group-flush border rounded">
						{toggles.map(([key, label]) => (
							<div key={key} className="list-group-item d-flex align-items-center gap-3">
								<span className="flex-fill">
									<span className="fw-semibold d-block">
										<T id={label} />
									</span>
									<span className="text-secondary small">
										<T id={`${label}.hint`} />
									</span>
								</span>
								<label className="form-check form-switch m-0">
									<input
										className="form-check-input"
										type="checkbox"
										aria-label={t(label)}
										checked={form[key]}
										onChange={(e) => set({ [key]: e.target.checked })}
									/>
								</label>
							</div>
						))}
					</div>
				</Section>

				<Section icon={<IconInfoCircle size={18} />} title="settings.cloudflare.how">
					<ul className="mb-0 ps-3 text-secondary small">
						<li>
							<T id="settings.cloudflare.how.1" />
						</li>
						<li>
							<T id="settings.cloudflare.how.2" />
						</li>
						<li>
							<T id="settings.cloudflare.how.3" />
						</li>
						<li>
							<T id="settings.cloudflare.how.4" />
						</li>
					</ul>
				</Section>
			</div>

			{dirty ? (
				<div className="card-footer geo-savebar mt-auto">
					<div className="d-flex align-items-center gap-3 flex-wrap">
						<strong className="small">
							<T id="settings.geo-filter.unsaved" />
						</strong>
						<div className="btn-list ms-auto">
							<button
								type="button"
								className="btn"
								onClick={() => {
									setForm(toForm(data));
									test.reset();
								}}
							>
								<T id="settings.geo-filter.discard" />
							</button>
							<Button
								type="button"
								actionType="primary"
								isLoading={save.isPending}
								disabled={save.isPending}
								onClick={onSave}
							>
								<T id="save" />
							</Button>
						</div>
					</div>
				</div>
			) : null}
		</div>
	);
}
