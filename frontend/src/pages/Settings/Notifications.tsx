import { IconBell, IconLock, IconMail, IconSend, IconServer, IconUsers, IconX } from "@tabler/icons-react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { Alert } from "react-bootstrap";
import type { NotificationSettings, NotificationSettingsInput, SmtpSecurity } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useNotifications, useTestNotifications, useUpdateNotifications } from "src/hooks";
import { intl, T } from "src/locale";
import { showObjectSuccess } from "src/notifications";

const t = (id: string, values?: Record<string, string | number>) => intl.formatMessage({ id }, values);
const EMAIL_RE = /^[^\s@<>"',;]+@[^\s@<>"',;]+\.[^\s@<>"',;]+$/;
const SECURITY: { id: SmtpSecurity; port: number }[] = [
	{ id: "ssl", port: 465 },
	{ id: "starttls", port: 587 },
	{ id: "none", port: 25 },
];

type Form = Omit<NotificationSettingsInput, "smtp"> & {
	smtp: NotificationSettingsInput["smtp"] & { password: string };
};

const toForm = (d: NotificationSettings): Form => ({
	enabled: d.enabled,
	appUrl: d.appUrl || "",
	smtp: {
		host: d.smtp.host,
		port: d.smtp.port,
		security: d.smtp.security,
		user: d.smtp.user,
		fromName: d.smtp.fromName,
		fromAddress: d.smtp.fromAddress,
		password: "",
	},
	recipients: [...d.recipients],
	events: { ...d.events },
	expiringDays: d.expiringDays,
	clearPassword: false,
});

function Section({
	icon,
	title,
	hint,
	children,
}: {
	icon: ReactNode;
	title: string;
	hint?: string;
	children: ReactNode;
}) {
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

export default function Notifications() {
	const { data, isLoading, error } = useNotifications();
	const save = useUpdateNotifications();
	const test = useTestNotifications();
	const [form, setForm] = useState<Form | null>(null);
	const [newRecipient, setNewRecipient] = useState("");
	const [testTo, setTestTo] = useState("");

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
	const setSmtp = (patch: Partial<Form["smtp"]>) => setForm((f) => (f ? { ...f, smtp: { ...f.smtp, ...patch } } : f));
	const recipientOk = EMAIL_RE.test(newRecipient.trim());
	const addRecipient = () => {
		const r = newRecipient.trim().toLowerCase();
		if (!EMAIL_RE.test(r) || form.recipients.includes(r)) return;
		set({ recipients: [...form.recipients, r] });
		setNewRecipient("");
	};

	const status = !data.enabled
		? { cls: "bg-secondary-lt", id: "settings.notifications.state.off" }
		: { cls: "bg-green-lt", id: "settings.notifications.state.on" };

	const onSave = () => {
		const payload: NotificationSettingsInput = { ...form, smtp: { ...form.smtp } };
		if (!form.smtp.password) delete payload.smtp.password;
		save.mutate(payload, { onSuccess: () => showObjectSuccess("setting", "saved") });
	};

	const field = (
		id: string,
		label: string,
		value: string | number,
		onChange: (v: string) => void,
		opts: { type?: string; placeholder?: string; hint?: string; col?: string; autoComplete?: string } = {},
	) => (
		<div className={opts.col || "col-md-6"}>
			<label className="form-label" htmlFor={id}>
				<T id={label} />
			</label>
			<input
				id={id}
				type={opts.type || "text"}
				className="form-control"
				autoComplete={opts.autoComplete || "off"}
				spellCheck={false}
				placeholder={opts.placeholder}
				value={value}
				onChange={(e) => onChange(e.target.value)}
			/>
			{opts.hint ? (
				<div className="form-hint">
					<T id={opts.hint} />
				</div>
			) : null}
		</div>
	);

	return (
		<div className="d-flex flex-column flex-fill">
			<div className="card-body">
				<div className="d-flex align-items-start justify-content-between gap-3 flex-wrap mb-4">
					<div>
						<span className="platform-kicker">
							<IconBell size={14} />
							<T id="settings.notifications.kicker" />
						</span>
						<h3 className="card-title mt-2 mb-1">
							<T id="settings.notifications" />
						</h3>
						<div className="text-secondary" style={{ maxWidth: "62ch" }}>
							<T id="settings.notifications.description" />
						</div>
					</div>
					<span className={`badge ${status.cls}`}>
						<T id={status.id} />
					</span>
				</div>

				{save.error ? (
					<Alert variant="danger" dismissible onClose={() => save.reset()}>
						{save.error.message}
					</Alert>
				) : null}

				{/* Versand an/aus */}
				<div className="platform-inline-panel d-flex align-items-center gap-3 mb-3">
					<label className="form-check form-switch m-0 flex-fill">
						<input
							className="form-check-input"
							type="checkbox"
							checked={form.enabled}
							onChange={(e) => set({ enabled: e.target.checked })}
						/>
						<span className="form-check-label fw-semibold">
							<T id="settings.notifications.enabled" />
						</span>
						<span className="d-block text-secondary small">
							<T id="settings.notifications.enabled.hint" />
						</span>
					</label>
				</div>

				<Section
					icon={<IconServer size={18} />}
					title="settings.notifications.smtp"
					hint="settings.notifications.smtp.hint"
				>
					<div className="row g-3">
						{field(
							"n-host",
							"settings.notifications.smtp.host",
							form.smtp.host,
							(v) => setSmtp({ host: v }),
							{
								placeholder: "mail.example.com",
								col: "col-md-8",
							},
						)}
						{field(
							"n-port",
							"settings.notifications.smtp.port",
							form.smtp.port,
							(v) => setSmtp({ port: Number(v) || 0 }),
							{
								type: "number",
								col: "col-md-4",
							},
						)}
						<div className="col-12">
							<div className="form-label">
								<T id="settings.notifications.smtp.security" />
							</div>
							<div className="geo-presets">
								{SECURITY.map((s) => (
									<button
										key={s.id}
										type="button"
										className={`geo-preset ${form.smtp.security === s.id ? "active" : ""}`}
										aria-pressed={form.smtp.security === s.id}
										onClick={() => setSmtp({ security: s.id, port: s.port })}
									>
										<span className="geo-preset-title d-flex align-items-center gap-1">
											{s.id !== "none" ? <IconLock size={14} /> : null}
											<T id={`settings.notifications.smtp.security.${s.id}`} />
										</span>
										<span className="geo-preset-meta">
											<T id={`settings.notifications.smtp.security.${s.id}.hint`} />
										</span>
									</button>
								))}
							</div>
						</div>
						{field(
							"n-user",
							"settings.notifications.smtp.user",
							form.smtp.user,
							(v) => setSmtp({ user: v }),
							{
								autoComplete: "username",
							},
						)}
						<div className="col-md-6">
							<label className="form-label" htmlFor="n-pass">
								<T id="settings.notifications.smtp.password" />
							</label>
							<input
								id="n-pass"
								type="password"
								className="form-control"
								autoComplete="new-password"
								placeholder={
									data.smtp.hasPassword && !form.clearPassword
										? t("settings.notifications.smtp.password.keep")
										: ""
								}
								value={form.smtp.password}
								onChange={(e) => setSmtp({ password: e.target.value })}
							/>
							{data.smtp.hasPassword ? (
								<div className="form-hint d-flex align-items-center gap-2">
									{form.clearPassword ? (
										<T id="settings.notifications.smtp.password.cleared" />
									) : (
										<T id="settings.notifications.smtp.password.stored" />
									)}
									<button
										type="button"
										className="btn btn-link btn-sm p-0"
										onClick={() => set({ clearPassword: !form.clearPassword })}
									>
										<T
											id={
												form.clearPassword
													? "settings.notifications.smtp.password.undo"
													: "settings.notifications.smtp.password.clear"
											}
										/>
									</button>
								</div>
							) : null}
						</div>
						{field(
							"n-fromname",
							"settings.notifications.smtp.from-name",
							form.smtp.fromName,
							(v) => setSmtp({ fromName: v }),
							{
								placeholder: "FloppyGuard",
							},
						)}
						{field(
							"n-from",
							"settings.notifications.smtp.from-address",
							form.smtp.fromAddress,
							(v) => setSmtp({ fromAddress: v }),
							{ type: "email", placeholder: "floppyguard@example.com" },
						)}
						{field("n-appurl", "settings.notifications.app-url", form.appUrl, (v) => set({ appUrl: v }), {
							type: "url",
							placeholder: window.location.origin,
							hint: "settings.notifications.app-url.hint",
							col: "col-12",
						})}
					</div>
				</Section>

				<Section icon={<IconUsers size={18} />} title="settings.notifications.recipients">
					<div className="geo-chips mb-3">
						{form.recipients.length ? (
							form.recipients.map((r) => (
								<span key={r} className="geo-chip">
									<IconMail size={14} className="text-secondary" />
									{r}
									<button
										type="button"
										className="geo-chip-remove"
										aria-label={t("settings.notifications.recipients.remove", { email: r })}
										onClick={() => set({ recipients: form.recipients.filter((x) => x !== r) })}
									>
										<IconX size={12} />
									</button>
								</span>
							))
						) : (
							<span className="text-secondary small">
								<T id="settings.notifications.recipients.none" />
							</span>
						)}
					</div>
					<div className="input-group" style={{ maxWidth: 460 }}>
						<input
							type="email"
							className="form-control"
							placeholder={t("settings.notifications.recipients.add")}
							value={newRecipient}
							onChange={(e) => setNewRecipient(e.target.value)}
							onKeyDown={(e) => {
								if (e.key === "Enter") {
									e.preventDefault();
									addRecipient();
								}
							}}
						/>
						<button type="button" className="btn" disabled={!recipientOk} onClick={addRecipient}>
							<T id="settings.notifications.recipients.add-button" />
						</button>
					</div>
				</Section>

				<Section icon={<IconBell size={18} />} title="settings.notifications.events">
					<div className="list-group list-group-flush border rounded">
						{(
							[
								["certFailed", "settings.notifications.event.cert-failed"],
								["certExpiring", "settings.notifications.event.cert-expiring"],
							] as const
						).map(([key, label]) => (
							<div key={key} className="list-group-item d-flex align-items-center gap-3">
								<span className="flex-fill">
									<span className="fw-semibold d-block">
										<T id={label} />
									</span>
									<span className="text-secondary small">
										<T id={`${label}.hint`} />
									</span>
									{key === "certExpiring" && form.events.certExpiring ? (
										<span className="d-flex align-items-center gap-2 mt-2 small">
											<T id="settings.notifications.expiring-days" />
											<input
												type="number"
												min={1}
												max={60}
												className="form-control form-control-sm"
												style={{ width: 80 }}
												value={form.expiringDays}
												onChange={(e) => set({ expiringDays: Number(e.target.value) || 1 })}
											/>
											<T id="settings.notifications.days" />
										</span>
									) : null}
								</span>
								<label className="form-check form-switch m-0">
									<input
										className="form-check-input"
										type="checkbox"
										aria-label={t(label)}
										checked={form.events[key]}
										onChange={(e) => set({ events: { ...form.events, [key]: e.target.checked } })}
									/>
								</label>
							</div>
						))}
					</div>
				</Section>

				<Section
					icon={<IconSend size={18} />}
					title="settings.notifications.test"
					hint="settings.notifications.test.hint"
				>
					<div className="d-flex gap-2 flex-wrap align-items-start">
						<input
							type="email"
							className="form-control"
							style={{ maxWidth: 340 }}
							placeholder={form.recipients[0] || t("settings.notifications.test.to")}
							value={testTo}
							onChange={(e) => setTestTo(e.target.value)}
						/>
						<Button
							type="button"
							isLoading={test.isPending}
							disabled={test.isPending || dirty || !data.smtp.host}
							onClick={() => test.mutate(testTo.trim() || undefined)}
						>
							<IconSend size={16} className="me-1" />
							<T id="settings.notifications.test.send" />
						</Button>
					</div>
					{dirty ? (
						<div className="form-hint mt-2">
							<T id="settings.notifications.test.save-first" />
						</div>
					) : null}
					{test.data ? (
						<Alert variant={test.data.ok ? "success" : "danger"} className="mt-3 mb-0 py-2">
							{test.data.message}
						</Alert>
					) : null}
					{test.error ? (
						<Alert variant="danger" className="mt-3 mb-0 py-2">
							{test.error.message}
						</Alert>
					) : null}
				</Section>
			</div>

			{dirty ? (
				<div className="card-footer geo-savebar mt-auto">
					<div className="d-flex align-items-center gap-3 flex-wrap">
						<strong className="small">
							<T id="settings.geo-filter.unsaved" />
						</strong>
						<div className="btn-list ms-auto">
							<button type="button" className="btn" onClick={() => setForm(toForm(data))}>
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
