/**
 * Benachrichtigungen per E-Mail (Einstellungen → Benachrichtigungen).
 *
 * SMTP-Zugang, Empfänger und Ereignisse liegen in /data/notifications.json (0600). Das Passwort verlässt das
 * Backend nie: die API meldet nur `has_password`. Versand über nodemailer direkt an den eingestellten
 * Mailserver – das lokale Postfix des Hosts wird nicht benutzt (Absender localdomain wird abgewiesen).
 */
import fs from "node:fs";
import path from "node:path";
import nodemailer from "nodemailer";
import errs from "../lib/error.js";
import { global as logger } from "../logger.js";

export const configPath = () => process.env.FG_NOTIFY_CONFIG || "/data/notifications.json";

export const DEFAULTS = Object.freeze({
	enabled: false,
	smtp: { host: "", port: 465, security: "ssl", user: "", from_name: "FloppyGuard", from_address: "" },
	recipients: [],
	events: { cert_failed: true, cert_expiring: true },
	expiring_days: 14,
	app_url: "",
});

const EMAIL_RE = /^[^\s@<>"',;]+@[^\s@<>"',;]+\.[^\s@<>"',;]+$/;
const HOST_RE = /^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$|^\[?[0-9a-fA-F:.]+\]?$/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: Steuerzeichen werden hier absichtlich abgewiesen
const CTRL_RE = /[\u0000-\u001f\u007f]/;
const SECURITY = ["ssl", "starttls", "none"];

const readRaw = () => {
	try {
		const raw = JSON.parse(fs.readFileSync(configPath(), "utf8"));
		return {
			...DEFAULTS,
			...raw,
			smtp: { ...DEFAULTS.smtp, ...(raw.smtp || {}) },
			events: { ...DEFAULTS.events, ...(raw.events || {}) },
			recipients: Array.isArray(raw.recipients) ? raw.recipients : [],
		};
	} catch {
		return { ...DEFAULTS, smtp: { ...DEFAULTS.smtp }, events: { ...DEFAULTS.events }, recipients: [] };
	}
};

const toPublic = (raw) => {
	const { password, ...smtp } = raw.smtp;
	return { ...raw, smtp: { ...smtp, has_password: Boolean(password) } };
};

const str = (v, max, field) => {
	const s = typeof v === "string" ? v.trim() : "";
	if (s.length > max || CTRL_RE.test(s)) throw new errs.ValidationError(`${field}: ungültig`);
	return s;
};

/** Eingabe prüfen; Passwort bleibt, wenn keins mitkommt (außer clear_password). */
export const validate = (input, existing) => {
	if (!input || typeof input !== "object") throw new errs.ValidationError("Ungültige Eingabe");
	const s = input.smtp || {};
	const smtp = {
		host: str(s.host, 253, "SMTP-Server"),
		port: Number(s.port),
		security: SECURITY.includes(s.security) ? s.security : "ssl",
		user: str(s.user, 254, "Benutzer"),
		from_name: str(s.from_name ?? "FloppyGuard", 80, "Absendername") || "FloppyGuard",
		from_address: str(s.from_address, 254, "Absenderadresse"),
	};
	if (smtp.host && !HOST_RE.test(smtp.host)) throw new errs.ValidationError("SMTP-Server: ungültiger Name");
	if (!Number.isInteger(smtp.port) || smtp.port < 1 || smtp.port > 65535) {
		throw new errs.ValidationError("Port muss zwischen 1 und 65535 liegen");
	}
	if (smtp.from_address && !EMAIL_RE.test(smtp.from_address)) {
		throw new errs.ValidationError("Absenderadresse ist keine gültige E-Mail-Adresse");
	}
	if (/[<>"]/.test(smtp.from_name)) throw new errs.ValidationError("Absendername: keine < > \" erlaubt");
	if (input.clear_password) smtp.password = "";
	else if (typeof s.password === "string" && s.password !== "") {
		if (s.password.length > 512 || CTRL_RE.test(s.password)) throw new errs.ValidationError("Passwort: ungültig");
		smtp.password = s.password;
	} else smtp.password = existing?.smtp?.password || "";

	const recipients = [...new Set((Array.isArray(input.recipients) ? input.recipients : []).map((r) => String(r).trim().toLowerCase()))].filter(Boolean);
	const bad = recipients.filter((r) => !EMAIL_RE.test(r) || r.length > 254);
	if (bad.length) throw new errs.ValidationError(`Ungültige Empfänger: ${bad.slice(0, 3).join(", ")}`);
	if (recipients.length > 20) throw new errs.ValidationError("Höchstens 20 Empfänger");

	const days = Number(input.expiring_days ?? DEFAULTS.expiring_days);
	if (!Number.isInteger(days) || days < 1 || days > 60) throw new errs.ValidationError("Vorwarnzeit: 1 bis 60 Tage");

	const appUrl = str(input.app_url ?? "", 300, "Adresse der App").replace(/\/+$/, "");
	if (appUrl && !/^https?:\/\/[A-Za-z0-9.-]+(:\d+)?(\/[^\s"'<>]*)?$/.test(appUrl)) {
		throw new errs.ValidationError("Adresse der App muss mit http(s):// beginnen");
	}
	const out = {
		enabled: input.enabled === true,
		app_url: appUrl,
		smtp,
		recipients,
		events: { cert_failed: input.events?.cert_failed !== false, cert_expiring: input.events?.cert_expiring !== false },
		expiring_days: days,
	};
	if (out.enabled) {
		if (!smtp.host) throw new errs.ValidationError("SMTP-Server fehlt");
		if (!smtp.from_address) throw new errs.ValidationError("Absenderadresse fehlt");
		if (!recipients.length) throw new errs.ValidationError("Mindestens einen Empfänger eintragen");
	}
	return out;
};

const writeAtomic = (data) => {
	const target = configPath();
	const tmp = path.join(path.dirname(target), `.notifications.json.${process.pid}.${Date.now()}.tmp`);
	fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
	try {
		fs.renameSync(tmp, target);
	} finally {
		fs.rmSync(tmp, { force: true });
	}
	fs.chmodSync(target, 0o600);
};

const transportFor = (smtp) =>
	nodemailer.createTransport({
		host: smtp.host,
		port: smtp.port,
		secure: smtp.security === "ssl",
		requireTLS: smtp.security === "starttls",
		ignoreTLS: smtp.security === "none",
		auth: smtp.user ? { user: smtp.user, pass: smtp.password } : undefined,
		connectionTimeout: 15000,
		greetingTimeout: 15000,
		socketTimeout: 30000,
		tls: { minVersion: "TLSv1.2" },
	});

const esc = (s) =>
	String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const LEVELS = {
	error: { color: "#d63939", soft: "#fbebeb", label: "Fehler" },
	warning: { color: "#e8590c", soft: "#fff0e6", label: "Warnung" },
	ok: { color: "#2fb344", soft: "#eaf7ec", label: "In Ordnung" },
	info: { color: "#206bc4", soft: "#e8f0fa", label: "Info" },
};

/**
 * Mail im FloppyGuard-Stil (Text + HTML): Kopf mit Marke und Status, Titel, Einleitung, Detailkarte,
 * Knopf zur passenden Seite der App. Tabellen-Layout + Inline-Styles für Outlook/Gmail, eigener Dunkelmodus.
 */
export const renderMail = ({ title, intro, rows = [], level = "info", action, appUrl, footer }) => {
	const lv = LEVELS[level] || LEVELS.info;
	const base = String(appUrl || "").replace(/\/+$/, "");
	const href = action && base ? `${base}${action.path || ""}` : null;
	const foot = footer || "Automatische Nachricht von FloppyGuard · Einstellungen → Benachrichtigungen";
	const text = [
		`FloppyGuard · ${lv.label}`,
		"",
		title,
		"",
		intro,
		"",
		...rows.map(([k, v]) => `${k}: ${v}`),
		...(href ? ["", `${action.label}: ${href}`] : []),
		"",
		`– ${foot}`,
	].join("\n");
	const rowHtml = rows
		.map(
			([k, v], idx) =>
				`<tr><td class="fg-k" style="padding:10px 14px;${idx ? "border-top:1px solid #edf0f5;" : ""}color:#6b778c;font-size:12px;white-space:nowrap;vertical-align:top;width:1%">${esc(k)}</td><td class="fg-v" style="padding:10px 14px;${idx ? "border-top:1px solid #edf0f5;" : ""}font-size:13px;color:#1d273b;word-break:break-word">${esc(v)}</td></tr>`,
		)
		.join("");
	const html = `<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark">
<title>${esc(title)}</title>
<style>
@media (prefers-color-scheme: dark) {
  .fg-bg { background:#0f141c !important; }
  .fg-card { background:#182030 !important; border-color:#263247 !important; }
  .fg-title, .fg-v, .fg-intro { color:#e6ebf2 !important; }
  .fg-k, .fg-muted { color:#97a3b6 !important; }
  .fg-details { background:#121a27 !important; border-color:#263247 !important; }
  .fg-details td { border-color:#263247 !important; }
}
@media (max-width:600px) { .fg-pad { padding-left:18px !important; padding-right:18px !important; } }
</style></head>
<body class="fg-bg" style="margin:0;padding:0;background:#eef1f6;-webkit-font-smoothing:antialiased">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">${esc(intro).slice(0, 140)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="fg-bg" style="background:#eef1f6;padding:28px 12px">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:580px">
<tr><td style="padding:0 4px 14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
<td style="font-size:15px;font-weight:700;letter-spacing:-.01em;color:#1d273b" class="fg-title"><span style="display:inline-block;width:22px;height:22px;line-height:22px;border-radius:6px;background:#206bc4;color:#fff;text-align:center;font-size:12px;margin-right:8px;vertical-align:1px">FG</span>FloppyGuard</td>
<td align="right"><span style="display:inline-block;padding:4px 10px;border-radius:999px;background:${lv.soft};color:${lv.color};font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase">${lv.label}</span></td>
</tr></table></td></tr>
<tr><td class="fg-card" style="background:#ffffff;border:1px solid #e3e7ee;border-radius:14px;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
<tr><td style="height:4px;background:${lv.color};line-height:4px;font-size:0">&nbsp;</td></tr>
<tr><td class="fg-pad" style="padding:26px 30px 4px"><h1 class="fg-title" style="margin:0;font-size:21px;line-height:1.3;font-weight:700;letter-spacing:-.02em;color:#1d273b">${esc(title)}</h1></td></tr>
<tr><td class="fg-pad fg-intro" style="padding:10px 30px 6px;font-size:14px;line-height:1.6;color:#3a4558">${esc(intro).replace(/\n/g, "<br>")}</td></tr>
${rows.length ? `<tr><td class="fg-pad" style="padding:12px 30px 4px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="fg-details" style="background:#f7f9fc;border:1px solid #edf0f5;border-radius:10px;border-collapse:separate">${rowHtml}</table></td></tr>` : ""}
${href ? `<tr><td class="fg-pad" style="padding:20px 30px 4px"><a href="${esc(href)}" style="display:inline-block;padding:11px 20px;border-radius:8px;background:#206bc4;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none">${esc(action.label)} →</a></td></tr>` : ""}
<tr><td style="padding:22px 30px 0;font-size:0;line-height:0">&nbsp;</td></tr>
</table></td></tr>
<tr><td class="fg-muted" style="padding:16px 8px 0;text-align:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:1.5;color:#7b879b">${esc(foot)}${base ? `<br><a href="${esc(base)}" style="color:#7b879b">${esc(base.replace(/^https?:\/\//, ""))}</a>` : ""}</td></tr>
</table></td></tr></table></body></html>`;
	return { text, html };
};

const internalNotifications = {
	get: () => toPublic(readRaw()),

	save: (input) => {
		const existing = readRaw();
		const next = validate(input, existing);
		writeAtomic(next);
		const changed = Object.keys(next).filter((k) => JSON.stringify(next[k]) !== JSON.stringify(existing[k]));
		return { settings: toPublic(next), changed: changed.map((k) => (k === "smtp" ? "smtp" : k)) };
	},

	/**
	 * Mail an alle Empfänger. Wirft nie; meldet { ok, message }.
	 * `event` (cert_failed/cert_expiring) wird gegen die Ereignis-Schalter geprüft, `force` übergeht `enabled`.
	 */
	send: async ({ subject, title, intro, rows, level, action, event, to, force = false, transport }) => {
		const cfg = readRaw();
		if (!force && !cfg.enabled) return { ok: false, message: "Benachrichtigungen sind ausgeschaltet" };
		if (event && cfg.events[event] === false) return { ok: false, message: `Ereignis ${event} ist ausgeschaltet` };
		const recipients = to ? [to] : cfg.recipients;
		if (!cfg.smtp.host || !cfg.smtp.from_address || !recipients.length) {
			return { ok: false, message: "SMTP-Server, Absender oder Empfänger fehlen" };
		}
		const { text, html } = renderMail({ title: title || subject, intro, rows, level, action, appUrl: cfg.app_url });
		try {
			const t = transport || transportFor(cfg.smtp);
			const info = await t.sendMail({
				from: { name: cfg.smtp.from_name || "FloppyGuard", address: cfg.smtp.from_address },
				to: recipients,
				subject: `[FloppyGuard] ${subject}`,
				text,
				html,
			});
			logger.info(`Mail „${subject}“ an ${recipients.length} Empfänger verschickt (${info.messageId || "ok"})`);
			return { ok: true, message: `Verschickt an ${recipients.join(", ")}` };
		} catch (err) {
			logger.error(`Mail „${subject}“ konnte nicht verschickt werden: ${err.message}`);
			return { ok: false, message: err.message };
		}
	},

	/** Testmail mit den gespeicherten Einstellungen (auch wenn noch ausgeschaltet). */
	test: async (to, opts = {}) => {
		const target = typeof to === "string" && to.trim() ? to.trim() : null;
		if (target && !EMAIL_RE.test(target)) throw new errs.ValidationError("Ungültige Empfängeradresse");
		return internalNotifications.send({
			subject: "Testnachricht",
			title: "Testnachricht",
			intro: "Diese Mail bestätigt, dass FloppyGuard Benachrichtigungen verschicken kann.",
			rows: [["Zeit", new Date().toLocaleString("de-DE")]],
			level: "ok",
			action: { label: "FloppyGuard öffnen", path: "/" },
			to: target,
			force: true,
			...opts,
		});
	},
};

export default internalNotifications;
