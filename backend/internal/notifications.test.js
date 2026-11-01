import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fg-notify-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));
process.env.FG_NOTIFY_CONFIG = path.join(tmp, "notifications.json");
process.env.FG_CERT_STATE = path.join(tmp, "cert-state.json");

const { default: notify, validate, renderMail } = await import("./notifications.js");
const { default: alerts } = await import("./cert-alerts.js");

const fakeTransport = () => {
	const sent = [];
	return {
		sent,
		sendMail: async (m) => {
			sent.push(m);
			return { messageId: "<x@y>" };
		},
	};
};
const base = {
	enabled: true,
	smtp: { host: "mail.example.com", port: 465, security: "ssl", user: "u@example.com", password: "geheim", from_name: "FloppyGuard", from_address: "fg@example.com" },
	recipients: ["Admin@Example.com"],
	app_url: "https://proxy.example.com/",
};

test("validate: Pflichtfelder, Adressen, Port, Passwort bleibt", () => {
	assert.throws(() => validate({ ...base, smtp: { ...base.smtp, port: 70000 } }), /Port/);
	assert.throws(() => validate({ ...base, recipients: ["kaputt"] }), /Empfänger/);
	assert.throws(() => validate({ ...base, recipients: [] }), /Mindestens einen Empfänger/);
	assert.throws(() => validate({ ...base, smtp: { ...base.smtp, host: "a b" } }), /SMTP-Server/);
	assert.throws(() => validate({ ...base, app_url: "javascript:alert(1)" }), /http/);
	assert.throws(() => validate({ ...base, smtp: { ...base.smtp, from_name: "x<y>" } }), /Absendername/);
	const v = validate(base);
	assert.deepEqual(v.recipients, ["admin@example.com"]);
	assert.equal(v.app_url, "https://proxy.example.com");
	const kept = validate({ ...base, smtp: { ...base.smtp, password: "" } }, v);
	assert.equal(kept.smtp.password, "geheim");
	assert.equal(validate({ ...base, clear_password: true }, v).smtp.password, "");
	assert.equal(validate({ ...base, enabled: false, recipients: [] }).enabled, false, "ausgeschaltet: Empfänger optional");
});

test("save/get: Passwort verlässt das Backend nie, Datei 0600", () => {
	const { settings, changed } = notify.save(base);
	assert.equal(settings.smtp.has_password, true);
	assert.equal(settings.smtp.password, undefined);
	assert.ok(changed.includes("smtp"));
	assert.equal(fs.statSync(process.env.FG_NOTIFY_CONFIG).mode & 0o777, 0o600);
	assert.equal(JSON.stringify(notify.get()).includes("geheim"), false);
});

test("renderMail: escaped, Knopf mit App-Adresse, Text-Fassung", () => {
	const { html, text } = renderMail({ title: "<b>x</b>", intro: "a & b", rows: [["Fehler", "<script>"]], level: "error", action: { label: "Öffnen", path: "/certificates" }, appUrl: "https://proxy.example.com" });
	assert.doesNotMatch(html, /<script>|<b>x<\/b>/);
	assert.match(html, /&lt;script&gt;/);
	assert.match(html, /href="https:\/\/proxy\.example\.com\/certificates"/);
	assert.match(html, /prefers-color-scheme: dark/);
	assert.match(text, /Fehler: <script>/);
	assert.match(text, /Öffnen: https:\/\/proxy\.example\.com\/certificates/);
});

test("send: Ereignis-Schalter, aus = nichts, Fehler wirft nicht", async () => {
	const t = fakeTransport();
	notify.save({ ...base, events: { cert_failed: false, cert_expiring: true } });
	assert.equal((await notify.send({ subject: "x", intro: "y", event: "cert_failed", transport: t })).ok, false);
	assert.equal((await notify.send({ subject: "x", intro: "y", event: "cert_expiring", transport: t })).ok, true);
	assert.equal(t.sent[0].subject, "[FloppyGuard] x");
	assert.deepEqual(t.sent[0].to, ["admin@example.com"]);
	assert.deepEqual(t.sent[0].from, { name: "FloppyGuard", address: "fg@example.com" });
	notify.save({ ...base, enabled: false });
	assert.equal((await notify.send({ subject: "x", intro: "y", transport: t })).ok, false);
	const r = await notify.test(undefined, { transport: { sendMail: async () => { throw new Error("535 auth failed"); } } });
	assert.deepEqual(r, { ok: false, message: "535 auth failed" });
	assert.equal((await notify.test("other@example.com", { transport: t })).ok, true, "Test geht auch ausgeschaltet");
	assert.deepEqual(t.sent.at(-1).to, ["other@example.com"]);
	await assert.rejects(notify.test("kein-mail", { transport: t }), /Ungültige/);
	notify.save(base);
});

test("cert-alerts: erster Fehlschlag mailt, danach max. 1×/24 h, Erfolg = Entwarnung, Zustand übersteht Neustart", async () => {
	const mails = [];
	const send = async (m) => {
		mails.push(m);
		return { ok: true };
	};
	const cert = { id: 116, nice_name: "*.example.com", expires_on: "2026-11-30 13:06:54" };
	const t0 = Date.parse("2026-11-01T12:00:00Z");
	await alerts.onFailure(cert, new Error("Invalid access token"), 1, t0 + 7200000, { now: t0, notify: send });
	await alerts.onFailure(cert, new Error("Invalid access token"), 2, t0 + 14400000, { now: t0 + 3600000, notify: send });
	assert.equal(mails.length, 1, "zweiter Fehlschlag innerhalb 24 h: keine Mail");
	assert.match(mails[0].subject, /fehlgeschlagen: \*\.example\.com/);
	assert.equal(mails[0].action.path, "/certificates");
	await alerts.onFailure(cert, new Error("x"), 3, t0 + 90000000, { now: t0 + 86400000 + 1, notify: send });
	assert.equal(mails.length, 2, "nach 24 h wieder");
	const restored = alerts.restoreFailures();
	assert.equal(restored.get(116).failures, 3);
	const probs = await alerts.problems({ days: 14, now: t0, rows: [{ id: 116, nice_name: "*.example.com", provider: "letsencrypt", expires_on: cert.expires_on }] });
	assert.equal(probs[0].kind, "failed");
	assert.match(probs[0].error, /x/);
	await alerts.onSuccess({ ...cert, expires_on: "2027-01-30 18:00:00" }, { now: t0 + 90000000, notify: send });
	assert.equal(mails.length, 3);
	assert.match(mails[2].subject, /wieder erneuert/);
	assert.equal(alerts.restoreFailures().size, 0);
	await alerts.onSuccess(cert, { notify: send });
	assert.equal(mails.length, 3, "ohne vorherigen Fehler keine Entwarnung");
});

test("cert-alerts: läuft bald ab / abgelaufen – einmal pro Tag", async () => {
	const mails = [];
	const send = async (m) => {
		mails.push(m);
		return { ok: true };
	};
	const now = Date.parse("2026-11-20T08:00:00Z");
	const rows = [
		{ id: 1, nice_name: "bald.example.com", provider: "letsencrypt", expires_on: "2026-11-25 10:00:00" },
		{ id: 2, nice_name: "weg.example.com", provider: "other", expires_on: "2026-11-01 10:00:00" },
		{ id: 3, nice_name: "gut.example.com", provider: "letsencrypt", expires_on: "2027-02-01 10:00:00" },
	];
	const probs = await alerts.problems({ days: 14, now, rows });
	assert.deepEqual(probs.map((p) => [p.id, p.kind]), [[2, "expired"], [1, "expiring"]]);
	assert.equal(await alerts.checkExpiring({ now, notify: send, rows }), true);
	assert.equal(await alerts.checkExpiring({ now: now + 3600000, notify: send, rows }), false, "gleicher Tag");
	assert.equal(mails.length, 1);
	assert.equal(mails[0].level, "error");
	assert.equal(mails[0].rows.length, 2);
});
