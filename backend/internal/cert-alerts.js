/**
 * Zertifikats-Warnungen: Erneuerung fehlgeschlagen / läuft bald ab / abgelaufen.
 *
 * Der Zustand liegt in /data/cert-renewal-state.json (übersteht Neustarts; vorher hielt nur eine Map im
 * Arbeitsspeicher die Fehlversuche, ein Fehlschlag verschwand still im Log):
 *   certs[id] = { state: "failed"|"ok", failures, error, since, last_attempt, next_attempt, last_mail_at, name }
 * Mails: beim ersten Fehlschlag, danach höchstens alle 24 h solange es klemmt, Entwarnung bei Erfolg;
 * "läuft bald ab" höchstens einmal pro Tag (Liste aller betroffenen). Die Oberfläche zeigt problems().
 */
import fs from "node:fs";
import moment from "moment";
import { ssl as logger } from "../logger.js";
import certificateModel from "../models/certificate.js";
import internalNotifications from "./notifications.js";

export const statePath = () => process.env.FG_CERT_STATE || "/data/cert-renewal-state.json";
const MAIL_EVERY_MS = 24 * 60 * 60 * 1000;

const readState = () => {
	try {
		const s = JSON.parse(fs.readFileSync(statePath(), "utf8"));
		return { certs: s.certs && typeof s.certs === "object" ? s.certs : {}, expiring_mail_day: s.expiring_mail_day || null };
	} catch {
		return { certs: {}, expiring_mail_day: null };
	}
};

const writeState = (s) => {
	const tmp = `${statePath()}.${process.pid}.tmp`;
	fs.writeFileSync(tmp, JSON.stringify(s, null, 2), { mode: 0o600 });
	fs.renameSync(tmp, statePath());
};

const certName = (c) => c?.nice_name || (Array.isArray(c?.domain_names) ? c.domain_names.join(", ") : `#${c?.id}`);
const fmt = (ms) => (ms ? new Date(ms).toLocaleString("de-DE", { timeZone: "Europe/Berlin" }) : "–");
const shortError = (msg) =>
	String(msg || "unbekannter Fehler")
		.replace(/\s+/g, " ")
		.slice(0, 600);

const internalCertAlerts = {
	/** Fehlversuche nach Neustart wiederherstellen (für das Backoff in certificate.js). */
	restoreFailures: () => {
		const out = new Map();
		for (const [id, c] of Object.entries(readState().certs)) {
			if (c.state === "failed") out.set(Number(id), { failures: c.failures || 1, nextAttempt: c.next_attempt || 0 });
		}
		return out;
	},

	onFailure: async (certificate, err, failures, nextAttempt, { now = Date.now(), notify = internalNotifications.send } = {}) => {
		const s = readState();
		const prev = s.certs[certificate.id] || {};
		const entry = {
			state: "failed",
			name: certName(certificate),
			failures,
			error: shortError(err?.message || err),
			since: prev.state === "failed" ? prev.since : now,
			last_attempt: now,
			next_attempt: nextAttempt,
			expires_on: certificate.expires_on || null,
			last_mail_at: prev.state === "failed" ? prev.last_mail_at || null : null,
		};
		const due = !entry.last_mail_at || now - entry.last_mail_at >= MAIL_EVERY_MS;
		if (due) {
			const r = await notify({
				event: "cert_failed",
				level: "error",
				subject: `Zertifikat-Erneuerung fehlgeschlagen: ${entry.name}`,
				title: "Zertifikat konnte nicht erneuert werden",
				intro:
					failures > 1
						? `Die automatische Erneuerung schlägt weiterhin fehl (${failures} Versuche). Bitte prüfen, bevor das Zertifikat abläuft.`
						: "Die automatische Erneuerung ist fehlgeschlagen. FloppyGuard versucht es weiter, bitte trotzdem prüfen.",
				rows: [
					["Zertifikat", `${entry.name} (#${certificate.id})`],
					["Läuft ab", certificate.expires_on ? moment(certificate.expires_on).format("DD.MM.YYYY HH:mm") : "–"],
					["Fehler", entry.error],
					["Fehlschlag seit", fmt(entry.since)],
					["Nächster Versuch", fmt(nextAttempt)],
				],
				action: { label: "Zertifikate öffnen", path: "/certificates" },
			});
			if (r.ok) entry.last_mail_at = now;
		}
		s.certs[certificate.id] = entry;
		writeState(s);
		return entry;
	},

	onSuccess: async (certificate, { now = Date.now(), notify = internalNotifications.send } = {}) => {
		const s = readState();
		const prev = s.certs[certificate.id];
		if (!prev) return null;
		delete s.certs[certificate.id];
		writeState(s);
		if (prev.state === "failed") {
			await notify({
				event: "cert_failed",
				level: "ok",
				subject: `Zertifikat wieder erneuert: ${certName(certificate)}`,
				title: "Zertifikat wieder in Ordnung",
				intro: "Die Erneuerung hat jetzt geklappt.",
				rows: [
					["Zertifikat", `${certName(certificate)} (#${certificate.id})`],
					["Gültig bis", certificate.expires_on ? moment(certificate.expires_on).format("DD.MM.YYYY HH:mm") : "–"],
					["Fehlschlag seit", fmt(prev.since)],
					["Behoben", fmt(now)],
				],
				action: { label: "Zertifikate öffnen", path: "/certificates" },
			});
		}
		return prev;
	},

	/** Zertifikat gelöscht → Zustand vergessen. */
	forget: (id) => {
		const s = readState();
		if (s.certs[id]) {
			delete s.certs[id];
			writeState(s);
		}
	},

	/**
	 * Alles, was die Oberfläche als Warnung zeigt: fehlgeschlagene Erneuerungen, abgelaufene und bald ablaufende
	 * Zertifikate (Let's Encrypt und eigene). `days` = Vorwarnzeit.
	 */
	problems: async ({ days = internalNotifications.get().expiring_days, now = Date.now(), rows } = {}) => {
		const certs =
			rows ||
			(await certificateModel
				.query()
				.where("is_deleted", 0)
				.select("id", "nice_name", "domain_names", "provider", "expires_on"));
		const state = readState().certs;
		const limit = now + days * 86400000;
		const out = [];
		for (const c of certs) {
			const exp = c.expires_on ? moment(c.expires_on).valueOf() : null;
			const failed = state[c.id]?.state === "failed" ? state[c.id] : null;
			const expired = exp !== null && exp <= now;
			const expiring = exp !== null && !expired && exp <= limit;
			if (!failed && !expired && !expiring) continue;
			out.push({
				id: c.id,
				name: certName(c),
				provider: c.provider,
				expires_on: c.expires_on,
				days_left: exp === null ? null : Math.floor((exp - now) / 86400000),
				kind: expired ? "expired" : failed ? "failed" : "expiring",
				error: failed?.error || null,
				failures: failed?.failures || 0,
				since: failed?.since || null,
				next_attempt: failed?.next_attempt || null,
			});
		}
		const order = { expired: 0, failed: 1, expiring: 2 };
		return out.sort((a, b) => order[a.kind] - order[b.kind] || (a.days_left ?? 0) - (b.days_left ?? 0));
	},

	/** Tägliche Mail "läuft bald ab / abgelaufen" (höchstens einmal pro Kalendertag). */
	checkExpiring: async ({ now = Date.now(), notify = internalNotifications.send, rows } = {}) => {
		const day = moment(now).format("YYYY-MM-DD");
		const s = readState();
		if (s.expiring_mail_day === day) return false;
		const list = (await internalCertAlerts.problems({ now, rows })).filter((p) => p.kind !== "failed");
		if (!list.length) return false;
		const r = await notify({
			event: "cert_expiring",
			level: list.some((p) => p.kind === "expired") ? "error" : "warning",
			subject: list.some((p) => p.kind === "expired")
				? `Zertifikat abgelaufen (${list.length})`
				: `Zertifikat läuft bald ab (${list.length})`,
			title: "Zertifikate laufen ab",
			intro: "Diese Zertifikate sind abgelaufen oder laufen bald ab:",
			rows: list.map((p) => [
				p.name,
				p.kind === "expired"
					? `abgelaufen am ${moment(p.expires_on).format("DD.MM.YYYY")}`
					: `noch ${p.days_left} Tag(e), bis ${moment(p.expires_on).format("DD.MM.YYYY")}`,
			]),
			action: { label: "Zertifikate öffnen", path: "/certificates" },
		});
		if (r.ok) {
			s.expiring_mail_day = day;
			writeState(s);
		}
		return r.ok;
	},

	initTimer: () => {
		const run = () => internalCertAlerts.checkExpiring().catch((err) => logger.error(`Ablauf-Warnung: ${err.message}`));
		// unref: die Warn-Timer halten keinen Prozess (Tests, Skripte) allein am Leben
		setTimeout(run, 60 * 1000).unref();
		setInterval(run, 60 * 60 * 1000).unref();
	},
};

export default internalCertAlerts;
