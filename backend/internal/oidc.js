import crypto from "node:crypto";
import fs from "node:fs";
import errs from "../lib/error.js";
import { express as logger } from "../logger.js";
import authModel from "../models/auth.js";
import TokenModel from "../models/token.js";
import userModel from "../models/user.js";
import userPermissionModel from "../models/user_permission.js";
import internalAuditLog from "./audit-log.js";
import { expirySeconds } from "./oidc-settings.js";

// Anmeldung über einen OpenID-Connect-Anbieter (hier: Authentik unter
// https://sso.comnic-it.de). Bewusst schlank gehalten:
//
//   * Es gibt GENAU EINE Berechtigungsgruppe. Wer darin ist, darf herein und
//     ist Admin; ein Konto wird bei der ersten Anmeldung selbst angelegt.
//   * Die Identität kommt aus dem userinfo-Endpunkt des Anbieters, nicht aus
//     dem ID-Token. Die Verbindung dorthin ist TLS-geprüft, damit ist eine
//     eigene Signaturprüfung nicht nötig (OIDC Core 3.1.3.7).
//   * SSO-Konten bekommen keinen Passwort-Datensatz. Sie können sich also
//     ausschließlich über den Anbieter anmelden.
//   * Eine lokal eingerichtete 2FA wird bei SSO NICHT zusätzlich abgefragt —
//     die Faktoren verwaltet der Anbieter.

const CONFIG_PATH = process.env.OIDC_CONFIG_PATH || "/data/oidc.json";
const DISCOVERY_TTL_MS = 10 * 60 * 1000;
const STATE_TTL_MS = 10 * 60 * 1000;
const RESULT_TTL_MS = 60 * 1000;
const FETCH_TIMEOUT_MS = 10 * 1000;

let configCache = null;
let discoveryCache = null;

// state und PKCE-Prüfwert liegen NICHT serverseitig, sondern verschlüsselt in
// einem HttpOnly-Cookie des Browsers, der die Anmeldung begonnen hat. Damit ist
// der Rückweg an genau diesen Browser gebunden (kein Login-CSRF), und es gibt
// keine gemeinsame Tabelle, aus der Fremde offene Anmeldungen verdrängen
// könnten. Der Schlüssel lebt nur im Prozess: Ein Neustart mitten in einer
// Anmeldung bedeutet nur, dass der Benutzer sie wiederholt.
const SEAL_KEY = crypto.randomBytes(32);

const seal = (kind, payload) => {
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv("aes-256-gcm", SEAL_KEY, iv);
	cipher.setAAD(Buffer.from(kind));
	const body = Buffer.concat([cipher.update(JSON.stringify({ ...payload, at: Date.now() }), "utf8"), cipher.final()]);
	return base64url(Buffer.concat([iv, cipher.getAuthTag(), body]));
};

const unseal = (kind, value, ttlMs) => {
	if (typeof value !== "string" || !value || value.length > 8192) {
		return null;
	}
	try {
		const raw = Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
		if (raw.length < 29) {
			return null;
		}
		const decipher = crypto.createDecipheriv("aes-256-gcm", SEAL_KEY, raw.subarray(0, 12));
		decipher.setAAD(Buffer.from(kind));
		decipher.setAuthTag(raw.subarray(12, 28));
		const plain = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
		const data = JSON.parse(plain);
		if (!data || typeof data.at !== "number" || Date.now() - data.at > ttlMs || data.at > Date.now() + 60000) {
			return null;
		}
		return data;
	} catch {
		return null;
	}
};

const safeEqual = (a, b) => {
	const ba = Buffer.from(String(a));
	const bb = Buffer.from(String(b));
	return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
};

// Abgewiesene Anmeldungen tragen einen festen Grund-Code. Die Anmeldeseite
// zeigt nur dazu passende, übersetzte Texte an - nie freien Text aus der URL.
const rejected = (reason, message) => {
	const err = new errs.AuthError(message);
	err.reason = reason;
	return err;
};

const readConfig = () => {
	let stat;
	try {
		stat = fs.statSync(CONFIG_PATH);
	} catch {
		return { enabled: false };
	}
	if (configCache && configCache.mtimeMs === stat.mtimeMs) {
		return configCache.value;
	}
	let parsed;
	try {
		parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
	} catch (err) {
		logger.error(`OIDC: ${CONFIG_PATH} ist kein gültiges JSON: ${err.message}`);
		return { enabled: false };
	}
	const value = {
		enabled: parsed.enabled === true,
		label: parsed.label || "Mit Firmenkonto anmelden",
		issuer: String(parsed.issuer || "").replace(/\/+$/, ""),
		client_id: parsed.client_id || "",
		client_secret: parsed.client_secret || "",
		redirect_uri: parsed.redirect_uri || "",
		required_group: parsed.required_group || "",
		groups_claim: parsed.groups_claim || "groups",
		scopes: parsed.scopes || "openid profile email",
		expiry: expirySeconds(parsed.expiry) === null ? "1d" : parsed.expiry,
	};
	if (parsed.expiry && value.expiry !== parsed.expiry) {
		logger.warn(`OIDC: ungültige Gültigkeitsdauer ${JSON.stringify(parsed.expiry)}, verwende 1d`);
	}
	configCache = { mtimeMs: stat.mtimeMs, value };
	return value;
};

const isConfigured = (cfg) =>
	cfg.enabled && !!cfg.issuer && !!cfg.client_id && !!cfg.client_secret && !!cfg.redirect_uri && !!cfg.required_group;

const discovery = async (cfg) => {
	if (discoveryCache && discoveryCache.issuer === cfg.issuer && Date.now() - discoveryCache.at < DISCOVERY_TTL_MS) {
		return discoveryCache.doc;
	}
	const res = await fetch(`${cfg.issuer}/.well-known/openid-configuration`, {
		redirect: "error",
		signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
	});
	if (!res.ok) {
		throw new Error(`Discovery antwortete mit HTTP ${res.status}`);
	}
	const doc = await res.json();
	if (String(doc.issuer || "").replace(/\/+$/, "") !== cfg.issuer) {
		throw new Error(`Issuer stimmt nicht: ${doc.issuer} statt ${cfg.issuer}`);
	}
	discoveryCache = { issuer: cfg.issuer, at: Date.now(), doc };
	return doc;
};

const base64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const groupsFrom = (claims, claimName) => {
	let groups = claims[claimName];
	if (typeof groups === "string") {
		groups = [groups];
	}
	return Array.isArray(groups) ? groups.map((g) => String(g).trim().toLowerCase()) : [];
};

// Markiert ein Konto als SSO-Konto (Auth-Typ "oidc", ohne Secret). Die
// Benutzerliste zeigt daran die Herkunft. Passwort- und 2FA-Prüfungen lesen
// ausschließlich Einträge vom Typ "password", ein "oidc"-Eintrag öffnet also
// keinen weiteren Anmeldeweg.
const markSso = async (userId, claims) => {
	const meta = { sub: String(claims.sub || ""), last_login: new Date().toISOString() };
	const row = await authModel.query().where("user_id", userId).andWhere("type", "oidc").first();
	if (row) {
		await authModel.query().patch({ meta, is_deleted: 0 }).where("id", row.id);
	} else {
		await authModel.query().insert({ user_id: userId, type: "oidc", secret: "", meta });
	}
};

// Entscheidet, ob eine Anmeldung mit `claims` an ein bestehendes Konto (per
// E-Mail gefunden) gebunden werden darf. Gibt null zurück oder einen Grund für
// die Ablehnung. Regeln:
//   * Ein Konto, das schon an eine Anbieter-Identität (sub) gebunden ist,
//     nimmt nur genau diese an — eine geänderte E-Mail beim Anbieter übernimmt
//     sonst ein fremdes Konto.
//   * Ein noch nicht verknüpftes Konto mit lokalem Passwort (z. B. der lokale
//     Notfall-Admin mit 2FA) wird NIE automatisch verknüpft.
//   * Meldet der Anbieter die E-Mail ausdrücklich als unbestätigt, wird nicht
//     verknüpft.
export const ssoLinkRefusal = ({ storedSub, hasPassword, claims }) => {
	const sub = String(claims?.sub || "");
	const bound = String(storedSub || "");
	if (bound) {
		return bound === sub ? null : "Konto ist an eine andere Anbieter-Identität gebunden";
	}
	if (hasPassword) {
		return "Konto hat ein lokales Passwort und ist nicht mit dem Anbieter verknüpft";
	}
	if (claims?.email_verified === false) {
		return "E-Mail-Adresse ist beim Anbieter nicht bestätigt";
	}
	return null;
};

// System audit entry for SSO events: account created / raised to admin, every
// successful SSO sign-in ("sso-login") and every refused link attempt
// ("sso-refused" — the security-relevant one: someone presented a provider
// identity for an account it may not take over). The entry is filed under the
// account concerned; meta carries the e-mail, the provider subject and, for a
// refusal, the reason — never tokens. A failed write is only logged.
async function auditSso(userId, action, email, note, extra = {}) {
	try {
		await internalAuditLog.add(
			{ token: { getUserId: () => userId } },
			{
				user_id: userId,
				action,
				object_type: "user",
				object_id: userId,
				meta: { name: `${email} (${note})`, ...extra },
			},
		);
	} catch (err) {
		logger.warn(`OIDC audit log failed: ${err.message}`);
	}
}

const internalOidc = {
	status: () => {
		const cfg = readConfig();
		return { enabled: isConfigured(cfg), label: cfg.label };
	},

	/**
	 * Baut die Adresse des Anbieters. `flow` gehört in ein HttpOnly-Cookie und
	 * muss beim Rückweg wieder vorgelegt werden.
	 * @returns {Promise<{url: String, flow: String}>}
	 */
	buildAuthorizeUrl: async () => {
		const cfg = readConfig();
		if (!isConfigured(cfg)) {
			throw new errs.ValidationError("Die Anmeldung über den Anbieter ist nicht eingerichtet");
		}
		const doc = await discovery(cfg);
		const verifier = base64url(crypto.randomBytes(48));
		const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
		const state = base64url(crypto.randomBytes(24));

		const flow = seal("flow", { state, verifier });

		const url = new URL(doc.authorization_endpoint);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("client_id", cfg.client_id);
		url.searchParams.set("redirect_uri", cfg.redirect_uri);
		url.searchParams.set("scope", cfg.scopes);
		url.searchParams.set("state", state);
		url.searchParams.set("code_challenge", challenge);
		url.searchParams.set("code_challenge_method", "S256");
		return { url: url.toString(), flow };
	},

	/**
	 * Löst den Code beim Anbieter ein und gibt ein FloppyGuard-Token zurück.
	 * @param   {String} code
	 * @param   {String} state
	 * @param   {String} flowCookie  Wert des Cookies aus buildAuthorizeUrl()
	 * @returns {Promise<{token: String, expires: String}>}
	 */
	completeLogin: async (code, state, flowCookie) => {
		const cfg = readConfig();
		if (!isConfigured(cfg)) {
			throw new errs.ValidationError("Die Anmeldung über den Anbieter ist nicht eingerichtet");
		}
		const parked = unseal("flow", flowCookie, STATE_TTL_MS);
		if (!parked || typeof parked.state !== "string" || !safeEqual(parked.state, state)) {
			throw rejected("expired", "Die Anmeldung ist abgelaufen, bitte erneut versuchen");
		}

		const doc = await discovery(cfg);
		const body = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: cfg.redirect_uri,
			client_id: cfg.client_id,
			client_secret: cfg.client_secret,
			code_verifier: parked.verifier,
		});
		const tokenRes = await fetch(doc.token_endpoint, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body,
			redirect: "error",
			signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
		});
		if (!tokenRes.ok) {
			throw new Error(`Token-Endpunkt antwortete mit HTTP ${tokenRes.status}`);
		}
		const accessToken = (await tokenRes.json()).access_token;
		if (!accessToken) {
			throw new Error("Der Anbieter lieferte kein access_token");
		}

		const infoRes = await fetch(doc.userinfo_endpoint, {
			headers: { Authorization: `Bearer ${accessToken}` },
			redirect: "error",
			signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
		});
		if (!infoRes.ok) {
			throw new Error(`userinfo antwortete mit HTTP ${infoRes.status}`);
		}
		const claims = await infoRes.json();

		const email = String(claims.email || "")
			.toLowerCase()
			.trim();
		if (!email) {
			throw rejected("noemail", "Der Anbieter lieferte keine E-Mail-Adresse");
		}
		const groups = groupsFrom(claims, cfg.groups_claim);
		if (!groups.includes(cfg.required_group.toLowerCase())) {
			logger.info(`OIDC: ${email} abgewiesen, Gruppe ${cfg.required_group} fehlt`);
			throw rejected("group", "Dieses Konto ist für FloppyGuard nicht freigegeben");
		}

		const user = await internalOidc.ensureUser(email, claims);
		// Lebensdauer einmal in Sekunden berechnen: JWT-exp, sso_exp und das
		// gemeldete `expires` stammen so aus demselben Wert.
		const lifetime = expirySeconds(cfg.expiry);
		if (lifetime === null) {
			throw new Error(`Ungültige Gültigkeitsdauer: ${cfg.expiry}`);
		}
		const expiry = new Date(Date.now() + lifetime * 1000);
		// sso_exp begrenzt auch alle späteren Verlängerungen über GET /tokens:
		// Danach muss der Benutzer erneut über den Anbieter, der dabei die
		// Gruppe neu prüft.
		const signed = await TokenModel().create({
			iss: "oidc",
			attrs: { id: user.id, sso_exp: Math.floor(expiry.getTime() / 1000) },
			scope: ["user"],
			expiresIn: lifetime,
		});
		logger.info(`OIDC: ${email} angemeldet`);
		return { token: signed.token, expires: expiry.toISOString() };
	},

	/**
	 * Verpackt das Ergebnis für das einmalige Abholen über POST /oidc/exchange.
	 * Das Token steht damit nie in der URL.
	 */
	sealResult: (result) => seal("result", { token: result.token, expires: result.expires }),

	/**
	 * @returns {{token: String, expires: String} | null}
	 */
	openResult: (value) => {
		const data = unseal("result", value, RESULT_TTL_MS);
		if (!data || typeof data.token !== "string" || typeof data.expires !== "string") {
			return null;
		}
		return { token: data.token, expires: data.expires };
	},

	/**
	 * Findet das Konto zur E-Mail-Adresse oder legt es als Admin an. Wer in der
	 * Gruppe ist, ist Admin - auch ein bestehendes Konto wird dazu angehoben.
	 */
	ensureUser: async (email, claims) => {
		const sub = String(claims.sub || "");
		// Zuerst über die gebundene Anbieter-Identität suchen: Ein bereits
		// verknüpftes Konto bleibt das eigene, auch wenn sich die E-Mail beim
		// Anbieter ändert.
		let existing = null;
		if (sub) {
			const oidcRows = await authModel.query().where("type", "oidc").andWhere("is_deleted", 0);
			const bound = oidcRows.find((r) => String(r.meta?.sub || "") === sub);
			if (bound) {
				existing = await userModel.query().where("id", bound.user_id).andWhere("is_deleted", 0).first();
			}
		}
		if (!existing) {
			existing = await userModel.query().where("email", email).andWhere("is_deleted", 0).first();
			if (existing) {
				const oidcRow = await authModel
					.query()
					.where("user_id", existing.id)
					.andWhere("type", "oidc")
					.andWhere("is_deleted", 0)
					.first();
				const passwordRow = await authModel
					.query()
					.where("user_id", existing.id)
					.andWhere("type", "password")
					.andWhere("is_deleted", 0)
					.first();
				const refusal = ssoLinkRefusal({
					storedSub: oidcRow?.meta?.sub,
					hasPassword: !!passwordRow?.secret,
					claims,
				});
				if (refusal) {
					logger.warn(`OIDC: ${email} abgewiesen: ${refusal}`);
					await auditSso(existing.id, "sso-refused", email, `SSO abgewiesen: ${refusal}`, {
						sub,
						reason: refusal,
					});
					throw rejected("linked", "Dieses Konto ist für FloppyGuard nicht freigegeben");
				}
			}
		}

		if (existing) {
			if (existing.is_disabled) {
				await auditSso(existing.id, "sso-refused", email, "SSO abgewiesen: Konto deaktiviert", {
					sub,
					reason: "disabled",
				});
				throw rejected("disabled", "Dieses Konto ist deaktiviert");
			}
			const roles = Array.isArray(existing.roles) ? existing.roles : [];
			if (!roles.includes("admin")) {
				await userModel
					.query()
					.patch({ roles: [...roles, "admin"] })
					.where("id", existing.id);
				logger.info(`OIDC: ${email} auf Admin angehoben`);
				await auditSso(existing.id, "updated", email, "SSO: Admin-Rolle");
			}
			await markSso(existing.id, claims);
			await auditSso(existing.id, "sso-login", email, "SSO-Anmeldung", { sub });
			return existing;
		}

		const name = String(claims.name || claims.preferred_username || email.split("@")[0]).trim();
		const created = await userModel.query().insertAndFetch({
			email,
			name,
			nickname: String(claims.given_name || name).trim(),
			avatar: "",
			roles: ["admin"],
			is_disabled: 0,
		});
		await userPermissionModel.query().insert({
			user_id: created.id,
			visibility: "all",
			proxy_hosts: "manage",
			redirection_hosts: "manage",
			dead_hosts: "manage",
			streams: "manage",
			access_lists: "manage",
			certificates: "manage",
		});
		await markSso(created.id, claims);
		logger.info(`OIDC: Konto für ${email} angelegt (Admin)`);
		await auditSso(created.id, "created", email, "SSO: Konto angelegt, Admin");
		await auditSso(created.id, "sso-login", email, "SSO-Anmeldung", { sub });
		return created;
	},
};

export const _testExports = { seal, unseal };

export default internalOidc;
