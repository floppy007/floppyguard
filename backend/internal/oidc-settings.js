import fs from "node:fs";
import path from "node:path";
import errs from "../lib/error.js";
import { express as logger } from "../logger.js";

// Verwaltung der SSO-Einstellungen (OpenID Connect) über die Oberfläche.
//
// Die Einstellungen liegen weiterhin in der Datei, die internal/oidc.js liest
// (Standard /data/oidc.json). oidc.js erkennt Änderungen an der mtime, ein
// Neustart ist also nicht nötig.
//
//   * Das Client-Secret verlässt den Server nie. Die Oberfläche bekommt nur
//     `has_client_secret`; ein leeres Feld beim Speichern behält das alte.
//   * Geschrieben wird atomar (Temp-Datei + rename) mit Modus 0600.

export const configPath = () => process.env.OIDC_CONFIG_PATH || "/data/oidc.json";

export const DEFAULTS = Object.freeze({
	enabled: false,
	label: "Mit Firmenkonto anmelden",
	issuer: "",
	client_id: "",
	redirect_uri: "",
	required_group: "",
	groups_claim: "groups",
	scopes: "openid profile email",
	expiry: "1d",
});

// Issuer ohne abschließende Slashes, damit Vergleiche mit dem Discovery-Dokument greifen.
export const normalizeIssuer = (value) =>
	String(value || "")
		.trim()
		.replace(/\/+$/, "");

const FIELDS = Object.keys(DEFAULTS);
// Nur Einheiten, die überall gleich gelesen werden. Die Lebensdauer wird
// daraus einmal in Sekunden berechnet (expirySeconds) und so an JWT, sso_exp
// und die Antwort an die Oberfläche gegeben. Früher erlaubte "M"/"Q" las
// jsonwebtoken (ms) als Minuten bzw. gar nicht.
const EXPIRY_RE = /^[1-9][0-9]{0,4}(y|w|d|h|m)$/;
const EXPIRY_UNIT_SECONDS = { y: 365 * 86400, w: 7 * 86400, d: 86400, h: 3600, m: 60 };
const EXPIRY_MAX_SECONDS = 366 * 86400;

/**
 * Wandelt eine Gültigkeitsdauer wie "8h" oder "1d" in Sekunden um.
 * Liefert null, wenn der Wert ungültig ist oder über einem Jahr liegt.
 */
export const expirySeconds = (value) => {
	if (typeof value !== "string") return null;
	const match = value.match(EXPIRY_RE);
	if (!match) return null;
	const seconds = Number.parseInt(match[0], 10) * EXPIRY_UNIT_SECONDS[match[1]];
	return seconds > 0 && seconds <= EXPIRY_MAX_SECONDS ? seconds : null;
};
// Kein Steuerzeichen, keine Zeilenumbrüche – die Werte landen in URLs und Logs.
// biome-ignore lint/suspicious/noControlCharactersInRegex: gewollt
const CTRL_RE = /[\u0000-\u001f\u007f]/;

const readRaw = () => {
	try {
		const parsed = JSON.parse(fs.readFileSync(configPath(), "utf8"));
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
	} catch (err) {
		if (err.code !== "ENOENT") {
			logger.error(`OIDC-Einstellungen: ${configPath()} nicht lesbar: ${err.message}`);
		}
		return {};
	}
};

const isHttpsUrl = (value, { allowHttpLocal = false } = {}) => {
	let url;
	try {
		url = new URL(value);
	} catch {
		return false;
	}
	if (url.username || url.password || url.hash) {
		return false;
	}
	if (url.protocol === "https:") {
		return true;
	}
	return allowHttpLocal && url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
};

const toPublic = (raw) => {
	const out = {};
	for (const key of FIELDS) {
		out[key] = typeof raw[key] === typeof DEFAULTS[key] ? raw[key] : DEFAULTS[key];
	}
	out.has_client_secret = typeof raw.client_secret === "string" && raw.client_secret.length > 0;
	out.config_path = configPath();
	return out;
};

/**
 * Prüft und normalisiert eine Eingabe. Wirft ValidationError mit einer
 * verständlichen Meldung.
 */
export const validate = (input, existing) => {
	if (!input || typeof input !== "object" || Array.isArray(input)) {
		throw new errs.ValidationError("Ungültige Einstellungen");
	}
	const out = {};
	for (const key of FIELDS) {
		const value = Object.hasOwn(input, key) ? input[key] : (existing[key] ?? DEFAULTS[key]);
		if (key === "enabled") {
			if (typeof value !== "boolean") throw new errs.ValidationError("„Aktiviert“ muss ein Wahrheitswert sein");
			out.enabled = value;
			continue;
		}
		if (typeof value !== "string") throw new errs.ValidationError(`Feld ${key} muss Text sein`);
		const trimmed = value.trim();
		if (CTRL_RE.test(trimmed)) throw new errs.ValidationError(`Feld ${key} enthält Steuerzeichen`);
		if (trimmed.length > 512) throw new errs.ValidationError(`Feld ${key} ist zu lang`);
		out[key] = trimmed;
	}

	out.issuer = normalizeIssuer(out.issuer);
	if (!out.label) out.label = DEFAULTS.label;
	if (out.label.length > 80)
		throw new errs.ValidationError("Die Button-Beschriftung darf höchstens 80 Zeichen haben");
	if (!out.groups_claim) out.groups_claim = DEFAULTS.groups_claim;
	if (!/^[A-Za-z0-9_.:/-]{1,100}$/.test(out.groups_claim)) {
		throw new errs.ValidationError("Der Gruppen-Claim enthält ungültige Zeichen");
	}
	if (!out.scopes) out.scopes = DEFAULTS.scopes;
	const scopes = out.scopes.split(/\s+/).filter(Boolean);
	if (!scopes.includes("openid") || scopes.some((s) => !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(s))) {
		throw new errs.ValidationError("Die Scopes müssen „openid“ enthalten und dürfen nur gültige Zeichen enthalten");
	}
	out.scopes = scopes.join(" ");
	if (expirySeconds(out.expiry) === null) {
		throw new errs.ValidationError("Gültigkeitsdauer im Format z. B. 8h, 1d oder 2w angeben (höchstens 1 Jahr)");
	}
	if (out.issuer && !isHttpsUrl(out.issuer, { allowHttpLocal: true })) {
		throw new errs.ValidationError("Die Issuer-URL muss mit https:// beginnen");
	}
	if (out.redirect_uri) {
		if (!isHttpsUrl(out.redirect_uri, { allowHttpLocal: true })) {
			throw new errs.ValidationError("Die Redirect-URI muss mit https:// beginnen");
		}
		if (!new URL(out.redirect_uri).pathname.endsWith("/api/oidc/callback")) {
			throw new errs.ValidationError("Die Redirect-URI muss auf /api/oidc/callback enden");
		}
	}

	// Secret: nur ersetzen, wenn ein neues übergeben wurde.
	let secret = typeof existing.client_secret === "string" ? existing.client_secret : "";
	if (typeof input.client_secret === "string" && input.client_secret.trim() !== "") {
		secret = input.client_secret.trim();
		if (CTRL_RE.test(secret) || secret.length > 512) {
			throw new errs.ValidationError("Das Client-Secret ist ungültig");
		}
	}
	if (input.clear_client_secret === true) {
		secret = "";
	}
	out.client_secret = secret;

	if (out.enabled) {
		const missing = [
			["issuer", "Issuer-URL"],
			["client_id", "Client-ID"],
			["client_secret", "Client-Secret"],
			["redirect_uri", "Redirect-URI"],
			["required_group", "Berechtigte Gruppe"],
		]
			.filter(([key]) => !out[key])
			.map(([, name]) => name);
		if (missing.length) {
			throw new errs.ValidationError(`Zum Aktivieren fehlen: ${missing.join(", ")}`);
		}
	}
	return out;
};

const writeAtomic = (data) => {
	const target = configPath();
	const dir = path.dirname(target);
	const tmp = path.join(dir, `.oidc.json.${process.pid}.${Date.now()}.tmp`);
	fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
	try {
		fs.renameSync(tmp, target);
	} catch (err) {
		fs.rmSync(tmp, { force: true });
		throw err;
	}
	fs.chmodSync(target, 0o600);
};

const internalOidcSettings = {
	get: () => toPublic(readRaw()),

	/**
	 * @returns {{ settings: object, changed: string[] }}
	 */
	save: (input) => {
		const existing = readRaw();
		const next = validate(input, existing);
		const changed = Object.keys(next).filter((key) => existing[key] !== next[key]);
		// Unbekannte Felder aus der Datei (manuelle Ergänzungen) bleiben erhalten.
		writeAtomic({ ...existing, ...next });
		return { settings: toPublic({ ...existing, ...next }), changed };
	},

	/**
	 * Holt das Discovery-Dokument des Anbieters, ohne etwas zu speichern.
	 */
	test: async (issuerInput) => {
		const issuer = normalizeIssuer(issuerInput || readRaw().issuer);
		if (!issuer || !isHttpsUrl(issuer, { allowHttpLocal: true })) {
			throw new errs.ValidationError("Bitte eine gültige https-Issuer-URL angeben");
		}
		let res;
		try {
			res = await fetch(`${issuer}/.well-known/openid-configuration`, {
				redirect: "error",
				signal: AbortSignal.timeout(8000),
			});
		} catch (err) {
			return { ok: false, message: `Anbieter nicht erreichbar: ${err.cause?.code || err.name}` };
		}
		if (!res.ok) {
			return { ok: false, message: `Discovery antwortete mit HTTP ${res.status}` };
		}
		let doc;
		try {
			doc = await res.json();
		} catch {
			return { ok: false, message: "Discovery-Dokument ist kein gültiges JSON" };
		}
		const docIssuer = normalizeIssuer(doc.issuer);
		if (docIssuer !== issuer) {
			return { ok: false, message: "Issuer im Discovery-Dokument stimmt nicht mit der URL überein" };
		}
		const required = ["authorization_endpoint", "token_endpoint", "userinfo_endpoint"];
		const missing = required.filter((key) => typeof doc[key] !== "string");
		if (missing.length) {
			return { ok: false, message: `Discovery-Dokument unvollständig: ${missing.join(", ")}` };
		}
		return { ok: true, message: "Anbieter erreichbar, Discovery-Dokument gültig" };
	},
};

export default internalOidcSettings;
