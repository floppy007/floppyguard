/**
 * Cloudflare-Anbindung (Einstellungen → Cloudflare).
 *
 * Ein API-Token ("Hauptschlüssel") mit Zone:DNS:Edit + Zone:Zone:Read, die öffentlichen Adressen für A/AAAA und
 * die Vorgaben für neue Proxy-Hosts liegen in /data/cloudflare.json (0600). Der Token verlässt das Backend nie: die
 * API meldet nur `has_token` und die letzten vier Zeichen. CLOUDFLARE_API_TOKEN / CLOUDFLARE_DNS_IPV4/6 aus der
 * Umgebung gelten weiter als Rückfall.
 */
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import errs from "../lib/error.js";

export const configPath = () => process.env.FG_CLOUDFLARE_CONFIG || "/data/cloudflare.json";

export const DEFAULTS = Object.freeze({
	api_token: "",
	ipv4: "",
	ipv6: "",
	auto_new_hosts: true,
	proxied_default: false,
	allow_all_users: false,
});

// Cloudflare-Tokens sind 40 Zeichen [A-Za-z0-9_-]; etwas Spielraum für künftige Formate
const TOKEN_RE = /^[A-Za-z0-9_-]{30,200}$/;

export const isPublicAddress = (address) => {
	if (address.includes(":")) return !/^(?:fc|fd|fe80:|::1$|::$)/i.test(address);
	return !/^(?:0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(
		address,
	);
};

/** Öffentliche Adressen der Netzwerkkarten (ohne private/link-local). */
export const detectAddresses = () => {
	const all = Object.values(os.networkInterfaces())
		.flat()
		.filter((a) => a && !a.internal && isPublicAddress(a.address))
		.map((a) => a.address);
	const unique = [...new Set(all)];
	return { ipv4: unique.filter((a) => net.isIPv4(a)), ipv6: unique.filter((a) => net.isIPv6(a)) };
};

export const readRaw = () => {
	try {
		return { ...DEFAULTS, ...JSON.parse(fs.readFileSync(configPath(), "utf8")) };
	} catch {
		return { ...DEFAULTS };
	}
};

/** Token für die Synchronisierung: Einstellungen vor Umgebung. */
export const settingsToken = (raw = readRaw()) => raw.api_token || process.env.CLOUDFLARE_API_TOKEN || "";

/**
 * Adressen für die Records: eingetragene Werte, sonst Umgebung, sonst erkannt. Ist irgendeine Adresse eingetragen,
 * gelten nur die eingetragenen – so lässt sich z. B. AAAA weglassen, indem nur IPv4 eingetragen wird.
 */
export const recordAddresses = (raw = readRaw()) => {
	const fromSettings = [raw.ipv4, raw.ipv6].filter(Boolean);
	if (fromSettings.length) return fromSettings;
	const fromEnv = [process.env.CLOUDFLARE_DNS_IPV4, process.env.CLOUDFLARE_DNS_IPV6].filter(Boolean);
	if (fromEnv.length) return fromEnv;
	const detected = detectAddresses();
	return [detected.ipv4[0], detected.ipv6[0]].filter(Boolean);
};

const toPublic = (raw) => {
	const { api_token, ...rest } = raw;
	const envToken = Boolean(process.env.CLOUDFLARE_API_TOKEN);
	return {
		...rest,
		has_token: Boolean(api_token),
		token_hint: api_token ? api_token.slice(-4) : "",
		env_token: envToken,
		detected: detectAddresses(),
		effective_addresses: recordAddresses(raw),
	};
};

const addr = (v, family, field) => {
	const s = typeof v === "string" ? v.trim() : "";
	if (!s) return "";
	const ok = family === 4 ? net.isIPv4(s) : net.isIPv6(s) && /^[0-9a-fA-F:.]+$/.test(s);
	if (!ok) throw new errs.ValidationError(`${field}: keine gültige IPv${family}-Adresse`);
	if (!isPublicAddress(s)) throw new errs.ValidationError(`${field}: muss eine öffentliche Adresse sein`);
	return s;
};

/** Eingabe prüfen; der Token bleibt, wenn keiner mitkommt (außer clear_token). */
export const validate = (input, existing = DEFAULTS) => {
	if (!input || typeof input !== "object") throw new errs.ValidationError("Ungültige Eingabe");
	let token = existing.api_token || "";
	if (input.clear_token) token = "";
	else if (typeof input.api_token === "string" && input.api_token.trim() !== "") {
		token = input.api_token.trim();
		if (!TOKEN_RE.test(token)) throw new errs.ValidationError("API-Token: ungültiges Format");
	}
	return {
		api_token: token,
		ipv4: addr(input.ipv4, 4, "IPv4"),
		ipv6: addr(input.ipv6, 6, "IPv6"),
		auto_new_hosts: input.auto_new_hosts !== false,
		proxied_default: input.proxied_default === true,
		allow_all_users: input.allow_all_users === true,
	};
};

const writeAtomic = (data) => {
	const target = configPath();
	const tmp = path.join(path.dirname(target), `.cloudflare.json.${process.pid}.${Date.now()}.tmp`);
	fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
	try {
		fs.renameSync(tmp, target);
	} finally {
		fs.rmSync(tmp, { force: true });
	}
	fs.chmodSync(target, 0o600);
};

const cloudflareSettings = {
	get: () => toPublic(readRaw()),

	save: (input) => {
		const existing = readRaw();
		const next = validate(input, existing);
		writeAtomic(next);
		const changed = Object.keys(next).filter((k) => JSON.stringify(next[k]) !== JSON.stringify(existing[k]));
		return { settings: toPublic(next), changed };
	},

	/**
	 * Was der Proxy-Host-Dialog für jeden Benutzer wissen darf (kein Token, keine Adressen).
	 * @param {{isAdmin: boolean}} actor
	 */
	status: (actor) => {
		const raw = readRaw();
		const configured = Boolean(settingsToken(raw));
		const available = configured && Boolean(actor?.isAdmin || raw.allow_all_users);
		return {
			configured,
			available,
			auto_new_hosts: available && raw.auto_new_hosts,
			proxied_default: available && raw.proxied_default,
		};
	},
};

export default cloudflareSettings;
