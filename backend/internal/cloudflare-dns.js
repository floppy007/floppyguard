import certificateModel from "../models/certificate.js";
import proxyHostModel from "../models/proxy_host.js";
import userModel from "../models/user.js";
import { global as logger } from "../logger.js";
import { readRaw as readSettings, recordAddresses, settingsToken } from "./cloudflare-settings.js";

const API_ROOT = "https://api.cloudflare.com/client/v4";
const MANAGED_COMMENT = "Managed by FloppyGuard";

// Felder, die nur der Server setzt. Aus Client-Daten werden sie entfernt,
// sonst könnte ein Host-Besitzer fremde Record-IDs unterschieben.
const SERVER_FIELDS = ["records", "status", "error", "syncedAt"];
const CONFIG_KEYS = ["cloudflareDns", "cloudflare_dns"];
const RECORD_ID_RE = /^[0-9a-f]{32}$/;

/**
 * Wer die Synchronisierung auslöst. Nur Admins dürfen den serverweiten
 * Token (CLOUDFLARE_API_TOKEN) und Zertifikat-Tokens anderer Benutzer
 * verwenden; alle anderen nur den Token eines eigenen Zertifikats.
 *
 * @param {Access} access
 * @returns {Promise<{userId: number, isAdmin: boolean}>}
 */
const resolveActor = async (access) => {
	const userId = access?.token?.getUserId?.(0) || 0;
	if (!userId) return { userId: 0, isAdmin: false };
	const user = await userModel.query().where("id", userId).andWhere("is_deleted", 0).first();
	return { userId, isAdmin: Array.isArray(user?.roles) && user.roles.includes("admin") };
};

const tokenFromCertificate = (certificate) => {
	const credentials = certificate?.meta?.dns_provider_credentials;
	if (certificate?.meta?.dns_provider !== "cloudflare" || typeof credentials !== "string") return null;
	return credentials.match(/^\s*dns_cloudflare_api_token\s*=\s*(.+?)\s*$/m)?.[1] || null;
};

/**
 * Reihenfolge: erst der Token des Cloudflare-DNS-Zertifikats des Hosts (spezifischer, trennt Rechte je Domain;
 * fremde Zertifikate nur für Admins), dann der Hauptschlüssel aus Einstellungen → Cloudflare bzw.
 * CLOUDFLARE_API_TOKEN – für Admins und, wenn dort freigegeben, für alle Benutzer.
 */
const getToken = async (host, actor) => {
	if (!actor) return null;
	if (host.certificate_id) {
		const certificate = await certificateModel.query().findById(host.certificate_id);
		if (certificate && !certificate.is_deleted && (actor.isAdmin || certificate.owner_user_id === actor.userId)) {
			const token = tokenFromCertificate(certificate);
			if (token) return token;
		}
	}
	const settings = readSettings();
	const main = settingsToken(settings);
	if (main && (actor.isAdmin || settings.allow_all_users)) return main;
	return null;
};

// A hanging Cloudflare API call must not hold a proxy-host save open forever.
const API_TIMEOUT_MS = 15 * 1000;

const api = async (token, path, options = {}) => {
	const response = await fetch(`${API_ROOT}${path}`, {
		...options,
		signal: options.signal ?? AbortSignal.timeout(API_TIMEOUT_MS),
		headers: {
			Authorization: `Bearer ${token}`,
			"Content-Type": "application/json",
			...options.headers,
		},
	});
	let payload;
	try {
		payload = await response.json();
	} catch {
		throw new Error(`Cloudflare API request failed (HTTP ${response.status}, no JSON response)`);
	}
	if (!response.ok || !payload.success) {
		throw new Error(payload.errors?.map((error) => error.message).join("; ") || "Cloudflare API request failed");
	}
	return payload.result;
};

const publicAddresses = () => recordAddresses();

const recordType = (address) => (address.includes(":") ? "AAAA" : "A");

// `cache` (candidate zone name -> zone or null) is shared across one sync so
// sibling domains don't probe the same suffixes again.
const findZone = async (token, domain, cache = new Map()) => {
	const labels = domain.split(".");
	// Start at 0: an apex domain (example.com) is its own zone. The bound keeps a bare TLD out.
	for (let index = 0; index < labels.length - 1; index += 1) {
		const name = labels.slice(index).join(".");
		if (!cache.has(name)) {
			const zones = await api(token, `/zones?name=${encodeURIComponent(name)}&status=active`);
			cache.set(name, zones[0] ?? null);
		}
		const zone = cache.get(name);
		if (zone) return zone;
	}
	throw new Error(`No Cloudflare zone is available for ${domain}`);
};

const syncRecord = async ({ token, zone, domain, type, content, proxied, recordId }) => {
	const body = { type, name: domain, content, proxied, ttl: 1, comment: MANAGED_COMMENT };
	if (
		typeof recordId === "string" &&
		RECORD_ID_RE.test(recordId) &&
		typeof zone.id === "string" &&
		RECORD_ID_RE.test(zone.id)
	) {
		// Nur einen Record ändern, der nachweislich von FloppyGuard stammt und
		// zu diesem Namen gehört. Sonst wie bei einem neuen Record verfahren.
		let existing = null;
		try {
			existing = await api(
				token,
				`/zones/${encodeURIComponent(zone.id)}/dns_records/${encodeURIComponent(recordId)}`,
			);
		} catch {
			existing = null;
		}
		if (
			existing &&
			existing.id === recordId &&
			existing.comment === MANAGED_COMMENT &&
			existing.type === type &&
			String(existing.name || "").toLowerCase() === domain.toLowerCase() &&
			(!existing.zone_id || existing.zone_id === zone.id)
		) {
			return await api(
				token,
				`/zones/${encodeURIComponent(zone.id)}/dns_records/${encodeURIComponent(recordId)}`,
				{
					method: "PUT",
					body: JSON.stringify(body),
				},
			);
		}
	}
	const records = await api(token, `/zones/${zone.id}/dns_records?type=${type}&name=${encodeURIComponent(domain)}`);
	const matching = records.find((record) => record.content === content && record.proxied === proxied);
	if (matching) return matching;
	// Ein von Hand angelegter Record, der schon auf diesen Server zeigt, wird übernommen (Proxy-Status + Kommentar);
	// einer, der woandershin zeigt, bleibt unangetastet.
	const ours = records.length === 1 && records[0].content === content ? records[0] : null;
	if (ours && RECORD_ID_RE.test(String(ours.id))) {
		return await api(token, `/zones/${zone.id}/dns_records/${encodeURIComponent(ours.id)}`, {
			method: "PUT",
			body: JSON.stringify(body),
		});
	}
	if (records.length) {
		throw new Error(
			`${domain} already has a ${type} record pointing elsewhere (${records.map((r) => r.content).join(", ")}): remove it in Cloudflare or change it to ${content}`,
		);
	}
	return await api(token, `/zones/${zone.id}/dns_records`, { method: "POST", body: JSON.stringify(body) });
};

/** Zone über ihren Namen (aus records[*].zone) – zum Löschen braucht es die Zonen-ID. */
const zoneByName = async (token, name, cache) => {
	if (!cache.has(name)) {
		const zones = await api(token, `/zones?name=${encodeURIComponent(name)}&status=active`);
		cache.set(name, zones[0] ?? null);
	}
	return cache.get(name);
};

/**
 * Löscht von FloppyGuard angelegte Records, deren ID nicht in `keepIds` steht. Gelöscht wird nur, was Cloudflare
 * selbst als unseren Record ausweist (Kommentar, Name nicht in `keepNames`). Gibt die Einträge zurück, die stehen
 * bleiben mussten (Fehler → beim nächsten Speichern erneut versuchen).
 */
const removeRecords = async (token, records, keepIds = new Set(), keepNames = new Set()) => {
	const failed = {};
	const done = new Set(keepIds);
	const zoneCache = new Map();
	for (const [key, entry] of Object.entries(records || {})) {
		const id = entry?.id;
		if (typeof id !== "string" || !RECORD_ID_RE.test(id) || done.has(id)) continue;
		done.add(id);
		try {
			const zone = entry.zone ? await zoneByName(token, String(entry.zone), zoneCache) : null;
			if (!zone || !RECORD_ID_RE.test(String(zone.id))) continue;
			const url = `/zones/${encodeURIComponent(zone.id)}/dns_records/${encodeURIComponent(id)}`;
			let existing = null;
			try {
				existing = await api(token, url);
			} catch {
				continue; // schon weg
			}
			const name = String(existing?.name || "").toLowerCase();
			if (existing?.id !== id || existing.comment !== MANAGED_COMMENT || keepNames.has(name)) continue;
			await api(token, url, { method: "DELETE" });
		} catch (error) {
			logger.warn(`Cloudflare record ${key} could not be removed: ${error.message}`);
			failed[key] = entry;
		}
	}
	return failed;
};

const configOf = (host) => {
	const configKey = host.meta?.cloudflareDns ? "cloudflareDns" : "cloudflare_dns";
	return { configKey, config: host.meta?.[configKey] };
};

const hasRecords = (config) => Boolean(config?.records && Object.keys(config.records).length);

const cloudflareDns = {
	/**
	 * Entfernt serverseitige Felder (records, status, error, syncedAt) aus
	 * Client-Meta und übernimmt sie aus den gespeicherten Daten.
	 *
	 * @param {Object|undefined} incomingMeta  meta aus der Anfrage
	 * @param {Object|undefined} storedMeta    meta des gespeicherten Hosts
	 * @returns {Object|undefined}
	 */
	sanitizeMeta: (incomingMeta, storedMeta) => {
		if (!incomingMeta || typeof incomingMeta !== "object" || Array.isArray(incomingMeta)) return incomingMeta;
		const out = { ...incomingMeta };
		for (const key of CONFIG_KEYS) {
			const config = out[key];
			if (!config || typeof config !== "object" || Array.isArray(config)) continue;
			const clean = { ...config };
			for (const field of SERVER_FIELDS) delete clean[field];
			const stored = storedMeta?.[key];
			if (stored && typeof stored === "object") {
				for (const field of SERVER_FIELDS) {
					if (stored[field] !== undefined) clean[field] = stored[field];
				}
			}
			out[key] = clean;
		}
		return out;
	},

	resolveActor,

	/** @internal for tests */
	_getToken: getToken,
	_api: api,
	_findZone: findZone,
	_removeRecords: removeRecords,

	/**
	 * @param {Object} host
	 * @param {{userId: number, isAdmin: boolean}} actor  wer die Änderung auslöst
	 */
	syncProxyHost: async (host, actor) => {
		const { configKey, config } = configOf(host);
		if (!config) return host;
		if (!config.enabled) {
			// Abgeschaltet: unsere Records wieder entfernen
			if (!hasRecords(config)) return host;
			const meta = { ...(host.meta || {}), [configKey]: { ...config } };
			try {
				const token = await getToken(host, actor);
				if (!token) throw new Error("No Cloudflare API token available to remove the records");
				const failed = await removeRecords(token, config.records);
				meta[configKey] = {
					...config,
					records: failed,
					status: Object.keys(failed).length ? "error" : null,
					error: Object.keys(failed).length ? "Some Cloudflare records could not be removed" : null,
					syncedAt: new Date().toISOString(),
				};
			} catch (error) {
				meta[configKey] = { ...config, status: "error", error: error.message, syncedAt: new Date().toISOString() };
			}
			await proxyHostModel.query().where({ id: host.id }).patch({ meta });
			return { ...host, meta };
		}

		const meta = { ...(host.meta || {}), [configKey]: { ...config } };
		try {
			const token = await getToken(host, actor);
			if (!token) {
				throw new Error(
					actor?.isAdmin
						? "No Cloudflare API token: add one under Settings -> Cloudflare or use a Cloudflare DNS certificate"
						: "No Cloudflare API token is available: use a Cloudflare DNS certificate you own",
				);
			}
			const addresses = publicAddresses();
			if (!addresses.length) {
				throw new Error("No public IP address found: enter it under Settings -> Cloudflare");
			}
			const previous = config.records || {};
			const records = {};
			const zoneCache = new Map();
			const domains = host.domain_names.filter((name) => !name.includes("*"));
			for (const domain of domains) {
				const zone = await findZone(token, domain, zoneCache);
				for (const address of addresses) {
					const type = recordType(address);
					const key = `${domain}|${type}`;
					const record = await syncRecord({
						token,
						zone,
						domain,
						type,
						content: address,
						proxied: Boolean(config.proxied),
						recordId: previous[key]?.id,
					});
					records[key] = { id: record.id, zone: zone.name };
				}
			}
			// Domains/Adressfamilien, die weggefallen sind, wieder abräumen
			const keepIds = new Set(Object.values(records).map((r) => r.id));
			const keepNames = new Set(domains.map((d) => d.toLowerCase()));
			const failed = await removeRecords(token, previous, keepIds, keepNames);
			meta[configKey] = {
				...config,
				records: { ...failed, ...records },
				status: "synced",
				error: null,
				syncedAt: new Date().toISOString(),
			};
		} catch (error) {
			meta[configKey] = { ...config, status: "error", error: error.message, syncedAt: new Date().toISOString() };
		}
		await proxyHostModel.query().where({ id: host.id }).patch({ meta });
		return { ...host, meta };
	},

	/** Beim Löschen eines Hosts: dessen Records bei Cloudflare entfernen. Fehler blockieren das Löschen nicht. */
	removeProxyHost: async (host, actor) => {
		const { config } = configOf(host);
		if (!config?.enabled || !hasRecords(config)) return;
		try {
			const token = await getToken(host, actor);
			if (token) await removeRecords(token, config.records);
		} catch (error) {
			logger.warn(`Cloudflare records of proxy host ${host.id} could not be removed: ${error.message}`);
		}
	},

	/**
	 * Token prüfen (Einstellungen → Cloudflare → Testen): gültig, Zonen sichtbar, DNS lesbar.
	 * @param {string} [token]  eingegebener, noch nicht gespeicherter Token; sonst der gespeicherte
	 */
	testToken: async (token) => {
		const use = (typeof token === "string" && token.trim()) || settingsToken();
		if (!use) return { ok: false, message: "No API token entered", zones: [] };
		try {
			const verify = await api(use, "/user/tokens/verify");
			if (verify?.status !== "active") return { ok: false, message: `Token status: ${verify?.status}`, zones: [] };
			const zones = await api(use, "/zones?per_page=50&status=active");
			if (!zones.length) return { ok: false, message: "Token is valid but sees no zone (Zone:Read missing?)", zones: [] };
			await api(use, `/zones/${encodeURIComponent(zones[0].id)}/dns_records?per_page=1`);
			return { ok: true, message: "Token works", zones: zones.map((z) => z.name).sort() };
		} catch (error) {
			return { ok: false, message: error.message, zones: [] };
		}
	},
};

export default cloudflareDns;
