import os from "node:os";
import certificateModel from "../models/certificate.js";
import proxyHostModel from "../models/proxy_host.js";
import userModel from "../models/user.js";

const API_ROOT = "https://api.cloudflare.com/client/v4";
const MANAGED_COMMENT = "Managed by FloppyGuard";

const isPublicAddress = (address) => {
	if (address.includes(":")) return !/^(?:fc|fd|fe80:)/i.test(address);
	return !/^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(address);
};

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

const getToken = async (host, actor) => {
	if (!actor) return null;
	if (actor.isAdmin && process.env.CLOUDFLARE_API_TOKEN) return process.env.CLOUDFLARE_API_TOKEN;
	if (!host.certificate_id) return null;
	const certificate = await certificateModel.query().findById(host.certificate_id);
	if (!certificate || certificate.is_deleted) return null;
	if (!actor.isAdmin && certificate.owner_user_id !== actor.userId) return null;
	return tokenFromCertificate(certificate);
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

const publicAddresses = () => {
	const configured = [process.env.CLOUDFLARE_DNS_IPV4, process.env.CLOUDFLARE_DNS_IPV6].filter(Boolean);
	if (configured.length) return configured;
	return Object.values(os.networkInterfaces())
		.flat()
		.filter((address) => address && !address.internal && isPublicAddress(address.address))
		.map((address) => address.address)
		.filter((address, index, all) => all.indexOf(address) === index);
};

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
	if (records.length) throw new Error(`${domain} already has an unmanaged ${type} record`);
	return await api(token, `/zones/${zone.id}/dns_records`, { method: "POST", body: JSON.stringify(body) });
};

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

	/**
	 * @param {Object} host
	 * @param {{userId: number, isAdmin: boolean}} actor  wer die Änderung auslöst
	 */
	syncProxyHost: async (host, actor) => {
		const configKey = host.meta?.cloudflareDns ? "cloudflareDns" : "cloudflare_dns";
		const config = host.meta?.[configKey];
		if (!config?.enabled) return host;

		const meta = { ...(host.meta || {}), [configKey]: { ...config } };
		try {
			const token = await getToken(host, actor);
			if (!token) {
				throw new Error(
					actor?.isAdmin
						? "No Cloudflare API token is configured for this host or its certificate"
						: "No Cloudflare API token is available: use a Cloudflare DNS certificate you own",
				);
			}
			const records = { ...(config.records || {}) };
			const zoneCache = new Map();
			for (const domain of host.domain_names.filter((name) => !name.includes("*"))) {
				const zone = await findZone(token, domain, zoneCache);
				for (const address of publicAddresses()) {
					const type = recordType(address);
					const key = `${domain}|${type}`;
					const record = await syncRecord({
						token,
						zone,
						domain,
						type,
						content: address,
						proxied: Boolean(config.proxied),
						recordId: records[key]?.id,
					});
					records[key] = { id: record.id, zone: zone.name };
				}
			}
			meta[configKey] = { ...config, records, status: "synced", error: null, syncedAt: new Date().toISOString() };
		} catch (error) {
			meta[configKey] = { ...config, status: "error", error: error.message, syncedAt: new Date().toISOString() };
		}
		await proxyHostModel.query().where({ id: host.id }).patch({ meta });
		return { ...host, meta };
	},
};

export default cloudflareDns;
