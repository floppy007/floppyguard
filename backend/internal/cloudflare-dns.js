import os from "node:os";
import certificateModel from "../models/certificate.js";
import proxyHostModel from "../models/proxy_host.js";

const API_ROOT = "https://api.cloudflare.com/client/v4";
const MANAGED_COMMENT = "Managed by FloppyGuard";

const isPublicAddress = (address) => {
	if (address.includes(":")) return !/^(?:fc|fd|fe80:)/i.test(address);
	return !/^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(address);
};

const getToken = async (host) => {
	if (process.env.CLOUDFLARE_API_TOKEN) return process.env.CLOUDFLARE_API_TOKEN;
	if (!host.certificate_id) return null;
	const certificate = await certificateModel.query().findById(host.certificate_id);
	const credentials = certificate?.meta?.dns_provider_credentials;
	if (certificate?.meta?.dns_provider !== "cloudflare" || typeof credentials !== "string") return null;
	return credentials.match(/^\s*dns_cloudflare_api_token\s*=\s*(.+?)\s*$/m)?.[1] || null;
};

const api = async (token, path, options = {}) => {
	const response = await fetch(`${API_ROOT}${path}`, {
		...options,
		headers: {
			Authorization: `Bearer ${token}`,
			"Content-Type": "application/json",
			...options.headers,
		},
	});
	const payload = await response.json();
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

const findZone = async (token, domain) => {
	const labels = domain.split(".");
	for (let index = 1; index < labels.length - 1; index += 1) {
		const name = labels.slice(index).join(".");
		const zones = await api(token, `/zones?name=${encodeURIComponent(name)}&status=active`);
		if (zones.length) return zones[0];
	}
	throw new Error(`No Cloudflare zone is available for ${domain}`);
};

const syncRecord = async ({ token, zone, domain, type, content, proxied, recordId }) => {
	const body = { type, name: domain, content, proxied, ttl: 1, comment: MANAGED_COMMENT };
	if (recordId) return await api(token, `/zones/${zone.id}/dns_records/${recordId}`, { method: "PUT", body: JSON.stringify(body) });
	const records = await api(token, `/zones/${zone.id}/dns_records?type=${type}&name=${encodeURIComponent(domain)}`);
	const matching = records.find((record) => record.content === content && record.proxied === proxied);
	if (matching) return matching;
	if (records.length) throw new Error(`${domain} already has an unmanaged ${type} record`);
	return await api(token, `/zones/${zone.id}/dns_records`, { method: "POST", body: JSON.stringify(body) });
};

const cloudflareDns = {
	syncProxyHost: async (host) => {
		const configKey = host.meta?.cloudflareDns ? "cloudflareDns" : "cloudflare_dns";
		const config = host.meta?.[configKey];
		if (!config?.enabled) return host;

		const meta = { ...(host.meta || {}), [configKey]: { ...config } };
		try {
			const token = await getToken(host);
			if (!token) throw new Error("No Cloudflare API token is configured for this host or its certificate");
			const records = { ...(config.records || {}) };
			for (const domain of host.domain_names.filter((name) => !name.includes("*"))) {
				const zone = await findZone(token, domain);
				for (const address of publicAddresses()) {
					const type = recordType(address);
					const key = `${domain}|${type}`;
					const record = await syncRecord({ token, zone, domain, type, content: address, proxied: Boolean(config.proxied), recordId: records[key]?.id });
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
