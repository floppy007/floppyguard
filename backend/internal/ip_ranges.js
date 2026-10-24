import fs from "node:fs";
import https from "node:https";
import net from "node:net";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ProxyAgent } from "proxy-agent";
import errs from "../lib/error.js";
import utils from "../lib/utils.js";
import { ipRanges as logger } from "../logger.js";
import internalNginx from "./nginx.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const CLOUDFRONT_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json";
const CLOUDFARE_V4_URL = "https://www.cloudflare.com/ips-v4";
const CLOUDFARE_V6_URL = "https://www.cloudflare.com/ips-v6";

const regIpV4Cidr = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\/(?:[0-9]|[12]\d|3[0-2])$/;
const regIpV6Chars = /^[0-9a-fA-F:.]+$/; // net.isIPv6 accepts "%zone" - exclude it

/** Strict CIDR check: the value is rendered verbatim into a root-loaded nginx conf. */
const isCidr = (value) => {
	if (typeof value !== "string") return false;
	const v = value.trim();
	if (regIpV4Cidr.test(v)) return true;
	const idx = v.indexOf("/");
	if (idx === -1) return false;
	const addr = v.slice(0, idx);
	const prefix = v.slice(idx + 1);
	return regIpV6Chars.test(addr) && net.isIPv6(addr) && /^\d{1,3}$/.test(prefix) && Number(prefix) <= 128;
};

const keepValid = (candidates, source) =>
	candidates.filter((c) => {
		if (isCidr(c)) return true;
		if (c) logger.warn(`Ignoring invalid IP range from ${source}: ${JSON.stringify(String(c)).slice(0, 80)}`);
		return false;
	});

const FETCH_TIMEOUT_MS = 15000;

const internalIpRanges = {
	interval_timeout: 1000 * 60 * 60 * 6, // 6 hours
	interval: null,
	interval_processing: false,
	iteration_count: 0,

	initTimer: () => {
		logger.info("IP Ranges Renewal Timer initialized");
		internalIpRanges.interval = setInterval(internalIpRanges.fetch, internalIpRanges.interval_timeout);
	},

	fetchUrl: (url) => {
		const agent = new ProxyAgent();
		return new Promise((resolve, reject) => {
			logger.info(`Fetching ${url}`);
			const req = https
				.get(url, { agent }, (res) => {
					if (res.statusCode < 200 || res.statusCode >= 300) {
						res.resume();
						reject(new Error(`Fetching ${url} failed: HTTP ${res.statusCode}`));
						return;
					}
					res.setEncoding("utf8");
					let raw_data = "";
					res.on("data", (chunk) => {
						raw_data += chunk;
					});

					res.on("end", () => {
						resolve(raw_data);
					});
				})
				.on("error", (err) => {
					reject(err);
				});
			// Without a timeout a blackholed connection delays startup (the
			// fetch runs before the backend listens) until the OS gives up.
			req.setTimeout(FETCH_TIMEOUT_MS, () => {
				req.destroy(new Error(`Timeout fetching ${url}`));
			});
			return req;
		});
	},

	/**
	 * Triggered at startup and then later by a timer, this will fetch the ip ranges from services and apply them to nginx.
	 */
	fetch: () => {
		if (!internalIpRanges.interval_processing) {
			internalIpRanges.interval_processing = true;
			logger.info("Fetching IP Ranges from online services...");

			let ip_ranges = [];

			return internalIpRanges
				.fetchUrl(CLOUDFRONT_URL)
				.then((cloudfront_data) => {
					const data = JSON.parse(cloudfront_data);

					const isCloudFront = (item) => item?.service === "CLOUDFRONT";
					const v4Candidates = Array.isArray(data?.prefixes)
						? data.prefixes.filter(isCloudFront).map((item) => item.ip_prefix)
						: [];
					const v6Candidates = Array.isArray(data?.ipv6_prefixes)
						? data.ipv6_prefixes.filter(isCloudFront).map((item) => item.ipv6_prefix)
						: [];
					ip_ranges.push(...keepValid(v4Candidates, CLOUDFRONT_URL));
					ip_ranges.push(...keepValid(v6Candidates, CLOUDFRONT_URL));
				})
				.then(() => {
					return internalIpRanges.fetchUrl(CLOUDFARE_V4_URL);
				})
				.then((cloudfare_data) => {
					const items = keepValid(
						cloudfare_data.split("\n").map((l) => l.trim()),
						CLOUDFARE_V4_URL,
					);
					// An error/captive-portal body yields no matches: keep the previous conf
					if (!items.length) throw new Error(`No IPv4 ranges found in ${CLOUDFARE_V4_URL}`);
					ip_ranges = [...ip_ranges, ...items];
				})
				.then(() => {
					return internalIpRanges.fetchUrl(CLOUDFARE_V6_URL);
				})
				.then((cloudfare_data) => {
					const items = keepValid(
						cloudfare_data.split("\n").map((l) => l.trim()),
						CLOUDFARE_V6_URL,
					);
					if (!items.length) throw new Error(`No IPv6 ranges found in ${CLOUDFARE_V6_URL}`);
					ip_ranges = [...ip_ranges, ...items];
				})
				.then(() => {
					const clean_ip_ranges = ip_ranges.filter(isCidr);
					if (!clean_ip_ranges.length) {
						throw new Error("No valid IP ranges fetched; keeping previous ip_ranges.conf");
					}

					return internalIpRanges.generateConfig(clean_ip_ranges).then((changed) => {
						// Only reload when the ranges actually changed: every reload
						// leaves the old workers running until their long-lived
						// (websocket) connections close.
						if (changed && internalIpRanges.iteration_count) {
							// Reload nginx
							return internalNginx.reload();
						}
					});
				})
				.then(() => {
					internalIpRanges.interval_processing = false;
					internalIpRanges.iteration_count++;
				})
				.catch((err) => {
					logger.fatal(err.message);
					internalIpRanges.interval_processing = false;
				});
		}
	},

	/**
	 * @param   {Array}  ip_ranges
	 * @returns {Promise<boolean>}  true when the file was (re)written, false when unchanged
	 */
	generateConfig: (ip_ranges) => {
		const renderEngine = utils.getRenderEngine();
		return new Promise((resolve, reject) => {
			let template = null;
			const filename = "/etc/nginx/conf.d/include/ip_ranges.conf";
			try {
				template = fs.readFileSync(`${__dirname}/../templates/ip_ranges.conf`, { encoding: "utf8" });
			} catch (err) {
				reject(new errs.ConfigurationError(err.message));
				return;
			}

			renderEngine
				.parseAndRender(template, { ip_ranges: ip_ranges })
				.then((config_text) => {
					let current = null;
					try {
						current = fs.readFileSync(filename, { encoding: "utf8" });
					} catch {
						// missing file: write it
					}
					if (current === config_text) {
						resolve(false);
						return;
					}
					fs.writeFileSync(filename, config_text, { encoding: "utf8" });
					resolve(true);
				})
				.catch((err) => {
					logger.warn(`Could not write ${filename}: ${err.message}`);
					reject(new errs.ConfigurationError(err.message));
				});
		});
	},
};

export default internalIpRanges;
