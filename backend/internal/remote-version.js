import https from "node:https";
import { ProxyAgent } from "proxy-agent";
import { debug, remoteVersion as logger } from "../logger.js";
import pjson from "../package.json" with { type: "json" };

const VERSION_URL = "https://api.github.com/repos/floppy007/floppyguard/releases/latest";
const FETCH_TIMEOUT_MS = 10 * 1000;

const internalRemoteVersion = {
	cache_timeout: 1000 * 60 * 15, // 15 minutes
	// Negative cache: after a failed fetch (GitHub unreachable, rate limit) every
	// caller gets the same error for this long instead of a new slow request.
	error_cache_timeout: 1000 * 60 * 5, // 5 minutes
	last_result: null,
	last_fetch_time: null,
	last_error: null,
	last_error_time: null,
	// Overall deadline for one fetch (overridable in tests)
	fetch_timeout: FETCH_TIMEOUT_MS,

	/**
	 * Fetch the latest version info, using a cached result if within the cache timeout period.
	 * @return {Promise<{current: string, latest: string, update_available: boolean}>} Version info
	 */
	get: async () => {
		if (
			!internalRemoteVersion.last_result ||
			!internalRemoteVersion.last_fetch_time ||
			Date.now() - internalRemoteVersion.last_fetch_time > internalRemoteVersion.cache_timeout
		) {
			if (
				internalRemoteVersion.last_error &&
				Date.now() - internalRemoteVersion.last_error_time < internalRemoteVersion.error_cache_timeout
			) {
				throw internalRemoteVersion.last_error;
			}
			try {
				const raw = await internalRemoteVersion.fetchUrl(VERSION_URL);
				const data = JSON.parse(raw);
				if (!data || typeof data.tag_name !== "string")
					throw new Error("Remote version response has no tag_name");
				internalRemoteVersion.last_result = data;
				internalRemoteVersion.last_fetch_time = Date.now();
				internalRemoteVersion.last_error = null;
			} catch (err) {
				internalRemoteVersion.last_error = err;
				internalRemoteVersion.last_error_time = Date.now();
				throw err;
			}
		} else {
			debug(logger, "Using cached remote version result");
		}

		const latestVersion = internalRemoteVersion.last_result.tag_name;
		const version = pjson.version.split("-").shift().split(".");
		const currentVersion = `v${version[0]}.${version[1]}.${version[2]}`;
		return {
			current: currentVersion,
			latest: latestVersion,
			update_available: internalRemoteVersion.compareVersions(currentVersion, latestVersion),
		};
	},

	fetchUrl: (url) => {
		const agent = new ProxyAgent();
		const headers = {
			"User-Agent": `FloppyGuard v${pjson.version}`,
		};

		const timeoutMs = internalRemoteVersion.fetch_timeout;
		return new Promise((resolve, reject) => {
			logger.info(`Fetching ${url}`);
			// Overall deadline (socket idle timeout alone would not stop a trickle).
			let timer;
			const done = (fn) => (value) => {
				clearTimeout(timer);
				fn(value);
			};
			const ok = done(resolve);
			const fail = done(reject);
			const req = https
				.get(url, { agent, headers, timeout: timeoutMs }, (res) => {
					if (res.statusCode !== 200) {
						res.resume();
						fail(new Error(`Remote version request failed: HTTP ${res.statusCode}`));
						return;
					}
					res.setEncoding("utf8");
					let raw_data = "";
					res.on("data", (chunk) => {
						raw_data += chunk;
					});
					res.on("end", () => ok(raw_data));
					res.on("error", fail);
				})
				.on("timeout", () => {
					req.destroy(new Error(`Remote version request timed out after ${timeoutMs / 1000}s`));
				})
				.on("error", fail);
			timer = setTimeout(() => {
				req.destroy(new Error(`Remote version request timed out after ${timeoutMs / 1000}s`));
			}, timeoutMs);
		});
	},

	compareVersions: (current, latest) => {
		const cleanCurrent = current.replace(/^v/, "");
		const cleanLatest = latest.replace(/^v/, "");

		const currentParts = cleanCurrent.split(".").map(Number);
		const latestParts = cleanLatest.split(".").map(Number);

		for (let i = 0; i < Math.max(currentParts.length, latestParts.length); i++) {
			const curr = currentParts[i] || 0;
			const lat = latestParts[i] || 0;

			if (lat > curr) return true;
			if (lat < curr) return false;
		}
		return false;
	},
};

export default internalRemoteVersion;
