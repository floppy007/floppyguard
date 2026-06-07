#!/usr/bin/env node

import app from "./app.js";
import internalAgent from "./internal/agent.js";
import internalCertificate from "./internal/certificate.js";
import internalIpRanges from "./internal/ip_ranges.js";
import { global as logger } from "./logger.js";
import { migrateUp } from "./migrate.js";
import { getCompiledSchema } from "./schema/index.js";
import setup from "./setup.js";

const IP_RANGES_FETCH_ENABLED = process.env.IP_RANGES_FETCH_ENABLED !== "false";
// Preview and staging environments must be able to avoid the upstream-fixed 3000 port.
const PORT = Number.parseInt(process.env.PORT || "3000", 10);

const MAX_RETRIES = 30;
let startAttempt = 0;

async function appStart() {
	startAttempt++;
	return migrateUp()
		.then(setup)
		.then(getCompiledSchema)
		.then(() => {
			if (!IP_RANGES_FETCH_ENABLED) {
				logger.info("IP Ranges fetch is disabled by environment variable");
				return;
			}
			logger.info("IP Ranges fetch is enabled");
			return internalIpRanges.fetch().catch((err) => {
				logger.error("IP Ranges fetch failed, continuing anyway:", err.message);
			});
		})
		.then(() => {
			startAttempt = 0;
			internalCertificate.initTimer();
			internalIpRanges.initTimer();
			internalAgent.startBackgroundTasks();

			const server = app.listen(PORT, () => {
				logger.info(`Backend PID ${process.pid} listening on port ${PORT} ...`);

				process.on("SIGTERM", () => {
					logger.info(`PID ${process.pid} received SIGTERM`);
					server.close(() => {
						logger.info("Stopping.");
						process.exit(0);
					});
				});
			});
		})
		.catch((err) => {
			const isDbError = /ECONNREFUSED|ENOTFOUND|ETIMEDOUT|ER_ACCESS_DENIED/.test(err.message);
			if (isDbError) {
				logger.error(`Database unreachable (attempt ${startAttempt}/${MAX_RETRIES}): ${err.message}`);
				logger.error("Check that your database server is running: systemctl status mariadb");
			} else {
				logger.error(`Startup Error (attempt ${startAttempt}/${MAX_RETRIES}): ${err.message}`, err);
			}

			if (startAttempt >= MAX_RETRIES) {
				logger.fatal(`Giving up after ${MAX_RETRIES} failed attempts. Fix the issue and restart: systemctl restart floppyguard-backend`);
				process.exit(1);
			}

			const delay = Math.min(1000 * startAttempt, 15000);
			setTimeout(appStart, delay);
		});
}

try {
	appStart();
} catch (err) {
	logger.fatal(err);
	process.exit(1);
}
