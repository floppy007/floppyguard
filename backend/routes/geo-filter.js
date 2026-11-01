import express from "express";
import internalAuditLog from "../internal/audit-log.js";
import internalGeoFilter, { hostUsesGeoFilter } from "../internal/geo-filter.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import rateLimit from "../lib/express/rate-limit.js";
import requireAdmin from "../lib/express/require-admin.js";
import { debug, express as logger } from "../logger.js";
import proxyHostModel from "../models/proxy_host.js";

// Einstellungen → Länder-Filter. Nur für Administratoren.

const refreshLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 6, bucket: "geo-filter-refresh" });

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

/** Proxy-Hosts mit eingeschaltetem Länder-Filter (für die Übersicht in den Einstellungen). */
const filteredHosts = async () => {
	const rows = await proxyHostModel.query().where("is_deleted", 0).select("id", "domain_names", "enabled", "meta");
	return rows
		.filter(hostUsesGeoFilter)
		.map((r) => ({ id: r.id, domain_names: r.domain_names, enabled: Boolean(r.enabled) }));
};

/**
 * /api/geo-filter
 */
router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())

	.get(async (req, res, next) => {
		try {
			res.status(200).send(internalGeoFilter.status(await filteredHosts()));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	.put(async (req, res, next) => {
		try {
			const result = await internalGeoFilter.save(req.body);
			if (result.changed) {
				await internalAuditLog.add(res.locals.access, {
					action: "updated",
					object_type: "geo-filter",
					meta: { before: result.before, countries: result.countries },
				});
			}
			res.status(200).send(internalGeoFilter.status(await filteredHosts()));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * /api/geo-filter/refresh
 */
router
	.route("/refresh")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())

	.post(refreshLimiter, async (req, res, next) => {
		try {
			await internalGeoFilter.refresh({ force: true });
			res.status(200).send(internalGeoFilter.status(await filteredHosts()));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
