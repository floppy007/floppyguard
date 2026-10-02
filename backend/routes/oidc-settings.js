import express from "express";
import internalAuditLog from "../internal/audit-log.js";
import internalOidcSettings from "../internal/oidc-settings.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import rateLimit from "../lib/express/rate-limit.js";
import requireAdmin from "../lib/express/require-admin.js";
import { debug, express as logger } from "../logger.js";

// Einstellungen der SSO-Anmeldung. Nur für Administratoren.

const testLimiter = rateLimit({ windowMs: 5 * 60 * 1000, max: 20, bucket: "oidc-test" });

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

/**
 * /api/oidc/settings
 */
router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())

	.get((req, res, next) => {
		try {
			res.status(200).send(internalOidcSettings.get());
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	.put(async (req, res, next) => {
		try {
			const { settings, changed } = internalOidcSettings.save(req.body);
			if (changed.length) {
				await internalAuditLog.add(res.locals.access, {
					action: "updated",
					object_type: "oidc-settings",
					// Nur die Feldnamen protokollieren, niemals das Secret.
					meta: { changed, enabled: settings.enabled },
				});
			}
			res.status(200).send(settings);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * /api/oidc/settings/test
 */
router
	.route("/test")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())

	.post(testLimiter, async (req, res, next) => {
		try {
			res.status(200).send(await internalOidcSettings.test(req.body?.issuer));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
