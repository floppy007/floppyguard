import express from "express";
import internalAuditLog from "../internal/audit-log.js";
import internalCertAlerts from "../internal/cert-alerts.js";
import internalNotifications from "../internal/notifications.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import rateLimit from "../lib/express/rate-limit.js";
import requireAdmin from "../lib/express/require-admin.js";
import { debug, express as logger } from "../logger.js";

// Einstellungen → Benachrichtigungen + Warnungen für die Oberfläche. Nur für Administratoren.

const testLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 10, bucket: "notifications-test" });

const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

const wrap = (fn) => async (req, res, next) => {
	try {
		await fn(req, res);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
};

/** /api/notifications */
router
	.route("/")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.all(requireAdmin())
	.get(wrap(async (_req, res) => res.status(200).send(internalNotifications.get())))
	.put(
		wrap(async (req, res) => {
			const { settings, changed } = internalNotifications.save(req.body);
			if (changed.length) {
				await internalAuditLog.add(res.locals.access, {
					action: "updated",
					object_type: "notifications",
					// nur Feldnamen, nie das Passwort
					meta: { changed, enabled: settings.enabled, recipients: settings.recipients.length },
				});
			}
			res.status(200).send(settings);
		}),
	);

/** /api/notifications/test */
router
	.route("/test")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.all(requireAdmin())
	.post(testLimiter, wrap(async (req, res) => res.status(200).send(await internalNotifications.test(req.body?.to))));

/** /api/notifications/problems – Warnungen für die Kopfzeile der App */
router
	.route("/problems")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.all(requireAdmin())
	.get(wrap(async (_req, res) => res.status(200).send({ certificates: await internalCertAlerts.problems() })));

export default router;
