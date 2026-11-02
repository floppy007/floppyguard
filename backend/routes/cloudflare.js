import express from "express";
import internalAuditLog from "../internal/audit-log.js";
import errs from "../lib/error.js";
import cloudflareDns from "../internal/cloudflare-dns.js";
import cloudflareSettings from "../internal/cloudflare-settings.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import rateLimit from "../lib/express/rate-limit.js";
import requireAdmin from "../lib/express/require-admin.js";
import { debug, express as logger } from "../logger.js";

// Einstellungen → Cloudflare. Einstellungen und Test nur für Administratoren, /status für jeden Benutzer
// (der Proxy-Host-Dialog braucht die Vorgaben für neue Hosts).

const testLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20, bucket: "cloudflare-test" });

const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

const wrap = (fn) => async (req, res, next) => {
	try {
		await fn(req, res);
	} catch (err) {
		debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
		next(err);
	}
};

/** /api/cloudflare */
router
	.route("/")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.all(requireAdmin())
	.get(wrap(async (_req, res) => res.status(200).send(cloudflareSettings.get())))
	.put(
		wrap(async (req, res) => {
			const { settings, changed } = cloudflareSettings.save(req.body);
			if (changed.length) {
				await internalAuditLog.add(res.locals.access, {
					action: "updated",
					object_type: "cloudflare",
					// nur Feldnamen, nie den Token
					meta: { changed, has_token: settings.has_token },
				});
			}
			res.status(200).send(settings);
		}),
	);

/** /api/cloudflare/test */
router
	.route("/test")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.all(requireAdmin())
	.post(testLimiter, wrap(async (req, res) => res.status(200).send(await cloudflareDns.testToken(req.body?.api_token))));

/** /api/cloudflare/status */
router
	.route("/status")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(
		wrap(async (_req, res) => {
			const actor = await cloudflareDns.resolveActor(res.locals.access);
			// jwtdecode lässt anonyme Anfragen durch – hier nur angemeldete Benutzer
			if (!actor.userId) throw new errs.PermissionError("Authentication required");
			res.status(200).send(cloudflareSettings.status(actor));
		}),
	);

export default router;
