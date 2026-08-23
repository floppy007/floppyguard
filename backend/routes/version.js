import express from "express";
import internalAppUpdate from "../internal/app-update.js";
import internalRemoteVersion from "../internal/remote-version.js";
import internalAuditLog from "../internal/audit-log.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import requireAdmin from "../lib/express/require-admin.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

/**
 * /api/version/check
 */
router
	.route("/check")
	.options((_, res) => {
		res.sendStatus(204);
	})

	/**
	 * GET /api/version/check
	 *
	 * Check for available updates
	 */
	.get(async (req, res, _next) => {
		try {
			const data = await internalRemoteVersion.get();
			res.status(200).send(data);
		} catch (error) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${error}`);
			// Send 200 even though there's an error to avoid triggering update checks repeatedly
			res.status(200).send({
				current: null,
				latest: null,
				update_available: false,
			});
		}
	});

/**
 * /api/version/update
 *
 * The status and start action are deliberately administrator-only. The actual
 * update is run by scripts/update.sh in a separate transient systemd unit.
 */
router
	.route("/update")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.get(async (req, res, next) => {
		try {
			res.status(200).send(await internalAppUpdate.getStatus());
		} catch (error) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${error}`);
			next(error);
		}
	})
	.post(async (req, res, next) => {
		try {
			const result = await internalAppUpdate.start();
			if (!result.alreadyRunning) {
				await internalAuditLog.add(res.locals.access, {
					action: "floppyguard.update",
					meta: { source: "admin-ui" },
				});
			}
			res.status(202).send(result);
		} catch (error) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${error}`);
			next(error);
		}
	});

export default router;
