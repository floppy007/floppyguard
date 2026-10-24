import express from "express";
import internal2FA from "../internal/2fa.js";
import internalUser from "../internal/user.js";
import Access from "../lib/access.js";
import errs from "../lib/error.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import rateLimit from "../lib/express/rate-limit.js";
import requireAdmin from "../lib/express/require-admin.js";
import userIdFromMe from "../lib/express/user-id-from-me.js";
import apiValidator from "../lib/validator/api.js";
import validator from "../lib/validator/index.js";
import { debug, express as logger } from "../logger.js";
import { getValidationSchema } from "../schema/index.js";
import { isSetup } from "../setup.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

// 2FA enable/disable/backup codes and the current-password check accept guesses from a
// session holder: throttle per IP in its own bucket so a mistyped code can't lock out login
const twoFaLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, bucket: "2fa" });

// Hoisted so Ajv compiles each schema once (it caches compiled validators by object identity)
const LIST_SCHEMA = {
	additionalProperties: false,
	properties: {
		expand: { $ref: "common#/properties/expand" },
		query: { $ref: "common#/properties/query" },
	},
};
const GET_SCHEMA = {
	required: ["user_id"],
	additionalProperties: false,
	properties: {
		user_id: { $ref: "common#/properties/id" },
		expand: { $ref: "common#/properties/expand" },
	},
};

/**
 * /api/users
 */
router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/users
	 *
	 * Retrieve all users (admin only)
	 */
	.get(requireAdmin(), async (req, res, next) => {
		try {
			const data = await validator(LIST_SCHEMA, {
				expand: typeof req.query.expand === "string" ? req.query.expand.split(",") : null,
				query: typeof req.query.query === "string" ? req.query.query : null,
			});
			const users = await internalUser.getAll(res.locals.access, data.expand, data.query);
			res.status(200).send(users);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * POST /api/users
	 *
	 * Create a new User
	 */
	.post(async (req, res, next) => {
		const body = req.body;

		try {
			// If we are in setup mode, we don't check access for current user
			const setup = await isSetup();
			if (!setup) {
				logger.info("Creating a new user in setup mode");
				const access = new Access(null);
				await access.load(true);
				res.locals.access = access;

				// We are in setup mode, set some defaults for this first new user, such as making
				// them an admin.
				body.is_disabled = false;
				if (!Array.isArray(body.roles)) {
					body.roles = [];
				}
				if (body.roles.indexOf("admin") === -1) {
					body.roles.push("admin");
				}
			}

			const payload = await apiValidator(getValidationSchema("/users", "post"), body);
			if (!setup && !payload.auth) {
				// First admin must have a password, otherwise isSetup() flips to true and nobody can ever log in
				throw new errs.ValidationError("Initial admin user requires auth credentials (password)");
			}
			const user = await internalUser.create(res.locals.access, payload);
			res.status(201).send(user);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * DELETE /api/users — disabled in production.
	 * Use the dedicated test harness for CI teardown.
	 */
	.delete((_, __, next) => {
		next(new errs.ItemNotFoundError());
	});

/**
 * Specific user
 *
 * /api/users/123
 */
router
	.route("/:user_id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(userIdFromMe)

	/**
	 * GET /users/123 or /users/me
	 *
	 * Retrieve a specific user
	 */
	.get(async (req, res, next) => {
		try {
			const data = await validator(GET_SCHEMA, {
				user_id: req.params.user_id,
				expand: typeof req.query.expand === "string" ? req.query.expand.split(",") : null,
			});

			const user = await internalUser.get(res.locals.access, {
				id: data.user_id,
				expand: data.expand,
			});
			res.status(200).send(user);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * PUT /api/users/123
	 *
	 * Update and existing user
	 */
	.put(async (req, res, next) => {
		try {
			const payload = await apiValidator(getValidationSchema("/users/{userID}", "put"), req.body);
			payload.id = req.params.user_id;
			const result = await internalUser.update(res.locals.access, payload);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * DELETE /api/users/123
	 *
	 * Update and existing user
	 */
	.delete(async (req, res, next) => {
		try {
			const result = await internalUser.delete(res.locals.access, {
				id: req.params.user_id,
			});
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * Specific user auth
 *
 * /api/users/123/auth
 */
router
	.route("/:user_id/auth")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(userIdFromMe)

	/**
	 * PUT /api/users/123/auth
	 *
	 * Update password for a user
	 */
	.put(twoFaLimiter, async (req, res, next) => {
		try {
			const payload = await apiValidator(getValidationSchema("/users/{userID}/auth", "put"), req.body);
			payload.id = req.params.user_id;
			const result = await internalUser.setPassword(res.locals.access, payload);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * Specific user permissions
 *
 * /api/users/123/permissions
 */
router
	.route("/:user_id/permissions")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(userIdFromMe)

	/**
	 * PUT /api/users/123/permissions
	 *
	 * Set some or all permissions for a user
	 */
	.put(async (req, res, next) => {
		try {
			const payload = await apiValidator(getValidationSchema("/users/{userID}/permissions", "put"), req.body);
			payload.id = req.params.user_id;
			const result = await internalUser.setPermissions(res.locals.access, payload);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * Specific user login as
 *
 * /api/users/123/login
 */
router
	.route("/:user_id/login")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(userIdFromMe)

	/**
	 * POST /api/users/123/login
	 *
	 * Log in as a user
	 */
	.post(async (req, res, next) => {
		try {
			const result = await internalUser.loginAs(res.locals.access, {
				id: req.params.user_id,
			});
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * User 2FA status
 *
 * /api/users/123/2fa
 */
router
	.route("/:user_id/2fa")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(userIdFromMe)

	/**
	 * POST /api/users/123/2fa
	 *
	 * Start 2FA setup, returns QR code URL
	 */
	.post(async (req, res, next) => {
		try {
			const result = await internal2FA.startSetup(res.locals.access, req.params.user_id);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * GET /api/users/123/2fa
	 *
	 * Get 2FA status for a user
	 */
	.get(async (req, res, next) => {
		try {
			const status = await internal2FA.getStatus(res.locals.access, req.params.user_id);
			res.status(200).send(status);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * DELETE /api/users/123/2fa  {"code": "XXXXXX"}
	 *
	 * Disable 2FA for a user. The code travels in the body so it doesn't end up in
	 * access logs; ?code= is still read for older clients.
	 */
	.delete(twoFaLimiter, async (req, res, next) => {
		try {
			let code = null;
			if (req.body && typeof req.body === "object" && typeof req.body.code !== "undefined") {
				({ code } = await apiValidator(getValidationSchema("/users/{userID}/2fa", "delete"), req.body));
			} else if (typeof req.query.code === "string") {
				code = req.query.code;
			}
			if (!code) {
				throw new errs.ValidationError("Missing required parameter: code");
			}
			await internal2FA.disable(res.locals.access, req.params.user_id, code);
			res.status(200).send(true);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * User 2FA enable
 *
 * /api/users/123/2fa/enable
 */
router
	.route("/:user_id/2fa/enable")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(userIdFromMe)

	/**
	 * POST /api/users/123/2fa/enable
	 *
	 * Verify code and enable 2FA
	 */
	.post(twoFaLimiter, async (req, res, next) => {
		try {
			const { code } = await apiValidator(getValidationSchema("/users/{userID}/2fa/enable", "post"), req.body);
			const result = await internal2FA.enable(res.locals.access, req.params.user_id, code);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * User 2FA backup codes
 *
 * /api/users/123/2fa/backup-codes
 */
router
	.route("/:user_id/2fa/backup-codes")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(userIdFromMe)

	/**
	 * POST /api/users/123/2fa/backup-codes
	 *
	 * Regenerate backup codes
	 */
	.post(twoFaLimiter, async (req, res, next) => {
		try {
			const { code } = await apiValidator(
				getValidationSchema("/users/{userID}/2fa/backup-codes", "post"),
				req.body,
			);
			const result = await internal2FA.regenerateBackupCodes(res.locals.access, req.params.user_id, code);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
