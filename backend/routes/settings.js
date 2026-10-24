import express from "express";
import { auditOnSuccess, bodyFieldNames } from "../internal/audit-route.js";
import internalSetting from "../internal/setting.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import apiValidator from "../lib/validator/api.js";
import { SAFE_HTTP_URL_PATTERN, SAFE_HTTPS_URL_PATTERN } from "../lib/safe-url.js";
import validator from "../lib/validator/index.js";
import { debug, express as logger } from "../logger.js";
import { getValidationSchema } from "../schema/index.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

// Hoisted so Ajv compiles each schema once (it caches compiled validators by object identity)
const GET_SCHEMA = {
	required: ["setting_id"],
	additionalProperties: false,
	properties: {
		setting_id: { type: "string", minLength: 1 },
	},
};

// The OpenAPI PUT schema (settings/settingID/put.json) is enum-locked to the
// nginx default-site values, which rejects every save of the agent-hub-url
// setting (value = public/fallback URL, meta.primary = internal primary URL).
// Validate that setting with its own schema instead: free-form http(s) URLs,
// empty string to clear. The pattern (lib/safe-url.js) mirrors sanitizeHubUrl() in
// internal/agent.js — these URLs end up in root-sourced agent config.env, so
// shell/sed metacharacters are rejected at the door.
const HUB_URL_PATTERN = `^$|${SAFE_HTTP_URL_PATTERN}`;
// The public/fallback URL (`value`) is the agents' path across the internet when
// the tunnel is down: https only (sanitizeFallbackHubUrl). Only `value` holds it;
// getAgentHubUrls() reads value + meta.primary, nothing reads meta.fallback.
const HUB_FALLBACK_URL_PATTERN = `^$|${SAFE_HTTPS_URL_PATTERN}`;
const agentHubUrlPutSchema = {
	type: "object",
	additionalProperties: false,
	minProperties: 1,
	properties: {
		value: {
			type: "string",
			maxLength: 255,
			pattern: HUB_FALLBACK_URL_PATTERN,
		},
		meta: {
			type: "object",
			additionalProperties: false,
			properties: {
				primary: {
					type: "string",
					maxLength: 255,
					pattern: HUB_URL_PATTERN,
				},
			},
		},
	},
};

/**
 * /api/settings
 */
router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/settings
	 *
	 * Retrieve all settings
	 */
	.get(async (req, res, next) => {
		try {
			const rows = await internalSetting.getAll(res.locals.access);
			res.status(200).send(rows);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * Specific setting
 *
 * /api/settings/something
 */
router
	.route("/:setting_id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	// Changes to default-site (rendered as root into the default nginx config) and
	// agent-hub-url (ends up in every agent's root-sourced config.env) must be traceable.
	// Names only, never values: meta.redirect/meta.html/hub URLs are not logged.
	.all(
		auditOnSuccess("setting", ({ method, params, body }) =>
			method === "PUT"
				? {
						action: "updated",
						meta: {
							name: String(params.setting_id ?? "").slice(0, 64),
							fields: bodyFieldNames(body),
							metaFields: bodyFieldNames(body?.meta),
						},
					}
				: null,
		),
	)

	/**
	 * GET /settings/something
	 *
	 * Retrieve a specific setting
	 */
	.get(async (req, res, next) => {
		try {
			const data = await validator(GET_SCHEMA, {
				setting_id: req.params.setting_id,
			});
			const row = await internalSetting.get(res.locals.access, {
				id: data.setting_id,
			});
			res.status(200).send(row);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})

	/**
	 * PUT /api/settings/something
	 *
	 * Update and existing setting
	 */
	.put(async (req, res, next) => {
		try {
			const schema =
				req.params.setting_id === "agent-hub-url"
					? agentHubUrlPutSchema
					: getValidationSchema("/settings/{settingID}", "put");
			const payload = await apiValidator(schema, req.body);
			payload.id = req.params.setting_id;
			const result = await internalSetting.update(res.locals.access, payload);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
