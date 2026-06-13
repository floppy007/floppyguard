import express from "express";
import internalAgent from "../internal/agent.js";
import error from "../lib/error.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import requireAdmin from "../lib/express/require-admin.js";
import rateLimit from "../lib/express/rate-limit.js";
import { debug, express as logger } from "../logger.js";

const agentLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, bucket: "agent" });

const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

// ─── Helper: extract Bearer token from Authorization header ─────────────────

function extractBearerToken(req) {
	const auth = req.headers.authorization || "";
	const match = auth.match(/^Bearer\s+(.+)$/i);
	return match ? match[1] : null;
}

// ─── Admin routes (JWT-authenticated) ────────────────────────────────────────

/**
 * GET /api/agents
 * List all agents
 */
router
	.route("/agents")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.get(async (req, res, next) => {
		try {
			const agents = await internalAgent.getAll();
			res.status(200).send(agents);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.post(async (req, res, next) => {
		try {
			const agent = await internalAgent.create(req.body || {});
			res.status(201).send(agent);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * GET /api/agents/:id
 * PUT /api/agents/:id
 * DELETE /api/agents/:id
 */
router
	.route("/agents/:id")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.get(async (req, res, next) => {
		try {
			const agent = await internalAgent.getById(Number.parseInt(req.params.id, 10));
			res.status(200).send(agent);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.put(async (req, res, next) => {
		try {
			const agent = await internalAgent.update(Number.parseInt(req.params.id, 10), req.body || {});
			res.status(200).send(agent);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.delete(async (req, res, next) => {
		try {
			await internalAgent.delete(Number.parseInt(req.params.id, 10));
			res.status(200).send({ deleted: true });
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * POST /api/agents/:id/reset-token
 * Generates a new reg_token so the agent can be reinstalled
 */
router
	.route("/agents/:id/reset-token")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(async (req, res, next) => {
		try {
			const result = await internalAgent.resetToken(Number.parseInt(req.params.id, 10));
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * GET /api/agents/:id/install
 * Returns the install script as text/plain
 * Query params: ?public_url=...&tunnel_url=...
 */
router
	.route("/agents/:id/install")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.get(async (req, res, next) => {
		try {
			const id = Number.parseInt(req.params.id, 10);
			const publicUrl = req.query.public_url;
			const tunnelUrl = req.query.tunnel_url || publicUrl;

			if (!publicUrl) {
				return next(new error.ValidationError("public_url query param is required"));
			}

			const script = await internalAgent.getInstallScript(id, publicUrl, tunnelUrl);
			res.status(200).type("text/plain").send(script);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

// ─── Agent routes (agent-token-authenticated, no JWT) ────────────────────────

/**
 * GET /api/agent/install?reg_token=...&public_url=...&tunnel_url=...
 * Public endpoint — authenticated via reg_token only, no JWT required.
 * Returns the install script as text/plain.
 */
router
	.route("/agent/install")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.get(agentLimiter, async (req, res, next) => {
		try {
			const { reg_token, public_url, tunnel_url } = req.query;
			if (!reg_token) {
				return next(new error.ValidationError("reg_token is required"));
			}
			if (!public_url) {
				return next(new error.ValidationError("public_url is required"));
			}
			const tunnelUrl = tunnel_url || public_url;
			const script = await internalAgent.getInstallScriptByToken(reg_token, public_url, tunnelUrl);
			res.status(200).type("text/plain").send(script);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * GET /api/agent/loop-script
 * Authorization: Bearer <agent_token>
 * Returns the current loop script for the agent (used for self-update).
 */
router
	.route("/agent/loop-script")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.get(async (req, res, next) => {
		try {
			const agentToken = extractBearerToken(req);
			if (!agentToken) return next(new error.AuthError("Bearer token required", "error.auth"));
			const { script, signature } = await internalAgent.getLoopScript(agentToken);
			res.setHeader("X-Script-Signature", signature);
			res.status(200).type("text/plain").send(script);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * POST /api/agent/register
 * Body: { reg_token: string }
 */
router
	.route("/agent/register")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.post(agentLimiter, async (req, res, next) => {
		try {
			const { reg_token } = req.body || {};
			if (!reg_token) {
				return next(new error.ValidationError("reg_token is required"));
			}
			const result = await internalAgent.register(reg_token);
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * GET /api/agent/config
 * Authorization: Bearer <agent_token>
 */
router
	.route("/agent/config")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.get(async (req, res, next) => {
		try {
			const agentToken = extractBearerToken(req);
			if (!agentToken) {
				return next(new error.AuthError("Bearer token required", "error.auth"));
			}
			const config = await internalAgent.getConfig(agentToken);
			res.status(200).send(config);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * POST /api/agent/heartbeat
 * Authorization: Bearer <agent_token>
 * Body: { hash: string, server: string }
 */
router
	.route("/agent/heartbeat")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.post(async (req, res, next) => {
		try {
			const agentToken = extractBearerToken(req);
			if (!agentToken) {
				return next(new error.AuthError("Bearer token required", "error.auth"));
			}
			const result = await internalAgent.heartbeat(agentToken, req.body || {});
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * POST /api/agent/upload-config
 * Authorization: Bearer <agent_token>
 * Body: { config_text: string }
 * Agents upload their local WG config when the server has none.
 */
router
	.route("/agent/upload-config")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.post(agentLimiter, async (req, res, next) => {
		try {
			const agentToken = extractBearerToken(req);
			if (!agentToken) {
				return next(new error.AuthError("Bearer token required", "error.auth"));
			}
			const result = await internalAgent.uploadConfig(agentToken, req.body || {});
			res.status(200).send(result);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
