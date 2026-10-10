import express from "express";
import internalAgent from "../internal/agent.js";
import internalAgentIngress from "../internal/agent-ingress.js";
import { auditOnSuccess, describeAgentRequest } from "../internal/audit-route.js";
import error from "../lib/error.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import requireAdmin from "../lib/express/require-admin.js";
import rateLimit from "../lib/express/rate-limit.js";
import { debug, express as logger } from "../logger.js";

const agentLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, bucket: "agent" });

const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

// Agent create/update/delete, token reset and install-script download (reg_token)
// leave an audit entry (ids + field names only).
const auditAgent = () => auditOnSuccess("agent", describeAgentRequest);

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
	.all(auditAgent())
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

// ─── Ingress filter ("Freigaben") per agent ──────────────────────────────────

// opts.status overrides the default status per method ({ post: 200 } for a
// read-only POST such as the flow tester).
const ingressRoute = (path, handlers, opts = {}) => {
	const r = router
		.route(path)
		.options((_, res) => {
			res.sendStatus(204);
		})
		.all(jwtdecode())
		.all(requireAdmin());
	for (const [method, fn] of Object.entries(handlers)) {
		r[method](async (req, res, next) => {
			try {
				const out = await fn(req, res);
				res.status(opts.status?.[method] ?? (method === "post" ? 201 : 200)).send(out);
			} catch (err) {
				debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
				next(err);
			}
		});
	}
};

const idParam = (v) => {
	const n = Number.parseInt(v, 10);
	if (!Number.isInteger(n) || n < 1) throw new error.ValidationError("invalid id");
	return n;
};

/**
 * GET /api/agent-ingress/check
 * Proxy hosts / streams whose upstream a restricted agent would drop, and
 * hub-sourced rules no upstream uses anymore.
 */
ingressRoute("/agent-ingress/check", {
	get: () => internalAgentIngress.proxyCheck(),
});

/**
 * GET /api/agents/:id/ingress   → { ingress_mode, rules }
 * PUT /api/agents/:id/ingress   → { ingress_mode } switch open/restricted
 */
ingressRoute("/agents/:id/ingress", {
	get: (req) => internalAgentIngress.list(idParam(req.params.id)),
	put: (req, res) => internalAgentIngress.setMode(res.locals.access, idParam(req.params.id), req.body?.ingress_mode),
});

/** GET /api/agents/:id/ingress/preview → generated iptables-restore text */
ingressRoute("/agents/:id/ingress/preview", {
	get: (req) => internalAgentIngress.preview(idParam(req.params.id)),
});

/** POST /api/agents/:id/ingress/rules */
ingressRoute("/agents/:id/ingress/rules", {
	post: (req, res) => internalAgentIngress.create(res.locals.access, idParam(req.params.id), req.body || {}),
});

/**
 * GET /api/agents/:id/ingress/catalog → known sources/destinations, port presets,
 * rules that look unused (pickers and wizards)
 */
ingressRoute("/agents/:id/ingress/catalog", {
	get: (req) => internalAgentIngress.catalog(idParam(req.params.id)),
});

/**
 * POST /api/agents/:id/ingress/test → what the agent's filter does with one flow
 * Body: { source, destination, port?, proto? } — read-only, hence 200 and no audit.
 */
ingressRoute(
	"/agents/:id/ingress/test",
	{
		post: (req) => internalAgentIngress.testFlow(idParam(req.params.id), req.body || {}),
	},
	{ status: { post: 200 } },
);

// Both bulk routes are registered BEFORE /rules/:ruleId so "bulk" never runs
// through that route's middleware as a rule id.

/** POST /api/agents/:id/ingress/rules/bulk  Body: { rules: [rule, …] } (1..100) */
ingressRoute("/agents/:id/ingress/rules/bulk", {
	post: (req, res) => internalAgentIngress.createBulk(res.locals.access, idParam(req.params.id), req.body?.rules),
});

/**
 * POST /api/agents/:id/ingress/rules/bulk-disable  Body: { rule_ids: [id, …], prune?: true }
 * prune = the "switch off unused" action: the ids are re-checked against the
 * current prune candidates.
 */
ingressRoute(
	"/agents/:id/ingress/rules/bulk-disable",
	{
		post: (req, res) =>
			internalAgentIngress.disableBulk(res.locals.access, idParam(req.params.id), req.body?.rule_ids, {
				prune: req.body?.prune === true,
			}),
	},
	{ status: { post: 200 } },
);

/** PUT|DELETE /api/agents/:id/ingress/rules/:ruleId */
ingressRoute("/agents/:id/ingress/rules/:ruleId", {
	put: (req, res) =>
		internalAgentIngress.update(
			res.locals.access,
			idParam(req.params.id),
			idParam(req.params.ruleId),
			req.body || {},
		),
	delete: (req, res) =>
		internalAgentIngress.delete(res.locals.access, idParam(req.params.id), idParam(req.params.ruleId)),
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
	.all(auditAgent())
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
			// ?force=1: gateway gone/offline for good (see internalAgent.delete).
			const force = req.query?.force === "1" || req.query?.force === "true";
			await internalAgent.delete(Number.parseInt(req.params.id, 10), { force });
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
	.all(auditAgent())
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
	.all(auditAgent())
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
