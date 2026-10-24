import express from "express";
import internalAgent from "../internal/agent.js";
import internalAgentIngress from "../internal/agent-ingress.js";
import { auditOnSuccess, describeAgentRequest } from "../internal/audit-route.js";
import error from "../lib/error.js";
import rateLimit from "../lib/express/rate-limit.js";
import createRoute from "../lib/express/route.js";

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

// Shared options/auth/try-catch scaffolding (lib/express/route.js).
const route = createRoute(router);

// Agent-token routes: Bearer token once, then fn(token, req, res).
const withAgentToken = (fn) => (req, res) => {
	const token = extractBearerToken(req);
	if (!token) throw new error.AuthError("Bearer token required", "error.auth");
	return fn(token, req, res);
};

const idParam = (v) => {
	const n = Number.parseInt(v, 10);
	if (!Number.isInteger(n) || n < 1) throw new error.ValidationError("invalid id");
	return n;
};

// ─── Admin routes (JWT-authenticated) ────────────────────────────────────────

/**
 * GET /api/agents
 * List all agents
 */
route(
	"/agents",
	{
		get: () => internalAgent.getAll(),
		post: (req) => internalAgent.create(req.body || {}),
	},
	{ audit: auditAgent() },
);

// ─── Ingress filter ("Freigaben") per agent ──────────────────────────────────

/**
 * GET /api/agent-ingress/check
 * Proxy hosts / streams whose upstream a restricted agent would drop, and
 * hub-sourced rules no upstream uses anymore.
 */
route("/agent-ingress/check", {
	get: () => internalAgentIngress.proxyCheck(),
});

/**
 * GET /api/agents/:id/ingress   → { ingress_mode, rules }
 * PUT /api/agents/:id/ingress   → { ingress_mode } switch open/restricted
 */
route("/agents/:id/ingress", {
	get: (req) => internalAgentIngress.list(idParam(req.params.id)),
	put: (req, res) => internalAgentIngress.setMode(res.locals.access, idParam(req.params.id), req.body?.ingress_mode),
});

/** GET /api/agents/:id/ingress/preview → generated iptables-restore text */
route("/agents/:id/ingress/preview", {
	get: (req) => internalAgentIngress.preview(idParam(req.params.id)),
});

/** POST /api/agents/:id/ingress/rules */
route("/agents/:id/ingress/rules", {
	post: (req, res) => internalAgentIngress.create(res.locals.access, idParam(req.params.id), req.body || {}),
});

/**
 * GET /api/agents/:id/ingress/catalog → known sources/destinations, port presets,
 * rules that look unused (pickers and wizards)
 */
route("/agents/:id/ingress/catalog", {
	get: (req) => internalAgentIngress.catalog(idParam(req.params.id)),
});

/**
 * POST /api/agents/:id/ingress/test → what the agent's filter does with one flow
 * Body: { source, destination, port?, proto? } — read-only, hence 200 and no audit.
 */
route(
	"/agents/:id/ingress/test",
	{
		post: (req) => internalAgentIngress.testFlow(idParam(req.params.id), req.body || {}),
	},
	{ status: { post: 200 } },
);

// Both bulk routes are registered BEFORE /rules/:ruleId so "bulk" never runs
// through that route's middleware as a rule id.

/** POST /api/agents/:id/ingress/rules/bulk  Body: { rules: [rule, …] } (1..100) */
route("/agents/:id/ingress/rules/bulk", {
	post: (req, res) => internalAgentIngress.createBulk(res.locals.access, idParam(req.params.id), req.body?.rules),
});

/**
 * POST /api/agents/:id/ingress/rules/bulk-disable  Body: { rule_ids: [id, …], prune?: true }
 * prune = the "switch off unused" action: the ids are re-checked against the
 * current prune candidates.
 */
route(
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
route("/agents/:id/ingress/rules/:ruleId", {
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
route(
	"/agents/:id",
	{
		get: (req) => internalAgent.getById(idParam(req.params.id)),
		put: (req) => internalAgent.update(idParam(req.params.id), req.body || {}),
		delete: async (req) => {
			// ?force=1: gateway gone/offline for good (see internalAgent.delete).
			const force = req.query?.force === "1" || req.query?.force === "true";
			await internalAgent.delete(idParam(req.params.id), { force });
			return { deleted: true };
		},
	},
	{ audit: auditAgent() },
);

/**
 * POST /api/agents/:id/reset-token
 * Generates a new reg_token so the agent can be reinstalled
 */
route(
	"/agents/:id/reset-token",
	{
		post: (req) => internalAgent.resetToken(idParam(req.params.id)),
	},
	{ audit: auditAgent(), status: { post: 200 } },
);

/**
 * GET /api/agents/:id/install
 * Returns the install script as text/plain
 * Query params: ?public_url=...&tunnel_url=...
 */
route(
	"/agents/:id/install",
	{
		get: (req) => {
			const id = idParam(req.params.id);
			const publicUrl = req.query.public_url;
			if (!publicUrl) throw new error.ValidationError("public_url query param is required");
			return internalAgent.getInstallScript(id, publicUrl, req.query.tunnel_url || publicUrl);
		},
	},
	{ audit: auditAgent(), type: "text/plain" },
);

// ─── Agent routes (agent-token-authenticated, no JWT) ────────────────────────

/**
 * GET /api/agent/install?reg_token=...&public_url=...&tunnel_url=...
 * Public endpoint — authenticated via reg_token only, no JWT required.
 * Returns the install script as text/plain.
 */
route(
	"/agent/install",
	{
		get: (req) => {
			const { reg_token, public_url, tunnel_url } = req.query;
			if (!reg_token) throw new error.ValidationError("reg_token is required");
			if (!public_url) throw new error.ValidationError("public_url is required");
			return internalAgent.getInstallScriptByToken(reg_token, public_url, tunnel_url || public_url);
		},
	},
	{ admin: false, limiter: agentLimiter, type: "text/plain" },
);

/**
 * GET /api/agent/loop-script
 * Authorization: Bearer <agent_token>
 * Returns the current loop script for the agent (used for self-update).
 */
route(
	"/agent/loop-script",
	{
		get: withAgentToken(async (token, _req, res) => {
			const { script, signature } = await internalAgent.getLoopScript(token);
			res.setHeader("X-Script-Signature", signature);
			return script;
		}),
	},
	{ admin: false, type: "text/plain" },
);

/**
 * POST /api/agent/register
 * Body: { reg_token: string }
 */
route(
	"/agent/register",
	{
		post: (req) => {
			const { reg_token } = req.body || {};
			if (!reg_token) throw new error.ValidationError("reg_token is required");
			return internalAgent.register(reg_token);
		},
	},
	{ admin: false, limiter: agentLimiter, status: { post: 200 } },
);

/**
 * GET /api/agent/config
 * Authorization: Bearer <agent_token>
 */
route(
	"/agent/config",
	{
		get: withAgentToken((token) => internalAgent.getConfig(token)),
	},
	{ admin: false },
);

/**
 * POST /api/agent/heartbeat
 * Authorization: Bearer <agent_token>
 * Body: { hash: string, server: string }
 */
route(
	"/agent/heartbeat",
	{
		post: withAgentToken((token, req) => internalAgent.heartbeat(token, req.body || {})),
	},
	{ admin: false, status: { post: 200 } },
);

/**
 * POST /api/agent/upload-config
 * Authorization: Bearer <agent_token>
 * Body: { config_text: string }
 * Agents upload their local WG config when the server has none.
 */
route(
	"/agent/upload-config",
	{
		post: withAgentToken((token, req) => internalAgent.uploadConfig(token, req.body || {})),
	},
	{ admin: false, limiter: agentLimiter, status: { post: 200 } },
);

export default router;
