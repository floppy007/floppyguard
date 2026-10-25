import express from "express";
import internalDirectLink from "../internal/agent-direct-link.js";
import error from "../lib/error.js";
import createRoute from "../lib/express/route.js";

// Direct links ("Direktverbindungen") between two site agents. Admin only;
// create/update/delete are audited inside internalDirectLink.
const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

const route = createRoute(router);

const idParam = (v) => {
	const n = Number.parseInt(v, 10);
	if (!Number.isInteger(n) || n < 1 || String(n) !== String(v)) throw new error.ValidationError("invalid id");
	return n;
};

/**
 * GET  /api/direct-links → [link]
 * POST /api/direct-links   Body: { name, agent_a_id, agent_b_id, listen_port, endpoint_host,
 *                                  tunnel_subnet, mtu?, enabled?, nat_a?, nat_b? }
 */
route(["", "/"], {
	get: () => internalDirectLink.list(),
	post: (req, res) => internalDirectLink.create(res.locals.access, req.body || {}),
});

/** PUT|DELETE /api/direct-links/:id */
route("/:id", {
	put: (req, res) => internalDirectLink.update(res.locals.access, idParam(req.params.id), req.body || {}),
	delete: (req, res) => internalDirectLink.delete(res.locals.access, idParam(req.params.id)),
});

export default router;
