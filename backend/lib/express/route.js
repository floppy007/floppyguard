import { debug, express as logger } from "../../logger.js";
import jwtdecode from "./jwt-decode.js";
import requireAdmin from "./require-admin.js";

/**
 * One route with the shared options/auth/try-catch scaffolding, bound to `router`:
 *
 *   const route = createRoute(router);
 *   route(path, { method: async (req, res) => body }, opts)
 *
 * opts:
 *   admin   (default true)  jwtdecode + requireAdmin; false = agent-token/public route
 *   audit   middleware run after requireAdmin, e.g. auditOnSuccess(...)
 *   limiter per-method middleware (never on OPTIONS), e.g. a rateLimit()
 *   status  { post: 200 } overrides the default (post → 201, else 200)
 *   type    e.g. "text/plain" for script downloads
 */
const createRoute =
	(router) =>
	(path, handlers, { admin = true, audit, limiter, status, type } = {}) => {
		const r = router.route(path).options((_, res) => {
			res.sendStatus(204);
		});
		if (admin) r.all(jwtdecode()).all(requireAdmin());
		if (audit) r.all(audit);
		for (const [method, fn] of Object.entries(handlers)) {
			const handler = async (req, res, next) => {
				try {
					const out = await fn(req, res);
					if (type) res.type(type);
					res.status(status?.[method] ?? (method === "post" ? 201 : 200)).send(out);
				} catch (err) {
					debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
					next(err);
				}
			};
			if (limiter) r[method](limiter, handler);
			else r[method](handler);
		}
	};

export default createRoute;
