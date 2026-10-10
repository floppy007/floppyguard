import express from "express";
import internalSiteIsolation from "../internal/site-isolation.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import requireAdmin from "../lib/express/require-admin.js";
import { debug, express as logger } from "../logger.js";

// "Standorte untereinander": which sites must not reach each other through the
// hub. Admin only; PUT is audited inside internalSiteIsolation.replace.
const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

const route = (path, handlers, opts = {}) => {
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
				res.status(opts.status?.[method] ?? 200).send(out);
			} catch (err) {
				debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
				next(err);
			}
		});
	}
};

/**
 * GET /api/site-isolation → { sites, pairs, applied, warnings }
 * PUT /api/site-isolation   Body: { pairs: [{ link_a, link_b }] } — replaces the
 *                           full set, applies it on the hub, returns the GET shape.
 */
route(["", "/"], {
	get: () => internalSiteIsolation.overview(),
	put: (req, res) => internalSiteIsolation.replace(res.locals.access, req.body || {}),
});

/** POST /api/site-isolation/test  Body: { source, destination } — read-only verdict. */
route("/test", {
	post: (req) => internalSiteIsolation.test(req.body || {}),
});

export default router;
