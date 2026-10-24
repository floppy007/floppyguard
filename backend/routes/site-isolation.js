import express from "express";
import internalSiteIsolation from "../internal/site-isolation.js";
import createRoute from "../lib/express/route.js";

// "Standorte untereinander": which sites must not reach each other through the
// hub. Admin only; PUT is audited inside internalSiteIsolation.replace.
const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

const route = createRoute(router);

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
route(
	"/test",
	{
		post: (req) => internalSiteIsolation.test(req.body || {}),
	},
	// read-only verdict, nothing is created
	{ status: { post: 200 } },
);

export default router;
