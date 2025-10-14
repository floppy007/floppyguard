import express from "express";
import errs from "../lib/error.js";
import pjson from "../package.json" with { type: "json" };
import { isSetup } from "../setup.js";
import auditLogRoutes from "./audit-log.js";
import accessListsRoutes from "./nginx/access_lists.js";
import certificatesHostsRoutes from "./nginx/certificates.js";
import deadHostsRoutes from "./nginx/dead_hosts.js";
import proxyHostsRoutes from "./nginx/proxy_hosts.js";
import redirectionHostsRoutes from "./nginx/redirection_hosts.js";
import streamsRoutes from "./nginx/streams.js";
import reportsRoutes from "./reports.js";
import schemaRoutes from "./schema.js";
import settingsRoutes from "./settings.js";
import tokensRoutes from "./tokens.js";
import usersRoutes from "./users.js";
import versionRoutes from "./version.js";
// FloppyGuard extension routes.
import agentRoutes from "./agent.js";
import wireGuardRoutes from "./wireguard.js";
import securityRoutes from "./security.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

/**
 * Health Check
 * GET /api
 */
// Keep both patterns because this router is mounted on `/api` and `/`,
// while express strict routing is enabled.
router.get(["", "/"], async (_, res /*, next*/) => {
	const version = pjson.version.split("-").shift().split(".");
	const setup = await isSetup();

	res.status(200).send({
		status: "OK",
		setup,
		version: {
			major: Number.parseInt(version.shift(), 10),
			minor: Number.parseInt(version.shift(), 10),
			revision: Number.parseInt(version.shift(), 10),
		},
	});
});

router.use("/schema", schemaRoutes);
router.use("/tokens", tokensRoutes);
router.use("/users", usersRoutes);
router.use("/audit-log", auditLogRoutes);
router.use("/reports", reportsRoutes);
router.use("/settings", settingsRoutes);
router.use("/version", versionRoutes);
// FloppyGuard extension routes.
router.use("/", agentRoutes);
router.use("/wireguard", wireGuardRoutes);
router.use("/security", securityRoutes);
router.use("/nginx/proxy-hosts", proxyHostsRoutes);
router.use("/nginx/redirection-hosts", redirectionHostsRoutes);
router.use("/nginx/dead-hosts", deadHostsRoutes);
router.use("/nginx/streams", streamsRoutes);
router.use("/nginx/access-lists", accessListsRoutes);
router.use("/nginx/certificates", certificatesHostsRoutes);

/**
 * API 404 for all other routes
 *
 * ALL /api/*
 */
router.all(/(.+)/, (req, _, next) => {
	req.params.page = req.params["0"];
	next(new errs.ItemNotFoundError(req.params.page));
});

export default router;
