import { exec } from "node:child_process";
import { promisify } from "node:util";
import express from "express";
import jwtdecode from "../lib/express/jwt-decode.js";
import error from "../lib/error.js";
import { debug, express as logger } from "../logger.js";

const execAsync = promisify(exec);
const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

/**
 * Run fail2ban-client and return stdout, or null if not available.
 */
async function f2b(...args) {
	try {
		const { stdout } = await execAsync(`fail2ban-client ${args.join(" ")}`, { timeout: 5000 });
		return stdout.trim();
	} catch {
		return null;
	}
}

/**
 * Parse "fail2ban-client status <jail>" output into a structured object.
 */
function parseJailStatus(raw) {
	if (!raw) return null;
	const get = (label) => {
		const m = raw.match(new RegExp(`${label}:\\s*(.+)`));
		return m ? m[1].trim() : "";
	};
	const bannedRaw = get("Banned IP list");
	return {
		currentlyFailed: parseInt(get("Currently failed"), 10) || 0,
		totalFailed:     parseInt(get("Total failed"),     10) || 0,
		currentlyBanned: parseInt(get("Currently banned"), 10) || 0,
		totalBanned:     parseInt(get("Total banned"),     10) || 0,
		bannedIps:       bannedRaw ? bannedRaw.split(/\s+/).filter(Boolean) : [],
	};
}

/**
 * GET /api/security/fail2ban
 * Returns all jails and their current status.
 */
router.route("/fail2ban")
	.options((_, res) => { res.sendStatus(204); })
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const statusRaw = await f2b("status");
			if (!statusRaw) {
				return res.status(200).send({ available: false, jails: [] });
			}

			const m = statusRaw.match(/Jail list:\s*(.+)/);
			const jailNames = m ? m[1].split(",").map((s) => s.trim()).filter(Boolean) : [];

			const jails = await Promise.all(
				jailNames.map(async (name) => {
					const raw = await f2b("status", name);
					return { name, ...parseJailStatus(raw) };
				}),
			);

			res.status(200).send({ available: true, jails });
		} catch (err) {
			debug(logger, `${req.method} ${req.path}: ${err}`);
			next(err);
		}
	});

/**
 * DELETE /api/security/fail2ban/:jail/:ip
 * Unban an IP from a specific jail.
 */
router.route("/fail2ban/:jail/:ip")
	.options((_, res) => { res.sendStatus(204); })
	.all(jwtdecode())
	.delete(async (req, res, next) => {
		try {
			const { jail, ip } = req.params;
			if (!/^[\w-]+$/.test(jail)) return next(new error.ValidationError("Invalid jail name"));
			if (!/^[\d.:a-fA-F/]+$/.test(ip)) return next(new error.ValidationError("Invalid IP address"));
			await f2b("set", jail, "unbanip", ip);
			res.status(200).send({ unbanned: true, jail, ip });
		} catch (err) {
			debug(logger, `${req.method} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
