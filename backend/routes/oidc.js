import express from "express";
import internalOidc from "../internal/oidc.js";
import rateLimit from "../lib/express/rate-limit.js";
import { debug, express as logger } from "../logger.js";

// Anmeldung über den OpenID-Connect-Anbieter.
//
// Ablauf:
//   1. /oidc/start setzt ein HttpOnly-Cookie mit state + PKCE-Prüfwert
//      (verschlüsselt) und leitet zum Anbieter.
//   2. /oidc/callback verlangt genau dieses Cookie (state muss passen) - eine
//      fremde Callback-URL in einem anderen Browser läuft damit ins Leere.
//      Das Ergebnis landet in einem kurzlebigen HttpOnly-Cookie, die URL
//      bekommt nur `#sso=done`.
//   3. Die Anmeldeseite holt das Token einmalig per POST /oidc/exchange ab.
//      Ein Token aus der URL wird nie übernommen.
// Fehler werden nur als feste Codes übergeben, nie als freier Text.

const ssoLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, bucket: "sso" });

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

const FLOW_COOKIE = "fg_oidc_flow";
const RESULT_COOKIE = "fg_oidc_result";
const REJECT_REASONS = new Set(["group", "disabled", "noemail"]);

const back = (res, fragment) => res.redirect(302, `/login#${fragment}`);

const cookieOptions = (req, maxAge) => ({
	httpOnly: true,
	sameSite: "lax",
	secure: req.secure,
	path: "/",
	maxAge,
});

const clearCookie = (req, res, name) => {
	res.clearCookie(name, { httpOnly: true, sameSite: "lax", secure: req.secure, path: "/" });
};

/**
 * Liest ein Cookie ohne zusätzliche Abhängigkeit.
 * @param {import("express").Request} req
 * @param {String} name
 * @returns {String}
 */
export const readCookie = (req, name) => {
	const header = typeof req.headers?.cookie === "string" ? req.headers.cookie : "";
	for (const part of header.split(";")) {
		const idx = part.indexOf("=");
		if (idx === -1) continue;
		if (part.slice(0, idx).trim() === name) {
			try {
				return decodeURIComponent(part.slice(idx + 1).trim());
			} catch {
				return "";
			}
		}
	}
	return "";
};

/**
 * Bringt einen vom Anbieter gemeldeten Fehlercode in eine sichere Log-Form
 * (keine Zeilenumbrüche, keine Steuerzeichen, begrenzte Länge).
 */
export const sanitizeProviderError = (value) =>
	String(Array.isArray(value) ? value[0] : value)
		.replace(/[^\w.-]/g, "")
		.slice(0, 64);

router
	.route("/status")
	.options((_, res) => {
		res.sendStatus(204);
	})

	/**
	 * GET /oidc/status
	 *
	 * Sagt der Anmeldeseite, ob der Knopf angezeigt werden soll.
	 */
	.get((_, res) => {
		res.status(200).send(internalOidc.status());
	});

router
	.route("/start")
	.options((_, res) => {
		res.sendStatus(204);
	})

	/**
	 * GET /oidc/start
	 *
	 * Leitet zum Anbieter weiter.
	 */
	.get(ssoLimiter, async (req, res) => {
		try {
			const { url, flow } = await internalOidc.buildAuthorizeUrl();
			res.cookie(FLOW_COOKIE, flow, cookieOptions(req, 10 * 60 * 1000));
			res.redirect(302, url);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			back(res, "sso_error=unconfigured");
		}
	});

router
	.route("/callback")
	.options((_, res) => {
		res.sendStatus(204);
	})

	/**
	 * GET /oidc/callback
	 *
	 * Rückweg vom Anbieter.
	 */
	.get(ssoLimiter, async (req, res) => {
		const flow = readCookie(req, FLOW_COOKIE);
		clearCookie(req, res, FLOW_COOKIE); // einmalig verwendbar
		if (req.query.error) {
			logger.info(`OIDC: Anbieter meldete ${sanitizeProviderError(req.query.error) || "(unbekannt)"}`);
			return back(res, "sso_error=denied");
		}
		const code = typeof req.query.code === "string" ? req.query.code : "";
		const state = typeof req.query.state === "string" ? req.query.state : "";
		if (!code || !state) {
			return back(res, "sso_error=invalid");
		}
		try {
			const result = await internalOidc.completeLogin(code, state, flow);
			res.cookie(RESULT_COOKIE, internalOidc.sealResult(result), cookieOptions(req, 60 * 1000));
			return back(res, "sso=done");
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			if (err.name === "AuthError") {
				if (err.reason === "expired") {
					return back(res, "sso_error=expired");
				}
				const reason = REJECT_REASONS.has(err.reason) ? `&reason=${err.reason}` : "";
				return back(res, `sso_error=rejected${reason}`);
			}
			logger.error(`OIDC: Anmeldung fehlgeschlagen: ${err.message}`);
			return back(res, "sso_error=failed");
		}
	});

router
	.route("/exchange")
	.options((_, res) => {
		res.sendStatus(204);
	})

	/**
	 * POST /oidc/exchange
	 *
	 * Gibt das Ergebnis der Anmeldung genau einmal heraus - nur an den Browser,
	 * der den Rückweg vom Anbieter durchlaufen hat (HttpOnly-Cookie).
	 */
	.post(ssoLimiter, (req, res) => {
		const result = internalOidc.openResult(readCookie(req, RESULT_COOKIE));
		clearCookie(req, res, RESULT_COOKIE);
		if (!result) {
			return res.status(401).send({ error: { code: 401, message: "No pending SSO login" } });
		}
		return res.status(200).send(result);
	});

export default router;
