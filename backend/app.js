import bodyParser from "body-parser";
import compression from "compression";
import express from "express";
import { isDebugMode } from "./lib/config.js";
import cors from "./lib/express/cors.js";
import jwt from "./lib/express/jwt.js";
import remoteGuard from "./lib/express/remote-guard.js";
import { debug, express as logger } from "./logger.js";
import mainRoutes from "./routes/main.js";

/**
 * App
 */
const app = express();
// Datei-Uploads werden nur in den jeweiligen Routen (nach der Anmeldung und
// mit Größengrenzen) angenommen, siehe lib/express/file-upload.js.
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Gzip
app.use(compression());

/**
 * General Logging, BEFORE routes
 */

app.disable("x-powered-by");
// Only the agent API is served to non-loopback clients (see remote-guard.js).
app.use(remoteGuard());
// Only the local nginx is a real proxy. NOTE: app.enable() ignores a value
// argument and would set trust proxy = true, letting any client choose req.ip
// (and therefore its rate-limit bucket) via X-Forwarded-For.
app.set("trust proxy", "loopback");
app.enable("strict routing");

// pretty print JSON when not live
if (isDebugMode()) {
	app.set("json spaces", 2);
}

// CORS for everything
app.use(cors);

// General security/cache related headers + server header
app.use((_, res, next) => {
	let x_frame_options = "DENY";

	if (typeof process.env.X_FRAME_OPTIONS !== "undefined" && process.env.X_FRAME_OPTIONS) {
		x_frame_options = process.env.X_FRAME_OPTIONS;
	}

	res.set({
		"X-XSS-Protection": "1; mode=block",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options": x_frame_options,
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; frame-ancestors 'none'",
		"Cache-Control": "no-cache, no-store, max-age=0, must-revalidate",
		Pragma: "no-cache",
		Expires: 0,
	});
	next();
});

app.use(jwt());
app.use("/api", mainRoutes);
app.use("/", mainRoutes);

// production error handler
// no stacktraces leaked to user
app.use((err, _req, res, _) => {
	// objection ValidationError (bad ?expand= relation / eager expression, model validation)
	// exposes `statusCode` (400) instead of `status`/`public`; treat 4xx as a public client error.
	if (
		typeof err.status === "undefined" &&
		Number.isInteger(err.statusCode) &&
		err.statusCode >= 400 &&
		err.statusCode < 500
	) {
		err.status = err.statusCode;
		err.public = true;
	}
	const payload = {
		error: {
			code: err.status || 500,
			message: err.public ? err.message : "Internal Error",
		},
	};

	if (typeof err.message_i18n !== "undefined") {
		payload.error.message_i18n = err.message_i18n;
	}

	if (isDebugMode() && process.env.NODE_ENV !== "production") {
		payload.debug = {
			stack: typeof err.stack !== "undefined" && err.stack ? err.stack.split("\n") : null,
			previous: err.previous,
		};
	}

	// Not every error is worth logging - but this is good for now until it gets annoying.
	if (typeof err.stack !== "undefined" && err.stack) {
		debug(logger, err.stack);
		if (typeof err.public === "undefined" || !err.public) {
			logger.warn(err.message);
		}
	}

	res.status(err.status || 500).send(payload);
});

export default app;
