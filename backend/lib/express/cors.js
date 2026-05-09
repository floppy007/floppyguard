/**
 * CORS middleware — only allows same-origin or explicitly configured origins.
 * Set CORS_ALLOWED_ORIGINS env var to a comma-separated list of allowed origins.
 * If unset, only requests where the Origin hostname matches the request hostname
 * are allowed. Disallowed cross-origin requests receive a 403.
 */
export default (req, res, next) => {
	if (req.headers.origin) {
		const allowedRaw = process.env.CORS_ALLOWED_ORIGINS || "";
		const allowed = new Set(
			allowedRaw
				.split(",")
				.map((s) => s.trim())
				.filter(Boolean),
		);

		// Allow if origin matches an explicit allowlist entry, or if no
		// allowlist is configured, allow same-host origins (port may differ
		// between dev frontend and API).
		const origin = req.headers.origin;
		const originHost = (() => {
			try { return new URL(origin).hostname; } catch { return null; }
		})();
		const requestHost = req.hostname || req.headers.host?.split(":")[0];
		const isAllowed = allowed.has(origin) || (allowed.size === 0 && originHost === requestHost);

		if (isAllowed) {
			res.set({
				"Access-Control-Allow-Origin": origin,
				"Access-Control-Allow-Credentials": true,
				"Access-Control-Allow-Methods": "OPTIONS, GET, POST, PUT, DELETE",
				"Access-Control-Allow-Headers":
					"Content-Type, Cache-Control, Pragma, Expires, Authorization, X-Dataset-Total, X-Dataset-Offset, X-Dataset-Limit",
				"Access-Control-Max-Age": 5 * 60,
				"Access-Control-Expose-Headers": "X-Dataset-Total, X-Dataset-Offset, X-Dataset-Limit",
			});
			next();
		} else {
			res.status(403).json({ error: "Origin not allowed" });
		}
	} else {
		next();
	}
};
