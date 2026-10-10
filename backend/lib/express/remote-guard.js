// The backend listens on every interface because the site agents reach it
// directly through the tunnel (http://10.10.0.1:3300/api/agent/*). Everything
// else (login, users, WireGuard, OIDC, …) is only meant to be used through the
// local nginx, which logs it for fail2ban. Requests that do not come from
// loopback may therefore only use the agent endpoints and the status probe the
// agent uses to pick a reachable server (GET /api).
//
// BACKEND_ALLOW_REMOTE_API=true switches the guard off (dev/preview setups
// whose proxy is not on the same host).

// Agent endpoints are /agent/* (singular); /agents (plural) is the admin API.
const REMOTE_ALLOWED_PATH = /^(?:\/api)?\/agent\/[^/]/;
const STATUS_PATHS = new Set(["/api", "/api/"]);

export const isLoopbackAddress = (addr) => {
	if (typeof addr !== "string" || addr === "") return false;
	const a = addr.startsWith("::ffff:") ? addr.slice(7) : addr;
	return a === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(a);
};

export const remoteRequestAllowed = (remoteAddress, method, path) => {
	if (isLoopbackAddress(remoteAddress)) return true;
	if (REMOTE_ALLOWED_PATH.test(path)) return true;
	return (method === "GET" || method === "HEAD") && STATUS_PATHS.has(path);
};

export default function remoteGuard() {
	const disabled = process.env.BACKEND_ALLOW_REMOTE_API === "true";
	return (req, res, next) => {
		// The socket address, not req.ip: X-Forwarded-For must not open this.
		if (disabled || remoteRequestAllowed(req.socket?.remoteAddress, req.method, req.path)) {
			return next();
		}
		res.status(403).send({ error: { code: 403, message: "Forbidden" } });
	};
}
