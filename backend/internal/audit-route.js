// Best-effort audit entries for admin routes whose internal modules do not audit
// themselves (agents, WireGuard, fail2ban). Records WHO did WHAT on which object:
// ids, operation and the NAMES of changed fields — never values, keys or tokens.
// A failing audit write is only logged; it can never fail the request.

import { express as logger } from "../logger.js";
import internalAuditLog from "./audit-log.js";

const MAX_META = 200;

const clip = (v) => String(v ?? "").slice(0, MAX_META);

/** Field names of a JSON body (values deliberately dropped). Pure. */
export function bodyFieldNames(body) {
	if (!body || typeof body !== "object" || Array.isArray(body)) return [];
	return Object.keys(body)
		.slice(0, 30)
		.map((k) => clip(k));
}

/**
 * Express middleware: after a successful (< 400) response, write one audit entry
 * described by `describe(info)`. `info` is captured when the request enters, so a
 * later req.url rewrite by the router cannot change it. describe returns
 * { action, object_id?, meta } or null (= not audited).
 */
export function auditOnSuccess(objectType, describe) {
	return (req, res, next) => {
		const info = {
			method: String(req.method || "").toUpperCase(),
			path: req.path,
			params: { ...(req.params || {}) },
			query: { ...(req.query || {}) },
			body: req.body,
		};
		let entry = null;
		try {
			entry = describe(info);
		} catch {
			entry = null;
		}
		if (entry) {
			res.on("finish", () => {
				const access = res.locals?.access;
				if (res.statusCode >= 400 || !access?.token) return;
				internalAuditLog
					.add(access, {
						action: entry.action,
						object_type: objectType,
						object_id: Number.isInteger(entry.object_id) ? entry.object_id : 0,
						meta: entry.meta || {},
					})
					.catch((err) => logger.warn(`${objectType} audit log failed: ${err.message}`));
			});
		}
		next();
	};
}

/** Audit entry for a WireGuard route (router mounted at /wireguard). Pure. */
export function describeWireGuardRequest({ method, path, query, body }) {
	const p = String(path || "");
	const b = body && typeof body === "object" ? body : {};
	let op = null;
	let action = "updated";
	let target = "";
	if (method === "GET") {
		// Peer config / QR downloads hand out (and may rotate) private keys.
		if (p === "/link-config" || p === "/link-config-qr") {
			op = p.slice(1);
			target = query?.link_id;
		}
	} else if (method === "POST" && p === "/plan-preview") {
		op = null; // read-only
	} else if (method === "POST" && b.dryRun === true && (p === "/delete-peer" || p === "/delete-interface")) {
		op = null; // read-only bound-agent check
	} else if (["POST", "PUT", "DELETE"].includes(method)) {
		const peerPath = /^\/peers\/(.+)$/.exec(p);
		const ifacePath = /^\/interfaces\/([^/]+)$/.exec(p);
		if (peerPath) {
			op = method === "DELETE" ? "delete-peer" : "update-peer";
			target = decodeURIComponent(peerPath[1]);
		} else if (ifacePath) {
			op = "delete-interface";
			target = decodeURIComponent(ifacePath[1]);
		} else if (p === "/peers") {
			op = "create-peer";
			target = b.name;
		} else if (p === "/interfaces") {
			op = "create-interface";
			target = b.name || b.address;
		} else {
			op = p.replace(/^\//, "") || "wireguard";
			target = b.linkId || b.link_id || b.name || b.backupPath || "";
		}
		if (/^delete-/.test(op)) action = "deleted";
		else if (/^create-/.test(op)) action = "created";
	}
	if (!op) return null;
	const t = clip(target);
	return {
		action,
		meta: {
			name: t ? `${op}: ${t}` : op,
			op,
			...(t ? { target: t } : {}),
			fields: bodyFieldNames(method === "GET" ? null : b),
		},
	};
}

/** Audit entry for an admin agent route (/agents, /agents/:id[/reset-token|/install]). Pure. */
export function describeAgentRequest({ method, path, params, query, body }) {
	const id = Number.parseInt(params?.id, 10);
	const p = String(path || "");
	let op = null;
	let action = "updated";
	if (p === "/agents" && method === "POST") {
		op = "create";
		action = "created";
	} else if (/^\/agents\/\d+$/.test(p) && method === "PUT") {
		op = "update";
	} else if (/^\/agents\/\d+$/.test(p) && method === "DELETE") {
		// Forced delete of an offline agent (skips the Freigaben teardown check).
		op = query?.force === "1" || query?.force === "true" ? "force-delete" : "delete";
		action = "deleted";
	} else if (/\/reset-token$/.test(p) && method === "POST") {
		op = "reset-token";
	} else if (/\/install$/.test(p) && method === "GET") {
		op = "install-script"; // carries the reg_token
	}
	if (!op) return null;
	const name = op === "create" ? clip(body?.name) : Number.isInteger(id) ? `#${id}` : "";
	return {
		action,
		object_id: Number.isInteger(id) ? id : 0,
		meta: { name: name ? `${name} (${op})` : op, op, fields: bodyFieldNames(method === "GET" ? null : body) },
	};
}
