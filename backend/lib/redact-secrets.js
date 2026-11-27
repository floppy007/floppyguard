// F-42: Secrets that must never be persisted outside their own table
// (certificate.meta keeps the DNS credentials it needs for renewals).
// - Host rows (proxy/redirection/dead) only pass DNS credentials through to
//   createQuickCertificate; they must not stay in host.meta.
// - Audit-log entries are a copy of the request data; they must not carry DNS
//   API tokens, private keys or Basic-Auth passwords.

export const REDACTED = "[redacted]";

// Keys whose values are secrets wherever they appear in an audit payload.
const AUDIT_SECRET_KEYS = new Set(["dns_provider_credentials", "certificate_key", "password", "secret"]);

const MAX_DEPTH = 12;

/**
 * Deep copy of `value` with every secret key replaced by "[redacted]".
 * Non-plain values (Dates, model instances) are copied via their JSON form.
 * @param {*} value
 * @returns {*}
 */
export const redactSecrets = (value, depth = 0) => {
	if (value === null || typeof value !== "object") return value;
	if (depth > MAX_DEPTH) return REDACTED;
	if (Array.isArray(value)) return value.map((v) => redactSecrets(v, depth + 1));
	const src = typeof value.toJSON === "function" ? value.toJSON() : value;
	if (src === null || typeof src !== "object") return src;
	if (Array.isArray(src)) return redactSecrets(src, depth);
	const out = {};
	for (const [k, v] of Object.entries(src)) {
		if (AUDIT_SECRET_KEYS.has(k) && v !== undefined && v !== null && v !== "") {
			out[k] = REDACTED;
		} else {
			out[k] = redactSecrets(v, depth + 1);
		}
	}
	return out;
};

/**
 * Host meta without DNS provider credentials (they belong to the certificate).
 * Returns the same object when nothing has to be removed.
 * @param {Object} meta
 * @returns {Object}
 */
export const stripHostMetaSecrets = (meta) => {
	if (!meta || typeof meta !== "object" || Array.isArray(meta)) return meta;
	if (!("dns_provider_credentials" in meta)) return meta;
	const { dns_provider_credentials: _drop, ...rest } = meta;
	return rest;
};
