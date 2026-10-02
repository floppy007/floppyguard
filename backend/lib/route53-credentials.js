// Route53-Zugangsdaten für certbot-dns-route53.
//
// Der Text landete früher unverändert in einer Datei, die boto3 als AWS-
// Config-Datei las. Darüber ließ sich z. B. `credential_process` setzen und
// ein beliebiger Befehl als root ausführen. Deshalb werden nur die bekannten
// Schlüssel im Profil [default] akzeptiert und die Datei neu aufgebaut.

const ALLOWED = {
	aws_access_key_id: /^[A-Z0-9]{16,128}$/,
	aws_secret_access_key: /^[A-Za-z0-9/+=]{16,128}$/,
	aws_session_token: /^[A-Za-z0-9/+=]{16,4096}$/,
	region: /^[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}$/,
};
const ORDER = Object.keys(ALLOWED);

/**
 * Prüft Route53-Zugangsdaten und liefert sie in kanonischer Form.
 *
 * @param {string} text
 * @returns {string}
 * @throws {Error} bei unbekannten Schlüsseln, Abschnitten oder Werten
 */
export const normalizeRoute53Credentials = (text) => {
	if (typeof text !== "string") {
		throw new Error("Route53 credentials must be text");
	}
	const values = {};
	let section = "default";
	for (const rawLine of text.split(/\r?\n/)) {
		const line = rawLine.trim();
		if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
		const header = line.match(/^\[\s*([^\]]*?)\s*\]$/);
		if (header) {
			section = header[1];
			if (section !== "default") {
				throw new Error("Route53 credentials may only contain the [default] section");
			}
			continue;
		}
		const pair = line.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
		if (!pair) {
			throw new Error("Route53 credentials contain an invalid line");
		}
		const key = pair[1].toLowerCase();
		const value = pair[2].trim();
		if (!Object.hasOwn(ALLOWED, key)) {
			throw new Error(`Route53 credentials: key "${key}" is not allowed`);
		}
		if (!ALLOWED[key].test(value)) {
			throw new Error(`Route53 credentials: invalid value for ${key}`);
		}
		values[key] = value;
	}
	if (!values.aws_access_key_id || !values.aws_secret_access_key) {
		throw new Error("Route53 credentials need aws_access_key_id and aws_secret_access_key");
	}
	const lines = ["[default]"];
	for (const key of ORDER) {
		if (values[key] !== undefined) lines.push(`${key}=${values[key]}`);
	}
	return `${lines.join("\n")}\n`;
};

/**
 * Inhalt für die Zugangsdaten-Datei eines DNS-Anbieters. Für route53 nur in
 * geprüfter, neu aufgebauter Form; andere Anbieter unverändert.
 *
 * @param {string} provider
 * @param {string} credentials
 * @returns {string}
 */
export const credentialsFileContent = (provider, credentials) =>
	provider === "route53" ? normalizeRoute53Credentials(credentials) : credentials;
