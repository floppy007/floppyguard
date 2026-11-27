import { redactSecrets, stripHostMetaSecrets } from "../lib/redact-secrets.js";
import { migrate as logger } from "../logger.js";

const migrateName = "redact_stored_secrets";

// F-42: DNS provider credentials were copied into host.meta (quick certificate
// with DNS challenge) and, like Basic-Auth passwords and private keys, into the
// audit log. The certificate keeps its own copy for renewals; everything else
// is removed / redacted here. Idempotent, data only.
const parse = (raw) => {
	if (raw === null || raw === undefined) return null;
	if (typeof raw === "object") return raw;
	try {
		return JSON.parse(raw);
	} catch {
		return null;
	}
};

const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	for (const table of ["proxy_host", "redirection_host", "dead_host"]) {
		if (!(await knex.schema.hasTable(table))) continue;
		const rows = await knex(table).select("id", "meta").where("meta", "like", "%dns_provider_credentials%");
		for (const row of rows) {
			const meta = parse(row.meta);
			if (!meta) continue;
			await knex(table)
				.where("id", row.id)
				.update({ meta: JSON.stringify(stripHostMetaSecrets(meta)) });
		}
		logger.info(`[${migrateName}] ${table}: ${rows.length} row(s) cleaned`);
	}
	if (await knex.schema.hasTable("audit_log")) {
		const rows = await knex("audit_log")
			.select("id", "meta")
			.where((q) =>
				q
					.where("meta", "like", "%dns_provider_credentials%")
					.orWhere("meta", "like", "%certificate_key%")
					.orWhere("meta", "like", '%"password"%')
					.orWhere("meta", "like", '%"secret"%'),
			);
		let changed = 0;
		for (const row of rows) {
			const meta = parse(row.meta);
			if (!meta) continue;
			const next = JSON.stringify(redactSecrets(meta));
			if (next !== JSON.stringify(meta)) {
				await knex("audit_log").where("id", row.id).update({ meta: next });
				changed += 1;
			}
		}
		logger.info(`[${migrateName}] audit_log: ${changed} row(s) redacted`);
	}
};

// Redacted secrets cannot be restored.
const down = async () => {
	logger.info(`[${migrateName}] Migrating Down... (nothing to do)`);
};

export { down, up };
