import { migrate as logger } from "../logger.js";

const migrateName = "agent_config_applied";

// WireGuard config feedback: the agent reports in its heartbeat which config hash
// it actually runs (written only after a successful apply) and the last apply
// error. The hub compares that with config_hash, so an agent stuck on an old
// config (no PrivateKey, syncconf / wg-quick up failing) no longer looks healthy.
// Both columns nullable = "not reported" (older agent).
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	if (!(await knex.schema.hasColumn("agent", "config_applied_hash"))) {
		await knex.schema.table("agent", (table) => {
			table.string("config_applied_hash", 64).nullable();
		});
	}
	if (!(await knex.schema.hasColumn("agent", "config_error"))) {
		await knex.schema.table("agent", (table) => {
			table.string("config_error", 255).nullable();
		});
	}
	logger.info(`[${migrateName}] agent.config_applied_hash + agent.config_error ensured`);
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	for (const col of ["config_applied_hash", "config_error"]) {
		if (await knex.schema.hasColumn("agent", col)) {
			await knex.schema.table("agent", (table) => {
				table.dropColumn(col);
			});
		}
	}
	logger.info(`[${migrateName}] dropped`);
};

export { down, up };
