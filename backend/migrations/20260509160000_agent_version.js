import { migrate as logger } from "../logger.js";

const migrateName = "agent_version";

const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	return knex.schema.alterTable("agent", (table) => {
		table.string("agent_version", 32).nullable().defaultTo(null);
	});
};

const down = (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	return knex.schema.alterTable("agent", (table) => {
		table.dropColumn("agent_version");
	});
};

export { up, down };
