import { migrate as logger } from "../logger.js";

const migrateName = "agent_wg_link";

const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	return knex.schema
		.table("agent", (table) => {
			table.string("wg_link_name", 255).nullable();
		})
		.then(() => {
			logger.info(`[${migrateName}] agent.wg_link_name column added`);
		});
};

const down = (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	return knex.schema
		.table("agent", (table) => {
			table.dropColumn("wg_link_name");
		})
		.then(() => {
			logger.info(`[${migrateName}] agent.wg_link_name column dropped`);
		});
};

export { down, up };
