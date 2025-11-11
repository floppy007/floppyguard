import { migrate as logger } from "../logger.js";

const migrateName = "agent_mgmt_url";

const up = function (knex) {
	logger.info(`[${migrateName}] Migrating Up...`);
	return knex.schema
		.table("agent", (table) => {
			table.string("mgmt_url", 512).nullable();
		})
		.then(() => {
			logger.info(`[${migrateName}] agent.mgmt_url column added`);
		});
};

const down = function (knex) {
	logger.info(`[${migrateName}] Migrating Down...`);
	return knex.schema
		.table("agent", (table) => {
			table.dropColumn("mgmt_url");
		})
		.then(() => {
			logger.info(`[${migrateName}] agent.mgmt_url column dropped`);
		});
};

export { up, down };
