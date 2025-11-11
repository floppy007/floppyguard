import { migrate as logger } from "../logger.js";

const migrateName = "agent_services";

const up = function (knex) {
	logger.info(`[${migrateName}] Migrating Up...`);
	return knex.schema
		.table("agent", (table) => {
			table.text("services").nullable(); // JSON: [{name, url}]
		})
		.then(() => {
			logger.info(`[${migrateName}] agent.services column added`);
		});
};

const down = function (knex) {
	logger.info(`[${migrateName}] Migrating Down...`);
	return knex.schema
		.table("agent", (table) => {
			table.dropColumn("services");
		})
		.then(() => {
			logger.info(`[${migrateName}] agent.services column dropped`);
		});
};

export { up, down };
