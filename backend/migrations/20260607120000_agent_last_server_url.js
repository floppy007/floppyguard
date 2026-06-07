import { migrate as logger } from "../logger.js";

const migrateName = "agent_last_server_url";

/**
 * Record which hub URL each agent last checked in on. Gives the operator
 * visibility during a hub domain/endpoint move (the Daniel/PVE incident class):
 * which agents have adopted the new URL vs are still on the old one.
 */
const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	return knex.schema.alterTable("agent", (table) => {
		table.string("last_server_url", 255).nullable().defaultTo(null);
	});
};

const down = (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	return knex.schema.alterTable("agent", (table) => {
		table.dropColumn("last_server_url");
	});
};

export { up, down };
