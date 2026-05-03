import { migrate as logger } from "../logger.js";

const migrateName = "agent";

/**
 * Migrate
 *
 * @see http://knexjs.org/#Schema
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	return knex.schema
		.createTable("agent", (table) => {
			table.increments("id").primary();
			table.string("name", 255).notNullable();
			table.string("reg_token", 255).nullable();
			table.string("agent_token", 255).nullable();
			table.string("hostname", 255).nullable();
			table.string("mode", 50).notNullable().defaultTo("native");          // native | unifi
			table.string("wg_interface", 50).notNullable().defaultTo("wg0");
			// native mode: wg-quick config text
			table.text("config_text").nullable();
			table.string("config_hash", 255).nullable();
			// unifi mode: controller connection
			table.string("unifi_url", 255).nullable();         // https://192.168.10.7
			table.string("unifi_user", 255).nullable();
			table.string("unifi_pass", 255).nullable();
			table.string("unifi_site", 100).nullable().defaultTo("default");
			table.integer("last_seen").nullable();
			table.string("status", 50).notNullable().defaultTo("pending");
			table.integer("created_on").notNullable();
			table.integer("modified_on").notNullable();
			table.tinyint("is_deleted").notNullable().defaultTo(0);
		})
		.then(() => {
			logger.info(`[${migrateName}] agent Table created`);
		});
};

/**
 * Undo Migrate
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const down = (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);

	return knex.schema
		.dropTable("agent")
		.then(() => {
			logger.info(`[${migrateName}] agent Table dropped`);
		});
};

export { up, down };
