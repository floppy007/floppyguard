import { migrate as logger } from "../logger.js";

const migrateName = "add-indexes";

/**
 * Add indexes on frequently queried columns for better performance.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	// proxy_host indexes
	await knex.schema.alterTable("proxy_host", (table) => {
		table.index("is_deleted");
		table.index("owner_user_id");
	});
	logger.info(`[${migrateName}] proxy_host indexes added`);

	// redirection_host indexes
	await knex.schema.alterTable("redirection_host", (table) => {
		table.index("is_deleted");
		table.index("owner_user_id");
	});
	logger.info(`[${migrateName}] redirection_host indexes added`);

	// dead_host indexes
	await knex.schema.alterTable("dead_host", (table) => {
		table.index("is_deleted");
		table.index("owner_user_id");
	});
	logger.info(`[${migrateName}] dead_host indexes added`);

	// stream indexes
	await knex.schema.alterTable("stream", (table) => {
		table.index("is_deleted");
		table.index("owner_user_id");
	});
	logger.info(`[${migrateName}] stream indexes added`);

	// certificate indexes
	await knex.schema.alterTable("certificate", (table) => {
		table.index("is_deleted");
	});
	logger.info(`[${migrateName}] certificate indexes added`);

	// user indexes
	await knex.schema.alterTable("user", (table) => {
		table.index("is_deleted");
		table.index("is_disabled");
	});
	logger.info(`[${migrateName}] user indexes added`);

	// auth indexes
	await knex.schema.alterTable("auth", (table) => {
		table.index("user_id");
		table.index("is_deleted");
	});
	logger.info(`[${migrateName}] auth indexes added`);

	// agent indexes
	await knex.schema.alterTable("agent", (table) => {
		table.index("is_deleted");
		table.index("status");
	});
	logger.info(`[${migrateName}] agent indexes added`);
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);

	await knex.schema.alterTable("proxy_host", (table) => {
		table.dropIndex("is_deleted");
		table.dropIndex("owner_user_id");
	});
	await knex.schema.alterTable("redirection_host", (table) => {
		table.dropIndex("is_deleted");
		table.dropIndex("owner_user_id");
	});
	await knex.schema.alterTable("dead_host", (table) => {
		table.dropIndex("is_deleted");
		table.dropIndex("owner_user_id");
	});
	await knex.schema.alterTable("stream", (table) => {
		table.dropIndex("is_deleted");
		table.dropIndex("owner_user_id");
	});
	await knex.schema.alterTable("certificate", (table) => {
		table.dropIndex("is_deleted");
	});
	await knex.schema.alterTable("user", (table) => {
		table.dropIndex("is_deleted");
		table.dropIndex("is_disabled");
	});
	await knex.schema.alterTable("auth", (table) => {
		table.dropIndex("user_id");
		table.dropIndex("is_deleted");
	});
	await knex.schema.alterTable("agent", (table) => {
		table.dropIndex("is_deleted");
		table.dropIndex("status");
	});
};

export { up, down };
