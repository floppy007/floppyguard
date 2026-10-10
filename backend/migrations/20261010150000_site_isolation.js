import { migrate as logger } from "../logger.js";

const migrateName = "site_isolation";

// "Standorte untereinander": one row = two site links that must NOT reach each
// other through the hub (both directions). Links are stored by their stable id
// ("wg0:<pubkey>"), not by name, so a rename never loosens the isolation.
// Order is normalized (link_a < link_b) and the pair is unique. No rows = every
// site may reach every other one (the behaviour before this table existed) —
// this migration deliberately creates no pairs.
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	if (!(await knex.schema.hasTable("site_isolation"))) {
		await knex.schema.createTable("site_isolation", (table) => {
			table.increments().primary();
			table.string("link_a", 128).notNullable();
			table.string("link_b", 128).notNullable();
			table.integer("created_on").unsigned().notNullable();
			table.integer("modified_on").unsigned().notNullable();
			table.unique(["link_a", "link_b"]);
		});
	}
	logger.info(`[${migrateName}] site_isolation ensured`);
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	await knex.schema.dropTableIfExists("site_isolation");
	logger.info(`[${migrateName}] dropped`);
};

export { down, up };
