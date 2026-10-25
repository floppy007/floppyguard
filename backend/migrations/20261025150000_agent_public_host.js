import { migrate as logger } from "../logger.js";

const migrateName = "agent_public_host";

// Public address of a site (DynDNS name or fixed IPv4), entered by the admin.
// Used as the default endpoint of direct links that dial this site and shown
// with the router settings (port forwards) per site. NULL = not set.
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	if (!(await knex.schema.hasColumn("agent", "public_host"))) {
		await knex.schema.alterTable("agent", (table) => {
			table.string("public_host", 255).nullable();
		});
	}
	logger.info(`[${migrateName}] agent.public_host ensured`);
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	if (await knex.schema.hasColumn("agent", "public_host")) {
		await knex.schema.alterTable("agent", (table) => {
			table.dropColumn("public_host");
		});
	}
	logger.info(`[${migrateName}] dropped`);
};

export { down, up };
