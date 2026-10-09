import { migrate as logger } from "../logger.js";

const migrateName = "agent_drop_unifi";
const UNIFI_COLUMNS = ["unifi_url", "unifi_user", "unifi_pass", "unifi_site"];

// The UniFi agent mode was removed; every agent is native from here on.
// Dropping the columns also discards any stored controller credentials.
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex("agent").where("mode", "unifi").update({ mode: "native" });
	for (const col of UNIFI_COLUMNS) {
		if (await knex.schema.hasColumn("agent", col)) {
			await knex.schema.table("agent", (table) => {
				table.dropColumn(col);
			});
		}
	}
	logger.info(`[${migrateName}] agent UniFi columns dropped`);
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	await knex.schema.table("agent", (table) => {
		table.string("unifi_url", 255).nullable();
		table.string("unifi_user", 255).nullable();
		table.string("unifi_pass", 255).nullable();
		table.string("unifi_site", 100).nullable().defaultTo("default");
	});
	logger.info(`[${migrateName}] agent UniFi columns restored`);
};

export { down, up };
