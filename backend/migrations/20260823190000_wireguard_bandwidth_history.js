import { migrate as logger } from "../logger.js";

const tableName = "wireguard_bandwidth_history";

const up = async (knex) => {
	if (await knex.schema.hasTable(tableName)) return;
	await knex.schema.createTable(tableName, (table) => {
		table.increments("id").primary();
		table.string("peer_key", 512).notNullable();
		table.string("resolution", 8).notNullable();
		table.bigInteger("bucket_start").notNullable();
		table.bigInteger("rx_bytes").notNullable().defaultTo(0);
		table.bigInteger("tx_bytes").notNullable().defaultTo(0);
		table.integer("samples").notNullable().defaultTo(0);
		table.unique(["peer_key", "resolution", "bucket_start"]);
		table.index(["resolution", "bucket_start"]);
	});
	logger.info(`[wireguard_bandwidth_history] ${tableName} created`);
};

const down = (knex) => knex.schema.dropTableIfExists(tableName);

export { down, up };
