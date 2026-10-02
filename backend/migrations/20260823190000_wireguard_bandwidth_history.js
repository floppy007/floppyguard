import { migrate as logger } from "../logger.js";

const tableName = "wireguard_bandwidth_history";

// Explicit short index names: knex's generated name for the unique key is 67
// characters, above the 64-character limit of MySQL/MariaDB. Installs that
// already ran an earlier version of this migration are repaired by
// 20261002120000_wireguard_bandwidth_history_indexes.js.
export const UNIQUE_INDEX = "wg_bw_hist_peer_res_bucket_uq";
export const RANGE_INDEX = "wg_bw_hist_res_bucket_idx";

const up = async (knex) => {
	if (await knex.schema.hasTable(tableName)) return;
	await knex.schema.createTable(tableName, (table) => {
		// BIGINT: on MySQL every INSERT ... ON DUPLICATE KEY UPDATE reserves an
		// auto-increment value, even when it ends as an UPDATE.
		table.bigIncrements("id").primary();
		table.string("peer_key", 512).notNullable();
		table.string("resolution", 8).notNullable();
		table.bigInteger("bucket_start").notNullable();
		table.bigInteger("rx_bytes").notNullable().defaultTo(0);
		table.bigInteger("tx_bytes").notNullable().defaultTo(0);
		table.integer("samples").notNullable().defaultTo(0);
		table.unique(["peer_key", "resolution", "bucket_start"], { indexName: UNIQUE_INDEX });
		table.index(["resolution", "bucket_start"], RANGE_INDEX);
	});
	logger.info(`[wireguard_bandwidth_history] ${tableName} created`);
};

const down = (knex) => knex.schema.dropTableIfExists(tableName);

export { down, up };
