import { migrate as logger } from "../logger.js";

// Widens wireguard_bandwidth_history.id to BIGINT. The traffic poller upserts
// three rows per peer every 10 seconds; on MySQL/MariaDB (InnoDB,
// innodb_autoinc_lock_mode 1/2) each INSERT ... ON DUPLICATE KEY UPDATE
// reserves an auto-increment value even when it only updates. With INT
// UNSIGNED the id range runs out after months to years and all history writes
// fail. SQLite ids are already 64-bit.

const migrateName = "wireguard_bandwidth_history_bigint_id";
const tableName = "wireguard_bandwidth_history";

const dialectOf = (knex) => {
	const name = String(knex.client?.dialect || knex.client?.config?.client || "").toLowerCase();
	if (name.includes("mysql") || name.includes("maria")) return "mysql";
	if (name.includes("sqlite")) return "sqlite";
	if (name.includes("postg") || name === "pg") return "postgres";
	return name;
};

const up = async (knex) => {
	if (!(await knex.schema.hasTable(tableName))) return;
	const dialect = dialectOf(knex);
	if (dialect === "mysql") {
		await knex.raw("ALTER TABLE ?? MODIFY ?? BIGINT UNSIGNED NOT NULL AUTO_INCREMENT", [tableName, "id"]);
	} else if (dialect === "postgres") {
		await knex.raw("ALTER TABLE ?? ALTER COLUMN ?? TYPE BIGINT", [tableName, "id"]);
		await knex.raw("ALTER SEQUENCE IF EXISTS ?? AS BIGINT", [`${tableName}_id_seq`]);
	} else {
		return;
	}
	logger.info(`[${migrateName}] ${tableName}.id widened to BIGINT`);
};

// Narrowing back could fail once ids exceed the INT range; keep BIGINT.
const down = async () => {};

export { down, up };
