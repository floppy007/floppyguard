import { migrate as logger } from "../logger.js";

// Repairs wireguard_bandwidth_history on installs where the original migration
// (20260823190000) failed half-way on MySQL/MariaDB: the CREATE TABLE committed,
// the ADD UNIQUE failed (generated index name > 64 characters), and the retry
// skipped everything because the table already existed. Such tables have no
// UNIQUE(peer_key, resolution, bucket_start) and no (resolution, bucket_start)
// index. This migration merges any duplicate bucket rows and then adds whatever
// index is missing. It is a no-op on healthy tables.

const migrateName = "wireguard_bandwidth_history_indexes";
const tableName = "wireguard_bandwidth_history";
const UNIQUE_COLUMNS = ["peer_key", "resolution", "bucket_start"];
const RANGE_COLUMNS = ["resolution", "bucket_start"];
const UNIQUE_INDEX = "wg_bw_hist_peer_res_bucket_uq";
const RANGE_INDEX = "wg_bw_hist_res_bucket_idx";

const dialectOf = (knex) => {
	const name = String(knex.client?.dialect || knex.client?.config?.client || "").toLowerCase();
	if (name.includes("mysql") || name.includes("maria")) return "mysql";
	if (name.includes("sqlite")) return "sqlite";
	if (name.includes("postg") || name === "pg") return "postgres";
	return name;
};

const rowsOf = (result) => {
	if (Array.isArray(result) && Array.isArray(result[0])) return result[0]; // mysql2
	if (Array.isArray(result)) return result; // sqlite
	if (result && Array.isArray(result.rows)) return result.rows; // pg
	return [];
};

/**
 * @returns {Promise<Array<{ name: string, unique: boolean, columns: string[] }>>}
 */
export const listIndexes = async (knex, table) => {
	const dialect = dialectOf(knex);
	if (dialect === "mysql") {
		const rows = rowsOf(await knex.raw("SHOW INDEX FROM ??", [table]));
		const byName = new Map();
		for (const row of rows) {
			const name = row.Key_name;
			const entry = byName.get(name) ?? { name, unique: Number(row.Non_unique) === 0, columns: [] };
			entry.columns[Number(row.Seq_in_index) - 1] = row.Column_name;
			byName.set(name, entry);
		}
		return [...byName.values()];
	}
	if (dialect === "sqlite") {
		const list = rowsOf(await knex.raw(`PRAGMA index_list(${JSON.stringify(table)})`));
		const result = [];
		for (const idx of list) {
			const info = rowsOf(await knex.raw(`PRAGMA index_info(${JSON.stringify(idx.name)})`));
			result.push({
				name: idx.name,
				unique: Number(idx.unique) === 1,
				columns: info.sort((a, b) => a.seqno - b.seqno).map((c) => c.name),
			});
		}
		return result;
	}
	if (dialect === "postgres") {
		const rows = rowsOf(
			await knex.raw("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = ?", [table]),
		);
		return rows.map((row) => {
			const cols = /\(([^)]*)\)\s*$/.exec(row.indexdef)?.[1] ?? "";
			return {
				name: row.indexname,
				unique: /\bUNIQUE\b/i.test(row.indexdef),
				columns: cols.split(",").map((c) => c.trim().replace(/^"|"$/g, "")),
			};
		});
	}
	return [];
};

const hasIndexOn = (indexes, columns, unique) =>
	indexes.some(
		(idx) =>
			(!unique || idx.unique) &&
			idx.columns.length >= columns.length &&
			columns.every((col, i) => idx.columns[i] === col),
	);

const mergeDuplicates = async (knex) => {
	const groups = await knex(tableName)
		.select(UNIQUE_COLUMNS)
		.count({ n: "*" })
		.groupBy(UNIQUE_COLUMNS)
		.havingRaw("count(*) > 1");
	for (const group of groups) {
		const rows = await knex(tableName)
			.where({ peer_key: group.peer_key, resolution: group.resolution, bucket_start: group.bucket_start })
			.orderBy("id", "asc");
		if (rows.length < 2) continue;
		const [keep, ...rest] = rows;
		const sum = (field) => rows.reduce((acc, row) => acc + Number(row[field] || 0), 0);
		await knex(tableName)
			.where({ id: keep.id })
			.update({ rx_bytes: sum("rx_bytes"), tx_bytes: sum("tx_bytes"), samples: sum("samples") });
		await knex(tableName)
			.whereIn(
				"id",
				rest.map((row) => row.id),
			)
			.delete();
	}
	return groups.length;
};

const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	if (!(await knex.schema.hasTable(tableName))) {
		return;
	}
	let indexes = await listIndexes(knex, tableName);

	if (!hasIndexOn(indexes, UNIQUE_COLUMNS, true)) {
		const merged = await mergeDuplicates(knex);
		if (merged) {
			logger.info(`[${migrateName}] merged ${merged} duplicate bucket group(s)`);
		}
		await knex.schema.alterTable(tableName, (table) => {
			table.unique(UNIQUE_COLUMNS, { indexName: UNIQUE_INDEX });
		});
		logger.info(`[${migrateName}] unique index ${UNIQUE_INDEX} added`);
		indexes = await listIndexes(knex, tableName);
	}

	if (!hasIndexOn(indexes, RANGE_COLUMNS, false)) {
		await knex.schema.alterTable(tableName, (table) => {
			table.index(RANGE_COLUMNS, RANGE_INDEX);
		});
		logger.info(`[${migrateName}] index ${RANGE_INDEX} added`);
	}
};

// Indexes only; nothing to undo that would not also break the table.
const down = async () => {};

export { down, up };
