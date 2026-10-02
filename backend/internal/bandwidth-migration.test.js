import assert from "node:assert/strict";
import { describe, it } from "node:test";
import knexFactory from "knex";
import * as original from "../migrations/20260823190000_wireguard_bandwidth_history.js";
import * as repair from "../migrations/20261002120000_wireguard_bandwidth_history_indexes.js";

const table = "wireguard_bandwidth_history";
const sqlite = () =>
	knexFactory({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });

describe("wireguard_bandwidth_history migrations", () => {
	it("uses index names that fit MySQL's 64-character limit", () => {
		const mysql = knexFactory({ client: "mysql2" });
		const statements = mysql.schema
			.createTable(table, (t) => {
				t.increments("id").primary();
				t.string("peer_key", 512);
				t.string("resolution", 8);
				t.bigInteger("bucket_start");
				t.unique(["peer_key", "resolution", "bucket_start"], { indexName: original.UNIQUE_INDEX });
				t.index(["resolution", "bucket_start"], original.RANGE_INDEX);
			})
			.toSQL()
			.map((s) => s.sql)
			.join("\n");
		const names = [...statements.matchAll(/(?:unique|index) `([^`]+)`/gi)].map((m) => m[1]);
		assert.ok(names.length >= 2, statements);
		for (const name of names) assert.ok(name.length <= 64, name);
	});

	it("repairs a table left without indexes and merges duplicate buckets", async () => {
		const knex = sqlite();
		try {
			// State left behind by the failed MySQL run: table, no indexes.
			await knex.schema.createTable(table, (t) => {
				t.increments("id").primary();
				t.string("peer_key", 512).notNullable();
				t.string("resolution", 8).notNullable();
				t.bigInteger("bucket_start").notNullable();
				t.bigInteger("rx_bytes").notNullable().defaultTo(0);
				t.bigInteger("tx_bytes").notNullable().defaultTo(0);
				t.integer("samples").notNullable().defaultTo(0);
			});
			await knex(table).insert([
				{ peer_key: "wg0:A", resolution: "1m", bucket_start: 60, rx_bytes: 10, tx_bytes: 1, samples: 1 },
				{ peer_key: "wg0:A", resolution: "1m", bucket_start: 60, rx_bytes: 5, tx_bytes: 2, samples: 2 },
				{ peer_key: "wg0:A", resolution: "1m", bucket_start: 120, rx_bytes: 7, tx_bytes: 7, samples: 1 },
			]);

			await repair.up(knex);

			const rows = await knex(table).where({ peer_key: "wg0:A", bucket_start: 60 });
			assert.equal(rows.length, 1);
			assert.equal(Number(rows[0].rx_bytes), 15);
			assert.equal(Number(rows[0].tx_bytes), 3);
			assert.equal(Number(rows[0].samples), 3);

			const indexes = await repair.listIndexes(knex, table);
			assert.ok(indexes.some((i) => i.unique && i.columns.join() === "peer_key,resolution,bucket_start"));
			assert.ok(indexes.some((i) => i.columns.join() === "resolution,bucket_start"));

			// Unique key now enforced: the atomic upsert path works.
			await knex(table)
				.insert({ peer_key: "wg0:A", resolution: "1m", bucket_start: 60, rx_bytes: 1, tx_bytes: 1, samples: 1 })
				.onConflict(["peer_key", "resolution", "bucket_start"])
				.merge({
					rx_bytes: knex.raw("?? + ?", [`${table}.rx_bytes`, 1]),
					tx_bytes: knex.raw("?? + ?", [`${table}.tx_bytes`, 1]),
					samples: knex.raw("?? + 1", [`${table}.samples`]),
				});
			const [merged] = await knex(table).where({ peer_key: "wg0:A", bucket_start: 60 });
			assert.equal(Number(merged.rx_bytes), 16);
			assert.equal(Number(merged.samples), 4);

			// Idempotent.
			await repair.up(knex);
			assert.equal((await repair.listIndexes(knex, table)).length, indexes.length);
		} finally {
			await knex.destroy();
		}
	});

	it("is a no-op after a healthy original migration", async () => {
		const knex = sqlite();
		try {
			await original.up(knex);
			const before = await repair.listIndexes(knex, table);
			await repair.up(knex);
			const afterIdx = await repair.listIndexes(knex, table);
			assert.deepEqual(afterIdx.map((i) => i.name).sort(), before.map((i) => i.name).sort());
			assert.ok(before.some((i) => i.name === original.UNIQUE_INDEX));
		} finally {
			await knex.destroy();
		}
	});
});
