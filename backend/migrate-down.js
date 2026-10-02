#!/usr/bin/env node
// Rolls back the named migrations (newest first) if they are recorded in the
// `migrations` table. Used by scripts/update.sh before it returns the checkout
// to the previous commit: the older code refuses to start while the table lists
// migration files it does not have ("The migration directory is corrupt").
//
// Usage: node migrate-down.js <migration file name> [...]
import db from "./db.js";
import { migrate as logger } from "./logger.js";

const NAME_RE = /^[0-9]{14}_[A-Za-z0-9_-]+\.js$/;

const main = async (names) => {
	if (!names.length) return;
	for (const name of names) {
		if (!NAME_RE.test(name)) {
			throw new Error(`Invalid migration name: ${name}`);
		}
	}
	const knex = db();
	const applied = new Set(
		(await knex("migrations").whereIn("name", names).select("name")).map((row) => row.name),
	);
	const toRevert = names.filter((name) => applied.has(name)).sort().reverse();
	for (const name of toRevert) {
		logger.info(`Reverting migration ${name}`);
		await knex.migrate.down({ tableName: "migrations", directory: "migrations", name });
	}
	logger.info(`Reverted ${toRevert.length} migration(s)`);
};

main(process.argv.slice(2))
	.then(() => process.exit(0))
	.catch((err) => {
		logger.error(`Migration rollback failed: ${err.message}`);
		process.exit(1);
	});
