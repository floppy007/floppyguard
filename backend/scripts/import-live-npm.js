import fs from "node:fs";
import path from "node:path";
import bcrypt from "bcrypt";
import mysql from "mysql2/promise";
import Database from "better-sqlite3";

const rootDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const targetSqliteFile = process.env.TARGET_SQLITE_FILE || path.join(rootDir, ".local-data/backend/database.sqlite");
const sourceConfig = {
	host: process.env.SOURCE_DB_HOST || "127.0.0.1",
	port: Number(process.env.SOURCE_DB_PORT || 3306),
	user: process.env.SOURCE_DB_USER || "npm",
	password: process.env.SOURCE_DB_PASSWORD || "npm",
	database: process.env.SOURCE_DB_NAME || "npm",
	dateStrings: true,
};
const previewEmail = process.env.PREVIEW_EMAIL || "preview@example.com";
const previewPassword = process.env.PREVIEW_PASSWORD || "Preview123!";

const excludedTables = new Set(["migrations", "token", "sqlite_sequence"]);

const now = () => new Date().toISOString().slice(0, 19).replace("T", " ");

const normalizeValue = (value) => {
	if (value === null || typeof value === "undefined") {
		return null;
	}
	if (Buffer.isBuffer(value)) {
		return value.toString("utf8");
	}
	if (typeof value === "object") {
		if (value instanceof Date) {
			return value.toISOString().slice(0, 19).replace("T", " ");
		}
		return JSON.stringify(value);
	}
	return value;
};

const quoteIdentifier = (name) => `"${String(name).replaceAll('"', '""')}"`;

const getSqliteTables = (sqlite) =>
	sqlite
		.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
		.all()
		.map((row) => row.name)
		.filter((name) => !excludedTables.has(name));

const getMysqlTables = async (mysqlConnection) => {
	const [rows] = await mysqlConnection.query("SHOW TABLES");
	return rows.map((row) => Object.values(row)[0]).filter((name) => !excludedTables.has(name));
};

const clearSqliteTables = (sqlite, tableNames) => {
	sqlite.exec("PRAGMA foreign_keys = OFF");
	for (const tableName of tableNames) {
		sqlite.prepare(`DELETE FROM ${quoteIdentifier(tableName)}`).run();
	}
	sqlite.prepare("DELETE FROM sqlite_sequence").run();
	sqlite.exec("PRAGMA foreign_keys = ON");
};

const importTable = async (mysqlConnection, sqlite, tableName) => {
	const [rows] = await mysqlConnection.query(`SELECT * FROM \`${tableName}\``);
	if (!rows.length) {
		return 0;
	}

	const columns = Object.keys(rows[0]);
	const placeholders = columns.map(() => "?").join(", ");
	const insert = sqlite.prepare(
		`INSERT INTO ${quoteIdentifier(tableName)} (${columns.map(quoteIdentifier).join(", ")}) VALUES (${placeholders})`,
	);

	const transaction = sqlite.transaction((inputRows) => {
		for (const row of inputRows) {
			insert.run(columns.map((column) => normalizeValue(row[column])));
		}
	});

	transaction(rows);
	return rows.length;
};

const ensurePreviewUser = (sqlite) => {
	const timestamp = now();
	const previewUser = sqlite.prepare("SELECT id FROM user WHERE email = ? LIMIT 1").get(previewEmail);
	const hashedPassword = bcrypt.hashSync(previewPassword, 13);

	let userId = previewUser?.id;
	if (!userId) {
		const maxUserId = sqlite.prepare("SELECT COALESCE(MAX(id), 0) AS maxId FROM user").get().maxId;
		userId = Number(maxUserId) + 1;
		sqlite
			.prepare(
				`INSERT INTO user (id, created_on, modified_on, is_deleted, is_disabled, email, name, nickname, avatar, roles)
				 VALUES (?, ?, ?, 0, 0, ?, ?, ?, ?, ?)`,
			)
			.run(
				userId,
				timestamp,
				timestamp,
				previewEmail,
				"Preview Admin",
				"Preview",
				"",
				JSON.stringify(["admin"]),
			);
	} else {
		sqlite
			.prepare(
				"UPDATE user SET modified_on = ?, is_deleted = 0, is_disabled = 0, name = ?, nickname = ?, roles = ? WHERE id = ?",
			)
			.run(timestamp, "Preview Admin", "Preview", JSON.stringify(["admin"]), userId);
	}

	sqlite.prepare("DELETE FROM auth WHERE user_id = ? AND type = 'password'").run(userId);
	const maxAuthId = sqlite.prepare("SELECT COALESCE(MAX(id), 0) AS maxId FROM auth").get().maxId;
	sqlite
		.prepare(
			`INSERT INTO auth (id, created_on, modified_on, user_id, type, secret, meta, is_deleted)
			 VALUES (?, ?, ?, ?, 'password', ?, '{}', 0)`,
		)
		.run(Number(maxAuthId) + 1, timestamp, timestamp, userId, hashedPassword);

	const permissionColumns = sqlite
		.prepare("PRAGMA table_info(user_permission)")
		.all()
		.map((column) => column.name)
		.filter((name) => !["id", "created_on", "modified_on", "user_id", "visibility"].includes(name));

	const values = {
		id: Number(sqlite.prepare("SELECT COALESCE(MAX(id), 0) AS maxId FROM user_permission").get().maxId) + 1,
		created_on: timestamp,
		modified_on: timestamp,
		user_id: userId,
		visibility: "all",
	};

	for (const column of permissionColumns) {
		values[column] = "manage";
	}

	sqlite.prepare("DELETE FROM user_permission WHERE user_id = ?").run(userId);
	const columns = Object.keys(values);
	sqlite
		.prepare(
			`INSERT INTO user_permission (${columns.map(quoteIdentifier).join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`,
		)
		.run(columns.map((column) => values[column]));
};

const main = async () => {
	if (!fs.existsSync(targetSqliteFile)) {
		throw new Error(`Target sqlite file not found: ${targetSqliteFile}`);
	}

	const mysqlConnection = await mysql.createConnection(sourceConfig);
	const sqlite = new Database(targetSqliteFile);

	try {
		const mysqlTables = await getMysqlTables(mysqlConnection);
		const sqliteTables = getSqliteTables(sqlite);
		const importTables = sqliteTables.filter((tableName) => mysqlTables.includes(tableName));

		clearSqliteTables(sqlite, sqliteTables);

		const imported = [];
		for (const tableName of importTables) {
			const count = await importTable(mysqlConnection, sqlite, tableName);
			imported.push(`${tableName}:${count}`);
		}

		ensurePreviewUser(sqlite);
		console.log(`Imported tables into ${targetSqliteFile}`);
		console.log(imported.join(", "));
		console.log(`Preview login ensured: ${previewEmail}`);
	} finally {
		sqlite.close();
		await mysqlConnection.end();
	}
};

main().catch((error) => {
	console.error(error.stack || error.message);
	process.exit(1);
});
