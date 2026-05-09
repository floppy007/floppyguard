import Database from "better-sqlite3";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";

const DATA_DIR = process.env.DATA_DIR || "/data";
const RATE_LIMIT_DIR = path.join(DATA_DIR, "rate-limit");

let db;

function getDb() {
	if (db) return db;
	if (!existsSync(RATE_LIMIT_DIR)) {
		mkdirSync(RATE_LIMIT_DIR, { recursive: true });
	}
	db = new Database(path.join(RATE_LIMIT_DIR, "rate-limit.db"));
	db.pragma("journal_mode = WAL");
	db.exec(`
		CREATE TABLE IF NOT EXISTS hits (
			ip TEXT NOT NULL,
			window_key INTEGER NOT NULL,
			count INTEGER DEFAULT 1,
			PRIMARY KEY (ip, window_key)
		)
	`);
	return db;
}

/**
 * Persistent rate limiter backed by SQLite.
 * Survives process restarts and is shared across cluster workers.
 * Uses req.ip which respects trust proxy settings.
 *
 * @param {object} opts
 * @param {number} opts.windowMs - Time window in milliseconds (default: 15 min)
 * @param {number} opts.max      - Max requests per window (default: 15)
 */
export default function rateLimit({ windowMs = 15 * 60 * 1000, max = 15 } = {}) {
	const database = getDb();

	const upsertStmt = database.prepare(`
		INSERT INTO hits (ip, window_key, count) VALUES (?, ?, 1)
		ON CONFLICT(ip, window_key) DO UPDATE SET count = count + 1
	`);
	const selectStmt = database.prepare(`
		SELECT count FROM hits WHERE ip = ? AND window_key = ?
	`);
	const cleanupStmt = database.prepare(`
		DELETE FROM hits WHERE window_key < ?
	`);

	// Periodically clean up old windows
	const cleanup = setInterval(() => {
		const currentWindow = Math.floor(Date.now() / windowMs);
		cleanupStmt.run(currentWindow - 1);
	}, windowMs);
	if (typeof cleanup.unref === "function") cleanup.unref();

	return (req, res, next) => {
		const ip = req.ip || req.connection?.remoteAddress || "unknown";
		const windowKey = Math.floor(Date.now() / windowMs);

		upsertStmt.run(ip, windowKey);
		const row = selectStmt.get(ip, windowKey);
		const count = row?.count || 1;

		res.set("X-RateLimit-Limit", String(max));
		res.set("X-RateLimit-Remaining", String(Math.max(0, max - count)));

		if (count > max) {
			const windowEnd = (windowKey + 1) * windowMs;
			const retryAfter = Math.ceil((windowEnd - Date.now()) / 1000);
			res.set("Retry-After", String(retryAfter));
			return res.status(429).json({
				error: { message: "Too many requests, please try again later." },
			});
		}

		next();
	};
}
