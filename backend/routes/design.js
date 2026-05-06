import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const UPLOAD_DIR = path.resolve(__dirname, "../../frontend/dist/design/uploads");

if (!existsSync(UPLOAD_DIR)) {
	mkdirSync(UPLOAD_DIR, { recursive: true });
}

const router = express.Router({ caseSensitive: true, strict: true });

/**
 * POST /api/design/screenshot
 * Unauthenticated — design tool only, saves uploaded image to frontend/dist/design/uploads/
 */
router.post("/screenshot", (req, res) => {
	if (!req.files?.screenshot) {
		return res.status(400).json({ error: "No file" });
	}

	const file = req.files.screenshot;
	const ext = path.extname(file.name).toLowerCase() || ".png";
	const allowed = [".png", ".jpg", ".jpeg", ".webp", ".gif"];
	if (!allowed.includes(ext)) {
		return res.status(400).json({ error: "Unsupported file type" });
	}

	const name = `${randomBytes(8).toString("hex")}${ext}`;
	const dest = path.join(UPLOAD_DIR, name);

	file.mv(dest, (err) => {
		if (err) return res.status(500).json({ error: String(err) });
		res.json({ url: `/design/uploads/${name}` });
	});
});

export default router;
