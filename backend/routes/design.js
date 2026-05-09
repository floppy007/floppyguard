import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import jwtdecode from "../lib/express/jwt-decode.js";
import requireAdmin from "../lib/express/require-admin.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const UPLOAD_DIR = path.resolve(__dirname, "../../frontend/dist/design/uploads");

if (!existsSync(UPLOAD_DIR)) {
	mkdirSync(UPLOAD_DIR, { recursive: true });
}

const router = express.Router({ caseSensitive: true, strict: true });

// Magic bytes for allowed image types
const MAGIC_BYTES = [
	{ ext: ".png", bytes: [0x89, 0x50, 0x4e, 0x47] },
	{ ext: ".jpg", bytes: [0xff, 0xd8, 0xff] },
	{ ext: ".jpeg", bytes: [0xff, 0xd8, 0xff] },
	{ ext: ".gif", bytes: [0x47, 0x49, 0x46] },
	{ ext: ".webp", bytes: [0x52, 0x49, 0x46, 0x46] },
];

function validateMagicBytes(buffer, ext) {
	const entry = MAGIC_BYTES.find((m) => m.ext === ext);
	if (!entry) return false;
	if (buffer.length < entry.bytes.length) return false;
	return entry.bytes.every((b, i) => buffer[i] === b);
}

/**
 * POST /api/design/screenshot
 * Admin-only — saves uploaded image to frontend/dist/design/uploads/
 */
router.post("/screenshot", jwtdecode(), requireAdmin(), (req, res) => {
	if (!req.files?.screenshot) {
		return res.status(400).json({ error: "No file" });
	}

	const file = req.files.screenshot;
	const ext = path.extname(file.name).toLowerCase() || ".png";
	const allowed = [".png", ".jpg", ".jpeg", ".webp", ".gif"];
	if (!allowed.includes(ext)) {
		return res.status(400).json({ error: "Unsupported file type" });
	}

	if (!validateMagicBytes(file.data, ext)) {
		return res.status(400).json({ error: "File content does not match declared type" });
	}

	const name = `${randomBytes(8).toString("hex")}${ext}`;
	const dest = path.join(UPLOAD_DIR, name);

	file.mv(dest, (err) => {
		if (err) return res.status(500).json({ error: String(err) });
		res.json({ url: `/design/uploads/${name}` });
	});
});

export default router;
