import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { createGuardrails, generateSecret, generateURI, verify } from "otplib";
import errs from "../lib/error.js";
import authModel from "../models/auth.js";
import internalAuditLog from "./audit-log.js";
import internalUser from "./user.js";

const APP_NAME = "FloppyGuard";
const BACKUP_CODE_COUNT = 8;
const BACKUP_CODE_LENGTH = 8; // randomBytes(4).toString("hex")

/**
 * Generate backup codes
 * @returns {Promise<{plain: string[], hashed: string[]}>}
 */
const generateBackupCodes = async () => {
	const plain = [];
	const hashed = [];

	for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
		const code = crypto.randomBytes(4).toString("hex").toUpperCase();
		plain.push(code);
		const hash = await bcrypt.hash(code, 10);
		hashed.push(hash);
	}

	return { plain, hashed };
};

// Lower otplib v13's 16-byte minimum to 10 bytes (the v12 minimum): secrets generated under
// otplib v12 are still in the wild and must keep working for login, disable and backup-code
// regeneration, otherwise people are locked out (or get a 500) after the upgrade.
const LEGACY_GUARDRAILS = createGuardrails({ MIN_SECRET_BYTES: 10 });
const verifyTotp = (secret, token) => verify({ token, secret, guardrails: LEGACY_GUARDRAILS });

/**
 * Render the otpauth URL as a PNG data URL on the server: the URL carries the TOTP secret,
 * so it must never be handed to a third-party QR image service.
 *
 * @param   {string} otpauthUrl
 * @returns {Promise<string>}
 */
const renderQrDataUrl = async (otpauthUrl) => {
	const QRCode = (await import("qrcode")).default;
	return QRCode.toDataURL(otpauthUrl, { type: "image/png", errorCorrectionLevel: "M", margin: 1, width: 240 });
};

const internal2fa = {
	/**
	 * Check if user has 2FA enabled
	 * @param {number} userId
	 * @returns {Promise<boolean>}
	 */
	isEnabled: async (userId) => {
		const auth = await internal2fa.getUserPasswordAuth(userId);
		return auth?.meta?.totp_enabled === true;
	},

	/**
	 * Get 2FA status for user
	 * @param   {Access}  access
	 * @param   {number}  userId
	 * @returns {Promise<{enabled: boolean, backup_codes_remaining: number}>}
	 */
	getStatus: async (access, userId) => {
		await access.can("users:password", userId);
		await internalUser.get(access, { id: userId });
		const auth = await internal2fa.getUserPasswordAuth(userId);
		const enabled = auth?.meta?.totp_enabled === true;
		let backup_codes_remaining = 0;

		if (enabled) {
			const backupCodes = auth.meta.backup_codes || [];
			backup_codes_remaining = backupCodes.length;
		}

		return {
			enabled,
			backup_codes_remaining,
		};
	},

	/**
	 * Start 2FA setup - store pending secret
	 *
	 * @param   {Access}  access
	 * @param   {number} userId
	 * @returns {Promise<{secret: string, otpauth_url: string, qr_data_url: string}>}
	 */
	startSetup: async (access, userId) => {
		await access.can("users:password", userId);
		const user = await internalUser.get(access, { id: userId });
		const secret = generateSecret();
		const otpauth_url = generateURI({
			issuer: APP_NAME,
			label: user.email,
			secret: secret,
		});
		const auth = await internal2fa.getUserPasswordAuth(userId);

		// ensure user isn't already setup for 2fa
		const enabled = auth?.meta?.totp_enabled === true;
		if (enabled) {
			throw new errs.ValidationError("2FA is already enabled");
		}

		const meta = auth.meta || {};
		meta.totp_pending_secret = secret;

		await authModel
			.query()
			.where("id", auth.id)
			.andWhere("user_id", userId)
			.andWhere("type", "password")
			.patch({ meta });

		const qr_data_url = await renderQrDataUrl(otpauth_url);

		return { secret, otpauth_url, qr_data_url };
	},

	/**
	 * Enable 2FA after verifying code
	 *
	 * @param   {Access}  access
	 * @param   {number}  userId
	 * @param   {string}  code
	 * @returns {Promise<{backup_codes: string[]}>}
	 */
	enable: async (access, userId, code) => {
		await access.can("users:password", userId);
		const user = await internalUser.get(access, { id: userId });
		const auth = await internal2fa.getUserPasswordAuth(userId);
		const secret = auth?.meta?.totp_pending_secret || false;

		if (!secret) {
			throw new errs.ValidationError("No pending 2FA setup found");
		}

		const result = await verifyTotp(secret, code);
		if (!result.valid) {
			throw new errs.ValidationError("Invalid verification code");
		}

		const { plain, hashed } = await generateBackupCodes();

		const meta = {
			...auth.meta,
			totp_secret: secret,
			totp_enabled: true,
			totp_enabled_at: new Date().toISOString(),
			backup_codes: hashed,
		};
		delete meta.totp_pending_secret;

		await authModel
			.query()
			.where("id", auth.id)
			.andWhere("user_id", userId)
			.andWhere("type", "password")
			.patch({ meta });

		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "user",
			object_id: userId,
			meta: { name: user.name, totp: "enabled" },
		});

		return { backup_codes: plain };
	},

	/**
	 * Disable 2FA
	 *
	 * @param   {Access}  access
	 * @param   {number} userId
	 * @param   {string} code
	 * @returns {Promise<void>}
	 */
	disable: async (access, userId, code) => {
		await access.can("users:password", userId);
		const user = await internalUser.get(access, { id: userId });
		const auth = await internal2fa.getUserPasswordAuth(userId);

		const enabled = auth?.meta?.totp_enabled === true;
		if (!enabled) {
			throw new errs.ValidationError("2FA is not enabled");
		}

		const result = await verifyTotp(auth.meta.totp_secret, code);

		if (!result.valid) {
			throw new errs.AuthError("Invalid verification code");
		}

		const meta = { ...auth.meta };
		delete meta.totp_secret;
		delete meta.totp_enabled;
		delete meta.totp_enabled_at;
		delete meta.backup_codes;

		await authModel
			.query()
			.where("id", auth.id)
			.andWhere("user_id", userId)
			.andWhere("type", "password")
			.patch({ meta });

		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "user",
			object_id: userId,
			meta: { name: user.name, totp: "disabled" },
		});
	},

	/**
	 * Verify 2FA code for login
	 *
	 * @param   {number} userId
	 * @param   {string} token
	 * @returns {Promise<boolean>}
	 */
	verifyForLogin: async (userId, token) => {
		const auth = await internal2fa.getUserPasswordAuth(userId);
		const secret = auth?.meta?.totp_secret || false;

		if (!secret) {
			return false;
		}

		// Try TOTP code first, if it's 6 chars. it will throw errors if it's not 6 chars
		// and the backup codes are 8 chars.
		if (token.length === 6) {
			const result = await verifyTotp(secret, token);

			if (result.valid) {
				return true;
			}
		}

		// Backup codes are always 8 hex chars; a 6/7-char token can never match, so don't
		// burn 8 bcrypt compares after a wrong TOTP.
		if (token.length !== BACKUP_CODE_LENGTH) {
			return false;
		}

		const candidate = token.toUpperCase();
		const backupCodes = auth?.meta?.backup_codes || [];
		for (const hash of backupCodes) {
			if (!(await bcrypt.compare(candidate, hash))) continue;

			// Consume atomically: re-read under a row lock and only remove the code if it is
			// still present, so two parallel requests with the same code cannot both succeed.
			return authModel.transaction(async (trx) => {
				const fresh = await authModel
					.query(trx)
					.where("id", auth.id)
					.andWhere("user_id", userId)
					.andWhere("type", "password")
					.forUpdate()
					.first();
				const current = fresh?.meta?.backup_codes || [];
				if (!current.includes(hash)) {
					return false;
				}
				await authModel
					.query(trx)
					.where("id", auth.id)
					.patch({ meta: { ...fresh.meta, backup_codes: current.filter((h) => h !== hash) } });
				return true;
			});
		}

		return false;
	},

	/**
	 * Regenerate backup codes
	 *
	 * @param   {Access}  access
	 * @param   {number}  userId
	 * @param   {string}  token
	 * @returns {Promise<{backup_codes: string[]}>}
	 */
	regenerateBackupCodes: async (access, userId, token) => {
		await access.can("users:password", userId);
		const user = await internalUser.get(access, { id: userId });
		const auth = await internal2fa.getUserPasswordAuth(userId);
		const enabled = auth?.meta?.totp_enabled === true;
		const secret = auth?.meta?.totp_secret || false;

		if (!enabled) {
			throw new errs.ValidationError("2FA is not enabled");
		}
		if (!secret) {
			throw new errs.ValidationError("No 2FA secret found");
		}

		const result = await verifyTotp(secret, token);

		if (!result.valid) {
			throw new errs.ValidationError("Invalid verification code");
		}

		const { plain, hashed } = await generateBackupCodes();

		const meta = { ...auth.meta, backup_codes: hashed };
		await authModel
			.query()
			.where("id", auth.id)
			.andWhere("user_id", userId)
			.andWhere("type", "password")
			.patch({ meta });

		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "user",
			object_id: userId,
			meta: { name: user.name, totp: "backup-codes-regenerated" },
		});

		return { backup_codes: plain };
	},

	getUserPasswordAuth: async (userId) => {
		const auth = await authModel.query().where("user_id", userId).andWhere("type", "password").first();

		if (!auth) {
			throw new errs.ItemNotFoundError("Auth not found");
		}

		return auth;
	},
};

export default internal2fa;
