import bcrypt from "bcrypt";
import { assertTokenNotRevoked } from "../lib/access.js";
import errs from "../lib/error.js";
import { parseDatePeriod } from "../lib/helpers.js";
import authModel from "../models/auth.js";
import TokenModel from "../models/token.js";
import userModel from "../models/user.js";
import twoFactor from "./2fa.js";

const ERROR_MESSAGE_INVALID_AUTH = "Invalid email or password";
const ERROR_MESSAGE_INVALID_AUTH_I18N = "error.invalid-auth";
const ERROR_MESSAGE_INVALID_2FA = "Invalid verification code";
const ERROR_MESSAGE_INVALID_2FA_I18N = "error.invalid-2fa";

// Pre-computed cost-13 hash (same cost as models/auth.js). Compared against on the
// unknown-e-mail / no-password-auth paths so a failed login takes the same time
// whether or not the account exists (prevents e-mail enumeration via timing).
const TIMING_PAD_HASH = "$2b$13$XzHj/zG5qzDEi4lRIQKUZeOo..YPEnbsquiFUgxBeBf5PGBm4fO6.";

export default {
	/**
	 * @param   {Object} data
	 * @param   {String} data.identity
	 * @param   {String} data.secret
	 * @param   {String} [data.expiry]
	 * @param   {String} [issuer]
	 * @returns {Promise}
	 */
	getTokenFromEmail: async (data, issuer) => {
		const Token = TokenModel();

		data.expiry = data.expiry || "1d";

		const user = await userModel
			.query()
			.where("email", data.identity.toLowerCase().trim())
			.andWhere("is_deleted", 0)
			.andWhere("is_disabled", 0)
			.first();

		if (!user) {
			await bcrypt.compare(String(data.secret ?? ""), TIMING_PAD_HASH);
			throw new errs.AuthError(ERROR_MESSAGE_INVALID_AUTH, ERROR_MESSAGE_INVALID_AUTH_I18N);
		}

		const auth = await authModel.query().where("user_id", "=", user.id).where("type", "=", "password").first();

		if (!auth) {
			await bcrypt.compare(String(data.secret ?? ""), TIMING_PAD_HASH);
			throw new errs.AuthError(ERROR_MESSAGE_INVALID_AUTH, ERROR_MESSAGE_INVALID_AUTH_I18N);
		}

		const valid = await auth.verifyPassword(data.secret);
		if (!valid) {
			throw new errs.AuthError(ERROR_MESSAGE_INVALID_AUTH, ERROR_MESSAGE_INVALID_AUTH_I18N);
		}

		// Check if 2FA is enabled (the auth row is already loaded, no second lookup)
		if (auth.meta?.totp_enabled === true) {
			// Return challenge token instead of full token
			const challengeToken = await Token.create({
				iss: issuer || "api",
				attrs: {
					id: user.id,
				},
				scope: ["2fa-challenge"],
				expiresIn: "5m",
			});

			return {
				requires_2fa: true,
				challenge_token: challengeToken.token,
			};
		}

		// Create a moment of the expiry expression
		const expiry = parseDatePeriod(data.expiry);
		if (expiry === null) {
			throw new errs.AuthError(`Invalid expiry time: ${data.expiry}`);
		}

		const signed = await Token.create({
			iss: issuer || "api",
			attrs: {
				id: user.id,
			},
			scope: ["user"],
			expiresIn: data.expiry,
		});

		return {
			token: signed.token,
			expires: expiry.toISOString(),
		};
	},

	/**
	 * @param {Access} access
	 * @param {Object} [data]
	 * @param {String} [data.expiry]
	 * @returns {Promise}
	 */
	getFreshToken: async (access, data) => {
		const Token = TokenModel();
		const thisData = data || {};

		thisData.expiry = thisData.expiry || "1d";

		if (access?.token.getUserId(0)) {
			// Only real login sessions may be refreshed. A 2FA challenge token
			// (scope "2fa-challenge", 5 minutes) must never be re-minted into a
			// long-lived token.
			if (access.token.hasScope("2fa-challenge") || !access.token.hasScope("user")) {
				throw new errs.AuthError("Invalid token");
			}

			// Re-check the account: deleted or disabled users get no fresh token.
			const userId = access.token.getUserId(0);
			const user = await userModel
				.query()
				.select("id")
				.where("id", userId)
				.andWhere("is_deleted", 0)
				.andWhere("is_disabled", 0)
				.first();
			if (!user) {
				// 401: the SPA drops the token and sends the user to /login
				throw new errs.UnauthorizedError("Invalid token");
			}
			// A token revoked by a password change must not be re-minted into a valid one
			await assertTokenNotRevoked(userId, access.token.get("iat"));

			// Create a moment of the expiry expression
			let expiry = parseDatePeriod(thisData.expiry);
			if (expiry === null) {
				throw new errs.AuthError(`Invalid expiry time: ${thisData.expiry}`);
			}

			// Cap token expiry to 30 days maximum
			const maxExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
			if (expiry > maxExpiry) {
				throw new errs.AuthError("Token expiry cannot exceed 30 days");
			}

			const token_attrs = {
				id: userId,
			};
			let expiresIn = thisData.expiry;

			// SSO sessions are bounded by the lifetime of the original IdP login.
			// Past that point the user must go through the IdP again, which
			// re-checks the required group.
			const ssoUntil = Number(access.token.get("attrs")?.sso_exp);
			if (ssoUntil) {
				const ssoUntilMs = ssoUntil * 1000;
				if (Date.now() >= ssoUntilMs - 5000) {
					throw new errs.AuthError("SSO session expired, please sign in again");
				}
				token_attrs.sso_exp = ssoUntil;
				// parseDatePeriod returns a moment (no getTime()); valueOf() is ms.
				if (expiry.valueOf() > ssoUntilMs) {
					expiry = new Date(ssoUntilMs);
					expiresIn = Math.max(1, Math.floor((ssoUntilMs - Date.now()) / 1000));
				}
			}

			const scope = access.token.get("scope");

			const signed = await Token.create({
				iss: "api",
				scope: scope,
				attrs: token_attrs,
				expiresIn,
			});

			return {
				token: signed.token,
				expires: expiry.toISOString(),
			};
		}
		throw new errs.AssertionFailedError("Existing token contained invalid user data");
	},

	/**
	 * Verify 2FA code and return full token
	 * @param {string} challengeToken
	 * @param {string} code
	 * @param {string} [expiry]
	 * @returns {Promise}
	 */
	verify2FA: async (challengeToken, code, expiry) => {
		const Token = TokenModel();
		const tokenExpiry = expiry || "1d";

		// Verify challenge token
		let tokenData;
		try {
			tokenData = await Token.load(challengeToken);
		} catch {
			throw new errs.AuthError("Invalid or expired challenge token");
		}

		// Check scope
		if (tokenData.scope?.[0] !== "2fa-challenge") {
			throw new errs.AuthError("Invalid challenge token");
		}

		const userId = tokenData.attrs?.id;
		if (!userId) {
			throw new errs.AuthError("Invalid challenge token");
		}

		// The challenge was earned with the password: a password change since then voids it
		try {
			await assertTokenNotRevoked(userId, tokenData.iat);
		} catch (err) {
			if (err instanceof errs.TokenRevokedError) {
				throw new errs.AuthError("Invalid or expired challenge token");
			}
			throw err;
		}

		// Verify 2FA code
		const valid = await twoFactor.verifyForLogin(userId, code);
		if (!valid) {
			throw new errs.AuthError(ERROR_MESSAGE_INVALID_2FA, ERROR_MESSAGE_INVALID_2FA_I18N);
		}

		// Create full token
		const expiryDate = parseDatePeriod(tokenExpiry);
		if (expiryDate === null) {
			throw new errs.AuthError(`Invalid expiry time: ${tokenExpiry}`);
		}

		const signed = await Token.create({
			iss: "api",
			attrs: {
				id: userId,
			},
			scope: ["user"],
			expiresIn: tokenExpiry,
		});

		return {
			token: signed.token,
			expires: expiryDate.toISOString(),
		};
	},

	/**
	 * @param   {Object} user
	 * @returns {Promise}
	 */
	getTokenFromUser: async (user) => {
		const expire = "1d";
		const Token = TokenModel();
		const expiry = parseDatePeriod(expire);

		const signed = await Token.create({
			iss: "api",
			attrs: {
				id: user.id,
			},
			scope: ["user"],
			expiresIn: expire,
		});

		return {
			token: signed.token,
			expires: expiry.toISOString(),
			user: user,
		};
	},
};
