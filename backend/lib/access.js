/**
 * Some Notes: This is a friggin complicated piece of code.
 *
 * "scope" in this file means "where did this token come from and what is using it", so 99% of the time
 * the "scope" is going to be "user" because it would be a user token. This is not to be confused with
 * the "role" which could be "user" or "admin". The scope in fact, could be "worker" or anything else.
 */

import fs from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv from "ajv/dist/2020.js";
import _ from "lodash";
import { access as logger } from "../logger.js";
import authModel from "../models/auth.js";
import TokenModel from "../models/token.js";
import userModel from "../models/user.js";
import permsSchema from "./access/permissions.json" with { type: "json" };
import roleSchema from "./access/roles.json" with { type: "json" };
import errs from "./error.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// The permission files and the role/permission schemas are static, so they are parsed and
// compiled once per process. Only the users-* permissions reference the per-token `objects#`
// schema (enum of the caller's own ids) and still need a fresh Ajv per call.
const AJV_OPTS = { verbose: true, allErrors: true, breakOnError: true, coerceTypes: true };
const staticAjv = new Ajv({ ...AJV_OPTS, schemas: [roleSchema, permsSchema] });
const permissionJsonCache = new Map();
const staticValidatorCache = new Map();

const loadPermissionJson = (permission) => {
	let entry = permissionJsonCache.get(permission);
	if (!entry) {
		const raw = fs.readFileSync(`${__dirname}/access/${permission.replace(/:/gim, "-")}.json`, {
			encoding: "utf8",
		});
		// Unknown permissions throw here (and are not cached), exactly as before
		const json = JSON.parse(raw);
		entry = { json, needsObjects: JSON.stringify(json).includes('"objects#') };
		permissionJsonCache.set(permission, entry);
	}
	return entry;
};

/**
 * Refuse a token minted before the user's password last changed: taking an account back
 * from whoever knows the old password has to end the sessions that password opened.
 * Both sides are whole seconds from the app clock: setPassword() stamps
 * meta.password_changed_at with Date.now(), jsonwebtoken stamps `iat`. A token from the
 * same second as the change is kept. Accounts without a password row (SSO only) or
 * without the marker (password unchanged since this check exists) are not affected.
 *
 * @param   {number} userId
 * @param   {number} iat     token issued-at, seconds
 * @returns {Promise<void>}
 */
export const assertTokenNotRevoked = async (userId, iat) => {
	const auth = await authModel.query().where("user_id", userId).andWhere("type", "password").first();
	const changedAt = Number(auth?.meta?.password_changed_at);
	if (changedAt > 0 && typeof iat === "number" && iat < changedAt) {
		throw new errs.TokenRevokedError("Token was issued before the password was changed");
	}
};

export default function (tokenString) {
	const Token = TokenModel();
	let tokenData = null;
	let initialised = false;
	const objectCache = {};
	let allowInternalAccess = false;
	let userRoles = [];
	let permissions = {};

	/**
	 * Loads the Token object from the token string
	 *
	 * @returns {Promise}
	 */
	this.init = async () => {
		if (initialised) {
			return;
		}

		if (!tokenString) {
			throw new errs.PermissionError("Permission Denied");
		}

		// jwtdecode() already verified the token via load(); don't RSA-verify it twice
		if (!tokenData) {
			tokenData = await Token.load(tokenString);
		}

		// At this point we need to load the user from the DB and make sure they:
		// - exist (and not soft deleted)
		// - still have the appropriate scopes for this token
		// This is only required when the User ID is supplied or if the token scope has `user`
		if (
			tokenData.attrs.id ||
			(typeof tokenData.scope !== "undefined" && _.indexOf(tokenData.scope, "user") !== -1)
		) {
			// Has token user id or token user scope
			const user = await userModel
				.query()
				.where("id", tokenData.attrs.id)
				.andWhere("is_deleted", 0)
				.andWhere("is_disabled", 0)
				.allowGraph("[permissions]")
				.withGraphFetched("[permissions]")
				.first();

			if (user) {
				// make sure user has all scopes of the token
				// The `user` role is not added against the user row, so we have to just add it here to get past this check.
				user.roles.push("user");

				let ok = true;
				_.forEach(tokenData.scope, (scope_item) => {
					if (_.indexOf(user.roles, scope_item) === -1) {
						ok = false;
					}
				});

				if (!ok) {
					throw new errs.UnauthorizedError("Invalid token scope for User");
				}

				await assertTokenNotRevoked(user.id, tokenData.iat);

				initialised = true;
				userRoles = user.roles;
				permissions = user.permissions;
			} else {
				throw new errs.UnauthorizedError("User cannot be loaded for Token");
			}
		}
		initialised = true;
	};

	/**
	 * Fetches the object ids for this token, only once per object type. This only applies
	 * to USER token scopes, as all other tokens are not really bound by object scopes.
	 * The only object type referenced via `objects#` is "users" (users-get/-update/-password).
	 *
	 * @param   {String} objectType
	 * @returns {Promise}
	 */
	this.loadObjects = async (objectType) => {
		let objects = null;

		if (Token.hasScope("user")) {
			if (typeof tokenData.attrs.id === "undefined" || !tokenData.attrs.id) {
				throw new errs.AuthError("User Token supplied without a User ID");
			}

			const tokenUserId = tokenData.attrs.id;

			if (typeof objectCache[objectType] !== "undefined") {
				objects = objectCache[objectType];
			} else {
				// USERS - should only return yourself
				if (objectType === "users") {
					objects = [tokenUserId];
				}
				objectCache[objectType] = objects;
			}
		}
		return objects;
	};

	/**
	 * Creates a schema object on the fly with the IDs and other values required to be checked against the permissionSchema
	 *
	 * @param   {String} permissionLabel
	 * @returns {Object}
	 */
	this.getObjectSchema = async (permissionLabel) => {
		const baseObjectType = permissionLabel.split(":").shift();

		const schema = {
			$id: "objects",
			description: "Actor Properties",
			type: "object",
			additionalProperties: false,
			properties: {},
		};

		const result = await this.loadObjects(baseObjectType);
		if (typeof result === "object" && result !== null) {
			schema.properties[baseObjectType] = {
				type: "number",
				enum: result,
				minimum: 1,
			};
		} else {
			schema.properties[baseObjectType] = {
				type: "number",
				minimum: 1,
			};
		}

		return schema;
	};

	// here:

	return {
		token: Token,

		/**
		 *
		 * @param   {Boolean}  [allowInternal]
		 * @returns {Promise}
		 */
		load: async (allowInternal) => {
			if (tokenString) {
				tokenData = await Token.load(tokenString);
				return tokenData;
			}
			allowInternalAccess = allowInternal;
			return allowInternal || null;
		},

		/**
		 *
		 * @param {String}  permission
		 * @param {*}       [data]
		 * @returns {Promise}
		 */
		can: async (permission, data) => {
			if (allowInternalAccess === true) {
				return true;
			}

			try {
				await this.init();
				const { json: permJson, needsObjects } = loadPermissionJson(permission);

				const dataSchema = {
					[permission]: {
						data: data,
						scope: Token.get("scope"),
						roles: userRoles,
						permission_visibility: permissions.visibility,
						permission_proxy_hosts: permissions.proxy_hosts,
						permission_redirection_hosts: permissions.redirection_hosts,
						permission_dead_hosts: permissions.dead_hosts,
						permission_streams: permissions.streams,
						permission_access_lists: permissions.access_lists,
						permission_certificates: permissions.certificates,
					},
				};

				let valid;
				if (needsObjects) {
					// users:get / users:update / users:password: the enum depends on the token,
					// so these keep a per-call Ajv with the dynamic objects schema
					const objectSchema = await this.getObjectSchema(permission);
					const permissionSchema = {
						$async: true,
						$id: "permissions",
						type: "object",
						additionalProperties: false,
						properties: { [permission]: permJson },
					};
					const ajv = new Ajv({
						...AJV_OPTS,
						schemas: [roleSchema, permsSchema, objectSchema, permissionSchema],
					});
					valid = await ajv.validate("permissions", dataSchema);
				} else {
					let validate = staticValidatorCache.get(permission);
					if (!validate) {
						// No $id: a second compile with $id "permissions" would collide in the shared Ajv
						validate = staticAjv.compile({
							$async: true,
							type: "object",
							additionalProperties: false,
							properties: { [permission]: permJson },
						});
						staticValidatorCache.set(permission, validate);
					}
					valid = await validate(dataSchema);
				}
				return valid && dataSchema[permission];
			} catch (err) {
				// Token/account no longer valid: keep the 401 so the SPA logs out
				if (err instanceof errs.UnauthorizedError || err instanceof errs.TokenRevokedError) throw err;
				err.permission = permission;
				err.permission_data = data;
				logger.error(permission, data, err.message);
				throw new errs.PermissionError("Permission Denied", err);
			}
		},
	};
}
