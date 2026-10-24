import gravatar from "gravatar";
import _ from "lodash";
import errs from "../lib/error.js";
import { withUserEmailLock } from "../lib/user-email-lock.js";
import utils from "../lib/utils.js";
import authModel from "../models/auth.js";
import userModel from "../models/user.js";
import userPermissionModel from "../models/user_permission.js";
import internalAuditLog from "./audit-log.js";
import internalToken from "./token.js";

const omissions = () => {
	return ["is_deleted", "permissions.id", "permissions.user_id", "permissions.created_on", "permissions.modified_on"];
};

const DEFAULT_AVATAR = gravatar.url("admin@example.com", { default: "mm" });

/**
 * Hängt an jedes Konto, woher es kommt: "local" (Passwort-Datensatz) und/oder
 * "sso" (über OpenID Connect angelegt bzw. angemeldet, Auth-Typ "oidc").
 * Konten ganz ohne Auth-Datensatz gelten als lokal (Passwort noch nicht gesetzt).
 */
const attachAuthSources = async (rows) => {
	const list = (Array.isArray(rows) ? rows : [rows]).filter((r) => r?.id);
	if (!list.length) return rows;
	const auths = await authModel
		.query()
		.select("user_id", "type")
		.whereIn(
			"user_id",
			list.map((r) => r.id),
		)
		.where("is_deleted", 0);
	for (const row of list) {
		const types = auths.filter((a) => a.user_id === row.id).map((a) => a.type);
		const sources = [];
		if (types.includes("oidc")) sources.push("sso");
		if (types.includes("password") || !sources.length) sources.push("local");
		row.auth_sources = sources;
	}
	return rows;
};

const internalUser = {
	/**
	 * Create a user can happen unauthenticated only once and only when no active users exist.
	 * Otherwise, a valid auth method is required.
	 *
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @returns {Promise}
	 */
	create: async (access, data) => {
		const auth = data.auth || null;
		delete data.auth;
		// Normalize like update(), login and the OIDC lookup do, so case-sensitive
		// collations can't produce an unreachable or duplicate account
		data.email = String(data.email || "")
			.toLowerCase()
			.trim();

		data.avatar = data.avatar || "";
		data.roles = data.roles || [];

		if (typeof data.is_disabled !== "undefined") {
			data.is_disabled = data.is_disabled ? 1 : 0;
		}

		await access.can("users:create", data);
		data.avatar = gravatar.url(data.email, { default: "mm" });

		// Check and insert under one lock: the user table has no unique index on email
		const user = await withUserEmailLock(async () => {
			if (!(await internalUser.isEmailAvailable(data.email))) {
				throw new errs.ValidationError(`Email address already in use - ${data.email}`);
			}
			return userModel.query().insertAndFetch(data).then(utils.omitRow(omissions()));
		});
		if (auth) {
			// Must not overwrite `user`: the auth row id differs from the user id as soon as
			// the auth table holds oidc rows or rows of deleted users
			await authModel.query().insert({
				user_id: user.id,
				type: auth.type,
				secret: auth.secret,
				meta: {},
			});
		}

		// Create permissions row as well
		const isAdmin = data.roles.indexOf("admin") !== -1;

		await userPermissionModel.insertDefaults(user.id, isAdmin);

		const created = await internalUser.get(access, { id: user.id, expand: ["permissions"] });

		await internalAuditLog.add(access, {
			action: "created",
			object_type: "user",
			object_id: created.id,
			meta: created,
		});

		return created;
	},

	/**
	 * @param  {Access}  access
	 * @param  {Object}  data
	 * @param  {Integer} data.id
	 * @param  {String}  [data.email]
	 * @param  {String}  [data.name]
	 * @return {Promise}
	 */
	update: (access, data) => {
		if (typeof data.is_disabled !== "undefined") {
			data.is_disabled = data.is_disabled ? 1 : 0;
		}

		return access
			.can("users:update", data.id)
			.then(() => {
				// Privileged fields may only be changed by an admin. The "users:update" permission
				// also passes for non-admin self-updates, so without this check any user could
				// escalate themselves by sending roles:["admin"]. Note: regular login tokens carry
				// scope "user" even for admins, so the requester's roles must be checked in the DB.
				if (typeof data.roles === "undefined" && typeof data.is_disabled === "undefined") {
					return;
				}
				return userModel
					.query()
					.where("id", access.token.getUserId(0))
					.andWhere("is_deleted", 0)
					.first()
					.then((requester) => {
						if (!requester || !Array.isArray(requester.roles) || requester.roles.indexOf("admin") === -1) {
							throw new errs.PermissionError("Permission Denied");
						}
					});
			})
			.then(() => {
				// The e-mail check and the patch run under one lock: the user table has no
				// unique index on email, so two concurrent writes could otherwise both pass
				return withUserEmailLock(async () => {
					// 1. get user we want to update
					const user = await internalUser.get(access, { id: data.id });
					// 2. if email is to be changed, make sure no other user is already using it
					if (typeof data.email !== "undefined") {
						data.email = data.email.toLowerCase().trim();
						if (user.email !== data.email && !(await internalUser.isEmailAvailable(data.email, data.id))) {
							throw new errs.ValidationError(`Email address already in use - ${data.email}`);
						}
					}

					if (user.id !== data.id) {
						// Sanity check that something crazy hasn't happened
						throw new errs.InternalValidationError(
							`User could not be updated, IDs do not match: ${user.id} !== ${data.id}`,
						);
					}

					data.avatar = gravatar.url(data.email || user.email, { default: "mm" });
					await userModel.query().where("id", user.id).patch(data);
				});
			})
			.then(() => {
				return internalUser.get(access, { id: data.id });
			})
			.then((user) => {
				// Add to audit log
				return internalAuditLog
					.add(access, {
						action: "updated",
						object_type: "user",
						object_id: user.id,
						meta: { ...data, id: user.id, name: user.name },
					})
					.then(() => {
						return user;
					});
			});
	},

	/**
	 * @param  {Access}   access
	 * @param  {Object}   [data]
	 * @param  {Integer}  [data.id]          Defaults to the token user
	 * @param  {Array}    [data.expand]
	 * @param  {Array}    [data.omit]
	 * @return {Promise}
	 */
	get: (access, data) => {
		const thisData = data || {};

		if (typeof thisData.id === "undefined" || !thisData.id) {
			thisData.id = access.token.getUserId(0);
		}

		return access
			.can("users:get", thisData.id)
			.then(() => {
				const query = userModel
					.query()
					.where("is_deleted", 0)
					.andWhere("id", thisData.id)
					.allowGraph("[permissions]")
					.first();

				if (typeof thisData.expand !== "undefined" && thisData.expand !== null) {
					query.withGraphFetched(`[${thisData.expand.join(", ")}]`);
				}

				return query.then(utils.omitRow(omissions()));
			})
			.then(async (row) => {
				if (!row?.id) {
					throw new errs.ItemNotFoundError(thisData.id);
				}
				if (row.avatar === "") {
					row.avatar = DEFAULT_AVATAR;
				}
				const out = await attachAuthSources(row);
				// Custom omissions
				if (typeof thisData.omit !== "undefined" && thisData.omit !== null) {
					return _.omit(out, thisData.omit);
				}
				return out;
			});
	},

	/**
	 * Checks if an email address is available, but if a user_id is supplied, it will ignore checking
	 * against that user.
	 *
	 * @param email
	 * @param user_id
	 */
	isEmailAvailable: (email, user_id) => {
		const query = userModel.query().where("email", "=", email.toLowerCase().trim()).where("is_deleted", 0).first();

		if (typeof user_id !== "undefined") {
			query.where("id", "!=", user_id);
		}

		return query.then((user) => {
			return !user;
		});
	},

	/**
	 * @param {Access}  access
	 * @param {Object}  data
	 * @param {Integer} data.id
	 * @param {String}  [data.reason]
	 * @returns {Promise}
	 */
	delete: (access, data) => {
		return access
			.can("users:delete", data.id)
			.then(() => {
				return internalUser.get(access, { id: data.id });
			})
			.then((user) => {
				if (!user) {
					throw new errs.ItemNotFoundError(data.id);
				}

				// Make sure user can't delete themselves
				if (user.id === access.token.getUserId(0)) {
					throw new errs.PermissionError("You cannot delete yourself.");
				}

				return userModel
					.query()
					.where("id", user.id)
					.patch({
						is_deleted: 1,
					})
					.then(() => {
						// Add to audit log
						return internalAuditLog.add(access, {
							action: "deleted",
							object_type: "user",
							object_id: user.id,
							meta: _.omit(user, omissions()),
						});
					});
			})
			.then(() => {
				return true;
			});
	},

	/**
	 * All users
	 *
	 * @param   {Access}  access
	 * @param   {Array}   [expand]
	 * @param   {String}  [search_query]
	 * @returns {Promise}
	 */
	getAll: async (access, expand, search_query) => {
		await access.can("users:list");
		const query = userModel
			.query()
			.where("is_deleted", 0)
			.groupBy("id")
			.allowGraph("[permissions]")
			.orderBy("name", "ASC");

		// Query is used for searching
		if (typeof search_query === "string") {
			query.where(function () {
				this.where("name", "like", `%${search_query}%`).orWhere("email", "like", `%${search_query}%`);
			});
		}

		if (typeof expand !== "undefined" && expand !== null) {
			query.withGraphFetched(`[${expand.join(", ")}]`);
		}

		const res = await query;
		return attachAuthSources(utils.omitRows(omissions())(res));
	},

	/**
	 * @param  {Access}  access
	 * @param  {Object}  data
	 * @param  {Integer} data.id
	 * @param  {String}  data.type
	 * @param  {String}  data.secret
	 * @return {Promise}
	 */
	setPassword: (access, data) => {
		return access
			.can("users:password", data.id)
			.then(() => {
				return internalUser.get(access, { id: data.id });
			})
			.then((user) => {
				if (user.id !== data.id) {
					// Sanity check that something crazy hasn't happened
					throw new errs.InternalValidationError(
						`User could not be updated, IDs do not match: ${user.id} !== ${data.id}`,
					);
				}

				if (user.id === access.token.getUserId(0)) {
					// they're setting their own password. Make sure their current password is correct
					if (typeof data.current === "undefined" || !data.current) {
						throw new errs.ValidationError("Current password was not supplied");
					}

					// Check the password row directly instead of running the whole login flow;
					// same error for a wrong password and an account without one (SSO-only)
					return authModel
						.query()
						.where("user_id", user.id)
						.andWhere("type", "password")
						.first()
						.then(async (auth) => {
							if (!auth || !(await auth.verifyPassword(data.current))) {
								throw new errs.AuthError("Invalid email or password", "error.invalid-auth");
							}
							return user;
						});
				}

				return user;
			})
			.then((user) => {
				// Get auth, patch if it exists
				return authModel
					.query()
					.where("user_id", user.id)
					.andWhere("type", data.type)
					.first()
					.then((existing_auth) => {
						// Tokens issued before this second stop working (lib/access.js assertTokenNotRevoked).
						// Stamped from the app clock, the same one that writes a token's `iat`, rather than
						// read off modified_on: the database clock/timezone can differ from Node's.
						const password_changed_at = Math.floor(Date.now() / 1000);

						if (existing_auth) {
							// patch
							return authModel
								.query()
								.where("user_id", user.id)
								.andWhere("type", data.type)
								.patch({
									type: data.type, // This is required for the model to encrypt on save
									secret: data.secret,
									meta: { ...(existing_auth.meta || {}), password_changed_at },
								});
						}
						// insert
						return authModel.query().insert({
							user_id: user.id,
							type: data.type,
							secret: data.secret,
							meta: { password_changed_at },
						});
					})
					.then(() => {
						// Add to Audit Log
						return internalAuditLog.add(access, {
							action: "updated",
							object_type: "user",
							object_id: user.id,
							meta: {
								name: user.name,
								password_changed: true,
								auth_type: data.type,
							},
						});
					});
			})
			.then(() => {
				return true;
			});
	},

	/**
	 * @param  {Access}  access
	 * @param  {Object}  data
	 * @return {Promise}
	 */
	setPermissions: (access, data) => {
		return access
			.can("users:permissions", data.id)
			.then(() => {
				return internalUser.get(access, { id: data.id });
			})
			.then((user) => {
				if (user.id !== data.id) {
					// Sanity check that something crazy hasn't happened
					throw new errs.InternalValidationError(
						`User could not be updated, IDs do not match: ${user.id} !== ${data.id}`,
					);
				}

				return user;
			})
			.then((user) => {
				// `data.id` is the user id injected by the route; it must not reach the permission row
				const perms = _.assign({ user_id: user.id }, _.omit(data, ["id"]));
				// Get perms row, patch if it exists
				return userPermissionModel
					.query()
					.where("user_id", user.id)
					.first()
					.then((existing_auth) => {
						if (existing_auth) {
							// patch
							return userPermissionModel
								.query()
								.where("user_id", user.id)
								.patchAndFetchById(existing_auth.id, perms);
						}
						// insert
						return userPermissionModel.query().insertAndFetch(perms);
					})
					.then((permissions) => {
						// Add to Audit Log
						return internalAuditLog.add(access, {
							action: "updated",
							object_type: "user",
							object_id: user.id,
							meta: {
								name: user.name,
								permissions: permissions,
							},
						});
					});
			})
			.then(() => {
				return true;
			});
	},

	/**
	 * @param {Access}   access
	 * @param {Object}   data
	 * @param {Integer}  data.id
	 */
	loginAs: (access, data) => {
		return access
			.can("users:loginas", data.id)
			.then(() => internalUser.get(access, data))
			.then(async (user) => {
				// get() hides deleted users but not disabled ones. A token for a disabled
				// account is refused on its first request (401), and that 401 makes the SPA
				// clear the whole token stack, logging the admin out as well.
				if (user.is_disabled) {
					throw new errs.ValidationError("Cannot log in as a disabled user");
				}
				// Admin impersonation: record who (access token user) signed in as whom
				await internalAuditLog.add(access, {
					action: "login-as",
					object_type: "user",
					object_id: user.id,
					meta: { name: user.name, email: user.email },
				});
				return internalToken.getTokenFromUser(user);
			});
	},
};

export default internalUser;
