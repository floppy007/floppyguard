import fs from "node:fs";
import batchflow from "batchflow";
import _ from "lodash";
import errs from "../lib/error.js";
import utils from "../lib/utils.js";
import { access as logger } from "../logger.js";
import accessListModel from "../models/access_list.js";
import accessListAuthModel from "../models/access_list_auth.js";
import accessListClientModel from "../models/access_list_client.js";
import proxyHostModel from "../models/proxy_host.js";
import internalAuditLog from "./audit-log.js";
import internalHost from "./host.js";
import internalNginx from "./nginx.js";

const omissions = () => {
	return ["is_deleted"];
};

// htpasswd: nginx ends the login at the first ':' and a line at '\n', so such a
// username would lock the user out or inject a second htpasswd entry.
const assertValidUsernames = (items) => {
	for (const item of items || []) {
		const name = item?.username;
		if (typeof name !== "string" || !name || name.includes(":") || [...name].some((c) => c.charCodeAt(0) < 0x20)) {
			throw new errs.ValidationError("Invalid username");
		}
	}
};

const internalAccessList = {
	/**
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @returns {Promise}
	 */
	create: async (access, data) => {
		await access.can("access_lists:create", data);
		assertValidUsernames(data.items);
		const row = await accessListModel
			.query()
			.insertAndFetch({
				name: data.name,
				satisfy_any: data.satisfy_any,
				pass_auth: data.pass_auth,
				owner_user_id: access.token.getUserId(1),
			})
			.then(utils.omitRow(omissions()));

		data.id = row.id;

		// Inserted one after another: the client rules render in id order, and
		// nginx evaluates allow/deny top-down, so the order must be the one the
		// user entered (Promise.all inserted in random order, upstream #5421).
		// Items
		for (const item of data.items || []) {
			if (item.password) {
				await accessListAuthModel.query().insert({
					access_list_id: row.id,
					username: item.username,
					password: item.password,
				});
			}
		}

		// Clients
		for (const client of data.clients || []) {
			await accessListClientModel.query().insert({
				access_list_id: row.id,
				address: client.address,
				directive: client.directive,
			});
		}

		// re-fetch with expansions
		const freshRow = await internalAccessList.get(
			access,
			{
				id: data.id,
				expand: ["owner", "items", "clients", "proxy_hosts.[certificate,access_list.[clients,items]]"],
			},
			true, // skip masking
		);

		// Audit log
		data.meta = _.assign({}, data.meta || {}, freshRow.meta);
		await internalAccessList.build(freshRow);

		if (Number.parseInt(freshRow.proxy_host_count, 10)) {
			await internalNginx.bulkGenerateConfigs("proxy_host", freshRow.proxy_hosts);
		}

		// Add to audit log
		await internalAuditLog.add(access, {
			action: "created",
			object_type: "access-list",
			object_id: freshRow.id,
			meta: internalAccessList.maskItems(data),
		});

		return internalAccessList.maskItems(freshRow);
	},

	/**
	 * @param  {Access}  access
	 * @param  {Object}  data
	 * @param  {Integer} data.id
	 * @param  {String}  [data.name]
	 * @param  {String}  [data.items]
	 * @return {Promise}
	 */
	update: async (access, data) => {
		await access.can("access_lists:update", data.id);
		assertValidUsernames(data.items);
		const row = await internalAccessList.get(access, { id: data.id });
		if (row.id !== data.id) {
			// Sanity check that something crazy hasn't happened
			throw new errs.InternalValidationError(
				`Access List could not be updated, IDs do not match: ${row.id} !== ${data.id}`,
			);
		}

		// patch only the scalar fields that were actually sent (schema allows any subset)
		const patch = _.pick(data, ["name", "satisfy_any", "pass_auth"]);
		if (Object.keys(patch).length) {
			await accessListModel.query().where({ id: data.id }).patch(patch);
		}

		// Check for items and add/update/remove them
		if (typeof data.items !== "undefined" && data.items) {
			// Empty password: keep the user, don't change the password
			const itemsToKeep = data.items.filter((item) => !item.password).map((item) => item.username);

			const query = accessListAuthModel.query().delete().where("access_list_id", data.id);

			if (itemsToKeep.length) {
				query.andWhere("username", "NOT IN", itemsToKeep);
			}

			await query;
			// Add new items, one after another (see create())
			for (const item of data.items) {
				if (item.password) {
					await accessListAuthModel.query().insert({
						access_list_id: data.id,
						username: item.username,
						password: item.password,
					});
				}
			}
		}

		// Check for clients and add/update/remove them
		if (typeof data.clients !== "undefined" && data.clients) {
			await accessListClientModel.query().delete().where("access_list_id", data.id);
			// Add new clients in the order given: nginx evaluates allow/deny top-down
			for (const client of data.clients) {
				if (client.address) {
					await accessListClientModel.query().insert({
						access_list_id: data.id,
						address: client.address,
						directive: client.directive,
					});
				}
			}
		}

		// Add to audit log
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "access-list",
			object_id: data.id,
			meta: internalAccessList.maskItems(data),
		});

		// re-fetch with expansions
		const freshRow = await internalAccessList.get(
			access,
			{
				id: data.id,
				expand: ["owner", "items", "clients", "proxy_hosts.[certificate,access_list.[clients,items]]"],
			},
			true, // skip masking
		);

		await internalAccessList.build(freshRow);
		if (Number.parseInt(freshRow.proxy_host_count, 10)) {
			await internalNginx.bulkGenerateConfigs("proxy_host", freshRow.proxy_hosts);
		}
		await internalNginx.reload();
		return internalAccessList.maskItems(freshRow);
	},

	/**
	 * @param  {Access}   access
	 * @param  {Object}   data
	 * @param  {Integer}  data.id
	 * @param  {Array}    [data.expand]
	 * @param  {Array}    [data.omit]
	 * @param  {Boolean}  [skipMasking]
	 * @return {Promise}
	 */
	get: async (access, data, skipMasking) => {
		const thisData = data || {};
		const accessData = await access.can("access_lists:get", thisData.id);

		const query = accessListModel
			.query()
			.select("access_list.*", accessListModel.raw("COUNT(proxy_host.id) as proxy_host_count"))
			.leftJoin("proxy_host", function () {
				this.on("proxy_host.access_list_id", "=", "access_list.id").andOn("proxy_host.is_deleted", "=", 0);
			})
			.where("access_list.is_deleted", 0)
			.andWhere("access_list.id", thisData.id)
			.groupBy("access_list.id")
			.allowGraph("[owner,items,clients,proxy_hosts.[certificate,access_list.[clients,items]]]")
			.first();

		if (accessData.permission_visibility !== "all") {
			query.andWhere("access_list.owner_user_id", access.token.getUserId(1));
		}

		if (typeof thisData.expand !== "undefined" && thisData.expand !== null) {
			query.withGraphFetched(`[${thisData.expand.join(", ")}]`);
		}

		let row = await query.then(utils.omitRow(omissions()));

		if (!row?.id) {
			throw new errs.ItemNotFoundError(thisData.id);
		}
		if (!skipMasking && typeof row.items !== "undefined" && row.items) {
			row = internalAccessList.maskItems(row);
		}
		// Custom omissions
		if (typeof data.omit !== "undefined" && data.omit !== null) {
			row = _.omit(row, data.omit);
		}
		return row;
	},

	/**
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @param   {Integer} data.id
	 * @param   {String}  [data.reason]
	 * @returns {Promise}
	 */
	delete: async (access, data) => {
		await access.can("access_lists:delete", data.id);
		const row = await internalAccessList.get(access, {
			id: data.id,
			expand: ["proxy_hosts.[certificate,access_list.[clients,items]]", "items", "clients"],
		});

		if (!row?.id) {
			throw new errs.ItemNotFoundError(data.id);
		}

		// 1. update row to be deleted
		// 2. update any proxy hosts that were using it (ignoring permissions)
		// 3. reconfigure those hosts
		// 4. audit log

		// 1. update row to be deleted
		await accessListModel.query().where("id", row.id).patch({
			is_deleted: 1,
		});

		// 2. update any proxy hosts that were using it (ignoring permissions)
		if (row.proxy_hosts) {
			await proxyHostModel.query().where("access_list_id", "=", row.id).patch({ access_list_id: 0 });

			// 3. reconfigure those hosts, then reload nginx
			// set the access_list_id to zero for these items
			row.proxy_hosts.map((_val, idx) => {
				row.proxy_hosts[idx].access_list_id = 0;
				return true;
			});

			await internalNginx.bulkGenerateConfigs("proxy_host", row.proxy_hosts);
		}

		await internalNginx.reload();

		// delete the htpasswd file
		try {
			fs.unlinkSync(internalAccessList.getFilename(row));
		} catch (_err) {
			// do nothing
		}

		// 4. audit log
		await internalAuditLog.add(access, {
			action: "deleted",
			object_type: "access-list",
			object_id: row.id,
			meta: _.omit(internalAccessList.maskItems(row), ["is_deleted", "proxy_hosts"]),
		});
		return true;
	},

	/**
	 * All Lists
	 *
	 * @param   {Access}  access
	 * @param   {Array}   [expand]
	 * @param   {String}  [searchQuery]
	 * @returns {Promise}
	 */
	getAll: async (access, expand, searchQuery) => {
		const accessData = await access.can("access_lists:list");

		const query = accessListModel
			.query()
			.select("access_list.*", accessListModel.raw("COUNT(proxy_host.id) as proxy_host_count"))
			.leftJoin("proxy_host", function () {
				this.on("proxy_host.access_list_id", "=", "access_list.id").andOn("proxy_host.is_deleted", "=", 0);
			})
			.where("access_list.is_deleted", 0)
			.groupBy("access_list.id")
			.allowGraph("[owner,items,clients]")
			.orderBy("access_list.name", "ASC");

		if (accessData.permission_visibility !== "all") {
			query.andWhere("access_list.owner_user_id", access.token.getUserId(1));
		}

		// Query is used for searching
		if (typeof searchQuery === "string") {
			query.where(function () {
				this.where("name", "like", `%${searchQuery}%`);
			});
		}

		if (typeof expand !== "undefined" && expand !== null) {
			query.withGraphFetched(`[${expand.join(", ")}]`);
		}

		const rows = await query.then(utils.omitRows(omissions()));
		if (rows) {
			rows.map((row, idx) => {
				if (typeof row.items !== "undefined" && row.items) {
					rows[idx] = internalAccessList.maskItems(row);
				}
				return true;
			});
		}
		return rows;
	},

	/**
	 * Count is used in reports
	 *
	 * @param   {Integer} userId
	 * @param   {String}  visibility
	 * @returns {Promise}
	 */
	getCount: async (userId, visibility) => {
		const query = accessListModel.query().count("id as count").where("is_deleted", 0);

		if (visibility !== "all") {
			query.andWhere("owner_user_id", userId);
		}

		const row = await query.first();
		return Number.parseInt(row.count, 10);
	},

	/**
	 * @param   {Object}  list
	 * @returns {Object}
	 */
	maskItems: (list) => {
		if (list && typeof list.items !== "undefined") {
			list.items.forEach((_val, idx) => {
				// constant hint: deriving it from the stored password leaked its first
				// character and exact length to every reader of the list
				list.items[idx].hint = "********";
				list.items[idx].password = "";
			});
		}
		// expand=proxy_hosts.access_list.items carries the same plaintext passwords
		if (list && Array.isArray(list.proxy_hosts)) {
			for (const host of list.proxy_hosts) internalHost.cleanRowAccessListPasswords(host);
		}
		return list;
	},

	/**
	 * @param   {Object}  list
	 * @param   {Integer} list.id
	 * @returns {String}
	 */
	getFilename: (list) => {
		return `/data/access/${list.id}`;
	},

	/**
	 * @param   {Object}  list
	 * @param   {Integer} list.id
	 * @param   {String}  list.name
	 * @param   {Array}   list.items
	 * @returns {Promise}
	 */
	build: async (list) => {
		logger.info(`Building Access file #${list.id} for: ${list.name}`);

		const htpasswdFile = internalAccessList.getFilename(list);

		// Hash every user first and write the file once at the end: a failing
		// openssl call used to leave a half-written htpasswd behind that locked
		// out every user after the failing one. On failure the old file stays.
		const lines = [];
		if (list.items.length) {
			await new Promise((resolve, reject) => {
				batchflow(list.items)
					.sequential()
					.each((_i, item, next) => {
						if (item.password?.length) {
							logger.info(`Adding: ${item.username}`);

							// "--": a password starting with "-" must not be parsed as an openssl option
							utils
								.execFile("openssl", ["passwd", "-apr1", "--", item.password])
								.then((res) => {
									lines.push(`${item.username}:${res}`);
									next();
								})
								.catch((err) => {
									logger.error(err);
									next(err);
								});
						} else {
							// No password set, skip this item but keep the sequence moving
							next();
						}
					})
					.error((err) => {
						logger.error(err);
						reject(err);
					})
					.end((results) => {
						resolve(results);
					});
			});
		}

		fs.writeFileSync(htpasswdFile, lines.length ? `${lines.join("\n")}\n` : "", { encoding: "utf8" });
		logger.success(`Built Access file #${list.id} for: ${list.name}`);
	},
};

export default internalAccessList;
