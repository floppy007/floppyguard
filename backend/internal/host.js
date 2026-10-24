import _ from "lodash";
import errs from "../lib/error.js";
import { castJsonIfNeed } from "../lib/helpers.js";
import accessListModel from "../models/access_list.js";
import certificateModel from "../models/certificate.js";
import deadHostModel from "../models/dead_host.js";
import proxyHostModel from "../models/proxy_host.js";
import redirectionHostModel from "../models/redirection_host.js";

const internalHost = {
	/**
	 * Prüft, ob der Anfragende das Zertifikat sehen (und damit verwenden) darf:
	 * Admins und Benutzer mit Sichtbarkeit "all" jedes, alle anderen nur
	 * eigene. Sonst könnte ein Benutzer fremde (z. B. Wildcard-)Zertifikate
	 * und deren DNS-Zugangsdaten an seine Hosts hängen.
	 *
	 * @param {Access} access
	 * @param {*}      certificateId
	 */
	assertCertificateAccess: async (access, certificateId) => {
		if (certificateId === undefined || certificateId === null || certificateId === 0 || certificateId === "new") {
			return;
		}
		const id = Number(certificateId);
		if (!Number.isInteger(id) || id <= 0) {
			throw new errs.ValidationError("Invalid certificate");
		}
		const accessData = await access.can("certificates:get", id);
		if (accessData === true) {
			// interner Zugriff
			return;
		}
		const query = certificateModel.query().where("is_deleted", 0).andWhere("id", id).first();
		if (accessData?.permission_visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}
		const row = await query;
		if (!row?.id) {
			throw new errs.ValidationError("Certificate not found or not accessible");
		}
	},

	/**
	 * Prüft, ob der Anfragende die Access-Liste sehen (und damit verwenden) darf:
	 * Admins und Benutzer mit Sichtbarkeit "all" jede, alle anderen nur eigene.
	 * Sonst könnte ein Benutzer fremde Listen an seine Hosts hängen.
	 *
	 * @param {Access} access
	 * @param {*}      accessListId
	 */
	assertAccessListAccess: async (access, accessListId) => {
		if (accessListId === undefined || accessListId === null || accessListId === 0) {
			return;
		}
		const id = Number(accessListId);
		if (!Number.isInteger(id) || id <= 0) {
			throw new errs.ValidationError("Invalid access list");
		}
		const accessData = await access.can("access_lists:get", id);
		if (accessData === true) {
			// interner Zugriff
			return;
		}
		const query = accessListModel.query().where("is_deleted", 0).andWhere("id", id).first();
		if (accessData?.permission_visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}
		const row = await query;
		if (!row?.id) {
			throw new errs.ValidationError("Access list not found or not accessible");
		}
	},

	/**
	 * Basic-Auth-Passwörter liegen für die htpasswd-Erzeugung im Klartext in der DB;
	 * sie dürfen nie in API-Antworten oder Audit-Log-Meta landen. Leert
	 * row.access_list.items[].password (Templates brauchen nur items.length).
	 *
	 * @param   {Object}  row
	 * @returns {Object}
	 */
	cleanRowAccessListPasswords: (row) => {
		const items = row?.access_list?.items;
		if (Array.isArray(items)) {
			for (const item of items) {
				if (item && "password" in item) item.password = "";
			}
		}
		return row;
	},

	/**
	 * Makes sure that the ssl_* and hsts_* fields play nicely together.
	 * ie: if there is no cert, then force_ssl is off.
	 *     if force_ssl is off, then hsts_enabled is definitely off.
	 *
	 * @param   {object} data
	 * @param   {object} [existing_data]
	 * @returns {object}
	 */
	cleanSslHstsData: (data, existingData) => {
		const combinedData = _.assign({}, existingData || {}, data);

		if (!combinedData.certificate_id) {
			combinedData.ssl_forced = false;
			combinedData.http2_support = false;
		}

		if (!combinedData.ssl_forced) {
			combinedData.hsts_enabled = false;
		}

		if (!combinedData.hsts_enabled) {
			combinedData.hsts_subdomains = false;
		}

		return combinedData;
	},

	/**
	 * used by the getAll functions of hosts, this removes the certificate meta if present
	 *
	 * @param   {Array}  rows
	 * @returns {Array}
	 */
	cleanAllRowsCertificateMeta: (rows) => {
		rows.map((_, idx) => {
			if (typeof rows[idx].certificate !== "undefined" && rows[idx].certificate) {
				rows[idx].certificate.meta = {};
			}
			return true;
		});

		return rows;
	},

	/**
	 * used by the get/update functions of hosts, this removes the certificate meta if present
	 *
	 * @param   {Object}  row
	 * @returns {Object}
	 */
	cleanRowCertificateMeta: (row) => {
		if (typeof row.certificate !== "undefined" && row.certificate) {
			row.certificate.meta = {};
		}

		return row;
	},

	/**
	 * This returns all the host types with any domain listed in the provided domainNames array.
	 * This is used by the certificates to temporarily disable any host that is using the domain
	 *
	 * @param   {Array}  domainNames
	 * @returns {Promise}
	 */
	getHostsWithDomains: async (domainNames) => {
		const responseObject = {
			total_count: 0,
			dead_hosts: [],
			proxy_hosts: [],
			redirection_hosts: [],
		};
		if (!Array.isArray(domainNames) || domainNames.length === 0) return responseObject;

		const wanted = new Set(domainNames.map((d) => String(d).toLowerCase()));
		const usesDomain = (row) => (row.domain_names || []).some((n) => wanted.has(String(n).toLowerCase()));

		// Load the relations the templates need: bulkGenerateConfigs() re-renders these
		// rows, and without certificate/access_list the confs silently lose SSL/auth.
		const [proxy, redirection, dead] = await Promise.all([
			internalHost._loadHostsUsingDomains(
				proxyHostModel,
				domainNames,
				"[certificate,access_list.[clients,items]]",
			),
			internalHost._loadHostsUsingDomains(redirectionHostModel, domainNames, "[certificate]"),
			internalHost._loadHostsUsingDomains(deadHostModel, domainNames, "[certificate]"),
		]);
		responseObject.proxy_hosts = (proxy || []).filter(usesDomain);
		responseObject.redirection_hosts = (redirection || []).filter(usesDomain);
		responseObject.dead_hosts = (dead || []).filter(usesDomain);
		responseObject.total_count =
			responseObject.proxy_hosts.length +
			responseObject.redirection_hosts.length +
			responseObject.dead_hosts.length;

		return responseObject;
	},

	/**
	 * Rows of `model` that are not deleted and whose domain_names may contain one of
	 * domainNames (LIKE prefilter, over-inclusive; callers match exactly). The optional
	 * graph is only fetched when given.
	 *
	 * @param   {Object}  model
	 * @param   {Array}   domainNames
	 * @param   {String}  [graph]
	 * @returns {Promise}
	 */
	_loadHostsUsingDomains: (model, domainNames, graph) => {
		const col = castJsonIfNeed("domain_names");
		const query = model
			.query()
			.where("is_deleted", 0)
			.andWhere((qb) => {
				for (const name of domainNames) qb.orWhere(col, "like", `%${name}%`);
			});
		return graph ? query.withGraphFetched(graph) : query;
	},

	/**
	 * Pure helper: returns the first entry of domainNames (in input order) that is
	 * used by one of the rows (case-insensitive), ignoring the row with id === ignoreId.
	 *
	 * @param   {Array}   domainNames
	 * @param   {Array}   rows
	 * @param   {Integer} [ignoreId]
	 * @returns {String|null}
	 */
	_findTakenHostname: (domainNames, rows, ignoreId) => {
		const taken = new Set();
		for (const row of rows || []) {
			if (ignoreId && row.id === ignoreId) continue;
			for (const name of row.domain_names || []) taken.add(String(name).toLowerCase());
		}
		return domainNames.find((d) => taken.has(String(d).toLowerCase())) ?? null;
	},

	/**
	 * Throws ValidationError("<name> is already in use") if any of domainNames is used
	 * by another proxy/redirection/dead host. 3 queries in total instead of 3 per name.
	 *
	 * @param   {Array}    domainNames
	 * @param   {String}   [ignoreType]   'proxy', 'redirection', 'dead'
	 * @param   {Integer}  [ignoreId]     Must be supplied if type was also supplied
	 * @returns {Promise}
	 */
	assertHostnamesFree: async (domainNames, ignoreType, ignoreId) => {
		if (!Array.isArray(domainNames) || domainNames.length === 0) return;
		const load = (model) => internalHost._loadHostsUsingDomains(model, domainNames);
		const [proxy, redirection, dead] = await Promise.all([
			load(proxyHostModel),
			load(redirectionHostModel),
			load(deadHostModel),
		]);
		for (const [type, rows] of [
			["proxy", proxy],
			["redirection", redirection],
			["dead", dead],
		]) {
			const hit = internalHost._findTakenHostname(
				domainNames,
				rows,
				ignoreType === type && ignoreId ? ignoreId : 0,
			);
			if (hit) throw new errs.ValidationError(`${hit} is already in use`);
		}
	},
};

export default internalHost;
