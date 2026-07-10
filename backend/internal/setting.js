import fs from "node:fs";
import errs from "../lib/error.js";
import settingModel from "../models/setting.js";
import internalNginx from "./nginx.js";

// meta.redirect is written verbatim into the root nginx config
// (`return 301 {{ meta.redirect }};`). Only a plain http(s) URL may pass:
// no whitespace/newlines/semicolons/quotes/config-or-shell metacharacters, so
// the value cannot close the location block and inject arbitrary directives.
const REDIRECT_URL_PATTERN = /^https?:\/\/[^\s"'$`\\;|&(){}<>!#]+$/;

/**
 * Throws a ValidationError unless `redirect` is a safe plain http(s) URL.
 * Used as the last gate before a 'redirect' default-site value is persisted
 * and rendered as root.
 *
 * @param {*} redirect
 */
function assertSafeRedirect(redirect) {
	if (typeof redirect !== "string" || redirect.length > 255 || !REDIRECT_URL_PATTERN.test(redirect)) {
		throw new errs.ValidationError("meta.redirect must be a plain http(s) URL when value is 'redirect'");
	}
}

const internalSetting = {
	/**
	 * @param  {Access}  access
	 * @param  {Object}  data
	 * @param  {String}  data.id
	 * @return {Promise}
	 */
	update: (access, data) => {
		return access
			.can("settings:update", data.id)
			.then((/*access_data*/) => {
				return internalSetting.get(access, { id: data.id });
			})
			.then((row) => {
				if (row.id !== data.id) {
					// Sanity check that something crazy hasn't happened
					throw new errs.InternalValidationError(
						`Setting could not be updated, IDs do not match: ${row.id} !== ${data.id}`,
					);
				}

				// The 'html' default-site value requires meta.html to write index.html.
				// Validate before persisting so a missing value can't half-apply the setting.
				if (data.id === "default-site" && data.value === "html" && (!data.meta || typeof data.meta.html !== "string")) {
					throw new errs.ValidationError("meta.html is required when value is 'html'");
				}

				// The 'redirect' default-site value writes meta.redirect verbatim into the
				// root nginx config (`return 301 {{ meta.redirect }};`). Reject anything but a
				// plain http(s) URL so newlines/semicolons/quotes/config metacharacters can't
				// close the location block and inject arbitrary nginx directives. This mirrors
				// the schema pattern but must live here too: the schema is only enforced at the
				// route layer, while this is the last gate before the value is persisted and
				// rendered as root.
				if (data.id === "default-site" && data.value === "redirect") {
					assertSafeRedirect(data.meta?.redirect);
				}

				return settingModel.query().where({ id: data.id }).patch(data);
			})
			.then(() => {
				return internalSetting.get(access, {
					id: data.id,
				});
			})
			.then((row) => {
				if (row.id === "default-site") {
					// write the html if we need to
					if (row.value === "html") {
						fs.writeFileSync("/data/nginx/default_www/index.html", row.meta.html, { encoding: "utf8" });
					}

					// Configure nginx
					return internalNginx
						.deleteConfig("default")
						.then(() => {
							return internalNginx.generateConfig("default", row);
						})
						.then(() => {
							return internalNginx.test();
						})
						.then(() => {
							return internalNginx.reload();
						})
						.then(() => {
							return row;
						})
						.catch((/*err*/) => {
							return internalNginx
								.deleteConfig("default")
								.then(() => {
									return internalNginx.test();
								})
								.then(() => {
									return internalNginx.reload();
								})
								.catch((/*recoveryErr*/) => {
									// Recovery itself failed - fall through to the error below
								})
								.then(() => {
									throw new errs.ValidationError("Could not reconfigure Nginx. Please check logs.");
								});
						});
				}
				return row;
			});
	},

	/**
	 * @param  {Access}   access
	 * @param  {Object}   data
	 * @param  {String}   data.id
	 * @return {Promise}
	 */
	get: (access, data) => {
		return access
			.can("settings:get", data.id)
			.then(() => {
				return settingModel.query().where("id", data.id).first();
			})
			.then((row) => {
				if (row) {
					return row;
				}
				throw new errs.ItemNotFoundError(data.id);
			});
	},

	/**
	 * This will only count the settings
	 *
	 * @param   {Access}  access
	 * @returns {*}
	 */
	getCount: (access) => {
		return access
			.can("settings:list")
			.then(() => {
				return settingModel.query().count("id as count").first();
			})
			.then((row) => {
				return Number.parseInt(row.count, 10);
			});
	},

	/**
	 * All settings
	 *
	 * @param   {Access}  access
	 * @returns {Promise}
	 */
	getAll: (access) => {
		return access.can("settings:list").then(() => {
			return settingModel.query().orderBy("description", "ASC");
		});
	},
};

export default internalSetting;

export const _testExports = { assertSafeRedirect };
