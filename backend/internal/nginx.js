import fs from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import _ from "lodash";
import errs from "../lib/error.js";
import utils from "../lib/utils.js";
import { debug, nginx as logger } from "../logger.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Directives that must never appear in a user-supplied advanced_config, because
 * this string is rendered verbatim into an nginx server{} block that is then
 * loaded and reloaded by root. Each of these is a direct file-read / SSRF /
 * key-exfiltration / RCE primitive on the OpenResty/lua-enabled nginx these
 * images ship:
 *   - *_by_lua* / *_by_perl* / perl* / js_*  -> code execution as root
 *   - alias / root                            -> arbitrary filesystem read
 *   - include                                 -> pull in arbitrary files / secrets
 *   - ssl_certificate* / ssl_password_file    -> read/override TLS private keys
 *   - load_module                             -> load arbitrary shared objects
 * Directive names are matched as whole tokens at the start of a statement
 * (line start, or immediately after `{` or `;`), case-insensitively. This does
 * not block proxy_pass, which is a legitimate advanced_config primitive.
 */
const FORBIDDEN_ADVANCED_CONFIG_DIRECTIVES = [
	"include",
	"alias",
	"root",
	"load_module",
	"ssl_certificate",
	"ssl_certificate_key",
	"ssl_password_file",
	"perl",
	"perl_set",
	"perl_modules",
	"perl_require",
];

// Any directive whose name contains "lua", "perl", or starts with "js_" (njs)
// is a code-execution surface and is rejected regardless of the exact name.
const FORBIDDEN_ADVANCED_CONFIG_DIRECTIVE_PATTERN = /(?:_by_lua\w*|lua_\w+|perl\w*|_by_perl\w*|^js_\w+)$/i;

/**
 * Validates a user-supplied advanced_config string before it is rendered into
 * a root-loaded nginx config. Throws a ValidationError on the first forbidden
 * directive found. Empty / non-string input is a no-op.
 *
 * @param   {String}  cfg
 * @throws  {errs.ValidationError}
 */
const assertSafeAdvancedConfig = (cfg) => {
	if (typeof cfg !== "string" || cfg === "") {
		return;
	}

	// Strip out quoted strings and comments so a directive name appearing inside
	// e.g. a log_format template or a `# comment` doesn't cause a false positive,
	// while the actual leading directive token of every statement is preserved.
	const withoutComments = cfg.replace(/#[^\n]*/g, "");

	// Split into candidate statements on statement separators: `;`, `{`, `}`
	// and newlines. The first whitespace-delimited token of each candidate is
	// the directive name.
	const statements = withoutComments.split(/[;{}\n]+/);

	for (const statement of statements) {
		const trimmed = statement.trim();
		if (trimmed === "") {
			continue;
		}
		// Directive name is the first token; may be preceded by nothing else.
		const directive = trimmed.split(/\s+/)[0].toLowerCase();
		if (directive === "") {
			continue;
		}

		if (
			FORBIDDEN_ADVANCED_CONFIG_DIRECTIVES.includes(directive) ||
			FORBIDDEN_ADVANCED_CONFIG_DIRECTIVE_PATTERN.test(directive)
		) {
			throw new errs.ValidationError(`advanced_config contains a forbidden nginx directive: ${directive}`);
		}
	}
};

// Characters that, if present in a per-location forward_host / forward_path,
// would break out of the `proxy_pass ...;` directive in templates/_location.conf
// (that value is rendered UNQUOTED and the config is then loaded/reloaded by
// root nginx). Any whitespace/newline or nginx metacharacter (`;` `{` `}`
// quotes, backslash, backtick, `$`) is a directive-injection primitive, so we
// reject anything that is not a plain host/path character. This mirrors the
// schema patterns on forward_host / forward_path and acts as a hard gate right
// at the render sink for defense in depth.
const UNSAFE_FORWARD_FIELD_PATTERN = /[^A-Za-z0-9._:/%?#=&+~-]/;

/**
 * Validates a per-location forward_host / forward_path value before it is
 * rendered verbatim (and unquoted) into a root-loaded nginx proxy_pass
 * directive. Throws a ValidationError on the first unsafe character found.
 * Empty / non-string input is a no-op (forward_path is optional).
 *
 * @param   {String}  value
 * @param   {String}  fieldName
 * @throws  {errs.ValidationError}
 */
const assertSafeForwardField = (value, fieldName) => {
	if (typeof value !== "string" || value === "") {
		return;
	}
	if (UNSAFE_FORWARD_FIELD_PATTERN.test(value)) {
		throw new errs.ValidationError(`${fieldName} contains an invalid character`);
	}
};

const internalNginx = {
	/**
	 * This will:
	 * - test the nginx config first to make sure it's OK
	 * - create / recreate the config for the host
	 * - test again
	 * - IF OK:  update the meta with online status
	 * - IF BAD: update the meta with offline status and remove the config entirely
	 * - then reload nginx
	 *
	 * @param   {Object|String}  model
	 * @param   {String}         host_type
	 * @param   {Object}         host
	 * @returns {Promise}
	 */
	configure: (model, host_type, host) => {
		let combined_meta = {};

		return internalNginx
			.test()
			.then(() => {
				// Nginx is OK
				// We're deleting this config regardless.
				// Don't throw errors, as the file may not exist at all
				// Delete the .err file too
				return internalNginx.deleteConfig(host_type, host, true);
			})
			.then(() => {
				return internalNginx.generateConfig(host_type, host);
			})
			.then(() => {
				// Test nginx again and update meta with result
				return internalNginx
					.test()
					.then(() => {
						// nginx is ok
						combined_meta = _.assign({}, host.meta, {
							nginx_online: true,
							nginx_err: null,
						});

						return model.query().where("id", host.id).patch({
							meta: combined_meta,
						});
					})
					.catch((err) => {
						// Remove the error_log line because it's a docker-ism false positive that doesn't need to be reported.
						// It will always look like this:
						//   nginx: [alert] could not open error log file: open() "/var/log/nginx/error.log" failed (6: No such device or address)

						const valid_lines = [];
						const err_lines = err.message.split("\n");
						err_lines.map((line) => {
							if (line.indexOf("/var/log/nginx/error.log") === -1) {
								valid_lines.push(line);
							}
							return true;
						});

						debug(logger, "Nginx test failed:", valid_lines.join("\n"));

						// config is bad, update meta and delete config
						combined_meta = _.assign({}, host.meta, {
							nginx_online: false,
							nginx_err: valid_lines.join("\n"),
						});

						return model
							.query()
							.where("id", host.id)
							.patch({
								meta: combined_meta,
							})
							.then(() => {
								return internalNginx.renameConfigAsError(host_type, host);
							})
							.then(() => {
								// The config file was renamed to .err above; this just makes
								// sure nothing is left behind. Keep the .err file for debugging.
								return internalNginx.deleteConfig(host_type, host);
							});
					});
			})
			.then(() => {
				return internalNginx.reload();
			})
			.then(() => {
				return combined_meta;
			});
	},

	/**
	 * @returns {Promise}
	 */
	test: () => {
		debug(logger, "Testing Nginx configuration");
		return utils.execFile("/usr/sbin/nginx", ["-t", "-g", "error_log off;"]);
	},

	/**
	 * @returns {Promise}
	 */
	reload: () => {
		return internalNginx.test().then(() => {
			logger.info("Reloading Nginx");
			return utils.execFile("/usr/sbin/nginx", ["-s", "reload"]);
		});
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Integer} host_id
	 * @returns {String}
	 */
	getConfigName: (host_type, host_id) => {
		if (host_type === "default") {
			return "/data/nginx/default_host/site.conf";
		}
		return `/data/nginx/${internalNginx.getFileFriendlyHostType(host_type)}/${host_id}.conf`;
	},

	/**
	 * Generates custom locations
	 * @param   {Object}  host
	 * @returns {Promise}
	 */
	renderLocations: (host) => {
		return new Promise((resolve, reject) => {
			let template;

			try {
				template = fs.readFileSync(`${__dirname}/../templates/_location.conf`, { encoding: "utf8" });
			} catch (err) {
				reject(new errs.ConfigurationError(err.message));
				return;
			}

			const renderEngine = utils.getRenderEngine();
			let renderedLocations = "";

			const locationRendering = async () => {
				for (let i = 0; i < host.locations.length; i++) {
					const locationCopy = Object.assign(
						{},
						{ access_list_id: host.access_list_id },
						{ certificate_id: host.certificate_id },
						{ ssl_forced: host.ssl_forced },
						{ caching_enabled: host.caching_enabled },
						{ block_exploits: host.block_exploits },
						{ allow_websocket_upgrade: host.allow_websocket_upgrade },
						{ http2_support: host.http2_support },
						{ hsts_enabled: host.hsts_enabled },
						{ hsts_subdomains: host.hsts_subdomains },
						{ access_list: host.access_list },
						{ certificate: host.certificate },
						host.locations[i],
					);

					// Per-location advanced_config is also rendered verbatim into
					// the root-loaded config, so it must be validated too.
					assertSafeAdvancedConfig(locationCopy.advanced_config);

					// forward_host / forward_path are rendered UNQUOTED into the
					// proxy_pass directive; validate before (and after) the split
					// so no newline/nginx-metachar can break out of the directive.
					assertSafeForwardField(locationCopy.forward_host, "forward_host");
					assertSafeForwardField(locationCopy.forward_path, "forward_path");

					if (locationCopy.forward_host.indexOf("/") > -1) {
						const splitted = locationCopy.forward_host.split("/");

						locationCopy.forward_host = splitted.shift();
						locationCopy.forward_path = `/${splitted.join("/")}`;
					}

					renderedLocations += await renderEngine.parseAndRender(template, locationCopy);
				}
			};

			// A throw inside locationRendering (e.g. a forbidden directive or an
			// unsafe forward_host in a location) must reject this promise rather
			// than leave it pending forever.
			locationRendering()
				.then(() => resolve(renderedLocations))
				.catch(reject);
		});
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Object}  host
	 * @returns {Promise}
	 */
	generateConfig: (host_type, host_row) => {
		// Prevent modifying the original object:
		const host = JSON.parse(JSON.stringify(host_row));
		const nice_host_type = internalNginx.getFileFriendlyHostType(host_type);

		debug(logger, `Generating ${nice_host_type} Config:`, JSON.stringify(host, null, 2));

		const renderEngine = utils.getRenderEngine();

		return new Promise((resolve, reject) => {
			let template = null;
			const filename = internalNginx.getConfigName(nice_host_type, host.id);

			try {
				template = fs.readFileSync(`${__dirname}/../templates/${nice_host_type}.conf`, { encoding: "utf8" });
			} catch (err) {
				reject(new errs.ConfigurationError(err.message));
				return;
			}

			let locationsPromise;
			let origLocations;

			// Reject dangerous nginx directives in user-supplied advanced_config
			// before it is ever rendered into a root-loaded config file.
			// Also gate host-level forwarding targets that are rendered UNQUOTED
			// into a root-loaded config — redirection_host.conf `return ...;` and
			// stream.conf `proxy_pass ...;`. Their schema domain pattern accepts
			// interior newlines, so a newline + arbitrary nginx directives would
			// otherwise inject into the http/stream block (bypassing
			// assertSafeAdvancedConfig entirely).
			try {
				assertSafeAdvancedConfig(host.advanced_config);
				if (nice_host_type === "redirection_host") {
					assertSafeForwardField(host.forward_domain_name, "forward_domain_name");
				}
				if (nice_host_type === "stream") {
					assertSafeForwardField(host.forwarding_host, "forwarding_host");
				}
			} catch (err) {
				reject(err);
				return;
			}

			// Manipulate the data a bit before sending it to the template
			if (nice_host_type !== "default") {
				host.use_default_location = true;
				if (typeof host.advanced_config !== "undefined" && host.advanced_config) {
					host.use_default_location = !internalNginx.advancedConfigHasDefaultLocation(host.advanced_config);
				}
			}

			// For redirection hosts, if the scheme is not http or https, set it to $scheme
			if (
				nice_host_type === "redirection_host" &&
				["http", "https"].indexOf(host.forward_scheme.toLowerCase()) === -1
			) {
				host.forward_scheme = "$scheme";
			}

			if (host.locations) {
				//logger.info ('host.locations = ' + JSON.stringify(host.locations, null, 2));
				origLocations = [].concat(host.locations);
				locationsPromise = internalNginx.renderLocations(host).then((renderedLocations) => {
					host.locations = renderedLocations;
				});

				// Allow someone who is using / custom location path to use it, and skip the default / location
				_.map(host.locations, (location) => {
					if (location.path === "/") {
						host.use_default_location = false;
					}
				});
			} else {
				locationsPromise = Promise.resolve();
			}

			// Set the IPv6 setting for the host
			host.ipv6 = internalNginx.ipv6Enabled();

			locationsPromise
				.then(() => {
					renderEngine
						.parseAndRender(template, host)
						.then((config_text) => {
							fs.writeFileSync(filename, config_text, { encoding: "utf8" });
							debug(logger, "Wrote config:", filename, config_text);

							// Restore locations array
							host.locations = origLocations;

							resolve(true);
						})
						.catch((err) => {
							debug(logger, `Could not write ${filename}:`, err.message);
							reject(new errs.ConfigurationError(err.message));
						});
				})
				// A rejection from renderLocations (e.g. a forbidden advanced_config
				// directive in a location) must reject the outer promise rather than
				// leaving it pending forever.
				.catch((err) => {
					reject(err);
				});
		});
	},

	/**
	 * This generates a temporary nginx config listening on port 80 for the domain names listed
	 * in the certificate setup. It allows the letsencrypt acme challenge to be requested by letsencrypt
	 * when requesting a certificate without having a hostname set up already.
	 *
	 * @param   {Object}  certificate
	 * @returns {Promise}
	 */
	generateLetsEncryptRequestConfig: (certificate) => {
		debug(logger, "Generating LetsEncrypt Request Config:", certificate);
		const renderEngine = utils.getRenderEngine();

		return new Promise((resolve, reject) => {
			let template = null;
			const filename = `/data/nginx/temp/letsencrypt_${certificate.id}.conf`;

			try {
				template = fs.readFileSync(`${__dirname}/../templates/letsencrypt-request.conf`, { encoding: "utf8" });
			} catch (err) {
				reject(new errs.ConfigurationError(err.message));
				return;
			}

			certificate.ipv6 = internalNginx.ipv6Enabled();

			renderEngine
				.parseAndRender(template, certificate)
				.then((config_text) => {
					fs.writeFileSync(filename, config_text, { encoding: "utf8" });
					debug(logger, "Wrote config:", filename, config_text);
					resolve(true);
				})
				.catch((err) => {
					debug(logger, `Could not write ${filename}:`, err.message);
					reject(new errs.ConfigurationError(err.message));
				});
		});
	},

	/**
	 * A simple wrapper around unlinkSync that writes to the logger
	 *
	 * @param   {String}  filename
	 */
	deleteFile: (filename) => {
		if (!fs.existsSync(filename)) {
			return;
		}
		try {
			debug(logger, `Deleting file: ${filename}`);
			fs.unlinkSync(filename);
		} catch (err) {
			debug(logger, "Could not delete file:", JSON.stringify(err, null, 2));
		}
	},

	/**
	 *
	 * @param   {String} host_type
	 * @returns String
	 */
	getFileFriendlyHostType: (host_type) => {
		return host_type.replace(/-/g, "_");
	},

	/**
	 * This removes the temporary nginx config file generated by `generateLetsEncryptRequestConfig`
	 *
	 * @param   {Object}  certificate
	 * @returns {Promise}
	 */
	deleteLetsEncryptRequestConfig: (certificate) => {
		const config_file = `/data/nginx/temp/letsencrypt_${certificate.id}.conf`;
		return new Promise((resolve /*, reject*/) => {
			internalNginx.deleteFile(config_file);
			resolve();
		});
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Object}  [host]
	 * @param   {Boolean} [delete_err_file]
	 * @returns {Promise}
	 */
	deleteConfig: (host_type, host, delete_err_file) => {
		const config_file = internalNginx.getConfigName(
			internalNginx.getFileFriendlyHostType(host_type),
			typeof host === "undefined" ? 0 : host.id,
		);
		const config_file_err = `${config_file}.err`;

		return new Promise((resolve /*, reject*/) => {
			internalNginx.deleteFile(config_file);
			if (delete_err_file) {
				internalNginx.deleteFile(config_file_err);
			}
			resolve();
		});
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Object}  [host]
	 * @returns {Promise}
	 */
	renameConfigAsError: (host_type, host) => {
		const config_file = internalNginx.getConfigName(
			internalNginx.getFileFriendlyHostType(host_type),
			typeof host === "undefined" ? 0 : host.id,
		);
		const config_file_err = `${config_file}.err`;

		return new Promise((resolve /*, reject*/) => {
			// Rename replaces any existing .err file atomically.
			// Ignore the result, as this is a debugging informative file anyway
			fs.rename(config_file, config_file_err, () => {
				resolve();
			});
		});
	},

	/**
	 * @param   {String}  hostType
	 * @param   {Array}   hosts
	 * @returns {Promise}
	 */
	bulkGenerateConfigs: (hostType, hosts) => {
		const promises = [];
		hosts.map((host) => {
			promises.push(internalNginx.generateConfig(hostType, host));
			return true;
		});

		return Promise.all(promises);
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Array}   hosts
	 * @returns {Promise}
	 */
	bulkDeleteConfigs: (host_type, hosts) => {
		const promises = [];
		hosts.map((host) => {
			promises.push(internalNginx.deleteConfig(host_type, host, true));
			return true;
		});

		return Promise.all(promises);
	},

	/**
	 * @param   {string}  config
	 * @returns {boolean}
	 */
	advancedConfigHasDefaultLocation: (cfg) => !!cfg.match(/^(?:.*;)?\s*?location\s*?\/\s*?{/im),

	/**
	 * @returns {boolean}
	 */
	ipv6Enabled: () => {
		if (typeof process.env.DISABLE_IPV6 !== "undefined") {
			const disabled = process.env.DISABLE_IPV6.toLowerCase();
			return !(disabled === "on" || disabled === "true" || disabled === "1" || disabled === "yes");
		}

		return true;
	},
};

export default internalNginx;

// Exported for unit testing only
export const _testExports = {
	assertSafeAdvancedConfig,
	assertSafeForwardField,
};
