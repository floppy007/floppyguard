import { AsyncLocalStorage } from "node:async_hooks";
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

// Directives that read or write arbitrary files as the root nginx master:
// TLS key/cert/CRL/password files, htpasswd files, temp/store paths, and logs.
const FORBIDDEN_FILE_DIRECTIVE_PATTERN =
	/(?:_certificate|_certificate_key|_certificate_cache|_password_file|_crl|_dhparam|_temp_path|_user_file|_store|_ticket_key|_stapling_file)$/i;

/**
 * Splits an nginx config fragment into statements the same way nginx's own
 * tokenizer (ngx_conf_read_token) does, so the gate sees exactly the directive
 * names nginx will see:
 *   - `#` starts a comment ONLY at the start of a token (`a#b` is one word),
 *   - a token starting with `"` or `'` is a quoted string (quotes removed),
 *   - a backslash escapes the next character,
 *   - `;`, `{` and `}` end a statement outside of quotes.
 *
 * @param   {String} cfg
 * @returns {Array<{ name: String, raw: String, args: String[] }>}
 */
const tokenizeNginxStatements = (cfg) => {
	const statements = [];
	let words = [];
	let rawFirst = null;
	let i = 0;
	const len = cfg.length;

	const endStatement = () => {
		if (words.length) {
			statements.push({ name: words[0], raw: rawFirst, args: words.slice(1) });
		}
		words = [];
		rawFirst = null;
	};

	while (i < len) {
		const ch = cfg[i];
		if (/\s/.test(ch)) {
			i++;
			continue;
		}
		if (ch === "#") {
			while (i < len && cfg[i] !== "\n") i++;
			continue;
		}
		if (ch === ";" || ch === "{" || ch === "}") {
			endStatement();
			i++;
			continue;
		}

		const startIdx = i;
		let word = "";
		if (ch === '"' || ch === "'") {
			const quote = ch;
			i++;
			while (i < len && cfg[i] !== quote) {
				if (cfg[i] === "\\" && i + 1 < len) {
					word += cfg[i + 1];
					i += 2;
					continue;
				}
				word += cfg[i];
				i++;
			}
			i++; // closing quote
		} else {
			while (i < len) {
				const c = cfg[i];
				if (/\s/.test(c) || c === ";" || c === "{" || c === "}") break;
				if (c === "\\" && i + 1 < len) {
					word += cfg[i + 1];
					i += 2;
					continue;
				}
				word += c;
				i++;
			}
		}
		if (!words.length) {
			rawFirst = cfg.slice(startIdx, i);
		}
		words.push(word);
	}
	endStatement();
	return statements;
};

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

	for (const statement of tokenizeNginxStatements(cfg)) {
		const directive = statement.name.toLowerCase();

		// nginx strips quotes/escapes from directive names too ("alias" == alias).
		// A legitimate directive name is never quoted or escaped, so refuse it
		// outright instead of trying to reason about it.
		if (/["'\\]/.test(statement.raw || "")) {
			throw new errs.ValidationError(
				`advanced_config contains a quoted or escaped nginx directive name: ${directive.slice(0, 64)}`,
			);
		}
		if (directive === "") {
			continue;
		}

		if (
			FORBIDDEN_ADVANCED_CONFIG_DIRECTIVES.includes(directive) ||
			FORBIDDEN_ADVANCED_CONFIG_DIRECTIVE_PATTERN.test(directive) ||
			FORBIDDEN_FILE_DIRECTIVE_PATTERN.test(directive)
		) {
			throw new errs.ValidationError(`advanced_config contains a forbidden nginx directive: ${directive}`);
		}

		// access_log/error_log create or append files as root. Only switching
		// the access log off is allowed.
		if (
			directive === "error_log" ||
			(directive === "access_log" && !(statement.args.length === 1 && statement.args[0] === "off"))
		) {
			throw new errs.ValidationError(`advanced_config contains a forbidden nginx directive: ${directive}`);
		}
	}
};

// A custom location path is rendered unquoted as `location {{ path }} {`.
// Allowed: an optional modifier (=, ~, ~*, ^~) followed by ONE token without
// whitespace or nginx metacharacters (; { } quotes # backtick). Regex
// locations keep working (\.php$, (a|b), [0-9] ...), but nothing can close the
// location block or start another directive.
const SAFE_LOCATION_PATH_PATTERN = /^(?:(?:=|~|~\*|\^~) +)?[^\s;{}"'#`]*[^\s;{}"'#`\\]$/;

/**
 * @param   {String} value
 * @throws  {errs.ValidationError}
 */
const assertSafeLocationPath = (value) => {
	if (typeof value !== "string" || !SAFE_LOCATION_PATH_PATTERN.test(value)) {
		throw new errs.ValidationError("location path contains an invalid character");
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

// Every conf mutation + `nginx -t` + reload runs behind one module-level
// lock: configure() and bulkGenerateConfigs() put untested confs live and keep
// the previous one in a fixed <conf>.bak, so two overlapping calls could test
// against each other's half-written state or consume each other's backup.
// Re-entrant (configure -> reload -> test) via AsyncLocalStorage.
const configLockContext = new AsyncLocalStorage();
let configLockTail = Promise.resolve();
const withConfigLock = (fn) => {
	if (configLockContext.getStore()) {
		return new Promise((resolve) => resolve(fn()));
	}
	const run = configLockTail.then(() => configLockContext.run(true, fn));
	configLockTail = run.catch(() => {});
	return run;
};

// `nginx -t` holds the lock: do not let a hung run block every later save.
const NGINX_TEST_TIMEOUT_MS = 120000;

const internalNginx = {
	/**
	 * Run every render-time safety gate on the user-supplied fields that are
	 * present in `data` (a full row or a partial update payload). Called by the
	 * host create/update paths BEFORE the DB write, so a rejected value is never
	 * persisted, and by configure() before the live conf is touched.
	 *
	 * @param   {String}  host_type
	 * @param   {Object}  data
	 * @throws  {errs.ValidationError}
	 */
	assertSafeHostFields: (host_type, data) => {
		if (!data || typeof data !== "object") return;
		const nice_host_type = internalNginx.getFileFriendlyHostType(host_type);
		assertSafeAdvancedConfig(data.advanced_config);
		if (nice_host_type === "redirection_host") {
			assertSafeForwardField(data.forward_domain_name, "forward_domain_name");
		}
		if (nice_host_type === "stream") {
			assertSafeForwardField(data.forwarding_host, "forwarding_host");
		}
		if (Array.isArray(data.locations)) {
			for (const location of data.locations) {
				if (!location || typeof location !== "object") continue;
				assertSafeAdvancedConfig(location.advanced_config);
				assertSafeLocationPath(location.path);
				assertSafeForwardField(location.forward_host, "forward_host");
				assertSafeForwardField(location.forward_path, "forward_path");
			}
		}
	},

	/**
	 * This will:
	 * - test the nginx config first to make sure it's OK
	 * - create / recreate the config for the host
	 * - test again
	 * - IF OK:  update the meta with online status
	 * - IF BAD: keep the new config as .err, put the previous working config back
	 *           (meta: still online + nginx_err) or, when there was none, mark
	 *           the host offline
	 * - then reload nginx
	 * - if the previous config was put back, reject with a ValidationError
	 *   carrying the nginx -t output, so the save visibly fails instead of
	 *   returning success while nginx keeps serving the old config
	 *
	 * @param   {Object|String}  model
	 * @param   {String}         host_type
	 * @param   {Object}         host
	 * @returns {Promise}
	 */
	configure: (model, host_type, host) => {
		let combined_meta = {};
		// Whether the working conf was saved to <conf>.bak before regenerating. If the
		// new conf fails `nginx -t` (or rendering), the previous one is put back so
		// the host keeps serving instead of disappearing on the next reload.
		let hadBackup = false;
		// nginx -t output when the new conf was rejected and the previous one restored.
		let rejectedOutput = null;

		const restorePrevious = () => {
			if (!hadBackup) return Promise.resolve(false);
			return internalNginx.restoreConfigBackup(host_type, host);
		};

		return internalNginx
			.test()
			.then(() => {
				// Run the safety gates BEFORE the working config is touched: a
				// rejected value used to leave the host without a conf file (and
				// still flagged online) until the next reload dropped it.
				internalNginx.assertSafeHostFields(host_type, host);
			})
			.then(() => internalNginx.backupConfig(host_type, host))
			.then((saved) => {
				hadBackup = saved;
				// Nginx is OK
				// We're deleting this config regardless (the working copy is in .bak).
				// Don't throw errors, as the file may not exist at all
				// Delete the .err file too
				return internalNginx.deleteConfig(host_type, host, true);
			})
			.then(() => {
				return internalNginx.generateConfig(host_type, host).catch((err) =>
					// Rendering failed after the delete — put the working conf back.
					internalNginx
						.deleteConfig(host_type, host)
						.then(restorePrevious)
						.then(() => {
							throw err;
						}),
				);
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

						return model
							.query()
							.where("id", host.id)
							.patch({
								meta: combined_meta,
							})
							.then(() => internalNginx.dropConfigBackup(host_type, host));
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

						// Keep the rejected conf as .err for debugging and take it out of
						// the live set; then put the previous working conf back (if any).
						return internalNginx
							.renameConfigAsError(host_type, host)
							.then(() => internalNginx.deleteConfig(host_type, host))
							.then(restorePrevious)
							.then((restored) => {
								if (restored) rejectedOutput = valid_lines.join("\n");
								combined_meta = _.assign(
									{},
									host.meta,
									restored
										? {
												// The previous conf is live again — the host stays online,
												// but the saved changes are NOT active.
												nginx_online: true,
												nginx_err: `New config rejected by nginx -t; the previous config is still active:\n${valid_lines.join("\n")}`,
											}
										: {
												nginx_online: false,
												nginx_err: valid_lines.join("\n"),
											},
								);
								return model.query().where("id", host.id).patch({
									meta: combined_meta,
								});
							});
					});
			})
			.then(() => {
				return internalNginx.reload();
			})
			.then(() => {
				if (rejectedOutput !== null) {
					// The DB already holds the new values; tell the admin they are
					// not live so they can fix them and save again.
					throw new errs.ValidationError(
						`nginx rejected the new configuration, so the changes are not active; the previous configuration is still being served. Fix the settings and save again.\n${rejectedOutput}`,
					);
				}
				return combined_meta;
			});
	},

	/**
	 * Copy the current conf of a host to <conf>.bak (not matched by the *.conf
	 * include). Resolves true when a working conf existed and was saved.
	 *
	 * @param   {String}  host_type
	 * @param   {Object}  host
	 * @returns {Promise<boolean>}
	 */
	backupConfig: (host_type, host) => {
		const config_file = internalNginx.getConfigName(internalNginx.getFileFriendlyHostType(host_type), host.id);
		return new Promise((resolve, reject) => {
			if (!fs.existsSync(config_file)) {
				// Taken out of the live set by stashConfig() (certificate issuance):
				// that stashed conf is the working one to fall back to.
				if (fs.existsSync(`${config_file}.disabled`)) {
					fs.rename(`${config_file}.disabled`, `${config_file}.bak`, (err) => (err ? reject(err) : resolve(true)));
					return;
				}
				resolve(false);
				return;
			}
			fs.copyFile(config_file, `${config_file}.bak`, (err) => (err ? reject(err) : resolve(true)));
		});
	},

	/**
	 * Take the conf of a host out of the live set WITHOUT losing it: it is moved
	 * to <conf>.disabled (not matched by the *.conf include). The next
	 * backupConfig() (configure / bulkGenerateConfigs) picks it up as the
	 * working conf to restore if the regenerated one is rejected.
	 *
	 * @param   {String}  host_type
	 * @param   {Object}  host
	 * @returns {Promise}
	 */
	stashConfig: (host_type, host) => {
		const config_file = internalNginx.getConfigName(internalNginx.getFileFriendlyHostType(host_type), host.id);
		return new Promise((resolve) => {
			if (!fs.existsSync(config_file)) {
				resolve(false);
				return;
			}
			fs.rename(config_file, `${config_file}.disabled`, (err) => {
				if (err) logger.error(`Could not stash ${config_file}: ${err.message}`);
				resolve(!err);
			});
		});
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Array}   hosts
	 * @returns {Promise}
	 */
	bulkStashConfigs: async (host_type, hosts) => {
		for (const host of Array.isArray(hosts) ? hosts : []) {
			await internalNginx.stashConfig(host_type, host);
		}
	},

	/**
	 * Move <conf>.bak back into place. Resolves true when it was restored.
	 *
	 * @param   {String}  host_type
	 * @param   {Object}  host
	 * @returns {Promise<boolean>}
	 */
	restoreConfigBackup: (host_type, host) => {
		const config_file = internalNginx.getConfigName(internalNginx.getFileFriendlyHostType(host_type), host.id);
		return new Promise((resolve) => {
			fs.rename(`${config_file}.bak`, config_file, (err) => {
				if (err) logger.error(`Could not restore ${config_file}.bak: ${err.message}`);
				resolve(!err);
			});
		});
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Object}  host
	 * @returns {Promise}
	 */
	dropConfigBackup: (host_type, host) => {
		const config_file = internalNginx.getConfigName(internalNginx.getFileFriendlyHostType(host_type), host.id);
		internalNginx.deleteFile(`${config_file}.bak`);
		return Promise.resolve();
	},

	/**
	 * @returns {Promise}
	 */
	test: () => {
		debug(logger, "Testing Nginx configuration");
		return utils.execFile("/usr/sbin/nginx", ["-t", "-g", "error_log off;"], { timeout: NGINX_TEST_TIMEOUT_MS });
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

					// path is rendered UNQUOTED as `location {{ path }} {`.
					assertSafeLocationPath(locationCopy.path);

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
				// A conf stashed for certificate issuance must not come back later.
				if (fs.existsSync(`${config_file}.disabled`)) internalNginx.deleteFile(`${config_file}.disabled`);
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
	 * Regenerate the confs of several hosts straight from their DB rows
	 * (access-list and certificate changes) without letting a bad row take the
	 * others down.
	 *
	 * A row can hold settings that nginx -t rejected earlier (configure() put
	 * the previous conf back but the DB keeps the new values). So: back up,
	 * generate all, test. If nginx -t fails, isolate the offending host(s): put
	 * every touched conf back, then regenerate one host at a time and keep each
	 * new conf that passes. A rejected conf is kept as <conf>.err, the host gets
	 * its previous conf back if it had one (otherwise it has no conf and is
	 * offline), its meta is updated, and the call rejects naming those hosts.
	 * The confs that passed stay in place and are reloaded.
	 *
	 * @param   {String}  hostType
	 * @param   {Array}   hosts
	 * @returns {Promise<Array>}
	 */
	bulkGenerateConfigs: async (hostType, hosts) => {
		const list = Array.isArray(hosts) ? hosts : [];
		if (!list.length) return [];
		const confOf = (host) =>
			internalNginx.getConfigName(internalNginx.getFileFriendlyHostType(hostType), host.id);
		const cleanOutput = (err) =>
			String(err?.message || err)
				.split("\n")
				.filter((line) => line.indexOf("/var/log/nginx/error.log") === -1)
				.join("\n");

		const backups = [];
		for (const host of list) {
			backups.push(await internalNginx.backupConfig(hostType, host));
		}
		// Put the pre-call state of host i back in the live set, keeping the .bak.
		const putBack = async (i) => {
			const conf = confOf(list[i]);
			if (backups[i]) {
				fs.copyFileSync(`${conf}.bak`, conf);
			} else {
				await internalNginx.deleteConfig(hostType, list[i]);
			}
		};
		const dropBackups = async () => {
			for (const [i, host] of list.entries()) {
				if (backups[i]) await internalNginx.dropConfigBackup(hostType, host);
			}
		};

		let firstOutput;
		try {
			await Promise.all(list.map((host) => internalNginx.generateConfig(hostType, host)));
			await internalNginx.test();
			await dropBackups();
			await internalNginx.clearHostErrors(hostType, list);
			return list;
		} catch (err) {
			firstOutput = cleanOutput(err);
		}

		// Something in the batch (or elsewhere) breaks nginx -t. Back to the
		// state before this call, then check that state is valid on its own.
		for (const i of list.keys()) await putBack(i);
		try {
			await internalNginx.test();
		} catch (baseErr) {
			await dropBackups();
			const output = cleanOutput(baseErr);
			logger.error(`Regenerating ${hostType} configs: nginx -t already fails without them: ${output}`);
			throw new errs.ValidationError(
				`nginx -t fails even with the previous ${hostType} configuration, so none of the regenerated configs were applied (the previous ones are still in place). Fix the nginx configuration first.\n${output}`,
				baseErr,
			);
		}

		const accepted = [];
		const rejected = [];
		for (const [i, host] of list.entries()) {
			try {
				await internalNginx.generateConfig(hostType, host);
				await internalNginx.test();
				accepted.push(host);
			} catch (err) {
				await internalNginx.renameConfigAsError(hostType, host);
				await putBack(i);
				rejected.push({ host, kept: backups[i], output: cleanOutput(err) });
			}
		}
		await dropBackups();
		await internalNginx.clearHostErrors(hostType, accepted);
		try {
			await internalNginx.markHostsRejected(hostType, rejected);
		} catch (err) {
			logger.error(`Could not record the rejected ${hostType} configs: ${err.message}`);
		}
		if (!rejected.length) {
			// The batch failed only together (should not happen); every conf passed
			// on its own and the combined state passed the last test.
			return list;
		}
		// The accepted confs are valid; make them live now instead of leaving
		// them for whatever reload comes next.
		try {
			await internalNginx.reload();
		} catch (err) {
			logger.error(`Reload after regenerating ${hostType} configs failed: ${err.message}`);
		}
		const lines = rejected.map(
			(r) =>
				`- ${hostType} #${r.host.id}: ${
					r.kept
						? "rejected, its previous configuration is still active"
						: "rejected and it had no previous configuration, so it is OFFLINE until it is fixed and saved again"
				}`,
		);
		logger.error(`Regenerating ${hostType} configs: ${rejected.length} rejected by nginx -t:\n${lines.join("\n")}\n${firstOutput}`);
		throw new errs.ValidationError(
			`nginx rejected the regenerated configuration of ${rejected.length} ${hostType}(s); the other hosts were updated. Fix the settings of these hosts and save them again:\n${lines.join("\n")}\n${rejected.map((r) => r.output).join("\n")}`,
		);
	},

	/**
	 * Load the model for a host type lazily (keeps nginx.js free of DB imports).
	 *
	 * @param   {String}  hostType
	 * @returns {Promise<Object|null>}
	 */
	hostModel: async (hostType) => {
		const file = {
			proxy_host: "../models/proxy_host.js",
			redirection_host: "../models/redirection_host.js",
			dead_host: "../models/dead_host.js",
			stream: "../models/stream.js",
		}[internalNginx.getFileFriendlyHostType(hostType)];
		if (!file) return null;
		return (await import(file)).default;
	},

	/**
	 * Record on each host that its regenerated conf was rejected by nginx -t.
	 *
	 * @param   {String}  hostType
	 * @param   {Array<{host: Object, kept: boolean, output: string}>}  rejected
	 */
	markHostsRejected: async (hostType, rejected) => {
		if (!rejected?.length) return;
		const model = await internalNginx.hostModel(hostType);
		if (!model) return;
		for (const r of rejected) {
			const meta = _.assign(
				{},
				r.host.meta || {},
				r.kept
					? {
							nginx_online: true,
							nginx_err: `Regenerated config rejected by nginx -t; the previous config is still active:\n${r.output}`,
						}
					: { nginx_online: false, nginx_err: r.output },
			);
			await model.query().where("id", r.host.id).patch({ meta });
		}
	},

	/**
	 * Clear a stale nginx_err on hosts whose regenerated conf passed nginx -t.
	 *
	 * @param   {String}  hostType
	 * @param   {Array}   hosts
	 */
	clearHostErrors: async (hostType, hosts) => {
		const stale = (hosts || []).filter(
			(h) => h && h.enabled !== false && h.enabled !== 0 && (h.meta?.nginx_err || h.meta?.nginx_online === false),
		);
		if (!stale.length) return;
		try {
			const model = await internalNginx.hostModel(hostType);
			if (!model) return;
			for (const host of stale) {
				await model
					.query()
					.where("id", host.id)
					.patch({ meta: _.assign({}, host.meta, { nginx_online: true, nginx_err: null }) });
			}
		} catch (err) {
			logger.error(`Could not clear nginx_err on ${hostType}: ${err.message}`);
		}
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

// Every function that writes, renames or deletes a conf runs under the lock too
// (re-entrant, so configure()'s own calls just pass through): a disable/delete
// of a host, a certificate's Let's Encrypt request conf or the default-site
// conf (setting.js) can no longer interleave with configure()'s
// backup -> generate -> test -> drop-.bak sequence of the same host.
for (const name of [
	"configure",
	"bulkGenerateConfigs",
	"bulkStashConfigs",
	"bulkDeleteConfigs",
	"stashConfig",
	"backupConfig",
	"restoreConfigBackup",
	"dropConfigBackup",
	"deleteConfig",
	"renameConfigAsError",
	"generateConfig",
	"generateLetsEncryptRequestConfig",
	"deleteLetsEncryptRequestConfig",
	"test",
	"reload",
]) {
	const impl = internalNginx[name];
	internalNginx[name] = (...args) => withConfigLock(() => impl(...args));
}

export default internalNginx;

// Exported for unit testing only
export const _testExports = {
	assertSafeAdvancedConfig,
	assertSafeLocationPath,
	tokenizeNginxStatements,
	assertSafeForwardField,
	withConfigLock,
};
