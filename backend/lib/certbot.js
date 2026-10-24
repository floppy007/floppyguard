import batchflow from "batchflow";
import dnsPlugins from "../certbot/dns-plugins.json" with { type: "json" };
import { certbot as logger } from "../logger.js";
import errs from "./error.js";
import utils from "./utils.js";

const CERTBOT_VERSION_REPLACEMENT = "$(certbot --version | grep -Eo '[0-9](\\.[0-9]+)+')";

/**
 * Quotes one pip argument for /bin/sh. Literal text is single-quoted, so a
 * version spec like `>=0.1.0` can never become a shell redirect; only the
 * {{certbot-version}} placeholder stays a (double-quoted) command substitution.
 *
 * @param   {string} arg
 * @returns {string}
 */
const shellQuotePipArg = (arg) =>
	arg
		.split("{{certbot-version}}")
		.map((part) => (part === "" ? "" : `'${part.replace(/'/g, "'\\''")}'`))
		.join(`"${CERTBOT_VERSION_REPLACEMENT}"`);

/**
 * Builds the shell command installing a plugin into the certbot venv.
 *
 * @param   {Object} plugin  entry of ../certbot/dns-plugins.json
 * @returns {string}
 */
const buildPipInstallCommand = (plugin) => {
	const pipArgs = [
		...plugin.dependencies.split(/\s+/).filter(Boolean),
		`${plugin.package_name}${plugin.version}`,
	].map(shellQuotePipArg);
	return `. /opt/certbot/bin/activate && pip install --no-cache-dir ${pipArgs.join(" ")} && deactivate`;
};

/**
 * Installs a cerbot plugin given the key for the object from
 * ../certbot/dns-plugins.json
 *
 * @param   {string}  pluginKey
 * @returns {Object}
 */
const installPlugin = async (pluginKey) => {
	if (typeof dnsPlugins[pluginKey] === "undefined") {
		// throw Error(`Certbot plugin ${pluginKey} not found`);
		throw new errs.ItemNotFoundError(pluginKey);
	}

	const plugin = dnsPlugins[pluginKey];
	logger.start(`Installing ${pluginKey}...`);

	// SETUPTOOLS_USE_DISTUTILS=local: Python 3.12+ (the certbot venv runs 3.13)
	// has no stdlib distutils anymore, so "stdlib" breaks source builds.
	let env = Object.assign({}, process.env, { SETUPTOOLS_USE_DISTUTILS: "local" });
	if (typeof plugin.env === "object") {
		env = Object.assign(env, plugin.env);
	}

	return utils
		.exec(buildPipInstallCommand(plugin), { env })
		.then((result) => {
			logger.complete(`Installed ${pluginKey}`);
			return result;
		})
		.catch((err) => {
			throw err;
		});
};

/**
 * @param {array} pluginKeys
 */
const installPlugins = async (pluginKeys) => {
	let hasErrors = false;

	return new Promise((resolve, reject) => {
		if (pluginKeys.length === 0) {
			resolve();
			return;
		}

		batchflow(pluginKeys)
			.sequential()
			.each((_i, pluginKey, next) => {
				installPlugin(pluginKey)
					.then(() => {
						next();
					})
					.catch((err) => {
						hasErrors = true;
						next(err);
					});
			})
			.error((err) => {
				logger.error(err.message);
			})
			.end(() => {
				if (hasErrors) {
					reject(new errs.CommandError("Some plugins failed to install. Please check the logs above", 1));
				} else {
					resolve();
				}
			});
	});
};

export { buildPipInstallCommand, installPlugin, installPlugins };
