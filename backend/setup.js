import { access, copyFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { removeStaleCredentialsFiles } from "./internal/certificate.js";
import { installPlugins } from "./lib/certbot.js";
import utils from "./lib/utils.js";
import { setup as logger } from "./logger.js";
import authModel from "./models/auth.js";
import certificateModel from "./models/certificate.js";
import settingModel from "./models/setting.js";
import userModel from "./models/user.js";
import userPermissionModel from "./models/user_permission.js";

export const isSetup = async () => {
	const row = await userModel.query().select("id").where("is_deleted", 0).first();
	return row?.id > 0;
};

/**
 * Creates a default admin users if one doesn't already exist in the database
 *
 * @returns {Promise}
 */
const setupDefaultUser = async () => {
	const initialAdminEmail = process.env.INITIAL_ADMIN_EMAIL;
	const initialAdminPassword = process.env.INITIAL_ADMIN_PASSWORD;

	// This will only create a new user when there are no active users in the database
	// and the INITIAL_ADMIN_EMAIL and INITIAL_ADMIN_PASSWORD environment variables are set.
	// Otherwise, users should be shown the setup wizard in the frontend.
	// I'm keeping this legacy behavior in case some people are automating deployments.

	if (!initialAdminEmail || !initialAdminPassword) {
		return Promise.resolve();
	}

	const userIsetup = await isSetup();
	if (!userIsetup) {
		// Create a new user and set password
		logger.info(`Creating initial admin user ${initialAdminEmail}`);

		const data = {
			is_deleted: 0,
			email: initialAdminEmail.toLowerCase().trim(),
			name: "Administrator",
			nickname: "Admin",
			avatar: "",
			roles: ["admin"],
		};

		const user = await userModel.query().insertAndFetch(data);

		await authModel.query().insert({
			user_id: user.id,
			type: "password",
			secret: initialAdminPassword,
			meta: {},
		});

		await userPermissionModel.insertDefaults(user.id, true);
		logger.info("Initial admin setup completed");
	}
};

/**
 * Creates default settings if they don't already exist in the database
 *
 * @returns {Promise}
 */
const setupDefaultSettings = async () => {
	const row = await settingModel.query().select("id").where({ id: "default-site" }).first();

	if (!row?.id) {
		await settingModel.query().insert({
			id: "default-site",
			name: "Default Site",
			description: "What to show when Nginx is hit with an unknown Host",
			value: "congratulations",
			meta: {},
		});
		logger.info("Default settings added");
	}
};

/**
 * Installs all Certbot plugins which are required for an installed certificate
 *
 * @returns {Promise}
 */
const setupCertbotPlugins = async () => {
	// Preview/staging can skip plugin bootstrap because those environments may
	// mount live cert paths without a full local certbot installation.
	if (process.env.SKIP_CERTBOT_PLUGIN_SETUP === "true") {
		logger.info("Skipping Certbot plugin setup");
		return;
	}

	const certificates = await certificateModel.query().where("is_deleted", 0).andWhere("provider", "letsencrypt");

	if (certificates?.length) {
		const plugins = [];

		certificates.map((certificate) => {
			if (certificate.meta && certificate.meta.dns_challenge === true) {
				if (plugins.indexOf(certificate.meta.dns_provider) === -1) {
					plugins.push(certificate.meta.dns_provider);
				}
			}
			return true;
		});

		await installPlugins(plugins);

		if (plugins.length) {
			logger.info(`Added Certbot plugins ${plugins.join(", ")}`);
		}
	}
};

/**
 * DNS provider credentials are only written for the duration of a certbot run
 * (internal/certificate.js). Older versions rewrote every credentials-<id> file
 * at start and left them on disk: remove those, unless one is the only copy.
 */
const removeStaleDnsCredentials = async () => {
	try {
		const removed = await removeStaleCredentialsFiles();
		if (removed) {
			logger.info(`Removed ${removed} stale DNS credentials file(s)`);
		}
	} catch (err) {
		logger.warn(`Could not remove stale DNS credentials files: ${err.message}`);
	}
};

const LOGROTATE_CONFIG_PATH = "/etc/logrotate.d/floppyguard";
const LOGROTATE_CONFIG_SOURCE = join(dirname(fileURLToPath(import.meta.url)), "config", "logrotate.d", "floppyguard");

/**
 * Installs the bundled logrotate config to /etc/logrotate.d on first run.
 * Without it, logrotate warns "cannot stat .../floppyguard" on every tick and
 * the per-host nginx logs in /data/logs never rotate.
 * @returns {Promise}
 */
const ensureLogrotateConfig = async () => {
	try {
		await access(LOGROTATE_CONFIG_PATH);
	} catch {
		try {
			await copyFile(LOGROTATE_CONFIG_SOURCE, LOGROTATE_CONFIG_PATH);
			logger.info(`Installed logrotate config at ${LOGROTATE_CONFIG_PATH}`);
		} catch (e) {
			logger.warn(`Could not install logrotate config: ${e.message}`);
		}
	}
};

/**
 * Starts a timer to call run the logrotation binary every two days
 * @returns {Promise}
 */
const setupLogrotation = () => {
	const intervalTimeout = 1000 * 60 * 60 * 24 * 2; // 2 days

	const runLogrotate = async () => {
		try {
			await ensureLogrotateConfig();
			await utils.execFile("logrotate", [LOGROTATE_CONFIG_PATH]);
			logger.info("Logrotate completed.");
		} catch (e) {
			logger.warn(e);
		}
	};

	logger.info("Logrotate Timer initialized");
	setInterval(runLogrotate, intervalTimeout);
	// And do this now as well
	return runLogrotate();
};

export default () =>
	setupDefaultUser()
		.then(setupDefaultSettings)
		.then(removeStaleDnsCredentials)
		.then(setupCertbotPlugins)
		.then(setupLogrotation);
