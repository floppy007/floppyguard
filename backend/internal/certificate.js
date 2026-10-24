import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "path";
import { ZipArchive } from "archiver";
import _ from "lodash";
import moment from "moment";
import { ProxyAgent } from "proxy-agent";
import tempWrite from "temp-write";
import dnsPlugins from "../certbot/dns-plugins.json" with { type: "json" };
import { installPlugin } from "../lib/certbot.js";
import { useLetsencryptServer, useLetsencryptStaging } from "../lib/config.js";
import error from "../lib/error.js";
import { credentialsFileContent, normalizeRoute53Credentials } from "../lib/route53-credentials.js";
import utils from "../lib/utils.js";
import { debug, ssl as logger } from "../logger.js";
import certificateModel from "../models/certificate.js";
import tokenModel from "../models/token.js";
import userModel from "../models/user.js";
import internalAuditLog from "./audit-log.js";
import internalHost from "./host.js";
import internalNginx from "./nginx.js";

const letsencryptConfig = "/etc/letsencrypt/cli.ini";
const certbotCommand = "/opt/certbot/bin/certbot";
const certbotLogsDir = "/data/logs";
const certbotWorkDir = "/tmp/letsencrypt-lib";
// Preview/staging can point at imported live certificate trees instead of the
// upstream fixed container paths.
const letsencryptRoot = process.env.NPM_LETSENCRYPT_ROOT || "/etc/letsencrypt";
// certbot runs without --config-dir, so it reads its renewal confs from its
// default dir — which on the hub is NOT letsencryptRoot (live/ and archive/ are
// symlinks into it, renewal/ is a separate real directory).
const certbotConfigDir = process.env.NPM_CERTBOT_CONFIG_DIR || path.dirname(letsencryptConfig);
const customSslRoot = process.env.NPM_CUSTOM_SSL_ROOT || "/data/custom_ssl";

const omissions = () => {
	return ["is_deleted", "owner.is_deleted", "meta.dns_provider_credentials"];
};

/**
 * Route53-Zugangsdaten vor dem Speichern prüfen und normalisieren.
 * @param {Object} meta
 */
const checkDnsCredentials = (meta) => {
	if (meta?.dns_provider === "route53" && meta.dns_provider_credentials !== undefined) {
		try {
			meta.dns_provider_credentials = normalizeRoute53Credentials(meta.dns_provider_credentials);
		} catch (err) {
			throw new error.ValidationError(err.message);
		}
	}
};

/**
 * Zugangsdaten-Datei schreiben; route53 nur in geprüfter Form.
 */
let credentialsTmpSeq = 0;
const writeCredentialsFile = (location, provider, credentials) => {
	let content;
	try {
		content = credentialsFileContent(provider, credentials);
	} catch (err) {
		throw new error.ValidationError(err.message);
	}
	// Write to a temp file and rename: a concurrent certbot run of the same
	// certificate never reads a half-written file, and an old file with looser
	// permissions is replaced instead of keeping its mode.
	const tmp = `${location}.${process.pid}.${++credentialsTmpSeq}.tmp`;
	try {
		fs.writeFileSync(tmp, content, { mode: 0o600 });
		fs.chmodSync(tmp, 0o600);
		fs.renameSync(tmp, location);
	} catch (err) {
		fs.rmSync(tmp, { force: true });
		throw err;
	}
};

/**
 * Builds the certbot `certonly` argument list shared by request and renewal,
 * HTTP and DNS challenge. Previously hand-built in four places, so every fix
 * (key_type, route53 env, duckdns flag) had to be applied four times.
 *
 * @param   {Object}  certificate
 * @param   {Object}  options
 * @param   {Boolean} [options.renew]                adds --force-renewal
 * @param   {String}  [options.email]                adds -m <email> (request only)
 * @param   {String}  options.challenge              "http" | "dns"
 * @param   {Object}  [options.dnsPlugin]            entry of dns-plugins.json (dns only)
 * @param   {String}  [options.credentialsLocation]  credentials file (dns only)
 * @returns {{args: Array<String>, opts: Object}}
 */
const buildCertbotArgs = (
	certificate,
	{ renew = false, email = null, challenge, dnsPlugin = null, credentialsLocation = null },
) => {
	const args = ["certonly"];
	if (renew) {
		args.push("--force-renewal");
	}
	args.push(
		"--config",
		letsencryptConfig,
		"--work-dir",
		certbotWorkDir,
		"--logs-dir",
		certbotLogsDir,
		"--cert-name",
		`npm-${certificate.id}`,
		"--agree-tos",
	);
	if (challenge === "http") {
		args.push(
			"--authenticator",
			"webroot",
			"--webroot-path",
			"/data/letsencrypt-acme-challenge",
			"--non-interactive",
		);
	}
	if (email) {
		args.push("-m", email);
	}
	args.push("--preferred-challenges", challenge, "--domains", certificate.domain_names.join(","));

	if (challenge === "dns") {
		args.push(`--${dnsPlugin.full_plugin_name}`);
		// Whether the plugin has a --<name>-credentials argument
		if (certificate.meta.dns_provider !== "route53") {
			args.push(`--${dnsPlugin.full_plugin_name}-credentials`, credentialsLocation);
		}
		if (certificate.meta.propagation_seconds !== undefined) {
			args.push(
				`--${dnsPlugin.full_plugin_name}-propagation-seconds`,
				certificate.meta.propagation_seconds.toString(),
			);
		}
	}

	// Add key-type parameter if specified
	if (certificate.meta?.key_type) {
		args.push("--key-type", certificate.meta.key_type);
	}

	// dns_provider only for the DNS challenge: a webroot run must never get the
	// duckdns flag or the route53 AWS env.
	const adds = internalCertificate.getAdditionalCertbotArgs(
		certificate.id,
		challenge === "dns" ? certificate.meta.dns_provider : undefined,
		credentialsLocation,
	);
	args.push(...adds.args);

	logger.info(`Command: ${certbotCommand} ${args.join(" ")}`);
	return { args, opts: adds.opts };
};

// Credentials dirs certbot may reference: FloppyGuard's own root and certbot's
// config dir (upstream default /etc/letsencrypt). A renewal conf pointing
// anywhere else is ignored (the file is written from user-controlled DB content).
const credentialsDirs = () => [...new Set([letsencryptRoot, certbotConfigDir].map((d) => `${d}/credentials`))];

/**
 * Where certbot expects the credentials of certificate <id>: the path its
 * renewal conf (renewal/npm-<id>.conf -> dns_*_credentials) references when
 * that is one of the known credentials dirs, otherwise
 * <letsencryptRoot>/credentials/credentials-<id>.
 *
 * @param   {Number} certificateId
 * @returns {String}
 */
export const credentialsLocationFor = (certificateId) => {
	const fallback = `${letsencryptRoot}/credentials/credentials-${certificateId}`;
	const allowed = credentialsDirs().map((d) => `${d}/credentials-${certificateId}`);
	for (const dir of [...new Set([certbotConfigDir, letsencryptRoot])]) {
		let conf;
		try {
			conf = fs.readFileSync(`${dir}/renewal/npm-${certificateId}.conf`, "utf8");
		} catch {
			continue;
		}
		const match = /^\s*dns_[a-z0-9_]+_credentials\s*=\s*(\S+)\s*$/m.exec(conf);
		if (!match) {
			continue;
		}
		if (allowed.includes(match[1])) {
			return match[1];
		}
		logger.warn(
			`Renewal conf of npm-${certificateId} references credentials at ${match[1]}, using ${fallback} instead`,
		);
		return fallback;
	}
	return fallback;
};

// certificate id → number of certbot runs currently using its credentials file
const credentialsInUse = new Map();

/**
 * Runs one certbot call with the DNS provider credentials on disk: the file
 * (0600) is written right before and removed right after the run, so the
 * secrets only exist on disk while certbot needs them. Concurrent runs of the
 * same certificate share the file, the last one to finish removes it.
 *
 * @param   {Object}   certificate
 * @param   {String}   credentials        provider credentials (from the DB)
 * @param   {Function} run                async (credentialsLocation) => result
 * @returns {Promise}
 */
const withDnsCredentials = async (certificate, credentials, run) => {
	const id = Number(certificate.id);
	const location = credentialsLocationFor(id);
	credentialsInUse.set(id, (credentialsInUse.get(id) || 0) + 1);
	try {
		fs.mkdirSync(path.dirname(location), { recursive: true });
		writeCredentialsFile(location, certificate.meta.dns_provider, credentials);
		return await run(location);
	} finally {
		const left = credentialsInUse.get(id) - 1;
		if (left > 0) {
			credentialsInUse.set(id, left);
		} else {
			credentialsInUse.delete(id);
			fs.rmSync(location, { force: true });
		}
	}
};

/**
 * True when the on-disk credentials-<id> file is the only copy of the
 * certificate's DNS provider credentials: a DNS certificate whose DB row has
 * none stored. Upstream (#5814) keeps such legacy files, they are what keeps
 * the certificate renewable. A failed lookup counts as "keep".
 *
 * @param   {Number}  id
 * @returns {Promise<Boolean>}
 */
const credentialsOnlyOnDisk = async (id) => {
	try {
		const row = await certificateModel.query().findById(id);
		return Boolean(row && !row.is_deleted && row.meta?.dns_challenge && !row.meta?.dns_provider_credentials);
	} catch (err) {
		logger.warn(`Could not look up certificate #${id}, keeping its DNS credentials file: ${err.message}`);
		return true;
	}
};

/**
 * Removes credentials-<id> files left on disk by older versions, which wrote
 * them at every start and kept them, and credentials-<id>.<pid>.<seq>.tmp files
 * of a write interrupted before its rename. Files of a certbot run in progress
 * stay, and so does a legacy file that is the only copy of the credentials.
 *
 * @returns {Promise<Number>} the number of removed files
 */
export const removeStaleCredentialsFiles = async () => {
	let removed = 0;
	const onlyOnDisk = new Map();
	for (const dir of credentialsDirs()) {
		let entries;
		try {
			entries = fs.readdirSync(dir);
		} catch {
			continue;
		}
		for (const entry of entries) {
			const m = /^credentials-(\d+)(\.\d+\.\d+\.tmp)?$/.exec(entry);
			if (!m) {
				continue;
			}
			const id = Number(m[1]);
			if (!m[2]) {
				if (!onlyOnDisk.has(id)) {
					onlyOnDisk.set(id, await credentialsOnlyOnDisk(id));
				}
				if (onlyOnDisk.get(id)) {
					logger.warn(
						`Keeping ${dir}/${entry}: certificate #${id} has no DNS credentials stored, this file is the only copy`,
					);
					continue;
				}
			}
			// checked after the lookup: a certbot run may have started meanwhile
			if (credentialsInUse.has(id)) {
				continue;
			}
			try {
				fs.rmSync(`${dir}/${entry}`, { force: true });
				removed++;
			} catch (err) {
				logger.warn(`Could not remove stale DNS credentials ${dir}/${entry}: ${err.message}`);
			}
		}
	}
	return removed;
};

/**
 * Back-off after a failed automatic renewal: 2h, 4h, 8h, 16h, then daily. The
 * timer runs hourly; without a back-off a persistent failure (e.g. nginx -t
 * broken by another host) re-ran certbot --force-renewal every hour and burned
 * through the Let's Encrypt duplicate-certificate limit.
 */
export function renewalBackoffMs(failures) {
	const hour = 60 * 60 * 1000;
	return Math.min(24 * hour, hour * 2 ** Math.max(1, Math.min(failures, 5)));
}

const internalCertificate = {
	allowedSslFiles: ["certificate", "certificate_key", "intermediate_certificate"],
	intervalTimeout: 1000 * 60 * 60, // 1 hour
	interval: null,
	intervalProcessing: false,
	renewBeforeExpirationBy: [30, "days"],
	// certificate id → { failures, nextAttempt } (automatic renewals only)
	renewFailures: new Map(),
	// A renewal wrote the new cert (expires_on already updated) but nginx could
	// not be reloaded: nginx still serves the OLD certificate from memory and the
	// timer would never pick this cert again. Retried every timer tick until a
	// reload succeeds; reported by the health check (GET /api).
	reloadPending: false,

	/** Retry a pending nginx reload (see reloadPending). Never throws. */
	retryPendingReload: async () => {
		if (!internalCertificate.reloadPending) return;
		try {
			await internalNginx.reload();
			internalCertificate.reloadPending = false;
			logger.info("Pending nginx reload after a certificate renewal succeeded — renewed certificates are served now");
		} catch (err) {
			logger.error(
				`nginx reload after a certificate renewal still fails — nginx serves the old certificate(s): ${err.message}`,
			);
		}
	},

	initTimer: () => {
		logger.info("Let's Encrypt Renewal Timer initialized");
		// A renewal interrupted by a crash/restart leaves the only copy of the
		// still-valid certificate in its .renewal-backup-npm-<id> dir: put it back.
		internalCertificate.recoverAllStaleRenewalBackups();
		internalCertificate.interval = setInterval(
			internalCertificate.processExpiringHosts,
			internalCertificate.intervalTimeout,
		);
		// And do this now as well
		internalCertificate.processExpiringHosts();
	},

	/**
	 * Triggered by a timer, this will check for expiring hosts and renew their ssl certs if required
	 */
	processExpiringHosts: () => {
		if (!internalCertificate.intervalProcessing) {
			internalCertificate.intervalProcessing = true;
			internalCertificate.retryPendingReload();
			logger.info(
				`Renewing SSL certs expiring within ${internalCertificate.renewBeforeExpirationBy[0]} ${internalCertificate.renewBeforeExpirationBy[1]} ...`,
			);

			const expirationThreshold = moment()
				.add(internalCertificate.renewBeforeExpirationBy[0], internalCertificate.renewBeforeExpirationBy[1])
				.format("YYYY-MM-DD HH:mm:ss");

			// Fetch all the letsencrypt certs from the db that will expire within the configured threshold
			certificateModel
				.query()
				.where("is_deleted", 0)
				.andWhere("provider", "letsencrypt")
				.andWhere("expires_on", "<", expirationThreshold)
				.then((certificates) => {
					if (!certificates?.length) {
						return null;
					}

					/**
					 * Renews must be run sequentially or we'll get an error 'Another
					 * instance of Certbot is already running.'
					 */
					let sequence = Promise.resolve();

					certificates.forEach((certificate) => {
						const failed = internalCertificate.renewFailures.get(certificate.id);
						if (failed && Date.now() < failed.nextAttempt) {
							debug(
								logger,
								`Skipping renewal of certificate #${certificate.id} until ${new Date(failed.nextAttempt).toISOString()} (${failed.failures} failed attempt(s))`,
							);
							return;
						}
						sequence = sequence.then(() =>
							internalCertificate
								.renew(
									{
										can: () =>
											Promise.resolve({
												permission_visibility: "all",
											}),
										token: tokenModel(),
									},
									{ id: certificate.id },
								)
								.then(() => {
									internalCertificate.renewFailures.delete(certificate.id);
								})
								.catch((err) => {
									// Don't want to stop the train here, just log the error
									const failures =
										(internalCertificate.renewFailures.get(certificate.id)?.failures || 0) + 1;
									const nextAttempt = Date.now() + renewalBackoffMs(failures);
									internalCertificate.renewFailures.set(certificate.id, { failures, nextAttempt });
									logger.error(
										`Renewal of certificate #${certificate.id} failed (${failures}x), next attempt ${new Date(nextAttempt).toISOString()}: ${err.message}`,
									);
								}),
						);
					});

					return sequence;
				})
				.then(() => {
					logger.info("Completed SSL cert renew process");
					internalCertificate.intervalProcessing = false;
				})
				.catch((err) => {
					logger.error(err);
					internalCertificate.intervalProcessing = false;
				});
		}
	},

	/**
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @returns {Promise}
	 */
	create: async (access, data) => {
		await access.can("certificates:create", data);
		checkDnsCredentials(data.meta);
		data.owner_user_id = access.token.getUserId(1);

		if (data.provider === "letsencrypt") {
			data.nice_name = data.domain_names.join(", ");
		}

		// this command really should clean up and delete the cert if it can't fully succeed
		const certificate = await certificateModel.query().insertAndFetch(data);

		try {
			if (certificate.provider === "letsencrypt") {
				// Request a new Cert from LE. Let the fun begin.

				// HTTP challenge:
				// 1. Find out any hosts that are using any of the hostnames in this cert
				// 2. Disable them in nginx temporarily
				// 3. Generate the LE config
				// 4. Request cert
				// 5. Remove LE config
				// 6. Re-instate previously disabled hosts
				// DNS challenge: only 4.

				// Validate the user email before touching any nginx configs, so a
				// validation failure can't leave disabled hosts behind
				const user = await userModel.query().where("is_deleted", 0).andWhere("id", data.owner_user_id).first();
				if (!user?.email) {
					throw new error.ValidationError(
						"A valid email address must be set on your user account to use Let's Encrypt",
					);
				}

				// With DNS challenge certbot never touches nginx: no hosts need to be
				// disabled, no challenge config is written, and the new cert is not yet
				// referenced by any host, so no reload is needed either.
				if (certificate.meta?.dns_challenge) {
					// 4. Request cert
					await internalCertificate.requestLetsEncryptSslWithDnsChallenge(certificate, user.email);
				} else {
					// 1. Find out any hosts that are using any of the hostnames in this cert
					const inUseResult = await internalHost.getHostsWithDomains(certificate.domain_names);
					// 2. Disable them in nginx temporarily (port-80 server_name clash with letsencrypt-request.conf)
					await internalCertificate.disableInUseHosts(inUseResult);
					try {
						// 3. Generate the LE config
						await internalNginx.generateLetsEncryptRequestConfig(certificate);
						await internalNginx.reload();
						// Give nginx a moment to finish activating the challenge config
						await new Promise((resolve) => setTimeout(resolve, 5000));
						// 4. Request cert
						await internalCertificate.requestLetsEncryptSsl(certificate, user.email);
						// 5. Remove LE config
						await internalNginx.deleteLetsEncryptRequestConfig(certificate);
						// 6. Re-instate previously disabled hosts
						await internalCertificate.enableInUseHosts(inUseResult);
						// certbot succeeded: lineage npm-<id> is on disk. A failed reload here
						// must NOT reach the outer catch (which hard-deletes the row and orphans
						// the issued cert); the timer retries the reload (retryPendingReload).
						try {
							await internalNginx.reload();
							internalCertificate.reloadPending = false;
						} catch (reloadErr) {
							internalCertificate.reloadPending = true;
							logger.error(
								`Certificate #${certificate.id} issued, but nginx reload failed — the temporarily disabled hosts stay offline until the next successful reload (retried every timer run): ${reloadErr.message}`,
							);
						}
					} catch (err) {
						// In the event of failure, revert things and throw err back
						await internalNginx.deleteLetsEncryptRequestConfig(certificate);
						await internalCertificate.enableInUseHosts(inUseResult);
						await internalNginx.reload();
						throw err;
					}
				}

				// At this point, the letsencrypt cert should exist on disk.
			}
		} catch (err) {
			// certbot failed: nothing was issued, so the row never existed properly. Hard delete.
			await certificateModel.query().deleteById(certificate.id);
			throw err;
		}

		if (certificate.provider === "letsencrypt") {
			// certbot succeeded, lineage npm-<id> is on disk: from here on the row must
			// survive, otherwise the issued cert is orphaned (never revoked, re-issued on
			// retry, counts against the LE rate limit). If one of these steps fails the row
			// keeps its default expires_on (now), so the hourly renewal timer records the
			// real expiry on its next pass, or the user can trigger "renew" by hand.
			const certInfo = await internalCertificate.getCertificateInfoFromFile(
				`${internalCertificate.getLiveCertPath(certificate.id)}/fullchain.pem`,
			);
			const savedRow = await certificateModel
				.query()
				.patchAndFetchById(certificate.id, {
					expires_on: moment(certInfo.dates.to, "X").format("YYYY-MM-DD HH:mm:ss"),
				})
				.then(utils.omitRow(omissions()));

			// Add cert data for audit log
			savedRow.meta = _.assign({}, savedRow.meta, {
				letsencrypt_certificate: certInfo,
			});

			await internalCertificate.addCreatedAuditLog(access, certificate.id, savedRow);

			return savedRow;
		}

		data.meta = _.assign({}, data.meta || {}, certificate.meta);

		// Add to audit log
		await internalCertificate.addCreatedAuditLog(access, certificate.id, utils.omitRow(omissions())(data));

		return utils.omitRow(omissions())(certificate);
	},

	addCreatedAuditLog: async (access, certificate_id, meta) => {
		await internalAuditLog.add(access, {
			action: "created",
			object_type: "certificate",
			object_id: certificate_id,
			meta: meta,
		});
	},

	/**
	 * @param  {Access}  access
	 * @param  {Object}  data
	 * @param  {Number}  data.id
	 * @param  {String}  [data.email]
	 * @param  {String}  [data.name]
	 * @return {Promise}
	 */
	update: async (access, data) => {
		await access.can("certificates:update", data.id);
		checkDnsCredentials(data.meta);
		const row = await internalCertificate.get(access, { id: data.id });

		if (row.id !== data.id) {
			// Sanity check that something crazy hasn't happened
			throw new error.InternalValidationError(
				`Certificate could not be updated, IDs do not match: ${row.id} !== ${data.id}`,
			);
		}

		const savedRow = await certificateModel
			.query()
			.patchAndFetchById(row.id, data)
			.then(utils.omitRow(omissions()));

		savedRow.meta = internalCertificate.cleanMeta(savedRow.meta);
		data.meta = internalCertificate.cleanMeta(data.meta);

		// Add row.nice_name for custom certs
		if (savedRow.provider === "other") {
			data.nice_name = savedRow.nice_name;
		}

		// Add to audit log
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "certificate",
			object_id: row.id,
			meta: _.omit(data, ["expires_on"]), // this prevents json circular reference because expires_on might be raw
		});

		return savedRow;
	},

	/**
	 * @param  {Access}   access
	 * @param  {Object}   data
	 * @param  {Number}   data.id
	 * @param  {Array}    [data.expand]
	 * @param  {Array}    [data.omit]
	 * @return {Promise}
	 */
	get: async (access, data) => {
		const accessData = await access.can("certificates:get", data.id);
		const query = certificateModel
			.query()
			.where("is_deleted", 0)
			.andWhere("id", data.id)
			.allowGraph("[owner,proxy_hosts,redirection_hosts,dead_hosts,streams]")
			.first();

		if (accessData.permission_visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}

		if (typeof data.expand !== "undefined" && data.expand !== null) {
			query.withGraphFetched(`[${data.expand.join(", ")}]`);
		}

		const row = await query.then(utils.omitRow(omissions()));
		if (!row?.id) {
			throw new error.ItemNotFoundError(data.id);
		}
		// Custom omissions
		if (typeof data.omit !== "undefined" && data.omit !== null) {
			return _.omit(row, [...data.omit]);
		}

		return internalCertificate.cleanExpansions(row);
	},

	cleanExpansions: (row) => {
		if (typeof row.proxy_hosts !== "undefined") {
			row.proxy_hosts = utils.omitRows(["is_deleted"])(row.proxy_hosts);
		}
		if (typeof row.redirection_hosts !== "undefined") {
			row.redirection_hosts = utils.omitRows(["is_deleted"])(row.redirection_hosts);
		}
		if (typeof row.dead_hosts !== "undefined") {
			row.dead_hosts = utils.omitRows(["is_deleted"])(row.dead_hosts);
		}
		if (typeof row.streams !== "undefined") {
			row.streams = utils.omitRows(["is_deleted"])(row.streams);
		}
		return row;
	},

	/**
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @param   {Number}  data.id
	 * @returns {Promise}
	 */
	download: async (access, data) => {
		await access.can("certificates:get", data);
		const certificate = await internalCertificate.get(access, data);
		if (certificate.provider === "letsencrypt") {
			const zipDirectory = internalCertificate.getLiveCertPath(data.id);
			if (!fs.existsSync(zipDirectory)) {
				throw new error.ItemNotFoundError(`Certificate ${certificate.nice_name} does not exists`);
			}

			const certFiles = fs
				.readdirSync(zipDirectory)
				.filter((fn) => fn.endsWith(".pem"))
				.map((fn) => fs.realpathSync(path.join(zipDirectory, fn)));

			// Private 0700 temp dir: the zip holds the private key. The route
			// removes the whole dir once the download finished.
			const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "npm-cert-"));
			const opName = path.join(tmpDir, `npm-${data.id}-${Date.now()}.zip`);

			try {
				await internalCertificate.zipFiles(certFiles, opName);
			} catch (err) {
				fs.rmSync(tmpDir, { recursive: true, force: true });
				throw err;
			}
			debug(logger, "zip completed : ", opName);
			return {
				fileName: opName,
			};
		}
		throw new error.ValidationError("Only Let'sEncrypt certificates can be downloaded");
	},

	/**
	 * @param   {String}  source
	 * @param   {String}  out
	 * @returns {Promise}
	 */
	zipFiles: async (source, out) => {
		const archive = new ZipArchive({ zlib: { level: 9 } });
		const stream = fs.createWriteStream(out, { mode: 0o600 });

		return new Promise((resolve, reject) => {
			source.map((fl) => {
				const fileName = path.basename(fl);
				debug(logger, fl, "added to certificate zip");
				archive.file(fl, { name: fileName });
				return true;
			});
			archive.on("error", (err) => reject(err)).pipe(stream);
			stream.on("close", () => resolve());
			archive.finalize();
		});
	},

	/**
	 * @param {Access}  access
	 * @param {Object}  data
	 * @param {Number}  data.id
	 * @param {String}  [data.reason]
	 * @returns {Promise}
	 */
	delete: async (access, data) => {
		await access.can("certificates:delete", data.id);
		const row = await internalCertificate.get(access, { id: data.id });

		if (!row?.id) {
			throw new error.ItemNotFoundError(data.id);
		}

		// Refuse to delete a certificate that hosts still reference. Revoking it with
		// --delete-after-revoke would remove the files their nginx configs point at,
		// making `nginx -t` fail and blocking all subsequent config operations.
		const inUse = await certificateModel
			.query()
			.findById(row.id)
			.withGraphFetched("[proxy_hosts, redirection_hosts, dead_hosts, streams]");
		const inUseCount =
			(inUse?.proxy_hosts?.length || 0) +
			(inUse?.redirection_hosts?.length || 0) +
			(inUse?.dead_hosts?.length || 0) +
			(inUse?.streams?.length || 0);
		if (inUseCount > 0) {
			throw new error.ValidationError(
				`Certificate is still in use by ${inUseCount} host${inUseCount === 1 ? "" : "s"}. Remove it from those hosts before deleting it.`,
			);
		}

		await certificateModel.query().where("id", row.id).patch({
			is_deleted: 1,
		});

		// Add to audit log
		row.meta = internalCertificate.cleanMeta(row.meta);

		await internalAuditLog.add(access, {
			action: "deleted",
			object_type: "certificate",
			object_id: row.id,
			meta: _.omit(row, omissions()),
		});

		if (row.provider === "letsencrypt") {
			// Revoke the cert
			await internalCertificate.revokeLetsEncryptSsl(row);
		}
		return true;
	},

	/**
	 * All Certs
	 *
	 * @param   {Access}  access
	 * @param   {Array}   [expand]
	 * @param   {String}  [searchQuery]
	 * @returns {Promise}
	 */
	getAll: async (access, expand, searchQuery) => {
		const accessData = await access.can("certificates:list");

		const query = certificateModel
			.query()
			.where("is_deleted", 0)
			.groupBy("id")
			.allowGraph("[owner,proxy_hosts,redirection_hosts,dead_hosts,streams]")
			.orderBy("nice_name", "ASC");

		if (accessData.permission_visibility !== "all") {
			query.andWhere("owner_user_id", access.token.getUserId(1));
		}

		// Query is used for searching
		if (typeof searchQuery === "string") {
			query.where(function () {
				this.where("nice_name", "like", `%${searchQuery}%`);
			});
		}

		if (typeof expand !== "undefined" && expand !== null) {
			query.withGraphFetched(`[${expand.join(", ")}]`);
		}

		const r = await query.then(utils.omitRows(omissions()));
		for (let i = 0; i < r.length; i++) {
			r[i] = internalCertificate.cleanExpansions(r[i]);
		}
		return r;
	},

	/**
	 * Report use
	 *
	 * @param   {Number}  userId
	 * @param   {String}  visibility
	 * @returns {Promise}
	 */
	getCount: async (userId, visibility) => {
		const query = certificateModel.query().count("id as count").where("is_deleted", 0);

		if (visibility !== "all") {
			query.andWhere("owner_user_id", userId);
		}

		const row = await query.first();
		return Number.parseInt(row.count, 10);
	},

	/**
	 * @param   {Object} certificate
	 * @returns {Promise}
	 */
	writeCustomCert: async (certificate) => {
		logger.info("Writing Custom Certificate:", certificate);

		const dir = `${customSslRoot}/npm-${certificate.id}`;

		return new Promise((resolve, reject) => {
			if (certificate.provider === "letsencrypt") {
				reject(new Error("Refusing to write letsencrypt certs here"));
				return;
			}

			let certData = certificate.meta.certificate;
			if (typeof certificate.meta.intermediate_certificate !== "undefined") {
				certData = `${certData}\n${certificate.meta.intermediate_certificate}`;
			}

			try {
				fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
			} catch (err) {
				reject(err);
				return;
			}

			fs.writeFile(`${dir}/fullchain.pem`, certData, (err) => {
				if (err) {
					reject(err);
				} else {
					resolve();
				}
			});
		}).then(() => {
			return new Promise((resolve, reject) => {
				const keyFile = `${dir}/privkey.pem`;
				// mode only applies on create; chmod covers re-uploads into an existing npm-<id> dir
				fs.writeFile(keyFile, certificate.meta.certificate_key, { mode: 0o600 }, (err) => {
					if (err) {
						reject(err);
						return;
					}
					fs.chmod(keyFile, 0o600, (chmodErr) => (chmodErr ? reject(chmodErr) : resolve()));
				});
			});
		});
	},

	/**
	 * @param   {Access}   access
	 * @param   {Object}   data
	 * @param   {Array}    data.domain_names
	 * @returns {Promise}
	 */
	createQuickCertificate: async (access, data) => {
		return await internalCertificate.create(access, {
			provider: "letsencrypt",
			domain_names: data.domain_names,
			meta: data.meta,
		});
	},

	/**
	 * Validates that the certs provided are good.
	 * No access required here, nothing is changed or stored.
	 *
	 * @param   {Object}  data
	 * @param   {Object}  data.files
	 * @returns {Promise}
	 */
	validate: (data) => {
		// Put file contents into an object
		const files = {};
		_.map(data.files, (file, name) => {
			if (internalCertificate.allowedSslFiles.indexOf(name) !== -1) {
				files[name] = file.data.toString();
			}
		});

		// For each file, create a temp file and write the contents to it
		// Then test it depending on the file type
		const promises = [];
		_.map(files, (content, type) => {
			promises.push(
				new Promise((resolve) => {
					if (type === "certificate_key") {
						resolve(internalCertificate.checkPrivateKey(content));
					} else {
						// this should handle `certificate` and intermediate certificate
						resolve(internalCertificate.getCertificateInfo(content, true));
					}
				}).then((res) => {
					return { [type]: res };
				}),
			);
		});

		return Promise.all(promises).then((files) => {
			let data = {};
			_.each(files, (file) => {
				data = _.assign({}, data, file);
			});
			return data;
		});
	},

	/**
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @param   {Number}  data.id
	 * @param   {Object}  data.files
	 * @returns {Promise}
	 */
	upload: async (access, data) => {
		const row = await internalCertificate.get(access, { id: data.id });
		if (row.provider !== "other") {
			throw new error.ValidationError("Cannot upload certificates for this type of provider");
		}

		const validations = await internalCertificate.validate(data);
		if (typeof validations.certificate === "undefined") {
			throw new error.ValidationError("Certificate file was not provided");
		}
		// A certificate-only re-upload is fine once a key is stored; without one
		// writeCustomCert() would crash after the DB row was already updated.
		if (typeof validations.certificate_key === "undefined" && !row.meta?.certificate_key) {
			throw new error.ValidationError("Certificate key file was not provided");
		}

		_.map(data.files, (file, name) => {
			if (internalCertificate.allowedSslFiles.indexOf(name) !== -1) {
				row.meta[name] = file.data.toString();
			}
		});

		const certificate = await internalCertificate.update(access, {
			id: data.id,
			expires_on: moment(validations.certificate.dates.to, "X").format("YYYY-MM-DD HH:mm:ss"),
			domain_names: validations.certificate.cn ? [validations.certificate.cn] : row.domain_names,
			meta: _.clone(row.meta), // Prevent the update method from changing this value that we'll use later
		});

		certificate.meta = row.meta;
		await internalCertificate.writeCustomCert(certificate);
		return _.pick(row.meta, internalCertificate.allowedSslFiles);
	},

	/**
	 * Uses the openssl command to validate the private key.
	 * It will save the file to disk first, then run commands on it, then delete the file.
	 *
	 * @param {String}  privateKey    This is the entire key contents as a string
	 */
	checkPrivateKey: async (privateKey) => {
		const filepath = await tempWrite(privateKey);

		try {
			// A passphrase-protected key makes openssl block waiting for input on
			// stdin, so kill the child and reject after 10s instead of hanging.
			const result = await utils.execFile("openssl", ["pkey", "-in", filepath, "-check", "-noout"], {
				timeout: 10000,
				killSignal: "SIGKILL",
			});
			if (!result.toLowerCase().includes("key is valid")) {
				throw new error.ValidationError(`Result Validation Error: ${result}`);
			}
			fs.unlinkSync(filepath);
			return true;
		} catch (err) {
			fs.unlinkSync(filepath);
			if (err?.previous?.killed) {
				throw new error.ValidationError(
					"Result Validation Error: Validation timed out. This could be due to the key being passphrase-protected.",
					err,
				);
			}
			throw new error.ValidationError(`Certificate Key is not valid (${err.message})`, err);
		}
	},

	/**
	 * Uses the openssl command to both validate and get info out of the certificate.
	 * It will save the file to disk first, then run commands on it, then delete the file.
	 *
	 * @param {String}  certificate      This is the entire cert contents as a string
	 * @param {Boolean} [throwExpired]  Throw when the certificate is out of date
	 */
	getCertificateInfo: async (certificate, throwExpired) => {
		const filepath = await tempWrite(certificate);
		try {
			const certData = await internalCertificate.getCertificateInfoFromFile(filepath, throwExpired);
			fs.unlinkSync(filepath);
			return certData;
		} catch (err) {
			fs.unlinkSync(filepath);
			throw err;
		}
	},

	/**
	 * Uses the openssl command to both validate and get info out of the certificate.
	 * It will save the file to disk first, then run commands on it, then delete the file.
	 *
	 * @param {String}  certificateFile The file location on disk
	 * @param {Boolean} [throw_expired]  Throw when the certificate is out of date
	 */
	getCertificateInfoFromFile: async (certificateFile, throw_expired) => {
		const certData = {};

		try {
			const result = await utils.execFile("openssl", [
				"x509",
				"-in",
				certificateFile,
				"-subject",
				"-issuer",
				"-dates",
				"-ext",
				"subjectAltName",
				"-noout",
			]);
			// One openssl call, one line per field:
			// subject=CN = something.example.com
			// issuer=C = US, O = Let's Encrypt, CN = E5
			// notBefore=Jul 14 04:04:29 2018 GMT
			// notAfter=Oct 12 04:04:29 2018 GMT
			let validFrom = null;
			let validTo = null;
			const sans = [];

			for (const raw of result.split("\n")) {
				const line = raw.trim();
				// X509v3 Subject Alternative Name block: "DNS:a.example.com, DNS:b.example.com"
				if (line.startsWith("DNS:") || line.includes(", DNS:")) {
					for (const part of line.split(",")) {
						const san = part.trim();
						if (san.startsWith("DNS:")) {
							sans.push(san.slice(4).trim());
						}
					}
					continue;
				}
				const eq = line.indexOf("=");
				if (eq < 0) {
					continue;
				}
				const key = line.slice(0, eq).toLowerCase();
				const value = line.slice(eq + 1).trim();
				if (key === "subject") {
					// Pick the CN attribute explicitly; openssl prints the RDNs in issuance order and,
					// depending on the version, with ("CN = x", 1.1) or without ("CN=x", 3.x) spaces
					// around "=", or in the legacy "/C=DE/CN=x" form (1.0).
					const match = /(?:^|[,/+]\s*)CN\s*=\s*([^,/+]+)/i.exec(value);
					const cn = match ? match[1].trim() : "";
					if (cn) {
						certData.cn = cn;
					}
				} else if (key === "issuer") {
					certData.issuer = value;
				} else if (key === "notbefore" || key === "notafter") {
					const date = Number.parseInt(moment(value, "MMM DD HH:mm:ss YYYY z").format("X"), 10);
					if (key === "notbefore") {
						validFrom = date;
					} else {
						validTo = date;
					}
				}
			}

			if (!certData.cn && sans.length) {
				certData.cn = sans[0];
			}

			if (!validFrom || !validTo) {
				throw new error.ValidationError(`Could not determine dates from certificate: ${result}`);
			}

			if (throw_expired && validTo < Number.parseInt(moment().format("X"), 10)) {
				throw new error.ValidationError("Certificate has expired");
			}

			certData.dates = {
				from: validFrom,
				to: validTo,
			};

			return certData;
		} catch (err) {
			throw new error.ValidationError(`Certificate is not valid (${err.message})`, err);
		}
	},

	/**
	 * Cleans the ssl keys from the meta object and sets them to "true"
	 *
	 * @param   {Object}  meta
	 * @param   {Boolean} [remove]
	 * @returns {Object}
	 */
	cleanMeta: (meta, remove) => {
		internalCertificate.allowedSslFiles.map((key) => {
			if (typeof meta[key] !== "undefined" && meta[key]) {
				if (remove) {
					delete meta[key];
				} else {
					meta[key] = true;
				}
			}
			return true;
		});
		return meta;
	},

	/**
	 * Request a certificate using the http challenge
	 * @param   {Object}  certificate   the certificate row
	 * @param   {String}  email         the email address to use for registration
	 * @returns {Promise}
	 */
	requestLetsEncryptSsl: async (certificate, email) => {
		logger.info(
			`Requesting LetsEncrypt certificates for Cert #${certificate.id}: ${certificate.domain_names.join(", ")}`,
		);

		const { args, opts } = buildCertbotArgs(certificate, { email, challenge: "http" });
		const result = await utils.execFile(certbotCommand, args, opts);
		logger.success(result);
		return result;
	},

	/**
	 * @param   {Object}   certificate  the certificate row
	 * @param   {String}   email        the email address to use for registration
	 * @returns {Promise}
	 */
	requestLetsEncryptSslWithDnsChallenge: async (certificate, email) => {
		await installPlugin(certificate.meta.dns_provider);
		const dnsPlugin = dnsPlugins[certificate.meta.dns_provider];
		if (!dnsPlugin) {
			throw Error(`Unknown DNS provider '${certificate.meta.dns_provider}'`);
		}
		logger.info(
			`Requesting LetsEncrypt certificates via ${dnsPlugin.name} for Cert #${certificate.id}: ${certificate.domain_names.join(", ")}`,
		);

		const credentials = certificate.meta.dns_provider_credentials;
		return withDnsCredentials(certificate, credentials, async (credentialsLocation) => {
			const { args, opts } = buildCertbotArgs(certificate, {
				email,
				challenge: "dns",
				dnsPlugin,
				credentialsLocation,
			});
			const result = await utils.execFile(certbotCommand, args, opts);
			logger.info(result);
			return result;
		});
	},

	/**
	 * @param   {Access}  access
	 * @param   {Object}  data
	 * @param   {Number}  data.id
	 * @returns {Promise}
	 */
	renew: async (access, data) => {
		await access.can("certificates:update", data);
		const certificate = await internalCertificate.get(access, data);

		if (certificate.provider === "letsencrypt") {
			const renewMethod = certificate.meta.dns_challenge
				? internalCertificate.renewLetsEncryptSslWithDnsChallenge
				: internalCertificate.renewLetsEncryptSsl;

			await renewMethod(certificate);
			const certInfo = await internalCertificate.getCertificateInfoFromFile(
				`${internalCertificate.getLiveCertPath(certificate.id)}/fullchain.pem`,
			);

			// Record the new expiry BEFORE the reload: the renewed cert is on disk
			// and valid. If nginx -t fails (often because of an unrelated host), the
			// old order left expires_on untouched and the hourly timer re-issued the
			// same certificate again and again (Let's Encrypt rate limit).
			const updatedCertificate = await certificateModel
				.query()
				.patchAndFetchById(certificate.id, {
					expires_on: moment(certInfo.dates.to, "X").format("YYYY-MM-DD HH:mm:ss"),
				})
				.then(utils.omitRow(omissions()));

			// Add to audit log
			await internalAuditLog.add(access, {
				action: "renewed",
				object_type: "certificate",
				object_id: updatedCertificate.id,
				meta: updatedCertificate,
			});

			// The renewed cert files are confirmed on disk, reload nginx so it
			// actually serves them instead of the old in-memory certificate
			try {
				await internalNginx.reload();
				internalCertificate.reloadPending = false;
			} catch (err) {
				// expires_on is already >30 days out, so the timer would not select
				// this cert again: keep retrying the reload instead (retryPendingReload)
				internalCertificate.reloadPending = true;
				logger.error(
					`Certificate #${certificate.id} renewed, but nginx reload failed — nginx still serves the old certificate until the next successful reload (retried every timer run): ${err.message}`,
				);
				throw new error.ConfigurationError(
					`Zertifikat erneuert (gültig bis ${updatedCertificate.expires_on}), aber nginx konnte nicht neu geladen werden: ${err.message}`,
				);
			}

			return updatedCertificate;
		}

		throw new error.ValidationError("Only Let'sEncrypt certificates can be renewed");
	},

	/**
	 * @param   {Object}  certificate   the certificate row
	 * @returns {Promise}
	 */
	/**
	 * True when certbot can renew lineage npm-<id> in place: its renewal conf
	 * (in certbot's config dir) and the live fullchain both exist. Then
	 * `certonly --cert-name npm-<id> --force-renewal` keeps the name and leaves
	 * the old cert untouched on failure, so nothing has to be moved aside.
	 */
	lineageIsIntact: (certificateId, configDir = certbotConfigDir) => {
		const prefix = `npm-${certificateId}`;
		return (
			fs.existsSync(`${configDir}/renewal/${prefix}.conf`) &&
			fs.existsSync(`${configDir}/live/${prefix}/fullchain.pem`)
		);
	},

	/**
	 * Run certbot for a renewal. An intact lineage is renewed in place, so the
	 * live cert nginx references never disappears during the certbot run. Only
	 * a broken lineage (renewal conf or live dir missing; certbot would create
	 * npm-<id>-0001 or refuse) is moved aside first. Even then the backup is
	 * discarded only once live/npm-<id>/fullchain.pem really exists again.
	 */
	runCertbotRenewal: async (certificateId, args, opts) => {
		if (internalCertificate.lineageIsIntact(certificateId)) {
			return utils.execFile(certbotCommand, args, opts);
		}
		logger.warn(`Lineage npm-${certificateId} is incomplete, moving it aside for a clean renewal`);
		const backup = internalCertificate.backupCertDirsForRenewal(certificateId);
		let result;
		try {
			result = await utils.execFile(certbotCommand, args, opts);
		} catch (err) {
			internalCertificate.restoreCertDirsBackup(backup);
			throw err;
		}
		if (!internalCertificate.renewedLiveCertExists(certificateId)) {
			internalCertificate.restoreCertDirsBackup(backup);
			throw new Error(
				`certbot did not write live/npm-${certificateId}/fullchain.pem (versioned lineage?); previous certificate restored`,
			);
		}
		internalCertificate.discardCertDirsBackup(backup);
		return result;
	},

	renewedLiveCertExists: (certificateId, dirs = [letsencryptRoot, certbotConfigDir]) =>
		dirs.every((d) => fs.existsSync(`${d}/live/npm-${certificateId}/fullchain.pem`)),

	/**
	 * Map a backup entry (archive/…, live/…, renewal/…, certbot-renewal/…) to
	 * the place it was moved from. certbot-renewal/ holds confs from certbot's
	 * own renewal dir when that is not letsencryptRoot/renewal.
	 */
	backupEntryTarget: (letsencryptDir, relPath, configDir = certbotConfigDir) => {
		if (relPath.startsWith("certbot-renewal/")) {
			return `${configDir}/renewal/${relPath.slice("certbot-renewal/".length)}`;
		}
		return `${letsencryptDir}/${relPath}`;
	},

	/**
	 * Move all certbot dirs and configs for a given certificate ID aside before
	 * running certonly --force-renewal on a BROKEN lineage, so certbot creates a
	 * clean npm-<id> lineage without versioned suffixes like npm-<id>-0001 —
	 * without destroying the still-valid certificate if certbot fails. The
	 * renewal confs are moved from certbot's own config dir too: leaving the
	 * conf certbot actually reads in place is exactly what makes it create
	 * npm-<id>-0001.
	 */
	backupCertDirsForRenewal: (certificateId, letsencryptDir = letsencryptRoot, configDir = certbotConfigDir) => {
		const prefix = `npm-${certificateId}`;
		const backupDir = `${letsencryptDir}/.renewal-backup-${prefix}`;
		const entries = [];

		// A backup left over from an interrupted renewal may hold the ONLY copy of
		// the valid certificate: put back what is missing before discarding it.
		internalCertificate.recoverStaleRenewalBackup(backupDir, configDir);

		for (const subdir of ["archive", "live"]) {
			const base = `${letsencryptDir}/${subdir}`;
			if (!fs.existsSync(base)) continue;
			for (const entry of fs.readdirSync(base)) {
				if (entry === prefix || entry.startsWith(`${prefix}-`)) {
					fs.mkdirSync(`${backupDir}/${subdir}`, { recursive: true });
					fs.renameSync(`${base}/${entry}`, `${backupDir}/${subdir}/${entry}`);
					entries.push(`${subdir}/${entry}`);
					logger.info(`Moved ${subdir}/${entry} aside for renewal`);
				}
			}
		}

		const renewalDir = `${letsencryptDir}/renewal`;
		if (fs.existsSync(renewalDir)) {
			for (const entry of fs.readdirSync(renewalDir)) {
				if ((entry === `${prefix}.conf` || entry.startsWith(`${prefix}-`)) && entry.endsWith(".conf")) {
					fs.mkdirSync(`${backupDir}/renewal`, { recursive: true });
					fs.renameSync(`${renewalDir}/${entry}`, `${backupDir}/renewal/${entry}`);
					entries.push(`renewal/${entry}`);
					logger.info(`Moved renewal config ${entry} aside for renewal`);
				}
			}
		}

		const certbotRenewalDir = `${configDir}/renewal`;
		let separateCertbotRenewal = false;
		try {
			separateCertbotRenewal =
				fs.existsSync(certbotRenewalDir) &&
				(!fs.existsSync(renewalDir) || fs.realpathSync(certbotRenewalDir) !== fs.realpathSync(renewalDir));
		} catch {
			separateCertbotRenewal = false;
		}
		if (separateCertbotRenewal) {
			for (const entry of fs.readdirSync(certbotRenewalDir)) {
				if ((entry === `${prefix}.conf` || entry.startsWith(`${prefix}-`)) && entry.endsWith(".conf")) {
					fs.mkdirSync(`${backupDir}/certbot-renewal`, { recursive: true });
					fs.renameSync(`${certbotRenewalDir}/${entry}`, `${backupDir}/certbot-renewal/${entry}`);
					entries.push(`certbot-renewal/${entry}`);
					logger.info(`Moved certbot renewal config ${entry} aside for renewal`);
				}
			}
		}

		return { backupDir, entries, letsencryptDir, configDir };
	},

	/**
	 * Put the previous certificate files back after a failed renewal, removing
	 * anything certbot partially created in their place first.
	 */
	restoreCertDirsBackup: (backup) => {
		const letsencryptDir = backup.letsencryptDir || letsencryptRoot;
		try {
			for (const relPath of backup.entries) {
				const target = internalCertificate.backupEntryTarget(letsencryptDir, relPath, backup.configDir);
				fs.rmSync(target, { recursive: true, force: true });
				fs.mkdirSync(path.dirname(target), { recursive: true });
				fs.renameSync(`${backup.backupDir}/${relPath}`, target);
				logger.info(`Restored ${relPath} after failed renewal`);
			}
			fs.rmSync(backup.backupDir, { recursive: true, force: true });
		} catch (err) {
			// Don't mask the certbot error; just log the restore failure
			logger.error(`Failed to restore certificate backup from ${backup.backupDir}: ${err.message}`);
		}
	},

	discardCertDirsBackup: (backup) => {
		fs.rmSync(backup.backupDir, { recursive: true, force: true });
	},

	/**
	 * Recover a .renewal-backup-npm-<id> dir left by an interrupted renewal.
	 * Entries are only kept in place when they are verifiably usable:
	 *   - live/<lineage>: its fullchain.pem must resolve (symlinks followed) to a
	 *     non-empty file. A dir certbot created before crashing (no fullchain yet,
	 *     dangling symlinks) is replaced by the backup copy — otherwise the only
	 *     valid certificate would be deleted with the backup dir.
	 *   - archive/<lineage>: kept when live/<lineage> is usable, else replaced
	 *     (the restored live symlinks point into the backed-up archive).
	 *   - renewal confs: kept when present (certbot re-created them for the same
	 *     lineage paths), else restored.
	 * The backup dir is removed only after every entry was restored or verified.
	 * On failure it is KEPT and the error is rethrown, so a renewal never starts
	 * on top of it.
	 */
	recoverStaleRenewalBackup: (backupDir, configDir = certbotConfigDir) => {
		if (!fs.existsSync(backupDir)) return;
		const letsencryptDir = path.dirname(backupDir);
		// lstat: a dangling symlink still occupies the path
		const occupied = (p) => {
			try {
				fs.lstatSync(p);
				return true;
			} catch {
				return false;
			}
		};
		const liveUsable = (dir) => {
			try {
				const st = fs.statSync(`${dir}/fullchain.pem`);
				return st.isFile() && st.size > 0;
			} catch {
				return false;
			}
		};
		const restore = (from, target, rel) => {
			if (occupied(target)) fs.rmSync(target, { recursive: true, force: true });
			fs.mkdirSync(path.dirname(target), { recursive: true });
			fs.renameSync(from, target);
			logger.warn(`Recovered ${rel} from an interrupted renewal`);
		};
		const liveEntries = fs.existsSync(`${backupDir}/live`) ? fs.readdirSync(`${backupDir}/live`) : [];
		try {
			// live first: whether a lineage's live dir is usable decides about its archive
			for (const subdir of ["live", "archive", "renewal", "certbot-renewal"]) {
				const base = `${backupDir}/${subdir}`;
				if (!fs.existsSync(base)) continue;
				for (const entry of fs.readdirSync(base)) {
					const rel = `${subdir}/${entry}`;
					const target = internalCertificate.backupEntryTarget(letsencryptDir, rel, configDir);
					let keep = occupied(target);
					if (keep && subdir === "live") keep = liveUsable(target);
					if (keep && subdir === "archive") keep = liveUsable(`${letsencryptDir}/live/${entry}`);
					if (keep) continue;
					restore(`${base}/${entry}`, target, rel);
				}
			}
			for (const entry of liveEntries) {
				if (!liveUsable(`${letsencryptDir}/live/${entry}`)) {
					logger.error(`live/${entry} has no usable fullchain.pem after recovering ${backupDir}`);
				}
			}
			fs.rmSync(backupDir, { recursive: true, force: true });
		} catch (err) {
			// Keep the backup dir: it may still hold the only valid copy
			logger.error(`Failed to recover renewal backup ${backupDir}: ${err.message}`);
			throw err;
		}
	},

	recoverAllStaleRenewalBackups: () => {
		let entries = [];
		try {
			entries = fs.readdirSync(letsencryptRoot).filter((e) => /^\.renewal-backup-npm-\d+$/.test(e));
		} catch {
			return;
		}
		for (const e of entries) {
			try {
				internalCertificate.recoverStaleRenewalBackup(`${letsencryptRoot}/${e}`);
			} catch {
				// logged above; the next renewal attempt retries the recovery
			}
		}
	},

	renewLetsEncryptSsl: async (certificate) => {
		logger.info(
			`Renewing LetsEncrypt certificates for Cert #${certificate.id}: ${certificate.domain_names.join(", ")}`,
		);

		const { args, opts } = buildCertbotArgs(certificate, { renew: true, challenge: "http" });
		const result = await internalCertificate.runCertbotRenewal(certificate.id, args, opts);
		logger.info(result);
		return result;
	},

	/**
	 * @param   {Object}  certificate   the certificate row
	 * @returns {Promise}
	 */
	renewLetsEncryptSslWithDnsChallenge: async (certificate) => {
		const dnsPlugin = dnsPlugins[certificate.meta.dns_provider];
		if (!dnsPlugin) {
			throw Error(`Unknown DNS provider '${certificate.meta.dns_provider}'`);
		}

		logger.info(
			`Renewing LetsEncrypt certificates via ${dnsPlugin.name} for Cert #${certificate.id}: ${certificate.domain_names.join(", ")}`,
		);

		await installPlugin(certificate.meta.dns_provider);

		// Credentials are stripped by omissions() in get(), fetch directly from DB
		const fullCert = await certificateModel.query().findById(certificate.id);
		const dnsCredentials = fullCert?.meta?.dns_provider_credentials;
		if (!dnsCredentials) {
			throw new error.ValidationError("DNS provider credentials not found for this certificate");
		}

		return withDnsCredentials(certificate, dnsCredentials, async (credentialsLocation) => {
			const { args, opts } = buildCertbotArgs(certificate, {
				renew: true,
				challenge: "dns",
				dnsPlugin,
				credentialsLocation,
			});
			const result = await internalCertificate.runCertbotRenewal(certificate.id, args, opts);
			logger.info(result);
			return result;
		});
	},

	/**
	 * @param   {Object}  certificate    the certificate row
	 * @param   {Boolean} [throwErrors]
	 * @returns {Promise}
	 */
	revokeLetsEncryptSsl: async (certificate, throwErrors) => {
		logger.info(
			`Revoking LetsEncrypt certificates for Cert #${certificate.id}: ${certificate.domain_names.join(", ")}`,
		);

		const args = [
			"revoke",
			"--config",
			letsencryptConfig,
			"--work-dir",
			certbotWorkDir,
			"--logs-dir",
			certbotLogsDir,
			"--cert-path",
			`${internalCertificate.getLiveCertPath(certificate.id)}/fullchain.pem`,
			"--delete-after-revoke",
		];

		const adds = internalCertificate.getAdditionalCertbotArgs(certificate.id);
		args.push(...adds.args);

		logger.info(`Command: ${certbotCommand} ${args ? args.join(" ") : ""}`);
		// resolved before --delete-after-revoke removes the renewal conf
		const credentialsLocation = credentialsLocationFor(certificate.id);

		try {
			const result = await utils.execFile(certbotCommand, args, adds.opts);
			// Normally gone already (only on disk during a certbot run); a file
			// left by an older version must not outlive the certificate.
			if (!credentialsInUse.has(Number(certificate.id))) {
				fs.rmSync(credentialsLocation, { force: true });
			}
			logger.info(result);
			return result;
		} catch (err) {
			logger.error(err.message);
			if (throwErrors) {
				throw err;
			}
		}
	},

	/**
	 * @param   {Object}  inUseResult
	 * @param   {Number}  inUseResult.total_count
	 * @param   {Array}   inUseResult.proxy_hosts
	 * @param   {Array}   inUseResult.redirection_hosts
	 * @param   {Array}   inUseResult.dead_hosts
	 * @returns {Promise}
	 */
	disableInUseHosts: async (inUseResult) => {
		// Stash (not delete) the confs: enableInUseHosts -> bulkGenerateConfigs
		// restores a stashed conf when the regenerated one fails nginx -t.
		if (inUseResult?.total_count) {
			if (inUseResult?.proxy_hosts.length) {
				await internalNginx.bulkStashConfigs("proxy_host", inUseResult.proxy_hosts);
			}

			if (inUseResult?.redirection_hosts.length) {
				await internalNginx.bulkStashConfigs("redirection_host", inUseResult.redirection_hosts);
			}

			if (inUseResult?.dead_hosts.length) {
				await internalNginx.bulkStashConfigs("dead_host", inUseResult.dead_hosts);
			}
		}
	},

	/**
	 * Regenerate the confs of the hosts taken out by disableInUseHosts. All three
	 * host types are always processed; a host whose conf nginx -t rejects is
	 * isolated by bulkGenerateConfigs (previous conf restored, meta.nginx_err
	 * set) and logged here, so a single bad host does not fail the certificate
	 * request or keep the other hosts down.
	 *
	 * @param   {Object}  inUseResult
	 * @param   {Number}  inUseResult.total_count
	 * @param   {Array}   inUseResult.proxy_hosts
	 * @param   {Array}   inUseResult.redirection_hosts
	 * @param   {Array}   inUseResult.dead_hosts
	 * @returns {Promise<Error[]>}  the per-type errors (empty when all passed)
	 */
	enableInUseHosts: async (inUseResult) => {
		const errors = [];
		if (inUseResult?.total_count) {
			for (const [type, hosts] of [
				["proxy_host", inUseResult.proxy_hosts],
				["redirection_host", inUseResult.redirection_hosts],
				["dead_host", inUseResult.dead_hosts],
			]) {
				if (!hosts?.length) continue;
				try {
					await internalNginx.bulkGenerateConfigs(type, hosts);
				} catch (err) {
					logger.error(`Re-enabling ${type} configs after certificate issuance: ${err.message}`);
					errors.push(err);
				}
			}
		}
		return errors;
	},

	/**
	 *
	 * @param   {Object}    payload
	 * @param   {string[]}  payload.domains
	 * @returns
	 */
	testHttpsChallenge: async (access, payload) => {
		await access.can("certificates:list");

		// Create a test challenge file
		const testChallengeDir = "/data/letsencrypt-acme-challenge/.well-known/acme-challenge";
		const testChallengeFile = `${testChallengeDir}/test-challenge`;
		fs.mkdirSync(testChallengeDir, { recursive: true });
		fs.writeFileSync(testChallengeFile, "Success", { encoding: "utf8" });

		const results = {};
		for (const domain of payload.domains) {
			results[domain] = await internalCertificate.performTestForDomain(domain);
		}

		// Remove the test challenge file
		fs.unlinkSync(testChallengeFile);

		return results;
	},

	performTestForDomain: async (domain) => {
		logger.info(`Testing http challenge for ${domain}`);
		const agent = new ProxyAgent();
		const url = `http://${domain}/.well-known/acme-challenge/test-challenge`;
		const formBody = `method=G&url=${encodeURI(url)}&bodytype=T&requestbody=&headername=User-Agent&headervalue=None&locationid=1&ch=false&cc=false`;
		const options = {
			method: "POST",
			headers: {
				"User-Agent": "Mozilla/5.0",
				"Content-Type": "application/x-www-form-urlencoded",
				"Content-Length": Buffer.byteLength(formBody),
			},
			agent,
		};

		const result = await new Promise((resolve) => {
			const req = https.request("https://www.site24x7.com/tools/restapi-tester", options, (res) => {
				let responseBody = "";

				res.on("data", (chunk) => {
					responseBody = responseBody + chunk;
				});

				res.on("end", () => {
					try {
						const parsedBody = JSON.parse(`${responseBody}`);
						if (res.statusCode !== 200) {
							logger.warn(
								`Failed to test HTTP challenge for domain ${domain} because HTTP status code ${res.statusCode} was returned: ${parsedBody.message}`,
							);
							resolve(undefined);
						} else {
							resolve(parsedBody);
						}
					} catch (err) {
						if (res.statusCode !== 200) {
							logger.warn(
								`Failed to test HTTP challenge for domain ${domain} because HTTP status code ${res.statusCode} was returned`,
							);
						} else {
							logger.warn(
								`Failed to test HTTP challenge for domain ${domain} because response failed to be parsed: ${err.message}`,
							);
						}
						resolve(undefined);
					}
				});
			});

			// Make sure to write the request body.
			req.write(formBody);
			req.end();
			req.on("error", (e) => {
				logger.warn(`Failed to test HTTP challenge for domain ${domain}`, e);
				resolve(undefined);
			});
		});

		if (!result) {
			// Some error occurred while trying to get the data
			return "failed";
		}
		if (result.error) {
			logger.info(
				`HTTP challenge test failed for domain ${domain} because error was returned: ${result.error.msg}`,
			);
			return `other:${result.error.msg}`;
		}
		if (`${result.responsecode}` === "200" && result.htmlresponse === "Success") {
			// Server exists and has responded with the correct data
			return "ok";
		}
		if (`${result.responsecode}` === "200") {
			// Server exists but has responded with wrong data
			logger.info(
				`HTTP challenge test failed for domain ${domain} because of invalid returned data:`,
				result.htmlresponse,
			);
			return "wrong-data";
		}
		if (`${result.responsecode}` === "404") {
			// Server exists but responded with a 404
			logger.info(`HTTP challenge test failed for domain ${domain} because code 404 was returned`);
			return "404";
		}
		if (
			`${result.responsecode}` === "0" ||
			(typeof result.reason === "string" && result.reason.toLowerCase() === "host unavailable")
		) {
			// Server does not exist at domain
			logger.info(`HTTP challenge test failed for domain ${domain} the host was not found`);
			return "no-host";
		}
		// Other errors
		logger.info(`HTTP challenge test failed for domain ${domain} because code ${result.responsecode} was returned`);
		return `other:${result.responsecode}`;
	},

	getAdditionalCertbotArgs: (certificate_id, dns_provider, credentialsLocation = null) => {
		const args = [];
		if (useLetsencryptServer() !== null) {
			args.push("--server", useLetsencryptServer());
		}
		if (useLetsencryptStaging() && useLetsencryptServer() === null) {
			args.push("--staging");
		}

		// For route53, pass the credentials file as the shared credentials file
		// (keys only, no credential_process) and disable the AWS config file.
		// A per-call copy keeps the global process env untouched.
		const opts = {};
		if (certificate_id && dns_provider === "route53") {
			opts.env = {
				...process.env,
				AWS_CONFIG_FILE: "/dev/null",
				AWS_SHARED_CREDENTIALS_FILE:
					credentialsLocation || `${letsencryptRoot}/credentials/credentials-${certificate_id}`,
			};
		}

		if (dns_provider === "duckdns") {
			args.push("--dns-duckdns-no-txt-restore");
		}

		return { args: args, opts: opts };
	},

	getLiveCertPath: (certificateId) => {
		return `${letsencryptRoot}/live/npm-${certificateId}`;
	},
};

export default internalCertificate;
