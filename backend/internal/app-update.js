import { execFile } from "node:child_process";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import errs from "../lib/error.js";
import { global as logger } from "../logger.js";
import internalRemoteVersion from "./remote-version.js";

const execFileAsync = promisify(execFile);
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const updateScript = process.env.FLOPPYGUARD_UPDATE_SCRIPT || path.join(projectRoot, "scripts", "update.sh");
const stateDir = process.env.FLOPPYGUARD_UPDATE_STATE_DIR || "/var/lib/floppyguard";
const stateFile = path.join(stateDir, "update-status.json");

const idleStatus = {
	state: "idle",
	step: "idle",
	message: "No update has been started.",
};

const ACTIVE_STATES = ["queued", "running", "restarting"];
const UPDATE_UNIT = "floppyguard-update.service";
// Grace period before an active status without a running unit counts as stale
// (systemd-run --no-block may take a moment to bring the unit up).
const STALE_GRACE_MS = 60 * 1000;
// Without systemd information, give up on an active status after this long.
const STALE_HARD_MS = 3 * 60 * 60 * 1000;

async function writeStatus(status) {
	await mkdir(stateDir, { recursive: true, mode: 0o700 });
	const tmp = `${stateFile}.${process.pid}.tmp`;
	await writeFile(tmp, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
	await rename(tmp, stateFile);
}

/**
 * @returns {Promise<boolean|null>} true/false, or null if systemd cannot tell
 */
async function isUpdateUnitActive() {
	try {
		const { stdout } = await execFileAsync("systemctl", ["is-active", UPDATE_UNIT], { timeout: 3000 });
		return ["active", "activating", "reloading", "deactivating"].includes(String(stdout).trim());
	} catch (error) {
		const out = String(error?.stdout || "").trim();
		if (out) {
			return ["active", "activating", "reloading", "deactivating"].includes(out);
		}
		return null;
	}
}

/**
 * An active status whose updater is gone (killed, OOM, reboot) would block
 * every later update forever. Turn it into "failed" so the UI can retry.
 */
async function reconcileStale(status, deps = { isUpdateUnitActive, now: Date.now }) {
	if (!ACTIVE_STATES.includes(status.state)) {
		return null;
	}
	const ts = Date.parse(status.updatedAt || status.startedAt || "");
	const age = Number.isNaN(ts) ? Number.POSITIVE_INFINITY : deps.now() - ts;
	if (age < STALE_GRACE_MS) {
		return null;
	}
	const active = await deps.isUpdateUnitActive();
	if (active === true || (active === null && age < STALE_HARD_MS)) {
		return null;
	}
	return {
		...status,
		state: "failed",
		message: "The updater terminated unexpectedly. See /var/lib/floppyguard/update.log.",
		finishedAt: new Date(deps.now()).toISOString(),
	};
}

// Release tags as published on GitHub (vX.Y.Z). The tag is passed to
// update.sh, which installs exactly that release instead of the branch tip.
const RELEASE_TAG_RE = /^v\d+\.\d+\.\d+$/;

/**
 * The release the UI offered ("update to vX.Y.Z"): the tag of GitHub's latest
 * release. update.sh fast-forwards to that tag's commit, so later unreleased
 * commits on the branch are never installed under a release's name.
 *
 * @returns {Promise<string>}
 */
async function resolveReleaseTag(deps = { getRemoteVersion: () => internalRemoteVersion.get() }) {
	let info;
	try {
		info = await deps.getRemoteVersion();
	} catch (error) {
		throw new errs.ValidationError("The latest release could not be determined; try again later.", error);
	}
	const tag = info?.latest;
	if (typeof tag !== "string" || !RELEASE_TAG_RE.test(tag)) {
		throw new errs.ValidationError("The latest release has no valid version tag.");
	}
	return tag;
}

// Serializes start() inside this process so two concurrent requests cannot
// both pass the "already running" check.
let startChain = Promise.resolve();

const internalAppUpdate = {
	async getStatus() {
		let parsed;
		try {
			parsed = JSON.parse(await readFile(stateFile, "utf8"));
		} catch (error) {
			if (error?.code === "ENOENT") return idleStatus;
			// A corrupt file must not brick GET /version/update and every future
			// start() (which reads the status first); only the updater rewrites it.
			if (error instanceof SyntaxError) {
				logger.warn(`${stateFile} is not valid JSON, treating the updater as idle: ${error.message}`);
				return idleStatus;
			}
			throw error;
		}
		if (typeof parsed?.state !== "string" || typeof parsed?.message !== "string") {
			return idleStatus;
		}
		const stale = await reconcileStale(parsed);
		if (stale) {
			await writeStatus(stale);
			return stale;
		}
		return parsed;
	},

	start() {
		const run = startChain.then(() => this._start());
		startChain = run.catch(() => {});
		return run;
	},

	async _start() {
		const current = await this.getStatus();
		if (ACTIVE_STATES.includes(current.state)) {
			return { ...current, alreadyRunning: true };
		}

		const releaseTag = await resolveReleaseTag();
		const startedAt = new Date().toISOString();
		const queued = {
			state: "queued",
			step: "queued",
			message: "Update queued. The service will restart after dependencies and the frontend build succeed.",
			target: releaseTag,
			startedAt,
		};
		await writeStatus(queued);

		try {
			await execFileAsync(
				"systemd-run",
				[
					"--unit=floppyguard-update",
					"--collect",
					"--no-block",
					"--service-type=exec",
					"/bin/bash",
					updateScript,
					releaseTag,
				],
				{ timeout: 5000 },
			);
			return queued;
		} catch (error) {
			// If an updater unit is in fact running (e.g. started outside this
			// process), do not overwrite its status with "failed".
			if ((await isUpdateUnitActive()) === true) {
				return { ...queued, alreadyRunning: true };
			}
			const failed = {
				state: "failed",
				step: "queue",
				message: "Unable to start the isolated update service.",
				startedAt,
				finishedAt: new Date().toISOString(),
			};
			await writeStatus(failed);
			throw error;
		}
	},
};

export const _testExports = { reconcileStale, resolveReleaseTag };

export default internalAppUpdate;
