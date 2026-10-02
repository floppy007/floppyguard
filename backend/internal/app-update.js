import { execFile } from "node:child_process";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

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

		const startedAt = new Date().toISOString();
		const queued = {
			state: "queued",
			step: "queued",
			message: "Update queued. The service will restart after dependencies and the frontend build succeed.",
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

export const _testExports = { reconcileStale };

export default internalAppUpdate;
