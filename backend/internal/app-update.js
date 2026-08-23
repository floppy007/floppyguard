import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
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

async function writeStatus(status) {
	await mkdir(stateDir, { recursive: true, mode: 0o700 });
	await writeFile(stateFile, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
}

const internalAppUpdate = {
	async getStatus() {
		try {
			const parsed = JSON.parse(await readFile(stateFile, "utf8"));
			if (typeof parsed?.state !== "string" || typeof parsed?.message !== "string") {
				return idleStatus;
			}
			return parsed;
		} catch (error) {
			if (error?.code === "ENOENT") return idleStatus;
			throw error;
		}
	},

	async start() {
		const current = await this.getStatus();
		if (["queued", "running", "restarting"].includes(current.state)) {
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

export default internalAppUpdate;
