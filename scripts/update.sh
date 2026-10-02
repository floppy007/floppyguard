#!/usr/bin/env bash
# Performs a deliberate, administrator-triggered FloppyGuard update.
# It is launched in its own systemd unit so restarting the backend does not
# interrupt the update process.
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATE_DIR="${FLOPPYGUARD_UPDATE_STATE_DIR:-/var/lib/floppyguard}"
STATE_FILE="${STATE_DIR}/update-status.json"
LOG_FILE="${STATE_DIR}/update.log"
LOCK_FILE="/run/floppyguard-update.lock"
SERVICE_NAME="floppyguard-backend.service"

mkdir -p -m 700 "${STATE_DIR}"
touch "${LOG_FILE}"
chmod 600 "${LOG_FILE}"
exec >> >(tee -a "${LOG_FILE}") 2>&1

current_step="start"
prev_head=""
restarted=0

write_status() {
	local state="$1"
	local step="$2"
	local message="$3"
	local current="${4:-}"
	local target="${5:-}"
	current_step="${step}"
	STATE_FILE="${STATE_FILE}" STATE="${state}" STEP="${step}" MESSAGE="${message}" CURRENT="${current}" TARGET="${target}" node <<'NODE'
const fs = require("node:fs");
const path = process.env.STATE_FILE;
const value = {
	state: process.env.STATE,
	step: process.env.STEP,
	message: process.env.MESSAGE,
	updatedAt: new Date().toISOString(),
};
if (process.env.CURRENT) value.current = process.env.CURRENT;
if (process.env.TARGET) value.target = process.env.TARGET;
fs.writeFileSync(`${path}.tmp`, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
fs.renameSync(`${path}.tmp`, path);
NODE
}

# Polls the backend's API until it answers. The backend runs its migrations,
# setup and the IP-range fetch before it listens, so allow a few minutes.
health_check() {
	local tries="${1:-60}" i
	for ((i = 0; i < tries; i++)); do
		if curl --fail --silent --show-error --max-time 3 http://127.0.0.1:3300/api/ >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
	done
	return 1
}

# Reverts migrations that the new commit added and that the new backend has
# already applied. The older code refuses to start while the `migrations`
# table lists files it does not have. Runs with the new code still checked out
# and with the environment of the running service (database settings).
revert_new_migrations() {
	local -a new_migrations=()
	local file
	while IFS= read -r file; do
		[[ -n "${file}" ]] && new_migrations+=("$(basename "${file}")")
	done < <(git diff --name-only --diff-filter=A "${prev_head}" HEAD -- 'backend/migrations/*.js')
	if [[ "${#new_migrations[@]}" -eq 0 ]]; then
		return 0
	fi
	echo "New migrations to revert: ${new_migrations[*]}"

	local pid
	pid="$(systemctl show --property=MainPID --value "${SERVICE_NAME}" 2>/dev/null || echo 0)"
	if [[ -z "${pid}" || "${pid}" == 0 || ! -r "/proc/${pid}/environ" ]]; then
		echo "Cannot read the backend's environment to revert migrations." >&2
		return 1
	fi
	local -a service_env=()
	mapfile -d '' service_env < "/proc/${pid}/environ" || return 1

	# Stop the backend so it does not re-apply the migrations meanwhile.
	systemctl stop "${SERVICE_NAME}" || return 1
	(cd backend && env -i "${service_env[@]}" node migrate-down.js "${new_migrations[@]}") || return 1
	return 0
}

# Returns the checkout to the commit that was running before this update and
# rebuilds it, so a failed install/build/health check never leaves a
# half-installed tree behind (and a retry is not mistaken for "up to date").
# `git reset --keep` (not --hard) preserves local, uncommitted changes.
# Returns 0 only when the previous version is running again; returns 2 when
# the new migrations could not be reverted and the code was left as it is.
rollback() {
	echo "Rolling back to ${prev_head}"
	write_status "running" "rollback" "The update failed; restoring the previous version."
	if [[ "${restarted}" == 1 ]]; then
		if ! revert_new_migrations; then
			# Rolling the code back now would leave a backend that cannot start.
			systemctl restart "${SERVICE_NAME}" || true
			return 2
		fi
	fi
	git reset --keep "${prev_head}" || return 1
	(cd backend && corepack yarn install --frozen-lockfile) || return 1
	(cd frontend && corepack yarn install --frozen-lockfile) || return 1
	(cd frontend && corepack yarn build) || return 1
	if [[ "${restarted}" == 1 ]]; then
		systemctl restart "${SERVICE_NAME}" || return 1
		health_check 60 || return 1
	fi
	return 0
}

fail() {
	local step="$1"
	local message="$2"
	# set -E makes subshells inherit the ERR trap; let the parent shell handle
	# the failure exactly once.
	if [[ "${BASH_SUBSHELL}" -gt 0 ]]; then
		exit 1
	fi
	trap - ERR TERM INT
	set +e
	if [[ -n "${prev_head}" ]]; then
		rollback
		case "$?" in
			0) message="${message} The previous version was restored." ;;
			2) message="${message} The new database migrations could not be reverted, so the new version was kept; manual repair is required (see ${LOG_FILE})." ;;
			*) message="${message} Restoring the previous version failed; manual repair is required (see ${LOG_FILE})." ;;
		esac
	fi
	write_status "failed" "${step}" "${message}"
	echo "Update failed during ${step}: ${message}" >&2
	exit 1
}

on_signal() {
	trap - ERR TERM INT
	set +e
	write_status "failed" "${current_step}" "The updater was terminated before it finished. See ${LOG_FILE}."
	exit 1
}

trap 'fail "${current_step}" "The updater stopped unexpectedly. See /var/lib/floppyguard/update.log."' ERR
trap on_signal TERM INT

exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
	# Another updater owns the status file; do not overwrite its state.
	echo "Another update is already running." >&2
	exit 1
fi

for command in git corepack node systemctl curl; do
	command -v "${command}" >/dev/null 2>&1 || fail "preflight" "Required command '${command}' is not available."
done

cd "${PROJECT_DIR}"
branch="$(git symbolic-ref --quiet --short HEAD)" || fail "preflight" "The installation is not on a Git branch."
[[ "${branch}" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "preflight" "The configured Git branch is invalid."

origin="$(git remote get-url origin)" || fail "preflight" "Git remote 'origin' is not configured."
case "${origin}" in
	"https://github.com/floppy007/floppyguard.git"|"git@github.com:floppy007/floppyguard.git"|"ssh://git@github.com/floppy007/floppyguard.git") ;;
	*) fail "preflight" "The Git origin is not an approved FloppyGuard repository." ;;
esac

current="$(git describe --always --dirty)"
write_status "running" "fetch" "Fetching the configured Git branch." "${current}"
git fetch --prune origin "${branch}"
target="$(git rev-parse FETCH_HEAD)"
head="$(git rev-parse HEAD)"

if [[ "${head}" == "${target}" ]]; then
	write_status "completed" "done" "Already up to date." "${current}" "${current}"
	exit 0
fi

write_status "running" "merge" "Applying the fast-forward Git update." "${current}" "${target}"
git merge --ff-only FETCH_HEAD || fail "merge" "Git could not fast-forward safely; local changes were preserved."
prev_head="${head}"

write_status "running" "backend-dependencies" "Installing locked backend dependencies."
(cd backend && corepack yarn install --frozen-lockfile)

write_status "running" "frontend-dependencies" "Installing locked frontend dependencies."
(cd frontend && corepack yarn install --frozen-lockfile)

write_status "running" "frontend-build" "Building the frontend."
(cd frontend && corepack yarn build)

new_version="$(node -p "require('./backend/package.json').version")"
write_status "restarting" "restart" "Restarting FloppyGuard backend." "${current}" "v${new_version}"
restarted=1
systemctl restart "${SERVICE_NAME}"

if health_check 90; then
	write_status "completed" "done" "Update completed successfully." "${current}" "v${new_version}"
	exit 0
fi

fail "health-check" "The backend did not pass its health check after the restart."
