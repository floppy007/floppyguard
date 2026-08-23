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

write_status() {
	local state="$1"
	local step="$2"
	local message="$3"
	local current="${4:-}"
	local target="${5:-}"
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

fail() {
	local step="$1"
	local message="$2"
	write_status "failed" "${step}" "${message}"
	echo "Update failed during ${step}: ${message}" >&2
	exit 1
}

trap 'fail "unexpected-error" "The updater stopped unexpectedly. See /var/lib/floppyguard/update.log."' ERR

exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
	write_status "failed" "lock" "Another update is already running."
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

write_status "running" "backend-dependencies" "Installing locked backend dependencies."
(cd backend && corepack yarn install --frozen-lockfile)

write_status "running" "frontend-dependencies" "Installing locked frontend dependencies."
(cd frontend && corepack yarn install --frozen-lockfile)

write_status "running" "frontend-build" "Building the frontend."
(cd frontend && corepack yarn build)

new_version="$(node -p "require('./backend/package.json').version")"
write_status "restarting" "restart" "Restarting FloppyGuard backend." "${current}" "v${new_version}"
systemctl restart "${SERVICE_NAME}"

for _ in {1..15}; do
	if curl --fail --silent --show-error --max-time 3 http://127.0.0.1:3300/api/ >/dev/null; then
		write_status "completed" "done" "Update completed successfully." "${current}" "v${new_version}"
		exit 0
	fi
	sleep 2
done

fail "health-check" "The backend did not pass its health check after the restart."
