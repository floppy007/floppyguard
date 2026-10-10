#!/usr/bin/env bash
# Performs a deliberate, administrator-triggered FloppyGuard update.
# It is launched in its own systemd unit so restarting the backend does not
# interrupt the update process.
# Usage: update.sh <release-tag>   (vX.Y.Z, the release the UI offered)
# Only the commit of that release tag is installed, never a newer unreleased
# commit on the branch, and only when it is on the configured branch and a
# fast-forward from the running version.
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATE_DIR="${FLOPPYGUARD_UPDATE_STATE_DIR:-/var/lib/floppyguard}"
STATE_FILE="${STATE_DIR}/update-status.json"
LOG_FILE="${STATE_DIR}/update.log"
LOCK_FILE="/run/floppyguard-update.lock"
SERVICE_NAME="floppyguard-backend.service"
# Releases are signed tags. Only a tag signed by this pinned key is installed.
# The public key comes from the CURRENT checkout (never from what is fetched).
RELEASE_KEY_FILE="${PROJECT_DIR}/scripts/release-signing-key.asc"
RELEASE_KEY_FPR="DB1389A906262D482BABE895200BC8B1CEBB445E"

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

# Prints the backend's environment (database settings), NUL-separated: from
# the running process when there is one, otherwise from the unit's
# Environment= and EnvironmentFile= settings. A release that crashes at
# startup leaves the unit failed with MainPID=0, and its migrations still have
# to be reverted (or confirmed unapplied) before the old code can come back.
service_environment() {
	local pid
	pid="$(systemctl show --property=MainPID --value "${SERVICE_NAME}" 2>/dev/null || echo 0)"
	if [[ -n "${pid}" && "${pid}" != 0 && -r "/proc/${pid}/environ" ]]; then
		cat "/proc/${pid}/environ"
		return
	fi
	UNIT_ENV="$(systemctl show --property=Environment --value "${SERVICE_NAME}" 2>/dev/null)" \
	UNIT_ENV_FILES="$(systemctl show --property=EnvironmentFiles --value "${SERVICE_NAME}" 2>/dev/null)" \
	node <<'NODE'
const fs = require("node:fs");
// systemctl prints Environment= as space-separated assignments, quoting the
// ones that contain whitespace or special characters.
const split = (s) => {
	const out = [];
	let cur = null;
	let quote = null;
	for (let i = 0; i < s.length; i++) {
		const c = s[i];
		if (quote) {
			if (c === quote) quote = null;
			else if (c === "\\" && quote === '"' && i + 1 < s.length) cur += s[++i];
			else cur += c;
			continue;
		}
		if (/\s/.test(c)) {
			if (cur !== null) out.push(cur);
			cur = null;
			continue;
		}
		if (cur === null) cur = "";
		if (c === '"' || c === "'") quote = c;
		else if (c === "\\" && i + 1 < s.length) cur += s[++i];
		else cur += c;
	}
	if (cur !== null) out.push(cur);
	return out;
};
const env = split(process.env.UNIT_ENV || "").filter((e) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(e));
// EnvironmentFile= entries override Environment= ones, as in systemd.
for (const m of (process.env.UNIT_ENV_FILES || "").matchAll(/(\S+) \(ignore_errors=(?:yes|no)\)/g)) {
	let text = "";
	try {
		text = fs.readFileSync(m[1], "utf8");
	} catch {
		continue;
	}
	for (const raw of text.split("\n")) {
		const kv = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(raw);
		if (!kv || /^\s*[#;]/.test(raw)) continue;
		let value = kv[2];
		if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.endsWith(value[0])) {
			value = value.slice(1, -1);
		}
		env.push(`${kv[1]}=${value}`);
	}
}
if (!env.some((e) => e.startsWith("PATH="))) env.push(`PATH=${process.env.PATH || "/usr/bin:/bin"}`);
process.stdout.write(env.map((e) => `${e}\0`).join(""));
NODE
}

# Reverts migrations that the new commit added and that the new backend has
# already applied. The older code refuses to start while the `migrations`
# table lists files it does not have. Runs with the new code still checked out
# and with the environment of the service (database settings). migrate-down.js
# only reverts names recorded in `migrations`, so a release that crashed
# before applying anything is rolled back without touching the database.
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

	local -a service_env=()
	mapfile -d '' service_env < <(service_environment) || return 1
	if [[ "${#service_env[@]}" -eq 0 ]]; then
		echo "Cannot read the backend's environment to revert migrations." >&2
		return 1
	fi

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

# verify_release_tag <ref> <tag>: succeed only when <ref> is an annotated tag
# object named <tag> with a valid OpenPGP signature by RELEASE_KEY_FPR, checked
# against a throw-away keyring that holds nothing but the pinned key (the
# root user's own keyring and trust settings play no part).
verify_release_tag() {
	local ref="$1" tag="$2" gnupg status rc
	[ "$(git cat-file -t "${ref}" 2>/dev/null)" = "tag" ] || return 1
	[ "$(git cat-file tag "${ref}" | sed -n 's/^tag //p' | head -n 1)" = "${tag}" ] || return 1
	[ -r "${RELEASE_KEY_FILE}" ] || return 1
	gnupg="$(mktemp -d)"
	chmod 700 "${gnupg}"
	if ! GNUPGHOME="${gnupg}" gpg --batch --quiet --import "${RELEASE_KEY_FILE}" >/dev/null 2>&1; then
		rm -rf "${gnupg}"
		return 1
	fi
	rc=0
	status="$(GNUPGHOME="${gnupg}" git -c gpg.format=openpgp -c gpg.program=gpg verify-tag --raw "${ref}" 2>&1 >/dev/null)" || rc=$?
	rm -rf "${gnupg}"
	[ "${rc}" -eq 0 ] || return 1
	printf '%s\n' "${status}" | awk -v fpr="${RELEASE_KEY_FPR}" '
		$1 == "[GNUPG:]" && $2 == "VALIDSIG" && ($3 == fpr || $NF == fpr) { ok = 1 }
		$1 == "[GNUPG:]" && ($2 == "BADSIG" || $2 == "ERRSIG" || $2 == "REVKEYSIG" || $2 == "EXPKEYSIG") { bad = 1 }
		END { exit !(ok && !bad) }'
}

for command in git corepack node systemctl curl gpg; do
	command -v "${command}" >/dev/null 2>&1 || fail "preflight" "Required command '${command}' is not available."
done

release_tag="${1:-}"
[[ "${release_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "preflight" "No valid release tag (vX.Y.Z) was given to the updater."

cd "${PROJECT_DIR}"
branch="$(git symbolic-ref --quiet --short HEAD)" || fail "preflight" "The installation is not on a Git branch."
[[ "${branch}" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "preflight" "The configured Git branch is invalid."

origin="$(git remote get-url origin)" || fail "preflight" "Git remote 'origin' is not configured."
case "${origin}" in
	"https://github.com/floppy007/floppyguard.git"|"git@github.com:floppy007/floppyguard.git"|"ssh://git@github.com/floppy007/floppyguard.git") ;;
	*) fail "preflight" "The Git origin is not an approved FloppyGuard repository." ;;
esac

current="$(git describe --always --dirty)"
write_status "running" "fetch" "Fetching release ${release_tag}." "${current}" "${release_tag}"
git fetch --prune origin "${branch}"
branch_tip="$(git rev-parse FETCH_HEAD)"
# Fetch the tag object into a private temporary ref (no local tag is created or
# overwritten), verify its signature against the pinned release key, and only
# then resolve the commit it points to.
tag_ref="refs/floppyguard-update/${release_tag}"
git update-ref -d "${tag_ref}" 2>/dev/null || true
git fetch --no-tags origin "+refs/tags/${release_tag}:${tag_ref}" || fail "fetch" "Release ${release_tag} was not found in the Git repository."
if ! verify_release_tag "${tag_ref}" "${release_tag}"; then
	git update-ref -d "${tag_ref}" 2>/dev/null || true
	fail "verify" "Release ${release_tag} is not signed by the pinned FloppyGuard release key (${RELEASE_KEY_FPR}); refusing to install it."
fi
target="$(git rev-parse --verify "${tag_ref}^{commit}")" || fail "fetch" "Release ${release_tag} does not point to a commit."
git update-ref -d "${tag_ref}" 2>/dev/null || true
head="$(git rev-parse HEAD)"

git merge-base --is-ancestor "${target}" "${branch_tip}" \
	|| fail "fetch" "Release ${release_tag} is not on the configured branch '${branch}'; refusing to install it."

if git merge-base --is-ancestor "${target}" "${head}"; then
	write_status "completed" "done" "Already up to date." "${current}" "${current}"
	exit 0
fi

write_status "running" "merge" "Applying the fast-forward Git update to ${release_tag}." "${current}" "${release_tag}"
git merge --ff-only "${target}" || fail "merge" "Git could not fast-forward safely to ${release_tag}; local changes were preserved."
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
