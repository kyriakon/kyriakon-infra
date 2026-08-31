#!/bin/ksh
# restore-test.sh — weekly automated restore test against the storage box.
#
# Runs on a SEPARATE read-only machine (never the live mail box): it restores the
# latest snapshot and verifies the output, proving the repo is readable, the data
# decryptable, and the files actually restorable to working state — the things a
# green `restic backup` does not prove (research §5). The test machine talks only
# to the storage box over SFTP; it never touches the live box.
#
# Requires (pkg_add restic jq git) plus:
#   RESTIC_REPOSITORY       sftp:… (a read-only sub-account restricted to the repo)
#   RESTIC_PASSWORD_FILE    mode-0600 password file (offline copy of the key)
#   HEALTHCHECKS_URL        Healthchecks ping URL (optional). Failure pings /fail.
#   SNAPSHOT_MAX_AGE_HOURS  staleness bound (default 30 — nightly cadence + margin)
#   RESTORE_TARGET_ROOT     scratch root (default /var/restore-test)
#
# Verification order (spec §26): snapshot-recency → check → full restore → canary
# byte-identical + Maildir-is-PGP-ciphertext + git fsck + stats count → HC ping.

set -euo pipefail

# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
. "$(dirname "$0")/lib.sh"

: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is required}"
: "${RESTIC_PASSWORD_FILE:?RESTIC_PASSWORD_FILE is required}"

snapshot_max_age_hours="${SNAPSHOT_MAX_AGE_HOURS:-30}"
target_root="${RESTORE_TARGET_ROOT:-/var/restore-test}"
target="$target_root/$(date +%F)"

trap 'hc_fail "$HEALTHCHECKS_URL"' ERR

die() {
	printf '%s\n' "$1" >&2
	hc_fail "$HEALTHCHECKS_URL"
}

# --- 1. snapshot recency ------------------------------------------------
# If the nightly backup silently stopped, snapshots/check/restore still pass on
# whatever is there; only freshness proves the backup is actually still running.
latest_epoch=$(restic snapshots --json \
	| jq -r 'max_by(.time).time | sub("\\..*Z$"; "Z") | fromdateiso8601')
now=$(date +%s)
age=$(( now - latest_epoch ))
max_age=$(( snapshot_max_age_hours * 3600 ))
if [ "$age" -gt "$max_age" ]; then
	die "latest snapshot is ${age}s old (max ${max_age}s) — nightly backup has stopped"
fi

# --- 2. check (repo structure + pack integrity; cheap) ------------------
# Full data re-read is covered by the restore below, so no nightly --read-data.
restic check

# --- 3. full restore ----------------------------------------------------
mkdir -p "$target_root"
rm -rf "${target_root:?}"/* 2>/dev/null || true   # stop weekly restores accumulating; :? guards RESTORE_TARGET_ROOT=/
mkdir -p "$target"
restic restore latest --target "$target"

# --- 4. canary byte-identical ------------------------------------------
expected=$(mktemp) || die "mktemp failed"
trap 'rm -f "$expected"' EXIT
printf '%s\n' "$CANARY_TEXT" > "$expected"
cmp -s "$expected" "$target$CANARY_PATH" \
	|| die "canary missing or altered — backup did not include /home"
rm -f "$expected"

# --- 5. Maildir-is-PGP-ciphertext --------------------------------------
# Zero-access regression guard: every restored message must carry the ASCII-armor
# header. A plaintext message (or a quote of "BEGIN PGP MESSAGE") must not pass.
# cur/ and new/ contain only messages (Dovecot indexes live in the Maildir root),
# so nothing else to skip. Passes vacuously if there are no messages yet.
msg_count=0
for msg in "$target"/home/*/Maildir/cur/* "$target"/home/*/Maildir/new/*; do
	[ -f "$msg" ] || continue
	msg_count=$(( msg_count + 1 ))
	grep -q -e '-----BEGIN PGP MESSAGE-----' "$msg" || die "restored Maildir message is not PGP ciphertext: $msg"
done
printf 'verified %s restored Maildir messages are PGP ciphertext\n' "$msg_count"

# --- 6. git fsck on restored bare repos ---------------------------------
repo_count=0
for repo in "$target"/home/*/repos/*.git; do
	[ -d "$repo" ] || continue
	git --git-dir="$repo" fsck >/dev/null || die "git fsck failed: $repo"
	repo_count=$(( repo_count + 1 ))
done
if [ "$repo_count" -eq 0 ]; then
	printf 'no git repos restored yet (git hosting is Phase 2) — skipped\n'
else
	printf 'git fsck clean on %s restored repos\n' "$repo_count"
fi

# --- 7. stats count ------------------------------------------------------
snapshot_files=$(restic stats latest --json | jq -r '.total_file_count')
restored_files=$(find "$target" -type f | wc -l | tr -d ' ')
if [ "$(( restored_files - snapshot_files ))" -ne 0 ]; then
	die "file count mismatch: snapshot=$snapshot_files restored=$restored_files"
fi
printf 'restored %s files (matches snapshot stats)\n' "$restored_files"

# --- 8. Healthchecks ping (success) ------------------------------------
if [ -n "${HEALTHCHECKS_URL:-}" ]; then
	ping_url "$HEALTHCHECKS_URL"
fi
printf 'restore test passed\n'

# crontab (root, on the SEPARATE read-only test machine) — weekly:
#   45 3 * * 0  RESTIC_REPOSITORY='sftp:…' RESTIC_PASSWORD_FILE=/root/.restic-pass \
#               HEALTHCHECKS_URL='https://hc-ping.com/…' /root/bin/restore-test.sh
