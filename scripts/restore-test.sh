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

script_dir="$(dirname "$0")"
if [ ! -f "$script_dir/lib.sh" ]; then
	printf '%s: lib.sh is not in %s. Install the two files together, as lib.sh describes.\n' \
		"$0" "$script_dir" >&2
	exit 1
fi

# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
. "$script_dir/lib.sh"

: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is required}"
: "${RESTIC_PASSWORD_FILE:?RESTIC_PASSWORD_FILE is required}"

# restic caches repository metadata under $HOME, and cron hands these scripts
# HOME=/var/log, so the cache would sit in the log directory instead. All three
# run as root.
: "${RESTIC_CACHE_DIR:=/root/.cache/restic}"
export RESTIC_CACHE_DIR

# Every restic call here passes --no-lock. This runs on the weekly test machine
# against a read-only storage sub-account, so it cannot create the lock file that
# snapshots, check, restore and stats otherwise write: without the flag each of
# them fails with "unable to create lock in backend". The sub-account is
# deliberate, since read-only means a fault on the test machine cannot delete the
# backups it exists to verify.

snapshot_max_age_hours="${SNAPSHOT_MAX_AGE_HOURS:-30}"
target_root="${RESTORE_TARGET_ROOT:-/var/restore-test}"
target="$target_root/$(date +%F)"

# Expansion happens when the trap runs, so an unset HEALTHCHECKS_URL must not be
# fatal here: under `set -u` it made the error handler itself die with "parameter
# not set", which replaced the real failure message with a shell error.
trap 'hc_fail "${HEALTHCHECKS_URL:-}"' ERR

die() {
	printf '%s\n' "$1" >&2
	hc_fail "${HEALTHCHECKS_URL:-}"
}

# --- 1. snapshot recency ------------------------------------------------
# If the nightly backup silently stopped, snapshots/check/restore still pass on
# whatever is there; only freshness proves the backup is actually still running.
latest_epoch=$(restic snapshots --json --no-lock \
	| jq -r 'max_by(.time).time | sub("\\..*Z$"; "Z") | fromdateiso8601')
now=$(date +%s)
age=$(( now - latest_epoch ))
max_age=$(( snapshot_max_age_hours * 3600 ))
if [ "$age" -gt "$max_age" ]; then
	die "latest snapshot is ${age}s old (max ${max_age}s) — nightly backup has stopped"
fi

# --- 2. check (repo structure + pack integrity; cheap) ------------------
# Full data re-read is covered by the restore below, so no nightly --read-data.
restic check --no-lock

# --- 3. full restore ----------------------------------------------------
mkdir -p "$target_root"
rm -rf "${target_root:?}"/* 2>/dev/null || true   # stop weekly restores accumulating; :? guards RESTORE_TARGET_ROOT=/
mkdir -p "$target"
restic restore latest --target "$target" --no-lock

# --- 4. canary byte-identical ------------------------------------------
expected=$(mktemp) || die "mktemp failed"
trap 'rm -f "$expected"' EXIT
printf '%s\n' "$CANARY_TEXT" > "$expected"
cmp -s "$expected" "$target$CANARY_PATH" \
	|| die "canary missing or altered — backup did not include /home"
rm -f "$expected"
# Printed on success too: the acceptance criterion names the canary, and a test
# that only speaks when it fails gives the log nothing to point at.
printf 'canary byte-identical at %s\n' "$CANARY_PATH"

# --- 5. secrets, in both directions ------------------------------------
# The backup takes /home and /etc/mail, and nothing else. /etc/mail carries the
# DKIM signing key and smtpd's queue key, which exist nowhere else, so a rebuild
# without them comes back unable to sign mail or read an existing queue. /root
# carries the box's env file and the restic password; the TSIG key in the former is
# DNS control for the domain, and the repository this test reads with read-only
# credentials is no place for it. Asserting both directions means an edit to the
# backup paths fails here, rather than quietly dropping a key or shipping a secret
# to the storage box.
for need in /etc/mail/dkim/private.rsa.key /etc/mail/smtpd.conf; do
	if [ ! -e "$target$need" ]; then
		die "missing from the snapshot: $need — the backup no longer covers /etc/mail"
	fi
done
for secret in /root/.kyriakon-env /root/.restic-pass; do
	if [ -e "$target$secret" ]; then
		die "present in the snapshot: $secret — the backup covers a path it should not"
	fi
done
printf 'verified /etc/mail secrets are in the snapshot and /root secrets are not\n'

# --- 6. Maildir-is-PGP-ciphertext --------------------------------------
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

# --- 7. git fsck on restored bare repos ---------------------------------
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

# --- 8. node count --------------------------------------------------------
# restic's total_file_count counts every node in the snapshot, directories
# included, which is why its restore summary reads "files/dirs". The comparison
# has to count nodes too, and -mindepth 1 drops the restore target itself, which
# is not a snapshot node. The first real run caught this: a files-only count
# reported 61 against a snapshot of 87, which is 61 files plus 26 directories.
snapshot_nodes=$(restic stats latest --json --no-lock | jq -r '.total_file_count')
restored_nodes=$(find "$target" -mindepth 1 | wc -l | tr -d ' ')
if [ "$(( restored_nodes - snapshot_nodes ))" -ne 0 ]; then
	die "node count mismatch: snapshot=$snapshot_nodes restored=$restored_nodes"
fi
printf 'restored %s nodes (matches snapshot stats)\n' "$restored_nodes"

# --- 9. Healthchecks ping (success) ------------------------------------
if [ -n "${HEALTHCHECKS_URL:-}" ]; then
	ping_url "$HEALTHCHECKS_URL"
fi
printf 'restore test passed\n'

# This script is run by scripts/restore-standup.sh, over ssh, on a box that exists
# for the length of the run: cron on the mail box creates it, runs this with
# RESTIC_REPOSITORY, RESTIC_PASSWORD_FILE and HEALTHCHECKS_URL in the environment,
# and deletes it again. There is no crontab here, and no box of its own.
