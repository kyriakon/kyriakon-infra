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
# byte-identical + Maildir-is-PGP-ciphertext + git fsck + stats count + the
# control store, account database and generated configs present → HC ping.

set -euo pipefail

script_dir="$(dirname "$0")"
if [ ! -f "$script_dir/lib.sh" ]; then
	printf '%s: lib.sh is not in %s. Install the two files together, as lib.sh describes.\n' \
		"$0" "$script_dir" >&2
	exit 1
fi

# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
. "$script_dir/lib.sh"

# The live pass's required environment is checked after the --self-test
# dispatch below: the guard's fixtures need no repository and no key file.

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

# maildir_ciphertext_ok <file>: a restored message is the RFC 3156 envelope this
# platform writes — the multipart/encrypted Content-Type on its first line — with
# the PGP armor inside it. A plaintext message that merely quotes the armor line
# fails the first test, and one with no armor fails the second.
maildir_ciphertext_ok() {
	head -n 1 "$1" | grep -q '^Content-Type: multipart/encrypted;' || return 1
	LC_ALL=C tr -d '\r' < "$1" | grep -qx -- '-----BEGIN PGP MESSAGE-----' || return 1
	return 0
}

# check_maildir_ciphertext <target-root>: every message in every mailbox, the
# hidden folders included (admin@ delivers to Maildir/.Admin), must be the
# envelope. Passes vacuously when there is no mail yet. A subfolder was the hole
# in the old glob: it scanned cur/ and new/ under each Maildir but nothing under
# Maildir/.*.
check_maildir_ciphertext() {
	typeset target="$1" msg msg_count=0
	for msg in "$target"/home/*/Maildir/cur/* \
		"$target"/home/*/Maildir/new/* \
		"$target"/home/*/Maildir/.[!.]*/cur/* \
		"$target"/home/*/Maildir/.[!.]*/new/*; do
		[ -f "$msg" ] || continue
		msg_count=$(( msg_count + 1 ))
		maildir_ciphertext_ok "$msg" ||
			die "restored Maildir message is not an RFC 3156 envelope with PGP armor: $msg"
	done
	printf 'verified %s restored Maildir messages are PGP ciphertext\n' "$msg_count"
}

# The guard's own fixtures, no box needed: a real envelope passes, a plaintext
# message quoting the armor line fails, and a plaintext message in a hidden
# folder is not invisible.
self_test() {
	self_test_begin
	# The fixtures exercise the failure paths on purpose; a real dead-man's
	# switch must not be told the box is down by its own test.
	unset HEALTHCHECKS_URL
	# shellcheck disable=SC2154 # set by self_test_begin
	tree=$self_test_work
	mkdir -p "$tree/home/alice/Maildir/cur" "$tree/home/alice/Maildir/.Admin/cur"
	{
		printf 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";\n'
		printf '\tboundary="kyriakon-self-test"\n\n'
		printf -- '-----BEGIN PGP MESSAGE-----\n\nciphertext\n'
	} > "$tree/home/alice/Maildir/cur/envelope"
	code=0
	( check_maildir_ciphertext "$tree" ) >/dev/null 2>&1 || code=$?
	check "a real envelope passes" "$code" 0
	printf 'From: sender@example.invalid\nSubject: hi\n\nquoted:\n-----BEGIN PGP MESSAGE-----\n' \
		> "$tree/home/alice/Maildir/cur/plain"
	code=0
	( check_maildir_ciphertext "$tree" ) >/dev/null 2>&1 || code=$?
	check "a plaintext quote of the armor line fails" "$code" 1
	rm "$tree/home/alice/Maildir/cur/plain"
	# An envelope line with no armor is a truncated restore: the armor half of
	# the guard must fail it on its own.
	printf 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";\n\nbody\n' \
		> "$tree/home/alice/Maildir/cur/no-armor"
	code=0
	( check_maildir_ciphertext "$tree" ) >/dev/null 2>&1 || code=$?
	check "an envelope with no armor fails" "$code" 1
	rm "$tree/home/alice/Maildir/cur/no-armor"
	# A quote of the armor line under a real envelope header is not the armor.
	printf 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";\n\n> -----BEGIN PGP MESSAGE-----\n' \
		> "$tree/home/alice/Maildir/cur/quoted-armor"
	code=0
	( check_maildir_ciphertext "$tree" ) >/dev/null 2>&1 || code=$?
	check "a quoted armor line under an envelope fails" "$code" 1
	rm "$tree/home/alice/Maildir/cur/quoted-armor"
	# A client re-upload can leave CRLF armor; it is still the real armor.
	printf 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";\r\n\r\n-----BEGIN PGP MESSAGE-----\r\n\r\nciphertext\r\n' \
		> "$tree/home/alice/Maildir/cur/crlf"
	code=0
	( check_maildir_ciphertext "$tree" ) >/dev/null 2>&1 || code=$?
	check "CRLF armor passes" "$code" 0
	rm "$tree/home/alice/Maildir/cur/crlf"
	printf 'From: sender@example.invalid\nSubject: hi\n\nplain body\n' \
		> "$tree/home/alice/Maildir/.Admin/cur/plain"
	code=0
	( check_maildir_ciphertext "$tree" ) >/dev/null 2>&1 || code=$?
	check "a plaintext message in a hidden folder fails" "$code" 1
	self_test_end
}

case "${1:-}" in
--self-test) self_test ;;
'') ;;
*)
	printf 'usage: doas ksh %s\n' "$0" >&2
	exit 2
	;;
esac

: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is required}"
: "${RESTIC_PASSWORD_FILE:?RESTIC_PASSWORD_FILE is required}"

# Before anything is restored or removed. `${target_root:?}` refuses unset and
# empty, not `/`, so the root is refused here by name. The removal below is
# bounded to the dated directories this script writes, which makes this guard a
# second line rather than the only one. A trailing slash is the same value, so it
# is stripped before the comparison.
case "${target_root%/}" in
"" | /)
	die "RESTORE_TARGET_ROOT=$target_root is the root of the filesystem, and this script restores into its target. Set it to a scratch directory (default /var/restore-test)."
	;;
esac

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
# Stop weekly restores accumulating. Only the dated directories this script
# creates are removed, so a RESTORE_TARGET_ROOT that is a mistyped system path
# costs a restore run rather than the contents of whatever it points at. A check
# of the value alone cannot promise that, because `/home` is a plausible typo and
# a perfectly valid directory. The root itself is refused above.
for d in "$target_root"/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]; do
	if [ -d "$d" ]; then
		rm -rf "$d"
	fi
done
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

# --- 5. secrets, account database and control state ---------------------
# The backup takes /home, /etc/mail, any capsule certificate pair, and the state
# a rebuild cannot recreate: the control store, the box keyring and drain
# secrets, the OS account database, the three generated daemon directories and
# the certificate queue. /etc/mail carries the DKIM signing key and smtpd's queue
# key, which exist nowhere else, so a rebuild without them comes back unable to
# sign mail or read an existing queue. A capsule key is the only copy of its
# long-lived certificate, so a pair that arrives without its key half is a
# broken backup. /root carries the box's env file and the restic password; the
# TSIG key in the former is DNS control for the domain, and the repository this
# test reads with read-only credentials is no place for it. The presence checks
# below and the absence of /root are both asserted. backup.sh and this test read
# the same list from lib.sh, so the two cannot drift; what fails here is a
# snapshot taken by an older list, or a secret that entered the set.
for need in /etc/mail/dkim/private.rsa.key /etc/mail/smtpd.conf; do
	if [ ! -e "$target$need" ]; then
		die "missing from the snapshot: $need — the backup no longer covers /etc/mail"
	fi
done
# The snapshot is of the mail box, which has carried the control plane and
# per-member hosting since they landed, so every path in BACKUP_PATHS exists on
# the box the backup runs on. A missing one in the restore is a payload that lost
# state, not a box that never had any, and it is not allowed to pass vacuously. A
# snapshot taken before these paths entered the payload fails this check until the
# manual post-deploy backup run replaces it; that run is named in the deploy step.
# The same here-doc shape as backup.sh, so the loop stays in this shell.
while read -r need; do
	[ -e "$target$need" ] \
		|| die "missing from the snapshot: $need — the backup no longer covers it"
done <<EOF
$BACKUP_PATHS
EOF
for secret in /root/.kyriakon-env /root/.restic-pass; do
	if [ -e "$target$secret" ]; then
		die "present in the snapshot: $secret — the backup covers a path it should not"
	fi
done
# A capsule pair is two files that share a stem, the cert in /etc/ssl and the key
# in /etc/ssl/private. Assert each restored half brings its mate, so a payload
# that takes one and not the other fails here. A box with no pair passes
# vacuously, the way the Maildir check does.
for f in "$target"/etc/ssl/capsule-*.crt "$target"/etc/ssl/private/capsule-*.key; do
	[ -f "$f" ] || continue
	name=${f##*/}
	stem=${name%.*}
	case "$name" in
	*.crt) mate="/etc/ssl/private/$stem.key" ;;
	*)     mate="/etc/ssl/$stem.crt" ;;
	esac
	[ -f "$target$mate" ] \
		|| die "capsule pair is split in the snapshot: ${f#"$target"} has no $mate"
done
# The account database is asserted as files here, not as a working login: libc
# reads the /etc/pwd.db and /etc/spwd.db that pwd_mkdb derives from
# /etc/master.passwd, and this test starts no service. The recovery procedure
# runs `pwd_mkdb -p /etc/master.passwd` before it starts anything, which is the
# step that makes the restored files the database the daemons and sshd read.
printf 'verified /etc/mail, control state and the account database are in the snapshot and /root secrets are not\n'

# --- 6. Maildir-is-PGP-ciphertext --------------------------------------
# Zero-access regression guard: every restored message must be the envelope this
# platform writes, with the armor inside it. A plaintext message, and a message
# that merely quotes "BEGIN PGP MESSAGE", must not pass. Every mailbox is
# scanned, hidden folders included: admin@ is delivered to alice+Admin, so that
# mail lives in Maildir/.Admin. Passes vacuously if there are no messages yet.
check_maildir_ciphertext "$target"

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
