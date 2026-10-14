#!/bin/ksh
# backup.sh — nightly encrypted restic backup to the Hetzner storage box.
#
# restic reads its config from the environment (it natively honours
# RESTIC_REPOSITORY and RESTIC_PASSWORD_FILE), so nothing is hardcoded here.
# Required env (set from root's crontab or a mode-0600 wrapper — see bottom):
#   RESTIC_REPOSITORY       sftp://uXXXXX@uXXXXX.your-storagebox.de:23/kyriakon-backup
#                           Storage Box SSH is on port 23, not 22 — the
#                           sftp://…:23/… URL form is required; the scp-style
#                           sftp:user@host:path form has no port and dials 22.
#   RESTIC_PASSWORD_FILE    path to the repo password file, mode 0600, root-only.
#                           The password IS the key — restic has no keyfile, so
#                           keep an offline copy (proposal §5.5), never the only
#                           copy on the box.
#
# Payload is /home: Maildir (/home/<u>/Maildir), git repos (/home/<u>/repos),
# and web roots (/home/<u>/www, /home/<u>/gemini) all live under each user's
# home (proposal §5.3, §6.9), so one tree covers every user-data path. Config
# is deliberately NOT backed up — it is the git-tracked public repo, not data.
# (the research note's /var/www /var/gemini /var/git predates §6.9's
# per-user-under-/home layout — /home is the authoritative, current path.)
#
# /etc/mail is the one exception: it holds the DKIM signing key and smtpd's queue
# key, which are secrets rather than git-tracked config and exist nowhere else.
# Without them a rebuild from git plus this repository comes back unable to sign
# mail or read an existing queue. The whole directory is taken rather than those
# two files by name, so a rotation cannot silently escape the backup.
#
# The ACME TLS keys stay out, but not for the reason once given here.
# acme-client generates a key only when the file is missing, so a renewal reuses
# the key it finds and a lost key is rebuilt. The file is regenerable if it goes
# missing, not reissued on renewal, and that is why the pair is not data.
#
# A capsule's pair is the opposite. A capsule serves a long-lived self-signed
# certificate, generated once with a ten-year life and never renewed, so nothing
# mints its key again: the file is the only copy. Losing the platform pair, which
# serves kyriakon.net and *.kyriakon.net, changes every capsule's certificate at
# once; an own-domain pair serves only that capsule, so losing it changes that
# one certificate. Every reader then trusts once more, since a gemini client pins
# the certificate on first use. The fingerprint on the help page is what a reader
# checks against, and a regeneration is a runbook step that updates it. Both
# halves enter the backup: the platform pair at /etc/ssl/capsule-*.crt and
# /etc/ssl/private/capsule-*.key, and an own-domain pair at
# /etc/ssl/capsule-<domain>.crt with its key. Only pairs present are passed,
# since restic exits on a path that does not exist.
#
# The canary: a fixed-content file written before each run and included in the
# snapshot. restore-test.sh asserts it returns byte-identical, so a backup job
# that silently stops including /home fails the restore test even though
# snapshots/check/restore would still run green on whatever it did back up.

set -euo pipefail

script_dir="$(dirname "$0")"
if [ ! -f "$script_dir/lib.sh" ]; then
	printf '%s: lib.sh is not in %s. Install the two files together, as lib.sh describes.\n' \
		"$0" "$script_dir" >&2
	exit 1
fi

# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
. "$script_dir/lib.sh"

# fail <found> <to do>: stop before restic runs at all, and mail it. The failure is
# mailed like every other, so it is not printed as well: cron mails a job's output
# under a subject of its own, which is the second copy this avoids.
fail() {
	notify_operator backup "snapshot failed" "$1" "$2"
	exit 1
}

if [ -z "${RESTIC_REPOSITORY:-}" ]; then
	fail "RESTIC_REPOSITORY is not set, so there is no repository to back up to." \
		"set it in /root/.kyriakon-env, which the crontab line sources: the storage box's sftp url, port 23 included."
fi
if [ -z "${RESTIC_PASSWORD_FILE:-}" ]; then
	fail "RESTIC_PASSWORD_FILE is not set, so there is no key to the repository." \
		"set it in /root/.kyriakon-env, and keep an offline copy of that password: it is the only thing that can decrypt the snapshots."
fi

# restic caches repository metadata under $HOME, and cron hands these scripts
# HOME=/var/log, so the cache would sit in the log directory instead. All three
# run as root.
: "${RESTIC_CACHE_DIR:=/root/.cache/restic}"
export RESTIC_CACHE_DIR

pw_file="$RESTIC_PASSWORD_FILE"
[ -f "$pw_file" ] || fail "the password file $pw_file is not there, so nothing can be decrypted or written." \
	"check RESTIC_PASSWORD_FILE in /root/.kyriakon-env against the file on disk."

# The password is the decryption key: enforce owner-only perms so it cannot leak
# to another user on the box. 600 is the criterion; 400 (read-only) is accepted.
perm=$(stat -f '%Lp' "$pw_file")
if [ "$perm" != "600" ] && [ "$perm" != "400" ]; then
	fail "the password file $pw_file is mode $perm, so it is not owner-only." \
		"run: chmod 600 $pw_file. The password is the only thing between a copy of the repository and every member's mail."
fi

# Canary path + content are single-sourced in lib.sh (cross-machine contract with
# restore-test.sh, which asserts byte-identity).
printf '%s\n' "$CANARY_TEXT" > "$CANARY_PATH"

# Whole /home tree (Maildir + git repos + web roots), plus the /etc/mail secrets
# and any capsule pair, all of which exist nowhere else. See the header for why
# these paths and no other config. The globs stay literal when no pair exists,
# so each candidate is tested before it is passed.
set -- /home /etc/mail
for f in /etc/ssl/capsule-*.crt /etc/ssl/private/capsule-*.key; do
	[ -f "$f" ] || continue
	set -- "$@" "$f"
done

# The two restic runs are the job's work, and their output is its report: it is
# mailed under a subject naming the component and the event rather than printed for
# cron to wrap in a subject of its own. restic's own words are the body either way,
# so a failure needs no paraphrase.
if ! snapshot=$(restic backup "$@" 2>&1); then
	notify_operator backup "snapshot failed" "$snapshot" \
		"nothing was backed up tonight. restic's own words are above: the repository and its password come from /root/.kyriakon-env, and whether last night's snapshot is there is what the monitor's stale-snapshot alert reads."
	exit 1
fi

# Retention is the purge mechanism: a content-addressed repo cannot target-delete
# a file, so the keep-* window bounds how long a deleted account's data survives
# (proposal §5.5). Window from docs/planning/research/encrypted-backup-restore.md.
if ! forget=$(restic forget --keep-daily 30 --keep-weekly 8 --keep-monthly 6 --prune 2>&1); then
	notify_operator backup "retention failed" "$forget" \
		"the snapshot above is taken and safe, so nothing is lost yet. Retention is what bounds how long a deleted account's data survives, so run this again before the next backup: tonight's window is still in place, and tomorrow's would leave it a night too long."
	exit 1
fi

notify_operator backup "snapshot taken" "$(printf '%s\n%s' "$snapshot" "$forget")" \
	"nothing: this is the nightly report. Its age is what the monitor's stale-snapshot alert reads, and the weekly restore test is what proves it can be restored."

# crontab (root) — nightly after mail's quiet hours. Install it with
# scripts/cron-apply.sh, which takes the values from /root/.kyriakon-env so
# the tab holds no secrets:
#   30 2 * * * . /root/.kyriakon-env; /root/bin/backup.sh
