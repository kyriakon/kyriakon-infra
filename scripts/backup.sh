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
# The canary: a fixed-content file written before each run and included in the
# snapshot. restore-test.sh asserts it returns byte-identical, so a backup job
# that silently stops including /home fails the restore test even though
# snapshots/check/restore would still run green on whatever it did back up.

set -euo pipefail

# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
. "$(dirname "$0")/lib.sh"

: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is required (sftp:...)}"
: "${RESTIC_PASSWORD_FILE:?RESTIC_PASSWORD_FILE is required}"

pw_file="$RESTIC_PASSWORD_FILE"
[ -f "$pw_file" ] || { printf 'password file %s not found\n' "$pw_file" >&2; exit 1; }

# The password is the decryption key: enforce owner-only perms so it cannot leak
# to another user on the box. 600 is the criterion; 400 (read-only) is accepted.
perm=$(stat -f '%Lp' "$pw_file")
if [ "$perm" != "600" ] && [ "$perm" != "400" ]; then
	printf 'password file %s must be mode 0600 (owner-only), got %s\n' "$pw_file" "$perm" >&2
	exit 1
fi

# Canary path + content are single-sourced in lib.sh (cross-machine contract with
# restore-test.sh, which asserts byte-identity).
printf '%s\n' "$CANARY_TEXT" > "$CANARY_PATH"

# Whole /home tree (Maildir + git repos + web roots).
restic backup /home

# Retention is the purge mechanism: a content-addressed repo cannot target-delete
# a file, so the keep-* window bounds how long a deleted account's data survives
# (proposal §5.5). Window from docs/planning/research/encrypted-backup-restore.md.
restic forget --keep-daily 30 --keep-weekly 8 --keep-monthly 6 --prune

# crontab (root) — nightly after mail's quiet hours:
#   30 2 * * *  RESTIC_REPOSITORY='sftp:…' RESTIC_PASSWORD_FILE=/root/.restic-pass /root/bin/backup.sh
