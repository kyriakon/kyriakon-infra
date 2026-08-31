#!/bin/ksh
# lib.sh — shared helpers for the backup/restore scripts (backup.sh,
# restore-test.sh, rehearsal.sh). Source it from the script's own directory:
#
#   . "$(dirname "$0")/lib.sh"
#
# Deployed alongside each script (scp into the same dir — the crontab examples
# assume /root/bin/<script> and /root/bin/lib.sh).

# ping_url <url> — best-effort GET that never fails the caller. A monitoring ping
# must not turn a transient curl failure into a script failure / cron mail storm.
ping_url() {
	curl -fsS -m 10 --retry 3 "$1" >/dev/null 2>&1 || true
}

# hc_fail <url> — ping Healthchecks /fail and exit 1. Wired to the ERR trap so a
# failed run reports failure before the shell dies.
hc_fail() {
	if [ -n "${1:-}" ]; then
		ping_url "$1/fail"
	fi
	exit 1
}

# Canary contract: backup.sh writes this file into the snapshot; restore-test.sh
# asserts it returns byte-identical. The two run on DIFFERENT boxes, so the path
# and content are single-sourced here rather than re-typed (and allowed to drift)
# per script. Exported (not just set) so shellcheck sees the cross-file use.
export CANARY_PATH='/home/.kyriakon-backup-canary'
export CANARY_TEXT='kyriakon backup canary v1'
