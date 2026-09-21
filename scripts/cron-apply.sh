#!/bin/ksh
# cron-apply.sh — put this repo's cron lines into root's crontab.
#
# Runs ON the box as root:
#
#   doas ksh scripts/cron-apply.sh --check                # show the diff, write nothing
#   doas ksh scripts/cron-apply.sh                        # add what is missing
#   doas ksh scripts/cron-apply.sh --role restore         # on the restore box instead
#
# Each script here documents the crontab line it needs in its own header, and
# nothing installed them: the mail deploy creates /root/bin and stops, so every
# line was pasted by hand, and the monitor's was missed for a week. The lines live
# in this file now, so the pull request that changes them is the review.
#
# The lines carry no values. Per-box settings come from /root/.kyriakon-cron-env,
# sourced by each line:
#
#   export ALERT_TOPIC='kyriakon-alerts'                      # ntfy topic (mail)
#   export HEALTHCHECKS_URL='https://hc-ping.com/<uuid>'       # dead-man's switch
#   export RESTIC_REPOSITORY='sftp://<user>@<host>:23/<repo>'
#   export RESTIC_PASSWORD_FILE='/root/.restic-pass'
#
# A mode-0600 file rather than literals in the tab, so `crontab -l` stays safe to
# paste and host-specific values stay out of this repo.
#
# Safety properties:
#   - it only appends, and skips any script whose path is already referenced, so
#     an existing line with its own values is never overwritten or duplicated;
#   - --check prints the diff and writes nothing;
#   - the tab it replaces is kept beside the original, timestamped;
#   - it refuses to add a line whose script or environment is missing. A cron line
#     that cannot run is worse than no line: cron mails root once, then silence
#     looks exactly like health.
#
# It does not remove lines, and it does not touch the system maintenance entries
# in /etc/crontab.

set -euo pipefail
umask 077

role=mail
check_only=no
while [ "$#" -gt 0 ]; do
	case "$1" in
	--check) check_only=yes ;;
	--role)
		shift
		role="${1:-}"
		;;
	*)
		printf 'usage: doas ksh %s [--check] [--role mail|restore]\n' "$0" >&2
		exit 2
		;;
	esac
	shift
done

env_file=/root/.kyriakon-cron-env
case "$role" in
mail)
	needed_scripts="abuse-monitor.sh renew-acme.sh backup.sh"
	needed_vars="ALERT_TOPIC HEALTHCHECKS_URL RESTIC_REPOSITORY RESTIC_PASSWORD_FILE"
	block=$(cat <<'EOF'

# --- kyriakon: monitoring and maintenance (scripts/cron-apply.sh) ---
*/15 * * * * . /root/.kyriakon-cron-env; /root/bin/abuse-monitor.sh
0 3 * * * . /root/.kyriakon-cron-env; /root/bin/renew-acme.sh
30 2 * * * . /root/.kyriakon-cron-env; /root/bin/backup.sh
# --- end kyriakon ---
EOF
)
	;;
restore)
	needed_scripts="restore-test.sh"
	needed_vars="HEALTHCHECKS_URL RESTIC_REPOSITORY RESTIC_PASSWORD_FILE"
	block=$(cat <<'EOF'

# --- kyriakon: weekly restore test (scripts/cron-apply.sh) ---
45 3 * * 0 . /root/.kyriakon-cron-env; /root/bin/restore-test.sh
# --- end kyriakon ---
EOF
)
	;;
*)
	printf 'unknown role: %s\n' "$role" >&2
	exit 2
	;;
esac

die() {
	printf 'cron-apply: %s\n' "$*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || die "run this with doas: it writes root's crontab"

current=$(crontab -l 2>/dev/null || true)

missing_scripts=""
to_add=""
for s in $needed_scripts; do
	[ -f "/root/bin/$s" ] || missing_scripts="$missing_scripts $s"
	printf '%s\n' "$current" | grep -q "bin/$s" || to_add="$to_add $s"
done

printf 'role: %s\n' "$role"
if [ -n "$missing_scripts" ]; then
	printf 'not installed in /root/bin:%s\n' "$missing_scripts"
fi
if [ -z "$to_add" ]; then
	printf 'nothing to do: every script this role schedules is already in the crontab\n\n'
	printf 'Compare what is there against the block this would have added:\n'
	printf '%s\n' "$block"
	exit 0
fi
printf 'to be added:%s\n' "$to_add"

if [ -n "$missing_scripts" ]; then
	die "install the missing scripts first; the mail deploy does it"
fi
# A missing or half-filled env is the likely first run, so print what to write
# rather than naming the variables and leaving the rest to a search.
hint() {
	case "$1" in
	ALERT_TOPIC) printf "'kyriakon-alerts'  # the ntfy.sh topic to push alerts to" ;;
	HEALTHCHECKS_URL) printf "'https://hc-ping.com/<uuid>'  # this box's check" ;;
	RESTIC_REPOSITORY) printf "'sftp://<user>@<host>:23/<repo>'" ;;
	RESTIC_PASSWORD_FILE) printf "'/root/.restic-pass'  # mode 0600" ;;
	*) printf "'<value>'" ;;
	esac
}

missing_vars=""
for v in $needed_vars; do
	grep -q "^export $v=" "$env_file" 2>/dev/null || missing_vars="$missing_vars $v"
done
if [ -n "$missing_vars" ]; then
	printf 'cron-apply: %s does not set:%s\n\nCreate it mode 0600 with:\n\n' \
		"$env_file" "$missing_vars" >&2
	for v in $missing_vars; do
		printf '  export %s=%s\n' "$v" "$(hint "$v")" >&2
	done
	printf '\nThen re-run this script. Nothing was written.\n' >&2
	exit 1
fi

work=$(mktemp)
before=$(mktemp)
bak=/root/crontab.bak.$(date +%Y%m%d%H%M%S)
printf '%s\n' "$current" > "$before"
printf '%s\n' "$current" > "$work"
printf '%s\n' "$block" >> "$work"

if [ "$check_only" = yes ]; then
	printf '\n--- the change that would be made ---\n'
	diff -u "$before" "$work" || true
	rm -f "$before" "$work"
	printf '\n--check: nothing was written.\n'
	exit 0
fi

printf '%s\n' "$current" > "$bak"
crontab "$work"
rm -f "$before" "$work"
printf '\nbacked up as %s\n' "$bak"
printf "installed. the lines now scheduled from /root/bin:\n"
crontab -l | grep '/root/bin/' | awk '{ print "\t" $0 }'
printf '\nrevert with: crontab %s\n' "$bak"
