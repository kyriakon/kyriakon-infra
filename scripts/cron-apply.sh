#!/bin/ksh
# cron-apply.sh - apply this repo's pending on-box state.
#
# Two jobs, because they run on different clocks.
#
#   1. Root's crontab lines for the scheduled scripts (the default mode).
#   2. The generated indexes that httpd.conf, gmid.conf and acme-client.conf
#      include, from the per-member files the signup path has written (--web).
#
# Runs ON the box as root:
#
#   doas ksh scripts/cron-apply.sh --check                # show the diff, write nothing
#   doas ksh scripts/cron-apply.sh                        # add what is missing
#   doas ksh scripts/cron-apply.sh --web --check           # show the index diff
#   doas ksh scripts/cron-apply.sh --web                  # rewrite the indexes, reload
#
# The crontab half runs once, when a scheduled script or its line changes. The
# web half runs whenever member files may have appeared, which is the drain's
# pass, and it is batched: see the note above regen_index.
#
# The restore test has no box of its own to schedule on: restore-standup.sh runs
# here and creates one for the minutes the test takes.
#
# Each script here documents the crontab line it needs in its own header, and
# nothing installed them: the mail deploy creates /root/bin and stops, so every
# line was pasted by hand, and the monitor's was missed for a week. The lines live
# in this file now, so the pull request that changes them is the review.
#
# The lines carry no values. Per-box settings come from /root/.kyriakon-env,
# sourced by each line:
#
#   export ALERT_EMAIL='you@example.invalid'                   # off-box alert address
#   export HEALTHCHECKS_URL='https://hc-ping.com/<uuid>'       # dead-man's switch
# check-keyring-drift.sh has its own check, with a daily period. It cannot be
# HEALTHCHECKS_URL above: that period belongs to the fifteen-minute monitor, and a
# second, daily pinger would make its liveness say nothing.
#   export KEYRING_HEALTHCHECKS_URL='https://hc-ping.com/<uuid>'
#   export RESTIC_REPOSITORY='sftp://<user>@<host>:23/<repo>'
#   export RESTIC_PASSWORD_FILE='/root/.restic-pass'
#   export HCLOUD_TOKEN='...'                                  # restore-standup.sh
#   export RESTORE_TEST_REPOSITORY='sftp://<user>-sub1@<host>:23/'
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

check_only=no
web_only=no
while [ "$#" -gt 0 ]; do
	case "$1" in
	--check) check_only=yes ;;
	--web) web_only=yes ;;
	*)
		printf 'usage: doas ksh %s [--web] [--check]\n' "$0" >&2
		exit 2
		;;
	esac
	shift
done

env_file="${KYRIAKON_ENV:-/root/.kyriakon-env}"
needed_scripts="abuse-monitor.sh check-keyring-drift.sh renew-acme.sh backup.sh restore-standup.sh acme-queue.sh"
needed_vars="ALERT_EMAIL HEALTHCHECKS_URL KEYRING_HEALTHCHECKS_URL RESTIC_REPOSITORY RESTIC_PASSWORD_FILE HCLOUD_TOKEN RESTORE_TEST_REPOSITORY RESTORE_TEST_HEALTHCHECKS_URL"

# The crontab line for one script. Built per script rather than as one block: a
# block would duplicate the lines of scripts that are already
# scheduled, which is what the first real run did, leaving the backup and the
# renewal running twice.
line_for() {
	case "$1" in
	abuse-monitor.sh) printf '*/15 * * * * . /root/.kyriakon-env; /root/bin/abuse-monitor.sh\n' ;;
	check-keyring-drift.sh) printf '0 4 * * * . /root/.kyriakon-env; /root/bin/check-keyring-drift.sh --box\n' ;;
	renew-acme.sh) printf '0 3 * * * . /root/.kyriakon-env; /root/bin/renew-acme.sh\n' ;;
	backup.sh) printf '30 2 * * * . /root/.kyriakon-env; /root/bin/backup.sh\n' ;;
	restore-standup.sh) printf '45 3 * * 0 . /root/.kyriakon-env; /root/bin/restore-standup.sh\n' ;;
	acme-queue.sh) printf '*/15 * * * * . /root/.kyriakon-env; /root/bin/acme-queue.sh --run\n' ;;
	*) return 1 ;;
	esac
}

die() {
	printf 'cron-apply: %s\n' "$*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || die "run this with doas: it writes root's crontab and the generated vhost indexes"

# --- the generated vhost indexes (--web) ------------------------------------
#
# httpd.conf, gmid.conf and acme-client.conf each carry an include of a generated
# index, and the index lists one file per member, because none of them can include
# a directory: include opens a single path with fopen, and a directory path is read
# as nothing rather than refused. The signup path writes the member files; this
# rewrites the indexes and tells the daemons, and it does the whole directory in
# one pass.
#
# One pass is the point. Both rc.d scripts here can be reloaded: rc.subr's reload
# action runs the script's configtest and then sends rc_reload_signal, which
# defaults to HUP, and httpd(8) and gmid(8) each document SIGHUP as a reread of
# the configuration. So a batch of vhost changes costs one action per daemon
# rather than one per member, and nothing already connected is dropped. Only the
# daemon whose index changed is reloaded, and the configtest runs before the
# signal, so a bad member file leaves the running configuration alone.
#
# The order is member file, then index, then reload. The index never lists a file
# that is not there, because the drain writes each member file with
# temp-then-rename and this reads the directory. A file that appears after the
# index rewrite waits for the next pass, which is the harmless direction.
#
# acme-client is the exception to the reload: it is not a daemon and holds no
# running copy of the config, so its index is rewritten and nothing is signalled.
# It reads /etc/acme-client.conf, and so the index, on the next run of the
# certificate queue.

httpd_d=/etc/httpd.d
gmid_d=/etc/gmid.d
acme_d=/etc/acme-client.d
httpd_conf=/etc/httpd.conf
gmid_conf=/etc/gmid.conf

# regen_index <dir>: rebuild <dir>/index.conf from the member files present.
# Returns 1 when the index already matches, so the caller skips the reload.
regen_index() {
	dir="$1"
	index="$dir/index.conf"
	work="$index.$$"
	: >"$work"
	for f in "$dir"/*.conf; do
		[ -e "$f" ] || continue
		[ "$f" = "$index" ] && continue
		printf 'include "%s"\n' "$f" >>"$work"
	done
	if [ -f "$index" ] && cmp -s "$work" "$index"; then
		rm -f "$work"
		return 1
	fi
	if [ "$check_only" = yes ]; then
		printf '\n--- %s ---\n' "$index"
		if [ -f "$index" ]; then
			diff -u "$index" "$work" || true
		else
			cat "$work"
		fi
		rm -f "$work"
		return 0
	fi
	# The index that works is kept until both configs have been checked, so a pass
	# that produces an unparseable one leaves the box with something it can start
	# from rather than nothing.
	if [ -f "$index" ]; then
		cp -p "$index" "$index.saved.$$"
	fi
	chmod 0644 "$work"
	mv "$work" "$index"
	return 0
}

restore_indexes() {
	for f in "$httpd_d/index.conf.saved.$$" "$gmid_d/index.conf.saved.$$" "$acme_d/index.conf.saved.$$"; do
		[ -f "$f" ] || continue
		mv "$f" "${f%.saved."$$"}"
	done
}

apply_web() {
	# changed is every index rewritten; reload is only the daemons that hold one,
	# because acme-client is not a daemon and rereads its config on its next run.
	changed=""
	reload=""
	regen_index "$httpd_d" && { changed="$changed httpd"; reload="$reload httpd"; }
	regen_index "$gmid_d" && { changed="$changed gmid"; reload="$reload gmid"; }
	# The acme-client directory arrives with the mail deploy. A box that has not
	# run the deploy since this lane was added has none, and the lane is skipped
	# with a note rather than aborting: the other two indexes are still worth
	# rewriting, and the note names the gap.
	if [ -d "$acme_d" ]; then
		regen_index "$acme_d" && changed="$changed acme-client"
	else
		printf 'note: %s does not exist, so its index was not regenerated\n' "$acme_d" >&2
	fi
	if [ -z "$changed" ]; then
		printf 'vhost indexes: nothing to change, nothing reloaded\n'
		return 0
	fi
	printf 'indexes to rewrite:%s\n' "$changed"
	if [ "$check_only" = yes ]; then
		printf '\n--check: nothing was written and nothing was reloaded.\n'
		return 0
	fi
	# Check each daemon config before reloading anything. rcctl runs the same
	# configtest, but doing it here names the failing file while both daemons are
	# still serving. Nothing is checked for acme-client: it is not a daemon, and a
	# bad member block is rejected by the certificate queue on its next run rather
	# than now.
	if [ -n "$reload" ]; then
		if ! httpd -n -f "$httpd_conf"; then
			restore_indexes
			die "${httpd_conf} does not check, so the running configuration was left alone"
		fi
		if ! gmid -n -c "$gmid_conf"; then
			restore_indexes
			die "${gmid_conf} does not check, so the running configuration was left alone"
		fi
	fi
	for d in $reload; do
		case "$d" in
		httpd) rcctl reload httpd || die "rcctl reload httpd failed" ;;
		gmid) rcctl reload gmid || die "rcctl reload gmid failed" ;;
		esac
	done
	rm -f "$httpd_d/index.conf.saved.$$" "$gmid_d/index.conf.saved.$$" "$acme_d/index.conf.saved.$$"
	if [ -n "$reload" ]; then
		printf 'reloaded:%s\n' "$reload"
	fi
	printf 'indexes rewritten:%s\n' "$changed"
}

if [ "$web_only" = yes ]; then
	apply_web
	exit 0
fi

current=$(crontab -l 2>/dev/null || true)

missing_scripts=""
to_add=""
pending=$(mktemp)
: >"$pending"
for s in $needed_scripts; do
	[ -f "/root/bin/$s" ] || missing_scripts="$missing_scripts $s"
	if ! printf '%s\n' "$current" | grep -q "bin/$s"; then
		to_add="$to_add $s"
		line_for "$s" >>"$pending"
	fi
done

if [ -n "$missing_scripts" ]; then
	printf 'not installed in /root/bin:%s\n' "$missing_scripts"
fi
if [ -z "$to_add" ]; then
	rm -f "$pending"
	printf 'nothing to do: every script this schedules is already in the crontab\n\n'
	printf 'Compare what is there against the lines this would have added:\n\n'
	for s in $needed_scripts; do
		line_for "$s"
	done
	exit 0
fi
printf 'to be added:%s\n' "$to_add"

# The block is assembled in a file, not a variable: command substitution strips
# the trailing newline, which puts the closing marker on the last cron line and
# leaves that job running a command with a comment glued to the end of it.
block=$(mktemp)
{
	printf '\n# --- kyriakon: scheduled by scripts/cron-apply.sh ---\n'
	cat "$pending"
	printf '# --- end kyriakon ---\n'
} >"$block"
rm -f "$pending"

if [ -n "$missing_scripts" ]; then
	die "install the missing scripts first; the mail deploy does it"
fi
# A missing or half-filled env is the likely first run, so report which variables
# are at fault and point at the one script that owns the file.
missing_vars=""
placeholder_vars=""
for v in $needed_vars; do
	if ! grep -q "^export $v=" "$env_file" 2>/dev/null; then
		missing_vars="$missing_vars $v"
	elif grep -q "^export $v='.*REPLACE_ME" "$env_file"; then
		placeholder_vars="$placeholder_vars $v"
	fi
done
if [ -n "$missing_vars" ] || [ -n "$placeholder_vars" ]; then
	printf 'cron-apply: %s is not usable\n' "$env_file" >&2
	if [ -n "$missing_vars" ]; then
		printf '  not set:%s\n' "$missing_vars" >&2
	fi
	if [ -n "$placeholder_vars" ]; then
		printf '  still a placeholder:%s\n' "$placeholder_vars" >&2
	fi
	printf 'Run: doas ksh %s/setup-env.sh\n' "$(dirname "$0")" >&2
	printf 'Nothing was written.\n' >&2
	exit 1
fi

work=$(mktemp)
before=$(mktemp)
bak=/root/crontab.bak.$(date +%Y%m%d%H%M%S)
printf '%s\n' "$current" > "$before"
printf '%s\n' "$current" > "$work"
cat "$block" >> "$work"
rm -f "$block"

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
