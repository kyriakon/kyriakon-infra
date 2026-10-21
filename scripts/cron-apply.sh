#!/bin/ksh
# cron-apply.sh - apply this repo's pending on-box state.
#
# Two jobs, because they run on different clocks.
#
#   1. Root's crontab lines for the scheduled scripts (the default mode).
#   2. The generated indexes that httpd.conf, gmid.conf and acme-client.conf
#      include, from the per-member files the signup path has written (--web).
#      httpd and gmid are reloaded after a rewrite; acme-client is not, because
#      it reads its configuration when it runs rather than holding it open.
#
# Runs ON the box as root:
#
#   doas ksh scripts/cron-apply.sh --check                # show the diff, write nothing
#   doas ksh scripts/cron-apply.sh                        # add what is missing
#   doas ksh scripts/cron-apply.sh --web --check           # show the index diff
#   doas ksh scripts/cron-apply.sh --web                  # rewrite the indexes, reload
#
# The index and reload behaviour is checked without a box, against a tree of its
# own with the daemons stubbed:
#
#   ksh scripts/cron-apply.sh --self-test
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
self_test_mode=no
while [ "$#" -gt 0 ]; do
	case "$1" in
	--check) check_only=yes ;;
	--web) web_only=yes ;;
	--self-test) self_test_mode=yes ;;
	*)
		printf 'usage: doas ksh %s [--web] [--check]\n       ksh %s --self-test\n' "$0" "$0" >&2
		exit 2
		;;
	esac
	shift
done

env_file="${KYRIAKON_ENV:-/root/.kyriakon-env}"
needed_scripts="abuse-monitor.sh check-keyring-drift.sh renew-acme.sh backup.sh restore-standup.sh acme-queue.sh"
needed_vars="ALERT_EMAIL HEALTHCHECKS_URL KEYRING_HEALTHCHECKS_URL RESTIC_REPOSITORY RESTIC_PASSWORD_FILE HCLOUD_TOKEN RESTORE_TEST_REPOSITORY RESTORE_TEST_HEALTHCHECKS_URL"

# The onboarding drain is a compiled binary, not one of the /root/bin shell
# scripts above, so it is installed by scripts/deploy-onboard.sh into sbin and
# its existence is checked there rather than in /root/bin. Its line still lives
# here with the others, so the pull request that changes the schedule is the
# review, and it is scheduled every minute because that is what makes a filed
# application move: the handler holds no privilege and only writes an intent,
# and the drain is the process that reads it, sends the review email and carries
# the decision out.
drain_bin=/usr/local/sbin/kyriakon-onboard-drain

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
	# Monday, not Sunday. The run creates a box, restores the snapshot into it and
	# mails the operator when it fails, and a failure mailed at 03:45 on a Sunday
	# is one nobody can act on until Monday anyway: the day is chosen for the
	# morning the mail is read, not for the test.
	restore-standup.sh) printf '45 3 * * 1 . /root/.kyriakon-env; /root/bin/restore-standup.sh\n' ;;
	acme-queue.sh) printf '*/15 * * * * . /root/.kyriakon-env; /root/bin/acme-queue.sh --run\n' ;;
	kyriakon-onboard-drain) printf '* * * * * %s\n' "$drain_bin" ;;
	*) return 1 ;;
	esac
}

die() {
	printf 'cron-apply: %s\n' "$*" >&2
	exit 1
}

# The self-test runs against a tree of its own, with the daemons and rcctl stubbed,
# so it is the one mode that needs no root: every other one here writes root's
# crontab or the box's generated indexes.
[ "$self_test_mode" = yes ] || [ "$(id -u)" -eq 0 ] \
	|| die "run this with doas: it writes root's crontab and the generated vhost indexes"

# --- the generated vhost indexes (--web) ------------------------------------
#
# httpd.conf and gmid.conf each carry an include of a generated index, and the
# index lists one file per member, because no daemon in this stack can include a
# directory: include opens a single path with fopen, and a directory path is read
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
	for f in "$httpd_d/index.conf.saved.$$" "$gmid_d/index.conf.saved.$$" \
		"$acme_d/index.conf.saved.$$"; do
		[ -f "$f" ] || continue
		mv "$f" "${f%.saved."$$"}"
	done
}

apply_web() {
	changed=""
	acme_changed=""
	regen_index "$httpd_d" && changed="$changed httpd"
	regen_index "$gmid_d" && changed="$changed gmid"
	# acme-client.conf's index is rewritten the same way and keeps the same saved
	# copy, but nothing is reloaded: acme-client is not a daemon, and it reads the
	# file when it next runs. The parse is still checked on the box, by the daily
	# renewal rather than here, since the check that names a bad member block is
	# acme-client itself.
	regen_index "$acme_d" && acme_changed=yes
	if [ -z "$changed" ] && [ -z "$acme_changed" ]; then
		printf 'generated indexes: nothing to change, nothing reloaded\n'
		return 0
	fi
	printf 'indexes to rewrite:%s%s\n' "$changed" "${acme_changed:+ acme-client}"
	if [ "$check_only" = yes ]; then
		printf '\n--check: nothing was written and nothing was reloaded.\n'
		return 0
	fi
	# Check both configs before either reload. rcctl runs the same configtest, but
	# doing it here names the failing file while both daemons are still serving.
	if ! httpd -n -f "$httpd_conf"; then
		restore_indexes
		die "${httpd_conf} does not check, so the running configuration was left alone"
	fi
	if ! gmid -n -c "$gmid_conf"; then
		restore_indexes
		die "${gmid_conf} does not check, so the running configuration was left alone"
	fi
	# A failed reload restores the indexes this pass wrote, as the two configtest
	# arms above do. The daemon is still serving the old configuration, so leaving
	# the new index on disk makes the next pass find it byte-identical and report
	# "nothing to change, nothing reloaded" while exiting 0: the member's vhost
	# then never loads, and nothing says so.
	#
	# A daemon that did reload drops its saved copy as it goes, so a later failure
	# in this loop cannot put the old index back under a daemon that has already
	# read the new one.
	for d in $changed; do
		case "$d" in
		httpd) idx="$httpd_d/index.conf" ;;
		gmid) idx="$gmid_d/index.conf" ;;
		esac
		rcctl reload "$d" || { restore_indexes; die "rcctl reload $d failed"; }
		rm -f "$idx.saved.$$"
	done
	rm -f "$httpd_d/index.conf.saved.$$" "$gmid_d/index.conf.saved.$$" \
		"$acme_d/index.conf.saved.$$"
	if [ -n "$changed" ]; then
		printf 'reloaded:%s\n' "$changed"
	fi
	if [ -n "$acme_changed" ]; then
		printf 'acme-client index rewritten; it reads the file at its next run, so nothing was reloaded\n'
	fi
}

# self_test — apply_web against a tree of its own, with the two daemons and rcctl
# stubbed. It runs the real function, because what is being checked is what the
# function does with the indexes when a reload fails, and that is not something a
# fixture can be asked about separately.
self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$(dirname "$0")/lib.sh"
	typeset tree stub code index_before gmid_before
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	# The daemons pass their configtest and rcctl fails only when told to, so the
	# box's own configuration is never parsed and its daemons are never signalled.
	stub="$tree/bin"
	mkdir "$stub"
	printf '#!/bin/sh\nexit 0\n' > "$stub/httpd"
	printf '#!/bin/sh\nexit 0\n' > "$stub/gmid"
	# The stub expands the variable at its own run time, which is the point, and it
	# fails one daemon when named, or all of them when told yes.
	cat > "$stub/rcctl" <<'STUB'
#!/bin/sh
case "${STUB_RCCTL_FAIL:-no}" in
no) exit 0 ;;
yes) exit 1 ;;
*) [ "$2" = "$STUB_RCCTL_FAIL" ] && exit 1; exit 0 ;;
esac
STUB
	chmod 0755 "$stub/httpd" "$stub/gmid" "$stub/rcctl"
	PATH="$stub:$PATH"
	export PATH

	httpd_d="$tree/httpd.d"
	gmid_d="$tree/gmid.d"
	acme_d="$tree/acme.d"
	httpd_conf="$tree/httpd.conf"
	gmid_conf="$tree/gmid.conf"
	mkdir -p "$httpd_d" "$gmid_d" "$acme_d"
	printf 'server "parish.example" {}\n' > "$httpd_d/parish.conf"

	# The first pass writes the indexes and reloads, which is the state everything
	# below is about.
	STUB_RCCTL_FAIL=no
	export STUB_RCCTL_FAIL
	apply_web > "$tree/first.out" 2>&1
	check "the first pass reloads the daemon whose index changed" \
		"$(grep -c '^reloaded: httpd' "$tree/first.out")" 1
	index_before=$(cat "$httpd_d/index.conf")

	# A member file appears, and the reload of it fails.
	printf 'server "school.example" {}\n' > "$httpd_d/school.conf"
	STUB_RCCTL_FAIL=yes
	export STUB_RCCTL_FAIL
	set +e
	( set -e; apply_web ) > "$tree/failed.out" 2>&1
	code=$?
	set -e
	check "a failed reload is a failure" "$([ "$code" -ne 0 ] && printf yes || printf no)" yes
	check "and names the daemon" "$(grep -c 'rcctl reload httpd failed' "$tree/failed.out")" 1
	# The point of the restored index: the daemon is still serving what the index
	# said before, so the next pass has to see a diff and try again. Left as it was,
	# every later pass would find the index byte-identical and report nothing to
	# change, and the member's site would never load.
	check "the index is back to what the running daemon was told" \
		"$(cat "$httpd_d/index.conf")" "$index_before"
	set -- "$httpd_d"/*.saved.*
	check "and no saved copy is left behind" "$([ -e "$1" ] && printf yes || printf no)" no

	# And so the next pass does the work rather than reporting nothing to change.
	STUB_RCCTL_FAIL=no
	export STUB_RCCTL_FAIL
	apply_web > "$tree/second.out" 2>&1
	check "the next pass sees the diff" "$(grep -c '^reloaded: httpd' "$tree/second.out")" 1
	check "and the index now lists the member" \
		"$(grep -c 'school.conf' "$httpd_d/index.conf")" 1

	# A reload that succeeds followed by one that fails: the daemon that reloaded
	# keeps this pass's index, so a reboot does not bring it up without the vhosts
	# the pass added, and the one that failed is back on the index it is serving.
	printf 'server "third.example" {}\n' > "$httpd_d/third.conf"
	printf 'server "another.example" {}\n' > "$gmid_d/another.conf"
	gmid_before=$(cat "$gmid_d/index.conf")
	STUB_RCCTL_FAIL=gmid
	export STUB_RCCTL_FAIL
	set +e
	( set -e; apply_web ) > "$tree/half.out" 2>&1
	code=$?
	set -e
	check "a reload that fails after one that succeeded is a failure" \
		"$([ "$code" -ne 0 ] && printf yes || printf no)" yes
	check "the daemon that reloaded keeps the index it read" \
		"$(grep -c 'third.conf' "$httpd_d/index.conf")" 1
	check "the daemon that failed keeps the old index" \
		"$(cat "$gmid_d/index.conf")" "$gmid_before"

	self_test_end
}

if [ "$self_test_mode" = yes ]; then
	self_test
	exit 0
fi

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

# The drain, checked at its own installed path. A line whose binary the deploy
# never installed is caught here rather than added for cron to fail on in
# silence.
if [ ! -x "$drain_bin" ]; then
	missing_scripts="$missing_scripts kyriakon-onboard-drain"
fi
if ! printf '%s\n' "$current" | grep -qF "$drain_bin"; then
	to_add="$to_add kyriakon-onboard-drain"
	line_for kyriakon-onboard-drain >>"$pending"
fi

if [ -n "$missing_scripts" ]; then
	printf 'not installed:%s\n' "$missing_scripts"
fi
if [ -z "$to_add" ]; then
	rm -f "$pending"
	printf 'nothing to do: every script this schedules is already in the crontab\n\n'
	printf 'Compare what is there against the lines this would have added:\n\n'
	for s in $needed_scripts; do
		line_for "$s"
	done
	line_for kyriakon-onboard-drain
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
	die "install the missing scripts first: scripts/deploy-onboard.sh installs the drain and the mail deploy the rest"
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
printf 'the drain:\n'
crontab -l | grep -F "$drain_bin" | awk '{ print "\t" $0 }'
printf '\nrevert with: crontab %s\n' "$bak"
