#!/bin/ksh
# cron-apply.sh - apply this repo's pending on-box state.
#
# Two jobs, because they run on different clocks.
#
#   1. Root's crontab lines for the scheduled scripts (the default mode).
#   2. The generated indexes that httpd.conf, gmid.conf and acme-client.conf
#      include, and the generated member keypair region of relayd.conf, from the
#      per-member files the signup path has written (--web). httpd, gmid and
#      relayd are reloaded after a rewrite; acme-client is not, because it reads
#      its configuration when it runs rather than holding it open.
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

script_dir=$(cd "$(dirname "$0")" && pwd)

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
# The one list of which scripts the box runs, and where. This script schedules
# its /root/bin rows; deploy-mail.sh installs them, deploy-control.sh installs
# the drain's, and deploy.sh routes a changed script by its row.
install_set="$script_dir/install-set.tsv"
needed_vars="ALERT_EMAIL HEALTHCHECKS_URL KEYRING_HEALTHCHECKS_URL RESTIC_REPOSITORY RESTIC_PASSWORD_FILE HCLOUD_TOKEN RESTORE_TEST_REPOSITORY RESTORE_TEST_HEALTHCHECKS_URL"

# row_dir <destination> — where the box reads that destination's scripts from at
# run time. This is the one place the destinations are named: only the two cron
# runs itself have a directory, because a drain row is installed by
# scripts/deploy-control.sh into the directory the drain's config names.
row_dir() {
	case "$1" in
	/root/bin) printf '/root/bin' ;;
	checkout) printf '%s/scripts' "$repo_dir" ;;
	*) return 1 ;;
	esac
}

# scheduled_scripts <table> — the rows that have a schedule, one name per line.
# A row whose schedule is `-` is a helper the other scripts source, which cron
# never runs. A scheduled row whose destination has no directory is refused here,
# once, rather than becoming a line that cannot run.
scheduled_scripts() {
	typeset name dest
	awk -F'\t' '!/^#/ && $3 != "-" { print $1 "\t" $2 }' "$1" |
		while IFS="$(printf '\t')" read -r name dest; do
			row_dir "$dest" >/dev/null || {
				printf 'cron-apply: %s is scheduled for %s, which no cron line can read\n' \
					"$name" "$dest" >&2
				exit 1
			}
			printf '%s\n' "$name"
		done
}

# The drain is a compiled binary, not one of the /root/bin shell
# scripts above, so it is installed by scripts/deploy-control.sh into sbin and
# its existence is checked there rather than in /root/bin. Its line still lives
# here with the others, so the pull request that changes the schedule is the
# review, and it is scheduled every minute because that is what makes a filed
# application move: the handler holds no privilege and only writes an intent,
# and the drain is the process that reads it, sends the review email and carries
# the decision out.
drain_bin=/usr/local/sbin/kyriakon-control-drain

# Where the checkout's own scripts are read from. A `checkout` row is run from
# there rather than installed: self-test-all.sh runs the scripts beside it and
# check-hygiene.sh reports on the tree it is in, so neither has an installed copy
# to drift from.
repo_dir=/usr/local/src/kyriakon-infra

# The crontab line for one script. Built per script rather than as one block: a
# block would duplicate the lines of scripts that are already
# scheduled, which is what the first real run did, leaving the backup and the
# renewal running twice.
#
# An installed script's destination, schedule and arguments are its install-set
# row, so the pull request that changes any of them is the review of the same
# line the deploys and the hygiene check read. The drain is the one line that is
# not a row: it is a compiled binary.
#
# A checkout row is read from the tree, and cron mails only what a job prints, so
# its line throws a clean run away and names the script when it fails.
line_for() {
	typeset name="$1" row dest sched args dir
	case "$name" in
	# The env file sets PATH, and the drain's scripts need the packages in
	# /usr/local: without it, cron-apply.sh inside a provision cannot find gmid,
	# refuses to reload, and fails the whole approval.
	kyriakon-control-drain) printf '* * * * * . /root/.kyriakon-env; %s\n' "$drain_bin" ;;
	*)
		row=$(awk -F'\t' -v n="$name" \
			'!/^#/ && $1 == n && $3 != "-" { print; exit }' "$install_set")
		[ -n "$row" ] || return 1
		dest=$(printf '%s\n' "$row" | cut -f2)
		sched=$(printf '%s\n' "$row" | cut -f3)
		args=$(printf '%s\n' "$row" | cut -f4)
		dir=$(row_dir "$dest") || return 1
		if [ "$dest" = checkout ]; then
			# A checkout script is read from the tree. A passing run says
			# nothing to cron, so its output is captured and printed only when
			# it fails, followed by the command that produced it: the mail
			# carries the finding, not just that there was one.
			# shellcheck disable=SC2016 # $out and the escapes are for the cron
			# shell; crontab(5) ends the command at an unescaped %, so every one
			# that must reach printf is written \% here.
			printf '%s . /root/.kyriakon-env; out=$(ksh %s/%s%s 2>&1) || printf "\\%%s\\n\\%%s\\n" "$out" "%s failed; run: ksh %s/%s"\n' \
				"$sched" "$dir" "$name" "${args:+ $args}" "$name" "$dir" "$name"
		else
			printf '%s . /root/.kyriakon-env; %s/%s%s\n' "$sched" "$dir" "$name" "${args:+ $args}"
		fi
		;;
	esac
}

# script_path <name> — where the box reads that script from at run time, which is
# what the install check and the crontab dedupe compare against. A drain row is
# installed into a directory its own config names, not one this can know, and is
# not scheduled from the table, so it has no path here.
script_path() {
	typeset row dir
	row=$(awk -F'\t' -v n="$1" '!/^#/ && $1 == n { print; exit }' "$install_set") || return 1
	[ -n "$row" ] || return 1
	dir=$(row_dir "$(printf '%s\n' "$row" | cut -f2)") || return 1
	printf '%s/%s\n' "$dir" "$1"
}

die() {
	printf 'cron-apply: %s\n' "$*" >&2
	# A failing --web pass must not leave its writer lock behind: the next run
	# takes over a dead pid's lock, but a self-test's pid is still alive.
	release_web_lock 2>/dev/null || true
	exit 1
}

# read_scheduled_scripts: set needed_scripts from the table. Called from the
# crontab path rather than at startup, because the --web lane rewrites the index
# files and never reads the table: a missing table must not fail the pass the
# drain asks for, and the installed copy finds its table beside itself.
read_scheduled_scripts() {
	[ -f "$install_set" ] || die "cannot read $install_set"
	needed_scripts=$(scheduled_scripts "$install_set") \
		|| die "$install_set has a scheduled row no cron line can run"
	[ -n "$needed_scripts" ] || die "$install_set names no scheduled script"
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
#
# The relayd half runs with them and for the same reason. relayd can only present
# a certificate its configuration names, and relayd.conf cannot include a file
# where a keypair is written (include is a top-level statement and a keypair is a
# statement inside `http protocol`), so the tracked file carries a marked region
# that scripts/relayd-members.sh fills from the member files. A certificate that
# lands after provisioning becomes a keypair line, a link relayd can load, and a
# reload on the next pass; the region is restored from a saved copy if anything
# in the batch fails, exactly as the indexes are.

httpd_d=/etc/httpd.d
gmid_d=/etc/gmid.d
acme_d=/etc/acme-client.d
httpd_conf=/etc/httpd.conf
gmid_conf=/etc/gmid.conf
relayd_conf=/etc/relayd.conf
ssl_dir=/etc/ssl
ssl_private=/etc/ssl/private
# One writer at a time for --web. The lock lives beside the deploy marker, which
# is root's directory on this box, and its shape is acme-queue.sh's run lock.
state_dir="${KYRIAKON_STATE_DIR:-/var/db/kyriakon}"
web_lock="$state_dir/cron-apply-web.lock"

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

# regen_keypairs: the member keypair region of relayd.conf, rewritten from the
# member files. Returns 0 when the region changed, 1 when it did not and 2 when
# there is no relayd.conf to rewrite (a box that has not run
# scripts/deploy-relayd.sh has no 443 at all, so there is nothing to key).
#
# The saved copy is taken before the write, and only kept when the region
# changed, so a failure later in the pass can put the region the running relay
# was started from back, for the reason restore_indexes exists.
regen_keypairs() {
	[ -f "$relayd_conf" ] || return 2
	if [ "$check_only" = yes ]; then
		set -- --check "$relayd_conf"
	else
		set -- "$relayd_conf"
	fi
	result=$(RELAYD_MEMBERS_HTTPD_D="$httpd_d" \
		RELAYD_MEMBERS_SSL_DIR="$ssl_dir" \
		RELAYD_MEMBERS_SSL_PRIVATE="$ssl_private" \
		ksh "$script_dir/relayd-members.sh" "$@") \
		|| {
			rm -f "$relayd_conf.saved.$$"
			die "$relayd_conf could not have its member keypair region rendered, so nothing was reloaded"
		}
	case "$result" in
	changed) return 0 ;;
	*) return 1 ;;
	esac
}

restore_keypairs() {
	[ -f "$relayd_conf.saved.$$" ] || return 0
	mv "$relayd_conf.saved.$$" "$relayd_conf"
}

# take_web_lock: the lock is one file created with noclobber, so a create only
# succeeds when no lock file exists and the old mkdir-plus-pid pair cannot be
# observed half-built. The takeover rule is acme-queue.sh's: a lock whose pid is
# gone, or whose contents are not a live pid at all, is removed and the create
# is retried, so a reboot cannot wedge the web lane. Returns 1 with the holder's
# pid on stderr when a live pass owns it: the caller has to retry, because that
# pass writes the indexes and this one would otherwise report success having
# written none of them.
take_web_lock() {
	typeset holder
	mkdir -p "$state_dir" \
		|| die "could not create $state_dir, so no index was rewritten"
	if ! (set -C; printf '%s\n' "$$" > "$web_lock") 2>/dev/null; then
		holder=$(cat "$web_lock" 2>/dev/null || true)
		if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
			printf 'another --web pass holds %s (pid %s); retry when it has finished\n' \
				"$web_lock" "$holder" >&2
			return 1
		fi
		rm -f "$web_lock"
		(set -C; printf '%s\n' "$$" > "$web_lock") 2>/dev/null \
			|| die "could not take $web_lock, and no live process holds it"
	fi
	return 0
}

release_web_lock() {
	[ -n "${web_lock:-}" ] || return 0
	# Only a lock this process wrote. Removing another pass's lock would be the
	# second writer this exists to prevent.
	[ "$(cat "$web_lock" 2>/dev/null || true)" = "$$" ] || return 0
	rm -f "$web_lock"
}

apply_web() {
	changed=""
	acme_changed=""
	keypairs_changed=no
	# A check writes nothing, so it needs no lock and must not block a live pass.
	# A pass that loses the lock exits non-zero: the holder writes the indexes,
	# and this pass has not, so the caller must retry rather than settle.
	if [ "$check_only" = no ]; then
		take_web_lock || return 1
	fi
	# The relayd region, from the same directory, rendered before any index is
	# written. A render that fails dies inside regen_keypairs, and doing it first
	# is what keeps that failure from leaving a new index on disk for a daemon
	# that was never told to read it. --check passes --check through to the
	# helper, so a dry run writes neither the file nor the certificate links it
	# makes.
	if [ -f "$relayd_conf" ] && [ "$check_only" = no ]; then
		cp -p "$relayd_conf" "$relayd_conf.saved.$$"
	fi
	if regen_keypairs; then
		keypairs_changed=yes
	else
		rm -f "$relayd_conf.saved.$$"
	fi
	regen_index "$httpd_d" && changed="$changed httpd"
	regen_index "$gmid_d" && changed="$changed gmid"
	# acme-client.conf's index is rewritten the same way and keeps the same saved
	# copy, but nothing is reloaded: acme-client is not a daemon, and it reads the
	# file when it next runs. The parse is still checked on the box, by the daily
	# renewal rather than here, since the check that names a bad member block is
	# acme-client itself.
	regen_index "$acme_d" && acme_changed=yes
	if [ -z "$changed" ] && [ -z "$acme_changed" ] && [ "$keypairs_changed" = no ]; then
		printf 'generated indexes: nothing to change, nothing reloaded\n'
		release_web_lock
		return 0
	fi
	printf 'indexes to rewrite:%s%s\n' "$changed" "${acme_changed:+ acme-client}"
	if [ "$keypairs_changed" = yes ]; then
		if [ "$check_only" = yes ]; then
			printf 'member keypairs: %s would change\n' "$relayd_conf"
		else
			printf 'member keypairs: %s rewritten\n' "$relayd_conf"
		fi
	fi
	if [ "$check_only" = yes ]; then
		printf '\n--check: nothing was written and nothing was reloaded.\n'
		return 0
	fi
	# Check every config before either reload. rcctl runs the same configtest, but
	# doing it here names the failing file while the daemons are still serving.
	if ! httpd -n -f "$httpd_conf"; then
		restore_indexes
		restore_keypairs
		die "${httpd_conf} does not check, so the running configuration was left alone"
	fi
	if ! gmid -n -c "$gmid_conf"; then
		restore_indexes
		restore_keypairs
		die "${gmid_conf} does not check, so the running configuration was left alone"
	fi
	if [ -f "$relayd_conf" ] && ! relayd -n -f "$relayd_conf"; then
		restore_indexes
		restore_keypairs
		die "${relayd_conf} does not check, so the running configuration was left alone"
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
		rcctl reload "$d" || { restore_indexes; restore_keypairs; die "rcctl reload $d failed"; }
		rm -f "$idx.saved.$$"
	done
	if [ "$keypairs_changed" = yes ]; then
		rcctl reload relayd || { restore_indexes; restore_keypairs; die "rcctl reload relayd failed"; }
		rm -f "$relayd_conf.saved.$$"
	fi
	rm -f "$httpd_d/index.conf.saved.$$" "$gmid_d/index.conf.saved.$$" \
		"$acme_d/index.conf.saved.$$"
	if [ -n "$changed" ]; then
		printf 'reloaded:%s\n' "$changed"
	fi
	if [ -n "$acme_changed" ]; then
		printf 'acme-client index rewritten; it reads the file at its next run, so nothing was reloaded\n'
	fi
	release_web_lock
}

# self_test — apply_web against a tree of its own, with the two daemons and rcctl
# stubbed. It runs the real function, because what is being checked is what the
# function does with the indexes when a reload fails, and that is not something a
# fixture can be asked about separately.
self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$(dirname "$0")/lib.sh"
	typeset tree stub code index_before gmid_before got installed
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	# The daemons pass their configtest and rcctl fails only when told to, so the
	# box's own configuration is never parsed and its daemons are never signalled.
	stub="$tree/bin"
	mkdir "$stub"
	printf '#!/bin/sh\nexit 0\n' > "$stub/httpd"
	printf '#!/bin/sh\nexit 0\n' > "$stub/gmid"
	printf '#!/bin/sh\nexit 0\n' > "$stub/relayd"
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
	chmod 0755 "$stub/httpd" "$stub/gmid" "$stub/relayd" "$stub/rcctl"
	PATH="$stub:$PATH"
	export PATH

	httpd_d="$tree/httpd.d"
	gmid_d="$tree/gmid.d"
	acme_d="$tree/acme.d"
	httpd_conf="$tree/httpd.conf"
	gmid_conf="$tree/gmid.conf"
	relayd_conf="$tree/relayd.conf"
	ssl_dir="$tree/ssl"
	ssl_private="$ssl_dir/private"
	state_dir="$tree/state"
	web_lock="$state_dir/cron-apply-web.lock"
	mkdir -p "$httpd_d" "$gmid_d" "$acme_d" "$ssl_private"
	printf 'server "parish.example" {}\n' > "$httpd_d/parish.conf"

	# One member whose certificate is already on disk and one whose certificate
	# has not landed: the first must gain a relayd keypair line and the second
	# must not, because a line relayd cannot load fails its config check.
	cat > "$relayd_conf" <<'EOF'
http protocol "kyriakon-https" {
	tls keypair "kyriakon.net"
	# --- BEGIN member keypairs ---
	# --- END member keypairs ---
}
EOF
	: > "$httpd_d/alice.kyriakon.net.conf"
	: > "$httpd_d/bob.kyriakon.net.conf"
	printf 'certificate\n' > "$ssl_dir/alice.kyriakon.net.fullchain.pem"
	printf 'key\n' > "$ssl_private/alice.kyriakon.net.key"

	# The first pass writes the indexes and reloads, which is the state everything
	# below is about.
	STUB_RCCTL_FAIL=no
	export STUB_RCCTL_FAIL
	apply_web > "$tree/first.out" 2>&1
	check "the first pass reloads the daemon whose index changed" \
		"$(grep -c '^reloaded: httpd' "$tree/first.out")" 1
	check "a member whose certificate is present gains a relayd keypair" \
		"$(grep -c 'tls keypair "alice.kyriakon.net"' "$relayd_conf")" 1
	check "and one whose certificate has not landed gains none" \
		"$(grep -c 'bob.kyriakon.net' "$relayd_conf")" 0
	check "the region gained a reload of its own" \
		"$(grep -c 'member keypairs: .* rewritten' "$tree/first.out")" 1
	check "the tracked keypair is untouched" \
		"$(grep -c 'tls keypair "kyriakon.net"' "$relayd_conf")" 1
	check "a pass releases its writer lock" \
		"$([ -e "$web_lock" ] && printf yes || printf no)" no
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
	set -- "$tree"/relayd.conf.saved.*
	check "and the relayd region keeps no saved copy" "$([ -e "$1" ] && printf yes || printf no)" no

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

	# A certificate that lands after provisioning, which is the case this lane
	# exists for: no member file appears, so no index changes, and only the relayd
	# region and relayd's own reload are due. The pass before it settles the gmid
	# retry the half test left pending.
	STUB_RCCTL_FAIL=no
	export STUB_RCCTL_FAIL
	apply_web > /dev/null 2>&1
	printf 'certificate\n' > "$ssl_dir/bob.kyriakon.net.fullchain.pem"
	printf 'key\n' > "$ssl_private/bob.kyriakon.net.key"
	apply_web > "$tree/relayd.out" 2>&1
	check "a certificate that lands later adds the member's keypair" \
		"$(grep -c 'tls keypair "bob.kyriakon.net"' "$relayd_conf")" 1
	check "and the pass rewrites the region" \
		"$(grep -c 'member keypairs: .* rewritten' "$tree/relayd.out")" 1
	check "with no index rewritten" "$(grep -c '^reloaded:' "$tree/relayd.out")" 0

	# A keypair render that fails must leave the indexes as they were. The render
	# runs before any index is written, so a relayd.conf the helper cannot read
	# (here, one without its markers) cannot leave a new index on disk for a
	# daemon that was never told to read it, while exiting non-zero.
	printf 'server "later.example" {}\n' > "$httpd_d/later.conf"
	index_before=$(cat "$httpd_d/index.conf")
	printf 'http protocol "kyriakon-https" {\n}\n' > "$relayd_conf"
	relayd_before=$(cat "$relayd_conf")
	code=0
	( set -e; apply_web ) > "$tree/render-failed.out" 2>&1 || code=$?
	check "a keypair render that fails is a failure" \
		"$([ "$code" -ne 0 ] && printf yes || printf no)" yes
	check "and names the region it could not render" \
		"$(grep -c 'member keypair region rendered' "$tree/render-failed.out")" 1
	check "and the index was not rewritten" "$(cat "$httpd_d/index.conf")" "$index_before"
	check "and the relayd config keeps its bytes" "$(cat "$relayd_conf")" "$relayd_before"
	check "and no writer lock is left" \
		"$([ -e "$web_lock" ] && printf yes || printf no)" no
	set -- "$relayd_conf".saved.*
	check "and no saved copy is left" "$([ -e "$1" ] && printf yes || printf no)" no

	# Two concurrent --web passes must not drop each other's keypair. The second
	# pass writes nothing while a live pid holds the lock, and it exits non-zero
	# so the caller retries instead of settling on a pass that wrote no index.
	cat > "$relayd_conf" <<'EOF'
http protocol "kyriakon-https" {
	tls keypair "kyriakon.net"
	# --- BEGIN member keypairs ---
	# --- END member keypairs ---
}
EOF
	mkdir -p "$state_dir"
	printf '%s\n' "$$" > "$web_lock"
	printf 'server "blocked.example" {}\n' > "$httpd_d/blocked.conf"
	index_before=$(cat "$httpd_d/index.conf")
	code=0
	apply_web > "$tree/locked.out" 2>&1 || code=$?
	check "a pass that loses the writer lock is a failure" \
		"$([ "$code" -ne 0 ] && printf yes || printf no)" yes
	check "and names the holder's pid" \
		"$(grep -c "(pid $$)" "$tree/locked.out")" 1
	check "and writes nothing" \
		"$(grep -vc '(pid ' "$tree/locked.out")" 0
	check "and leaves the index alone" "$(cat "$httpd_d/index.conf")" "$index_before"
	check "and leaves the holder's lock alone" "$(cat "$web_lock")" "$$"

	# A lock left by a pass that died is taken over, so a reboot or a killed run
	# cannot wedge the web lane for ever.
	printf '%s\n' 999999 > "$web_lock"
	apply_web > "$tree/takeover.out" 2>&1
	check "a dead pass's lock is taken over" \
		"$(grep -c 'blocked.conf' "$httpd_d/index.conf")" 1
	check "and the pass releases the lock" \
		"$([ -e "$web_lock" ] && printf yes || printf no)" no

	# An empty or corrupt lock is a dead holder's too, not one to join. Leaving
	# it in place would make every later pass read it as live forever.
	printf 'server "empty-lock.example" {}\n' > "$httpd_d/empty-lock.conf"
	: > "$web_lock"
	apply_web > "$tree/empty-lock.out" 2>&1
	check "an empty lock is taken over" \
		"$(grep -c 'empty-lock.conf' "$httpd_d/index.conf")" 1
	check "and released" "$([ -e "$web_lock" ] && printf yes || printf no)" no
	printf 'not-a-pid\n' > "$web_lock"
	printf 'server "corrupt-lock.example" {}\n' > "$httpd_d/corrupt-lock.conf"
	apply_web > "$tree/corrupt-lock.out" 2>&1
	check "a corrupt lock is taken over" \
		"$(grep -c 'corrupt-lock.conf' "$httpd_d/index.conf")" 1
	check "and released" "$([ -e "$web_lock" ] && printf yes || printf no)" no

	check "the checkout-run checks have lines of their own" \
		"$(line_for check-hygiene.sh | grep -c 'scripts/check-hygiene.sh')" 1
	check "and the self-test runner has one" \
		"$(line_for self-test-all.sh | grep -c 'scripts/self-test-all.sh')" 1
	# shellcheck disable=SC2016 # the generated line is what is matched
	check "a clean weekly run prints nothing to cron" \
		"$(line_for check-hygiene.sh | grep -c 'out=$(ksh')" 1
	# shellcheck disable=SC2016 # as above
	check "and a failing one keeps its output in the mail" \
		"$(line_for check-hygiene.sh | grep -cF '"$out"')" 1
	# crontab(5) ends the command at the first unescaped %, so every percent
	# that has to reach printf is rendered as \%. A line with a bare one runs a
	# truncated printf and the mail is a syntax error instead of a finding.
	check "no unescaped percent reaches the crontab" \
		"$(line_for check-hygiene.sh | grep -c '[^\\]%')" 0
	check "and the percents printf needs are escaped" \
		"$(line_for check-hygiene.sh | grep -oF '\%s' | wc -l | tr -d ' ')" 2
	check "and does not throw the run away" \
		"$(line_for check-hygiene.sh | grep -c '>/dev/null')" 0
	# Both are rows rather than arms here, so the table is what decides they are
	# scheduled and where they are read from.
	check "the checkout scripts are the table's checkout rows" \
		"$(install_rows "$install_set" checkout | paste -sd ' ' -)" \
		"check-hygiene.sh self-test-all.sh"
	check "a checkout row's schedule comes from the row" \
		"$(line_for self-test-all.sh | cut -d' ' -f1-5)" '0 5 * * 1'
	check "and its path is the checkout's scripts" \
		"$(script_path check-hygiene.sh)" "$repo_dir/scripts/check-hygiene.sh"
	got=0
	script_path kyriakon-control-drain >/dev/null || got=$?
	check "a name with no scheduled row has no path" "$got" 1

	# A checkout row with arguments carries them, the same way an installed
	# row's do, and the failure line names the command that ran.
	printf 'probe.sh\tcheckout\t0 5 * * 1\t--box\n' > "$tree/checkout-args.tsv"
	install_set="$tree/checkout-args.tsv"
	check "a checkout row's arguments reach the line" \
		"$(line_for probe.sh | grep -cF 'scripts/probe.sh --box')" 1
	check "and the failure names the command" \
		"$(line_for probe.sh | grep -cF "ksh $repo_dir/scripts/probe.sh --box")" 1
	# A row scheduled for a destination no cron line can read is refused here,
	# rather than becoming a line that cannot run.
	printf 'probe.sh\tdrain\t0 5 * * 1\n' > "$tree/mixed.tsv"
	got=0
	( scheduled_scripts "$tree/mixed.tsv" ) > "$tree/mixed.out" 2>&1 || got=$?
	check "a scheduled drain row is refused" \
		"$([ "$got" -ne 0 ] && printf yes || printf no)" yes
	check "and names the row and its destination" \
		"$(grep -c 'probe.sh is scheduled for drain' "$tree/mixed.out")" 1
	install_set="$script_dir/install-set.tsv"

	# An installed script's line is its install-set row, so the row's schedule and
	# arguments have to reach the crontab unchanged, and a row that has neither a
	# schedule nor a row at all has to produce no line.
	check "an installed script's line carries its row's schedule" \
		"$(line_for backup.sh | cut -d' ' -f1-5)" '30 2 * * *'
	check "and the row's arguments" \
		"$(line_for acme-queue.sh)" \
		"$(printf '%s . /root/.kyriakon-env; /root/bin/acme-queue.sh --run' '*/15 * * * *')"
	check "a row with no arguments gets no trailing one" \
		"$(line_for renew-acme.sh)" \
		"$(printf '%s . /root/.kyriakon-env; /root/bin/renew-acme.sh' '0 3 * * *')"
	got=0
	line_for lib.sh >/dev/null || got=$?
	check "a /root/bin helper has no cron line" "$got" 1
	got=0
	line_for no-such-script.sh >/dev/null || got=$?
	check "a script with no row has no cron line" "$got" 1
	check "the scheduled set is the table's rows" \
		"$(scheduled_scripts "$install_set" | grep -c '^lib\.sh$')" 0

	# The table and the two lanes. A missing table has to fail the crontab pass
	# and name the file; the web pass must run without it, which is what keeps the
	# drain's --web call working while the table install has not landed.
	install_set="$tree/absent.tsv"
	got=0
	( read_scheduled_scripts ) >"$tree/absent.out" 2>&1 || got=$?
	check "a missing table fails the crontab pass" \
		"$([ "$got" -ne 0 ] && printf yes || printf no)" yes
	check "and names the file it could not read" \
		"$(grep -c 'cannot read' "$tree/absent.out")" 1
	check_only=yes
	code=0
	apply_web >"$tree/web-no-table.out" 2>&1 || code=$?
	check "the web pass runs without the table" \
		"$([ "$code" -eq 0 ] && printf yes || printf no)" yes
	check "and never reads it" "$(grep -c 'absent.tsv' "$tree/web-no-table.out")" 0
	check_only=no
	install_set="$script_dir/install-set.tsv"

	# The installed layout: deploy-control.sh copies the table's drain rows, the
	# table itself and lib.sh into the drain's directory, and that copy reads the
	# table from its own directory. Its own self-test is the probe, and it covers
	# both lanes from there. The guard is a file only the checkout has, so the copy
	# cannot spawn another copy of itself.
	if [ -f "$script_dir/self-test-all.sh" ]; then
		installed="$tree/installed"
		mkdir "$installed"
		for s in $(install_rows "$script_dir/install-set.tsv" drain); do
			cp "$script_dir/$s" "$installed/" \
				|| die "cannot copy $s into the installed-layout probe"
		done
		cp "$script_dir/install-set.tsv" "$installed/"
		code=0
		ksh "$installed/cron-apply.sh" --self-test >"$tree/installed.out" 2>&1 || code=$?
		check "the installed copy, with its table beside it, passes its own self-test" \
			"$([ "$code" -eq 0 ] && printf yes || printf no)" yes
	fi

	self_test_end
}

if [ "$self_test_mode" = yes ]; then
	self_test
fi

if [ "$web_only" = yes ]; then
	apply_web
	exit 0
fi

read_scheduled_scripts
current=$(crontab -l 2>/dev/null || true)

missing_scripts=""
to_add=""
pending=$(mktemp)
: >"$pending"
for s in $needed_scripts; do
	path=$(script_path "$s") || die "$install_set names $s for no destination this schedules"
	[ -f "$path" ] || missing_scripts="$missing_scripts $s"
	if ! printf '%s\n' "$current" | grep -qF "$path"; then
		to_add="$to_add $s"
		line_for "$s" >>"$pending"
	fi
done

# The drain, checked at its own installed path. A line whose binary the deploy
# never installed is caught here rather than added for cron to fail on in
# silence.
if [ ! -x "$drain_bin" ]; then
	missing_scripts="$missing_scripts kyriakon-control-drain"
fi
if ! printf '%s\n' "$current" | grep -qF "$drain_bin"; then
	to_add="$to_add kyriakon-control-drain"
	line_for kyriakon-control-drain >>"$pending"
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
	line_for kyriakon-control-drain
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
	die "install the missing scripts first: scripts/deploy-control.sh installs the drain and the mail deploy the rest"
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
# The rename in #633 moved the drain's binary. This script only ever adds lines,
# so the old one would stay and point at a path the deploy removes once the
# crontab is clean; a line cron cannot run mails the operator every minute.
# `before` keeps the real old crontab, so the backup and the --check diff show
# the removal.
printf '%s\n' "$current" | grep -vF '/usr/local/sbin/kyriakon-onboard-drain' > "$work" || true
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
# The two that run from the checkout are on cron too, and a summary that left
# them out read as if a clean run had scheduled nothing new.
printf 'the checkout-run checks:\n'
crontab -l | grep -E 'scripts/(check-hygiene|self-test-all)\.sh' | awk '{ print "\t" $0 }'
printf '\nrevert with: crontab %s\n' "$bak"
