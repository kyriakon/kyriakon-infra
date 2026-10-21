#!/bin/ksh
# lib.sh: shared helpers for the scripts that run on the box (backup.sh,
# restore-test.sh, rehearsal.sh, abuse-monitor.sh, check-hygiene.sh,
# check-keyring-drift.sh, renew-acme.sh, restore-standup.sh, acme-queue.sh).
# Source it
# from the script's own directory:
#
#   . "$(dirname "$0")/lib.sh"
#
# Deployed alongside each script (install both into the same dir; the crontab
# examples assume /root/bin/<script> and /root/bin/lib.sh).

# cron(8) runs jobs with PATH=/usr/bin:/bin, and OpenBSD keeps packages under
# /usr/local. Without this the nightly run dies at its first restic call with
# "restic: not found" and nothing reaches the storage box. Set here rather than
# in each caller so backup.sh, restore-test.sh and rehearsal.sh cannot drift.
PATH="/usr/local/bin:$PATH"
export PATH

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

# Per-box values, so nothing has to be retyped or passed on a command line:
# /root/.kyriakon-env, mode 0600, one 'export VAR=value' per line. The tracked
# template is openbsd/etc/kyriakon.env in the repo, which deploy-mail.sh installs.
# Sourced rather than parsed, which is also how the cron lines read it, so the two
# cannot disagree about the format. Override the path with KYRIAKON_ENV.
KYRIAKON_ENV="${KYRIAKON_ENV:-/root/.kyriakon-env}"
export KYRIAKON_ENV
if [ -r "$KYRIAKON_ENV" ]; then
	# shellcheck disable=SC1090 # the path is the operator's, not a fixed literal
	. "$KYRIAKON_ENV"
fi


# dnsbl_verdict <ip> — ask the blocklists what they make of an address, and print one
# line naming both the verdict and the list that gave it:
#
#   listed <zone> <answer>   that list has the address
#   clean <zone>             that list has no record of it
#   unchecked <why>          no list answered
#
# Always returns 0, so a caller running under `set -e` reads the verdict instead of
# trapping on it, and so nothing is tempted to treat a status as the finding.
#
# One zone was not enough, and a single zone is how this went wrong. zen.spamhaus.org
# is the list that matters for deliverability and it refuses to answer any resolver
# serving more than one machine, which is this box's system resolver, a workstation's
# and every public resolver tried on 2026-09-23. A refusal is 127.255.255.x and a
# listing is 127.0.0.x, so the old code reported "cannot check" and "clean" in the same
# breath, and mailed the first of those every cooldown. The zones below are ordered
# strongest first, the first to answer wins, and the verdict names it, because a
# listing on SpamCop is not a listing on Spamhaus and the reader needs to know which.
dnsbl_zones="${DNSBL_ZONES:-${DNSBL_ZONE:-zen.spamhaus.org bl.spamcop.net all.s5h.net dnsbl.dronebl.org}}"

dnsbl_verdict() {
	dnsbl_ip="$1"
	dnsbl_rev=$(printf '%s\n' "$dnsbl_ip" | awk -F. '{ print $4"."$3"."$2"."$1 }')
	# A resolver serving one machine is answered by everyone; a shared one is not.
	# Patient on purpose, three tries at five seconds. This probe is itself the first
	# query after a boot, so it is the one query that primes the root while the cache
	# is empty, and a two-second version gave up on a resolver with nothing wrong with
	# it. That is the 2026-10-05 alert: the box had just rebooted, the probe failed,
	# the check fell through to the system resolver, Spamhaus ignored it by design,
	# and the operator was told to go and look at a healthy unbound. A slow run here
	# costs nothing, and a week of runs is still one query a quarter hour.
	if dig +short +time=5 +tries=3 @127.0.0.1 . NS >/dev/null 2>&1; then
		dnsbl_at="@127.0.0.1"
	else
		dnsbl_at=""
	fi
	dnsbl_skipped=""
	for dnsbl_zone in $dnsbl_zones; do
		# Prove the zone answers at all before trusting its silence. Every DNSBL
		# publishes a test entry for this, 2.0.0.127, and the reason is exactly the
		# trap here: a zone with no record and a zone that does not exist both
		# answer NXDOMAIN, so without the control a typo in the list would read as
		# clean forever, and silence from a zone refusing this resolver would read
		# as clean too. A zone that fails its own control is skipped rather than
		# believed.
		# shellcheck disable=SC2086 # deliberately empty or one argument
		dnsbl_ctl=$(dig +short +time=10 +tries=3 $dnsbl_at "2.0.0.127.$dnsbl_zone" A 2>/dev/null | head -1 || true)
		case "$dnsbl_ctl" in
		127.0.0.*) ;;
		127.255.255.*)
			# Answered, and the answer is a refusal: the zone is up and will not
			# serve this resolver. Recording which happened separates it from a zone
			# that said nothing at all, and the two need different advice, because
			# one is a policy and the other is DNS on this box.
			dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=refused"
			continue
			;;
		*)
			dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=silent"
			continue
			;;
		esac
		# shellcheck disable=SC2086 # deliberately empty or one argument
		dnsbl_out=$(dig +time=10 +tries=3 $dnsbl_at "$dnsbl_rev.$dnsbl_zone" A 2>/dev/null || true)
		dnsbl_status=$(printf '%s\n' "$dnsbl_out" | awk '/status:/ { s=$6; sub(/,.*/, "", s); print s; exit }')
		dnsbl_answer=$(printf '%s\n' "$dnsbl_out" \
			| awk -F'[ \t]+' '/IN[ \t]+A[ \t]+/ && $1 !~ /^;/ { print $5; exit }')
		case "$dnsbl_status:$dnsbl_answer" in
		NOERROR:127.0.0.*)
			printf 'listed %s %s\n' "$dnsbl_zone" "$dnsbl_answer"
			return 0
			;;
		NOERROR:127.255.255.*)
			# The zone refusing the resolver after passing its own control, which a
			# proxy between here and there would explain. Not a verdict.
			dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=refused"
			continue
			;;
		NOERROR:|NXDOMAIN:)
			# Answered, and no record for this address: the verdict this whole
			# function exists to be able to give.
			printf 'clean %s%s\n' "$dnsbl_zone" "${dnsbl_skipped:+ [skipped:$dnsbl_skipped]}"
			return 0
			;;
		*)
			# The status says which kind of nothing this was. SERVFAIL is what
			# Spamhaus's zones look like through QNAME minimisation, because their
			# NS and SOA answers do not match RFC 1034 and minimisation needs them;
			# a bare timeout carries no status at all.
			case "$dnsbl_status" in
			SERVFAIL) dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=servfail" ;;
			REFUSED) dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=refused" ;;
			"") dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=no-answer" ;;
			*) dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=$dnsbl_status" ;;
			esac
			continue
			;;
		esac
	done
	printf 'unchecked no zone answered%s\n' "${dnsbl_skipped:+ [skipped:$dnsbl_skipped]}"
	return 0
}

# --- operator mail ---------------------------------------------------------
#
# notify_operator <component> <event> <found> [<what to do>]
#
# The one way a scheduled script tells the operator something, so the shape
# cannot drift per script. The subject names the component and the event, both
# drawn from the vocabulary below, and the body says what ran, when, what it
# found and what to do about it. The subject is the part that has to hold: an
# operator triaging a crowded mailbox sorts and filters on it, and a mail whose
# subject says nothing is read last, if at all.
#
# The components, one word per thing the box runs, the same word in every mail
# about it. onboard/src/notice.rs builds the identical shape for the drain:
#
#   onboard  the signup service: the handler, the drain and the store
#   mail     smtpd, dovecot, and the accounts and allowances behind them
#   spamd    the greylisting and blocking layer in front of smtpd
#   ssh      sshd, and the keys and accounts it admits
#   acme     certificate issuance, renewal and the queue
#   backup   the nightly restic snapshot and the weekly restore test
#   keyring  the published mail keys the encrypting LMTP reads
#   host     the box itself: filesystems, snapshots and the hygiene checks
#
# Never fails the caller, for the reason ping_url gives: an alert that cannot be
# sent must not become a second failure stacked on the one being reported, and a
# script that dies on its own alert is silent about the failure it was
# reporting. Mail that could not be sent is printed instead, so cron's own mail
# still carries it, under cron's subject, which hides the component and is
# still better than silence.
notify_operator() {
	# Locals, so a caller's own variables of any name survive the call. The
	# scripts that source this one run under `set -u`, and a helper that left a
	# stray variable behind would be a bug in a script nowhere near it.
	typeset component="$1" event="$2" found="$3" todo="${4:-}" subject body
	subject="kyriakon: $component: $event"
	body="$found"
	if [ -n "$todo" ]; then
		body="$body

what to do: $todo"
	fi
	body="$body

run: $0 on $(hostname) at $(date '+%F %T')"
	if [ -n "${ALERT_EMAIL:-}" ] &&
		printf '%s\n' "$body" | mail -s "$subject" "$ALERT_EMAIL" >/dev/null 2>&1; then
		return 0
	fi
	printf '%s\n\n%s\n' "$subject" "$body" >&2
	return 0
}

# --- self-tests ------------------------------------------------------------
#
# A --self-test is the one check a script can run without the box's own state, so
# most scripts carry one. These three pieces are the shape, kept here rather than
# copied into each: the scratch directory and its cleanup, the assertion, and the
# summary that makes the exit status mean something.
#
# Source lib.sh from inside self_test, not at the top of the script: the live path
# takes no new dependency, and the drain's copies of these scripts run without
# lib.sh beside them.
#
#   self_test_begin                     # sets $self_test_work, clears the count
#   check "what it proves" "$got" "$want"
#   self_test_end                       # prints the summary, exits 0 or 1

self_test_begin() {
	self_test_fails=0
	self_test_work=$(mktemp -d "${TMPDIR:-/tmp}/kyriakon-self-test.XXXXXX") || exit 1
	# Expanded now rather than at exit: the function's locals are gone by then.
	# shellcheck disable=SC2064
	trap "rm -rf '$self_test_work'" EXIT
}

check() {
	if [ "$2" = "$3" ]; then
		printf 'ok: %s\n' "$1"
	else
		printf 'FAIL: %s: expected [%s], got [%s]\n' "$1" "$3" "$2"
		self_test_fails=$((self_test_fails + 1))
	fi
}

self_test_end() {
	if [ "${self_test_fails:-0}" -ne 0 ]; then
		printf '\nself-test: %s check(s) failed\n' "$self_test_fails" >&2
		exit 1
	fi
	printf '\nself-test: every check passed\n'
	exit 0
}
