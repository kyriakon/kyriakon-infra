#!/bin/ksh
# abuse-monitor.sh: cron-driven abuse + health monitoring for the mail box.
#
# Watches ten signals (spec §30-33, plus the release additions in issue #173 and
# the certificate queue in issue #288), each tripping a content-rich alert:
#   1. outbound mail volume: relayed message count (MTA sessions), and the
#      per-account submission cap, which lapses an account above 50 recipients
#      in a run and alerts
#   2. auth failures: smtpd + dovecot (maillog), sshd (authlog), and the
#      applicant sshd's admissions per source, which are what the second
#      public listener adds to authlog
#      mail-side: a real member at one, an unknown username above a bound; ssh
#      per source address
#   3. quota approach: per-user edquota usage vs soft limit
#   4. spamd greylist/blocklist: greylist churn + new TRAPPED (blacklisted) hosts
#   5. senders deferred from several addresses: mail lost to a rotating retry IP
#   6. IP reputation blocklist: reversed-IPv4 A lookup on a DNSBL, and whether the
#      strongest list was the one that answered
#   7. drain: intents filed and left unapplied
#   8. backup recency: a restic snapshot inside the last 26 hours
#   9. root filesystem: / filling, and any filesystem with none left
#  10. certificate queue: the age of the oldest pending certificate request
#
# The per-account cap counts sessions that authenticated on an egress listener,
# smtps or the auth-optional STARTTLS one. A local enqueue logs "smtp connected
# address=local" and never authenticates, so cron, sendmail(1) and the future
# _mlmmj mailing-list lane, which enqueues on /var/run/smtpd.sock, cannot trip a
# member cap: a parish announcement list fans out on its own lane and is not one
# member's submission. An account outside the members group, or a member account
# in wheel, is alerted but never lapsed: lapse-user.sh empties every secondary
# group, which would take doas from the operator.
#
# The numbers all come from the dogfood logs, baselined in
# docs/planning/research/alert-thresholds.md (PR #179, read 2026-10-01). Each
# one below carries its basis, because that window is short: the whole box has
# 35 days of logs, the mail platform 12, and /var/log/maillog only 8, because
# /etc/newsyslog.conf keeps seven daily files. A value the window cannot
# support is marked as a bound rather than a fit.
#
# Plus the dead-man's switch (§34/35): a Healthchecks.io ping on a clean run.
# If this script stops running, or the box goes silent, Healthchecks alerts from
# OUTSIDE the box (the only channel that still works when the box is compromised).
# Findings go out as mail to ALERT_EMAIL and mark that same check down, so the
# external channel carries them too.
#
# Env (all optional; the script degrades to stderr output):
#   ALERT_EMAIL            the one address to mail alerts to, off this box, so an
#                          alert survives this box being the broken thing. One
#                          address and not a list: a list mails every name in it,
#                          which is how an alert about the mail box ends up in a
#                          mailbox on that same box. check-hygiene flags an
#                          address at a domain this box accepts.
#   MAIL_PROBE_MAX         failed SMTP/IMAP logins per run for usernames that do
#                          not exist here before alerting (default 50). With no
#                          members there is no mailbox to enter, so a scanner
#                          probing one is background and a bound is the signal.
#   HEALTHCHECKS_URL       this box's check: a ping every run, with the finding's
#                          component attached to the event log and never the
#                          member or address detail, which stays in the mail.
#                          Not /fail, because a finding is not an outage;
#                          silence is what marks it down.
#   PUBLIC_IP              IPv4 for the DNSBL check (default: auto-detect from `ifconfig egress`)
#   DNSBL_ZONES            blocklists to query, strongest first (default in lib.sh:
#                          zen.spamhaus.org bl.spamcop.net all.s5h.net dnsbl.dronebl.org)
#   MAIL_SPIKE_MAX         outbound msgs per run that counts as a spike (default 50)
#   MAIL_SENDER_RCPT_MAX   outbound recipients one authenticated account may
#                          submit per run before the account is lapsed (default 50)
#   AUTH_FAIL_MAX          failed ssh logins, or applicant admissions, from one
#                          address before alert (default 300)
#   QUOTA_WARN_PCT         quota usage % of soft limit that trips the alert (default 80)
#   GREY_MAX               spamd greylist entries before "flood" alert (default 100)
#   DEFER_MIN              distinct addresses one sender may be deferred from before it alerts (default 6)
#   ONBOARD_DIR            the store the drain applies intents from
#                          (default /var/db/onboard, the store drain.toml names)
#   DRAIN_INTENT_MAX_MIN   minutes an intent may sit unapplied (default 240)
#   ACME_QUEUE_DIR         the certificate queue store, whose pending/ directory
#                          this reads for the oldest request (default
#                          /var/db/kyriakon-acme-queue; scripts/acme-queue.sh
#                          files the requests into it)
#   ACME_PENDING_MAX_MIN   minutes the oldest certificate request may wait before
#                          the alert (default 1440)
#   SNAPSHOT_MAX_AGE_HOURS age at which the latest restic snapshot is stale (default 26)
#   ROOT_FS_WARN_PCT       usage % on / that trips the alert (default 80)
#   DAEMONLOG              spamd's verbose log, carrying greylist envelopes (default /var/log/daemon)
#   ALERT_COOLDOWN_MINUTES alert suppression window, per signal (default 60)
#   STATE_DIR              state-file dir, created 0700 with its files 0600
#                          (default /var/db/kyriakon-monitor)
#
# Runs as root (reads /var/log/*, spamdb, quota, and the backup repository).
# Every threshold is deliberately a tunable, not fixed. Log-line formats below
# are pinned to OpenBSD 7.x sources and were checked against the live box on
# 2026-10-01.

set -euo pipefail

script_dir="$(dirname "$0")"
if [ ! -f "$script_dir/lib.sh" ]; then
	printf '%s: lib.sh is not in %s. Install the two files together, as lib.sh describes.\n' \
		"$0" "$script_dir" >&2
	exit 1
fi

# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
. "$script_dir/lib.sh"

# Where lapse-user.sh lives. It is a drain script, not a /root/bin one: the
# monitor runs from /root/bin and the circuit breaker calls the copy the drain
# installs, the same one its non-payment sweep runs. The directory comes from the
# drain's config the way acme-queue.sh reads it, with the compiled-in default for
# a box whose config cannot be read. DRAIN_SCRIPTS points it at a copy;
# LAPSE_USER_SH names the script itself, which is what --self-test uses.
drain_toml="${DRAIN_TOML:-/etc/kyriakon/onboard/drain.toml}"
drain_scripts="${DRAIN_SCRIPTS:-/usr/local/libexec/kyriakon/scripts}"
if [ -z "${DRAIN_SCRIPTS:-}" ] && [ -r "$drain_toml" ]; then
	configured_scripts=$(awk -F'"' '/^scripts[[:space:]]*=/ { print $2; exit }' "$drain_toml")
	[ -z "$configured_scripts" ] || drain_scripts=$configured_scripts
fi

# The group lookup the breaker's safety check uses. ID_CMD points it at a stub in
# --self-test, the way LAPSE_USER_SH points the lapse at one.
id_cmd=${ID_CMD:-id}

# A storm keeps a signal true for hours, and telling the operator the same thing
# every hour is how an alert channel stops being read. These are the ones a
# stranger can hold true indefinitely: a source working through a list of
# usernames, one opening applicant sessions in a loop, and a spamtrap campaign.
# Everything else fires on a condition that has to be dealt with, so the shorter
# default suits it.
cooldown_for() {
	case "$1" in
	"ssh guesses" | "ssh applicant admissions" | "spamd blocklist")
		printf '%s' "${STORM_COOLDOWN_MINUTES:-360}"
		;;
	*) printf '%s' "${alert_cooldown:-60}" ;;
	esac
}

# source_tally <failures|admissions> — read authlog lines on stdin and print
# "<worst> <high> <total>": the source address with the most matching lines, its
# count, and the count from every address.
#
# The address is the token before the last "port", rather than the token after
# the first "from": scanners do try usernames like "from" and "port", and either
# one would otherwise be read as the address.
#
# failures counts one line per attempt. An attempt against an unknown username
# writes two lines for the one event, "Invalid user X from IP port N" and
# "Failed password for invalid user X from IP port N", so the "Invalid user"
# line is taken for an unknown username and the "Failed password" line only when
# it does not also name an invalid user, which is the attempt against a real
# account.
#
# admissions anchors on the "Accepted" line naming hello, which is the account
# the applicant sshd serves: the applicant's "Accepted none for hello from
# <address> port <n> ssh2" and the member port's "Accepted publickey for hello
# from <address> port <n> ssh2: <type> SHA256:<fingerprint>". It takes neither a
# member's own login on 22 nor the operator's, which name their own accounts,
# and not the "Postponed publickey" or "Failed publickey" lines the member port
# writes at VERBOSE for a key it tests or refuses: those name hello without a
# connection being admitted, and the failure tally already counts them.
#
# A failed password against hello is written "Failed password for hello from"
# and is the failure tally's line, never an admission.
source_tally() {
	awk -v mode="$1" '
		{
			keep = 0
			if (mode == "failures") {
				keep = ($0 ~ /Invalid user/ || ($0 ~ /Failed password/ && $0 !~ /invalid user/))
			} else if (mode == "admissions") {
				keep = ($0 ~ /Accepted (none|publickey) for hello from/)
			}
			if (keep) {
				ip = ""
				for (i = NF; i >= 2; i--) if ($i == "port") { ip = $(i-1); break }
				if (ip != "") { n[ip]++; t++ }
			}
		}
		END {
			worst = ""; high = 0
			for (ip in n) if (n[ip] > high) { high = n[ip]; worst = ip }
			printf "%s %d %d\n", worst, high, t+0
		}'
}

# mail_auth_events <member-usernames> — read maillog lines on stdin and print one
# "<kind>\t<user>\t<source>" per failed SMTP/IMAP login, kind real or unknown.
#
# real means the username names a member, which is the case the alert text was
# written for: a client or phone still sending a password that was changed. It is
# the only case worth a mail at one, because it has an owner who can fix it.
# Everything else is a scanner trying a name with no mailbox behind it; a single
# attempt is background, so those are counted and compared with MAIL_PROBE_MAX.
#
# The two log forms differ. smtpd writes "smtp authentication user=X
# result=permfail|tempfail" and no source address. Dovecot writes "(auth failed,
# N attempts in M secs)" with user=<X> and rip=<address>.
mail_auth_events() {
	awk -v members="$1" '
		BEGIN {
			# Exact equality, not a substring of the joined list: with members
			# "alice bob carol", the substring test called "alice bob" real.
			n = split(members, m, /[[:space:]]+/)
			for (i = 1; i <= n; i++) if (m[i] != "") member[m[i]] = 1
		}
		function user_of(line,   s) {
			if (match(line, /user=<[^>]*>/)) {
				s = substr(line, RSTART + 6, RLENGTH - 7)
				return s
			}
			if (match(line, /user=[^ ,]+/)) {
				s = substr(line, RSTART + 5, RLENGTH - 5)
				return s
			}
			return ""
		}
		function source_of(line,   s) {
			if (match(line, /rip=[0-9A-Fa-f:.]+/))
				return substr(line, RSTART + 4, RLENGTH - 4)
			return ""
		}
		{
			if ($0 ~ /smtp authentication user=.*result=(perm|temp)fail/) {
				user = user_of($0)
				source = ""
			} else if ($0 ~ /auth failed, [0-9]+ attempts in/) {
				user = user_of($0)
				source = source_of($0)
			} else {
				next
			}
			# A localpart cannot contain a space, so a name that parses with one
			# is never a member, whatever a substring of the list would say.
			kind = "unknown"
			if (user != "" && user !~ /[[:space:]]/ && (user in member))
				kind = "real"
			printf "%s\t%s\t%s\n", kind, user, source
		}'
}

# sender_recipients <maillog> — read this run's maillog lines on stdin and print
# "<user> <recipients>", one line per account, for messages accepted on a
# session that authenticated as that account.
#
# The join key is the session id OpenSMTPD prefixes to every line of a session.
# The account comes from "smtp authentication user=X result=ok" and the volume
# from "smtp message ... nrcpt=N" on the same id. The whole current maillog is
# read for the authentication half, because a session can authenticate in one
# run and send in the next; only the lines on stdin are counted, so the tally is
# still this run's window. The one session this misses is one that authenticates
# before the daily rotation and sends after it, a window of minutes at most.
#
# nrcpt is the recipient count the server accepted for the message, and it is
# one line per message. The "smtp envelope ... to=<...>" lines carry the same
# recipients one per line, so counting both would double the tally.
#
# A message whose session never authenticated is not counted. That is every
# local enqueue: the socket and lo0 listeners log "smtp connected address=local"
# and have no authentication, so cron, sendmail(1) and the future _mlmmj list
# lane on /var/run/smtpd.sock cannot trip a member cap. Inbound mail from other
# MTAs is unauthenticated for the same reason.
sender_recipients() {
	awk -v maillog_path="$1" '
		BEGIN {
			while ((getline line < maillog_path) > 0) {
				if (line !~ /smtp authentication user=/) continue
				id = ""; user = ""; ok = 0
				n = split(line, f, " ")
				for (i = 1; i <= n; i++) {
					if (f[i] == "smtp") id = f[i - 1]
					else if (f[i] ~ /^user=/) user = substr(f[i], 6)
					else if (f[i] == "result=ok") ok = 1
				}
				if (ok && id != "" && user != "") user_of[id] = user
			}
			close(maillog_path)
		}
		/smtp message / && / nrcpt=/ {
			id = ""; nrcpt = 0
			n = split($0, f, " ")
			for (i = 1; i <= n; i++) {
				if (f[i] == "smtp") id = f[i - 1]
				else if (f[i] ~ /^nrcpt=/) nrcpt = substr(f[i], 7) + 0
			}
			if (id != "" && (id in user_of) && nrcpt > 0)
				count[user_of[id]] += nrcpt
		}
		END { for (u in count) printf "%s %d\n", u, count[u] }
	'
}

# lapse_refusal <user> <members> — print why the account must not be lapsed, or
# nothing when it may be.
#
# The breaker must never take doas from the operator. lapse-user.sh runs
# `usermod -S ''`, which empties every secondary group, so a wheel account loses
# wheel, and on a box with PermitRootLogin no the alert's own recovery command
# can no longer be run. An account outside the members group is refused for the
# same class of reason: it is not a member mailbox, and emptying its groups would
# break whatever it is for. Both are alerted without being lapsed.
lapse_refusal() {
	case " ${2:-} " in
	*" $1 "*) ;;
	*) printf 'is not in the members group'; return 0 ;;
	esac
	user_groups=$("${ID_CMD:-$id_cmd}" -Gn "$1" 2>/dev/null || true)
	case " $user_groups " in
	*" wheel "*) printf 'is privileged (wheel)' ;;
	esac
	return 0
}

# enforce_sender_cap <max> <tally> <members> — for each "<user> <recipients>"
# line over max, lapse that account and alert, unless lapse_refusal refuses it.
#
# The window is the cron interval: the tally is what the account submitted since
# the last run, and the next run starts it again. The action is
# scripts/lapse-user.sh, the primitive the drain's non-payment sweep already
# uses: auth-smtp=reject stops submission while IMAP and the site keep working.
# It leaves the account record alone, so `lapse-user.sh --restore <username>`
# hands it back after the password is changed.
#
# A failed lapse stops the run and still alerts. The account is still sending,
# and carrying on would report the next one while this one relays; the nonzero
# exit is what leaves the dead-man's switch to alert on silence.
enforce_sender_cap() {
	sender_max="$1"; tally="${2:-}"; member_list="${3:-}"
	[ -n "$tally" ] || return 0
	while read -r user count; do
		[ -n "$user" ] || continue
		[ "${count:-0}" -gt "$sender_max" ] || continue
		refusal=$(lapse_refusal "$user" "$member_list")
		if [ -n "$refusal" ]; then
			alert mail "sender cap held $user" "$user is over the cap at $count outbound recipients since last run (max $sender_max) but $refusal; not lapsed. Outbound submission is still open; inspect the account and stop it by hand if it is compromised"
			continue
		fi
		# The lapse's output goes through a file rather than `$(... 2>&1)`:
		# ksh93 leaves the substitution's stderr redirection in place afterwards,
		# so the alert raised next would have its own stderr swallowed.
		lapse_out_file="$state/lapse.out"
		if ksh "${LAPSE_USER_SH:-$drain_scripts/lapse-user.sh}" "$user" >"$lapse_out_file" 2>&1; then
			lapse_rc=0
		else
			lapse_rc=$?
		fi
		lapse_out=$(cat "$lapse_out_file")
		rm -f "$lapse_out_file"
		if [ "$lapse_rc" -eq 0 ]; then
			alert mail "sender cap $user" "$user submitted $count outbound recipients since last run (max $sender_max), so its submission was lapsed with scripts/lapse-user.sh. Mail still arrives and the site stays up; change the password, then run scripts/lapse-user.sh --restore $user"
		else
			# A distinct event key, so this alert cannot sit inside the successful
			# lapse's cooldown and leave "still open" as the last mail.
			alert mail "sender cap fail $user" "$user submitted $count outbound recipients since last run (max $sender_max) and the lapse FAILED: $lapse_out. Outbound submission is still open; run scripts/lapse-user.sh $user by hand" "" fail
			printf 'abuse-monitor: could not lapse %s after %s recipients: %s\n' "$user" "$count" "$lapse_out" >&2
			exit 1
		fi
	done <<EOF
$tally
EOF
}

# Entries in the first list that are not in the second. Files rather than strings,
# so a caller can hand it a state file and a fresh dump.
new_entries() {
	awk 'NR == FNR { old[$0] = 1; next } NF && !($0 in old) { print }' "$2" "$1"
}

newest_snapshot_epoch() {
	# Reads `restic snapshots --json` on stdin and prints the newest snapshot time
	# as an epoch, or nothing if none can be read.
	#
	# restic writes each time as RFC3339. The form depends on the zone the snapshot
	# was taken in: this box is UTC and restic gives it as
	# "2026-10-01T13:00:09.510876011Z", while a machine in a named zone gets a
	# numeric offset, which can be written +02:00 or +0200. date -j -f takes %z as
	# Z, +hhmm or +hh:mm, so the fraction is dropped, Z becomes +0000, and an
	# offset with a colon loses it.
	typeset newest time epoch
	newest=""
	# The value is taken by matching around it rather than by field position: restic
	# prints each object on its own line today, but nothing in the format promises
	# that, and a field number that reads the key instead of the value would parse
	# as empty and silence the check.
	#
	# Every match on a line is taken, not the first, and that is what this check got
	# wrong a second time on 2026-10-05: restic 0.19 prints the whole array on one
	# line, and a single match() per line read only the first object in it. With
	# --latest 1 returning one snapshot per group and the older group listed first,
	# the newest time was never seen, so the box reported the old payload's snapshot
	# from 18 September as the latest while the real one was minutes old. The
	# fixtures below were multi-line, so the self-test agreed with the bug.
	for time in $(awk '
		{
			line = $0
			while (match(line, /"time"[ \t]*:[ \t]*"[^"]+"/)) {
				value = substr(line, RSTART, RLENGTH)
				sub(/^"time"[ \t]*:[ \t]*"/, "", value)
				sub(/"$/, "", value)
				print value
				line = substr(line, RSTART + RLENGTH)
			}
		}' 2>/dev/null || true); do
		# The offset is applied by arithmetic rather than handed to `date -j -f %z`,
		# because OpenBSD's date ignores the offset: 2026-10-03T02:30:01+02:00 parsed
		# there as 02:30:01 UTC, two hours out, and the self-test caught it on the box
		# while passing on the machine the case was written on. Splitting the string
		# into a naive part and an offset in seconds behaves the same on both, and UTC
		# is what the subtraction is against.
		time=$(printf '%s' "$time" | sed 's/\.[0-9]*//; s/Z$/+00:00/')
		naive=$(printf '%s' "$time" | sed 's/[+-][0-9][0-9]:[0-9][0-9]$//')
		offset=$(printf '%s' "$time" | sed -n 's/.*\([+-]\)\([0-9][0-9]\):\([0-9][0-9]\)$/\1 \2 \3/p' | tr -d ' ')
		epoch=$(date -u -j -f "%Y-%m-%dT%H:%M:%S" "$naive" +%s 2>/dev/null || true)
		[ -n "$epoch" ] || continue
		if [ -n "$offset" ]; then
			# "+" means the instant is the naive reading less the offset.
			secs=$(( (10#$(printf '%s' "$offset" | cut -c2-3) * 60 + 10#$(printf '%s' "$offset" | cut -c4-5)) * 60 ))
			case "$offset" in
			-*) epoch=$((epoch + secs)) ;;
			*) epoch=$((epoch - secs)) ;;
			esac
		fi
		if [ -z "$newest" ] || [ "$epoch" -gt "$newest" ]; then
			newest="$epoch"
		fi
	done
	[ -n "$newest" ] && printf '%s' "$newest"
	return 0
}

# --- new_lines: emit log lines appended since last run -------------------
# Line-offset delta is rotation-safe and needs no date parsing: cron interval
# IS the detection window. First run only baselines (no historical replay).
#
# An absent or unreadable log returns 1, which the caller reads as a failed
# check: the outbound, sender-cap and mail-auth alerts read the maillog, and treating a lost one as an
# empty one let the run ping Healthy with all six blind. Defined above the
# self-test dispatch so --self-test drives the real function.
new_lines() {
	log="$1"; posfile="$2"
	[ -f "$log" ] && [ -r "$log" ] || return 1
	cur=$(wc -l < "$log" | tr -d ' ')
	[ "$cur" -gt 0 ] || return 0
	if [ ! -f "$posfile" ]; then
		printf '%s\n' "$cur" > "$posfile"
		return 0
	fi
	prev=$(cat "$posfile")
	if [ "$cur" -lt "$prev" ]; then
		tail -n +1 "$log"        # newsyslog rotated/truncated: rescan the new file
	elif [ "$cur" -gt "$prev" ]; then
		tail -n +"$(( prev + 1 ))" "$log"
	fi
	printf '%s\n' "$cur" > "$posfile"
}

# --- alert: content-rich mail, plus the external check --------------------
# Alerts go out as mail to ALERT_EMAIL, an address off this box, and the same
# event marks the Healthchecks check down so the external channel carries it too.
#
# Two channels because they fail differently. Mail is what can describe a finding:
# the check's dashboard shows a stored body but the notification itself does not
# repeat it. And the check is what survives this box being the broken thing: mail
# cannot report a broken mail path, and the check's silence covers that case.
#
# alert <component> <event> <body> [<what to do>] [<check: ok|fail>]: the
# component and the event are the two words the subject carries, from the
# vocabulary notify_operator in lib.sh lists, so a list of subjects says what
# happened without any of them being opened. The check argument is the state to
# leave the external check in, ok by default; fail is for a run that could not do
# its job, which today is the circuit breaker's own lapse failing.
#
# Nothing is printed for an alert. The mail is the report, and cron mails what a
# job prints, so a print would be the same finding a second time under a subject
# of cron's own. The line that used to be printed here was that second copy;
# notify_operator prints instead when it could not mail, so an alert raised while
# the mail path is broken still reaches the operator, ugly and once.
#
# The cooldown is per signal, one file named from the component and the event. It
# used to be one file for all six checks, so the first to fire silenced the rest
# for the hour, and the baseline note found that in the state directory: an
# address making hundreds of ssh guesses trips every quarter hour, which held the
# channel shut and is why the ssh threshold could not be lowered. The single file
# the old code wrote, $state/alert.last, is left where it is and no longer read,
# and the file names changed when the subject did, so the first run after this
# deploys may fire once on a signal that was inside its cooldown.
#
# It is defined above the self-test dispatch so a --self-test exercises the real
# cooldown and notification path rather than a stand-in.
alert() {
	component="$1"; event="$2"; body="$3"; to_do="${4:-}"
	now=$(date +%s)
	last_file="$state/alert.last.$(printf '%s-%s' "$component" "$event" | tr 'A-Z ' 'a-z-' | tr -cd 'a-z0-9-')"
	last=0
	[ -f "$last_file" ] && last=$(cat "$last_file")
	if [ "$(( now - last ))" -lt "$(( $(cooldown_for "$component $event") * 60 ))" ]; then
		return 0
	fi
	printf '%s\n' "$now" > "$last_file"
	when=$(date '+%F %T')
	notify_operator "$component" "$event" "$body" "$to_do"
	# The check's event log is a third party's and the operator's notice names
	# only Stripe and Hetzner, so nothing that names a member or an address goes
	# here: the body is the timestamp and the component, and every identifying
	# detail stays in the mail above. The event string is left out with it because
	# a sender-cap event carries the username, and one body shape has to be safe
	# for every caller.
	#
	# A finding is not an outage, so the default is the success URL: pinging /fail
	# marked the dead-man's switch down and the ping at the end of the same run
	# brought it straight back up, which mailed "is UP, the downtime lasted 0
	# seconds" every time the monitor had something to say. The check means "the
	# monitor is running". A run that cannot do its job passes fail and exits
	# nonzero; the alert pings /fail itself because it runs before that exit, and
	# a success ping here would mark the check up on the one run that must not
	# look clean.
	if [ -n "${HEALTHCHECKS_URL:-}" ]; then
		check_url="$HEALTHCHECKS_URL"
		[ "${5:-ok}" = "fail" ] && check_url="$HEALTHCHECKS_URL/fail"
		curl -fsS -m 10 --retry 3 --data "$when $component" \
			"$check_url" >/dev/null 2>&1 || true
	fi
}

# log_failure <paths>: the report for a run whose log it could not read. The
# caller exits non-zero after this, which skips the dead-man's-switch ping, and
# the alert marks the check down itself: a run that cannot see what it is
# checking is a finding, the shape check-keyring-drift.sh uses for a missing
# keyring.
log_failure() {
	alert mail "log unreadable" \
		"cannot read $1, so the signals that read it did not run and this run is not a clean one" \
		"restore it, or point MAILLOG/AUTHLOG at the file the service writes, and check the rotation that removed it" fail
}

# state_dir <dir>: create the monitor's state directory private, and tighten one
# an older run left group- or world-readable. umask 077 then covers every file
# this run writes: deferred-senders holds correspondents' envelope senders and
# spamd-trapped-list every blocked host, and no local unprivileged process has
# any business reading either.
state_dir() {
	install -d -m 0700 "$1"
	chmod 0700 "$1"
	umask 077
}

# state_write <file>: write stdin to a state file only root can read. The chmod
# covers a file an older run left 0644; umask 077 only covers new ones.
state_write() {
	cat > "$1"
	chmod 0600 "$1"
}

# drain_backlog <intents-dir> <max-minutes>: alert when the oldest unapplied
# intent has waited past the drain's limit. A missing intents/ directory is a
# finding, not a quiet pass: the check exists for a drain that stopped, and a
# store with no intents/ is the one shape a healthy drain never has. Returning 1
# stops the run the way an unreadable log does.
drain_backlog() {
	typeset intents="$1" max_min="$2" oldest pending age_min
	if [ ! -d "$intents" ]; then
		alert control "drain store" "$intents is missing, so the drain backlog could not be read. scripts/control-store.sh creates it on a box running the control plane, so this is the drain's half not deployed or the store root moved" "run scripts/control-store.sh, or point ONBOARD_DIR at the store root drain.toml names" fail
		return 1
	fi
	oldest=$(find "$intents" -type f -exec stat -f '%m' {} + 2>/dev/null \
		| awk 'NR == 1 || $1 < m { m = $1 } END { print m }' || true)
	[ -n "$oldest" ] || return 0
	pending=$(find "$intents" -type f 2>/dev/null | wc -l | tr -d ' ')
	age_min=$(( ( $(date +%s) - oldest ) / 60 ))
	if [ "$age_min" -gt "$max_min" ]; then
		alert control "drain backlog" "$pending unapplied intent(s) in the store, oldest $age_min minutes (max $max_min). The drain is the service's privileged half; an intent this old is a member whose payment or approval was accepted and who still has no account"
	fi
	return 0
}

self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	work=$self_test_work
	# Two groups, the newer one with the larger time, and the older listed first:
	# the shape that produced the false "364 hours old". Written the way restic
	# 0.19 actually prints it, on one line, because the multi-line form is what let
	# the check agree with itself while reading only the first object.
	two_groups='[{"time":"2026-09-18T14:42:12.000000000Z","paths":["/home"]},{"time":"2026-10-03T02:30:01.000000000Z","paths":["/etc/mail","/home"]}]'
	expect=$(date -j -f "%Y-%m-%dT%H:%M:%S%z" "2026-10-03T02:30:01+0000" +%s)
	check "the newest of two groups is chosen" \
		"$(printf '%s' "$two_groups" | newest_snapshot_epoch)" "$expect"

	# One group, both stale: the newest of them is still what is reported.
	both_old='[{"time":"2026-09-18T14:42:12.000000000Z"},{"time":"2026-09-19T02:30:01.000000000Z"}]'
	expect_old=$(date -j -f "%Y-%m-%dT%H:%M:%S%z" "2026-09-19T02:30:01+0000" +%s)
	check "an all-stale repository reports its newest" \
		"$(printf '%s' "$both_old" | newest_snapshot_epoch)" "$expect_old"

	# The same times spread over lines, which is what `jq` prints if anyone ever
	# pipes the listing through it: one match per line has to keep working.
	spread='[
	{
		"time": "2026-09-18T14:42:12.000000000Z"
	},
	{
		"time": "2026-10-03T02:30:01.000000000Z"
	}
]'
	check "a listing spread over lines parses too" \
		"$(printf '%s' "$spread" | newest_snapshot_epoch)" "$expect"

	# A named-zone offset, which restic writes off this box.
	offset='{"snapshots":[{"time":"2026-10-03T04:30:01.000000000+02:00"}]}'
	check "a numeric offset parses" \
		"$(printf '%s' "$offset" | newest_snapshot_epoch)" "$expect"

	check "nothing to parse prints nothing" \
		"$(printf '%s' '' | newest_snapshot_epoch)" ""

	# The trap diff: one new entry is churn and has to stay quiet, several at once
	# is the burst the signal is for.
	printf '%s\n' '10.0.0.1' '10.0.0.2' '10.0.0.3' > "$work/old"
	printf '%s\n' '10.0.0.1' '10.0.0.2' '10.0.0.3' '10.0.0.9' > "$work/new1"
	check "one new trap entry is seen" "$(new_entries "$work/new1" "$work/old" | tr '\n' ' ')" "10.0.0.9 "
	printf '%s\n' '10.0.0.1' '10.0.0.2' '10.0.0.3' '10.0.0.9' '10.0.0.10' '10.0.0.11' > "$work/new3"
	check "three new trap entries are seen" "$(new_entries "$work/new3" "$work/old" | grep -c .)" "3"
	check "an unchanged list has none" "$(new_entries "$work/old" "$work/old" | grep -c .)" "0"

	# The cooldown two signals get for being holdable by a stranger.
	check "a storm signal waits six hours" "$(cooldown_for "ssh guesses")" "360"
	check "an admission flood gets the storm cooldown" "$(cooldown_for "ssh applicant admissions")" "360"
	check "an ordinary signal waits the default hour" "$(cooldown_for "quota")" "60"

	# The authlog split: the applicant sshd's two admission forms, a
	# member's own login on 22 and the operator's, an unknown username's usual
	# pair of failure lines, and the hello lines that are not admissions (the
	# member port's Postponed and Failed publickey, and a failed password). The
	# admission count takes the two Accepted hello lines and nothing else; the
	# failure tally is the pair folded to one attempt, plus the failed password.
	cat > "$work/authlog" <<'AUTHLOG'
Oct 27 09:00:01 mail sshd-session[1]: Accepted none for hello from 203.0.113.9 port 40000 ssh2
Oct 27 09:00:02 mail sshd-session[2]: Accepted publickey for hello from 203.0.113.9 port 40001 ssh2: ED25519 SHA256:aaaa
Oct 27 09:00:03 mail sshd-session[3]: Accepted publickey for oliver from 198.51.100.7 port 22 ssh2: ED25519 SHA256:bbbb
Oct 27 09:00:04 mail sshd-session[4]: Accepted publickey for root from 198.51.100.8 port 22 ssh2: ED25519 SHA256:cccc
Oct 27 09:00:05 mail sshd-session[5]: Invalid user admin from 192.0.2.5 port 55555
Oct 27 09:00:05 mail sshd-session[5]: Failed password for invalid user admin from 192.0.2.5 port 55555 ssh2
Oct 27 09:00:06 mail sshd-session[6]: Postponed publickey for hello from 203.0.113.9 port 40002 ssh2: ED25519 SHA256:dddd
Oct 27 09:00:07 mail sshd-session[6]: Failed publickey for hello from 203.0.113.9 port 40002 ssh2: ED25519 SHA256:eeee
Oct 27 09:00:08 mail sshd-session[7]: Failed password for hello from 192.0.2.5 port 40003 ssh2
AUTHLOG
	check "the admission count takes only the Accepted hello lines" \
		"$(source_tally admissions < "$work/authlog")" "203.0.113.9 2 2"
	check "the failure tally still counts the pair as one attempt" \
		"$(source_tally failures < "$work/authlog")" "192.0.2.5 2 2"

	# The mail-side split: a failure naming a member is the stale-client case and
	# alerts at one; a name with no member behind it is a scanner and is bounded
	# instead. The two log forms carry different fields, and smtpd's successful
	# authentication is in the fixture to prove it is not counted at all.
	cat > "$work/maillog" <<'MAILLOG'
Nov  7 11:00:01 mail smtpd[1]: 0000000000000001 smtp authentication user=admin result=permfail
Nov  7 11:00:02 mail smtpd[1]: 0000000000000002 smtp authentication user=alice result=ok
Nov  7 11:00:03 mail smtpd[1]: 0000000000000003 smtp authentication user=alice result=permfail
Nov  7 11:00:04 mail dovecot: imap-login: Info: Disconnection (auth failed, 1 attempts in 0 secs): user=<alice>, method=PLAIN, rip=192.0.2.5, lip=203.0.113.1
Nov  7 11:00:05 mail dovecot: imap-login: Info: Disconnection (auth failed, 2 attempts in 1 secs): user=<nobody>, method=PLAIN, rip=198.51.100.7, lip=203.0.113.1
MAILLOG
	check "a member's failures are told apart from scanner usernames" \
		"$(mail_auth_events alice < "$work/maillog" | awk -F'\t' '{ printf "%s:%s:%s ", $1, $2, $3 }')" \
		"unknown:admin: real:alice: real:alice:192.0.2.5 unknown:nobody:198.51.100.7 "

	# A username that is a run of adjacent member names is not a member. The test
	# against the space-joined list was a substring match, so with members
	# "alice bob carol" it called "alice bob" real and the alert named an account
	# string that is not an account.
	spaced='Nov  7 11:00:04 mail dovecot: imap-login: Info: Disconnection (auth failed, 1 attempts in 0 secs): user=<alice bob>, method=PLAIN, rip=203.0.113.9, lip=203.0.113.1'
	check "a space-joined run of member names is unknown" \
		"$(printf '%s\n' "$spaced" | mail_auth_events "alice bob carol" | awk -F'\t' '{ print $1 }')" \
		"unknown"
	member_line='Nov  7 11:00:05 mail dovecot: imap-login: Info: Disconnection (auth failed, 1 attempts in 0 secs): user=<bob>, method=PLAIN, rip=203.0.113.9, lip=203.0.113.1'
	check "and an exact member name in the same list is still real" \
		"$(printf '%s\n' "$member_line" | mail_auth_events "alice bob carol" | awk -F'\t' '{ print $1 }')" \
		"real"

	# The per-account recipient cap. The account comes from the session's
	# successful authentication and the volume from nrcpt on the same session id.
	# The window fixture deliberately carries no authentication line: the map is
	# built from the whole maillog, because a session can authenticate in one run
	# and send in the next.
	cat > "$work/cap-maillog" <<'CAPLOG'
Nov  7 11:00:01 mail smtpd[1]: 00000000000000a1 smtp connected address=203.0.113.9 host=client
Nov  7 11:00:02 mail smtpd[1]: 00000000000000a1 smtp authentication user=alice result=ok
Nov  7 11:00:03 mail smtpd[1]: 00000000000000a2 smtp connected address=198.51.100.7 host=phone
Nov  7 11:00:04 mail smtpd[1]: 00000000000000a2 smtp authentication user=bob result=ok
Nov  7 11:00:05 mail smtpd[1]: 00000000000000a3 smtp connected address=local host=mail
Nov  7 11:00:06 mail smtpd[1]: 00000000000000a4 smtp connected address=203.0.113.44 host=scan
Nov  7 11:00:07 mail smtpd[1]: 00000000000000a4 smtp authentication user=alice result=permfail
CAPLOG
	cat > "$work/cap-window" <<'CAPWINDOW'
Nov  7 11:01:01 mail smtpd[1]: 00000000000000a1 smtp message msgid=00000001 size=100 nrcpt=30 proto=ESMTP
Nov  7 11:01:02 mail smtpd[1]: 00000000000000a2 smtp message msgid=00000002 size=100 nrcpt=20 proto=ESMTP
Nov  7 11:01:03 mail smtpd[1]: 00000000000000a3 smtp message msgid=00000003 size=100 nrcpt=100 proto=ESMTP
Nov  7 11:01:04 mail smtpd[1]: 00000000000000a4 smtp message msgid=00000004 size=100 nrcpt=40 proto=ESMTP
Nov  7 11:01:05 mail smtpd[1]: 00000000000000a1 smtp message msgid=00000005 size=100 nrcpt=25 proto=ESMTP
Nov  7 11:01:06 mail smtpd[1]: 00000000000000a1 smtp envelope evpid=0000000500000001 from=<alice@kyriakon.net> to=<one@example.org>
CAPWINDOW
	check "recipients are joined to the account that authenticated the session" \
		"$(sender_recipients "$work/cap-maillog" < "$work/cap-window" | sort | tr '\n' ' ')" \
		"alice 55 bob 20 "
	check "a local socket burst is not a member submission" \
		"$(printf '%s\n' 'Nov  7 11:01:03 mail smtpd[1]: 00000000000000a3 smtp message msgid=00000003 size=100 nrcpt=100 proto=ESMTP' \
			| sender_recipients "$work/cap-maillog")" ""

	# The breaker. Over the cap lapses and alerts; under it, or with no
	# attributable message, does nothing; a failed lapse alerts and exits nonzero
	# so the run is not a clean ping.
	state="$work/state"
	mkdir -p "$state"
	unset HEALTHCHECKS_URL
	cat > "$work/lapse-ok" <<'STUB'
#!/bin/sh
printf '%s\n' "$1" >>"$LAPSE_LOG"
STUB
	cat > "$work/lapse-fail" <<'STUB'
#!/bin/sh
printf '%s\n' "$1" >>"$LAPSE_LOG"
printf 'usermod: permission denied\n' >&2
exit 1
STUB
	chmod 0700 "$work/lapse-ok" "$work/lapse-fail"
	# The group lookup: wheelie is a member and also in wheel, stranger is neither.
	cat > "$work/groups" <<'STUB'
#!/bin/sh
case "$2" in
wheelie) printf '%s\n' "wheelie wheel members" ;;
*) printf '%s\n' "$2 members" ;;
esac
STUB
	chmod 0700 "$work/groups"
	export ID_CMD="$work/groups"
	cap_members="alice bob carol wheelie"
	export LAPSE_LOG="$work/lapsed"
	export LAPSE_USER_SH="$work/lapse-ok"

	# A missing log is a failed check, not a clean run. new_lines used to return 0
	# with no lines, so a lost or rotated-away maillog silenced six of the ten
	# signals and the run still pinged Healthy. The path is named and the check is
	# marked down, which is what check-keyring-drift.sh does for a missing keyring.
	unset HEALTHCHECKS_URL
	if new_lines "$work/absent-maillog" "$work/absent.pos" >/dev/null 2>&1; then missing_rc=0; else missing_rc=$?; fi
	check "a missing log is not an empty one" "$missing_rc" "1"
	check "and no offset is written for it" \
		"$([ -e "$work/absent.pos" ] && printf yes || printf no)" "no"
	log_failure "$work/absent-maillog" >"$work/logfail.out" 2>&1
	check "the failed check names the log it could not read" \
		"$(grep -c "cannot read $work/absent-maillog" "$work/logfail.out")" "1"
	check "and says the run is not a clean one" \
		"$(grep -c 'this run is not a clean one' "$work/logfail.out")" "1"

	# The alert's stderr goes through a file: ksh93 leaves a `$(... 2>&1)` around
	# a function call redirecting the shell's stderr afterwards, and notify_operator
	# is the thing being tested here.
	enforce_sender_cap 50 "$(sender_recipients "$work/cap-maillog" < "$work/cap-window")" "$cap_members" >"$work/cap.out" 2>&1
	check "the account over the cap is lapsed" "$(cat "$work/lapsed")" "alice"
	check "the account under the cap is left alone" "$(grep -c '^bob$' "$work/lapsed")" "0"
	check "the cap alert names the account" \
		"$(grep -c 'kyriakon: mail: sender cap alice' "$work/cap.out")" "1"
	check "the cap alert carries the count and the threshold" \
		"$(grep -c '55 outbound recipients since last run (max 50)' "$work/cap.out")" "1"
	enforce_sender_cap 50 "bob 20" "$cap_members" >"$work/cap.out" 2>&1
	check "an account under the cap does not alert" "$(cat "$work/cap.out")" ""
	check "an account under the cap is not lapsed" "$(cat "$work/lapsed")" "alice"
	enforce_sender_cap 50 "" "$cap_members" >"$work/cap.out" 2>&1
	check "a run with no attributable recipient does not alert" "$(cat "$work/cap.out")" ""
	# The external check must not be marked up by the alert on a failed lapse.
	# curl is stubbed, and the last argument is the URL it was asked to ping.
	mkdir -p "$work/bin"
	cat > "$work/bin/curl" <<'STUB'
#!/bin/sh
last=""
for arg in "$@"; do last=$arg; done
printf '%s\n' "$last" >>"$CURL_LOG"
STUB
	chmod 0700 "$work/bin/curl"
	export CURL_LOG="$work/curl.log"
	export PATH="$work/bin:$PATH"
	health_url="https://check.example.invalid/token"
	export HEALTHCHECKS_URL="$health_url"
	rm -f "$CURL_LOG"
	export LAPSE_USER_SH="$work/lapse-fail"
	if ( enforce_sender_cap 50 "carol 51" "$cap_members" ) >"$work/cap.out" 2>&1; then cap_rc=0; else cap_rc=$?; fi
	check "a failed lapse exits nonzero" "$cap_rc" "1"
	check "a failed lapse still alerts under its own key" \
		"$(grep -c 'kyriakon: mail: sender cap fail carol' "$work/cap.out")" "1"
	check "a failed lapse reports why" \
		"$(grep -c 'lapse FAILED: usermod: permission denied' "$work/cap.out")" "1"
	check "a failed lapse leaves the external check failed" \
		"$(cat "$CURL_LOG")" "$health_url/fail"
	rm -f "$CURL_LOG"
	export LAPSE_USER_SH="$work/lapse-ok"
	enforce_sender_cap 50 "carol 51" "$cap_members" >"$work/cap.out" 2>&1
	check "a successful lapse after a failed one is not in its cooldown" \
		"$(grep -c 'kyriakon: mail: sender cap carol' "$work/cap.out")" "1"
	check "a successful lapse leaves the external check up" "$(cat "$CURL_LOG")" "$health_url"
	unset HEALTHCHECKS_URL

	# The safety filter: an account the breaker must not touch is alerted, not
	# lapsed. A member in wheel keeps doas, and an account outside members is not
	# a member mailbox at all, operator included.
	enforce_sender_cap 50 "wheelie 51" "$cap_members" >"$work/cap.out" 2>&1
	check "a wheel account is not lapsed" "$(grep -c '^wheelie$' "$work/lapsed")" "0"
	check "a wheel account still alerts" \
		"$(grep -c 'kyriakon: mail: sender cap held wheelie' "$work/cap.out")" "1"
	check "the wheel alert says what stopped the lapse" \
		"$(grep -c 'is privileged (wheel); not lapsed' "$work/cap.out")" "1"
	enforce_sender_cap 50 "stranger 51" "$cap_members" >"$work/cap.out" 2>&1
	check "an account outside members is not lapsed" "$(grep -c '^stranger$' "$work/lapsed")" "0"
	check "an account outside members still alerts" \
		"$(grep -c 'kyriakon: mail: sender cap held stranger' "$work/cap.out")" "1"
	check "the non-member alert says what stopped the lapse" \
		"$(grep -c 'is not in the members group; not lapsed' "$work/cap.out")" "1"

	# The state directory and the two sensitive state files are root-only: the
	# directory is 0700, a loose one from an older run is tightened, and a state
	# file is 0600 whether it is new or was world-readable. The rewrite is also
	# what a later run reads back, so the state survives across runs.
	state_dir "$work/fresh-state"
	check "a fresh state directory is 0700" \
		"$(stat -f '%Lp' "$work/fresh-state")" "700"
	mkdir -p "$work/loose-state"
	chmod 0755 "$work/loose-state"
	state_dir "$work/loose-state"
	check "an existing loose state directory is tightened to 0700" \
		"$(stat -f '%Lp' "$work/loose-state")" "700"
	printf 'old\n' | state_write "$work/fresh-state/deferred-senders"
	check "a new state file is 0600" \
		"$(stat -f '%Lp' "$work/fresh-state/deferred-senders")" "600"
	chmod 0644 "$work/fresh-state/deferred-senders"
	printf 'new\n' | state_write "$work/fresh-state/deferred-senders"
	check "an existing loose state file is tightened to 0600" \
		"$(stat -f '%Lp' "$work/fresh-state/deferred-senders")" "600"
	check "and the run reads its state back" \
		"$(cat "$work/fresh-state/deferred-senders")" "new"

	# The drain backlog reads the store the drain actually owns. An intent past
	# the limit alerts, and never names its file; an empty backlog is silent; a
	# missing intents/ directory is a named failure rather than a clean pass.
	mkdir -p "$work/onboard/intents"
	printf '{}\n' > "$work/onboard/intents/one.json"
	touch -t 202001010000 "$work/onboard/intents/one.json"
	drain_backlog "$work/onboard/intents" 240 >"$work/drain.out" 2>&1
	check "a pending intent past the limit alerts" \
		"$(grep -c 'kyriakon: control: drain backlog' "$work/drain.out")" "1"
	check "and the alert carries the count, not the filename" \
		"$(grep -c '1 unapplied intent' "$work/drain.out")" "1"
	rm -f "$work/onboard/intents/one.json"
	drain_backlog "$work/onboard/intents" 240 >"$work/drain.out" 2>&1
	check "an empty backlog does not alert" "$(cat "$work/drain.out")" ""
	if drain_backlog "$work/absent-store/intents" 240 >"$work/drain.out" 2>&1; then
		drain_rc=0
	else
		drain_rc=$?
	fi
	check "a missing intents directory is a named failure" "$drain_rc" "1"
	check "and the failure names the directory" \
		"$(grep -c "$work/absent-store/intents is missing" "$work/drain.out")" "1"

	# The Healthchecks body is a third party's, and the operator's notice names
	# only Stripe and Hetzner: an alert that names an account and an address must
	# send neither. curl is stubbed to record its whole command line, and the
	# operator mail is captured separately by notify_operator's ALERT_EMAIL-unset
	# fallback, so the detail can only be in the mail.
	cat > "$work/bin/curl" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$CURL_LOG"
STUB
	chmod 0700 "$work/bin/curl"
	rm -f "$CURL_LOG"
	export HEALTHCHECKS_URL="$health_url"
	alert mail "sender cap bob" \
		"bob submitted 55 recipients since last run (max 50) from 203.0.113.9" \
		>"$work/privacy.out" 2>&1
	check "the check is still pinged" "$(grep -c "$health_url" "$CURL_LOG")" "1"
	check "the check body carries no username" "$(grep -c 'bob' "$CURL_LOG")" "0"
	check "the check body carries no address" \
		"$(grep -c '203\.0\.113\.9' "$CURL_LOG")" "0"
	check "the operator mail still names the account" \
		"$(grep -c 'sender cap bob' "$work/privacy.out")" "1"
	unset HEALTHCHECKS_URL

	# A cold resolver must be retried rather than skipped past, which is the
	# 2026-10-05 alert: the box had just rebooted, the probe gave up, the query fell
	# through to the system resolver, Spamhaus ignored that by design, and the verdict
	# came from the next list down, which reads as a downgrade of the strongest one.
	# The stub answers the root prime slowly, the way a resolver with an empty cache
	# or a slow link does, and answers nothing at all unless it is asked of the local
	# resolver, which is how a shared one looks to Spamhaus.
	mkdir -p "$work/bin"
	cat > "$work/bin/dig" <<'STUB'
#!/bin/sh
at=""; name=""; qtype=""; tmo=5
for a in "$@"; do
	case "$a" in
	@*) at="$a" ;;
	+time=*) tmo="${a#+time=}" ;;
	+*) : ;;
	*) if [ -z "$name" ]; then name="$a"; else qtype="$a"; fi ;;
	esac
done
# A shared resolver gets silence from the strongest lists, which is the fallback.
[ "$at" = "@127.0.0.1" ] || exit 0
if [ "$name" = "." ] && [ "$qtype" = "NS" ]; then
	# The deadline is the thing under test, so the stub honours +time the way the
	# real dig does and answers the prime a little slower than the old one allowed.
	sleep 3
	[ "$tmo" -ge 3 ] || exit 9
	printf 'x. 3600 IN NS a.root-servers.net.\n'
	exit 0
fi
case "$name" in
2.0.0.127.*) printf '127.0.0.2\n' ;;  # the zone answering its own control entry
*) printf ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n' ;;
esac
exit 0
STUB
	chmod 0700 "$work/bin/dig"
	export PATH="$work/bin:$PATH"
	check "a cold local resolver is retried, so the strongest list still answers" \
		"$(dnsbl_verdict 203.0.113.9)" "clean zen.spamhaus.org"

	# The operator mail's subject, which is the part an operator triages a mailbox
	# by and the part nothing else here can see. With no address there is nothing
	# to mail, so notify_operator prints instead of sending: the first line of
	# that is the subject, and the print is also the fallback a broken mail path
	# falls back to. Exported, so shellcheck sees the cross-file use in lib.sh.
	export ALERT_EMAIL=''
	check "an operator subject names the component and the event" \
		"$(notify_operator mail "self test" "the subject check" 2>&1 | head -n 1)" \
		"kyriakon: mail: self test"

	self_test_end
}

# --self-test runs the parse checks and leaves, before any signal reads a log or
# writes state, so it is safe to run as an unprivileged user on any machine.
if [ "${1:-}" = "--self-test" ]; then
	self_test
fi

# --- one run at a time ------------------------------------------------------
# mkdir is the atomic test-and-set available in base: this box has no shlock(1)
# and no flock(1), only the flock(2) syscall, which has no shell wrapper. The
# blocklist walk is patient by design, ten seconds and three tries per query over
# four zones, so a run can take minutes, and two overlapping runs would race on
# every file under $state. A lock left by a killed run is taken over once its pid
# is gone, so a reboot cannot wedge the monitor. --self-test never reaches this
# point: its dispatch is above, so an unprivileged run does not touch /var/run.
lock=/var/run/abuse-monitor.lock
if ! mkdir -m 0700 "$lock" 2>/dev/null; then
	holder=$(cat "$lock/pid" 2>/dev/null || true)
	if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
		exit 0
	fi
	rm -f "$lock/pid"
	rmdir "$lock" 2>/dev/null || true
	if ! mkdir -m 0700 "$lock" 2>/dev/null; then
		printf '%s: could not take %s, and no live process holds it\n' "$0" "$lock" >&2
		exit 1
	fi
fi
printf '%s\n' "$$" > "$lock/pid"
trap 'rm -f "$lock/pid"; rmdir "$lock" 2>/dev/null || true' EXIT

maillog="${MAILLOG:-/var/log/maillog}"
authlog="${AUTHLOG:-/var/log/authlog}"
state="${STATE_DIR:-/var/db/kyriakon-monitor}"
state_dir "$state"

alert_cooldown="${ALERT_COOLDOWN_MINUTES:-60}"
mail_spike_max="${MAIL_SPIKE_MAX:-50}"
auth_fail_max="${AUTH_FAIL_MAX:-300}"
mail_probe_max="${MAIL_PROBE_MAX:-50}"
quota_warn_pct="${QUOTA_WARN_PCT:-80}"
grey_max="${GREY_MAX:-100}"
trapped_rise_min="${TRAPPED_RISE_MIN:-3}"
trapped_max="${TRAPPED_MAX:-20}"
defer_min="${DEFER_MIN:-6}"
daemon_log="${DAEMONLOG:-/var/log/daemon}"
onboard_dir="${ONBOARD_DIR:-/var/db/onboard}"
drain_intent_max_min="${DRAIN_INTENT_MAX_MIN:-240}"
acme_queue_dir="${ACME_QUEUE_DIR:-/var/db/kyriakon-acme-queue}"
acme_pending_max_min="${ACME_PENDING_MAX_MIN:-1440}"
snapshot_max_age_hours="${SNAPSHOT_MAX_AGE_HOURS:-26}"
root_fs_warn_pct="${ROOT_FS_WARN_PCT:-80}"

# Both logs are checked before either offset moves: a run that consumed the
# maillog window and then failed on the authlog would drop those lines for good,
# because nothing replays a consumed offset.
unreadable_logs=""
[ -f "$maillog" ] && [ -r "$maillog" ] || unreadable_logs="$maillog"
[ -f "$authlog" ] && [ -r "$authlog" ] || \
	unreadable_logs="${unreadable_logs:+$unreadable_logs, }$authlog"
if [ -n "$unreadable_logs" ]; then
	log_failure "$unreadable_logs"
	exit 1
fi
new_maillog=$(new_lines "$maillog" "$state/maillog.pos") || unreadable_logs="$maillog"
new_authlog=$(new_lines "$authlog" "$state/authlog.pos") || \
	unreadable_logs="${unreadable_logs:+$unreadable_logs, }$authlog"
if [ -n "$unreadable_logs" ]; then
	log_failure "$unreadable_logs"
	exit 1
fi

# The members group add-user.sh puts every member in. The breaker uses it to
# decide who may be lapsed, and the auth split below to tell a member's stale
# client from a scanner. An account outside it, the operator mailbox included,
# is never lapsed by the breaker.
members=$(getent group members 2>/dev/null | cut -d: -f4 | tr ',' ' ' || true)

# --- 1. outbound mail-volume spike ---------------------------------------
# Outbound relay completions only (mta = relay; inbound is smtp to LMTP, not mta).
# Log line (mta_session.c): "<id> mta disconnected reason=quit messages=N".
#
# Threshold 50 per run, down from 200. The eight days of maillog the rotation
# keeps carry 0 to 4 messages per 15-minute interval, every one of them cron
# output from this box, so the value is a bound from the harm model and not a
# fit: a spam run is a step change rather than a trend, and 50 raises the alert
# inside the same interval as the first burst while sitting 12 times above the
# busiest interval seen. One unverified input, recorded in the note: whether a
# send to sixty recipients counts as one relay or sixty. That observation is
# what would move this value.
#
# This count is box-wide and takes no origin, so a local enqueue counts too and a
# mailing list fanning out through the socket can still trip it. The "mta
# disconnected" line carries only messages=N. Attributing a relay to the enqueue
# behind it means joining "mta delivery evpid" to "smtp message msgid" (the evpid
# starts with the message id), which has not been verified on this box and is not
# needed until the _mlmmj lane exists. That split is deferred to the lane; the
# per-account cap below is the member-facing exclusion.
outbound=$(printf '%s\n' "$new_maillog" \
	| awk '/mta disconnected reason=quit/ { split($0, a, "messages="); s += a[2]+0 } END { print s+0 }')
if [ "$outbound" -gt "$mail_spike_max" ]; then
	alert mail "outbound spike" "outbound: $outbound messages relayed since last run (max $mail_spike_max)"
fi

# Per-account submission cap, the signal that can act by itself. The box-wide
# count above says a spam run is happening; this says whose account it is, and
# stops it at the authenticated session before the run that would get the box
# listed. One account's password is the thing a phish takes, so the tally is by
# the authenticated `user=`, not by the envelope sender: /etc/mail/mail_from is a
# shared set of addresses, and a compromised account can submit as any of them.
#
# Threshold 50 recipients per run per account, the same number as the box-wide
# spike and for the same reason: nothing in the eight-day window goes near it,
# while a spam run clears it in one interval. It counts recipients rather than
# messages, so one send to sixty counts sixty; the note's open question about
# whether the MTA records that as one relay or sixty does not apply to `nrcpt`,
# which is the recipient count the server accepted for the message. A member
# mailing a parish from their own account trips it, which is the intended cost:
# the account is lapsed read-only, not suspended, and `--restore` puts it back.
sender_rcpt_max="${MAIL_SENDER_RCPT_MAX:-50}"
per_user=$(printf '%s\n' "$new_maillog" | sender_recipients "$maillog")
enforce_sender_cap "$sender_rcpt_max" "$per_user" "$members"

# --- 2. auth failures ----------------------------------------------------
# Split by kind, because the two mean opposite things. A mail-side failure that
# names a member is a real client getting its password wrong, and the first one
# is worth knowing about: it has an owner who can fix it. A failure that names a
# username with no member behind it cannot enter anything; before the first member
# exists every one of those is a scanner, and a single attempt is background. So
# the member case alerts at one and the scanner case only above MAIL_PROBE_MAX.
#
# The log forms and the fields they carry are in mail_auth_events above. The
# member list computed above is the group add-user.sh puts every member in, so an
# attempt on a system account is a guess like any other and not a stale client.
mail_events=$(printf '%s\n' "$new_maillog" | mail_auth_events "$members")
real_auth=$(printf '%s\n' "$mail_events" | awk -F'\t' '$1 == "real" { c++ } END { print c + 0 }')
unknown_auth=$(printf '%s\n' "$mail_events" | awk -F'\t' '$1 == "unknown" { c++ } END { print c + 0 }')
if [ "$real_auth" -gt 0 ]; then
	real_names=$(printf '%s\n' "$mail_events" | awk -F'\t' '$1 == "real" && $2 != "" { print $2 }' | sort -u | paste -sd, -)
	alert mail "auth failures" "$real_auth failed SMTP/IMAP login(s) since last run for $real_names, which is a real address here. The likeliest cause is a mail client or phone still sending an old password, and it stops when that is fixed; a stranger cannot use it"
fi
if [ "$unknown_auth" -gt "$mail_probe_max" ]; then
	probe_sources=$(printf '%s\n' "$mail_events" | awk -F'\t' '$1 == "unknown" && $3 != "" { print $3 }' | sort | uniq -c | sort -rn | head -n 3 | awk '{ printf "%s%s (%s)", sep, $2, $1; sep = ", " }')
	from_clause=""
	if [ -n "$probe_sources" ]; then
		from_clause=", busiest sources $probe_sources"
	fi
	alert mail "guesses" "$unknown_auth failed SMTP/IMAP logins since last run for usernames that do not exist here (max $mail_probe_max$from_clause). No mailbox can be entered and no member is affected; this is a scanner working through names, and it is worth a look only if the number keeps climbing"
fi

# sshd, tallied by source address, reporting the worst one and the total.
#
# The counting rules, including one line per attempt and the address taken from
# before the last "port", are in source_tally above.
#
# A failed attempt against a real account leaves no line at all now: with
# PasswordAuthentication no, sshd writes "Connection closed by authenticating
# user X [preauth]" and nothing else. Guessing at usernames is what this counts,
# and it is the case the threshold is for.
#
# Threshold 300 per run per source address, up from 10. The 35 days of authlog
# retained hold 1,797 addresses, a worst single address of 358 lines in one
# 15-minute interval (2026-09-08), 67 at worst across the last nine quieter
# days, and an address above 10 in 1,826 of 3,111 intervals, which is most of
# every day of the storm. The baseline was set against the double-counted line
# figure, so 300 here is 300 attempts rather than the ~180 the note described;
# it is kept at the baselined value rather than re-derived from eight quiet
# days. An address threshold cannot see a swarm, which is why the total is
# printed beside it and why the note leaves the total as the swarm signal.
# shellcheck disable=SC2046 # the tally is three space-separated fields by contract
set -- $(printf '%s\n' "$new_authlog" | source_tally failures)
ssh_ip=$1 ssh_high=${2:-0} ssh_total=${3:-0}
if [ "$ssh_high" -gt "$auth_fail_max" ]; then
	alert ssh "guesses" "$ssh_ip made $ssh_high failed ssh attempts since last run, out of $ssh_total from all addresses (max per address $auth_fail_max). Password auth is off everywhere, so none of this can succeed; it is worth a look only because one source is working through a list"
fi

# The applicant listener's admissions, counted beside the failures and from the
# same window. Both admitted forms name the account hello, which is what keeps a
# member's own login on 22 and the operator's out of the count; the applicant's
# is "Accepted none for hello from", the member port's "Accepted publickey for
# hello from". The member port's "Postponed publickey" and "Failed publickey"
# lines also name hello and are not admissions, which is why the anchor is the
# Accepted line rather than the account. It counts connections rather than
# applications, and the TUI's own session caps are what bound what a source can
# do with them.
#
# It is compared against the same per-address value as the failures because that
# is the number the note re-measures from these very lines once the second
# listener is live (docs/planning/research/alert-thresholds.md). Until that
# reading exists the value is the 300 the note records as pending, and no
# separate admission threshold is invented.
# shellcheck disable=SC2046 # the tally is three space-separated fields by contract
set -- $(printf '%s\n' "$new_authlog" | source_tally admissions)
onboard_ip=$1 onboard_high=${2:-0} onboard_total=${3:-0}
if [ "$onboard_high" -gt "$auth_fail_max" ]; then
	alert ssh "applicant admissions" "$onboard_ip opened $onboard_high applicant sessions since last run, out of $onboard_total from all addresses (max per address $auth_fail_max). The applicant port asks for no credential, so a source this busy is a script rather than a person; the TUI's session caps are what stop it filing, and this count is what says they are being reached"
fi

# --- 3. quota approach ---------------------------------------------------
# Threshold 80, unchanged, and inert: /home carries no quota until the hosting
# changes in issue #160 run, so `quota -u` answers "none", the awk below finds
# no line with a nonzero soft limit, and this check cannot fire. No value can
# be fitted from the dogfood window for that reason, and the day the first
# `quota -u` carries a soft limit is the day to set one against the plan
# (5 GB soft, 5.5 GB hard, issue #154) rather than against usage.
for dir in /home/*/; do
	user=$(basename "$dir")
	msg=$(quota -u "$user" 2>/dev/null | awk -v u="$user" -v p="$quota_warn_pct" '
		/^\// && $3 > 0 {
			pct = int($2 * 100 / $3)
			if (pct >= p) printf "%s at %d%% of soft limit (%d / %d blocks)", u, pct, $2, $3
			exit
		}')
	[ -n "$msg" ] && alert mail "quota" "$msg"
done

# --- 4. spamd greylist / blocklist changes -------------------------------
# spamdb dump: GREY|<ip>|... and TRAPPED|<ip>|<expire> (a host blacklisted for
# hitting a spamtrap). Greylist churn = mail flood; a NEW TRAPPED entry is a
# real event worth seeing (spam source, or worse, a legit sender got trapped).
#
# Threshold 100, down from 200, and a bound rather than a fit. Nothing samples
# the live count, so the only reading the note has is 3 GREY on 2026-09-30;
# the busiest day of the 12-day mail window created 37 tuples and the whole
# window created 90. 100 sits above any day this box has produced. A week of
# live counts once real members exist is what would set it properly.
spamdb_out=$(spamdb 2>/dev/null || true)
grey=$(printf '%s\n' "$spamdb_out" | grep -c '^GREY|' || true)
trapped=$(printf '%s\n' "$spamdb_out" | grep -c '^TRAPPED|' || true)
if [ "$grey" -gt "$grey_max" ]; then
	alert spamd "greylist" "$grey greylisted hosts (max $grey_max), possible mail flood"
fi
# Thresholds 3 new and 20 total. Trap entries carry an expiry, so the count rises
# and falls by one all day as hosts come and go, which is churn and not news: this
# alerted hourly on it until 2026-10-03, always "1 new, total 6". A burst of three
# at once, or a total that has grown past where ordinary churn sits, is the event
# worth a mail. The new hosts are named, because a legitimate sender caught in the
# trap is the case a person has to recognise rather than a number.
trapped_list=$(printf '%s\n' "$spamdb_out" | awk -F'|' '/^TRAPPED\|/ { print $2 }')
work_trapped=$(mktemp "${TMPDIR:-/tmp}/kyriakon-trapped.XXXXXX")
printf '%s\n' "$trapped_list" > "$work_trapped"
if [ -f "$state/spamd-trapped-list" ]; then
	new_trapped=$(new_entries "$work_trapped" "$state/spamd-trapped-list")
	new_count=$(printf '%s\n' "$new_trapped" | grep -c . || true)
	if [ "$new_count" -ge "$trapped_rise_min" ] || [ "$trapped" -ge "$trapped_max" ]; then
		named=$(printf '%s\n' "$new_trapped" | head -5 | tr '\n' ' ')
		alert spamd "blocklist" "$new_count new blacklisted host(s), total $trapped (burst at $trapped_rise_min, total at $trapped_max): $named"
	fi
fi
rm -f "$work_trapped"
printf '%s\n' "$trapped" > "$state/spamd-trapped"
printf '%s\n' "$trapped_list" | state_write "$state/spamd-trapped-list"

# --- 5. senders deferred from several addresses --------------------------
# Greylisting promotes an address only when a retry arrives for the same tuple,
# and a tuple is keyed on the connecting IP, so a sender that rotates its outbound
# address between retries is never promoted: it is deferred until it gives up and
# its mail bounces. Outlook.com and Exchange Online do that, and one such message
# was lost on 2026-09-20 before the nospamd exemption existed. This is the check
# that would have said so at the time.
#
# The signal sits in one log. A sender whose address has been whitelisted stops
# appearing in greylist decisions, so a real correspondent that keeps being
# deferred shows up as the same envelope-from arriving from several different
# addresses in a day. The delivery log is deliberately not consulted: maillog
# rotates daily while this one does not, so the two windows would not line up and
# a delivery older than the rotation would read as a failure to deliver.
#
# Threshold 6 per day, up from 3. Observed spam senders use 1 to 4 addresses a
# day and the one real incident (the Outlook sender above) used 11 and then 22,
# so 6 sits in the gap with margin on both sides: above every spam sender seen,
# below the two days a message was actually lost. At 3 the check reported on 8
# of the 13 days in the window. A known cost of the margin: the SendGrid bounce
# sender sitting in the live table on 2026-09-30 used 3 addresses and stays
# unreported.
#
# spamd -v (set by deploy-mail.sh) logs the envelope of every decision:
#   "... (GREY) <ip>: <from> -> <to>"
# With no -v there is nothing to count, and this reports nothing.
today=$(date '+%b %e')
flagged=$(awk -v day="$today" -v min="$defer_min" '
	$0 ~ "^" day && /\(GREY\)/ {
		f = $8; gsub(/[<>]/, "", f)
		pair = f "|" $7
		if (!(pair in seen)) { seen[pair] = 1; n[f]++ }
	}
	END { for (f in n) if (n[f] >= min) print n[f], f }
' "$daemon_log" 2>/dev/null | sort -rn || true)
# One alert for the day's set, carrying how many addresses each sender used. The
# state file is a snapshot of what has been reported, rewritten every run, so it
# prunes itself and a sender stuck for days is not news on every run.
reported=$(cat "$state/deferred-senders" 2>/dev/null || true)
if [ -n "$flagged" ] && [ "$flagged" != "$reported" ]; then
	alert spamd "deferred senders" "deferred from several addresses today: $(printf '%s' "$flagged" | tr '\n' ';'). If one is a real correspondent, add its mail ranges to /etc/mail/nospamd (docs/planning/research/spamd-greylisting.md)"
fi
printf '%s\n' "$flagged" | state_write "$state/deferred-senders"

# --- 6. IP reputation blocklist ------------------------------------------
ip="${PUBLIC_IP:-$(ifconfig egress inet 2>/dev/null | awk '/inet / { print $2; exit }')}"
if [ -n "$ip" ]; then
	verdict=$(dnsbl_verdict "$ip")
	case "$verdict" in
	listed*)
		alert mail "blocklisted" "$ip is listed: ${verdict#listed }. That code names the list, which the verdict names too; look it up and request removal. Deliverability is at risk until it clears"
		rm -f "$state/dnsbl.unchecked"
		rm -f "$state/dnsbl.downgraded"
		;;
	clean*)
		# Nothing to say on a strong clean, and this must stay quiet. Printing the
		# verdict here looked helpful and was not, because cron mails anything a
		# job writes to stderr and this job runs every fifteen minutes: a clean
		# verdict became an email every quarter of an hour, which is the same
		# failure as alerting on a refusal and harder to spot, since the message
		# reads like good news. check-hygiene.sh is where a human asks and gets
		# the zone named.
		#
		# A clean from a weaker list is not nothing, though, and it used to be
		# invisible. When this box's own resolver stops answering, lib.sh drops
		# the @127.0.0.1 query, Spamhaus refuses a shared resolver with its
		# control answer, the function skips the zone and returns a verdict from
		# the next list down. That reads as checked while the list the large
		# providers filter on was never consulted, and a listing there costs the
		# members' outbound mail for no local symptom. So the zone in the verdict
		# is compared against the head of the configured list, which lib.sh
		# leaves in dnsbl_zones, and a downgrade is reported once per change of
		# zone rather than every hour.
		zone=$(printf '%s' "$verdict" | awk '{print $2}')
		# shellcheck disable=SC2154 # dnsbl_zones is set by lib.sh when sourced
		strongest=${dnsbl_zones%% *}
		# Why the strongest list was skipped decides what to say, and lib.sh
		# records it in the verdict. A zone that answered with a refusal is a
		# policy aimed at this resolver and nothing here is broken; a zone that
		# said nothing at all is this box's DNS. Sending the reader to check
		# unbound for the first is what this alert did on 2026-10-03, to an
		# operator whose unbound was answering everything else.
		skipped=$(printf '%s' "$verdict" | sed -n 's/.*\[skipped: //p' | sed 's/\]$//')
		reason=${skipped#*=}
		reason=${reason%% *}
		if [ "$zone" != "$strongest" ]; then
			# A zone that is slow rather than down gives one downgrade and then a
			# clean run, and under a once-per-change rule that is an alert every
			# other run. That is what reached the operator every few hours on
			# 2026-10-09. A downgrade is reported only once it has held for three
			# consecutive runs, three quarters of an hour, and the count resets the
			# moment the zone gives a verdict again.
			dnsbl_seen=$(cat "$state/dnsbl.downgraded" 2>/dev/null || true)
			case "$dnsbl_seen" in
			"$zone:$reason:"*) dnsbl_strikes=$((${dnsbl_seen##*:} + 1)) ;;
			*) dnsbl_strikes=1 ;;
			esac
			printf '%s\n' "$zone:$reason:$dnsbl_strikes" > "$state/dnsbl.downgraded"
			if [ "$dnsbl_strikes" -eq 3 ]; then
				case "$reason" in
				refused)
					# A refusal is a policy aimed at this resolver, and nothing on
					# this box is broken. Spamhaus refuses a shared resolver with
					# its control answer, which is what the second query gets; the
					# check asks 127.0.0.1 first, so a refusal means the box's own
					# resolver did not answer and the fallback was refused.
					alert mail "blocklist downgraded" "$ip is clean on $zone only: $strongest refused the query rather than giving a verdict, which is Spamhaus's answer to a resolver it will not serve. Nothing is listed on $strongest as far as this check can tell, and the runbook's blocklist section reads this one"
					;;
				servfail)
					# QNAME minimisation is already off in the tracked config, so a
					# servfail is usually a lookup that timed out rather than a
					# setting to change. The runbook's section says how to tell.
					alert mail "blocklist downgraded" "$ip is clean on $zone only: $strongest gave servfail rather than a verdict. Nothing is listed on $strongest as far as this check can tell. The tracked config sets the QNAME minimisation line to no, so if that has been deployed the likely cause is a lookup that timed out, and the runbook's blocklist section says how to tell"
					;;
				*)
					# Something said nothing at all, which has two causes and only one
					# of them is this box's DNS. Either unbound is not answering, or it
					# was not answering in time and the query went to the system
					# resolver, which Spamhaus ignores by design: a silent zen through
					# that fallback is expected, not a finding. The old advice named
					# only the second and blamed a reboot, which sent the operator to
					# a healthy resolver on 2026-10-05 and told them the next run
					# would be clean when it was not.
					alert mail "blocklist downgraded" "$ip is clean on $zone only; $strongest did not answer for three runs in a row. The strongest list is the one that matters for deliverability, so a listing there would go unnoticed. The look-up timed out rather than being answered: the zone's answers live ten seconds, so this check is a cold walk nearly every time, and Spamhaus's servers are occasionally slower than the query's patience. A query that goes to the system resolver is refused rather than left silent, so silence here is a timeout and not the wrong resolver. Run check-hygiene.sh by hand if it repeats, and the runbook's blocklist section says what to look at"
					;;
				esac
			fi
		else
			rm -f "$state/dnsbl.downgraded"
		fi
		rm -f "$state/dnsbl.unchecked"
		;;
	*)
		# Every configured zone refused. That is a hole rather than a finding, and
		# it is the state this check was in for its whole life before the list
		# existed, mailing an alert every cooldown. Report the transition, stay
		# quiet while it persists, and speak again if it clears and returns.
		if [ "$(cat "$state/dnsbl.unchecked" 2>/dev/null || true)" != "$verdict" ]; then
			alert mail "blocklist unchecked" "$verdict for $ip, so a listing would go unnoticed. refused above means the zone answered and will not serve this resolver; silent means it said nothing at all, which is DNS on this box"
			printf '%s\n' "$verdict" > "$state/dnsbl.unchecked"
		fi
		;;
	esac
fi

# --- 7. drain: health and backlog -----------------------------
# The drain is the privileged half of the control plane (issue #156): a
# root cron job that applies the intents the unprivileged handler files, one
# file per intent under the store's intents/ directory. The store root is
# /var/db/onboard (drain.toml and control-store.sh), and a missing intents/
# directory there is a finding rather than a quiet pass, because a store without
# one is the drain's half not deployed or its root moved, and this check exists
# for a drain that stopped. The interface it needs is the one #156 already fixes:
# an applied intent is deleted, a failed one is left in place, so the age of the
# oldest file is how long something has waited.
#
# That one age answers all three conditions the ticket names. A drain that has
# not run leaves the file, a drain that fails to apply leaves the file, and a
# member who has paid and has no account is exactly a file that will not clear.
# The case it cannot see is a drain that has died while the queue is empty,
# which is invisible precisely because there is nothing waiting on it.
#
# The alert carries the count and the age and never the filename, so no
# username lands in the check's event log.
#
# Threshold 240 minutes. A minute is the drain's own cadence and provisioning
# is promised within a minute of payment, so nothing here should ever be old;
# the value is set above the one wait that is legitimate, the certificate queue
# draining against Let's Encrypt's refill of one certificate every 202 minutes
# (issue #166), because a queued certificate request is not a stuck intent.
drain_backlog "$onboard_dir/intents" "$drain_intent_max_min" || exit 1

# --- 8. backup recency ---------------------------------------------------
# A missing nightly restic snapshot is invisible until the weekly restore test
# runs on another machine, six days later, because restore-test.sh takes the
# latest snapshot and the latest snapshot is whatever is still there. This asks
# the repository directly. The query is a read: --no-lock so it cannot collide
# with the 02:30 backup, and RESTIC_CACHE_DIR set because cron hands this job
# HOME=/var/log and the cache would otherwise land in the log directory.
#
# Threshold 26 hours: a nightly cadence plus two, so a job delayed by a long
# run or by the storage box being slow does not alert, and a missed night does.
# Nothing in the dogfood window can fit this, since it holds one snapshot per
# night and no failure.
#
# The trap this check fell into on 2026-10-03: --latest 1 returns the latest
# snapshot per group, and a group here is a host and a set of paths. Adding
# /etc/mail to the payload made a second group, so the listing held one snapshot
# from the old payload and one from the new, and taking the first time reported
# the old one's age as if it were the newest. It alerted "364 hours old" while
# the newest snapshot was eighteen hours old. The newest across everything is
# the answer, whatever the grouping does.
if [ -n "${RESTIC_REPOSITORY:-}" ] && [ -n "${RESTIC_PASSWORD_FILE:-}" ]; then
	: "${RESTIC_CACHE_DIR:=/root/.cache/restic}"
	export RESTIC_CACHE_DIR
	# restic writes the snapshot time as RFC3339. The form depends on the zone
	# the snapshot was taken in: this box is UTC and restic gives it as
	# "2026-10-01T13:00:09.510876011Z", while a machine in a named zone gets a
	# numeric offset instead. date -j -f takes %z as Z, +hhmm or +hh:mm and not
	# as a fraction, so the fraction is dropped and Z is turned into +0000.
	snap_epoch=$(restic snapshots --latest 1 --json --no-lock 2>/dev/null \
		| newest_snapshot_epoch || true)
	if [ -z "$snap_epoch" ]; then
		# The repository could not be read, which is not the same finding as an
		# old snapshot and must not be reported every hour as if it were. Report
		# the transition, then stay quiet while it persists.
		if [ "$(cat "$state/snapshot.unchecked" 2>/dev/null || true)" != "unreadable" ]; then
			alert backup "snapshot check" "no snapshot time could be read from the backup repository, so last night's backup is unverified rather than missing. restic could not list the repository: check the credentials in /root/.kyriakon-env, the storage box, and the key file"
			printf '%s\n' "unreadable" > "$state/snapshot.unchecked"
		fi
	else
		rm -f "$state/snapshot.unchecked"
		snap_age_h=$(( ( $(date +%s) - snap_epoch ) / 3600 ))
		if [ "$snap_age_h" -gt "$snapshot_max_age_hours" ]; then
			alert backup "snapshot stale" "the latest restic snapshot is $snap_age_h hours old (max $snapshot_max_age_hours). The weekly restore test would not run for another six days, so nothing else is going to tell you the nightly backup stopped"
		fi
	fi
fi

# --- 9. root filesystem --------------------------------------------------
# Per-user quotas cover /home, and until issue #160 lands them they cover
# nothing at all, so no check watched the system filesystems. Root is 986 MB
# (df -P -k / on 2026-10-01) and the packages under /usr/local are what grow
# it, so a package install with nowhere to unpack is the failure this catches.
#
# Threshold 80 per cent, the same convention as the quota check, and a bound
# rather than a fit: nothing in the dogfood window came near it, the box
# sitting at 15 per cent. The second check is absolute rather than a
# percentage, because a filesystem with no blocks left is already failing.
root_pct=$(df -P -k / 2>/dev/null | awk 'NR == 2 { print $5+0 }' || true)
if [ -n "$root_pct" ] && [ "$root_pct" -ge "$root_fs_warn_pct" ]; then
	alert host "root filesystem" "/ is at ${root_pct}% (warn at ${root_fs_warn_pct}%). The biggest mover is /usr/local, so a package install or its logs is the place to look before a service fails to write"
fi
full_fs=$(df -P -k 2>/dev/null | awk 'NR > 1 && $2 > 0 && $4 == 0 { print $6 }' || true)
if [ -n "$full_fs" ]; then
	alert host "filesystem full" "no free space on: $(printf '%s' "$full_fs" | tr '\n' ' '). A writable filesystem with nothing left will fail its next write, and this is separate from the percentage above because it is already broken rather than approaching it"
fi

# --- 10. certificate queue: the oldest pending request -------------------
# A member's certificate is issued by HTTP-01 and is not immediate: it spends the
# registered domain's budget of 50 new certificates per seven days, which refills
# at one every 202 minutes (docs/planning/research/cert-issuance-ceiling.md,
# section 2). scripts/acme-queue.sh holds one request per name, works them oldest
# first, and attempts a name on the next pass while fewer than 40 attempts sit in
# the last seven days, then one every 202 minutes. This reads the age of the
# oldest request straight from the queue's store, so the signal is real the day
# the first request is filed.
#
# The alert carries the count and the age and never a name, so no member lands in
# the check's event log, the same rule the drain signal above follows.
#
# Threshold 1440 minutes, a day, and it is the queue's own age rather than the
# drain's 240: a burst week issues a name on the next pass, and even inside the
# refill the wait is hours, so a value near either would alert on every signup. A
# day is where the queue is either not draining at all or deep enough that the
# oldest member has waited a day; both are worth a person, and a backlog that
# shallow is not. The value lives here as ACME_PENDING_MAX_MIN, and
# scripts/acme-queue.sh states the same 1440 in its header as the age this
# watches.
acme_queue_pending="$acme_queue_dir/pending"
if [ -d "$acme_queue_pending" ]; then
	oldest=$(find "$acme_queue_pending" -type f -exec stat -f '%m' {} + 2>/dev/null \
		| awk 'NR == 1 || $1 < m { m = $1 } END { print m }' || true)
	if [ -n "$oldest" ]; then
		acme_pending=$(find "$acme_queue_pending" -type f 2>/dev/null | wc -l | tr -d ' ')
		age_min=$(( ( $(date +%s) - oldest ) / 60 ))
		if [ "$age_min" -gt "$acme_pending_max_min" ]; then
			alert acme "certificate queue" "$acme_pending certificate request(s) pending, oldest $age_min minutes (max $acme_pending_max_min). The queue attempts a name on the next pass while fewer than 40 have been attempted in the last seven days and one every 202 minutes after that, so an age past this means it is not draining or the backlog is this deep, and either way a member is waiting on a certificate the page says is coming"
		fi
	fi
fi

# --- dead-man's switch: Healthchecks ping on a clean run ------------------
# Any hard failure above exits before here (set -e) and the ping is skipped, so
# Healthchecks alerts on silence. This is the channel that survives a
# compromised box, unlike the alert mail this same script sends.
if [ -n "${HEALTHCHECKS_URL:-}" ]; then
	curl -fsS -m 10 --retry 3 "$HEALTHCHECKS_URL" >/dev/null 2>&1 || true
fi

# crontab (root): every 15 min; the interval is the detection window. Install it
# with scripts/cron-apply.sh, which takes the values from /root/.kyriakon-env
# so the tab holds no secrets:
#   */15 * * * * . /root/.kyriakon-env; /root/bin/abuse-monitor.sh
