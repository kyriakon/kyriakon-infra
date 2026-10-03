#!/bin/ksh
# abuse-monitor.sh: cron-driven abuse + health monitoring for the mail box.
#
# Watches nine signals (spec §30-33, plus the release additions in issue #173),
# each tripping a content-rich alert:
#   1. outbound mail-volume spike: relayed message count (MTA sessions)
#   2. auth failures: smtpd + dovecot (maillog), sshd (authlog)
#      mail-side any; ssh per source address
#   3. quota approach: per-user edquota usage vs soft limit
#   4. spamd greylist/blocklist: greylist churn + new TRAPPED (blacklisted) hosts
#   5. senders deferred from several addresses: mail lost to a rotating retry IP
#   6. IP reputation blocklist: reversed-IPv4 A lookup on a DNSBL, and whether the
#      strongest list was the one that answered
#   7. onboarding drain: intents filed and left unapplied
#   8. backup recency: a restic snapshot inside the last 26 hours
#   9. root filesystem: / filling, and any filesystem with none left
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
#   ALERT_EMAIL            address to mail alerts to, off this box, so an alert
#                          survives this box being the broken thing
#   HEALTHCHECKS_URL       this box's check: a ping every run, with any finding
#                          attached to the event log. Not /fail, because a finding
#                          is not an outage; silence is what marks it down.
#   PUBLIC_IP              IPv4 for the DNSBL check (default: auto-detect from `ifconfig egress`)
#   DNSBL_ZONES            blocklists to query, strongest first (default in lib.sh:
#                          zen.spamhaus.org bl.spamcop.net all.s5h.net dnsbl.dronebl.org)
#   MAIL_SPIKE_MAX         outbound msgs per run that counts as a spike (default 50)
#   AUTH_FAIL_MAX          failed ssh logins from one address before alert (default 300)
#   QUOTA_WARN_PCT         quota usage % of soft limit that trips the alert (default 80)
#   GREY_MAX               spamd greylist entries before "flood" alert (default 100)
#   DEFER_MIN              distinct addresses one sender may be deferred from before it alerts (default 6)
#   ONBOARD_DIR            the onboarding store the drain applies intents from
#                          (default /var/db/kyriakon-onboard)
#   DRAIN_INTENT_MAX_MIN   minutes an intent may sit unapplied (default 240)
#   SNAPSHOT_MAX_AGE_HOURS age at which the latest restic snapshot is stale (default 26)
#   ROOT_FS_WARN_PCT       usage % on / that trips the alert (default 80)
#   DAEMONLOG              spamd's verbose log, carrying greylist envelopes (default /var/log/daemon)
#   ALERT_COOLDOWN_MINUTES alert suppression window, per signal (default 60)
#   STATE_DIR              state-file dir (default /var/db/kyriakon-monitor)
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
	for time in $(awk 'match($0, /"time":"[^"]+"/) { print substr($0, RSTART + 8, RLENGTH - 9) }' 2>/dev/null || true); do
		time=$(printf '%s' "$time" | sed 's/\.[0-9]*//; s/Z$/+0000/; s/\([+-][0-9][0-9]\):\([0-9][0-9]\)$/\1\2/')
		epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S%z" "$time" +%s 2>/dev/null || true)
		[ -n "$epoch" ] || continue
		if [ -z "$newest" ] || [ "$epoch" -gt "$newest" ]; then
			newest="$epoch"
		fi
	done
	[ -n "$newest" ] && printf '%s' "$newest"
	return 0
}

self_test() {
	typeset fails=0
	check() {
		if [ "$2" = "$3" ]; then
			printf '  ok   %s\n' "$1"
		else
			printf '  FAIL %s: expected [%s], got [%s]\n' "$1" "$3" "$2"
			fails=$((fails + 1))
		fi
	}
	# Two groups, the newer one with the larger time, and the older listed first:
	# the shape that produced the false "364 hours old".
	two_groups='{"snapshots":[
	{"time":"2026-09-18T14:42:12.000000000Z","paths":["/home"]},
	{"time":"2026-10-03T02:30:01.000000000Z","paths":["/etc/mail","/home"]}]}'
	expect=$(date -j -f "%Y-%m-%dT%H:%M:%S%z" "2026-10-03T02:30:01+0000" +%s)
	check "the newest of two groups is chosen" \
		"$(printf '%s' "$two_groups" | newest_snapshot_epoch)" "$expect"

	# One group, both stale: the newest of them is still what is reported.
	both_old='{"snapshots":[
	{"time":"2026-09-18T14:42:12.000000000Z"},
	{"time":"2026-09-19T02:30:01.000000000Z"}]}'
	expect_old=$(date -j -f "%Y-%m-%dT%H:%M:%S%z" "2026-09-19T02:30:01+0000" +%s)
	check "an all-stale repository reports its newest" \
		"$(printf '%s' "$both_old" | newest_snapshot_epoch)" "$expect_old"

	# A named-zone offset, which restic writes off this box.
	offset='{"snapshots":[{"time":"2026-10-03T04:30:01.000000000+02:00"}]}'
	check "a numeric offset parses" \
		"$(printf '%s' "$offset" | newest_snapshot_epoch)" "$expect"

	check "nothing to parse prints nothing" \
		"$(printf '%s' '' | newest_snapshot_epoch)" ""

	if [ "$fails" -eq 0 ]; then
		printf 'self-test: all checks passed\n'
	else
		printf 'self-test: %s failed\n' "$fails" >&2
		exit 1
	fi
}

# --self-test runs the parse checks and leaves, before any signal reads a log or
# writes state, so it is safe to run as an unprivileged user on any machine.
if [ "${1:-}" = "--self-test" ]; then
	self_test
	exit 0
fi


maillog="${MAILLOG:-/var/log/maillog}"
authlog="${AUTHLOG:-/var/log/authlog}"
state="${STATE_DIR:-/var/db/kyriakon-monitor}"
mkdir -p "$state"

alert_cooldown="${ALERT_COOLDOWN_MINUTES:-60}"
mail_spike_max="${MAIL_SPIKE_MAX:-50}"
auth_fail_max="${AUTH_FAIL_MAX:-300}"
quota_warn_pct="${QUOTA_WARN_PCT:-80}"
grey_max="${GREY_MAX:-100}"
defer_min="${DEFER_MIN:-6}"
daemon_log="${DAEMONLOG:-/var/log/daemon}"
onboard_dir="${ONBOARD_DIR:-/var/db/kyriakon-onboard}"
drain_intent_max_min="${DRAIN_INTENT_MAX_MIN:-240}"
snapshot_max_age_hours="${SNAPSHOT_MAX_AGE_HOURS:-26}"
root_fs_warn_pct="${ROOT_FS_WARN_PCT:-80}"

# --- alert: content-rich mail, plus the external check --------------------
# Alerts go out as mail to ALERT_EMAIL, an address off this box, and the same
# event marks the Healthchecks check down so the external channel carries it too.
#
# Two channels because they fail differently. Mail is what can describe a finding:
# the check's dashboard shows a stored body but the notification itself does not
# repeat it. And the check is what survives this box being the broken thing: mail
# cannot report a broken mail path, and the check's silence covers that case.
#
# The cooldown is per signal, one file named from the title. It used to be one
# file for all six checks, so the first to fire silenced the rest for the hour,
# and the baseline note found that in the state directory: an address making
# hundreds of ssh guesses trips every quarter hour, which held the channel shut
# and is why the ssh threshold could not be lowered. The single file the old
# code wrote, $state/alert.last, is left where it is and no longer read.
alert() {
	title="$1"; body="$2"
	now=$(date +%s)
	last_file="$state/alert.last.$(printf '%s' "$title" | tr 'A-Z ' 'a-z-' | tr -cd 'a-z0-9-')"
	last=0
	[ -f "$last_file" ] && last=$(cat "$last_file")
	if [ "$(( now - last ))" -lt "$(( alert_cooldown * 60 ))" ]; then
		return 0
	fi
	printf '%s\n' "$now" > "$last_file"
	when=$(date '+%F %T')
	if [ -n "${ALERT_EMAIL:-}" ]; then
		printf '%s\n\n%s on %s\n' "$body" "$title" "$(hostname)" \
			| mail -s "kyriakon: $title" "$ALERT_EMAIL" >/dev/null 2>&1 || true
	fi
	# The body lands in the check's event log, which is what makes an alert
	# raised while mail is broken still readable somewhere.
	#
	# Pinned to the success URL rather than /fail on purpose. A finding is not an
	# outage: pinging /fail marked the dead-man's switch down and the ping at the
	# end of the same run brought it straight back up, so Healthchecks mailed
	# "is UP, the downtime lasted 0 seconds" every time the monitor had something
	# to say, which is noise that trains you to ignore the one channel that
	# survives this box going away. The check's state now means "the monitor is
	# running". /fail belongs to a run that could not do its job, and under set -e
	# such a run dies before reaching any ping, leaving Healthchecks to alert on
	# silence, which is what the switch is for.
	if [ -n "${HEALTHCHECKS_URL:-}" ]; then
		curl -fsS -m 10 --retry 3 --data "$when $title: $body" \
			"$HEALTHCHECKS_URL" >/dev/null 2>&1 || true
	fi
	printf '%s %s: %s\n' "$when" "$title" "$body" >&2
}

# --- new_lines: emit log lines appended since last run -------------------
# Line-offset delta is rotation-safe and needs no date parsing: cron interval
# IS the detection window. First run only baselines (no historical replay).
new_lines() {
	log="$1"; posfile="$2"
	[ -f "$log" ] || return 0
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

new_maillog=$(new_lines "$maillog" "$state/maillog.pos")
new_authlog=$(new_lines "$authlog" "$state/authlog.pos")

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
outbound=$(printf '%s\n' "$new_maillog" \
	| awk '/mta disconnected reason=quit/ { split($0, a, "messages="); s += a[2]+0 } END { print s+0 }')
if [ "$outbound" -gt "$mail_spike_max" ]; then
	alert "mail spike" "outbound: $outbound messages relayed since last run (max $mail_spike_max)"
fi

# --- 2. auth failures ----------------------------------------------------
# Split by kind, because the two mean opposite things. Mail-side failures are rare
# and each is a real client getting its password wrong, so the first one is worth
# knowing about. sshd failures are the background noise of any public box: this one
# takes a steady trickle of dictionary guesses from all over, and a total summed
# across mail and ssh says nothing except that the internet is on. Twelve guesses
# from twelve addresses is that background; twelve from one address is somebody
# working through a list, and that is the one worth waking up for.
#   smtpd (smtp_session.c): "smtp authentication user=X result=permfail|tempfail"
#   dovecot: "(auth failed, N attempts in M secs)". This is the line the build
#     writes and it is in libdovecot-login.so.4.0; the pattern used to look for
#     "pam_authenticate() failed", which belongs to passdb-pam.c and is in none
#     of the installed Dovecot objects, because the deployed passdb is bsdauth.
#     The one real IMAP failure in the retained maillog (2026-09-24, an NTLM
#     probe from a scanner) is exactly the form above and went unmatched.
#   sshd (authlog): see the tally below.
mail_auth=$(printf '%s\n' "$new_maillog" \
	| awk '
		/smtp authentication user=.*result=(perm|temp)fail/ { c++ }
		/auth failed, [0-9]+ attempts in/ { c++ }
		END { print c+0 }')
if [ "$mail_auth" -gt 0 ]; then
	alert "mail auth failures" "$mail_auth failed SMTP/IMAP logins since last run. Each one is a client whose password is wrong, so check the address before assuming a stranger: a phone with a stale password looks exactly like this"
fi

# sshd, tallied by source address, reporting the worst one and the total.
#
# One count per attempt. An attempt against an unknown username writes two lines
# for the one event, "Invalid user X from IP port N" and "Failed password for
# invalid user X from IP port N", and the old pattern matched both, so it
# reported about 1.5 times the attempts: over the retained authlogs it counts
# 217,320 lines where one line per attempt counts 142,298. The rule below takes
# the "Invalid user" line for an unknown username, and the "Failed password"
# line only when it does not also name an invalid user, which is the attempt
# against a real account.
#
# The address is the token before the last "port", rather than the token after
# the first "from": scanners do try usernames like "from" and "port", and either
# one would otherwise be read as the address.
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
ssh_auth=$(printf '%s\n' "$new_authlog" \
	| awk '
		{
			if ($0 ~ /Invalid user/ || ($0 ~ /Failed password/ && $0 !~ /invalid user/)) {
				ip = ""
				for (i = NF; i >= 2; i--) if ($i == "port") { ip = $(i-1); break }
				if (ip != "") { n[ip]++; t++ }
			}
		}
		END {
			worst = ""; high = 0
			for (ip in n) if (n[ip] > high) { high = n[ip]; worst = ip }
			printf "%s %d %d\n", worst, high, t+0
		}')
ssh_ip=$(printf '%s\n' "$ssh_auth" | awk '{ print $1 }')
ssh_high=$(printf '%s\n' "$ssh_auth" | awk '{ print $2+0 }')
ssh_total=$(printf '%s\n' "$ssh_auth" | awk '{ print $3+0 }')
if [ "$ssh_high" -gt "$auth_fail_max" ]; then
	alert "ssh guesses" "$ssh_ip made $ssh_high failed ssh attempts since last run, out of $ssh_total from all addresses (max per address $auth_fail_max). Password auth is off everywhere, so none of this can succeed; it is worth a look only because one source is working through a list"
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
	[ -n "$msg" ] && alert "quota" "$msg"
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
	alert "spamd greylist" "$grey greylisted hosts (max $grey_max), possible mail flood"
fi
prev_trapped=0
if [ -f "$state/spamd-trapped" ]; then
	prev_trapped=$(cat "$state/spamd-trapped")
	if [ "$trapped" -gt "$prev_trapped" ]; then
		alert "spamd blocklist" "$(( trapped - prev_trapped )) new blacklisted host(s), total $trapped"
	fi
fi
printf '%s\n' "$trapped" > "$state/spamd-trapped"

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
	alert "greylisted senders" "deferred from several addresses today: $(printf '%s' "$flagged" | tr '\n' ';'). If one is a real correspondent, add its mail ranges to /etc/mail/nospamd (docs/planning/research/spamd-greylisting.md)"
fi
printf '%s\n' "$flagged" > "$state/deferred-senders"

# --- 6. IP reputation blocklist ------------------------------------------
ip="${PUBLIC_IP:-$(ifconfig egress inet 2>/dev/null | awk '/inet / { print $2; exit }')}"
if [ -n "$ip" ]; then
	verdict=$(dnsbl_verdict "$ip")
	case "$verdict" in
	listed*)
		alert "blocklisted" "$ip is listed: ${verdict#listed }. That code names the list, which the verdict names too; look it up and request removal. Deliverability is at risk until it clears"
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
		zone=${verdict#clean }
		# shellcheck disable=SC2154 # dnsbl_zones is set by lib.sh when sourced
		strongest=${dnsbl_zones%% *}
		if [ "$zone" != "$strongest" ]; then
			if [ "$(cat "$state/dnsbl.downgraded" 2>/dev/null || true)" != "$zone" ]; then
				alert "blocklist downgraded" "$ip is clean on $zone only; $strongest did not answer. The strongest list is the one that matters for deliverability, so a listing there would go unnoticed. Check that unbound is running on this box: rcctl check unbound"
				printf '%s\n' "$zone" > "$state/dnsbl.downgraded"
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
			alert "blocklist check" "$verdict for $ip, so a listing would go unnoticed. Every configured zone refused, which points at DNS on this box rather than at the lists"
			printf '%s\n' "$verdict" > "$state/dnsbl.unchecked"
		fi
		;;
	esac
fi

# --- 7. onboarding drain: health and backlog -----------------------------
# The drain is the privileged half of the onboarding service (issue #156): a
# root cron job that applies the intents the unprivileged handler files, one
# file per intent under the store's intents/ directory. It is not built yet, so
# on a box without the store this check reads nothing and says nothing; it
# starts working the day the store appears. The interface it needs is the one
# #156 already fixes: an applied intent is deleted, a failed one is left in
# place, so the age of the oldest file is how long something has waited.
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
intents_dir="$onboard_dir/intents"
if [ -d "$intents_dir" ]; then
	oldest=$(find "$intents_dir" -type f -exec stat -f '%m' {} + 2>/dev/null \
		| awk 'NR == 1 || $1 < m { m = $1 } END { print m }' || true)
	if [ -n "$oldest" ]; then
		pending=$(find "$intents_dir" -type f 2>/dev/null | wc -l | tr -d ' ')
		age_min=$(( ( $(date +%s) - oldest ) / 60 ))
		if [ "$age_min" -gt "$drain_intent_max_min" ]; then
			alert "drain backlog" "$pending unapplied intent(s) in the onboarding store, oldest $age_min minutes (max $drain_intent_max_min). The drain is the service's privileged half; an intent this old is a member whose payment or approval was accepted and who still has no account"
		fi
	fi
fi

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
			alert "snapshot check" "no snapshot time could be read from the backup repository, so last night's backup is unverified rather than missing. restic could not list the repository: check the credentials in /root/.kyriakon-env, the storage box, and the key file"
			printf '%s\n' "unreadable" > "$state/snapshot.unchecked"
		fi
	else
		rm -f "$state/snapshot.unchecked"
		snap_age_h=$(( ( $(date +%s) - snap_epoch ) / 3600 ))
		if [ "$snap_age_h" -gt "$snapshot_max_age_hours" ]; then
			alert "snapshot stale" "the latest restic snapshot is $snap_age_h hours old (max $snapshot_max_age_hours). The weekly restore test would not run for another six days, so nothing else is going to tell you the nightly backup stopped"
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
	alert "root filesystem" "/ is at ${root_pct}% (warn at ${root_fs_warn_pct}%). The biggest mover is /usr/local, so a package install or its logs is the place to look before a service fails to write"
fi
full_fs=$(df -P -k 2>/dev/null | awk 'NR > 1 && $2 > 0 && $4 == 0 { print $6 }' || true)
if [ -n "$full_fs" ]; then
	alert "filesystem full" "no free space on: $(printf '%s' "$full_fs" | tr '\n' ' '). A writable filesystem with nothing left will fail its next write, and this is separate from the percentage above because it is already broken rather than approaching it"
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
