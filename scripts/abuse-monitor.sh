#!/bin/ksh
# abuse-monitor.sh — cron-driven abuse + health monitoring for the mail box.
#
# Watches six signals (spec §30-33), each tripping a content-rich alert:
#   1. outbound mail-volume spike  — relayed message count (MTA sessions)
#   2. auth failures                — smtpd + dovecot (maillog), sshd (authlog)
#                                     mail-side any; ssh per source address
#   3. quota approach               — per-user edquota usage vs soft limit
#   4. spamd greylist/blocklist     — greylist churn + new TRAPPED (blacklisted) hosts
#   5. senders deferred from several addresses — mail lost to a rotating retry IP
#   6. IP reputation blocklist      — reversed-IPv4 A lookup on a DNSBL
#
# Plus the dead-man's switch (§34/35): a Healthchecks.io ping on a clean run.
# If this script stops running, or the box goes silent, Healthchecks alerts from
# OUTSIDE the box (the only channel that still works when the box is compromised).
# Findings go out as mail to ALERT_EMAIL and mark that same check down, so the
# external channel carries them too.
#
# Env (all optional — the script degrades to stderr output):
#   ALERT_EMAIL            address to mail alerts to, off this box, so an alert
#                          survives this box being the broken thing
#   HEALTHCHECKS_URL       this box's check: a plain ping on a clean run, and
#                          /fail with the finding when something trips
#   PUBLIC_IP              IPv4 for the DNSBL check (default: auto-detect from `ifconfig egress`)
#   DNSBL_ZONE             DNSBL to query (default zen.spamhaus.org)
#   MAIL_SPIKE_MAX         outbound msgs per run that counts as a spike (default 200)
#   AUTH_FAIL_MAX          failed ssh logins from one address before alert (default 10)
#   QUOTA_WARN_PCT         quota usage % of soft limit that trips the alert (default 80)
#   GREY_MAX               spamd greylist entries before "flood" alert (default 200)
#   DEFER_MIN              distinct addresses one sender may be deferred from before it alerts (default 3)
#   DAEMONLOG              spamd's verbose log, carrying greylist envelopes (default /var/log/daemon)
#   ALERT_COOLDOWN_MINUTES alert suppression window (default 60)
#   STATE_DIR              state-file dir (default /var/db/kyriakon-monitor)
#
# Runs as root (reads /var/log/*, spamdb, quota). Every threshold is deliberately
# a tunable, not fixed: they are set during dogfood (spec "Further Notes"), before
# real users exist to generate false positives. Log-line formats below are pinned
# to OpenBSD 7.x sources and should be re-checked against the live box on first run.

set -euo pipefail
maillog="${MAILLOG:-/var/log/maillog}"
authlog="${AUTHLOG:-/var/log/authlog}"
state="${STATE_DIR:-/var/db/kyriakon-monitor}"
mkdir -p "$state"

alert_cooldown="${ALERT_COOLDOWN_MINUTES:-60}"
mail_spike_max="${MAIL_SPIKE_MAX:-200}"
auth_fail_max="${AUTH_FAIL_MAX:-10}"
quota_warn_pct="${QUOTA_WARN_PCT:-80}"
grey_max="${GREY_MAX:-200}"
defer_min="${DEFER_MIN:-3}"
daemon_log="${DAEMONLOG:-/var/log/daemon}"
dnsbl_zone="${DNSBL_ZONE:-zen.spamhaus.org}"

# --- alert: content-rich mail, plus the external check --------------------
# Alerts go out as mail to ALERT_EMAIL, an address off this box, and the same
# event marks the Healthchecks check down so the external channel carries it too.
#
# Two channels because they fail differently. Mail is what can describe a finding:
# the check's dashboard shows a stored body but the notification itself does not
# repeat it. And the check is what survives this box being the broken thing: mail
# cannot report a broken mail path, and the check's silence covers that case.
#
# ponytail: single global cooldown (one state file). Per-check cooldowns if a
# real incident ever suppresses a second check within the window.
alert() {
	title="$1"; body="$2"
	now=$(date +%s)
	last=0
	[ -f "$state/alert.last" ] && last=$(cat "$state/alert.last")
	if [ "$(( now - last ))" -lt "$(( alert_cooldown * 60 ))" ]; then
		return 0
	fi
	printf '%s\n' "$now" > "$state/alert.last"
	when=$(date '+%F %T')
	if [ -n "${ALERT_EMAIL:-}" ]; then
		printf '%s\n\n%s on %s\n' "$body" "$title" "$(hostname)" \
			| mail -s "kyriakon: $title" "$ALERT_EMAIL" >/dev/null 2>&1 || true
	fi
	# The body lands in the check's event log, which is what makes an alert
	# raised while mail is broken still readable somewhere.
	if [ -n "${HEALTHCHECKS_URL:-}" ]; then
		curl -fsS -m 10 --retry 3 --data "$when $title: $body" \
			"$HEALTHCHECKS_URL/fail" >/dev/null 2>&1 || true
	fi
	printf '%s — %s: %s\n' "$when" "$title" "$body" >&2
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
# Outbound relay completions only (mta = relay; inbound is smtp→LMTP, not mta).
# Log line (mta_session.c): "<id> mta disconnected reason=quit messages=N".
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
# working through a list, and that is the one worth waking up for. Nothing here can
# succeed: every account authenticates by key, and no password login has ever been
# accepted, which is why the per-address count is a tidiness signal, not an alarm.
#   smtpd (smtp_session.c): "smtp authentication user=X result=permfail|tempfail"
#   dovecot PAM (passdb-pam.c): "auth: ... pam_authenticate() failed" / "unknown user"
#   sshd (authlog): "Failed password for ... from <ip> port ..." / "Invalid user ... from <ip>"
mail_auth=$(printf '%s\n' "$new_maillog" \
	| awk '
		/smtp authentication user=.*result=(perm|temp)fail/ { c++ }
		/auth:.*(pam_authenticate\(\) failed|unknown user)/ { c++ }
		END { print c+0 }')
if [ "$mail_auth" -gt 0 ]; then
	alert "mail auth failures" "$mail_auth failed SMTP/IMAP logins since last run. Each one is a client whose password is wrong, so check the address before assuming a stranger: a phone with a stale password looks exactly like this"
fi

# sshd, tallied by source address, reporting the worst one and the total.
ssh_auth=$(printf '%s\n' "$new_authlog" \
	| awk '
		/Failed password|Invalid user/ {
			for (i = 1; i < NF; i++) if ($i == "from") { n[$(i+1)]++; t++; break }
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
	alert "ssh guesses" "$ssh_ip made $ssh_high failed ssh logins since last run, out of $ssh_total from all addresses (max per address $auth_fail_max). Password auth is off everywhere, so none of this can succeed; it is worth a look only because one source is working through a list"
fi

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
# spamdb dump: GREY|<ip>|… and TRAPPED|<ip>|<expire> (a host blacklisted for
# hitting a spamtrap). Greylist churn = mail flood; a NEW TRAPPED entry is a
# real event worth seeing (spam source, or worse, a legit sender got trapped).
spamdb_out=$(spamdb 2>/dev/null || true)
grey=$(printf '%s\n' "$spamdb_out" | grep -c '^GREY|' || true)
trapped=$(printf '%s\n' "$spamdb_out" | grep -c '^TRAPPED|' || true)
if [ "$grey" -gt "$grey_max" ]; then
	alert "spamd greylist" "$grey greylisted hosts (max $grey_max) — possible mail flood"
fi
prev_trapped=0
if [ -f "$state/spamd-trapped" ]; then
	prev_trapped=$(cat "$state/spamd-trapped")
	if [ "$trapped" -gt "$prev_trapped" ]; then
		alert "spamd blocklist" "$(( trapped - prev_trapped )) new blacklisted host(s) — total $trapped"
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
# spamd -v (set by deploy-mail.sh) logs the envelope of every decision:
#   "… (GREY) <ip>: <from> -> <to>"
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
	alert "greylisted senders" "deferred from several addresses today: $(printf '%s' "$flagged" | tr '\n' ';') — if one is a real correspondent, add its mail ranges to /etc/mail/nospamd (docs/planning/research/spamd-greylisting.md)"
fi
printf '%s\n' "$flagged" > "$state/deferred-senders"

# --- 6. IP reputation blocklist ------------------------------------------
ip="${PUBLIC_IP:-$(ifconfig egress inet 2>/dev/null | awk '/inet / { print $2; exit }')}"
if [ -n "$ip" ]; then
	rev=$(printf '%s\n' "$ip" | awk -F. '{ print $4"."$3"."$2"."$1 }')
	# Zen answers 127.0.0.2 to 127.0.0.11 for a real listing, the last octet naming
	# the list that matched, and 127.255.255.0/24 when it refuses the resolver
	# asking. The refusal is the common case: the system resolver on this box, on
	# the workstation, and every public resolver tried all get it, because Spamhaus
	# does not answer shared resolvers. A resolver serving one machine is answered,
	# so ask one here if it exists.
	if dig +short +time=2 +tries=1 @127.0.0.1 . NS >/dev/null 2>&1; then
		answer=$(dig +short +time=5 +tries=2 @127.0.0.1 "$rev.$dnsbl_zone" A 2>/dev/null || true)
		via="the resolver on this box"
	else
		answer=$(dig +short +time=5 +tries=2 "$rev.$dnsbl_zone" A 2>/dev/null || true)
		via="the system resolver, which this box has no resolver of its own behind"
	fi
	case "$answer" in
	127.255.255.*)
		# Reporting this as a listing is a false alarm, and staying silent about it
		# is worse: a real listing would go unnoticed. Say what it is, once per
		# cooldown, and name the fix.
		alert "blocklist check" "cannot check $dnsbl_zone via $via: Spamhaus refuses it, so a listing would go unnoticed. A local recursive resolver is answered and is not refused; unbound ships in base"
		;;
	127.0.0.*)
		alert "blocklisted" "$ip is on $dnsbl_zone as 127.0.0.$(printf '%s\n' "$answer" | head -1 | awk -F. '{ print $4 }') — deliverability at risk. That code names the list; look it up and request removal at check.spamhaus.org"
		;;
	esac
fi

# --- dead-man's switch: Healthchecks ping on a clean run ------------------
# Any hard failure above exits before here (set -e) and the ping is skipped →
# Healthchecks alerts on silence. This is the channel that survives a
# compromised box, unlike the alert mail this same script sends.
if [ -n "${HEALTHCHECKS_URL:-}" ]; then
	curl -fsS -m 10 --retry 3 "$HEALTHCHECKS_URL" >/dev/null 2>&1 || true
fi

# crontab (root) — every 15 min; the interval is the detection window. Install it
# with scripts/cron-apply.sh, which takes the values from /root/.kyriakon-env
# so the tab holds no secrets:
#   */15 * * * * . /root/.kyriakon-env; /root/bin/abuse-monitor.sh
