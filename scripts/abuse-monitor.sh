#!/bin/ksh
# abuse-monitor.sh — cron-driven abuse + health monitoring for the mail box.
#
# Watches five signals (spec §30-33), each tripping a content-rich alert:
#   1. outbound mail-volume spike  — relayed message count (MTA sessions)
#   2. repeated auth failures       — smtpd + dovecot (maillog), sshd (authlog)
#   3. quota approach               — per-user edquota usage vs soft limit
#   4. spamd greylist/blocklist     — greylist churn + new TRAPPED (blacklisted) hosts
#   5. IP reputation blocklist      — reversed-IPv4 A lookup on a DNSBL
#
# Plus the dead-man's switch (§34/35): a Healthchecks.io ping on a clean run.
# If this script stops running, or the box goes silent, Healthchecks alerts from
# OUTSIDE the box (the only channel that still works when the box is compromised).
# Content-rich detail goes to a separate external channel (ntfy.sh push) so the
# two concerns — liveness and content — stay split as the spec intends.
#
# Env (all optional — the script degrades to stderr output):
#   ALERT_TOPIC            ntfy.sh topic for content-rich alerts (no topic = stderr only)
#   HEALTHCHECKS_URL       Healthchecks ping URL for the dead-man's switch
#   PUBLIC_IP              IPv4 for the DNSBL check (default: auto-detect from `ifconfig egress`)
#   DNSBL_ZONE             DNSBL to query (default zen.spamhaus.org)
#   MAIL_SPIKE_MAX         outbound msgs per run that counts as a spike (default 200)
#   AUTH_FAIL_MAX          auth failures per run before alert (default 10)
#   QUOTA_WARN_PCT         quota usage % of soft limit that trips the alert (default 80)
#   GREY_MAX               spamd greylist entries before "flood" alert (default 200)
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
dnsbl_zone="${DNSBL_ZONE:-zen.spamhaus.org}"

# --- alert: content-rich, external channel, rate-limited -----------------
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
	if [ -n "${ALERT_TOPIC:-}" ]; then
		curl -fsS -m 10 --retry 3 -H "Title: $title" -d "$body" \
			"https://ntfy.sh/$ALERT_TOPIC" >/dev/null 2>&1 || true
	fi
	printf '%s — %s: %s\n' "$(date '+%F %T')" "$title" "$body" >&2
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

# --- 2. repeated auth failures -------------------------------------------
# smtpd (smtp_session.c): "smtp authentication user=X result=permfail|tempfail".
# dovecot PAM (passdb-pam.c): "auth: ... pam_authenticate() failed" / "unknown user".
# sshd (authlog): "Failed password" / "Invalid user".
auth=$(printf '%s\n' "$new_maillog" "$new_authlog" \
	| awk '
		/smtp authentication user=.*result=(perm|temp)fail/ { c++ }
		/auth:.*(pam_authenticate\(\) failed|unknown user)/ { c++ }
		/Failed password|Invalid user/ { c++ }
		END { print c+0 }')
if [ "$auth" -gt "$auth_fail_max" ]; then
	alert "auth failures" "$auth failed SMTP/IMAP/SSH logins since last run (max $auth_fail_max)"
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

# --- 5. IP reputation blocklist ------------------------------------------
ip="${PUBLIC_IP:-$(ifconfig egress inet 2>/dev/null | awk '/inet / { print $2; exit }')}"
if [ -n "$ip" ]; then
	rev=$(printf '%s\n' "$ip" | awk -F. '{ print $4"."$3"."$2"."$1 }')
	listed=$(dig +short +time=5 +tries=2 "$rev.$dnsbl_zone" A 2>/dev/null \
		| grep -Ec '^[0-9]' || true)
	if [ "$listed" -gt 0 ]; then
		alert "blocklisted" "$ip is listed on $dnsbl_zone — deliverability at risk"
	fi
fi

# --- dead-man's switch: Healthchecks ping on a clean run ------------------
# Any hard failure above exits before here (set -e) and the ping is skipped →
# Healthchecks alerts on silence. This is the channel that survives a
# compromised box, unlike the ntfy push.
if [ -n "${HEALTHCHECKS_URL:-}" ]; then
	curl -fsS -m 10 --retry 3 "$HEALTHCHECKS_URL" >/dev/null 2>&1 || true
fi

# crontab (root) — every 15 min; the interval is the detection window:
#   */15 * * * *  ALERT_TOPIC='kyriakon-alerts' \
#                 HEALTHCHECKS_URL='https://hc-ping.com/<uuid>' /root/bin/abuse-monitor.sh
