# Alert thresholds from the dogfood logs (public release, monitoring, §30-33)

**Question.** What should each of the abuse monitor's six thresholds be, from this platform's own
traffic rather than from a placeholder? The six run on defaults chosen before any traffic existed:
`MAIL_SPIKE_MAX=200`, `AUTH_FAIL_MAX=10`, `QUOTA_WARN_PCT=80`, `GREY_MAX=200`, `DEFER_MIN=3`, plus
the blocklist check, which is a verdict rather than a number.

**Answer, in six lines.** Outbound volume is 0 to 4 messages per 15-minute interval, all of it the
box's own cron mail, so 200 is 50 times the busiest interval ever seen; 50 is the value proposed,
and it is a judgement about what a compromised account looks like, not a measurement. SSH failures
are the only signal with real numbers: 217,300 matching log lines over 35 days from 1,797 addresses,
with single addresses reaching 358 in one interval, so 10 is far below the noise floor and 300 is
proposed. Mail-side authentication failures barely occurred, one IMAP probe in 8 days, and the
pattern that looks for them does not match the line this build writes for a failure. Quota has no
data because `/home` carries no quota, so 80 has never executed. Greylist churn reads a live count
of 3 today, with nothing sampling it, so 100 is a bound rather than a fit. Rotating senders
separate cleanly: observed spam senders use 1
to 4 addresses a day and the one real incident used 11 and then 22, so 6 is proposed where 3 fires
on 8 days out of 13. The blocklist check answers `clean zen.spamhaus.org`, and its failure mode is a
silent downgrade to a weaker list, not a threshold.

**Where the numbers come from.** `mail.kyriakon.net`, OpenBSD 7.9 GENERIC.MP#11 amd64, reached over
SSH as an unprivileged account in `wheel`, which is enough to read every log used here, because the
`640` mode is group `wheel`. Read-only throughout: `gzip -dc` on the rotated files, `awk`, `grep`,
`spamdb`, `quota`, `dig`, and `strings` on installed binaries. Nothing on the box was written
outside `/tmp`, no daemon was signalled, and the monitor itself was never run, since a manual run
would advance its state files and ping Healthchecks. The one scratch file, `/tmp/wf-ssh-out.txt`
from a counting pass, was removed at the end. One function, `dnsbl_verdict` from `scripts/lib.sh`,
was sourced on the box over stdin so that its verdict could be reported as the monitor computes it.

---

## The dogfood period as the logs define it

The box's own logs begin at `2026-08-26 18:46:48` (`/var/log/daemon.0.gz`, first line, when the host
was still named `kyriakon`) and run to `2026-09-30 18:47`. That is 35 days, and it is the longest
window any signal here has.

Three shorter windows sit inside it, and each one is set by a different mechanism:

| window | from | to | length | set by |
|---|---|---|---|---|
| whole box | 2026-08-26 18:46:48 | 2026-09-30 18:47 | 35 days | first line retained in `/var/log/daemon.0.gz` |
| mail platform | 2026-09-18 19:40:57 | 2026-09-30 18:47 | 12 days | first spamd line, `listening for incoming connections` |
| maillog | 2026-09-23 02:00:01 | 2026-09-30 18:47 | 8 days | `/etc/newsyslog.conf`: `maillog 7 * 24 Z`, seven daily files |
| monitor state | 2026-09-21 17:00 | 2026-09-30 18:47 | 9 days | `mtime` of `/var/db/kyriakon-monitor` |

The maillog boundary is the one that hurts. Outbound volume and mail-side authentication failures
are both read from `/var/log/maillog`, and rotation keeps seven compressed files, so those two
signals have 8 days and cannot be extended backwards without one having been kept. Rotating the
verdict: `ls -l /var/log/maillog.6.gz` gives the oldest file, and its first line is the boundary.

Everything before 2026-09-18 belongs to a box with no mail on it, which is why the greylist and
sender evidence in sections 4 and 5 starts there.

## What the cooldown and the state directory do to a count

Four facts about `/var/db/kyriakon-monitor` change what any threshold means, and all four were read
off the live directory on 2026-09-30:

	alert.last=1790793001                     # 2026-09-30 18:30:01
	authlog.pos=37124
	maillog.pos=310
	deferred-senders=3 bounces+112604537-3ded-ob=kyriakon.net@em8770.jerichoaquino.net
	spamd-trapped=2

**Every count covers one 15-minute interval, not a day.** `new_lines()` stores a line offset per
log and each run counts only the lines appended since the previous run. The cron line in
`cron-apply.sh` is `*/15 * * * *`, and the state files show it running: `maillog.pos`,
`authlog.pos`, `spamd-trapped` and `deferred-senders` all carry `mtime` 18:45:01, and had 18:30:01
four minutes earlier. So a threshold is a count per 15 minutes, and a run that cron delays merges
two windows into one larger reading.

**The window is not the clock quarter.** The counts above bucket the logs by wall clock, which is
the right reconstruction because the cron fires on the quarter hour, but the monitor's real window
is between its own runs.

**One alert per hour for all six checks.** `alert()` returns early while `now - alert.last` is under
`ALERT_COOLDOWN_MINUTES=60`, and it writes the timestamp before sending. The file is global, so the
first check to fire silences the other five for the next hour. The alert at 18:30:01 is holding the
window open at 18:45, where the run rewrote four state files and left `alert.last` untouched, which
is what a suppressed alert and an absent finding look like alike. With 96 runs a day the ceiling is
24 alerts, and a check that trips on most runs drives the other five silent. This is the largest
constraint on the SSH value.

**Three checks do remember, three do not.** `deferred-senders` holds the whole day's flagged set and
alerts only when the string changes, so a sender stuck for days is not news every run.
`spamd-trapped` alerts only when the count rises. The other three, outbound volume, mail
authentication and quota, call `alert()` whenever their condition holds, so a condition that
persists past an hour reports every hour until it stops.

---

## The six signals

Commands are abbreviated here and written out in the matching section.

| signal | extraction | observed in the window | proposed | false positive cost |
|---|---|---|---|---|
| outbound volume | `mta disconnected reason=quit messages=N` in maillog, summed per 15 min | 0 to 4 per interval; 3 to 10 messages a day; 57 total over 8 days; all of it cron mail | 50 per interval | An operator alert only. It could fire on one send to more than 50 recipients, and the AUP ladder's first rung is a warning mail, so the member's cost is that warning, not a bounce |
| ssh authentication failures | `Failed password` or `Invalid user` lines in authlog, counted per source address per 15 min | 217,300 lines, 1,797 addresses, 35 days; worst single address 358 in one interval; 1,826 of 3,111 intervals above 10 | 300 per interval | Nothing lands on the member. The cost is that ssh alerts hold the one-hour cooldown and keep the other five checks silent |
| mail authentication failures | failed `smtp authentication` lines, and the dovecot pattern in section 2 | No SMTP failures; one IMAP failure on 2026-09-24, which the pattern does not match; 1,049 pre-auth scanner disconnects | keep the alert at any failure, and fix the pattern | A false alert here is one operator read. A missed one is a member's client failing to log in with nobody told |
| quota approach | `quota -u <user>` for each `/home/*/` | No quota exists on `/home`; the only reading is 1.2 MB used of 8.2 GB | keep 80, no data | None today. Once quotas exist, a member parked above the line re-alerts every hour forever; the member's mail is not refused until the soft limit plus grace |
| spamd greylist churn | `spamdb`, counting the lines that start with `GREY` | 3 live now; 3 to 37 new tuples a day, 90 tuples over 12 days; nothing samples the live count | 100 | Greylisting defers and then delivers, so the member sees nothing. The cost is an ignored "possible mail flood" |
| rotating senders | `(GREY) <ip>: <from> -> <to>` lines in `/var/log/daemon` for today, distinct addresses per sender | Spam senders use 1 to 4 addresses a day; the 2026-09-20 Outlook incident used 11 and 22 | 6 per day | A miss costs a member a bounced message, which is the 2026-09-20 incident. A false hit costs an operator read |
| IP blocklist | `dnsbl_verdict` in `scripts/lib.sh`, four zones, each behind its own control query | `clean zen.spamhaus.org` for 95.216.152.17 on 2026-09-30 | not a threshold | A refusal read as clean costs deliverability, so the member's outbound mail is rejected elsewhere with no local symptom |

---

## 1. Outbound volume spike

**Where it lives.** `/var/log/maillog`, one line per completed relay:

	Sep 30 11:15:12 mail smtpd[59508]: cd3923ee50818c21 mta disconnected reason=quit messages=1

**Command.** The monitor's own sum, per day and per 15-minute clock bucket:

	for f in /var/log/maillog.[0-6].gz; do gzip -dc "$f"; done | cat - /var/log/maillog |
	awk '/mta disconnected reason=quit/ {
		split($0,a,"messages="); n = a[2]+0
		if ($1 ~ /^[0-9]{4}-/) { t = substr($1,12,5); day = substr($1,1,10) }
		else { t = substr($3,1,5); day = $1 " " $2 }
		split(t,x,":"); b = x[1] ":" int(x[2]/15)*15
		msg[day " " b] += n; day_total[day] += n
	}
	END { for (k in msg) printf "%s %d\n", k, msg[k] }'

**Observed.** Over the eight days the log keeps, the daily totals are 9, 8, 5, 8, 10, 8, 6 and 3
messages, which are also the session counts, because every counted completion carries `messages=1`.
Bucketed into 15 minutes, 53 intervals hold one message and one holds four. The one interval with
more than a single message is 2026-09-28 16:30, where four messages left in eight minutes, and that
is the worst single reading in the window, against a proposed value of 50.

Two facts about what that traffic is. Every one of the 57 messages went to
`o.brotchie@gmail.com`, 52 of them from `root@mail.kyriakon.net` and 5 from
`oliver@mail.kyriakon.net`: this is cron output leaving the box, not a member sending. Inbound, for
contrast, runs 6 to 21 delivered messages a day.

**Proposed: 50 per interval.** The threshold cannot be fitted to this traffic, because the traffic
is 0 to 4. It can be bounded by it, and the rest of the choice is about what a real event looks
like. A compromised account is a step change rather than a trend: a spam run pushes hundreds or
thousands of messages through in one interval, and nothing in the monitor limits the rate, so 50
puts the first alert inside the same interval as the first burst while sitting 12 times above the
busiest interval this box has produced. The shipped 200 waits three more intervals, which is 45
minutes of a spam run nobody has been told about.

**False positive cost.** An operator alert and, at the worst, a warning mail under the AUP ladder,
because this alert is the first rung of it. Nothing in the monitor stops a member's mail, so a
false alarm cannot bounce a message by itself. The cost that matters runs the other way: a value
high enough to sit through a real relay means the first news arrives after the box is listed, and
the member's mail bounces at Gmail for reasons they cannot see.

**Not verified.** How a multi-recipient send counts. Every message in the window carried `nrcpt=1`,
so nothing here shows whether a send to 60 recipients reads as one or as 60 relayed messages, and
that is the observation which would move this value. It belongs with the same review that adds
members, since the count is global and not per member.

## 2. Authentication failures

### 2a. Mail side

**Where it lives.** Two patterns in `/var/log/maillog`, as the script has them:

	smtp authentication user=.*result=(perm|temp)fail
	auth:.*(pam_authenticate\(\) failed|unknown user)

**Command.**

	for f in /var/log/maillog.[0-6].gz; do gzip -dc "$f"; done | cat - /var/log/maillog |
	grep -cE 'smtp authentication user=.*result=(perm|temp)fail|auth:.*(pam_authenticate\(\) failed|unknown user)'

**Observed.** No SMTP submission has failed authentication in the window: there is no
`smtp authentication` line at all. For IMAP, Dovecot logged exactly one authentication failure, on
2026-09-24, and the pattern the monitor uses does not match it:

	Sep 24 21:46:12 mail dovecot: imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 0 secs): user=<>, method=NTLM, rip=118.26.104.78, lip=95.216.152.17, session=<...>

	$ awk '/auth:.*(pam_authenticate\(\) failed|unknown user)/{c++} END{print c+0}'
	0

That is a scanner offering NTLM with no username, so it is not a member's stale password, but it is
a genuine authentication failure in the form this build writes, and it went past the check.

The rest of the mail-side noise is probes rather than failures. Of the 4,426 lines in the retained
maillog, 1,057 mention `auth`; 1,049 of those are `(no auth attempts in N secs)` disconnects, the
rest are TLS failures and disconnects before authentication began. The other large group is 542
lines of `smtp disconnected reason="io-error: handshake failed: ..."` from scanners that never
reached a command, against which the log also holds 13 malformed-command refusals and 3 `550`
rejections.

**The dovecot half of the pattern matches nothing this build emits.**
`openbsd/dovecot/dovecot.conf` sets `passdb { driver = bsdauth }`, and the PAM failure string the
pattern names belongs to `passdb-pam.c`, which is not in this build:
`grep -rl pam_authenticate /usr/local/lib/dovecot` finds nothing, while
`strings /usr/local/lib/dovecot/libdovecot-login.so.4.0` holds the text this build does write,
`(auth failed, %u attempts in %u secs)`. The one failure in the window is exactly that form. The
alert fires on a count above zero, so there is no number to set here; the finding is that the check
is blind to the failure it exists to report.

**Proposed.** Keep the alert at any mail-side failure, since each one is a real client with a stale
password, and fix the pattern to the log line this build writes. A failed login is the one
member-visible failure in this group: the member's mail client stops working and the first they hear
of it is their own client's error, or nothing at all.

**False positive cost.** An operator read. A stale password on a phone produces exactly this alert,
and the body already says so.

**Not verified.** Whether a member's wrong password produces the same line form as the scanner
failure above. The deployed passdb driver, the strings in the installed objects and the one observed
failure all point at `(auth failed, N attempts in M secs)`, and producing a member-side failure needs
a state change that this ticket forbids.

### 2b. SSH side

**Where it lives.** `/var/log/authlog`:

	Sep  3 21:43:40 mail sshd-session[55550]: Invalid user admin from 2.57.121.25 port 63572
	Sep  3 21:43:40 mail sshd-session[55550]: Failed password for invalid user admin from 2.57.121.25 port 63572 ssh2

**Command.** The monitor's per-address tally is in `scripts/abuse-monitor.sh`. The window figures
below come from the same match, bucketed into 15 minutes and reduced to the worst address per
window:

	for f in /var/log/authlog.[0-4].gz; do gzip -dc "$f"; done | cat - /var/log/authlog |
	awk '/Failed password|Invalid user/ {
		for (i = 1; i < NF; i++) if ($i == "from") { ip = $(i+1); break }
		if (ip == "") next
		if ($1 ~ /^[0-9]{4}-/) { t = substr($1,12,5); day = substr($1,1,10) }
		else { t = substr($3,1,5); day = $1 " " $2 }
		split(t,x,":"); b = x[1] ":" int(x[2]/15)*15
		c[day " " b "|" ip]++
	}
	END { for (k in c) { w = substr(k,1,index(k,"|")-1); if (c[k] > mx[w]) mx[w] = c[k] }
	      for (w in mx) print mx[w] }'

**Observed.** 217,300 matching lines over 35 days, from 1,797 distinct source addresses. The count
is inflated relative to the number of attempts: an attempt with an unknown username writes both an
`Invalid user` line and a `Failed password` line, the pattern matches both, and the IP is taken from
the same `from` token, so the tally is about 1.7 times the attempts (130,770 `Failed password` lines
and 86,530 `Invalid user` lines, with 75,022 of the former belonging to the latter).

Daily totals run from 458 (2026-09-30) to 14,267 (2026-09-12). The storm is the stretch from
2026-08-28 to 2026-09-21, when no day fell below 2,242 lines, largely one /24 rotating through
`109.160.32.x`. From 2026-09-22 to 2026-09-30 the daily total is 458 to 1,606 lines.

Bucketed into 15-minute intervals, 3,111 intervals contain at least one failure, and the worst
single address in each interval distributes like this:

| worst address in the interval | intervals |
|---|---|
| 0 to 9 | 1,200 |
| 10 to 99 | 1,448 |
| 100 to 199 | 170 |
| 200 to 299 | 253 |
| 300 or more | 40 |

Counted as intervals rather than address-interval pairs, an address above 10 is present in 1,826 of
the 3,111 intervals, above 100 in 462, above 200 in 291, and above 300 in 38. The worst reading
anywhere is 358, from `109.160.32.200` in the 17:45 interval on 2026-09-08. Over the last nine days
the worst is 67, on 2026-09-22.

**Proposed: 300 per interval.** At 10 the threshold sits inside the background of a public box
rather than above it, and it fires in 1,826 intervals, which is most of every day of the storm. With
one global cooldown that does not merely make noise: it holds the alert channel for an hour at a
time and keeps the outbound, quota, greylist, sender and blocklist checks from ever being heard.
300 is roughly 20 guesses a minute from one address sustained for a quarter of an hour, above
every interval of the quiet period (worst 67) and at the top of the storm's range, so it means a
single source is working hard rather than that the internet is on. The number counts what the
script counts, which is lines and not attempts, so it is about 180 real attempts.

An honest limit: a threshold on one address cannot see a swarm. The storm that dominates this
period was thousands of lines a day from addresses that mostly stayed under 20, and no value of
`AUTH_FAIL_MAX` would have reported it. The total, which the alert already prints without testing
it, is the signal that moves for a swarm.

**False positive cost.** None of it lands on a member. Password authentication is off everywhere, so
no guess can succeed, and the alert's action is an optional pf block. The cost is the alert channel:
each ssh alert locks the other five checks out for an hour, and at the shipped 10 that is a
permanent lockout during an attack. The cost of a value that is too high is that a single host
grinding through a list goes unmentioned, which is a log-volume and CPU matter and not a
member-visible one.

## 3. Quota approach

**Where it lives.** `quota -u <user>` for each directory under `/home/`.

**Command.**

	quota -u oliver
	quota -u oliver | awk '/^\// && $3 > 0 { pct = int($2*100/$3); if (pct >= 80) print }'

**Observed.** No quota has ever been computed, because none is enabled. `quota -u oliver` prints
`Disk quotas for user oliver (uid 1000): none`. There is no `/home/quota.user`,
`/etc/fstab` mounts `/home` as `rw,nodev,nosuid` with no `userquota`, and the check requires a line
beginning with `/` whose third field is a nonzero soft limit, so the awk cannot print anything at
any value of `QUOTA_WARN_PCT`. The one reading available is usage rather than a percentage: 1.2 MB
used of 8,207 MB on `/home`, with one account in it.

**Proposed: leave 80, and say plainly that the period cannot support a number.** The only
observation that changes this is the first `quota -u` line that carries a soft limit, which is the
day `/home` mounts with `userquota` and `quotaon` runs. That value should then be set against the
member's plan rather than against usage data, because the alert is about approaching a limit the
plan sets, and the soft limit is where the grace period starts rather than where mail stops.

**False positive cost.** Nothing today, because the check cannot fire. Once quotas exist, this is
the check that does not remember anything: any run with usage at or above the line calls `alert()`,
so a member parked at 81 percent re-alerts every hour until they drop below it, and the cooldown
turns that into 24 alerts a day. The member's mail and files are unaffected until the soft limit
plus the grace period is reached, so the cost of a value that is too low is the operator's
attention, not the member's mailbox.

## 4. Spamd greylist churn

**Where it lives.** The `spamdb` dump for the live count, and `/var/log/daemon` for new decisions:

	Sep 20 10:19:49 mail spamd[8707]: (GREY) 209.85.222.202: <noreply-dmarc-support@google.com> -> <dmarc@kyriakon.net>

**Command.**

	spamdb | awk -F'|' '{c[$1]++} END {for (k in c) printf "%s %d\n", k, c[k]}'
	for f in /var/log/daemon.[0-4].gz; do gzip -dc "$f"; done | cat - /var/log/daemon |
	grep -c '(GREY)'

**Observed.** The live count on 2026-09-30 is 3 GREY, 5 WHITE and 2 TRAPPED. The log records new
greylist decisions: 3 on 2026-09-18, 17 on the 19th, 37 on the 20th, 13, 4, 4, 12, 4, 5, 3, 4 and 8
on the 30th, 114 lines in all and 90 distinct tuples over 12 days. The busiest period is
2026-09-20, and the worst single reading of the value the check actually tests is 37, if every tuple
created that day were alive at once, which it was not.

The check reads a live count and nothing samples it, so the peak in the period is unmeasured and
only the current 3 is known. Two bounds come from the log: the most tuples ever created in one day
is 37, and the most ever created in the whole window is 90. Spamd connections, which are the
background the churn sits on, run 24 a day at the start and 150 to 440 a day through the rest of
the period, with a worst interval of 150 connections on 2026-09-26 at 09:15.

**Proposed: 100.** This is the weakest of the six values, and the reasoning is a bound rather than a
fit. The busiest day created 37 tuples in 24 hours and the live count today is 3, so 100 sits above
any day this box has produced and well below what a flood means, which is many hosts arriving at
once. The observation that would set it properly is a week of live counts after real members exist,
sampled from `spamdb` on a timer, since the steady state grows with the number of correspondents
and this check reads that steady state rather than a rate.

**False positive cost.** Greylisting defers a message and delivers it on the retry, so a member
sees nothing when this alert is wrong. The cost is an operator who reads "possible mail flood" on a
day when a new member's correspondents were simply being seen for the first time.

## 5. Senders deferred from several addresses

**Where it lives.** `/var/log/daemon`, in the spamd verbose lines for today:

	Sep 20 11:55:45 mail spamd[8707]: (GREY) 52.101.95.123: <oliver.brotchie@edinburgh-orthodox.org.uk> -> <oliver@kyriakon.net>

**Command.** The monitor's own awk prints, for each envelope-from seen today, how many distinct
addresses it was deferred from, and keeps only those at or above `DEFER_MIN`:

	awk -v day="$(date '+%b %e')" -v min=6 '
		$0 ~ "^" day && /\(GREY\)/ {
			f = $8; gsub(/[<>]/, "", f)
			pair = f "|" $7
			if (!(pair in seen)) { seen[pair] = 1; n[f]++ }
		}
		END { for (f in n) if (n[f] >= min) print n[f], f }' /var/log/daemon | sort -rn

**Observed.** Twelve days, and the senders fall into two groups with a gap between them. Below 5
addresses a day are the relay attempts and the spam: `spameri@tiscali.it` appears from 2 to 4
addresses on seven of the twelve days, and the one-off senders all appear from a single address.
Above that are the real correspondents: `oliver.brotchie@edinburgh-orthodox.org.uk`, which is the
Outlook-hosted sender of the 2026-09-20 incident, from 11 addresses on the 19th and 22 on the 20th,
and `noreply-dmarc-support@google.com` from 5 addresses on the 20th, which the `nospamd` table now
covers. On 2026-09-30 a SendGrid bounce sender, `bounces+112604537-3ded-ob=kyriakon.net@...`, was
deferred from 3 addresses and is still in the live table.

At the shipped 3, the check reports on 8 of the 13 days. At 6 it reports on the 19th and the 20th,
which are the days the message was actually lost.

**Proposed: 6 per day.** The gap between 4 and 11 is what the data gives, and 6 sits in it with
margin on both sides: above every spam sender observed, and below the two days of the real incident.
The alternative reading is a threshold of 4, which catches more and pays for it with an alert every
second or third day.

**False positive cost.** A miss costs a member a message. That is not a hypothetical: the Outlook
sender on 2026-09-20 was deferred from 22 addresses until it gave up, and the mail bounced. A false
hit costs an operator read, which is the cheaper error, except that it is the same channel as the
failures that matter and the alert's advice, add the sender to `nospamd`, is wrong advice for a
botnet. One case the proposed 6 would not report is the 3-address SendGrid sender stuck in the table
today, which is the known cost of the margin.

## 6. IP reputation blocklist

**Where it lives.** No log. `dnsbl_verdict` in `scripts/lib.sh` queries the four zones
`zen.spamhaus.org bl.spamcop.net all.s5h.net dnsbl.dronebl.org` in order, each behind a control
query for `2.0.0.127.<zone>`, and returns the first verdict.

**Command.** The function, run on the box over stdin from the checked-out `lib.sh`:

	. scripts/lib.sh && dnsbl_verdict 95.216.152.17
	# clean zen.spamhaus.org

and the underlying queries, which is where the failure mode shows:

	for z in zen.spamhaus.org bl.spamcop.net all.s5h.net dnsbl.dronebl.org; do
		dig +short @127.0.0.1 2.0.0.127.$z A; dig +short @127.0.0.1 17.152.216.95.$z A
	done

**Observed.** The box is not listed, as of 2026-09-30 18:45. All four zones answer their control
through the box's own `unbound`, which is running and answers on 127.0.0.1, so the function takes the
first zone and reports `clean zen.spamhaus.org`. The state directory holds no `dnsbl.unchecked`,
which agrees: that file is written only when every zone refuses, and the last run would have left it
behind.

There is no number to set here. What there is instead is a failure mode in the fallback. Queried
against the resolver in `/etc/resolv.conf`, Hetzner's `185.12.64.2` rather than the local
`unbound`, `zen.spamhaus.org` answers its own control with `127.255.255.254`, which the function
reads as a refusal, skips the zone and takes the verdict from `bl.spamcop.net` instead. The comment
in `lib.sh` covers the refusal honestly, but the fallback still prints a clean verdict from a weaker
list, so a box whose `unbound` stops answering would appear checked while the list that drives
filtering at the large providers is no longer being asked.

**False positive cost.** A listing is a fact rather than a threshold, and the control query stops a
refusal from being read as one. The error that costs a member something is the other one: a
downgraded or unanswered check reports clean, nobody acts, and the member's outbound mail is
refused at Gmail and Outlook while everything on this box looks healthy.

---

## What the dogfood period cannot support

- **Any member-scale traffic.** There is one account, no quota, no list sending and no second
  mailbox. Every outbound message in the window is the box's own cron output.
- **A fitted outbound value.** The observed range is 0 to 4 per interval, so 50 is a bound from the
  harm model, not a measurement, and how a multi-recipient message counts is unverified.
- **A fitted SSH value for swings.** 35 days is enough to see the storm and the quiet week, and not
  enough to know which is normal. The storm was still 1,000 to 1,600 lines a day when the window
  ended.
- **Any number for quota.** The check requires a soft limit that does not exist. 80 has never run.
- **A mail-side failure rate.** Eight days hold one authentication failure, and it came from a
  scanner rather than a client, so there is no shape to fit and nothing to set. What the window does
  support is the finding that the pattern misses the form this build writes.
- **The greylist peak.** Nothing samples the live count, so the only value ever observed is 3 today.
  100 is bounded by 37 tuples created in the busiest day, not fitted to a distribution.
- **A firm separation for rotating senders.** Two days carry the real-incident side of the gap, and
  one of them is the day the Outlook message was lost. A third case at 3 addresses, the SendGrid
  sender live today, sits on the spam side of the proposed line.
- **Anything about the blocklist over time.** One clean reading at one moment. Whether the box was
  listed on any other day is in Healthchecks' event log, off this box and not read here.
- **The effect of starting from the shipped values.** The monitor's first run baselines without
  alerting, and no historical replay exists, so none of these thresholds has ever been evaluated
  against the traffic in this note.

## Tested versus documentary

Run on the box, read-only, with nothing written outside `/tmp`:

- Counts and distributions from `gzip -dc` over `/var/log/authlog.{0-4}.gz` and `/var/log/authlog`,
  `/var/log/daemon.{0,}.gz` and `/var/log/daemon`, `/var/log/maillog.{0-6}.gz` and `/var/log/maillog`,
  through `awk`, `grep`, `sort` and `wc`. Every number in this note comes from those reads.
- `ls -l`, `stat -f` and `cat` on `/var/db/kyriakon-monitor/*`, twice, which is how the 18:30:01 and
  18:45:01 runs and the single global cooldown were seen rather than read from the source.
- `spamdb`, which the unprivileged account can run, for `GREY`, `WHITE` and `TRAPPED` counts.
- `quota -u oliver`, `df -h /home`, `/etc/fstab` and `/etc/newsyslog.conf` for the quota and
  rotation facts.
- `dig` against `127.0.0.1` and against the resolver in `/etc/resolv.conf`, for the four zones, their
  controls and the box's own address, and `dnsbl_verdict` from `scripts/lib.sh` sourced over stdin.
- `strings` on `/usr/local/lib/dovecot/libauthdb_imap.so`,
  `/usr/local/lib/dovecot/libdovecot-login.so.4.0` and `/usr/local/libexec/dovecot/imap-login`, and
  `grep -rl` for `pam_authenticate` across `/usr/local/lib/dovecot`.
- Reads of `openbsd/dovecot/dovecot.conf`, `/etc/mail/spamd.conf`, `/etc/mail/nospamd`,
  `/etc/syslog.conf`, `/etc/resolv.conf`, and `man 8 spamdb`.
- `rcctl check cron unbound`, `pgrep -l cron unbound`, `ifconfig egress`.

Read from the repository rather than the box:

- `scripts/abuse-monitor.sh` and `scripts/lib.sh` for what each check reads, what the cooldown does,
  and which state files exist. The deployed copies under `/root/bin` are mode-restricted to root and
  were not readable, so the on-box script was not compared against this revision.
- `scripts/cron-apply.sh` for the `*/15` line and the environment file it sources.

Not verified, and not verifiable without a state change:

- What the deployed `/root/bin/abuse-monitor.sh` contains. The state files prove a copy is running
  every 15 minutes; whether it matches this revision is a separate question, and the file is not
  readable from the account used.
- Whether the monitor or its pattern would have reported a failing member client. One failure was
  observed and the pattern did not match it, so the blind spot is real; what is not observed is a
  failure caused by a member's own client, which needs an account with a wrong password.
- Whether a multi-recipient send counts once or once per recipient in the outbound tally.
- What the monitor has alerted on since 2026-09-21. Alerts leave the box by mail and by Healthchecks
  ping, and neither store was read.

## Primary sources

OpenBSD 7.9, on the box:

- `/etc/newsyslog.conf`, for the retention of `maillog`, `authlog` and `daemon`, which sets the
  window every signal here is measured over.
- `/etc/fstab`, `/etc/passwd`, `/etc/syslog.conf`, `/etc/resolv.conf`.
- `man 8 spamdb`, for the entry types and fields of the `spamdb` dump.
- `man 8 spamd`, for the greylist database `spamdb` reads.
- `/etc/mail/spamd.conf` (the empty `all:` tag) and `/etc/mail/nospamd` (the Microsoft and Google
  ranges that make the 2026-09-20 sender class stop appearing).

This repository:

- `scripts/abuse-monitor.sh`, the six checks, the alert function and the cooldown, and the crontab
  line the header documents.
- `scripts/lib.sh`, `dnsbl_verdict` and the zone list it defaults to.
- `scripts/cron-apply.sh`, for how the line is installed and where the per-box values live.
- `docs/planning/specs/phase-1-foundations.md` items 30 to 33 and the note that the thresholds are
  to be tuned during dogfood.
- `docs/planning/research/spamd-greylisting.md`, for the 2026-09-20 Outlook incident this note uses
  as the worked example of the rotating-sender signal.
- `openbsd/dovecot/dovecot.conf`, for the deployed passdb driver.

## What this means for the map

Three of the six values can be set now from the data in this note: the SSH per-address count to 300,
the sender count to 6, and the outbound volume to 50 as a bound from the harm model. Two carry a
defect that no threshold fixes, and they belong in the spec as work rather than as numbers. The
mail-side authentication pattern misses the line this build writes for a failure, which the window
shows with one real failure it did not catch, so requirement 31 is only half met: SSH failures are
visible and SMTP and IMAP failures are not. The quota check has no soft
limit to read, which is the same missing quota the per-account note records for the suspended state,
so requirement 32 is met by a check that cannot fire.

The scaling question belongs in the same review. Five of the six counts are global to the box, so
member count changes what normal means, and the values above are set for one member. The observation
that would move them is a week of the same extractions once real members and quotas exist, and the
two worth re-deriving first are the outbound volume, which a single large send can reach, and the
greylist count, whose steady state grows with the number of correspondents.
