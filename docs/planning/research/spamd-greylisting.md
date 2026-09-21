# spamd greylisting: what switches it on and what does not

Greylisting is configured in two places, and `spamd.conf` is neither of them.

The pf divert is the switch. Until the fragment below is in `/etc/pf.conf` and
the ruleset is reloaded, no inbound mail reaches spamd and nothing greylists.

`/etc/mail/spamd.alloweddomains` is the second place, and spamd reads that fixed
path itself. It lists destination domain suffixes. A greylisted host that sends
mail to a destination matching none of them is treated as a spammer and
blacklisted for 24 hours, which is why the file lists every domain the platform
accepts mail for.

## The fragment

Appended to the END of `/etc/pf.conf`, because pf is last-match-wins: a divert
placed before the stock `pass all` line is silently overridden by it.

	table <spamd-white> persist
	pass in on egress proto tcp to any port smtp \
	    divert-to 127.0.0.1 port spamd
	pass in log on egress proto tcp from <spamd-white> to any port smtp

Three details.

The `table <spamd-white> persist` line is upstream's own, from the example in
spamd(8). spamd writes the hosts it decides to let through into that table, and
`persist` is what keeps the table in the kernel when no rule refers to it:
pf.conf(5) removes a non-persistent table as soon as the last rule referring to
it is flushed, so a reload would otherwise throw the learned whitelist away.

An earlier draft of this fragment left the line out, on the theory that pf
refuses to load a rule referencing an undeclared table. That is not something a
parse check can show: table existence is a kernel property, so `pfctl -nf`
accepts the rule either way, and the claim was never verified against a real
load. The line stays because spamd needs a table to write into and because
upstream declares it, not because the alternative is proven broken.

`<spamd-white>` is maintained by spamd itself, from the `/var/db/spamd`
database. Neither `spamd-setup(8)` nor `spamd.alloweddomains` fills it. It is how
a host that has retried gets to the real MTA: its next connection matches the
third rule instead of the divert.

The third rule only works because it sits after the divert. For a whitelisted
host the later `pass` overrides the earlier redirect, and for everyone else the
divert stands.

## The second daemon

`spamlogd` is not optional, and leaving it out looks exactly like a broken
firewall. spamd(8) says so twice: whitelist entries in `/var/db/spamd` are updated
by spamlogd when it sees connections pass to the real MTA on the SMTP port, and
they are removed when no such activity is seen within `whiteexp`. It reads the
pflog interface, which is why the passthrough rule carries `log`.

Without it nothing is ever whitelisted. `<spamd-white>` stays empty, rule 3 never
matches, every contact is diverted to spamd, and a sender that retries forever is
refused forever. That was the state of this box on 2026-09-18: the table existed
and was empty, the divert worked, and three separate contacts from one outside
host at 19:48, 20:17 and 20:18 were all answered by spamd.

## What is not needed for greylisting, and the one file that is

Greylisting is spamd's default mode and needs no list to run. `spamd.conf` and
`spamd-setup(8)` exist to load blacklists, so neither is needed *for greylisting*.

`spamd.conf` is installed anyway, for an unrelated reason: /etc/rc.d/spamd runs
`spamd-setup` on every start, and spamd-setup reads that fixed path and aborts with
`Can't find "all" in spamd config` when the tag is absent. A start that returns
nonzero takes the deploy down with it under `set -e`. The file carries an empty
`all:` and no lists, so it loads nothing.

That tag is easy to get wrong. `all:\` with nothing after the backslash is an
unterminated capability record, and cgetent(3) then fails to find the tag while
reporting the failure with a stale errno from an earlier open, so the message
reads `Can't find "all" in spamd config: No such file or directory` while the
file sits there readable. Confirmed with a throwaway cgetent harness on the box:
the bare `all:` is found, and so is `all:\` followed by a whitespace-only
continuation line. The deploy's `spamd-setup -n` is the check that catches it.

A `spamd-setup` cron entry is not needed either. The rc.d start path already runs
it, and with no blacklists there is nothing to refresh.

`spamd.alloweddomains` is not a `spamd.conf` white list. It holds destination
domain suffixes, while a `:white:` list in `spamd.conf` holds source addresses
that get removed from a preceding blacklist. Pointing a `:white:` entry at the
domains file would fail to parse as an address, and a list needs its own
`:file=` besides.

If blacklists are wanted later, the `all:` tag is where they get listed. Address
traps are separate again and are added with `spamdb -T -a 'spamtrap@kyriakon.net'`.

## Timing

Defaults, from `-G passtime:greyexp:whiteexp` in spamd(8):

- `passtime` 25 minutes. How long a host waits before a retry is accepted. This is
  the delay a first-time sender sees, by design.
- `greyexp` 4 hours. A greylist tuple is dropped if the host never retries.
- `whiteexp` 864 hours, about 36 days. How long a whitelisted host stays
  whitelisted, and the retention figure `docs/threat-model.md` quotes.

## Applying and reverting

The supported way is

	doas ksh scripts/pf-apply.sh --check     # show the diff, write nothing
	doas ksh scripts/pf-apply.sh             # append, check, back up, load

It appends whichever fragment is missing, skips one whose rules are already
present, refuses to install a candidate that `pfctl -n` rejects, keeps the file
it replaced as `/etc/pf.conf.bak.<timestamp>`, and loads nothing that fails to
re-check. It only appends: it never removes a rule, and it does not touch sshd.
pf loads a ruleset atomically, so a rejected load leaves the running ruleset in
place. Running it is a human step.

The recipe below is what that script does, for reading:

	doas cp /etc/pf.conf /tmp/pf.conf.new
	cat >> /tmp/pf.conf.new <<'EOF'
	...fragment...
	EOF
	doas pfctl -nf /tmp/pf.conf.new     # config test: parses, checks tables
	doas cp /tmp/pf.conf.new /etc/pf.conf
	doas pfctl -f /etc/pf.conf

`pfctl -nf` checks syntax only. It does not check tables, which live in the
kernel, so it accepts a ruleset referencing a table nobody declared and will not
catch that class of mistake. To test the load itself without touching the live
ruleset, load the fragment into a scratch anchor:

	pfctl -a spamd-test -f /tmp/pf-frag-test.conf
	pfctl -sT | grep spamd            # the tables now exist in the kernel
	pfctl -a spamd-test -sr           # the three rules parsed into the anchor
	pfctl -a spamd-test -F rules      # drop the scratch anchor; tables remain

Nothing routes through an anchor the main ruleset does not reference, so this
changes no traffic, and the tables it creates are the ones the real load needs.

Reverting is the same in reverse: remove the three lines, then `pfctl -f
/etc/pf.conf`. `rcctl disable spamd` plus `rcctl stop spamd` retires the daemon.

## Senders that rotate their address

Promotion needs a retry for the same tuple, and a tuple is the connecting IP plus
the HELO, envelope-from and envelope-to, per spamd(8). A sender that picks a
different outbound address for every retry never presents the same tuple twice,
so it is never promoted, stays greylisted, and is eventually bounced.

That is what happened on 2026-09-20 to mail from an Outlook-hosted domain. One
message, five attempts in four hours, five different `52.101.x` addresses:

	10:55:47 (GREY) 52.101.196.120: <oliver.brotchie@edinburgh-orthodox.org.uk> -> <oliver@kyriakon.net>
	11:55:45 (GREY) 52.101.95.123:  same envelope
	12:56:17 (GREY) 52.101.96.136:  same envelope
	13:56:29 (GREY) 52.101.196.122: same envelope
	14:57:19 (GREY) 52.101.195.135: same envelope

Google's mail the same morning got through, because its retry came from the same
address as its first attempt: `209.85.216.74` connected at 10:49 and again at
13:07, which promoted the address and let the delivery in at 14:38.

The fix is the `nospamd` table in the man page's fragment, which sends inbound
SMTP from listed networks straight to smtpd. `openbsd/etc/nospamd` holds
Microsoft's published outbound ranges and the deploy installs it; the two pf
rules that read it are the second fragment `pf-apply.sh` adds. Refresh the list
from the same source, which is Microsoft's own SPF record:

	dig +short TXT spf.protection.outlook.com

Add other large senders the same way once one is seen being deferred from a
rotating address. Whitelisting single addresses with `spamdb -a` does not help
with a pool, since each retry arrives on a different one.

## Verifying

	rcctl check spamd spamlogd                    # both; see the second daemon above
	pfctl -sr | grep -E 'divert-to|spamd-white'   # the divert, then the passthrough
	pfctl -t spamd-white -T show                  # fills once a host is whitelisted
	doas spamdb | grep -c '^GREY|'                # grows on first contact
	doas spamdb | grep '^WHITE|'                  # the host, after it retries

`pfctl -sr` prints a service name as its port number, so the loaded divert rule
reads `divert-to 127.0.0.1 port 8025`. Searching that output for "spamd" finds the
passthrough rule and not the divert, which reads as a missing redirect on a box
where the redirect is present and working. `spamdb` needs root: as an ordinary
user it prints nothing at all, which reads as an empty database.

First contact from a new sender is deferred with a 4xx and appears as a `GREY`
tuple. Once the host retries, past `passtime`, the mail is accepted and the host
appears as `WHITE`. `scripts/abuse-monitor.sh` already reads `spamdb`, so its
greylist churn and trapped-host alerts start producing real numbers the moment
the divert is live.
