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

Three details, all from spamd(8).

The `table <spamd-white> persist` line is required. spamd continuously writes the
hosts it has decided to let through into that table, and pf(4) refuses to load a
ruleset that references a table which does not exist. The two-line version of
this fragment that issue #43 carried would have failed to load.

`<spamd-white>` is maintained by spamd itself, from the `/var/db/spamd`
database. Neither `spamd-setup(8)` nor `spamd.alloweddomains` fills it. It is how
a host that has retried gets to the real MTA: its next connection matches the
third rule instead of the divert.

The third rule only works because it sits after the divert. For a whitelisted
host the later `pass` overrides the earlier redirect, and for everyone else the
divert stands.

## What is not needed for greylisting

`spamd.conf` and a `spamd-setup` cron entry exist to load blacklists, from DNSBLs
or from local files. Greylisting is spamd's default mode and runs with no lists
at all, which is why this repository has no `spamd.conf`.

`spamd.alloweddomains` is not a `spamd.conf` white list. It holds destination
domain suffixes, while a `:white:` list in `spamd.conf` holds source addresses
that get removed from a preceding blacklist. Pointing a `:white:` entry at the
domains file would either do nothing or fail to parse, and the config test below
would fail with it.

If blacklists are wanted later, that is when `spamd.conf` (an `all:` line plus
the list entries) and the cron entry earn their place. Address traps are separate
again and are added with `spamdb -T -a 'spamtrap@kyriakon.net'`.

## Timing

Defaults, from `-G passtime:greyexp:whiteexp` in spamd(8):

- `passtime` 25 minutes. How long a host waits before a retry is accepted. This is
  the delay a first-time sender sees, by design.
- `greyexp` 4 hours. A greylist tuple is dropped if the host never retries.
- `whiteexp` 864 hours, about 36 days. How long a whitelisted host stays
  whitelisted, and the retention figure `docs/threat-model.md` quotes.

## Applying and reverting

	doas cp /etc/pf.conf /tmp/pf.conf.new
	cat >> /tmp/pf.conf.new <<'EOF'
	...fragment...
	EOF
	doas pfctl -nf /tmp/pf.conf.new     # config test: parses, checks tables
	doas cp /tmp/pf.conf.new /etc/pf.conf
	doas pfctl -f /etc/pf.conf

`pfctl -nf` is the check that matters here, since it is what catches a table that
was never declared before the ruleset goes live.

Reverting is the same in reverse: remove the three lines, then `pfctl -f
/etc/pf.conf`. `rcctl disable spamd` plus `rcctl stop spamd` retires the daemon.

## Verifying

	rcctl check spamd                        # ok
	pfctl -sr | grep spamd                   # divert first, white pass second
	spamdb | grep -c '^GREY|'                # grows on first contact
	spamdb | grep '^WHITE|'                  # the host, after it retries

First contact from a new sender is deferred with a 4xx and appears as a `GREY`
tuple. Once the host retries, past `passtime`, the mail is accepted and the host
appears as `WHITE`. `scripts/abuse-monitor.sh` already reads `spamdb`, so its
greylist churn and trapped-host alerts start producing real numbers the moment
the divert is live.
