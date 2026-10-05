# The SSH onboarding TUI

> Spec synthesised from [Spec the SSH onboarding TUI](https://github.com/kyriakon/kyriakon-infra/issues/245) and the decisions it takes as input: [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) (the second sshd instance, the password-less session and the wizard), [#154](https://github.com/kyriakon/kyriakon-infra/issues/154) (the hosting port split and the mandatory upload key), [#182](https://github.com/kyriakon/kyriakon-infra/issues/182) (the shared question list, the status token and the counters), [#176](https://github.com/kyriakon/kyriakon-infra/issues/176) and [#185](https://github.com/kyriakon/kyriakon-infra/issues/185) (the key walkthrough and the shared check crate), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156) (the service's trust boundary), [#233](https://github.com/kyriakon/kyriakon-infra/issues/233) (the community block) and [#150](https://github.com/kyriakon/kyriakon-infra/issues/150) (the OpenBSD mechanics, tested on the box). The proposal's section 5.9.2 is superseded on the transport by [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) and is not decided again here.

## Problem statement

Kyriakon takes applications three ways and writes them into one back end: the web form at release, and a gemini capsule and an SSH TUI built once the platform is live. The SSH path is the one where the applicant already has a terminal, so it can do what the web form does and a little more, and the risk is that it grows into a second privileged way into the platform.

[#183](https://github.com/kyriakon/kyriakon-infra/issues/183) settled the transport. The platform runs a second stock `sshd` instance rather than the bespoke `russh` server the proposal parked. OpenBSD's own `sshd_config(5)` lists `none` among the authentication methods, "used for access to password-less accounts when `PermitEmptyPasswords` is enabled" (read on 2026-10-05), so the daemon the base system audits carries the key exchange and the authentication and the only authored program is the one the applicant talks to behind `ForceCommand`.

What remains is the shape of that program and its session: the config file, port, account and unit the instance needs, the screens the applicant sees, how the application and its key are handled, what the applicant takes away, and what the session must never be able to do. This spec fixes all of that and leaves the web form, the capsule and the drain to their own specs.

## Solution

A second `sshd` instance runs from its own config file on a port chosen when the box is built, and the only account it can serve is a password-less system account named `onboard`. Nothing is asked of the applicant: no password, no key, no published credential. The account has no shell and the instance forces one program, a line-oriented TUI, so the connection is a text pipe into an application form.

The TUI prints a first screen that says what it is, then walks the shared question list one question at a time with a counter, then prints the key walkthrough, accepts a pasted public key and checks it with the same crate the web form uses, then shows a summary to confirm, then files one intent through the onboarding handler and hands back the status token. It can read that status back later by token. Its per-address counters answer an over-eager source with a plain screen. It holds no privilege, no secrets and no shell, and the human approval stays the real gate.

## The second sshd instance

The instance is a stock `/usr/sbin/sshd` started with `-f /etc/ssh/sshd_config.onboard`, the file the repo keeps at `openbsd/etc/sshd_config.onboard`. It is a separate file, port, `PidFile` and account from the member sshd in `/etc/ssh/sshd_config`, which this change does not touch. It shares the box's host keys, because no `HostKey` line is set and sshd falls back to the same `/etc/ssh/ssh_host_*` files, so the box keeps one SSH identity.

The file is applied by hand, like the member one, with `doas sshd -t -f /etc/ssh/sshd_config.onboard` and then an `rcctl restart kyriakon_onboard`. The port line carries the deploy value the build chose, written as `REPLACE_ME` in the repository and substituted from `/etc/kyriakon/onboard/tui.env` at install.

```ssh_config
# /etc/ssh/sshd_config.onboard
# The applicant-facing sshd, run by /etc/rc.d/kyriakon_onboard. Separate file,
# port, PidFile and account from the member sshd in /etc/ssh/sshd_config, which
# is not touched. Reviewed line by line and applied by hand.

# No HostKey line, so sshd reads the same /etc/ssh/ssh_host_* keys the member
# instance uses and the box keeps one SSH identity.
Port REPLACE_ME
PidFile /var/run/sshd.onboard.pid

# Only the onboard account is reachable, before authentication. That is what
# lets the instance carry PasswordAuthentication yes, which the none method
# needs: userauth_none() calls mm_auth_password("") only when
# permit_empty_passwd and password_authentication are both on (auth2-none.c).
AllowUsers onboard
PermitRootLogin no
LoginGraceTime 30

# Pre-auth connection caps. PerSourceMaxStartups is the per-address one.
# sshd drops the excess TCP connection and writes nothing; the TUI's own
# counter answers the same condition with the screen in its own section.
MaxStartups 4:50:10
PerSourceMaxStartups 2
PerSourceNetBlockSize 32:128

Banner none
VersionAddendum none

# Every connection lands in authlog, where the abuse monitor counts it.
LogLevel VERBOSE
SyslogFacility AUTH

Match User onboard
	# Nothing is asked of the applicant: no credential exists to leak, rotate
	# or publish. The account is password-less, which is the condition the
	# none method documents.
	PermitEmptyPasswords yes
	PasswordAuthentication yes
	AuthenticationMethods none
	KbdInteractiveAuthentication no

	# A text pipe and nothing else: no pty, no forwarding, no ~/.ssh/rc, and
	# one channel per connection.
	MaxSessions 1
	PermitTTY no
	DisableForwarding yes
	PermitOpen none
	PermitUserRC no

	# The one program the account can run, on every path.
	ForceCommand /usr/local/sbin/kyriakon-onboard-tui
```

`PermitEmptyPasswords` in the `Match` block is inside the subset of keywords `sshd_config(5)` allows after `Match`. `PerSourceMaxStartups` is not, so it sits at the top level, which is harmless because `AllowUsers onboard` makes the instance serve one account. `Banner none` is the documented default and is written out so a future default change cannot quietly reintroduce a banner; a banner is read by every scanner and by nobody the platform wants. The protocol identification string itself cannot be removed, and `VersionAddendum none` stops it carrying the local operating system suffix.

### The account

`onboard` is a system account with an empty password field, a home of `/var/empty` and a `/sbin/nologin` shell. It is created once, at build time, after its login class exists:

```
useradd -d /var/empty -c "Kyriakon onboarding TUI" \
	-s /sbin/nologin -L onboard -p '' onboard
```

`useradd -p ''` stores the empty string in the password field (user(8) writes `up->u_password` verbatim), and provisioning verifies the result before the instance is enabled:

```
awk -F: '$1 == "onboard" { print length($2) }' /etc/master.passwd   # must print 0
```

A non-zero length fails the build, because a disabled account (`*`) would not authenticate with the `none` method and the instance would be a port that refuses everyone.

The shell in the password file stays `/sbin/nologin`, which is the one [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) asks for, and the session still runs the TUI because sshd takes its shell from the account's login class rather than from the password field. `do_child()` runs `shell = login_getcapstr(lc, "shell", pw_shell, pw_shell)` in `session.c`, and `auth.c` sets `lc = login_getclass(pw->pw_class)`, so the class's `shell` capability is the shell sshd execs the forced command through. The class is a new stanza in `/etc/login.conf`, kept in the repo as `openbsd/etc/login.conf`:

```
onboard:\
	:shell=/usr/local/sbin/kyriakon-onboard-tui:\
	:tc=default:
```

and `cap_mkdb /etc/login.conf` builds the database. Without the class the account could not run the TUI at all: `sshd_config(5)` says a forced command "is invoked by using the user's login shell with the -c option" and `do_child()` runs `execve(shell, {shell, "-c", command})`, and `/sbin/nologin` ignores `-c` and exits, which is what the mechanics note already found for `authorized_keys` commands (section 4 of `docs/planning/research/openbsd-per-member-hosting.md`). The class is the standard OpenBSD way to give one account a different session shell without putting a program in its password entry, and it keeps the property [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) wanted: there is no shell on the account, and a client that sends no command and one that sends its own both land in the same program, which ignores its arguments because `ForceCommand` replaces whatever the client asked for.

### The rc.d unit

The unit is the stock `sshd` script with the second flag set, kept in the repo at `openbsd/etc/rc.d/kyriakon_onboard` and installed to `/etc/rc.d/kyriakon_onboard`:

```ksh
#!/bin/ksh
# The applicant-facing sshd. A second instance, not a second daemon: rc.subr
# tells the two apart by the -f flag in the process title.
daemon="/usr/sbin/sshd"
daemon_flags="-f /etc/ssh/sshd_config.onboard"
. /etc/rc.d/rc.subr

pexp="sshd: ${daemon}${daemon_flags:+ ${daemon_flags}} \[listener\].*"

rc_configtest() {
	${daemon} ${daemon_flags} -t
}

rc_pre() {
	install -d -o root -g wheel -m 755 /var/empty
}

rc_cmd $1
```

The operator enables it with `rcctl enable kyriakon_onboard`, starts it with `rcctl start kyriakon_onboard`, and applies a later config change with `rcctl reload kyriakon_onboard`, which `rc.subr` sends as `HUP` after running the config test above. The unit answers `rcctl` like any other OpenBSD service, so the runbook's service commands work on it unchanged.

## The port and the firewall

The port is a deployment value, chosen when the box is built from what is free, and recorded exactly once in `/etc/kyriakon/onboard/tui.env` as `TUI_PORT`. Ports 22 and 2222 are already taken by the member sshd and git. The build walks the reserved range 2200 to 2299 in order, skips anything already listening (`netstat -naf inet` plus the same check for `inet6`) and anything named in `/etc/services`, and takes the first free value. The default on a fresh box is therefore 2200. If no candidate in the range is free the build fails rather than picking an arbitrary port, because an unreviewed listener is worse than a stopped build.

The chosen value is substituted into three places from that one file: the `Port` line in the installed sshd config, the `pass` rule below, and the connection instructions the site publishes. The repository carries `REPLACE_ME` in each, the same deploy-value convention the postal address uses.

The firewall change is propose-only. It is a new block in `scripts/pf-apply.sh`, beside the existing 2222 block and in the same shape:

```
# --- kyriakon: onboarding TUI (openbsd/etc/sshd_config.onboard) ---
pass in log on egress proto tcp to any port 2200 keep state (max-src-conn 4)
# --- end kyriakon: onboarding TUI ---
```

`log` makes a probe or a flood attributable in `pflog` instead of invisible, and `max-src-conn 4` bounds established connections from one source while sshd's `PerSourceMaxStartups 2` bounds the unauthenticated ones and the TUI's counter bounds whole sessions. The block, with its port substituted at install, is reviewed in the pull request; the live command is the operator's manual step, `doas ksh scripts/pf-apply.sh`, which builds the candidate in a temp file, checks it with `pfctl -n`, backs up the current file and loads it. The spec does not run it and no deploy runs it, exactly as the existing fragments work.

The rule covers IPv4 and IPv6 because it has no `inet` qualifier, and it needs to: `signup.kyriakon.net` resolves through the zone's wildcard, which carries both an `A` and an `AAAA`, so a client that prefers IPv6 reaches the port too.

## The first screen

The instance has no banner, so the first thing the applicant reads is the TUI's own screen. It says what this is, that the web form is another way in, that applying does not require a terminal, how to leave, and that this is not a login. It is plain text, because the session has no pty (`PermitTTY no`) and the program reads lines rather than drawing a full screen.

```
Kyriakon onboarding

This is one of three ways to apply for a Kyriakon account. It is the SSH way.
If you would rather not use a terminal, the same form is at
https://signup.kyriakon.net and needs none.

A person reads every application and decides. Nothing here is approved by a
program, and nothing here asks you for a password or a key of ours.

This is not a login. It files an application, or reads the status of one, and
it cannot change anything.

You can leave at any time with Ctrl-C or by closing the connection. Nothing is
filed until you confirm at the end.

Press Enter to start. Type "status" to check an application you have already
filed.
```

The wording obeys the rules [#158](https://github.com/kyriakon/kyriakon-infra/issues/158) fixed for member-facing copy: no uptime claim, no belief test, the person who reads every application named, and "gemini" lowercase if the capsule is ever named here. The first screen is the only place the TUI makes a promise, and it makes the same one the web form and the capsule make.

## The wizard over the shared question list

The questions are one data file owned by the service workstream and read by all three front-ends, not three copies of the list. The file is ordered and each entry carries an id, the prompt, its type (short text, choice, yes or no, multi-line, one address per line, a key paste, an acceptance), whether it is shown for a person, a body or a monastic, and its validation. The web form renders the list as one page with the community block conditional, and the capsule and the TUI render it one entry at a time. This spec does not restate a question, and neither does an implementation: the TUI reads the installed file, renders each entry, and validates it locally for the applicant's benefit while the handler validates again when the intent is filed, because a front-end cannot be trusted.

The order and the branches are the web form's order and branches. The counter reads `question 4 of 12`, where the total is the count for the applicant's own branch rather than a fixed number: the second question (for yourself or for a body) opens the community block from [#233](https://github.com/kyriakon/kyriakon-infra/issues/233), and the monastic answer opens the elder's blessing, which is the one answer an application cannot be filed without. Until the branch question is answered the counter shows the individual count.

The interaction is line-oriented. Enter submits the current answer, `back` returns to the previous question with the answer kept, and `quit` or a closed connection abandons the session and files nothing. The username is checked for format and against `reserved-usernames.txt` and never for existence, which is the no-oracle rule [#182](https://github.com/kyriakon/kyriakon-infra/issues/182) fixed, and a wrong answer is re-asked on the same screen with the reason rather than dropping the session.

The TUI holds its answers in memory for the life of the connection and files nothing until the confirm screen. The capsule needs server-side draft state only because gemini overwrites the query on every status 10 prompt; the TUI has one connection, so it has no draft to store and a dropped connection costs the answers and nothing else. A cancelled prompt sends nothing, the same as the capsule.

## The key

The web form's walkthrough serves three front-ends, and the TUI prints the part of it that applies to the applicant's own machine: Thunderbird desktop as the primary path, Thunderbird for Android as the mobile one once the prototype has tested it end to end, and the address of the browser generator on `signup.kyriakon.net` for anyone who would rather not make a key by hand. It states the two upload ports plainly, sftp on 22 for uploads and git on 2222 for `pass` repositories, and it presents the upload key as a step for anyone who wants a website rather than an optional extra, because both paths are key-based and a member who skips the key gets mail and nothing else ([#154](https://github.com/kyriakon/kyriakon-infra/issues/154)). For an applicant at a terminal it also prints the `ssh-keygen -t ed25519` line that makes the upload key.

The TUI never generates a key and never sees a private key. It accepts a pasted public key on stdin, reading to the armor's end line, and it can accept a long one: SSH has no 1024 byte request limit, so the paste that can fail on the capsule works here. It runs the same inspection the web form runs, from the same crate ([#176](https://github.com/kyriakon/kyriakon-infra/issues/176), [#185](https://github.com/kyriakon/kyriakon-infra/issues/185)), built natively where the browser builds it to WASM, so the two verdicts cannot disagree.

The inspection returns a verdict on the three conditions that break delivery, each with its own message and its own fix: no encryption-capable subkey, preferences that would make gpg emit a packet the member's client cannot read, and expiry or revocation. It warns and proceeds, because the platform cannot verify what a client generated and a refusal would turn a guarantee into a support queue. The AEAD condition is the one to implement carefully: gpg writes the AEAD ciphersuite preference as subpacket type 34, which `pgp` 0.20 parses into `PreferredEncryptionModes`, while the variant named `PreferredAeadAlgorithms` is a different subpacket; a check written to the obvious name reports a false clean on a real gpg key, which is the dangerous direction. Present-day gpg advertises AEAD without being asked, so this warning is what a member gets from the ordinary path, not an unusual case.

The upload key gets a shape check only, not the mail check: it must parse as an OpenSSH public key, which is what the account needs before sftp and git will accept it. Nothing about either key is written to the log.

## The token and the status path

The confirm screen shows the answers once, with the key fingerprints, and files nothing until the applicant confirms. On confirmation the TUI posts one intent to the onboarding handler over loopback, alongside the web form and the capsule, and receives the application token. It prints the token and the status address:

```
Your application is filed.

Keep this link. It is the only thing that identifies your application:
https://signup.kyriakon.net/status/<token>

The link shows the stage and never your answers. A person reads every
application; approval is not automatic. If you gave an address, everything
after this arrives there. Payment follows approval by email.

Your account page, once there is an account, is on the web at
https://signup.kyriakon.net.
```

The token is the same 128-bit bearer capability the web form and the capsule issue ([#182](https://github.com/kyriakon/kyriakon-infra/issues/182)), separate from the `KYR-` payment token drawn at approval, and it is the only thing that identifies the application for an applicant who gave no outside address.

The TUI also reads status. Typing `status` on the first screen, or reconnecting and pasting the token, asks the handler for the stage, which is received, with the reviewer, or decided, and prints that and nothing else. It never echoes an answer, and a token that is not found returns the same reply as an application that has expired, so the path cannot be used to test whether a token exists. The lookup is rate-limited per source address in the handler, the same counter the capsule uses.

The TUI is signup and status and nothing more. The account page is the login surface, and no part of this session logs anyone in.

## Counters, caps and the too-many-sessions screen

Four limits bound an address, at three layers.

The `pf` rule's `max-src-conn 4` bounds established TCP connections from one source. sshd's `PerSourceMaxStartups 2` bounds unauthenticated connections from one address and drops the excess before it reaches the TUI. The TUI's own counter bounds whole sessions and completed applications, and answers with a screen rather than a dropped connection, which is the plain "too many sessions" screen [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) asks for. A session that is over the limit gets:

```
Too many sessions are open from this address.

Wait a few minutes and try again. The web form at
https://signup.kyriakon.net works the same way and has no session limit.
```

The TUI takes the source address from `SSH_CONNECTION`, the `client_ip client_port server_ip server_port` quartet sshd puts in the session environment, and keeps its counters under `/var/db/kyriakon-onboard-tui/`, which it owns. One lock file per live session is written at start and removed on exit, and a stale file whose session is gone is pruned on the next start, so an abandoned session cannot lock an address out for good. The caps start at two concurrent sessions per address, matching `PerSourceMaxStartups 2`, and a small box-wide total, with completed applications counted per address per day; a bot that lands here finds a program that files one intent per completed application and a counter that stops it after a few, and the human approval is still the gate. The exact submission count is set when the port is live, from the baseline below rather than from a guess.

Everything lands in `authlog`. sshd writes the admission line at `INFO` in the form `Accepted none for onboard from <address> port <n> ssh2`, and the abuse monitor gains a per-source count of exactly that line, anchored on `for onboard from` so member and operator traffic on 22 is not mixed in. The TUI's own stage events (a filed application, a status read, an abandoned session) go to `authlog` through `syslog` with facility `AUTH`, and carry no address and no answer, so the completion count cannot become a member list in the logs.

The existing SSH-failure threshold in `docs/planning/research/alert-thresholds.md` (300 lines per source address per 15-minute interval) is re-measured once this port is live and the new number recorded there. A second public listener changes what `authlog` holds, and an unmeasured shift is how a real attack hides in the noise. That re-measurement is a build step, not this spec's number.

## What the session must never do

- It is never a login. The only account on the instance is `onboard`, which holds no member state; a session never authenticates as a member and never opens a member's account.
- It never gives anyone a shell. The password-file shell is `/sbin/nologin`, the login class gives the session only the TUI, and `ForceCommand` pins the same program for a client-supplied command.
- It never changes anything. It files one intent for one completed application and reads a status by token. It cannot provision, suspend, delete, issue a certificate, rotate a key, or move a payment.
- It never generates a key, and never sees a private key. It prints the walkthrough and the generator's address, accepts a pasted public key, and inspects it.
- It is never the only way in. The web form at `signup.kyriakon.net` asks the same questions and needs no terminal, and nothing about applying requires a terminal.
- It is never a username oracle. Format and reserved names are checked live; existence never is.
- It never echoes an application's answers on the status path, and a token that does not exist reads as an expired one.
- It never holds privilege or secrets. It runs as `onboard`, reads no root-only file, and reaches the handler over loopback.
- It never forwards anything. `DisableForwarding` and `PermitOpen none` leave no TCP, agent, X11 or streamlocal channel and no tunnel.
- It never writes an address or an answer to a log of its own; sshd's admission line is the only place the address appears.
- It never files twice. One confirm files one intent; an abandoned or dropped session files nothing.

## The trust boundary

The TUI is a front-end and sits on the same side of the boundary as the web handler ([#156](https://github.com/kyriakon/kyriakon-infra/issues/156)). It runs as the unprivileged `onboard` account and can do three things: read the shared question list, ask the handler to file an intent or read a status, and run the shared key check. It holds no Stripe secret, no repository token and no signing key, and it cannot read the store, the account files or any member's mail.

Its one network reach is the handler on the loopback address, the same process that answers the web form and the capsule behind `relayd` and `gmid`. That keeps one intent writer. The TUI passes the source address it took from `SSH_CONNECTION` so the handler's per-address counters apply to it the same way they apply to the capsule, but the handler validates every field again as it does for any front-end, so a bug in the TUI cannot become a privileged write. The drain still does every privileged thing, on its next run.

The handoff for the browser generator is one URL in the printed walkthrough. It is the site spec's page, linked rather than reimplemented, so the TUI carries no OpenPGP generator, no WASM, and no private key, ever.

## Testing decisions

Three behaviours are worth a test each, and little else here is.

A scripted session, answers fed on stdin and output read back, must produce exactly one intent for one completed application, and none when the session is abandoned or the connection drops before the confirm. That is the property a bug would break in either direction: a double file, or a file on an abandon.

The config check is a test in the ordinary sense: `sshd -T -f /etc/ssh/sshd_config.onboard` must return the chosen port, `permitemptypasswords yes`, `passwordauthentication yes`, `authenticationmethods none`, `permittty no` and the forced command, and a connection attempt as any user other than `onboard` must be refused before authentication.

The key verdicts are the one place two builds of the shared crate could disagree. The native check the TUI links and the WASM module the page runs must return the same verdict for the four fixtures the prototype used: the generator's clean key, a gpg 2.5 key advertising AEAD, a key with no encryption subkey, and a key whose subkey expired. The AEAD fixture is the one that catches the subpacket-34 trap.

## Out of scope

The web form and the capsule, which have their own specs. The onboarding service's handler, drain, store and account page ([#156](https://github.com/kyriakon/kyriakon-infra/issues/156), [#159](https://github.com/kyriakon/kyriakon-infra/issues/159)). The key generator and the browser check page ([#176](https://github.com/kyriakon/kyriakon-infra/issues/176), [#185](https://github.com/kyriakon/kyriakon-infra/issues/185)). The certificate queue and the pending-certificate state ([#154](https://github.com/kyriakon/kyriakon-infra/issues/154)). The reconciliation of the proposal's section 5.9.2, which is its own ticket. The embedded-in-Kleio experience, which needs terminal emulation on Kleio's side and stays off this map. The shared question list's exact entries and its file format, which are the service workstream's to fix; this spec depends only on the list being one ordered file with the two branches.

## Sources

- OpenBSD 7.9 `sshd_config(5)`, read at <https://man.openbsd.org/sshd_config.5> on 2026-10-05: the `none` method "used for access to password-less accounts when `PermitEmptyPasswords` is enabled"; `PermitEmptyPasswords`; ForceCommand's command "invoked by using the user's login shell with the -c option"; the list of keywords allowed after `Match`; `Banner none`; `MaxSessions`, `MaxStartups`, `PerSourceMaxStartups`, `PerSourceNetBlockSize`.
- OpenBSD source, read on 2026-10-05: `usr.bin/ssh/auth2-none.c`, where `userauth_none()` calls `mm_auth_password(ssh, "")` only when `options.permit_empty_passwd && options.password_authentication`, `usr.bin/ssh/auth.c`, where `lc = login_getclass(pw->pw_class)` takes the session's login class from the account, and `usr.bin/ssh/session.c`, where `do_child()` runs a forced command as `execve(shell, {shell, "-c", command})` after taking `shell` from that class. The stock unit is `etc/rc.d/sshd`.
- OpenBSD `useradd(8)` and `usr.sbin/user/user.c`, read on 2026-10-05: `-p` stores its argument as the password field, so `-p ''` writes an empty one.
- Repo notes and files: `docs/planning/research/openbsd-per-member-hosting.md` (the chroot, `git-shell` and the tested refusal of non-sftp forced commands under `nologin`, section 4), `docs/planning/research/alert-thresholds.md` (the SSH per-address threshold), `scripts/pf-apply.sh`, `scripts/abuse-monitor.sh`, `openbsd/etc/sshd_config` and `docs/planning/prototypes/keygen-spike/`.
- Decisions: [#150](https://github.com/kyriakon/kyriakon-infra/issues/150), [#154](https://github.com/kyriakon/kyriakon-infra/issues/154), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156), [#158](https://github.com/kyriakon/kyriakon-infra/issues/158), [#176](https://github.com/kyriakon/kyriakon-infra/issues/176), [#182](https://github.com/kyriakon/kyriakon-infra/issues/182), [#183](https://github.com/kyriakon/kyriakon-infra/issues/183), [#185](https://github.com/kyriakon/kyriakon-infra/issues/185), [#233](https://github.com/kyriakon/kyriakon-infra/issues/233).

Two facts this spec could not settle from the record: the shared question list's file name and schema, which the service workstream owns, and the re-measured SSH failure threshold, which can only be taken once the port is live.
