# The SSH onboarding TUI

> Spec synthesised from [Spec the SSH onboarding TUI](https://github.com/kyriakon/kyriakon-infra/issues/245) and the decisions it takes as input: [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) (the second sshd instance, the password-less session and the wizard), [#154](https://github.com/kyriakon/kyriakon-infra/issues/154) (the hosting port split and the mandatory upload key), [#182](https://github.com/kyriakon/kyriakon-infra/issues/182) (the shared question list, the status token and the counters), [#176](https://github.com/kyriakon/kyriakon-infra/issues/176) and [#185](https://github.com/kyriakon/kyriakon-infra/issues/185) (the key walkthrough and the shared check crate), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156) (the service's trust boundary), [#233](https://github.com/kyriakon/kyriakon-infra/issues/233) (the community block) and [#150](https://github.com/kyriakon/kyriakon-infra/issues/150) (the OpenBSD mechanics, tested on the box). The proposal's section 5.9.2 is superseded on the transport by [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) and is not decided again here.

> Amended on 2026-10-13 for the portal redesign: the terminal front-end becomes a portal that mirrors the site over one shared service catalogue ([Decide the shared copy: one service catalogue and the check that keeps the three renderings in step](https://github.com/kyriakon/kyriakon-infra/issues/359) and `docs/planning/specs/shared-copy.md`), the session gains a pty and a plain mode, a member's path is added beside the applicant's ([Research what the onboard sshd tells the TUI about the key that connected](https://github.com/kyriakon/kyriakon-infra/issues/356)), the instruction becomes `ssh apply@ssh.kyriakon.net` ([Decide the SSH portal's entry address and port](https://github.com/kyriakon/kyriakon-infra/issues/360)), and the ksh program this spec first described is retired.

## Problem statement

Kyriakon takes applications three ways and writes them into one back end: the web form at release, and a gemini capsule and an SSH TUI built once the platform is live. The SSH path is the one where the applicant already has a terminal, so it can do what the web form does and a little more, and the risk is that it grows into a second privileged way into the platform.

[#183](https://github.com/kyriakon/kyriakon-infra/issues/183) settled the transport. The platform runs a second stock `sshd` instance rather than the bespoke `russh` server the proposal parked. OpenBSD's own `sshd_config(5)` lists `none` among the authentication methods, "used for access to password-less accounts when `PermitEmptyPasswords` is enabled" (read on 2026-10-05), so the daemon the base system audits carries the key exchange and the authentication and the only authored program is the one the applicant talks to behind `ForceCommand`.

What remains is the shape of that program and its session: the config file, port, account and unit the instance needs, the screens the applicant sees, how the application and its key are handled, what the applicant takes away, and what the session must never be able to do. This spec fixes all of that and leaves the web form, the capsule and the drain to their own specs. Amended on 2026-10-13: the program is a portal rather than an application wizard. It mirrors the platform over one shared catalogue, it serves a member as well as an applicant, and the applicant's flow is one thing it does rather than the whole of it. What does not change is the risk named above: every session is unprivileged, files intents, and holds no member state.

## Solution

A second `sshd` instance runs from its own config file on a port chosen when the box is built, and the only account it can serve is a password-less system account named `apply`. The applicant reaches it as `ssh apply@ssh.kyriakon.net`, the instruction the site publishes on the signup page, on an address the portal has of its own, because the applicant path and the member path cannot share one `Match` block and one address therefore carries two ports. The username is part of both instructions, because `AllowUsers apply` refuses every other name before authentication, so the address on its own lands a connection as the caller's own local user and is refused. Nothing is asked once the connection is made: no password, no key, no published credential. The account has no shell and the instance forces one program, a line-oriented TUI, so the connection is a text pipe into an application form.

The program is a portal. It opens on a menu over the shared service catalogue, the same list the web page and the capsule render, and its rows say what the platform offers and what state each service is in. One row starts the application: a first screen that says what this is, the shared question list one question at a time with a counter, the key walkthrough, a pasted public key checked with the same crate the web form uses, a summary to confirm, one intent filed through the onboarding handler, and the status token handed back. Another row reads that status back by token, and the rest show a service's own page. The account section arrives when the drain does. A plain mode ships in the same binary for screen readers and bad links. Its per-address counters answer an over-eager source with a plain screen. It holds no privilege, no secrets and no shell, and the human approval stays the real gate.

## The second sshd instance

The instance is a stock `/usr/sbin/sshd` started with `-f /etc/ssh/sshd_config.onboard`, the file the repo keeps at `openbsd/etc/sshd_config.onboard`. It is a separate file, ports, `PidFile` and account from the member sshd in `/etc/ssh/sshd_config`, which this change touches only to pin that instance to the primary address, so the portal can take port 22 on its own. It shares the box's host keys, because no `HostKey` line is set and sshd falls back to the same `/etc/ssh/ssh_host_*` files, so the box keeps one SSH identity.

The file is applied by hand, like the member one, with `doas sshd -t -f /etc/ssh/sshd_config.onboard` and then an `rcctl restart kyriakon_onboard_sshd`. The port line carries the deploy value the build chose, written as `REPLACE_ME` in the repository and substituted from `/root/.kyriakon-env` at install.

```ssh_config
# /etc/ssh/sshd_config.onboard
# The applicant-facing sshd, run by /etc/rc.d/kyriakon_onboard_sshd. Separate file,
# port, PidFile and account from the member sshd in /etc/ssh/sshd_config, which
# is not touched. Reviewed line by line and applied by hand.

# No HostKey line, so sshd reads the same /etc/ssh/ssh_host_* keys the member
# instance uses and the box keeps one SSH identity.
#
# The portal has an address of its own, so its applicant port can be the real
# one: the member sshd is pinned to the primary address and this instance takes
# 22 here. The member front-end is a second port on the same address, because
# the two paths cannot share one Match block. A list naming none is settled by
# the client's first request, which is always a none request, and one Match
# criterion carries one configuration, so the split is by local port.
ListenAddress REPLACE_ME_ADDR
Port 22
Port REPLACE_ME
PidFile /var/run/sshd.onboard.pid

# Only the apply account is reachable, before authentication. That is what
# lets the instance carry PasswordAuthentication yes, which the none method
# needs: userauth_none() calls mm_auth_password("") only when
# permit_empty_passwd and password_authentication are both on (auth2-none.c).
AllowUsers apply
PasswordAuthentication yes
PermitRootLogin no
LoginGraceTime 30

# Pre-auth connection caps. PerSourceMaxStartups is the per-address one.
# sshd drops the excess connection, tells the client "Not allowed at this
# time" and logs the drop at INFO under its own rate limit; the TUI's own
# counter answers the same condition with the screen in its own section.
MaxStartups 4:50:10
PerSourceMaxStartups 2
PerSourceNetBlockSize 32:128

Banner none

# Every connection lands in authlog, where the abuse monitor counts it.
LogLevel VERBOSE
SyslogFacility AUTH

# The applicant's path, on port 22 of the portal's own address. Nothing is
# asked: no credential exists to leak, rotate or publish, and the account is
# password-less, which is the condition the none method documents.
Match LocalPort 22 User apply
	PermitEmptyPasswords yes
	AuthenticationMethods none
	KbdInteractiveAuthentication no

	# Whoever connected, sshd writes the method, and the key when a key was
	# presented, to the file this names in the session's environment.
	ExposeAuthInfo yes

	# A terminal, because the portal draws a screen and the plain mode reads
	# lines. PermitTTY is in the subset sshd_config(5) allows after Match.
	PermitTTY yes
	MaxSessions 1
	DisableForwarding yes
	PermitOpen none
	PermitUserRC no

	# The one program the account can run, on every path.
	ForceCommand /usr/local/sbin/kyriakon-onboard-tui

# The member's path, on the same address's second port. Every key is admitted,
# and the key itself is the identity: AuthorizedKeysCommand is never consulted
# for the none method, which is why this cannot be the same block as above.
Match LocalPort REPLACE_ME User apply
	AuthenticationMethods publickey
	AuthorizedKeysCommand /usr/local/sbin/kyriakon-onboard-keyecho %t %k
	AuthorizedKeysCommandUser apply
	ExposeAuthInfo yes
	PermitTTY yes
	MaxSessions 1
	DisableForwarding yes
	PermitOpen none
	PermitUserRC no

	ForceCommand /usr/local/sbin/kyriakon-onboard-tui
```

`PermitEmptyPasswords` and `PermitTTY` in the `Match` blocks are inside the subset of keywords `sshd_config(5)` allows after `Match`. `AuthorizedKeysCommand` and `AuthorizedKeysCommandUser` are written there too, and the operator's config test confirms they are accepted where they sit, which the identity research leaves as a check rather than an observation. `PasswordAuthentication` sits at the top level, as the resolution has it, and `PerSourceMaxStartups` sits there too because `sshd_config(5)` does not allow it after `Match`; both are harmless there because `AllowUsers onboard` makes the instance serve one account. `Banner none` is the documented default and is written out so a future default change cannot quietly reintroduce a banner; a banner is read by every scanner and by nobody the platform wants. The protocol identification string itself cannot be removed, and its version addendum already defaults to `none`, so it carries no local operating system suffix.

### The account

`apply` is a system account with an empty password field, a home of `/var/empty` and a `/sbin/nologin` shell. It is created once, at build time, after its login class exists:

```
useradd -d /var/empty -c "Kyriakon portal" \
	-s /sbin/nologin -L apply -p '' apply
```

`useradd -p ''` stores the empty string in the password field (user(8) writes `up->u_password` verbatim), and provisioning verifies the result before the instance is enabled:

```
awk -F: '$1 == "apply" { print length($2) }' /etc/master.passwd   # must print 0
```

A non-zero length fails the build, because a disabled account (`*`) would not authenticate with the `none` method and the instance would be a port that refuses everyone.

The shell in the password file stays `/sbin/nologin`, which is the one [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) asks for, and the session still runs the TUI because sshd takes its shell from the account's login class rather than from the password field. `do_child()` runs `shell = login_getcapstr(lc, "shell", pw_shell, pw_shell)` in `session.c`, and `auth.c` sets `lc = login_getclass(pw->pw_class)`, so the class's `shell` capability is the shell sshd execs the forced command through. The class is a new stanza in `/etc/login.conf`, kept in the repo as `openbsd/etc/login.conf.d/apply`:

```
apply:\
	:shell=/usr/local/sbin/kyriakon-onboard-tui:\
	:tc=default:
```

It goes in `/etc/login.conf.d/apply`, the drop-in directory this box already uses for `dovecot` and `rspamd`, where a class takes precedence over the same name in `/etc/login.conf` and the base file is never edited. `cap_mkdb /etc/login.conf` then rebuilds the database, which is required after an edit to either file whenever `/etc/login.conf.db` exists. Without the class the account could not run the TUI at all: `sshd_config(5)` says a forced command "is invoked by using the user's login shell with the -c option" and `do_child()` runs `execve(shell, {shell, "-c", command})`, and `/sbin/nologin` ignores `-c` and exits, which is what the mechanics note already found for `authorized_keys` commands (section 4 of `docs/planning/research/openbsd-per-member-hosting.md`). The class is the standard OpenBSD way to give one account a different session shell without putting a program in its password entry, and it keeps the property [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) wanted: there is no shell on the account, and a client that sends no command and one that sends its own both land in the same program, which ignores its arguments because `ForceCommand` replaces whatever the client asked for.

### The rc.d unit

The unit is the stock `sshd` script with the second flag set, kept in the repo at `openbsd/etc/rc.d/kyriakon_onboard_sshd` and installed to `/etc/rc.d/kyriakon_onboard_sshd`. The name says which process it supervises: `kyriakon_onboard` is the onboarding handler's own unit, named after the binary it runs, and this is the second sshd instance beside it, so neither name can be mistaken for the other at an `rcctl` prompt:

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

The operator enables it with `rcctl enable kyriakon_onboard_sshd`, starts it with `rcctl start kyriakon_onboard_sshd`, and applies a later config change with `rcctl reload kyriakon_onboard_sshd`, which `rc.subr` sends as `HUP` after running the config test above. The unit answers `rcctl` like any other OpenBSD service, so the runbook's service commands work on it unchanged.

## The port and the firewall

The portal has two ports and only one of them is a choice. The applicant's is 22 on the address the portal has of its own, and it needs no firewall change at all: 22 is already open for the member sshd, a rule is per port rather than per address, and the instance binds the address itself with its `ListenAddress` line. The member's port is the deployment value below, walked when the box is built from what is free, and recorded exactly once in `/root/.kyriakon-env` as `TUI_PORT`. Ports 22 and 2222 are already taken by the member sshd and git. The build walks the reserved range 2200 to 2299 in order, skips anything already listening (`netstat -naf inet` plus the same check for `inet6`) and anything named in `/etc/services`, and takes the first free value. The default on a fresh box is therefore 2200. If no candidate in the range is free the build fails rather than picking an arbitrary port, because an unreviewed listener is worse than a stopped build.

The chosen value reaches three places from that one file, and the address reaches two of its own: the `ListenAddress` line in the installed config, and the DNS record that `Take the second address for the SSH portal` creates, whose Terraform and `sshd_config` pin are that ticket's work rather than this spec's. The `Port` line in the installed sshd config and the connection instructions the site publishes on the signup page carry it substituted at install, and the repository carries `REPLACE_ME` in both, the same deploy-value convention the postal address uses. The firewall is the third, and it is not installed anywhere: `scripts/pf-apply.sh` is run in place, so it reads `TUI_PORT` from that file at run time and expands it into the rule as it builds the candidate. The block is added when the file is there and skipped with a note when it is not, so the script still runs on a box without the TUI, and a value that is not a port number stops it rather than writing a rule `pfctl -n` rejects.

The firewall change is propose-only, and it covers the member port alone, for the reason above. It is a new block in `scripts/pf-apply.sh`, beside the existing 2222 block and in the same shape:

```
# --- kyriakon: onboarding TUI (openbsd/etc/sshd_config.onboard) ---
pass in log on egress proto tcp to any port ${TUI_PORT} keep state (max-src-conn 4)
# --- end kyriakon: onboarding TUI ---
```

`log` makes a probe or a flood attributable in `pflog` instead of invisible, and `max-src-conn 4` bounds established connections from one source while sshd's `PerSourceMaxStartups 2` bounds the unauthenticated ones and the TUI's counter bounds whole sessions. The block, with its port read from `/root/.kyriakon-env` when the candidate is built, is reviewed in the pull request; the live command is the operator's manual step, `doas ksh scripts/pf-apply.sh`, which builds the candidate in a temp file, checks it with `pfctl -n`, backs up the current file and loads it. The spec does not run it and no deploy runs it, exactly as the existing fragments work.

The rule covers IPv4 and IPv6 because it has no `inet` qualifier, and it needs to: `signup.kyriakon.net` resolves through the zone's wildcard, which carries both an `A` and an `AAAA`, so a client that prefers IPv6 reaches the port too.

## The first screen

The instance has no banner, so the first thing the applicant reads is the TUI's own screen. It says what this is, that the web form is another way in, that applying does not require a terminal, how to leave, and that this is not a login. The session has a pty (`PermitTTY yes`), so `TERM` and the window size arrive with the connection and a resize reaches the program as `SIGWINCH`, and the full-screen program draws a menu over the shared catalogue with the application and the status behind it. The plain mode prints a screen and reads lines. Both say the same things; the plain one says them without drawing.

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

The full-screen program draws the same thing as a menu, one row per entry in the shared catalogue, with the state beside the name and the entry's own clause under the selected row:

```
 Kyriakon
 > Mail                live     zero-access mail, 5 GB, IMAP and SMTP, readable only by you
   A website           live     static pages at an address of your own, uploaded by sftp
   A gemini capsule    live     the same pages over the gemini protocol
   Repositories        live     pass-compatible git over ssh, on port 2222
   ...
   Your account        live     the password, the keys, the space used, the notices
   Apply               ->       start an application
   Status              ->       read an application you have already filed
 q quit
```

The wording obeys the rules [#158](https://github.com/kyriakon/kyriakon-infra/issues/158) fixed for member-facing copy: no uptime claim, no belief test, the person who reads every application named, and "gemini" lowercase if the capsule is ever named here. The first screen is the only place the TUI makes a promise, and it makes the same one the web form and the capsule make.

## The portal, the menu and the shared question list

The questions are one data file owned by the service workstream and read by all three front-ends, not three copies of the list. The file is ordered and each entry carries an id, the prompt, its type (short text, choice, yes or no, multi-line, one address per line, a key paste, an acceptance), whether it is shown for a person, a body or a monastic, and its validation. The web form renders the list as one page with the community block conditional, and the capsule and the TUI render it one entry at a time. This spec does not restate a question, and neither does an implementation: the TUI reads the installed file, renders each entry, and validates it locally for the applicant's benefit while the handler validates again when the intent is filed, because a front-end cannot be trusted.

The order and the branches are the web form's order and branches. The counter reads `question 4 of 12`, where the total is the count for the applicant's own branch rather than a fixed number: the second question (for yourself or for a body) opens the community block from [#233](https://github.com/kyriakon/kyriakon-infra/issues/233), and the monastic answer opens the elder's blessing, which is the one answer an application cannot be filed without. Until the branch question is answered the counter shows the individual count.

The menu is the catalogue, one row per entry read from `openbsd/etc/onboard/catalogue.tsv`, with the same names and clauses the web page and the capsule render because that file is the only place the list exists (`docs/planning/specs/shared-copy.md`). One row opens the status lookup, one starts the application, one opens the member's own account once there is one to open, and the rest show a service's own page. Inside the flow, Enter submits the current answer, `back` or the left arrow returns to the previous question with the answer kept, and `quit` or a closed connection abandons the session and files nothing. The username is checked for format and against `reserved-usernames.txt` and never for existence, which is the no-oracle rule [#182](https://github.com/kyriakon/kyriakon-infra/issues/182) fixed, and a wrong answer is re-asked on the same screen with the reason rather than dropping the session.

The plain mode keeps every screen's words, the counter, the confirm, the token and the checks, and drops only the drawing: no redraw, no box characters, no keys beyond line input, and `back` and `quit` typed as words. It is the mode for a screen reader and for a bad link, and it is one program rather than two, so the two cannot drift.

The TUI holds its answers in memory for the life of the connection and files nothing until the confirm screen. The capsule needs server-side draft state only because gemini overwrites the query on every status 10 prompt; the TUI has one connection, so it has no draft to store and a dropped connection costs the answers and nothing else. A cancelled prompt sends nothing, the same as the capsule.

## The member path

A second port on the portal's address serves a member. The split is forced rather than chosen: `AuthorizedKeysCommand` is never consulted for the `none` method, because `userauth_none()` asks only the password path, and one `Match` criterion carries one configuration, so an instance cannot admit any key and learn which key it was in the same block that admits everyone with `none`. On the member port every key is accepted by a small program that echoes the offered key back, and the key is then the identity rather than the admission.

`ExposeAuthInfo yes` is what makes that usable. sshd writes the method, and the key when a key was presented, to the file it names in `SSH_USER_AUTH` in the session's environment: `/tmp/sshauth.XXXXXXXXXXXXXXX`, mode 0600, unlinked at the end of the session. The file holds one line, `none` for the applicant path and `publickey <type> <base64>` for the member path, with no comment, so what the program matches on is the key material itself.

The program does not read the store and cannot: it asks the handler which account a key fingerprint belongs to, and the handler is the only thing that reads the account records. A caller that reaches that question has already signed with the private key, which is the same proof `authorized_keys` asks for, so answering it is not an oracle: only the holder of a key learns anything about it, and a key that matches nothing simply gets the applicant's menu rather than an error.

A member's session reads what the reading half needs: the state of the account, whether the site and capsule are being served, the space used, and the notices sent. The account section, which files the intents the account page also files, is the last piece built, because the drain is what makes an account action real. Until then the member path is a keyed way to read, and nothing more.

## The key

The web form's walkthrough serves three front-ends, and the TUI prints the part of it that applies to the applicant's own machine: Thunderbird desktop as the primary path, Thunderbird for Android as the mobile one once the prototype has tested it in a browser and on a phone, and the address of the browser generator on `signup.kyriakon.net` for anyone who would rather not make a key by hand. It states the two upload ports plainly, sftp on 22 for uploads and git on 2222 for `pass` repositories, and it presents the upload key as a step for anyone who wants a website rather than an optional extra, because both paths are key-based and a member who skips the key gets mail and nothing else ([#154](https://github.com/kyriakon/kyriakon-infra/issues/154)).

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

The portal is signup, status and, for a key the handler knows, the member's own account. The account page remains the login surface: the portal never asks for a password, so nothing here logs anyone in.

## Counters, caps and the too-many-sessions screen

Four limits bound an address, at three layers.

The `pf` rule's `max-src-conn 4` bounds established TCP connections from one source. sshd's `PerSourceMaxStartups 2` bounds unauthenticated connections from one address and drops the excess before it reaches the TUI. The TUI's own counter bounds whole sessions and completed applications, and answers with a screen rather than a dropped connection, which is the plain "too many sessions" screen [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) asks for. A session that is over the limit gets:

```
Too many sessions are open from this address.

Wait a few minutes and try again. The web form at
https://signup.kyriakon.net works the same way and has no session limit.
```

The TUI takes the source address from `SSH_CONNECTION`, the `client_ip client_port server_ip server_port` quartet sshd puts in the session environment, and keeps its counters under `/var/db/kyriakon-onboard-tui/`, which it owns. One lock file per live session is written at start and removed on exit, and a stale file whose session is gone is pruned on the next start, so an abandoned session cannot lock an address out for good. The caps are the ones [#182](https://github.com/kyriakon/kyriakon-infra/issues/182) fixed so the front-ends agree: sixty requests a minute and five drafts a day per address. The session layer below them starts at two concurrent sessions per address, matching `PerSourceMaxStartups 2`, with a small box-wide total; a bot that lands here finds a program that files one intent per completed application and a counter that stops it after a few, and the human approval is still the gate. The exact submission count is set when the port is live, from the baseline below rather than from a guess.

Everything lands in `authlog`. sshd writes the admission line at `INFO` in the form `Accepted none for apply from <address> port <n> ssh2`, and on the member port `Accepted publickey for apply from <address> port <n> ssh2: <type> SHA256:<fingerprint>`. The abuse monitor gains a per-source count anchored on `for apply from`, which counts both lines and mixes in neither the members' own sshd traffic nor the operator's. The TUI's own stage events (a filed application, a status read, an abandoned session) go to `authlog` through `syslog` with facility `AUTH`, and carry no address and no answer, so the completion count cannot become a member list in the logs.

The existing SSH-failure threshold in `docs/planning/research/alert-thresholds.md` (300 lines per source address per 15-minute interval) is re-measured once this port is live and the new number recorded there. A second public listener changes what `authlog` holds, and an unmeasured shift is how a real attack hides in the noise. That re-measurement is a build step, not this spec's number.

## What the session must never do

- It is never a login to a member's account. The only account on the instance is `apply`, which holds no member state and no shell; a member's session is identified by the key it presented and reaches only what the handler renders for that account.
- It never gives anyone a shell. The password-file shell is `/sbin/nologin`, the login class gives the session only the TUI, and `ForceCommand` pins the same program for a client-supplied command.
- It never changes anything itself. It files intents: one for a completed application, and, once the drain exists, the account intents the account page also files. Provisioning, suspension, deletion, certificates, key rotation and payments stay the drain's, and no session performs them.
- It never generates a key, and never sees a private key. It prints the walkthrough and the generator's address, accepts a pasted public key, and inspects it.
- It is never the only way in. The web form at `signup.kyriakon.net` asks the same questions and needs no terminal, and nothing about applying requires a terminal.
- It is never a username oracle. Format and reserved names are checked live; existence never is.
- It never echoes an application's answers on the status path, and a token that does not exist reads as an expired one.
- It never holds privilege or secrets. It runs as `apply`, reads no root-only file, and reaches the handler over loopback.
- It never forwards anything. `DisableForwarding` and `PermitOpen none` leave no TCP, agent, X11 or streamlocal channel and no tunnel.
- It never writes an address or an answer to a log of its own; sshd's admission line is the only place the address appears.
- It never files twice. One confirm files one intent; an abandoned or dropped session files nothing.

## The trust boundary

The TUI is a front-end and sits on the same side of the boundary as the web handler ([#156](https://github.com/kyriakon/kyriakon-infra/issues/156)). It runs as the unprivileged `apply` account and can do three things: read the shared question list and the catalogue, ask the handler to file an intent, read a status, or name the account a key belongs to, and run the shared key check. It holds no Stripe secret, no repository token and no signing key, and it cannot read the store, the account files or any member's mail.

Its one network reach is the handler on the loopback address, the same process that answers the web form and the capsule behind `relayd` and `gmid`. That keeps one intent writer. The TUI passes the source address it took from `SSH_CONNECTION` so the handler's per-address counters apply to it the same way they apply to the capsule, but the handler validates every field again as it does for any front-end, so a bug in the TUI cannot become a privileged write. The drain still does every privileged thing, on its next run.

The handoff for the browser generator is one URL in the printed walkthrough. It is the site spec's page, linked rather than reimplemented, so the TUI carries no OpenPGP generator, no WASM, and no private key, ever.

## The program, its home and what it replaces

The portal is a Rust program in the handler's own crate, `onboard/`, as a second binary beside `kyriakon-onboard`. The crate gains a library so that the catalogue, the question list and the key check have one home, and the terminal front-end links that library rather than carrying a copy of anything, which is what `docs/planning/specs/shared-copy.md` asks of it. The install line and `scripts/deploy-onboard.sh` take both binaries from the same `cargo build`.

It replaces the ksh program this spec first described, at the same path, `/usr/local/sbin/kyriakon-onboard-tui`, which the login class's `shell` capability already names, so the class, the unit, the port and the deploy keep their shape and only the file changes. The ksh program is retired in the same change: `openbsd/usr/local/sbin/kyriakon-onboard-tui` leaves the repository rather than sitting beside the new program, and no fallback runs it. A full-screen interface is unusable by a screen reader and unhappy over a bad link, which is why the plain mode ships inside the new binary rather than as the old one kept for the purpose.

## Testing decisions

Three behaviours are worth a test each, and little else here is.

A scripted session, answers fed on stdin and output read back, must produce exactly one intent for one completed application, and none when the session is abandoned or the connection drops before the confirm. That is the property a bug would break in either direction: a double file, or a file on an abandon.

The config check is a test in the ordinary sense: `sshd -T -f /etc/ssh/sshd_config.onboard` must return both ports, `passwordauthentication yes` at the top level, `permitemptypasswords yes` and `authenticationmethods none` on the applicant port, `authenticationmethods publickey` with the `authorizedkeyscommand` on the member port, `permittty yes` and `exposeauthinfo yes` on both, and the forced command, and a connection attempt as any user other than `apply` must be refused before authentication. `docs/planning/research/onboard-sshd-identity.md` carries the operator's end-to-end version of this: a dry run on throwaway ports under an account whose shell is `/bin/sh`, whose forced command prints `TERM`, `SSH_TTY`, `SSH_USER_AUTH` and the file's contents, connected with and without `-t` and once with `-i` on the member port, and `authlog` then showing `Accepted none` for the anonymous sessions and `Accepted publickey` with a fingerprint for the keyed one.

The two modes must say the same things: a session driven in the plain mode and one driven through the full-screen program's own harness must file the same intent for the same answers, and the menu must render every entry in the shared catalogue, which the check in `docs/planning/specs/shared-copy.md` covers for all three front-ends at once.

The key verdicts are the one place two builds of the shared crate could disagree. The native check the TUI links and the WASM module the page runs must return the same verdict for the four fixtures the prototype used: the generator's clean key, a gpg 2.5 key advertising AEAD, a key with no encryption subkey, and a key whose subkey expired. The AEAD fixture is the one that catches the subpacket-34 trap.

## Out of scope

The web form and the capsule, which have their own specs. The onboarding service's handler, drain, store and account page ([#156](https://github.com/kyriakon/kyriakon-infra/issues/156), [#159](https://github.com/kyriakon/kyriakon-infra/issues/159)). The key generator and the browser check page ([#176](https://github.com/kyriakon/kyriakon-infra/issues/176), [#185](https://github.com/kyriakon/kyriakon-infra/issues/185)). The certificate queue and the pending-certificate state ([#154](https://github.com/kyriakon/kyriakon-infra/issues/154)). The reconciliation of the proposal's section 5.9.2, which is its own ticket. The embedded-in-Kleio experience, which needs terminal emulation on Kleio's side and stays off this map. The shared question list's exact entries and its file format, which are the service workstream's to fix; this spec depends only on the list being one ordered file with the two branches.

## Sources

- OpenBSD 7.9 `sshd_config(5)`, read at <https://man.openbsd.org/sshd_config.5> on 2026-10-05: the `none` method "used for access to password-less accounts when `PermitEmptyPasswords` is enabled"; `PermitEmptyPasswords`; ForceCommand's command "invoked by using the user's login shell with the -c option"; the list of keywords allowed after `Match`; `Banner none`; the version addendum's `none` default; `MaxSessions`, `MaxStartups`, `PerSourceMaxStartups`, `PerSourceNetBlockSize`.
- OpenBSD source, read on 2026-10-05: `usr.bin/ssh/auth2-none.c`, where `userauth_none()` calls `mm_auth_password(ssh, "")` only when `options.permit_empty_passwd && options.password_authentication`, `usr.bin/ssh/auth.c`, where `lc = login_getclass(pw->pw_class)` takes the session's login class from the account, and `usr.bin/ssh/session.c`, where `do_child()` runs a forced command as `execve(shell, {shell, "-c", command})` after taking `shell` from that class. The stock unit is `etc/rc.d/sshd`.
- OpenBSD `useradd(8)` and `usr.sbin/user/user.c`, read on 2026-10-05: `-p` stores its argument as the password field, so `-p ''` writes an empty one.
- Repo notes and files: `docs/planning/research/openbsd-per-member-hosting.md` (the chroot, `git-shell` and the tested refusal of non-sftp forced commands under `nologin`, section 4), `docs/planning/research/alert-thresholds.md` (the SSH per-address threshold), `scripts/pf-apply.sh`, `scripts/abuse-monitor.sh`, `openbsd/etc/sshd_config` and `docs/planning/prototypes/keygen-spike/`.
- Decisions: [#150](https://github.com/kyriakon/kyriakon-infra/issues/150), [#154](https://github.com/kyriakon/kyriakon-infra/issues/154), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156), [#158](https://github.com/kyriakon/kyriakon-infra/issues/158), [#176](https://github.com/kyriakon/kyriakon-infra/issues/176), [#182](https://github.com/kyriakon/kyriakon-infra/issues/182), [#183](https://github.com/kyriakon/kyriakon-infra/issues/183), [#185](https://github.com/kyriakon/kyriakon-infra/issues/185), [#233](https://github.com/kyriakon/kyriakon-infra/issues/233).

`docs/planning/research/onboard-sshd-identity.md`, read on 2026-10-13: `ExposeAuthInfo` writes `$SSH_USER_AUTH` for the `none` method too, holding the single line `none`, and holding `publickey <type> <base64>` for a keyed session; `AuthorizedKeysCommand` is never consulted for `none`; one `Match` criterion carries one configuration, and `AuthenticationMethods` cannot express anonymous or key because the client's first request is always a `none` request, so the two paths take two criteria and, with one account, two ports selected by `LocalPort`; `PermitTTY yes` with `ForceCommand` gives a real terminal, `TERM` and `SIGWINCH` included; and the operator's checklist for the facts that need root or a live session.

`docs/planning/specs/shared-copy.md`, read on 2026-10-13: the service catalogue, its columns, the wording that must read identically, and the check that every entry appears in every rendering.

What this spec still could not settle from the record: the re-measured SSH failure threshold, which can only be taken once the port is live; the two-port split, `ExposeAuthInfo` and `AuthorizedKeysCommand` in a `Match` block, which the identity research reads from the manual pages and the source with its operator checklist unrun; and the portal itself, which does not exist in Rust yet.
