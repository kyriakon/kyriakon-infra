# What the onboard sshd tells the TUI about the key that connected (public release, §5.9.2)

> The tracked portal account is `hello`; the probes below used `onboard`, the name at the time.
> The evidence is otherwise unchanged.

**Question:** the portal redesign gives one connection two jobs. An applicant authenticates with
`none`, and a member is whoever the public key sshd saw belongs to. The TUI has no other source
for who is connected, so four things need settling against the daemon itself: whether
`ExposeAuthInfo yes` writes `$SSH_USER_AUTH` for a `none` session at all, what that file holds for
`none` and for `publickey`, where it lives, and whether a forced command can reach it; whether
`AuthorizedKeysCommand` is consulted for `none`, and what that leaves for one instance serving
both paths; whether `PermitTTY yes` with `ForceCommand` gives the forced program a usable pty on
OpenBSD 7.9; and what `AuthenticationMethods` would have to say for a member path to sit beside an
anonymous one.

**Answer, in five lines.** The auth info file is written for a `none` session as well as for a
`publickey` one, because the write depends on `ExposeAuthInfo` and on the session info buffer
being non-empty, and a `none` session puts the single line `none` into that buffer. The file is
`/tmp/sshauth.XXXXXXXXXXXXXXX`, mode 0600, owned by the account; sshd points `SSH_USER_AUTH` at it
in the environment it execs the forced command with, and unlinks it when the connection ends.
`AuthorizedKeysCommand` is never consulted for `none`, because `userauth_none()` asks only the
password path, and with `AuthenticationMethods` naming no key method, `authmethod_lookup()`
refuses a `publickey` request before any key is looked at. Two paths therefore need two Match
criteria, and with one account the only usable criterion is `LocalPort`, which means a second
`Port` line in the same config file. `PermitTTY yes` with `ForceCommand` does give the forced
program a terminal: sshd allocates the pty on the client's `pty-req` before the session request,
sets `TERM` from that request, hands the child the slave as stdin, stdout and stderr with a
controlling tty, and applies window changes with `TIOCSWINSZ`, on which the kernel sends
`SIGWINCH` to the foreground process group. `AuthenticationMethods` accepts `none` in a list, but
one line is a sequence and several lines are alternatives, and the client's first request is
always a `none` request, so a list containing `none` is settled by that request and the key path
goes unused.

**Tested against versus read from sources.** An OpenBSD 7.9 host is reachable and was used
read-only: `mail.kyriakon.net` (7.9 GENERIC.MP#11 amd64, OpenSSH 10.3, LibreSSL 4.3.0, with the
split `/usr/libexec/sshd-session` present). Nothing was written to the box: each candidate
configuration went in over standard input and no file there was created or changed. The
agent-forwarded connection does make the box's sshd create its own agent socket under
`~/.ssh/agent/` for the life of the connection, which is the only thing it leaves behind. No
command ran as root, and no session was attempted there, because the `onboard` account does not
exist on it.

Plain `sshd -T` fails as `oliver` with `sshd: no hostkeys available -- exiting.` because
`/etc/ssh/ssh_host_*_key` are mode 0600 root, but on a connection with agent forwarding,
`sshd -T -f /dev/stdin -o "HostKeyAgent=$SSH_AUTH_SOCK"` runs as `oliver` and dumps a config,
because sshd then accepts the world-readable `.pub` host keys. That is how the eight candidate
configs were checked, including the two-block design and the Match criteria. The man pages read
were the box's own: `sshd_config(5)`, `sshd(8)`, `ssh(1)`, `tty(4)`, `pty(4)` and `mktemp(3)`.
Everything that happens at session time, meaning the empty-password admission, the file's
contents, the pty, `SIGWINCH` and the authlog lines, is read from the 7.9 source and was not
observed; it needs a root-started instance and the account, so it is in the operator checklist
at the end. Section 9 lists every claim by class.

## 1. The write depends on the option, not on a credential

`sshd_config(5)` on the box (7.9) says of `ExposeAuthInfo`:

> Writes a temporary file containing a list of authentication methods and public credentials
> (e.g. keys) used to authenticate the user. The location of the file is exposed to the user
> session through the SSH_USER_AUTH environment variable. The default is no.

The code that writes it has two conditions and neither mentions the method:

```c
/* session.c 1.348 (OpenBSD 7.9), prepare_auth_info_file() at line 219 */
	if (!options.expose_userauth_info || info == NULL)
		return;
```

`info` is `authctxt->session_info`, a buffer with one line per authentication method that
succeeded or went partial. `auth2_update_session_info()` (auth2.c 1.173, line 724) builds each
line as the method name, optionally a slash and submethod, then the key if one was recorded for
that method, then any method info, then a newline.

The `none` method reaches that buffer by asking for password authentication with an empty string:

```c
/* auth2-none.c 1.26, userauth_none() at line 51 */
	none_enabled = 0;
	if ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	if (options.permit_empty_passwd && options.password_authentication)
		return mm_auth_password(ssh, "");
	return (0);
```

That call ends up in the monitor process, and the monitor records the empty password on the first
password check of a connection under the name `none`, not `password`:

```c
/* monitor.c 1.255, mm_answer_authpassword() at line 927 */
	call_count++;
	if (plen == 0 && call_count == 1)
		auth_method = "none";
	else
		auth_method = "password";
```

`monitor_child_preauth()` then calls `auth2_update_session_info()` whenever a method produced an
authentication or a partial one (monitor.c line 290 to 296). So a `none` session has a non-empty
session info buffer, `prepare_auth_info_file()` writes it, and the session gets both the variable
and the file.

Whether the empty string is accepted at all is decided further down, and it is the one condition
the account has to meet. sshd's `sys_auth_passwd()` hands the password to `auth_usercheck()`
(auth-passwd.c 1.49, line 137), which runs the login class's `auth-ssh` style, `passwd` by
default, as the program `/usr/libexec/auth/login_passwd`. That program reads the account's hash
with `getpwnam_shadow()` and compares with `crypt_checkpass()`:

```c
/* lib/libc/crypt/cryptutil.c 1.13 (OpenBSD 7.9) */
	/* empty password */
	if (strlen(goodhash) == 0 && strlen(pass) == 0)
		return 0;
```

An empty stored hash with an empty password succeeds. Every other hash, the `*` of a disabled
account included, takes the failure path, and a hash that is not bcrypt is not supported at all,
so the account's password field must be empty and not a hash of anything.

That also fixes the log line the spec already relies on. `auth_log()` prints the method name and
appends the key only when one was recorded (auth.c 1.164, line 239 to 281), so the applicant line
is `Accepted none for onboard from <address> port <n> ssh2` at `SYSLOG_LEVEL_INFO`, which is the
line the abuse monitor anchors on.

## 2. What the file holds, for `none` and for `publickey`

For a `none` session the file holds one line and nothing else:

```
none
```

The key is not mentioned, and no credential appears, because `auth_method_key` and
`auth_method_info` are both NULL on that path. The applicant's file therefore proves an
authentication happened and says nothing about identity.

For a member who presents one key, the file holds one line:

```
publickey ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

The second field is the base64 key blob with the key type before it, produced by
`sshkey_format_text()` as `"%s %s"` of `sshkey_ssh_name(key)` and `sshkey_to_base64(key)`
(sshkey.c, line 1360 to 1374), and the newline is added by `auth2_update_session_info()`.

Three details the TUI has to plan for:

- The comment field is not there. The TUI gets the type and the blob, so it computes a
  fingerprint itself (`SHA256:<base64>`) for its lookup and for display.
- A certificate arrives as a certificate type, for example
  `ssh-ed25519-cert-v01@openssh.com`, and the blob is the certificate.
- A security key adds method info after the key, `signature count = <n>`
  (auth2-pubkey.c 1.126, line 230), because that path sets `sig_details`. A plain key does not.

Successfully used methods are appended in order, so a connection that completes two methods has
two lines. Nothing in the file names the credential's owner, which is the point: the key is what
sshd verified, and the mapping from key to member is the TUI's to make.

## 3. Where the file is, its permissions, and reaching it from the forced command

`prepare_auth_info_file()` runs in the sshd-session process as the connecting account, with the
account's uid in force, and uses a fixed template in `/tmp`:

```c
/* session.c 1.348, line 219 */
	temporarily_use_uid(pw);
	auth_info_file = xstrdup("/tmp/sshauth.XXXXXXXXXXXXXXX");
	if ((fd = mkstemp(auth_info_file)) == -1) {
```

`mkstemp()` creates the file with mode 0600 (mktemp(3) on the box), so the file is owned by the
account with no group or other access, in `/tmp` (`drwxrwxrwt` on this box). `$TMPDIR` is not
consulted. The path is unpredictable by design, and the daemon never reuses it.

The variable is set where the environment for the session is built, in the same function that
then execs the session's program:

```c
/* session.c 1.348, do_setup_env() at line 791 */
	if (auth_info_file != NULL)
		child_set_env(&env, &envsize, "SSH_USER_AUTH", auth_info_file);
```

`do_child()` (line 1188) runs `do_setup_env()`, takes the new environment with `environ = env`,
and execs either the login shell or, when there is a command, the login shell with `-c` (lines
1342 and 1356). A forced command is a command on that path: `do_exec()` (line 594) replaces the
client's command with `auth_opts->force_command` before calling the child, so the TUI is exec'd
by `do_child()` and inherits `SSH_USER_AUTH`, the file it names, and `SSH_TTY` when a pty exists.
Reading `getenv("SSH_USER_AUTH")` and opening that path is all the TUI needs, and it works for a
`none` session and for a `publickey` one with no difference.

Two limits follow. The variable is set only if the file was created, so a failure in `mkstemp()`
or in the write leaves the TUI with no path at all and only a line in the daemon's log to explain
it. And the file is unlinked when the connection ends (`do_cleanup()`, session.c line 2299 to
2306), so the TUI reads it during the session and keeps no copy of the path for later.

The client cannot forge the variable either. Environment requests from the client are filtered by
`AcceptEnv`, which defaults to an empty list (servconf.c 1.446, line 171 sets
`options->num_accept_env = 0`, and `session_env_req()` at session.c line 1718 requires a match),
and sshd sets its own copy of `SSH_USER_AUTH` after the client's variables have been applied, so
the daemon's value wins even if an operator were to accept the name.

## 4. `AuthorizedKeysCommand` is never consulted for `none`

The daemon dispatches on the method name the client sends. `input_userauth_request()` looks the
method up with `authmethod_lookup()` and calls only that method's handler, and the lookup refuses
a method that no `AuthenticationMethods` list names:

```c
/* auth2.c 1.173, authmethod_lookup() at line 490 */
	if (!auth2_method_allowed(authctxt, method->cfg->name, NULL)) {
		debug3_f("method %s not allowed by AuthenticationMethods", name);
		return NULL;
	}
```

A `publickey` request under `AuthenticationMethods none` therefore fails the lookup and is never
tried: no key is read, no `AuthorizedKeysFile` is opened, and `AuthorizedKeysCommand` does not
run. The command is reached only from the publickey path, through
`user_key_allowed()` and `user_key_command_allowed2()` (auth2-pubkey.c lines 789 and 859), which
the monitor calls when it evaluates a key it was offered (monitor.c line 1084).

`none` is a one-shot method as well. `userauth_none()` sets `none_enabled` to 0 on its first run,
and every OpenSSH client sends a `none` request before anything else, as the comment in
`ssh_userauth2()` says:

```c
/* sshconnect2.c 1.385, line 502 */
	/* initial userauth request */
	userauth_none(ssh);
```

On a config where `none` is available, that first request is the one that succeeds, and the
client is finished before a key could matter. An applicant and a member are indistinguishable
there.

The echo config does parse, which makes the trap easy to miss. A block carrying both settings
passes the config test and shows both in a dump, and changes nothing about what happens:

```
port 2200
allowusers onboard
authorizedkeyscommand /usr/local/sbin/keyecho %t %k
authorizedkeyscommanduser onboard
authenticationmethods none
```

`sshd -t` on the box accepts that config, exit 0, and `sshd -T` prints those lines. The command
is dead configuration on an all-`none` instance.

Two things about the keyword itself, since the member block needs it. `AuthorizedKeysCommand` and
`AuthorizedKeysCommandUser` are allowed after `Match`: both are `SSHCFG_ALL` in the 7.9 keyword
table (servconf.c lines 686 and 687, where `SSHCFG_ALL` is `SSHCFG_GLOBAL|SSHCFG_MATCH`), and both
appear in the keyword list of the `Match` section in `sshd_config(5)` on the box. Observed: a
config with them inside `Match User onboard LocalPort 2201` passes `sshd -t` and shows them in
`sshd -T -C ...,lport=2201`. And `AuthorizedKeysCommand` without its user name is fatal, not a
warning: `sshd -t` on the box answered `AuthorizedKeysCommand set without
AuthorizedKeysCommandUser` and exited 255, matching the check in sshd.c (line 1497 area) and
sshd-session.c (line 947).

What the echo admits is the key it was handed. The command's output is parsed as authorized_keys
lines, and a line of exactly `<type> <base64>` matches the key being tested, so every key is
allowed. `sshd_config(5)` on the box records the order and the valid-user rule:

> AuthorizedKeysCommand is tried after the usual AuthorizedKeysFile files and will not be
> executed if a matching key is found there. By default, no AuthorizedKeysCommand is run. This
> command is only executed for valid users.

The daemon then logs what it accepted, `Accepted publickey for onboard from <address> port <n>
ssh2: ED25519 SHA256:<fingerprint>`, from `auth_log()` with the key appended by
`format_method_key()`. Accepting every key is the useful property here, because the TUI decides
what a key means, but it means the port never refuses a key and the identity it records is the
first key the client offered.

## 5. One instance, two paths

What does not work is a second `Match` block with the same criterion. A block sets values, and a
later block with the same criterion overrides only the keywords it sets, leaving the earlier
block's values in place for the rest. Observed, with two consecutive `Match User onboard` blocks:

```
forcecommand /usr/local/sbin/first
authorizedkeyscommand /usr/local/sbin/keyecho %t %k
authorizedkeyscommanduser onboard
authenticationmethods none
```

The forced command comes from the first block, the key command from the second, and the one
effective method set is `none`. One criterion gives one configuration.

What works is a second criterion. `sshd_config(5)` on the box lists the criteria as `User`,
`Group`, `Host`, `LocalAddress`, `LocalPort`, `Version`, `RDomain` and `Address`, and `Port` takes
multiple values ("Multiple options of this type are permitted"). With one account and one
address, `LocalPort` is the criterion left, so the instance listens on two ports and each
`Match User onboard LocalPort <port>` block carries one path. Observed on the box, with
`Port 2200` and `Port 2201` in one file:

```
$ sshd -T -C user=onboard,host=signup.kyriakon.net,addr=203.0.113.9,lport=2200
passwordauthentication yes
permitemptypasswords yes
authenticationmethods none
permittty yes
exposeauthinfo yes
authorizedkeyscommand none
forcecommand /usr/local/sbin/kyriakon-onboard-tui
```

```
$ sshd -T -C user=onboard,host=signup.kyriakon.net,addr=203.0.113.9,lport=2201
passwordauthentication no
permitemptypasswords no
authenticationmethods publickey
authorizedkeyscommand /usr/local/sbin/kyriakon-onboard-keyecho %t %k
authorizedkeyscommanduser onboard
permittty yes
exposeauthinfo yes
forcecommand /usr/local/sbin/kyriakon-onboard-tui
```

Both ports listen (`sshd -T` prints four `listenaddress` lines, one IPv4 and one IPv6 for each
port), the two blocks do not interfere, and `sshd -t` accepts the file. The anonymous block keeps
`PasswordAuthentication yes` because the `none` method needs it, so putting that keyword inside
the block rather than at the top level leaves the member port with no password path at all.

The alternatives cost more and buy less. A second instance means a second config file, a second
`PidFile`, a second rc.d unit and a third listener, and it buys only separate process limits and
independent restarts. A second account, matched by `Match User`, contradicts the one-account
decision the spec records. The two-port single instance matches the shape the mechanics note
already verified for the sftp and git split on the member sshd, so it needs no new mechanism, but
it does need a second published port and a second pf rule (or one rule listing both ports).

## 6. `PermitTTY yes` with `ForceCommand`

`PermitTTY` is allowed after `Match`: it is `SSHCFG_ALL` in the 7.9 keyword table (servconf.c line
672) and it appears in the `Match` keyword list of `sshd_config(5)` on the box. Observed: a block
carrying `PermitTTY yes` passes `sshd -t` and `sshd -T` prints `permittty yes` for that port.

With `PermitTTY yes`, the pty comes from the client's `pty-req` request, which sshd handles in
`session_pty_req()`. The guard sits before the request is even parsed, which is why a refused pty
request leaves no terminal type behind:

```c
/* session.c 1.348, session_pty_req() at line 1543 */
	if (!auth_opts->permit_pty_flag || !options.permit_tty) {
		debug("Allocating a pty not permitted for this connection.");
		return 0;
	}
	if ((r = sshpkt_get_cstring(ssh, &s->term, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->col)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &s->row)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
```

The rest of that function allocates the pair with `mm_pty_allocate()` (which is `openpty()`,
sshpty.c line 47), applies the terminal modes with `ssh_tty_parse_modes()`, and sets the window
size on the master with `pty_change_window_size()`, which is `ioctl(TIOCSWINSZ)` (sshpty.c line
123).

`TERM` is set only when that request happened, because the environment takes it from the session's
terminal type:

```c
/* session.c 1.348, do_setup_env() at line 791 */
	if (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
```

The forced command then runs with the pty as its own terminal. `do_exec()` sends a session with a
pty to `do_exec_pty()` and one without to `do_exec_no_pty()` (session.c line 651), and
`do_exec_pty()` makes the slave the controlling tty and dup2's it onto the standard descriptors
before `do_child()` execs the forced command (lines 553 to 565). So the TUI finds `isatty(0)`
true, `/dev/tty` usable, `SSH_TTY` set, `TERM` set to what the client sent, and the starting size
from the client's request.

Window changes and `SIGWINCH` come next. `session_window_change_req()` applies the new size to the
master (session.c line 1534, with the ioctl at line 1544), and the signal is the kernel's, sent
when the size actually changes:

```c
/* sys/kern/tty.c 1.183.2.1 (OpenBSD 7.9), TIOCSWINSZ */
	case TIOCSWINSZ:
		if (bcmp((caddr_t)&tp->t_winsize, data, sizeof (struct winsize))) {
			tp->t_winsize = *(struct winsize *)data;
			pgsignal(tp->t_pgrp, SIGWINCH, 1);
		}
		break;
```

`pgsignal()` delivers to the foreground process group, which is the forced command's group, so a
full-screen TUI gets its resize signal from the kernel and not from sshd. A client that connects
with `ssh -T` never sends `pty-req`, so it gets a pipe: no `SSH_TTY`, no `TERM`, no size, no
`SIGWINCH` (the ioctl is attempted on a descriptor of -1 and does nothing). The TUI can tell the
two apart with `isatty(0)`, and `SSH_TTY`, which is set only when a pty was allocated, works as a
second check.

None of this was observed. The config half is observed, the behaviour is read from the 7.9 source,
and the checklist at the end is where the operator confirms it with a real session.

## 7. `AuthenticationMethods` and the member path

`none` is a legal entry in a list. `sshd_config(5)` on the box lists it among the available
methods, "(used for access to password-less accounts when PermitEmptyPasswords is enabled)". The
config parser validates every list name with `auth2_methods_valid()` (servconf.c line 2568), and
the listener validates again requiring each named method to be enabled (sshd.c line 1497, and
sshd-session.c line 966), where `none` counts as enabled because its flag starts at 1
(auth2-methods.c lines 39 to 43). Observed: `sshd -t` accepted `AuthenticationMethods
none,publickey` and `AuthenticationMethods publickey,none`, exit 0, and rejected `nonesuch` with
`Unknown authentication method "nonesuch" in list`, exit 255.

The semantics are what makes the member path awkward. One line is a sequence: every method in it
must complete, in order. Several lines are alternatives: completing any one list authenticates
(auth2_setup_methods_lists() at auth2.c line 517, auth2_update_methods_lists() at line 614).
Against that:

- `none,publickey` requires both. Nothing is admitted until a key is accepted, so the applicant
  cannot use it.
- `publickey,none` cannot be completed. The client's initial `none` request arrives first and the
  list does not start with `none`, so it is refused (`list_starts_with()` at auth2.c line 556);
  after the key completes, the remaining method is `none`, which the client is never asked for
  again and which the server would refuse anyway once `none_enabled` is 0. The server does not
  advertise `none` in the failure message at all, by design (`authmethods_get()` skips it at
  auth2.c line 454), so no client can be prompted back into it.
- Two lines, one `none` and one `publickey`, read as alternatives but are not alternatives in
  practice. Where `none` is available, the client's first request satisfies the `none` line, so
  the key is never presented. This is the dead end that forces the two-criterion design in
  section 5.

For the member block the setting is therefore just `AuthenticationMethods publickey`, with
`PasswordAuthentication no` alongside it so the `none` path cannot be reached even by accident:
`authmethod_lookup()` refuses `none` because no list names it, and with `PasswordAuthentication`
off `userauth_none()` would return 0 in any case.

Two consequences for the TUI's copy and for its key handling follow from the echo command, and
they are inference from the code rather than observation. First, every key is accepted, so the key
sshd records is the first key the client offered; a member with several keys in an agent gets
whichever the client tries first, and the walkthrough should tell members to connect with
`-i <key> -o IdentitiesOnly=yes`. Second, a member who offers a key no account knows still gets a
session, so the TUI has to answer with "this key is not one I know" rather than with a refused
connection, which also keeps the member port from becoming a key oracle.

## 8. What the spec amendment can write down

- The applicant's session has no identity to read. `$SSH_USER_AUTH` holds the single line `none`,
  so the TUI takes the anonymous path without asking sshd anything else, and it must not treat
  the file as a credential.
- The member's session carries the key sshd verified: `publickey <type> <base64>`, from which the
  TUI computes the fingerprint itself. The comment field is not available, and a certificate
  arrives as a certificate type.
- Both paths read the same variable from the same place. Nothing else about the daemon's identity
  handling changes between them, and the file is gone when the connection ends.
- The member path needs its own `Match` block selected by `LocalPort`, on its own `Port` line,
  with `AuthenticationMethods publickey`, `PasswordAuthentication no`,
  `AuthorizedKeysCommand <path> %t %k` and `AuthorizedKeysCommandUser onboard`. The echo command
  accepts every key, so the port is not a login and the TUI makes the decision.
- The anonymous block keeps `PermitEmptyPasswords yes`, `AuthenticationMethods none` and
  `PasswordAuthentication yes`, and the whole `PasswordAuthentication` keyword should move inside
  the block so the member port has no password path.
- `PermitTTY yes` in both blocks is what gives the TUI a terminal, and the TUI should check
  `isatty(0)` rather than assume it, since a `ssh -T` client still gets a pipe.
- The existing claim that the applicant lands in `authlog` as `Accepted none for onboard from
  <address> port <n> ssh2` survives checking, and the member path adds
  `Accepted publickey for onboard from <address> port <n> ssh2: <type> SHA256:<fingerprint>`.

## 9. Claims by class

Observed on the box, read-only, nothing written:

- Versions: `uname -a` gives 7.9 GENERIC.MP#11 amd64, `ssh -V` and `sshd -V` give OpenSSH_10.3
  LibreSSL 4.3.0, and `/usr/libexec/sshd-session` exists beside `/usr/sbin/sshd`.
- Unprivileged `sshd -T` fails without a host key (`sshd: no hostkeys available -- exiting.`,
  exit 1) because `/etc/ssh/ssh_host_*_key` are 0600 root; it works with
  `-o "HostKeyAgent=$SSH_AUTH_SOCK"` on an agent-forwarded connection.
- Every config check quoted above: the amended single-port block, the two-port two-block design,
  two blocks with the same criterion, `none,publickey`, `publickey,none`, `nonesuch`, and
  `AuthorizedKeysCommand` without `AuthorizedKeysCommandUser`.
- `/tmp` is `drwxrwxrwt`.
- The man pages named in the sources below were read on the box, so their wording is the deployed
  version's.

Read from source, OpenBSD 7.9 revisions fetched from cvsweb, with the -current copies agreeing on
every point quoted: session.c 1.348, auth2.c 1.173, auth2-none.c 1.26, auth2-methods.c,
auth2-pubkey.c 1.126, auth.c 1.164, auth-passwd.c 1.49, monitor.c 1.255, servconf.c 1.446,
servconf.h 1.176, sshpty.c 1.35, sshkey.c, sshd.c 1.626, sshd-session.c 1.23, sshconnect2.c 1.385,
libexec/login_passwd/login_passwd.c 1.20, lib/libc/crypt/cryptutil.c 1.13, and sys/kern/tty.c
1.183.2.1.

Man page only: the wording of `ExposeAuthInfo`, `PermitTTY`, `ForceCommand`,
`AuthorizedKeysCommand`, `AuthorizedKeysCommandUser` and `AuthenticationMethods`, the list of
keywords allowed after `Match`, the token list for `AuthorizedKeysCommand`, the `Port` multiple
values note, and the `Match` criteria list.

Not observed, and not observable without root: any session at all, which covers the empty-password
admission, the file's contents for `none` and for `publickey`, the pty a forced command sees,
`SIGWINCH`, and the authlog lines. The `onboard` account does not exist on the live box, so no
session could have been attempted as the unprivileged account either.

Inference, from the code and not from a run: that the member's recorded key is the first key the
client offered, and that a member who offers an unknown key still reaches the TUI.

## Primary sources

- `sshd_config(5)`, OpenBSD 7.9, read on the box on 2026-10-13: `ExposeAuthInfo`, `PermitTTY`,
  `ForceCommand`, `PasswordAuthentication`, `PermitEmptyPasswords`, `AuthorizedKeysCommand`,
  `AuthorizedKeysCommandUser`, `AuthenticationMethods` including the `none` entry, the `Match`
  criteria and the keyword subset allowed after `Match`, `Port`, and the `TOKENS` list.
  <https://man.openbsd.org/sshd_config.5>
- `sshd(8)`, OpenBSD 7.9, on the box: the `SSH_ORIGINAL_COMMAND` reference and the
  `AUTHORIZED_KEYS FILE FORMAT` section the key command's output is parsed as.
  <https://man.openbsd.org/sshd.8>
- `ssh(1)`, OpenBSD 7.9, on the box: `SSH_USER_AUTH` "may contain a pathname to a file that lists
  the authentication methods successfully used when the session was established, including any
  public keys that were used".
- `mktemp(3)`, OpenBSD 7.9, on the box: `mkstemp()` creates the file with mode 0600.
- `tty(4)` and `pty(4)`, OpenBSD 7.9, on the box, for the terminal interface and the pty pair.
- `usr.bin/ssh/session.c` 1.348: `prepare_auth_info_file()` at line 219, the call site in
  `do_authenticated()` at line 318, `do_setup_env()` at line 791 with `SSH_USER_AUTH` at line 903
  and `TERM` at line 836, `do_exec_pty()` at line 502 with the controlling tty at line 553,
  `do_exec()` at line 594 with the forced command substitution at line 604, `do_child()` at line
  1188 with the exec at lines 1342 and 1356, `session_pty_req()` at line 1543,
  `session_window_change_req()` at line 1544, and the unlink in `do_cleanup()` at line 2299.
  <https://cvsweb.openbsd.org/src/usr.bin/ssh/session.c?rev=OPENBSD_7_9>
- `usr.bin/ssh/auth2.c` 1.173: `auth2_method_allowed()` at line 425, `authmethods_get()` at line
  445 with the skip of `none` at line 454, `authmethod_lookup()` at line 490,
  `auth2_setup_methods_lists()` at line 517, `list_starts_with()` at line 556,
  `auth2_update_methods_lists()` at line 614, and `auth2_update_session_info()` at line 724.
- `usr.bin/ssh/auth2-none.c` 1.26: `userauth_none()` at line 51, with `none_enabled = 0` and the
  empty-string password call.
- `usr.bin/ssh/auth2-methods.c`: the `none` method config with its enabled flag at lines 39 to 43,
  and `auth2_methods_valid()` at line 91.
- `usr.bin/ssh/auth2-pubkey.c` 1.126: `user_key_allowed()` at line 789 and
  `user_key_command_allowed2()` at line 859, which is the only caller of `AuthorizedKeysCommand`,
  plus the security-key method info at line 230.
- `usr.bin/ssh/auth.c` 1.164: `format_method_key()` at line 202 and `auth_log()` at line 239.
- `usr.bin/ssh/auth-passwd.c` 1.49: `auth_password()` at line 74 with the empty-password gate at
  line 85, and `sys_auth_passwd()` at line 131, which calls `auth_usercheck()` at line 137.
- `libexec/login_passwd/login_passwd.c` 1.20: the `getpwnam_shadow()` read and the
  `crypt_checkpass()` call at line 162. `lib/libc/crypt/cryptutil.c` 1.13:
  `crypt_checkpass()` at line 25, where an empty password matches only an empty hash and any
  unsupported hash fails.
- `usr.bin/ssh/monitor.c` 1.255: `monitor_child_preauth()` at line 231 with the session info
  update at lines 290 to 296, `mm_answer_authpassword()` at line 927 with the `none` naming at
  line 952, `mm_answer_keyallowed()` at line 1056 with the key check at line 1084, and the key
  record for a verified signature at line 1386.
- `usr.bin/ssh/servconf.c` 1.446: the keyword table entries for `permittty` at line 672,
  `authorizedkeyscommand` and `authorizedkeyscommanduser` at lines 686 and 687,
  `authenticationmethods` at line 691 and `exposeauthinfo` at line 697, the
  `SSHCFG_ALL` definition at line 559, the `AcceptEnv` default at line 171, and the parse-time
  method check at line 2568. `servconf.h` 1.176: the option declarations for the same keywords.
- `usr.bin/ssh/sshpty.c` 1.35: `pty_allocate()` at line 47, which calls `openpty()`, and
  `pty_change_window_size()` at line 123 with `ioctl(ptyfd, TIOCSWINSZ, &w)` at line 133.
- `usr.bin/ssh/sshkey.c`: `sshkey_format_text()` at line 1360.
- `usr.bin/ssh/sshd.c` 1.626: the handler validation block around line 1497, the host key load
  and the "no hostkeys available" exit at line 1615, and the config dump at line 1676 with the
  test-mode exit at line 1686.
- `usr.bin/ssh/sshd-session.c` 1.23: the postauth flow at lines 1150 to 1192, where the process
  that ran the authentication calls `do_authenticated()`, and the same handler validation at
  lines 947 and 966.
- `usr.bin/ssh/sshconnect2.c` 1.385: the `none` client method at line 407, the initial request at
  lines 502 and 503, and `authmethod_get()` at line 2310.
- `sys/kern/tty.c` 1.183.2.1 (the OpenBSD 7.9 branch): `TIOCSWINSZ` with
  `pgsignal(tp->t_pgrp, SIGWINCH, 1)` at line 1030.
- Repo files read for the current shape: `openbsd/etc/sshd_config.onboard`,
  `docs/planning/specs/ssh-onboarding-tui.md`, `docs/planning/research/openbsd-per-member-hosting.md`
  (the earlier `sshd -T` work with a throwaway host key and the sftp and git port split).
- Decisions: [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) and
  [#245](https://github.com/kyriakon/kyriakon-infra/issues/245), and this ticket,
  [#356](https://github.com/kyriakon/kyriakon-infra/issues/356).

## For the operator

Every command below needs root and none was run. Each line states what the output must be for the
claim to hold.

Config, as the file stands amended with two ports and the per-path blocks:

```
doas sshd -t -f /etc/ssh/sshd_config.onboard
```

Must print nothing and exit 0. Any output is a config error, and `AuthorizedKeysCommand set
without AuthorizedKeysCommandUser` is the one that is easy to hit.

```
doas sshd -T -f /etc/ssh/sshd_config.onboard -C user=onboard,host=signup.kyriakon.net,addr=203.0.113.9,lport=2200
doas sshd -T -f /etc/ssh/sshd_config.onboard -C user=onboard,host=signup.kyriakon.net,addr=203.0.113.9,lport=2201
```

The first must contain `authenticationmethods none`, `permitemptypasswords yes`,
`passwordauthentication yes`, `permittty yes`, `exposeauthinfo yes`,
`forcecommand /usr/local/sbin/kyriakon-onboard-tui`, `authorizedkeyscommand none`, `maxsessions 1`,
`permitopen none`, `permituserrc no` and `disableforwarding yes`. The second must contain
`authenticationmethods publickey`, `passwordauthentication no`, `permitemptypasswords no`,
`authorizedkeyscommand /usr/local/sbin/kyriakon-onboard-keyecho %t %k`,
`authorizedkeyscommanduser onboard`, and the same five session keywords. Both must print four
`listenaddress` lines, one IPv4 and one IPv6 for each port. An operator run of the second command
should look exactly like the transcript in section 5.

```
awk -F: '$1 == "onboard" { print length($2) }' /etc/master.passwd
ls -l /usr/local/sbin/kyriakon-onboard-keyecho
```

The first must print 0. `crypt_checkpass()` accepts an empty password only against an empty
stored hash, and the `*` of a disabled account takes the failure path, so a non-zero length means
the applicant path refuses everyone. The second must show the command owned by root and not
writable by group or others, for example `-rwxr-xr-x 1 root wheel`. Anything else and sshd ignores
the key command.

The session probe. Use a throwaway account whose login class is `default` and whose shell is a
real one, because the forced command is exec'd as `<login shell> -c '<command>'` and
`/sbin/nologin` would swallow it. The real `onboard` account does not qualify until its class
carries the TUI as its shell.

```
doas useradd -d /var/empty -s /bin/sh -L -p '' onboardprobe
doas cp /etc/ssh/sshd_config.onboard /tmp/sshd_config.identity-probe
```

In the copy, set the ports to 2299 and 2300, change `AllowUsers onboard` to
`AllowUsers onboardprobe`, and change each block's `ForceCommand` to

```
	ForceCommand /bin/sh -c "echo TERM=$TERM; echo TTY=$SSH_TTY; echo USERAUTH=$SSH_USER_AUTH; ls -l $SSH_USER_AUTH 2>&1; cat $SSH_USER_AUTH 2>&1; stty size"
```

Then:

```
doas /usr/sbin/sshd -D -dd -f /tmp/sshd_config.identity-probe
ssh -p 2299 -t onboardprobe@signup.kyriakon.net
ssh -p 2299 -T onboardprobe@signup.kyriakon.net
ssh -p 2300 -i <member key> -o IdentitiesOnly=yes onboardprobe@signup.kyriakon.net
```

The first connection must print `TTY=/dev/ttyp<n>`, a non-empty `TERM`, and a size from `stty
size` such as `24 80`, and must print `USERAUTH=/tmp/sshauth.<15 chars>`, an `ls -l` line reading
`-rw------- 1 onboardprobe onboardprobe`, and then `none` from `cat`. The second must print no
`TTY` and no `TERM`, `stty size` must fail with `not a tty`, and `cat` of the same file must still
print `none`, which is the whole of what an applicant's session proves. The third must print
`publickey ssh-ed25519 <base64>` from `cat`, and `ssh-keygen -lf` of that blob's fingerprint must
equal the fingerprint of the key the client sent. An `ssh -T` on port 2300 must print the same
`publickey` line with no `TERM`.

Resize delivery, in the first connection: if the client's window changes, the TUI receives
`SIGWINCH` and `stty size` in the probe reports the new size. `ssh -vv` on either anon connection
must show `Next authentication method: none` before any other method, which is the request the
`none` line comes from.

```
doas grep -E 'Accepted (none|publickey)' /var/log/authlog
```

Must contain `Accepted none for onboardprobe from <address> port <n> ssh2` for each anonymous
connection and `Accepted publickey for onboardprobe from <address> port <n> ssh2: ED25519
SHA256:<fingerprint>` for the keyed one, with the fingerprint matching the member key. The member
port must refuse an anonymous attempt:

```
ssh -p 2300 -o PreferredAuthentications=none -o PubkeyAuthentication=no onboardprobe@signup.kyriakon.net
```

Must fail with `Permission denied (publickey).`, which is what keeps the member port from carrying
the applicant path.

Finish by removing the probe account and the copy:

```
doas userdel onboardprobe
doas rm /tmp/sshd_config.identity-probe
```
