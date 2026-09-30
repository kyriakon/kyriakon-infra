# Per-account enforcement for the lifecycle states (public release, section 5.9.1)

**Question:** what can this box enforce, per account, for the account lifecycle states,
without editing `sshd_config` and without inventing a second password store? The premise
in the ticket is that one password opens both IMAP and SMTP submission, so locking it stops
everything at once, and that read-only therefore has to mean something narrower.

**Answer, in eight lines.** Revoking submission while IMAP keeps working is real, and it needs
no second store, because OpenBSD's BSD authentication consults a per-service capability in the
user's login class: smtpd authenticates with the type string `auth-smtp` and Dovecot with
`auth-imap`, and `login_getstyle()` uses that string as the `login.conf` capability name, so a
class containing `auth-smtp=reject` fails every submission attempt and leaves IMAP alone. It
takes effect on the next authentication, with no daemon restart and no password change. A
credentials table on the `listen on` line is real but replaces system authentication for that
listener, so it is an allowlist and it is a second password store, which rules it out. A
`match` rule over the authenticated username with `reject` also works and needs no second
store, but it rejects the message rather than the login. A Dovecot `passwd-file` passdb is
only reachable by Dovecot, so a second credential is IMAP-only by construction, at the cost of
a second file of hashes. LMTP delivery does a userdb lookup and never a passdb lookup, so a
locked password does not stop mail: it keeps arriving and keeps consuming disk, and there is
no quota on `/home` today to stop it. Mailbox read-only is real only through the ACL plugin,
one `owner` line per mailbox in a `dovecot-acl` file, and the right to keep is `post`, added to
lookup, read and seen. Key revocation without a config edit has one honest answer, which is
that removing `~/.ssh/authorized_keys` stops both key paths at once; group membership is not a
revocation lever, and `usermod -Z` stops everything except the in-process sftp server.

**Tested against versus read from sources.** The live mail box was reachable read-only:
`mail.kyriakon.net`, OpenBSD 7.9 GENERIC.MP#11 amd64, dovecot-2.3.21.1p3v0, gmid 2.1.1p0,
git 2.53.0, restic 0.19.1, with `/home` on its own ffs (`/dev/sd1l`). The account used is
unprivileged and `doas` needs a password, so every command run on the box either read a file
or wrote under `/tmp`. The commands actually run there were `sshd -T` against a throwaway host
key and against a throwaway Match fragment under `/tmp`, `smtpd -n` against throwaway configs
under `/tmp`, `man` pages, `doveconf -n`, `rcctl check`, and reads of `/etc/passwd`,
`/etc/group`, `/etc/fstab`, `/etc/login.conf`, `/etc/login.conf.d/*`, `/etc/httpd.conf`,
`/etc/gmid.conf`, `/etc/acme-client.conf`, `/home` and `/usr/local/lib/dovecot`. No account was
created, locked or changed, no daemon was signalled, and nothing outside `/tmp` was written.
Everything about the software's behaviour comes from the OpenBSD 7.9 and Dovecot 2.3.21.1
sources and man pages, quoted below with the file the line came from. Section 10 lists each
claim and which of the two it rests on.

---

## 1. Revoking submission while IMAP keeps working

The lever exists and it is the login class. Both services authenticate with BSD
authentication, and both pass a service type string that becomes a `login.conf` capability
name for that user's login class.

OpenSMTPD passes `auth-smtp`. `usr.sbin/smtpd/smtpd.c` (HEAD, rev 1.451):

```
int
parent_auth_user(const char *username, const char *password)
{
	char	user[LOGIN_NAME_MAX];
	char	pass[LINE_MAX];
	int	ret;

	(void)strlcpy(user, username, sizeof(user));
	(void)strlcpy(pass, password, sizeof(pass));

	ret = auth_userokay(user, NULL, "auth-smtp", pass);
```

Dovecot builds the same shape from the protocol name. `src/auth/passdb-bsdauth.c` (2.3.21.1):

```
	/* check if the password is valid */
	type = t_strdup_printf("auth-%s", request->fields.service);
	result = auth_userokay(request->fields.user, NULL,
			       t_strdup_noconst(type),
			       t_strdup_noconst(password));
```

For an IMAP login `request->fields.service` is `imap`, so the type is `auth-imap`.

`auth_userokay()` reaches the user's class and then the type-specific capability.
`src/lib/libc/gen/authenticate.c` (HEAD):

```
	if ((lc = login_getclass(pwd ? pwd->pw_class : NULL)) == NULL)
		return (NULL);

	if ((style = login_getstyle(lc, style, type)) == NULL) {
```

`src/lib/libc/gen/login_cap.c` (HEAD), and this is the part that decides everything:

```
login_getstyle(login_cap_t *lc, char *style, char *atype)
{
    	char **authtypes = _authtypes;
	...
    	if (!atype || !(auths = login_getcapstr(lc, atype, NULL, NULL)))
		auths = login_getcapstr(lc, "auth", NULL, NULL);
```

`atype` is used verbatim as the capability name, with a fall back to the class's `auth`
capability and then to the built-in default list. Because the callers pass `auth-smtp` and
`auth-imap`, the capability names are those strings.

login.conf(5) documents the pattern, quoted from the box:

> `auth`	list	passwd	Allowed authentication styles. The first value is the default style.
> `auth-type`	list		Allowed authentication styles for the authentication type type.

The shipped `/etc/login.conf` on this box already uses it for ftpd, which shows the exact
spelling of a per-service capability:

```
# Default allowed authentication styles for authentication type ftp
auth-ftp-defaults:auth-ftp=passwd:
```

`reject` is a valid style, and `login_reject(8)` exists on the box with the description
"provide rejected authentication". So the fragment is:

```
# /etc/login.conf.d/lapsed
lapsed:\
	:auth-smtp=reject:\
	:tc=default:
```

and the per-account command is:

```
doas usermod -L lapsed <user>
```

The account keeps its password and its IMAP access, because IMAP looks up the capability
`auth-imap`, finds nothing, falls back to `auth` (from `auth-defaults`, `passwd,skey`) and uses
`passwd`. Submission fails at AUTH. Nothing needs restarting: `auth_userokay()` calls
`login_getclass()` on every attempt, and the class file is read then. `/etc/login.conf.db` does
not exist on this box, so the `cap_mkdb` requirement in login.conf(5) does not apply here; if
the database is ever built, `cap_mkdb` has to run after each edit.

There is a second per-service hook in the same class, `approve-service`: login.conf(5) lists
"`approve-service` program, Program to approve login for service", and `auth_approval()` in
`authenticate.c` looks up the capability `approve-<type>` and falls back to `approve`:

```
		len = snprintf(path, sizeof(path), "approve-%s", type);
	...
	if ((approve = login_getcapstr(lc, s = path, NULL, NULL)) == NULL)
		approve = login_getcapstr(lc, s = "approve", NULL, NULL);
```

That gives a class the ability to route one service's approval through a program, which is
a heavier mechanism than `reject` and not needed for this state.

**What is not real, or not usable, and why.**

A credentials table on the listener is real but replaces system authentication rather than
filtering it. `usr.sbin/smtpd/lka.c` (HEAD) branches on whether the listener named a table:

```
		if (!tablename[0]) {
			m_create(p_parent, IMSG_LKA_AUTHENTICATE,
			    0, 0, -1);
			m_add_id(p_parent, reqid);
			m_add_string(p_parent, username);
			m_add_string(p_parent, password);
			m_close(p_parent);
			return;
		}

		ret = lka_authenticate(tablename, username, password);
```

When a table is named, `lka_authenticate()` looks the user up in it and checks the password
against the table entry, and nothing consults the system password:

```
	switch (table_lookup(table, K_CREDENTIALS, user, &lk)) {
	case -1:
		...
		return (LKA_TEMPFAIL);
	case 0:
		return (LKA_PERMFAIL);
	default:
		if (crypt_checkpass(password, lk.creds.password) == 0)
			return (LKA_OK);
		return (LKA_PERMFAIL);
	}
```

The man page's "either their own normal login credentials or a credentials table" is therefore
per listener, not per user: a listener with a table accepts only users in that table. That
makes it a usable allowlist, and it makes it a second password store, so the ticket's
constraint excludes it. `table(5)` describes the credentials format; the `auth` offload path
(`table_check_service(table, K_AUTH)`) exists for backends that authenticate themselves and is
the same one-or-the-other choice.

`match` rules over the authenticated username are real and need no second store. smtpd.conf(5)
lists the transaction options that can be matched:

> `[!] auth` matches transactions which have been authenticated.
> `[!] auth [regex] username | <username>` matches transactions which have been authenticated for user or user list username.
> `[!] mail-from [regex] sender | <sender>` specifies that transaction's MAIL FROM should match the string or list table sender.

and `match options reject` means "Reject the incoming message during the SMTP dialogue."

The syntax was checked against the real binary on the box. `smtpd -n -f /tmp/wf_c.conf` returned
`configuration OK` for:

```
table denied_submission { "alice" }
action "relay" relay
match from any auth <denied_submission> for any reject
match auth from any for any action "relay"
```

and the same file with a wrong keyword returned `syntax error`, so the parse result is
distinguishable from a lucky pass. `mail-from`, the bare `auth`, and `match for any auth
<table> reject` all parse as well.

Two limits are worth stating. This rule rejects the message, not the AUTH command, so the
credential still authenticates and the client learns at DATA rather than at login. And
placed ahead of `match from any for domain <mail_domains> action "local_mail"`, which is how
first-match-wins ordering requires it, it also stops the member sending to a local address.
For a member whose access is being withdrawn, that is the wanted behaviour; for a narrower
policy it is not.

Dovecot's own per-protocol restriction is real but points the wrong way for submission. The
`deny` passdb is documented as "If the user is found from the passdb, the authentication will
fail", and the service name expands into the filename:

```
passdb {
  driver = passwd-file
  args = /etc/dovecot/deny.%s
  deny = yes
}
```

with "This makes Dovecot look for `/etc/dovecot/deny.imap` and `/etc/dovecot/deny.pop3` files"
and "this deny passdb must be before other passdbs". That suspends IMAP while leaving LMTP
delivery alone, which is useful for the suspended state, and it cannot revoke SMTP submission
because smtpd does not read Dovecot's passdb configuration at all.

There is one more OpenBSD knob that reaches a single service, and it is the wrong size:
account expiry. `login_check_expire(3)` is "called by a BSD Authentication login script to check
whether the user's password entry ... has expired", so `usermod -e` blocks every BSD auth
service at once, IMAP included. It is a suspension, not a submission revocation.

## 2. What a second credential costs

A second credential is only ever a credential for the services that read the file it lives in.
smtpd reads system accounts and a credentials table; it never reads a Dovecot passdb. So a
`passwd-file` entry is IMAP-only by construction, which is the property that makes it usable
as a read-only password. It does not revoke anything: the original system password still opens
submission until the login class or a match rule from section 1 is applied as well.

The passdb, from the Passwd-file page:

```
user:password:uid:gid:(gecos):home:(shell):extra_fields
```

> For a password database it's enough to have only the user and password fields.

The password field has four accepted forms: a bare value read as CRYPT, `{SCHEME}password`, a
libpam-passwd compatible `password[13]` for CRYPT, and `password[34]` for MD5. The default
scheme is CRYPT and the `scheme=` argument overrides it, which matters on this box because
`/etc/login.conf` sets `localcipher=blowfish,a`. Dovecot's own generator lists what this build
supports; `doveadm pw -l` on the box returned

```
SHA1 SSHA512 SCRAM-SHA-256 BLF-CRYPT PLAIN HMAC-MD5 OTP SHA512 SHA DES-CRYPT CRYPT SSHA MD5-CRYPT PLAIN-MD4 PLAIN-MD5 S...
```

so `{BLF-CRYPT}` is available and is the honest choice:

```
doas doveadm pw -s BLF-CRYPT
```

The file belongs to the account Dovecot's auth process runs as, which on the OpenBSD package is
`_dovecot`. The upstream example uses mode 640 with a group owner:

```
# fgrep -v '*' /etc/master.passwd | cut -d : -f 1-4,8-10 > /path/to/file-with-encrypted-passwords
# chmod 640 /path/to/file-with-encrypted-passwords
# chown root:dovecot /path/to/file-with-encrypted-passwords
```

which on this box becomes `chown root:_dovecot` and mode 640.

Coexistence with the existing block is a matter of order and of two documented defaults.
The passdb settings page gives the defaults for each passdb:

```
  result_failure = continue
  result_internalfail = continue
  result_success = return-ok
```

and the Multiple Authentication Databases page says "Dovecot supports defining multiple
authentication databases, so that if the password doesn't match in the first database, it
checks the next one". So `passdb { driver = bsdauth }` first, then the passwd-file, leaves
every real system account authenticating exactly as it does now, and a mismatch at bsdauth
falls through to the file. One caveat is stated on the same page: "Currently the fallback works
only with the PLAIN authentication mechanism." IMAP clients send plaintext credentials over
TLS with `LOGIN` or `PLAIN`, which are plaintext mechanisms, so the fallback applies to normal
mail clients; a CRAM-MD5 or SCRAM client would not fall through.

The bsdauth block cannot carry extra fields, so `nologin` and friends cannot come from it. The
passdb page classifies it as a success or failure database: "These databases simply verify if
the given password is correct for the user. Dovecot doesn't get the correct password from the
database, it only gets a success or a failure reply", which is why the bsdauth source's only
field write is the username itself.

Cost summary: one file of bcrypt hashes, one passdb block, and the ordering rule. What it buys
is a credential that reaches IMAP and nothing else. What it does not buy is revocation of the
first credential, and it moves the "who may read mail" decision into a second place that has to
be kept in step with `/etc/master.passwd`.

## 3. Delivery to a locked account

Delivery does not consult the password, because LMTP resolves a recipient with a userdb lookup
and never a passdb lookup. `src/lmtp/lmtp-local.c` (2.3.21.1) sets the service name and calls
the storage service:

```
	i_zero(&input);
	input.module = input.service = "lmtp";
	input.username = username;
	...
	ret = mail_storage_service_lookup(storage_service, &input,
					  &service_user, &error);
```

and `src/lib-storage/mail-storage-service.c` answers that with a userdb call:

```
	if ((flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0) {
		ret = service_auth_userdb_lookup(ctx, input, temp_pool,
			&username, &userdb_fields, error_r);
```

`service_auth_userdb_lookup()` calls `auth_master_user_lookup()`. There is no passdb lookup
anywhere in that path, and the deployed `userdb { driver = passwd }` supplies uid, gid and home
from `/etc/passwd`.

The password field semantics are in passwd(5):

> The password field is the encrypted form of the password. If the password field is empty, no password will be required to gain access to the machine. ... By convention, accounts that are not intended to be logged in to (e.g. bin, daemon, sshd) only contain a single asterisk in the password field. Note that there is nothing special about `*', it is just one of many characters that cannot occur in a valid encrypted password.

So `usermod -p '*' <user>` sets a value no password can produce, and LMTP is indifferent to it.
Mail addressed to a locked account whose home still exists is delivered into
`~/Maildir` exactly as before, and the Maildir keeps growing.

Two things do stop delivery, and one of them is a trap in the deletion order. If the home or the
Maildir root is missing or is not writable by the account, the Maildir save fails. If the
keyring entry is gone, the platform's own encryption plugin fails closed by design
(`openbsd/dovecot/dovecot.conf`: "Fail-closed: a missing key or daemon aborts the save"), which
means a temporary failure, a message held in the queue and a bounce after four days. Deleting
`/etc/kyriakon/keys/<localpart>.asc` while the account still exists therefore converts inbound
mail into delayed bounces rather than a clean refusal.

Two limits on how much of this is observable today. There is exactly one human account on the
box, `oliver`, so there is no locked member account to watch. And `/etc/passwd` cannot be used
to tell a locked account from a live one, because pwd_mkdb(8) replaces the hash with an
asterisk in the public file: passwd(5) says "The publicly-readable passwd file is generated
from the master.passwd file by pwd_mkdb(8) and has the class, change, and expire fields removed.
Also, the encrypted password field is replaced by an asterisk." Every line in `/etc/passwd` on
the box shows `*`, including `oliver`, and that says nothing about `oliver`'s real password.
What is established is that `openbsd/dovecot/dovecot.conf` records a live delivery on
2026-09-18 with `user=oliver`, while `/var/log/maillog` is mode 0640 root:wheel and could not be
read to confirm it again.

## 4. Key-based access without touching sshd_config

The deployed box does not yet have the shape the ticket assumes. `/etc/ssh/sshd_config` on the
box is 2441 bytes and matches the repo copy, which is OpenBSD's shipped v1.105 with two
departures. It has no `Match` block, one port, no `ChrootDirectory` and no `ForceCommand`, and
`sshd -T` against a throwaway host key confirms the effective values:

```
port 22
permitrootlogin no
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
permittty yes
allowtcpforwarding yes
disableforwarding no
forcecommand none
chrootdirectory none
authorizedkeysfile .ssh/authorized_keys
subsystem sftp /usr/libexec/sftp-server
```

The chrooted sftp on port 2222 and the `Match Group members` block described in
`openbsd-per-member-hosting.md` section 4 are a proposal, not the live state. So the question
"sftp is chrooted on 2222 and git runs git-shell on 22" describes where the design is going.
The levers below were checked against the real sshd binary with the proposed fragment, run as
`sshd -T -f /tmp/wf_sshd -h /tmp/wf_hk -C user=...,lport=...`.

Removing `authorized_keys` stops both paths at once. Both the git session on 22 and the sftp
session on 2222 authenticate from the same file, because the deployed
`AuthorizedKeysFile .ssh/authorized_keys` names one file and there is no per-port variant, and
`Match` cannot discriminate on which key was used, only on user, group, address or port.
sshd_config(5): "Arguments to AuthorizedKeysFile may include wildcards and accept the tokens
described in the TOKENS section. After expansion, AuthorizedKeysFile is taken to be an absolute
path or one relative to the user's home directory." Nothing needs reloading: the daemon is not
being reconfigured, and the file is read as part of authentication, which sshd(8) describes
under AUTHORIZED_KEYS FILE FORMAT: "Each line of the file contains one key".

Group membership is not a revocation lever. With a fragment containing
`Match Group wheel` plus the shared hardening, and `Match Group wheel LocalPort 2222` plus the
chroot and the forced command, the tested results were:

```
== oliver (in wheel), lport 22 ==
permittty no
disableforwarding yes
authenticationmethods publickey
== oliver, lport 2222 ==
permittty no
forcecommand internal-sftp -u 0022
chrootdirectory /home/%u
== nobody (not in wheel), lport 22 ==
permittty yes
disableforwarding no
authenticationmethods any
chrootdirectory none
forcecommand none
== nobody, lport 2222 ==
forcecommand none
chrootdirectory none
```

Removing the user from the group does not deny access. It stops the block from applying, so the
chroot and the forced command disappear and the session falls back to the default path. On port
2222 the sftp subsystem would be executed through the login shell instead of the in-process
server, and on port 22 the account keeps its plain `git-shell` behaviour. An account whose shell
had been left at `/bin/ksh` would end up with an unrestricted shell. Membership in `members` is
what turns the restrictions on, so it is a signup-time setting, not a suspend-time one.

Changing the login shell stops one path and leaves the other. `usermod -s /sbin/nologin <user>`
leaves sftp on 2222 working and breaks port 22. The reason is the order of operations in
`usr.bin/ssh/session.c` `do_child()`, which the sibling note quotes: the chroot and the
`internal-sftp` hand-off happen before the login shell would be exec'd with `-c`, so the
in-process server never touches the shell. Every other command goes through the shell. Tested on
the box:

```
$ /sbin/nologin -c "echo hi"
This account is currently not available.
nologin exit=1
```

`usermod -Z` is the closest single command to a suspension, and it is broader than the shell
change because it touches the password too. usermod(8):

> -Z	Lock the account by appending a `-' to the user's shell and prefixing the password with `*'.

and for the reverse:

> -U	Unlock the account by removing the trailing `-' from the user's shell and the `*' prefix from the password.

The shell becomes a path that does not exist, so the port 22 session fails at exec, and the
password becomes unmatchable, so IMAP and submission fail. What survives is the in-process sftp
server on 2222, for the same reason `/sbin/nologin` does. To stop that too, remove
`authorized_keys` or take the account out of the group that the fragment matches on.

Two mechanisms would make key revocation per-account from a file rather than per-account by
hand, and both need a one-time `sshd_config` edit, so neither is available under the ticket's
constraint. `AuthorizedKeysFile none` and `RevokedKeys` are both in the list of keywords
allowed after a `Match` line, and sshd_config(5) says of `RevokedKeys`: "Specifies revoked public
keys file, or none to not use one. Keys listed in this file will be refused for public key
authentication. ... This file may be consulted for each public key authentication attempt
received by sshd(8)". `RefuseConnection` is on the same allowed-keyword list. Adding one
`RevokedKeys /etc/ssh/revoked_keys` line once, then maintaining that file, is the design that
removes the per-account manual step; it is a change, not something the current file supports.

## 5. Mailbox-level read-only

There is no read-only setting. The namespace settings in 2.3 are `alias_for`, `disabled`,
`hidden`, `ignore_on_failure`, `inbox`, `list`, `location`, `order`, `prefix`, `separator`,
`subscriptions` and `type`. `disabled` is the only switch and it removes the namespace entirely
("If `yes`, namespace is disabled and cannot be accessed by user in any way"), which is not
read-only. Nothing in the passdb extra field list expresses read-only either: the fields are
`user`, `login_user`, `allow_nets`, `allow_real_nets`, `proxy`, `proxy_maybe`, `host`,
`nologin`, `nodelay`, `nopassword`, `fail`, `k5principals`, `delay_until`, `noauthenticate` and
the `forward_` and `event_` families. The nearest is `nologin`, which is a full stop: "User
isn't actually allowed to log in even if the password matches", with the note that to "entirely
block the user from logging in (i.e. account is suspended)" you must ensure "neither `proxy` nor
`host` are defined as one of the passdb extra fields".

Read-only is real through the ACL plugin, and it is enforced on the save path. The plugin is
enabled by a `mail_plugins` entry and a required setting, since "This setting is REQUIRED - if
empty, the acl plugin is disabled":

```
mail_plugins = $mail_plugins acl

plugin {
  acl = vfile
}
```

The rights are the RFC 4314 set: `l` lookup, `r` read, `w` write, `s` write-seen, `t`
write-deleted, `i` insert, `p` post, `e` expunge, `k` create, `x` delete, `a` admin. The
decisive line is in `src/plugins/acl/acl-mailbox.c` (2.3.21.1):

```
static int
acl_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct mailbox *box = ctx->transaction->box;
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);
	enum acl_storage_rights save_right;

	save_right = (box->flags & MAILBOX_FLAG_POST_SESSION) != 0 ?
		ACL_STORAGE_RIGHT_POST : ACL_STORAGE_RIGHT_INSERT;
	if (acl_mailbox_right_lookup(box, save_right) <= 0)
		return -1;
```

An IMAP APPEND is not a post session, so it needs `insert`. An LMTP or LDA delivery is a post
session, so it needs `post`. That single branch is what makes "keep receiving, refuse APPEND"
possible: the line

```
owner lrsp
```

gives lookup, read, write-seen and post. IMAP can select the mailbox and read it, and can change
the `\Seen` flag, which the right `s` covers. APPEND fails for want of `i`, other flag changes
fail for want of `w`, expunge needs `e`, creating mailboxes needs `k`, deleting needs `x`, and
editing ACLs needs `a`. The failure is `MAIL_ERRSTR_NO_PERMISSION`, returned by the same lookup.

Where the line lives decides its scope, and there is no per-user global file. The vfile backend
reads per-mailbox `dovecot-acl` files by default, or one global file when the setting names a
path:

```
plugin {
  # Per-user ACL:
  acl = vfile

  # Global ACL; check for changes every minute
  #acl = vfile:/etc/dovecot/dovecot-acl:cache_secs=60
}
```

The global file's first field is a mailbox-name pattern, matching "the shell-string matching,
not stopping at any boundaries", so `* owner lrsp` applies to every mailbox of every user. That
is a platform-wide policy, not a per-account switch. It also cannot be made conditional on the
user without leaving the setting behind: `acl_backend_vfile_init()` splits the argument on
colons and takes the first field as the path with no variable expansion:

```
	tmp = t_strsplit(data, ":");
	backend->global_path = p_strdup_empty(_backend->pool, *tmp);
```

So per-account read-only is the per-mailbox files. In a Maildir, the docs put them at "The
Maildir's mail directory (eg. `~/Maildir`, `~/Maildir/.folder/`)". That is
`/home/<user>/Maildir/dovecot-acl` for INBOX and one file per existing folder, and the docs add
that a new mailbox takes its ACLs from its parent mailbox at creation: "Every time you create a
new mailbox, it gets its ACLs from the parent mailbox. If you're creating a root-level mailbox,
it uses the namespace's default ACLs." So INBOX's file covers folders created after it was
written, and folders that already existed need their own file.

One caveat to keep: per-mailbox files are only read when `acl_globals_only` is at its default of
`no`, which it is. Setting it to `yes` stops Dovecot looking for `dovecot-acl` files in mailbox
directories, which would silently ignore the per-account files.

The cost, then, is the plugin load, the `acl` setting, and a walk over the account's Maildir
writing one line per existing mailbox, repeated whenever folders were created in between. The
`imap_acl` plugin is deliberately left out: it is the plugin that exposes the IMAP ACL commands,
and the point of the state is that the member cannot change their own rights. And there is a
per-user route worth knowing about for later. The userdb extra fields page says any unknown
setting returned by userdb "is placed into the plugin {} section", so a userdb returning
`acl=vfile:<path>` selects a read-only ACL file per account without touching anybody's maildir.
That route needs a userdb that can return extra fields, and the deployed
`userdb { driver = passwd }` cannot: "The Passwd userdb doesn't support extra fields." It would
mean the passwd-file from section 2, so it trades a maildir walk for the second store.

## 6. Deletion

The commands below assume the section 6.9 layout, with everything under `/home/<user>`. Two
differences from the deployed box are worth stating before the list. The deployed httpd and gmid
chroot to `/var/www` and have no per-member include, so the vhost steps describe the generated
include files from `openbsd-per-member-hosting.md` section 1 rather than files that exist today.
And `/home` has no quota, so the quota step is currently a no-op.

Deletion is a sequence, and the order avoids writing into a tree that is being removed.

1. Take the account out of the access paths before destroying anything, so the window between
   the decision to delete and the deletion itself is closed. The lock stops the password and the
   shell, and the empty secondary-group list stops the `Match Group members` block from applying
   on the next connection:
   ```
   doas usermod -Z <user>
   doas usermod -S '' <user>
   ```
2. Remove the account and its home, which takes the Maildir, the git repos and the web and
   Gemini roots with it. userdel(8):
   ```
        -r	     Remove the user's home directory, any subdirectories, and any
   		     files and other entries in them.
   ```
   ```
   doas userdel -r <user>
   ```
   `userdel` runs pwd_mkdb(8) itself, so the password database is rebuilt without a separate
   step. Once the account is gone, mail addressed to it meets a permanent failure rather than a
   queue, because LMTP cannot resolve the recipient:
   ```
   	if (ret == 0) {
   		smtp_server_recipient_reply(rcpt, 550, "5.1.1",
   					    "User doesn't exist: %s",
   					    username);
   		return -1;
   	}
   ```
   That is `550 5.1.1` from `lmtp_local_rcpt()`, which smtpd treats as permanent and bounces
   immediately, so nothing is written into a home that is being removed.
3. Remove the primary group. `add-user.sh` creates each account with `-g =uid`, which makes a
   group whose id matches the uid, and userdel(8) documents only the home directory and the
   password entry. groupdel(8) "removes a group from the system":
   ```
   doas groupdel <user>
   ```
   Then confirm no group still lists the account, since step 1 emptied the secondary groups and
   this is the check that it worked:
   ```
   grep -F <user> /etc/group
   ```
   No output is the expected result. A line here means the account is still in a group that
   `Match Group members` or `Match Group wheel` might match on, and usermod(8) `-S` is the
   command that fixes it: it "Sets the secondary groups the user will be a member of in the
   /etc/group file", and an "empty value (e.g. '') removes the user from all secondary groups".
4. Remove the keyring entry, on the box and in the repo:
   ```
   doas rm /etc/kyriakon/keys/<localpart>.asc
   git rm keys/<localpart>.asc
   ```
   There is a gap here worth a fix in the same change. `scripts/deploy-mail.sh` installs each
   key it finds and never removes one that has left the set:
   ```
   for k in "$repo_dir"/keys/*.asc; do
   	[ -e "$k" ] || continue
   	install -m 0644 "$k" "$keyring_dir/$(basename "$k")"
   ```
   so deleting the repo file alone leaves the on-box entry in place, and delivery keeps working
   for a key that is supposed to be gone.
5. Remove the per-member vhost files and their include lines, then reload:
   ```
   doas rm /etc/httpd.d/<user>.conf /etc/gmid.d/<user>.kyriakon.net.conf
   doas vi /etc/httpd.d/index.conf      # drop the two include lines
   doas vi /etc/gmid.d/index.conf
   doas httpd -n -f /etc/httpd.conf
   doas gmid -n -c /etc/gmid.conf
   doas rcctl reload httpd gmid
   ```
   The reload is documented behaviour, not a guess: httpd(8) and gmid(8) both reread their
   configuration on SIGHUP, and `rcctl reload` sends it.
6. Revoke and remove the certificate. acme-client(1) has the revocation flag:
   ```
        -r	     Revoke the X.509 certificate.
   ```
   ```
   doas acme-client -r <user>.kyriakon.net
   doas rm /etc/ssl/<user>.kyriakon.net.fullchain.pem
   doas rm /etc/ssl/private/<user>.kyriakon.net.key
   ```
   Then remove the matching `domain` block from the acme-client configuration, or the member
   fragment and its include line if the generated-index layout is in use, or the next renewal
   run recreates the certificate. Removing the files alone does not un-issue anything; the
   revocation is what makes the certificate stop being trusted.
7. Clear the quota entry. edquota(8) has no delete operation, and zeroing is the documented
   way to remove an imposed limit: "Setting a quota to zero indicates that no quota should be
   imposed."
   ```
   doas edquota -u <user>
   doas repquota -a
   ```
   On today's box this is a no-op: `/home/quota.user` does not exist and `/etc/fstab` has no
   quota option on `/home`, so no quota has ever been set.
8. Nothing to do in DNS. The zone already answers every member subdomain from a wildcard, so
   there is no per-member record to remove. `openbsd/etc/nsd/kyriakon.net.zone` carries
   `*	IN	A` and `*	IN	AAAA`, and the spec records why: "a wildcard `*.kyriakon.net` record, so
   that per-user subdomains resolve without a DNS write per signup".
9. Regenerate the finger page, which is derived from the httpd and gmid configs:
   ```
   doas ksh scripts/gen-finger-page.sh > /tmp/finger.txt
   doas install -m 0644 /tmp/finger.txt /etc/kyriakon/finger.txt
   ```
10. Remove any cron entry and alias entry if one was ever created. Standard accounts have no
    crontab, and `/etc/mail/aliases` today points only at `oliver`, so both are guards rather
    than steps. If an alias was added, edit `/etc/mail/aliases` and reload smtpd.

**What survives.**

The payment state dies with the account and the financial ledger does not. ADR 0009 keeps two
records with different keys: "The **payment state** lives with the account ... It is what decides
access, and it dies with the account", while "The **financial ledger** ... is keyed by that
token. It holds the amount, the date received, the rail and the resulting paid-until date. It
holds no username, no contact address and no name." So after deletion there is a dated payment
record that no longer resolves to a person, and nothing in the deletion list touches it. The
token reference written with the account goes away with the account.

Backups survive until retention ages them out. `scripts/backup.sh` backs up `/home` and
`/etc/mail`, and its purge is the retention window:

```
restic forget --keep-daily 30 --keep-weekly 8 --keep-monthly 6 --prune
```

A restic repository is content addressed and cannot target-delete a file, so the last snapshot
that contained the home remains until the monthly window drops it, which is about six months.
The weekly restore-test box holds a restored copy for as long as that box lives. Both are
covered by the same reasoning the proposal already gives for deletion: erasure is bounded by
the retention window, and the window is the mechanism.

## 7. Quotas

Today nothing bounds a suspended account's mail. `/home` is its own filesystem
(`/dev/sd1l on /home type ffs (local, nodev, nosuid)`), `/home/quota.user` does not exist, and
`/etc/fstab` has no quota option on that mount:

```
bbb8a630c9f5d96e.l /home ffs rw,nodev,nosuid 1 2
```

So a locked account keeps receiving mail, because delivery only needs the userdb entry and a
writable Maildir, and the Maildir grows until the filesystem fills. The section 6.9 note covers
turning the quota on with `edquota` and reading it with `repquota`; what follows is what happens
once it is on.

A write past the hard limit fails with `EDQUOT`, because a hard limit stops allocation rather
than reclaiming anything. edquota(8) states the extreme case as a feature: "Setting a hard limit
to one indicates that no allocations should be permitted." Existing mail is never deleted by
reaching a limit, so a lapsed mailbox keeps every message it already has.

Dovecot turns that errno into a quota error. `src/lib-storage/index/maildir/maildir-save.c`:

```
	} else if (ENOQUOTA(errno)) {
		mail_storage_set_error(storage, MAIL_ERROR_NOQUOTA,
```

and the LMTP DATA phase maps that to the over-quota reply:

```
	case MAIL_DELIVER_ERROR_NOQUOTA:
		lmtp_local_rcpt_reply_overquota(llrcpt, error);
		break;
```

```
static void
lmtp_local_rcpt_reply_overquota(struct lmtp_local_recipient *llrcpt,
				const char *error)
{
	...
	if (lda_set->quota_full_tempfail)
		smtp_server_recipient_reply(rcpt, 452, "4.2.2", "%s", error);
	else
		smtp_server_recipient_reply(rcpt, 552, "5.2.2", "%s", error);
}
```

The default is the permanent one, from `src/lib-lda/lda-settings.c`:

```
	.quota_full_tempfail = FALSE,
```

so the choice matters, and the two behaviours are:

- With the default, LMTP answers `552 5.2.2`, which is permanent, so smtpd bounces the message
  and the sender learns at once. This is the honest signal to a correspondent that the mailbox
  is not accepting mail.
- With `quota_full_tempfail = yes`, LMTP answers `452 4.2.2`, which is temporary, so smtpd holds
  the message and retries. The queue lifetime is four days, from `usr.sbin/smtpd/smtpd.h`:
  `#define SMTPD_QUEUE_EXPIRY	 (4 * 24 * 60 * 60)`, set into the config as
  `conf->sc_ttl = SMTPD_QUEUE_EXPIRY;`. sendmail-style warnings follow the smtpd.conf(5)
  default, "bounce warn-interval 4h". The message then bounces after four days of retries. This
  is the setting that turns "mailbox is full" into four days of queue on `/var`.

There is a Maildir consequence that is easy to miss, and the Dovecot fs quota page states it:

> Maildir needs to be able to add UIDs of new messages to `dovecot-uidlist` file. If it can't do this, it can give an error when opening the mailbox, making it impossible to expunge any mails.

On this layout `dovecot-uidlist` lives in the member's own Maildir, on the same quota-limited
filesystem as the mail, so a mailbox at its hard limit can become unopenable rather than merely
unwritable, and the member cannot expunge their way out. The page's remedy is to put the index
and control files on a filesystem with no quota, using `INDEX=` and `CONTROL=` on
`mail_location`. That is a change to the storage layout, not a setting to flip.

The Dovecot quota plugin is the alternative to the filesystem quota, and it is packaged here
(`lib10_quota_plugin.so` and `lib11_imap_quota_plugin.so` are in
`/usr/local/lib/dovecot`). It needs `mail_plugins = $mail_plugins quota` and a `plugin` block,
and when the filesystem quota is the thing enforcing the limit, the documented pairing is the
`noenforcing` argument: "Don't try to enforce quotas by calculating if saving would get user over
quota. Only handle write failures." Two related knobs are worth naming. `lmtp_rcpt_check_quota`
moves the check to RCPT, so the MTA refuses the recipient instead of accepting the body and then
failing, which is the code path visible in `lmtp_local_rcpt_check_quota()` reading
`client->lmtp_set->lmtp_rcpt_check_quota`. And per-user limits come from userdb extra fields
rather than the plugin block, which is another reason a userdb that can return extra fields is
in the design.

For accounting, `repquota -a` reads usage per account and `abuse-monitor.sh` already watches the
soft limit ("quota approach: per-user edquota usage vs soft limit", with `QUOTA_WARN_PCT`
defaulting to 80), so the alerting path for a lapsed mailbox filling up exists before the quota
does.

## 8. The states, as the commands that produce them

| State | What the member can do | Commands |
|---|---|---|
| Active | Mail, submission, sftp, git, web and Gemini | `useradd -m -d /home/<u> -s /sbin/nologin -g =uid -G members <u>`, then set the password, install the keyring entry, write the vhosts, set the quota. The `-G members` part comes from the fragment in `openbsd-per-member-hosting.md` section 4; `scripts/add-user.sh` today runs the same command without it, and there is no `members` group on the box. |
| Lapsed, read-only | Read mail, cannot submit, cannot APPEND | `/etc/login.conf.d/lapsed` with `auth-smtp=reject`, `usermod -L lapsed <u>`, and `owner lrsp` in each `dovecot-acl` |
| Suspended | Nothing, and mail is still delivered | `usermod -Z <u>` and `rm /home/<u>/.ssh/authorized_keys` |
| Preserved, no login, files kept | Nothing | `userdel -p true <u>`, which userdel(8) describes as preserving "the user information in the password file, but do not allow the user to login, by switching the password to an 'impossible' one, and by setting the user's shell to the nologin(8) program" |
| Deleted | Nothing, and mail bounces | The ordered list in section 6 |

The lapsed row is the one the proposal's lifecycle text calls for ("On failed renewal the
account drops to read-only and the user is emailed"), and it needs no second password store.

## 9. What this means for the map

The enforcement primitive for the lapsed state is `usermod -L` against a login class, and it
should be named in the account-lifecycle spec as the mechanism, because it is the only one that
denies submission without touching IMAP, without a second store, and without a daemon restart.
The class file and the class name are part of the deploy, not per-account state, so
`scripts/add-user.sh` or the provisioning service should own them.

`scripts/del-user.sh`, which the proposal already names, has to become the ordered list in
section 6. Two items in it are currently wrong in ways that matter: the keyring sync in
`deploy-mail.sh` never removes entries, and the quota step is meaningless until `/home` carries
a quota.

The read-only state needs a decision the ACL mechanism forces. Per-account read-only is one
`dovecot-acl` line per existing mailbox, so either the provisioning service writes them at lapse
time and again when folders appear, or the design accepts a platform-wide `* owner lrsp` global
ACL file, or the design takes on the passwd-file userdb so the `acl` setting can be overridden
per user. The three are not equivalent and the choice belongs in the spec.

Item 4 changes shape depending on whether the port 2222 fragment has landed. Until it has, the
only per-account switch for key access is removing `authorized_keys`, which stops sftp and git
together. If per-account key revocation from a file is wanted, `RevokedKeys` with a one-time
`sshd_config` line is the design, and it should be settled at the same time as the fragment so
the file is reviewed once.

Item 7 has no enforcement today. No quota exists on `/home`, so the suspended state is "mail
keeps arriving and the disk fills". The quota has to land before any suspended account can be
left that way.

## 10. Tested versus documentary

Run on the box, read-only or writing only under `/tmp`:

- `sshd -T -h /tmp/wf_hk` for the deployed config, and `sshd -T -f /tmp/wf_sshd -h /tmp/wf_hk -C user=...,lport=...` for three Match-fragment cases, including a user in the matched group and a user outside it.
- `sshd -t` on the fragment, which returned `config-ok`.
- `smtpd -n -f` on throwaway configs under `/tmp`: one reject-rule config returned `configuration OK`, a deliberately invalid rule returned `/tmp/wf_c.conf:2: syntax error`, and four further reject-rule forms parsed and then failed lower down at certificate loading, because the throwaway certificate in `/tmp` was not owned by uid 0.
- `/sbin/nologin -c "echo hi"`, which printed "This account is currently not available." and exited 1.
- `doveadm pw -l`, `doveconf -n`, `man` pages for smtpd.conf(5), sshd_config(5), sshd(8), passwd(5), usermod(8), userdel(8), groupdel(8), acme-client(1), edquota(8), login.conf(5), auth_approval(3), login_check_expire(3).
- Reads of `/etc/passwd`, `/etc/group`, `/etc/fstab`, `/etc/login.conf`, `/etc/login.conf.d/dovecot`, `/etc/login.conf.d/rspamd`, `/etc/httpd.conf`, `/etc/gmid.conf`, `/etc/acme-client.conf`, `/etc/mail/aliases`, `/home`, `/etc/ssl`, `/var/dovecot`, `/usr/local/lib/dovecot`.
- `rcctl check smtpd dovecot httpd gmid`, and `netstat -an -f inet` for the listening ports.

Read from sources rather than run:

- The `login_getstyle` capability lookup, and the `auth-smtp` and `auth-imap` type strings. The end-to-end result, an account whose submission fails while IMAP succeeds, needs a state change on a member account, which this ticket forbids, so it is inferred from the four source reads and not observed.
- Every LMTP path and every quota path, which need a delivery to a quota-full or locked mailbox.
- The ACL save path, which needs a mailbox with a `dovecot-acl` file and an IMAP session.
- `httpd -n` and `gmid -n` on a deletion-shaped config, since both refuse to run as a non-root user; the sibling note reached the same limit with `httpd -n`.
- `acme-client -r`, which needs a certificate to revoke.

Not verified, and not verifiable without a state change:

- That `usermod -L <class>` plus `auth-smtp=reject` produces a failed AUTH at the wire. The mechanism is read from four files, but no AUTH was attempted.
- Whether the account `expire` field, set with `usermod -e`, is checked by this build's `login_passwd` style. `login_check_expire(3)` says a BSD auth login script calls it, and getting the style's own source was not possible: `cvsweb.openbsd.org` returns `Invalid path` for `src/libexec/auth/`, so only the library man page was available.
- The current password state of `oliver`. `/etc/master.passwd` is mode 0600 root, and the public `/etc/passwd` shows `*` for every account, so nothing readable distinguishes a set password from a locked one.
- The delivery log. `/var/log/maillog` is mode 0640 root:wheel, so the `user=oliver` delivery line recorded in `openbsd/dovecot/dovecot.conf` could not be re-read.
- Whether `userdel -r` also removes the account from `/etc/group`. userdel(8) documents only `/etc/usermgmt.conf` and the password database, and no account was deleted to test it, so section 6 removes the group explicitly.
- Whether the ACL rights actually produce `MAIL_ERRSTR_NO_PERMISSION` on APPEND for this build's Maildir backend, beyond the `acl_save_begin` source read.
- The Dovecot 2.3 documentation is the 2.3 series, not the released 2.3.21.1 tarball in every page. Where a page names a version ("New in version v2.3.21.1.4" for `acl_dict_index`, for instance), the deployed build is below it and the setting is absent.

## 11. Primary sources

OpenBSD 7.9, read on the box:

- smtpd.conf(5): the `listen on` options, the `match options` list, `match options reject`, `action`, `ttl`.
- sshd_config(5): `Match`, the keywords allowed after `Match`, `AuthorizedKeysFile`, `RevokedKeys`, `ForceCommand`, `Subsystem`, `ChrootDirectory`.
- sshd(8): AUTHORIZED_KEYS FILE FORMAT.
- passwd(5): the password field, the asterisk convention, the public file's asterisk substitution.
- usermod(8), userdel(8), groupdel(8), edquota(8), acme-client(1), login.conf(5), auth_approval(3), login_check_expire(3).
- `/etc/login.conf` shipped by OpenBSD 7.9 (`auth-ftp-defaults:auth-ftp=passwd:`).

OpenBSD source, HEAD as read on 2026-09-30:

- `usr.sbin/smtpd/smtpd.c` (`parent_auth_user`).
- `usr.sbin/smtpd/lka.c` (`lka_authenticate`, the `tablename[0]` branch).
- `usr.sbin/smtpd/smtp_session.c` (`smtp_rfc4954_auth_plain`).
- `usr.sbin/smtpd/smtpd.h` (`SMTPD_QUEUE_EXPIRY`).
- `usr.sbin/smtpd/config.c` (`sc_ttl`).
- `lib/libc/gen/authenticate.c` (`auth_usercheck`).
- `lib/libc/gen/login_cap.c` (`login_getstyle`).

Dovecot 2.3.21.1:

- `src/auth/passdb-bsdauth.c`, `src/auth/passdb-passwd-file.c`.
- `src/lib-storage/mail-storage-service.c`, `src/lmtp/lmtp-local.c`.
- `src/lib-storage/index/maildir/maildir-save.c`.
- `src/lib-lda/lda-settings.c`.
- `src/plugins/acl/acl-mailbox.c`, `src/plugins/acl/acl-backend-vfile.c`.
- The 2.3 documentation: Authentication, Multiple Authentication Databases, Passwd-file, Password database extra fields, User database extra fields, Nologin extra field, Restricting IMAP/POP3 access, Access Control Lists and the acl plugin settings, Quota Configuration, Quota Plugin and the quota plugin settings, Quota Backend: fs, Namespaces, Dovecot LDA, BSDAuth.

Repository files read for the deployed shape:

- `openbsd/etc/smtpd.conf`, `openbsd/dovecot/dovecot.conf`, `openbsd/etc/sshd_config`, `openbsd/etc/httpd.conf`, `openbsd/etc/gmid.conf`, `openbsd/etc/acme-client.conf`, `openbsd/etc/nsd/kyriakon.net.zone`.
- `scripts/add-user.sh`, `scripts/deploy-mail.sh`, `scripts/backup.sh`, `scripts/abuse-monitor.sh`, `scripts/gen-finger-page.sh`.
- `docs/aup.md` (the detect, warn, suspend, delete ladder), `docs/planning/specs/phase-1-foundations.md`, `docs/planning/research/openbsd-per-member-hosting.md`.
- `kyriakon/docs/decisions/kyriakon-net-project-proposal.md` section 5.9.1, and `kyriakon/docs/decisions/0009-payment-records-keyed-by-token.md` on branch `docs/adr-0009-payment-records`.
