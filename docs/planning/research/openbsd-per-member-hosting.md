# OpenBSD mechanics for per-member hosting (public release, §6.9)

**Question:** what does OpenBSD 7.9 actually support for one member per OS account with
`username.kyriakon.net` served over HTTPS and Gemini, an sftp-only upload path, `pass` git
repos over SSH keys, and a 5 GB quota? Specifically: config includes, Let's Encrypt rate
limits per member subdomain, quota mechanics, the chrooted `internal-sftp` shape, and what
`git-shell` needs per key.

**Answer, in five lines.** None of `httpd.conf`, `gmid.conf` or `acme-client.conf` includes
a directory; each takes one file path, and a directory path is accepted but silently reads
nothing, so a signup writes a generated index file that the daemons include. The Let's
Encrypt limit that binds is 50 new certificates per registered domain per 7 days, which caps
onboarding at 50 immediately and about 7.1 per day after that, so 200 members take roughly
three weeks to onboard unless an override is granted; renewals are exempt, and the
renewal load at 200 members is about 3.3 certificates per day, well inside the same budget.
A 5 GB member quota is `edquota`, one `quota.user` file at the root of one ffs, with a soft
and a hard limit and a one week grace period, set non-interactively with `edquota -p` and
read back with `repquota`. The chroot for sftp works with `/sbin/nologin` only because
sshd runs `internal-sftp` in-process and never execs the login shell; every other forced
command, `git-shell` included, is exec'd through that shell and `nologin` ignores `-c` and
exits 1. Because `ChrootDirectory` applies to every session of the matched user, a chrooted
member cannot run `git-shell` in the same chroot, and the fix is to put sftp on its own
port and match on `LocalPort`.

**Tested against versus read from sources.** An OpenBSD 7.9 host is reachable and was used:
`mail.kyriakon.net` (7.9 GENERIC.MP#11 amd64, gmid 2.1.1p0, git 2.53.0). The account is
unprivileged and `doas` requires a password, so every command run on the box was read-only
or wrote under `/tmp`: `gmid -n` config checks, `/sbin/nologin -c`, `git-shell -c`,
`quota`, `repquota`, `quotaon` (which fails with `Operation not permitted` as non-root),
`ls` and `stat` of `/home` and `/var/www`. `sshd -T` does run without root once it is given a
throwaway host key with `-h`, so both sshd_config fragments were checked against the real
binary, including which Match block applies on which port. `httpd -n` and `acme-client -n`
refuse to run without root (`httpd: need root privileges`, `acme-client: must be run as
root`), so the include behaviour of those two parsers comes from their source and man pages
rather than from a run. Section 7 lists every claim by class.

---

## 1. Config includes: one file per include, never a directory

All three daemons document `include` and all three implement it as a single path opened with
`fopen(3)`. There is no globbing and no directory support in any of them.

httpd.conf(5), OpenBSD 7.9:

> Additional configuration files can be included with the include keyword, for example:
>
>     include "/etc/httpd.conf.local"

acme-client.conf(5), OpenBSD 7.9:

> Additional configuration files can be included with the include keyword, for example:
>
>     include "/etc/acme-client.sub.conf"

gmid.conf(5), gmid 2.1.1p0 (a port, so its own documentation applies rather than OpenBSD
base):

> Additional configuration files can be included with the include keyword, for example:
>
>     include "/etc/gmid.conf.local"

The grammar of each is a single `include STRING` rule that calls `pushfile()`:

```
include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = pushfile($2, 0)) == NULL) {
				yyerror("failed to include file %s", $2);
```

`pushfile()` in each parser is `fopen()` on the string as given:

```
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("can't open %s", nfile->name);
```

Sources: `usr.sbin/httpd/parse.y` (rule at line 182, `pushfile` at line 1972),
`usr.sbin/acme-client/parse.y` (rule at line 129, `pushfile` at line 804),
`omar-polo/gmid` `parse.y` (rule at line 165, `pushfile` at line 1092). `grep -n 'glob('`
returns no match in any of the three files, which is why a glob is passed to `fopen`
literally.

A glob is not expanded, and gmid is the case that was tested. `include
"/tmp/wf-test/conf.d/*.conf"` with two config files present gives:

```
can't open /tmp/wf-test/conf.d/*.conf: No such file or directory
/tmp/wf-test/gmid-glob.conf:1 error: failed to include file /tmp/wf-test/conf.d/*.conf
```

`gmid -n` exits 1. httpd and acme-client cannot be exercised without root, but their source
has the same `fopen` and no `glob(3)` call.

A directory path is worse than a glob, and gmid is again the tested case. `include
"/tmp/wf-test/d2"`, where `/tmp/wf-test/d2/one.conf` holds a server block that is
deliberately invalid, prints `config OK` and exits 0. `fopen()` on a directory succeeds, so
`pushfile()` returns a handle and the parser reads zero bytes. None of the three lexers
checks `ferror()`, so an include path that is a directory is a silent no-op rather than an
error. That is the failure mode to design against: a typo that drops the file name silently
serves nothing.

Include nests, because the include rule sits at the top level of the grammar in all three
(`grammar: ... | grammar include '\n'` in httpd and acme-client, `conf: ... | conf include nl`
in gmid). A generated index file that lists per-member files therefore works.

Quoting rules differ slightly. httpd.conf(5) says "Arguments not beginning with a letter,
digit, or underscore must be quoted", and acme-client.conf(5) says "Arguments not beginning
with a letter, digit, underscore, or '/' must be quoted". Paths start with `/`, so both are
quoted in practice.

### What the signup flow does instead

One generated index per daemon, rewritten atomically, and never the hand-written config. The
member file is written first and the index lists it:

```
# /etc/httpd.d/index.conf  (generated by the signup script, never edited by hand)
include "/etc/httpd.d/alice.conf"
include "/etc/httpd.d/bob.conf"
```

```
# /etc/httpd.d/alice.conf  (generated)
server "alice.kyriakon.net" {
	listen on * tls port 443
	tls {
		certificate "/etc/ssl/alice.kyriakon.net.fullchain.pem"
		key "/etc/ssl/private/alice.kyriakon.net.key"
	}
	location "/.git/*" {
		block
	}
	location "/*" {
		root "/alice/www"          # relative to chroot "/home", see §4
	}
}

server "alice.kyriakon.net" {
	listen on * port 80
	location "/.well-known/acme-challenge/*" {
		root "/acme"               # /home/acme, see below
		request strip 2
	}
	location "/*" {
		block return 301 "https://alice.kyriakon.net$REQUEST_URI"
	}
}
```

The hand-written `/etc/httpd.conf` gains exactly one line, `include "/etc/httpd.d/index.conf"`.
httpd(8) states that "httpd rereads its configuration file when it receives SIGHUP and reopens
log files when it receives SIGUSR1", so the reload is `rcctl reload httpd` after `httpd -n`
passes. gmid(8) states the same for Gemini, "gmid rereads the configuration file when it
receives SIGHUP and reopens log files when it receives SIGUSR1", so `rcctl reload gmid` covers
the Gemini side.

acme-client is driven per domain handle (`acme-client alice.kyriakon.net`), so all members
must be in the loaded config. The same index pattern applies to `/etc/acme-client.conf`:

```
# /etc/acme-client.d/members.conf  (generated)
domain alice.kyriakon.net {
	domain key "/etc/ssl/private/alice.kyriakon.net.key"
	domain full chain certificate "/etc/ssl/alice.kyriakon.net.fullchain.pem"
	sign with letsencrypt
}
```

gmid, same pattern, with the port's own paths for `cert` and `key`:

```
# /etc/gmid.d/index.conf  (generated)
include "/etc/gmid.d/alice.kyriakon.net.conf"
```

```
# /etc/gmid.d/alice.kyriakon.net.conf  (generated)
server "alice.kyriakon.net" {
	listen on * port 1965
	cert "/etc/ssl/alice.kyriakon.net.fullchain.pem"
	key "/etc/ssl/private/alice.kyriakon.net.key"
	root "/alice/gemini"           # relative to chroot "/home", see §4
}
```

gmid.conf(5) states that "All the paths in the configuration file are relative to the chroot
directory, except for the cert, key and ocsp paths", which is why the `cert` and `key` lines
stay absolute and match `openbsd/etc/gmid.conf` today.

The alternative, if a generated index is unwanted, is to write the whole config file on each
signup and point `-f`/`-c` at it. That loses the one property the index has: the operator's
hand-written server blocks are never in a file the signup path writes.

## 2. Let's Encrypt limits at one certificate per member subdomain

The wildcard route is closed twice over. acme-client.conf(5) and `openbsd/etc/acme-client.conf`
already record that acme-client is HTTP-01 only, and the Let's Encrypt documentation page
"Challenge Types" (last updated 12 February 2026) lists under HTTP-01's cons: "This challenge
cannot be used to issue wildcard certificates." So each member gets a certificate for one
identifier, `username.kyriakon.net`, and every limit below is paid per member.

The published numbers are on "Rate Limits" (last updated 5 August 2026). Verbatim:

> Up to 50 certificates can be issued per registered domain (or IPv4 address, or IPv6 /64
> range) every 7 days. This is a global limit, and all new order requests, regardless of
> which account submits them, count towards this limit. The ability to issue new certificates
> for the same registered domain refills at a rate of 1 certificate every 202 minutes.

> Up to 5 certificates can be issued per exact same set of identifiers every 7 days.

> Up to 300 new orders can be created by a single account every 3 hours. The ability to
> create new orders refills at a rate of 1 order every 36 seconds.

> Up to 5 authorization failures per identifier can be incurred by one account every hour.

> Up to 1,152 consecutive authorization failures per identifier can be incurred by one
> account.

The page adds that "Limits are calculated, per request, using a token bucket", that a
rate-limited response carries a `Retry-After` header, and that "To exceed this limit, you must
request an override ... It takes a few weeks to process requests."

### What this means at 50 members

A new member costs one order and one certificate against the registered domain
`kyriakon.net`. Fifty signups in one burst consume the entire weekly budget, minus any other
new certificate issued in the same window (the platform's own apex, mail, defensive domain
and operator certificates are renewals once they exist, and renewals are exempt), so a launch
of exactly 50 fits in one afternoon and the 51st waits about 202 minutes. Steady state is
renewals, and renewals do not touch this limit (see "Renewal load" below), so 50 members are
comfortably inside the default.

### What this means at 200 members

Onboarding is throttled by refill, not by the bucket: 50 immediately, then 1 per 202 minutes
for the remaining 150, which is about 21 days. The limit is global per registered domain, so
running the signup path on a second account or a second host does not help. Two ways out,
both real: pace signups at about 7 per day, or request the registered-domain override (weeks
of lead time, so it has to be filed before launch, not during it). The 300 orders per account
per 3 hours limit does not bind at 200 members, and it refills at one order every 36 seconds.

One more thing that scales with the member count: the 5 authorization failures per identifier
per hour is per identifier, so a member whose DNS is broken burns only their own budget.
The 1,152 consecutive-failure pause is also per identifier and clears with one successful
validation, and the same page documents a self-service portal to unpause.

### Renewal load

acme-client(1) states the policy: "For certificates with a lifetime of more than 10 days,
this is done when less than a third of the lifetime remains. Otherwise, renewal is done when
half the lifetime has expired." For the current 90 day certificates that is a renewal per
member every 60 days, so 200 members produce about 3.3 renewals per day, or 200 per 60 days.
The per-registered-domain budget refills at about 7.1 per day, so even if renewals counted
against it the load would fit, and they do not count: the Rate Limits page says a
non-ARI renewal "would be exempt from the New Orders per Account and New Certificates per
Registered Domain rate limits", while still counting against the 5 per 7 days per exact
identifier set and against authorization failures. One renewal per member per 60 days never
reaches 5 per 7 days for a single identifier.

acme-client has no ARI. The `acme-client(1)` man page describes only the one-third rule, the
source directory `usr.sbin/acme-client/` contains no renewal-info handling, and there is no
`renewalInfo` or `renewal-info` mention anywhere in the man page or the parser. That matters
because Let's Encrypt's 24 February 2026 post "Shorter Certificate Lifetimes and Rate Limits"
says the default lifetime moves from 90 days to 64 and then 45 days, and that "renewals are
exempt" from rate limits through ARI. With 45 day certificates and acme-client's one-third
rule, renewals land at about day 30, so 200 members would need about 6.7 per day against a
refill of 7.13 per day. That fits, but with no margin, and ARI, the mechanism designed to make
short lifetimes a non-event, is the one thing acme-client 7.9 does not implement. Design
consequence: budget the per-registered-domain limit for signups only, and treat a future
lifetime cut as a reason to re-check rather than a problem already solved.

### 2025 to 2026 changes to the limits

The thresholds are unchanged, and the enforcement around them is not.

- 30 January 2025, "Scaling Our Rate Limits to Prepare for a Billion Active Certificates":
  the MariaDB counter-and-window system was replaced by Redis with the Generic Cell Rate
  Algorithm. The post describes the old weekly windows as the problem ("Subscribers could
  deplete their entire limit in just a few moments by repeating the same request, and find
  themselves locked out for the remainder of the week") and the new behaviour as continuous
  refill plus `Retry-After`. The published limits are now stated as burst plus refill rate,
  which is where "1 certificate every 202 minutes" comes from.
- Late 2024 and 4 June 2025, "How We Reduced the Impact of Zombie Clients": consecutive
  authorization failures are recorded per account and identifier and issuance is paused, with
  the self-service unpause documented on the Rate Limits page. This is the 1,152 figure
  above.
- 16 September 2025: ARI published as RFC 9773, and the Rate Limits page now grants ARI
  renewals exemption from all limits.
- 2 December 2025, "Decreasing Certificate Lifetimes to 45 Days", and 15 January 2026,
  "6-day and IP Address Certificates are Generally Available": lifetimes are shrinking on a
  published schedule. The 24 February 2026 post cited above confirms that rate limits are
  unaffected "because renewals do not count toward limits", which is only true for clients
  that support ARI.

## 3. Quotas

Quotas in OpenBSD are per filesystem, ffs only, and stored in a file at the root of that
filesystem. quotactl(2) states it directly: "Currently quotas are supported only for the
'ffs' filesystem", and the files are `quota.user` and `quota.group` at the filesystem root.

### Enabling them

fstab(5) is the config point:

> If the options "userquota" and/or "groupquota" are specified, the filesystem is
> automatically processed by the quotacheck(8) command, and user and/or group disk quotas are
> enabled with quotaon(8). By default, filesystem quotas are maintained in files named
> quota.user and quota.group which are located at the root of the associated filesystem.

The fs type field in fstab for such a filesystem is `rq` ("read/write with quotas").

quotacheck(8) builds the file: "If a file is not present, quotacheck will create it", and it
"is normally run at boot time from the /etc/rc file ... before enabling disk quotas with
quotaon(8)", and it "accesses the raw device in calculating the actual disk usage for each
user. Thus, the filesystems checked should be quiescent while quotacheck is running."

quotaon(8) turns them on: "quotaon announces to the system that disk quotas should be
enabled on one or more filesystems ... The filesystems specified must have entries in
/etc/fstab and be mounted."

The kernel side, `sys/ufs/ufs/ufs_quota.c`, `quotaon()` (line 481): it opens the quota file
`FREAD|FWRITE`, rejects anything that is not a regular file with `EACCES`, and then sets
`mp->mnt_flag |= MNT_QUOTA`. So the mount flag is set by the syscall, not only by mount time.
quotactl(2) confirms the requirement: "The quota file must exist; it is normally created with
the quotacheck(8) program ... Only the superuser may turn quotas on."

Reading it back is also syscall-level. quotactl(2) defines `Q_GETQUOTA` ("Get disk quota
limits and current usage for the user or group ... with identifier id"), `Q_SETQUOTA`
("restricted to the superuser"), and `Q_SYNC`. The struct is `struct dqblk` in
`sys/ufs/ufs/quota.h`:

```
struct dqblk {
	u_int32_t dqb_bhardlimit;	/* absolute limit on disk blks alloc */
	u_int32_t dqb_bsoftlimit;	/* preferred limit on disk blks */
	u_int32_t dqb_curblocks;	/* current block count */
	u_int32_t dqb_ihardlimit;	/* maximum # allocated inodes + 1 */
	u_int32_t dqb_isoftlimit;	/* preferred inode limit */
	u_int32_t dqb_curinodes;	/* current # allocated inodes */
	u_int32_t dqb_btime;		/* time limit for excessive disk use */
	u_int32_t dqb_itime;		/* time limit for excessive files */
};
```

Usage is only maintained while quotas are on: `getinoquota()` in the same file attaches the
quota record per inode and its comment reads "EINVAL means that quotas are not enabled", so
reading usage from a service is only meaningful with quotas enabled on that filesystem.

### Soft versus hard, and the units

edquota(8) is the quota editor, and the man page on this box states the semantics:

> Setting a quota to zero indicates that no quota should be imposed. Setting a hard limit to
> one indicates that no allocations should be permitted. Setting a soft limit to one with a
> hard limit of zero indicates that allocations should be permitted on only a temporary
> basis.

> Users are permitted to exceed their soft limits for a grace period that may be specified
> per filesystem. Once the grace period has expired, the soft limit is enforced as a hard
> limit. The default grace period for a filesystem is specified in
> /usr/include/ufs/ufs/quota.h. The -t flag can be used to change the grace period.

The default is a week, from `quota.h` in the kernel tree: `#define MAX_IQ_TIME (7*24*60*60)`
and `#define MAX_DQ_TIME (7*24*60*60)`. `edquota -t` sets it in days, hours, minutes or
seconds, and "Setting a grace period to one second indicates that no grace period should be
granted." For a platform that bills a 5 GB allowance, the shape that matches is one hard
limit set at the allowance and the soft limit either equal to it or slightly below with a
grace period, so a member gets a warning window instead of a hard cut mid-upload.

Units are kilobytes in edquota's text file. `usr.sbin/edquota/edquota.c` (line 405) writes:

```
	(void)fprintf(fp, "Quotas for %s %s:\n", qfextension[quotatype], name);
	for (qup = quplist; qup; qup = qup->next) {
		(void)fprintf(fp, "%s: %s %d, limits (soft = %d, hard = %d)\n",
		    qup->fsname, "KBytes in use:",
```

and parses the same numbers back with `btodb(value * 1024)` (line 461), so a 5 GB quota is
`5242880` in the file, not `5368709120`. Getting that wrong by a factor of 1024 is a one-line
mistake with a 5 GB consequence, so the signup path should set it from a constant named in
gigabytes and let one function do the conversion.

### Does /home need its own filesystem?

No, but it wants one. Quotas are per filesystem, so `userquota` on the root filesystem with
`/quota.user` is legal and works: `quotaon /` takes the same path as any other filesystem, and
quotactl(2) restricts quotas only to ffs and to the superuser. What changes is the blast
radius. A member whose quota is enforced against `/` can fill the root filesystem up to their
allowance before the quota stops them, and the root filesystem is where the platform itself
lives. A separate `/home` filesystem with `userquota` bounds member data without bounding the
system, and the existing box already has one: `/etc/fstab` lists
`bbb8a630c9f5d96e.l /home ffs rw,nodev,nosuid 1 2`, and `df -h` reports it as `/dev/sd1l`,
8.2 GB, 1.2 MB used. That line has no `userquota` option, so quotas are not enabled there
today. Adding it and rebooting is the clean path; `quotacheck -v /home` followed by
`quotaon -v /home` is the live path on a mounted filesystem.

### Setting a quota non-interactively

edquota is the only tool OpenBSD has for this. There is no `setquota`; `man setquota` reports
"No entry for setquota in the manual" and the binary is absent. edquota's interactive mode
opens `$EDITOR` (vi by default), which is unusable from a script, so the scriptable route is
the prototype flag, which the man page calls out as the intended one:

> If the -p flag is specified, edquota will duplicate the quotas of the prototypical user
> specified for each user specified. This is the normal mechanism used to initialize quotas
> for groups of users.

So the design keeps one locked prototype account and copies from it:

```
# create once, by hand: a real OS account used only as a quota template
doas edquota -p proto-member alice
```

`edquota -p` loads the prototype's limits for every filesystem listed in `/etc/fstab` with
user quotas, writes them for the named user, and exits without an editor. It needs the target
account to exist (or a numeric uid, which edquota(8) accepts: "If a numeric ID is given
instead of a name, that UID/GID will be used even if there is not a corresponding ID in the
/etc/passwd or /etc/group files"), and it needs root. `edquota -t` sets the grace period once
for the filesystem, not per user.

If the design would rather not shell out, `quotactl(2)` with `Q_SETQUOTA` writes the same
struct dqblk directly and is the documented interface the tools use. That is more code than
`edquota -p` and worth it only if the signup service is in a language that would otherwise
parse edquota's output.

### Reading per-member usage from a root-run service

`repquota(8)` is the tool, and it exists in base:
`/usr/sbin/repquota`. The man page says it "prints a summary of the disk usage and quotas for
the specified filesystem(s)", that for each user "the current number of files and amount of
space (in kilobytes) is printed, along with any quotas created with edquota(8)", and that
"Only members of the operator group or the superuser may use this command."

```
doas repquota -u /home          # per uid: blocks, files, soft and hard limits
doas quota -v -u alice          # one user's quotas; -u for another user needs root
```

quota(1) is the per-user view and its man page notes "Only the superuser may use the -g and
-u flags to view the limits of other groups and users", so a root-run service can both.

For a service that wants a number rather than a table, `quotactl(2)` `Q_GETQUOTA` returns
`struct dqblk` for one uid, which has `dqb_curblocks` and `dqb_curinodes` alongside the
limits. `repquota -u` output is column-aligned text meant for a terminal, so parsing it is
more fragile than the syscall, and the syscall is what the tools themselves call.

Three honest caveats for the design. Usage is only counted while quotas are enabled on that
fs, so a service that reads usage must handle a filesystem with quotas off rather
than reporting zero. `repquota /home` printed nothing at all on this box, with exit 0, and so
did `repquota -v /home`, because `/home` has no `userquota` option and no `/home/quota.user`
file; there is no error to notice. And the quota numbers are per uid per filesystem, so if a
member ever gets a second account the 5 GB is two quotas of 5 GB or one group quota
(`edquota -g`), not one allowance.

## 4. The chrooted internal-sftp member

### The shape sshd requires

sshd_config(5), ChrootDirectory:

> Specifies the pathname of a directory to chroot(2) to after authentication. At session
> startup sshd(8) checks that all components of the pathname are root-owned directories which
> are not writable by group or others. After the chroot, sshd(8) changes the working directory
> to the user's home directory. Arguments to ChrootDirectory accept the tokens described in
> the TOKENS section.

The check is in `safely_chroot()` in `usr.bin/ssh/session.c` (line 1033), and it is stricter
than "root-owned": every path component must be uid 0 and have no group or other write bit.

```
		if (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
```

So mode 0755 passes, 0775 and 0770 fail on the group and other write bits, and a directory
owned by the member fails on the uid even at mode 0700. The check is fatal, so a mis-owned
home shows up as a refused connection rather than a silent one. On this box
`/home` is `drwxr-xr-x root wheel`, which passes. `useradd -m` creates `/home/<user>` owned by
the member, so the signup script has to chown it to root and chmod 0755 after creating it.

sshd_config(5) also notes that this check is unconditional, unlike the general StrictModes
handling: "Note that this does not apply to ChrootDirectory, whose permissions and ownership
are checked unconditionally."

ForceCommand:

> Forces the execution of the command specified by ForceCommand, ignoring any command
> supplied by the client and ~/.ssh/rc if present. The command is invoked by using the user's
> login shell with the -c option. This applies to shell, command, or subsystem execution. It
> is most useful inside a Match block. The command originally supplied by the client is
> available in the SSH_ORIGINAL_COMMAND environment variable. Specifying a command of
> internal-sftp will force the use of an in-process SFTP server that requires no support
> files when used with ChrootDirectory.

Subsystem:

> Alternately the name internal-sftp implements an in-process SFTP server. This may simplify
> configurations using ChrootDirectory to force a different filesystem root on clients. It
> accepts the same command line arguments as sftp-server.

Because internal-sftp accepts sftp-server's arguments, the upload umask is set with `-u`.
sftp-server(8): "`-u umask` sets an explicit umask(2) to be applied to newly-created files and
directories, instead of the user's default mask", and `-d start_directory` sets the starting
directory.

The mechanism that makes `/sbin/nologin` work is in `session.c` `do_child()` (line 1193). It
calls `do_setusercontext(pw)`, which performs the chroot, and only then, after the rc files,
does it either hand off to the in-process sftp server or exec the login shell:

```
	if (s->is_subsystem == SUBSYSTEM_INT_SFTP_ERROR) {
		error("Connection from %s: refusing non-sftp session",
		    remote_id);
		printf("This service allows sftp connections only.\n");
		fflush(NULL);
		exit(1);
	} else if (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		...
		exit(sftp_server_main(sftp_argc, sftp_argv, s->pw));
	}
```

```
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (char *) shell0;
	argv[1] = "-c";
	argv[2] = (char *) command;
	argv[3] = NULL;
	execve(shell, argv, env);
```

`internal-sftp` is intercepted before that exec, which is why it works with a shell that
cannot run anything. Every other forced command goes through the login shell with `-c`, which
is why `/sbin/nologin` breaks them (tested: `/sbin/nologin -c 'echo from-nologin'` prints
"This account is currently not available." and exits 1, ignoring the argument).

One more requirement that is easy to miss: the `Subsystem sftp` line must exist. `do_exec()`
is only reached for a subsystem request when the client's subsystem name is found in the
configured list (`session_subsystem_req()` in `session.c` loops over
`options.num_subsystems` and logs "subsystem request for %s ... failed, subsystem not found"
otherwise). The base config already has `Subsystem sftp /usr/libexec/sftp-server`, and with
ForceCommand set, that path is never used: the in-process server runs instead.

### The fragment

For an sftp-only member, one port and one Match block. The same file with `Match Group wheel`
(the group the test account belongs to) was parsed with `sshd -T` on the host, and the
effective values came back as written.

```
# /etc/ssh/sshd_config
Subsystem sftp /usr/libexec/sftp-server
PasswordAuthentication no
KbdInteractiveAuthentication no

Match Group members
	ChrootDirectory /home/%u
	ForceCommand internal-sftp -u 0022
	PermitTTY no
	DisableForwarding yes
	AuthenticationMethods publickey
	AllowTcpForwarding no
	X11Forwarding no
	PermitTunnel no
```

`Match Group members` rather than `Match User` per member: the group is set once at signup
(`useradd -m -d /home/$user -s /sbin/nologin -g =uid -G members "$user"`; useradd(8) says
"`-G secondary-group[,group,...]` sets the secondary groups to which the user will be added
in the /etc/group file"), and sshd_config(5) accepts comma-separated and negated patterns in
Match criteria. `DisableForwarding yes` covers TCP, agent, socket and X11 forwarding in one
option; the individual options are listed as well, matching the way
`openbsd/etc/sshd_config` spells out the settings it cares about.

### www/ and gemini/ inside one chroot

Both are ordinary subdirectories of the chroot root, owned by the member, and the daemons
reach them because the chroot root of each daemon contains them. That is the whole trick, and
it has one consequence worth stating plainly: `chroot` is a global option in both daemons, so
member content and platform content have to live under the same root.

httpd.conf(5) documents it under "Global configuration": "`chroot directory` sets the
chroot(2) directory. If not specified, it defaults to /var/www, the home directory of the
www user." The default comes from `usr.sbin/httpd/httpd.c` (line 209):
`if (env->sc_chroot == NULL) env->sc_chroot = ps->ps_pw->pw_dir;`. The log directory is
derived from the same value (line 214): `asprintf(&env->sc_logdir, "%s%s", env->sc_chroot,
HTTPD_LOGROOT)`, so moving the chroot moves the log directory with it.

gmid's is also global: gmid.conf(5) lists `chroot path` under "Global Options" and states
"All the paths in the configuration file are relative to the chroot directory, except for the
cert, key and ocsp paths", and every `server` block's `root` is relative to it.

The repo's own §6.9 layout puts member web roots at `/home/<u>/www` and `/home/<u>/gemini`,
and `scripts/backup.sh` records that ("Maildir (/home/<u>/Maildir), git repos
(/home/<u>/repos), and web roots (/home/<u>/www, /home/<u>/gemini) all live under each user's
home ... one tree covers every user-data path"). Under that layout the fragments are:

```
# /etc/httpd.conf (hand-written header, one added line)
chroot "/home"
include "/etc/httpd.d/index.conf"
```

httpd needs no `logdir` line: with none set, the default is the chroot plus `/logs`
(`HTTPD_LOGROOT`), so `/home/logs` has to exist, owned the way `/var/www/logs` is today
(`drwxr-xr-x root daemon`).

```
# /etc/gmid.conf
user "_gmid"
chroot "/home"
include "/etc/gmid.d/index.conf"
```

with the per-member `root` values shown in §1 (`"/alice/www"`, `"/alice/gemini"`).

Moving the daemons' chroot to `/home` moves the platform's own served trees with it: the
landing site checkout moves from `/var/www/kyriakon.net` to `/home/kyriakon.net`, the
operator's site likewise, and the ACME challenge directory moves from `/var/www/acme` to
`/home/acme`. acme-client's side of that is one config line per domain block, since
acme-client.conf(5) says "`challengedir path` specifies the directory in which the challenge
file will be stored. If it is not specified, a default of /var/www/acme will be used."

The alternative keeps the daemons exactly as they are and puts member content at
`/var/www/<u>.kyriakon.net/{www,gemini}`, serving it with `root "/<u>.kyriakon.net/www"`. It
costs less config churn and costs more elsewhere: the content leaves `scripts/backup.sh`'s
`restic backup /home` scope, and it lands on the `/var` filesystem, so a single 5 GB allowance
per member becomes two quotas on two filesystems unless the member's mail follows it there.

### What the chroot costs the git path

`ChrootDirectory` is per user, not per key and not per subsystem, and `do_setusercontext()` is
called from `do_child()` for every session before anything else happens. A git push is a
session like any other, so a chrooted member's `git-shell` would have to run inside the
chroot, where `/usr/local/bin/git-shell` and its libraries do not exist. git on this box is a
4.8 MB dynamically linked binary from the port (`git-2.53.0`, `/usr/local/bin/git`), with
`git-shell` as a hard link to it, so the options are to populate a copy of the toolchain
inside every member chroot, to accept that the account is sftp-only, or to move the git
session out of the chroot. OpenBSD has no nullfs (`/sbin/mount_*` on the box lists
`cd9660 ext2fs ffs mfs msdos nfs ntfs tmpfs udf vnd`, and `man mount_null` reports "No entry
for mount_null in the manual"), so a chroot cannot borrow `/usr/local` by mount or by symlink.

The clean way out is that sshd's Match rules can distinguish the two traffic types by the port
they arrive on, because `LocalPort` is a documented criterion. sshd_config(5): "The available
criteria are User, Group, Host, LocalAddress, LocalPort, Version, RDomain, and Address". The
same paragraph adds "If a keyword appears in multiple Match blocks that are satisfied, only
the first instance of the keyword is applied", which is why the shared hardening goes in the
first block and the chroot and the forced command go in the second.

```
# /etc/ssh/sshd_config
Port 22                    # git over SSH, no chroot
Port 2222                  # sftp uploads, chrooted
Subsystem sftp /usr/libexec/sftp-server

Match Group members
	AuthenticationMethods publickey
	DisableForwarding yes
	PermitTTY no

Match Group members LocalPort 2222
	ChrootDirectory /home/%u
	ForceCommand internal-sftp -u 0022
```

With that split the member's account has the login shell `git-shell`, so port 22 runs
`git-shell -c '<client command>'` for a push or fetch, and port 2222 runs the in-process sftp
server and nothing else. The split was checked with `sshd -T` against the real binary: with
`-C user=oliver,...,lport=22` the effective `chrootdirectory` and `forcecommand` are `none`,
and with `lport=2222` they are `/home/%u` and `internal-sftp -u 0022`. Each port refuses the
other's traffic: on 2222 `ForceCommand` overrides whatever the client asked for, and on 22 the
sftp subsystem command `/usr/libexec/sftp-server` is exec'd through `git-shell`, which rejects
it as an unrecognized command (tested below). The cost is that the upload path is not the
default port, so the signup instructions and any file manager have to say `sftp -P 2222`, and
the port has to be allowed wherever the box is firewalled.

For a member who is genuinely sftp-only, the single-port fragment earlier in this section is
enough and `/sbin/nologin` stays the shell.

## 5. git-shell

`git-shell(1)` from git 2.53.0, the version installed here:

> This is a login shell for SSH accounts to provide restricted Git access. It permits
> execution only of server-side Git commands implementing the pull/push functionality, plus
> custom commands present in a subdirectory named git-shell-commands in the user's home
> directory.

> accepts the following commands after the -c option: git receive-pack <argument>, git
> upload-pack <argument>, git upload-archive <argument> ... cvs server

> By default, the commands above can be executed only with the -c option; the shell is not
> interactive.

Two ways to wire it, and only one of them survives `/sbin/nologin`. With the login shell set
to `git-shell`, sshd's own path does the work: the client sends `git-upload-pack '/home/alice/repos/x.git'`,
sshd execs the login shell with `-c`, and git-shell runs it. No `authorized_keys` entry is
needed at all, and that is the shape that works with the port split in §4.

The `authorized_keys` form exists for the case where the login shell is something else. Its
options are documented in sshd(8) under "AUTHORIZED_KEYS FILE FORMAT":

> command="command"
>     Specifies that the command is executed whenever this key is used for authentication. The
>     command supplied by the user (if any) is ignored. ... A quote may be included in the
>     command by quoting it with a backslash. ... The command originally supplied by the
>     client is available in the SSH_ORIGINAL_COMMAND environment variable. Note that this
>     option applies to shell, command or subsystem execution. Also note that this command may
>     be superseded by an sshd_config(5) ForceCommand directive.

which gives:

```
# ~alice/.ssh/authorized_keys
restrict,command="git-shell -c \"$SSH_ORIGINAL_COMMAND\"" ssh-ed25519 AAAA... alice@laptop
```

`restrict` is the sshd(8) option that "Enable[s] all restrictions, i.e. disable port, agent
and X11 forwarding, as well as disabling PTY allocation and execution of ~/.ssh/rc".

### Quoting pitfalls, all tested on the box with git 2.53.0

The path argument is git-quoted, and a hand-written plain path fails. The git client does the
quoting, so a normal push never sees this: `transport/connect.c` writes the remote command and
then adds the path with `sq_quote_buf(&cmd, path)` (line 1489). Hand-written entries do:

```
$ git-shell -c 'git-upload-pack /tmp/wf-test/gitsrv/r.git'
fatal: bad argument
$ git-shell -c "git-upload-pack '/tmp/wf-test/gitsrv/r.git'"
<runs, emits the upload-pack capability list>
```

git-shell splits the `-c` string and `sq_dequote(3)`s the argument, so the quote characters
have to survive sshd, the shell, and git-shell itself. In sshd_config they must be written
`\"$SSH_ORIGINAL_COMMAND\"`; inside a script, single quotes around the path are simplest.

Wrapping git-shell in git-shell fails. On an account whose login shell is already `git-shell`,
the documented `authorized_keys` command runs
`git-shell -c 'git-shell -c "git-upload-pack ..."'` and git-shell rejects the outer command:

```
$ git-shell -c 'git-shell -c "git-upload-pack /tmp/wf-test/gitsrv/r.git"'
fatal: unrecognized command 'git-shell -c "git-upload-pack /tmp/wf-test/gitsrv/r.git"'
```

Use one or the other, never both.

The `command=` entry cannot run at all when the login shell is `/sbin/nologin`. sshd executes
forced commands through the login shell, and nologin ignores `-c` entirely:

```
$ /sbin/nologin -c 'echo from-nologin'
This account is currently not available.
$ echo $?
1
```

So `restrict,command="git-shell -c \"$SSH_ORIGINAL_COMMAND\""` on a nologin account produces a
session that authenticates and then dies with nologin's message. `ForceCommand internal-sftp`
escapes this only because internal-sftp never reaches the shell.

### One key for sftp and git, or two?

Neither key design solves it on its own, because the constraint is not the key. Two facts
decide it. `ChrootDirectory` is a per-user directive, so any key belonging to that user gets
the same chroot, and inside the chroot git cannot run (§4). And the server's `ForceCommand`
beats the key's `command=`: `do_exec()` in `session.c` tests `options.adm_forced_command`
before `auth_opts->force_command`, and sshd(8) says so in the same breath ("this command may
be superseded by an sshd_config(5) ForceCommand directive"). So a member whose Match block
sets `ForceCommand internal-sftp` is sftp-only for every key they own, and adding a second
key changes nothing.

What actually works, per member:

- sftp only: `ChrootDirectory` plus `ForceCommand internal-sftp`, shell `/sbin/nologin`, one
  key. Git is not available on that account at all.
- sftp and git on one account: the port split from §4. Shell `git-shell`, one key, git on 22,
  sftp on 2222. One key serves both because each connection type is routed by the port, not
  by the key.
- sftp and git with no chroot: a dispatcher as the login shell, since `ForceCommand` runs
  through the login shell and cannot be used with nologin. The dispatcher reads
  `SSH_ORIGINAL_COMMAND` and execs `git-shell -c` for `git-*` commands and
  `/usr/libexec/sftp-server` otherwise. This is the only variant that needs custom code, and
  it trades the chroot for it.

A note on what git-shell does and does not restrict. It restricts the command, not the
repository: `git-shell -c "git-upload-pack '/etc/passwd'"` runs and fails inside git with
`fatal: invalid gitfile format: /etc/passwd`, not at the git-shell layer. Per-member isolation
therefore comes from the uid and the file modes on `/home/<u>/repos`, not from git-shell.
Since the repo holds private work, `repos/` should be 0700 and owned by the member, and the
daemons do not need to read it.

Interactive sessions: an `ssh` with no command reaches git-shell with no arguments, and
`cmd_main()` in git's `shell.c` then requires a `git-shell-commands` directory, dying with
"Interactive git shell is not enabled." when it is absent. If the directory does exist, the
shell runs interactively and executes commands from it, so the directory is the tool that
grants extra commands, not a restriction. git-shell(1) documents the way to keep the
directory and still refuse an interactive session: "If a no-interactive-login command exists,
then it is run and the interactive shell is aborted", with the example script that prints a
greeting and exits 128.

## 6. What this means for the map

Four decisions the research forces, none of which the platform can dodge:

1. All served content lives under one filesystem, because each daemon has exactly one global
   chroot. Either the daemons move their chroot to `/home` (matches §6.9 and `backup.sh`; the
   landing site, the operator's site and the ACME challenge directory move with it), or member
   content moves to `/var/www` (no daemon change; member data leaves the backup scope and the
   5 GB allowance splits across two filesystems).
2. Per-member vhosts and certificates are generated files listed by a generated index, since
   no daemon in the stack can include a directory. The index is the only file the signup path
   rewrites in the shared config tree, which is what the ticket asked for and is as close as
   the three daemons get.
3. Signups are paced at roughly 7 per day after the first 50, or the registered domain gets a
   rate limit override weeks before launch. Renewals are not the problem; onboarding is.
4. The member either gets a chrooted upload path and no git on the same account, or keeps one
   account with both and gives up the chroot, or takes the port split. The port split is the
   only one that satisfies the ticket's target as written.

## 7. Tested versus documentary

Tested on the live OpenBSD 7.9 host `mail.kyriakon.net` (7.9 GENERIC.MP#11 amd64, gmid
2.1.1p0, git 2.53.0), as an unprivileged user, with files written only under `/tmp`:

- `gmid -n -c` with `include` of a single file: parses. Command:
  `printf 'prefork 3\n' > /tmp/wf-test/conf.d/opt.conf; printf 'include ...\n' > ...; gmid -n -c /tmp/wf-test/gmid-inc2.conf`.
- `gmid -n -c` with a glob include: fails, path taken literally, exit 1.
- `gmid -n -c` with a directory include: prints `config OK`, exit 0, and never reads the
  invalid server block inside the directory.
- `/sbin/nologin -c 'echo from-nologin'`: prints "This account is currently not available.",
  exit 1.
- `git-shell -c` with a bare path (fatal: bad argument), with a git-quoted path (runs
  upload-pack), with a nested `git-shell -c` (fatal: unrecognized command), with
  `git-upload-pack '/etc/passwd'` (runs; git-shell does not check paths).
- `quota -v` returns "Disk quotas for user oliver (uid 1000): none", exit 0.
- `repquota /home` and `repquota -v /home` print nothing and exit 0, because quotas are not
  enabled on `/home`.
- `quotaon -v /home` resolves `/home/quota.user` and `/home/quota.group` (the default paths)
  and fails with "Operation not permitted" as non-root.
- `ls -ld /home /var/www`: `drwxr-xr-x root wheel /home`, `drwxr-xr-x root daemon /var/www`.
  `stat -f '%Sp %Su %Sg %N'` reports the same modes by owner.
- `df -h /home /var`: `/home` is `/dev/sd1l`, 8.2 GB; `/var` is `/dev/sd1e`, 3.1 GB.
- `/etc/fstab`, read on the box: `/home` is `rw,nodev,nosuid` with no `userquota` option, and
  `/home/quota.user` does not exist.
- Presence and absence of tools: `/usr/sbin/repquota`, `/usr/sbin/edquota`, `/sbin/quotacheck`
  exist; `setquota` does not, and `man setquota` reports no entry.
- `/sbin/mount_*` listing has no `mount_null`, and `man mount_null` reports no entry.
- `/usr/libexec/sftp-server -h` on the box prints `[-d start_directory] ... [-u umask]`, so the
  `-u 0022` and `-d` arguments used in the fragments exist in the deployed binary.
- `sshd -T -f <file> -h /tmp/wf-test/hostkey -C user=oliver,host=h,addr=127.0.0.1` against
  the single-port fragment, with `Match Group wheel` in place of `Match Group members`
  (oliver is in wheel), returns `chrootdirectory /home/%u`,
  `forcecommand internal-sftp -u 0022`, `permittty no`, `disableforwarding yes`,
  `authenticationmethods publickey` and `subsystem sftp /usr/libexec/sftp-server`.
- The same tool against the two-port fragment returns `chrootdirectory none` with
  `-C ...,lport=22` and `chrootdirectory /home/%u` with `forcecommand internal-sftp -u 0022`
  with `-C ...,lport=2222`, which is the whole point of routing sftp and git onto different
  ports.

Documentary, that is, read from the man page or the source rather than executed:

- The include behaviour of `httpd.conf` and `acme-client.conf`. Both parsers are the same
  `fopen`-based `include STRING` rule with no `glob()`, but `httpd -n` exits with "httpd: need
  root privileges" and `acme-client -n` with "acme-client: must be run as root" for this
  account, so neither was run.
- What sshd does at session start with the config that `-T` showed as valid: that the chroot
  is entered for every session type, that a chrooted session cannot exec
  `/usr/local/bin/git-shell`, and that a chrooted `internal-sftp` session starts in `/` when
  the passwd home does not exist inside the chroot. All three follow from `do_child()`,
  `do_setusercontext()` and the `chdir(pw->pw_dir)` failure handling in `session.c`, and none
  was exercised, because creating a member account on the live mail host is out of scope.
- Every quota enforcement claim, including soft-limit grace expiry. Enabling quotas needs root
  and an `/etc/fstab` change on a live mail host.
- The 50 certificates per registered domain figure and the other published numbers. They are
  Let's Encrypt policy, not something this box can test.
- The claim that no `nullfs` exists is tested only in the sense that the binary and man page
  are absent; the source tree was not searched for a mount type registered differently.

Not reachable at all: no second OpenBSD host, and no root on this one, so nothing that
requires `doas`, `pkg_add`, a service restart, or an fstab edit was verified. The host key
generated for `sshd -T` lives in `/tmp` and never went near `/etc/ssh`.

## 8. Primary sources

- httpd.conf(5), OpenBSD 7.9, on the box: `ssh kyriakon 'man httpd.conf'`. `include` at the
  end of the description, `chroot` under "Global configuration", `logdir` with its default
  inside the chroot. https://man.openbsd.org/httpd.conf.5
- acme-client.conf(5), OpenBSD 7.9: `include`, `challengedir` (default `/var/www/acme`),
  `alternative names`, `profile`. https://man.openbsd.org/acme-client.conf.5
- acme-client(1), OpenBSD 7.9, on the box: renewal "when less than a third of the lifetime
  remains", `-n` no-op check, exit codes. https://man.openbsd.org/acme-client.1
- sshd_config(5), OpenBSD 7.9, on the box: `Match` criteria including `LocalPort` and the
  first-instance rule, `ChrootDirectory`, `ForceCommand`, `Subsystem`, `StrictModes` note.
  https://man.openbsd.org/sshd_config.5
- sshd(8), OpenBSD 7.9, on the box: "AUTHORIZED_KEYS FILE FORMAT", `command="command"`,
  `restrict`, `SSH_ORIGINAL_COMMAND`. https://man.openbsd.org/sshd.8
- `usr.bin/ssh/session.c` (OpenBSD source, master): `do_child()` at line 1193,
  `do_setusercontext()` at line 1084, `safely_chroot()` at line 1033, the internal-sftp
  hand-off at line 1316, the login-shell exec at line 1360, `do_exec()` at line 599.
  https://raw.githubusercontent.com/openbsd/src/master/usr.bin/ssh/session.c
- `usr.sbin/httpd/parse.y` (`include` rule, `pushfile`), `usr.sbin/httpd/httpd.c` (chroot and
  logdir defaults). https://raw.githubusercontent.com/openbsd/src/master/usr.sbin/httpd/httpd.c
- `usr.sbin/acme-client/parse.y` (`include` rule, `pushfile`).
  https://raw.githubusercontent.com/openbsd/src/master/usr.sbin/acme-client/parse.y
- gmid 2.1.1p0, `parse.y` (`include` rule at line 165, `pushfile` at line 1092), plus
  gmid.conf(5) and gmid(8) as installed on the box.
  https://github.com/omar-polo/gmid
- edquota(8), quotacheck(8), quotaon(8), quota(1), repquota(8), quotactl(2), fstab(5),
  OpenBSD 7.9, all read on the box. https://man.openbsd.org/quotactl.2
- `sys/ufs/ufs/ufs_quota.c` (`quotaon()` at line 481, `getquota()` at line 620, `getinoquota()`
  at line 151) and `sys/ufs/ufs/quota.h` (`struct dqblk`, `MAX_DQ_TIME`).
  https://raw.githubusercontent.com/openbsd/src/master/sys/ufs/ufs/ufs_quota.c
- `usr.sbin/quotaon/quotaon.c` (`hasquota()` with its `force` argument, `quotaonoff()`) and
  `usr.sbin/edquota/edquota.c` (KBytes output at line 405, `btodb(... * 1024)` at line 461).
  https://raw.githubusercontent.com/openbsd/src/master/usr.sbin/quotaon/quotaon.c
- git-shell(1), git 2.53.0, on the box (`man git-shell`), plus `shell.c` in git for
  `do_generic_cmd`, its `sq_dequote` requirement, and the `git-shell-commands` check in
  `cmd_main()`. https://raw.githubusercontent.com/git/git/master/shell.c
- git's `transport/connect.c` for the client side of the same quoting:
  `sq_quote_buf(&cmd, path)` at line 1489.
  https://raw.githubusercontent.com/git/git/master/transport/connect.c
- Let's Encrypt, "Rate Limits", last updated 5 August 2026.
  https://letsencrypt.org/docs/rate-limits/
- Let's Encrypt, "Challenge Types", last updated 12 February 2026, for the HTTP-01 wildcard
  exclusion. https://letsencrypt.org/docs/challenge-types/
- Let's Encrypt, "Scaling Our Rate Limits to Prepare for a Billion Active Certificates",
  30 January 2025. https://letsencrypt.org/2025/01/30/scaling-rate-limits
- Let's Encrypt, "How We Reduced the Impact of Zombie Clients", 4 June 2025.
  https://letsencrypt.org/2025/06/04/how-we-reduced-the-impact-of-zombie-clients
- Let's Encrypt, "Shorter Certificate Lifetimes and Rate Limits", 24 February 2026.
  https://letsencrypt.org/2026/02/24/rate-limits-45-day-certs
- Let's Encrypt, "Decreasing Certificate Lifetimes to 45 Days", 2 December 2025, and "6-day
  and IP Address Certificates are Generally Available", 15 January 2026.
  https://letsencrypt.org/2025/12/02/from-90-to-45
- Repo files read for the current shape: `openbsd/etc/httpd.conf`, `openbsd/etc/gmid.conf`,
  `openbsd/etc/acme-client.conf`, `openbsd/etc/sshd_config`, `scripts/add-user.sh`,
  `scripts/backup.sh`, `scripts/renew-acme.sh`.
