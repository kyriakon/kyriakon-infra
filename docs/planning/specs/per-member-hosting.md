# Per-member hosting: the build

> Spec synthesised from [Spec the per-member hosting build](https://github.com/kyriakon/kyriakon-infra/issues/260) and the decisions it points at: [#154](https://github.com/kyriakon/kyriakon-infra/issues/154) (the tree split, the generated configuration and the port split), [#244](https://github.com/kyriakon/kyriakon-infra/issues/244) (the capsule's long-lived certificate), [#150](https://github.com/kyriakon/kyriakon-infra/issues/150) (the OpenBSD mechanics it rests on), [#160](https://github.com/kyriakon/kyriakon-infra/issues/160) (the host changes, landed), [#166](https://github.com/kyriakon/kyriakon-infra/issues/166) (what issuance does past the rate limit), with [#232](https://github.com/kyriakon/kyriakon-infra/issues/232), [#243](https://github.com/kyriakon/kyriakon-infra/issues/243), [#241](https://github.com/kyriakon/kyriakon-infra/issues/241) and [#245](https://github.com/kyriakon/kyriakon-infra/issues/245) for the paths this spec does not restate.

## Problem statement

The daemons carry the seam and nothing writes into it. `openbsd/etc/httpd.conf` and
`openbsd/etc/gmid.conf` each chroot to `/home/www` and each include one generated index;
`openbsd/etc/sshd_config` carries `Port 22`, `Port 2222` and the `Match Group members`
blocks; `scripts/deploy-mail.sh` creates `/home/www`, its `logs/` and `acme/`
subdirectories, `/etc/httpd.d/` and `/etc/gmid.d/` with empty indexes, and the `members`
group; `scripts/add-user.sh` creates the account, its Maildir and its quota record. What
does not exist is the builder. Nothing creates a member's public tree, writes their vhost
or capsule file, writes an `acme-client` block for their name, generates or installs the
capsule certificate, or writes their upload key. `scripts/cron-apply.sh --web` regenerates
the two indexes and reloads the daemons; its header says plainly that the signup path
writes the member files.

Two consequences follow. A member cannot be provisioned by any path in the repository, so
the hosting the release sells does not exist yet. And the capsule certificate
[#244](https://github.com/kyriakon/kyriakon-infra/issues/244) decided has no home, no path
and no generation step, so the copy the hosting page is to carry about it has nothing
underneath it.

The host half is already in place and this spec treats it as given: the tree migration
(`/home/www` with the daemons chrooted there), the amended `sshd_config`, the `members`
group, the `userquota` mount option with `/home/quota.user` live and quotas on, and the
`pf` rule for 2222. The build verifies each rather than repeating it.

## Solution

A member is one OS account in `members` whose password entry keeps `/sbin/nologin`, with
the session shell coming from a login class. Private data stays at
`/home/<name>/{Maildir,repos}`; everything published lives at
`/home/www/<name>.kyriakon.net/{www,gemini}`, which is where `httpd` and `gmid` chroot to
serve it. Sessions split by port: 22 is the chrooted `internal-sftp` upload, 2222 runs
`git-shell`, and one key serves both. Per-member configuration is generated and never
hand-edited: one file per member per daemon, listed by a generated index that the tracked
config includes, written member file first and index second, syntax-checked, then applied
with `rcctl reload`. The web side gets an ACME certificate in the ordinary queue; the
capsule side serves one long-lived self-signed pair, generated once. The quota record is
written per account. Removal reverses each of those steps in an order that never leaves a
daemon referencing a file that is gone.

### The account, the group and the tree

`scripts/provision-member.sh <username>` is the builder, and it is idempotent: running it
on a provisioned member rewrites the same files and changes nothing else.

- The public hostname is `<name>.kyriakon.net` and the public root is
  `/home/www/<name>.kyriakon.net`. `install -d -m 0755 -o root -g wheel` creates it,
  because `sshd`'s `safely_chroot` requires every component of the chroot path to be owned
  by uid 0 and writable by neither group nor other.
- Its two subdirectories belong to the member: `install -d -m 0755 -o <name> -g members`
  for `www/` and for `gemini/`, empty and ready for upload.
- `/home/<name>/repos` is created mode 0700 owned by the member, beside the Maildir
  `scripts/add-user.sh` already makes. Both stay outside every chroot.
- The account, its Maildir and its quota record come from `scripts/add-user.sh`, which the
  signup path calls first; this script asserts the account exists and is in `members`
  rather than creating it.
- Every path is asserted after creation, and the script fails loudly rather than
  continuing, because a half-built tree that reports success is worse than a refusal.

### The two sessions and the one key

- One key serves both paths. The member's public key is written to
  `/home/<name>/.ssh/authorized_keys`, owned by the member, mode 0600, directory 0700. No
  `authorized_keys` line is written for a comment-key or a forced command: the port, not
  the key, decides which service the session reaches.
- The session shell comes from the login class. `/etc/login.conf.d/member` carries
  `member:shell=/usr/local/bin/git-shell:tc=default:`, and `usermod -L member <name>`
  assigns it, so `git-shell` runs on 2222 while `passwd` keeps `/sbin/nologin`. The
  drop-in directory is the convention already in use on the box (`dovecot`, `rspamd`), and
  `cap_mkdb /etc/login.conf` is required after an edit to either file while
  `/etc/login.conf.db` exists, which it does on this box since the onboard
  class was built. The provisioning script runs it only when the database is
  older than the drop-in, and says which of the two states it found.
- `sshd -T` is the check, run against the fragment as `#154` requires, and the stale
  comment in `openbsd/etc/sshd_config` that says an account "uploads on 22 but cannot
  push" is corrected in the same change, which `#154` asked for.
- A member may hold more than one upload key; add and remove are one line each in
  `authorized_keys`, and the account page is where the member asks for them
  ([#245](https://github.com/kyriakon/kyriakon-infra/issues/245) owns the TUI half).

### The generated configuration

Three lanes, one shape. Each tracked config gains, or already has, a single include of a
generated index, and each index lists one generated file per member.

| Daemon | Tracked config | Generated index | Per-member file |
| --- | --- | --- | --- |
| httpd | `openbsd/etc/httpd.conf`, `include "/etc/httpd.d/index.conf"` | `/etc/httpd.d/index.conf` | `/etc/httpd.d/<name>.conf` |
| gmid | `openbsd/etc/gmid.conf`, `include "/etc/gmid.d/index.conf"` | `/etc/gmid.d/index.conf` | `/etc/gmid.d/<name>.kyriakon.net.conf` |
| acme-client | `openbsd/etc/acme-client.conf`, gains `include "/etc/acme-client.d/index.conf"` | `/etc/acme-client.d/index.conf` | `/etc/acme-client.d/<name>.kyriakon.net.conf` |

The acme-client line is the one addition to a tracked config: `acme-client.conf(5)` states
that "additional configuration files can be included with the `include` keyword", and the
directory does not exist yet, so `scripts/deploy-mail.sh` creates it with an empty index
beside the other two. Including rather than editing the top-level file also keeps member
names out of the daily renewal lane, which reads the top level only and deliberately does
not follow an include.

The httpd member file holds two server blocks. The port 80 block comes first, with
`root "/acme"`, `request strip 2` and a 301 to HTTPS, because the ACME challenge must be
answered before any other location. The port 443 block is written only when the member's
certificate file exists, and carries
`certificate "/etc/ssl/<name>.kyriakon.net.fullchain.pem"`,
`key "/etc/ssl/private/<name>.kyriakon.net.key"`,
`location "/.git/*" { block }` and `location "/*" { root "/<name>.kyriakon.net/www" }`.

The gmid member file is one `server "<name>.kyriakon.net"` block on port 1965 with
`location "/.git/*" { block }`, `root "/<name>.kyriakon.net/gemini"`, and the capsule
certificate pair of the next section rather than the ACME pair.

The acme-client member file is one `domain <name>.kyriakon.net { ... }` block carrying the
same lines every hand-written block carries, including
`challengedir "/home/www/acme"`, `domain key "/etc/ssl/private/<name>.kyriakon.net.key"`,
`domain full chain certificate "/etc/ssl/<name>.kyriakon.net.fullchain.pem"` and
`sign with letsencrypt`, because the header of `openbsd/etc/acme-client.conf` states that
a generated block has to repeat the line for the same reason.

Writing is ordered and atomic. The member file is written first, then the index is
regenerated from the directory's `*.conf` files with `index.conf` skipped, compared and
moved into place, then each touched daemon is checked with `httpd -n -f /etc/httpd.conf`
and `gmid -n -c /etc/gmid.conf`, and only then reloaded with `rcctl reload`. A failed check
leaves the previous configuration in place. `scripts/cron-apply.sh` grows the third lane so
that `regen_index` covers `/etc/acme-client.d` as it covers the other two.

Nothing else in the stack includes a directory, and a missing include fails the whole
config, so an index must exist even when it is empty; the deploy creates all three empty
rather than leaving them absent.

### Certificates: the ACME lane and the capsule lane

The web side keeps ACME. Each member's name is issued its own certificate by HTTP-01,
which is why the port 80 block exists and why the challenge location comes first. Issuance
is not immediate: a new certificate spends the registered domain's budget of 50 per seven
days, refilling at one every 202 minutes, so provisioning has to tolerate a pending state
rather than assume a certificate in hand. Between account creation and issuance the member
has mail, an upload path and a capsule, and the page says the padlock is coming rather than
promising it now, which is [#166](https://github.com/kyriakon/kyriakon-infra/issues/166)'s
decision and not restated here. The 443 block of the vhost is written when the certificate
lands, not before.

The capsule side does not use ACME at all, per
[#244](https://github.com/kyriakon/kyriakon-infra/issues/244). One self-signed pair serves
`kyriakon.net` and `*.kyriakon.net`, covering every capsule this platform runs and every
member capsule hostname, and each capsule on a member's own domain gets its own pair
generated at provisioning. The pair lives at
`/etc/ssl/capsule-kyriakon.net.crt` and `/etc/ssl/private/capsule-kyriakon.net.key` for the
platform pair, and `/etc/ssl/capsule-<domain>.crt` with its key in `/etc/ssl/private/` for
an own-domain pair, which is the same split the ACME material uses.

It is generated once, with a ten-year life, by `openssl req -x509` driven from a small
configuration file that sets `subjectAltName = DNS:kyriakon.net, DNS:*.kyriakon.net` and
`basicConstraints = critical, CA:FALSE`. A configuration file rather than command-line
extension flags is what LibreSSL 4.3.0, the `openssl` on this box, is known to carry. The
build verifies the result with `gmid -n` and records the fingerprint on the help page.

The key is backup data rather than a renewable secret. `scripts/backup.sh` deliberately
excludes TLS keys today, and the capsule key is added to the payload so a restore does not
lose it, which is
[Correct the backup's TLS-key premise and take the capsule certificate's key](https://github.com/kyriakon/kyriakon-infra/issues/262).
Losing the pair is recoverable rather than fatal: a new pair is generated by the same step
and the fingerprint on the help page is updated, and every member's client asks once more.
That regeneration is a runbook line, not an automated job, because the fingerprints only
change when a human does it.

### The quota

The quota is on: `/home` is mounted `rw,nodev,nosuid,userquota` on `/dev/sd1l`,
`/home/quota.user` exists, and the mount reports "with quotas". Soft 5 GB, hard 5.5 GB and
a week of grace are written per account by `scripts/quota-apply.sh`, which
`scripts/add-user.sh` already calls, by writing the record directly rather than through
`edquota`. The hosting build adds no quota work of its own; it asserts that the mount is
live and that the new account's record reads back, because a member whose hosting works and
whose quota record does not is a disk-exhaustion path with no signal.

### The hosting page's copy about the capsule

The page says three things and no more, per
[#244](https://github.com/kyriakon/kyriakon-infra/issues/244): that a gemini client asks
you to trust the certificate once; that the certificate does not change, so it is asked
once and not again; and that the fingerprint is published on a help page so a member can
check it by hand if they want to. The page does not say the capsule is encrypted, does not
call the certificate a security guarantee, and does not promise a padlock date for the
website beyond what [#166](https://github.com/kyriakon/kyriakon-infra/issues/166) allows.
The help page carries the fingerprint and the date it was last changed.

### Removing a member's hosting

`scripts/del-user.sh <username>` is the reverse, run inside the deletion transition that
[#241](https://github.com/kyriakon/kyriakon-infra/issues/241) owns rather than before it.
The order matters: remove `/etc/httpd.d/<name>.conf`, `/etc/gmid.d/<name>.kyriakon.net.conf`
and `/etc/acme-client.d/<name>.kyriakon.net.conf`, regenerate the three indexes and reload
the daemons, and only then remove the public tree and the account, so a daemon is never
serving a config that names a file which has already gone. The certificate material for the
member's name is removed with it. What deletion does to the member's data, the export and
the backup window is [#241](https://github.com/kyriakon/kyriakon-infra/issues/241)'s.

## Out of scope

Enforcement is not provisioning, and none of it is decided here: the state contract and the
AUP ladder ([#153](https://github.com/kyriakon/kyriakon-infra/issues/153)), the login class
that changes what a lapsed or suspended account can reach
(`docs/planning/research/per-account-enforcement.md`), the `dovecot-acl` mechanism, and
key revocation. Nor is the own-domain path
([#232](https://github.com/kyriakon/kyriakon-infra/issues/232)), the onboarding capsule
([#243](https://github.com/kyriakon/kyriakon-infra/issues/243)), the TUI
([#245](https://github.com/kyriakon/kyriakon-infra/issues/245)), the export and deletion
transition ([#241](https://github.com/kyriakon/kyriakon-infra/issues/241)), the payment
ledger ([#114](https://github.com/kyriakon/kyriakon-infra/issues/114)) or the mail stack
([#1](https://github.com/kyriakon/kyriakon-infra/issues/1)). The certificate queue itself,
its spacing and its pending state, is
[#166](https://github.com/kyriakon/kyriakon-infra/issues/166)'s; this spec consumes it.

## Not verified

No member has been provisioned through this path, because the path does not exist yet. The
`sshd -T` re-test of the amended fragment is a build step rather than something this spec
observed, as `#154` records. The `openssl req` invocation and the login-class drop-in are
written from the mechanics they rest on and the box's own state, not from a run.

## Sources

- `docs/planning/research/openbsd-per-member-hosting.md`, the mechanics note: include
  semantics, generated file shapes, the Let's Encrypt ceiling, quota mechanics, the port
  split. Read 2026-10-07. Its `chroot "/home"` shape and its port comments are superseded
  by the `/home/www` migration and by `#260`; the deployed configuration is the record.
- `docs/planning/research/per-account-enforcement.md`, for the login-class mechanism and
  the deletion order this spec leaves to enforcement. Read 2026-10-07.
- The live box, read-only, 2026-10-07: `/etc/acme-client.conf` documents the `include`
  keyword; `/etc/login.conf.d/` holds `dovecot` and `rspamd` and no `login.conf.db` exists;
  `/usr/local/bin/git-shell` is present; `/etc/httpd.d/index.conf` and
  `/etc/gmid.d/index.conf` exist and `/etc/acme-client.d` does not; `/home` carries
  `userquota` with `/home/quota.user` present and the mount reporting "with quotas";
  `getent group members` answers; `openssl version` reports LibreSSL 4.3.0.
- `openbsd/etc/httpd.conf`, `openbsd/etc/gmid.conf`, `openbsd/etc/sshd_config`,
  `openbsd/etc/acme-client.conf`, `scripts/add-user.sh`, `scripts/quota-apply.sh`,
  `scripts/cron-apply.sh`, `scripts/deploy-mail.sh`, `scripts/backup.sh`. Read 2026-10-07.
