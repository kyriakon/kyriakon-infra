# What an organisation account requires on this setup (public release)

**Question:** if the release sells a parish its own domain, several addresses, one shared
website and one bill, what does that need on this box and in this service that an
individual account does not already need?

**Answer, in six lines.** Mail for the parish's own domain is a line in the `mail_domains`
table and either a virtual alias table or the global aliases file, but not both: OpenSMTPD
refuses `alias` and `virtual` on the same action, and the global aliases file is keyed on the
localpart, so two parishes both wanting `secretary` collide in it. DKIM is one key per filter
process, so the smallest correct shape shares one key across the platform's domains rather
than carrying a key per parish. Addresses share a mailbox and a key for free when they are
aliases; separate mailboxes mean separate OS accounts, separate key files and separate
quotas, because the encryptor resolves exactly one cert per account and Dovecot authenticates
real system accounts. The service needs a group record so that N account intents apply as one
unit and one subscription writes one paid-until date, which is ADR 0009's token join with the
account replaced by the group. The parish's certificate is ordinary HTTP-01 against somebody
else's DNS, and it spends the parish's own 50-per-week budget rather than `kyriakon.net`'s.

**Tested against versus read from sources.** The box (`mail.kyriakon.net`, OpenBSD 7.9
GENERIC.MP#11 amd64) was read over SSH as an unprivileged user, with the only writes under
`/tmp` on the box: `doveconf -n`, `man` pages for `filter-dkimsign(8)`, `aliases(5)`,
`smtpd.conf(5)`, `edquota(8)` and `acme-client(1)`, reads of `/etc/fstab`, `/etc/group`,
`/etc/passwd`, `/etc/mail/aliases` and `/etc/kyriakon/keys`, and `smtpd -n -f` against
throwaway configs under `/tmp`. `doas` needs a password and `/etc/mail/smtpd.conf` is mode
0600 root, so the deployed file could not be read or syntax-checked directly; the repo copy of
it was read instead. OpenSMTPD's alias and virtual alias lookup was read from the OpenBSD
source for `usr.sbin/smtpd/aliases.c`. Let's Encrypt figures come from its own Rate Limits
page. Every command run, and every claim not exercised, is listed at the end.

---

## 1. Mail for a second domain

The deployment receives mail for exactly one domain and says so in one line of
`openbsd/etc/smtpd.conf`:

```
table mail_domains { "kyriakon.net" }
```

Routing is `match from any for domain <mail_domains> action "local_mail"`, and the action
hands mail to Dovecot with `lmtp "/var/dovecot/lmtp" alias <aliases>`. There is no
per-domain table and no virtual expansion in the file. The action deliberately omits
`rcpt-to`, and the comment in the file explains why: with `rcpt-to` the LMTP session carries
the recipient address instead of the local user, and both the Dovecot userdb and the
encryptor's key lookup are keyed on the account name.

Carrying a parish's own domain changes four things.

**The domain list.** `mail_domains` grows a second entry, for example
`parish.example`. This is a static table in a root-owned file, so it is a config deploy and
an `smtpd` reload, not runtime state, and it is the same file that holds the DKIM filter and
the queue key. Nothing about the routing rule changes: `match from any for domain` already
takes a table.

**Per-address mapping.** The obvious move is an entry in `/etc/mail/aliases`, which is how
`abuse`, `admin`, `dmarc` and `hello` are handled today. That file cannot hold two parishes'
`secretary`: `aliases(5)` on the box describes the format but not the lookup key, and the
source settles it. `aliases_get()` in `usr.sbin/smtpd/aliases.c` takes a single `username`
argument, lowercases it, and looks it up in the alias table; the domain is never part of the
key. So the aliases file is one global namespace of localparts for the whole box. Two
parishes both wanting `secretary@theirparish.org` cannot both have it.

OpenSMTPD has a per-address mechanism for exactly this. `smtpd.conf(5)` documents
`virtual <table>` as an action option: "Use the mapping table for virtual expansion." The
lookup in `aliases_virtual_get()` of the same source tries `user@domain`, then `user`, then
`@domain`, then `@`. So a virtual table is keyed by full address first and can carry a
per-domain catch-all, which the aliases file cannot. The catch is that the two are
alternatives, not layers: running `smtpd -n -f` on a copy with both `alias <aliases>` and
`virtual <virtuals>` on one action gives `alias mapping already specified for this
dispatcher`. Choosing `virtual` therefore means moving the system aliases into it too
(`postmaster`, `abuse`, `root`, `dmarc`, `MAILER-DAEMON`, and whatever catch-all the operator
wants), because the aliases file stops being consulted for local delivery. The same test
confirmed that the multi-domain shape parses: a copy with
`table mail_domains { "kyriakon.net", "parish.example" }` and `virtual <table>` reached the
PKI loading stage and failed only on a throwaway certificate that is not root-owned, which is
a root-only check rather than a syntax error.

**DKIM.** `filter-dkimsign(8)` has one `-k` key file. `-d` may be given several times, and
the filter then picks the domain that matches the From header, falling back to the first one
given. The deployed filter is invoked once for `kyriakon.net`, and its comment already warns
about the fallback: a filter attached to the submission listener will stamp a signature for
its own domain on mail whose From domain it does not know. So one filter process signs for
every domain it is given, with one key. A key per parish domain would mean one filter process
per key on the same listener, and each of those would still sign everything that reaches it,
producing a second signature under a domain that did not send the mail. That is legal (DKIM
allows multiple signatures, and DMARC alignment uses the matching `d=`) but it is a claim
that another domain handled the message. The smallest correct shape is one DKIM key shared
across the platform's domains, published under the same selector in each domain's DNS, which
also keeps rotation to one operation. Rotation itself is the documented selector swap: add a
new selector's TXT record and public key, switch the filter, retire the old record, as
`docs/planning/research/dns-nsd-he-mail-records.md` §4.1 sets out.

**The parish's MX and the records around it.** The box's reverse DNS is set at Hetzner and
points at the platform's mail hostname, and it cannot be per parish. The parish therefore
points its MX at that mail hostname (preference 10) rather than at a name of its own, and adds
A/AAAA for the apex and `www` pointing at the box, an SPF record authorising the box, a DKIM
TXT record at the selector, and a DMARC record. The platform does not host the parish's zone:
proposal §6.13 defers per-parish zone hosting and says the own-domain tier "only needs
documented MX/SPF/DKIM/CNAME instructions at the parish's existing DNS". The parish or its DNS
operator applies them, which makes the parish's DNS an external dependency of the platform's
mail path rather than a record the platform controls.

## 2. Per-address keys

The keyring is a directory of armored public certs, one per account, at
`/etc/kyriakon/keys`, and `kyriakon-encrypt/src/lib.rs` resolves a recipient in one line:

```rust
let base = base_localpart(user)?;
let key = keyring.join(format!("{base}.asc"));
if !key.is_file() {
    return Err(Error::MissingKey(base.to_string()));
}
```

`base_localpart` strips a `+tag`, so plus addressing resolves to the base localpart, and the
lookup is per save. There is no cache and no daemon-side key state, so a key added or replaced
on disk takes effect on the next message with no restart. The key file is then passed to
`gpg --recipient-file`, one file, one recipient.

Three consequences for a parish.

**Addresses that are aliases cost nothing.** The key is named after the account localpart,
not the address. Because alias and virtual expansion happen before LMTP (the reason
`rcpt-to` is off), `office@parish.example` delivered to account `parish` is encrypted to
`parish.asc`. Any number of addresses can share one mailbox and one key, and none of them
needs a key file of its own. The published key set (proposal §5.1, §5.6) stays one file per
account, and no alias appears in it.

**A mailbox with two addresses that should be one mailbox is one key.** Two people logging in
to the same account with `bsdauth` use one system password, so they are the same identity to
the platform. Zero-access is unaffected, because the server still holds only public certs.
What changes is confidentiality granularity: everyone with access holds the same private key
and reads everything sent to any address on that account. The encryptor cannot do better
without a change, because it encrypts to exactly one cert per recipient. Giving the members
of one mailbox separate keys would need multi-recipient encryption in the crate, which is not
there today.

**Two mailboxes need two accounts and two keys.** A missing key fails the save closed, so an
account without its `keys/<localpart>.asc` in the repo cannot receive mail at all. Adding a
person is therefore: create the account, add their public cert to the repo, install it into
the keyring (`scripts/deploy-mail.sh` copies `keys/*.asc` under their basenames), and set
their password. Key rotation is forward only: the platform holds no private key and cannot
re-encrypt stored mail, so a new cert affects future messages, and whoever holds the old
private key keeps the old cert to read what is already stored.

## 3. The account model

An individual account is a real OpenBSD account created by `scripts/add-user.sh`:
`useradd -m -d /home/<u> -s /sbin/nologin -g =uid`, a Maildir under the home, the shell forced
to `/sbin/nologin`, and no interactive session anywhere. Dovecot authenticates it through
`bsdauth` and OpenSMTPD through BSD auth, and the nologin shell does not affect either. The
account name is also the public subdomain `username.kyriakon.net` (proposal §5.2, §5.9.3) and
the keyring filename.

Two shapes are possible for a parish.

Several shell-less accounts, one per person or mailbox:

- Each account has its own login and password, so a person can be removed without touching
  anyone else, and per-account abuse monitoring attributes activity to a person.
- Each account has its own Maildir, its own key and its own public subdomain, so the parish
  mints N subdomains and N username reservations, and each name has to pass the reserved-name
  check and the live `/etc/master.passwd` check.
- Quota is per uid per filesystem. `/home` is its own filesystem
  (`bbb8a630c9f5d96e.l /home ffs rw,nodev,nosuid 1 2` in `/etc/fstab`, read on the box), but
  it has no quota option and no `/home/quota.user`, so no quota is enforced today. When
  quotas are enabled, N accounts are N five-gigabyte allowances unless the design uses a
  group quota. `edquota(8)` on the box takes `-g` for group quotas and `-p` for a prototype,
  so a parish group whose members share it as their primary group can carry one allowance
  instead of N. Both `userquota` and `groupquota` have to be added to the `/home` line, and
  `useradd -g <group>` rather than `-g =uid` is what puts new files in the group.
- Backup is unaffected: `scripts/backup.sh` backs up `/home` and `/etc/mail` with restic, so
  the org costs nothing extra in scope. Deletion is the cost: GDPR erasure, the lapsed state
  and the paid-until date are all per account, so an org of N accounts is N of each.

One account with aliases:

- One login and password for everyone, one Maildir, one key, one five-gigabyte quota, one
  subdomain, one thing to delete.
- There is no per-person revocation short of changing the password for everyone, no
  per-person attribution in the logs, and no way to give one person a private mailbox later
  without creating a second account at that point.
- The site root problem (below) is unchanged, because the shared site already implies one
  account.

The sftp chroot decides how a shared website can be uploaded. The hosting design puts
`ChrootDirectory /home/%u` on the upload port, so each account is chrooted to its own home;
that is one chroot per account and a member cannot see another member's home at all.
`www/` and `gemini/` are subdirectories of that home, with the daemons moved to a global
chroot of `/home` so those directories are visible (proposal §6.9, worked out in
`docs/planning/research/openbsd-per-member-hosting.md` §4; the deployed `httpd` and `gmid`
still serve from `/var/www` today). A shared site root therefore lives in exactly one
account's home, and exactly one sftp credential can upload to it. The
smallest shapes are: one account owns the site and one person holds that credential, or the
site is a git repository in that account and the person who edits it uses the git path. Giving
several accounts write access to one site root would mean either giving up the chroot or
running the git path on a separate port, and both are real work for a feature nobody has
asked for yet.

Practical middle shape: accounts only for the mailboxes that need their own key, plus a
virtual table mapping the org's other addresses onto those accounts, plus a `parish-<slug>`
group with a group quota if the org is to have one allowance. One detail to pass to members:
`auth_username_format = %Ln` strips the domain part, so a client authenticates as the
account's localpart. An address that exists only as an alias or virtual entry (a localpart
with no OS account) cannot be used to log in; the member is told the account name.

## 4. The service side

The onboarding service is planned in `kyriakon-onboard` (proposal §5.9, §6.14): a web
application, an operator approval, Stripe Checkout, a verified webhook and a narrow
provisioning privilege. This ticket states that its state is flat files and that a root-run
drain applies its intents; that design is not written down in this repo yet, and
`kyriakon-onboard` currently holds only docs. What follows is what an organisation adds to
that shape.

**A group of accounts.** Today one application becomes one account. An organisation is one
approval and one payment that has to become N accounts. The drain needs a group record so the
N account intents apply as one unit: a parish half-provisioned (a mailbox with no key, a site
with no certificate) is a support incident, and the intents have to be idempotent
individually so a retry after a crash cannot create a second account. The flat files also need
somewhere to keep the org's name and its DNS contact, rather than a person's application
alone.

**One subscription.** `docs/planning/research/stripe-rail-set.md` §1 sets out the card rail:
one Product, one yearly Price, a Checkout Session from the service, and a Subscription Stripe
renews. For an organisation all of that stays, with N accounts behind one Subscription and
one `client_reference_id` pointing at the organisation's application rather than at a
username. The prepaid rail needs nothing in Stripe, and it extends the same one date.

**The token join.** ADR 0009 (`kyriakon/docs/decisions/0009-payment-records-keyed-by-token.md`)
puts the payment state with the account (paid-until, rail, token reference) and the financial
ledger in a separate record keyed by the approval token, holding amount, date, rail and
paid-until, with no username or contact address. An organisation is billed once, so the
state belongs with the group and each account references it; a copy per account would be N
dates that can drift, and a defect in that join is the one bug ADR 0009 already singles out
as worth a test. The ledger is unchanged: one token per subscription, one row per payment, and
deleting the organisation is what makes the row unlinkable, exactly as the ADR intends. The
lapse path is also unchanged in mechanism and larger in blast radius:
`invoice.payment_failed` drops every account in the group to read-only (`usermod -L lapsed`,
`docs/planning/research/per-account-enforcement.md` §8), and the 40-day reach-out runs against
the group, which is the "parish whose technical user has gone AWOL" case proposal §5.9.1
already names as the reason deletion is admin-mediated.

## 5. The certificate

Certificates here are HTTP-01 only. `acme-client(1)` on the box documents the one challenge
type and the default challenge directory `/var/www/acme`, and the repo's `acme-client.conf`
carries one `domain` block per certificate with a comment repeating that DNS-01 is not
implemented. A parish domain is what that pattern already does for `oliver.kyriakon.net`:
one `domain` block, one port 80 vhost serving `/.well-known/acme-challenge/`, one port 443
vhost for the site, and, if Gemini is wanted, a matching `gmid` server block using the same
certificate.

Two things are different when the DNS is somebody else's.

**The name must point at the box while issuance runs.** HTTP-01 validation reaches the name on
port 80, so the parish's A/AAAA has to be live and the box has to answer on that name before
`acme-client` is run. Nothing the platform does can substitute for that, and a renewal
depends on the record staying live for the life of the account. The vhost that serves the
challenge needs no valid certificate, so issuance itself does not depend on an existing cert;
what does depend on it is the parish's HTTPS site, which shows the wrong name until its own
certificate lands (httpd serves its default certificate when a vhost names none,
`httpd.conf(5)` via `docs/planning/research/cert-issuance-ceiling.md`).

**The budget is the parish's own.** Let's Encrypt's Rate Limits page (last updated
5 August 2026, read 1 October 2026) states "Up to 50 certificates can be issued per
registered domain ... every 7 days", refilling at one certificate per 202 minutes, and the
limit is global across accounts. A registered domain is the domain itself, so issuing for
`parish.example` spends the parish's own fifty and leaves `kyriakon.net`'s fifty alone. A
parish does not eat the platform's onboarding budget, and the platform's own ceiling is
unchanged by selling the tier. Renewals with the same set of identifiers are exempt from that
limit (same page), so the recurring cost is not issuance. The recurring risk is the failure
mode: if the parish's DNS stops resolving to the box, validations fail, five failures per
identifier per hour then block new orders for that identifier, and 1,152 consecutive failures
pause it until a human unpauses it in Let's Encrypt's Self-Service Portal (same page). The
platform can see that only in the client's output, which reaches cron mail on this box.

One mechanical task follows: `scripts/renew-acme.sh` renews a hardcoded list of handles
(`mail.kyriakon.net`, `kyriakon.net`, `kyriakon.com`). A parish handle has to be added there,
or the script generalised to iterate the `domain` blocks in `acme-client.conf`. A failure on
one handle already does not stop the others and still exits non-zero, which is the behaviour
wanted here.

## The smallest design that carries one parish

1. One account for the parish's shared mailbox and its website, say `parish`. Add an account
   only for a person who needs a private mailbox; each of those brings its own key file,
   its own reservation and its own quota line.
2. `parish.example` added to the `mail_domains` table, and the local delivery action switched
   from `alias` to `virtual` with a table holding one entry per address
   (`office@parish.example parish`, and so on) plus the system aliases as per-domain or
   catch-all entries. No global aliases entry is used, so nothing collides with another
   parish.
3. One site root in the parish account's home, served by a vhost for `parish.example` (and
   `www` if wanted) once the daemons' chroot is the tree that holds member homes, uploaded
   with that account's sftp credential or through its git repository. Gemini gets the same
   posture and the same certificate if it is wanted.
4. One certificate for `parish.example` (with `www` as an alternative name, so it is one
   order) and the parish handle added to, or discovered by, the renewal script.
5. One subscription, one approval token, one paid-until date on the group; each account
   references the group. A `parish-<slug>` group and a group quota if the org is to have one
   allowance rather than five gigabytes per account. Quotas are documentary until the `fstab`
   line carries them.
6. DKIM starts on the platform's existing key, published at the selector in the parish's
   DNS. Per-domain keys are a later change and cost a filter process each.
7. DNS records the parish applies at its own provider: A/AAAA for the domain and `www`,
   MX 10 at the platform's mail hostname, SPF, DKIM TXT, DMARC.

Nothing in that list changes the account tier. Every account stays a real system account with
`/sbin/nologin`, the upload path stays the chrooted `internal-sftp`, and git stays
`git-shell` behind SSH keys.

## What this costs in operator attention each month

In the steady state, one healthy parish costs about what one individual account costs: a line
in the daily cron mail if a renewal fails, and nothing else. The recurring work sits in four
event-driven places rather than in the month.

- An org-level change (a person added, moved or removed, or a new address) is admin-mediated,
  the same as an individual signup, but it touches a group rather than one account.
- The parish's DNS is an external dependency the platform can only observe. If it stops
  pointing at the box, mail for the parish and the certificate renewal both fail, and the
  first signal is cron mail.
- A lapsed subscription drops the whole group read-only at once and starts the 40-day reach
  out, which is one conversation for several people.
- The first parish costs a setup session of its own: applying its records with its DNS
  operator, adding the vhosts, issuing the certificate, creating the accounts and keys,
  and adding the DKIM record. Later parishes reuse the shape but still need the records and
  the vhosts.

Nothing here is a per-message or per-address cost. Disk is about 3.6p per gigabyte per year
(proposal §6.5), so the price of the tier is answerable from attention and support, not from
storage.

## What the signup form has to collect

Beyond the individual fields in proposal §5.9.1, an organisation application needs:

- the organisation's name, and the domain it wants mail and a website for;
- the address list, each marked as a mailbox or as a forward to another address;
- one mail public key per mailbox (only the public half, generated client-side as for an
  individual);
- an optional SSH public key for whichever account owns the website, and which account that
  is;
- a contact email for approval and billing, and a DNS contact if a different person applies
  the records;
- an acknowledgement that the domain's DNS stays with them and that the platform does not
  host the zone.

## Not verified against the box or a man page

- `smtpd -n` against the deployed `/etc/mail/smtpd.conf`. The file is mode 0600 root and
  `doas` needs a password, so it was neither read nor checked. The syntax checks were run
  against a copy of the repo's file under `/tmp`, which does not prove the deployed file
  matches the repo.
- Whether one `filter-dkimsign` process signs all of its `-d` domains with the single `-k`
  key. The synopsis has one `-k` file, which is what the conclusion rests on; the prose does
  not state it, and it was not exercised because doing so needs the signing key and a filter
  protocol session. No mail was sent.
- The behaviour of two filters chained on one listener (the second signature under the wrong
  domain). Read from the man page's fallback rule, not tested.
- Every quota and group-quota enforcement claim. Quotas are off on `/home`, enabling them
  needs root and an `fstab` change on the live mail host, and no account was created.
- That `httpd` and `gmid` accept the parish vhost and certificate shapes as described, and
  that the design's move of their chroot from `/var/www` to the tree holding member homes
  lands as written. Read from the deployed configs and man pages, not exercised.
- The onboarding service's flat files and root drain. Taken from the ticket; the design is
  not written in this repo, and `kyriakon-onboard` holds only docs at the time of writing.
- The 50-per-registered-domain arithmetic is only as exact as the Public Suffix List. For
  `parish.example` the registered domain is the domain itself; a parish on a suffix such as
  `.co.uk` would be measured at the higher registered domain.
- Anything needing root: creating accounts, enabling quotas, reloading `smtpd` or `httpd`,
  and issuing a certificate.

## Primary sources

- `openbsd/etc/smtpd.conf`, `openbsd/etc/httpd.conf`, `openbsd/etc/gmid.conf`,
  `openbsd/etc/acme-client.conf`, `openbsd/dovecot/dovecot.conf`, `scripts/add-user.sh`,
  `scripts/backup.sh`, `scripts/renew-acme.sh`, `kyriakon-encrypt/src/lib.rs`,
  `reserved-usernames.txt` in this repo, read 2026-10-01.
- `man filter-dkimsign` (OpenBSD 7.9), `man aliases`, `man smtpd.conf`, `man edquota`,
  `man acme-client`, `doveconf -n`, `/etc/fstab`, `/etc/group`, `/etc/mail/aliases`,
  `/etc/kyriakon/keys` on `mail.kyriakon.net`, read 2026-10-01.
- OpenSMTPD `usr.sbin/smtpd/aliases.c`, `aliases_get()` and `aliases_virtual_get()`,
  https://raw.githubusercontent.com/openbsd/src/master/usr.sbin/smtpd/aliases.c, read
  2026-10-01.
- Let's Encrypt, Rate Limits, last updated 5 August 2026,
  https://letsencrypt.org/docs/rate-limits/, read 2026-10-01.
- `kyriakon/docs/decisions/0009-payment-records-keyed-by-token.md` (accepted 2026-09-30) and
  `kyriakon/docs/decisions/kyriakon-net-project-proposal.md` §5.1, §5.2, §5.6, §5.9, §6.13,
  §7, read 2026-10-01.
- `docs/planning/research/dns-nsd-he-mail-records.md`,
  `docs/planning/research/openbsd-per-member-hosting.md`,
  `docs/planning/research/per-account-enforcement.md`,
  `docs/planning/research/cert-issuance-ceiling.md`,
  `docs/planning/research/stripe-rail-set.md` in this repo, read 2026-10-01.
