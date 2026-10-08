# The own-domain tier's provisioning

> Spec synthesised from [Spec the own-domain tier's provisioning](https://github.com/kyriakon/kyriakon-infra/issues/232) and the decisions it points at: [#188](https://github.com/kyriakon/kyriakon-infra/issues/188) (the tier set, the price and the ten-address cap), [#190](https://github.com/kyriakon/kyriakon-infra/issues/190) (what an organisation account requires), [#233](https://github.com/kyriakon/kyriakon-infra/issues/233) (the community block and the keys), [#163](https://github.com/kyriakon/kyriakon-infra/issues/163) (no country on the record, VAT evidence from the rail), [#150](https://github.com/kyriakon/kyriakon-infra/issues/150) and [#154](https://github.com/kyriakon/kyriakon-infra/issues/154) (the per-member hosting design), [#166](https://github.com/kyriakon/kyriakon-infra/issues/166) (the certificate queue), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156) (the service's two halves and the intent path), [#189](https://github.com/kyriakon/kyriakon-infra/issues/189) (the per-domain price shape) and [#153](https://github.com/kyriakon/kyriakon-infra/issues/153) (the account lifecycle).

## Problem statement

The release sells a body its own domain at £40 a year: up to ten addresses, each mailbox carrying the standard 5 GB, mail, a website and a gemini capsule for that domain, and git per account. A body is a parish, a monastery or a small Orthodox business, and nothing in the tier is decided on which. The body keeps its domain's DNS and applies a recipe the platform publishes, because the platform does not host the zone.

None of the machinery exists yet. The box receives mail for one domain, `kyriakon.net`, and delivers it through `/etc/mail/aliases`, a file keyed on the localpart with no domain, so two bodies both wanting `secretary` cannot both have it. The DKIM filter signs every domain it is given with one key. Per-member hosting is generated from a member name, and a member certificate is issued against `kyriakon.net`'s own issuance budget. One application becomes one account under one subscription. Carrying a body's domain needs each of those to extend to a second domain, and the release bar requires the extension automated rather than hand-provisioned.

## Solution

One application from one accountable person, with the conditional community block, becomes one group record and one approval. The drain applies the group as one intent: an account for each mailbox, a virtual entry for each address, the domain in the mail domain table and in the DKIM filter, a generated vhost and capsule, a certificate added to the queue, and one subscription with one paid-until date that every account in the group references.

Mail moves as soon as the domain resolves, the tables are applied and `smtpd` reloads. The website follows its certificate through the same oldest-first queue member certificates use, and spends the body's own issuance budget rather than `kyriakon.net`'s. The body publishes the platform's public DKIM key at the platform's selector in its own domain. The fee covers the whole group, so a mailbox added or removed inside the ten-address cap changes nothing about the price or the renewal date.

The service keeps its two halves. The internet-facing handler files the application and holds no privilege; the drain owns provisioning, the approval token, the certificate requests and the lifecycle, and it validates every field of a group intent as strictly as a privilege boundary requires ([#156](https://github.com/kyriakon/kyriakon-infra/issues/156)).

## What an application provisions

On approval the drain applies one group intent. Every step is idempotent, so a retry after a crash cannot create a second account, a second virtual entry or a second certificate request.

- It creates the group record under `groups/<domain>/`, and one system account for each mailbox in the address table, each with a Maildir, the shell `/sbin/nologin`, membership of the members group, and the standard 5 GB allowance (`scripts/add-user.sh`).
- It installs each mailbox's public key from the application into the on-box keyring and opens a pull request to publish it, which the service merges ([#155](https://github.com/kyriakon/kyriakon-infra/issues/155)).
- It installs the block's upload key into the site owner's `authorized_keys`. sftp and git are both key-based, so this key is what fills the site tree and reaches the repositories, and a body that leaves the block's upload key empty has a site no one can fill until it supplies one ([#154](https://github.com/kyriakon/kyriakon-infra/issues/154)).
- It gives each mailbox a login class whose `shell` capability names `git-shell`, so sshd execs a session's shell from the class while the password entry keeps `/sbin/nologin`, which ignores `-c`: a push reaches `git-shell` and the account still holds no login shell. sftp runs on 22 and git on 2222, so one key serves both ([#154](https://github.com/kyriakon/kyriakon-infra/issues/154), `openbsd/etc/sshd_config`).
- It adds the domain to the mail domain table and writes one virtual entry for each address.
- It adds the domain to the DKIM filter's domain list.
- It writes the generated vhost, capsule and certificate block, with the site tree in the account named as the site owner.
- It requests one certificate for the website, covering the domain and `www`, through the queue.
- It issues one approval token, opens the payment window, and sends the approval email, which carries the payment instructions and the DNS recipe.

The configuration writes land in one batched pass, applied by the same script that applies the vhost indexes, so a wave of approvals costs one reload per daemon rather than one per approval ([#154](https://github.com/kyriakon/kyriakon-infra/issues/154)).

## The mail path

### The virtual table replaces the aliases file

`/etc/mail/aliases` is keyed on the localpart and never on the domain. `aliases_get()` in `usr.sbin/smtpd/aliases.c` takes one `username`, lowercases it and looks it up, so the file is one global namespace for the whole box and two bodies cannot both own a `secretary`. OpenSMTPD's per-address mechanism is the action's `virtual <table>`, whose lookup in `aliases_virtual_get()` tries `user@domain`, then `user`, then `@domain`, then `@`. The two are alternatives rather than layers: `smtpd -n` refuses a config with both on one dispatcher, returning `alias mapping already specified for this dispatcher` ([#190](https://github.com/kyriakon/kyriakon-infra/issues/190)).

The tier therefore switches the local delivery action to the virtual table. The hand-written config names two generated files and drops the aliases file from local delivery:

```
table mail_domains file:/etc/mail/mail_domains
table virtuals file:/etc/mail/virtuals
action "local_mail" lmtp "/var/dovecot/lmtp" virtual <virtuals>
```

The platform's own system aliases move into `/etc/mail/virtuals` as bare localparts, alongside one full-address entry for each body address. A body keeps no catch-all entry, because the ten-address cap counts the addresses the platform provisions and a catch-all would answer for any number of them. Adding the body's domain to `/etc/mail/mail_domains` is what makes the routing `match from any for domain <mail_domains>` accept its mail; removing the line is what makes it reject. The drain writes both files and reloads `smtpd` in the same pass as the rest of the provisioning.

### Addresses, mailboxes, aliases and keys

The community block's address table marks each address as its own mailbox or as an alias into one. A mailbox is a system account with its own Maildir, its own public key file and its own 5 GB. Its virtual entry points at the account. An alias has no account: its virtual entry points at the account of the mailbox it names, so it shares that mailbox, that key and that allowance. This is the behaviour the platform's own aliases already have, because expansion happens before LMTP and no `rcpt-to` is set on the action, so the encryptor resolves one key per account (`kyriakon-encrypt/src/lib.rs`, [#190](https://github.com/kyriakon/kyriakon-infra/issues/190)). The published key set stays one file per account, and no alias appears in it.

The ten addresses count mailboxes and aliases together. An office mailbox with four addresses pointing into it costs four of the ten and one mailbox's storage.

### Account names

The account name is the local part the platform knows a mailbox by, and the name of its key file, its home and its public tree. It must fit the charset `scripts/add-user.sh` enforces, lowercase letters, digits, dot, underscore and hyphen up to 32 characters, it must not be a reserved username, and it must not already exist. The applicant chooses one name per mailbox, because the address carries the domain and the account name does not, so two bodies may both have `secretary@` without collision. The front-ends offer no username oracle, so the form cannot say whether a name is free. The reviewer's view flags a reserved or taken name and approval waits until the applicant supplies another, and the drain refuses the intent if a collision reaches it anyway.

### One DKIM key for every domain the filter signs

`filter-dkimsign` takes one key with `-k` and any number of domains with `-d`, and it signs the message with the domain matching its From header, falling back to the first domain given (`man filter-dkimsign`, [#190](https://github.com/kyriakon/kyriakon-infra/issues/190)). A key per body would need a filter process per key on the same listener, and each process would still sign every message it saw, so the platform keeps one key for every domain it signs and publishes it at the same selector in each. The body's DNS carries the platform's public key at `mail._domainkey.<domain>`, and the domain joins the filter's `-d` list when it is provisioned.

The domain must be in the list before it sends mail. A domain the filter does not know is signed with the fallback domain, so the body's outbound mail would carry a `d=` that does not match its From domain and fail DMARC alignment. Because the key is shared, rotation is one operation for every domain the platform signs, which is why the selector is dated and rotating it is one filter change plus one new record in each body's DNS. A body that leaves rotates nothing: the key it published is the platform's, still in use by the domains that stay, and its own job is to delete the selector record from its zone, which the platform cannot do for it.

## The hosting path

### The generated vhost and capsule

The hosting design generates one file per member per daemon from a name, and the own-domain tier passes the body's domain as that name. The site tree keeps the member shape, so the document root is `/home/www/<site-account>.kyriakon.net/www` and the capsule root is `/home/www/<site-account>.kyriakon.net/gemini`, where `<site-account>` is the mailbox named as the site owner in the community block. The generated HTTP vhost is the member vhost with a different server name and certificate:

```
server "parish.example" {
	listen on * tls port 443
	tls {
		certificate "/etc/ssl/parish.example.fullchain.pem"
		key "/etc/ssl/private/parish.example.key"
	}
	location "/.git/*" {
		block
	}
	location "/*" {
		root "/parish-secretary.kyriakon.net/www"
	}
}
```

The generator writes the `www` vhost and its redirect, the port 80 challenge vhost, and the gmid server block with the domain's capsule certificate and the gemini root. The files go under `/etc/httpd.d/`, `/etc/gmid.d/` and the certificate config's directory, each listed by the index the hand-written config includes, which the drain rewrites atomically ([#150](https://github.com/kyriakon/kyriakon-infra/issues/150)).

The document root is the site owner's public directory rather than a directory named after the domain, because the upload session's chroot is `/home/www/%u.kyriakon.net` and `sshd_config` is applied by hand rather than written by the provisioning path. Reusing the member public directory keeps a body's upload path identical to a member's and needs no change to that file.

The port 80 block is written first and the port 443 block only once the certificate file exists, so a body whose certificate is still queued has a resolving name and a working challenge but nothing served over TLS. That is the pending state a member already has ([#154](https://github.com/kyriakon/kyriakon-infra/issues/154), [#166](https://github.com/kyriakon/kyriakon-infra/issues/166)).

### The certificate and the queue

The certificate is one order for the domain with `www.<domain>` as an alternative name, issued over HTTP-01 against the body's name pointed at the box. The A and AAAA records have to be live first, and the port 80 vhost serves the challenge. The request joins the drain's certificate queue, which works oldest-first and spaces requests against the refill of one certificate every 202 minutes ([#166](https://github.com/kyriakon/kyriakon-infra/issues/166)). `acme-client` 7.9 does not read `Retry-After`, so the wait is the queue's own rather than the header's (`scripts/renew-acme.sh`).

The body's domain has its own budget. Let's Encrypt allows 50 new certificates per registered domain every seven days and refills one every 202 minutes; a registered domain is the Public Suffix List's eTLD+1, the part the body bought from its registrar, so issuing for a name under the body's own registered domain spends the body's fifty and leaves `kyriakon.net`'s untouched (Let's Encrypt, Rate Limits, read 2026-10-01, cited in [#190](https://github.com/kyriakon/kyriakon-infra/issues/190)). Selling the tier therefore does not consume the platform's own onboarding ceiling. A body's queued request waits behind earlier requests in the same queue, not behind `kyriakon.net`'s budget.

The queue does not attempt a name whose records do not resolve yet. Repeated failures spend five authorization attempts per identifier per hour, and a long run of them pauses the identifier until a human clears it, so a body that has not applied its records is held pending, its state is visible on its account page, and the drain's health signal alerts when the oldest pending request passes a stated age ([#165](https://github.com/kyriakon/kyriakon-infra/issues/165), [#166](https://github.com/kyriakon/kyriakon-infra/issues/166)). A rate-limit refusal is not a broken name: the queue backs off on it rather than counting it against the identifier, and the refusal reaches the operator rather than being retried quietly (`scripts/renew-acme.sh`). Renewals are exempt from the budget, but a body's certificate does not renew by itself. Its generated domain block sits in a file the certificate config includes, and `/etc/acme-client.conf` carries no `include` today, so that line has to be added. `scripts/renew-acme.sh` reads only the top-level blocks and deliberately does not follow an included file, and its `services_for` is a fixed list that stops the run for a handle it does not know, so the body's handle has to reach the script too, either by following the include or by extending that list. Both are provisioning steps the release has to land (`scripts/renew-acme.sh`).

## The group record and the subscription

A body's application is one approval, one token and one subscription. The drain writes one group record under `groups/<domain>/group.json` holding the domain, the body's name and kind, the payment state, the accounts in the group and the account that owns the site. The name and kind are the body's own words, used to address it in notices and to filter the reviewer's queue; the DNS contact and the rest of the application's answers are purged with the application inside the ninety-day window (ADR 0005).

Each account's `account.json` gains a reference to its group and holds no paid-until date of its own. The card rail is one yearly Price and one Stripe Subscription whose `client_reference_id` is the group's application identifier rather than a username, so one renewal writes one date. The prepaid rail is one token and one window, and the ledger stays keyed by the token as ADR 0009 requires, so deleting the group is what makes the row unlinkable. A group approved without charge has no window, no token and no paid-until date, and it never lapses; the permanence of a free group is this spec's proposal rather than a recorded decision, which the tickets leave open ([#177](https://github.com/kyriakon/kyriakon-infra/issues/177), [#188](https://github.com/kyriakon/kyriakon-infra/issues/188)).

The account page resolves the signed-in mailbox account to its group, so anyone who holds a mailbox in the group can see the group's billing, quota and state. There is no separate group login, and the state stays on the group rather than being copied per account, which is what keeps one renewal from leaving several dates that can drift.

No country is asked on the form and none is held on the record, because the payment rail supplies the two pieces of evidence HMRC wants for a cross-border consumer. A business applicant may give a VAT number, which turns a supply to a Union business into a reverse-charge supply with no VAT charged ([#163](https://github.com/kyriakon/kyriakon-infra/issues/163)).

## The body's DNS recipe

The approval email carries the records the body creates, generated from the domain, and the account page repeats them. The recipe opens by saying that the body keeps its domain, that the platform never touches its zone, and that mail and the website start working only after the records are live. The records are:

| What it is for | Name | Type | Value |
| --- | --- | --- | --- |
| Mail arrives | `@` | MX | `10 mail.kyriakon.net.` |
| The website and the certificate reach the box | `@` and `www` | A and AAAA | the platform's IPv4 and IPv6 addresses |
| Outbound mail is authorised | `@` | TXT | `v=spf1 mx -all` |
| Outbound mail is signed | `mail._domainkey` | TXT | `v=DKIM1; k=rsa; p=<the platform's public key>` |
| Mail that fails is reported | `_dmarc` | TXT | `v=DMARC1; p=none; rua=mailto:dmarc@kyriakon.net` |

The MX points at the platform's mail host rather than a name of the body's own, because the box's reverse DNS is set at the hosting provider against `mail.kyriakon.net` and cannot be varied per body. The SPF record authorises the box through that MX target. The DKIM record uses the platform's selector and its public key, the same key every domain the platform signs uses. The DMARC policy starts at `p=none` so the first aggregate reports can be read, and tightens to `quarantine` once every report row passes, which is the path the platform's own zone took ([`dns-nsd-he-mail-records.md`](../research/dns-nsd-he-mail-records.md) sections 2 and 4).

Three things the recipe says plainly that the platform cannot do: it does not host the zone, it cannot set a reverse DNS record for the body's domain, and it can only observe the records. If they stop resolving, mail to the body stops arriving and the certificate cannot renew.

## What the reviewer sees and decides

The reviewer's queue stays one stream, filterable by kind, and a body's row shows the body, its kind, its domain and its addresses with mailboxes and aliases marked. The kind is a filter, not a gate, and nothing is approved or declined on it.

The reviewer checks four things. The domain resolves, and the applicant says they can add its records. The applicant is not a resident of a country under UK sanctions, which the reviewer checks at approval because no country is held on the record ([#163](https://github.com/kyriakon/kyriakon-infra/issues/163)). The account names are free. Each mailbox carries a public key that passes the delivery checks the individual path warns about but never refuses ([#176](https://github.com/kyriakon/kyriakon-infra/issues/176)). The outcomes are the same three the release ships: approve paid, approve without charge, decline. A body reaches the free tier through approve without charge, the same way a person does, rather than through a category test ([#188](https://github.com/kyriakon/kyriakon-infra/issues/188)).

Two things the reviewer carries that the form does not ask. An applicant applying in the course of business is not a consumer, so the fourteen-day cancellation right does not reach the body the way it reaches a person, which the terms record rather than the form. And the applicant's statement that they control the records is the only evidence until the records appear, because the platform cannot query the body's DNS authority.

## Limits and changes

### The ten-address cap and the eleventh

A domain carries up to ten addresses, counted across mailboxes and aliases, and one mailbox allowance of 5 GB for each mailbox. There is no pooled group allowance: each mailbox carries its own 5 GB, which is what the tier's published wording says ([#188](https://github.com/kyriakon/kyriakon-infra/issues/188)). The price is per domain and not per address: the market research that set the band rejects a per-address rate, because an address on a shared box costs storage and attention rather than a licence, and because a per-address price penalises the shape a parish has ([#189](https://github.com/kyriakon/kyriakon-infra/issues/189)). An eleventh address is therefore not a line item, which is this spec's proposal rather than a decision: [#188](https://github.com/kyriakon/kyriakon-infra/issues/188) settles the price and the cap but leaves the pricing of an eleventh open. A body that needs more than ten has outgrown the tier's shape, and the answer is either a second domain at the same £40, which is how a body with a hall, a cemetery or a school on its own domain is served, or a decision the operator makes by hand. The tier itself stops at ten and the eleventh is not automated.

### Adding an address, upgrading a mailbox, leaving the body

Adding an alias is one virtual entry pointing at an existing mailbox. It creates no account and no key, takes no new allowance, and moves the address count. Adding a mailbox creates an account, installs a key the member supplies, and points the address at it, inside the same ten-address cap.

Upgrading an alias into a mailbox is the same operation with the virtual entry repointed from the shared mailbox to the new account, so the person who was reading the office mailbox gets a private key and a private allowance without anything else in the group changing. The address count does not move, because the address already existed.

A mailbox leaving the body is one of two things. It becomes an individual account at £20 with its own subscription and its own paid-until date, or it is closed. Either way its account, key file, quota line and virtual entries go, the group's other accounts are untouched, and the group's own paid-until date does not move, because the fee is per domain. A closed account's username is held for ninety days before it is released ([#153](https://github.com/kyriakon/kyriakon-infra/issues/153)). If the account that leaves owns the site, the body names another mailbox to own it first, and the generated vhosts and capsule move their root before the old account is deleted.

### Removing the domain

Removing a body's domain removes its virtual entries and its line in the mail domain table, its domain from the DKIM filter's domain list, its generated vhosts, capsule and certificate block, and its group record. The certificate stops being renewed, and the accounts close through the deletion transition an individual account uses, which removes the token's index entry and makes the ledger row unlinkable. The records stay in the body's own zone, because the platform never held them, and the body removes them. With the domain gone from the mail tables and the vhosts gone, mail and web for the name stop answering.

## When the domain lapses or its DNS breaks

A lapsed subscription lapses the whole group at once. Every account moves to the lapsed state, each mailbox holder keeps readable mail, the site stays up, and sending, uploading and pushing stop. The forty-day grace and the notices that lead to deletion run against the group, one conversation for the whole body, and the end of the grace deletes every account in it. A suspension under the acceptable use policy takes the site down while inbound mail keeps arriving, the same as for an individual account ([#153](https://github.com/kyriakon/kyriakon-infra/issues/153)).

Broken DNS is the case the platform can only watch. The body's MX and A records are its own, so if they stop resolving, mail to the body stops arriving and the certificate renewal fails. The platform sees both in cron mail and in the drain's health signal, notifies the DNS contact if the application gave one and the accountable address otherwise, and waits. It does not touch the zone. A renewal that fails repeatedly can pause the body's identifier at the certificate authority, which the operator clears in the authority's own portal once the records are back ([#165](https://github.com/kyriakon/kyriakon-infra/issues/165)).

## State

Paths are relative to the service's store root ([#156](https://github.com/kyriakon/kyriakon-infra/issues/156)).

| Path | Status | What the own-domain tier puts in it |
| --- | --- | --- |
| `groups/<domain>/group.json` | new | the domain, the body's name and kind, `payment{rail, token_ref, paid_until, window}`, the accounts in the group, and the site owner |
| `accounts/<username>/account.json` | modified | a `group` reference; no per-account `paid_until` |
| `accounts/<username>/application.json` | modified | the community block's answers, purged with the rest inside ninety days |
| `tokens/<token>.json` | modified | one token per group, resolving to the group rather than an account |
| `ledger/payments.jsonl` | unchanged | one line per payment, keyed by the group's token |
| `intents/<id>.json` | modified | a `provision-group` intent carrying the domain, the addresses, the mailboxes and the site owner |
| `journal.jsonl` | modified | one line per group transition |

Outside the store, the drain writes `/etc/mail/mail_domains`, `/etc/mail/virtuals`, the DKIM filter's domain list, the generated index entries, the certificate config and its `include`, the mailboxes' login class, and each account's `authorized_keys`.

## Testing decisions

The seam is the group, because a defect there provisions the wrong set of accounts or the wrong renewal date. Four behaviours are worth a test each.

Applying one group intent twice leaves one account per mailbox, one virtual entry per address and one certificate request, which is the property a retry after a crash depends on. An alias and the mailbox it points at deliver to one account and one key, and removing the alias leaves the mailbox untouched. Removing one mailbox from a group removes exactly its account, its key and its virtual entries, and leaves the group's paid-until date and every other account unchanged. A certificate request for a name whose A record does not resolve is not attempted, so the identifier's authorization-failure budget is not spent before the body's records exist.

## Out of scope

The managed instance tier, which the operator orders by hand. Hosting the body's DNS zone, which the proposal defers and the recipe states. Per-domain DKIM keys, which would need a filter process per key. Catch-all addressing on a body's domain, which the ten-address cap does not admit. The terms and privacy notice, where the business-customer cancellation position and the VAT mechanics live. The site copy, which the hosting page's workstream owns.

## Sources

- [`organisation-accounts.md`](../research/organisation-accounts.md): the `virtual` table, the aliases-file collision, the shared DKIM key, the group record, and the body's certificate spending its own budget, read 2026-10-01.
- [`openbsd-per-member-hosting.md`](../research/openbsd-per-member-hosting.md): the generated index files, the chroot shape, the quota mechanics, and the port split, read 2026-10-01.
- [`cert-issuance-ceiling.md`](../research/cert-issuance-ceiling.md): the 50-per-registered-domain limit, the 202-minute refill, and the authorization-failure limits, read 2026-10-01.
- [`dns-nsd-he-mail-records.md`](../research/dns-nsd-he-mail-records.md): the MX, SPF, DKIM, DMARC and reverse-DNS record set, read 2026-10-01.
- [`mail-pricing-landscape.md`](../research/mail-pricing-landscape.md): the flat per-domain price and the rejection of per-address pricing, read 2026-10-01.
- OpenSMTPD `usr.sbin/smtpd/aliases.c`, `aliases_get()` and `aliases_virtual_get()`, https://raw.githubusercontent.com/openbsd/src/master/usr.sbin/smtpd/aliases.c, read 2026-10-01.
- `man filter-dkimsign`, `man aliases`, `man smtpd.conf` and `man acme-client` on OpenBSD 7.9, read 2026-10-01, cited in the research notes above.
- OpenBSD `login.conf(5)` and `sshd_config(5)`: the session shell comes from the account's login class rather than its password entry, and a forced command is exec'd through that shell, read 2026-10-05, the mechanism the SSH onboarding TUI spec ([#245](https://github.com/kyriakon/kyriakon-infra/issues/245)) applies to the onboard account.
- RFC 5321 section 5.1 (MX), RFC 7208 section 4 (SPF), RFC 6376 sections 3.6.1 and 3.6.2.1 (DKIM selector and key placement), RFC 7489 section 6.3 (DMARC), RFC 1035 sections 3.3.12 and 3.3.13 (PTR and SOA).
- Let's Encrypt, Rate Limits, last updated 5 August 2026, https://letsencrypt.org/docs/rate-limits/, read 2026-10-01.
- Repo files at this commit: `openbsd/etc/smtpd.conf`, `openbsd/etc/httpd.conf`, `openbsd/etc/gmid.conf`, `openbsd/etc/acme-client.conf`, `openbsd/etc/sshd_config`, `scripts/add-user.sh`, `scripts/renew-acme.sh`, `scripts/deploy-mail.sh`, `kyriakon-encrypt/src/lib.rs`.
- `kyriakon/docs/decisions/0009-payment-records-keyed-by-token.md` and the project proposal sections 5.6, 5.9, 6.5 and 6.13, cited in the research notes above.
