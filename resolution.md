Note landed on `research/organisation-accounts` in #191: `docs/planning/research/organisation-accounts.md`.

## Headline findings

1. **A parish's own domain is small in `smtpd`, but the address mapping is the real change.** Mail for a second domain is a line in the `mail_domains` table, which already takes a table. Per-address mapping is the problem: `/etc/mail/aliases` is keyed on the localpart with no domain (`aliases_get()` in `usr.sbin/smtpd/aliases.c`), so two parishes both wanting `secretary` collide, and `who@theirdomain` cannot be distinguished. OpenSMTPD has the right primitive, `virtual <table>` on the action, whose lookup tries `user@domain`, then `user`, then `@domain`, then `@`. `alias` and `virtual` cannot both be set on one action (`smtpd -n -f` on a copy under `/tmp` returned `alias mapping already specified for this dispatcher`), so the own-domain tier trades the global aliases file for a virtual table and moves the system aliases into it.
2. **DKIM is one key per filter process.** `filter-dkimsign(8)` takes one `-k` key and may take several `-d` domains, picking the From domain and falling back to the first. A key per parish domain would need one filter process per key on the same listener, and each would still sign everything it sees. The smallest correct shape shares one key across the platform's domains, published at the same selector in each, which also keeps rotation to one operation.
3. **Shared mailbox and shared key are free; separate mailboxes are not.** The encryptor resolves `<localpart>.asc` per save with no cache, and alias or virtual expansion happens before LMTP, so any number of addresses on one account share one mailbox and one key, and the published key set stays one file per account. Zero-access is unaffected. What a shared mailbox costs is granularity: everyone holds the same private key, and the encryptor encrypts to exactly one cert per recipient, so two people needing separate keys for one mailbox is a code change, not a config one.
4. **Account shape decides quota, chroot, backup and names.** Several shell-less accounts give per-person revocation and attribution, but N five-gigabyte per-uid quotas, N public subdomains and N reservations; a group quota via `edquota -g` with the parish group as primary group gives one allowance instead. The sftp chroot is per account (`/home/%u`), so a shared site root lives in exactly one account and one credential uploads it. Backup (`/home` and `/etc/mail`, restic) costs nothing extra; deletion, lapse and the paid-until date stay per account.
5. **The service needs a group, not several subscriptions.** One approval, one Stripe Subscription, one `client_reference_id` for the organisation. ADR 0009's split still holds, with payment state on the group and each account referencing it, so one renewal writes one paid-until date instead of N that can drift. The ledger is unchanged: one token per subscription, one row per payment, no name.
6. **The parish's certificate spends the parish's budget.** HTTP-01 only, so the parish's A/AAAA must point at the box on port 80 at issuance and stay there. Let's Encrypt's own Rate Limits page (read 2026-10-01) puts 50 new certificates per registered domain per 7 days, refilling one per 202 minutes. Issuing for `parish.example` therefore spends that domain's fifty, not `kyriakon.net`'s, so the own-domain tier does not eat the platform's onboarding ceiling. Renewals with the same identifier set are exempt. The risk is the parish's DNS failing, which blocks orders after five authorization failures and can pause the identifier until a human unpauses it.

## Smallest design that carries one parish

- One account (`parish`) for the shared mailbox and the site. Additional accounts only for people who need private mailboxes, each with its own key file, reservation and quota line.
- The domain added to `mail_domains`; the action switched from `alias` to `virtual` with one entry per address, and the system aliases as per-domain or catch-all entries in the same table.
- One site root in the parish account's home, one vhost per name, uploaded with that account's sftp credential or its git repo.
- One certificate for the domain (with `www` as an alternative name, one order) and the handle added to, or discovered by, `scripts/renew-acme.sh`, which currently hardcodes three handles.
- One subscription, one token, one paid-until date on the group; a `parish-<slug>` group and group quota if the org gets one allowance rather than five gigabytes per account.
- DKIM on the platform's existing key at a selector in the parish's DNS to start with.
- The parish applies its own records: A/AAAA, MX 10 at the platform's mail hostname, SPF, DKIM TXT, DMARC. The platform does not host their zone (proposal section 6.13).

Nothing in it grants a shell: `/sbin/nologin`, chrooted `internal-sftp`, `git-shell`.

## Monthly attention

In the steady state, about what one individual account costs: a line in the daily cron mail only if a renewal fails. The rest is event-driven, not monthly: an org-level change (add/remove a person or address), the parish's DNS failing (mail and the certificate renewal both break, and the platform can only observe it), a lapsed subscription dropping the whole group read-only and starting the 40-day reach out, and the one-off setup session per parish (records with their DNS operator, vhosts, certificate, accounts, DKIM record). Nothing is per message or per address; disk is about 3.6p per gigabyte per year, so the price is a question about attention and support, not storage.

## Not verified against the box or a man page

- `smtpd -n` against the deployed `/etc/mail/smtpd.conf`: mode 0600 root and `doas` needs a password, so it was neither read nor checked. All syntax checks ran against a copy of the repo's file under `/tmp`, which does not prove the deployed file matches the repo.
- That one `filter-dkimsign` process signs all its `-d` domains with the single `-k` key: inferred from the synopsis (one `-k` file), not stated in the prose and not exercised. No mail was sent.
- The behaviour of two filters chained on one listener (the extra signature under the fallback domain): read from the man page's fallback rule, not tested.
- Every quota and group-quota enforcement claim: quotas are off on `/home`, enabling them needs root and an `fstab` change on a live box, and no account was created.
- That `httpd` and `gmid` accept the parish vhost and certificate shapes as described, and that the hosting design's move of their chroot from `/var/www` to the tree holding member homes lands as written.
- The onboarding service's flat-file state and root drain: taken from the ticket, not written in this repo; `kyriakon-onboard` holds only docs today.
- The 50-per-registered-domain arithmetic is only as exact as the Public Suffix List: a parish on a suffix such as `.co.uk` would be measured at the higher registered domain.
- Anything needing root: creating accounts, enabling quotas, reloading `smtpd`/`httpd`, issuing a certificate.
