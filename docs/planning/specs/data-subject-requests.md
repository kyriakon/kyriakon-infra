# Data-subject requests in the onboarding service

> Spec synthesised from [Spec the data-subject request path](https://github.com/kyriakon/kyriakon-infra/issues/241) and the decisions it rests on: [#153](https://github.com/kyriakon/kyriakon-infra/issues/153) (the lifecycle states and the automated deletion), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156) (the handler and drain split, the flat-file state and the operator surface), [#159](https://github.com/kyriakon/kyriakon-infra/issues/159) (the flow and the account page) and [#163](https://github.com/kyriakon/kyriakon-infra/issues/163) (the EU consumer position, which set the requirement that this be a script). ADR 0009 in the sibling meta repository carries the payment-record split the deletion answer depends on, and the retention schedule is section 5 of `docs/planning/research/sole-trader-obligations.md`.

## Problem statement

A member can ask for a copy of what the platform holds about them, or ask for that data and the account to be erased, and the platform has to answer inside the law's clock from a box whose mail it cannot read. The request can arrive while the member is logged into the account page, or after they have lost the password, the mailbox, or both. It has to be answerable by an operator running a script rather than by hand, because [#163](https://github.com/kyriakon/kyriakon-infra/issues/163) decided that export and delete stay on the account page and everything else is a script with a written record.

Two facts shape the answer. The mail is ciphertext to a key the platform does not hold, so an export cannot be a readable archive; the platform can only hand over what it already has in the form it is stored. The platform's own record of the member is also small and machine-written, and most of it is about the account rather than its contents, so the export is a set of documents and a manifest rather than a copy of the mailbox.

## Solution

Two entry points answer everything. The account page carries the member's own export and their own account closure, because those are the two a logged-in member can set going themselves. Everything else, including a request from someone who cannot log in and every request from a Union member, goes through `onboardctl`, run by the operator, with one written record per request.

The export is the platform's record of the member, written into the member's own tree where the sftp they already have can collect it, plus the tree itself, which they pull at the same time. The platform decrypts nothing and copies nothing it does not have to. Deletion reuses the lifecycle's automated deletion from [#153](https://github.com/kyriakon/kyriakon-infra/issues/153) and adds no second path: the account page's closure and an operator's erasure request both end in the same transition, and both say the same things about what survives.

Every request is recorded with its date, the evidence that established who was asking, what was done, and the date the answer is due. That date is one month from receipt under [Article 12(3)](https://www.legislation.gov.uk/eur/2016/679/article/12/adopted) and, in the UK version as it now stands, [Article 12A.](https://www.legislation.gov.uk/eur/2016/679/article/12A.)

## What an export contains

The export has two parts, and separating them keeps a mailbox of gigabytes out of a bundle the platform would otherwise have to copy to hand over something it cannot read.

The written part is built from one account directory and the token that account references. It holds `account.json`, the member's own document, with the state, the contact and recovery addresses, the key fingerprints, the rail and token reference, the paid-until date and the approval decision. It holds `notices.jsonl`, every notice sent, when, and to which address. It holds `application.json`, the answers the member wrote, while they are still inside the 90-day purge from ADR 0005; once purged there is nothing there, and the manifest says so rather than leaving a silence. It holds the account's lines from `journal.jsonl`, one per transition. It holds the keyring entry `keys/<localpart>.asc`, the member's public key as published, together with the fingerprints the account carries for it. And it holds the payment lines for the account's token, selected from `ledger/payments.jsonl`: the token, the amount, the date, the rail and the paid-until date each line produced. The token is the only join and it exists while the account does, which is what makes this a selection for one member rather than a slice of the ledger.

The other part is the member's tree: the Maildir, the git repositories, and the web and Gemini roots under `/home/<username>`. The export neither copies nor touches them. They are the member's, they are reachable over the sftp the member already has, and copying them into a bundle would not change the one fact that matters, which is that the mail is ciphertext to a key the platform does not hold. The manifest names the paths and says the member pulls them; the platform's part is to leave them exactly as they are.

## What is deliberately left out

Three things are not in the bundle, and the written answer says so rather than letting silence imply an exhaustive record.

The operator's own mailbox holds the member's application email, and with it the member's own words. It is not part of the export. It is the operator's correspondence, encrypted to the operator's key, and the application purge in ADR 0005 is what bounds the text in it. A member who wants their own words back is told where they are, and is not given a second copy of them in the bundle.

The per-user log records, the smtpd envelope line, the Dovecot authentication line, sshd and nsd, live seven days and are gone after that. `openbsd/etc/newsyslog.conf` rotates `maillog`, `authlog` and `nsd.log` weekly with seven generations and nothing keeps the raw per-user record beyond it, so the export does not reconstruct the logs and a request that arrives inside the seven days does not turn a log into a records store.

Nothing about another member can be in the bundle, because nothing is selected that is not reached from this account's directory or from this account's token. One Maildir, one set of repositories and one pair of site roots belong to one account, and the boundary is the account.

Nothing in the platform's own record is withheld either. The mail the platform cannot read is not a redaction; it is handed over in the form it is stored, and the member opens it with the key they already hold.

## How the bundle reaches the member

A member already has sftp on their own tree, so that is the delivery path. `onboardctl export <username>` writes the written part under the member's chroot at `/home/<username>/export/<timestamp>/`, owned by the member, and records a notice that says it is ready. Over sftp it appears inside the chroot as `export/<timestamp>/`, beside the `www/` and `gemini/` the member already uploads to, and they collect it with the client they already use and pull the rest of the tree at the same time. Nothing here needs a terminal, a signing key, or PGP knowledge beyond opening the mail they already read, and the platform does no work proportional to the size of the mailbox.

Where the member cannot log in but still holds the key, the operator can send the small written part the way a notice is sent, as an attachment encrypted to the member's public key with the same encryptor that encrypts their mail, and the member opens it in their own client before the login is restored. Where the member cannot log in and cannot produce the key, the mail is unreadable to them too, and the platform holds no key that would open it. What can still be reached is the written part and the login, through the password path in `docs/runbook.md`, and the answer says which parts are reachable rather than promising the whole.

## What deletion does

An erasure request goes through the lifecycle's automated deletion and no second path. On the account page, "Close my account" puts the account into the `closing` state; the account works normally for seven days so the member can take the export and their tree, and the day the window ends the drain runs the deletion transition. The operator's `onboardctl delete <username>` runs the same transition and is what an erasure request from anywhere other than the page uses. There is no erasure the page can start that the script cannot, and no second deletion script.

The transition removes what the runbook's sequence removes: the OS account and its home, which takes the Maildir, the repositories and the site and capsule roots; the keyring entry on the box and in `keys/`; the per-member vhost files and their include lines; the certificate and its files; the quota entry; the account's store directory with its `account.json`, `notices.jsonl`, `application.json` and token index entry; and the finger page, regenerated. Reusing the deletion means this path inherits those steps and the tests that prove them.

The written answer says three things about what survives, because silence would read as an instant and total delete.

The backup repository is one. `scripts/backup.sh` holds `/home` and `/etc/mail` in an encrypted, content-addressed restic repository, pruned with `restic forget --keep-daily 30 --keep-weekly 8 --keep-monthly 6`. A content-addressed repository cannot target-delete one member's files, so erasure there is the snapshot expiring: the oldest kept snapshot is the last one of the month six months back, so a deleted home can survive in the repository for about seven months, and the answer names that window. The retention schedule in `docs/planning/research/sole-trader-obligations.md` section 5 is the source, and `docs/planning/research/encrypted-backup-restore.md` records the reasoning.

The payment ledger line is the second. The financial ledger is keyed by the approval token and holds the amount, the date, the rail and the paid-until date, with no username, no contact address and no name (ADR 0009). Removing the account removes the token index, the only record that joined the token to a person, so the surviving line is a dated payment that no longer resolves back to anyone. It survives because HMRC requires a sole trader's records for [five years after the 31 January submission deadline](https://www.gov.uk/self-employed-records/how-long-to-keep-your-records) for the tax year, and [six years once VAT is registered](https://www.gov.uk/charge-reclaim-record-vat/keeping-vat-records), which is longer than anything else the platform keeps.

The username is the third. It is held for 90 days and then released, so a returning applicant applies as a new applicant and a correspondent's old address does not land in a stranger's mailbox by accident.

Deletion and refund are separate answers. A closure inside the [14-day cancellation right](https://www.legislation.gov.uk/uksi/2013/3134/regulation/30) carries a full refund on the prepaid rails' path; a refund of an overpayment or a duplicate does not touch the account. The erasure answer says which of the two the member is getting.

## How a request arrives and who is asking

On the account page the member is already authenticated, and the closure re-enters the password regardless of how fresh the session is, because it is the irreversible one. The password is checked against the real system account through `doveadm auth test`, so the service holds no copy of it. What reaches the drain is an intent for one export or one close, carrying the account the session belongs to and nothing else.

Off the page, a request arrives as mail to the role address, `admin@kyriakon.net`, which is the address the lifecycle notices already come from. The hard case is a sender who cannot log in and whose identity has to be established from what they hold rather than from what they remember. The mail key is that evidence. A message from the account's own `@kyriakon.net` address, signed by the private key the platform already encrypts to, verifies against the public key already in the keyring. A valid signature shows the sender holds the key that opens the mailbox, and it asks no more of them than the signing button in the client they already use.

Where the signature does not verify, or the message comes from the outside contact address, the operator asks for what is missing: a signed message from the account address, or the password through the page. Where neither can be produced, the operator cannot confirm it is the member, says so, and does not answer as though identity were established. Where the member still holds the key but cannot log in, the operator can put the login back through the runbook's password path once the signed message has shown the account is theirs. The platform adds no identity scheme of its own here; it uses the password it already checks and the key it already holds, and the record names which of the two was used.

## What gets recorded

Every request gets one append-only line in the account's store directory, `requests.jsonl`, written by the drain whether the request came from the page or the script. The line holds the date received, the kind, the evidence that established who was asking, what was done and on what date, how the bundle was delivered where there was one, and the date the answer is due. The kinds are access or portability, erasure, and rectification.

The due date is one calendar month from receipt. [Article 12(3)](https://www.legislation.gov.uk/eur/2016/679/article/12/adopted) requires the controller to answer "without undue delay and in any event within one month of receipt of the request", extendable by two further months where a request is complex. The UK version as it now stands reads the same period through [Article 12A.](https://www.legislation.gov.uk/eur/2016/679/article/12A.), inserted by [section 76 of the Data (Use and Access) Act 2025](https://www.legislation.gov.uk/ukpga/2025/18/section/76) and in force from 5 February 2026: one month from the "relevant time", which is the latest of receipt, the identity information the controller asks for, and any fee. The seven-day closing window sits well inside the month, so the deletion path's own wait is not an obstacle to answering within it.

The record is the member's data, so it goes out with a later export and it is removed by the deletion. That is deliberate. A permanent, by-name log of who asked for what would be the long-lived personal record that [Article 5(1)(e)](https://www.legislation.gov.uk/eur/2016/679/article/5) and ADR 0009 both push against, and the lifecycle's transition journal is where the fact that an account was deleted is recorded, not a new file. The journal's own retention is the lifecycle's, and this spec does not change it.

## The two entry points

The account page carries two controls: "Take my data out", which files an export intent, and "Close my account", which files a close intent, starts the seven-day window, and requires the password re-entered because it is the irreversible one. The handler holds no privilege and does nothing but validate the session and file the intent; the drain does the work on its next run, within a minute.

Everything else is the operator's, through `onboardctl`, in the shape the other commands already use:

```
onboardctl export <username>
onboardctl request list
onboardctl request record --username <u> --kind <access|erasure|rectification> \
  --received <date> --evidence <text> --note <text>
onboardctl request close <id> --done <date> --note <text>
onboardctl delete <username>
```

`export` writes the bundle into the member's tree. `request record` writes the line and prints the date the answer is due. `request close` writes what was done, and `request list` shows what is open and what is nearly due. `delete` is the lifecycle's existing command, and this spec adds no flag to it and no second deletion path.

The privilege boundary is unchanged. The export and the deletion run in the drain, which already provisions accounts, owns the store and writes to the member's home. The script reads one account's directory and the ledger lines for one token, and it never reads the Maildir, which it could not read anyway. The handler gains no file access, and the export intent carries the account from the session and nothing the caller supplies.

## State

Paths are relative to the store root, except the export destination, which is in the member's home.

| Path | Status | What this adds |
|---|---|---|
| `accounts/<username>/requests.jsonl` | new | one line per request, with its date, evidence, action and due date; deleted with the account |
| `intents/<id>.json` | modified | new kinds `export` and `close`; the body names the account and nothing else |
| `journal.jsonl` | modified | one line per request transition, as for every other transition |
| `/home/<username>/export/<timestamp>/` | new | the written part of an export, owned by the member, collectable over sftp, removed with the home |

## Out of scope

The wording of the privacy notice's data-request section belongs to [#235](https://github.com/kyriakon/kyriakon-infra/issues/235), though the one-month deadline and the contact route recorded here are what it states. The Article 27 representative line, which [#163](https://github.com/kyriakon/kyriakon-infra/issues/163) decided is needed, is placed by the same ticket. The rectification mechanics, beyond recording the request and answering it, are undecided. The handling of the operator's own mailbox is ADR 0005's. And the accountant still has the question ADR 0009 leaves open, whether HMRC accepts a payment ledger that becomes permanently unlinkable once the account is deleted.

## Further notes

Two facts are worth carrying into the build. The platform never decrypts, so every path that touches mail touches ciphertext and nothing in this workstream can change that. And the ledger line is the only record that outlives the account, so the token on it has to stay the random string it is; a token that could be recomputed from the account would turn a surviving payment record back into a named one and undo the point of the deletion answer.

One thing could not be settled from the record and is named rather than invented: the retention of the transition journal after an account is deleted. If the journal keeps a username forever, the promise that a deleted member's account leaves no long-lived personal record is weaker than it reads, and the lifecycle reconciliation in [#169](https://github.com/kyriakon/kyriakon-infra/issues/169) is where that is answered.

## Sources

Read on 2026-10-05.

- [Article 12(3) as adopted](https://www.legislation.gov.uk/eur/2016/679/article/12/adopted), for the one month and the two-month extension.
- [Article 12A.](https://www.legislation.gov.uk/eur/2016/679/article/12A.) and [section 76 of the Data (Use and Access) Act 2025](https://www.legislation.gov.uk/ukpga/2025/18/section/76), for the UK "applicable time period" and the "relevant time" in force from 5 February 2026.
- [Article 5(1)(e)](https://www.legislation.gov.uk/eur/2016/679/article/5), storage limitation, [Article 15](https://www.legislation.gov.uk/eur/2016/679/article/15), the right of access, and [Article 17](https://www.legislation.gov.uk/eur/2016/679/article/17), the right to erasure.
- GOV.UK, [business records if you are self-employed](https://www.gov.uk/self-employed-records/how-long-to-keep-your-records) and [keeping VAT records](https://www.gov.uk/charge-reclaim-record-vat/keeping-vat-records), for the five and six year figures.
- `docs/planning/research/sole-trader-obligations.md` section 5, the retention schedule and the backup window, and `docs/planning/research/encrypted-backup-restore.md`, the content-addressed repository reasoning.
- `docs/runbook.md`, the deletion sequence, and the password and lost-key paths.
- ADR 0005, the 90-day application purge, and ADR 0009, payment records keyed by a token (accepted 2026-09-30), in the sibling meta repository.
- Issues [#153](https://github.com/kyriakon/kyriakon-infra/issues/153), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156), [#159](https://github.com/kyriakon/kyriakon-infra/issues/159), [#163](https://github.com/kyriakon/kyriakon-infra/issues/163) and [#169](https://github.com/kyriakon/kyriakon-infra/issues/169) in this repository.
