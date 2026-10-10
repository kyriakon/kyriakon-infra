# The release's web form and account page

> Spec synthesised from [Spec the release's web form and account page](https://github.com/kyriakon/kyriakon-infra/issues/274) and the decisions it points at: [#159](https://github.com/kyriakon/kyriakon-infra/issues/159) (the flow end to end, the three outcomes, payment following approval), [#233](https://github.com/kyriakon/kyriakon-infra/issues/233) (the application questions and the community block), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156) (the service's architecture and its trust boundary), [#153](https://github.com/kyriakon/kyriakon-infra/issues/153) (the lifecycle and what each state does), [#114](https://github.com/kyriakon/kyriakon-infra/issues/114) (the token, the rails and the payment window), [#151](https://github.com/kyriakon/kyriakon-infra/issues/151) (the card rail), [#152](https://github.com/kyriakon/kyriakon-infra/issues/152) and [#235](https://github.com/kyriakon/kyriakon-infra/issues/235) (the documents and their acceptance), [#177](https://github.com/kyriakon/kyriakon-infra/issues/177) and [#188](https://github.com/kyriakon/kyriakon-infra/issues/188) (the free path and the tiers), [#187](https://github.com/kyriakon/kyriakon-infra/issues/187) (the hostname), [#163](https://github.com/kyriakon/kyriakon-infra/issues/163) (the Union gate), [#182](https://github.com/kyriakon/kyriakon-infra/issues/182) and [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) (the no-oracle rule and the front-ends), [#176](https://github.com/kyriakon/kyriakon-infra/issues/176) and [#185](https://github.com/kyriakon/kyriakon-infra/issues/185) (the key walkthrough), [#169](https://github.com/kyriakon/kyriakon-infra/issues/169) (what the proposal's text drifted from), and the specs `prepaid-rails.md`, `data-subject-requests.md`, `own-domain-tier.md`, `ssh-onboarding-tui.md`, `gemini-capsule.md` and `per-member-hosting.md`.

## Problem statement

The release ships the web form. It is the one workstream the destination names that has no spec: seven files sit in `docs/planning/specs/` and none of them covers the applicant-facing form, the approval step, or the account page a member uses afterwards. Every decision those need has been taken, across some twenty tickets and a prototype, so the work here is not deciding what the form is. It is writing down the one document a build can be cut from, in a form where each part names the ticket it rests on.

Two consequences follow. A build of the web form has no contract to implement, so the release's own front door is the least specified thing in the repository. And the intent API that `ssh-onboarding-tui.md` and `gemini-capsule.md` already point at, deferring its shape to the service workstream, is defined nowhere: both front-ends post into a back end that no document describes, so three front-ends would invent three shapes unless the shape is fixed once, here.

The decisions this spec rests on are treated as given and are not reopened: the five lifecycle states ([#153](https://github.com/kyriakon/kyriakon-infra/issues/153)), the rails' own mechanics (`docs/planning/specs/prepaid-rails.md`), the export and close paths (`docs/planning/specs/data-subject-requests.md`), the per-member hosting build (`docs/planning/specs/per-member-hosting.md`), the tier set ([#188](https://github.com/kyriakon/kyriakon-infra/issues/188)), the hostname ([#187](https://github.com/kyriakon/kyriakon-infra/issues/187)), and the two front-ends to come (`docs/planning/specs/ssh-onboarding-tui.md`, `docs/planning/specs/gemini-capsule.md`).

## Solution

**One service, two halves split by privilege.** The handler is a Rust service (`axum`) listening only on loopback, with `relayd` terminating TLS for `signup.kyriakon.net`, which is the fixed hostname for both the form and the account page ([#187](https://github.com/kyriakon/kyriakon-infra/issues/187), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156)). It holds no privilege and no secrets: it validates, renders, writes one JSON intent file, and writes a webhook's raw body and signature header when one arrives, which is the third thing the runbook's own description of the handler names. The drain is a root cron job, running every minute with an hourly sweep, that reads Stripe's signing secret and the keyring publish token from `/etc/kyriakon/onboard/`, verifies and deduplicates what it finds, and carries each transition out through the repository's own scripts. Between them sits the intent directory, which is the privilege boundary, so every intent field is validated at least as strictly as a `doas` rule would have been.

**One applicant page, one account page.** The applicant's half is a single page of four sections with a conditional block for a body; the member's half is the bounded page proposal section 5.9.1 describes, and nothing more. Both are rendered by the handler, which reads the store and holds no privilege over it.

**Three front-ends, one intent writer.** The web form and the SSH TUI reach the same handler over loopback and the gemini capsule reaches it through gmid's FastCGI unix socket, so the service has one writer and the platform has one back end. None of the three holds privilege, and none may grow its own privileged path.

### The applicant's half

One page, four sections, and a conditional community block that opens from a single question: whether the application is for the applicant or for a body ([#233](https://github.com/kyriakon/kyriakon-infra/issues/233)). The order is the prototype's, and the copy is the prototype's, adopted rather than rewritten; the spec at the end names where that copy is to live.

**You.** The username; the person-or-body question; a VAT number, optional and only where the application is for a business, because it is what makes a Union business supply a reverse-charge supply; an address outside the platform, optional, with the acknowledgement when it is left empty.

The mail password is not asked here. [Decide what the public release promises, and where](https://github.com/kyriakon/kyriakon-infra/issues/158) lists the form's fields without a password among them, [#182](https://github.com/kyriakon/kyriakon-infra/issues/182) rules out finishing an application on a browser, and `docs/planning/specs/gemini-capsule.md` records the seam and leaves the decision to this spec, which owns the account page. So: the account is created with no usable password, the decision email carries a one-time link that sets one, and the status page carries the same link for an applicant who gave no address outside the platform. It is the signed-link mechanism the approval already uses, and it is the only place a password is chosen.

**Your mail key.** The applicant's public mail key, generated in the browser by the walkthrough, of which only the public half is submitted. An optional upload key, needed only for a website or repositories.

**How you will pay.** One rail chosen from card at £20 a year, cash by post, Monero, or no charge, the last being how a person who cannot pay asks ([#177](https://github.com/kyriakon/kyriakon-infra/issues/177)).

**What to tell us about you.** All optional except the elder's or confessor's blessing, which is required for a monastic. The free-text box asking a person who cannot pay to say so is what the free path turns on: it is read by a person, on the same evidence and at the same moment as any other application, with no means test and no proof asked for.

**The community block**, shown to a body: its name and kind, its domain and the checkbox that it can add the DNS records the platform will ask for, a table of up to ten addresses naming for each one whose it is, whether it is its own mailbox or an alias into one, and its account name, a mail key per mailbox, an optional upload key for the domain's website, and an optional DNS contact. An alias shares the mailbox and therefore the key of the address it points at; a mailbox of its own gets its own key and its own 5 GB. Delivery fails closed without a key, since a mailbox that cannot receive mail is not an account.

**Validation, and the one rule that shapes it.** The username must fit the charset `scripts/add-user.sh` enforces, lowercase letters, digits, dot, underscore and hyphen, starting with a letter or a digit and no longer than 32 characters. It must not be a reserved name, and the front-end never checks whether it already exists ([#182](https://github.com/kyriakon/kyriakon-infra/issues/182)). The reviewer's view flags a reserved or taken name, approval waits until another is supplied, and the drain refuses the intent if a collision reaches it anyway. The reserved set includes every hostname the platform uses, among them `mail`, `www`, `kleio`, `press` and `signup`, and lives in one file the three front-ends share rather than three copies of a list.

**The questions are data, not code.** One ordered file owned by the service workstream, read by all three front-ends. Each entry carries an id, the prompt, its answer type, the branch it belongs to, meaning whether it is shown for a person, a body or a monastic, whether it is required, and its validation. The web form renders it, the capsule renders it, and the TUI asks it in order; the file is the only place the list exists. Its schema is fixed here so the two existing front-end specs have something to read. The form it takes: one tab-separated record per line, in display order, under a header naming the columns, `id`, `prompt`, `type`, `branch`, `required` and `validation`. The type is one of `text`, `choice`, `yesno`, `multiline`, `addresses`, `key` and `acceptance`; the branch is one of `person`, `body`, `monastic` and `all`; required is `yes` or `no`. A validation names a rule each front-end implements rather than carrying an expression, so a rule added for one front-end has to be added to all three: `none`, `username`, `address`, `mail-key`, `upload-key`, `maxlen:<n>`, and `choice:<value>=<label>` with the pairs pipe-separated, which is where a choice question's answers live, because a file holding only the prompts would put the answers in three places again.

**Rate keeping, so the form is not a weapon.** Sixty requests a minute and five drafts a day per address, counted by the handler. There is no CAPTCHA and no challenge: a person reads every application, and that is the gate.

**Two checkboxes, recorded separately.** The first, at the application, accepts the terms, the acceptable use policy and the privacy notice. The second, before payment, records the request for immediate supply and the digital-content acknowledgement ([#152](https://github.com/kyriakon/kyriakon-infra/issues/152)). The refusal list is linked and stated, never accepted. Each acceptance records the version accepted, which is the date and short commit of each document, and that record is what the confirmation email quotes.

**Submitting files an application intent** and answers with the status link, which is a 128-bit capability in the path, the same one the capsule and the TUI issue, separate from the payment token. The status page answers for seven days after a decision. It is the durable thing for an applicant who gave no address outside the platform, and its token is never a username oracle either: an unknown token and an expired one read the same.

### Approval

One person reviews, and the whole application reaches them in one email so the decision can be made from a phone. That email carries every answer the applicant gave, the mail-key check result, whether an upload key was supplied, the rail, and whether the no-charge path was asked for, with three signed one-click links and the `onboardctl` equivalents. The links are signed by the drain, which holds the key under `/etc/kyriakon/onboard/`; the handler passes a click through as an intent and the drain verifies the signature, so a replay finds the application already decided and takes no action, which is the deduplication `prepaid-rails.md` asks for and needs no nonce store of its own. A reviewer action, not a form field, checks the sanctions list; an application from a resident of a country under UK sanctions is declined there. A body's application has one further check, that its domain resolves.

The decision is one of three: approve paid, approve without charge, or decline. The same person makes the free judgement at the same moment on the same evidence, on the applicant's own words, and the account records only that it is free and never why.

**Declining** gives no reason and always offers the way back. The application is held for a week, then purged and the username released. A monastic decline is the one exception: its message names what is missing, because what is missing is a conversation.

**Approval provisions the account and opens the mailbox**, and payment follows. This is the sequence the tickets fixed against the proposal's older text: there is no waiting for an account to exist, because mail is what the account is for.

**The confirmation email goes out before the account is created**, so that the record of what was agreed exists before the service begins. It restates the request for immediate supply and the digital-content acknowledgement, names the version of each document accepted by date and short commit, states the 14-day right plainly with how to use it, and carries no attachments. The account's own notice, with its address and what works now, follows provisioning.

**A paid approval draws the token** and opens the payment window; an approval without charge draws none. The token is drawn from `getrandom` at approval and written into the new account, never derived from anything about the member, and never logged or placed in a URL that `relayd` will log, because it is a bearer secret.

**A body's approval** additionally issues the domain's records and its mailboxes rather than one address, as its own `provision-group` step.

### The payment handoff

The card rail is one yearly Price with a Subscription Stripe renews ([#151](https://github.com/kyriakon/kyriakon-infra/issues/151)). Its signup path is a **Payment Link** with `client_reference_id` set to the application's identifier, not a Checkout Session, because a session URL expires within 24 hours and an emailed link has to outlive the email. Stripe creates the Customer, because subscription mode requires one.

Provisioning already happened at approval, so the card events do not create accounts. `checkout.session.completed` attaches the subscription and nothing else, because `invoice.paid` is the single event that sets or extends the paid-until date. Both arrive for a first payment, they name different objects so a deduplication keyed on the event id cannot see that they are one payment, and the date computed as the later of today and the current date plus a year would land a first payment 24 months out, which `prepaid-rails.md` refuses as a credit without an override. `invoice.paid` extends the date `invoice.paid` extends the date **after retrieving the subscription and confirming it is active**, since a paid invoice does not prove an active subscription; `invoice.payment_failed` records the attempt with its count and the next attempt; `customer.subscription.updated` and `deleted` reconcile; `invoice.upcoming` is the hook for the annual reminder. Stripe owns the dunning itself, including the retry policy and the recovery end state, which are dashboard settings and not service code. Every webhook is verified by HMAC-SHA256 over the raw body, in constant time, within a five-minute tolerance, against a per-endpoint secret, and an unverified or replayed request must never provision, extend a date, add a key or mark a payment received.

The prepaid rails have no Stripe object at all. Credit, receipt and reconciliation live on this machine, recorded by the drain from an intent or from the operator's own reconciliation.

**The paid-until date is ours.** Stripe reports, it does not rule. A subscription in `past_due` with a date still in the future keeps access, `cancel_at_period_end` runs to the period's end, and a missed webhook is repaired from the API rather than from the event stream.

**The window.** A paid approval opens 14 days with `paid_until` null. Paying sets the date. If the window closes with nothing paid, the account lapses: mail arrives and stays readable, everything already published stays up, and what stops is sending from the address, uploading to the site and pushing to git. Paying restores it. Forty days of grace follow, ending in automated deletion.

**The free path** has no window, no token, no paid-until date and nothing in the ledger. It never lapses, the sweep skips it, and one notice a year records that it is still free.

### The intent API

This is the part no earlier document fixed, and the part the two other front-end specs defer to. It is decided here.

**A record is one JSON file at `intents/<id>.json`.** The id is a ULID, which is this spec's choice, so the directory sorts by age; the ledger's example in `prepaid-rails.md` is ULID-shaped, which is where the shape came from. The file is written by rename, so a reader never sees half of one.

**The transport has two hops.** A front-end posts to the handler, the web form and the TUI over loopback and the capsule through gmid's FastCGI unix socket, and the handler writes the file. The handler never posts to the drain: the drain reads the directory. The record's fields are validated on the way in, as strictly as a privilege boundary demands, and validated again by the drain before anything is carried out.

**An application intent holds:** its id; its kind; when it was filed; which front-end filed it; the application it concerns, by username and status token, since `applications/<token>.json` is the store's own key; the domain where there is one; the address outside the platform where one was given; the answers, keyed by the question list's ids; the mail keys and the optional upload key as fingerprints with their material; the rail chosen; whether no charge was asked for; the acceptance records, each with its document versions; and the version of the question list it was answered against.

**Every other kind carries a payload whose shape the owning spec fixes**, which keeps this document from restating them: `approve`, `decline` and the credit, refund, window and reconciliation kinds from `docs/planning/specs/prepaid-rails.md`; `export` and `close` from `docs/planning/specs/data-subject-requests.md`; `provision-group` from `docs/planning/specs/own-domain-tier.md`.

**The store root is `/var/db/onboard/`.** `docs/planning/specs/gemini-capsule.md` is the one document that names it, and this spec adopts it and completes the listing the other specs have been adding to in pieces: `accounts/<username>/{account.json,notices.jsonl,application.json}`, `applications/<token>.json`, `drafts/<token>.json`, `groups/<domain>/group.json`, `tokens/<token>.json`, `ledger/{payments,unattributed}.jsonl`, `rates/xmr-gbp.json`, `intents/`, `webhooks/`, `mail/` for the `apply@` mailbox, and one `journal.jsonl`. The operator's own configuration stays outside it, root-only under `/etc/kyriakon/onboard/`.

The boundary is the privilege split. The handler runs as the unprivileged `_onboard` user, the same account the capsule's FastCGI process uses. It reads the shared question list and the account state it renders for the signed-in member, and it writes `intents/`, `drafts/`, `applications/` and `webhooks/`. `applications/` is the handler's because filing is the handler's act: the draft becomes the application record, and the status page both front-ends answer with is rendered from it, which is also why the capsule's own unit creates that directory for the same user. It reads no secret, no other member's state and no mail, and it cannot reach the drain. The drain runs as root and owns everything else. This does not loosen the TUI's own boundary, which says the TUI cannot read the store: the handler reads what it renders, and neither of them reads the mail or a secret.

**The drain owns** provisioning, manual payment credits, the keyring publish pull request, certificate requests queued against the refill, the lifecycle transitions and their notices, the 90-day application purge, and the grace sweeps. It appends the journal line **before** carrying the transition out, so a crash leaves a record it can rerun. When it is stuck, the reading order is its log, the oldest file in `intents/`, then the last line of `journal.jsonl`.

**Notices are deduplicated and recorded before they are enqueued**, keyed on the notice type and its subject against the account's own `notices.jsonl`. That ordering means a crash can lose an email rather than send two, which is the accepted direction. Everything leaves through the local `smtpd` enqueuer and is DKIM-signed.

### The account page

The page is what proposal section 5.9.1 bounds, with each part against the document that owns it. It is a member's surface, not an operator's, and it is where the impatience of a build must not add anything.

| What the page does | What specifies it |
| --- | --- |
| Log in | the mail password, verified through `doveadm auth test` by a `doas` rule, so passwords have one source of truth and the service holds no hash |
| Change the mail password | the password re-entered regardless of how fresh the session is, filed as an intent; the drain sets the hash as root, since `doveadm auth test` only ever verifies |
| Add and remove upload keys | `docs/planning/specs/per-member-hosting.md`; one key serves sftp and git, and the page shows its fingerprints and dates |
| Add and change the address outside the platform | the account's contact and recovery address, with the bounce rule from [#153](https://github.com/kyriakon/kyriakon-infra/issues/153) |
| See the space used | the filesystem quota, read by the drain: soft 5 GB, hard 5.5 GB across mail, site and repositories together |
| See the payment window and what a lapse stops | `docs/planning/specs/prepaid-rails.md`: the block at the top while the window runs, naming the rail, the days left and the close date, the amount, the token in full and the rail's own instructions; `Lapsed` once it closes with nothing recorded, repeating the close date, stating what still works and what has stopped in the lapse notice's own words, and showing the token again; then the paid-until date once it is set |
| Turn HTTP and gemini serving on and off | proposal section 5.2: two independent booleans, applied by the drain as generated include lines and a reload, because it is a config write and not a service call |
| Stop the yearly renewal | Stripe's `cancel_at_period_end`, which runs to the period's end |
| Replace the mail key | the rotation in [#155](https://github.com/kyriakon/kyriakon-infra/issues/155): a 72-hour pending window, cancellable from the page, confirmed from every address held, and applied at once when the request is signed by the current key |
| Take the data out | `docs/planning/specs/data-subject-requests.md`: an export intent, a bundle written into the sftp chroot, and a notice when it is ready |
| Close the account | the same spec, with its 7-day window, cancellation from the page and the password re-entered |
| Read the notices | every notice sent, at every address it went to, which is also the audit of what the platform has told the member |

Login is by password alone. No key admits anyone to the page: the mail key protects mail and the upload key protects sftp and git, and neither is a session credential. A session is a server-side file referenced by a signed, HttpOnly, SameSite cookie with a 12-hour expiry. Where a member cannot log in, the runbook's lost-key path and the password path apply, and where the password is forgotten the address outside the platform is what makes a reset possible without the operator.

The page also states plainly what it cannot do, because a member will ask: read the mail, recover the key, restore deleted mail, or provide a shell.

A body's member sees the body: the page resolves a signed-in mailbox to its group, so anyone holding a mailbox in the group sees the group's billing, quota and state, which live on the group's own record rather than per account.

In a suspended account the page stays open, so the member can read the reason and answer it. In a closing one it works normally throughout, because the window exists so the member can retrieve everything.

The prototype is worth reading for the copy and is not to be copied blindly. It draws no login screen, which this spec adds. It still shows a Monero payment ID, which `docs/planning/specs/prepaid-rails.md` calls legacy copy: the page shows the subaddress and the quoted amount. Its certificate copy follows [#166](https://github.com/kyriakon/kyriakon-infra/issues/166): within a day, and longer in a busy week.

### What the member is sent

| When | What |
| --- | --- |
| On filing | the status token and its link, which is the durable record rather than an email |
| Before provisioning | the confirmation, restating the immediate-supply request, the digital-content acknowledgement, the document versions and the 14-day right |
| At approval, card | the decision with the Payment Link |
| At approval, prepaid | the decision with the token and the rail's instructions: a postal address, or the Monero subaddress with the quoted amount |
| At approval, no charge | the decision, with no window and no token |
| First payment | Stripe's receipt and invoice for a card; the platform's own receipt for a prepaid credit |
| A year on | Stripe's upcoming-invoice reminder for a card; the platform's own 30-day notice for a prepaid member, who has no processor to send one |
| Lapse and its grace | the lapse notice, the grace notice, and a final notice seven days before deletion |
| Suspension | the reason, and how to answer it |
| A refund | the credit notice with the settlement date |
| Rotation and export | the rotation's confirmations at every address, and the notice that an export is ready |

## Out of scope

- The build itself, which is a separate effort, and the deployment of the service, `relayd`'s front end and its certificate among them.
- The gemini capsule and SSH TUI front-ends. Their specs bound them, and this document only fixes the back end they write into.
- The rails' own mechanics, the export bundle's contents, the close path's files, and the group tier's provisioning, each of which has its own spec.
- The public site: which pages the documents are rendered onto and by what. The form's copy is adopted here but rendered by the site workstream.

## Further notes

- **The signup copy has no owning ticket.** [#169](https://github.com/kyriakon/kyriakon-infra/issues/169) recorded this gap. The words exist in the prototype; this spec adopts them, and the site workstream carries them. If a document is wanted for the copy alone, it is a ticket of its own.
- **Nothing sets an age.** No decision, ticket or draft states a minimum age, and this spec does not invent one. Whether a line belongs on the form is a decision that has not been taken.
- **Suspension borrows the lapse login class.** The runbook's suspend step is `usermod -L lapsed <username>`, the class named for the other state, while the two differ in what they do to the vhosts. Whether suspension needs a class of its own is undecided.
- **`doas`, not `sudo`, and no argument-constrained rules at all.** Proposal section 6.14 says `sudo` in the generic sense, and root over SSH is disabled on this box. The shape it asks for is met differently here: the handler holds no rule, because it files intents rather than running commands, and the drain is root, running the scripts the repository tracks. The one rule the build needs is for the login check, and it cannot name the check's own arguments: `doas.conf(5)` matches the argument list literally, so a rule written `cmd doveadm args auth test` would refuse the username the check has to pass, and every login would be denied. The rule therefore authorises a fixed-argument checker the build adds, `permit nopass _onboard as root cmd /usr/local/libexec/kyriakon-authcheck`, and the checker is what runs `doveadm auth test` with the name it is given. Naming `doveadm` in the rule with no `args` clause would also work, and would hand the handler every `doveadm` subcommand, which is the argument-constrained shape 6.14 asks for turned inside out; the checker is what keeps it constrained. What 6.14 forbids, a rule that could reset an existing account's password and so take the account over, does not arise: a password is set once, as a hash, on an account the member is finishing, and never changed on one that exists.
- **Two tokens, two jobs.** The status token is 128 bits of lowercase Crockford in a path and answers for an application; the payment token begins `KYR-` and joins a payment to an account. Both can be live during a window, and the copy keeps them apart.
- **Where the store root came from.** `prepaid-rails.md` leaves it to the store root named in the service's TOML and the runbook leaves the path to the build; `gemini-capsule.md` is the only document naming one, `/var/db/onboard`, so this spec adopts that rather than inventing a third answer. The handler's draft and mail areas are subdirectories of it, not a second tree.
- **The operator's command surface is only partly recorded.** The verbs this spec needs are `approve`, `decline`, `suspend`, `delete`, `export`, `token resend` and the refund path; the runbook owns the list and will need it completed.

## Testing decisions

One seam is worth a test and the rest is copy. An application submitted end to end files exactly one intent and nothing else; a webhook whose signature does not verify leaves the store untouched and extends no date; a click on an approval link whose application is already decided does nothing; and the drain run twice over the same intent directory produces the same store, which is what the journal line written before the transition is for. The page's own rendering is checked by eye against the prototype until the build gives it a harness.

## Not verified

Nothing in this document has been run. The store layout, the intent record's fields and the id format are decisions of this spec and no repository code implements them yet; the box has no service installed, so the counter limits, the session cookie and the two-hop transport are written from their tickets rather than from a working service. `docs/planning/specs/per-member-hosting.md` records what was checked on the live box for the hosting half; this half has had no such pass.

## Sources

- `docs/planning/specs/prepaid-rails.md`, `data-subject-requests.md`, `own-domain-tier.md`, `ssh-onboarding-tui.md`, `gemini-capsule.md`, `per-member-hosting.md`
- `docs/runbook.md`, `docs/terms.md`, `docs/privacy.md`, `docs/aup.md`
- `docs/planning/research/stripe-rail-set.md`, `sole-trader-obligations.md`, `openbsd-per-member-hosting.md`, `per-account-enforcement.md`, `key-generator-capability.md`
- `docs/planning/prototypes/signup-and-account-page.html`, and the community block draft it rests on
- `../kyriakon/docs/decisions/kyriakon-net-project-proposal.md` sections 5.2, 5.9.1, 5.9.2 and 6.14, read against the ticket that reconciled each
- Tickets [#274](https://github.com/kyriakon/kyriakon-infra/issues/274), [#159](https://github.com/kyriakon/kyriakon-infra/issues/159), [#233](https://github.com/kyriakon/kyriakon-infra/issues/233), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156), [#153](https://github.com/kyriakon/kyriakon-infra/issues/153), [#155](https://github.com/kyriakon/kyriakon-infra/issues/155), [#114](https://github.com/kyriakon/kyriakon-infra/issues/114), [#151](https://github.com/kyriakon/kyriakon-infra/issues/151), [#152](https://github.com/kyriakon/kyriakon-infra/issues/152), [#235](https://github.com/kyriakon/kyriakon-infra/issues/235), [#177](https://github.com/kyriakon/kyriakon-infra/issues/177), [#188](https://github.com/kyriakon/kyriakon-infra/issues/188), [#187](https://github.com/kyriakon/kyriakon-infra/issues/187), [#163](https://github.com/kyriakon/kyriakon-infra/issues/163), [#182](https://github.com/kyriakon/kyriakon-infra/issues/182), [#183](https://github.com/kyriakon/kyriakon-infra/issues/183), [#176](https://github.com/kyriakon/kyriakon-infra/issues/176), [#185](https://github.com/kyriakon/kyriakon-infra/issues/185), [#169](https://github.com/kyriakon/kyriakon-infra/issues/169), [#174](https://github.com/kyriakon/kyriakon-infra/issues/174), [#158](https://github.com/kyriakon/kyriakon-infra/issues/158)
