# The Gemini capsule front-end

> Spec synthesised from [Spec the Gemini capsule front-end](https://github.com/kyriakon/kyriakon-infra/issues/243) and the decisions it points at: [Decide the Gemini onboarding front-end](https://github.com/kyriakon/kyriakon-infra/issues/182), whose resolution this spec implements rather than reopens, and the research note it rests on, [Research serving a dynamic Gemini capsule alongside gmid](https://github.com/kyriakon/kyriakon-infra/issues/181) (`docs/planning/research/gemini-dynamic-capsule.md`). It takes the application's questions from [Decide the organisation's application questions](https://github.com/kyriakon/kyriakon-infra/issues/233), the key's behaviour from [Decide the member key walkthrough and the browser generator](https://github.com/kyriakon/kyriakon-infra/issues/176), its promises from [Decide what the public release promises, and where](https://github.com/kyriakon/kyriakon-infra/issues/158), and its place in the service from [Decide the onboarding service's architecture and its trust boundary](https://github.com/kyriakon/kyriakon-infra/issues/156). The [Gemini protocol specification 0.24.1](https://geminiprotocol.net/docs/protocol-specification.gmi) is the normative source for the flow.

## Problem statement

The release ships the web form and nothing else, and the map requires onboarding to have three front-ends writing into one back end so that no single front-end is the only way in. The web form needs a browser, and a member who has a Gemini client and no browser cannot reach it. The capsule is the second way in: the same application, the same questions, the same intents, served over the Gemini protocol on the hostname the web form already uses.

The protocol decides most of the shape before any code exists. Status 10 is the only input mechanism, and a client that receives a 1x response to a URI that already carries a query "MUST replace the query string with the user input", so an answer cannot accumulate in the URL. The whole request URI "MUST NOT exceed 1024 bytes, and a server MUST reject requests where the URI exceeds this limit". An abandoned flow sends nothing at all, because every client examined closes the connection when the prompt is cancelled, so state left behind has no disconnect event to hang its expiry on. A public key is the one field that can exceed the request budget, and gmid's own limit is the same 1024 bytes.

What is left to settle is what the server block is, what runs behind it, where the state lives and how it expires, what the applicant is asked and in what order, how a key gets in when it does not fit, what the status page shows, how a public endpoint is bounded, and what the capsule is allowed to say.

## Solution

One block is added to `gmid.conf` for `signup.kyriakon.net`, and the Rust service that already answers HTTPS behind `relayd` gets a FastCGI socket that gmid connects to. The service runs as its own user with state under `/var/db/onboard`, no read access to member homes or to the certificate keys, and no privilege at all: it validates and files, and the root drain applies.

State lives server-side in a draft keyed by a 128-bit random token carried in the path. Each page asks one question and shows "question N of M". Submitting an answer re-requests the same path with the answer as the query; the handler stores it and redirects to the next page. A draft untouched for seven days is purged by the drain, because a cancelled prompt sends nothing and the expiry is the only bound on an abandoned application.

The mail public key is pasted where it fits, and the prompt warns before the input that a client enforcing the 1024-byte limit may refuse it; the same key can be mailed to `apply@kyriakon.net` with the draft's token in the subject, and the drain reads that mailbox and files the key against the draft. A status page at `/status/<token>` shows the stage and never echoes an answer. Counters keyed on `REMOTE_ADDR` answer 44 slow down rather than a failure. The terms, the acceptable use policy and the privacy notice are generated onto the capsule from the same source the site uses, and are mirrored rather than linked, because a Gemini client cannot open an HTTPS page.

## Where it lives

The capsule is `gemini://signup.kyriakon.net`, the same hostname the web form and the account page use, because a hostname is protocol-agnostic. That name is already in the apex certificate's alternative-name list and already has port 80 and port 443 vhosts in `httpd.conf`, so the capsule costs one server block and a socket and no certificate work at all. It presents the apex certificate and key, the pair `httpd` serves for the same name, exactly as the Kleio and Press capsules reuse theirs.

The repository's `gmid.conf` gains one block. The paths inside it are relative to gmid's chroot except `cert` and `key`, which stay absolute ([gmid.conf(5)](https://man.openbsd.org/gmid.conf.5), "All the paths in the configuration file are relative to the chroot directory, except for the cert, key and ocsp paths"):

```
server "signup.kyriakon.net" {
	listen on * port 1965

	cert "/etc/ssl/kyriakon.net.fullchain.pem"
	key "/etc/ssl/private/kyriakon.net.key"

	# Every request URI carries the draft token and the applicant's answer, so
	# gmid's own access log would record both. The handler keeps its own log
	# without the query; this stops the URI landing in gmid's.
	log off

	# The socket path is resolved after the chroot, so the file lives at
	# <chroot>/run/onboard/onboard.sock on disk. The repository chroots to
	# /home/www; the deployed box still chroots /var/www until the hosting
	# change from #160 is applied, so the deploy creates the directory under
	# whichever chroot the installed gmid.conf names.
	fastcgi socket "/run/onboard/onboard.sock"
}
```

`log off` is a server-block option that disables logging for that block ([gmid.conf(5)](https://man.openbsd.org/gmid.conf.5), "log bool. Enable or disable the logging for the current server or location block"). It is deliberate here rather than incidental: the default legacy log format writes "the request URI", which for this vhost is the token and the answer. The handler logs the route, the response code and the client address, never the query.

No `root` is set, because every request goes to the handler. gmid connects to the socket per request (`apply_fastcgi()`), and a mistyped socket path is accepted at config time and fails only when a request arrives, so the deploy checks `gmid -n` and then exercises one request. `slowcgi` around a CGI program is the fallback if a native FastCGI listener proves awkward in Rust; it uses the same socket path with `param SCRIPT_NAME = "/onboard"`, because gmid's default `SCRIPT_NAME` is the empty string and `slowcgi` execs the path from it.

The socket directory is created by the deploy, owned by the handler's user with group `_gmid` and mode 0770, and the socket file is mode 0660. gmid's server process is inside the chroot as `_gmid`, so it needs traverse on the directory and read-write on the socket; nothing else does. A loopback TCP socket was considered and rejected: it avoids the chroot coupling, but any local user could connect to it directly and forge the FastCGI parameters, including `REMOTE_ADDR`, which is the key the limits and the audit depend on.

## The process, its user and its state

The handler is the same binary that answers HTTPS, started by its own `rc.d` unit:

```
daemon="/usr/local/sbin/kyriakon-onboard"
daemon_flags="serve"

. /etc/rc.d/rc.subr

rc_bg=YES
rc_reload=NO
daemon_logger="daemon.info"

rc_pre() {
	install -d -m 0755 /var/db/onboard
	install -d -m 0750 -o _onboard -g _onboard /var/db/onboard/drafts
	install -d -m 0750 -o _onboard -g _onboard /var/db/onboard/applications
	install -d -m 0700 -o _onboard -g _onboard /var/db/onboard/intents
	install -d -m 0700 -o _onboard -g _onboard /var/db/onboard/mail
	install -d -m 0700 -o _onboard -g _onboard /var/db/onboard/mail/cur \
	    /var/db/onboard/mail/new /var/db/onboard/mail/tmp
}

rc_cmd $1
```

The user is `_onboard`, created in the same shape as `_gmid`: a reserved numeric uid and gid, home `/var/empty`, shell `/sbin/nologin`, no group memberships beyond its own, and no `doas` rule. It must not be `_gmid`, because a fault in the form would then reach whatever `_gmid` can reach, and it must not be `www`, which is `slowcgi`'s default user. It takes the `default` login class rather than `daemon`, because `daemon` carries `openfiles-cur=128`, which is a connection limit for anything serving many applicants at once; the deploy sets it explicitly rather than inheriting it by accident.

The trust boundary is the research note's. The handler reads its own state, its socket directory, and its own log. It does not read `/home/<member>` or `drafts` that are not its own, and it cannot read `/etc/ssl/private` because the private keys are root-only and gmid reads them before dropping privileges. It holds no provisioning credential: the drain does, under `/etc/kyriakon/onboard/`.

The handler writes its log through the rc.d `daemon_logger` path and the deploy adds a `newsyslog.conf` entry with `count 7`, the same seven-day bound every other log on the box carries. The log holds the route, the code and the client address, and never the token, the query or an answer.

## The draft store

The token is 128 random bits drawn from `getrandom` when the draft is created, encoded as 26 lowercase Crockford base32 characters, and carried in the path. It is separate from the `KYR-` payment token that the drain draws at approval and that the prepaid rails spec keys the ledger by. The two are never the same value and neither is derived from the other.

A draft is a JSON document at `/var/db/onboard/drafts/<token>.json`: the answers given so far, the page cursor, the key fingerprints and check verdicts, `created_at` and `updated_at`. On file it becomes `/var/db/onboard/applications/<token>.json` and an `intents/<id>.json` is written for the drain, which validates and applies it the way it applies every other intent.

The expiry is the protocol's. A client that receives a 1x response to a URI that already carries a query replaces the query with the input, so the query cannot accumulate answers, and a cancelled prompt sends nothing, so the server never learns the applicant stopped. There is no disconnect event. The drain purges any draft whose `updated_at` is more than seven days old. The status page answers for a filed application until the application is cleared away, seven days after a decision, which is [#159](https://github.com/kyriakon/kyriakon-infra/issues/159)'s hold; the answers themselves stay inside the 90-day window of ADR 0005.

The store joins the backup set in `scripts/backup.sh`, so a restore does not lose an application that was in progress.

## The questions

The application is one list of questions, shared by all three front-ends as data rather than copied three times, which is what the map's "three front-ends, one back end" requires and what [#183](https://github.com/kyriakon/kyriakon-infra/issues/183) repeats for the TUI. One question is one page, so the client's single line is always one answer. The pages, in order:

| Page | Question | Input | When it is asked |
|---|---|---|---|
| 1 | Username | 10 | always |
| 2 | Is this for you, or for a body? | 10 | always |
| 3 | An address outside the platform | 10 | always, optional |
| 4 | Diocese | 10 | always, optional |
| 5 | Priest, deacon, monk, nun, or layperson? | 10 | always, optional |
| 6 | What do you hope to use this for? | 10 | always, optional, multi-line |
| 7 | If you cannot pay and would like an account without charge, say so here | 10 | always, optional, multi-line |
| 8 | Anything else | 10 | always, optional, multi-line |
| 9 | If you are a monk or a nun, do you have your elder's blessing? | 10 | if page 5 is monastic; required, multi-line |
| 10 | If you are a layman, do you have your spiritual father's blessing to keep a website? | 10 | if page 5 is layperson; optional, multi-line |
| 11 | Your mail public key | 10 | always (one page per mailbox for a body) |
| 12 | Your upload key | 10 | always, optional |
| 13 | How you will pay | 10 | always |
| 14 | I accept the terms, the acceptable use policy and the privacy notice | 10 | always |

The order follows the resolution's sequence, with page 2 from [#233](https://github.com/kyriakon/kyriakon-infra/issues/233) (the second question, which opens the community block) and pages 9 and 10 from the web form's own order. The list is the same data the web form renders as four cards and the TUI renders as a wizard; the grouping is presentation.

Every page is a status 10 whose META is the question, preceded by the counter, as in `question 4 of 12. Diocese (optional):`. The total is the number of pages this applicant's path will ask, recomputed as answers arrive: the individual path is 12 pages when no blessing question applies and 13 when one does, and the body path is longer by the community block and one key page per mailbox. A conditional page is counted once its condition is known, so a page after a branch shows the new total.

The META is also the only place an error can appear, because the specification fixes META as "the text that a client MUST use to prompt the user for the information". A required answer that is refused (a username of the wrong format, or a reserved name) is re-asked with the reason in the prompt rather than ending the flow.

The username check is format and reserved names only, never existence. Format and the reserved set (`mail`, `www`, `kleio`, `press`, `signup`, and the other names the platform uses itself) are validated live, because they are a static list in the service's configuration. Whether the name is taken is not checked, on either front-end, because answering "taken" hands a stranger a member list one guess at a time and because the accounts live in root-owned state the handler never reads. A collision is resolved by the reviewer, who asks for another name.

### Multi-line answers

Multi-line answers work, because Lagrange and Kristall send them. The handler reads `QUERY_STRING` and percent-decodes it itself rather than using `GEMINI_SEARCH_STRING`, because gmid sets the decoded copy only when the query is non-empty and contains no `=`, and a pasted key or a free-text answer may contain one. Spaces arrive as `%20` and the handler leaves `+` as a plus, because the specification requires `%20` for a space and does not define `+` as one.

After decoding, a line break arrives as `%0A` (LF) or `%0D%0A` (CRLF). The handler normalises CRLF to LF and stores LF, and treats a bare CR as an ordinary character, matching the specification's "servers SHOULD recognise both '%0A' and '%0D%0A' as linebreaks". A literal newline sent by a client that leaves it unencoded is normalised the same way.

An optional question is left with a single full stop, which the handler stores as empty, because several clients return without sending anything when the input is empty and a cancelled prompt is indistinguishable from an abandoned flow. A required question re-prompts when the answer is empty or the full stop.

### The mail password

The capsule does not ask for the mail password. Every answer appears in the request URI, and while the handler never logs the query, the answer is still the kind of secret that should not travel as a query at all when it can avoid it. The password is taken on the web form, which the capsule names as another way in, and the account page's single-use link is what sets it for an applicant who used only the capsule. The resolution does not place the password in the capsule's flow, and this is where the record is silent; the build settles the exact handoff with the web form rather than inventing one here.

## The community block

A body's application adds questions after page 2, in the order the community block draft and [#233](https://github.com/kyriakon/kyriakon-infra/issues/233) give them:

| Question | Input | Notes |
|---|---|---|
| The body's name | 10 | required |
| The body's kind | 10 | parish, monastery, school, business, or other; a filter for the reviewer, never a gate |
| The body's domain | 10 | the domain the mail will live on |
| Whether you can add the domain's records | 10 | yes or no |
| The addresses, one per line | 10 | each line `localpart: own` or `localpart: alias <localpart>` |
| An account name for each mailbox | 10 | one per line, in the order of the addresses |
| A public key for each mailbox | 10 | one page per mailbox, with the mailbox named in the prompt |
| An upload key for the site | 10 | optional |
| A DNS contact | 10 | optional |

The address format is the one line the resolution gives, "the addresses one per line followed by which of them are aliases", written as `secretary: own` and `hall: alias secretary`. An address that is an alias shares the mailbox and therefore the key of the one it points at. The rail and the acceptances are asked once for both paths, after the block.

A body with no mailboxes listed, or a list longer than the ten the tier allows, is re-asked. The reviewer checks the domain resolves and that the applicant can add its records; nothing mechanical depends on the kind.

## The key

A public key is the one field that may not fit. An armored Curve25519 block plus the path and the token runs at or past the 1024 bytes the specification allows, and a client that enforces the limit refuses to send it. So the key page takes the paste where it fits and says before the prompt what to do when it does not:

```
10 Paste the public key for secretary@theirparish.example (question 11 of 24). Paste the whole
block. If your client refuses the paste because the address is too long, mail the block to
apply@kyriakon.net with <token> as the subject instead, and name this mailbox in the message.
```

The warning is in META because META is the only text a client shows before the input; the specification forces that, and it means there is nowhere else for it to go. The prompt stays inside the 1024-byte reply header gmid allows.

On the answer the handler extracts the armored block, runs the same three-condition check the web form runs, and records the fingerprint and the verdict. The conditions are the ones [#176](https://github.com/kyriakon/kyriakon-infra/issues/176) and the #185 prototype fix: no encryption-capable subkey, a preference that would make gpg emit a packet the member's client cannot read (the AEAD preference), and an expired or revoked key or subkey. The signup warns with the specific message and proceeds. It never refuses on the shape of a key, because the platform cannot verify what a client generated, and a heuristic refusal would turn a guarantee into a support queue.

### The mail route

`apply@kyriakon.net` is deliberately not delivered through the encrypting LMTP path. The drain has to read the key to file it, and zero-access mail is exactly the thing the drain cannot read. The deploy adds a dedicated `smtpd` action to `openbsd/etc/smtpd.conf`, matched before the general local delivery, delivering to a plaintext Maildir under `/var/db/onboard/mail`:

```
action "onboard_mail" maildir "/var/db/onboard/mail" user _onboard
match from any for domain <mail_domains> rcpt-to apply@kyriakon.net action "onboard_mail"
```

This is a stated exception, not a hole: the address exists to carry an application's key, the applicant is told the service reads it, and it holds nothing else. The action's `user` option runs the delivery as `_onboard`, the account that already owns the spool ([smtpd.conf(5)](https://man.openbsd.org/smtpd.conf.5)).

The drain reads the Maildir on each run. It matches the draft's token in the subject, case-insensitively, and takes the first PGP public key block from the message body. For a body with more than one mailbox it takes each block labelled with the mailbox above it and refuses an unlabelled block when there is more than one, replying to name what is missing. It runs the same three-condition check, records the verdict, and files the key against the draft. The message is deleted once it has been acted on, so the plaintext spool stays empty between runs.

A key whose subject carries a token that no longer resolves has arrived after the draft expired. The drain replies to the sender with one message carrying a fresh draft link, rather than leaving the applicant without an answer; it creates no draft from the mail alone, so the applicant starts again from the link. The reply is sent only when the message actually carries a public key block, and is rate-limited per sender, so ordinary mail to the address is not answered and the address is not a backscatter source.

## The status page

`gemini://signup.kyriakon.net/status/<token>` is a `text/gemini` page keyed by the same 128-bit token the draft carries, which is also what the web form shows an applicant who gave no outside address. The page shows the stage: with us, waiting to be read (received); being read (with the reviewer); or decided, with the outcome being an account on the paid tier, an account without charge, or a decline, which offers the way back of [#159](https://github.com/kyriakon/kyriakon-infra/issues/159). The `KYR-` token the prototype's status link showed is the payment token drawn at approval, and is superseded here.

The page never echoes an answer, the contact address or the key. A token that is unknown and a token that has expired return the same page, so the endpoint cannot be used to test whether a token exists. The page answers while the record exists: a draft until seven days after its last update, a filed application until seven days after the decision.

## Limits

The handler keeps two counters in memory, keyed on `REMOTE_ADDR`: 60 requests a minute and five new drafts a day per address, with a draft counted where it is created. Exceeding either answers 44 slow down rather than a failure, which the specification defines as "The server is requesting the client to slow down requests, and SHOULD use an exponential back off". A shared address has to stay workable, since a monastery applying for six mailboxes sits behind one; five drafts a day and 60 requests a minute do that, and the limits are a starting point rather than a settled number.

No CAPTCHA is used, because it is a third-party script and the refusal list rules those out. The human approval is the real gate. The counters reset when the process restarts, which is an accepted ceiling: a restart is rare and the gate does not depend on them.

A `pf` rule on port 1965 is a separate deploy-time proposal, because `pf.conf` is propose-only, and it would bound every capsule on the port rather than this one, since `pf` cannot see the SNI. The app-level counters are the release mechanism; the `pf` rule is the crude outer bound if it is wanted later.

## What the capsule says

The capsule carries the site's promises, with the limits inline, from the same source rather than a second draft of them. It says what a member gets and what each claim's limit is: zero-access covers message content and not correspondence metadata; a lost device plus a lost recovery phrase is permanent mail loss; hosting waits on a certificate that can take a day or three; there is one server and one operator, nightly encrypted backups and a restore tested weekly, and no uptime figure. It says a person reads every application and that optional information makes approval quicker, with no belief test and no published criterion. It says that clergy, monastics and anyone without the means to pay are not charged, and that the applicant's word is the ground.

It says what it is: one of three ways in, with the web form at `signup.kyriakon.net` as another and the SSH TUI later, so nothing here is ever the only way in. Its front page names the web form explicitly for anyone who would rather use a browser.

The terms, the acceptable use policy and the privacy notice are mirrored onto the capsule from the same generated source the site publishes, as `text/gemini` pages rather than links, because a Gemini client cannot open an HTTPS page. The acceptances page carries the same three acceptances and the version of the source it was generated from, the way the web form does. The refusal list and the threat model stay published over HTTPS, and the capsule says so rather than implying it can be read from Gemini.

The capsule never claims general resistance to a government threat actor, that it cannot be compelled, that it would tell a member if it were asked, a warrant canary, "no logs", "anonymous", end-to-end encryption, forward secrecy, or metadata protection, all of which the map's resistance decision refuses. It never calls zero-access mail "encrypted at rest" or "end-to-end", and it states the metadata limit wherever the property is claimed. It never says the certificate proves identity to a stranger, because TLS validation is client policy and the capsule relies on trust on first use. It never says a lost key can be recovered, that hosting is instant, or that this is the only way in. "gemini" stays lowercase in prose and there are no em dashes, as the site's wording discipline requires.

## The cost it accepts

Trust on first use. The specification recommends it, and it means the capsule relies on a pin rather than a CA. An ACME certificate renews about a month before it expires, and that lands in the branch where the pinned certificate is still inside its validity window, which all three clients examined treat as suspicious: Amfora offers an accept button, Lagrange refuses until the certificate is trusted through Page Information, Kristall has no accept button on that error page and needs its stored entry cleared in settings. A first visit after a renewal may be refused outright, and the capsule cannot explain it on a page the client will not show. This is accepted because an onboarding capsule's visitors are one-time; a member's own capsule, whose visitors return, cannot accept it the same way and is a separate ticket.

## State on disk

| Path | Written by | Contents | Lifetime |
|---|---|---|---|
| `drafts/<token>.json` | handler | answers so far, page cursor, keys and check verdicts, timestamps | purged by the drain seven days after the last update |
| `applications/<token>.json` | handler on file, drain on decision | answers, key fingerprints, verdicts, status | seven days after the decision, inside the 90-day window |
| `intents/<id>.json` | handler | one filed application | consumed and deleted by the drain |
| `mail/` | `smtpd` | the Maildir for `apply@kyriakon.net` | drained each run; a message is deleted once acted on |
| `journal.jsonl` | handler and drain | one line per transition | bounded with the service |

The counters are process state and are not on disk.

## Testing decisions

The seam is the redirect chain, because a defect there files a wrong application. Answering a page advances the cursor exactly once, and re-requesting the same page with the same answer (a client retry, or a reload) does it once and not twice. A token that has been purged leaves no answers behind. Two different tokens never write to each other's draft.

The key mail is the other seam. A token in the subject files the block against the right draft and the right mailbox; an unknown token replies with a fresh link and creates no draft; a message with no key block is not answered.

The limits and the counter are worth one case each. Exceeding either counter answers 44, and one shared address can still make the single draft a six-mailbox body needs. The counter's total matches the pages the path will actually ask, including after a branch answer. Multi-line normalisation is one table: `%0A`, `%0D%0A`, a literal newline and a bare CR, each landing as LF or as an ordinary character as the specification requires, with `+` staying a plus.

## Not verified

The request-time FastCGI behaviour was read from gmid's source (`fcgi.c`, `server.c`) rather than observed, because no handler was run on the box. The first build should exercise one request end to end before the config is relied on. gmid's log lines and the `log off` server option are read from `gmid.conf(5)` and the source; the deploy confirms with `gmid -n` and one live request.

## Out of scope

The HTTPS web form and the account page, which are the site and service specs. The SSH TUI, which is [#183](https://github.com/kyriakon/kyriakon-infra/issues/183). The drain's provisioning, lifecycle and notice mechanics, which are [#156](https://github.com/kyriakon/kyriakon-infra/issues/156) and [#153](https://github.com/kyriakon/kyriakon-infra/issues/153). The content of the terms, the AUP and the privacy notice, which is [#235](https://github.com/kyriakon/kyriakon-infra/issues/235). The key crate's internals, which are [#185](https://github.com/kyriakon/kyriakon-infra/issues/185). The `pf` rule on 1965, which is propose-only and separate. How a member's own capsule survives the same renewal problem.

## Sources

- Gemini protocol specification 0.24.1, [protocol-specification.gmi](https://geminiprotocol.net/docs/protocol-specification.gmi), read 2026-10-05. The 1024-byte request limit, the 1x query-replacement rule, the `%0A` and `%0D%0A` line breaks, status 10, status 11 and status 44 are quoted from it.
- `gmid` 2.1.1 and [gmid.conf(5)](https://man.openbsd.org/gmid.conf.5) on the box. The `fastcgi` directive, the chroot-relative path rule, the `log bool` server option, the legacy log format's "the request URI", and the 1024-byte reply header are from the man page and the installed binary.
- `docs/planning/research/gemini-dynamic-capsule.md` (PR #184). The FastCGI mechanism, the CGI variables, the client behaviour, the trust boundary and the rate-limiting options are its findings.
- The `gmid` source at version 2.1.1 (`fcgi.c`, `server.c`), read 2026-10-05, for `QUERY_STRING`, `GEMINI_SEARCH_STRING`, `REMOTE_ADDR` and the reply-code check.
- [smtpd.conf(5)](https://man.openbsd.org/smtpd.conf.5) for the `maildir` action, its `user` option, and `rcpt-to` matching.
- The tickets: [#243](https://github.com/kyriakon/kyriakon-infra/issues/243), [#182](https://github.com/kyriakon/kyriakon-infra/issues/182), [#181](https://github.com/kyriakon/kyriakon-infra/issues/181), [#233](https://github.com/kyriakon/kyriakon-infra/issues/233), [#176](https://github.com/kyriakon/kyriakon-infra/issues/176), [#158](https://github.com/kyriakon/kyriakon-infra/issues/158), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156), [#183](https://github.com/kyriakon/kyriakon-infra/issues/183), and [#185](https://github.com/kyriakon/kyriakon-infra/issues/185).
