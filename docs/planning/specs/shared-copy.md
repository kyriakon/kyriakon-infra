# The shared copy across the three front-ends

> Spec synthesised from [Spec the shared copy across the three front-ends](https://github.com/kyriakon/kyriakon-infra/issues/362) and the decisions it rests on: [Decide the shared copy: one service catalogue and the check that keeps the three renderings in step](https://github.com/kyriakon/kyriakon-infra/issues/359) (the container, the rules and the check), [Spec the release's web form and account page](https://github.com/kyriakon/kyriakon-infra/issues/274) (the intent API, the question file's schema and the account page's own table), [Decide the Gemini onboarding front-end](https://github.com/kyriakon/kyriakon-infra/issues/182) and [Spec the Gemini capsule front-end](https://github.com/kyriakon/kyriakon-infra/issues/243), [Decide the SSH onboarding front-end](https://github.com/kyriakon/kyriakon-infra/issues/183) and [Spec the SSH onboarding TUI](https://github.com/kyriakon/kyriakon-infra/issues/245), [Decide the SSH portal's entry address and port](https://github.com/kyriakon/kyriakon-infra/issues/360), [Decide whether the projects sit on their own hostnames](https://github.com/kyriakon/kyriakon-infra/issues/187), [Decide the organisation's application questions](https://github.com/kyriakon/kyriakon-infra/issues/233), and [Decide what the public release promises, and where](https://github.com/kyriakon/kyriakon-infra/issues/158).

## Problem statement

One platform is reached three ways. The web form and the account page answer over HTTPS behind `relayd`, the capsule answers through gmid's FastCGI socket, and the terminal answers over ssh. The question list is already one file that all three read, and it is the only fact they share today.

Everything else a front-end says about the platform is free to drift: which services exist, what state each is in, where it lives, what pressing it does, and what a member's own account holds. Three copies of a list drift in a way that is invisible until someone is told about a service the capsule never mentioned, or offered a toggle the site has stopped promising, or handed a sentence that only one of the three has the newer wording for. The release's own promise, that every claim on the public site is implemented or removed, cannot hold while the claim lives in three drafts.

The account half has the same shape of problem one level down. A member's credentials are now two kinds, upload keys and pinned gemini client certificates, and a list held in three places would let a device be registered on one front-end and invisible on another.

## Solution

One catalogue file, read by all three front-ends and copied by none, with the rules that keep the renderings in step and a check that fails when they do not. The flow stays data; only the chrome is per protocol. A job a protocol cannot finish hands off to one that can rather than dead-ending. A member's credential set is one record rendered three ways.

This document names the file, its columns and the words that must read identically, so that the three front-end specs can defer to it the way they already defer to the intent API in `signup-and-account-page.md`. The terminal front-end's own home and shape are fixed by [Amend the SSH onboarding TUI spec for the portal redesign](https://github.com/kyriakon/kyriakon-infra/issues/361); this document fixes only what all three share.

## The catalogue

The catalogue is `openbsd/etc/onboard/catalogue.tsv` in the repository, seeded into the store as `/var/db/onboard/catalogue.tsv` by `scripts/onboard-store.sh` beside the question list and the reserved names, and read from the path `onboard.toml` gives it, beside the `questions` and `reserved` keys it already carries (`catalogue = "/var/db/onboard/catalogue.tsv"`), on the reason that file already gives for the other two: so that a layout moves them rather than the service reading an empty list and rendering nothing. It is tab-separated with a header line naming the columns, one record per line in display order, which is the shape the question file already set: a reader can open it in an editor, a diff of it is readable, and no front-end needs a parser beyond splitting on tabs.

The columns are `id`, `name`, `summary`, `state`, `host` and `action`.

- **`id`** is stable and lowercase. The check compares ids, and an intent that names a service names it by id.
- **`name`** is what a reader sees, in sentence case, and it is the same string in all three renderings.
- **`summary`** is one clause, no trailing full stop, short enough for a gemini link label and for one terminal menu row.
- **`state`** is one of `live`, `by_request` or `planned`. `live` is served today, `by_request` exists and is arranged with a person, and `planned` is decided and not built. The three words are the whole vocabulary, and a front-end may not invent a fourth.
- **`host`** is the hostname the service lives at, with no scheme, because a hostname is protocol-agnostic: that is the reason the capsule already shares one name with the web page. A front-end adds the scheme its own protocol speaks. A host containing `<name>` is rendered from the session's member where there is one, and as the pattern itself where there is not.
- **`action`** is one of `read`, `apply`, `account` or `pay`. `read` shows the service's own page, `apply` starts the application, `account` opens the member's account surface, and `pay` opens the payment window or the rail's instructions. A hand-off is how a front-end renders `pay` where the protocol cannot take a card, so it is a rule rather than a fifth value.

The values as they stand on 2026-10-13, which is a snapshot and not the source: once the file exists, the file is the source and this table is history.

| id | name | summary | state | host | action |
| --- | --- | --- | --- | --- | --- |
| mail | Mail | zero-access mail, 5 GB, IMAP and SMTP, readable only by you | live | mail.kyriakon.net | read |
| web | A website | static pages at an address of your own, uploaded by sftp | live | `<name>`.kyriakon.net | read |
| gemini | A gemini capsule | the same pages over the gemini protocol | live | `<name>`.kyriakon.net | read |
| git | Repositories | `pass`-compatible git over ssh, on port 2222 | live | mail.kyriakon.net | read |
| account | Your account | the password, the keys, the space used, the serving switches, the notices | live | signup.kyriakon.net | account |
| pay | Paying | card, cash by post or Monero, and the window each one opens | live | signup.kyriakon.net | pay |
| free | No charge | for clergy, monastics, and anyone who cannot pay | live | signup.kyriakon.net | read |
| own_domain | A parish's own domain | your domain, up to ten addresses, with mail, a site and a capsule | live | signup.kyriakon.net | apply |
| managed | A managed instance | your own server, run for you, by arrangement | by_request | signup.kyriakon.net | read |
| key | Keys | making a mail key and an upload key, and the browser generator | live | signup.kyriakon.net | read |
| capsule_signup | Applying over gemini | the whole application over gemini, with no browser | planned | signup.kyriakon.net | apply |
| terminal | The terminal | apply, read your account and manage your keys from an ssh session | planned | ssh.kyriakon.net | read |
| press | Kyriakon Press | the press, its books, and the state it is in | live | press.kyriakon.net | read |
| shop | The bookshop | the Press's books, ordered from its own page once the shop is built | planned | press.kyriakon.net | read |
| kleio | Kleio | the sibling project, and the state it is in | live | kleio.kyriakon.net | read |

Two of those lines are projects rather than services, and they are in the catalogue because the site's own splash carries them and a member exploring the platform should find them the same way. Their pages state their own state, and their `state` word here says nothing more.

A front-end that is itself named in the list marks its own entry as where the reader is. The web form marks nothing, because it is the default.

## What each front-end renders

The renderers are pure functions of the catalogue. Each returns rows, and the templates or the drawing code format them, which is what makes the check possible: a list that came from somewhere else cannot pass it.

- **Web.** `onboard/src/page.rs` renders the rows into `onboard/templates/`, as a card per entry on the application page and a list on the account page, each one a link on the entry's `host` over `https`. The card's body is the `summary`.
- **Gemini.** The same binary's gemtext renderer writes one line per entry, `=> gemini://<host>/ <name>: <summary>`, so the name and the clause travel in the link label, which is the only place a gemtext link carries text.
- **Terminal.** The front-end draws a menu, one row per entry, `name` followed by the state's word, with the `summary` shown beneath the selected row. Enter follows the `action`.

One entry, three ways, which is what a reader should see move together when it changes:

```
https://signup.kyriakon.net/  ->  a card titled "Mail", reading
                                  "zero-access mail, 5 GB, IMAP and SMTP, readable only by you"

gemini://signup.kyriakon.net/ ->  => gemini://mail.kyriakon.net/ Mail: zero-access mail, 5 GB,
                                  IMAP and SMTP, readable only by you

ssh apply@ssh.kyriakon.net    ->  Mail                    live
                                  zero-access mail, 5 GB, IMAP and SMTP, readable only by you
```

## The rules that keep them in step

**A fact lives in one file.** The catalogue, the question list and the reserved names are each one file read by three front-ends, and none of them is copied. The state words and the action words are one table in the crate rather than one per renderer, so a new state cannot arrive with a word for the web and none for the terminal.

**The flow is data and the chrome is per protocol.** The order, the branches and the validation are the question file's; the catalogue's order is the catalogue's. What a front-end owns is its chrome: the titles, the hints, the confirmations and the shape of a screen. The capsule spec already says this of the application's grouping, that it is presentation and the capsule ignores it, and this document generalises it to everything the three render.

**Hand off rather than dead-end.** Where a protocol cannot finish a job, the entry points at one that can, as a link the client can open rather than an address to transcribe:

| The job | The web page | The capsule | The terminal |
| --- | --- | --- | --- |
| Paying by card | in place | hand off to the payment link over `https` | hand off to the payment link, printed as a link |
| Paying by post or Monero | the token, the address or the subaddress, in place | the token printed; the rail's instructions over `https` | the token and the instructions, in place |
| Reading a document with images | in place | the gemtext mirror of it | hand off to the page over `https` |
| A key too large to paste | never arises | upload by Titan, or the `apply@` mail route | never arises |
| An account action | in place | hand off to the terminal or the web page until the capsule can identify a member | in place |
| The data export | the bundle is in the member's own sftp tree | hand off to the terminal or the web page | in place, as the intent |

**A member's credentials are one record.** The upload keys and the pinned gemini certificate hashes live on the account, and every front-end that can identify a member lists the same set and files the same intents to add or remove one. Registering a device is a first-class action rather than something only an ssh session can do. The web page and the terminal both carry it, because they both have the member; the capsule carries it once a pinned certificate identifies them, which is the mechanism in `gemini-capsule.md`.

## The wording that must read identically

| The wording | Where it lives | Who reads it |
| --- | --- | --- |
| A service's name and its one clause | `openbsd/etc/onboard/catalogue.tsv` | all three |
| A question's prompt, its type and its validation | `openbsd/etc/onboard/questions.tsv` | all three |
| The word for each state and each action | one table in `onboard/src/catalogue.rs` | all three |
| The hand-off sentence for each job a protocol cannot finish | the same table | per front-end |
| The account page's capability list and what each part rests on | `docs/planning/specs/signup-and-account-page.md` | the web page and the terminal |
| The terms, the acceptable use policy and the privacy notice | `docs/`, generated onto the site | the site and the capsule's mirrors |
| The reserved names, including every hostname the platform uses | one file shared by the three | all three |

## What is deliberately per front-end

- The shape of a screen: four cards, one question per page with a counter, or a full-screen menu.
- Titles, hints and confirmations, which should be short, because gemini has no styling and a terminal has less room than a page.
- What a protocol cannot do: images, a card payment, a pty, a link a client will open.
- The length of a line. A gemtext link label is one line, and a terminal row is one line, so the `summary` is written to fit both.

## The account's surfaces, per front-end

The account page's table in `signup-and-account-page.md` is the whole list of what an account can do, and it is the source for all three. What each front-end does with it is the split decided in [Decide the shared copy](https://github.com/kyriakon/kyriakon-infra/issues/359): the web page carries every part today, the terminal carries the same parts as intents once the drain exists, and the capsule carries the reading half first and the acting half once a member's certificate identifies them. No front-end may add a capability the table does not have, which is the account-level form of the rule that no front-end may show a service the catalogue does not.

## Testing decisions

One seam is worth tests, and it is the join between the catalogue and the three renderings, because a defect there tells a reader about a service that does not exist or hides one that does.

- Every id in the tracked `catalogue.tsv` appears in all three renderings, compared as rows rather than as strings, since each renderer returns a list and the templates format it.
- Each renderer is rendered from a small fixture that differs from the shipped file, and the three outputs must follow the fixture. This is what catches a list that was hard-coded beside the file: a renderer that ignores its input passes the first check and fails this one.
- Every `state` and every `action` value in the file has a word in every front-end's vocabulary, so a new value cannot arrive with a rendering for one front-end and none for the others.
- The question list gets the same treatment where the three renderings of a question differ, and the existing checks in `onboard/src/questions.rs` stay.

Nothing else here is worth a test. The chrome is copy, and copy is checked by reading it.

## Not verified

Nothing in this document has been run. `openbsd/etc/onboard/catalogue.tsv` does not exist, `onboard/src/catalogue.rs` does not exist, the three renderings named here are not written, and the terminal front-end has no Rust home yet: [Amend the SSH onboarding TUI spec for the portal redesign](https://github.com/kyriakon/kyriakon-infra/issues/361) fixes that, and it should provide the crate as a library so the catalogue has one home and no copy. The catalogue's values are a snapshot of 2026-10-13 and the file is the source once it exists, which is the point of writing them down in one place.

## Sources

- `openbsd/etc/onboard/questions.tsv`, the file shape this document copies: a header naming the columns, tab-separated, one record per line in display order.
- `onboard/src/questions.rs`, `onboard/src/page.rs` and `onboard/templates/`, the service as built: the question list is read once and rendered by more than one front-end already.
- `docs/planning/specs/signup-and-account-page.md`, read on 2026-10-13: the intent API and its record, the question file's six columns, the store root, the handler's write boundary, the account page's capability table, and the line that the signup copy's home is the site workstream.
- `docs/planning/specs/gemini-capsule.md`, read on 2026-10-13: the counter and the pages, the status page, the `apply@` route, the pinned-certificate mechanism, and the sentence that the application's grouping is presentation and the capsule ignores it.
- `docs/planning/specs/ssh-onboarding-tui.md` and `docs/planning/specs/per-member-hosting.md`, read on 2026-10-13: the terminal front-end's session, the port split, and the one key that serves sftp and git.
- Decisions: [Decide the shared copy](https://github.com/kyriakon/kyriakon-infra/issues/359), [Decide the SSH portal's entry address and port](https://github.com/kyriakon/kyriakon-infra/issues/360), [Decide whether the projects sit on their own hostnames](https://github.com/kyriakon/kyriakon-infra/issues/187), [Decide what the public release promises, and where](https://github.com/kyriakon/kyriakon-infra/issues/158).
