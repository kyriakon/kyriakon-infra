# Prepaid payment rails in the onboarding service

> Spec synthesised from [Spec the prepaid payment rails in the onboarding service](https://github.com/kyriakon/kyriakon-infra/issues/114) and the decisions it points at: [#151](https://github.com/kyriakon/kyriakon-infra/issues/151) (the Stripe rail set), [#152](https://github.com/kyriakon/kyriakon-infra/issues/152) (the agreement set, the refund position and the ledger key), [#153](https://github.com/kyriakon/kyriakon-infra/issues/153) (the lifecycle states), [#156](https://github.com/kyriakon/kyriakon-infra/issues/156) (the service's architecture and trust boundary), [#158](https://github.com/kyriakon/kyriakon-infra/issues/158) (what the site may promise) and [#159](https://github.com/kyriakon/kyriakon-infra/issues/159) (the flow and the account page). ADR 0009 in the sibling meta repository keys the financial ledger by the approval token. Working material: this file lives in `docs/planning/specs/` until its tickets close.

## Problem statement

The public release sells the same £20 membership on two paths. Card payers keep Stripe, so the renewal reminder and the dunning path that `invoice.payment_failed` provides keep working. Everyone else pays cash by post, cash in hand, or Monero, and nothing about those payments reaches a payment processor at all.

That second path is where the platform's own record becomes the only record. There is no processor to ask whether a member has paid, no processor-held list of who they are, and no processor event to tell the service a payment arrived. The operator has to join an anonymous payment to an account, extend a date, keep a record good enough for HMRC, and do it without the account name ending up in six years of financial history.

Two things make this work. Each approval issues one token, and that token is the payment reference the member posts or sends, the key the ledger holds, and the bearer secret of the status page. The paid-until date on the platform's own machine decides access, so a rail is only ever a way to extend a date.

## Solution

Approval provisions the account, issues a token and opens a 14-day payment window. The member pays by card, by post, in hand, or in Monero. The operator records the payment as one action tagged with the rail, which writes a line to a ledger keyed by the token and moves the paid-until date. A window that closes with nothing recorded leaves the account lapsed, and the existing 40-day grace and deletion sweep from [#153](https://github.com/kyriakon/kyriakon-infra/issues/153) run from there.

The service keeps its two halves. The internet-facing handler renders the account page and files intents, and it holds no privilege. The one-minute cron drain issues tokens, applies credits, writes the ledger, extends dates and sends notices. There is one write path into payment state, and it is the drain's.

## The token

**Format.** `KYR-` followed by twelve characters drawn from Crockford base32 (the digits and the uppercase letters with `I`, `L`, `O` and `U` removed), grouped into three blocks of four, as in `KYR-4F2M-9QH7-XT3B`. Twelve characters at five bits each carry 60 bits of entropy, which is far beyond what a rate-limited lookup could be guessed against, and the alphabet keeps a token read off paper unambiguous.

**Generation.** The drain draws the twelve characters from `getrandom` at approval and writes them into a new account. The token is not derived from the username, the mail key, the application answers or the date. A token that could be recomputed from the account would undo ADR 0009: the ledger would stop being unlinkable once an account is deleted.

**Three jobs.** The token joins a payment to an account, it is the key the HMRC ledger holds with no username, and it is the string the account page shows while the window runs. This is [#159](https://github.com/kyriakon/kyriakon-infra/issues/159)'s reading of Mullvad's payment page, mapped onto the ledger key ADR 0009 already requires.

**Lifetime.** The token is created at approval and the account carries a reference to it for as long as the account exists. The status page answers with it for seven days after the decision, and the account page shows it in full while `paid_until` is null. Once a credit has set a paid-until date, the account page stops showing it, which is the [#114](https://github.com/kyriakon/kyriakon-infra/issues/114) decision that the token is visible again only while the account is unpaid. The string stays in the ledger for the records duty, which runs five years past the filing deadline and six once VAT is registered, and the mapping from the string to the username is deleted with the account.

**Reissue.** There is no reissue. `onboardctl token resend` sends the same token again, because a second token for one account would leave the first one in the ledger as an entry that no longer resolves to the same member, and would orphan a payment already in flight.

**Custody.** The token is a bearer secret: anyone holding it can open the status page, and anyone holding it can have a payment attributed to that account. It is never written to a log line, never put in a URL that is logged by `relayd`, and never sent to a third party. The status page is rate-limited per source address in the handler, and a lookup that finds no token returns the same page as an expired application, so the endpoint cannot be used to test whether a token exists.

## The rails

### Card

Unchanged, and specified in `docs/planning/research/stripe-rail-set.md`. The approval email carries a Payment Link with `client_reference_id` set to the application's identifier, Stripe's webhook pays into the drain, and the credit is deduplicated on `event.id`, with `data.object.id` and the event type breaking the tie when one change produces two events. This spec only notes the one shared rule: a card credit and a prepaid credit both call the same date arithmetic described under "Recording a credit".

### Cash by post

The account page and the approval email carry the token, the amount, and the postal address. The member writes the token on the envelope, or on a slip of paper inside it, and posts the money. Nothing else is asked for: no name, no return address, no application reference.

The postal address the member is given is a deployment value, not a repository one. It lives in the service's operator configuration on the box, `REPLACE_ME` in every tracked file, because it is the operator's own address and the repository is public. The terms page publishes the same address with the trader's identity, as the seller-obligations research requires, and the site build substitutes it at deploy time.

The operator opens the envelope, reads the token, banks the cash with the rest of the takings, and destroys the envelope. Nothing written on the envelope is retained: a name or a note inside it is read and not recorded, because the platform collects no legal name and no postal address from a member (ADR 0009). The token is already known to the service, so the only new fact is that £20 arrived on a date.

An envelope whose token is missing or illegible is not a credit. It goes to the unattributed queue described below.

### Cash in hand

A member who meets the operator hands over the money, and the operator credits it on the spot with the rail tag `cash-hand`. There is no envelope and no token to read, so this is the one credit the operator makes against a username rather than a token; the drain resolves the username to the token before it writes anything, so the ledger line is keyed the same way as every other one.

### Monero

The price is £20 and it is denominated in pounds. Monero is a way to settle that debt, not a separate price, and the platform quotes a Monero amount for the window rather than holding a Monero balance as the thing that is owed.

**The address.** Each member is given a subaddress of the platform's wallet, one per account, at approval. The Monero project's own guidance is to give services subaddresses rather than payment IDs: long payment IDs were removed from the wallet in release 0.15, and the deprecation notice recommends subaddresses directly, since one subaddress per payer attributes a payment with nothing to match by hand and nothing to forget. A mainnet address is 95 characters in a form the wallet generates freely, so the member sends to it exactly as they would send to any other address.

**No payment ID.** The code the member is given for the cash rail is not a Monero payment ID. A modern wallet can attach only a 64-bit compact payment ID, and only inside an integrated address, and the token is a twelve-character string. Attribution comes from the subaddress, and the account page and the approval email say so. The clickable prototype on the open pull request [#186](https://github.com/kyriakon/kyriakon-infra/pull/186) shows a payment ID in the Monero block; that line is legacy copy and is replaced by the subaddress and the quoted amount.

**The payment identifier.** The transaction id is what the service deduplicates on. The credit command takes `--txid`, the drain records it on the ledger line, and a second credit for the same transaction is refused.

**Confirmations.** A payment is credited once the operator sees ten confirmations, which is the depth the wallet itself asks for before the funds can be spent. How long a member should expect to wait is a promise about the site, and what the site may promise about the rail is #178's to settle rather than this spec's.

**The wallet's home, and its watching.** Decided in [#178](https://github.com/kyriakon/kyriakon-infra/issues/178): the wallet is the operator's and the mail box holds **no key material of any kind**, no spend key, no view key and no watch-only credential, because this box is the machine the threat model treats as seizable and because OpenBSD 7.9 carries no Monero package and this box has no ports tree, so a wallet here would mean building Monero from source on a mail server. Nothing on the platform watches the chain either: an arrival is seen in the operator's own wallet during the same pass that records the credit, so there is no process to keep alive and nothing on the box that could credit a fabricated transfer. That pairing is what makes the credit below a human action rather than a poll result.

The subaddress is created at approval in the operator's wallet and recorded against the account, one per member, permanent, never rotated and never reused, since a subaddress costs nothing and there are more than four billion of them. An approval made away from the wallet leaves the address to the next wallet pass, and the account page says the address is not ready yet rather than showing an empty field.

When Monero volume makes the manual step bite, the upgrade is a view-only wallet on a small always-on operator host with an authenticated RPC the drain may call, against its own node or a trusted public one, with the credit still confirmed against the operator's own wallet, because a public node could feed a fabricated transfer.
## The rate

The quoted amount is computed once, when the window opens, and honoured for the window's fourteen days. The member has one number to send and does not have to check the page at the moment they send it; the drift is bounded by one year's fee and the platform carries it. That is a deliberate choice against re-quoting daily, which would leave a member who sent the amount they were shown owing a difference they never agreed to.

The rate comes from one named source, recorded with the quote. The endpoint used here is CoinGecko's public price endpoint, which needs no key: `https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies=gbp&include_last_updated_at=true` returned `{"monero":{"gbp":409.44,"last_updated_at":1790857880}}` when read on 2026-10-01. The drain caches the response for 24 hours in `rates/xmr-gbp.json`, so the egress is a handful of requests a day and nothing about a member leaves the box. The handler never calls the endpoint; it reads the cached value.

Two cases are handled explicitly. If the source is unreachable but a cached rate exists, the quote is taken from the cache and marked stale, and the account page does not show the Monero block at all. If no rate has ever been fetched, the window opens with cash as the only prepaid rail and the page says so.

The quoted amount is `price ÷ rate`, rounded up to six decimal places, which is inside Monero's twelve-decimal atomic unit. A transfer within one percent of the quote is credited in full, which absorbs the rounding and the drift between the quote and the transfer; a larger shortfall leaves the remainder quoted on the account page to top up; and anything above the price becomes `payment.balance_gbp` against the next renewal rather than being refused or treated as a donation. The ledger line carries the invoice amount in pounds, the rate that produced the quote together with its source and timestamp, the amount received in XMR, and the rate on the day the payment was recorded. HMRC's cryptoassets manual requires profits and gains to be converted to sterling "using the appropriate rate at the time of each transaction" with a consistent methodology and a record of it (CRYPTO40100, read 2026-10-01), so the receipt-date rate is the one that values what arrived, and the quoted rate is the one that explains what was asked for. The gap between them is where the platform's rate risk lands, and it is visible in the ledger rather than buried in a balance.

The rate source's free-tier request limit is not stated on the endpoint and was not verified in this session; the 24-hour cache is what keeps the drain inside any plausible tier.

## The window

Approval opens the window. `paid_until` is null at that moment, the account state is `active`, and the window closes fourteen days later. A member who pays inside the window gets a year from the day the payment is recorded, not from the day the window opened, so paying early costs nothing and paying late costs nothing either.

The window closes and the account lapses. Lapsed is the [#153](https://github.com/kyriakon/kyriakon-infra/issues/153) state, not a new one: mail keeps arriving and stays readable, everything published stays up, and sending, uploading and pushing stop. The account is not deleted. The 40-day grace and the notices that lead to deletion are the same ones the failed-renewal path already uses, and the seven-day final notice runs from the same sweep.

One extension is available. A member who says the money is in the post gets `onboardctl window extend <token> --days 14 --reason "member says posted"`, which moves `closes_at` fourteen days and increments a counter on the window. A second extension is refused. This exists because the post is unreliable in both directions and a lost envelope is not the member's fault; it is capped because the window is a courtesy, not a free tier.

## Recording a credit

Every credit runs the same arithmetic:

```
paid_until_after = max(today, paid_until_before or today) + 1 calendar year
```

One calendar year means the same day in the following year, with 29 February clamped to 28 February. Extending from the later of today and the existing date means a renewal paid early adds a full year with nothing lost, and a payment made after a lapse restores access from the day it is recorded. A credit also sets `payment.rail`, closes the window and sends the receipt notice, and it is the setting of `paid_until` that hides the token from the account page.

A credit that would push `paid_until` more than 24 months past today is refused without `--override <reason>`. The ceiling is not a product limit; the price is annual and prepaying further is not offered. It catches an operator who credits the same envelope twice or types the amount into the wrong field, and the override writes its reason to the journal.

The ledger line is append-only and looks like this:

```json
{"version":1,"seq":1043,"token":"KYR-4F2M-9QH7-XT3B","kind":"payment","rail":"cash",
 "received_on":"2026-10-04","amount_gbp":"20.00","applied_gbp":"20.00",
 "paid_until_after":"2027-10-04","amount_xmr":null,"rate_quoted":null,
 "rate_source":null,"rate_at":"2026-10-04T09:10:00Z","txid":null,
 "intent":"01J8Z0Q4C7","note":"posted envelope"}
```

`seq` is an append-only counter, and a refund line names the `seq` it reverses. The line holds no username, no contact address and no name, which is what makes ADR 0009's unlinkability true rather than aspirational. The username lives in the token index, which is deleted with the account.

## Two payments with one token, and one payment with none

Two payments sharing a token, where the first is already credited, are treated as a renewal. The second credit needs `--confirm-double`, because for cash the second envelope may be a stranger's with a copied token, and because the same member paying twice by accident is the likelier case only if they say so. If the second credit is applied it extends the date and lands under the 24-month ceiling; if the operator cannot tell whose money it is, it goes to the unattributed queue and the account keeps the first credit.

A payment that carries no token, or a Monero payment to the wallet's main address rather than a member's subaddress, cannot be joined to anything. It goes to `ledger/unattributed.jsonl` and is held: recorded with the rail, the amount, the date and a free-text note, and marked `held`. It is not income until it is attributed or the tax year ends, and it is never silently absorbed into a member's credit. The operator tries the postmark, the date, the amount and any note, and either attributes it with `onboardctl reconcile attribute` or returns it with `onboardctl reconcile return`, which records the postal evidence and nothing about the person. Anything still held at the end of the tax year is recorded in the main ledger as a payment with no token, which is the one line in that file without a token and the only one without an invoice behind it.

## Refunds

A cancellation inside the fourteen days is refunded in full, in the rail the member paid, or held against the next year if they would rather (from [#152](https://github.com/kyriakon/kyriakon-infra/issues/152)). A refund under the cancellation right closes the account and starts the seven-day closing window; a refund of an overpayment or a duplicate does not touch the account.

The command is `onboardctl refund (--token <t> | --username <u>) --amount <gbp> --rail <rail> --reason <text>`, with `--close` for a cancellation and `--excess` otherwise. It writes a negative ledger line naming the `seq` it reverses, and it does not move `paid_until` on an `--excess` refund. Reg 34(4) gives fourteen days to pay it back, so the notice that goes with the refund states the date it will be settled.

Card refunds go through Stripe with an `Idempotency-Key`, which is the same mechanism the research note describes for the rail's other calls.

Monero refunds send back the amount of XMR recorded on the receipt line, to an address the member supplies. Returning the recorded amount exactly undoes the transaction, is verifiable from the ledger, and avoids the platform acting as a currency exchanger. If the member would rather have the sterling price at the refund date, the operator records the refund-date rate instead and the same line carries it; the choice is visible in the ledger either way.

Posted cash is the case with no clean answer. Paying it back by bank transfer, from a rail that received untraceable cash, to an account the platform cannot verify, at a volume where identity checks are disproportionate, is the shape of a laundering service and the platform will not do it. So a refund of posted cash goes back as cash by post: the operator posts the money, recorded delivery or signed for, to an address the member supplies, and keeps the posting receipt as the evidence. The member may instead take the credit against the next year, or ask for the money to go to a cause. The address is used once and is not written to the account or the ledger, because the platform deliberately collects no address that ties an account to a person's other life.

The refusal is checkable in the configuration, which is the ADR 0008 standard: no code path sends money out on a rail other than the one the payment arrived on, and the refund path for cash contains no bank details at all.

Hosting is not a regulated sector under the Money Laundering Regulations 2017. Regulation 8 lists the relevant persons, and the list runs to credit and financial institutions, auditors, tax advisers, legal professionals, trust and company service providers, estate agents, high value dealers, casinos, art market participants, cryptoasset exchange providers and custodian wallet providers (read on 2026-10-01). The platform is none of these at £20 a year. The one entry that comes near it is high value dealer, which regulation 14(1)(a) defines as a firm or sole trader who by way of business trades in goods and receives cash of at least £10,000 in one transaction, or in several that appear to be linked (read on 2026-10-01). Hosting is a service rather than trade in goods, and the payment is three orders of magnitude below the figure, so neither condition is met. The rule above is one the platform keeps for its own sake rather than one these regulations impose.

## The operator's reconciliation

The drain does the automatic work: the window-close sweep, the lapse, the grace and the deletion notices, and applying whatever intents are waiting. The operator's part is a weekly pass during which they read the post, open the envelopes, look at the wallet, and record what they found.

```
onboardctl prepaid list --window open --expiring 3
```

This is the pass's first command. It lists every open window with the token, the username, the rail, the close date and the days left, and `--expiring 3` narrows it to the ones about to close, which are the ones worth an email before they lapse.

```
onboardctl credit --token KYR-4F2M-9QH7-XT3B --rail cash --amount 20.00 --received 2026-10-04
onboardctl credit --username frseraphim --rail cash-hand --amount 20.00 --received 2026-10-04
onboardctl credit --token KYR-4F2M-9QH7-XT3B --rail monero --amount 20.00 --received 2026-10-04 \
  --txid <64 hex> --xmr 0.048847
```

The credit is the one action per payment. It writes an intent, and the drain applies it on its next run, so the operator can record four envelopes in a row without waiting for each one.

```
onboardctl reconcile list
onboardctl reconcile attribute UN-3K7QW2M9 --token KYR-4F2M-9QH7-XT3B
onboardctl reconcile return UN-3K7QW2M9 --note "posted back 2026-10-08, receipt in book"
```

The first lists everything held without a token. The second joins one to an account and turns it into an ordinary credit. The third records that it went back or was kept, with the evidence, and closes the item.

```
onboardctl window extend --token KYR-4F2M-9QH7-XT3B --days 14 --reason "member says posted 2026-10-02"
onboardctl refund --username frseraphim --amount 20.00 --rail cash --reason "cancelled inside 14 days" --close
onboardctl token resend frseraphim
onboardctl payment show --username frseraphim
onboardctl ledger export --tax-year 2026-27 --format csv
```

The window extension is the one case the operator answers on the member's word. The refund is the command; posting the money, or issuing the Stripe refund, or sending the Monero, is the human step that follows it, and the operator records the settlement with `onboardctl refund --settled <date>` on the same line. `token resend` repeats the payment instructions without issuing anything new. The ledger export is the year's file for the accountant, and it contains tokens, amounts and dates, and no usernames.

The commands that already exist for the lifecycle are unchanged: `onboardctl approve`, `onboardctl decline`, `onboardctl suspend`, `onboardctl delete`. `delete` is the one that matters here, because removing the account's token index entry is what makes the ledger unlinkable, and it happens in the same transition that removes the mailbox.

Two human steps have no command. Opening the post and banking the cash is one, and holding the Monero is the other: the platform receives XMR and does not convert it, so the operator decides when, and whether, to sell. HMRC treats business income paid in cryptoassets as trading income and taxes what the holder does with it, so the ledger's record of the receipt rate is what the eventual disposal is measured against (CRYPTO40350 and CRYPTO40100, read on 2026-10-01). Whether a disposal is taxed as trading or as a capital gain is the accountant's question, and it is out of scope here.

## The account page while the window runs

The payment block sits at the top of the account page, above the usage and certificate rows, because it is the only thing on the page that expires.

While the window is open and `paid_until` is null, the page shows: the state (`active`), the rail the member chose, the days left in the window and the date it closes, the amount, the token in full, and the rail's instructions. For cash by post that is the token and the postal address. For Monero it is the subaddress, the quoted XMR amount, the rate it was quoted at, and the sentence that the pound amount is what is owed. Both blocks carry the sentence that the money must arrive before the close date, that the account lapses if it does not, and that nothing is deleted at that point. The Monero block states what [#178](https://github.com/kyriakon/kyriakon-infra/issues/178) allows the site to promise: the pound amount is what is owed and the XMR figure is only its conversion, the quote holds for the window, the address is the member's permanently, and the payment counts once it has ten confirmations. The rail's own copy states that money sent to the wrong address or with no subaddress is held and reconciled by hand rather than absorbed, and that a refund returns in XMR to an address the member gives, or as credit against the next year.

After a credit, the block reads `Paid until <date>`, the token disappears, and the receipt notice is listed with the other notices. The rail stays visible, because the member needs to know which rail the next payment will be quoted for.

After the window closes with nothing recorded, the block reads `Lapsed`, repeats the close date, and states what still works and what has stopped, with the same wording the lapse notice uses. The token is shown again, because the account is unpaid and someone who lost the email still needs it, and the page keeps a line to `admin@` for anyone who has posted the money.

An account whose approval was without charge has no window, no token and no payment block.

## State

The store is the flat-file one from [#156](https://github.com/kyriakon/kyriakon-infra/issues/156), one directory per account under the store root named in the service's TOML, with an append-only journal and an intents directory. Paths below are relative to that root.

| Path | Status | What the prepaid rails put in it |
|---|---|---|
| `accounts/<username>/account.json` | modified | `payment.rail`, `payment.token_ref`, `payment.token_issued_at`, `payment.paid_until`, `payment.balance_gbp`, `payment.window{opened_at,closes_at,state,extensions}`, `payment.monero{address,quote_xmr,rate_gbp_per_xmr,rate_source,rate_at}` |
| `accounts/<username>/notices.jsonl` | modified | `prepaid.window_open`, `prepaid.window_closing`, `prepaid.receipt`, `prepaid.lapsed`, `prepaid.refund`, one line per notice with its date and address |
| `accounts/<username>/application.json` | modified | `status_link_until`, seven days after the decision; the answers themselves follow the existing 90-day purge (ADR 0005) |
| `tokens/<token>.json` | new | the join: token, username, `issued_at`, `window_closes_at`, `state`. Created at approval, deleted by `onboardctl delete` |
| `ledger/payments.jsonl` | new | append-only, keyed by token, no username. Every credit, every refund |
| `ledger/unattributed.jsonl` | new | payments with no token, held until attributed, returned or taken as income at the year end |
| `rates/xmr-gbp.json` | new | the cached XMR/GBP rate, its source and its fetch time; read by the handler, written by the drain |
| `intents/<id>.json` | modified | new kinds: `credit`, `refund`, `window-extend`, `reconcile-attribute`, `reconcile-return` |
| `journal.jsonl` | modified | one line per payment transition, naming the intent that caused it |

Outside the store: the postal address and the rate endpoint URL live in the service's operator configuration under `/etc/kyriakon/onboard/`, root-only and off the repository. The price is a configuration value too, because the Stripe Price and the prepaid price have to agree and neither belongs in a literal.

`ledger/` sits inside the tree the existing backup job takes. The live file is never purged, so the records duty is met by the file itself rather than by a snapshot; the restic window of roughly seven months only bounds the copies, which the seller-obligations research already flags as the reason an accounting record must not live only inside the purge path.

## Events that can arrive twice

| Event | Dedup key | What the second arrival must do |
|---|---|---|
| The signed approve or decline link in the operator's email | the link's nonce, single use | find the application already decided and take no action |
| The approval intent | `intents/<id>.json` | find `payment.token_ref` set and write no second token and no second window |
| A card payment | `event.id`, plus `data.object.id` with the event type | find the credit already applied and extend nothing |
| A manual credit | the intent id, and for Monero the `txid` | refuse with the date of the first credit unless `--confirm-double` |
| The same Monero transaction seen again by whatever watches the wallet | `txid` | attribute nothing; the ledger already holds it |
| A refund | the intent id, and `refund_of` naming the original `seq` | refuse a second identical refund |
| The window-close sweep | the account's `payment.window.state` | find the window already closed and lapse nothing twice |
| The lapse notice, the grace notice and the final notice | `<notice-type>:<subject>`, checked against `notices.jsonl` | send nothing the account already records as sent |
| A rate fetch by two drain runs | the 24-hour window in `rates/xmr-gbp.json` | write the cache from whichever ran last |

Notices are recorded before they are enqueued, and a crash between the record and the send loses one email. That is the accepted direction of the trade: a lost notice is visible in `notices.jsonl` and on the account page, where a duplicate is a member reading the same message twice.

## Places where a human acts

| Step | Who | What they run |
|---|---|---|
| Approve, approve without charge, or decline | operator | the signed link in the email, or `onboardctl approve <username>`, `onboardctl decline <username>` |
| Open the post | operator | no command; the date the envelope was opened is the credit's `--received` |
| Record a posted cash payment | operator | `onboardctl credit --token <t> --rail cash --amount <gbp> --received <date>` |
| Record cash handed over | operator | `onboardctl credit --username <u> --rail cash-hand --amount <gbp> --received <date>` |
| Check the wallet and record Monero | operator | `onboardctl credit --token <t> --rail monero --amount <gbp> --received <date> --txid <id> --xmr <amount>` |
| Deal with money that arrived with no token | operator | `onboardctl reconcile list`, then `onboardctl reconcile attribute` or `onboardctl reconcile return` |
| Give a member one more fortnight | operator | `onboardctl window extend --token <t> --days 14 --reason <text>` |
| Refund | operator | `onboardctl refund ...`, then the Stripe refund, the Monero send, or the postal step, then `--settled <date>`; a posted-cash refund keeps the posting receipt |
| Bank the cash, hold or sell the Monero | operator | no command |
| Create the member's Monero subaddress | operator | `monero-wallet-cli` in the operator's own wallet, then `onboardctl monero address <username> <address>` |
| Hold the wallet, its seed and its view key | operator | no command; the seed and the view key stay together off the box, and the seed is what rebuilds watching if the machine is lost |
| Send the payment instructions again | operator | `onboardctl token resend <username>` |
| Close the books for the year | operator | `onboardctl ledger export --tax-year <year> --format csv` |
| Delete an account, which unlinks the ledger entry | operator | `onboardctl delete <username>` |
| Set the postal address and the price before release | operator | editing `/etc/kyriakon/onboard/`, once, off the repository |

## Testing decisions

The seam is the join between a payment and an account, because ADR 0009 says a defect there produces a wrong paid-until date. Three behaviours are worth a test each, and nothing else here is.

Extending a date twice from one intent leaves one ledger line and one year, which is the property that has to hold when the drain is restarted mid-write. Crediting a token that is not in the index is refused and goes to the unattributed queue rather than creating an account or a ledger line. A sweep run over an account whose window closed after a credit leaves the state `active`, which is the bug that would otherwise lapse a member who paid on the last day of the window.

The arithmetic itself is worth one table of cases: paying inside the window, paying after a lapse, renewing before the date, and 29 February. The rate conversion is worth one case for the rounding, since a quote that rounds down leaves the member a fraction short of the amount owed.

## Out of scope

The card rail's events, objects and dashboard configuration, which belong to the Stripe research note and to the card rail's own build. The site copy, which is the site workstream's. The tax treatment of disposing of received XMR, which is the accountant's. The DMCCA subscription regime, which is stated to commence in spring 2027.

## Further notes

The refusal list stays true by absence. The prepaid rail creates no object in Stripe, so nothing about a prepaid member reaches the processor. The paid-until date is on the box and decides access, so Stripe reports rather than rules. The ledger holds no username, no contact address and no name, and the token index that joins a token to an account is deleted with the account. The cash refund path contains no bank transfer, which is a refusal a reader can check by searching for one.

The two facts worth carrying into the build: the token is a bearer secret and must be kept out of logs, and the ledger line is the only record that survives the account, so the `seq`, the rail, the amount and the date are the fields that must never be guessed or derived.

## Sources

- CoinGecko public price endpoint, `https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies=gbp&include_last_updated_at=true`, read on 2026-10-01, returned `409.44` GBP per XMR. The free tier's request limit is not documented on the endpoint and was not verified.
- Monero: [Payment ID](https://www.getmonero.org/resources/moneropedia/paymentid.html), [Address](https://www.getmonero.org/resources/moneropedia/address.html), [View Key](https://www.getmonero.org/resources/moneropedia/viewkey.html) and [Accepting Monero](https://www.getmonero.org/get-started/accepting/), all read on 2026-10-01, together with the [long payment ID deprecation notice](https://www.getmonero.org/2019/06/04/Long-Payment-ID-Deprecation.html) of 2019-06-04.
- HMRC Cryptoassets Manual: [CRYPTO40100, conversion to Sterling and accountancy](https://www.gov.uk/hmrc-internal-manuals/cryptoassets-manual/crypto40100) and [CRYPTO40350, business income paid in cryptoassets](https://www.gov.uk/hmrc-internal-manuals/cryptoassets-manual/crypto40350), both read on 2026-10-01.

- The Money Laundering Regulations 2017, [regulation 8](https://www.legislation.gov.uk/uksi/2017/692/regulation/8) and [regulation 14](https://www.legislation.gov.uk/uksi/2017/692/regulation/14), read on 2026-10-01. GOV.UK, [business records if you are self-employed](https://www.gov.uk/self-employed-records/how-long-to-keep-your-records), read on 2026-10-01.
- Repo notes: `docs/planning/research/stripe-rail-set.md` and `docs/planning/research/sole-trader-obligations.md`. ADRs 0005, 0008 and 0009 in the sibling meta repository. The clickable prototype behind the account-page copy is on the open pull request [#186](https://github.com/kyriakon/kyriakon-infra/pull/186), at `docs/planning/prototypes/signup-and-account-page.html`.
