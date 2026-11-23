# Card-rail tax handling: non-Union OSS with Stripe Tax, or a merchant of record

**Question:** for the card rail only, is a merchant of record (MoR) less total work than
the recorded plan, which is a non-Union OSS registration plus Stripe Tax, at this
platform's scale and privacy posture? If it is, which provider?

**Answer:** no, and the recorded plan stands. The prepaid rails (cash by post, cash in
hand, Monero) are open to every member, including a consumer in the Union, so the
platform remains the seller for those supplies and still owes the non-Union OSS
registration. A MoR moves only the card work. It also makes a payment processor the
seller of record, which contradicts ADR 0008's refusal of "a customer list held by a
payment processor" and the public check in `docs/refusals.md` that the processor holds
no member list. The fee difference is small either way: on a 70 per cent UK, 20 per cent
Union, 10 per cent rest-of-world card mix, Stripe Managed Payments costs £68 more than
the recorded plan at 100 members and £340 more at 500. If the card rail ever had to
move, Stripe Managed Payments is the provider, because it is the same Stripe account
and Payment Link, a UK business is eligible, website hosting is an eligible tax code,
and it absorbs the Union, India, Norway and the other thresholds for managed card
sales. Paddle and Polar need a new integration and cost more on the expected mix. Lemon Squeezy stops
accepting new stores and shuts down on 31 March 2027.

**How to read the sourcing.** Fees and contract terms below were read at the primary
source on 20 November 2026, and each carries a link. A sentence marked *(interpretation)*
applies a source to this platform and is a reading, not a quotation. Anything not
readable at a primary source is marked unverified. Nothing here is legal or tax advice.

---

## 1. The options, and the two things that changed

| Option | Seller of record | Fee per £20 card sale | Monthly fee | Registration and filing | Integration |
|---|---|---|---|---|---|
| Recorded plan: Stripe Payments, Stripe Tax Basic, operator registers non-Union OSS | the operator | 1.5% + 20p (UK card), 2.5% + 20p (EEA card), 3.15% + 20p (international card), plus 0.5% Stripe Tax where registered | none | operator registers the OSS and files quarterly, plus India on the trigger from #249 | built |
| Stripe Managed Payments | Stripe, through Onelink | 3.5% on top of the processing fee above | none | Stripe registers and files in 80+ countries for managed sales | same Stripe account and webhook shape; a new Payment Link |
| Paddle | Paddle, as reseller | 5% + USD 0.50 | none | Paddle handles sales tax for its sales | new integration |
| Polar | Polar | 5% + USD 0.50, plus 1.5% for non-US cards on Starter | none on Starter, USD 20 or more on paid plans | Polar handles tax for its sales | new integration |
| Lemon Squeezy | Lemon Squeezy | 5% + 50¢ | none | handled for its sales | not available: no new sign-ups, shutdown 31 March 2027 |

The recorded plan's card fees are on the UK pricing page ([Stripe pricing,
GB](https://stripe.com/gb/pricing), read 2026-11-20). Stripe Billing is 0.7 per cent of
Billing volume on pay as you go, and applies to the recorded plan and to Managed
Payments subscriptions, so it is common to both and is shown separately below. Stripe
Tax Basic is 0.5 per cent per transaction for a no-code integration such as a Payment
Link, or 40p per transaction for an API integration, and only where a registration is
active ([Stripe Tax pricing](https://stripe.com/gb/tax/pricing), read 2026-11-20).
Managed Payments adds 3.5 per cent per successful transaction to the standard
processing fees ([Stripe pricing, GB](https://stripe.com/gb/pricing), read 2026-11-20;
[Managed Payments
FAQ](https://stripe.com/gb/managed-payments), read 2026-11-20).

Two facts have changed since `stripe-rail-set.md` and `sole-trader-obligations.md` were
written, and both matter.

1. **Stripe Tax Complete now registers and files.** The recorded plan uses Tax Basic,
   which calculates and collects tax only, with the operator registering the OSS. Tax
   Complete is the newer option: it starts at £70 per month and includes EU non-Union
   OSS registration and filing, with 2 registrations, 200 transactions a month and 4
   filings a year in the entry tier ([Stripe Tax
   pricing](https://stripe.com/gb/tax/pricing), read 2026-11-20). It is a way to buy out
   the OSS filing work while remaining the seller, and it covers the prepaid rail's
   Union sales too, which a MoR does not.
2. **Stripe now has a merchant of record, and Lemon Squeezy is going.** Managed Payments
   is Stripe's MoR, built from the Lemon Squeezy acquisition. Lemon Squeezy stopped
   accepting new stores on 16 November 2026 and stops processing transactions on 31
   March 2027, and its migration page recommends Managed Payments
   ([Lemon Squeezy migration](https://docs.lemonsqueezy.com/migration), read
   2026-11-20; [Lemon Squeezy pricing](https://www.lemonsqueezy.com/pricing), read
   2026-11-20). A new merchant cannot choose Lemon Squeezy, so the "Stripe acquisition"
   question has one answer: the distinct product is now Managed Payments, and existing
   Stripe Payment Links remain direct Stripe sales unless they are replaced.

## 2. Cost at 100 and 500 paying members

Assumptions, all stated so the arithmetic can be checked.

- The standard tier is £20 a year, so 100 members is £2,000 of revenue and 500 is
  £10,000.
- Every member pays by card, because this note is about the card rail.
- The card mix is 70 per cent UK, 20 per cent Union, 10 per cent outside both. An
  all-UK mix is also shown, because it is the floor for the recorded plan.
- The Union rate is 20 per cent and the £20 is tax-inclusive, which is the #163
  decision that the price absorbs the Union rate. The tax is not a provider fee, so it
  is kept out of the fee totals and noted separately.
- The pound to dollar rate is £1 = USD 1.27, used only to turn Paddle's and Polar's
  USD 0.50 into pounds. The rate is an assumption, not a source.
- No disputes, refunds, currency conversion or failed payments are counted. Those are
  per-event costs, and section 3 describes who handles them.

### 2.1 Per member, per year

| Line | UK card | Union card | International card |
|---|---|---|---|
| Recorded plan, card processing | £0.50 | £0.70 | £0.83 |
| Recorded plan, Stripe Tax Basic | £0.00 (no UK VAT registration at this revenue) | £0.10 | £0.00 (no registration in that country) |
| Recorded plan, total | £0.50 | £0.80 | £0.83 |
| Managed Payments, 3.5 per cent | £0.70 | £0.70 | £0.70 |
| Managed Payments, processing | £0.50 | £0.70 | £0.83 |
| Managed Payments, total | £1.20 | £1.40 | £1.53 |
| Paddle, 5 per cent + USD 0.50 | £1.39 | £1.39 | £1.39 |
| Polar Starter, 6.5 per cent + USD 0.50 | £1.69 | £1.69 | £1.69 |

The UK processing figure is 1.5 per cent of £20 plus 20p. The Union figure is 2.5 per
cent plus 20p. The international figure is 3.15 per cent plus 20p, with no currency
conversion because the charge is in pounds ([Stripe pricing,
GB](https://stripe.com/gb/pricing), read 2026-11-20). Paddle's rate is 5 per cent of the
price plus USD 0.50 ([Paddle
pricing](https://www.paddle.com/pricing), read 2026-11-20; [Paddle master services
agreement](https://www.paddle.com/legal/terms), clause 3.2, read 2026-11-20). Polar's
Starter rate is 5 per cent plus USD 0.50, with 1.5 per cent added for non-US cards
([Polar fees](https://github.com/polarsource/polar/blob/main/docs/merchant-of-record/fees.mdx),
read 2026-11-20), so a UK or Union card is 6.5 per cent plus USD 0.50.

The Paddle row applies 5 per cent to the full £20. If Paddle computes its discount on
the tax-exclusive price, the Union figure falls to 5 per cent of £16.67 plus £0.39, or
£1.22, and the mixed annual figures fall by £0.034 a member, which is £3.40 at 100 and
£17 at 500. The pricing page does not settle which base applies, so the higher figure is
used and the difference is marked unverified.

### 2.2 Annual provider fees

| Option | 100 members, all UK | 500 members, all UK | 100 members, mixed | 500 members, mixed |
|---|---|---|---|---|
| Recorded plan, card and tax fees | £50.00 | £250.00 | £59.30 | £296.50 |
| Recorded plan, plus Stripe Billing at 0.7 per cent | £64.00 | £320.00 | £73.30 | £366.50 |
| Managed Payments, card and MoR fee | £120.00 | £600.00 | £127.30 | £636.50 |
| Managed Payments, plus Stripe Billing | £134.00 | £670.00 | £141.30 | £706.50 |
| Paddle | £139.00 | £695.00 | £139.00 | £695.00 |
| Polar Starter | £169.00 | £845.00 | £169.00 | £845.00 |

The mixed recorded-plan figure is 0.7 × £0.50 + 0.2 × £0.80 + 0.1 × £0.83 = £0.593 a
member, so £59.30 at 100 and £296.50 at 500. The mixed Managed Payments figure is
0.7 × £1.20 + 0.2 × £1.40 + 0.1 × £1.53 = £1.273 a member, so £127.30 and £636.50.

The Billing line is the known subscription fee. Stripe's Managed Payments support
article also says subscription payments incur an additional fee, but the article's body
did not render in this session and the amount could not be read. The 0.7 per cent is
therefore used for both Stripe options, and the exact Managed Payments subscription
surcharge is marked unverified at the end.

### 2.3 The difference against the recorded plan

Excluding Stripe Billing, which both Stripe options pay and Paddle and Polar include:

| Option | 100 members, all UK | 500 members, all UK | 100 members, mixed | 500 members, mixed |
|---|---|---|---|---|
| Managed Payments | +£70.00 | +£350.00 | +£68.00 | +£340.00 |
| Paddle | +£89.00 | +£445.00 | +£79.70 | +£398.50 |
| Polar Starter | +£119.00 | +£595.00 | +£109.70 | +£548.50 |

At this scale the fee difference is between £68 and £350 a year for the cheapest MoR.
The Union VAT is separate. Under the recorded plan the operator remits it through the
OSS. Under a MoR the MoR withholds and remits it. At 20 per cent, a £20 Union sale
leaves £16.67 before any provider fee under either option.

Two optional costs bracket the decision. Stripe Tax Complete at £70 a month is £840 a
year, which is 42 per cent of revenue at 100 members and 8.4 per cent at 500. It buys
the OSS registration and four filings a year, and it can include the prepaid Union
sales if they are imported. Stripe Tax Basic on the recorded plan costs £0.10 per Union
card sale, which is £2 a year at 20 Union members and £10 a year at 100.

## 3. What each provider actually handles

| Task | Recorded plan | Stripe Managed Payments | Paddle | Polar |
|---|---|---|---|---|
| Tax registration | operator registers the non-Union OSS; India on the #249 trigger | Stripe registers in supported countries for managed sales; the operator still registers the OSS for prepaid Union sales | Paddle registers for its resales; the operator still needs the OSS for prepaid Union sales | Polar registers for its resales; the operator still needs the OSS for prepaid Union sales |
| Filing | operator files the OSS quarterly, and GSTR-5A monthly if India is registered | Stripe files for managed sales; the operator still files the OSS for prepaid sales | Paddle files for its sales; the operator still files for prepaid | Polar files for its sales; the operator still files for prepaid |
| VAT invoices | none today, because there is no VAT registration in the UK; a Union B2C invoice is not issued by Stripe | Stripe issues tax invoices for managed sales where required | Paddle issues invoices as reseller | Polar issues invoices as reseller |
| Refunds | operator records the refund in the ledger, then refunds in the Stripe Dashboard; 14 days under reg 34 | operator or Stripe can refund; Stripe can refund within 60 days in certain cases, and without approval if a product support request goes unanswered for 48 hours | Paddle handles buyer refund requests and first-tier support; the supplier informs Paddle | Polar handles refunds; transaction fees are not returned |
| Chargebacks | operator responds or accepts in Stripe; £20 received fee and £20 to counter, returned only if won | Stripe handles the dispute and submits evidence; £20 received fee, evidence fee covered by Stripe | Paddle handles chargebacks and sets off losses | Polar charges USD 15 a dispute |
| Subscription dunning | Stripe Smart Retries and its customer emails; the paid-until date is ours | Stripe Billing and Onelink emails; the paid-until date is still ours | Paddle recovery and dunning | Polar dunning |
| Currency and payout | GBP charges; GBP payout, or 1 per cent for additional settlement currencies | Adaptive Pricing in the buyer's currency; GBP payout | buyer currency, converted to the supplier's Payment Currency with a 2 per cent margin for major currencies; monthly payout above £100 on the 15th | payouts through Stripe, USD 2 a month plus 0.25 per cent + USD 0.25 a payout, plus currency conversion |
| May a Union consumer be refused? | no, the platform's own decision is that anyone may apply; refusing the Union would reverse #163 and would not remove the OSS | no, every Union state is in the supported customer list; refusing them is a product choice, not a term | no Union state is excluded by the acceptable use policy; refusing them is a product choice | same |

The refund and chargeback fees are on the Stripe pricing page ([Stripe pricing,
GB](https://stripe.com/gb/pricing), read 2026-11-20). Managed Payments' handling of
disputes, support and refunds is in [How Managed Payments
works](https://docs.stripe.com/payments/managed-payments/how-it-works), read 2026-11-20.
Paddle's reseller role, first-tier support, refunds, chargebacks, set-off and payout
terms are in [the master services
agreement](https://www.paddle.com/legal/terms), clauses 2, 6, 7 and 10, read 2026-11-20.
Polar's refund and dispute terms are in [its fees
page](https://github.com/polarsource/polar/blob/main/docs/merchant-of-record/fees.mdx),
read 2026-11-20.

## 4. Seller of record and the data each option holds

| Option | Who the member buys from | What the processor holds | What the platform holds |
|---|---|---|---|
| Recorded plan | the operator, on every rail | a Stripe Customer for each card payer because subscription mode requires one, card data, receipts and invoices, and the billing address and country that Stripe uses as tax evidence | the token-keyed ledger, the paid-until date, the rail, and no name, postal address or country on the account |
| Managed Payments | Stripe, through Onelink, for a managed card sale; the operator still supplies the service | name, billing address, country, card, purchase history and subscription; the merchant's Stripe account also holds the Customer, PaymentMethod, Invoice, Subscription and Charge objects | the token-keyed ledger and the paid-until date; the card sale is not the operator's sale |
| Paddle | Paddle, as reseller | buyer name, address, country, card and transaction; some data is shared with the supplier under the Data Sharing Addendum | account data and the payment record, with Paddle as the seller |
| Polar | Polar | customer and payment data | account data and the payment record |

Managed Payments requires the customer to have a name and a valid billing address,
because it calculates tax from them ([Update a Checkout
integration](https://docs.stripe.com/payments/managed-payments/update-checkout), read
2026-11-20). The merchant's Stripe account holds the Customer, Invoice, Subscription and
Charge objects, and a customer deletion request deletes those objects in the merchant's
account too ([How Managed Payments
works](https://docs.stripe.com/payments/managed-payments/how-it-works), read 2026-11-20).

### 4.1 The conflicts with the current posture

**ADR 0008 and `docs/refusals.md`.** The refusal list says "No customer list held by a
payment processor", and the public check is "the payment state in the control plane,
once it lands, with the processor holding no member list" (the "A customer list held by
a payment processor" refusal in `docs/refusals.md`).
A MoR is a customer list held by a payment processor by definition. The processor is
also the seller, so it holds the name, address and purchase history that the platform
deliberately does not. This is not a wording problem. It reverses a refusal by choice
that a reader can currently check.

**`docs/transparency.md`.** "What it does not hold is a list of members" (the "Payments"
section) becomes false for card payers under a MoR.

**`docs/threat-model.md`.** The table row "A card processor cannot unilaterally cut the
platform off" (the "Prepaid payment rails" row under "Defence priorities") becomes
false: the MoR can terminate the seller relationship and stop card sales. The seizure
story also gains a third party that holds a member list, which is the property the
platform's payment design exists to avoid.

**`docs/privacy.md`.** "We collect no postal address at signup or at approval" and "We
hold no country on your account" remain true of the platform's own record, but checkout
now asks for a name and a billing address, and Stripe holds them as seller. The
third-party paragraph, "Stripe processes card payments and holds the card data", has to
say that Stripe is the seller of record for card purchases and the controller of the
name, address and country. The rights route for that data is Onelink support, not
`admin@`. The retention table needs a row for the data Stripe holds as seller, whose
retention the platform does not set.

**ADR 0009.** The token-keyed ledger still works and still becomes unlinkable on the
box after deletion, but the unlinkability claim weakens: the MoR keeps the link between
a name, an address and the purchase, outside the platform's deletion path. The decision
that the platform collects no legal name and no postal address is contradicted at
checkout, even though the platform's own account record stays clean.

**`docs/terms.md`.** The seller line, the contract counterparty for a card sale, the
14-day cancellation and refund route, the VAT invoice statement, the renewal reminder
(who sends it and in whose name), the statement descriptor and the sanctions line all
have to be rewritten for the card rail. Paddle reserves the right to set the price as
reseller (clause 3.4), which conflicts with the "the number on the page is the number
you pay" promise unless the supplier controls the price in practice.

### 4.2 The documents that would change

- `docs/privacy.md`: controller and seller lines, third parties, retention, rights route.
- `docs/refusals.md`: remove or narrow the "no customer list held by a payment
  processor" item and its check.
- `docs/transparency.md`: the payments section.
- `docs/threat-model.md`: the payment row and the third-party list.
- `docs/terms.md`: seller, refunds, invoices, renewal reminders, statement descriptor.
- `docs/planning/research/stripe-rail-set.md`: the "Stripe Tax" subsection, and the
  Answer paragraph on the Customer object being compatible with ADR 0008.
- `docs/planning/research/sole-trader-obligations.md`: sections 1.4 and 3.2, because
  the refund and invoice duties move to the seller.
- `docs/planning/specs/prepaid-rails.md`: the card section and the "refusal list stays
  true by absence" sentence, though the prepaid rail itself does not change.
- ADR 0008 in the meta repo: the refusal item. ADR 0009: the caveat about processor
  linkage. Both need human review and are not edited here.

## 5. The decisive constraint: the prepaid rails

`docs/planning/specs/prepaid-rails.md` sells the same £20 membership on four rails:
card, cash by post, cash in hand, and Monero. The prepaid path is offered to every
member, and nothing in the spec or the terms gates it by country. The terms say "You
pay by card through Stripe, by cash by post, by cash in hand, or in Monero"
(`docs/terms.md`, "Price and payment"), and the #163 resolution is that anyone may
apply, anywhere, with the Union served once the OSS registration and the Article 27
representative exist. A Union consumer may therefore pay by cash or Monero today, and
the platform is the seller for that supply.

| Rail | Seller of record, recorded plan | Seller of record, with an MoR | Registration the operator still holds |
|---|---|---|---|
| Card | operator | Stripe, Paddle or Polar | non-Union OSS for the Union prepaid sales; India on the #249 trigger if card stays direct |
| Cash by post | operator | operator | non-Union OSS; the India exposure with no country evidence |
| Cash in hand | operator | operator | non-Union OSS; the India exposure with no country evidence |
| Monero | operator | operator | non-Union OSS; the India exposure with no country evidence |
| Free tier | none, because there is no consideration | none | none for VAT |

A MoR removes no registration at all. It moves the card work: the card tax calculation,
the card VAT invoice, the card refund and the card chargeback. The non-Union OSS
registration is driven by the prepaid Union supplies, which the operator still makes,
and the Article 27 representative is driven by processing Union members' data for the
service, which a MoR does not touch. The India registration trigger in #249 fires on
the first Indian card sale. Under a MoR that sale is the MoR's, so the trigger stops
firing for card, but an Indian prepaid sale creates the same liability with no country
evidence, which is the limit #249 already records. No registration can be dropped with
certainty.

This is the whole answer to the ticket's fourth question. The MoR does not remove the
OSS, does not remove the representative, and does not remove the Indian exposure. It
moves a quarterly return line that is filed anyway, and the card-only work around it.

Refusing Union consumers the card rail would not change the registration position
either. The prepaid rails and the free tier would still serve them, so the OSS and the
Article 27 representative would still be required, and the platform would have narrowed
its own offer for no compliance gain. None of the MoR terms read here requires that
refusal: Managed Payments' restricted customer list excludes China, Russia and a few
other states but no Union state, and Paddle's acceptable use policy restricts products
rather than buyer countries. Refusing the Union would reverse #163's "anyone may apply,
anywhere" for nothing.

## 6. Migration cost from the current Stripe integration

The current card rail is a Payment Link with `client_reference_id` set to the
application, a webhook that deduplicates on `event.id`, and a ledger keyed by the
approval token. `control/crates/drain/src/transitions/stripe.rs` retrieves the
subscription and the session through `scripts/stripe-api.sh`, confirms the invoice
currency is GBP and the amount covers the configured price, extends `paid_until`, and
appends the ledger line. The webhook path makes no Stripe writes. The one write is
`cancel`, which sets `cancel_at_period_end` on the subscription the member already
holds; `stripe-api.sh` charges nothing and refunds nothing. A refund is a human step in
the Dashboard followed by `kyriakon-admin refund` in
`control/crates/drain/src/transitions/payments.rs`, which appends a negative line
naming the `seq` it reverses and records `--settled` when the money moves.

### 6.1 To Stripe Managed Payments

The migration is small because it is the same account.

1. Create a new Payment Link with Managed Payments enabled. Managed Payments cannot be
   enabled on an existing link ([Use payment links with Managed
   Payments](https://docs.stripe.com/payments/managed-payments/use-payment-links), read
   2026-11-20).
2. Set an eligible product tax code. `txcd_10701100` is Website Hosting and
   `txcd_10000000` is General, Electronically Supplied Services ([Managed Payments
   eligibility](https://docs.stripe.com/payments/managed-payments/eligibility), read
   2026-11-20).
3. Set the price's `tax_behavior` to inclusive, so the £20 stays the number the member
   pays. The default is exclusive, which would add tax on top ([Use payment links with
   Managed Payments](https://docs.stripe.com/payments/managed-payments/use-payment-links),
   read 2026-11-20).
4. Add `managed_payments[enabled]=true` to the Checkout Session call and use API
   version `2025-03-31.basil` or later.
5. Remove `automatic_tax`, `payment_method_types`, `customer_update[name]`,
   `customer_update[address]`, `subscription_data.invoice_settings`,
   `invoice_creation` and `custom_text`. Custom domains are not supported ([Update a
   Checkout
   integration](https://docs.stripe.com/payments/managed-payments/update-checkout),
   read 2026-11-20).
6. Teach the drain to tell a managed transaction from a direct one. The webhook event
   names stay in the Stripe family, but the invoice and payout now separate the tax and
   the 3.5 per cent fee.
7. Change the ledger's money reading. `invoice_money` in `stripe.rs` reads
   `amount_paid` and records it as revenue. For a managed sale the gross includes tax
   and the payout is net of tax and the fee, so recording `amount_paid` as income would
   overstate turnover for HMRC. The ledger line needs a net amount and a withheld tax
   field, and `append_invoice_ledger` needs to write them. This is the one substantive
   code change.
8. Add a reconciliation path for a refund the operator did not file. Stripe can refund
   within 60 days without approval, and `payments.rs::refund` deduplicates on its own
   intent id, so an external refund currently has no path.
9. Accept `LINK.COM*` as the statement descriptor and Onelink as the sender of
   receipts, invoices and renewal reminders.
10. Existing subscriptions are not eligible for Managed Payments. They stay direct, and
    the operator remains the seller for them, or they are cancelled and re-subscribed
    with the member's consent ([Update a Checkout
    integration](https://docs.stripe.com/payments/managed-payments/update-checkout),
    read 2026-11-20). The repository is pre-release, so the expected count is zero; if
    any subscription exists at cutover, it stays direct and the operator remains the
    seller for it.

The eligibility risk is separate from the migration. Managed Payments supports
"electronically supplied business and web services, such as website hosting", but it
also requires a "fully automated digital product", and this platform approves
applications by hand before issuing a Payment Link. Whether manual approval
disqualifies the product is not stated in the eligibility page and was not confirmed in
this session. That is marked unverified.

### 6.2 To Paddle or Polar

Both need a new checkout integration, a new webhook signature scheme and event names, a
new cancel and refund API, a new payout report, and a new identifier to join a payment
to the token. `scripts/stripe-api.sh` is replaced, and `stripe.rs` becomes a new
transition module. Existing Stripe subscriptions cannot be imported automatically;
they are cancelled and re-subscribed. Paddle's own migration tooling is for stores
moving to Paddle, not a Stripe import, and that was not verified. This is weeks of work
against days for Managed Payments, for a higher fee. Lemon Squeezy is not available at
all.

## 7. Non-UK thresholds under each option

The thresholds are the ones settled in #249 and recorded in
`worldwide-obligations.md`.

| Jurisdiction | Threshold | Roughly | Recorded plan | Managed Payments, card | Prepaid |
|---|---|---|---|---|---|
| India | no floor | 1 | register on the first Indian card sale, within 30 days, GSTR-5A monthly | absorbed for managed card sales | operator is liable, no country evidence, stated limit |
| Norway | NOK 50,000 over 12 months | 190 | monitor, VOEC quarterly on crossing | absorbed | operator, no country evidence |
| Canada | CAD 30,000 over 12 months | 800 | monitor | absorbed | operator |
| New Zealand | NZD 60,000 over 12 months | 1,350 | monitor | absorbed | operator |
| Australia | AUD 75,000 over 12 months | 1,900 | monitor | absorbed | operator |
| Japan | JPY 10,000,000 over 12 months | 2,600 | monitor | absorbed | operator |
| Switzerland | CHF 100,000 worldwide turnover | 4,600 | monitor | absorbed | operator |
| Singapore | SGD 1,000,000 over 12 months | far above this scale | monitor | absorbed | operator |
| European Union | no floor for B2C digital services | 1 | non-Union OSS | absorbed for card, OSS still needed for prepaid | operator |

Managed Payments' cross-border tax coverage lists India, Norway, Canada, New Zealand,
Australia, Japan, Switzerland, Singapore, the United Kingdom and every Union state
([Managed Payments tax
compliance](https://docs.stripe.com/payments/managed-payments/tax-compliance), read
2026-11-20). For a managed card sale in any of those, Stripe registers, collects, files
and remits. For a prepaid sale, none of it is absorbed, because the payment never
touches the MoR. The operator's card-sale thresholds disappear under a MoR, but the
prepaid exposure and the Union OSS stay.

Paddle's pricing page claims "global tax and regulatory compliance" and its agreement
makes Paddle the reseller responsible for sales tax on its transactions, but a
country-by-country coverage list was not found on the pages read. Its coverage of the
#249 jurisdictions is marked unverified. Polar's coverage is likewise unverified.

## 8. Recommendation

Keep the recorded plan. Do not adopt a merchant of record.

Per rail, the seller of record stays the operator: card, cash by post, cash in hand and
Monero. The operator's registrations are the ICO data protection fee at £52, the
non-Union OSS, the Indian GST registration on the first Indian card sale, and nothing
in Norway, Canada, New Zealand, Australia, Japan, Switzerland or Singapore until a
threshold is crossed. UK VAT registration waits for £90,000 of taxable turnover.

The annual card cost at 100 members is £59.30 in provider fees on the mixed card mix,
or £73.30 including Stripe Billing. At 500 members it is £296.50, or £366.50 with
Billing. Add the OSS registration and four quarterly returns, which have no stated fee
at the Commission pages read, and the operator's time. Prepaid payments carry no
processor fee and the operator's time per payment.

No terms, privacy notice or ADR changes are proposed, because the recommendation
confirms #163 and #249. There is no provider migration. The one documentation change
worth a follow-up is the correction to `stripe-rail-set.md`: Stripe Tax Basic does not
register the seller, but Tax Complete does, and the "Receipts, invoices and tax"
section of that note should say which plan it means. The Answer's statement that a
Stripe Customer is compatible with ADR 0008 should also be read against this note,
because a Customer under a MoR is the customer list the ADR refuses.

If the decision is ever reversed, the ADR to amend is 0008, not 0009. Its refusal item
and the Consequences paragraph are what a MoR contradicts. That is a meta-repo change
for human review, and it is not drafted here because this note does not reverse the
decision.

## 9. Why the merchant of record is rejected, so it is not re-litigated

1. The prepaid rails keep the non-Union OSS registration. A Union consumer may pay by
   cash or Monero, and the platform is the seller for that supply. A MoR removes no
   registration at all, only the card work.
2. It reverses a public refusal. `docs/refusals.md` says the platform will not have "a
   customer list held by a payment processor", and the check is that the processor
   holds no member list. A MoR is that list.
3. It asks for a name and a billing address at checkout. The platform's own account
   still holds no country, but the processor now holds the person, the place and the
   purchase, and the privacy notice has to say so.
4. It costs more for no filing that is not already required. Managed Payments adds £68
   a year at 100 members and £340 at 500 on the mixed mix, and the OSS return is filed
   for the prepaid sales either way.
5. Eligibility is not certain. Managed Payments requires a fully automated digital
   product, and this platform approves applications by hand. A rejection after building
   the integration would leave the card rail where it is.
6. The fee is not the decision. Between £68 and £350 a year does not buy a change to
   the seller-of-record posture, and the posture is the product: no member list worth
   seizing on the box or at the processor.

## 10. What would change the answer

- Closing the prepaid rails to Union consumers, or blocking Union prepaid sales. Then
  the OSS could be dropped for the remaining supplies, and a MoR would remove the card
  and Union work. That reverses #163, so it is a human decision, not a research result.
- Amending ADR 0008 to accept a processor-held customer list. Then Managed Payments is
  the provider: same account, GB eligible, website hosting tax code, and the lowest fee
  of the MoRs. It still needs the privacy notice, terms and transparency changes in
  section 4.
- A written confirmation from Stripe that manual application approval is compatible
  with the "fully automated" requirement, and a decision that a name and billing
  address at checkout are acceptable. Both are prerequisites, not follow-ups.
- Card volume large enough that the 3.5 per cent is cheaper than the card admin. The
  platform still does the webhook reconciliation, the paid-until date and the token
  ledger under a MoR, so the saving is only the card tax line and the card refund and
  dispute handling. No volume in the first years makes that the larger number.

## 11. What needs a lawyer or an accountant

- Whether a MoR can be the seller of the membership while the platform supplies the
  service, and how the 14-day cancellation right in the Consumer Contracts Regulations
  splits between the MoR and the operator.
- Whether requiring a name and billing address at checkout, held by the MoR, is
  compatible with the privacy notice's "no postal address" statement and with the
  Article 27 representative arrangement.
- Whether Paddle's acceptable use policy accepts mail hosting as a software-related
  service, or treats it as a human service. The policy excludes "human services that
  are not related to a software offering" ([Paddle
  AUP](https://www.paddle.com/help/start/intro-to-paddle/what-am-i-not-allowed-to-sell-on-paddle),
  read 2026-11-20).
- Whether Managed Payments' "fully automated digital product" requirement is met by a
  manually approved application.
- Whether the operator's UK VAT turnover under a MoR is the gross consumer price or the
  net payout, which changes how far the £90,000 threshold is.
- Whether HMRC accepts a token-keyed ledger that becomes unlinkable on deletion, which
  is the caveat ADR 0009 already carries.

## 12. Sources

All read on 20 November 2026 unless a different date is stated.

Stripe:

- [Pricing, GB](https://stripe.com/gb/pricing): UK card 1.5% + 20p, EEA 2.5% + 20p,
  international 3.15% + 20p, Billing 0.7%, Managed Payments 3.5%, dispute fees £20.
- [Stripe Tax pricing, GB](https://stripe.com/gb/tax/pricing): Tax Basic 0.5% for
  no-code and 40p for API, Tax Complete from £70 a month with OSS registration and
  filing.
- [Managed Payments](https://stripe.com/gb/managed-payments): 3.5% on top of processing
  fees, 80+ countries, Onelink as the seller.
- [How Managed Payments
  works](https://docs.stripe.com/payments/managed-payments/how-it-works).
- [Managed Payments eligibility](https://docs.stripe.com/payments/managed-payments/eligibility):
  GB supported, website hosting tax code, fully automated requirement, restricted
  customer countries.
- [Managed Payments tax
  compliance](https://docs.stripe.com/payments/managed-payments/tax-compliance):
  country coverage including India and Norway.
- [Update a Checkout
  integration](https://docs.stripe.com/payments/managed-payments/update-checkout):
  existing subscriptions ineligible, unsupported parameters, name and billing address.
- [Use payment links with Managed
  Payments](https://docs.stripe.com/payments/managed-payments/use-payment-links):
  cannot enable on an existing link, tax behaviour.
- [Track a payment link](https://docs.stripe.com/payment-links/url-parameters):
  `client_reference_id`.

Paddle:

- [Pricing](https://www.paddle.com/pricing): 5% + USD 0.50.
- [Master services agreement](https://www.paddle.com/legal/terms): reseller role,
  clause 3.2 fee, clause 3.4 price control, clause 7 payout and FX, clause 10 refunds
  and chargebacks. Last updated 6 October 2026.
- [Acceptable use
  policy](https://www.paddle.com/help/start/intro-to-paddle/what-am-i-not-allowed-to-sell-on-paddle),
  last updated 13 April 2026.

Polar:

- [Fees](https://github.com/polarsource/polar/blob/main/docs/merchant-of-record/fees.mdx):
  Starter 5% + USD 0.50, 1.5% international cards, USD 15 a dispute, payout fees.

Lemon Squeezy:

- [Pricing](https://www.lemonsqueezy.com/pricing): 5% + 50¢.
- [Migration](https://docs.lemonsqueezy.com/migration): no new sign-ups from 16
  November 2026, shutdown 31 March 2027, recommends Managed Payments.

Tax and platform context:

- European Commission, [The One Stop Shop](https://vat-one-stop-shop.ec.europa.eu/one-stop-shop_en):
  the non-Union scheme, quarterly returns, and the EUR 10,000 threshold that does not
  help a UK-established trader.
- HMRC, [VAT rules for supplies of digital services to
  consumers](https://www.gov.uk/guidance/the-vat-rules-if-you-supply-digital-services-to-private-consumers):
  non-Union OSS or per-state registration, and the two pieces of country evidence.
- Repo files read at this commit: `docs/privacy.md`, `docs/terms.md`,
  `docs/refusals.md`, `docs/transparency.md`, `docs/threat-model.md`,
  `docs/planning/research/stripe-rail-set.md`,
  `docs/planning/research/sole-trader-obligations.md`,
  `docs/planning/research/worldwide-obligations.md`,
  `docs/planning/specs/prepaid-rails.md`,
  `control/crates/drain/src/transitions/stripe.rs`,
  `control/crates/drain/src/transitions/payments.rs`, `scripts/stripe-api.sh`.
- ADRs 0008 and 0009 in the sibling meta repo `../kyriakon/docs/decisions/`, read but
  not edited.

Not verified in this session:

- The amount of the additional fee the Managed Payments support article says applies to
  subscription payments. The article did not render its body text, and Stripe Billing's
  published 0.7 per cent is used instead.
- Whether `client_reference_id` survives a Managed Payments Payment Link. It is a
  Checkout Session field and no Managed Payments page says it is removed, but no page
  confirms it either.
- Paddle's country-by-country tax coverage, and whether its 5 per cent is computed on a
  tax-inclusive or tax-exclusive price.
- Polar's country-by-country tax coverage.
- Whether Paddle's acceptable use policy accepts mail hosting.
- Whether Managed Payments accepts a manually approved application as a "fully
  automated digital product".
- The pound to dollar rate used for the USD 0.50 components.
- Operator time per OSS return, which is the cost the MoR would have to beat.
