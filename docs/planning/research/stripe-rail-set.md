# Stripe for the rail set and the account page

**Question.** What does Stripe actually provide for an annual £20 membership sold by a sole trader, alongside a manually credited prepaid path, when the paid-until date is authoritative on our own machine and ADR 0008 refuses a customer list held by a payment processor? Which objects, events and settings are needed, what must the operator configure by hand, and what has to be decided rather than configured?

**Answer.** The card rail is one Product, one yearly Price, a Checkout Session created from our service, and a Subscription that Stripe renews. The prepaid rail needs nothing in Stripe at all, and that is the cheapest reading of ADR 0008. Stripe holds a Customer for card payers because subscription mode cannot work without one, and that is compatible with the ADR: the refusal is about treating the processor as the system of record, not about refusing a customer object. Our machine keeps the date. Six webhook events carry the whole lifecycle, deduplicated on `event.id`, verified with `Stripe-Signature`, and never trusted for provisioning until the signature and the timestamp are checked.

Two facts shape the Checkout design. A Checkout Session URL expires within 24 hours, so an emailed link has to be a Payment Link or be recreated at approval time. A Payment Link accepts `client_reference_id` as a URL parameter, which is how an emailed link carries the application reference back.

---

## 1. Objects that map to the two rails

### The card rail

| Object | Shape for this product | Source |
|---|---|---|
| Product | one, named for the membership | [products create](https://docs.stripe.com/api/products/create) |
| Price | `currency: "gbp"`, `unit_amount: 2000`, `type: "recurring"`, `recurring: {interval: "year", interval_count: 1}`, `billing_scheme: "per_unit"` | [Price object](https://docs.stripe.com/api/prices/object), [prices create](https://docs.stripe.com/api/prices/create) |
| Checkout Session | `mode: "subscription"`, one `line_items[0][price]`, `success_url`, `client_reference_id`, `metadata`, `subscription_data.metadata` | [sessions create](https://docs.stripe.com/api/checkout/sessions/create) |
| Customer | created by Checkout, because subscription mode requires one | [sessions create](https://docs.stripe.com/api/checkout/sessions/create) (`customer_creation`: subscription mode requires a Customer) |
| Subscription | `collection_method: "charge_automatically"`, status `active`, `current_period_end` on the items | [Subscription object](https://docs.stripe.com/api/subscriptions/object) |
| Invoice | one per year, created by the subscription when it renews (`billing_reason`) | [Invoice object](https://docs.stripe.com/api/invoices/object) |
| PaymentIntent and Charge | created per invoice by Stripe; we never create these by hand | [PaymentIntents](https://docs.stripe.com/api/payment_intents) |

`automatic_tax.enabled` on the session is a one-line addition when we ever need Stripe Tax ([sessions create](https://docs.stripe.com/api/checkout/sessions/create)).

### The prepaid rail

Stripe has no object for a payment that never touches it, and we should not invent one. The two ways to put an off-Stripe payment into Stripe both cost more than they return:

- A Payment Record models an off-Stripe payment ([Payment Records](https://docs.stripe.com/payments/payment-records)). `POST /v1/payment_records/report_payment` does not require a Customer; `customer_details` is optional, while `amount_requested`, `initiated_at`, `payment_method_details` and `processor_details` are required ([report a payment](https://docs.stripe.com/api/payment-record/report)). It exists to mark a Stripe Invoice paid, and that Invoice needs a Customer.
- Marking an Invoice paid out of band uses `POST /v1/invoices/:id/attach_payment` with a `payment_record`, or a PaymentIntent ([attach a payment](https://docs.stripe.com/api/invoices/attach_payment)). This requires a Customer and an Invoice.

Neither produces a receipt the member did not already get from us, and both send the member's payment to Stripe. The lazy correct answer is that the prepaid rail lives entirely in `kyriakon-onboard`: the operator records the credit and the rail tag on our machine, extends the paid-until date, and issues the receipt from our side.

### One authority, two rails

The paid-until date is ours. Stripe's job is to tell us when a card payment succeeded, not to define whether a member is paid. Two consequences follow.

When Stripe and our date disagree, our date wins for access, and Stripe is the input that extends it. A subscription in `past_due` with a date in the future still has access until that date lapses. A cancelled subscription does not shorten a date the member already paid for; `cancel_at_period_end` means the subscription runs to the end of the period anyway ([Cancel a subscription](https://docs.stripe.com/billing/subscriptions/cancel)).

When a webhook is missed, the API is the repair path. Stripe's own guidance is to retrieve the missing object from the API rather than trust the event stream for state ([event ordering](https://docs.stripe.com/webhooks#event-ordering)). A subscription never creates or deletes our account: it extends or fails to extend a date.

## 2. Events, idempotency and ordering

The canonical list of subscription events is Stripe's own table at [Subscription webhooks](https://docs.stripe.com/billing/subscriptions/webhooks). These are the events this service needs.

| Event | Fires when | Deduplication key | What it must do |
|---|---|---|---|
| `checkout.session.completed` | a Checkout Session completes ([events list](https://docs.stripe.com/api/events/types#event_types-checkout.session.completed)) | `event.id`, plus `data.object.id` with the event type | provision: read `client_reference_id`, then retrieve the subscription and invoice |
| `checkout.session.async_payment_succeeded` | a delayed payment method settles ([events list](https://docs.stripe.com/api/events/types#event_types-checkout.session.async_payment_succeeded)) | as above | provision, for non-card methods only |
| `checkout.session.async_payment_failed` | a delayed payment method fails | as above | do not provision |
| `checkout.session.expired` | the session expires | as above | nothing, the application stays unprovisioned |
| `customer.subscription.created` | a subscription is created; status may be `incomplete` ([webhooks](https://docs.stripe.com/billing/subscriptions/webhooks)) | `event.id` | reconcile by subscription ID |
| `customer.subscription.updated` | renewal, status change, or `cancel_at_period_end` set ([Cancel](https://docs.stripe.com/billing/subscriptions/cancel)) | `event.id` | reconcile the status and the period end |
| `customer.subscription.deleted` | the subscription ends, either from a delete call or a period-end cancellation ([Cancel](https://docs.stripe.com/billing/subscriptions/cancel)) | `event.id` | stop renewing; do not revoke a paid date |
| `invoice.paid` | a payment succeeds or an invoice is marked paid out of band ([events list](https://docs.stripe.com/api/events/types#event_types-invoice.paid)) | `event.id` | extend the date, after confirming the subscription is `active` |
| `invoice.payment_succeeded` | an invoice payment attempt succeeds ([events list](https://docs.stripe.com/api/events/types#event_types-invoice.payment_succeeded)) | `event.id` | the older sibling of `invoice.paid`; listen to one, not both |
| `invoice.payment_failed` | a payment attempt fails, including a soft decline or a missing payment method ([events list](https://docs.stripe.com/api/events/types#event_types-invoice.payment_failed)) | `event.id` | record the attempt, the `attempt_count` and `next_payment_attempt` |
| `invoice.payment_action_required` | the invoice needs customer authentication | `event.id` | ask the member to complete it |
| `invoice.upcoming` | some days before a renewal, `charge_automatically` only ([webhooks](https://docs.stripe.com/billing/subscriptions/webhooks)) | `event.id` | the reminder hook; the invoice has no ID yet |
| `charge.dispute.created` | a cardholder disputes a charge ([webhooks](https://docs.stripe.com/billing/subscriptions/webhooks)) | `event.id` | flag the member; decide access by hand |
| `charge.refunded` | a refund is issued | `event.id` | reconcile the date |
| `radar.early_fraud_warning.created` | the issuer reports a suspected fraudulent charge before a dispute | `event.id` | review |
| `payment_method.automatically_updated` | the card network updates a saved card ([Automatic card updates](https://docs.stripe.com/payments/cards/overview#automatic-card-updates)) | `event.id` | no action; the subscription keeps charging |
| `customer.source.expiring` | a legacy Card or Source will expire ([events list](https://docs.stripe.com/api/events/types#event_types-customer.source.expiring)) | `event.id` | ignored; this event does not fire for the PaymentMethod API |

Two selection notes. Stripe only creates event types marked "Selection required" when at least one endpoint listens for them, and an endpoint set to all events does not count ([events list](https://docs.stripe.com/api/events/types)). Subscribe to the list above by name, which the endpoint API takes as `enabled_events` ([webhook endpoints create](https://docs.stripe.com/api/webhook_endpoints/create)). The renewal reminder for annual payers is the `invoice.upcoming` event or the dashboard email at [Automate customer emails](https://docs.stripe.com/billing/revenue-recovery/customer-emails), not a cron job we write.

### Idempotency keys

Two different keys apply to two different directions.

For requests we send, the `Idempotency-Key` header makes a retried POST safe. Stripe suggests a version 4 UUID, keys may be up to 255 characters, and Stripe prunes them after at least 24 hours. Reusing a key returns the stored result, including a stored error, and a reused key with different parameters returns an error instead of running the request ([Idempotent requests](https://docs.stripe.com/api/idempotent_requests)). Use one key per logical action: one for the Checkout Session created for an application, one for the Payment Link, one for a cancellation.

For events we receive, `event.id` is the key. Stripe recommends logging the event IDs you have processed and skipping the ones already logged, and notes that two separate Event objects can carry one change, in which case the pair `data.object.id` and `event.type` identifies the duplicate ([Handle duplicate events](https://docs.stripe.com/webhooks#handle-duplicate-events)).

Provisioning idempotency is a third key and it is ours. Before creating a mail account, a git repo or a web root, read the current provisioning state for that member from our own store, because the same event will arrive more than once and a second delivery after a crash must not create a second account.

### Retries and duplicates to survive

Stripe retries delivery for up to three days with exponential backoff in live mode, and three times over a few hours in a sandbox ([automatic retries](https://docs.stripe.com/webhooks#automatic-retries)). A manual resend from the dashboard works for 15 days and from the CLI for 30, and a manual resend does not cancel the automatic retries ([manual retries](https://docs.stripe.com/webhooks#manual-retries)). A retry carries a new timestamp and a new signature, so the same payload can be verified twice ([signature verification](https://docs.stripe.com/webhooks#verify-manually)). The endpoint must return a 2xx before doing slow work, which means the handler either returns early and queues, or does its work in a way that is safe to repeat ([quickly return a 2xx response](https://docs.stripe.com/webhooks#quickly-return-a-2xx-response)).

Every one of those retries lands on the deduplication rules above. A handler that provisions first and records `event.id` afterwards will provision twice on a crash.

### Ordering pitfalls

Stripe does not guarantee event order ([event ordering](https://docs.stripe.com/webhooks#event-ordering)). The documented example is a subscription that produces `customer.subscription.created` before `invoice.created`, and the ordering between `checkout.session.completed` and `customer.subscription.updated` is equally unspecified. Two traps follow:

- Distinct events can share a `created` timestamp, because it has second resolution, so `created` cannot order events or identify an already-processed one.
- The event payload is a snapshot taken when the event was generated, not the current state. Retrieve the object from the API when the decision depends on its current value.

The specific ordering rule for this product is that a paid invoice does not by itself mean the member is active. Stripe says to retrieve the subscription after `invoice.paid` and confirm the status is `active` before extending access, because a paid invoice does not always move the subscription to `active` ([Track active subscriptions](https://docs.stripe.com/billing/subscriptions/webhooks)). That retrieval is what makes our date authoritative rather than a copy of an event stream.

### Abandonment

A session the member never completes expires, by default 24 hours after creation, at a time the caller sets between 30 minutes and 24 hours ([sessions create](https://docs.stripe.com/api/checkout/sessions/create)). Stripe sends `checkout.session.expired`, and nothing is provisioned and no date is written. Setting `after_expiration.recovery.enabled` makes Stripe attach a recovery URL to the session when it expires, and a payment made through that URL creates a new session whose `recovered_from` field points at the expired one ([sessions create](https://docs.stripe.com/api/checkout/sessions/create), [Session object](https://docs.stripe.com/api/checkout/sessions/object)).

A subscription whose first payment never completes does not simply stay open. It moves to `incomplete`, and if the first invoice is still unpaid after 23 hours it moves to `incomplete_expired`, which is terminal: the open invoice is voided and no further invoices are generated ([Subscription object](https://docs.stripe.com/api/subscriptions/object)). A member who abandons checkout at the payment step therefore needs a fresh session, which is one more reason the emailed link should be a Payment Link rather than a session created days earlier.

## 3. Signature verification

Stripe signs every event with an HMAC-SHA256 over the string formed by the timestamp, a period, and the raw request body. The `Stripe-Signature` header carries `t=` and one or more signatures, with the live scheme `v1` and a test-only `v0` ([verify manually](https://docs.stripe.com/webhooks#verify-manually)).

The rules that matter here:

- Verify the raw body exactly as received. Parsing and re-serialising the JSON breaks the HMAC ([example endpoint](https://docs.stripe.com/webhooks#example-endpoint)).
- Accept only `v1` signatures, and compare in constant time. The header can carry several `v1` values while a secret rolls.
- Keep the timestamp inside a tolerance window. Stripe's libraries default to 5 minutes, and a tolerance of 0 disables the recency check entirely, which Stripe tells you not to do ([preventing replay attacks](https://docs.stripe.com/webhooks#preventing-replay-attacks)). Run NTP on the box so the window means something.
- The signing secret is per endpoint and differs between test and live. A secret rotates with up to 24 hours of overlap, during which Stripe signs with each active secret ([roll endpoint signing secrets periodically](https://docs.stripe.com/webhooks#roll-endpoint-secrets), [verify manually](https://docs.stripe.com/webhooks#verify-manually)).
- In live mode the endpoint URL must be HTTPS with a valid certificate, so the relayd front end and its certificate are part of the webhook contract ([example endpoint](https://docs.stripe.com/webhooks#example-endpoint)).
- Signature verification and an IP allowlist are the two protections Stripe asks for, and the event source addresses are published at [Stripe IP addresses](https://docs.stripe.com/ips).

Stripe states the failure mode directly: without verification, an attacker could send fake events "to trigger actions like fulfilling orders, granting account access, or modifying records" ([verify events are sent from Stripe](https://docs.stripe.com/webhooks#verify-events-are-sent-from-stripe)). For this service that means an unverified or stale request must be unable to create a member, extend a paid-until date, add an SSH key, or mark an invoice paid. The check happens before the body reaches any handler that can write to the account store, and a failed check is logged and dropped, never queued for later.

## 4. Receipts, invoices and tax

### What Stripe issues by default

Stripe creates a receipt for every successful payment and refund, including invoice payments and recurring subscription payments ([Receipts and paid invoices](https://docs.stripe.com/receipts)). Automatic emailing is a dashboard toggle at Settings, Business, Customer emails, under Payments; nothing is sent for a failed payment. Receipt links expire after 30 days, although the receipt itself does not. A subscription also produces an Invoice with a hosted page and a PDF, exposed as `hosted_invoice_url` and `invoice_pdf` on the Invoice object ([Invoice object](https://docs.stripe.com/api/invoices/object)).

Receipts carry required support details: the legal business name, a support address, a support email and a privacy policy URL ([support requirements](https://docs.stripe.com/receipts#support-requirements)). Those come from the public business information set during verification.

### Stripe Tax

Stripe Tax calculates the tax, collects it, monitors sales against registration thresholds, and can file ([Stripe Tax](https://docs.stripe.com/tax), [How Stripe Tax works](https://docs.stripe.com/tax/how-tax-works)). It needs three things configured before it does anything: the head office address, a preset product tax code, and the default tax behavior for prices ([Set up Stripe Tax](https://docs.stripe.com/tax/set-up)). A registration added under Locations is what actually turns collection on for a jurisdiction.

The United Kingdom is supported for VAT ([supported countries](https://docs.stripe.com/tax/supported-countries), the `GB` row). Stripe charges its tax fee on live transactions in jurisdictions where a registration is active, and charges nothing for configuring settings or for abandoned sessions ([tax pricing](https://docs.stripe.com/tax/how-tax-works#pricing), [Stripe Tax pricing](https://stripe.com/tax/pricing)).

The accounting reality at this scale is simpler than the feature set. A UK sole trader registers for VAT once taxable turnover passes £90,000 in the previous 12 months, or is expected to pass it in the next 30 days ([Register for VAT](https://www.gov.uk/vat-registration/when-to-register)). Below that threshold there is no VAT to collect, so `automatic_tax` stays off and the £20 is the whole price. The obligations that do apply are Self Assessment and keeping records, at £1,000 of earnings ([Become a sole trader](https://www.gov.uk/become-sole-trader)). Stripe's reports and payouts are then inputs to that return, not a tax system in their own right.

### Recording a prepaid payment without a processor-held customer

A Payment Record can be created with no customer. Only `customer_details` is optional among the descriptive fields, and the report call needs an amount, a timestamp, a payment method description and a processor description ([report a payment](https://docs.stripe.com/api/payment-record/report)). So it is technically possible to tell Stripe about a non-card payment without creating a Customer.

It is still the wrong shape for this rail. A Payment Record that is not attached to an Invoice accomplishes nothing in Stripe, and attaching it to an Invoice needs both a Customer and an Invoice ([attach a payment](https://docs.stripe.com/api/invoices/attach_payment)). Recording the payment on our machine, and issuing the receipt ourselves, keeps the prepaid rail consistent with ADR 0008 and produces the same evidence for the accounts.

The consequence for the operator's books is that two income streams arrive in two forms. Card income appears in Stripe's balance and payouts, net of Stripe's fees, with Stripe invoices and receipts as the supporting documents. Prepaid income appears only in our own records, so the operator keeps the bank or Monero confirmation and issues a receipt from the platform. Both feed the same Self Assessment return.

## 5. Sole trader onboarding

An account can be used in a sandbox immediately after creation, and live mode needs the account set up first ([Stripe accounts](https://docs.stripe.com/get-started/account)). Verification happens in the dashboard, which asks for information about the business, the product and the operator's relationship to it, and Stripe says it may request more information as more services are used ([Set up your account](https://docs.stripe.com/get-started/account/set-up)). Two constraints are documented and sharp: the business origin country cannot be changed after a live service is activated, and the public business information (business name, website URL, support email, phone, address, statement descriptor) is what members see on statements and receipts.

There is no account-type choice in the Connect sense. Standard, Express and Custom are Connect account types, and Connect exists for platforms that route payments to other sellers ([Stripe Connect](https://docs.stripe.com/connect)). Here the operator is the merchant, so the choice during onboarding is the legal entity: individual, meaning sole trader. The field list Stripe publishes for a United Kingdom individual with the `card_payments` capability is the authoritative answer to what verification asks for:

| Requirement | Field |
|---|---|
| Identity | `individual.first_name`, `individual.last_name` |
| Address | `individual.address.line1`, `individual.address.postal_code`, `individual.address.city` |
| Date of birth | `individual.dob.day`, `individual.dob.month`, `individual.dob.year` |
| Contact | `individual.email`, `individual.phone` |
| Business | `business_profile.mcc`, `business_profile.url`, `business_profile.product_description`, `business_profile.support_phone` |
| Terms | `tos_acceptance.date`, `tos_acceptance.ip` |
| Payouts | `external_account` |

Source: the requirements endpoint the Stripe documentation itself calls, `GET https://docs.stripe.com/_endpoint/get-requirements-for-setups` with `accountCountry=GB`, `legalEntityType=individual` and `capabilities[0]=card_payments`, reached from [Required verification information](https://docs.stripe.com/connect/required-verification-information). Identity document checks can be requested on top of these fields; the endpoint tags the individual fields in this response with `eu_orr_identity_verification_rep`. **Lead times are not stated anywhere on docs.stripe.com.** The verification flow is interactive and its duration is not documented, so ticket planning cannot assume a number, and this note does not invent one.

Test and live are separate environments with separate keys, separate objects and separate webhook secrets ([Sandbox versus live mode](https://docs.stripe.com/keys#sandbox-versus-live-mode)). Products and prices created in a sandbox cannot be used in live mode, so they are recreated by hand and the code must refer to the live IDs; the code should read the price ID from configuration for exactly this reason ([Go-live checklist](https://docs.stripe.com/get-started/checklist/go-live)). Live secret keys are displayed once and cannot be revealed again, so they go into a secrets file on the box and never into the repo ([Reveal an API key](https://docs.stripe.com/keys#reveal-an-api-key)).

## 6. What the operator configures by hand

None of this is done by the service. Each item is a dashboard action, and the service fails in a visible way when one is missing.

Before the first live payment:

1. Create the account with the country set to the United Kingdom and the business type individual, then verify the business under Dashboard, Account, Onboarding. The origin country is fixed after this step ([Set up your account](https://docs.stripe.com/get-started/account/set-up)).
2. Set 2FA with a passkey or a security key ([Account checklist](https://docs.stripe.com/get-started/account/checklist)).
3. Confirm the public details and the statement descriptor. The descriptor is 5 to 22 characters, needs at least 5 letters, and cannot contain `<`, `>`, `'` or `"` ([Account checklist](https://docs.stripe.com/get-started/account/checklist)).
4. Confirm the bank account and the payout schedule ([Account checklist](https://docs.stripe.com/get-started/account/checklist)).
5. Create the Product and the yearly Price in live mode, and again in each sandbox. Copy the live price ID into the service configuration ([Go-live checklist](https://docs.stripe.com/get-started/checklist/go-live)).
6. Register the webhook endpoint in live mode and in test mode, select exactly the event names from section 2, set the endpoint API version, and copy each signing secret to the box ([Webhook endpoints](https://docs.stripe.com/api/webhook_endpoints/create), [webhooks](https://docs.stripe.com/webhooks)).
7. Create a restricted API key with only the permissions the service needs, rather than a secret key ([Create a restricted API key](https://docs.stripe.com/keys#create-restricted-api-key)).
8. Create the Payment Link for the emailed checkout, and get the URL form with `client_reference_id` appended ([Reconcile with a URL parameter](https://docs.stripe.com/payment-links/url-parameters)).

Billing and email behaviour:

9. Turn on automatic receipts at Settings, Business, Customer emails, under Payments ([Receipts](https://docs.stripe.com/receipts)).
10. Turn on failed payment emails, expiring card emails and renewal reminders under Billing, Revenue recovery ([Automate customer emails](https://docs.stripe.com/billing/revenue-recovery/customer-emails)).
11. Choose the retry policy and the end state. Smart Retries defaults to 8 attempts in 2 weeks, and the recovery end state is cancel, mark unpaid, or remain `past_due` ([Automate payment retries](https://docs.stripe.com/billing/revenue-recovery/smart-retries)).
12. Set the days before renewal for `invoice.upcoming`, under Upcoming renewal events ([Subscription webhooks](https://docs.stripe.com/billing/subscriptions/webhooks)).
13. Set the account notification preferences for successful charges and disputes ([Account checklist](https://docs.stripe.com/get-started/account/checklist)).

Tax, only if a registration exists:

14. Set the head office address, the preset product tax code and the default tax behavior ([Set up Stripe Tax](https://docs.stripe.com/tax/set-up)).
15. Add each VAT registration under Locations. Until then Stripe collects nothing and `automatic_tax` stays off ([Register for tax](https://docs.stripe.com/tax/registering)).

## 7. The API our service calls

The service is a small Rust HTTP app behind relayd. Its Stripe calls are these, all with `Idempotency-Key` on the POSTs:

| Call | Use |
|---|---|
| `POST /v1/checkout/sessions` | create the session for one application when the operator approves it ([sessions create](https://docs.stripe.com/api/checkout/sessions/create)) |
| `GET /v1/checkout/sessions/:id` | reconcile after a delivery gap, using `client_reference_id` to find the application |
| `GET /v1/subscriptions/:id` | read the current status and `current_period_end` before extending the date |
| `GET /v1/invoices/:id` | read `status`, `amount_paid` and `hosted_invoice_url` for the member's billing view |
| `POST /v1/subscriptions/:id` with `cancel_at_period_end=true` | let a member cancel and keep the period they paid for ([Cancel](https://docs.stripe.com/billing/subscriptions/cancel)) |
| `DELETE /v1/subscriptions/:id` | cancel immediately, which forfeits the rest of the period |
| `POST /v1/payment_links` | only if the approval email sends a reusable link rather than a session URL ([payment links create](https://docs.stripe.com/api/payment-link/create)) |

The webhook side of the service does no Stripe writes at all. It verifies the signature, deduplicates, writes the payment fact and the date to our own database, and queues provisioning. Nothing in the webhook path marks a Stripe Invoice paid, because nothing in the card rail needs that.

## 8. Decisions this raises, rather than answers

1. **Payment Link or per-application Checkout Session.** A session URL expires between 30 minutes and 24 hours after creation, and the `url` field is only present while the session is active ([sessions create](https://docs.stripe.com/api/checkout/sessions/create), [Session object](https://docs.stripe.com/api/checkout/sessions/object)). A Payment Link is reusable and carries `client_reference_id` as a URL parameter. The decision is whether the approval email sends a stable Payment Link whose reference the operator sets per applicant, or a session created at approval time that may need recreating if the applicant is slow.
2. **What happens to access when a renewal fails.** The retry policy and the recovery end state are ours to set, and they decide whether a member keeps service through `past_due`, through `unpaid`, or loses it at the paid-until date. ADR 0008 makes the date ours, so this is a policy question, not a Stripe question.
3. **Whether the operator ever creates a Subscription by hand for a prepaid member.** The prepaid rail's whole point is to avoid a processor-held record, so the default is no. If a prepaid member later moves to card, the decision is whether the new subscription starts a fresh year or is backdated with `backdate_start_date` ([subscriptions create](https://docs.stripe.com/api/subscriptions/create)).
4. **Whether `client_reference_id` or `subscription_data.metadata` is the identifier that survives.** The reference is on the session and the metadata can be put on the subscription ([sessions create](https://docs.stripe.com/api/checkout/sessions/create)). The renewal invoices then carry the subscription's metadata, not the session's reference, so the service needs a decision on which is the durable key.
5. **Whether Stripe Tax is enabled at all before a VAT registration exists.** Enabling it before registering adds a fee with nothing to collect in the UK. The decision is whether to leave it off and revisit at the threshold.
6. **Whether the account is verified now or immediately before release.** Verification needs the public website to exist, since `business_profile.url` and the support details are required, and the documented flow gives no lead time. That sequencing is a planning decision.
7. **Whether identity documents will be asked for.** The GB individual requirement set does not list a document upload, and the endpoint tags the personal fields for an identity check, so the outcome at onboarding is unknown until it is attempted.
8. **What the service does with a dispute for an active member.** Nothing in the event list dictates access, and the policy for pausing or keeping an account while a chargeback is answered belongs in the threat model rather than in Stripe.

## 9. What to skip

- Payment Records and out-of-band invoice marking. They require a Customer or an Invoice to be useful, and the prepaid rail needs neither.
- Stripe Tax until a VAT registration exists, and tax filings before that.
- Subscriptions created by hand in the dashboard for normal members.
- A local mirror of Stripe customers. Retrieval from the API at the moment of need is the repair path for a missed event, and a mirror would recreate the customer list ADR 0008 refuses.
- Stripe Connect entirely. There is one seller here.

## Primary sources

- Stripe API reference: [Checkout Sessions](https://docs.stripe.com/api/checkout/sessions/create), [Session object](https://docs.stripe.com/api/checkout/sessions/object), [Prices](https://docs.stripe.com/api/prices/object), [Subscriptions](https://docs.stripe.com/api/subscriptions/object), [Invoices](https://docs.stripe.com/api/invoices/object), [Payment Records](https://docs.stripe.com/api/payment-record/report), [Invoice attach payment](https://docs.stripe.com/api/invoices/attach_payment), [Webhook endpoints](https://docs.stripe.com/api/webhook_endpoints/create), [Idempotent requests](https://docs.stripe.com/api/idempotent_requests), [Event types](https://docs.stripe.com/api/events/types).
- Stripe documentation: [Webhooks](https://docs.stripe.com/webhooks), [Subscription webhooks](https://docs.stripe.com/billing/subscriptions/webhooks), [Cancel a subscription](https://docs.stripe.com/billing/subscriptions/cancel), [Smart Retries](https://docs.stripe.com/billing/revenue-recovery/smart-retries), [Customer emails](https://docs.stripe.com/billing/revenue-recovery/customer-emails), [Receipts](https://docs.stripe.com/receipts), [Stripe Tax](https://docs.stripe.com/tax), [Set up Stripe Tax](https://docs.stripe.com/tax/set-up), [Register for tax](https://docs.stripe.com/tax/registering), [Payment Links URL parameters](https://docs.stripe.com/payment-links/url-parameters), [Keys](https://docs.stripe.com/keys), [Account setup](https://docs.stripe.com/get-started/account/set-up), [Account checklist](https://docs.stripe.com/get-started/account/checklist), [Go-live checklist](https://docs.stripe.com/get-started/checklist/go-live), [Payment Records](https://docs.stripe.com/payments/payment-records), [Automatic card updates](https://docs.stripe.com/payments/cards/overview#automatic-card-updates).
- Requirements endpoint used by the Stripe documentation itself: `GET https://docs.stripe.com/_endpoint/get-requirements-for-setups` with `accountCountry=GB`, `legalEntityType=individual`, `capabilities[0]=card_payments`, reached from [Required verification information](https://docs.stripe.com/connect/required-verification-information).
- GOV.UK: [Register for VAT](https://www.gov.uk/vat-registration/when-to-register), [Become a sole trader](https://www.gov.uk/become-sole-trader).
- Repo context: ADR 0008 in `../kyriakon`, proposal sections 5.9.1 and 6.14, and `kyriakon-onboard` `AGENTS.md` on signature verification and provisioning idempotency.

Not verified: the time Stripe takes to verify a UK sole trader's account. No lead time appears on docs.stripe.com or in the requirements endpoint, and `web_search` was unavailable in this session, so this note records the gap instead of a number.
