//! The card rail: the webhook pass that settles Stripe's events, plus the card
//! link and the payment instructions for card, cash and Monero that the account
//! pages, the approval mail and the renewal note carry.

use super::boxrun::{script_error, spawn_script};
use super::groups::{group_record, write_account_record, write_group_record};
use super::lifecycle::{dns_contact, report_record};
use super::payments::{restore_group_mailboxes, token_join, write_payment_copy};
use super::report_failure;
use crate::config::DrainConfig;
use crate::journal::Journal;
use crate::ledger::Ledger;
use crate::ledger::LedgerLine;
use crate::notice;
use crate::sign;
use crate::store::{self, Account, GroupRecord, Monero, Store};
use crate::util;
use crate::validate;
use serde_json::Value;
use std::collections::HashSet;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The rail's own payment instructions, one line each, in the words the
/// approval email and both account pages carry. Monero has no subaddress until
/// the operator's wallet makes one, so the line says that rather than leaving an
/// empty field for the member to wonder at; and a window with no usable quote
/// falls back to cash by post, which is the one prepaid rail it does have.
pub fn rail_instructions(
    rail: &str,
    postal_address: &str,
    card_link: Option<&str>,
    monero: Option<&Monero>,
    amount_gbp: &str,
) -> Vec<String> {
    let cash = || {
        vec![
            "Post the money to:".to_string(),
            postal_address.to_string(),
            "Write the reference on the envelope, or on a slip inside it.".to_string(),
        ]
    };
    match rail {
        "cash" => cash(),
        "monero" => match monero.filter(|m| !m.stale && m.quote_xmr.is_some()) {
            Some(m) => {
                let mut out = Vec::new();
                match m.address.as_deref() {
                    Some(address) => out.push(format!("Your Monero subaddress is {address}.")),
                    None => out.push(
                        "Your Monero subaddress is not ready yet; it will follow in a second \
                         message."
                            .to_string(),
                    ),
                }
                if let Some(rate) = m.rate_gbp_per_xmr.as_deref() {
                    // The stored quote is for the full price. A held balance
                    // re-quotes what is still owed at the same rate, because
                    // otherwise the page asks for GBP 19.50 and the XMR amount
                    // for GBP 20.00 beside it. On a window with nothing held the
                    // recomputation is the stored quote.
                    let quote = crate::util::pence(amount_gbp)
                        .ok()
                        .and_then(|pence| crate::xmr::quote_xmr(pence, rate).ok())
                        .or_else(|| m.quote_xmr.clone());
                    if let Some(quote) = quote {
                        let on = m
                            .rate_at
                            .as_deref()
                            .and_then(|at| at.get(..10))
                            .unwrap_or("");
                        out.push(format!(
                            "Send {quote} XMR for GBP {amount_gbp}, quoted at GBP {rate} per XMR on {on}."
                        ));
                    }
                }
                out.push(
                    "The pound amount is what is owed; the quoted amount in Monero settles it."
                        .to_string(),
                );
                out.push(
                    "Send it to the subaddress: a payment to the wallet's main address cannot be \
                     joined to an account."
                        .to_string(),
                );
                out
            }
            None => {
                let mut out = vec![
                    "Monero is not quoted for this window, so cash by post is the only prepaid \
                     rail."
                        .to_string(),
                ];
                out.extend(cash());
                out
            }
        },
        "card" => match card_link {
            Some(link) => vec![
                "Pay by card at this link, which carries your reference:".to_string(),
                link.to_string(),
            ],
            None => vec!["A card payment link will follow in a second message.".to_string()],
        },
        other => vec![format!(
            "The rail you chose, {other}, will be quoted to you."
        )],
    }
}

/// The card rail's Payment Link, keyed to one payment token.
///
/// The reference is the account's `KYR-` token, which is what the token index
/// joins to the account: the same join `credit()` uses. `client_reference_id`
/// is the one Payment Link parameter that carries it, and it is what
/// `checkout.session.completed` names the account by. A placeholder that
/// reached the box is refused rather than mailed, because a member cannot pay
/// at REPLACE_ME.
pub fn card_link(payment_link: &str, token: &str) -> Result<Option<String>, String> {
    if token.is_empty() {
        return Ok(None);
    }
    let link = payment_link.trim_end_matches(['&', '?']);
    if link.is_empty() || link.contains("REPLACE_ME") {
        return Err(
            "stripe_payment_link is not configured, so a card approval has no link to send"
                .to_string(),
        );
    }
    let joiner = if link.contains('?') { '&' } else { '?' };
    Ok(Some(format!("{link}{joiner}client_reference_id={token}")))
}

/// How far a webhook's timestamp may be from this box's clock. Stripe's own
/// libraries default to five minutes, and the box runs NTP so the window means
/// something. A body older than this is a replay, not a delivery.
const WEBHOOK_TOLERANCE: i64 = 300;

/// Settle the Stripe events the handler wrote under `webhooks/`.
///
/// The handler holds no secret and verifies nothing: it stores the raw body and
/// the `Stripe-Signature` header and answers 2xx. This pass is the half with the
/// secret, so it is the half that decides. Each pair is verified over the exact
/// bytes received, inside five minutes of now, and against every `v1` value the
/// header carries (a rolled secret signs with two). A refusal is logged with the
/// file it names and both files are deleted; nothing else is written. A verified
/// event is deduplicated on its id and on `(type, object.id)`, applied, recorded
/// in `webhooks/processed.jsonl`, and only then removed.
///
/// An event that cannot be applied yet — the Stripe API unreachable for an
/// invoice's subscription — is left in place so the next pass tries again. The
/// date is never extended on trust.
pub async fn stripe_webhooks(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
) -> Result<(), String> {
    // A box whose card rail is not configured yet has no secret, and a pass
    // with nothing to verify must not fail every minute. The first delivery
    // makes the missing secret loud.
    if !store
        .list("webhooks")
        .await?
        .iter()
        .any(|n| n.ends_with(".body"))
    {
        return Ok(());
    }
    // A missing secret is a misconfigured box, not a failed pass: mailed once,
    // and the deliveries stay for the pass that has a secret to verify them.
    let secret = match sign::read_key(std::path::Path::new(&cfg.stripe_webhook_secret)) {
        Ok(secret) => secret,
        Err(e) => {
            report_failure(cfg, store, journal, "stripe-secret", "config", &e).await;
            return Ok(());
        }
    };
    let mut seen = processed_events(store).await?;
    // A checkout that attaches a subscription is settled before the invoice
    // that names it, whatever order the two files were written in: Stripe does
    // not promise the order, and the invoice has no other way to find the
    // account. An invoice with no target yet is left for the next pass, so a
    // delivery that genuinely arrives first is not dropped.
    for checkout_first in [true, false] {
        for name in store.list("webhooks").await? {
            let Some(id) = name.strip_suffix(".body") else {
                continue;
            };
            let body = match tokio::fs::read(store.path(&format!("webhooks/{name}"))).await {
                Ok(body) => body,
                // A pair another iteration of this pass already settled.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    eprintln!("kyriakon-onboard: webhook {id} is unreadable: {e}");
                    remove_webhook(store, id).await?;
                    continue;
                }
            };
            let sig = store
                .read_record("webhooks", &format!("{id}.sig"))
                .await
                .unwrap_or_default();
            if let Err(why) = verify_webhook(
                &secret,
                &sig,
                &body,
                OffsetDateTime::now_utc().unix_timestamp(),
            ) {
                eprintln!("kyriakon-onboard: webhook {id} refused: {why}");
                remove_webhook(store, id).await?;
                continue;
            }
            let event: Value = match serde_json::from_slice(&body) {
                Ok(event) => event,
                Err(e) => {
                    eprintln!("kyriakon-onboard: webhook {id} is not JSON: {e}");
                    remove_webhook(store, id).await?;
                    continue;
                }
            };
            let event_id = event.get("id").and_then(Value::as_str).unwrap_or("");
            let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
            let object_id = event
                .pointer("/data/object/id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let is_checkout = kind == "checkout.session.completed";
            if is_checkout != checkout_first {
                continue;
            }
            if event_id.is_empty() || kind.is_empty() {
                eprintln!("kyriakon-onboard: webhook {id} names no event id or type");
                remove_webhook(store, id).await?;
                continue;
            }
            if seen.contains(&format!("event:{event_id}")) {
                remove_webhook(store, id).await?;
                continue;
            }
            if let Some(pair) = invoice_pair(kind, object_id) {
                if seen.contains(&pair) {
                    remove_webhook(store, id).await?;
                    continue;
                }
            }
            match settle_event(cfg, store, journal, kind, &event).await {
                Ok(Settled::Applied) => {
                    let line = serde_json::json!({
                        "at": util::filed_at(),
                        "event": event_id,
                        "type": kind,
                        "object": object_id,
                    });
                    let bytes = serde_json::to_vec(&line)
                        .map_err(|e| format!("cannot encode the processed event: {e}"))?;
                    store.log("webhooks/processed.jsonl").append(&bytes).await?;
                    seen.insert(format!("event:{event_id}"));
                    if let Some(pair) = invoice_pair(kind, object_id) {
                        seen.insert(pair);
                    }
                    remove_webhook(store, id).await?;
                }
                // A valid event with nothing of ours in it settles nothing and
                // writes nothing; the pair is still removed so it is not retried.
                Ok(Settled::Ignored) => remove_webhook(store, id).await?,
                // The account this names is not known yet, which a checkout
                // still in the directory, or one arriving later, will change.
                Ok(Settled::Deferred) => {}
                Err(e) => {
                    eprintln!(
                        "kyriakon-onboard: webhook {id} ({kind}) could not be settled yet: {e}"
                    );
                }
            }
        }
    }
    Ok(())
}

/// Whether a `Stripe-Signature` header proves this body, and that the delivery
/// is recent. Accepts only `v1`: `v0` is the test-only older scheme. The
/// comparison is constant time through [`sign::verify_bytes`], and every `v1`
/// value is tried so a secret mid-roll verifies either way.
pub fn verify_webhook(secret: &[u8], header: &str, body: &[u8], now: i64) -> Result<(), String> {
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<&str> = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part
            .split_once('=')
            .ok_or_else(|| format!("the signature header carries {part:?} without a value"))?;
        match name {
            "t" => {
                timestamp = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| format!("the timestamp {value:?} is not a number"))?,
                );
            }
            "v1" => signatures.push(value),
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or("the signature header carries no t=")?;
    if signatures.is_empty() {
        return Err("the signature header carries no v1 signature".to_string());
    }
    if (now - timestamp).abs() > WEBHOOK_TOLERANCE {
        return Err(format!(
            "the timestamp {timestamp} is more than five minutes from {now}"
        ));
    }
    let mut payload = timestamp.to_string().into_bytes();
    payload.push(b'.');
    payload.extend_from_slice(body);
    if signatures
        .iter()
        .any(|sig| sign::verify_bytes(secret, &payload, sig))
    {
        Ok(())
    } else {
        Err("no v1 signature matches the body".to_string())
    }
}

async fn remove_webhook(store: &Store, id: &str) -> Result<(), String> {
    store.remove("webhooks", &format!("{id}.body")).await?;
    store.remove("webhooks", &format!("{id}.sig")).await
}

/// The one pair key the dedup uses: an invoice is one payment, so a second
/// `invoice.paid` for the same invoice (with a fresh event id) settles nothing.
/// Every other event type is deduplicated on its id alone: one subscription's
/// `updated` arrives many times, and each one is a state to record.
fn invoice_pair(kind: &str, object: &str) -> Option<String> {
    (kind == "invoice.paid" && !object.is_empty()).then(|| format!("invoice.paid:{object}"))
}

/// The event ids and `(type, object)` pairs already settled. One append-only
/// record, so a resend sees what an earlier pass did.
async fn processed_events(store: &Store) -> Result<HashSet<String>, String> {
    let mut seen = HashSet::new();
    for value in store
        .log("webhooks/processed.jsonl")
        .jsonl::<Value>()
        .await?
    {
        if let Some(event) = value.get("event").and_then(Value::as_str) {
            seen.insert(format!("event:{event}"));
        }
        if let (Some(kind), Some(object)) = (
            value.get("type").and_then(Value::as_str),
            value.get("object").and_then(Value::as_str),
        ) {
            if let Some(pair) = invoice_pair(kind, object) {
                seen.insert(pair);
            }
        }
    }
    Ok(seen)
}

/// One account or group the card rail belongs to, with the payment block the
/// event changes.
enum BillingTarget {
    Account(Box<Account>),
    Group(Box<GroupRecord>),
}

impl BillingTarget {
    fn stripe(&self) -> &store::StripeBilling {
        match self {
            BillingTarget::Account(a) => a.payment.as_ref().map(|p| &p.stripe).unwrap_or(&EMPTY),
            BillingTarget::Group(g) => &g.payment.stripe,
        }
    }

    fn stripe_mut(&mut self) -> &mut store::StripeBilling {
        match self {
            BillingTarget::Account(a) => {
                &mut a.payment.as_mut().expect("a target has a payment").stripe
            }
            BillingTarget::Group(g) => &mut g.payment.stripe,
        }
    }

    /// The paid date, when one is set. A free or unpaid account has none.
    fn paid_until(&self) -> Option<&str> {
        match self {
            BillingTarget::Account(a) => a.payment.as_ref()?.paid_until.as_deref(),
            BillingTarget::Group(g) => g.payment.paid_until.as_deref(),
        }
    }

    /// The token the ledger line is keyed by. An account's is its own; a
    /// group's is the one token the whole body shares, so a card payment for a
    /// group is one line that stops naming the body once the group is gone.
    fn token(&self) -> Option<&str> {
        match self {
            BillingTarget::Account(a) => a.payment.as_ref()?.token_ref.as_deref(),
            BillingTarget::Group(g) => g.payment.token_ref.as_deref(),
        }
    }

    /// A payment extends the date and marks the window paid. A group's window
    /// closes the same way: one date, shared by every mailbox in it, and every
    /// mailbox a lapse had stopped comes back through the same restore loop a
    /// prepaid credit runs.
    async fn set_paid_until(
        &mut self,
        cfg: &DrainConfig,
        store: &Store,
        date: String,
    ) -> Result<(), String> {
        match self {
            BillingTarget::Account(a) => {
                let payment = a
                    .payment
                    .as_mut()
                    .ok_or("the account has no payment block")?;
                payment.paid_until = Some(date);
                if let Some(window) = payment.window.as_mut() {
                    window.state = "paid".to_string();
                }
            }
            BillingTarget::Group(g) => {
                g.payment.paid_until = Some(date);
                if let Some(window) = g.payment.window.as_mut() {
                    window.state = "paid".to_string();
                }
                restore_group_mailboxes(cfg, store, g).await?;
            }
        }
        Ok(())
    }

    async fn save(&self, store: &Store) -> Result<(), String> {
        match self {
            BillingTarget::Account(a) => {
                let bytes = serde_json::to_vec_pretty(a)
                    .map_err(|e| format!("cannot encode the account: {e}"))?;
                write_account_record(store, &a.username, &bytes).await
            }
            BillingTarget::Group(g) => write_group_record(store, g).await,
        }
    }

    /// The address a notice about this payment goes to: the member's outside
    /// address, or the mailbox the platform made. A group's notice goes to the
    /// address its application gave, which for a body is on the body's own
    /// domain rather than the platform's.
    async fn recipient(&self, store: &Store) -> String {
        match self {
            BillingTarget::Account(a) => a
                .outside_address
                .clone()
                .unwrap_or_else(|| format!("{}@kyriakon.net", a.username)),
            BillingTarget::Group(g) => dns_contact(store, g)
                .await
                .unwrap_or_else(|_| format!("{}@{}", g.site_owner, g.domain)),
        }
    }
}

static EMPTY: store::StripeBilling = store::StripeBilling {
    subscription: None,
    customer: None,
    status: None,
    cancel_at_period_end: false,
    current_period_end: None,
    next_payment_attempt: None,
    failed_attempts: 0,
    last_invoice: None,
};

/// A target named by an application or a subscription.
#[derive(Clone)]
enum TargetRef {
    Account(String),
    Group(String),
}

async fn load_target(store: &Store, target: &TargetRef) -> Result<Option<BillingTarget>, String> {
    match target {
        TargetRef::Account(username) => {
            let Some(account) = store.account(username).await? else {
                return Ok(None);
            };
            // A free approval has no payment block, so a card event is not its
            // to change.
            if account.payment.is_none() {
                return Ok(None);
            }
            Ok(Some(BillingTarget::Account(Box::new(account))))
        }
        TargetRef::Group(domain) => Ok(group_record(store, domain)
            .await?
            .map(|record| BillingTarget::Group(Box::new(record)))),
    }
}

/// The account or group a subscription belongs to, found by the id the checkout
/// event attached. Invoices name only the subscription, and the application
/// record may be long purged, so the subscription is the durable join.
///
/// A record that cannot be read is reported and fails this event. The filename
/// (a username or a domain) does not say whose subscription it is, so the scan
/// cannot skip a damaged record without risking settling the event as nobody's;
/// the delivery stays queued until the record is fixed.
async fn target_for_subscription(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    subscription: &str,
) -> Result<Option<TargetRef>, String> {
    for username in store.list("accounts").await? {
        let account = match store.account(&username).await {
            Ok(account) => account,
            Err(e) => {
                // A corrupt account could own the subscription, so the scan
                // cannot skip it. Report the record and fail this event; the
                // delivery stays queued for the pass after the record is fixed.
                report_record(cfg, store, journal, "account", &username, &e).await;
                return Err(e);
            }
        };
        let Some(account) = account else {
            continue;
        };
        if account
            .payment_state()
            .and_then(|p| p.stripe.subscription)
            .as_deref()
            == Some(subscription)
        {
            return Ok(Some(TargetRef::Account(username)));
        }
    }
    for domain in store.list("groups").await? {
        let record = match group_record(store, &domain).await {
            Ok(record) => record,
            Err(e) => {
                report_record(cfg, store, journal, "group", &domain, &e).await;
                return Err(e);
            }
        };
        let Some(record) = record else {
            continue;
        };
        if record.payment.stripe.subscription.as_deref() == Some(subscription) {
            return Ok(Some(TargetRef::Group(domain)));
        }
    }
    Ok(None)
}

/// What settling one event did. `Deferred` leaves the pair in `webhooks/` for
/// the next pass, because the account it names is not attached yet.
enum Settled {
    Applied,
    Ignored,
    Deferred,
}

async fn settle_event(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    kind: &str,
    event: &Value,
) -> Result<Settled, String> {
    let object = event
        .pointer("/data/object")
        .ok_or("the event carries no data.object")?;
    match kind {
        "checkout.session.completed" => checkout_completed(store, object).await,
        "invoice.paid" => invoice_paid(cfg, store, journal, object).await,
        "invoice.payment_failed" => invoice_payment_failed(cfg, store, journal, object).await,
        "invoice.payment_action_required" => {
            invoice_payment_action_required(cfg, store, journal, object).await
        }
        "customer.subscription.updated" | "customer.subscription.deleted" => {
            subscription_changed(
                cfg,
                store,
                journal,
                object,
                kind == "customer.subscription.deleted",
            )
            .await
        }
        "invoice.upcoming" => invoice_upcoming(cfg, store, journal, object).await,
        // Everything else the endpoint is not subscribed to. A verified event of
        // an unknown type is not an error; it is simply not ours.
        _ => Ok(Settled::Ignored),
    }
}

/// The account a payment token names, through the index the credit path uses:
/// `tokens/<ref>.json` → username → `accounts/<username>/account.json`. Only a
/// card account's own token resolves; anything else, including a status token
/// or a token whose record names another token, is not a reference this rail
/// answers. The account must carry a payment block, because a free approval has
/// nothing to settle.
async fn account_for_payment_reference(
    store: &Store,
    reference: &str,
) -> Result<Option<Account>, String> {
    if !store::is_payment_token(reference) {
        return Ok(None);
    }
    // A record that is there and does not parse is drift, not a token that
    // names nothing: an `Ok(None)` here would settle the delivery as ignored
    // and delete it, so the caller gets the reason and leaves it for a retry.
    let Some(join) = store.token(reference).await? else {
        return Ok(None);
    };
    if join.token != reference || validate::username_shape(&join.username).is_some() {
        return Ok(None);
    }
    let Some(account) = store.account(&join.username).await? else {
        return Ok(None);
    };
    let Some(payment) = account.payment_state() else {
        return Ok(None);
    };
    if account.rail != "card"
        || account.no_charge
        || payment.token_ref.as_deref() != Some(reference)
    {
        return Ok(None);
    }
    Ok(Some(account))
}

/// The account or group a checkout's `client_reference_id` names. The index
/// resolves to one or the other: a person's token names their account, a
/// group's token names the group, so one subscription and one renewal write one
/// date for every mailbox in it.
async fn target_for_payment_reference(
    store: &Store,
    reference: &str,
) -> Result<Option<TargetRef>, String> {
    if let Some(account) = account_for_payment_reference(store, reference).await? {
        return Ok(Some(TargetRef::Account(account.username)));
    }
    if !store::is_payment_token(reference) {
        return Ok(None);
    }
    let Some(join) = token_join(store, reference).await? else {
        return Ok(None);
    };
    let Some(domain) = join.group.as_deref() else {
        return Ok(None);
    };
    if validate::domain(domain).is_some() {
        return Ok(None);
    }
    let Some(group) = group_record(store, domain).await? else {
        return Ok(None);
    };
    if group.payment.no_charge
        || group.payment.rail != "card"
        || group.payment.token_ref.as_deref() != Some(reference)
    {
        return Ok(None);
    }
    Ok(Some(TargetRef::Group(domain.to_string())))
}

/// Attach a subscription and its customer to an account or a group, which is
/// all a checkout does. The date stays `invoice.paid`'s to set.
async fn attach_subscription(
    store: &Store,
    billing: &mut BillingTarget,
    subscription: &str,
    customer: Option<&str>,
) -> Result<(), String> {
    let stripe = billing.stripe_mut();
    stripe.subscription = Some(subscription.to_string());
    stripe.customer = customer.map(str::to_string);
    billing.save(store).await
}

/// `checkout.session.completed`: the `client_reference_id` is the account's or
/// the group's `KYR-` token, and the subscription and customer are attached to
/// what it indexes. Nothing else happens: `invoice.paid` owns the date, so a
/// first payment extends exactly one year and never two.
async fn checkout_completed(store: &Store, object: &Value) -> Result<Settled, String> {
    let Some(reference) = object
        .get("client_reference_id")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
    else {
        return Ok(Settled::Ignored);
    };
    let Some(subscription) = object.get("subscription").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(target) = target_for_payment_reference(store, reference).await? else {
        return Ok(Settled::Ignored);
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    let customer = object.get("customer").and_then(Value::as_str);
    attach_subscription(store, &mut billing, subscription, customer).await?;
    Ok(Settled::Applied)
}

/// `invoice.paid`: retrieve the subscription and confirm it is `active`, then
/// extend the date one calendar year from the later of today and the date the
/// account already holds. The invoice id is the key the extension is idempotent
/// on, so a redelivery with a fresh event id settles nothing twice. A
/// subscription that is not active is recorded and does not move the date.
async fn invoice_paid(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    object: &Value,
) -> Result<Settled, String> {
    let Some(subscription) = object.get("subscription").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(invoice) = object.get("id").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    // The API, not the event: a paid invoice does not prove an active
    // subscription. An unreachable API is an error, which leaves the event for
    // the next pass rather than extending the date on trust. The same answer is
    // the repair path: a missed checkout leaves the subscription naming its
    // account in metadata, and that is how the attachment is made here.
    let subscription_json = retrieve_subscription(cfg, subscription).await?;
    let status = subscription_json
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    let period_end = period_end(&subscription_json);
    let customer = subscription_json.get("customer").and_then(Value::as_str);
    let target = match target_for_subscription(cfg, store, journal, subscription).await? {
        Some(target) => target,
        None => {
            // A missed `checkout.session.completed` leaves no store record, so
            // the session the subscription came from is the repair: the list
            // filter names it, and its `client_reference_id` is the account's or
            // the group's token. A subscription with no session reference stays
            // deferred.
            let session = retrieve_session(cfg, subscription).await?;
            let reference = card_reference(&session, &subscription_json);
            let Some(target) = target_for_payment_reference(store, reference).await? else {
                return Ok(Settled::Deferred);
            };
            let Some(mut billing) = load_target(store, &target).await? else {
                return Ok(Settled::Deferred);
            };
            attach_subscription(store, &mut billing, subscription, customer).await?;
            target
        }
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    {
        let stripe = billing.stripe_mut();
        stripe.status = Some(status.to_string());
        stripe.customer = customer.map(str::to_string);
        stripe.current_period_end = period_end;
        stripe.subscription = Some(subscription.to_string());
    }
    if status != "active" {
        billing.save(store).await?;
        return Ok(Settled::Applied);
    }
    // The ledger line must carry what the invoice says was paid, on the day it
    // was paid, not the configured price on the day the drain happened to run.
    let (amount_gbp, received_on) = invoice_money(object)?;
    if billing.stripe().last_invoice.as_deref() == Some(invoice) {
        // The date was saved on an earlier pass. The ledger line it opens may
        // still be missing if that pass died between the save and the append,
        // and the invoice id is the dedup key that finishes it once.
        append_invoice_ledger(
            store,
            billing.token(),
            billing.paid_until(),
            invoice,
            &amount_gbp,
            &received_on,
        )
        .await?;
        billing.save(store).await?;
        return Ok(Settled::Applied);
    }
    let received = util::filed_at();
    let date = crate::billing::extend_paid_until(&received, billing.paid_until())?;
    billing.set_paid_until(cfg, store, date).await?;
    billing.stripe_mut().last_invoice = Some(invoice.to_string());
    billing.stripe_mut().failed_attempts = 0;
    billing.stripe_mut().next_payment_attempt = None;
    billing.save(store).await?;
    if let BillingTarget::Account(account) = &billing {
        if let Some(payment) = &account.payment {
            write_payment_copy(store, &account.username, payment).await?;
        }
    }
    append_invoice_ledger(
        store,
        billing.token(),
        billing.paid_until(),
        invoice,
        &amount_gbp,
        &received_on,
    )
    .await?;
    Ok(Settled::Applied)
}

/// What a paid invoice says it paid, in pounds, and the day it was paid. The
/// ledger's amount and date must come from the processor's object rather than
/// the configured price and the drain's clock: a discount, a price change, or
/// an event applied after the tax-year boundary would otherwise be recorded
/// wrong. A missing amount or timestamp is an error, which leaves the event for
/// the next pass rather than writing a guess.
fn invoice_money(object: &Value) -> Result<(String, String), String> {
    let amount = object
        .get("amount_paid")
        .and_then(Value::as_i64)
        .ok_or("the paid invoice carries no amount_paid")?;
    let paid = object
        .pointer("/status_transitions/paid_at")
        .and_then(Value::as_i64)
        .or_else(|| object.get("created").and_then(Value::as_i64))
        .ok_or("the paid invoice carries no paid timestamp")?;
    let when = OffsetDateTime::from_unix_timestamp(paid)
        .map_err(|e| format!("the invoice's paid timestamp cannot be read: {e}"))?;
    Ok((util::gbp(amount), util::date_string(when.date())))
}

/// The ledger line a paid card invoice opens. Without it a card payment has no
/// `seq`, and the refund path has nothing to reverse. It is keyed by the token
/// the payment is for: an account's own, or the one token a group holds, so a
/// body's card payment is one line like its prepaid one. The invoice id is the
/// dedup key, which is also what recovers a crash between the record write and
/// this append. Nothing here talks to Stripe: the card rail stays read-only
/// towards it.
async fn append_invoice_ledger(
    store: &Store,
    token: Option<&str>,
    paid_until_after: Option<&str>,
    invoice: &str,
    amount_gbp: &str,
    received_on: &str,
) -> Result<(), String> {
    let Some(token) = token else {
        return Ok(());
    };
    if Ledger::open(store).has_intent(invoice).await? {
        return Ok(());
    }
    let mut line = LedgerLine::empty(token, "payment", "card");
    line.received_on = Some(received_on.to_string());
    line.amount_gbp = Some(amount_gbp.to_string());
    line.applied_gbp = Some(amount_gbp.to_string());
    line.paid_until_after = paid_until_after.map(str::to_string);
    line.intent = Some(invoice.to_string());
    Ledger::open(store).append(line).await?;
    Ok(())
}

/// The current subscription from the Stripe API, through the one script that
/// holds the key. Read-only: the webhook path makes no Stripe writes.
async fn retrieve_subscription(cfg: &DrainConfig, subscription: &str) -> Result<Value, String> {
    if !subscription
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(format!("the subscription id {subscription:?} is not an id"));
    }
    let out = spawn_script(
        cfg,
        "stripe-api.sh",
        &["subscription", subscription, &cfg.stripe_api_key],
    )
    .await?;
    if !out.status.success() {
        return Err(script_error(cfg, "stripe-api.sh", &out));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("stripe-api.sh did not answer with a subscription: {e}"))
}

/// The Checkout Session a subscription came from, read through the same script.
/// The list is filtered by the subscription and bounded to one; an empty list or
/// an unreachable API is an error, so the event stays for the next pass.
async fn retrieve_session(cfg: &DrainConfig, subscription: &str) -> Result<Value, String> {
    if !subscription
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(format!("the subscription id {subscription:?} is not an id"));
    }
    let out = spawn_script(
        cfg,
        "stripe-api.sh",
        &["session", subscription, &cfg.stripe_api_key],
    )
    .await?;
    if !out.status.success() {
        return Err(script_error(cfg, "stripe-api.sh", &out));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("stripe-api.sh did not answer with a checkout session: {e}"))
}

/// The account reference a repaired payment carries: the session's own
/// `client_reference_id` first, then the metadata keys a Stripe object can hold
/// it under.
fn card_reference<'a>(session: &'a Value, subscription: &'a Value) -> &'a str {
    let pick = |value: &'a Value| {
        value
            .pointer("/client_reference_id")
            .or_else(|| value.pointer("/metadata/client_reference_id"))
            .or_else(|| value.pointer("/metadata/kyriakon_application"))
            .and_then(Value::as_str)
            .filter(|reference| !reference.is_empty())
    };
    pick(session).or_else(|| pick(subscription)).unwrap_or("")
}

/// `invoice.payment_failed`: record the attempt and the next retry on the
/// account, and nothing else. Stripe's own dunning email is the member's copy;
/// a platform copy would be a second mail about one failed attempt. The date
/// does not move: access is the paid date's, not a failed attempt's.
async fn invoice_payment_failed(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    object: &Value,
) -> Result<Settled, String> {
    let Some(subscription) = object.get("subscription").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(target) = target_for_subscription(cfg, store, journal, subscription).await? else {
        return Ok(Settled::Deferred);
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    let next = object.get("next_payment_attempt").and_then(stamp);
    let attempts = object
        .get("attempt_count")
        .and_then(Value::as_u64)
        .unwrap_or(u64::from(billing.stripe().failed_attempts) + 1);
    {
        let stripe = billing.stripe_mut();
        stripe.failed_attempts = attempts.min(u64::from(u32::MAX)) as u32;
        stripe.next_payment_attempt = next;
    }
    billing.save(store).await?;
    Ok(Settled::Applied)
}

/// `invoice.payment_action_required`: the one card event the member must act
/// on, because the bank is waiting for authentication and no retry can settle
/// it. The attempt is recorded and one notice asks them to complete it.
async fn invoice_payment_action_required(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    object: &Value,
) -> Result<Settled, String> {
    let Some(subscription) = object.get("subscription").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(target) = target_for_subscription(cfg, store, journal, subscription).await? else {
        return Ok(Settled::Deferred);
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    let invoice = object
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("an invoice");
    let attempts = object
        .get("attempt_count")
        .and_then(Value::as_u64)
        .unwrap_or(u64::from(billing.stripe().failed_attempts) + 1);
    {
        let stripe = billing.stripe_mut();
        stripe.failed_attempts = attempts.min(u64::from(u32::MAX)) as u32;
        stripe.next_payment_attempt = object.get("next_payment_attempt").and_then(stamp);
    }
    billing.save(store).await?;
    let owner = billing.notice_owner();
    let body = format!(
        "A card payment for your membership needs you to complete it: the bank has \
         asked for authentication and will not settle it on its own. Open the link in \
         your approval email and complete the payment there. Nothing has been deleted \
         and your access has not changed.\n\n\
         Invoice: {invoice}\n\
         Attempts so far: {attempts}\n"
    );
    notice::send_account_notice(
        cfg,
        store,
        &owner,
        "payment.action-required",
        &format!("Complete your card payment ({invoice})"),
        &billing.recipient(store).await,
        &body,
    )
    .await?;
    Ok(Settled::Applied)
}

impl BillingTarget {
    /// The account whose `notices.jsonl` records a notice about this target: a
    /// group's notices are its site owner's.
    fn notice_owner(&self) -> String {
        match self {
            BillingTarget::Account(a) => a.username.clone(),
            BillingTarget::Group(g) => g.site_owner.clone(),
        }
    }
}

/// `customer.subscription.updated` and `deleted`: reconcile the status and the
/// period end. A deletion stops renewal and never revokes a paid date.
async fn subscription_changed(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    object: &Value,
    deleted: bool,
) -> Result<Settled, String> {
    let Some(subscription) = object.get("id").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(target) = target_for_subscription(cfg, store, journal, subscription).await? else {
        return Ok(Settled::Deferred);
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    let status = if deleted {
        "canceled"
    } else {
        object.get("status").and_then(Value::as_str).unwrap_or("")
    };
    let stripe = billing.stripe_mut();
    stripe.status = Some(status.to_string());
    stripe.current_period_end = period_end(object);
    // The flag comes from the event: `updated` carries the member's choice, a
    // `deleted` subscription renews nothing, and an event that omits it is
    // another fact about the same subscription rather than a resumption.
    stripe.cancel_at_period_end = deleted
        || object
            .get("cancel_at_period_end")
            .and_then(Value::as_bool)
            .unwrap_or(stripe.cancel_at_period_end);
    if let Some(customer) = object.get("customer").and_then(Value::as_str) {
        stripe.customer = Some(customer.to_string());
    }
    billing.save(store).await?;
    Ok(Settled::Applied)
}

/// `invoice.upcoming`: record the period end the upcoming invoice names. Stripe
/// sends the annual reminder itself, with its own copy, so the platform sends
/// none; this event is a state fact and nothing more.
async fn invoice_upcoming(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    object: &Value,
) -> Result<Settled, String> {
    let Some(subscription) = object.get("subscription").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(target) = target_for_subscription(cfg, store, journal, subscription).await? else {
        return Ok(Settled::Deferred);
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    billing.stripe_mut().current_period_end = period_end(object);
    billing.save(store).await?;
    Ok(Settled::Applied)
}

/// A Stripe unix timestamp as RFC 3339, or `None` where the field is absent or
/// null (an invoice with no next attempt yet).
fn stamp(value: &Value) -> Option<String> {
    let seconds = value.as_i64()?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// A subscription's or invoice's period end. Newer API versions moved it onto
/// the items, so both shapes are read.
fn period_end(value: &Value) -> Option<String> {
    value
        .get("current_period_end")
        .or_else(|| value.get("period_end"))
        .and_then(stamp)
        .or_else(|| {
            value
                .pointer("/items/data/0/current_period_end")
                .and_then(stamp)
        })
}
