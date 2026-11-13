//! The card rail: the webhook pass that settles Stripe's events.
//!
//! The card link and the payment instructions the account pages, the approval
//! mail and the renewal note carry live in `payments::rails`.

use super::boxrun::{run_script, script_error, spawn_script};
use super::groups::{group_record, write_account_record, write_group_record};
use super::lifecycle::{dns_contact, report_record};
use super::payments::{restore_group_mailboxes, token_join, write_payment_copy};
use super::report_failure;
use super::Error;
use kyriakon_control_core::account::sign;
use kyriakon_control_core::config::DrainConfig;
use kyriakon_control_core::flow::validate;
use kyriakon_control_core::mail::notice;
use kyriakon_control_core::payments::ledger::Ledger;
use kyriakon_control_core::payments::ledger::LedgerLine;
use kyriakon_control_core::store::journal::Journal;
use kyriakon_control_core::store::{self, Account, GroupRecord, Store};
use kyriakon_control_core::util;
use serde_json::Value;
use std::collections::HashSet;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// How far a webhook's timestamp may be from this box's clock at the moment
/// the handler accepted the delivery. Stripe's own libraries default to five
/// minutes, and the box runs NTP so the window means something. A timestamp
/// more than this from the delivery's arrival is a replay, not a delivery.
const WEBHOOK_TOLERANCE: i64 = 300;

/// Settle the Stripe events the handler wrote under `webhooks/`.
///
/// The handler holds no secret and verifies nothing: it stores the raw body and
/// the `Stripe-Signature` header and answers 2xx. This pass is the half with the
/// secret, so it is the half that decides. The first sight of an event is
/// verified over the exact bytes received, inside five minutes of the arrival
/// the handler stamped beside it, and against every `v1` value the header
/// carries (a rolled secret signs with two);
/// its id is then recorded in root-only `verified/`. A later pass trusts that
/// record and checks only the HMAC: a deferred event is waiting for the event it
/// follows, not late, so the clock no longer deletes it. The record goes when
/// the event is applied or settles.
///
/// A pair never proven is refused and both files are deleted, which is what a
/// forged or replayed delivery is. A pair proven before keeps its queue entry if
/// a later check fails: the bytes or the secret changed, and a money-bearing
/// event is not root's to drop. A verified event is deduplicated on its id and
/// on `(type, object.id)`, applied, recorded in `webhooks/processed.jsonl`, and
/// only then removed.
///
/// An event that cannot be applied yet — the Stripe API unreachable for an
/// invoice's subscription — is left in place so the next pass tries again. The
/// date is never extended on trust.
pub async fn stripe_webhooks(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
) -> Result<(), Error> {
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
            report_failure(
                cfg,
                store,
                journal,
                "stripe-secret",
                "config",
                &Error::from(e),
            )
            .await;
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
                    Error::Failed(format!("is unreadable: {e}")).report(&format!("webhook {id}"));
                    remove_webhook(store, id).await?;
                    continue;
                }
            };
            let sig = store
                .read_record("webhooks", &format!("{id}.sig"))
                .await
                .unwrap_or_default();
            // The body is parsed first, because the event id in it decides
            // whether this is the first sight of the delivery. A body that is
            // not JSON is refused whatever the id would have said.
            let event: Value = match serde_json::from_slice(&body) {
                Ok(event) => event,
                Err(e) => {
                    Error::Json {
                        context: "parse the webhook",
                        source: e,
                    }
                    .report(&format!("webhook {id}"));
                    remove_webhook(store, id).await?;
                    continue;
                }
            };
            let event_id = event.get("id").and_then(Value::as_str).unwrap_or("");
            let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
            // The id names a file under `verified/`, so its shape is checked
            // before it is joined into one. Stripe's ids are `evt_` and
            // alphanumerics; anything else is not an event this rail settles.
            if !event_id_shape(event_id) || kind.is_empty() {
                Error::Failed("names no event id or type".to_string())
                    .report(&format!("webhook {id}"));
                remove_webhook(store, id).await?;
                continue;
            }
            // A delivery proven on an earlier pass is not judged against this
            // pass's clock: it is waiting for the event it follows, not late.
            // Only the HMAC is checked again.
            let record = match store.verified_webhook(event_id).await {
                Ok(record) => record,
                Err(e) => {
                    // A record that cannot be read is not proof, and dropping
                    // the pair could lose the payment it carries.
                    Error::from(e).report(&format!("webhook {id}"));
                    continue;
                }
            };
            let verified = match record {
                Some(_) => verify_signature(&secret, &sig, &body),
                None => {
                    // Recency is measured against the moment the handler took
                    // the delivery, not this pass's clock: a pass delayed by a
                    // restart or a slow step must not turn a genuine delivery
                    // into a replay. A pair queued before the handler wrote the
                    // stamp falls back to its body's mtime, which is when it was
                    // stored.
                    let arrived = webhook_received(store, id)
                        .await
                        .unwrap_or_else(|| OffsetDateTime::now_utc().unix_timestamp());
                    verify_webhook(&secret, &sig, &body, arrived)
                }
            };
            if let Err(why) = verified {
                why.report(&format!("webhook {id} refused"));
                // A pair never proven is forged, replayed or unreadable, and
                // stays the refusal it always was. One proven before keeps its
                // queue entry: the signatures or the secret changed since, and
                // the event is not ours to delete. The proof names the queue
                // entry it was taken from, so a forged pair carrying a proven
                // event id does not inherit the trust.
                let proven_pair = record
                    .as_ref()
                    .and_then(|value| value.get("pair").and_then(Value::as_str))
                    .is_some_and(|pair| pair == id);
                if !proven_pair {
                    remove_webhook(store, id).await?;
                }
                continue;
            }
            let object_id = event
                .pointer("/data/object/id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let is_checkout = kind == "checkout.session.completed";
            // The first sight is recorded before anything can defer it, so a
            // later pass has the proof rather than a stale timestamp.
            if record.is_none() {
                let line = serde_json::json!({
                    "at": util::filed_at(),
                    "pair": id,
                    "event": event_id,
                    "type": kind,
                    "object": object_id,
                });
                let bytes = serde_json::to_vec(&line).map_err(|source| Error::Json {
                    context: "encode the verified event",
                    source,
                })?;
                store.ensure_dir("verified").await?;
                store
                    .write_record("verified", &format!("{event_id}.json"), &bytes)
                    .await?;
            }
            if is_checkout != checkout_first {
                continue;
            }
            if seen.contains(&format!("event:{event_id}")) {
                remove_webhook(store, id).await?;
                forget_verified(store, event_id).await?;
                continue;
            }
            if let Some(pair) = invoice_pair(kind, object_id) {
                if seen.contains(&pair) {
                    remove_webhook(store, id).await?;
                    forget_verified(store, event_id).await?;
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
                    let bytes = serde_json::to_vec(&line).map_err(|source| Error::Json {
                        context: "encode the processed event",
                        source,
                    })?;
                    // A pair whose record cannot be written is left in place:
                    // the event is settled and must be retried, and dropping
                    // the webhook here would apply it twice.
                    if let Err(e) = store.log("webhooks/processed.jsonl").append(&bytes).await {
                        e.report(&format!(
                            "webhook {id} ({kind}) could not be recorded as processed; it will be retried"
                        ));
                        continue;
                    }
                    seen.insert(format!("event:{event_id}"));
                    if let Some(pair) = invoice_pair(kind, object_id) {
                        seen.insert(pair);
                    }
                    remove_webhook(store, id).await?;
                    forget_verified(store, event_id).await?;
                }
                // A valid event with nothing of ours in it settles nothing and
                // writes nothing; the pair is still removed so it is not retried.
                Ok(Settled::Ignored) => {
                    remove_webhook(store, id).await?;
                    forget_verified(store, event_id).await?;
                }
                // The account this names is not known yet, which a checkout
                // still in the directory, or one arriving later, will change.
                // The pair and its record stay for the pass that can settle it.
                Ok(Settled::Deferred) => {}
                Err(e) => {
                    e.report(&format!("webhook {id} ({kind}) could not be settled yet"));
                }
            }
        }
    }
    Ok(())
}

/// Whether the signature header proves this body, and that the delivery is
/// recent. Accepts only `v1`: `v0` is the test-only older scheme. The
/// comparison is constant time through [`sign::verify_bytes`], and every `v1`
/// value is tried so a secret mid-roll verifies either way.
///
/// The recency check is a replay guard, so it is first-sight only and `now` is
/// the delivery's arrival, not the pass's clock. A delivery whose id `verified/`
/// already records was proven once; the clock is not applied to it again.
pub fn verify_webhook(secret: &[u8], header: &str, body: &[u8], arrived: i64) -> Result<(), Error> {
    let (timestamp, payload, signatures) = signature_parts(header, body)?;
    if (arrived - timestamp).abs() > WEBHOOK_TOLERANCE {
        return Err(Error::Failed(format!(
            "the timestamp {timestamp} is more than five minutes from its arrival {arrived}"
        )));
    }
    check_signatures(secret, &payload, &signatures)
}

/// The HMAC alone, with no clock: a delivery already recorded under `verified/`
/// is verified against the secret again but not judged for recency, because a
/// deferred event is not late.
pub fn verify_signature(secret: &[u8], header: &str, body: &[u8]) -> Result<(), Error> {
    let (_, payload, signatures) = signature_parts(header, body)?;
    check_signatures(secret, &payload, &signatures)
}

/// The header split into its timestamp, the signed payload and its `v1` values.
fn signature_parts<'a>(
    header: &'a str,
    body: &[u8],
) -> Result<(i64, Vec<u8>, Vec<&'a str>), Error> {
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<&str> = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part.split_once('=').ok_or_else(|| {
            Error::Failed(format!(
                "the signature header carries {part:?} without a value"
            ))
        })?;
        match name {
            "t" => {
                timestamp = Some(value.parse::<i64>().map_err(|source| {
                    Error::context(format!("the timestamp {value:?} is not a number"), source)
                })?);
            }
            "v1" => signatures.push(value),
            _ => {}
        }
    }
    let timestamp =
        timestamp.ok_or_else(|| Error::Failed("the signature header carries no t=".to_string()))?;
    if signatures.is_empty() {
        return Err(Error::Failed(
            "the signature header carries no v1 signature".to_string(),
        ));
    }
    let mut payload = timestamp.to_string().into_bytes();
    payload.push(b'.');
    payload.extend_from_slice(body);
    Ok((timestamp, payload, signatures))
}

fn check_signatures(secret: &[u8], payload: &[u8], signatures: &[&str]) -> Result<(), Error> {
    if signatures
        .iter()
        .any(|sig| sign::verify_bytes(secret, payload, sig))
    {
        Ok(())
    } else {
        Err(Error::Failed(
            "no v1 signature matches the body".to_string(),
        ))
    }
}

/// Whether `id` has the shape Stripe gives an event and is safe as a filename
/// under `verified/`: `evt_`, then letters, digits and `_`. The id comes from
/// the body, so it is a shape check before it is a path; a longer bound keeps a
/// name the filesystem would refuse out of the record write.
pub fn event_id_shape(id: &str) -> bool {
    id.strip_prefix("evt_").is_some_and(|rest| {
        !rest.is_empty()
            && rest.len() <= 200
            && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

async fn remove_webhook(store: &Store, id: &str) -> Result<(), Error> {
    store.remove("webhooks", &format!("{id}.body")).await?;
    store.remove("webhooks", &format!("{id}.sig")).await?;
    store
        .remove("webhooks", &format!("{id}.at"))
        .await
        .map_err(Error::from)
}

/// When the handler accepted this delivery, as a unix timestamp. It writes
/// `webhooks/<id>.at` before the body, so a body's presence means the stamp is
/// there. A pair queued by an older handler has no stamp, so the body's mtime —
/// the instant it was written — stands in for it; `None` only when neither can
/// be read, and the caller keeps its old comparison against now.
async fn webhook_received(store: &Store, id: &str) -> Option<i64> {
    if let Some(stamp) = store.read_record("webhooks", &format!("{id}.at")).await {
        if let Ok(at) = stamp.trim().parse::<i64>() {
            return Some(at);
        }
    }
    let modified = tokio::fs::metadata(store.path(&format!("webhooks/{id}.body")))
        .await
        .ok()?
        .modified()
        .ok()?;
    Some(OffsetDateTime::from(modified).unix_timestamp())
}

/// Drop the first-sight record once the event has settled, so `verified/` does
/// not grow with every payment. A deferred event keeps it for the retry.
async fn forget_verified(store: &Store, event_id: &str) -> Result<(), Error> {
    store
        .remove("verified", &format!("{event_id}.json"))
        .await
        .map_err(Error::from)
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
async fn processed_events(store: &Store) -> Result<HashSet<String>, Error> {
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

    /// The name the operator alert uses for this target: the account's username
    /// or the body's domain.
    fn label(&self) -> &str {
        match self {
            BillingTarget::Account(a) => &a.username,
            BillingTarget::Group(g) => &g.domain,
        }
    }

    /// The field and value a year's price is read from. An account pays its own
    /// price; a body's is the group price, not a person's price with a multiple.
    fn price<'a>(&self, cfg: &'a DrainConfig) -> (&'static str, &'a String) {
        match self {
            BillingTarget::Account(_) => ("price_gbp", &cfg.price_gbp),
            BillingTarget::Group(_) => ("group_price_gbp", &cfg.group_price_gbp),
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
    ) -> Result<(), Error> {
        match self {
            BillingTarget::Account(a) => {
                // A payment after a lapse restores access from the day it is
                // recorded. The restore runs before the record says active, as
                // `apply_payment` does, so a failure leaves the account lapsed
                // and the retry repeats an idempotent script.
                if a.state == "lapsed" {
                    run_script(cfg, "lapse-user.sh", &["--restore", &a.username]).await?;
                    a.state = "active".to_string();
                    a.grace_until = None;
                }
                let payment = a
                    .payment
                    .as_mut()
                    .ok_or_else(|| Error::Failed("the account has no payment block".to_string()))?;
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
                g.grace_until = None;
                restore_group_mailboxes(cfg, store, g).await?;
            }
        }
        Ok(())
    }

    async fn save(&self, store: &Store) -> Result<(), Error> {
        match self {
            BillingTarget::Account(a) => {
                let bytes = serde_json::to_vec_pretty(a).map_err(|source| Error::Json {
                    context: "encode the account",
                    source,
                })?;
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
            BillingTarget::Account(a) => a.notice_address(),
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

async fn load_target(store: &Store, target: &TargetRef) -> Result<Option<BillingTarget>, Error> {
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
) -> Result<Option<TargetRef>, Error> {
    for username in store.list("accounts").await? {
        let account = match store.account(&username).await {
            Ok(account) => account,
            Err(e) => {
                // A corrupt account could own the subscription, so the scan
                // cannot skip it. Report the record and fail this event; the
                // delivery stays queued for the pass after the record is fixed.
                let error = Error::Store(e);
                report_record(cfg, store, journal, "account", &username, &error).await;
                return Err(error);
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
                let error = e;
                report_record(cfg, store, journal, "group", &domain, &error).await;
                return Err(error);
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
) -> Result<Settled, Error> {
    let object = event
        .pointer("/data/object")
        .ok_or_else(|| Error::Failed("the event carries no data.object".to_string()))?;
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
        // Money the platform did not choose, so the operator answers it by
        // hand. The alert names the charge, and the settled line the caller
        // writes carries the same reference as `object`.
        "charge.dispute.created" => {
            charge_notice(
                cfg,
                kind,
                object,
                "decide the member's access by hand; nothing was revoked or refunded here",
            )
            .await
        }
        "charge.refunded" => {
            charge_notice(
                cfg,
                kind,
                object,
                "reconcile the paid-until date by hand if the refund was not one of ours",
            )
            .await
        }
        // Everything else the endpoint is not subscribed to. A verified event of
        // an unknown type is not an error; it is simply not ours.
        _ => Ok(Settled::Ignored),
    }
}

/// One `charge.*` event: tell the operator and settle, because the charge is
/// not ours to move money on or to refuse. The two objects differ. A dispute's
/// object is the dispute, which names its charge; a refund's object is the
/// charge, whose `amount` is the total and whose `amount_refunded` is the money
/// that came back. The processed line records the object's own id either way.
async fn charge_notice(
    cfg: &DrainConfig,
    kind: &str,
    object: &Value,
    todo: &str,
) -> Result<Settled, Error> {
    let text = |name: &str| object.get(name).and_then(Value::as_str);
    let found = if kind == "charge.dispute.created" {
        format!(
            "{kind} for dispute {} on charge {}",
            text("id").unwrap_or("an unnamed dispute"),
            text("charge").unwrap_or("an unnamed charge")
        )
    } else {
        let charge = text("id").unwrap_or("an unnamed charge");
        match object.get("amount_refunded").and_then(Value::as_i64) {
            Some(amount) => format!("{kind} for charge {charge}, {amount} minor units refunded"),
            None => format!("{kind} for charge {charge}"),
        }
    };
    notice::alert(cfg, "stripe", kind, &found, todo).await;
    Ok(Settled::Applied)
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
) -> Result<Option<Account>, Error> {
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
) -> Result<Option<TargetRef>, Error> {
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
) -> Result<(), Error> {
    let stripe = billing.stripe_mut();
    stripe.subscription = Some(subscription.to_string());
    stripe.customer = customer.map(str::to_string);
    billing.save(store).await
}

/// `checkout.session.completed`: the `client_reference_id` is the account's or
/// the group's `KYR-` token, and the subscription and customer are attached to
/// what it indexes. Nothing else happens: `invoice.paid` owns the date, so a
/// first payment extends exactly one year and never two.
async fn checkout_completed(store: &Store, object: &Value) -> Result<Settled, Error> {
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
) -> Result<Settled, Error> {
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
    if !invoice_covers(cfg, object, &billing)? {
        // A zero-amount invoice, one in another currency, or one below the
        // target's year is not a payment for this account or body. The member
        // may still have been charged, so the operator is told before the event
        // is settled: the date does not move, no ledger line opens, and the
        // account stays where it was.
        let currency = object
            .get("currency")
            .and_then(Value::as_str)
            .unwrap_or("none");
        let paid = object
            .get("amount_paid")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let (field, price) = billing.price(cfg);
        notice::alert(
            cfg,
            "stripe",
            "invoice.paid",
            &format!(
                "invoice {invoice} for {} paid {paid} minor units in {currency}; the configured {field} is {price}, so no year was added",
                billing.label()
            ),
            "check the member's payment and access by hand; the invoice was settled and no date was extended",
        )
        .await;
        billing.save(store).await?;
        return Ok(Settled::Applied);
    }
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
    let date = kyriakon_control_core::payments::billing::extend_paid_until(
        &received,
        billing.paid_until(),
    )?;
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

/// Whether a paid invoice is the target's year in pounds. The invoice's own
/// currency and `amount_paid` decide: a Payment Link can be substituted with
/// another target's token, and a zero-amount invoice is still an `invoice.paid`.
/// Both sides are integer pence, so no float rounding decides a year's access.
fn invoice_covers(
    cfg: &DrainConfig,
    object: &Value,
    billing: &BillingTarget,
) -> Result<bool, Error> {
    if object.get("currency").and_then(Value::as_str) != Some("gbp") {
        return Ok(false);
    }
    let (field, price) = billing.price(cfg);
    let price = util::pence(price)
        .map_err(|e| Error::context(format!("the drain's configured {field}"), e))?;
    if price <= 0 {
        return Err(Error::Failed(format!(
            "the drain's configured {field} must be more than zero"
        )));
    }
    let paid = object
        .get("amount_paid")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    Ok(paid >= price)
}

/// What a paid invoice says it paid, in pounds, and the day it was paid. The
/// ledger's amount and date must come from the processor's object rather than
/// the configured price and the drain's clock: a discount, a price change, or
/// an event applied after the tax-year boundary would otherwise be recorded
/// wrong. A missing amount or timestamp is an error, which leaves the event for
/// the next pass rather than writing a guess.
fn invoice_money(object: &Value) -> Result<(String, String), Error> {
    let amount = object
        .get("amount_paid")
        .and_then(Value::as_i64)
        .ok_or_else(|| Error::Failed("the paid invoice carries no amount_paid".to_string()))?;
    let paid = object
        .pointer("/status_transitions/paid_at")
        .and_then(Value::as_i64)
        .or_else(|| object.get("created").and_then(Value::as_i64))
        .ok_or_else(|| Error::Failed("the paid invoice carries no paid timestamp".to_string()))?;
    let when = OffsetDateTime::from_unix_timestamp(paid)
        .map_err(|e| Error::context("the invoice's paid timestamp cannot be read", e))?;
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
) -> Result<(), Error> {
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
async fn retrieve_subscription(cfg: &DrainConfig, subscription: &str) -> Result<Value, Error> {
    if !subscription
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(Error::Failed(format!(
            "the subscription id {subscription:?} is not an id"
        )));
    }
    let out = spawn_script(
        cfg,
        "stripe-api.sh",
        &["subscription", subscription, &cfg.stripe_api_key],
    )
    .await?;
    if !out.status.success() {
        return Err(Error::from(script_error(cfg, "stripe-api.sh", &out)));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| {
        Error::Failed(format!(
            "stripe-api.sh did not answer with a subscription: {e}"
        ))
    })
}

/// The Checkout Session a subscription came from, read through the same script.
/// The list is filtered by the subscription and bounded to one; an empty list or
/// an unreachable API is an error, so the event stays for the next pass.
async fn retrieve_session(cfg: &DrainConfig, subscription: &str) -> Result<Value, Error> {
    if !subscription
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(Error::Failed(format!(
            "the subscription id {subscription:?} is not an id"
        )));
    }
    let out = spawn_script(
        cfg,
        "stripe-api.sh",
        &["session", subscription, &cfg.stripe_api_key],
    )
    .await?;
    if !out.status.success() {
        return Err(Error::from(script_error(cfg, "stripe-api.sh", &out)));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| {
        Error::Failed(format!(
            "stripe-api.sh did not answer with a checkout session: {e}"
        ))
    })
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
) -> Result<Settled, Error> {
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
) -> Result<Settled, Error> {
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
) -> Result<Settled, Error> {
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
) -> Result<Settled, Error> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The event id becomes a filename under `verified/`, so a body that names
    /// a path is refused before the join. Stripe's ids are `evt_` and
    /// alphanumerics.
    #[test]
    fn an_event_id_is_a_name_not_a_path() {
        assert!(event_id_shape("evt_1Nqk9abcdef_XYZ"));
        for id in [
            "",
            "evt_",
            "evt_a/b",
            "evt_..",
            "../evt_a",
            "cs_example",
            "evt_a.b",
            "evt_a b",
            "evt_\u{00e9}",
        ] {
            assert!(!event_id_shape(id), "{id:?} was accepted as an event id");
        }
    }
}
