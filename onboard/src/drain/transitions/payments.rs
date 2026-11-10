//! Money in: a manual credit, a held payment joined to its token, a refund and
//! the reconcile pair, with the ledger reads and writes each one needs.
//!
//! The ledger is append-only and the paid-until date it moves is the account
//! record's; every verb here returns a [`Settlement`](super::Settlement) and
//! leaves the line, the after-line work and the remove to the seam.

use super::boxrun::run_script;
use super::groups::{group_record, write_account_record, write_group_record};
use super::lifecycle::dns_contact;
use super::{AfterLine, Settlement};
use crate::config::DrainConfig;
use crate::flow::validate;
use crate::intent::{
    AttributeIntent, CreditIntent, RefundIntent, ReturnIntent, CREDIT_RAILS, REFUND_RAILS,
};
use crate::mail::notice;
use crate::payments::ledger::Ledger;
use crate::payments::ledger::LedgerLine;
use crate::payments::ledger::RefundTail;
use crate::store::journal::Journal;
use crate::store::{
    self, Account, ApplicationRef, CreditProgress, GroupRecord, JournalLine, Monero, Payment,
    Store, TokenRecord,
};
use crate::util;
use serde_json::json;
use serde_json::Value;
use time::OffsetDateTime;

/// The note a credit's applied line carries: the override's reason when the
/// credit used one.
fn override_note(reason: Option<&str>) -> Option<String> {
    reason.map(|reason| format!("24-month override: {reason}"))
}

/// Apply a manual credit: one payment, the one date arithmetic, one ledger line.
///
/// The token index joins the token to a username and nothing else is trusted
/// from the intent's shape: the rail, the amount, the date and the token are
/// revalidated here because `intents/` belongs to the unprivileged half. The
/// ledger's own `intent` field is the dedup key, so a replay writes nothing and
/// extends nothing.
///
/// A credit with no token is the one case with nothing to join: it is held in
/// `ledger/unattributed.jsonl` rather than refused, because the money is real
/// and a member may still be found for it.
pub async fn credit(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: CreditIntent,
) -> Result<Settlement, String> {
    // The ledger line is the settlement marker, and a credit settles in one of
    // two: a payment joined to a token, or a held line in the unattributed
    // queue. A second arrival of the same intent finds its line and stops before
    // any other check, so a replay cannot refuse itself on a rule it already met.
    if Ledger::open(store).has_intent(&intent.id).await?
        || held_has_intent(store, &intent.id).await?
    {
        return Ok(Settlement::applied(
            ApplicationRef::default(),
            Some("replayed: the ledger already holds this credit".to_string()),
        ));
    }
    // A refusal is recorded once; the intent is left in place, as every other
    // refused intent is, and a new intent is the way to change it.
    let amount = match credit_fields(&intent) {
        Ok(amount) => amount,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    let received = util::parse_date(&intent.received).expect("the date was validated above");

    // A payment with no token cannot be joined to an account, so it is held
    // until `reconcile` joins it or closes it.
    if intent.token.is_empty() {
        return hold(store, &intent, amount, received).await;
    }

    // The token index says which of the two the money pays for: one account, or
    // the one group a body holds. A group's credit writes the one date every
    // mailbox in it shares.
    let join = match token_join(store, &intent.token).await {
        Ok(join) => join,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    if let Some(domain) = join.as_ref().and_then(|j| j.group.clone()) {
        return group_credit(cfg, store, journal, &intent, &domain, None).await;
    }

    let (username, account, payment) = match resolve_payment(store, &intent.token).await {
        Ok(found) => found,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    let app = PaymentApplication {
        intent: &intent,
        username: &username,
        account,
        payment,
        amount,
        received,
        attributed_item: None,
    };
    apply_payment(cfg, store, journal, app).await
}

/// The fields a credit's money arrives with, revalidated here because `intents/`
/// belongs to the unprivileged half. Returns the amount in pence. A token is
/// checked only when there is one: a payment with none is held, not refused.
fn credit_fields(intent: &CreditIntent) -> Result<i64, String> {
    if !CREDIT_RAILS.contains(&intent.rail.as_str()) {
        return Err("the credit names a rail that is not cash, cash-hand or monero".to_string());
    }
    if !intent.token.is_empty() && !store::is_payment_token(&intent.token) {
        return Err("the credit's token is not the shape of a payment token".to_string());
    }
    let Some(received) = util::parse_date(&intent.received) else {
        return Err("the credit's received date is not YYYY-MM-DD".to_string());
    };
    // A hand-written intent can carry any date. Two years ahead is the ceiling
    // the paid-until arithmetic measures from, and a wake at this boundary is
    // the difference between a refused intent and a pass that panics and starves
    // every intent behind it.
    if util::received_beyond_window(received, OffsetDateTime::now_utc().date()) {
        return Err(format!(
            "the credit's received date {} is more than two years ahead",
            intent.received
        ));
    }
    if !valid_txid(intent.txid.as_deref()) {
        return Err("the credit's transaction id is not 64 hexadecimal characters".to_string());
    }
    if !valid_xmr(intent.amount_xmr.as_deref()) {
        return Err("the credit's XMR amount is not a decimal amount".to_string());
    }
    match util::pence(&intent.amount_gbp) {
        Ok(amount) if amount > 0 => Ok(amount),
        Ok(_) => Err("the credit's amount must be more than zero".to_string()),
        Err(e) => Err(e),
    }
}

/// The token index entry a payment token names, when the entry is this token's.
/// The index is the only join, so a token that is not in it resolves to nothing.
pub(super) async fn token_join(store: &Store, token: &str) -> Result<Option<TokenRecord>, String> {
    let Some(join) = store.token(token).await? else {
        return Ok(None);
    };
    if join.token != token {
        return Err("the token record does not name this token".to_string());
    }
    Ok(Some(join))
}

/// The account a payment token names, through `tokens/<token>.json` and its
/// account record. The token index is the only join, so a token that resolves to
/// nothing is refused rather than made into an account. A group's token names no
/// single account, so the paths that only know about accounts refuse it here.
pub(super) async fn resolve_payment(
    store: &Store,
    token: &str,
) -> Result<(String, Account, Payment), String> {
    let Some(join) = token_join(store, token).await? else {
        return Err(
            "the token is not in the index; an unattributed payment belongs in the queue"
                .to_string(),
        );
    };
    if join.group.is_some() {
        return Err(
            "the token belongs to a group, whose payment is held on the group's record".to_string(),
        );
    }
    if validate::username_shape(&join.username).is_some() {
        return Err("the token record does not name this token".to_string());
    }
    let username = join.username;
    let Some(account) = store.account(&username).await? else {
        return Err("the token resolves to an account that is gone".to_string());
    };
    let Some(payment) = account.payment_state() else {
        return Err("the account carries no payment block".to_string());
    };
    if payment.token_ref.as_deref() != Some(token) {
        return Err("the token is not the one the account's payment block holds".to_string());
    }
    Ok((username, account, payment))
}

/// One payment about to be applied to an account: the values a manual credit and
/// a `reconcile attribute` both hold once the token has resolved. Passed as one
/// value, so the two callers cannot disagree about any of them.
struct PaymentApplication<'a> {
    intent: &'a CreditIntent,
    username: &'a str,
    account: Account,
    payment: Payment,
    amount: i64,
    received: time::Date,
    /// The held item this payment came from, when the transition is a
    /// `reconcile attribute`. Its own txid is the one in the queue, so that
    /// item's held line is not a second sighting of the payment.
    attributed_item: Option<&'a str>,
}

/// What a credit does to an account: the ceiling, the arithmetic, the account
/// write, the payment copy, the ledger line and the receipt. Shared by the
/// console's credit and `reconcile attribute`, so a held payment and a direct
/// one are never applied differently.
async fn apply_payment(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    app: PaymentApplication<'_>,
) -> Result<Settlement, String> {
    let PaymentApplication {
        intent,
        username,
        mut account,
        mut payment,
        amount,
        received,
        attributed_item,
    } = app;

    // A pass that journaled `applying` and wrote the account but crashed before
    // the ledger append is finished here, from the values it recorded then. The
    // account is the witness: its paid-until date (or, for a shortfall, its
    // balance) is the one this credit computed, so nothing is extended again and
    // no second notice is sent.
    let progress = journal.credit_progress(&intent.id);
    let written = progress.as_ref().is_some_and(|p| {
        if p.paid {
            payment.paid_until.as_deref() == p.paid_until_after.as_deref()
        } else {
            payment.balance_gbp.as_deref() == p.balance_gbp.as_deref()
        }
    });
    if let Some(progress) = progress.as_ref().filter(|_| written) {
        if !Ledger::open(store).has_intent(&intent.id).await? {
            append_credit_ledger(
                store,
                intent,
                payment.monero.as_ref(),
                &util::date_string(received),
                &util::gbp(amount),
                &progress.applied_gbp,
                progress.paid_until_after.as_deref(),
            )
            .await?;
        }
        // A crash between the account write and its copies leaves the status
        // page behind; the account is the truth now, so rewrite them from it.
        write_payment_copy(store, username, &payment).await?;
        return Ok(Settlement::applied(
            ApplicationRef::account(username.to_string()),
            override_note(intent.override_reason.as_deref()),
        ));
    }

    let before = match payment.paid_until.as_deref() {
        Some(stamp) => match util::parse_date(stamp) {
            Some(date) => Some(date),
            None => {
                return Ok(Settlement::refused(
                    "the account's paid-until date cannot be read",
                ))
            }
        },
        None => None,
    };
    let Some(until) = util::paid_until_after(received, before) else {
        return Ok(Settlement::refused(
            "the account's paid-until date has no year in the calendar",
        ));
    };
    let override_reason = intent
        .override_reason
        .as_deref()
        .filter(|r| !r.trim().is_empty());
    if util::credit_ceiling(received).is_some_and(|ceiling| until > ceiling)
        && override_reason.is_none()
    {
        return Ok(Settlement::refused("the credit would put paid_until more than 24 months past --received; give --override <reason> to mean it"));
    }

    let price = util::pence(&cfg.price_gbp)
        .map_err(|e| format!("the drain's configured price_gbp: {e}"))?;
    if price <= 0 {
        return Err("the drain's configured price_gbp must be more than zero".to_string());
    }
    let balance = match payment.balance_gbp.as_deref() {
        Some(text) => match util::pence(text) {
            Ok(pence) => pence,
            Err(e) => {
                return Ok(Settlement::refused(format!(
                    "the account's balance cannot be read: {e}"
                )))
            }
        },
        None => 0,
    };
    let applied = credit_money(price, balance, amount);

    // A transaction already in the ledger is the same payment seen again. It
    // must never extend a date, whatever else the intent says. The queue is
    // checked too: a payment held with no token and then credited with one is
    // one payment, not two, unless this transition is attributing that very
    // held item.
    if let Some(txid) = intent.txid.as_deref() {
        if let Some((seq, received_on)) = ledger_txid(store, txid).await? {
            return Ok(Settlement::refused(format!(
                "transaction {txid} was already credited on {received_on} at ledger seq {seq}"
            )));
        }
        if let Some((id, received_on)) = held_txid(store, txid).await? {
            if attributed_item != Some(id.as_str()) {
                return Ok(Settlement::refused(format!(
                        "transaction {txid} is already held as {id}, received on {received_on}; attribute that item instead"
                    )));
            }
        }
    }
    // A token already credited is a renewal, and the second credit needs the
    // operator to have said so: for cash the second envelope may be a
    // stranger's with a copied token. Held money is never a renewal, because it
    // was never joined to the token in the first place.
    if let (Some(paid_until), false) = (payment.paid_until.as_deref(), intent.confirm_double) {
        let problem = if intent.kind == "credit" {
            format!(
                "this token was already credited until {paid_until}; give --confirm-double for a renewal"
            )
        } else {
            format!(
                "the token was already credited until {paid_until}; record a renewal with `credit --confirm-double`"
            )
        };
        return Ok(Settlement::refused(&problem));
    }

    let until_text = util::date_string(until);
    let paid_until_after = if applied.paid {
        Some(until_text.clone())
    } else {
        before.map(util::date_string)
    };
    let balance_text = (applied.balance > 0).then(|| util::gbp(applied.balance));

    // The values the account write is about to set, recorded before the write so
    // a crash leaves enough to finish the ledger line.
    if progress.is_none() {
        journal_credit_applying(
            store,
            journal,
            &cfg.release,
            intent,
            username,
            &CreditProgress {
                paid: applied.paid,
                paid_until_after: paid_until_after.clone(),
                applied_gbp: util::gbp(applied.applied),
                balance_gbp: balance_text.clone(),
            },
        )
        .await?;
    }

    // A payment after a lapse restores access from the day it is recorded. The
    // restore runs before the record says active: a failure here leaves the
    // account lapsed, and the retry repeats an idempotent script rather than
    // reporting an active account whose sending and pushing are still stopped.
    if applied.paid && account.state == "lapsed" {
        run_script(cfg, "lapse-user.sh", &["--restore", username]).await?;
    }
    payment.rail = Some(intent.rail.clone());
    payment.balance_gbp = balance_text;
    if applied.paid {
        payment.paid_until = Some(until_text);
        // The window closes with the credit; a null paid-until date is what
        // shows the token, so setting the date is also what hides it.
        if let Some(window) = payment.window.as_mut() {
            window.state = "paid".to_string();
        }
        // Only a lapsed account is restored. A closing or suspended account
        // keeps its state: the payment is recorded, and the decision that put
        // it there is not the payment sweep's to overturn.
        if account.state == "lapsed" || account.state == "active" {
            account.state = "active".to_string();
            account.grace_until = None;
        }
    }
    account.payment = Some(payment.clone());
    let bytes = serde_json::to_vec_pretty(&account)
        .map_err(|e| format!("cannot encode the account: {e}"))?;
    write_account_record(store, username, &bytes).await?;
    write_payment_copy(store, username, &payment).await?;
    append_credit_ledger(
        store,
        intent,
        payment.monero.as_ref(),
        &util::date_string(received),
        &util::gbp(amount),
        &util::gbp(applied.applied),
        paid_until_after.as_deref(),
    )
    .await?;

    // The receipt is for every payment, including a shortfall: the money
    // arrived, and the account page quotes what still does.
    let to = account
        .outside_address
        .clone()
        .unwrap_or_else(|| format!("{username}@kyriakon.net"));
    let (subject, body) = if applied.paid {
        let paid = util::date_string(until);
        (
            format!("Your payment to kyriakon.net was received (paid until {paid})"),
            format!(
                "We have recorded a payment of GBP {} on {} by {}.\n\n\
                 Your account is paid until {}.\n",
                util::gbp(amount),
                util::date_string(received),
                intent.rail,
                paid,
            ),
        )
    } else {
        let remaining = util::gbp(price - applied.balance);
        (
            format!("Your part payment to kyriakon.net was received (GBP {remaining} remains)"),
            format!(
                "We have recorded a payment of GBP {} on {} by {}.\n\n\
                 GBP {} remains due for the year, and your account page quotes it.\n",
                util::gbp(amount),
                util::date_string(received),
                intent.rail,
                remaining,
            ),
        )
    };
    notice::send_account_notice(
        cfg,
        store,
        username,
        "prepaid.receipt",
        &subject,
        &to,
        &body,
    )
    .await?;

    Ok(Settlement::applied(
        ApplicationRef::account(username.to_string()),
        override_note(override_reason),
    ))
}

/// Apply a prepaid credit to the group its token names. The arithmetic, the
/// ceiling, the double-credit rule, the transaction check and the ledger line
/// are the account path's; what differs is where the one date is written and
/// who is told. One credit sets one date on the group, restores every mailbox in
/// it that lapsed, and sends one receipt for the body.
#[allow(clippy::too_many_arguments)]
async fn group_credit(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: &CreditIntent,
    domain: &str,
    attributed_item: Option<&str>,
) -> Result<Settlement, String> {
    let amount = match credit_fields(intent) {
        Ok(amount) => amount,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    let received = util::parse_date(&intent.received).expect("the date was validated above");
    if let Some(why) = validate::domain(domain) {
        return Err(format!("the token's group domain {domain:?}: {why}"));
    }
    let Some(mut group) = group_record(store, domain).await? else {
        return Ok(Settlement::refused(
            "the token resolves to a group that is gone",
        ));
    };
    if group.payment.no_charge {
        return Ok(Settlement::refused(
            "the group was approved without charge, so it has no payment to record",
        ));
    }
    if group.payment.token_ref.as_deref() != Some(intent.token.as_str()) {
        return Ok(Settlement::refused(
            "the token is not the one the group's payment block holds",
        ));
    }

    // A pass that journaled `applying` and wrote the group but crashed before
    // the ledger append is finished here. The group's date is the witness, so
    // nothing is extended twice and no second receipt is sent.
    let progress = journal.credit_progress(&intent.id);
    let written = progress.as_ref().is_some_and(|p| {
        p.paid && group.payment.paid_until.as_deref() == p.paid_until_after.as_deref()
    });
    if let Some(progress) = progress.as_ref().filter(|_| written) {
        if !Ledger::open(store).has_intent(&intent.id).await? {
            append_credit_ledger(
                store,
                intent,
                None,
                &util::date_string(received),
                &util::gbp(amount),
                &progress.applied_gbp,
                progress.paid_until_after.as_deref(),
            )
            .await?;
        }
        return Ok(Settlement::applied(
            ApplicationRef::account(group.site_owner.clone()),
            override_note(intent.override_reason.as_deref()),
        ));
    }

    let before = match group.payment.paid_until.as_deref() {
        Some(stamp) => match util::parse_date(stamp) {
            Some(date) => Some(date),
            None => {
                return Ok(Settlement::refused(
                    "the group's paid-until date cannot be read",
                ))
            }
        },
        None => None,
    };
    let Some(until) = util::paid_until_after(received, before) else {
        return Ok(Settlement::refused(
            "the group's paid-until date has no year in the calendar",
        ));
    };
    let override_reason = intent
        .override_reason
        .as_deref()
        .filter(|r| !r.trim().is_empty());
    if util::credit_ceiling(received).is_some_and(|ceiling| until > ceiling)
        && override_reason.is_none()
    {
        return Ok(Settlement::refused("the credit would put the group's paid_until more than 24 months past --received; give --override <reason> to mean it"));
    }
    let price = util::pence(&cfg.group_price_gbp)
        .map_err(|e| format!("the drain's configured group_price_gbp: {e}"))?;
    if price <= 0 {
        return Err("the drain's configured group_price_gbp must be more than zero".to_string());
    }
    // The fee covers the whole group, so the year is one payment and the group
    // holds no balance to carry a shortfall or an excess into.
    let money = credit_money(price, 0, amount);
    if !money.paid {
        return Ok(Settlement::refused(format!(
            "a group's year is one payment of GBP {}; GBP {} is not enough",
            util::gbp(price),
            util::gbp(amount)
        )));
    }
    if money.balance > 0 {
        return Ok(Settlement::refused(format!(
            "a group's year is one payment of GBP {}; GBP {} is more than the fee",
            util::gbp(price),
            util::gbp(amount)
        )));
    }

    // A transaction already in the ledger is the same payment seen again, and a
    // token already credited is a renewal the operator must have meant.
    if let Some(txid) = intent.txid.as_deref() {
        if let Some((seq, received_on)) = ledger_txid(store, txid).await? {
            return Ok(Settlement::refused(format!(
                "transaction {txid} was already credited on {received_on} at ledger seq {seq}"
            )));
        }
        if let Some((id, received_on)) = held_txid(store, txid).await? {
            // The item this transition is attributing is not a second sighting
            // of the payment, exactly as on the account path.
            if attributed_item != Some(id.as_str()) {
                return Ok(Settlement::refused(format!(
                        "transaction {txid} is already held as {id}, received on {received_on}; attribute that item instead"
                    )));
            }
        }
    }
    if let Some(paid_until) = group.payment.paid_until.as_deref() {
        if !intent.confirm_double {
            return Ok(Settlement::refused(format!(
                    "the group's token was already credited until {paid_until}; give --confirm-double for a renewal"
                )));
        }
    }

    let until_text = util::date_string(until);
    let applied = util::gbp(money.applied);
    journal_credit_applying(
        store,
        journal,
        &cfg.release,
        intent,
        &group.site_owner,
        &CreditProgress {
            paid: true,
            paid_until_after: Some(until_text.clone()),
            applied_gbp: applied.clone(),
            balance_gbp: None,
        },
    )
    .await?;

    // A payment after a lapse restores every mailbox in the group. A closing or
    // suspended state is a decision of its own, and the payment sweep does not
    // overturn it.
    restore_group_mailboxes(cfg, store, &group).await?;
    group.payment.paid_until = Some(until_text.clone());
    group.payment.rail = intent.rail.clone();
    if let Some(window) = group.payment.window.as_mut() {
        window.state = "paid".to_string();
    }
    write_group_record(store, &group).await?;
    append_credit_ledger(
        store,
        intent,
        None,
        &util::date_string(received),
        &util::gbp(amount),
        &applied,
        Some(&until_text),
    )
    .await?;

    // One receipt for the body, on the address its application gave. The
    // ledger line is keyed by the group's token and holds no username, so the
    // row stops naming the body once the group is gone.
    let to = dns_contact(store, &group).await?;
    let subject = format!("Your payment to kyriakon.net was received (paid until {until_text})");
    let body = format!(
        "We have recorded a payment of GBP {} on {} by {} for {}.\n\n\
         The whole group is paid until {until_text}, and every mailbox in it shares that date.\n",
        util::gbp(amount),
        util::date_string(received),
        intent.rail,
        group.domain,
    );
    notice::send_account_notice(
        cfg,
        store,
        &group.site_owner,
        "group.receipt",
        &subject,
        &to,
        &body,
    )
    .await?;
    Ok(Settlement::applied(
        ApplicationRef::account(group.site_owner.clone()),
        override_note(override_reason),
    ))
}

/// Bring back every mailbox in a group that lapsed with it: the group lapsed as
/// one and comes back as one, so a prepaid credit and a card renewal restore the
/// same set through the same steps.
pub(super) async fn restore_group_mailboxes(
    cfg: &DrainConfig,
    store: &Store,
    group: &GroupRecord,
) -> Result<(), String> {
    for mailbox in &group.accounts {
        let Some(mut account) = store.account(mailbox).await? else {
            continue;
        };
        if account.state != "lapsed" {
            continue;
        }
        run_script(cfg, "lapse-user.sh", &["--restore", mailbox]).await?;
        account.state = "active".to_string();
        account.grace_until = None;
        let bytes = serde_json::to_vec_pretty(&account)
            .map_err(|e| format!("cannot encode the account: {e}"))?;
        write_account_record(store, mailbox, &bytes).await?;
    }
    Ok(())
}

/// The payment a refund reverses: the token's most recent `kind == "payment"`
/// line. `seq`, the rail and the amount come from the ledger, never from the
/// intent, so a refund cannot invent a payment to reverse.
struct PaymentLine {
    seq: u64,
    rail: String,
    amount: i64,
    amount_xmr: Option<String>,
    paid_until_after: Option<String>,
}

async fn last_payment_line(store: &Store, token: &str) -> Result<Option<PaymentLine>, String> {
    let Some(line) = Ledger::open(store).last_payment(token).await? else {
        return Ok(None);
    };
    let amount = line
        .amount_gbp
        .as_deref()
        .ok_or("a payment line carries no amount")?;
    Ok(Some(PaymentLine {
        seq: line.seq,
        rail: line.rail,
        amount: util::pence(amount)
            .map_err(|e| format!("the payment line's amount cannot be read: {e}"))?,
        amount_xmr: line.amount_xmr,
        paid_until_after: line.paid_until_after,
    }))
}

/// Refund one payment, or settle a refund already recorded. The console signs
/// every field, and `Intent::verify` checks the signature before anything else
/// because `intents/` belongs to the unprivileged half.
///
/// The refund form appends one negative line naming the `seq` it reverses and,
/// with `--close`, sets the account closing. The settlement form rewrites the
/// newest unsettled refund line under the ledger's lock. The ledger's own
/// `intent` field is the dedup key for a refund, and `settled_intent` for a
/// settlement, so a replay writes nothing.
pub async fn refund(
    cfg: &DrainConfig,
    store: &Store,
    intent: RefundIntent,
) -> Result<Settlement, String> {
    let amount_text = intent.amount_gbp.as_deref().unwrap_or("");
    let rail = intent.rail.as_deref().unwrap_or("");
    let reason = intent.reason.as_deref().unwrap_or("");
    let settled_text = intent.settled_on.as_deref().unwrap_or("");
    if !store::is_payment_token(&intent.token) {
        return Ok(Settlement::refused(
            "the refund's token is not the shape of a payment token",
        ));
    }

    // The settlement form. It never writes a line of its own, so its dedup is
    // the `settled_intent` it left on the refund line rather than `intent`.
    if !settled_text.is_empty() {
        if intent.amount_gbp.is_some()
            || intent.rail.is_some()
            || intent.reason.is_some()
            || intent.close
            || intent.excess
            || intent.rate.is_some()
        {
            return Ok(Settlement::refused(
                "a settlement names only --settled and the account's token",
            ));
        }
        if util::parse_date(settled_text).is_none() {
            return Ok(Settlement::refused(
                "the refund's settled date is not YYYY-MM-DD",
            ));
        }
        if Ledger::open(store).settled_by(&intent.id).await? {
            return Ok(Settlement::applied(
                ApplicationRef::default(),
                Some("replayed: the ledger already records this settlement".to_string()),
            ));
        }
        return settle_refund(store, &intent, settled_text).await;
    }

    // The ledger line is the settlement marker: a second arrival of the same
    // intent finds it and stops before any check it already met.
    if Ledger::open(store).has_intent(&intent.id).await? {
        return Ok(Settlement::applied(
            ApplicationRef::default(),
            Some("replayed: the ledger already holds this refund".to_string()),
        ));
    }

    let problem = if !REFUND_RAILS.contains(&rail) {
        Some("the refund names a rail that is not card, cash, cash-hand or monero")
    } else if intent.close == intent.excess {
        Some("the refund needs exactly one of --close or --excess")
    } else if reason.trim().is_empty() {
        Some("the refund's reason is empty")
    } else if intent.rate.is_some() && rail != "monero" {
        Some("a --rate is only a monero refund paid in sterling")
    } else {
        None
    };
    if let Some(problem) = problem {
        return Ok(Settlement::refused(problem));
    }
    let amount = match util::pence(amount_text) {
        Ok(a) if a > 0 => a,
        Ok(_) => {
            return Ok(Settlement::refused(
                "the refund's amount must be more than zero",
            ))
        }
        Err(e) => return Ok(Settlement::refused(&e)),
    };
    let rate = match intent.rate.as_deref() {
        None => None,
        Some(text) => match util::pence(text) {
            Ok(p) if p > 0 => Some(util::gbp(p)),
            Ok(_) => {
                return Ok(Settlement::refused(
                    "the refund's rate must be more than zero",
                ))
            }
            Err(e) => return Ok(Settlement::refused(&e)),
        },
    };

    let original = match last_payment_line(store, &intent.token).await {
        Ok(Some(line)) => line,
        Ok(None) => {
            return Ok(Settlement::refused(
                "the token has no payment line for a refund to reverse",
            ))
        }
        Err(e) => return Ok(Settlement::refused(&e)),
    };
    if rail != original.rail {
        return Ok(Settlement::refused(format!(
            "the payment arrived by {} and a refund never leaves on another rail",
            original.rail
        )));
    }
    if amount > original.amount {
        return Ok(Settlement::refused(format!(
            "the refund is GBP {}, more than the GBP {} that arrived at ledger seq {}",
            util::gbp(amount),
            util::gbp(original.amount),
            original.seq
        )));
    }
    if intent.close && amount != original.amount {
        return Ok(Settlement::refused(format!(
            "a --close refund must be the full GBP {} that arrived at ledger seq {}",
            util::gbp(original.amount),
            original.seq
        )));
    }
    // The token index is the only join, through the same helper the credit
    // path uses, so a refund and a credit cannot disagree about whose token it
    // is. A group's token names the group's one payment, which this path
    // reverses the same way with one less account to write.
    let join = match token_join(store, &intent.token).await {
        Ok(join) => join,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    if let Some(domain) = join.as_ref().and_then(|j| j.group.clone()) {
        return refund_group(
            cfg,
            store,
            &intent,
            &domain,
            rail,
            amount,
            reason,
            rate.as_deref(),
            &original,
        )
        .await;
    }
    let (username, mut account, mut payment) = match resolve_payment(store, &intent.token).await {
        Ok(found) => found,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };

    // An excess refund gives back held overpayment, so whatever it takes has
    // to leave the balance too. The sum check caps the refund at the payment; a
    // duplicate payment that bought a year has no balance, and this leaves that
    // year alone as the spec says.
    let balance = match payment.balance_gbp.as_deref() {
        Some(text) => match util::pence(text) {
            Ok(pence) => pence,
            Err(e) => {
                return Ok(Settlement::refused(format!(
                    "the account's balance cannot be read: {e}"
                )))
            }
        },
        None => 0,
    };
    if let Err(problem) = refund_total(store, &intent.token, &original, amount).await {
        return Ok(Settlement::refused(&problem));
    }

    let received_on = util::filed_at()[..10].to_string();
    let closing_until = util::date_after_days(7);
    let settlement_by = util::date_after_days(14);
    let deducted = format!("-{}", util::gbp(amount));

    // The account write comes before the ledger append: a crash between them
    // leaves a close or a spent balance that a rerun applies again, and the
    // ledger still holds the one line. The other order would leave the money
    // recorded and the account still holding it, which no rerun could see.
    if intent.close || intent.excess {
        if intent.close {
            account.state = "closing".to_string();
            account.closing_until = Some(closing_until);
        }
        if intent.excess {
            let left = (balance - amount).max(0);
            payment.balance_gbp = (left > 0).then(|| util::gbp(left));
        }
        account.payment = Some(payment.clone());
        let bytes = serde_json::to_vec_pretty(&account)
            .map_err(|e| format!("cannot encode the account: {e}"))?;
        write_account_record(store, &username, &bytes).await?;
    }

    let seq = append_refund_ledger(
        store,
        &intent,
        &original,
        rail,
        &deducted,
        reason.trim(),
        rate.as_deref(),
        &received_on,
        payment.paid_until.as_deref(),
    )
    .await?;

    let to = account
        .outside_address
        .clone()
        .unwrap_or_else(|| format!("{username}@kyriakon.net"));
    let (subject, body) = refund_notice(
        rail,
        &util::gbp(amount),
        &received_on,
        &settlement_by,
        rate.as_deref(),
        seq,
    );
    notice::send_account_notice(
        cfg,
        store,
        &username,
        "prepaid.refund",
        &subject,
        &to,
        &body,
    )
    .await?;

    let note = if rail == "card" {
        format!("Stripe Idempotency-Key refund-{seq}")
    } else {
        format!("recorded at ledger seq {seq}")
    };
    let printed = if rail == "card" {
        AfterLine::Print(format!(
            "the Stripe refund's Idempotency-Key is refund-{seq}"
        ))
    } else {
        AfterLine::Nothing
    };
    Ok(Settlement::line(
        "applied",
        ApplicationRef::account(username.clone()),
        Some(note.clone()),
    )
    .with_after(printed))
}

/// Refunds of one payment sum to no more than that payment, whatever their
/// sizes: the per-refund check alone lets two partial refunds overshoot. An
/// identical line is the same refund seen twice.
async fn refund_total(
    store: &Store,
    token: &str,
    original: &PaymentLine,
    amount: i64,
) -> Result<(), String> {
    let deducted = format!("-{}", util::gbp(amount));
    let ledger = Ledger::open(store);
    // A line this cannot read is not zero: counting it as zero would let this
    // refund and the unreadable one together exceed the payment.
    let refunds = ledger.refunded_total(token, original.seq).await?;
    for line in &refunds.lines {
        let on = line.received_on.as_deref().unwrap_or("an earlier date");
        if line.amount_gbp.as_deref() == Some(deducted.as_str()) {
            return Err(format!(
                "an identical refund is already recorded at ledger seq {} on {on}",
                line.seq
            ));
        }
    }
    if refunds.total + amount > original.amount {
        return Err(format!(
            "refunds of ledger seq {} already total GBP {}; another GBP {} would exceed the GBP {} that arrived",
            original.seq,
            util::gbp(refunds.total),
            util::gbp(amount),
            util::gbp(original.amount)
        ));
    }
    Ok(())
}

/// Refund one group payment. The group holds no balance and no closing state,
/// so only `--excess` is meaningful: the negative ledger line reverses the
/// year, and the group's own removal is the transition that ends the domain.
// The fields are the refund's own, resolved by the caller; one list keeps the
// group and account paths' checks identical.
#[allow(clippy::too_many_arguments)]
async fn refund_group(
    cfg: &DrainConfig,
    store: &Store,
    intent: &RefundIntent,
    domain: &str,
    rail: &str,
    amount: i64,
    reason: &str,
    rate: Option<&str>,
    original: &PaymentLine,
) -> Result<Settlement, String> {
    let Some(group) = group_record(store, domain).await? else {
        return Ok(Settlement::refused(
            "the token resolves to a group that is gone",
        ));
    };
    if intent.close {
        return Ok(Settlement::refused("a group has no closing state, so --close cannot cancel one; reverse the payment with --excess, and end the group with `onboardctl group remove <domain>`"));
    }
    if let Err(problem) = refund_total(store, &intent.token, original, amount).await {
        return Ok(Settlement::refused(&problem));
    }
    let received_on = util::filed_at()[..10].to_string();
    let settlement_by = util::date_after_days(14);
    let deducted = format!("-{}", util::gbp(amount));
    let seq = append_refund_ledger(
        store,
        intent,
        original,
        rail,
        &deducted,
        reason.trim(),
        rate,
        &received_on,
        group.payment.paid_until.as_deref(),
    )
    .await?;
    let to = dns_contact(store, &group).await?;
    let (subject, body) = refund_notice(
        rail,
        &util::gbp(amount),
        &received_on,
        &settlement_by,
        rate,
        seq,
    );
    notice::send_account_notice(
        cfg,
        store,
        &group.site_owner,
        "group.refund",
        &subject,
        &to,
        &body,
    )
    .await?;
    let note = if rail == "card" {
        format!("Stripe Idempotency-Key refund-{seq}")
    } else {
        format!("recorded at ledger seq {seq}")
    };
    let printed = if rail == "card" {
        AfterLine::Print(format!(
            "the Stripe refund's Idempotency-Key is refund-{seq}"
        ))
    } else {
        AfterLine::Nothing
    };
    Ok(Settlement::line(
        "applied",
        ApplicationRef::group(group.site_owner.clone(), group.domain.clone()),
        Some(note.clone()),
    )
    .with_after(printed))
}

/// The refund notice: what was refunded, by which rail, and the date reg 34(4)
/// gives to settle it. A cash refund says posted back, and no rail's text names
/// a bank detail: the cash path holds none at all.
fn refund_notice(
    rail: &str,
    amount: &str,
    received_on: &str,
    settlement_by: &str,
    rate: Option<&str>,
    seq: u64,
) -> (String, String) {
    let how = match rail {
        "cash" | "cash-hand" => "posted back in cash, to the address you gave us",
        "card" => "to the card you paid with",
        _ => "in Monero, in the amount recorded on your receipt",
    };
    let price = match (rail, rate) {
        ("monero", Some(rate)) => {
            format!("\nThe rate recorded for this refund is GBP {rate} per XMR.\n")
        }
        _ => String::new(),
    };
    (
        // The notices record dedups on (type, subject), so two refunds of the
        // same amount need the ledger seq to be two notices.
        format!("Your refund from kyriakon.net (GBP {amount}, refund {seq})"),
        format!(
            "We have recorded a refund of GBP {amount} on {received_on}, paid {how}.\n\
             It will be settled by {settlement_by}. Ledger seq {seq}.\n{price}",
        ),
    )
}

/// Append the refund's negative line. The amount is negative in both money
/// fields so a sum over the ledger is the year's takings; the XMR and the basis
/// it was computed on stay visible for a Monero refund.
#[allow(clippy::too_many_arguments)]
async fn append_refund_ledger(
    store: &Store,
    intent: &RefundIntent,
    original: &PaymentLine,
    rail: &str,
    deducted: &str,
    reason: &str,
    rate: Option<&str>,
    received_on: &str,
    paid_until_after: Option<&str>,
) -> Result<u64, String> {
    let refund_basis = match rail {
        "monero" => Some(if rate.is_some() {
            "sterling"
        } else {
            "recorded_xmr"
        }),
        _ => None,
    };
    let mut line = LedgerLine::empty(&intent.token, "refund", rail);
    line.received_on = Some(received_on.to_string());
    line.amount_gbp = Some(deducted.to_string());
    line.applied_gbp = Some(deducted.to_string());
    line.paid_until_after = paid_until_after
        .or(original.paid_until_after.as_deref())
        .map(str::to_string);
    line.amount_xmr = original.amount_xmr.clone();
    line.intent = Some(intent.id.clone());
    line.note = Some(reason.to_string());
    line.refund = Some(RefundTail {
        refund_of: Some(original.seq),
        settled_on: None,
        refund_basis: refund_basis.map(str::to_string),
        rate_refund: rate.map(str::to_string),
    });
    Ledger::open(store).append(line).await
}

/// A settlement rewrites the newest refund line for the token that has no
/// `settled_on`, under the ledger's lock, and nothing else on it. This is the
/// ledger's one non-append write: `--settled` names a line already recorded, and
/// appending a second line would leave two records of one refund.
async fn settle_refund(
    store: &Store,
    intent: &RefundIntent,
    on: &str,
) -> Result<Settlement, String> {
    let settled_on = util::date_string(util::parse_date(on).expect("the date was validated"));
    let Some(seq) = Ledger::open(store)
        .settle_refund(&intent.token, &intent.id, &settled_on)
        .await?
    else {
        return Ok(Settlement::refused(
            "the token has no unsettled refund to record a settlement against",
        ));
    };
    Ok(Settlement::line(
        "applied",
        ApplicationRef::default(),
        Some(format!(
            "refund at ledger seq {seq} settled on {settled_on}"
        )),
    ))
}

/// Hold a credit that names no token: validate it exactly as a credit is
/// validated, dedup it on the intent id and the transaction id, and append one
/// line to the unattributed queue. No account is written, no payment line is
/// appended and no notice is sent, because nothing here has a member yet.
#[allow(clippy::too_many_arguments)]
async fn hold(
    store: &Store,
    intent: &CreditIntent,
    amount: i64,
    received: time::Date,
) -> Result<Settlement, String> {
    if intent.rail == "cash-hand" {
        return Ok(Settlement::refused(
            "cash in hand is credited against a username; give --username",
        ));
    }
    let Some(note) = intent
        .note
        .as_deref()
        .map(str::trim)
        .filter(|note| !note.is_empty())
    else {
        return Ok(Settlement::refused(
            "a payment with no token needs --note so the operator can tell what it is",
        ));
    };
    // A transaction already seen is the same payment, whether it was held or
    // credited: it must never become a second line the operator could join
    // twice. The queue and the ledger are two records of one payment, so both
    // are consulted from either side.
    if let Some(txid) = intent.txid.as_deref() {
        if let Some((seq, received_on)) = ledger_txid(store, txid).await? {
            return Ok(Settlement::refused(format!(
                "transaction {txid} was already credited on {received_on} at ledger seq {seq}"
            )));
        }
        if let Some((id, received_on)) = held_txid(store, txid).await? {
            return Ok(Settlement::refused(format!(
                "transaction {txid} is already held as {id}, received on {received_on}"
            )));
        }
    }
    let line = json!({
        "version": 1,
        "id": store::unattributed_id().await?,
        "kind": "held",
        "state": "held",
        "rail": intent.rail.as_str(),
        "amount_gbp": util::gbp(amount),
        "received_on": util::date_string(received),
        "amount_xmr": intent.amount_xmr.as_deref(),
        "txid": intent.txid.as_deref(),
        "intent": intent.id.as_str(),
        "note": note,
    });
    let encoded =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode the queue: {e}"))?;
    store
        .log(store::UNATTRIBUTED)
        .append(encoded.as_bytes())
        .await?;
    Ok(Settlement::line(
        "applied",
        ApplicationRef::default(),
        Some("held: the payment carries no token".to_string()),
    ))
}

/// Join a held payment to an account: the same arithmetic, account write,
/// payment copy and receipt as a credit, then the one ledger line for the token
/// and the held line marked `attributed`. The held line names the token it went
/// to and never the username, because the ledger outlives the account.
pub async fn reconcile_attribute(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: AttributeIntent,
) -> Result<Settlement, String> {
    if !store::is_unattributed_id(&intent.item) {
        return Ok(Settlement::refused(
            "the held item's id is not the shape of an unattributed payment",
        ));
    }
    if !store::is_payment_token(&intent.token) {
        return Ok(Settlement::refused(
            "the token is not the shape of a payment token",
        ));
    }

    // The payment line is the settlement marker. A replay of the very intent
    // that attributed the item still has to finish marking the held line, if a
    // crash landed between the two writes.
    if Ledger::open(store).has_intent(&intent.id).await? {
        let username = token_join(store, &intent.token)
            .await?
            .map(|join| join.username)
            .unwrap_or_default();
        return Ok(Settlement::applied(
            ApplicationRef::account(username),
            override_note(intent.override_reason.as_deref()),
        ));
    }

    let held = match store
        .held()
        .await?
        .into_iter()
        .find(|line| line.id == intent.item)
    {
        Some(held) => held,
        None => {
            return Ok(Settlement::refused(format!(
                "no held payment with id {}",
                intent.item
            )))
        }
    };
    if held.state != "held" {
        return Ok(Settlement::refused(format!(
            "{} is {}, not held",
            intent.item, held.state
        )));
    }

    // The held line is data the console wrote earlier, so it is revalidated
    // exactly as a credit's fields are. The intent it carries is this intent's
    // id: the payment line and the journal are keyed by the join, not by the
    // hold.
    let payment_intent = CreditIntent {
        id: intent.id.clone(),
        kind: intent.kind.clone(),
        filed_at: intent.filed_at.clone(),
        token: intent.token.clone(),
        rail: held.rail.clone(),
        amount_gbp: held.amount_gbp.clone(),
        received: held.received_on.clone(),
        txid: held.txid.clone(),
        amount_xmr: held.amount_xmr.clone(),
        confirm_double: intent.confirm_double,
        override_reason: intent.override_reason.clone(),
        note: held.note.clone(),
        sig: String::new(),
    };
    let amount = match credit_fields(&payment_intent) {
        Ok(amount) => amount,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    let received =
        util::parse_date(&payment_intent.received).expect("the date was validated above");

    // A group's token takes the held money the same way it takes a direct
    // credit: one date on the group. The ledger line is the settlement marker,
    // so the held item is attributed only once that line exists.
    let join = match token_join(store, &payment_intent.token).await {
        Ok(join) => join,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    if let Some(domain) = join.as_ref().and_then(|j| j.group.clone()) {
        let settled = group_credit(
            cfg,
            store,
            journal,
            &payment_intent,
            &domain,
            Some(&intent.item),
        )
        .await?;
        return Ok(settled);
    }

    let (username, account, payment) = match resolve_payment(store, &payment_intent.token).await {
        Ok(found) => found,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    let app = PaymentApplication {
        intent: &payment_intent,
        username: &username,
        account,
        payment,
        amount,
        received,
        attributed_item: Some(&intent.item),
    };
    apply_payment(cfg, store, journal, app).await
}

/// Close a held payment with the evidence it went back or was kept. No payment
/// line and no notice: no money moved and no account was touched.
pub async fn reconcile_return(store: &Store, intent: ReturnIntent) -> Result<Settlement, String> {
    if !store::is_unattributed_id(&intent.item) {
        return Ok(Settlement::refused(
            "the held item's id is not the shape of an unattributed payment",
        ));
    }
    let note = intent.note.trim();
    if note.is_empty() {
        return Ok(Settlement::refused("the evidence for the return is needed"));
    }
    let state = store
        .held()
        .await?
        .into_iter()
        .find(|line| line.id == intent.item)
        .map(|line| line.state);
    match state.as_deref() {
        None => {
            return Ok(Settlement::refused(format!(
                "no held payment with id {}",
                intent.item
            )))
        }
        Some("held") => {}
        Some(other) => {
            return Ok(Settlement::refused(format!(
                "{} is {other}, not held",
                intent.item
            )))
        }
    }

    let evidence = format!("returned: {note}");
    let item = intent.item.clone();
    rewrite_unattributed(store, &item, |line| {
        if line.state != "held" {
            return Err(format!("{item} is {}, not held", line.state));
        }
        line.state = "returned".to_string();
        line.returned_at = Some(util::filed_at());
        // The original note is kept and the evidence is appended to it: what the
        // operator first wrote down is part of the item's history too.
        line.note = Some(match line.note.take() {
            Some(original) => format!("{original}; {evidence}"),
            None => evidence.clone(),
        });
        Ok(())
    })
    .await?;
    Ok(Settlement::line("applied", ApplicationRef::default(), None))
}

/// Mark one held line attributed to a token. Idempotent for the replay path, and
/// a returned item is refused rather than relabelled.
pub(super) async fn mark_attributed(store: &Store, item: &str, token: &str) -> Result<(), String> {
    let id = item.to_string();
    let token = token.to_string();
    rewrite_unattributed(store, item, move |line| {
        if line.state == "returned" {
            return Err(format!("{id} was returned, so it cannot be attributed"));
        }
        if line.state == "held" {
            line.state = "attributed".to_string();
            line.attributed_at = Some(util::filed_at());
            line.attributed_to = Some(token);
        }
        Ok(())
    })
    .await
}

/// Rewrite one held line under the queue's lock, through `change`.
///
/// The lock is in a file of its own, not on the queue: the rewrite replaces the
/// record by rename, and a lock on the replaced inode would stop guarding the
/// path the moment the rename landed. It is held across the read and the write,
/// so a line the drain appended in between is not dropped.
async fn rewrite_unattributed(
    store: &Store,
    id: &str,
    change: impl FnOnce(&mut store::HeldItem) -> Result<(), String>,
) -> Result<(), String> {
    let _guard = store.log(store::UNATTRIBUTED).lock().await?;
    let mut items = store.held().await?;
    let at = items
        .iter()
        .position(|line| line.id == id)
        .ok_or_else(|| format!("no held payment with id {id}"))?;
    change(&mut items[at])?;
    let mut bytes = String::new();
    for item in &items {
        bytes.push_str(
            &serde_json::to_string(item).map_err(|e| format!("cannot encode the queue: {e}"))?,
        );
        bytes.push('\n');
    }
    store
        .rewrite_log(store::UNATTRIBUTED, bytes.as_bytes())
        .await
}

/// Whether the unattributed queue already holds this intent's line.
async fn held_has_intent(store: &Store, id: &str) -> Result<bool, String> {
    store
        .log(store::UNATTRIBUTED)
        .jsonl_any(|line: &store::HeldItem| line.intent == id)
        .await
}

/// The held line carrying this transaction id, with its id and the date it was
/// received, so a second sighting of one payment can name both.
async fn held_txid(store: &Store, txid: &str) -> Result<Option<(String, String)>, String> {
    Ok(store
        .held()
        .await?
        .into_iter()
        .find(|line| line.txid.as_deref() == Some(txid))
        .map(|line| (line.id, line.received_on)))
}

fn valid_txid(txid: Option<&str>) -> bool {
    match txid {
        None => true,
        Some(t) => t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()),
    }
}

/// An XMR amount is written as a decimal, never a float, with at most the
/// twelve decimal places the coin's atomic unit carries.
fn valid_xmr(amount: Option<&str>) -> bool {
    let Some(amount) = amount else {
        return true;
    };
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    !whole.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && fraction.len() <= 12
        && fraction.bytes().all(|b| b.is_ascii_digit())
}

/// What a credit's money does, in pence. Any amount at or above the price is
/// applied in full and the excess is held. A shortfall within one percent is
/// rounded up to the price, which absorbs the drift and the rounding; a larger
/// shortfall holds everything received and does not move the date, so the
/// remainder stays quoted.
struct CreditMoney {
    applied: i64,
    balance: i64,
    paid: bool,
}

fn credit_money(price: i64, balance: i64, amount: i64) -> CreditMoney {
    let total = balance + amount;
    if total >= price {
        // Anything above the price is held, however small: the band exists for
        // a shortfall, not for money that arrived.
        CreditMoney {
            applied: price,
            balance: total - price,
            paid: true,
        }
    } else if (price - total) as u64 * 100 <= price as u64 {
        // One percent, exactly: a 20.00 quote absorbs 19.80.
        CreditMoney {
            applied: price,
            balance: 0,
            paid: true,
        }
    } else {
        CreditMoney {
            applied: 0,
            balance: total,
            paid: false,
        }
    }
}

/// Journal a credit's `applying` line with what it is about to write, so the
/// ledger line can be finished if the write succeeds and the append does not.
async fn journal_credit_applying(
    store: &Store,
    journal: &Journal,
    release: &str,
    intent: &CreditIntent,
    username: &str,
    progress: &CreditProgress,
) -> Result<(), String> {
    let line = JournalLine {
        version: 1,
        at: util::filed_at(),
        intent: intent.id.clone(),
        kind: intent.kind.clone(),
        release: release.to_string(),
        application: ApplicationRef::account(username.to_string()),
        outcome: "applying".to_string(),
        note: None,
        credit: Some(progress.clone()),
    };
    journal.append(store, &line).await
}

/// The ledger line carrying this transaction id, with the date it was first
/// credited and its `seq`, so a second credit can name both.
async fn ledger_txid(store: &Store, txid: &str) -> Result<Option<(u64, String)>, String> {
    Ok(Ledger::open(store).by_txid(txid).await?.map(|line| {
        (
            line.seq,
            line.received_on
                .unwrap_or_else(|| "an earlier date".to_string()),
        )
    }))
}

/// Rewrite the payment block on the application copy the handler reads, so a
/// status page that has the application still shows the credit rather than the
/// token. The account's copy is rewritten too; the applications copy only when
/// it still exists, because recreating a purged application would undo the
/// purge's own promise.
pub async fn write_payment_copy(
    store: &Store,
    username: &str,
    payment: &Payment,
) -> Result<(), String> {
    let Some(text) = store.account_application_text(username).await? else {
        return Ok(());
    };
    let mut copy: Value = serde_json::from_str(&text)
        .map_err(|e| format!("the application copy does not parse: {e}"))?;
    copy["payment"] = serde_json::to_value(payment)
        .map_err(|e| format!("cannot encode the payment block: {e}"))?;
    let bytes = serde_json::to_vec_pretty(&copy)
        .map_err(|e| format!("cannot encode the application copy: {e}"))?;
    store
        .write_record(&format!("accounts/{username}"), "application.json", &bytes)
        .await?;
    if let Some(token) = copy.get("status_token").and_then(Value::as_str) {
        if store.filed_application_text(token).await?.is_some() {
            let owner = store.dir_owner("applications");
            store
                .write_record_owned("applications", &format!("{token}.json"), &bytes, owner)
                .await?;
        }
    }
    Ok(())
}

/// Append the credit's line, keyed by the token, with no username. A Monero
/// credit carries the rate that produced the window's quote, its source and
/// when it was fetched; every other rail's rate fields stay null. The XMR amount
/// and the transaction id are recorded when the operator gave them.
async fn append_credit_ledger(
    store: &Store,
    intent: &CreditIntent,
    monero: Option<&Monero>,
    received_on: &str,
    amount_gbp: &str,
    applied_gbp: &str,
    paid_until_after: Option<&str>,
) -> Result<(), String> {
    let quoted = monero.filter(|_| intent.rail == "monero");
    let mut line = LedgerLine::empty(&intent.token, "payment", &intent.rail);
    line.received_on = Some(received_on.to_string());
    line.amount_gbp = Some(amount_gbp.to_string());
    line.applied_gbp = Some(applied_gbp.to_string());
    line.paid_until_after = paid_until_after.map(str::to_string);
    line.amount_xmr = intent.amount_xmr.clone();
    line.rate_quoted = quoted.and_then(|m| m.rate_gbp_per_xmr.clone());
    line.rate_source = quoted.and_then(|m| m.rate_source.clone());
    line.rate_at = quoted.and_then(|m| m.rate_at.clone());
    line.txid = intent.txid.clone();
    line.intent = Some(intent.id.clone());
    Ledger::open(store).append(line).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::sign;
    use crate::drain::transitions::test_support::quota_config;
    use crate::drain::transitions::{settle, Disposition, Envelope, RefusalFile};
    use crate::intent::RefundIntent;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn a_credit_applies_the_price_and_holds_the_rest() {
        // Within one percent, either side, is the price itself.
        assert_eq!(
            (
                credit_money(2000, 0, 1980).applied,
                credit_money(2000, 0, 1980).balance
            ),
            (2000, 0)
        );
        assert!(credit_money(2000, 0, 2020).paid);
        // Above it: the price is applied and the excess is held.
        let over = credit_money(2000, 0, 2500);
        assert_eq!((over.applied, over.balance, over.paid), (2000, 500, true));
        // A larger shortfall holds what arrived and moves nothing.
        let short = credit_money(2000, 0, 1979);
        assert_eq!((short.applied, short.balance, short.paid), (0, 1979, false));
        // A held balance is spent before the new money is counted.
        let spends = credit_money(2000, 500, 1500);
        assert_eq!(
            (spends.applied, spends.balance, spends.paid),
            (2000, 0, true)
        );
        let short_still = credit_money(2000, 500, 1000);
        assert_eq!(short_still.balance, 1500);
        assert!(!short_still.paid);
    }

    #[test]
    fn a_signed_credit_payload_covers_the_reason_and_the_fields_before_it() {
        let a = sign::credit_payload(
            "KYR-4F2M-9QH7-XT3B",
            "cash",
            "20.00",
            "2026-10-04",
            None,
            None,
            false,
            Some("posted twice"),
            None,
        );
        let b = sign::credit_payload(
            "KYR-4F2M-9QH7-XT3B",
            "cash",
            "20.00",
            "2026-10-04",
            None,
            None,
            false,
            Some("posted once"),
            None,
        );
        assert_ne!(a, b);
        assert!(a.contains("posted twice"));
        // The note is free text and last, so a note that carries a colon cannot
        // shift the fields before it into agreeing with another intent's.
        let c = sign::credit_payload(
            "",
            "cash",
            "20.00",
            "2026-10-04",
            None,
            None,
            false,
            None,
            Some("no token: envelope in book"),
        );
        assert!(c.contains("no token: envelope in book"));
        assert_ne!(c, a);
    }

    /// Whether the ledger lock can be taken without waiting. `false` means a
    /// descriptor in this process holds it.
    fn ledger_lock_is_free(path: &std::path::Path) -> bool {
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
        else {
            return false;
        };
        let fd = file.as_raw_fd();
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            unsafe { libc::flock(fd, libc::LOCK_UN) };
            true
        } else {
            false
        }
    }

    /// A settlement releases the ledger lock with its write. The journal line
    /// that follows is not part of the ledger, so a second writer must be able
    /// to take the lock while the line is being appended: here the append blocks
    /// on a pipe nobody reads yet, which holds the settlement exactly there.
    #[test]
    fn a_settlement_journals_with_the_ledger_lock_released() {
        use std::ffi::CString;
        use std::io::Read;
        use std::time::{Duration, Instant};

        let dir = std::env::temp_dir().join(format!("onboard-settle-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("store");
        std::fs::create_dir_all(root.join("ledger")).unwrap();
        let root_text = root.to_str().unwrap().to_string();
        let token = "KYR-AAAA-BBBB-CCCC";
        let ledger = root.join("ledger/payments.jsonl");
        std::fs::write(
            &ledger,
            format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "version": 1,
                    "seq": 7,
                    "token": token,
                    "kind": "refund",
                    "rail": "cash",
                    "received_on": "2026-11-04",
                    "amount_gbp": "-5.00",
                    "applied_gbp": "-5.00",
                    "refund_of": 1,
                }))
                .unwrap()
            ),
        )
        .unwrap();
        // The journal is a pipe, so its append waits for a reader: the state of
        // the lock is observable at that point rather than a race. The index is
        // loaded first, while the file is still missing (an empty journal), so
        // the settlement's append is what blocks on the pipe.
        let journal = {
            let store = Store::new_for_test(&root_text);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(Journal::load(&store)).unwrap()
        };
        let journal_path = root.join("journal.jsonl");
        let c_path = CString::new(journal_path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let value = json!({
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "kind": "refund",
            "token": token,
            "settled_on": "2026-11-05",
            "sig": "",
        });
        let intent: RefundIntent = serde_json::from_value(value.clone()).unwrap();
        let thread_dir = dir.clone();
        let settle = std::thread::spawn(move || {
            let cfg = quota_config(&thread_dir);
            let store = Store::new_for_test(&root_text);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(settle(
                &cfg,
                &store,
                &journal,
                "settle.json",
                &Envelope::of(&value, "settle.json", "refund"),
                Disposition::new(AfterLine::Nothing, RefusalFile::Keep),
                settle_refund(&store, &intent, "2026-11-05"),
            ))
        });

        // Wait for the ledger write, which is the step the guard covers.
        let wrote = || {
            std::fs::read_to_string(&ledger)
                .map(|text| text.contains("settled_on"))
                .unwrap_or(false)
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !wrote() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(wrote(), "the settlement never wrote the ledger");

        // The append is now waiting on the pipe. The lock must be free: a
        // retry covers the instant between the write and the guard's drop.
        let lock_path = root.join("ledger/payments.jsonl.lock");
        let mut free = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if ledger_lock_is_free(&lock_path) {
                free = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        // Unblock the append and let the settlement finish either way, so a
        // failure reads as an assertion rather than a hang.
        let read_journal = {
            let journal = journal_path.clone();
            std::thread::spawn(move || {
                let mut text = String::new();
                std::fs::File::open(&journal)
                    .and_then(|mut f| f.read_to_string(&mut text))
                    .map(|_| text)
            })
        };
        let settled = settle.join().unwrap();
        read_journal.join().unwrap().unwrap();

        assert!(
            free,
            "the ledger lock is still held while the settlement journals"
        );
        assert!(settled.is_ok(), "{settled:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A line the settlement cannot read is an error, never a line it skips to
    /// settle an older refund in its place.
    #[tokio::test]
    async fn a_corrupt_ledger_line_is_an_error_on_the_settlement_path() {
        let dir =
            std::env::temp_dir().join(format!("onboard-settle-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ledger")).unwrap();
        let ledger = dir.join("ledger/payments.jsonl");
        let line = json!({
            "version": 1,
            "seq": 7,
            "token": "KYR-AAAA-BBBB-CCCC",
            "kind": "refund",
            "rail": "cash",
            "received_on": "2026-11-04",
            "amount_gbp": "-5.00",
            "refund_of": 1,
        });
        std::fs::write(&ledger, format!("{line}\nnot json\n")).unwrap();
        let store = Store::new_for_test(dir.to_str().unwrap());
        let intent = RefundIntent {
            token: "KYR-AAAA-BBBB-CCCC".to_string(),
            ..Default::default()
        };
        let error = settle_refund(&store, &intent, "2026-11-04")
            .await
            .expect_err("a line that does not parse must fail the settlement");
        assert!(error.contains("line 2 does not parse"), "{error}");
        assert_eq!(
            std::fs::read_to_string(&ledger).unwrap(),
            format!("{line}\nnot json\n")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
