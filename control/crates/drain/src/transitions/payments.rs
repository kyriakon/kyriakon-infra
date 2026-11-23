//! Money in: a manual credit, a held payment joined to its token, a refund and
//! the reconcile pair, with the ledger reads and writes each one needs.
//!
//! The ledger is append-only and the paid-until date it moves is the account
//! record's; every verb here returns a [`Settlement`](super::Settlement) and
//! leaves the line, the after-line work and the remove to the seam.

use super::boxrun::{cancel_stripe_if_active, run_script};
use super::groups::{application_token, group_record};
use super::lifecycle::dns_contact;
use super::Error;
use super::{AfterLine, Settlement};
use kyriakon_control_core::account::state::Standing;
use kyriakon_control_core::config::DrainConfig;
use kyriakon_control_core::flow::validate;
use kyriakon_control_core::intent::{
    AttributeIntent, CreditIntent, RefundIntent, ReturnIntent, CREDIT_RAILS, REFUND_RAILS,
};
use kyriakon_control_core::mail::notice;
use kyriakon_control_core::payments::ledger::LedgerLine;
use kyriakon_control_core::payments::ledger::RefundTail;
use kyriakon_control_core::payments::ledger::{self, Ledger};
use kyriakon_control_core::payments::target::PaymentTarget;
use kyriakon_control_core::payments::xmr;
use kyriakon_control_core::store::journal::Journal;
use kyriakon_control_core::store::{
    self, Account, ApplicationRef, CreditProgress, GroupRecord, JournalLine, Monero, Payment,
    RefundProgress, Store, TokenRecord,
};
use kyriakon_control_core::util;
use serde_json::json;
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
) -> Result<Settlement, Error> {
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
    // A refusal is recorded once and its intent removed by the seam: a new
    // intent is the way to change it, and a kept file would sit in the
    // unapplied backlog for good.
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
        return credit_group(
            cfg, store, journal, &intent, amount, received, &domain, None,
        )
        .await;
    }
    credit_account(cfg, store, journal, &intent, amount, received, None).await
}

/// A credit for a person's account. The token index has already said the token
/// is not a group's.
async fn credit_account(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: &CreditIntent,
    amount: i64,
    received: time::Date,
    attributed_item: Option<&str>,
) -> Result<Settlement, Error> {
    let (username, mut account, _payment) = match resolve_payment(store, &intent.token).await {
        Ok(found) => found,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    let price = match util::pence(&cfg.price_gbp) {
        Ok(price) if price > 0 => price,
        Ok(_) => {
            return Err(Error::Failed(
                "the drain's configured price_gbp must be more than zero".to_string(),
            ))
        }
        Err(e) => return Err(Error::context("the drain's configured price_gbp", e)),
    };
    let address = account.notice_address();
    let party = CreditParty::Account {
        username: username.clone(),
        address,
    };
    let mut target = PaymentTarget::account(&mut account);
    apply_credit(
        cfg,
        store,
        journal,
        &mut target,
        &party,
        intent,
        amount,
        received,
        price,
        attributed_item,
    )
    .await
}

/// A credit for a body's one payment. Its fee covers every mailbox and the
/// group holds no balance, so only a full year is accepted.
#[allow(clippy::too_many_arguments)]
async fn credit_group(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: &CreditIntent,
    amount: i64,
    received: time::Date,
    domain: &str,
    attributed_item: Option<&str>,
) -> Result<Settlement, Error> {
    if let Some(why) = validate::domain(domain) {
        return Err(Error::Failed(format!(
            "the token's group domain {domain:?}: {why}"
        )));
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
    let price = match util::pence(&cfg.group_price_gbp) {
        Ok(price) if price > 0 => price,
        Ok(_) => {
            return Err(Error::Failed(
                "the drain's configured group_price_gbp must be more than zero".to_string(),
            ))
        }
        Err(e) => return Err(Error::context("the drain's configured group_price_gbp", e)),
    };
    let address = match dns_contact(store, &group).await {
        Ok(address) => address,
        Err(e) => return Err(e),
    };
    let domain = group.domain.clone();
    let site_owner = group.site_owner.clone();
    let party = CreditParty::Group {
        domain: domain.clone(),
        site_owner,
        address,
    };
    let mut target = PaymentTarget::group(&mut group);
    apply_credit(
        cfg,
        store,
        journal,
        &mut target,
        &party,
        intent,
        amount,
        received,
        price,
        attributed_item,
    )
    .await
}

/// The fields a credit's money arrives with, revalidated here because `intents/`
/// belongs to the unprivileged half. Returns the amount in pence. A token is
/// checked only when there is one: a payment with none is held, not refused.
fn credit_fields(intent: &CreditIntent) -> Result<i64, Error> {
    if !CREDIT_RAILS.contains(&intent.rail.as_str()) {
        return Err(Error::Failed(
            "the credit names a rail that is not cash, cash-hand or monero".to_string(),
        ));
    }
    if !intent.token.is_empty() && !store::is_payment_token(&intent.token) {
        return Err(Error::Failed(
            "the credit's token is not the shape of a payment token".to_string(),
        ));
    }
    let Some(received) = util::parse_date(&intent.received) else {
        return Err(Error::Failed(
            "the credit's received date is not YYYY-MM-DD".to_string(),
        ));
    };
    // A hand-written intent can carry any date. Two years ahead is the ceiling
    // the paid-until arithmetic measures from, and a wake at this boundary is
    // the difference between a refused intent and a pass that panics and starves
    // every intent behind it.
    if util::received_beyond_window(received, OffsetDateTime::now_utc().date()) {
        return Err(Error::Failed(format!(
            "the credit's received date {} is more than two years ahead",
            intent.received
        )));
    }
    if !xmr::valid_txid(intent.txid.as_deref()) {
        return Err(Error::Failed(
            "the credit's transaction id is not 64 hexadecimal characters".to_string(),
        ));
    }
    if !xmr::valid_xmr(intent.amount_xmr.as_deref()) {
        return Err(Error::Failed(
            "the credit's XMR amount is not a decimal amount".to_string(),
        ));
    }
    if intent.rate.is_some() && intent.rail != "monero" {
        return Err(Error::Failed(
            "a --rate is only a monero credit's receipt-date rate".to_string(),
        ));
    }
    if let Some(rate) = intent.rate.as_deref() {
        if !xmr::valid_rate(rate) {
            return Err(Error::Failed(format!(
                "the credit's rate {rate:?} is not a positive decimal amount"
            )));
        }
    }
    match util::pence(&intent.amount_gbp) {
        Ok(amount) if amount > 0 => Ok(amount),
        Ok(_) => Err(Error::Failed(
            "the credit's amount must be more than zero".to_string(),
        )),
        Err(e) => Err(Error::from(e)),
    }
}

/// The token index entry a payment token names, when the entry is this token's.
/// The index is the only join, so a token that is not in it resolves to nothing.
pub(super) async fn token_join(store: &Store, token: &str) -> Result<Option<TokenRecord>, Error> {
    let Some(join) = store.token(token).await? else {
        return Ok(None);
    };
    if join.token != token {
        return Err(Error::Failed(
            "the token record does not name this token".to_string(),
        ));
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
) -> Result<(String, Account, Payment), Error> {
    let Some(join) = token_join(store, token).await? else {
        return Err(Error::Failed(
            "the token is not in the index; an unattributed payment belongs in the queue"
                .to_string(),
        ));
    };
    if join.group.is_some() {
        return Err(Error::Failed(
            "the token belongs to a group, whose payment is held on the group's record".to_string(),
        ));
    }
    if validate::username_shape(&join.username).is_some() {
        return Err(Error::Failed(
            "the token record does not name this token".to_string(),
        ));
    }
    let username = join.username;
    let Some(account) = store.account(&username).await? else {
        return Err(Error::Failed(
            "the token resolves to an account that is gone".to_string(),
        ));
    };
    let Some(payment) = account.payment_state() else {
        return Err(Error::Failed(
            "the account carries no payment block".to_string(),
        ));
    };
    if payment.token_ref.as_deref() != Some(token) {
        return Err(Error::Failed(
            "the token is not the one the account's payment block holds".to_string(),
        ));
    }
    Ok((username, account, payment))
}

/// Which record a credit pays for. The arithmetic and the ledger line are the
/// same; only the owner, the price and the receipt's words differ.
enum CreditParty {
    Account {
        username: String,
        address: String,
    },
    Group {
        domain: String,
        site_owner: String,
        address: String,
    },
}

impl CreditParty {
    fn owner(&self) -> &str {
        match self {
            CreditParty::Account { username, .. } => username,
            CreditParty::Group { site_owner, .. } => site_owner,
        }
    }

    fn application(&self) -> ApplicationRef {
        match self {
            CreditParty::Account { username, .. } => ApplicationRef::account(username.clone()),
            CreditParty::Group {
                domain, site_owner, ..
            } => ApplicationRef::group(site_owner.clone(), domain.clone()),
        }
    }
}

/// Apply a credit to whichever record holds the payment: one arithmetic, one
/// ledger line, one receipt. A group's year is one payment with no balance; a
/// person's may be part-paid and carries the difference.
#[allow(clippy::too_many_arguments)]
async fn apply_credit(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    target: &mut PaymentTarget<'_>,
    party: &CreditParty,
    intent: &CreditIntent,
    amount: i64,
    received: time::Date,
    price: i64,
    attributed_item: Option<&str>,
) -> Result<Settlement, Error> {
    // A pass that journaled `applying` and wrote the record but crashed before
    // the ledger append is finished here, from the values it recorded then. The
    // record is the witness: its paid-until date (or, for a shortfall, its
    // balance) is the one this credit computed, so nothing is extended again
    // and no second notice is sent.
    let progress = journal.credit_progress(&intent.id);
    let written = progress.as_ref().is_some_and(|p| {
        if p.paid {
            target.paid_until() == p.paid_until_after.as_deref()
        } else {
            target.balance_is(p.balance_gbp.as_deref())
        }
    });
    // A recovery's account already carries the date the first pass wrote, so
    // the quote is taken from the block the journal said it recorded rather
    // than from `payment_quote`, which only offers one before the date is set.
    let quote = target.block().and_then(|payment| {
        if progress.as_ref().is_some_and(|progress| progress.quoted) {
            payment.monero
        } else {
            payment_quote(&payment).cloned()
        }
    });
    if let Some(progress) = progress.as_ref().filter(|_| written) {
        if !Ledger::open(store).has_intent(&intent.id).await? {
            append_credit_ledger(
                cfg,
                store,
                intent,
                quote.as_ref(),
                &util::date_string(received),
                &util::gbp(amount),
                &progress.applied_gbp,
                progress.paid_until_after.as_deref(),
            )
            .await?;
        }
        sync_payment_copy(store, target, party.owner(), target.is_group()).await?;
        return Ok(Settlement::applied(
            party.application(),
            override_note(intent.override_reason.as_deref()),
        ));
    }

    let before = match target.paid_until() {
        Some(stamp) => match util::parse_date(stamp) {
            Some(date) => Some(date),
            None => {
                return Ok(Settlement::refused(format!(
                    "the {} paid-until date cannot be read",
                    label(party)
                )))
            }
        },
        None => None,
    };
    let Some(until) = util::paid_until_after(received, before) else {
        return Ok(Settlement::refused(format!(
            "the {} paid-until date has no year in the calendar",
            label(party)
        )));
    };
    let override_reason = intent
        .override_reason
        .as_deref()
        .filter(|r| !r.trim().is_empty());
    if util::credit_ceiling(received).is_some_and(|ceiling| until > ceiling)
        && override_reason.is_none()
    {
        return Ok(Settlement::refused(format!(
            "the credit would put the {} paid_until more than 24 months past --received; give --override <reason> to mean it",
            label(party)
        )));
    }

    let balance = match target.balance() {
        Ok(Some(text)) => match util::pence(text) {
            Ok(pence) => pence,
            Err(e) => {
                return Ok(Settlement::refused(format!(
                    "the {} balance cannot be read: {e}",
                    label(party)
                )))
            }
        },
        Ok(None) => 0,
        Err(e) => return Err(Error::from(e)),
    };
    let applied = credit_money(price, balance, amount);
    // A group's year is one payment and the fee covers every mailbox, so there
    // is no balance to carry a shortfall or an excess into.
    if target.is_group() {
        if !applied.paid {
            return Ok(Settlement::refused(format!(
                "a group's year is one payment of GBP {}; GBP {} is not enough",
                util::gbp(price),
                util::gbp(amount)
            )));
        }
        if applied.balance > 0 {
            return Ok(Settlement::refused(format!(
                "a group's year is one payment of GBP {}; GBP {} is more than the fee",
                util::gbp(price),
                util::gbp(amount)
            )));
        }
    }

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
    if let (Some(paid_until), false) = (target.paid_until(), intent.confirm_double) {
        let problem = if intent.kind == "credit" {
            format!(
                "the {} was already credited until {paid_until}; give --confirm-double for a renewal",
                label(party)
            )
        } else {
            format!(
                "the {} was already credited until {paid_until}; record a renewal with `credit --confirm-double`",
                label(party)
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

    // The values the write is about to set, recorded before it so a crash
    // leaves enough to finish the ledger line.
    if progress.is_none() {
        journal_credit_applying(
            store,
            journal,
            &cfg.release,
            intent,
            party.owner(),
            &CreditProgress {
                paid: applied.paid,
                paid_until_after: paid_until_after.clone(),
                applied_gbp: util::gbp(applied.applied),
                balance_gbp: balance_text.clone(),
                quoted: quote.is_some(),
            },
        )
        .await?;
    }

    // A payment after a lapse restores access from the day it is recorded. The
    // restore runs before the record says active: a failure here leaves the
    // account lapsed, and the retry repeats an idempotent script rather than
    // reporting an active account whose sending and pushing are still stopped.
    if applied.paid {
        if target.is_lapsed() {
            let username = party.owner().to_string();
            run_script(cfg, "lapse-user.sh", &["--restore", &username]).await?;
        }
        if let Some(group) = target.group_ref() {
            restore_group_mailboxes(cfg, store, group).await?;
        }
        target.restore_after_payment();
        if target.is_active() {
            target.clear_grace();
        }
    }
    target.set_rail(&intent.rail);
    target.set_balance(balance_text);
    if applied.paid {
        target.set_paid_until(until_text.clone())?;
    }
    target.save(store, applied.paid).await?;
    sync_payment_copy(store, target, party.owner(), target.is_group()).await?;
    append_credit_ledger(
        cfg,
        store,
        intent,
        quote.as_ref(),
        &util::date_string(received),
        &util::gbp(amount),
        &util::gbp(applied.applied),
        paid_until_after.as_deref(),
    )
    .await?;

    // The receipt is for every payment, including a shortfall: the money
    // arrived, and the account page quotes what still does.
    let (subject, body) = match party {
        CreditParty::Account { .. } if applied.paid => (
            format!(
                "Your payment to kyriakon.net was received (paid until {until_text})"
            ),
            format!(
                "We have recorded a payment of GBP {} on {} by {}.\n\n\
                 Your account is paid until {until_text}.\n",
                util::gbp(amount),
                util::date_string(received),
                intent.rail,
            ),
        ),
        CreditParty::Account { .. } => {
            let remaining = util::gbp(price - applied.balance);
            (
                format!(
                    "Your part payment to kyriakon.net was received (GBP {remaining} remains)"
                ),
                format!(
                    "We have recorded a payment of GBP {} on {} by {}.\n\n\
                     GBP {remaining} remains due for the year, and your account page quotes it.\n",
                    util::gbp(amount),
                    util::date_string(received),
                    intent.rail,
                ),
            )
        }
        CreditParty::Group { domain, .. } => (
            format!("Your payment to kyriakon.net was received (paid until {until_text})"),
            format!(
                "We have recorded a payment of GBP {} on {} by {} for {domain}.\n\n\
                 The whole group is paid until {until_text}, and every mailbox in it shares that date.\n",
                util::gbp(amount),
                util::date_string(received),
                intent.rail,
            ),
        ),
    };
    let kind = if target.is_group() {
        "group.receipt"
    } else {
        "prepaid.receipt"
    };
    notice::send_account_notice(
        cfg,
        store,
        party.owner(),
        kind,
        &subject,
        &party_address(party),
        &body,
    )
    .await?;

    Ok(Settlement::applied(
        party.application(),
        override_note(override_reason),
    ))
}

/// The name the refusal text uses. A body's is its domain, not one mailbox.
fn label(party: &CreditParty) -> &str {
    match party {
        CreditParty::Account { username, .. } => username,
        CreditParty::Group { domain, .. } => domain,
    }
}

fn party_address(party: &CreditParty) -> String {
    match party {
        CreditParty::Account { address, .. } => address.clone(),
        CreditParty::Group { address, .. } => address.clone(),
    }
}

/// Write the changed block into the record the page reads. An account's copy is
/// its retained application; a group's is the filed application the handler
/// renders, found through the site owner.
async fn sync_payment_copy(
    store: &Store,
    target: &PaymentTarget<'_>,
    owner: &str,
    is_group: bool,
) -> Result<(), Error> {
    let application = if is_group {
        match application_token(store, owner).await {
            Some(token) => token,
            None => return Ok(()),
        }
    } else {
        String::new()
    };
    target
        .sync_application_copy(store, &application)
        .await
        .map_err(Error::from)
}

/// Bring back every mailbox in a group that lapsed with it: the group lapsed as
/// one and comes back as one, so a prepaid credit and a card renewal restore the
/// same set through the same steps.
pub(super) async fn restore_group_mailboxes(
    cfg: &DrainConfig,
    store: &Store,
    group: &GroupRecord,
) -> Result<(), Error> {
    for mailbox in &group.accounts {
        let Some(account) = store.account(mailbox).await? else {
            continue;
        };
        if account.state != Standing::Lapsed {
            continue;
        }
        run_script(cfg, "lapse-user.sh", &["--restore", mailbox]).await?;
        store
            .update_account(mailbox, |current| {
                if let Some(account) = current.as_mut() {
                    if account.state == Standing::Lapsed {
                        account.state = Standing::Active;
                        account.grace_until = None;
                        account.notice_stopped = None;
                    }
                }
                Ok::<(), Error>(())
            })
            .await?;
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
    /// The part of `amount` that bought time. An `--excess` refund may only
    /// give back what is left, because money that bought time returns through
    /// `--close`, which also takes the access away.
    applied_gbp: Option<i64>,
    amount_xmr: Option<String>,
    paid_until_after: Option<String>,
}

async fn last_payment_line(store: &Store, token: &str) -> Result<Option<PaymentLine>, Error> {
    let Some(line) = Ledger::open(store).last_payment(token).await? else {
        return Ok(None);
    };
    let amount = line
        .amount_gbp
        .as_deref()
        .ok_or_else(|| Error::Failed("a payment line carries no amount".to_string()))?;
    Ok(Some(PaymentLine {
        seq: line.seq,
        rail: line.rail,
        amount: util::pence(amount)
            .map_err(|e| Error::context("the payment line's amount cannot be read", e))?,
        applied_gbp: match line.applied_gbp.as_deref() {
            Some(text) => Some(util::pence(text).map_err(|e| {
                Error::context("the payment line's applied amount cannot be read", e)
            })?),
            None => None,
        },
        amount_xmr: line.amount_xmr,
        paid_until_after: line.paid_until_after,
    }))
}

/// The part of a payment that never bought time. An `--excess` refund may
/// return only this. Money that did buy time returns through the transition
/// that ends the access: `--close` on an account, `group remove` on a group.
///
/// A line with no applied figure is unknown rather than fully unapplied: an old
/// or truncated payment line must not make the whole payment refundable.
fn unapplied(original: &PaymentLine) -> Option<i64> {
    original
        .applied_gbp
        .map(|applied| original.amount - applied)
}

/// Refuse an `--excess` refund that asks for money the payment applied, with
/// both figures named. `full_return` names the transition that ends the access
/// instead of the refund.
fn excess_cap(original: &PaymentLine, amount: i64, full_return: &str) -> Result<(), String> {
    let Some(unapplied) = unapplied(original) else {
        return Err(format!(
            "ledger seq {} records no applied amount, so an --excess refund cannot tell what never bought time; a full return goes through {full_return}",
            original.seq
        ));
    };
    if amount > unapplied {
        return Err(format!(
            "an --excess refund is GBP {}, more than the GBP {} of ledger seq {} that never bought time (GBP {} arrived, GBP {} of it was applied); a full return goes through {full_return}",
            util::gbp(amount),
            util::gbp(unapplied.max(0)),
            original.seq,
            util::gbp(original.amount),
            util::gbp(original.applied_gbp.unwrap_or(0))
        ));
    }
    Ok(())
}

/// Refund one payment, or settle a refund already recorded. The console signs
/// every field, and `verify` checks the signature before anything else
/// because `intents/` belongs to the unprivileged half.
///
/// The refund form appends one negative line naming the `seq` it reverses and,
/// with `--close`, sets the account closing. An `--excess` refund is capped at
/// the part of the payment that never bought time, so a full return has to go
/// through `--close`, which also ends the access. The settlement form rewrites
/// the newest unsettled refund line under the ledger's lock. The ledger's own
/// `intent` field is the dedup key for a refund, and `settled_intent` for a
/// settlement, so a replay writes nothing.
pub async fn refund(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: RefundIntent,
) -> Result<Settlement, Error> {
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
    // is. A group's token names the group's one payment, reversed on the
    // group's record; a person's names their account.
    let join = match token_join(store, &intent.token).await {
        Ok(join) => join,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    if let Some(domain) = join.as_ref().and_then(|j| j.group.clone()) {
        if intent.close {
            return Ok(Settlement::refused(
                "a group has no closing state, so --close cannot cancel one; end the group with `kyriakon-admin group remove <domain>`",
            ));
        }
        let Some(mut group) = group_record(store, &domain).await? else {
            return Ok(Settlement::refused(
                "the token resolves to a group that is gone",
            ));
        };
        if let Err(problem) =
            excess_cap(&original, amount, "`kyriakon-admin group remove <domain>`")
        {
            return Ok(Settlement::refused(&problem));
        }
        if let Err(problem) = refund_total(store, &intent.token, &original, amount, true).await {
            return Ok(Settlement::refused(&problem));
        }
        let address = match dns_contact(store, &group).await {
            Ok(address) => address,
            Err(e) => return Err(e),
        };
        let party = RefundParty::Group {
            domain: group.domain.clone(),
            site_owner: group.site_owner.clone(),
            address,
        };
        let mut target = PaymentTarget::group(&mut group);
        return apply_refund(
            cfg,
            store,
            journal,
            &intent,
            &mut target,
            &party,
            rail,
            amount,
            reason,
            rate.as_deref(),
            &original,
        )
        .await;
    }

    let (username, mut account, _payment) = match resolve_payment(store, &intent.token).await {
        Ok(found) => found,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    // An excess refund gives back held overpayment, so whatever it takes has
    // to leave the balance too. Its ceiling is the part of the payment that
    // never bought time, not the balance: the card rail holds no balance, and
    // a full return of money that did buy time is `--close`, which also takes
    // the access away.
    if intent.excess {
        if let Err(problem) = excess_cap(&original, amount, "--close") {
            return Ok(Settlement::refused(&problem));
        }
    }
    if let Err(problem) = refund_total(store, &intent.token, &original, amount, intent.excess).await
    {
        return Ok(Settlement::refused(&problem));
    }
    let address = account.notice_address();
    let party = RefundParty::Account {
        username: username.clone(),
        address,
    };
    let mut target = PaymentTarget::account(&mut account);
    apply_refund(
        cfg,
        store,
        journal,
        &intent,
        &mut target,
        &party,
        rail,
        amount,
        reason,
        rate.as_deref(),
        &original,
    )
    .await
}

/// Refunds of one payment sum to no more than their ceiling, whatever their
/// sizes: the per-refund check alone lets two partial refunds overshoot. The
/// ceiling is the payment's amount for a `--close`, and the part of it that
/// never bought time for an `--excess`. An identical line is the same refund
/// seen twice.
async fn refund_total(
    store: &Store,
    token: &str,
    original: &PaymentLine,
    amount: i64,
    excess: bool,
) -> Result<(), Error> {
    let ceiling = if excess {
        unapplied(original).unwrap_or(0)
    } else {
        original.amount
    };
    let deducted = format!("-{}", util::gbp(amount));
    let ledger = Ledger::open(store);
    // A line this cannot read is not zero: counting it as zero would let this
    // refund and the unreadable one together exceed the payment.
    let refunds = ledger.refunded_total(token, original.seq).await?;
    for line in &refunds.lines {
        let on = line.received_on.as_deref().unwrap_or("an earlier date");
        if line.amount_gbp.as_deref() == Some(deducted.as_str()) {
            return Err(Error::Failed(format!(
                "an identical refund is already recorded at ledger seq {} on {on}",
                line.seq
            )));
        }
    }
    if refunds.total + amount > ceiling {
        let what = if excess {
            "that never bought time"
        } else {
            "that arrived"
        };
        return Err(Error::Failed(format!(
            "refunds of ledger seq {} already total GBP {}; another GBP {} would exceed the GBP {} {what}",
            original.seq,
            util::gbp(refunds.total),
            util::gbp(amount),
            util::gbp(ceiling)
        )));
    }
    Ok(())
}

/// Which record a refund reverses. The checks, the ledger line and the notice
/// are shared; the owner and the notice's kind differ.
enum RefundParty {
    Account {
        username: String,
        address: String,
    },
    Group {
        domain: String,
        site_owner: String,
        address: String,
    },
}

impl RefundParty {
    fn owner(&self) -> &str {
        match self {
            RefundParty::Account { username, .. } => username,
            RefundParty::Group { site_owner, .. } => site_owner,
        }
    }

    fn address(&self) -> &str {
        match self {
            RefundParty::Account { address, .. } => address,
            RefundParty::Group { address, .. } => address,
        }
    }

    fn application(&self) -> ApplicationRef {
        match self {
            RefundParty::Account { username, .. } => ApplicationRef::account(username.clone()),
            RefundParty::Group {
                domain, site_owner, ..
            } => ApplicationRef::group(site_owner.clone(), domain.clone()),
        }
    }

    fn notice_kind(&self) -> &'static str {
        match self {
            RefundParty::Account { .. } => "prepaid.refund",
            RefundParty::Group { .. } => "group.refund",
        }
    }
}

/// Record one refund against whichever record holds the payment, or finish one
/// an earlier pass wrote but did not append a ledger line for.
#[allow(clippy::too_many_arguments)]
async fn apply_refund(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: &RefundIntent,
    target: &mut PaymentTarget<'_>,
    party: &RefundParty,
    rail: &str,
    amount: i64,
    reason: &str,
    rate: Option<&str>,
    original: &PaymentLine,
) -> Result<Settlement, Error> {
    let received_on = util::filed_at()[..10].to_string();
    let settlement_by = util::date_after_days(14);
    let deducted = format!("-{}", util::gbp(amount));

    // An excess refund's balance write is the one this pass may have made
    // before a failed append. The journal's `applying` line carries the balance
    // it meant to leave, so a retry finishes the ledger line instead of
    // subtracting the amount again (#872).
    let progress = journal.refund_progress(&intent.id);
    let written = progress
        .as_ref()
        .is_some_and(|p| target.balance_is(p.balance_after.as_deref()));
    if written {
        if !Ledger::open(store).has_intent(&intent.id).await? {
            append_refund_ledger(
                store,
                intent,
                original,
                rail,
                amount,
                &deducted,
                reason.trim(),
                rate,
                &received_on,
                target.paid_until(),
            )
            .await?;
        }
        sync_payment_copy(store, target, party.owner(), target.is_group()).await?;
        return Ok(Settlement::applied(
            party.application(),
            Some("replayed: the balance already records this refund".to_string()),
        ));
    }

    if intent.close {
        // A cancellation refund closes the account, so the card stops before
        // the record that names the subscription goes. A failure fails the
        // pass and the intent stays for the backoff.
        if !target.is_group() && cancel_stripe_if_active(cfg, &target.stripe()).await? {
            target.cancel_card();
        }
        target.enter_closing(util::date_after_days(7), true)?;
    }
    if intent.excess {
        let before = target.balance()?.map(str::to_string);
        let after = target.spend_balance(amount)?;
        journal_refund_applying(
            store,
            journal,
            &cfg.release,
            intent,
            party.owner(),
            &RefundProgress {
                balance_before: before,
                balance_after: after,
            },
        )
        .await?;
    }
    target.save(store, false).await?;
    sync_payment_copy(store, target, party.owner(), target.is_group()).await?;

    let seq = append_refund_ledger(
        store,
        intent,
        original,
        rail,
        amount,
        &deducted,
        reason.trim(),
        rate,
        &received_on,
        target.paid_until(),
    )
    .await?;
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
        party.owner(),
        party.notice_kind(),
        &subject,
        party.address(),
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
    Ok(Settlement::line("applied", party.application(), Some(note)).with_after(printed))
}

/// Journal a refund's `applying` line with the balance it is about to leave, so
/// the ledger line can be finished if the write succeeds and the append does
/// not.
async fn journal_refund_applying(
    store: &Store,
    journal: &Journal,
    release: &str,
    intent: &RefundIntent,
    username: &str,
    progress: &RefundProgress,
) -> Result<(), Error> {
    let line = JournalLine {
        version: 1,
        at: util::filed_at(),
        intent: intent.id.clone(),
        kind: intent.kind.clone(),
        release: release.to_string(),
        application: ApplicationRef::account(username.to_string()),
        outcome: "applying".to_string(),
        note: None,
        review: None,
        credit: None,
        refund: Some(progress.clone()),
    };
    journal.append(store, &line).await.map_err(Error::from)
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

/// The fraction of the recorded XMR a partial refund gives back. Rounded down
/// at six decimal places, the precision `monero-wallet-cli` prints. A full
/// refund keeps the receipt's own string, so its figure cannot drift through a
/// parse and a format.
fn prorated_xmr(recorded: &str, part: i64, whole: i64) -> Option<String> {
    if whole <= 0 {
        return None;
    }
    if part == whole {
        return Some(recorded.to_string());
    }
    let (whole_text, fraction_text) = recorded.split_once('.').unwrap_or((recorded, ""));
    let whole_part: u128 = whole_text.parse().ok()?;
    let mut fraction = fraction_text.to_string();
    fraction.truncate(6);
    while fraction.len() < 6 {
        fraction.push('0');
    }
    let fraction_part: u128 = fraction.parse().ok()?;
    let units = whole_part
        .checked_mul(1_000_000)?
        .checked_add(fraction_part)?;
    let scaled = units.checked_mul(part as u128)? / whole as u128;
    Some(format!("{}.{:06}", scaled / 1_000_000, scaled % 1_000_000))
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
    amount: i64,
    deducted: &str,
    reason: &str,
    rate: Option<&str>,
    received_on: &str,
    paid_until_after: Option<&str>,
) -> Result<u64, Error> {
    let partial = amount < original.amount;
    let refund_basis = match rail {
        "monero" => Some(if rate.is_some() {
            "sterling"
        } else if partial {
            // A partial payout returns the same fraction of the recorded coin
            // it returns in sterling; the basis says the figure was scaled
            // rather than the whole amount that arrived (#873).
            "recorded_xmr_partial"
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
    line.amount_xmr = original
        .amount_xmr
        .as_deref()
        .and_then(|xmr| prorated_xmr(xmr, amount, original.amount));
    line.intent = Some(intent.id.clone());
    line.note = Some(reason.to_string());
    line.refund = Some(RefundTail {
        refund_of: Some(original.seq),
        settled_on: None,
        refund_basis: refund_basis.map(str::to_string),
        rate_refund: rate.map(str::to_string),
    });
    Ledger::open(store).append(line).await.map_err(Error::from)
}

/// A settlement rewrites the refund line at the intent's `seq`, under the
/// ledger's lock, and nothing else on it. This is the ledger's one non-append
/// write: `--settled` names a line already recorded, and appending a second
/// line would leave two records of one refund.
async fn settle_refund(
    store: &Store,
    intent: &RefundIntent,
    on: &str,
) -> Result<Settlement, Error> {
    let settled_on = util::date_string(util::parse_date(on).expect("the date was validated"));
    let Some(seq) = intent.seq else {
        return Ok(Settlement::refused(
            "a settlement names the refund's ledger seq; give --seq",
        ));
    };
    match Ledger::open(store)
        .settle_refund(&intent.token, seq, &intent.id, &settled_on)
        .await?
    {
        ledger::Settlement::Settled { seq } => Ok(Settlement::line(
            "applied",
            ApplicationRef::default(),
            Some(format!(
                "refund at ledger seq {seq} settled on {settled_on}"
            )),
        )),
        ledger::Settlement::AlreadySettled { seq, on } => Ok(Settlement::applied(
            ApplicationRef::default(),
            Some(format!(
                "refund at ledger seq {seq} was already settled on {on}"
            )),
        )),
        ledger::Settlement::NotFound => Ok(Settlement::refused(format!(
            "the token has no refund at ledger seq {seq}"
        ))),
    }
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
) -> Result<Settlement, Error> {
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
    let encoded = serde_json::to_string(&line).map_err(|source| Error::Json {
        context: "encode the queue",
        source,
    })?;
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
) -> Result<Settlement, Error> {
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
        rate: None,
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
        return credit_group(
            cfg,
            store,
            journal,
            &payment_intent,
            amount,
            received,
            &domain,
            Some(&intent.item),
        )
        .await;
    }
    credit_account(
        cfg,
        store,
        journal,
        &payment_intent,
        amount,
        received,
        Some(&intent.item),
    )
    .await
}

/// Close a held payment with the evidence it went back or was kept. No payment
/// line and no notice: no money moved and no account was touched.
pub async fn reconcile_return(store: &Store, intent: ReturnIntent) -> Result<Settlement, Error> {
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
            return Err(Error::Failed(format!("{item} is {}, not held", line.state)));
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
pub(super) async fn mark_attributed(store: &Store, item: &str, token: &str) -> Result<(), Error> {
    let id = item.to_string();
    let token = token.to_string();
    rewrite_unattributed(store, item, move |line| {
        if line.state == "returned" {
            return Err(Error::Failed(format!(
                "{id} was returned, so it cannot be attributed"
            )));
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
    change: impl FnOnce(&mut store::HeldItem) -> Result<(), Error>,
) -> Result<(), Error> {
    let _guard = store.log(store::UNATTRIBUTED).lock().await?;
    let mut items = store.held().await?;
    let at = items
        .iter()
        .position(|line| line.id == id)
        .ok_or_else(|| Error::Failed(format!("no held payment with id {id}")))?;
    change(&mut items[at])?;
    let mut bytes = String::new();
    for item in &items {
        bytes.push_str(&serde_json::to_string(item).map_err(|source| Error::Json {
            context: "encode the queue",
            source,
        })?);
        bytes.push('\n');
    }
    store
        .rewrite_log(store::UNATTRIBUTED, bytes.as_bytes())
        .await
        .map_err(Error::from)
}

/// Whether the unattributed queue already holds this intent's line.
async fn held_has_intent(store: &Store, id: &str) -> Result<bool, Error> {
    store
        .log(store::UNATTRIBUTED)
        .jsonl_any(|line: &store::HeldItem| line.intent == id)
        .await
        .map_err(Error::from)
}

/// The held line carrying this transaction id, with its id and the date it was
/// received, so a second sighting of one payment can name both.
async fn held_txid(store: &Store, txid: &str) -> Result<Option<(String, String)>, Error> {
    Ok(store
        .held()
        .await?
        .into_iter()
        .find(|line| line.txid.as_deref() == Some(txid))
        .map(|line| (line.id, line.received_on)))
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
) -> Result<(), Error> {
    let line = JournalLine {
        version: 1,
        at: util::filed_at(),
        intent: intent.id.clone(),
        kind: intent.kind.clone(),
        release: release.to_string(),
        application: ApplicationRef::account(username.to_string()),
        outcome: "applying".to_string(),
        note: None,
        review: None,
        credit: Some(progress.clone()),
        refund: None,
    };
    journal.append(store, &line).await.map_err(Error::from)
}

/// The ledger line carrying this transaction id, with the date it was first
/// credited and its `seq`, so a second credit can name both.
async fn ledger_txid(store: &Store, txid: &str) -> Result<Option<(u64, String)>, Error> {
    Ok(Ledger::open(store).by_txid(txid).await?.map(|line| {
        (
            line.seq,
            line.received_on
                .unwrap_or_else(|| "an earlier date".to_string()),
        )
    }))
}

/// The window quote a payment row may carry. A renewal's account block still
/// holds the year-one quote, so only a first credit records it: stamping it on
/// year two would record a rate that was never in force for that payment.
fn payment_quote(payment: &Payment) -> Option<&Monero> {
    payment
        .monero
        .as_ref()
        .filter(|_| payment.paid_until.is_none())
}

/// The XMR/GBP rate in force on the receipt date: the operator's `--rate` when
/// given, otherwise the cache only when it was fetched on that very day. The
/// cache is refreshed every pass, so a backdated credit must not stamp today's
/// market rate as the receipt-date valuation; with no same-day cache the row
/// carries no rate and the operator supplies `--rate`.
fn receipt_rate(
    cfg: &DrainConfig,
    intent: &CreditIntent,
    received_on: &str,
) -> Option<(String, String, String)> {
    if intent.rail != "monero" {
        return None;
    }
    if let Some(rate) = intent.rate.as_deref() {
        return Some((
            rate.to_string(),
            "operator".to_string(),
            received_on.to_string(),
        ));
    }
    let cached = xmr::cached(cfg)?;
    let fetched_on = cached.fetched_at.get(..10)?;
    if fetched_on != received_on || !xmr::fresh(&cached, OffsetDateTime::now_utc()) {
        return None;
    }
    Some((cached.rate_gbp_per_xmr, cached.source, cached.fetched_at))
}

/// Append the credit's line, keyed by the token, with no username. A Monero
/// credit carries the rate in force on the receipt date beside the rate that
/// produced the window's quote; every other rail's rate fields stay null. The
/// XMR amount and the transaction id are recorded when the operator gave them.
///
/// A Monero row with no receipt-date rate leaves those fields absent and says so
/// in its note: the accountant values it from the market on that date, and the
/// row never pretends a stale cache was in force.
#[allow(clippy::too_many_arguments)]
async fn append_credit_ledger(
    cfg: &DrainConfig,
    store: &Store,
    intent: &CreditIntent,
    quote: Option<&Monero>,
    received_on: &str,
    amount_gbp: &str,
    applied_gbp: &str,
    paid_until_after: Option<&str>,
) -> Result<(), Error> {
    let quoted = quote.filter(|_| intent.rail == "monero");
    let mut line = LedgerLine::empty(&intent.token, "payment", &intent.rail);
    line.received_on = Some(received_on.to_string());
    line.amount_gbp = Some(amount_gbp.to_string());
    line.applied_gbp = Some(applied_gbp.to_string());
    line.paid_until_after = paid_until_after.map(str::to_string);
    line.amount_xmr = intent.amount_xmr.clone();
    line.rate_quoted = quoted.and_then(|m| m.rate_gbp_per_xmr.clone());
    line.rate_source = quoted.and_then(|m| m.rate_source.clone());
    line.rate_at = quoted.and_then(|m| m.rate_at.clone());
    if intent.rail == "monero" {
        match receipt_rate(cfg, intent, received_on) {
            Some((rate, source, at)) => {
                line.rate_received = Some(rate);
                line.rate_received_source = Some(source);
                line.rate_received_at = Some(at);
            }
            None => {
                line.note = Some(
                    "no receipt-date XMR rate available; value this row at the rate on its date"
                        .to_string(),
                )
            }
        }
    }
    line.txid = intent.txid.clone();
    line.intent = Some(intent.id.clone());
    Ledger::open(store).append(line).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transitions::test_support::quota_config;
    use crate::transitions::{settle, Disposition, Envelope, RefusalFile};
    use kyriakon_control_core::account::sign;
    use kyriakon_control_core::intent::RefundIntent;
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
            None,
            false,
            None,
            Some("no token: envelope in book"),
        );
        assert!(c.contains("no token: envelope in book"));
        assert_ne!(c, a);
    }

    fn monero_intent(id: &str, token: &str, rate: Option<&str>) -> CreditIntent {
        CreditIntent {
            id: id.to_string(),
            token: token.to_string(),
            rail: "monero".to_string(),
            amount_gbp: "20.00".to_string(),
            received: "2026-10-04".to_string(),
            amount_xmr: Some("0.048848".to_string()),
            rate: rate.map(str::to_string),
            ..Default::default()
        }
    }

    fn year_one_quote() -> Monero {
        Monero {
            address: None,
            quote_xmr: Some("0.066667".to_string()),
            rate_gbp_per_xmr: Some("300.00".to_string()),
            rate_source: Some("coingecko".to_string()),
            rate_at: Some("2025-10-01T09:00:00Z".to_string()),
            stale: false,
        }
    }

    fn write_rate_cache(cfg: &DrainConfig, fetched_at: &str) {
        let path = std::path::Path::new(&cfg.rates);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            serde_json::to_vec(&json!({
                "version": 1,
                "rate_gbp_per_xmr": "409.44",
                "source": "coingecko",
                "fetched_at": fetched_at,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// A person's first credit, a renewal and a group payment all record the
    /// rate in force on the receipt date; only the first credit carries the
    /// window's quote, so a renewal never stamps the year-one rate on year two.
    #[tokio::test]
    async fn monero_rows_carry_the_receipt_rate_and_a_renewal_drops_the_year_one_quote() {
        let dir = std::env::temp_dir().join(format!("onboard-xmr-rate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = quota_config(&dir);
        std::fs::create_dir_all(&cfg.store_root).unwrap();
        let now = OffsetDateTime::now_utc();
        let received = util::date_string(now.date());
        write_rate_cache(&cfg, &util::stamp(now));
        let store = Store::new_for_test(&cfg.store_root);
        let quote = year_one_quote();
        for (id, quote) in [("person", Some(&quote)), ("renewal", None), ("group", None)] {
            append_credit_ledger(
                &cfg,
                &store,
                &monero_intent(id, "KYR-AAAA-BBBB-CCCC", None),
                quote,
                &received,
                "20.00",
                "20.00",
                Some("2027-10-04"),
            )
            .await
            .unwrap();
        }
        let lines = Ledger::open(&store).lines().await.unwrap();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            assert_eq!(line.rate_received.as_deref(), Some("409.44"), "{line:?}");
            assert_eq!(
                line.rate_received_source.as_deref(),
                Some("coingecko"),
                "{line:?}"
            );
        }
        assert_eq!(lines[0].rate_quoted.as_deref(), Some("300.00"));
        assert!(lines[1].rate_quoted.is_none(), "{:?}", lines[1]);
        assert!(lines[2].rate_quoted.is_none(), "{:?}", lines[2]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A cache fetched the next day is not the rate on the receipt day: a
    /// backdated credit must not stamp today's market rate on yesterday's money.
    #[tokio::test]
    async fn a_cache_fetched_on_another_day_is_not_the_receipt_rate() {
        let dir = std::env::temp_dir().join(format!("onboard-xmr-nextday-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = quota_config(&dir);
        std::fs::create_dir_all(&cfg.store_root).unwrap();
        let now = OffsetDateTime::now_utc();
        let today = util::date_string(now.date());
        let yesterday = util::date_string((now - time::Duration::days(1)).date());
        write_rate_cache(&cfg, &util::stamp(now));
        let store = Store::new_for_test(&cfg.store_root);
        for received in [&yesterday, &today] {
            append_credit_ledger(
                &cfg,
                &store,
                &monero_intent("day", "KYR-AAAA-BBBB-CCCC", None),
                None,
                received,
                "20.00",
                "20.00",
                Some("2027-10-04"),
            )
            .await
            .unwrap();
        }
        let lines = Ledger::open(&store).lines().await.unwrap();
        assert!(
            lines[0].rate_received.is_none(),
            "a next-day cache was stamped on the receipt day: {:?}",
            lines[0]
        );
        assert_eq!(lines[1].rate_received.as_deref(), Some("409.44"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `--rate` is the operator's receipt-date rate; a cache older than the
    /// twenty-four-hour window is no rate, and the row says so instead of
    /// writing a number that was true days earlier.
    #[tokio::test]
    async fn an_operator_rate_wins_and_a_stale_cache_is_not_written() {
        let dir = std::env::temp_dir().join(format!("onboard-xmr-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = quota_config(&dir);
        std::fs::create_dir_all(&cfg.store_root).unwrap();
        let store = Store::new_for_test(&cfg.store_root);
        append_credit_ledger(
            &cfg,
            &store,
            &monero_intent("operator", "KYR-AAAA-BBBB-CCCC", Some("410.00")),
            None,
            "2026-10-04",
            "20.00",
            "20.00",
            Some("2027-10-04"),
        )
        .await
        .unwrap();
        write_rate_cache(&cfg, "2020-01-01T00:00:00Z");
        append_credit_ledger(
            &cfg,
            &store,
            &monero_intent("stale", "KYR-AAAA-BBBB-CCCC", None),
            None,
            "2026-10-04",
            "20.00",
            "20.00",
            Some("2027-10-04"),
        )
        .await
        .unwrap();

        let lines = Ledger::open(&store).lines().await.unwrap();
        assert_eq!(lines[0].rate_received.as_deref(), Some("410.00"));
        assert_eq!(lines[0].rate_received_source.as_deref(), Some("operator"));
        assert_eq!(lines[0].rate_received_at.as_deref(), Some("2026-10-04"));
        assert!(lines[1].rate_received.is_none(), "{:?}", lines[1]);
        assert!(
            lines[1]
                .note
                .as_deref()
                .is_some_and(|note| note.contains("rate")),
            "the row does not say the rate is missing: {:?}",
            lines[1]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_renewal_does_not_reuse_the_year_one_quote() {
        let mut payment = Payment {
            monero: Some(year_one_quote()),
            ..Default::default()
        };
        assert!(payment_quote(&payment).is_some());
        payment.paid_until = Some("2027-10-04".to_string());
        assert!(payment_quote(&payment).is_none());
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
        // The journal lock is held here, so the settlement's append waits on it:
        // the state of the ledger lock is observable at that point rather than a
        // race. The index is loaded first, while the file is missing (an empty
        // journal), so the append is what waits.
        let journal = {
            let store = Store::new_for_test(&root_text);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(Journal::load(&store)).unwrap()
        };
        let journal_path = root.join("journal.jsonl");
        let held = {
            let store = Store::new_for_test(&root_text);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(store.log("journal.jsonl").lock()).unwrap()
        };

        let value = json!({
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "kind": "refund",
            "token": token,
            "settled_on": "2026-11-05",
            "seq": 7,
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
        drop(held);
        let settled = settle.join().unwrap();

        assert!(
            free,
            "the ledger lock is still held while the settlement journals"
        );
        assert!(settled.is_ok(), "{settled:?}");
        assert!(
            std::fs::read_to_string(&journal_path)
                .unwrap()
                .contains("\"kind\":\"refund\""),
            "the settlement journalled"
        );
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
            seq: Some(7),
            ..Default::default()
        };
        let error = settle_refund(&store, &intent, "2026-11-04")
            .await
            .expect_err("a line that does not parse must fail the settlement");
        assert!(
            matches!(
                &error,
                Error::Core(kyriakon_control_core::Error::ParseLine { line: 2, .. })
            ),
            "{error}"
        );
        assert_eq!(
            std::fs::read_to_string(&ledger).unwrap(),
            format!("{line}\nnot json\n")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
