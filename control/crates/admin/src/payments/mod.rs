//! One job of the operator console.

use crate::Error;
use crate::*;

pub(crate) mod credit;
pub(crate) mod ledger;
pub(crate) mod monero;
pub(crate) mod payment;
pub(crate) mod prepaid;
pub(crate) mod refund;

/// The token and the payment block a `credit`, `refund` or `payment show` acts
/// on, resolved here at the terminal so a name with no token is a refusal the
/// operator sees now rather than an intent the drain refuses a minute later. A
/// group mailbox holds no payment of its own, so its name resolves to the one
/// block the whole body paid by: `credit`, `refund` and the group's page share
/// that join and its `no_charge` refusal.
pub(crate) async fn payment_block(
    store: &Store,
    username: &str,
) -> Result<(String, store::Payment), Error> {
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::Failed(format!("the username {username:?}: {why}")));
    }
    let account = store
        .account(username)
        .await?
        .ok_or_else(|| Error::Failed(format!("no account for {username}")))?;
    // An individual approved without charge and a free group's mailbox both hold
    // no payment at all, and are refused in the same words.
    if account.no_charge {
        return Err(Error::Failed(format!(
            "{username} was approved without charge, so there is no payment token"
        )));
    }
    if let Some(mut payment) = account.payment_state() {
        let token = payment
            .token_ref
            .clone()
            .ok_or_else(|| Error::Failed(format!("{username} has no payment token")))?;
        // The record's own rail is what the last credit arrived on; a legacy
        // block carries none, and the account's approval rail is what it was.
        payment.rail.get_or_insert(account.rail.clone());
        return Ok((token, payment));
    }
    let Some(domain) = account.group.as_deref() else {
        return Err(Error::Failed(format!("{username} has no payment token")));
    };
    let group = transitions::groups::group_record(store, domain)
        .await?
        .ok_or_else(|| Error::Failed(format!("no group record for {domain}")))?;
    let token = group
        .payment
        .token_ref
        .clone()
        .ok_or_else(|| Error::Failed(format!("the group {domain} has no payment token")))?;
    Ok((token, group_payment(&group.payment)))
}

/// The token a `credit` or `refund` acts on: `--token` itself, or the block a
/// `--username` resolves to through [`payment_block`].
pub(crate) async fn payment_token(
    store: &Store,
    flags: &BTreeMap<String, String>,
) -> Result<String, Error> {
    match (flags.get("token"), flags.get("username")) {
        (Some(token), None) => {
            if !store::is_payment_token(token) {
                return Err(Error::Failed(format!(
                    "the token {token:?} is not a payment token"
                )));
            }
            Ok(token.clone())
        }
        (None, Some(username)) => payment_block(store, username).await.map(|(token, _)| token),
        (Some(_), Some(_)) => Err(Error::Failed(
            "give either --token or --username, not both".to_string(),
        )),
        (None, None) => Err(Error::Failed("give --token or --username".to_string())),
    }
}

/// A group's payment block read as an account's, so both print through one
/// printer. Every field is named: a group has no token-issue date, no held
/// balance and no Monero quote, and a field added to `Payment` fails here until
/// someone decides what a group's value is.
pub(crate) fn group_payment(payment: &store::GroupPayment) -> store::Payment {
    store::Payment {
        token_ref: payment.token_ref.clone(),
        token_issued_at: None,
        paid_until: payment.paid_until.clone(),
        window: payment.window.clone(),
        rail: Some(payment.rail.clone()),
        balance_gbp: None,
        stripe: payment.stripe.clone(),
        monero: None,
    }
}

/// The payment block on the console: the rail, the paid-until date or the
/// window's own state, the token, and the window's dates. `payment show` and
/// both branches of `show` print through this, so the three cannot drift.
///
/// `no_charge` is the group record's own flag. A tokenless block reads `none`
/// unless the payment really was free, which a legacy paid record never is.
pub(crate) fn print_payment(payment: &store::Payment, no_charge: bool) {
    if let Some(rail) = payment.rail.as_deref() {
        println!("  rail     {}", safe(rail));
    }
    // `paid_until` is null while a window runs, so null alone says nothing
    // about whether one exists: the window does.
    let paid = match (&payment.paid_until, &payment.window) {
        (Some(until), _) => until.as_str(),
        (None, Some(_)) => "null: the window is open",
        (None, None) => "null: no window was opened",
    };
    println!("  paid     {}", safe(paid));
    let token = match (payment.token_ref.as_deref(), no_charge) {
        (Some(token), _) => token,
        (None, true) => "none (no charge)",
        (None, false) => "none",
    };
    println!("  token    {}", safe(token));
    if let Some(w) = &payment.window {
        println!(
            "  window   {} to {}",
            safe(&w.opened_at),
            safe(&w.closes_at)
        );
    }
}
