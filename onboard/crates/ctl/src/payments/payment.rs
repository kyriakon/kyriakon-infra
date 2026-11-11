//! One job of the operator console.

use super::{payment_block, print_payment};
use crate::Error;
use crate::*;

/// `payment show --username <u>`: the account's rail, paid-until date and every
/// ledger line keyed by its token. The ledger is read strictly, so a corrupt
/// record is an error rather than a payment history that looks empty.
pub(crate) async fn payment(store: &Store, args: &[String]) -> Result<(), Error> {
    let [verb, rest @ ..] = args else {
        return Err(Error::Failed(usage()));
    };
    if verb != "show" {
        return Err(Error::Failed(usage()));
    }
    let flags = flags(rest, &["username"])?;
    let username = need(&flags, "username")?;
    let (token, payment) = payment_block(store, username).await?;
    println!("account {username}");
    print_payment(&payment, false);

    println!("ledger for {token}");
    let mut any = false;
    for line in Ledger::open(store).lines().await? {
        if line.token != token {
            continue;
        }
        any = true;
        let received_on = line.received_on.as_deref().unwrap_or("-");
        let amount_gbp = line.amount_gbp.as_deref().unwrap_or("-");
        let applied_gbp = line.applied_gbp.as_deref().unwrap_or("-");
        let mut extra = String::new();
        if let Some(of) = line.refund_of() {
            extra.push_str(&format!("  refund_of {of}"));
        }
        if let Some(on) = line.settled_on() {
            extra.push_str(&format!("  settled_on {on}"));
        }
        println!(
            "  {:>5}  {:<8}  {:<4}  {}  {}  applied {}{}",
            line.seq, line.kind, line.rail, received_on, amount_gbp, applied_gbp, extra,
        );
    }
    if !any {
        println!("  no ledger lines");
    }
    Ok(())
}
