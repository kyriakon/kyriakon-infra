//! One job of the operator console.

use crate::Error;
use crate::*;
use kyriakon_control_core::payments::target::PaymentTarget;

/// `monero address <username> <address>`: record the subaddress the operator's
/// own wallet made for this member. The account is read and written here, at the
/// terminal, because root runs it and the address is the operator's own fact;
/// the account page then shows it rather than saying it is not ready.
///
/// One per account and permanent: the same address again is a replay that says
/// so, and a different one is refused rather than rotated, because the first
/// may already have been sent a payment and reusing it for somebody else would
/// join money to the wrong account.
pub(crate) async fn monero(store: &Store, args: &[String]) -> Result<(), Error> {
    let (username, address) = match args {
        [verb, username, address] if verb == "address" => (username.as_str(), address.as_str()),
        _ => return Err(Error::Failed(usage())),
    };
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::Failed(format!("the username {username:?}: {why}")));
    }
    if let Some(why) = monero_address_shape(address) {
        return Err(Error::Failed(format!("the address {address:?} {why}")));
    }
    let account = store
        .account(username)
        .await?
        .ok_or_else(|| Error::Failed(format!("no account for {username}")))?;
    // A person's block is on the account; a group mailbox's is on the group,
    // which holds the one payment for every mailbox in it. Recording the
    // subaddress on the account would give a charged group mailbox a block of
    // its own and still leave the group's payments without one (#905).
    if let Some(domain) = account.group.clone() {
        let mut group = transitions::groups::group_record(store, &domain)
            .await?
            .ok_or_else(|| Error::Failed(format!("no group record for {domain}")))?;
        if group.payment.no_charge {
            return Err(Error::Failed(format!(
                "the group {domain} was approved without charge, so it has no Monero rail"
            )));
        }
        if group.payment.rail != "monero" {
            return Err(Error::Failed(format!(
                "the group {domain} chose the {} rail, so it has no Monero subaddress to record",
                group.payment.rail
            )));
        }
        let written = {
            let mut target = PaymentTarget::group(&mut group);
            target.set_monero_address(address).map_err(Error::from)?
        };
        if !written {
            println!(
                "{username}'s group Monero subaddress is already {}",
                safe(address)
            );
            return Ok(());
        }
        let domain = group.domain.clone();
        let payment = group.payment.clone();
        store
            .update_group(&domain, move |current| {
                if let Some(group) = current.as_mut() {
                    group.payment = payment.clone();
                }
                Ok::<(), Error>(())
            })
            .await?;
        println!(
            "recorded Monero subaddress for the group {domain} ({username}): {}",
            safe(address)
        );
        return Ok(());
    }
    if account.payment_state().is_none() {
        return Err(Error::Failed(format!(
            "{username} was approved without charge, so it has no Monero rail"
        )));
    }
    if account.rail != "monero" {
        return Err(Error::Failed(format!(
            "{username} chose the {} rail, so it has no Monero subaddress to record",
            account.rail
        )));
    }
    // The read and the write are one step under the account's own lock: the
    // drain writes the same record from another process, and an interleaved
    // write would drop one of the two changes.
    let payment = store
        .update_account(username, |current| {
            let Some(account) = current.as_mut() else {
                return Err(Error::Failed(format!("no account for {username}")));
            };
            let written = PaymentTarget::account(account)
                .set_monero_address(address)
                .map_err(Error::from)?;
            Ok(written.then(|| account.payment.clone()).flatten())
        })
        .await?;
    let Some(payment) = payment else {
        println!(
            "{username}'s Monero subaddress is already {}",
            safe(address)
        );
        return Ok(());
    };
    store.write_payment_copy(username, &payment).await?;
    println!(
        "recorded Monero subaddress for {username}: {}",
        safe(address)
    );
    Ok(())
}

/// A mainnet Monero subaddress: 95 base58 characters beginning with `8`, the
/// shape `monero-wallet-cli` gives a subaddress. The checksum is the wallet's to
/// verify; this refuses a truncated paste and a standard address (which begins
/// `4`), which are the two ways a wrong value would look right in a store.
pub(crate) fn monero_address_shape(address: &str) -> Option<&'static str> {
    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if address.len() != 95 {
        return Some("is not the 95 characters of a Monero address");
    }
    if !address.starts_with('8') {
        return Some("is not a subaddress; a member's address begins with 8");
    }
    if !address.bytes().all(|b| BASE58.as_bytes().contains(&b)) {
        return Some("is not base58");
    }
    None
}
