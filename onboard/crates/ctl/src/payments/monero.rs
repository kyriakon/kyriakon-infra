//! One job of the operator console.

use crate::*;

/// `monero address <username> <address>`: record the subaddress the operator's
/// own wallet made for this member. The account is read and written here, at the
/// terminal, because root runs it and the address is the operator's own fact;
/// the account page then shows it rather than saying it is not ready.
///
/// One per account and permanent: the same address again is a replay that says
/// so, and a different one is refused rather than rotated, because the first
/// may already have been sent a payment and reusing it for somebody else would
/// join money to the wrong account.
pub(crate) async fn monero(store: &Store, args: &[String]) -> Result<(), String> {
    let (username, address) = match args {
        [verb, username, address] if verb == "address" => (username.as_str(), address.as_str()),
        _ => return Err(usage()),
    };
    if let Some(why) = validate::username_shape(username) {
        return Err(format!("the username {username:?}: {why}"));
    }
    if let Some(why) = monero_address_shape(address) {
        return Err(format!("the address {address:?} {why}"));
    }
    let mut account = store
        .account(username)
        .await?
        .ok_or_else(|| format!("no account for {username}"))?;
    let Some(mut payment) = account.payment_state() else {
        return Err(format!(
            "{username} was approved without charge, so it has no Monero rail"
        ));
    };
    if account.rail != "monero" {
        return Err(format!(
            "{username} chose the {} rail, so it has no Monero subaddress to record",
            account.rail
        ));
    }
    let block = payment.monero.get_or_insert_with(Default::default);
    match block.address.as_deref() {
        Some(existing) if existing == address => {
            println!("{username}'s Monero subaddress is already {address}");
            return Ok(());
        }
        Some(existing) => {
            return Err(format!(
                "{username}'s Monero subaddress is already {existing}; a subaddress is never rotated or reused"
            ))
        }
        None => block.address = Some(address.to_string()),
    }
    account.payment = Some(payment.clone());
    let bytes = serde_json::to_vec_pretty(&account)
        .map_err(|e| format!("cannot encode the account: {e}"))?;
    // The same writer the drain uses: the handler reads this record as
    // `_onboard`, so a 0600 root file would leave the page without a payment
    // block.
    transitions::groups::write_account_record(store, username, &bytes).await?;
    transitions::payments::write_payment_copy(store, username, &payment).await?;
    println!("recorded Monero subaddress for {username}: {address}");
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
