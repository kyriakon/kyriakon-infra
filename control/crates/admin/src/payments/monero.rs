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
        _ => return Err(Error::Usage),
    };
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::InvalidUsername {
            username: username.to_string(),
            why,
        });
    }
    if let Some(why) = monero_address_shape(address) {
        return Err(Error::InvalidMoneroAddress {
            address: address.to_string(),
            why: why.to_string(),
        });
    }
    let account = store
        .account(username)
        .await?
        .ok_or_else(|| Error::NoAccount {
            username: username.to_string(),
        })?;
    // A person's block is on the account; a group mailbox's is on the group,
    // which holds the one payment for every mailbox in it. Recording the
    // subaddress on the account would give a charged group mailbox a block of
    // its own and still leave the group's payments without one (#905).
    if let Some(domain) = account.group.clone() {
        let inside = domain.clone();
        let written = store
            .update_group(&domain, move |current| {
                let Some(group) = current.as_mut() else {
                    return Err(Error::NoGroup {
                        domain: inside.clone(),
                    });
                };
                if group.payment.no_charge {
                    return Err(Error::GroupNoCharge {
                        domain: inside.clone(),
                    });
                }
                if group.payment.rail != "monero" {
                    return Err(Error::GroupRailNotMonero {
                        domain: inside.clone(),
                        rail: group.payment.rail.clone(),
                    });
                }
                PaymentTarget::group(group)
                    .set_monero_address(address)
                    .map_err(Error::from)
            })
            .await?;
        if !written {
            println!(
                "{username}'s group Monero subaddress is already {}",
                safe(address)
            );
            return Ok(());
        }
        // The payer's page renders the filed application record, not the
        // root-owned group record, so the block is copied there too. The group
        // was read inside the lock above, so a concurrent credit's date is not
        // replaced by a stale snapshot.
        if let Some(group) = transitions::groups::group_record(store, &domain).await? {
            if let Some(token) =
                transitions::groups::application_token(store, &group.site_owner).await
            {
                store
                    .write_filed_payment(&token, &group.payment.as_payment())
                    .await?;
            }
        }
        println!(
            "recorded Monero subaddress for the group {domain} ({username}): {}",
            safe(address)
        );
        return Ok(());
    }
    if account.payment_state().is_none() {
        return Err(Error::NoChargeMonero {
            username: username.to_string(),
        });
    }
    if account.rail != "monero" {
        return Err(Error::RailNotMonero {
            username: username.to_string(),
            rail: account.rail.clone(),
        });
    }
    // The read and the write are one step under the account's own lock: the
    // drain writes the same record from another process, and an interleaved
    // write would drop one of the two changes.
    let payment = store
        .update_account(username, |current| {
            let Some(account) = current.as_mut() else {
                return Err(Error::NoAccount {
                    username: username.to_string(),
                });
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
