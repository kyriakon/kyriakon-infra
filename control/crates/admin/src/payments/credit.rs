//! One job of the operator console.

use super::payment_token;
use crate::Error;
use crate::*;
use kyriakon_control_core::payments::xmr;

/// `token resend <username>`: the member's payment instructions again, with the
/// token their account already holds. Nothing is minted, because a second token
/// would leave the first one in the ledger as an entry that no longer resolves
/// to the same member and would orphan a payment already in flight.
///
/// The account is read here, at the terminal, so a member who was approved
/// without charge, or one with no account yet, is a refusal the operator sees
/// now rather than an intent the drain refuses a minute later.
pub(crate) async fn token(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), Error> {
    let (verb, username) = match args {
        [verb, username] if verb == "resend" => (verb.as_str(), username.as_str()),
        _ => return Err(Error::Failed(usage())),
    };
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::Failed(format!("the username {username:?}: {why}")));
    }
    let account = store
        .account(username)
        .await?
        .ok_or_else(|| Error::Failed(format!("no account for {username}")))?;
    let token = account
        .payment_state()
        .and_then(|p| p.token_ref)
        .ok_or_else(|| {
            Error::Failed(format!(
                "{username} was approved without charge, so there is no payment token"
            ))
        })?;
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(&key, &sign::resend_payload(username, &token))?;
    let id = intent::Intent::Resend(intent::ResendIntent {
        username: username.to_string(),
        token: token.clone(),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed {verb} for {username} as intent {id}");
    Ok(())
}

/// `credit`: record one payment against the token its account holds. A
/// `--username` is resolved to the account's token here, at the terminal, so a
/// name with no token is a refusal the operator sees now rather than an intent
/// the drain refuses a minute later. The intent carries the token and every
/// field the drain acts on; the signature is over all of them.
///
/// `--note` is for money that cannot be joined to an account: it is the only
/// reference the queue has, so it comes with no token and no username.
pub(crate) async fn credit(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), Error> {
    // `--confirm-double` is a bare switch, which the pair reader does not take.
    let confirm_double = args.iter().any(|a| a == "--confirm-double");
    let paired: Vec<String> = args
        .iter()
        .filter(|a| a.as_str() != "--confirm-double")
        .cloned()
        .collect();
    let flags = flags(
        &paired,
        &[
            "token", "username", "rail", "amount", "received", "txid", "xmr", "rate", "override",
            "note",
        ],
    )?;
    let note = match flags.get("note") {
        Some(text) if text.trim().is_empty() => {
            return Err(Error::Failed("--note is empty".to_string()))
        }
        Some(text) => Some(text.as_str()),
        None => None,
    };
    let token = match (flags.get("token"), flags.get("username"), note) {
        (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
            return Err(Error::Failed(
                "--note is for a payment with no token: give neither --token nor --username"
                    .to_string(),
            ))
        }
        (None, None, Some(_)) => String::new(),
        (None, None, None) => {
            return Err(Error::Failed(
                "give --token, --username or --note".to_string(),
            ))
        }
        _ => payment_token(store, &flags).await?,
    };
    let rail = need(&flags, "rail")?;
    if !intent::CREDIT_RAILS.contains(&rail) {
        return Err(Error::Failed(format!(
            "--rail {rail:?} is not one of {}",
            intent::CREDIT_RAILS.join(", ")
        )));
    }
    // Cash in hand is the one rail keyed by a username: the operator was there
    // and the drain resolves the name to a token before it writes anything. A
    // hand payment with no name has nothing to be joined to, by construction.
    if note.is_some() && rail == "cash-hand" {
        return Err(Error::Failed(
            "cash in hand is credited against a username; give --username, not --note".to_string(),
        ));
    }
    let amount = need(&flags, "amount")?;
    match util::pence(amount) {
        Ok(pence) if pence > 0 => {}
        Ok(_) => return Err(Error::Failed("--amount must be more than zero".to_string())),
        Err(e) => return Err(Error::Failed(format!("--amount: {e}"))),
    }
    let received = need(&flags, "received")?;
    let received_date = match util::parse_date(received) {
        Some(date) => date,
        None => {
            return Err(Error::Failed(format!(
                "--received {received:?} is not YYYY-MM-DD"
            )))
        }
    };
    // The drain measures the ceiling from this date, and a year it cannot hold
    // has no paid-until date: refuse it here rather than file an intent the
    // drain will only refuse later.
    if util::received_beyond_window(received_date, crate::account_requests::today()) {
        return Err(Error::Failed(format!(
            "--received {received:?} is more than two years ahead"
        )));
    }
    let txid = flags.get("txid").map(String::as_str);
    let xmr = flags.get("xmr").map(String::as_str);
    // The drain's own checks, so a field it would refuse is refused here
    // before an intent is filed and left unapplied.
    if !xmr::valid_txid(txid) {
        return Err(Error::Failed(
            "--txid is not 64 hexadecimal characters".to_string(),
        ));
    }
    if !xmr::valid_xmr(xmr) {
        return Err(Error::Failed("--xmr is not a decimal amount".to_string()));
    }
    let rate = flags.get("rate").map(String::as_str);
    if let Some(rate) = rate {
        if rail != "monero" {
            return Err(Error::Failed(
                "--rate is only a monero credit's receipt-date rate".to_string(),
            ));
        }
        if !xmr::valid_rate(rate) {
            return Err(Error::Failed(format!(
                "--rate {rate:?} is not a positive decimal amount"
            )));
        }
    }
    let override_reason = flags.get("override").map(String::as_str);
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(
        &key,
        &sign::credit_payload(
            &token,
            rail,
            amount,
            received,
            txid,
            xmr,
            rate,
            confirm_double,
            override_reason,
            note,
        ),
    )?;
    let id = intent::Intent::Credit(intent::CreditIntent {
        token: token.clone(),
        rail: rail.to_string(),
        amount_gbp: amount.to_string(),
        received: received.to_string(),
        txid: txid.map(str::to_string),
        amount_xmr: xmr.map(str::to_string),
        rate: rate.map(str::to_string),
        confirm_double,
        override_reason: override_reason.map(str::to_string),
        note: note.map(str::to_string),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    let what = if token.is_empty() {
        "a payment with no token".to_string()
    } else {
        token.clone()
    };
    println!("filed credit for {what} as intent {id}");
    Ok(())
}

/// `window extend --token <t> --days 14 --reason <text>`: the one extension a
/// member whose money is in the post is given. The console signs every field the
/// drain acts on, because the intent moves the date the account lapses on.
pub(crate) async fn window(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), Error> {
    let (verb, rest) = match args {
        [verb, rest @ ..] => (verb.as_str(), rest),
        _ => return Err(Error::Failed(usage())),
    };
    if verb != "extend" {
        return Err(Error::Failed(usage()));
    }
    let flags = flags(rest, &["token", "days", "reason"])?;
    let token = need(&flags, "token")?;
    if !store::is_payment_token(token) {
        return Err(Error::Failed(format!(
            "the token {token:?} is not a payment token"
        )));
    }
    let days = need(&flags, "days")?
        .parse::<i64>()
        .map_err(|_| Error::Failed("--days is not a whole number".to_string()))?;
    if days != 14 {
        return Err(Error::Failed(
            "a window extension is fourteen days and no other number".to_string(),
        ));
    }
    let reason = need(&flags, "reason")?;
    if reason.trim().is_empty() {
        return Err(Error::Failed(
            "--reason must say why the window is being extended".to_string(),
        ));
    }
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(&key, &sign::window_extend_payload(token, days, reason))?;
    let id = intent::Intent::WindowExtend(intent::WindowExtendIntent {
        token: token.to_string(),
        days,
        reason: reason.to_string(),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed window extension for {token} as intent {id}");
    Ok(())
}
