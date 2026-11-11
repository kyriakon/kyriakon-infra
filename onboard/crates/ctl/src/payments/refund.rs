//! One job of the operator console.

use super::payment_token;
use crate::Error;
use crate::*;

/// `refund`: either record a refund against the payment its token last made, or
/// settle one already recorded. The refund form names the money, the rail, why
/// and whether the account closes; the settlement form names only the day. A
/// `--username` is resolved to the account's token here, as `credit` does, and
/// the signature covers every field the drain acts on.
pub(crate) async fn refund(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), Error> {
    // `--close` and `--excess` are bare switches, which the pair reader does not
    // take.
    let close = args.iter().any(|a| a == "--close");
    let excess = args.iter().any(|a| a == "--excess");
    let paired: Vec<String> = args
        .iter()
        .filter(|a| a.as_str() != "--close" && a.as_str() != "--excess")
        .cloned()
        .collect();
    let flags = flags(
        &paired,
        &[
            "token", "username", "amount", "rail", "reason", "rate", "settled",
        ],
    )?;
    let token = payment_token(store, &flags).await?;

    if let Some(settled) = flags.get("settled").map(String::as_str) {
        for name in ["amount", "rail", "reason", "rate"] {
            if flags.contains_key(name) {
                return Err(Error::Failed(format!("--settled takes no --{name}")));
            }
        }
        if close || excess {
            return Err(Error::Failed(
                "--settled takes no --close or --excess".to_string(),
            ));
        }
        if util::parse_date(settled).is_none() {
            return Err(Error::Failed(format!(
                "--settled {settled:?} is not YYYY-MM-DD"
            )));
        }
        let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
        let sig = sign::sign(
            &key,
            &sign::refund_payload(&token, "", "", false, false, "", settled, ""),
        )?;
        let id = intent::Intent::Refund(intent::RefundIntent {
            token: token.clone(),
            settled_on: Some(settled.to_string()),
            sig,
            ..Default::default()
        })
        .file(store)
        .await?;
        println!("filed refund settlement for {token} as intent {id}");
        return Ok(());
    }

    let rail = need(&flags, "rail")?;
    if !intent::REFUND_RAILS.contains(&rail) {
        return Err(Error::Failed(format!(
            "--rail {rail:?} is not one of {}",
            intent::REFUND_RAILS.join(", ")
        )));
    }
    let amount = need(&flags, "amount")?;
    match util::pence(amount) {
        Ok(pence) if pence > 0 => {}
        Ok(_) => return Err(Error::Failed("--amount must be more than zero".to_string())),
        Err(e) => return Err(Error::Failed(format!("--amount: {e}"))),
    }
    let reason = need(&flags, "reason")?;
    if reason.trim().is_empty() {
        return Err(Error::Failed(
            "--reason must say why the money is going back".to_string(),
        ));
    }
    if close == excess {
        return Err(Error::Failed(
            "give exactly one of --close or --excess".to_string(),
        ));
    }
    let rate = flags.get("rate").map(String::as_str);
    if let Some(rate) = rate {
        if rail != "monero" {
            return Err(Error::Failed(
                "--rate is only a monero refund paid in sterling".to_string(),
            ));
        }
        match util::pence(rate) {
            Ok(pence) if pence > 0 => {}
            Ok(_) => return Err(Error::Failed("--rate must be more than zero".to_string())),
            Err(e) => return Err(Error::Failed(format!("--rate: {e}"))),
        }
    }
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(
        &key,
        &sign::refund_payload(
            &token,
            amount,
            rail,
            close,
            excess,
            rate.unwrap_or(""),
            "",
            reason,
        ),
    )?;
    let id = intent::Intent::Refund(intent::RefundIntent {
        token: token.clone(),
        amount_gbp: Some(amount.to_string()),
        rail: Some(rail.to_string()),
        reason: Some(reason.to_string()),
        close,
        excess,
        rate: rate.map(str::to_string),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed refund for {token} as intent {id}");
    Ok(())
}
