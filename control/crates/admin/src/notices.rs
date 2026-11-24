//! The notice verbs: the operator's half of the bounce safeguard.
//!
//! A delivery report is unauthenticated inbound mail, so it is evidence, not a
//! decision: the drain records it and alerts. `notice stop` is the decision that
//! holds the grace clock, and `notice resend` is the one command that clears it:
//! it sends the notice again over a channel the operator knows works, records
//! the send, and gives the account a fresh forty days.

use crate::*;

/// `notice stop <username>`: hold the account's deletion after a permanent
/// failure is recorded for every address its lifecycle notices went to.
pub(crate) async fn notices(
    cfg: &DrainConfig,
    store: &Store,
    args: &[String],
) -> Result<(), Error> {
    let (verb, rest) = match args {
        [verb, rest @ ..] => (verb.as_str(), rest),
        _ => return Err(Error::Failed(usage())),
    };
    let (username, rest) = match rest {
        [username, rest @ ..] => (username.as_str(), rest),
        _ => return Err(Error::Failed(usage())),
    };
    match verb {
        "stop" => {
            flags(rest, &[])?;
            let stop = transitions::lifecycle::stop_notice(store, username).await?;
            println!(
                "held {username}: {} reported {} on {}. The grace clock is stopped; \
                 `kyriakon-admin notice resend {username}` clears it once a channel works.",
                stop.address, stop.status, stop.at
            );
            Ok(())
        }
        "resend" => {
            let flags = flags(rest, &["to", "group"])?;
            let (to, grace) = transitions::lifecycle::resend_notice(
                cfg,
                store,
                username,
                flags.get("to").map(String::as_str),
                flags.get("group").map(String::as_str),
            )
            .await?;
            println!(
                "re-sent the lifecycle notice for {username} to {to}; the grace now ends {grace}"
            );
            Ok(())
        }
        _ => Err(Error::Failed(usage())),
    }
}
