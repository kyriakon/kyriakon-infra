//! The notice verbs: the operator's half of the bounce safeguard.
//!
//! A lifecycle notice that hard-bounces at every address an account holds has
//! stopped that account's grace clock. The drain will not delete an account in
//! that state, and this is the one command that clears it: it sends the notice
//! again over a channel the operator knows works, records the send, and gives
//! the account a fresh forty days.

use crate::*;

/// `notice resend <username> [--to <address>]`: send the lifecycle notice again
/// and restart the grace. The address defaults to the account's platform
/// mailbox, which a lapsed or suspended account can still read; `--to` names a
/// channel outside the platform when the mailbox is the thing that failed.
pub(crate) async fn notices(
    cfg: &DrainConfig,
    store: &Store,
    args: &[String],
) -> Result<(), Error> {
    let (verb, rest) = match args {
        [verb, rest @ ..] => (verb.as_str(), rest),
        _ => return Err(Error::Failed(usage())),
    };
    if verb != "resend" {
        return Err(Error::Failed(usage()));
    }
    let (username, rest) = match rest {
        [username, rest @ ..] => (username.as_str(), rest),
        _ => return Err(Error::Failed(usage())),
    };
    let flags = flags(rest, &["to"])?;
    let (to, grace) = transitions::lifecycle::resend_notice(
        cfg,
        store,
        username,
        flags.get("to").map(String::as_str),
    )
    .await?;
    println!("re-sent the lifecycle notice for {username} to {to}; the grace now ends {grace}");
    Ok(())
}
