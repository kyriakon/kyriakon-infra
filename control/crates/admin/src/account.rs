//! One job of the operator console.

use crate::payments::{group_payment, print_payment};
use crate::Error;
use crate::*;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Print what the store holds for a username: the application, while it is
/// inside ADR 0005's window, and the account once an approval has made one. The
/// purge deletes the application after ninety days, so it is optional here and
/// an account with none still prints its state and payment.
pub(crate) async fn show(store: &Store, username: &str) -> Result<(), Error> {
    let account = store.account(username).await?;
    match find_application(store, username).await? {
        Some((token, record)) => {
            println!("application {username} (token {token})");
            println!("  filed    {}", record.filed_at);
            println!("  stage    {}", record.stage);
            println!("  rail     {}", record.rail);
            println!(
                "  decided  {}",
                record.decided_at.as_deref().unwrap_or("not yet")
            );
        }
        None if account.is_some() => {
            println!("application {username} purged (ADR 0005's 90-day window)");
        }
        None => return Err(Error::Failed(format!("no application for {username}"))),
    }
    match account {
        Some(account) => {
            println!("account {username}");
            println!("  state    {}", account.state);
            println!("  decision {}", account.decision);
            // A group mailbox holds no payment of its own: the group does. The
            // console prints the group's one rail, token, window and date, which
            // is what the body's page shows too.
            if let Some(group) = &account.group {
                println!("  group    {group}");
                let Some(record) = store.group(group).await? else {
                    println!("  payment  no group record at groups/{group}/group.json");
                    return Ok(());
                };
                let payment = group_payment(&record.payment);
                print_payment(&payment, record.payment.no_charge);
                return Ok(());
            }
            // A free account has no payment block at all: no window, no token,
            // and nothing that lapses.
            let Some(payment) = account.payment_state() else {
                println!("  token    none (no charge)");
                println!("  paid     none: no charge was made, so nothing expires");
                return Ok(());
            };
            print_payment(&payment, false);
        }
        None => println!("account  none yet"),
    }
    Ok(())
}

/// `suspend`: the AUP ladder's suspension, run now, because it is the operator's
/// decision and nothing about it is routine. The reason is required: the notice
/// and the account page both carry it, and a suspension with no words for the
/// member is not the state contract #153 decided.
pub(crate) async fn suspend(
    cfg: &DrainConfig,
    store: &Store,
    rest: &[String],
) -> Result<(), Error> {
    let (username, args) = match rest {
        [username, args @ ..] => (username.as_str(), args),
        _ => return Err(Error::Failed(usage())),
    };
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::Failed(format!("the username {username:?}: {why}")));
    }
    let flags = flags(args, &["reason"])?;
    let reason = need(&flags, "reason")?;
    let journal = Journal::load(store).await?;
    transitions::lifecycle::suspend(cfg, store, &journal, username, reason).await?;
    println!("suspended {username}");
    Ok(())
}

/// `resume`: lift a suspension, the inverse of `suspend`. The three access
/// paths come back, the state returns to active, and the reason and grace the
/// suspension started are cleared.
pub(crate) async fn resume(cfg: &DrainConfig, store: &Store, rest: &[String]) -> Result<(), Error> {
    let username = one_username(rest)?;
    let journal = Journal::load(store).await?;
    transitions::lifecycle::resume(cfg, store, &journal, username).await?;
    println!("resumed {username}");
    Ok(())
}

/// `delete`: the lifecycle's one deletion transition, run now. The page's
/// closure reaches the same function through the drain's closing sweep, so an
/// erasure from the console and one from the page cannot differ. No flag: a
/// deletion erases the account it names and nothing about the deletion is
/// optional.
pub(crate) async fn delete(cfg: &DrainConfig, store: &Store, rest: &[String]) -> Result<(), Error> {
    let username = one_username(rest)?;
    // A name with no record and no deletion journal line is not an account this
    // service made. Refusing here keeps a typo from printing "deleted" and from
    // touching a keyring or token entry. A deletion that stopped partway is
    // still accepted: the account record has gone but its journal line has not.
    let recorded = store.account(username).await?.is_some();
    let interrupted = store
        .log("journal.jsonl")
        .jsonl::<Value>()
        .await?
        .iter()
        .any(|value| {
            value
                .get("intent")
                .and_then(Value::as_str)
                .is_some_and(|id| owns_delete(id, username))
        });
    if !recorded && !interrupted {
        return Err(Error::Failed(format!("no account for {username}")));
    }
    let journal = Journal::load(store).await?;
    transitions::lifecycle::delete_account(cfg, store, &journal, username).await?;
    println!("deleted {username}");
    Ok(())
}

/// Whether a journal line's id names this account's deletion: `delete-<name>-`
/// followed by an RFC 3339 timestamp, the id shape `delete_account` writes.
///
/// A hyphenated account writes `delete-bo-x-<time>`, and a bare prefix match
/// makes `delete bo` claim it: the console would print "deleted bo" for an
/// erasure that never ran. The drain's `Released::owns` has the same rule.
pub(crate) fn owns_delete(id: &str, username: &str) -> bool {
    id.strip_prefix(&format!("delete-{username}-"))
        .is_some_and(|created| OffsetDateTime::parse(created, &Rfc3339).is_ok())
}

/// `free`: how many accounts were approved without charge. The count is read
/// from the accounts themselves rather than kept beside them, so it cannot
/// drift; a group mailbox is not counted, because the group holds the payment.
pub(crate) async fn free(store: &Store, rest: &[String]) -> Result<(), Error> {
    if !rest.is_empty() {
        return Err(Error::Failed(usage()));
    }
    match free_account_count(store).await? {
        1 => println!("1 account without charge"),
        n => println!("{n} accounts without charge"),
    }
    Ok(())
}

/// The newest application filed for a username, or `None` when the store holds
/// none. The front-end never checks whether a name exists, so more than one can
/// be on disk, and this is only `show`'s summary of the newest; a decision names
/// its application by token rather than starting here. A record that cannot be
/// read is an error, not an absence: the purge leaves no file, and damage is a
/// different thing.
pub(crate) async fn find_application(
    store: &Store,
    username: &str,
) -> Result<Option<(String, Record)>, Error> {
    let mut best: Option<(String, Record)> = None;
    for name in store.list("applications").await? {
        if !name.ends_with(".json") {
            continue;
        }
        let Some(record) = store.application(name.trim_end_matches(".json")).await? else {
            continue;
        };
        if record.username != username {
            continue;
        }
        let better = best
            .as_ref()
            .map(|(_, b)| record.filed_at > b.filed_at)
            .unwrap_or(true);
        if better {
            best = Some((record.status_token.clone(), record));
        }
    }
    Ok(best)
}
