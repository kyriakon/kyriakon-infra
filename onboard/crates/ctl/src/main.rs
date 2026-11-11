//! onboardctl: the reviewer's three decisions at a terminal, and a way to read
//! one application's state.
//!
//! It is deliberately the smallest possible writer. Each decision is filed as an
//! intent and nothing else: the drain applies it on its next minute, exactly as
//! a click on a signed link would. That is what makes `onboardctl approve` the
//! equivalent of the review email's first link, and it is also why there is no
//! privileged work here at all. Root runs it, but it holds no key beyond the
//! approval key and touches no account. `delete` is the one exception: the
//! lifecycle has one deletion transition and the console runs it directly, so an
//! erasure from the console and one from the page's closing sweep cannot take
//! different paths.
//!
//! Usage:
//!
//!   kyriakon-onboardctl [--config PATH] approve <username>
//!   kyriakon-onboardctl [--config PATH] approve-free <username>
//!   kyriakon-onboardctl [--config PATH] decline <username>
//!   kyriakon-onboardctl [--config PATH] delete <username>
//!   kyriakon-onboardctl [--config PATH] address --domain <domain> --action <change> \
//!       --mailbox <account> [--address <localpart>] [--key-file <path>] \
//!       [--site-owner <account>]
//!   kyriakon-onboardctl [--config PATH] group remove <domain>
//!   kyriakon-onboardctl [--config PATH] token resend <username>
//!   kyriakon-onboardctl [--config PATH] credit (--token <t> | --username <u> | --note <text>) \
//!       --rail <cash|cash-hand|monero> --amount <gbp> --received <YYYY-MM-DD>
//!   kyriakon-onboardctl [--config PATH] prepaid list --window open [--expiring <days>]
//!   kyriakon-onboardctl [--config PATH] window extend --token <t> --days 14 \
//!       --reason <text>
//!   kyriakon-onboardctl [--config PATH] reconcile list
//!   kyriakon-onboardctl [--config PATH] reconcile attribute <UN-id> --token <t>
//!   kyriakon-onboardctl [--config PATH] reconcile return <UN-id> --note <evidence>
//!   kyriakon-onboardctl [--config PATH] payment show --username <u>
//!   kyriakon-onboardctl [--config PATH] monero address <username> <address>
//!   kyriakon-onboardctl [--config PATH] refund (--token <t> | --username <u>) \
//!       --rail <card|cash|cash-hand|monero> --amount <gbp> --reason <text> \
//!       (--close | --excess) [--rate <gbp-per-xmr>]
//!   kyriakon-onboardctl [--config PATH] refund (--token <t> | --username <u>) \
//!       --settled <YYYY-MM-DD>
//!   kyriakon-onboardctl [--config PATH] export <username> [--by-mail] [--request <id>]
//!   kyriakon-onboardctl [--config PATH] show <username>
//!   kyriakon-onboardctl [--config PATH] free
//!   kyriakon-onboardctl request list
//!   kyriakon-onboardctl request record
//!   kyriakon-onboardctl request verify
//!   kyriakon-onboardctl request extend <id>
//!   kyriakon-onboardctl request close <id>
//!
//! The flags the three writing verbs take are in `usage`, which is the one copy
//! of the text.
//!
//! The `request` verbs write the data-subject request record straight into the
//! account's store directory, and `monero address` writes the subaddress the
//! operator's own wallet made. They are root's, like the decisions: the record is
//! the member's data and the account directory is not the handler's to write.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use kyriakon_onboard_core::account::export;
use kyriakon_onboard_core::account::requests as account_requests;
use kyriakon_onboard_core::account::sign;
use kyriakon_onboard_core::config::DrainConfig;
use kyriakon_onboard_core::flow::validate;
use kyriakon_onboard_core::intent;
use kyriakon_onboard_core::intent::Decision;
use kyriakon_onboard_core::mail::keycheck;
use kyriakon_onboard_core::payments::ledger::{Ledger, LedgerLine};
use kyriakon_onboard_core::store::journal::Journal;
use kyriakon_onboard_core::store::{self, free_account_count, Record, Store};
use kyriakon_onboard_core::util;
use kyriakon_onboard_drain::prepaid;
use kyriakon_onboard_drain::transitions;
use serde_json::Value;
use time::OffsetDateTime;

const DEFAULT_CONFIG: &str = "/etc/kyriakon/onboard/drain.toml";

mod error;
pub(crate) use error::Error;

mod account;
mod address;
mod decisions;
mod group;
mod payments;
mod requests;

use account::{delete, free, resume, show, suspend};
use address::address;
use decisions::sign_and_file;
use group::group;
use payments::credit::{credit, token, window};
use payments::ledger::ledger;
use payments::monero::monero;
use payments::payment::payment;
use payments::prepaid::{prepaid, reconcile};
use payments::refund::refund;
use requests::request;

#[tokio::main]
async fn main() -> ExitCode {
    let mut cfg_path = std::env::var("KYRIAKON_DRAIN_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG));
    let mut rest = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            match args.next() {
                Some(p) => cfg_path = PathBuf::from(p),
                None => {
                    eprintln!("kyriakon-onboardctl: --config needs a path");
                    return ExitCode::FAILURE;
                }
            }
        } else {
            rest.push(arg);
        }
    }
    match run(&cfg_path, &rest).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            e.report("the console");
            ExitCode::FAILURE
        }
    }
}

async fn run(cfg_path: &std::path::Path, rest: &[String]) -> Result<(), Error> {
    let cfg = DrainConfig::load(cfg_path)?;
    let store = Store::new(&cfg.store_root);
    let Some(verb) = rest.first().map(String::as_str) else {
        return Err(Error::Failed(usage()));
    };
    match verb {
        "request" => request(&cfg, &store, &rest[1..]).await,
        "address" => address(&cfg, &store, &rest[1..]).await,
        "group" => group(&cfg, &store, &rest[1..]).await,
        "token" => token(&cfg, &store, &rest[1..]).await,
        "credit" => credit(&cfg, &store, &rest[1..]).await,
        "prepaid" => prepaid(&store, &rest[1..]).await,
        "window" => window(&cfg, &store, &rest[1..]).await,
        "reconcile" => reconcile(&cfg, &store, &rest[1..]).await,
        "payment" => payment(&store, &rest[1..]).await,
        "monero" => monero(&store, &rest[1..]).await,
        "refund" => refund(&cfg, &store, &rest[1..]).await,
        "ledger" => ledger(&store, &rest[1..]).await,
        "export" => export(&cfg, &store, &rest[1..]).await,
        "show" => show(&store, one_username(rest)?).await,
        "suspend" => suspend(&cfg, &store, &rest[1..]).await,
        "resume" => resume(&cfg, &store, rest).await,
        "delete" => delete(&cfg, &store, rest).await,
        "free" => free(&store, &rest[1..]).await,
        // Each decision is signed with the same root-only key the review links
        // are signed with, because the drain carries out a decision intent only
        // when its signature verifies, and `intents/` belongs to the
        // unprivileged half. The verb, the kind and the action come from the
        // crate's one decision list, so a verb this console takes is a decision
        // the drain knows.
        verb => {
            let username = one_username(rest)?;
            let Some(decision) = intent::decision_for(verb) else {
                return Err(Error::Failed(usage()));
            };
            let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
            sign_and_file(&store, &key, decision, username).await
        }
    }
}

fn usage() -> String {
    "usage: kyriakon-onboardctl [--config PATH] \
     approve|approve-free|decline|delete|show <username>
       kyriakon-onboardctl suspend <username> --reason <text>
       kyriakon-onboardctl resume <username>
       kyriakon-onboardctl free
       kyriakon-onboardctl token resend <username>
       kyriakon-onboardctl credit (--token <t> | --username <u> | --note <text>) \
     --rail <cash|cash-hand|monero> --amount <gbp> --received <YYYY-MM-DD> \
     [--txid <id>] [--xmr <amount>] [--override <reason>] [--confirm-double]
       kyriakon-onboardctl prepaid list --window open [--expiring <days>]
       kyriakon-onboardctl window extend --token <t> --days 14 --reason <text>
       kyriakon-onboardctl reconcile list
       kyriakon-onboardctl reconcile attribute <UN-id> --token <t> \
     [--confirm-double] [--override <reason>]
       kyriakon-onboardctl reconcile return <UN-id> --note <evidence>
       kyriakon-onboardctl payment show --username <u>
       kyriakon-onboardctl monero address <username> <address>
       kyriakon-onboardctl refund (--token <t> | --username <u>) \
     --rail <card|cash|cash-hand|monero> --amount <gbp> --reason <text> \
     (--close | --excess) [--rate <gbp-per-xmr>]
       kyriakon-onboardctl refund (--token <t> | --username <u>) \
     --settled <YYYY-MM-DD>
       kyriakon-onboardctl ledger export --tax-year <YYYY-YY|YYYY-YYYY> \
     --format csv
       kyriakon-onboardctl export <username> [--by-mail] [--request <id>]
       kyriakon-onboardctl address --domain <domain> \
     --action <add-alias|add-mailbox|upgrade|remove> --mailbox <account> \
     [--address <localpart>] [--key-file <path>] [--site-owner <account>]
       kyriakon-onboardctl group remove <domain>
       kyriakon-onboardctl request list
       kyriakon-onboardctl request record --username <u> --kind <access|erasure|rectification> \
     --received <YYYY-MM-DD> --evidence <text> --identity <password|mail-key> \
     [--note <text>] [--identity-at <YYYY-MM-DD>] [--fee-at <YYYY-MM-DD>] [--id <ulid>] \
       kyriakon-onboardctl request verify --username <u> --message <file> \
     [--signature <file>] \
       kyriakon-onboardctl request extend <id> --reason <text> \
     [--extended-on <YYYY-MM-DD>] \
       kyriakon-onboardctl request close <id> --done <YYYY-MM-DD> --note <text>"
        .to_string()
}

/// The one username a verb that takes one reads. `request` and `free` take none.
fn one_username(rest: &[String]) -> Result<&str, Error> {
    let username = match rest {
        [_, username] => username.as_str(),
        _ => return Err(Error::Failed(usage())),
    };
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::Failed(format!("the username {username:?}: {why}")));
    }
    Ok(username)
}

type Flags = BTreeMap<String, String>;

/// `--flag value` pairs for one subcommand. A repeated flag is refused rather
/// than letting the last one win: this record is evidence, and a typo that
/// silently replaced a date would be a wrong clock.
fn flags(args: &[String], known: &[&str]) -> Result<Flags, Error> {
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let flag = &args[i];
        let Some(name) = flag.strip_prefix("--") else {
            return Err(Error::Failed(format!(
                "unexpected argument {flag:?}\n{}",
                usage()
            )));
        };
        if !known.contains(&name) {
            return Err(Error::Failed(format!("unknown flag {flag:?}\n{}", usage())));
        }
        let Some(value) = args.get(i + 1) else {
            return Err(Error::Failed(format!("{flag} needs a value")));
        };
        if out.insert(name.to_string(), value.clone()).is_some() {
            return Err(Error::Failed(format!("{flag} is given twice")));
        }
        i += 2;
    }
    Ok(out)
}

fn need<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, Error> {
    flags
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| Error::Failed(format!("--{name} is needed")))
}

/// `export <username>`: the written part of the member's data export.
///
/// It goes into the member's own sftp chroot, with a ready notice, because that
/// is the delivery path they already have. `--by-mail` is the member who cannot
/// log in but still holds their key: the same written part, as one attachment
/// encrypted to that public key. `--request <id>` records how the bundle was
/// delivered on the data-subject request line that asked for it.
///
/// Root's, like the request verbs: it reads one account's directory and writes
/// into the member's home. It never reads the Maildir, which it could not read
/// anyway.
async fn export(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), Error> {
    let Some(username) = args.first().map(String::as_str) else {
        return Err(Error::Failed(usage()));
    };
    if username.starts_with("--") {
        return Err(Error::Failed(usage()));
    }
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::Failed(format!("the username {username:?}: {why}")));
    }
    let rest = &args[1..];
    let by_mail = rest.iter().any(|arg| arg == "--by-mail");
    let paired: Vec<String> = rest
        .iter()
        .filter(|arg| arg.as_str() != "--by-mail")
        .cloned()
        .collect();
    let flags = flags(&paired, &["request"])?;
    let delivered = if by_mail {
        export::deliver_by_mail(cfg, store, username).await?
    } else {
        export::deliver(cfg, store, username).await?
    };
    println!("{username}: {delivered}");
    if let Some(id) = flags.get("request") {
        let line = account_requests::set_bundle(store, id, username, &delivered).await?;
        println!("request {}: bundle recorded", line.id);
    }
    Ok(())
}

/// One payment column: the header the accountant reads and how to print it.
type PaymentColumn = (&'static str, fn(&LedgerLine) -> String);

#[cfg(test)]
mod tests;
