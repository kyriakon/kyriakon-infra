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

use kyriakon_onboard::config::DrainConfig;
use kyriakon_onboard::export;
use kyriakon_onboard::intents;
use kyriakon_onboard::journal::Journal;
use kyriakon_onboard::keycheck;
use kyriakon_onboard::prepaid;
use kyriakon_onboard::requests;
use kyriakon_onboard::sign;
use kyriakon_onboard::store::{self, free_account_count, Record, Store};
use kyriakon_onboard::transitions::{self, Decision};
use kyriakon_onboard::util;
use kyriakon_onboard::validate;
use serde_json::Value;
use time::OffsetDateTime;

const DEFAULT_CONFIG: &str = "/etc/kyriakon/onboard/drain.toml";

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
            eprintln!("kyriakon-onboardctl: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cfg_path: &std::path::Path, rest: &[String]) -> Result<(), String> {
    let cfg = DrainConfig::load(cfg_path)?;
    let store = Store::new(&cfg.store_root);
    let Some(verb) = rest.first().map(String::as_str) else {
        return Err(usage());
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
            let Some(decision) = transitions::decision_for(verb) else {
                return Err(usage());
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
fn one_username(rest: &[String]) -> Result<&str, String> {
    let username = match rest {
        [_, username] => username.as_str(),
        _ => return Err(usage()),
    };
    if let Some(why) = validate::username_shape(username) {
        return Err(format!("the username {username:?}: {why}"));
    }
    Ok(username)
}

/// `--flag value` pairs for one subcommand. A repeated flag is refused rather
/// than letting the last one win: this record is evidence, and a typo that
/// silently replaced a date would be a wrong clock.
fn flags(args: &[String], known: &[&str]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let flag = &args[i];
        let Some(name) = flag.strip_prefix("--") else {
            return Err(format!("unexpected argument {flag:?}\n{}", usage()));
        };
        if !known.contains(&name) {
            return Err(format!("unknown flag {flag:?}\n{}", usage()));
        }
        let Some(value) = args.get(i + 1) else {
            return Err(format!("{flag} needs a value"));
        };
        if out.insert(name.to_string(), value.clone()).is_some() {
            return Err(format!("{flag} is given twice"));
        }
        i += 2;
    }
    Ok(out)
}

fn need<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    flags
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("--{name} is needed"))
}

/// `token resend <username>`: the member's payment instructions again, with the
/// token their account already holds. Nothing is minted, because a second token
/// would leave the first one in the ledger as an entry that no longer resolves
/// to the same member and would orphan a payment already in flight.
///
/// The account is read here, at the terminal, so a member who was approved
/// without charge, or one with no account yet, is a refusal the operator sees
/// now rather than an intent the drain refuses a minute later.
async fn token(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
    let (verb, username) = match args {
        [verb, username] if verb == "resend" => (verb.as_str(), username.as_str()),
        _ => return Err(usage()),
    };
    if let Some(why) = validate::username_shape(username) {
        return Err(format!("the username {username:?}: {why}"));
    }
    let account = store
        .account(username)
        .await?
        .ok_or_else(|| format!("no account for {username}"))?;
    let token = account
        .payment_state()
        .and_then(|p| p.token_ref)
        .ok_or_else(|| {
            format!("{username} was approved without charge, so there is no payment token")
        })?;
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(&key, &sign::resend_payload(username, &token))?;
    let id = intents::Intent::Resend(transitions::ResendIntent {
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
async fn credit(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
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
            "token", "username", "rail", "amount", "received", "txid", "xmr", "override", "note",
        ],
    )?;
    let note = match flags.get("note") {
        Some(text) if text.trim().is_empty() => return Err("--note is empty".to_string()),
        Some(text) => Some(text.as_str()),
        None => None,
    };
    let token = match (flags.get("token"), flags.get("username"), note) {
        (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
            return Err(
                "--note is for a payment with no token: give neither --token nor --username"
                    .to_string(),
            )
        }
        (None, None, Some(_)) => String::new(),
        (Some(token), None, None) => {
            if !store::is_payment_token(token) {
                return Err(format!("the token {token:?} is not a payment token"));
            }
            token.clone()
        }
        (None, Some(username), None) => {
            if let Some(why) = validate::username_shape(username) {
                return Err(format!("the username {username:?}: {why}"));
            }
            let account = store
                .account(username)
                .await?
                .ok_or_else(|| format!("no account for {username}"))?;
            match account.payment_state().and_then(|p| p.token_ref) {
                Some(token) => token,
                // A group mailbox holds no payment of its own: its name
                // resolves to the one token the whole body is credited by, the
                // same join the group's page and its renewal use.
                None => match account.group.as_deref() {
                    Some(domain) => {
                        let group = transitions::group_record(store, domain)
                            .await?
                            .ok_or_else(|| format!("no group record for {domain}"))?;
                        group.payment.token_ref.ok_or_else(|| {
                            format!("the group {domain} has no payment token to credit")
                        })?
                    }
                    None => {
                        return Err(format!("{username} has no payment token to credit"));
                    }
                },
            }
        }
        (Some(_), Some(_), None) => {
            return Err("give either --token or --username, not both".to_string())
        }
        (None, None, None) => return Err("give --token, --username or --note".to_string()),
    };
    let rail = need(&flags, "rail")?;
    if !transitions::CREDIT_RAILS.contains(&rail) {
        return Err(format!(
            "--rail {rail:?} is not one of {}",
            transitions::CREDIT_RAILS.join(", ")
        ));
    }
    // Cash in hand is the one rail keyed by a username: the operator was there
    // and the drain resolves the name to a token before it writes anything. A
    // hand payment with no name has nothing to be joined to, by construction.
    if note.is_some() && rail == "cash-hand" {
        return Err(
            "cash in hand is credited against a username; give --username, not --note".to_string(),
        );
    }
    let amount = need(&flags, "amount")?;
    match util::pence(amount) {
        Ok(pence) if pence > 0 => {}
        Ok(_) => return Err("--amount must be more than zero".to_string()),
        Err(e) => return Err(format!("--amount: {e}")),
    }
    let received = need(&flags, "received")?;
    let received_date = match util::parse_date(received) {
        Some(date) => date,
        None => return Err(format!("--received {received:?} is not YYYY-MM-DD")),
    };
    // The drain measures the ceiling from this date, and a year it cannot hold
    // has no paid-until date: refuse it here rather than file an intent the
    // drain will only refuse later.
    if util::received_beyond_window(received_date, requests::today()) {
        return Err(format!(
            "--received {received:?} is more than two years ahead"
        ));
    }
    let txid = flags.get("txid").map(String::as_str);
    let xmr = flags.get("xmr").map(String::as_str);
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
            confirm_double,
            override_reason,
            note,
        ),
    )?;
    let id = intents::Intent::Credit(transitions::CreditIntent {
        token: token.clone(),
        rail: rail.to_string(),
        amount_gbp: amount.to_string(),
        received: received.to_string(),
        txid: txid.map(str::to_string),
        amount_xmr: xmr.map(str::to_string),
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
async fn window(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
    let (verb, rest) = match args {
        [verb, rest @ ..] => (verb.as_str(), rest),
        _ => return Err(usage()),
    };
    if verb != "extend" {
        return Err(usage());
    }
    let flags = flags(rest, &["token", "days", "reason"])?;
    let token = need(&flags, "token")?;
    if !store::is_payment_token(token) {
        return Err(format!("the token {token:?} is not a payment token"));
    }
    let days = need(&flags, "days")?
        .parse::<i64>()
        .map_err(|_| "--days is not a whole number".to_string())?;
    if days != 14 {
        return Err("a window extension is fourteen days and no other number".to_string());
    }
    let reason = need(&flags, "reason")?;
    if reason.trim().is_empty() {
        return Err("--reason must say why the window is being extended".to_string());
    }
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(&key, &sign::window_extend_payload(token, days, reason))?;
    let id = intents::Intent::WindowExtend(transitions::WindowExtendIntent {
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

/// `prepaid list --window open [--expiring <days>]`: the first command of the
/// operator's weekly pass. Only an open window is asked for; any other value is
/// refused rather than answered with a list that means something else.
async fn prepaid(store: &Store, args: &[String]) -> Result<(), String> {
    let (verb, rest) = match args {
        [verb, rest @ ..] => (verb.as_str(), rest),
        _ => return Err(usage()),
    };
    if verb != "list" {
        return Err(usage());
    }
    let flags = flags(rest, &["window", "expiring"])?;
    let window = need(&flags, "window")?;
    if window != "open" {
        return Err(format!(
            "--window {window:?} is not open; only the open windows are listed"
        ));
    }
    let expiring = match flags.get("expiring") {
        Some(text) => Some(
            text.parse::<i64>()
                .ok()
                .filter(|days| *days >= 0)
                .ok_or_else(|| format!("--expiring {text:?} is not a whole number of days"))?,
        ),
        None => None,
    };
    let rows: Vec<_> = prepaid::open_windows(store, OffsetDateTime::now_utc())
        .await?
        .into_iter()
        .filter(|row| prepaid::closes_within(row.days_left, expiring))
        .collect();
    println!("{} open window(s)", rows.len());
    for row in rows {
        println!(
            "{}  {}  {}  closes {}  {} days left",
            row.token, row.username, row.rail, row.closes_on, row.days_left
        );
    }
    Ok(())
}

/// `reconcile`: the queue of money that arrived with no token.
async fn reconcile(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
    match args {
        [verb] if verb == "list" => reconcile_list(store).await,
        [verb, rest @ ..] if verb == "attribute" => reconcile_attribute(cfg, store, rest).await,
        [verb, rest @ ..] if verb == "return" => reconcile_return(cfg, store, rest).await,
        _ => Err(usage()),
    }
}

/// Print every held item: what the operator can still join to an account or
/// close with the evidence.
async fn reconcile_list(store: &Store) -> Result<(), String> {
    let held: Vec<_> = store
        .held()
        .await?
        .into_iter()
        .filter(|line| line.state == "held")
        .collect();
    if held.is_empty() {
        println!("nothing held");
        return Ok(());
    }
    println!("{} held payment(s)", held.len());
    for line in held {
        println!(
            "{}  {}  {}  received {}  {}",
            line.id,
            line.rail,
            line.amount_gbp,
            line.received_on,
            line.note.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

/// `reconcile attribute <UN-id> --token <t>`: join held money to an account as
/// an ordinary credit. Both shapes are checked here, so a mistyped id or token
/// is a refusal at the terminal rather than an intent the drain refuses later.
async fn reconcile_attribute(
    cfg: &DrainConfig,
    store: &Store,
    args: &[String],
) -> Result<(), String> {
    let (item, rest) = match args {
        [item, rest @ ..] if !item.starts_with("--") => (item.as_str(), rest),
        _ => return Err(usage()),
    };
    if !store::is_unattributed_id(item) {
        return Err(format!(
            "the held item {item:?} is not an unattributed payment id"
        ));
    }
    // `--confirm-double` is a bare switch, which the pair reader does not take.
    let confirm_double = rest.iter().any(|a| a == "--confirm-double");
    let paired: Vec<String> = rest
        .iter()
        .filter(|a| a.as_str() != "--confirm-double")
        .cloned()
        .collect();
    let flags = flags(&paired, &["token", "override"])?;
    let token = need(&flags, "token")?;
    if !store::is_payment_token(token) {
        return Err(format!("the token {token:?} is not a payment token"));
    }
    let override_reason = flags.get("override").map(String::as_str);
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(
        &key,
        &sign::reconcile_attribute_payload(item, token, confirm_double, override_reason),
    )?;
    let id = intents::Intent::ReconcileAttribute(transitions::AttributeIntent {
        item: item.to_string(),
        token: token.to_string(),
        confirm_double,
        override_reason: override_reason.map(str::to_string),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed reconcile attribute for {item} as intent {id}");
    Ok(())
}

/// `reconcile return <UN-id> --note <evidence>`: close held money with what
/// happened to it. The evidence is the record, so an empty one is refused here.
async fn reconcile_return(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
    let (item, rest) = match args {
        [item, rest @ ..] if !item.starts_with("--") => (item.as_str(), rest),
        _ => return Err(usage()),
    };
    if !store::is_unattributed_id(item) {
        return Err(format!(
            "the held item {item:?} is not an unattributed payment id"
        ));
    }
    let flags = flags(rest, &["note"])?;
    let note = need(&flags, "note")?;
    if note.trim().is_empty() {
        return Err("--note is empty; name the evidence the return was made on".to_string());
    }
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(&key, &sign::reconcile_return_payload(item, note))?;
    let id = intents::Intent::ReconcileReturn(transitions::ReturnIntent {
        item: item.to_string(),
        note: note.to_string(),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed reconcile return for {item} as intent {id}");
    Ok(())
}

/// The token a `credit` or `refund` acts on: `--token` itself, or the token the
/// named account's payment block holds, resolved here at the terminal so a name
/// with no token is a refusal the operator sees now rather than an intent the
/// drain refuses a minute later.
async fn payment_token(store: &Store, flags: &BTreeMap<String, String>) -> Result<String, String> {
    match (flags.get("token"), flags.get("username")) {
        (Some(token), None) => {
            if !store::is_payment_token(token) {
                return Err(format!("the token {token:?} is not a payment token"));
            }
            Ok(token.clone())
        }
        (None, Some(username)) => {
            if let Some(why) = validate::username_shape(username) {
                return Err(format!("the username {username:?}: {why}"));
            }
            let account = store
                .account(username)
                .await?
                .ok_or_else(|| format!("no account for {username}"))?;
            match account.payment_state().and_then(|p| p.token_ref) {
                Some(token) => Ok(token),
                // A group mailbox holds no payment of its own, so its name
                // resolves to the one token the whole body paid by, the same
                // join `credit` uses.
                None => match account.group.as_deref() {
                    Some(domain) => {
                        let group = transitions::group_record(store, domain)
                            .await?
                            .ok_or_else(|| format!("no group record for {domain}"))?;
                        group.payment.token_ref.ok_or_else(|| {
                            format!("the group {domain} has no payment token to refund")
                        })
                    }
                    None => Err(format!("{username} has no payment token")),
                },
            }
        }
        (Some(_), Some(_)) => Err("give either --token or --username, not both".to_string()),
        (None, None) => Err("give --token or --username".to_string()),
    }
}

/// `refund`: either record a refund against the payment its token last made, or
/// settle one already recorded. The refund form names the money, the rail, why
/// and whether the account closes; the settlement form names only the day. A
/// `--username` is resolved to the account's token here, as `credit` does, and
/// the signature covers every field the drain acts on.
async fn refund(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
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
                return Err(format!("--settled takes no --{name}"));
            }
        }
        if close || excess {
            return Err("--settled takes no --close or --excess".to_string());
        }
        if util::parse_date(settled).is_none() {
            return Err(format!("--settled {settled:?} is not YYYY-MM-DD"));
        }
        let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
        let sig = sign::sign(
            &key,
            &sign::refund_payload(&token, "", "", false, false, "", settled, ""),
        )?;
        let id = intents::Intent::Refund(transitions::RefundIntent {
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
    if !transitions::REFUND_RAILS.contains(&rail) {
        return Err(format!(
            "--rail {rail:?} is not one of {}",
            transitions::REFUND_RAILS.join(", ")
        ));
    }
    let amount = need(&flags, "amount")?;
    match util::pence(amount) {
        Ok(pence) if pence > 0 => {}
        Ok(_) => return Err("--amount must be more than zero".to_string()),
        Err(e) => return Err(format!("--amount: {e}")),
    }
    let reason = need(&flags, "reason")?;
    if reason.trim().is_empty() {
        return Err("--reason must say why the money is going back".to_string());
    }
    if close == excess {
        return Err("give exactly one of --close or --excess".to_string());
    }
    let rate = flags.get("rate").map(String::as_str);
    if let Some(rate) = rate {
        if rail != "monero" {
            return Err("--rate is only a monero refund paid in sterling".to_string());
        }
        match util::pence(rate) {
            Ok(pence) if pence > 0 => {}
            Ok(_) => return Err("--rate must be more than zero".to_string()),
            Err(e) => return Err(format!("--rate: {e}")),
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
    let id = intents::Intent::Refund(transitions::RefundIntent {
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

/// `ledger export --tax-year <year> --format csv`: the year's lines for the
/// accountant. It reads `ledger/payments.jsonl` in place and prints; nothing is
/// written, because the ledger is the record and the file is never purged. The
/// held money in `ledger/unattributed.jsonl` is not income until it is
/// attributed, so it follows the keyed rows in a section of its own rather than
/// as a row without a token.
async fn ledger(store: &Store, args: &[String]) -> Result<(), String> {
    let rest = match args {
        [verb, rest @ ..] if verb == "export" => rest,
        _ => return Err(usage()),
    };
    let flags = flags(rest, &["tax-year", "format"])?;
    let (start, end) = tax_year(need(&flags, "tax-year")?)?;
    let format = need(&flags, "format")?;
    if format != "csv" {
        return Err(format!("--format {format:?} is not csv"));
    }
    let fields = [
        "seq",
        "token",
        "kind",
        "rail",
        "received_on",
        "amount_gbp",
        "applied_gbp",
        "paid_until_after",
        "amount_xmr",
        "txid",
        "refund_of",
        "settled_on",
        "rate_quoted",
        "rate_source",
        "rate_at",
    ];
    println!("{}", fields.join(","));

    let mut rows = Vec::new();
    for row in store.log("ledger/payments.jsonl").jsonl::<Value>().await? {
        if !in_tax_year(&row, start, end) {
            continue;
        }
        rows.push((row["seq"].as_u64().unwrap_or(0), row));
    }
    rows.sort_by_key(|(seq, _)| *seq);
    for (_, row) in rows {
        let cells: Vec<String> = fields
            .iter()
            .map(|field| csv_cell(&cell(&row[*field])))
            .collect();
        println!("{}", cells.join(","));
    }

    println!();
    println!("# unattributed");
    println!("id,rail,received_on,amount_gbp");
    for row in store
        .log("ledger/unattributed.jsonl")
        .jsonl::<Value>()
        .await?
    {
        if row["state"].as_str() != Some("held") || !in_tax_year(&row, start, end) {
            continue;
        }
        let cells: Vec<String> = ["id", "rail", "received_on", "amount_gbp"]
            .iter()
            .map(|field| csv_cell(&cell(&row[*field])))
            .collect();
        println!("{}", cells.join(","));
    }
    Ok(())
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
async fn export(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
    let Some(username) = args.first().map(String::as_str) else {
        return Err(usage());
    };
    if username.starts_with("--") {
        return Err(usage());
    }
    if let Some(why) = validate::username_shape(username) {
        return Err(format!("the username {username:?}: {why}"));
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
        let line = requests::set_bundle(store, id, username, &delivered).await?;
        println!("request {}: bundle recorded", line.id);
    }
    Ok(())
}

/// Whether a ledger row's `received_on` falls in the half-open-by-year tax
/// window it is exported for. A row with no date, such as the approval's
/// `window_open`, is not in any year.
fn in_tax_year(row: &Value, start: time::Date, end: time::Date) -> bool {
    row.get("received_on")
        .and_then(Value::as_str)
        .and_then(util::parse_date)
        .is_some_and(|date| date >= start && date <= end)
}

/// A tax year's bounds: the `YYYY-YY` or `YYYY-YYYY` spelling, 6 April to the
/// following 5 April inclusive. The second year is not accepted on trust: a
/// mistyped pair would quietly export a different year's money.
fn tax_year(s: &str) -> Result<(time::Date, time::Date), String> {
    let refuse = || {
        format!("--tax-year {s:?} is not YYYY-YY or YYYY-YYYY, or its years are not consecutive")
    };
    let (first, second) = s.split_once('-').ok_or_else(refuse)?;
    if first.len() != 4 || !first.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refuse());
    }
    let year: i32 = first.parse().map_err(|_| refuse())?;
    let next = year.checked_add(1).ok_or_else(refuse)?;
    let second_ok = match second.len() {
        2 => {
            second.bytes().all(|b| b.is_ascii_digit())
                && second.parse::<i32>().map_err(|_| refuse())? == next.rem_euclid(100)
        }
        4 => {
            second.bytes().all(|b| b.is_ascii_digit())
                && second.parse::<i32>().map_err(|_| refuse())? == next
        }
        _ => return Err(refuse()),
    };
    if !second_ok {
        return Err(refuse());
    }
    let start =
        time::Date::from_calendar_date(year, time::Month::April, 6).map_err(|_| refuse())?;
    let end = time::Date::from_calendar_date(next, time::Month::April, 5).map_err(|_| refuse())?;
    Ok((start, end))
}

/// One ledger value as the CSV cell it prints as. A missing or null field is an
/// empty cell; a number keeps its own spelling.
fn cell(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// RFC 4180: a comma, a quote or a line break in a cell puts the whole cell in
/// quotes, and a quote inside it is doubled. The ledger's free text can carry
/// any of the three, though the export never prints `note`.
fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// File one address change in a group. The signature is the console's, over
/// every field the drain acts on: an address intent creates a root account or
/// removes one, and `intents/` is writable by the unprivileged handler.
///
/// `--key-file` is the new mailbox's armored public key, read here and carried
/// in the intent so the drain installs it in the keyring and publishes it.
async fn address(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
    let flags = flags(
        args,
        &[
            "domain",
            "action",
            "address",
            "mailbox",
            "key-file",
            "site-owner",
        ],
    )?;
    let domain = need(&flags, "domain")?;
    if let Some(why) = validate::domain(domain) {
        return Err(format!("the domain {domain:?}: {why}"));
    }
    let action = need(&flags, "action")?;
    if !transitions::ADDRESS_ACTIONS.contains(&action) {
        return Err(format!(
            "--action {action:?} is not one of {:?}\n{}",
            transitions::ADDRESS_ACTIONS,
            usage()
        ));
    }
    let mailbox = need(&flags, "mailbox")?;
    if let Some(why) = validate::username_shape(mailbox) {
        return Err(format!("the mailbox {mailbox:?}: {why}"));
    }
    let address = flags.get("address").map(String::as_str).unwrap_or("");
    if action != "remove" {
        if address.is_empty() {
            return Err("--address is needed for this change".to_string());
        }
        if let Some(why) = validate::username_shape(address) {
            return Err(format!("the address {address:?}: {why}"));
        }
    }
    let site_owner = flags.get("site-owner").map(String::as_str);
    if let Some(owner) = site_owner {
        if let Some(why) = validate::username_shape(owner) {
            return Err(format!("the site owner {owner:?}: {why}"));
        }
    }
    let mail_key = match flags.get("key-file") {
        Some(path) => {
            let material = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read the mail key {path}: {e}"))?;
            if material.trim().is_empty() {
                return Err(format!("the mail key {path} is empty"));
            }
            // The same check the responder and the portal run, so a console
            // submission cannot file a mailbox the pages would have refused:
            // the fingerprint and verdict are computed from the material, never
            // left blank or "unchecked" for something that is not a key.
            let record = keycheck::mail_key(mailbox.to_string(), &material);
            if record.fingerprint.is_empty() {
                let why = keycheck::pgp_public_key(&material)
                    .err()
                    .unwrap_or_else(|| "it carries no key packet".to_string());
                return Err(format!("the mail key {path}: {why}"));
            }
            Some(record)
        }
        None => None,
    };
    if matches!(action, "add-mailbox" | "upgrade") && mail_key.is_none() {
        return Err("--key-file is needed for a new mailbox".to_string());
    }
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(
        &key,
        &sign::address_payload(
            domain,
            action,
            address,
            mailbox,
            site_owner.unwrap_or(""),
            mail_key.as_ref().map(|k| k.material.as_str()).unwrap_or(""),
        ),
    )?;
    let id = intents::Intent::GroupAddress(store::GroupAddressIntent {
        domain: domain.to_string(),
        action: action.to_string(),
        address: address.to_string(),
        mailbox: mailbox.to_string(),
        mail_key: mail_key.clone(),
        site_owner: site_owner.map(str::to_string),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed {action} for {domain} as intent {id}");
    Ok(())
}

/// `group remove <domain>`: take a body's domain down and close every account
/// in it. Signed here, because the transition deletes accounts, and the drain
/// refuses a domain that has no group record.
async fn group(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
    let [verb, domain] = args else {
        return Err(usage());
    };
    if verb != "remove" {
        return Err(usage());
    }
    if let Some(why) = validate::domain(domain) {
        return Err(format!("the domain {domain:?}: {why}"));
    }
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(&key, &sign::group_remove_payload(domain))?;
    let id = intents::Intent::RemoveGroup(store::GroupRemoveIntent {
        domain: domain.to_string(),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed group remove for {domain} as intent {id}");
    Ok(())
}

async fn request(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("record") => request_record(store, &args[1..]).await,
        Some("verify") => request_verify(cfg, store, &args[1..]).await,
        Some("extend") => request_extend(store, &args[1..]).await,
        Some("close") => request_close(store, &args[1..]).await,
        Some("list") => request_list(store).await,
        _ => Err(usage()),
    }
}

async fn request_record(store: &Store, args: &[String]) -> Result<(), String> {
    let flags = flags(
        args,
        &[
            "username",
            "kind",
            "received",
            "evidence",
            "identity",
            "note",
            "identity-at",
            "fee-at",
            "id",
        ],
    )?;
    let line = requests::record(
        store,
        requests::NewRequest {
            username: need(&flags, "username")?,
            kind: need(&flags, "kind")?,
            received: need(&flags, "received")?,
            evidence: need(&flags, "evidence")?,
            identity: need(&flags, "identity")?,
            note: flags.get("note").map(String::as_str),
            identity_at: flags.get("identity-at").map(String::as_str),
            fee_at: flags.get("fee-at").map(String::as_str),
            id: flags.get("id").map(String::as_str),
        },
    )
    .await?;
    println!("recorded {}; answer due {}", line.id, line.due);
    Ok(())
}

/// `request verify`: the mail-key route's check. It reads a message and an
/// optional detached signature, refuses anything not from the account's own
/// platform address, and verifies the signature against the keyring entry the
/// platform encrypts to. It writes nothing: verification is the check the
/// operator records afterwards with `request record --identity mail-key`.
async fn request_verify(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), String> {
    let flags = flags(args, &["username", "message", "signature"])?;
    let username = need(&flags, "username")?;
    if let Some(why) = validate::username_shape(username) {
        return Err(format!("the username {username:?}: {why}"));
    }
    let account = store
        .account(username)
        .await?
        .ok_or_else(|| format!("no account for {username}"))?;
    let own = account.platform_address();

    let message_path = std::path::Path::new(need(&flags, "message")?);
    let message = std::fs::read(message_path)
        .map_err(|e| format!("cannot read {}: {e}", message_path.display()))?;
    let signature = match flags.get("signature") {
        Some(path) => Some(std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?),
        None => None,
    };

    let from = message_from(&String::from_utf8_lossy(&message))?;
    if !from.eq_ignore_ascii_case(&own) {
        let outside = account
            .outside_address
            .as_deref()
            .is_some_and(|address| address.eq_ignore_ascii_case(&from));
        return Err(if outside {
            format!(
                "the message is from {from}, the account's outside contact address; \
                 ask for a message from {own} signed with the mail key, or for the \
                 password route on the account page"
            )
        } else {
            format!("the message is from {from}, not the account's own address {own}")
        });
    }
    let key_file = keycheck::keyring_file(&cfg.keyring_dir, username);
    if !key_file.is_file() {
        return Err(format!(
            "the box holds no key for {username} at {}",
            key_file.display()
        ));
    }
    if signature.is_none() && !String::from_utf8_lossy(&message).contains(CLEARSIGNED) {
        return Err(
            "the message is not clearsigned; pass --signature with its detached signature \
             or export the message clearsigned from the client"
                .to_string(),
        );
    }
    let fingerprint =
        keycheck::verify_signature(&cfg.gpg, &key_file, &message, signature.as_deref())
            .await?
            .ok_or_else(|| {
                format!("the signature does not verify against {username}'s keyring entry")
            })?;
    println!("verified {fingerprint}; From: {own}");
    Ok(())
}

const CLEARSIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----";

/// The address in a message's `From:` header. A delivered message carries its
/// own headers outside the armour, and a client's clearsigned export carries
/// them inside it. The outer block is read first and the armour's is the
/// fallback, and a `From:` in both that disagrees is refused: the signature is
/// the proof, so the outer header adds no forgeable path.
fn message_from(message: &str) -> Result<String, String> {
    let message = message.replace("\r\n", "\n");
    let (outer, armour) = match message.split_once(CLEARSIGNED) {
        Some((outer, rest)) => {
            let body = rest
                .split_once("\n\n")
                .map(|(_, body)| body)
                .ok_or("the clearsigned message has no blank line after its armour")?;
            let body = body
                .split_once("\n-----BEGIN PGP SIGNATURE-----")
                .map(|(body, _)| body)
                .unwrap_or(body);
            (outer, Some(body))
        }
        None => (message.as_str(), None),
    };
    let outer = header_from(outer)?;
    let armour = match armour {
        Some(armour) => header_from(armour)?,
        None => None,
    };
    match (outer, armour) {
        (Some(outer), Some(armour)) if !outer.eq_ignore_ascii_case(&armour) => Err(format!(
            "the message's own From: is {outer} but the clearsigned one is {armour}"
        )),
        (Some(outer), _) => Ok(outer),
        (None, Some(armour)) => Ok(armour),
        (None, None) => Err("the message has no From: header".to_string()),
    }
}

/// The address in one header block's `From:`, with RFC 5322 continuation lines
/// unfolded first. `None` when the block carries no `From:`.
fn header_from(block: &str) -> Result<Option<String>, String> {
    let mut headers: Vec<String> = Vec::new();
    for line in block.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.push(' ');
                last.push_str(line.trim());
            }
        } else {
            headers.push(line.trim_end().to_string());
        }
    }
    let mut values = headers.iter().filter_map(|header| {
        let (name, value) = header.split_once(':')?;
        name.eq_ignore_ascii_case("from")
            .then(|| value.trim().to_string())
    });
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("the message has more than one From: header".to_string());
    }
    let address = match (value.rfind('<'), value.rfind('>')) {
        (Some(open), Some(close)) if open < close => &value[open + 1..close],
        _ => value.as_str(),
    };
    if address.trim().is_empty() {
        return Err("the message's From: header holds no address".to_string());
    }
    Ok(Some(address.trim().to_string()))
}

async fn request_extend(store: &Store, args: &[String]) -> Result<(), String> {
    let (id, rest) = match args {
        [id, rest @ ..] if !id.starts_with("--") => (id.as_str(), rest),
        _ => return Err(usage()),
    };
    let flags = flags(rest, &["reason", "extended-on"])?;
    let line = requests::extend(
        store,
        id,
        need(&flags, "reason")?,
        flags.get("extended-on").map(String::as_str),
    )
    .await?;
    println!(
        "extended {}; answer due {} (was {})",
        line.id,
        line.effective_due(),
        line.due
    );
    Ok(())
}

async fn request_close(store: &Store, args: &[String]) -> Result<(), String> {
    let (id, rest) = match args {
        [id, rest @ ..] if !id.starts_with("--") => (id.as_str(), rest),
        _ => return Err(usage()),
    };
    let flags = flags(rest, &["done", "note"])?;
    let line = requests::close(store, id, need(&flags, "done")?, need(&flags, "note")?).await?;
    println!(
        "closed {} (done {})",
        line.id,
        line.done_at.as_deref().unwrap_or("")
    );
    Ok(())
}

async fn request_list(store: &Store) -> Result<(), String> {
    let open = requests::open(store).await?;
    if open.is_empty() {
        println!("no open requests");
        return Ok(());
    }
    let today = requests::today();
    let mut nearly = 0;
    let mut overdue = 0;
    let mut rows = Vec::new();
    for line in open {
        let state = match line
            .state(today)
            .map_err(|e| format!("request {}: {e}", line.id))?
        {
            requests::DueState::Overdue => {
                overdue += 1;
                "OVERDUE"
            }
            requests::DueState::NearlyDue => {
                nearly += 1;
                "nearly due"
            }
            requests::DueState::Open => "open",
        };
        let due = if line.extended_until.is_some() {
            format!("{} (extended from {})", line.effective_due(), line.due)
        } else {
            line.effective_due().to_string()
        };
        rows.push((line, due, state));
    }
    println!(
        "{} open request(s), {nearly} nearly due, {overdue} overdue",
        rows.len()
    );
    for (line, due, state) in rows {
        let identity = if line.identity.is_empty() {
            "unrecorded"
        } else {
            &line.identity
        };
        println!(
            "{}  {}  {}  identity {}  received {}  due {}  {state}",
            line.id, line.username, line.kind, identity, line.received, due
        );
    }
    Ok(())
}

/// Sign one decision and file it as an intent. The application it names is
/// looked up by username now, at the terminal, so the intent carries the token
/// the drain keys on and not a name a second application could share. The action
/// and its signature go with it, so the drain carries the decision out only if it
/// was signed under the approval key.
async fn sign_and_file(
    store: &Store,
    key: &[u8],
    decision: &Decision,
    username: &str,
) -> Result<(), String> {
    let (token, _record) = find_application(store, username).await?;
    let sig = sign::sign(key, &sign::decide_payload(&token, decision.action))?;
    let id = intents::Intent::Decision(transitions::DecisionIntent {
        kind: decision.kind.to_string(),
        application: store::ApplicationRef::application(username.to_string(), token.clone()),
        action: decision.action.to_string(),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed {} for {username} as intent {id}", decision.kind);
    Ok(())
}

/// `payment show --username <u>`: the account's rail, paid-until date and every
/// ledger line keyed by its token. The ledger is read strictly, so a corrupt
/// record is an error rather than a payment history that looks empty.
async fn payment(store: &Store, args: &[String]) -> Result<(), String> {
    let [verb, rest @ ..] = args else {
        return Err(usage());
    };
    if verb != "show" {
        return Err(usage());
    }
    let flags = flags(rest, &["username"])?;
    let username = need(&flags, "username")?;
    if let Some(why) = validate::username_shape(username) {
        return Err(format!("the username {username:?}: {why}"));
    }
    let account = store
        .account(username)
        .await?
        .ok_or_else(|| format!("no account for {username}"))?;
    // A group mailbox holds no payment block: the group holds the one rail, the
    // one token and the one date, so a mailbox's name prints those.
    let payment = match account.payment_state() {
        Some(payment) => payment,
        None => match account.group.as_deref() {
            Some(domain) => {
                let group = transitions::group_record(store, domain)
                    .await?
                    .ok_or_else(|| format!("no group record for {domain}"))?;
                if group.payment.no_charge {
                    return Err(format!(
                        "{domain} was approved without charge, so there is no payment to show"
                    ));
                }
                store::Payment {
                    token_ref: group.payment.token_ref.clone(),
                    paid_until: group.payment.paid_until.clone(),
                    window: group.payment.window.clone(),
                    rail: Some(group.payment.rail.clone()),
                    ..store::Payment::default()
                }
            }
            None => {
                return Err(format!(
                    "{username} was approved without charge, so there is no payment to show"
                ));
            }
        },
    };
    let Some(token) = payment.token_ref.as_deref() else {
        return Err(format!("{username} has no payment token"));
    };
    println!("account {username}");
    println!(
        "  rail     {}",
        payment.rail.as_deref().unwrap_or(&account.rail)
    );
    let paid = match (&payment.paid_until, &payment.window) {
        (Some(until), _) => until.as_str(),
        (None, Some(_)) => "null: the window is open",
        (None, None) => "null: no window was opened",
    };
    println!("  paid     {paid}");
    println!("  token    {token}");

    println!("ledger for {token}");
    let mut any = false;
    for line in store.log("ledger/payments.jsonl").jsonl::<Value>().await? {
        if line.get("token").and_then(serde_json::Value::as_str) != Some(token) {
            continue;
        }
        any = true;
        let seq = line
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".to_string());
        let get = |key: &str| {
            line.get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
        };
        let mut extra = String::new();
        if let Some(of) = line.get("refund_of").and_then(serde_json::Value::as_u64) {
            extra.push_str(&format!("  refund_of {of}"));
        }
        if let Some(on) = line.get("settled_on").and_then(serde_json::Value::as_str) {
            extra.push_str(&format!("  settled_on {on}"));
        }
        println!(
            "  {seq:>5}  {:<8}  {:<4}  {}  {}  applied {}{}",
            get("kind"),
            get("rail"),
            get("received_on"),
            get("amount_gbp"),
            get("applied_gbp"),
            extra,
        );
    }
    if !any {
        println!("  no ledger lines");
    }
    Ok(())
}

/// Print what the store holds for a username: the application and, once an
/// approval has made one, the account.
async fn show(store: &Store, username: &str) -> Result<(), String> {
    let (token, record) = find_application(store, username).await?;
    println!("application {username} (token {token})");
    println!("  filed    {}", record.filed_at);
    println!("  stage    {}", record.stage);
    println!("  rail     {}", record.rail);
    println!(
        "  decided  {}",
        record.decided_at.as_deref().unwrap_or("not yet")
    );
    match store.account(username).await? {
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
                let payment = &record.payment;
                println!("  rail     {}", payment.rail);
                let paid = match (&payment.paid_until, &payment.window) {
                    (Some(until), _) => until.as_str(),
                    (None, Some(_)) => "null: the window is open",
                    (None, None) => "null: no window was opened",
                };
                println!("  paid     {paid}");
                println!(
                    "  token    {}",
                    payment.token_ref.as_deref().unwrap_or("none (no charge)")
                );
                if let Some(w) = &payment.window {
                    println!("  window   {} to {}", w.opened_at, w.closes_at);
                }
                return Ok(());
            }
            // A free account has no payment block at all: no window, no token,
            // and nothing that lapses.
            let Some(payment) = account.payment_state() else {
                println!("  token    none (no charge)");
                println!("  paid     none: no charge was made, so nothing expires");
                return Ok(());
            };
            println!(
                "  token    {}",
                payment.token_ref.as_deref().unwrap_or("none")
            );
            // `paid_until` is null while a window runs, so null alone says
            // nothing about whether one exists: the window does.
            let paid = match (&payment.paid_until, &payment.window) {
                (Some(until), _) => until.as_str(),
                (None, Some(_)) => "null: the window is open",
                (None, None) => "null: no window was opened",
            };
            println!("  paid     {paid}");
            if let Some(w) = &payment.window {
                println!("  window   {} to {}", w.opened_at, w.closes_at);
            }
        }
        None => println!("account  none yet"),
    }
    Ok(())
}

/// `suspend`: the AUP ladder's suspension, run now, because it is the operator's
/// decision and nothing about it is routine. The reason is required: the notice
/// and the account page both carry it, and a suspension with no words for the
/// member is not the state contract #153 decided.
async fn suspend(cfg: &DrainConfig, store: &Store, rest: &[String]) -> Result<(), String> {
    let (username, args) = match rest {
        [username, args @ ..] => (username.as_str(), args),
        _ => return Err(usage()),
    };
    if let Some(why) = validate::username_shape(username) {
        return Err(format!("the username {username:?}: {why}"));
    }
    let flags = flags(args, &["reason"])?;
    let reason = need(&flags, "reason")?;
    let journal = Journal::load(store).await?;
    transitions::suspend(cfg, store, &journal, username, reason).await?;
    println!("suspended {username}");
    Ok(())
}

/// `resume`: lift a suspension, the inverse of `suspend`. The three access
/// paths come back, the state returns to active, and the reason and grace the
/// suspension started are cleared.
async fn resume(cfg: &DrainConfig, store: &Store, rest: &[String]) -> Result<(), String> {
    let username = one_username(rest)?;
    let journal = Journal::load(store).await?;
    transitions::resume(cfg, store, &journal, username).await?;
    println!("resumed {username}");
    Ok(())
}

/// `delete`: the lifecycle's one deletion transition, run now. The page's
/// closure reaches the same function through the drain's closing sweep, so an
/// erasure from the console and one from the page cannot differ. No flag: a
/// deletion erases the account it names and nothing about the deletion is
/// optional.
async fn delete(cfg: &DrainConfig, store: &Store, rest: &[String]) -> Result<(), String> {
    let username = one_username(rest)?;
    // A name with no record and no deletion journal line is not an account this
    // service made. Refusing here keeps a typo from printing "deleted" and from
    // touching a keyring or token entry. A deletion that stopped partway is
    // still accepted: the account record has gone but its journal line has not.
    let recorded = store.account(username).await?.is_some();
    let prefix = format!("delete-{username}-");
    let interrupted = store
        .log("journal.jsonl")
        .jsonl::<Value>()
        .await?
        .iter()
        .any(|value| {
            value
                .get("intent")
                .and_then(Value::as_str)
                .is_some_and(|id| id.starts_with(&prefix))
        });
    if !recorded && !interrupted {
        return Err(format!("no account for {username}"));
    }
    let journal = Journal::load(store).await?;
    transitions::delete_account(cfg, store, &journal, username).await?;
    println!("deleted {username}");
    Ok(())
}

/// `monero address <username> <address>`: record the subaddress the operator's
/// own wallet made for this member. The account is read and written here, at the
/// terminal, because root runs it and the address is the operator's own fact;
/// the account page then shows it rather than saying it is not ready.
///
/// One per account and permanent: the same address again is a replay that says
/// so, and a different one is refused rather than rotated, because the first
/// may already have been sent a payment and reusing it for somebody else would
/// join money to the wrong account.
async fn monero(store: &Store, args: &[String]) -> Result<(), String> {
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
    transitions::write_account_record(store, username, &bytes).await?;
    transitions::write_payment_copy(store, username, &payment).await?;
    println!("recorded Monero subaddress for {username}: {address}");
    Ok(())
}

/// A mainnet Monero subaddress: 95 base58 characters beginning with `8`, the
/// shape `monero-wallet-cli` gives a subaddress. The checksum is the wallet's to
/// verify; this refuses a truncated paste and a standard address (which begins
/// `4`), which are the two ways a wrong value would look right in a store.
fn monero_address_shape(address: &str) -> Option<&'static str> {
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

/// `free`: how many accounts were approved without charge. The count is read
/// from the accounts themselves rather than kept beside them, so it cannot
/// drift; a group mailbox is not counted, because the group holds the payment.
async fn free(store: &Store, rest: &[String]) -> Result<(), String> {
    if !rest.is_empty() {
        return Err(usage());
    }
    match free_account_count(store).await? {
        1 => println!("1 account without charge"),
        n => println!("{n} accounts without charge"),
    }
    Ok(())
}

/// The newest application filed for a username. The front-end never checks
/// whether a name exists, so more than one can be on disk; the one the reviewer
/// means is the one filed last.
async fn find_application(store: &Store, username: &str) -> Result<(String, Record), String> {
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
    best.ok_or_else(|| format!("no application for {username}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_read_pairs_and_refuse_a_bad_shape() {
        let map = flags(
            &args(&["--username", "alice", "--kind", "access"]),
            &["username", "kind"],
        )
        .unwrap();
        assert_eq!(map["username"], "alice");
        assert_eq!(map["kind"], "access");

        assert!(flags(&args(&["--nope", "x"]), &["username"])
            .unwrap_err()
            .contains("unknown flag"));
        assert!(flags(
            &args(&["--username", "a", "--username", "b"]),
            &["username"]
        )
        .unwrap_err()
        .contains("given twice"));
        assert!(flags(&args(&["--username"]), &["username"])
            .unwrap_err()
            .contains("needs a value"));
        assert!(flags(&args(&["alice"]), &["username"])
            .unwrap_err()
            .contains("unexpected argument"));
    }

    #[test]
    fn one_username_takes_exactly_one_valid_name() {
        let show = args(&["show", "alice"]);
        assert_eq!(one_username(&show).unwrap(), "alice");
        assert!(one_username(&args(&["show"])).is_err());
        assert!(one_username(&args(&["show", "alice", "extra"])).is_err());
        assert!(one_username(&args(&["show", "Alice"]))
            .unwrap_err()
            .contains("starts with"));
    }

    #[test]
    fn a_tax_year_is_six_april_to_five_april_in_either_spelling() {
        let (start, end) = tax_year("2026-27").unwrap();
        assert_eq!(start.to_string(), "2026-04-06");
        assert_eq!(end.to_string(), "2027-04-05");
        assert_eq!(tax_year("2026-2027").unwrap(), (start, end));

        // The two spellings agree across the century's end, where the
        // two-digit form wraps and the four-digit one does not.
        let (start, end) = tax_year("2099-00").unwrap();
        assert_eq!(start.to_string(), "2099-04-06");
        assert_eq!(end.to_string(), "2100-04-05");
        assert_eq!(tax_year("2099-2100").unwrap(), (start, end));

        for bad in [
            "2026-28",
            "2026-2026",
            "2026-26",
            "2026-2",
            "2026",
            "26-27",
            "2026-27-1",
            "abcd-ef",
        ] {
            assert!(tax_year(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_csv_cell_is_quoted_only_when_it_has_to_be() {
        assert_eq!(csv_cell("cash"), "cash");
        assert_eq!(csv_cell("20.00"), "20.00");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_cell("a\nb"), "\"a\nb\"");
        assert_eq!(csv_cell("a\rb"), "\"a\rb\"");
        assert_eq!(csv_cell(""), "");
    }

    const SIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n\
                          From: Alice <alice@kyriakon.net>\n\nPlease send me a copy.\n\
                          -----BEGIN PGP SIGNATURE-----\n\nAAAA\n\
                          -----END PGP SIGNATURE-----\n";

    #[test]
    fn a_delivered_message_takes_its_from_outside_the_armour() {
        let message = format!(
            "From: Alice <alice@kyriakon.net>\nTo: admin@kyriakon.net\n\
             Subject: my data\n\n{SIGNED}"
        );
        assert_eq!(message_from(&message).unwrap(), "alice@kyriakon.net");
    }

    #[test]
    fn a_folded_from_header_is_unfolded() {
        let message =
            "From: A Long Name\n <alice@kyriakon.net>\nTo: admin@kyriakon.net\n\nPlease.\n";
        assert_eq!(message_from(message).unwrap(), "alice@kyriakon.net");
    }

    #[test]
    fn an_outer_from_that_differs_from_the_armour_is_refused() {
        let message = format!("From: attacker@evil.example\nTo: admin@kyriakon.net\n\n{SIGNED}");
        let err = message_from(&message).unwrap_err();
        assert!(err.contains("attacker@evil.example"), "{err}");
        assert!(err.contains("alice@kyriakon.net"), "{err}");
    }

    #[test]
    fn a_quoted_signed_request_under_another_from_is_refused() {
        let message = format!(
            "From: attacker@evil.example\nTo: admin@kyriakon.net\nSubject: fwd\n\n\
             Here is their signed request:\n\n{SIGNED}"
        );
        assert!(message_from(&message)
            .unwrap_err()
            .contains("but the clearsigned one is alice@kyriakon.net"));
    }
}
