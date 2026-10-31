//! onboardctl: the reviewer's three decisions at a terminal, and a way to read
//! one application's state.
//!
//! It is deliberately the smallest possible writer. Each decision is filed as an
//! intent and nothing else: the drain applies it on its next minute, exactly as
//! a click on a signed link would. That is what makes `onboardctl approve` the
//! equivalent of the review email's first link, and it is also why there is no
//! privileged work here at all. Root runs it, but it holds no key and touches no
//! account.
//!
//! Usage:
//!
//!   kyriakon-onboardctl [--config PATH] approve <username>
//!   kyriakon-onboardctl [--config PATH] approve-free <username>
//!   kyriakon-onboardctl [--config PATH] decline <username>
//!   kyriakon-onboardctl [--config PATH] address --domain <domain> --action <change> \
//!       --mailbox <account> [--address <localpart>] [--key-file <path>] \
//!       [--site-owner <account>]
//!   kyriakon-onboardctl [--config PATH] group remove <domain>
//!   kyriakon-onboardctl [--config PATH] token resend <username>
//!   kyriakon-onboardctl [--config PATH] credit (--token <t> | --username <u> | --note <text>) \
//!       --rail <cash|cash-hand|monero> --amount <gbp> --received <YYYY-MM-DD>
//!   kyriakon-onboardctl [--config PATH] prepaid list --window open [--expiring <days>]
//!   kyriakon-onboardctl [--config PATH] reconcile list
//!   kyriakon-onboardctl [--config PATH] reconcile attribute <UN-id> --token <t>
//!   kyriakon-onboardctl [--config PATH] reconcile return <UN-id> --note <evidence>
//!   kyriakon-onboardctl [--config PATH] payment show --username <u>
//!   kyriakon-onboardctl [--config PATH] refund (--token <t> | --username <u>) \
//!       --rail <card|cash|cash-hand|monero> --amount <gbp> --reason <text> \
//!       (--close | --excess) [--rate <gbp-per-xmr>]
//!   kyriakon-onboardctl [--config PATH] refund (--token <t> | --username <u>) \
//!       --settled <YYYY-MM-DD>
//!   kyriakon-onboardctl [--config PATH] show <username>
//!   kyriakon-onboardctl [--config PATH] free
//!   kyriakon-onboardctl request list
//!   kyriakon-onboardctl request record
//!   kyriakon-onboardctl request extend <id>
//!   kyriakon-onboardctl request close <id>
//!
//! The flags the three writing verbs take are in `usage`, which is the one copy
//! of the text.
//!
//! The `request` verbs write the data-subject request record straight into the
//! account's store directory. They are root's, like the decisions: the record is
//! the member's data and the account directory is not the handler's to write.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use kyriakon_onboard::config::DrainConfig;
use kyriakon_onboard::intents;
use kyriakon_onboard::prepaid;
use kyriakon_onboard::requests;
use kyriakon_onboard::sign;
use kyriakon_onboard::store::{self, free_account_count, KeyRecord, Record, Store};
use kyriakon_onboard::transitions::{self, Decision};
use kyriakon_onboard::util;
use kyriakon_onboard::validate;
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
        "request" => request(&store, &rest[1..]).await,
        "address" => address(&cfg, &store, &rest[1..]).await,
        "group" => group(&cfg, &store, &rest[1..]).await,
        "token" => token(&cfg, &store, &rest[1..]).await,
        "credit" => credit(&cfg, &store, &rest[1..]).await,
        "prepaid" => prepaid(&store, &rest[1..]).await,
        "reconcile" => reconcile(&cfg, &store, &rest[1..]).await,
        "payment" => payment(&store, &rest[1..]).await,
        "refund" => refund(&cfg, &store, &rest[1..]).await,
        "show" => show(&store, one_username(rest)?).await,
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
     approve|approve-free|decline|show <username>
       kyriakon-onboardctl free
       kyriakon-onboardctl token resend <username>
       kyriakon-onboardctl credit (--token <t> | --username <u> | --note <text>) \
     --rail <cash|cash-hand|monero> --amount <gbp> --received <YYYY-MM-DD> \
     [--txid <id>] [--xmr <amount>] [--override <reason>] [--confirm-double]
       kyriakon-onboardctl prepaid list --window open [--expiring <days>]
       kyriakon-onboardctl reconcile list
       kyriakon-onboardctl reconcile attribute <UN-id> --token <t> \
     [--confirm-double] [--override <reason>]
       kyriakon-onboardctl reconcile return <UN-id> --note <evidence>
       kyriakon-onboardctl payment show --username <u>
       kyriakon-onboardctl refund (--token <t> | --username <u>) \
     --rail <card|cash|cash-hand|monero> --amount <gbp> --reason <text> \
     (--close | --excess) [--rate <gbp-per-xmr>]
       kyriakon-onboardctl refund (--token <t> | --username <u>) \
     --settled <YYYY-MM-DD>
       kyriakon-onboardctl address --domain <domain> \
     --action <add-alias|add-mailbox|upgrade|remove> --mailbox <account> \
     [--address <localpart>] [--key-file <path>] [--site-owner <account>]
       kyriakon-onboardctl group remove <domain>
       kyriakon-onboardctl request list
       kyriakon-onboardctl request record --username <u> --kind <access|erasure|rectification> \
     --received <YYYY-MM-DD> --evidence <text> [--note <text>] \
     [--identity-at <YYYY-MM-DD>] [--fee-at <YYYY-MM-DD>] [--id <ulid>] \
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
    let text = store
        .read_record(&format!("accounts/{username}"), "account.json")
        .await
        .ok_or_else(|| format!("no account for {username}"))?;
    let account: kyriakon_onboard::store::Account = serde_json::from_str(&text)
        .map_err(|e| format!("the account record does not parse: {e}"))?;
    let token = account
        .payment_state()
        .and_then(|p| p.token_ref)
        .ok_or_else(|| {
            format!("{username} was approved without charge, so there is no payment token")
        })?;
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(&key, &sign::resend_payload(username, &token))?;
    let id = intents::file_resend(store, username, &token, &sig).await?;
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
            let text = store
                .read_record(&format!("accounts/{username}"), "account.json")
                .await
                .ok_or_else(|| format!("no account for {username}"))?;
            let account: kyriakon_onboard::store::Account = serde_json::from_str(&text)
                .map_err(|e| format!("the account record does not parse: {e}"))?;
            account
                .payment_state()
                .and_then(|p| p.token_ref)
                .ok_or_else(|| format!("{username} has no payment token to credit"))?
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
    if util::parse_date(received).is_none() {
        return Err(format!("--received {received:?} is not YYYY-MM-DD"));
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
    let id = intents::file_credit(
        store,
        &token,
        rail,
        amount,
        received,
        txid,
        xmr,
        confirm_double,
        override_reason,
        note,
        &sig,
    )
    .await?;
    let what = if token.is_empty() {
        "a payment with no token".to_string()
    } else {
        token.clone()
    };
    println!("filed credit for {what} as intent {id}");
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
    let id = intents::file_reconcile_attribute(
        store,
        item,
        token,
        confirm_double,
        override_reason,
        &sig,
    )
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
    let id = intents::file_reconcile_return(store, item, note, &sig).await?;
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
            let text = store
                .read_record(&format!("accounts/{username}"), "account.json")
                .await
                .ok_or_else(|| format!("no account for {username}"))?;
            let account: kyriakon_onboard::store::Account = serde_json::from_str(&text)
                .map_err(|e| format!("the account record does not parse: {e}"))?;
            account
                .payment_state()
                .and_then(|p| p.token_ref)
                .ok_or_else(|| format!("{username} has no payment token"))
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
        let id = intents::file_refund(
            store,
            &token,
            None,
            None,
            None,
            false,
            false,
            None,
            Some(settled),
            &sig,
        )
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
    let id = intents::file_refund(
        store,
        &token,
        Some(amount),
        Some(rail),
        Some(reason),
        close,
        excess,
        rate,
        None,
        &sig,
    )
    .await?;
    println!("filed refund for {token} as intent {id}");
    Ok(())
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
            Some(KeyRecord {
                mailbox: mailbox.to_string(),
                fingerprint: String::new(),
                material,
                verdict: "unchecked".to_string(),
            })
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
    let id = intents::file_group_address(
        store,
        domain,
        action,
        address,
        mailbox,
        mail_key.as_ref(),
        site_owner,
        &sig,
    )
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
    let id = intents::file_remove_group(store, domain, &sig).await?;
    println!("filed group remove for {domain} as intent {id}");
    Ok(())
}

async fn request(store: &Store, args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("record") => request_record(store, &args[1..]).await,
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
        println!(
            "{}  {}  {}  received {}  due {}  {state}",
            line.id, line.username, line.kind, line.received, due
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
    let id = intents::file_decision(
        store,
        decision.kind,
        decision.action,
        username,
        &token,
        &sig,
    )
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
    let text = store
        .read_record(&format!("accounts/{username}"), "account.json")
        .await
        .ok_or_else(|| format!("no account for {username}"))?;
    let account: store::Account = serde_json::from_str(&text)
        .map_err(|e| format!("the account record does not parse: {e}"))?;
    let Some(payment) = account.payment_state() else {
        return Err(format!(
            "{username} was approved without charge, so there is no payment to show"
        ));
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
    for line in store.json_lines("ledger/payments.jsonl").await? {
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
    match store
        .read_record(&format!("accounts/{username}"), "account.json")
        .await
    {
        Some(text) => {
            let account: kyriakon_onboard::store::Account = serde_json::from_str(&text)
                .map_err(|e| format!("the account record does not parse: {e}"))?;
            println!("account {username}");
            println!("  state    {}", account.state);
            println!("  decision {}", account.decision);
            // A group mailbox holds no payment of its own: the group does. The
            // payment block is absent for exactly that reason, and printing
            // "no charge" would answer a money question wrongly.
            if let Some(group) = &account.group {
                println!("  group    {group}");
                println!("  token    held by the group");
                println!("  paid     held by the group, in groups/{group}/group.json");
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
        let Some(text) = store.read_record("applications", &name).await else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<Record>(&text) else {
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
}
