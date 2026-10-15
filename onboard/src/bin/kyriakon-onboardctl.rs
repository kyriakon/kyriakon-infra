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
//!   kyriakon-onboardctl [--config PATH] show <username>

use std::path::PathBuf;
use std::process::ExitCode;

use kyriakon_onboard::config::DrainConfig;
use kyriakon_onboard::intents;
use kyriakon_onboard::sign;
use kyriakon_onboard::store::{Record, Store};
use kyriakon_onboard::transitions::{self, Decision};
use kyriakon_onboard::validate;

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
    let verb = rest.first().map(String::as_str).unwrap_or("");
    let username = rest.get(1).map(String::as_str);
    let username = username.ok_or_else(usage)?;
    if rest.len() > 2 {
        return Err(usage());
    }
    if let Some(why) = validate::username_shape(username) {
        return Err(format!("the username {username:?}: {why}"));
    }
    match verb {
        "show" => show(&store, username).await,
        // Each decision is signed with the same root-only key the review links
        // are signed with, because the drain carries out a decision intent only
        // when its signature verifies, and `intents/` belongs to the
        // unprivileged half. The verb, the kind and the action come from the
        // crate's one decision list, so a verb this console takes is a decision
        // the drain knows.
        verb => {
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
     approve|approve-free|decline|show <username>"
        .to_string()
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
            println!(
                "  token    {}",
                account.token_ref.as_deref().unwrap_or("none (no charge)")
            );
            // `paid_until` is null while a window runs, so null alone says
            // nothing about whether one exists: the window does. A no-charge
            // approval has no window and never lapses, and saying it does would
            // have a member watching for one to close.
            let paid = match (&account.paid_until, &account.window) {
                (Some(until), _) => until.as_str(),
                (None, Some(_)) => "null: the window is open",
                (None, None) => "none: no charge was made, so nothing expires",
            };
            println!("  paid     {paid}");
            if let Some(w) = &account.window {
                println!("  window   {} to {}", w.opened_at, w.closes_at);
            }
        }
        None => println!("account  none yet"),
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
