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
//!   kyriakon-onboardctl request list
//!   kyriakon-onboardctl request record
//!   kyriakon-onboardctl request close <id>
//!
//! The flags the two writing verbs take are in `usage`, which is the one copy
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
use kyriakon_onboard::requests;
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
    let Some(verb) = rest.first().map(String::as_str) else {
        return Err(usage());
    };
    match verb {
        "request" => request(&store, &rest[1..]).await,
        "show" => show(&store, one_username(rest)?).await,
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
       kyriakon-onboardctl request list
       kyriakon-onboardctl request record --username <u> --kind <access|erasure|rectification> \
     --received <YYYY-MM-DD> --evidence <text> [--note <text>] \
     [--identity-at <YYYY-MM-DD>] [--fee-at <YYYY-MM-DD>] [--id <ulid>] \
       kyriakon-onboardctl request close <id> --done <YYYY-MM-DD> --note <text>"
        .to_string()
}

/// The one username a verb other than `request` takes.
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

async fn request(store: &Store, args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("record") => request_record(store, &args[1..]).await,
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
        let due =
            requests::parse_date(&line.due).map_err(|e| format!("request {}: {e}", line.id))?;
        let state = match requests::due_state(due, today) {
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
        rows.push((line, state));
    }
    println!(
        "{} open request(s), {nearly} nearly due, {overdue} overdue",
        rows.len()
    );
    for (line, state) in rows {
        println!(
            "{}  {}  {}  received {}  due {}  {state}",
            line.id, line.username, line.kind, line.received, line.due
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
            // token and paid-until fields are empty for exactly that reason, and
            // printing "no charge" would answer a money question wrongly.
            if let Some(group) = &account.group {
                println!("  group    {group}");
                println!("  token    held by the group");
                println!("  paid     held by the group, in groups/{group}/group.json");
                return Ok(());
            }
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
