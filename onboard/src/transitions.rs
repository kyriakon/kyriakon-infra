//! The transitions the drain carries out: the review email a filed application
//! produces, the three outcomes a reviewer can choose, and the purge a decline
//! ends in.
//!
//! Every transition appends its journal line **before** it does the work, so a
//! crash leaves a record a rerun can read. Every decision is deduplicated on the
//! application's own state, so a click on an already-decided application changes
//! nothing and the journal records only that the click was seen.

use serde_json::{json, Value};
use time::OffsetDateTime;
use tokio::process::Command;

use crate::config::DrainConfig;
use crate::notice;
use crate::sign;
use crate::store::{
    self, Account, ApplicationRef, Intent, JournalLine, Record, Store, TokenRecord, Window,
};
use crate::util;
use crate::validate;

/// The rails an application may name. `no_charge` is the fourth, and it is a
/// rail rather than a flag because it is one of the four buttons on the form.
const RAILS: [&str; 4] = ["card", "cash", "monero", "no_charge"];

/// A reviewer's decision intent, from `onboardctl` or a signed link. The field
/// shapes here are the whole of what a decision intent carries: which
/// application, which decision, and, when it came from a link, the signed action
/// the drain checks.
#[derive(Debug, serde::Deserialize)]
pub struct DecisionIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub application: ApplicationRef,
    /// `approve`, `approve-free` or `decline` on an intent that came from a
    /// link. `None` from `onboardctl`, which is a local root action and carries
    /// no signature.
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub sig: Option<String>,
}

/// The username release and the three privileged scripts, called by their
/// configured paths so a test points the whole service at stubs.
async fn run_script(cfg: &DrainConfig, name: &str, args: &[&str]) -> Result<(), String> {
    let path = format!("{}/{}", cfg.scripts.trim_end_matches('/'), name);
    let out = Command::new(&path)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("cannot run {path}: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "{path} exited {}: {}",
            out.status,
            err.trim()
        ));
    }
    Ok(())
}

/// Append one journal line. The caller writes this before the transition, which
/// is the whole point of the journal.
async fn journal(
    store: &Store,
    intent: &str,
    kind: &str,
    application: &ApplicationRef,
    outcome: &str,
    note: Option<&str>,
) -> Result<(), String> {
    let line = JournalLine {
        version: 1,
        at: util::filed_at(),
        intent: intent.to_string(),
        kind: kind.to_string(),
        application: application.clone(),
        outcome: outcome.to_string(),
        note: note.map(str::to_string),
    };
    let encoded =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode a journal line: {e}"))?;
    store.append("journal.jsonl", encoded.as_bytes()).await
}

/// Whether the journal already holds a line for this intent id, whatever its
/// outcome. A refusal is recorded once, so two runs do not append it twice.
async fn intent_seen(store: &Store, id: &str) -> bool {
    for line in store.lines("journal.jsonl").await {
        if let Ok(j) = serde_json::from_str::<JournalLine>(&line) {
            if j.intent == id {
                return true;
            }
        }
    }
    false
}

/// Whether the journal already holds a line of this kind for this application.
/// Used for the review email, whose dedup key is the application and not the
/// intent: a re-filed application must not be mailed twice either.
async fn application_seen(store: &Store, token: &str, kind: &str, outcome: &str) -> bool {
    for line in store.lines("journal.jsonl").await {
        if let Ok(j) = serde_json::from_str::<JournalLine>(&line) {
            if j.application.status_token == token && j.kind == kind && j.outcome == outcome {
                return true;
            }
        }
    }
    false
}

/// Refuse an intent of a kind this build does not implement, by name, and leave
/// it in place. The journal records the refusal once, so two runs over the same
/// directory do not append the same line twice.
pub async fn refuse(store: &Store, file: &str, value: &Value) -> Result<(), String> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| file.trim_end_matches(".json").to_string());
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let application = value
        .get("application")
        .and_then(|a| serde_json::from_value::<ApplicationRef>(a.clone()).ok())
        .unwrap_or_else(|| ApplicationRef {
            username: String::new(),
            status_token: String::new(),
        });
    if intent_seen(store, &id).await {
        return Ok(());
    }
    journal(
        store,
        &id,
        &kind,
        &application,
        "refused",
        Some("this build does not implement this kind; the intent is left in place"),
    )
    .await
}

/// A filed application: one review email to the reviewer, carrying every answer,
/// the mail-key result, whether an upload key was supplied, the rail, whether no
/// charge was asked for, and three signed links.
pub async fn filed_application(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    text: &str,
    file: &str,
) -> Result<(), String> {
    let intent: Intent =
        serde_json::from_str(text).map_err(|e| format!("the intent does not parse: {e}"))?;
    if intent.kind != "application" {
        return Err(format!("kind {:?} is not an application", intent.kind));
    }
    if let Some(why) = validate::username_shape(&intent.application.username) {
        return Err(format!("the username: {why}"));
    }
    if !store::is_status_token(&intent.application.status_token) {
        return Err("the status token is not 128 bits of Crockford".to_string());
    }
    if !RAILS.contains(&intent.rail.as_str()) {
        return Err(format!("the rail {:?} is not one of the four", intent.rail));
    }

    // One review email per application, not per intent: the journal is the
    // record and it is written before the send, so a crash loses an email
    // rather than sending two.
    let token = &intent.application.status_token;
    if application_seen(store, token, "application", "review-sent").await {
        store.remove("intents", file).await?;
        return Ok(());
    }
    journal(
        store,
        &intent.id,
        "application",
        &intent.application,
        "review-sent",
        None,
    )
    .await?;

    let subject = format!(
        "Application {} ({})",
        intent.application.username, intent.application.status_token
    );
    let body = review_body(cfg, key, &intent)?;
    notice::enqueue(cfg, &cfg.reviewer, &subject, &body).await?;
    store.remove("intents", file).await?;
    Ok(())
}

/// The review email's body. Every field the ticket lists, and the three links
/// beside their `onboardctl` equivalents.
fn review_body(cfg: &DrainConfig, key: &[u8], intent: &Intent) -> Result<String, String> {
    let token = &intent.application.status_token;
    let mut out = String::new();
    out.push_str(&format!("Application {}\n", intent.application.username));
    out.push_str(&format!("Filed {} by the {} front end\n", intent.filed_at, intent.front_end));
    out.push_str(&format!("Question list {}\n", intent.question_list));
    out.push_str(&format!("Rail: {}\n", intent.rail));
    out.push_str(&format!(
        "No charge asked for: {}\n",
        if intent.no_charge { "yes" } else { "no" }
    ));
    out.push_str(&format!(
        "Domain: {}\n",
        intent.domain.as_deref().unwrap_or("none")
    ));
    out.push_str(&format!(
        "Address outside the platform: {}\n",
        intent.outside_address.as_deref().unwrap_or("none")
    ));
    out.push_str(&format!(
        "Upload key: {}\n",
        if intent.upload_key.is_some() {
            "supplied"
        } else {
            "not supplied"
        }
    ));

    if intent.mail_keys.is_empty() {
        out.push_str("Mail key: none submitted\n");
    } else {
        out.push_str("Mail keys:\n");
        for k in &intent.mail_keys {
            let mailbox = if k.mailbox.is_empty() { "address" } else { &k.mailbox };
            out.push_str(&format!(
                "  {mailbox}: {} (fingerprint {})\n",
                k.verdict, k.fingerprint
            ));
        }
    }

    out.push_str("\nAnswers\n");
    for (id, answer) in &intent.answers {
        // A multiline answer keeps its own lines, indented under its id, so a
        // free-text answer reads as the applicant wrote it.
        let mut lines = answer.lines();
        let first = lines.next().unwrap_or("");
        out.push_str(&format!("{id}: {first}\n"));
        for line in lines {
            out.push_str(&format!("  {line}\n"));
        }
    }

    out.push_str("\nDecide\n");
    for (label, action) in [
        ("approve, with the charge", "approve"),
        ("approve, without charge", "approve-free"),
        ("decline", "decline"),
    ] {
        out.push_str(&format!(
            "  {label}: {}\n",
            sign::decide_link(&cfg.base_url, key, token, action)?
        ));
    }
    let username = &intent.application.username;
    out.push_str("\nFrom a terminal\n");
    out.push_str(&format!("  onboardctl approve {username}\n"));
    out.push_str(&format!("  onboardctl approve-free {username}\n"));
    out.push_str(&format!("  onboardctl decline {username}\n"));
    Ok(out)
}

/// A decision intent: an approval with the charge, an approval without it, or a
/// decline. Revalidates every field, checks a link's signature when one is
/// present, and carries out the outcome.
pub async fn decision(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    intent: DecisionIntent,
    file: &str,
) -> Result<(), String> {
    if !store::is_status_token(&intent.application.status_token) {
        return Err("the status token is not 128 bits of Crockford".to_string());
    }
    if let Some(why) = validate::username_shape(&intent.application.username) {
        return Err(format!("the username: {why}"));
    }
    // A link click carries the signed action; `onboardctl` is a local root
    // action and carries neither. When a signature is present it must verify,
    // and the action it names must be the one this kind carries out.
    if let Some(action) = &intent.action {
        let sig = intent
            .sig
            .as_deref()
            .ok_or("a link click carries an action but no signature")?;
        if !sign::verify(key, &sign::decide_payload(&intent.application.status_token, action), sig)
        {
            return Err("the link's signature does not verify".to_string());
        }
        let expected = match intent.kind.as_str() {
            "approve" => "approve",
            "provision" => "approve-free",
            "decline" => "decline",
            other => return Err(format!("kind {other:?} is not a decision")),
        };
        if action != expected {
            return Err(format!(
                "the link's action {action:?} does not match the intent's kind {:?}",
                intent.kind
            ));
        }
    }
    match intent.kind.as_str() {
        "approve" => approve(cfg, store, key, &intent, false, file).await,
        "provision" => approve(cfg, store, key, &intent, true, file).await,
        "decline" => decline(cfg, store, &intent, file).await,
        other => Err(format!("kind {other:?} is not a decision")),
    }
}

/// The approval path, charged and without charge. `no_charge` is the free
/// outcome: no token, no window, no ledger line, and an account that never
/// lapses. The application's own answer is honoured too: an application that
/// asked for no charge is never charged by a charge-carrying intent.
async fn approve(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    intent: &DecisionIntent,
    no_charge: bool,
    file: &str,
) -> Result<(), String> {
    let token = &intent.application.status_token;
    let username = &intent.application.username;
    let record = application_record(store, token).await?;
    if record.username != *username {
        return Err("the intent's username is not the application's".to_string());
    }
    let no_charge = no_charge || record.no_charge;
    if record.decided_at.is_some() {
        journal(
            store,
            &intent.id,
            &intent.kind,
            &intent.application,
            "already-decided",
            Some("the application was already decided; nothing was carried out"),
        )
        .await?;
        store.remove("intents", file).await?;
        return Ok(());
    }

    journal(store, &intent.id, &intent.kind, &intent.application, "applying", None).await?;

    // Provisioning first, so a failure leaves the application undecided and the
    // next run retries it. The two scripts are idempotent, and `add-user.sh`
    // comes first because the mailbox is what everything after it needs.
    run_script(cfg, "add-user.sh", &[username]).await?;
    run_script(cfg, "provision-member.sh", &[username]).await?;

    let now = util::filed_at();
    // A rerun after a crash must not draw a second token or open a second
    // window: the account's own record is reused when it is already there.
    let existing = existing_account(store, username).await;
    let token_ref = if no_charge {
        None
    } else {
        match existing.as_ref().and_then(|a| a.token_ref.clone()) {
            Some(t) => Some(t),
            None => Some(store::payment_token().await?),
        }
    };
    let window = if no_charge {
        None
    } else {
        existing
            .as_ref()
            .and_then(|a| a.window.clone())
            .or_else(|| {
                Some(Window {
                    opened_at: now.clone(),
                    closes_at: util::after_days(14),
                    state: "open".to_string(),
                    extensions: 0,
                })
            })
    };

    let account = Account {
        version: 1,
        username: username.clone(),
        state: "active".to_string(),
        decision: "approve".to_string(),
        decided_at: now.clone(),
        rail: if no_charge {
            "no_charge".to_string()
        } else {
            record.rail.clone()
        },
        no_charge,
        created_at: now.clone(),
        token_ref: token_ref.clone(),
        token_issued_at: token_ref.as_ref().map(|_| now.clone()),
        paid_until: None,
        window: window.clone(),
        outside_address: record.outside_address.clone(),
    };
    store.ensure_dir(&format!("accounts/{username}")).await?;
    let account_bytes =
        serde_json::to_vec_pretty(&account).map_err(|e| format!("cannot encode the account: {e}"))?;
    store
        .write_record(&format!("accounts/{username}"), "account.json", &account_bytes)
        .await?;

    if let (Some(token), Some(window)) = (&token_ref, &window) {
        let join = TokenRecord {
            token: token.clone(),
            username: username.clone(),
            issued_at: now.clone(),
            window_closes_at: window.closes_at.clone(),
            state: "issued".to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&join)
            .map_err(|e| format!("cannot encode the token record: {e}"))?;
        store.ensure_dir("tokens").await?;
        store
            .write_record("tokens", &format!("{token}.json"), &bytes)
            .await?;
        append_ledger(cfg, store, token, &record.rail, &intent.id, &now).await?;
    }

    // The account's own copy of the application, inside the 90-day purge, with
    // the status link's own end written on it.
    let mut app_copy: Value = serde_json::from_str(
        &store
            .read_record("applications", &format!("{token}.json"))
            .await
            .ok_or("the application record vanished mid-approval")?,
    )
    .map_err(|e| format!("the application record does not parse: {e}"))?;
    app_copy["status_link_until"] = json!(util::after_days(7));
    let copy_bytes = serde_json::to_vec_pretty(&app_copy)
        .map_err(|e| format!("cannot encode the application copy: {e}"))?;
    store
        .write_record(
            &format!("accounts/{username}"),
            "application.json",
            &copy_bytes,
        )
        .await?;

    // The decision email, recorded in the account's notices before it is
    // enqueued. The address outside the platform when one was given, and the
    // mailbox the approval just created otherwise.
    let to = record
        .outside_address
        .clone()
        .unwrap_or_else(|| format!("{username}@kyriakon.net"));
    let subject = decision_subject("approved", username);
    let body = decision_body(cfg, &record, no_charge, token_ref.as_deref(), &window)?;
    let notice_type = if no_charge {
        "approval.free"
    } else {
        "approval.paid"
    };
    notice::send_account_notice(cfg, store, username, notice_type, &subject, &to, &body).await?;

    // The decision is recorded last, so a crash anywhere above leaves the
    // application undecided and rerunnable.
    mark_decided(
        store,
        token,
        "approved: an account was made",
        &now,
        Some(sign::password_link(
            &cfg.base_url,
            key,
            token,
            &util::date_after_days(7),
        )?),
    )
    .await?;
    store.remove("intents", file).await?;
    Ok(())
}

/// The decline: no reason, a message that offers the way back, the application
/// held a week, and only a monastic decline says what is missing.
async fn decline(
    cfg: &DrainConfig,
    store: &Store,
    intent: &DecisionIntent,
    file: &str,
) -> Result<(), String> {
    let token = &intent.application.status_token;
    let username = &intent.application.username;
    let record = application_record(store, token).await?;
    if record.username != *username {
        return Err("the intent's username is not the application's".to_string());
    }
    if record.decided_at.is_some() {
        journal(
            store,
            &intent.id,
            &intent.kind,
            &intent.application,
            "already-decided",
            Some("the application was already decided; nothing was carried out"),
        )
        .await?;
        store.remove("intents", file).await?;
        return Ok(());
    }
    journal(store, &intent.id, &intent.kind, &intent.application, "applying", None).await?;

    let now = util::filed_at();
    let to = record
        .outside_address
        .clone()
        .unwrap_or_else(|| format!("{username}@kyriakon.net"));
    let subject = decision_subject("declined", username);
    let body = decline_body(&record);
    // No account exists to hold a `notices.jsonl`, so the record that stops a
    // second email is the application's own decision, written below and before
    // the send in the ordinary case: mark it first, then mail.
    mark_decided(store, token, "declined", &now, None).await?;
    notice::enqueue(cfg, &to, &subject, &body).await?;
    store.remove("intents", file).await?;
    Ok(())
}

/// Clear away every declined application whose week is up, and release the
/// username. Run once per drain pass, after the intents: this is what carries
/// the decline's week out without the application being touched again.
pub async fn purge_declined(cfg: &DrainConfig, store: &Store) -> Result<(), String> {
    let now = OffsetDateTime::now_utc();
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
        if !record.stage.starts_with("declined") {
            continue;
        }
        let Some(decided_at) = record.decided_at.as_deref() else {
            continue;
        };
        // The status link's own window is the week: inside it the record
        // answers and nothing is purged.
        if util::link_answers(decided_at, now) {
            continue;
        }
        // Release the name first, so a script that is missing or fails leaves
        // the record for the next pass rather than losing the release.
        run_script(cfg, "delete-user.sh", &[&record.username]).await?;
        journal(
            store,
            &format!("purge-{}", record.status_token),
            "decline",
            &ApplicationRef {
                username: record.username.clone(),
                status_token: record.status_token.clone(),
            },
            "purged",
            Some("the week passed; the application was cleared away and the username released"),
        )
        .await?;
        store.remove("applications", &name).await?;
    }
    Ok(())
}

/// The application record a decision acts on, or an error naming what is
/// missing. A decision intent for an application that is not on disk is refused
/// rather than creating anything.
async fn application_record(store: &Store, token: &str) -> Result<Record, String> {
    let text = store
        .read_record("applications", &format!("{token}.json"))
        .await
        .ok_or("there is no application for this token")?;
    serde_json::from_str(&text).map_err(|e| format!("the application record does not parse: {e}"))
}

/// The account a username already has, when one is there.
async fn existing_account(store: &Store, username: &str) -> Option<Account> {
    let text = store
        .read_record(&format!("accounts/{username}"), "account.json")
        .await?;
    serde_json::from_str(&text).ok()
}

/// Write the decision onto the application record. `password_link` is written
/// only when there is one: a decline has no account and so no password to set.
async fn mark_decided(
    store: &Store,
    token: &str,
    stage: &str,
    decided_at: &str,
    password_link: Option<String>,
) -> Result<(), String> {
    let text = store
        .read_record("applications", &format!("{token}.json"))
        .await
        .ok_or("the application record vanished before it could be decided")?;
    let mut record: Record =
        serde_json::from_str(&text).map_err(|e| format!("the application record does not parse: {e}"))?;
    record.stage = stage.to_string();
    record.decided_at = Some(decided_at.to_string());
    record.password_link = password_link;
    let bytes =
        serde_json::to_vec_pretty(&record).map_err(|e| format!("cannot encode the record: {e}"))?;
    store
        .write_record("applications", &format!("{token}.json"), &bytes)
        .await
}

/// Append the ledger line a paid approval opens with: the amount owed and the
/// window it falls due in, keyed by the token and holding no username. A rerun
/// finds the line already there and writes none.
async fn append_ledger(
    cfg: &DrainConfig,
    store: &Store,
    token: &str,
    rail: &str,
    intent: &str,
    at: &str,
) -> Result<(), String> {
    let mut seq = 0u64;
    for line in store.lines("ledger/payments.jsonl").await {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if let Some(t) = v.get("token").and_then(Value::as_str) {
                if t == token && v.get("kind").and_then(Value::as_str) == Some("window_open") {
                    return Ok(());
                }
            }
            if let Some(s) = v.get("seq").and_then(Value::as_u64) {
                seq = seq.max(s);
            }
        }
    }
    let line = json!({
        "version": 1,
        "seq": seq + 1,
        "token": token,
        "kind": "window_open",
        "rail": rail,
        "received_on": Value::Null,
        "amount_gbp": cfg.price_gbp,
        "applied_gbp": "0.00",
        "paid_until_after": Value::Null,
        "amount_xmr": Value::Null,
        "rate_quoted": Value::Null,
        "rate_source": Value::Null,
        "rate_at": at,
        "txid": Value::Null,
        "intent": intent,
        "note": "the window opened at approval; no money has arrived yet",
    });
    let encoded = serde_json::to_string(&line).map_err(|e| format!("cannot encode the ledger: {e}"))?;
    store.append("ledger/payments.jsonl", encoded.as_bytes()).await
}

fn decision_subject(what: &str, username: &str) -> String {
    format!("Your application to kyriakon.net was {what} ({username})")
}

/// The decision email for an approval. The words are short because #333 owns
/// the notice copy; what matters here is that the token and the rail's own
/// instructions are on it, and that the free path says neither.
fn decision_body(
    cfg: &DrainConfig,
    record: &Record,
    no_charge: bool,
    token: Option<&str>,
    window: &Option<Window>,
) -> Result<String, String> {
    if no_charge {
        return Ok(format!(
            "Your application for {} has been approved, with no charge.\n\n\
             There is nothing to pay and no payment window. The account does not lapse.\n",
            record.username
        ));
    }
    let token = token.ok_or("a charged approval has no token")?;
    let window = window.as_ref().ok_or("a charged approval has no window")?;
    let mut out = format!(
        "Your application for {} has been approved.\n\n\
         The amount is GBP {} for the year.\n\
         Your payment reference is {token}.\n",
        record.username, cfg.price_gbp
    );
    match record.rail.as_str() {
        "cash" => out.push_str(&format!(
            "\nPost the money to:\n\n  {}\n\nWrite the reference on the envelope, or on a slip inside it.\n",
            cfg.postal_address
        )),
        "monero" => out.push_str(
            "\nYour Monero subaddress will follow in a second message. The pound amount is what is owed; the quoted amount in Monero settles it.\n",
        ),
        "card" => out.push_str("\nA card payment link will follow in a second message.\n"),
        other => out.push_str(&format!("\nThe rail you chose, {other}, will be quoted to you.\n")),
    }
    out.push_str(&format!(
        "\nThe money must arrive before {} or the account lapses: mail keeps arriving and\n\
         everything published stays up, and sending, uploading and pushing stop.\n\
         Nothing is deleted at that point.\n",
        &window.closes_at[..10]
    ));
    Ok(out)
}

/// The decline email: no reason, the way back, and the week. A monastic decline
/// is the one case that names what is missing, because what is missing is a
/// conversation.
fn decline_body(record: &Record) -> String {
    let monastic = matches!(record.answers.get("orders").map(String::as_str), Some("monk") | Some("nun"));
    let mut out = format!(
        "Your application for {} was not accepted this time.\n\n\
         We hold it for a week in case a word arrives, and then it is cleared away\n\
         and the name is free again. To have us look again, reply if we wrote to you,\n\
         or write to admin@kyriakon.net from anywhere.\n",
        record.username
    );
    if monastic {
        out.push_str(
            "\nThe blessing of your elder did not reach us. If you can ask him to write to us,\n\
             or send his blessing, we will look again.\n",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(answers: &[(&str, &str)]) -> Record {
        serde_json::from_value(json!({
            "username": "secretary",
            "status_token": "0123456789abcdefghjkmnpqrst",
            "filed_at": "2026-10-01T09:00:00Z",
            "front_end": "web",
            "stage": "received",
            "answers": answers.iter().cloned().collect::<std::collections::BTreeMap<_, _>>(),
            "mail_keys": [],
            "rail": "cash",
            "no_charge": false,
            "acceptances": [],
            "question_list": "2026-10-01 abc1234"
        }))
        .unwrap()
    }

    #[test]
    fn a_decline_body_names_a_missing_blessing_only_for_a_monastic() {
        let lay = decline_body(&record(&[("orders", "layman")]));
        assert!(!lay.contains("blessing"), "{lay}");
        assert!(lay.contains("admin@kyriakon.net"), "{lay}");
        let monk = decline_body(&record(&[("orders", "monk")]));
        assert!(monk.contains("blessing"), "{monk}");
    }

    #[test]
    fn a_decision_subject_names_the_application_and_the_outcome() {
        assert_eq!(
            decision_subject("approved", "secretary"),
            "Your application to kyriakon.net was approved (secretary)"
        );
    }
}
