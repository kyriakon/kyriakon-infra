//! The transitions the drain carries out: the review email a filed application
//! produces, the three outcomes a reviewer can choose, and the purge a decline
//! ends in.
//!
//! Every transition appends its journal line **before** it does the work, so a
//! crash leaves a record a rerun can read. Every decision is deduplicated on the
//! application's own state, so a click on an already-decided application changes
//! nothing and the journal records only that the click was seen.

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;

use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::process::Command;

use crate::config::DrainConfig;
use crate::notice;
use crate::questions;
use crate::sign;
use crate::store::{
    self, Account, ApplicationRef, Intent, JournalLine, KeyRecord, Record, Store, TokenRecord,
    Window,
};
use crate::util;
use crate::validate;

/// The rails an application may name. `no_charge` is the fourth, and it is a
/// rail rather than a flag because it is one of the four buttons on the form.
const RAILS: [&str; 4] = ["card", "cash", "monero", "no_charge"];

/// One of the three decisions a reviewer can make.
pub struct Decision {
    /// The word the console takes and a decision link carries, and the action
    /// the signature covers.
    pub action: &'static str,
    /// The intent kind the drain dispatches on.
    pub kind: &'static str,
    /// The words the operator reads, in the review email and on the confirm page
    /// a link opens.
    pub label: &'static str,
}

/// The three decisions, as one list. Everything that names one takes its words
/// from here: the console's verb, the intent's kind, the action the signature
/// covers and the label the operator reads. They were four tables in four
/// places, which is how a decision comes to be added in one of them and refused
/// by another after the reviewer has already made it.
pub const DECISIONS: [Decision; 3] = [
    Decision {
        action: "approve",
        kind: "approve",
        label: "approve, with the charge",
    },
    Decision {
        action: "approve-free",
        kind: "provision",
        label: "approve, without charge",
    },
    Decision {
        action: "decline",
        kind: "decline",
        label: "decline",
    },
];

/// The decision a console verb or a link named, by the word it carries.
pub fn decision_for(action: &str) -> Option<&'static Decision> {
    DECISIONS.iter().find(|d| d.action == action)
}

/// The decision an intent carries, by its kind.
pub fn decision_for_kind(kind: &str) -> Option<&'static Decision> {
    DECISIONS.iter().find(|d| d.kind == kind)
}

/// A reviewer's decision intent, from `kyriakon-onboardctl` or a signed link.
/// Every
/// decision intent carries the action it performs and the signature over it: the
/// directory it is read from belongs to the unprivileged half, so an unsigned
/// decision would be root work driven by a file any writer of `intents/` could
/// leave. `kyriakon-onboardctl` signs with the same root-only key the links use.
#[derive(Debug, serde::Deserialize)]
pub struct DecisionIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub application: ApplicationRef,
    /// `approve`, `approve-free` or `decline`, and it must match the kind.
    pub action: String,
    /// The HMAC-SHA256 of `decide:<status_token>:<action>` under the approval
    /// key.
    pub sig: String,
}

/// A password set through the member's one-time link. Everything the drain needs
/// to check it is here, including the signature: the handler holds no key, so
/// the link's signature is the proof and the drain is the half that checks it.
#[derive(serde::Deserialize)]
pub struct PasswordIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub application: ApplicationRef,
    /// The date the link carried. In the signed payload, never beside it.
    pub until: String,
    pub sig: String,
    /// The bcrypt hash the handler computed. The password itself never travels.
    pub hash: String,
}

/// Run one of the repository's privileged scripts by its configured path and
/// hand back what it wrote. It is called with argv only: there is no shell
/// anywhere in the drain, and every value that reaches it was validated first.
async fn spawn_script(
    cfg: &DrainConfig,
    name: &str,
    args: &[&str],
) -> Result<std::process::Output, String> {
    let path = format!("{}/{}", cfg.scripts.trim_end_matches('/'), name);
    // The drain runs from root cron, whose PATH is /usr/bin:/bin, and the scripts
    // it runs reach the packages in /usr/local: without this, a provision's
    // reload call cannot find gmid, refuses, and fails the whole approval.
    Command::new(&path)
        .args(args)
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin",
        )
        .output()
        .await
        .map_err(|e| format!("cannot run {path}: {e}"))
}

/// Run a script and refuse a non-zero exit, naming what it said.
async fn run_script(cfg: &DrainConfig, name: &str, args: &[&str]) -> Result<(), String> {
    let out = spawn_script(cfg, name, args).await?;
    if !out.status.success() {
        return Err(script_error(cfg, name, &out));
    }
    Ok(())
}

/// Run a script and tolerate one known refusal, named by the message it prints.
/// `add-user.sh` exits non-zero when the account already exists, which is the
/// state a run that died after it leaves and the state a retry has to get past.
async fn run_script_tolerating(
    cfg: &DrainConfig,
    name: &str,
    args: &[&str],
    tolerate: &str,
) -> Result<(), String> {
    let out = spawn_script(cfg, name, args).await?;
    if out.status.success() || String::from_utf8_lossy(&out.stderr).contains(tolerate) {
        return Ok(());
    }
    Err(script_error(cfg, name, &out))
}

fn script_error(cfg: &DrainConfig, name: &str, out: &std::process::Output) -> String {
    let path = format!("{}/{}", cfg.scripts.trim_end_matches('/'), name);
    format!(
        "{path} exited {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

/// Write the member's upload key where `provision-member.sh` reads it, in the
/// store's own `keys/` directory, root-owned like the rest of the drain's half.
async fn write_public_key(store: &Store, username: &str, material: &str) -> Result<(), String> {
    let body = material.trim();
    if body.is_empty() {
        return Err("the upload key material is empty".to_string());
    }
    store.ensure_dir("keys").await?;
    let mut bytes = body.as_bytes().to_vec();
    bytes.push(b'\n');
    store
        .write_record("keys", &format!("{username}.pub"), &bytes)
        .await
}

/// The localpart a mail key is published and served under: the mailbox when the
/// application named one, and the account's own name otherwise. The keyring file,
/// the published file and the branch the change is opened on all take it.
fn mail_key_localpart<'a>(username: &'a str, key: &'a KeyRecord) -> &'a str {
    if key.mailbox.is_empty() {
        username
    } else {
        key.mailbox.as_str()
    }
}

/// Publish the member's mail keys into the box keyring the encrypting LMTP reads,
/// one `<localpart>.asc` each, before any path can deliver to the account. The
/// file is created once and then left alone, so the drift check's age for it is
/// the moment this service first wrote it. Delivery fails closed without the key,
/// so an application that carries none is refused rather than made into an
/// account whose mail bounces.
async fn publish_mail_keys(
    cfg: &DrainConfig,
    username: &str,
    keys: &[KeyRecord],
) -> Result<(), String> {
    if keys.is_empty() {
        return Err(
            "the application carries no mail key, so the account could not receive mail"
                .to_string(),
        );
    }
    let dir = std::path::Path::new(&cfg.keyring_dir);
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    for key in keys {
        let localpart = mail_key_localpart(username, key);
        if let Some(why) = validate::username_shape(localpart) {
            return Err(format!("the mail key's mailbox {localpart:?}: {why}"));
        }
        let body = key.material.trim();
        if body.is_empty() {
            return Err(format!("the mail key for {localpart} is empty"));
        }
        let path = dir.join(format!("{localpart}.asc"));
        let mut bytes = body.as_bytes().to_vec();
        bytes.push(b'\n');
        // Written only when the bytes differ. The drift check's seven days for an
        // unpublished key are the age of this file, and the publish runs after
        // this in the same transition, so a retry whose publish failed must leave
        // the file, and its mtime, exactly as they are. Rewriting an identical
        // file would restart that window on every retry and it would never close.
        let same = std::fs::read(&path)
            .map(|have| have == bytes)
            .unwrap_or(false);
        if !same {
            std::fs::write(&path, &bytes)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        }
        // deploy-mail installs the tracked keys 0644, and the drift check and the
        // encrypting daemon both read them as they find them.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("cannot set the mode on {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Offer the member's mail keys to the published set, one `keys/<localpart>.asc`
/// each, by opening a change against the public repository through
/// scripts/publish-mail-key.sh, which holds the mechanism and the token.
///
/// This runs after the keyring write and after the member is built, and before
/// the account record and the notice. Nothing about the publish may stand between
/// the member and their mail: the box keyring is what delivers, so a failed
/// publish costs the member nothing, while its failure is loud and its retry
/// leaves the keyring file, and the drift check's seven days, untouched. The
/// window in check-keyring-drift.sh is the backstop for one that never succeeds.
async fn publish_mail_keys_publicly(
    cfg: &DrainConfig,
    username: &str,
    keys: &[KeyRecord],
) -> Result<(), String> {
    let dir = cfg.keyring_dir.trim_end_matches('/');
    for key in keys {
        let localpart = mail_key_localpart(username, key);
        let path = format!("{dir}/{localpart}.asc");
        run_script(
            cfg,
            "publish-mail-key.sh",
            &[localpart, path.as_str(), cfg.keyring_publish_token.as_str()],
        )
        .await?;
    }
    Ok(())
}

/// The address an approval notice goes to: the applicant's own outside address,
/// validated again here because it was written by the unprivileged half and is
/// about to become a mail header, or the mailbox the approval just created.
fn recipient(record: &Record, username: &str) -> Result<String, String> {
    match record.outside_address.as_deref() {
        Some(addr) => {
            if let Some(why) = validate::address(addr) {
                return Err(format!("the address outside the platform {addr:?}: {why}"));
            }
            Ok(addr.to_string())
        }
        None => Ok(format!("{username}@kyriakon.net")),
    }
}

/// Append one journal line. The caller writes this before the transition, which
/// is the whole point of the journal, and again on completion so an approval that
/// finished and one that died midway do not read alike.
async fn journal(
    store: &Store,
    release: &str,
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
        release: release.to_string(),
        application: application.clone(),
        outcome: outcome.to_string(),
        note: note.map(str::to_string),
    };
    let encoded =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode a journal line: {e}"))?;
    store.append("journal.jsonl", encoded.as_bytes()).await
}

/// Whether the journal already holds a line for this intent id with this
/// outcome. A refusal is recorded once, and a purge that already released the
/// name is not released twice.
async fn journal_has(store: &Store, id: &str, outcome: &str) -> bool {
    for line in store.lines("journal.jsonl").await {
        if let Ok(j) = serde_json::from_str::<JournalLine>(&line) {
            if j.intent == id && j.outcome == outcome {
                return true;
            }
        }
    }
    false
}

/// Whether the journal already holds a line for this intent id, whatever its
/// outcome.
async fn intent_seen(store: &Store, id: &str) -> bool {
    for line in store.lines("journal.jsonl").await {
        if let Ok(j) = serde_json::from_str::<JournalLine>(&line) {
            // A failed line is the reason the next pass retries, not a
            // settlement: counting it would drop the intent after one failure.
            if j.intent == id && j.outcome != "failed" {
                return true;
            }
        }
    }
    false
}

/// How long to wait before retrying an id that has failed `failures` times, in
/// minutes. A healthy intent is handled on the very next pass, which is the cron
/// interval; a failing one backs off instead, so a permanent failure is retried
/// after a minute, five, fifteen, then hourly rather than every minute. The
/// schedule is a courtesy, not a limit: the retry never stops, so fixing the
/// cause and waiting is enough.
pub fn retry_after_minutes(failures: u32) -> i64 {
    const SCHEDULE: [i64; 4] = [1, 5, 15, 60];
    match failures {
        0 => 0,
        n => SCHEDULE[((n - 1) as usize).min(SCHEDULE.len() - 1)],
    }
}

/// The failed passes recorded for an id: how many, when the last was, and what
/// it said. Read back from the journal, so the count and the last message
/// survive a restart, which is what makes both the backoff and the dedup hold
/// across cron runs.
pub async fn failures(store: &Store, id: &str) -> (u32, Option<OffsetDateTime>, Option<String>) {
    let mut count = 0u32;
    let mut last = None;
    let mut message = None;
    for line in store.lines("journal.jsonl").await {
        if let Ok(j) = serde_json::from_str::<JournalLine>(&line) {
            if j.intent == id && j.outcome == "failed" {
                count += 1;
                if let Ok(at) = OffsetDateTime::parse(&j.at, &Rfc3339) {
                    last = Some(at);
                }
                if j.note.is_some() {
                    message = j.note;
                }
            }
        }
    }
    (count, last, message)
}

/// Record a failed pass and say whether it is a new one worth mailing. The same
/// message as the last failure is the same event, so the operator is not mailed
/// it again; a different message is. This is the notices path's rule, applied to
/// the drain's own output: record first, and let the record stop the duplicate.
pub async fn note_failure(
    store: &Store,
    release: &str,
    id: &str,
    kind: &str,
    message: &str,
) -> Result<bool, String> {
    let (_, _, previous) = failures(store, id).await;
    journal(
        store,
        release,
        id,
        kind,
        &ApplicationRef {
            username: String::new(),
            status_token: String::new(),
        },
        "failed",
        Some(message),
    )
    .await?;
    Ok(previous.as_deref() != Some(message))
}

/// Report a failed pass once, by mail. The journal records every failed pass, so
/// a pass whose message the last failure already carried is not mailed again:
/// the operator gets one mail per distinct failure rather than one a minute.
///
/// A failure that was mailed is not also printed. cron mails a job's output
/// under a subject of its own, so printing would be the same news a second time,
/// and the copy that names neither the component nor the event.
pub async fn report_failure(cfg: &DrainConfig, store: &Store, id: &str, kind: &str, message: &str) {
    let fresh = note_failure(store, &cfg.release, id, kind, message)
        .await
        .unwrap_or(true);
    if fresh {
        // The drain's own configuration is journalled under the id `config`,
        // which is the one failure that is not about an intent: the id and the
        // kind are the same word there.
        let what = if id == kind {
            "its own configuration".to_string()
        } else {
            format!("{kind} {id}")
        };
        notice::alert(
            cfg,
            "onboard",
            "drain failed",
            &format!("the drain failed on {what}: {message}"),
            "nothing is lost: the work stays in place and the next pass tries it \
             again, and this is sent once per distinct failure rather than once a \
             minute, because the journal already carries the same message. \
             docs/runbook.md, in the onboarding section, has the order to read when \
             the drain is stuck.",
        )
        .await;
    }
}

/// Whether a failing id is due for another attempt, and whether it should be
/// reported when it fails again. `true` means go ahead.
pub async fn due(store: &Store, id: &str, now: OffsetDateTime) -> bool {
    let (failures, last, _) = failures(store, id).await;
    match last {
        None => true,
        Some(last) => now >= last + Duration::minutes(retry_after_minutes(failures)),
    }
}

/// Whether the journal already holds a line of this kind for this application,
/// written by an intent whose pass has not failed since.
///
/// Used for the review email, whose dedup key is the application and not the
/// intent: a re-filed application must not be mailed twice either.
///
/// The line is written before the send on purpose, so that a crash loses an
/// email rather than sending two. A returned error is not a crash: the pass that
/// gets one knows the send did not happen, and it leaves a `failed` line for its
/// own intent, so a marker counted there would have the next pass drop the
/// intent and lose the review email for good. A crash writes no failed line, so
/// the direction the marker is written in is unchanged.
///
/// A failure counts only when it comes after the marker, so an intent that
/// failed once and then sent successfully keeps its marker standing. Order is
/// the file's own: several lines of one pass share a timestamp.
async fn application_seen(store: &Store, token: &str, kind: &str, outcome: &str) -> bool {
    let mut marks: Vec<(usize, String)> = Vec::new();
    let mut failed: Vec<(usize, String)> = Vec::new();
    for (at, line) in store.lines("journal.jsonl").await.iter().enumerate() {
        if let Ok(j) = serde_json::from_str::<JournalLine>(line) {
            if j.outcome == "failed" {
                failed.push((at, j.intent.clone()));
            }
            if j.application.status_token == token && j.kind == kind && j.outcome == outcome {
                marks.push((at, j.intent));
            }
        }
    }
    marks
        .iter()
        .any(|(at, id)| !failed.iter().any(|(f, fid)| fid == id && f > at))
}

/// Refuse an intent of a kind this build does not implement, by name, and leave
/// it in place. The journal records the refusal once, so two runs over the same
/// directory do not append the same line twice.
/// Apply a password set through a one-time link.
///
/// Four checks before anything runs, and each is the half the handler cannot do:
/// the signature over the token and its date (the key is root-only), the date
/// still being ahead, the hash being one this build made, and the record still
/// holding the link. The last is what makes the link one-time: applying it clears
/// the link, so a replay finds nothing to apply and is refused like any other
/// spent link.
pub async fn set_password(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    intent: PasswordIntent,
    file: &str,
    value: &Value,
) -> Result<(), String> {
    if intent_seen(store, &intent.id).await {
        return Ok(());
    }
    let token = intent.application.status_token.as_str();
    let username = intent.application.username.as_str();
    let problem = if !sign::verify(
        key,
        &sign::password_payload(token, &intent.until),
        &intent.sig,
    ) {
        Some("the link's signature does not verify")
    } else if intent.until.as_str() < util::date_after_days(0).as_str() {
        Some("the link's date has passed")
    } else if !crate::password::is_hash(&intent.hash) {
        Some("the intent does not carry a bcrypt hash")
    } else {
        None
    };
    if let Some(problem) = problem {
        return refuse_with(cfg, store, file, value, problem).await;
    }
    let name = format!("{token}.json");
    let Some(text) = store.read_record("applications", &name).await else {
        return refuse_with(cfg, store, file, value, "the application record is gone").await;
    };
    // Read as a Value and edit one key: the record carries fields this build
    // does not model, and writing it back through the typed struct would drop
    // them.
    let mut record: Value = serde_json::from_str(&text)
        .map_err(|e| format!("the application record does not parse: {e}"))?;
    if record.get("username").and_then(Value::as_str) != Some(username) {
        return refuse_with(cfg, store, file, value, "the intent names another account").await;
    }
    if record.get("password_link").is_none_or(Value::is_null) {
        return refuse_with(cfg, store, file, value, "the link has already been used").await;
    }
    run_script(cfg, "set-mail-password.sh", &[username, &intent.hash]).await?;
    // One use: the record keeps no link, so the page stops answering.
    record["password_link"] = Value::Null;
    let bytes = serde_json::to_vec_pretty(&record)
        .map_err(|e| format!("cannot encode the application record: {e}"))?;
    // `applications/` belongs to the handler, which renders the status page as
    // _onboard: a root-owned record reads as missing to it.
    let owner = store.dir_owner("applications");
    store
        .write_record_owned("applications", &name, &bytes, owner)
        .await?;
    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &intent.application,
        "applied",
        None,
    )
    .await?;
    // Done: the file goes, as every other applied transition removes its own.
    store.remove("intents", file).await
}

/// Journal a refusal with its reason. The intent is left in place, as `refuse`
/// leaves an unknown kind, and the journal's own line stops it being retried.
async fn refuse_with(
    cfg: &DrainConfig,
    store: &Store,
    file: &str,
    value: &Value,
    reason: &str,
) -> Result<(), String> {
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
    journal(
        store,
        &cfg.release,
        &id,
        &kind,
        &application,
        "refused",
        Some(reason),
    )
    .await
}

pub async fn refuse(
    cfg: &DrainConfig,
    store: &Store,
    file: &str,
    value: &Value,
) -> Result<(), String> {
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
        &cfg.release,
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
    name_allowed(cfg, &intent.application.username).await?;
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
        &cfg.release,
        &intent.id,
        "application",
        &intent.application,
        "review-sent",
        None,
    )
    .await?;

    // The same subject shape as every other operator mail: the component, then
    // the event, with the application named in it. The token stays because it is
    // the one thing in this mail that is not written out anywhere in the body,
    // and two applications from one username differ only by it.
    let subject = notice::operator_subject(
        "onboard",
        &format!(
            "application filed ({}, {})",
            intent.application.username, intent.application.status_token
        ),
    );
    let body = review_body(cfg, key, &intent)?;
    notice::enqueue(cfg, &cfg.reviewer, &subject, &body).await?;
    store.remove("intents", file).await?;
    Ok(())
}

/// The review email's body. Every field the ticket lists, and the three links
/// beside their `kyriakon-onboardctl` equivalents.
fn review_body(cfg: &DrainConfig, key: &[u8], intent: &Intent) -> Result<String, String> {
    let token = &intent.application.status_token;
    let mut out = String::new();
    out.push_str(&format!("Application {}\n", intent.application.username));
    out.push_str(&format!(
        "Filed {} by the {} front end\n",
        intent.filed_at, intent.front_end
    ));
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
            let mailbox = if k.mailbox.is_empty() {
                "address"
            } else {
                &k.mailbox
            };
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

    // The terminal form comes first. A decision URL is about 140 characters and
    // the signature is at the end of it, so a mail client that hard-wraps at 72
    // cuts it before the signature whatever the label does: the fix is to lead
    // with the form that cannot be wrapped, and say so rather than let the link
    // look like the reliable one.
    let username = &intent.application.username;
    out.push_str("\nFrom a terminal\n");
    out.push_str(&format!("  kyriakon-onboardctl approve {username}\n"));
    out.push_str(&format!("  kyriakon-onboardctl approve-free {username}\n"));
    out.push_str(&format!("  kyriakon-onboardctl decline {username}\n"));
    out.push_str(
        "\nOr by link, which works once. Each is 140 characters and the signature\n\
         is at the end, so a mail client that wraps a long line cuts it at the\n\
         wrap: open it as one unbroken line, or use the terminal form above.\n",
    );
    for d in DECISIONS.iter() {
        out.push_str(&format!(
            "\n  {}\n  {}\n",
            d.label,
            sign::decide_link(&cfg.base_url, key, token, d.action)?
        ));
    }
    Ok(out)
}

/// A decision intent: an approval with the charge, an approval without it, or a
/// decline. Revalidates every field and requires a signature over the
/// application and the action, so an intent is carried out only when the
/// root-only key signed it, whether by the reviewer or by the reviewer's link.
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
    let expected = match decision_for_kind(&intent.kind) {
        Some(d) => d.action,
        None => return Err(format!("kind {:?} is not a decision", intent.kind)),
    };
    if intent.action != expected {
        return Err(format!(
            "the action {:?} does not match the kind {:?}",
            intent.action, intent.kind
        ));
    }
    if !sign::verify(
        key,
        &sign::decide_payload(&intent.application.status_token, &intent.action),
        &intent.sig,
    ) {
        return Err("the decision intent's signature does not verify".to_string());
    }
    match intent.kind.as_str() {
        "approve" => approve(cfg, store, key, &intent, false, file).await,
        "provision" => approve(cfg, store, key, &intent, true, file).await,
        "decline" => decline(cfg, store, &intent, file).await,
        // Unreachable after the kind match above, kept so the dispatch is total.
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
            &cfg.release,
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

    // The recipient is revalidated before anything is written or journaled, so a
    // record whose address could inject a header is refused rather than
    // half-applied.
    let to = recipient(&record, username)?;

    // Whether this application's own approval already began. A genuine retry has
    // its own "applying" line; anything else holding this name is not this
    // application's.
    let begun = approval_started(store, token).await;
    let existing = existing_account(store, username).await;

    // An account record that this application never began is a second
    // application for a username that already has one. Nothing here is this
    // application's to reuse: not the payment token, not its window, and not its
    // ledger row, and an approval reached this way would rewrite the first
    // application's payment state, leaving the account and the ledger
    // disagreeing about what is owed. This is the replay rule for a different
    // reason: the click is recorded and the intent is dropped.
    if existing.is_some() && !begun {
        journal(
            store,
            &cfg.release,
            &intent.id,
            &intent.kind,
            &intent.application,
            "already-member",
            Some(
                "this username already has an account that this application did not make; nothing was carried out",
            ),
        )
        .await?;
        store.remove("intents", file).await?;
        return Ok(());
    }

    // The held-back names are checked here, where the account would be made,
    // rather than where the intent is read: only an approval creates an account,
    // and a decline of a held-back name must still be carried out. Only when the
    // approval is starting, so a name added to the list after an approval began
    // does not turn the retry of a half-made account into an intent that can
    // never finish.
    if !begun {
        name_allowed(cfg, username).await?;
    }

    // The box is the oracle and the record only a fast path. A name already on
    // the box that this application did not create is somebody else's, and it is
    // refused rather than adopted: the front end may not check existence at all,
    // so the drain must not silently take the account. The check runs before the
    // journal line, so a refusal records nothing and leaves the intent in place.
    let mut on_box = false;
    if existing.is_none() {
        on_box = account_on_box(cfg, username)?;
        if on_box && !begun {
            return Err(format!(
                "the username {username} is already in use on this box and this application did not create it; the intent is left in place"
            ));
        }
    }

    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &intent.application,
        "applying",
        None,
    )
    .await?;

    // Provisioning, and only when there is no account record yet, so a retry
    // does not repeat it. When the box already holds the name this application
    // started, add-user.sh is skipped: it is not idempotent, and the account it
    // would refuse is the one this application made.
    if existing.is_none() {
        // The keyring first, before the builder makes the address live: the
        // encrypting LMTP fails closed without the member's key, so mail offered
        // between the two would bounce at the door.
        publish_mail_keys(cfg, username, &record.mail_keys).await?;
        if !on_box {
            run_script_tolerating(cfg, "add-user.sh", &[username], "already exists").await?;
        }
        // The member is always built, because mail is unconditional: the builder
        // writes the member's address and the allowance, and the key decides
        // only what else. When the application carried one, it is written where
        // that script reads it first, since the public tree and the upload
        // session are built from it.
        if let Some(upload) = record.upload_key.as_ref() {
            write_public_key(store, username, &upload.material).await?;
        }
        run_script(cfg, "provision-member.sh", &[username]).await?;
        // The lanes wrote the member's httpd and gmid files, and regenerating the
        // indexes and reloading those daemons is cron-apply.sh --web's job, as
        // its own header says. Only a hosting member has new files, so a
        // mail-only approval does not run it and prints nothing.
        if record.upload_key.is_some() {
            run_script(cfg, "cron-apply.sh", &["--web"]).await?;
        }
        // Last, with the member already built and mail already delivering: the
        // published set is what the drift check compares the keyring against, and
        // the forge is never on a path the key or the member waits on. A failure
        // here is loud and leaves the intent in place, and the retry above leaves
        // the keyring file alone, so the seven days the check allows an
        // unpublished key are not restarted by it.
        publish_mail_keys_publicly(cfg, username, &record.mail_keys).await?;
    }

    let now = util::filed_at();
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
        certificates: Vec::new(),
        site_served: None,
        capsule_served: None,
        space_used: None,
    };
    store.ensure_dir(&format!("accounts/{username}")).await?;
    let account_bytes = serde_json::to_vec_pretty(&account)
        .map_err(|e| format!("cannot encode the account: {e}"))?;
    store
        .write_record(
            &format!("accounts/{username}"),
            "account.json",
            &account_bytes,
        )
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
    let subject = decision_subject("approved", username);
    // Built before the body, so the mail that says the account exists also says
    // how to set the password. The spec asks for the link in the email and on
    // the status page both.
    let password_until = util::date_after_days(7);
    let password_link = sign::password_link(&cfg.base_url, key, token, &password_until)?;
    let body = format!(
        "{}\n\nSet your mail password from this one-time link, which works until {password_until}:\n\n{password_link}\n\nIt works once. The same link is on your status page.\n",
        decision_body(cfg, &record, no_charge, token_ref.as_deref(), &window)?
    );
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
        Some(password_link),
    )
    .await?;
    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &intent.application,
        "applied",
        None,
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
            &cfg.release,
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
    // The address is validated before the journal line, so a record whose
    // address could inject a header is refused before anything is carried out.
    // A decline creates no mailbox, so the fallback an approval uses does not
    // exist here: the message goes to the address outside the platform when the
    // applicant gave one, and without one nothing is sent and the status link,
    // which answers for the week, is the channel the spec makes durable.
    let outside = match record.outside_address.as_deref() {
        Some(addr) => {
            if let Some(why) = validate::address(addr) {
                return Err(format!("the address outside the platform {addr:?}: {why}"));
            }
            Some(addr.to_string())
        }
        None => None,
    };
    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &intent.application,
        "applying",
        None,
    )
    .await?;

    let now = util::filed_at();
    if let Some(addr) = &outside {
        let subject = decision_subject("declined", username);
        let body = decline_body(&record);
        notice::enqueue(cfg, addr, &subject, &body).await?;
    }
    // The decision is recorded after the send, which is what the approval does
    // and for the same reason: a decline marked before a send that then returned
    // an error left a record saying the applicant had been told, so the next pass
    // took the already-decided branch above and dropped the intent without ever
    // sending anything. No account exists to hold a `notices.jsonl`, so this
    // record is the only thing that stops a second email. Recording it after the
    // send leaves one window in which a crash could send twice, between sendmail
    // returning and this write, against the certain loss of the notice before.
    mark_decided(store, token, "declined", &now, None).await?;
    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &intent.application,
        "applied",
        None,
    )
    .await?;
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
        // The record was written by the unprivileged half, so the username is
        // revalidated before it can reach a root script's argv; a record whose
        // name does not fit is skipped rather than erroring the whole pass.
        if validate::username_shape(&record.username).is_some() {
            eprintln!(
                "kyriakon-onboard-drain: declined record {name} has no usable username; skipped"
            );
            continue;
        }
        let app = ApplicationRef {
            username: record.username.clone(),
            status_token: record.status_token.clone(),
        };
        let purge_id = format!("purge-{}", record.status_token);
        // A purge that keeps failing backs off, and its error is mailed once,
        // through the same rule the intents use.
        if !due(store, &purge_id, now).await {
            continue;
        }
        // The journal line goes before the transition, as it does for an intent,
        // and once: a pass that already released the name does not release it
        // again, and a crash after the line still clears the record away.
        if !journal_has(store, &purge_id, "purged").await {
            if !journal_has(store, &purge_id, "applying").await {
                journal(
                    store,
                    &cfg.release,
                    &purge_id,
                    "decline",
                    &app,
                    "applying",
                    Some("the week passed; the username is being released"),
                )
                .await?;
            }
            // Release the name only when nothing holds it. The box is the oracle
            // and the record only a fast path: an account made by the operator
            // or by a script run by hand has no record, and the front end never
            // checks whether a name is taken, so either form means the name is
            // in use and the purge must not delete what holds it. A failed
            // script leaves the record for the next pass rather than losing the
            // release, and its error is reported once rather than every minute.
            let taken = existing_account(store, &record.username).await.is_some()
                || account_on_box(cfg, &record.username)?;
            if !taken {
                if let Err(e) = run_script(cfg, "delete-user.sh", &[&record.username]).await {
                    report_failure(cfg, store, &purge_id, "decline", &e).await;
                    continue;
                }
            }
            journal(
                store,
                &cfg.release,
                &purge_id,
                "decline",
                &app,
                "purged",
                Some("the application was cleared away"),
            )
            .await?;
        }
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

/// The account a username already has, when one is there. This is the fast path:
/// the box itself, read below, is the oracle.
async fn existing_account(store: &Store, username: &str) -> Option<Account> {
    let text = store
        .read_record(&format!("accounts/{username}"), "account.json")
        .await?;
    serde_json::from_str(&text).ok()
}

/// Whether the box itself holds an account for a username, read from the passwd
/// file rather than by running `id(1)`. This is the oracle the account record is
/// not: an account the operator made, or one `provision-member.sh` made by hand,
/// has no `account.json`, and the drain must neither adopt it nor release its
/// name. An unreadable file is an error rather than a "no", so the drain fails
/// closed instead of acting on a box it cannot see.
fn account_on_box(cfg: &DrainConfig, username: &str) -> Result<bool, String> {
    let text = std::fs::read_to_string(&cfg.passwd)
        .map_err(|e| format!("cannot read {}: {e}", cfg.passwd))?;
    Ok(text
        .lines()
        .any(|line| line.split(':').next() == Some(username)))
}

/// The names the platform holds back, read from the path the config names.
///
/// Read where it is used rather than held for the pass: it is a short file, read
/// at most twice a minute by a cron job, and a read that fails must refuse the
/// work rather than let it through on an empty list.
async fn reserved_names(cfg: &DrainConfig) -> Result<HashSet<String>, String> {
    Ok(validate::reserved(&Store::read_text(&cfg.reserved).await?))
}

/// Refuse a username the platform holds back, naming it. Both gates that can
/// create an account go through this: the filing, and the approval.
///
/// The name is in the message because a failed pass is journalled against an
/// empty application and mailed to the operator, so the message is the only
/// place either of them can read which name was refused.
async fn name_allowed(cfg: &DrainConfig, username: &str) -> Result<(), String> {
    let reserved = reserved_names(cfg).await?;
    match validate::username(username, &reserved) {
        None => Ok(()),
        Some(why) => Err(format!("the username {username}: {why}")),
    }
}

/// Whether this application's approval already began. The journal records
/// "applying" after the name check and before provisioning, so a name that is on
/// the box and has that line is one this application made, and the retry
/// continues with it rather than refusing it as taken.
///
/// The kind is matched as well. Three transitions write that word for a token:
/// the approval, the decline and the purge. Without the kind, a decline that
/// could not finish would make a later approval of the same application believe
/// the account on the box was its own, and it would adopt a name this
/// application never made.
async fn approval_started(store: &Store, token: &str) -> bool {
    for line in store.lines("journal.jsonl").await {
        if let Ok(j) = serde_json::from_str::<JournalLine>(&line) {
            if j.application.status_token == token
                && j.outcome == "applying"
                && (j.kind == "approve" || j.kind == "provision")
            {
                return true;
            }
        }
    }
    false
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
    let mut record: Record = serde_json::from_str(&text)
        .map_err(|e| format!("the application record does not parse: {e}"))?;
    record.stage = stage.to_string();
    record.decided_at = Some(decided_at.to_string());
    record.password_link = password_link;
    let bytes =
        serde_json::to_vec_pretty(&record).map_err(|e| format!("cannot encode the record: {e}"))?;
    // `applications/` belongs to the handler, so the drain hands the rewritten
    // record back to that directory's owner. A root-owned 0600 file would read
    // as missing to the unprivileged process that renders the status page, and
    // the link would answer as an unknown token for the week it should answer.
    let owner = store.dir_owner("applications");
    store
        .write_record_owned("applications", &format!("{token}.json"), &bytes, owner)
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
    let encoded =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode the ledger: {e}"))?;
    store
        .append("ledger/payments.jsonl", encoded.as_bytes())
        .await
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
    let monastic = questions::is_monastic(record.answers.get("orders").map(String::as_str));
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

    #[test]
    fn a_failing_id_backs_off_a_minute_then_five_then_fifteen_then_hourly() {
        assert_eq!(retry_after_minutes(0), 0);
        assert_eq!(retry_after_minutes(1), 1);
        assert_eq!(retry_after_minutes(2), 5);
        assert_eq!(retry_after_minutes(3), 15);
        assert_eq!(retry_after_minutes(4), 60);
        // The cap holds, so the drain keeps retrying rather than stopping.
        assert_eq!(retry_after_minutes(40), 60);
    }
}
