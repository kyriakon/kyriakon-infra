//! The transitions the drain carries out: the review email a filed application
//! produces, the three outcomes a reviewer can choose, and the purge a decline
//! ends in.
//!
//! Every transition appends its journal line **before** it does the work, so a
//! crash leaves a record a rerun can read. Every decision is deduplicated on the
//! application's own state, so a click on an already-decided application changes
//! nothing and the journal records only that the click was seen.

use std::collections::{BTreeMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;

use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::process::Command;

use crate::config::DrainConfig;
use crate::dns;
use crate::notice;
use crate::questions;
use crate::sign;
use crate::store::{
    self, Account, ApplicationRef, CreditProgress, FlatPayment, GroupAddress, GroupAddressIntent,
    GroupIntent, GroupPayment, GroupRecord, GroupRemoveIntent, Intent, JournalLine, KeyRecord,
    Payment, Record, Store, TokenRecord, Window,
};
use crate::util;
use crate::validate;

/// The rails an application may name. `no_charge` is the fourth, and it is a
/// rail rather than a flag because it is one of the four buttons on the form.
const RAILS: [&str; 4] = ["card", "cash", "monero", "no_charge"];

/// The address changes a `group-address` intent carries. The console's
/// `--action` takes one of these and the drain refuses any other.
pub const ADDRESS_ACTIONS: [&str; 4] = ["add-alias", "add-mailbox", "upgrade", "remove"];

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

/// The `token-resend` intent: the member's payment instructions again, and
/// nothing minted. It carries the token the account already holds, so the drain
/// can check the account before it sends, and the console's signature, because
/// `intents/` belongs to the unprivileged half and a second copy of the
/// instructions is not the handler's to file.
#[derive(serde::Deserialize)]
pub struct ResendIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub username: String,
    pub token: String,
    pub sig: String,
}

/// A manual credit: one payment recorded against the token its account holds.
/// The console resolves a `--username` to that token before filing, and this
/// carries the token, the rail, the money, the day the money arrived and the
/// override reason when the operator gave one. The signature covers all of it,
/// because the intent moves a paid-until date and `intents/` belongs to the
/// unprivileged half.
#[derive(Debug, serde::Deserialize)]
pub struct CreditIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub token: String,
    pub rail: String,
    pub amount_gbp: String,
    pub received: String,
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default)]
    pub amount_xmr: Option<String>,
    #[serde(default)]
    pub confirm_double: bool,
    #[serde(default)]
    pub override_reason: Option<String>,
    /// What the operator wrote down about a payment that carries no token. Free
    /// text, so it is signed last and never read as a field.
    #[serde(default)]
    pub note: Option<String>,
    pub sig: String,
}

/// A `reconcile-attribute` intent: the held item and the token it is joined to.
/// The console signs it, because the transition writes a paid-until date and
/// `intents/` belongs to the unprivileged half.
#[derive(Debug, serde::Deserialize)]
pub struct AttributeIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    /// The `UN-` id of the line in `ledger/unattributed.jsonl`.
    pub item: String,
    /// The payment token the held money is joined to.
    pub token: String,
    /// A renewal: the token already has a paid-until date, and the operator has
    /// said this held payment is another year's money.
    #[serde(default)]
    pub confirm_double: bool,
    /// The override reason for a credit that would pass the 24-month ceiling,
    /// as the corresponding credit flag carries it.
    #[serde(default)]
    pub override_reason: Option<String>,
    pub sig: String,
}

/// A `reconcile-return` intent: the held item and the evidence it went back or
/// was kept. The evidence is free text and signed last.
#[derive(Debug, serde::Deserialize)]
pub struct ReturnIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub item: String,
    pub note: String,
    pub sig: String,
}

/// A refund: one negative ledger line naming the payment it reverses, or a
/// settlement of one already recorded. The console resolves a `--username` to
/// the account's token before filing, and this carries the token, the money, the
/// rail, the reason and the `--close`/`--excess` choice. A settlement carries
/// only `settled_on`. The signature covers all of it, because the intent writes
/// the ledger and closes an account, and `intents/` belongs to the unprivileged
/// half.
#[derive(Debug, serde::Deserialize)]
pub struct RefundIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub token: String,
    #[serde(default)]
    pub amount_gbp: Option<String>,
    #[serde(default)]
    pub rail: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub close: bool,
    #[serde(default)]
    pub excess: bool,
    /// `--rate`, the sterling price of one XMR on the refund date, when the
    /// member asked for sterling rather than the recorded XMR back.
    #[serde(default)]
    pub rate: Option<String>,
    /// The day the refund was paid out, for the settlement form.
    #[serde(default)]
    pub settled_on: Option<String>,
    pub sig: String,
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

/// The address the applicant gave outside the platform, revalidated here because
/// it was written by the unprivileged half and is about to become a mail header.
/// `None` when none was given.
fn outside_address(record: &Record) -> Result<Option<String>, String> {
    match record.outside_address.as_deref() {
        Some(addr) => {
            if let Some(why) = validate::address(addr) {
                return Err(format!("the address outside the platform {addr:?}: {why}"));
            }
            Ok(Some(addr.to_string()))
        }
        None => Ok(None),
    }
}

/// The address an approval notice goes to: the applicant's own outside address,
/// or the mailbox the approval just created.
fn recipient(record: &Record, username: &str) -> Result<String, String> {
    Ok(outside_address(record)?.unwrap_or_else(|| format!("{username}@kyriakon.net")))
}

/// The address a body's approval notice goes to. A body has no account of the
/// applicant's own, so the fallback is the site owner's mailbox on the body's
/// domain rather than the person path's `username@kyriakon.net`, which the drain
/// never makes for a body.
fn group_recipient(record: &Record, site_owner: &str, domain: &str) -> Result<String, String> {
    Ok(outside_address(record)?.unwrap_or_else(|| format!("{site_owner}@{domain}")))
}

/// The application record's confirmation lock. The stamp is a read-check-write of
/// a record that is replaced by rename, so the lock lives beside it rather than
/// on it; two drain passes on the same application could otherwise both read it
/// as unconfirmed.
///
/// It is held across the send rather than only across the write. Two passes
/// serialised for the one enqueue is cheap, and releasing it before the send
/// reopens the window this lock exists to close: the second pass would find the
/// stamp and skip, and a failed send would be left recorded as sent.
///
/// The drain runs as root and the handler owns `applications/`, so the lock is
/// handed to the directory's owner like every record `write_record_owned`
/// writes; a root-owned file there reads as store drift to the hygiene check.
async fn lock_confirmation(store: &Store) -> Result<tokio::fs::File, String> {
    let path = store.path("applications/.confirmation.lock");
    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).mode(0o600);
    let file = opts
        .open(&path)
        .await
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    if let Some((uid, gid)) = store.dir_owner("applications") {
        if unsafe { libc::geteuid() } == 0 {
            std::os::unix::fs::chown(&path, Some(uid), Some(gid))
                .map_err(|e| format!("cannot hand {} to the handler: {e}", path.display()))?;
        }
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!(
            "cannot lock {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

/// Send the confirmation the spec promises before provisioning: it restates the
/// immediate-supply request and the digital-content acknowledgement, quotes every
/// document accepted with its version, and states the 14-day right with how to
/// use it.
///
/// The stamp is written on the application before the enqueue, the direction
/// every notice takes: a crash loses an email rather than sending it twice. An
/// enqueue that *returns* an error is not a crash, though: the stamp is cleared
/// before the error leaves this function, so the retry sends the mail. Leaving
/// it set would provision the applicant without the confirmation and record that
/// it was sent.
///
/// With no outside address there is no mailbox that can receive one before the
/// account exists. The acceptances stay on the application record, which is what
/// the confirmation quotes; the status page carries the decision and the
/// password link, not this letter.
async fn confirm(
    cfg: &DrainConfig,
    store: &Store,
    token: &str,
    record: &Record,
) -> Result<(), String> {
    let Some(to) = outside_address(record)? else {
        return Ok(());
    };
    let _lock = lock_confirmation(store).await?;
    let mut live = application_record(store, token).await?;
    if live.confirmation_at.is_some() {
        return Ok(());
    }
    let subject = confirmation_subject(&live.username);
    let body = confirmation_body(&live);
    live.confirmation_at = Some(util::filed_at());
    save_application(store, token, &live).await?;
    if let Err(e) = notice::enqueue(cfg, &to, &subject, &body).await {
        // The stamp goes back before the error, so a retry is a resend rather
        // than an approval that provisions with the letter lost.
        live.confirmation_at = None;
        save_application(store, token, &live).await?;
        return Err(e);
    }
    Ok(())
}

/// Write the application record, handed to the handler's owner like every other
/// record in `applications/`.
async fn save_application(store: &Store, token: &str, record: &Record) -> Result<(), String> {
    let bytes =
        serde_json::to_vec_pretty(record).map_err(|e| format!("cannot encode the record: {e}"))?;
    let owner = store.dir_owner("applications");
    store
        .write_record_owned("applications", &format!("{token}.json"), &bytes, owner)
        .await
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
        credit: None,
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

    // A body's accounts are the address table's, not the applicant's: the person
    // path below would make one account for the accountable person and none of
    // the mailboxes. The whole application is one group intent instead.
    if record.domain.is_some() {
        return approve_group(cfg, store, intent, file, &record, no_charge).await;
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
        // A group mailbox that closed leaves the name held for ninety days, and
        // this is the other gate that can create an account. Without it a person
        // could take a name a removal had just held.
        if let Some(until) = name_held(store, username).await? {
            return Err(format!(
                "the username {username} is held until {until}, so it cannot be reused yet"
            ));
        }
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

    // The confirmation the spec promises goes out before the journal's
    // "applying" line and before any provisioning, so the record of what was
    // agreed exists before the service begins.
    confirm(cfg, store, token, &record).await?;

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
        match existing
            .as_ref()
            .and_then(|a| a.payment_state())
            .and_then(|p| p.token_ref)
        {
            Some(t) => Some(t),
            None => Some(store::payment_token().await?),
        }
    };
    let window = if no_charge {
        None
    } else {
        existing
            .as_ref()
            .and_then(|a| a.payment_state())
            .and_then(|p| p.window)
            .or_else(|| {
                Some(Window {
                    opened_at: now.clone(),
                    closes_at: util::after_days(14),
                    state: "open".to_string(),
                    extensions: 0,
                })
            })
    };
    // A no-charge approval writes no payment block at all: no window, no token,
    // and nothing that could lapse.
    let payment = if no_charge {
        None
    } else {
        Some(Payment {
            token_ref: token_ref.clone(),
            token_issued_at: Some(now.clone()),
            paid_until: None,
            window: window.clone(),
            rail: Some(record.rail.clone()),
            balance_gbp: None,
            stripe: Default::default(),
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
        payment,
        legacy_payment: FlatPayment::default(),
        outside_address: record.outside_address.clone(),
        certificates: Vec::new(),
        site_served: None,
        capsule_served: None,
        space_used: None,
        group: None,
        closing_until: None,
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
    // The handler renders the status page as `_onboard` and cannot read the
    // root-owned account, so the payment block it shows is this copy, written
    // back into the record it does read. A free approval carries none, which is
    // also why an undecided application never shows one.
    if let Some(block) = &account.payment {
        app_copy["payment"] = serde_json::to_value(block)
            .map_err(|e| format!("cannot encode the payment block: {e}"))?;
    }
    let copy_bytes = serde_json::to_vec_pretty(&app_copy)
        .map_err(|e| format!("cannot encode the application copy: {e}"))?;
    store
        .write_record(
            &format!("accounts/{username}"),
            "application.json",
            &copy_bytes,
        )
        .await?;
    let owner = store.dir_owner("applications");
    store
        .write_record_owned("applications", &format!("{token}.json"), &copy_bytes, owner)
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
        decision_body(
            cfg,
            &record.username,
            &record.rail,
            no_charge,
            token_ref.as_deref(),
            &window
        )?
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

/// `onboardctl token resend`: the same payment instructions again and nothing
/// minted. A second token would leave the first one in the ledger as an entry
/// that no longer resolves to the same member and would orphan a payment already
/// in flight, so the account's own token is read and re-sent.
///
/// The instructions are the approval email's, built by the same function, and
/// the notice is recorded as a sent one before it leaves. It is sent rather than
/// deduplicated: the member asking for a second copy is the whole point.
pub async fn resend(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    intent: ResendIntent,
    file: &str,
) -> Result<(), String> {
    if !sign::verify(
        key,
        &sign::resend_payload(&intent.username, &intent.token),
        &intent.sig,
    ) {
        return Err("the token resend's signature does not verify".to_string());
    }
    let username = intent.username.as_str();
    let text = store
        .read_record(&format!("accounts/{username}"), "account.json")
        .await
        .ok_or_else(|| format!("no account for {username}"))?;
    let account: Account = serde_json::from_str(&text)
        .map_err(|e| format!("the account record does not parse: {e}"))?;
    let Some(payment) = account.payment_state() else {
        return Err(format!(
            "{username} was approved without charge, so there is no payment token to resend"
        ));
    };
    if payment.token_ref.as_deref() != Some(intent.token.as_str()) {
        return Err(format!(
            "the token the resend names is not the one {username}'s account holds"
        ));
    }
    let body = decision_body(
        cfg,
        username,
        &account.rail,
        false,
        payment.token_ref.as_deref(),
        &payment.window,
    )?;
    let to = account
        .outside_address
        .clone()
        .unwrap_or_else(|| format!("{username}@kyriakon.net"));
    let subject = decision_subject("approved", username);
    notice::send_again(
        cfg,
        store,
        username,
        "prepaid.instructions",
        &subject,
        &to,
        &body,
    )
    .await?;
    // Every settling transition journals its outcome, and the line names the
    // application the account was made from.
    let application = store
        .read_record(&format!("accounts/{username}"), "application.json")
        .await
        .and_then(|copy| serde_json::from_str::<Value>(&copy).ok())
        .and_then(|copy| {
            let status_token = copy.get("status_token")?.as_str()?.to_string();
            Some(ApplicationRef {
                username: username.to_string(),
                status_token,
            })
        })
        .ok_or_else(|| format!("no application record for {username}"))?;
    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &application,
        "applied",
        None,
    )
    .await?;
    store.remove("intents", file).await
}

/// Apply a manual credit: one payment, the one date arithmetic, one ledger line.
///
/// The token index joins the token to a username and nothing else is trusted
/// from the intent's shape: the rail, the amount, the date and the token are
/// revalidated here because `intents/` belongs to the unprivileged half. The
/// ledger's own `intent` field is the dedup key, so a replay writes nothing and
/// extends nothing.
///
/// A credit with no token is the one case with nothing to join: it is held in
/// `ledger/unattributed.jsonl` rather than refused, because the money is real
/// and a member may still be found for it.
pub async fn credit(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    intent: CreditIntent,
    file: &str,
    value: &Value,
) -> Result<(), String> {
    if !sign::verify(
        key,
        &sign::credit_payload(
            &intent.token,
            &intent.rail,
            &intent.amount_gbp,
            &intent.received,
            intent.txid.as_deref(),
            intent.amount_xmr.as_deref(),
            intent.confirm_double,
            intent.override_reason.as_deref(),
            intent.note.as_deref(),
        ),
        &intent.sig,
    ) {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the credit intent's signature does not verify",
        )
        .await;
    }

    // The ledger line is the settlement marker, and a credit settles in one of
    // two: a payment joined to a token, or a held line in the unattributed
    // queue. A second arrival of the same intent finds its line and stops before
    // any other check, so a replay cannot refuse itself on a rule it already met.
    if ledger_has_intent(store, &intent.id).await || held_has_intent(store, &intent.id).await? {
        if !journal_has(store, &intent.id, "applied").await {
            journal(
                store,
                &cfg.release,
                &intent.id,
                &intent.kind,
                &ApplicationRef {
                    username: String::new(),
                    status_token: String::new(),
                },
                "applied",
                Some("replayed: the ledger already holds this credit"),
            )
            .await?;
        }
        store.remove("intents", file).await?;
        return Ok(());
    }
    // A refusal is recorded once; the intent is left in place, as every other
    // refused intent is, and a new intent is the way to change it.
    if journal_has(store, &intent.id, "refused").await {
        return Ok(());
    }
    let amount = match credit_fields(&intent) {
        Ok(amount) => amount,
        Err(problem) => return refuse_with(cfg, store, file, value, &problem).await,
    };
    let received = util::parse_date(&intent.received).expect("the date was validated above");

    // A payment with no token cannot be joined to an account, so it is held
    // until `reconcile` joins it or closes it.
    if intent.token.is_empty() {
        return hold(cfg, store, &intent, file, value, amount, received).await;
    }

    let (username, account, payment) = match resolve_payment(store, &intent.token).await {
        Ok(found) => found,
        Err(problem) => return refuse_with(cfg, store, file, value, &problem).await,
    };
    let app = PaymentApplication {
        intent: &intent,
        username: &username,
        account,
        payment,
        amount,
        received,
        attributed_item: None,
    };
    if apply_payment(cfg, store, file, value, app).await? {
        store.remove("intents", file).await?;
    }
    Ok(())
}

/// The fields a credit's money arrives with, revalidated here because `intents/`
/// belongs to the unprivileged half. Returns the amount in pence. A token is
/// checked only when there is one: a payment with none is held, not refused.
fn credit_fields(intent: &CreditIntent) -> Result<i64, String> {
    if !CREDIT_RAILS.contains(&intent.rail.as_str()) {
        return Err("the credit names a rail that is not cash, cash-hand or monero".to_string());
    }
    if !intent.token.is_empty() && !store::is_payment_token(&intent.token) {
        return Err("the credit's token is not the shape of a payment token".to_string());
    }
    if util::parse_date(&intent.received).is_none() {
        return Err("the credit's received date is not YYYY-MM-DD".to_string());
    }
    if !valid_txid(intent.txid.as_deref()) {
        return Err("the credit's transaction id is not 64 hexadecimal characters".to_string());
    }
    if !valid_xmr(intent.amount_xmr.as_deref()) {
        return Err("the credit's XMR amount is not a decimal amount".to_string());
    }
    match util::pence(&intent.amount_gbp) {
        Ok(amount) if amount > 0 => Ok(amount),
        Ok(_) => Err("the credit's amount must be more than zero".to_string()),
        Err(e) => Err(e),
    }
}

/// The account a payment token names, through `tokens/<token>.json` and its
/// account record. The token index is the only join, so a token that resolves to
/// nothing is refused rather than made into an account.
async fn resolve_payment(store: &Store, token: &str) -> Result<(String, Account, Payment), String> {
    let Some(join_text) = store.read_record("tokens", &format!("{token}.json")).await else {
        return Err(
            "the token is not in the index; an unattributed payment belongs in the queue"
                .to_string(),
        );
    };
    let join: TokenRecord = serde_json::from_str(&join_text)
        .map_err(|e| format!("the token record does not parse: {e}"))?;
    if join.token != token || validate::username_shape(&join.username).is_some() {
        return Err("the token record does not name this token".to_string());
    }
    let username = join.username;
    let Some(account_text) = store
        .read_record(&format!("accounts/{username}"), "account.json")
        .await
    else {
        return Err("the token resolves to an account that is gone".to_string());
    };
    let account: Account = serde_json::from_str(&account_text)
        .map_err(|e| format!("the account record does not parse: {e}"))?;
    let Some(payment) = account.payment_state() else {
        return Err("the account carries no payment block".to_string());
    };
    if payment.token_ref.as_deref() != Some(token) {
        return Err("the token is not the one the account's payment block holds".to_string());
    }
    Ok((username, account, payment))
}

/// One payment about to be applied to an account: the values a manual credit and
/// a `reconcile attribute` both hold once the token has resolved. Passed as one
/// value, so the two callers cannot disagree about any of them.
struct PaymentApplication<'a> {
    intent: &'a CreditIntent,
    username: &'a str,
    account: Account,
    payment: Payment,
    amount: i64,
    received: time::Date,
    /// The held item this payment came from, when the transition is a
    /// `reconcile attribute`. Its own txid is the one in the queue, so that
    /// item's held line is not a second sighting of the payment.
    attributed_item: Option<&'a str>,
}

/// What a credit does to an account: the ceiling, the arithmetic, the account
/// write, the payment copy, the ledger line and the receipt. Shared by the
/// console's credit and `reconcile attribute`, so a held payment and a direct
/// one are never applied differently.
async fn apply_payment(
    cfg: &DrainConfig,
    store: &Store,
    file: &str,
    value: &Value,
    app: PaymentApplication<'_>,
) -> Result<bool, String> {
    let PaymentApplication {
        intent,
        username,
        mut account,
        mut payment,
        amount,
        received,
        attributed_item,
    } = app;

    // A pass that journaled `applying` and wrote the account but crashed before
    // the ledger append is finished here, from the values it recorded then. The
    // account is the witness: its paid-until date (or, for a shortfall, its
    // balance) is the one this credit computed, so nothing is extended again and
    // no second notice is sent.
    let progress = credit_progress(store, &intent.id).await;
    let written = progress.as_ref().is_some_and(|p| {
        if p.paid {
            payment.paid_until.as_deref() == p.paid_until_after.as_deref()
        } else {
            payment.balance_gbp.as_deref() == p.balance_gbp.as_deref()
        }
    });
    if let Some(progress) = progress.as_ref().filter(|_| written) {
        if !ledger_has_intent(store, &intent.id).await {
            append_credit_ledger(
                store,
                intent,
                &util::date_string(received),
                &util::gbp(amount),
                &progress.applied_gbp,
                progress.paid_until_after.as_deref(),
            )
            .await?;
        }
        // A crash between the account write and its copies leaves the status
        // page behind; the account is the truth now, so rewrite them from it.
        write_payment_copy(store, username, &payment).await?;
        if !journal_has(store, &intent.id, "applied").await {
            journal_credit_applied(
                cfg,
                store,
                intent,
                username,
                intent.override_reason.as_deref(),
            )
            .await?;
        }
        return Ok(true);
    }

    let before = match payment.paid_until.as_deref() {
        Some(stamp) => match util::parse_date(stamp) {
            Some(date) => Some(date),
            None => {
                return refuse_with(
                    cfg,
                    store,
                    file,
                    value,
                    "the account's paid-until date cannot be read",
                )
                .await
                .map(|()| false)
            }
        },
        None => None,
    };
    let until = util::paid_until_after(received, before);
    let override_reason = intent
        .override_reason
        .as_deref()
        .filter(|r| !r.trim().is_empty());
    if until > util::credit_ceiling(received) && override_reason.is_none() {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the credit would put paid_until more than 24 months past --received; give --override <reason> to mean it",
        )
        .await
        .map(|()| false);
    }

    let price = util::pence(&cfg.price_gbp)
        .map_err(|e| format!("the drain's configured price_gbp: {e}"))?;
    if price <= 0 {
        return Err("the drain's configured price_gbp must be more than zero".to_string());
    }
    let balance = match payment.balance_gbp.as_deref() {
        Some(text) => match util::pence(text) {
            Ok(pence) => pence,
            Err(e) => {
                return refuse_with(
                    cfg,
                    store,
                    file,
                    value,
                    &format!("the account's balance cannot be read: {e}"),
                )
                .await
                .map(|()| false)
            }
        },
        None => 0,
    };
    let applied = credit_money(price, balance, amount);

    // A transaction already in the ledger is the same payment seen again. It
    // must never extend a date, whatever else the intent says. The queue is
    // checked too: a payment held with no token and then credited with one is
    // one payment, not two, unless this transition is attributing that very
    // held item.
    if let Some(txid) = intent.txid.as_deref() {
        if let Some((seq, received_on)) = ledger_txid(store, txid).await {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                &format!(
                    "transaction {txid} was already credited on {received_on} at ledger seq {seq}"
                ),
            )
            .await
            .map(|()| false);
        }
        if let Some((id, received_on)) = held_txid(store, txid).await? {
            if attributed_item != Some(id.as_str()) {
                return refuse_with(
                    cfg,
                    store,
                    file,
                    value,
                    &format!(
                        "transaction {txid} is already held as {id}, received on {received_on}; attribute that item instead"
                    ),
                )
                .await
                .map(|()| false);
            }
        }
    }
    // A token already credited is a renewal, and the second credit needs the
    // operator to have said so: for cash the second envelope may be a
    // stranger's with a copied token. Held money is never a renewal, because it
    // was never joined to the token in the first place.
    if let (Some(paid_until), false) = (payment.paid_until.as_deref(), intent.confirm_double) {
        let problem = if intent.kind == "credit" {
            format!(
                "this token was already credited until {paid_until}; give --confirm-double for a renewal"
            )
        } else {
            format!(
                "the token was already credited until {paid_until}; record a renewal with `credit --confirm-double`"
            )
        };
        return refuse_with(cfg, store, file, value, &problem)
            .await
            .map(|()| false);
    }

    let until_text = util::date_string(until);
    let paid_until_after = if applied.paid {
        Some(until_text.clone())
    } else {
        before.map(util::date_string)
    };
    let balance_text = (applied.balance > 0).then(|| util::gbp(applied.balance));

    // The values the account write is about to set, recorded before the write so
    // a crash leaves enough to finish the ledger line.
    if progress.is_none() {
        journal_credit_applying(
            store,
            &cfg.release,
            intent,
            username,
            &CreditProgress {
                paid: applied.paid,
                paid_until_after: paid_until_after.clone(),
                applied_gbp: util::gbp(applied.applied),
                balance_gbp: balance_text.clone(),
            },
        )
        .await?;
    }

    payment.rail = Some(intent.rail.clone());
    payment.balance_gbp = balance_text;
    if applied.paid {
        payment.paid_until = Some(until_text);
        // The window closes with the credit; a null paid-until date is what
        // shows the token, so setting the date is also what hides it.
        if let Some(window) = payment.window.as_mut() {
            window.state = "paid".to_string();
        }
    }
    account.payment = Some(payment.clone());
    let bytes = serde_json::to_vec_pretty(&account)
        .map_err(|e| format!("cannot encode the account: {e}"))?;
    store
        .write_record(&format!("accounts/{username}"), "account.json", &bytes)
        .await?;
    write_payment_copy(store, username, &payment).await?;
    append_credit_ledger(
        store,
        intent,
        &util::date_string(received),
        &util::gbp(amount),
        &util::gbp(applied.applied),
        paid_until_after.as_deref(),
    )
    .await?;

    // The receipt is for every payment, including a shortfall: the money
    // arrived, and the account page quotes what still does.
    let to = account
        .outside_address
        .clone()
        .unwrap_or_else(|| format!("{username}@kyriakon.net"));
    let (subject, body) = if applied.paid {
        let paid = util::date_string(until);
        (
            format!("Your payment to kyriakon.net was received (paid until {paid})"),
            format!(
                "We have recorded a payment of GBP {} on {} by {}.\n\n\
                 Your account is paid until {}.\n",
                util::gbp(amount),
                util::date_string(received),
                intent.rail,
                paid,
            ),
        )
    } else {
        let remaining = util::gbp(price - applied.balance);
        (
            format!("Your part payment to kyriakon.net was received (GBP {remaining} remains)"),
            format!(
                "We have recorded a payment of GBP {} on {} by {}.\n\n\
                 GBP {} remains due for the year, and your account page quotes it.\n",
                util::gbp(amount),
                util::date_string(received),
                intent.rail,
                remaining,
            ),
        )
    };
    notice::send_account_notice(
        cfg,
        store,
        username,
        "prepaid.receipt",
        &subject,
        &to,
        &body,
    )
    .await?;

    journal_credit_applied(cfg, store, intent, username, override_reason).await?;
    Ok(true)
}

/// The rails a refund may name. A refund never leaves on a rail the payment did
/// not arrive on, and the check is the original line's own rail.
pub const REFUND_RAILS: [&str; 4] = ["card", "cash", "cash-hand", "monero"];

/// The payment a refund reverses: the token's most recent `kind == "payment"`
/// line. `seq`, the rail and the amount come from the ledger, never from the
/// intent, so a refund cannot invent a payment to reverse.
struct PaymentLine {
    seq: u64,
    rail: String,
    amount: i64,
    amount_xmr: Option<String>,
    paid_until_after: Option<String>,
}

async fn last_payment_line(store: &Store, token: &str) -> Result<Option<PaymentLine>, String> {
    let mut found = None;
    for line in store.lines("ledger/payments.jsonl").await {
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if v.get("token").and_then(Value::as_str) != Some(token)
            || v.get("kind").and_then(Value::as_str) != Some("payment")
        {
            continue;
        }
        let amount = v
            .get("amount_gbp")
            .and_then(Value::as_str)
            .ok_or("a payment line carries no amount")?;
        found = Some(PaymentLine {
            seq: v.get("seq").and_then(Value::as_u64).unwrap_or(0),
            rail: v
                .get("rail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            amount: util::pence(amount)
                .map_err(|e| format!("the payment line's amount cannot be read: {e}"))?,
            amount_xmr: v
                .get("amount_xmr")
                .and_then(Value::as_str)
                .map(str::to_string),
            paid_until_after: v
                .get("paid_until_after")
                .and_then(Value::as_str)
                .map(str::to_string),
        });
    }
    Ok(found)
}

/// Refund one payment, or settle a refund already recorded. The console signs
/// every field, and the drain checks the signature before anything else because
/// `intents/` belongs to the unprivileged half.
///
/// The refund form appends one negative line naming the `seq` it reverses and,
/// with `--close`, sets the account closing. The settlement form rewrites the
/// newest unsettled refund line under the ledger's lock. The ledger's own
/// `intent` field is the dedup key for a refund, and `settled_intent` for a
/// settlement, so a replay writes nothing.
pub async fn refund(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    intent: RefundIntent,
    file: &str,
    value: &Value,
) -> Result<(), String> {
    let amount_text = intent.amount_gbp.as_deref().unwrap_or("");
    let rail = intent.rail.as_deref().unwrap_or("");
    let reason = intent.reason.as_deref().unwrap_or("");
    let rate_text = intent.rate.as_deref().unwrap_or("");
    let settled_text = intent.settled_on.as_deref().unwrap_or("");
    if !sign::verify(
        key,
        &sign::refund_payload(
            &intent.token,
            amount_text,
            rail,
            intent.close,
            intent.excess,
            rate_text,
            settled_text,
            reason,
        ),
        &intent.sig,
    ) {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the refund intent's signature does not verify",
        )
        .await;
    }

    if !store::is_payment_token(&intent.token) {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the refund's token is not the shape of a payment token",
        )
        .await;
    }

    // The settlement form. It never writes a line of its own, so its dedup is
    // the `settled_intent` it left on the refund line rather than `intent`.
    if !settled_text.is_empty() {
        if intent.amount_gbp.is_some()
            || intent.rail.is_some()
            || intent.reason.is_some()
            || intent.close
            || intent.excess
            || intent.rate.is_some()
        {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                "a settlement names only --settled and the account's token",
            )
            .await;
        }
        if util::parse_date(settled_text).is_none() {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                "the refund's settled date is not YYYY-MM-DD",
            )
            .await;
        }
        if ledger_settled_by(store, &intent.id).await {
            if !journal_has(store, &intent.id, "applied").await {
                journal(
                    store,
                    &cfg.release,
                    &intent.id,
                    &intent.kind,
                    &ApplicationRef {
                        username: String::new(),
                        status_token: String::new(),
                    },
                    "applied",
                    Some("replayed: the ledger already records this settlement"),
                )
                .await?;
            }
            store.remove("intents", file).await?;
            return Ok(());
        }
        if journal_has(store, &intent.id, "refused").await {
            return Ok(());
        }
        return settle_refund(cfg, store, &intent, file, value, settled_text).await;
    }

    // The ledger line is the settlement marker: a second arrival of the same
    // intent finds it and stops before any check it already met.
    if ledger_has_intent(store, &intent.id).await {
        if !journal_has(store, &intent.id, "applied").await {
            journal(
                store,
                &cfg.release,
                &intent.id,
                &intent.kind,
                &ApplicationRef {
                    username: String::new(),
                    status_token: String::new(),
                },
                "applied",
                Some("replayed: the ledger already holds this refund"),
            )
            .await?;
        }
        store.remove("intents", file).await?;
        return Ok(());
    }
    if journal_has(store, &intent.id, "refused").await {
        return Ok(());
    }

    let problem = if !REFUND_RAILS.contains(&rail) {
        Some("the refund names a rail that is not card, cash, cash-hand or monero")
    } else if intent.close == intent.excess {
        Some("the refund needs exactly one of --close or --excess")
    } else if reason.trim().is_empty() {
        Some("the refund's reason is empty")
    } else if intent.rate.is_some() && rail != "monero" {
        Some("a --rate is only a monero refund paid in sterling")
    } else {
        None
    };
    if let Some(problem) = problem {
        return refuse_with(cfg, store, file, value, problem).await;
    }
    let amount = match util::pence(amount_text) {
        Ok(a) if a > 0 => a,
        Ok(_) => {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                "the refund's amount must be more than zero",
            )
            .await
        }
        Err(e) => return refuse_with(cfg, store, file, value, &e).await,
    };
    let rate = match intent.rate.as_deref() {
        None => None,
        Some(text) => match util::pence(text) {
            Ok(p) if p > 0 => Some(util::gbp(p)),
            Ok(_) => {
                return refuse_with(
                    cfg,
                    store,
                    file,
                    value,
                    "the refund's rate must be more than zero",
                )
                .await
            }
            Err(e) => return refuse_with(cfg, store, file, value, &e).await,
        },
    };

    // The token index is the only join, exactly as the credit path uses it.
    let Some(join_text) = store
        .read_record("tokens", &format!("{}.json", intent.token))
        .await
    else {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the token is not in the index, so there is no account to refund",
        )
        .await;
    };
    let join: TokenRecord = match serde_json::from_str(&join_text) {
        Ok(join) => join,
        Err(e) => {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                &format!("the token record does not parse: {e}"),
            )
            .await
        }
    };
    if join.token != intent.token || validate::username_shape(&join.username).is_some() {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the token record does not name this token",
        )
        .await;
    }
    let username = join.username;
    let Some(account_text) = store
        .read_record(&format!("accounts/{username}"), "account.json")
        .await
    else {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the token resolves to an account that is gone",
        )
        .await;
    };
    let mut account: Account = match serde_json::from_str(&account_text) {
        Ok(account) => account,
        Err(e) => {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                &format!("the account record does not parse: {e}"),
            )
            .await
        }
    };
    let Some(payment) = account.payment_state() else {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the account carries no payment block",
        )
        .await;
    };
    if payment.token_ref.as_deref() != Some(intent.token.as_str()) {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the token is not the one the account's payment block holds",
        )
        .await;
    }

    let original = match last_payment_line(store, &intent.token).await {
        Ok(Some(line)) => line,
        Ok(None) => {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                "the token has no payment line for a refund to reverse",
            )
            .await
        }
        Err(e) => return refuse_with(cfg, store, file, value, &e).await,
    };
    if rail != original.rail {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            &format!(
                "the payment arrived by {} and a refund never leaves on another rail",
                original.rail
            ),
        )
        .await;
    }
    if amount > original.amount {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            &format!(
                "the refund is GBP {}, more than the GBP {} that arrived at ledger seq {}",
                util::gbp(amount),
                util::gbp(original.amount),
                original.seq
            ),
        )
        .await;
    }
    if intent.close && amount != original.amount {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            &format!(
                "a --close refund must be the full GBP {} that arrived at ledger seq {}",
                util::gbp(original.amount),
                original.seq
            ),
        )
        .await;
    }
    let deducted = format!("-{}", util::gbp(amount));
    for line in store.lines("ledger/payments.jsonl").await {
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if v.get("token").and_then(Value::as_str) == Some(intent.token.as_str())
            && v.get("kind").and_then(Value::as_str) == Some("refund")
            && v.get("refund_of").and_then(Value::as_u64) == Some(original.seq)
            && v.get("amount_gbp").and_then(Value::as_str) == Some(deducted.as_str())
        {
            let first = v.get("seq").and_then(Value::as_u64).unwrap_or(0);
            let on = v
                .get("received_on")
                .and_then(Value::as_str)
                .unwrap_or("an earlier date");
            return refuse_with(
                cfg,
                store,
                file,
                value,
                &format!("an identical refund is already recorded at ledger seq {first} on {on}"),
            )
            .await;
        }
    }

    let received_on = util::filed_at()[..10].to_string();
    let closing_until = util::date_after_days(7);
    let settlement_by = util::date_after_days(14);

    // The account write comes before the ledger append: a crash between them
    // leaves a close that a rerun applies again, and the ledger still holds the
    // one line. The other order would leave the money recorded and the account
    // open, which no rerun could see.
    if intent.close {
        account.state = "closing".to_string();
        account.closing_until = Some(closing_until);
        account.payment = Some(payment.clone());
        let bytes = serde_json::to_vec_pretty(&account)
            .map_err(|e| format!("cannot encode the account: {e}"))?;
        store
            .write_record(&format!("accounts/{username}"), "account.json", &bytes)
            .await?;
    }

    let seq = append_refund_ledger(
        store,
        &intent,
        &original,
        rail,
        &deducted,
        reason.trim(),
        rate.as_deref(),
        &received_on,
        payment.paid_until.as_deref(),
    )
    .await?;

    let to = account
        .outside_address
        .clone()
        .unwrap_or_else(|| format!("{username}@kyriakon.net"));
    let (subject, body) = refund_notice(
        rail,
        &util::gbp(amount),
        &received_on,
        &settlement_by,
        rate.as_deref(),
    );
    notice::send_account_notice(
        cfg,
        store,
        &username,
        "prepaid.refund",
        &subject,
        &to,
        &body,
    )
    .await?;

    let note = if rail == "card" {
        format!("Stripe Idempotency-Key refund-{seq}")
    } else {
        format!("recorded at ledger seq {seq}")
    };
    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &ApplicationRef {
            username: username.clone(),
            status_token: String::new(),
        },
        "applied",
        Some(&note),
    )
    .await?;
    if rail == "card" {
        println!("the Stripe refund's Idempotency-Key is refund-{seq}");
    }
    store.remove("intents", file).await
}

/// The refund notice: what was refunded, by which rail, and the date reg 34(4)
/// gives to settle it. A cash refund says posted back, and no rail's text names
/// a bank detail: the cash path holds none at all.
fn refund_notice(
    rail: &str,
    amount: &str,
    received_on: &str,
    settlement_by: &str,
    rate: Option<&str>,
) -> (String, String) {
    let how = match rail {
        "cash" | "cash-hand" => "posted back in cash, to the address you gave us",
        "card" => "to the card you paid with",
        _ => "in Monero, in the amount recorded on your receipt",
    };
    let price = match (rail, rate) {
        ("monero", Some(rate)) => {
            format!("\nThe rate recorded for this refund is GBP {rate} per XMR.\n")
        }
        _ => String::new(),
    };
    (
        format!("Your refund from kyriakon.net (GBP {amount})"),
        format!(
            "We have recorded a refund of GBP {amount} on {received_on}, paid {how}.\n\
             It will be settled by {settlement_by}.\n{price}",
        ),
    )
}

/// Append the refund's negative line. The amount is negative in both money
/// fields so a sum over the ledger is the year's takings; the XMR and the basis
/// it was computed on stay visible for a Monero refund.
#[allow(clippy::too_many_arguments)]
async fn append_refund_ledger(
    store: &Store,
    intent: &RefundIntent,
    original: &PaymentLine,
    rail: &str,
    deducted: &str,
    reason: &str,
    rate: Option<&str>,
    received_on: &str,
    paid_until_after: Option<&str>,
) -> Result<u64, String> {
    let seq = next_ledger_seq(store).await;
    let refund_basis = match rail {
        "monero" => Some(if rate.is_some() {
            "sterling"
        } else {
            "recorded_xmr"
        }),
        _ => None,
    };
    let line = json!({
        "version": 1,
        "seq": seq,
        "token": intent.token.as_str(),
        "kind": "refund",
        "rail": rail,
        "received_on": received_on,
        "amount_gbp": deducted,
        "applied_gbp": deducted,
        "paid_until_after": paid_until_after.or(original.paid_until_after.as_deref()),
        "amount_xmr": original.amount_xmr.as_deref(),
        "rate_quoted": Value::Null,
        "rate_source": Value::Null,
        "rate_at": Value::Null,
        "txid": Value::Null,
        "intent": intent.id.as_str(),
        "note": reason,
        "refund_of": original.seq,
        "settled_on": Value::Null,
        "refund_basis": refund_basis,
        "rate_refund": rate,
    });
    let encoded =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode the ledger: {e}"))?;
    store
        .append("ledger/payments.jsonl", encoded.as_bytes())
        .await?;
    Ok(seq)
}

/// The next `seq`: one past the highest the ledger holds.
async fn next_ledger_seq(store: &Store) -> u64 {
    let mut seq = 0u64;
    for line in store.lines("ledger/payments.jsonl").await {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if let Some(s) = v.get("seq").and_then(Value::as_u64) {
                seq = seq.max(s);
            }
        }
    }
    seq + 1
}

/// The ledger's exclusive lock for the one rewrite: a settlement completes a
/// line that is already there, and an append between the read and the write
/// would be lost without it. The lock lives in a file of its own rather than on
/// `payments.jsonl`, because the rewrite replaces that file by rename and a lock
/// on the replaced inode would stop guarding the path.
async fn ledger_lock(store: &Store) -> Result<tokio::fs::File, String> {
    let path = store.path("ledger/.payments.lock");
    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).mode(0o600);
    let file = opts
        .open(&path)
        .await
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!(
            "cannot lock {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

/// Whether a refund line already records this settlement intent. The settlement
/// does not append, so `ledger_has_intent` cannot be its dedup key.
async fn ledger_settled_by(store: &Store, id: &str) -> bool {
    for line in store.lines("ledger/payments.jsonl").await {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if v.get("settled_intent").and_then(Value::as_str) == Some(id) {
                return true;
            }
        }
    }
    false
}

/// The index of the newest refund line for the token that has no `settled_on`.
fn unsettled_refund(lines: &[String], token: &str) -> Option<usize> {
    let mut found = None;
    for (index, line) in lines.iter().enumerate() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if v.get("token").and_then(Value::as_str) == Some(token)
            && v.get("kind").and_then(Value::as_str) == Some("refund")
            && v.get("settled_on").and_then(Value::as_str).is_none()
        {
            found = Some(index);
        }
    }
    found
}

/// A settlement rewrites the newest refund line for the token that has no
/// `settled_on`, under the ledger's lock, and nothing else on it. This is the
/// ledger's one non-append write: `--settled` names a line already recorded, and
/// appending a second line would leave two records of one refund.
async fn settle_refund(
    cfg: &DrainConfig,
    store: &Store,
    intent: &RefundIntent,
    file: &str,
    value: &Value,
    on: &str,
) -> Result<(), String> {
    let settled_on = util::date_string(util::parse_date(on).expect("the date was validated"));
    // The refusal is decided before the lock is taken: it journals, which can
    // reach the mail enqueuer, and no append should wait behind that.
    let before_lock = store.lines("ledger/payments.jsonl").await;
    if unsettled_refund(&before_lock, &intent.token).is_none() {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the token has no unsettled refund to record a settlement against",
        )
        .await;
    }
    let _guard = ledger_lock(store).await?;
    let mut lines = store.lines("ledger/payments.jsonl").await;
    let Some(index) = unsettled_refund(&lines, &intent.token) else {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the token has no unsettled refund to record a settlement against",
        )
        .await;
    };
    let mut line: Value = serde_json::from_str(&lines[index])
        .map_err(|e| format!("the refund line does not parse: {e}"))?;
    let seq = line.get("seq").and_then(Value::as_u64).unwrap_or(0);
    line["settled_on"] = json!(settled_on);
    line["settled_intent"] = json!(intent.id);
    lines[index] =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode the ledger: {e}"))?;
    let mut text = lines.join("\n");
    text.push('\n');
    store
        .write_record("ledger", "payments.jsonl", text.as_bytes())
        .await?;

    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &ApplicationRef {
            username: String::new(),
            status_token: String::new(),
        },
        "applied",
        Some(&format!(
            "refund at ledger seq {seq} settled on {settled_on}"
        )),
    )
    .await?;
    store.remove("intents", file).await
}

pub const CREDIT_RAILS: [&str; 3] = ["cash", "cash-hand", "monero"];

/// Hold a credit that names no token: validate it exactly as a credit is
/// validated, dedup it on the intent id and the transaction id, and append one
/// line to the unattributed queue. No account is written, no payment line is
/// appended and no notice is sent, because nothing here has a member yet.
async fn hold(
    cfg: &DrainConfig,
    store: &Store,
    intent: &CreditIntent,
    file: &str,
    value: &Value,
    amount: i64,
    received: time::Date,
) -> Result<(), String> {
    if intent.rail == "cash-hand" {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "cash in hand is credited against a username; give --username",
        )
        .await;
    }
    let Some(note) = intent
        .note
        .as_deref()
        .map(str::trim)
        .filter(|note| !note.is_empty())
    else {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "a payment with no token needs --note so the operator can tell what it is",
        )
        .await;
    };
    // A transaction already seen is the same payment, whether it was held or
    // credited: it must never become a second line the operator could join
    // twice. The queue and the ledger are two records of one payment, so both
    // are consulted from either side.
    if let Some(txid) = intent.txid.as_deref() {
        if let Some((seq, received_on)) = ledger_txid(store, txid).await {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                &format!(
                    "transaction {txid} was already credited on {received_on} at ledger seq {seq}"
                ),
            )
            .await;
        }
        if let Some((id, received_on)) = held_txid(store, txid).await? {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                &format!("transaction {txid} is already held as {id}, received on {received_on}"),
            )
            .await;
        }
    }
    let line = json!({
        "version": 1,
        "id": store::unattributed_id().await?,
        "kind": "held",
        "state": "held",
        "rail": intent.rail.as_str(),
        "amount_gbp": util::gbp(amount),
        "received_on": util::date_string(received),
        "amount_xmr": intent.amount_xmr.as_deref(),
        "txid": intent.txid.as_deref(),
        "intent": intent.id.as_str(),
        "note": note,
    });
    let encoded =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode the queue: {e}"))?;
    store
        .append(store::UNATTRIBUTED, encoded.as_bytes())
        .await?;
    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &ApplicationRef {
            username: String::new(),
            status_token: String::new(),
        },
        "applied",
        Some("held: the payment carries no token"),
    )
    .await?;
    store.remove("intents", file).await
}

/// Join a held payment to an account: the same arithmetic, account write,
/// payment copy and receipt as a credit, then the one ledger line for the token
/// and the held line marked `attributed`. The held line names the token it went
/// to and never the username, because the ledger outlives the account.
pub async fn reconcile_attribute(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    intent: AttributeIntent,
    file: &str,
    value: &Value,
) -> Result<(), String> {
    if !sign::verify(
        key,
        &sign::reconcile_attribute_payload(
            &intent.item,
            &intent.token,
            intent.confirm_double,
            intent.override_reason.as_deref(),
        ),
        &intent.sig,
    ) {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the reconcile-attribute intent's signature does not verify",
        )
        .await;
    }
    if !store::is_unattributed_id(&intent.item) {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the held item's id is not the shape of an unattributed payment",
        )
        .await;
    }
    if !store::is_payment_token(&intent.token) {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the token is not the shape of a payment token",
        )
        .await;
    }

    // The payment line is the settlement marker. A replay of the very intent
    // that attributed the item still has to finish marking the held line, if a
    // crash landed between the two writes.
    if ledger_has_intent(store, &intent.id).await {
        mark_attributed(store, &intent.item, &intent.token).await?;
        store.remove("intents", file).await?;
        return Ok(());
    }
    if journal_has(store, &intent.id, "refused").await {
        return Ok(());
    }

    let held = match store
        .held()
        .await?
        .into_iter()
        .find(|line| line.id == intent.item)
    {
        Some(held) => held,
        None => {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                &format!("no held payment with id {}", intent.item),
            )
            .await
        }
    };
    if held.state != "held" {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            &format!("{} is {}, not held", intent.item, held.state),
        )
        .await;
    }

    let (username, account, payment) = match resolve_payment(store, &intent.token).await {
        Ok(found) => found,
        Err(problem) => return refuse_with(cfg, store, file, value, &problem).await,
    };
    // The held line is data the console wrote earlier, so it is revalidated
    // exactly as a credit's fields are. The intent it carries is this intent's
    // id: the payment line and the journal are keyed by the join, not by the
    // hold.
    let payment_intent = CreditIntent {
        id: intent.id.clone(),
        kind: intent.kind.clone(),
        filed_at: intent.filed_at.clone(),
        token: intent.token.clone(),
        rail: held.rail.clone(),
        amount_gbp: held.amount_gbp.clone(),
        received: held.received_on.clone(),
        txid: held.txid.clone(),
        amount_xmr: held.amount_xmr.clone(),
        confirm_double: intent.confirm_double,
        override_reason: intent.override_reason.clone(),
        note: held.note.clone(),
        sig: String::new(),
    };
    let amount = match credit_fields(&payment_intent) {
        Ok(amount) => amount,
        Err(problem) => return refuse_with(cfg, store, file, value, &problem).await,
    };
    let received =
        util::parse_date(&payment_intent.received).expect("the date was validated above");
    let app = PaymentApplication {
        intent: &payment_intent,
        username: &username,
        account,
        payment,
        amount,
        received,
        attributed_item: Some(&intent.item),
    };
    if !apply_payment(cfg, store, file, value, app).await? {
        return Ok(());
    }
    mark_attributed(store, &intent.item, &intent.token).await?;
    store.remove("intents", file).await
}

/// Close a held payment with the evidence it went back or was kept. No payment
/// line and no notice: no money moved and no account was touched.
pub async fn reconcile_return(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    intent: ReturnIntent,
    file: &str,
    value: &Value,
) -> Result<(), String> {
    if !sign::verify(
        key,
        &sign::reconcile_return_payload(&intent.item, &intent.note),
        &intent.sig,
    ) {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the reconcile-return intent's signature does not verify",
        )
        .await;
    }
    if !store::is_unattributed_id(&intent.item) {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the held item's id is not the shape of an unattributed payment",
        )
        .await;
    }
    if journal_has(store, &intent.id, "refused").await {
        return Ok(());
    }
    let note = intent.note.trim();
    if note.is_empty() {
        return refuse_with(
            cfg,
            store,
            file,
            value,
            "the evidence for the return is needed",
        )
        .await;
    }
    let state = store
        .held()
        .await?
        .into_iter()
        .find(|line| line.id == intent.item)
        .map(|line| line.state);
    match state.as_deref() {
        None => {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                &format!("no held payment with id {}", intent.item),
            )
            .await
        }
        Some("held") => {}
        Some(other) => {
            return refuse_with(
                cfg,
                store,
                file,
                value,
                &format!("{} is {other}, not held", intent.item),
            )
            .await
        }
    }

    let evidence = format!("returned: {note}");
    let item = intent.item.clone();
    rewrite_unattributed(store, &item, |line| {
        if line.state != "held" {
            return Err(format!("{item} is {}, not held", line.state));
        }
        line.state = "returned".to_string();
        line.returned_at = Some(util::filed_at());
        // The original note is kept and the evidence is appended to it: what the
        // operator first wrote down is part of the item's history too.
        line.note = Some(match line.note.take() {
            Some(original) => format!("{original}; {evidence}"),
            None => evidence.clone(),
        });
        Ok(())
    })
    .await?;
    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &ApplicationRef {
            username: String::new(),
            status_token: String::new(),
        },
        "applied",
        None,
    )
    .await?;
    store.remove("intents", file).await
}

/// Mark one held line attributed to a token. Idempotent for the replay path, and
/// a returned item is refused rather than relabelled.
async fn mark_attributed(store: &Store, item: &str, token: &str) -> Result<(), String> {
    let id = item.to_string();
    let token = token.to_string();
    rewrite_unattributed(store, item, move |line| {
        if line.state == "returned" {
            return Err(format!("{id} was returned, so it cannot be attributed"));
        }
        if line.state == "held" {
            line.state = "attributed".to_string();
            line.attributed_at = Some(util::filed_at());
            line.attributed_to = Some(token);
        }
        Ok(())
    })
    .await
}

/// An exclusive lock on a store file, for the one record write that is not an
/// append: a reconcile reads every line and writes them back, and the drain and
/// the console are different processes, so a line appended between the read and
/// the write would be dropped by the rewrite.
///
/// The lock lives in a file of its own rather than on the record, as
/// `requests::lock` does: the rewrite replaces the record by rename, and a lock
/// on the replaced inode would stop guarding the path the moment the rename
/// landed. The caller owns the completion under this lock.
pub(crate) async fn lock_store_file(store: &Store, rel: &str) -> Result<tokio::fs::File, String> {
    if let Some(parent) = std::path::Path::new(rel).parent().and_then(|p| p.to_str()) {
        if !parent.is_empty() {
            store.ensure_dir(parent).await?;
        }
    }
    let path = store.path(rel);
    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).mode(0o600);
    let file = opts
        .open(&path)
        .await
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!(
            "cannot lock {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

/// Rewrite one held line under the queue's lock, through `change`.
async fn rewrite_unattributed(
    store: &Store,
    id: &str,
    change: impl FnOnce(&mut store::HeldItem) -> Result<(), String>,
) -> Result<(), String> {
    let _guard = lock_store_file(store, "ledger/.unattributed.lock").await?;
    let mut items = store.held().await?;
    let at = items
        .iter()
        .position(|line| line.id == id)
        .ok_or_else(|| format!("no held payment with id {id}"))?;
    change(&mut items[at])?;
    let mut bytes = String::new();
    for item in &items {
        bytes.push_str(
            &serde_json::to_string(item).map_err(|e| format!("cannot encode the queue: {e}"))?,
        );
        bytes.push('\n');
    }
    store
        .write_record("ledger", "unattributed.jsonl", bytes.as_bytes())
        .await
}

/// Whether the unattributed queue already holds this intent's line.
async fn held_has_intent(store: &Store, id: &str) -> Result<bool, String> {
    Ok(store.held().await?.iter().any(|line| line.intent == id))
}

/// The held line carrying this transaction id, with its id and the date it was
/// received, so a second sighting of one payment can name both.
async fn held_txid(store: &Store, txid: &str) -> Result<Option<(String, String)>, String> {
    Ok(store
        .held()
        .await?
        .into_iter()
        .find(|line| line.txid.as_deref() == Some(txid))
        .map(|line| (line.id, line.received_on)))
}

fn valid_txid(txid: Option<&str>) -> bool {
    match txid {
        None => true,
        Some(t) => t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()),
    }
}

/// An XMR amount is written as a decimal, never a float, with at most the
/// twelve decimal places the coin's atomic unit carries.
fn valid_xmr(amount: Option<&str>) -> bool {
    let Some(amount) = amount else {
        return true;
    };
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    !whole.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && fraction.len() <= 12
        && fraction.bytes().all(|b| b.is_ascii_digit())
}

/// What a credit's money does, in pence. Any amount at or above the price is
/// applied in full and the excess is held. A shortfall within one percent is
/// rounded up to the price, which absorbs the drift and the rounding; a larger
/// shortfall holds everything received and does not move the date, so the
/// remainder stays quoted.
struct CreditMoney {
    applied: i64,
    balance: i64,
    paid: bool,
}

fn credit_money(price: i64, balance: i64, amount: i64) -> CreditMoney {
    let total = balance + amount;
    if total >= price {
        // Anything above the price is held, however small: the band exists for
        // a shortfall, not for money that arrived.
        CreditMoney {
            applied: price,
            balance: total - price,
            paid: true,
        }
    } else if (price - total) as u64 * 100 <= price as u64 {
        // One percent, exactly: a 20.00 quote absorbs 19.80.
        CreditMoney {
            applied: price,
            balance: 0,
            paid: true,
        }
    } else {
        CreditMoney {
            applied: 0,
            balance: total,
            paid: false,
        }
    }
}

/// The values a credit recorded on its `applying` journal line, if it has got
/// that far. A pass that finds them again is recovering from a crash between the
/// account write and the ledger append, not applying a new credit.
async fn credit_progress(store: &Store, id: &str) -> Option<CreditProgress> {
    for line in store.lines("journal.jsonl").await {
        if let Ok(j) = serde_json::from_str::<JournalLine>(&line) {
            if j.intent == id && j.outcome == "applying" {
                if let Some(progress) = j.credit {
                    return Some(progress);
                }
            }
        }
    }
    None
}

/// Journal a credit's `applying` line with what it is about to write, so the
/// ledger line can be finished if the write succeeds and the append does not.
async fn journal_credit_applying(
    store: &Store,
    release: &str,
    intent: &CreditIntent,
    username: &str,
    progress: &CreditProgress,
) -> Result<(), String> {
    let line = JournalLine {
        version: 1,
        at: util::filed_at(),
        intent: intent.id.clone(),
        kind: intent.kind.clone(),
        release: release.to_string(),
        application: ApplicationRef {
            username: username.to_string(),
            status_token: String::new(),
        },
        outcome: "applying".to_string(),
        note: None,
        credit: Some(progress.clone()),
    };
    let encoded =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode a journal line: {e}"))?;
    store.append("journal.jsonl", encoded.as_bytes()).await
}

/// Journal a credit's completion, carrying an override's reason when there was
/// one.
async fn journal_credit_applied(
    cfg: &DrainConfig,
    store: &Store,
    intent: &CreditIntent,
    username: &str,
    override_reason: Option<&str>,
) -> Result<(), String> {
    let note = override_reason.map(|reason| format!("24-month override: {reason}"));
    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &ApplicationRef {
            username: username.to_string(),
            status_token: String::new(),
        },
        "applied",
        note.as_deref(),
    )
    .await
}

/// The ledger line carrying this transaction id, with the date it was first
/// credited and its `seq`, so a second credit can name both.
async fn ledger_txid(store: &Store, txid: &str) -> Option<(u64, String)> {
    for line in store.lines("ledger/payments.jsonl").await {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if v.get("txid").and_then(Value::as_str) == Some(txid) {
                let seq = v.get("seq").and_then(Value::as_u64).unwrap_or(0);
                let received = v
                    .get("received_on")
                    .and_then(Value::as_str)
                    .unwrap_or("an earlier date")
                    .to_string();
                return Some((seq, received));
            }
        }
    }
    None
}

/// Whether the ledger already holds this intent's line. Read as a `Value`
/// because a line written by a later release may carry fields this one does not
/// model.
async fn ledger_has_intent(store: &Store, id: &str) -> bool {
    store
        .lines("ledger/payments.jsonl")
        .await
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|v| v.get("intent").and_then(Value::as_str) == Some(id))
}

/// Rewrite the payment block on the application copy the handler reads, so a
/// status page that has the application still shows the credit rather than the
/// token. The account's copy is rewritten too; the applications copy only when
/// it still exists, because recreating a purged application would undo the
/// purge's own promise.
async fn write_payment_copy(
    store: &Store,
    username: &str,
    payment: &Payment,
) -> Result<(), String> {
    let Some(text) = store
        .read_record(&format!("accounts/{username}"), "application.json")
        .await
    else {
        return Ok(());
    };
    let mut copy: Value = serde_json::from_str(&text)
        .map_err(|e| format!("the application copy does not parse: {e}"))?;
    copy["payment"] = serde_json::to_value(payment)
        .map_err(|e| format!("cannot encode the payment block: {e}"))?;
    let bytes = serde_json::to_vec_pretty(&copy)
        .map_err(|e| format!("cannot encode the application copy: {e}"))?;
    store
        .write_record(&format!("accounts/{username}"), "application.json", &bytes)
        .await?;
    if let Some(token) = copy.get("status_token").and_then(Value::as_str) {
        if store
            .read_record("applications", &format!("{token}.json"))
            .await
            .is_some()
        {
            let owner = store.dir_owner("applications");
            store
                .write_record_owned("applications", &format!("{token}.json"), &bytes, owner)
                .await?;
        }
    }
    Ok(())
}

/// The next `seq`: one past the highest the ledger holds. Every ledger writer
/// goes through here, so a refund and a credit cannot both claim the same
/// number.
pub(crate) async fn next_ledger_seq(store: &Store) -> u64 {
    let mut seq = 0u64;
    for line in store.lines("ledger/payments.jsonl").await {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if let Some(s) = v.get("seq").and_then(Value::as_u64) {
                seq = seq.max(s);
            }
        }
    }
    seq + 1
}

/// Append the credit's line: the next `seq`, keyed by the token, with no
/// username. The rate fields stay null until the Monero quote lands (#303); the
/// XMR amount and the transaction id are recorded when the operator gave them.
async fn append_credit_ledger(
    store: &Store,
    intent: &CreditIntent,
    received_on: &str,
    amount_gbp: &str,
    applied_gbp: &str,
    paid_until_after: Option<&str>,
) -> Result<(), String> {
    let seq = next_ledger_seq(store).await;
    let line = json!({
        "version": 1,
        "seq": seq,
        "token": intent.token.as_str(),
        "kind": "payment",
        "rail": intent.rail.as_str(),
        "received_on": received_on,
        "amount_gbp": amount_gbp,
        "applied_gbp": applied_gbp,
        "paid_until_after": paid_until_after,
        "amount_xmr": intent.amount_xmr.as_deref(),
        "rate_quoted": Value::Null,
        "rate_source": Value::Null,
        "rate_at": Value::Null,
        "txid": intent.txid.as_deref(),
        "intent": intent.id.as_str(),
        "note": Value::Null,
    });
    let encoded =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode the ledger: {e}"))?;
    store
        .append("ledger/payments.jsonl", encoded.as_bytes())
        .await
}

/// The approval of a body's application: the community block's addresses become
/// one `provision-group` intent, which is then applied in this pass. The intent
/// is written before it is applied, so a crash between the two leaves the work
/// for the next pass rather than losing it.
///
/// Its name is a fresh ULID, so the intent directory's lexical order stays the
/// order things were filed; a replay files a second intent whose apply finds its
/// own accounts and makes nothing twice.
async fn approve_group(
    cfg: &DrainConfig,
    store: &Store,
    intent: &DecisionIntent,
    file: &str,
    record: &Record,
    no_charge: bool,
) -> Result<(), String> {
    let domain = record
        .domain
        .clone()
        .ok_or("the application names no domain")?;
    if let Some(why) = validate::domain(&domain) {
        return Err(format!("the domain {domain:?}: {why}"));
    }
    // The recipe is part of this approval, so a config the deploy never
    // substituted refuses before the group check, the journal line or any
    // account: a misconfigured box must not half-make a body on every pass.
    let values = dns::Values::from(cfg);
    values.check()?;
    // A group that is already there and was not made by this application is
    // somebody else's, and this approval must not adopt it. A retry of this
    // application's own approval has its "applying" line, the way the person
    // path's does.
    let existing_group = group_record(store, &domain).await?;
    if existing_group.is_some() && !approval_started(store, &record.status_token).await {
        return Err(format!(
            "the domain {domain} already has a group that this application did not make"
        ));
    }
    let (addresses, mailboxes) = group_addresses(record)?;
    let site_owner = site_owner(record, &mailboxes)?;
    // Every mailbox's key must be in hand before anything is journaled, so a
    // refusal records nothing and no intent is left for a name or a key the
    // applicant has to change.
    for mailbox in &mailboxes {
        if !record.mail_keys.iter().any(|k| &k.mailbox == mailbox) {
            return Err(format!(
                "the mailbox {mailbox} has no mail key, so its mail would bounce"
            ));
        }
    }
    // The recipient is read before the journal and the intent for the same
    // reason the person path does it: an address that cannot be mailed is a
    // refusal, not a group half-made and an applicant never told.
    let to = group_recipient(record, &site_owner, &domain)?;
    // Names, before the journal line and the intent: a reserved or taken name is
    // a refusal the reviewer has to take back to the applicant, not an approval
    // that started.
    check_group_names(cfg, store, &domain, &mailboxes, existing_group.as_ref()).await?;
    let name = record.answers.get("body_name").cloned().unwrap_or_default();
    let body_kind = record.answers.get("body_kind").cloned().unwrap_or_default();

    // The confirmation is the applicant's and goes before the body's accounts
    // exist, as it does on the person path. Every refusal above has already run,
    // so a refused application still sends nothing.
    confirm(cfg, store, &record.status_token, record).await?;

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

    // A fresh ULID rather than the status token: the intent directory sorts by
    // name and the loop reads it in that order, so every intent's name has to be
    // a ULID for a lexical sort to be an age sort.
    let id = ulid::Ulid::new().to_string();
    let group = json!({
        "id": id,
        "kind": "provision-group",
        "filed_at": util::filed_at(),
        "application": {
            "username": record.username,
            "status_token": record.status_token,
        },
        "domain": domain,
        "name": name,
        "body_kind": body_kind,
        "payment": {
            "rail": if no_charge { "no_charge" } else { record.rail.as_str() },
            "no_charge": no_charge,
            "paid_until": Value::Null,
        },
        "addresses": addresses,
        "mailboxes": mailboxes,
        "site_owner": site_owner,
        "upload_key": record.upload_key.as_ref().map(|k| k.material.clone()).unwrap_or_default(),
        "mail_keys": record.mail_keys,
    });
    let filename = format!("{id}.json");
    let bytes =
        serde_json::to_vec_pretty(&group).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store.write_record("intents", &filename, &bytes).await?;
    provision_group(cfg, store, &group, &filename).await?;

    // The body's approval notice: the recipe is the whole point of it, because
    // mail and the website do not work until the body has published the records
    // itself. It is recorded before it is enqueued, so a crash between the two
    // loses an email rather than sending two on the retry.
    let recipe = dns::recipe(&domain, &values);
    let subject = decision_subject("approved", &domain);
    let body = format!(
        "Your application for {domain} has been approved. The mailboxes in the group are \
         ready to receive mail as soon as the records below are live.\n\n{}",
        recipe.text()
    );
    notice::send_account_notice(
        cfg,
        store,
        &site_owner,
        "approval.body",
        &subject,
        &to,
        &body,
    )
    .await?;

    let now = util::filed_at();
    mark_decided(
        store,
        &record.status_token,
        "approved: a group was made",
        &now,
        None,
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

/// The address table the community block answered, paired with the account
/// names. An `own` line names a mailbox; an `alias` line points at one already
/// named, and the address shares that mailbox. The name on an alias line is not
/// used: the mailbox is the one its `own` target names.
fn group_addresses(record: &Record) -> Result<(Vec<GroupAddress>, Vec<String>), String> {
    let text = record
        .answers
        .get("body_addresses")
        .map(String::as_str)
        .unwrap_or("");
    if let Some(why) = validate::address_lines(text) {
        return Err(format!("the address table: {why}"));
    }
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let names = questions::account_names(&record.answers);
    if names.len() != lines.len() {
        return Err(format!(
            "{} addresses and {} account names; there is one name per address",
            lines.len(),
            names.len()
        ));
    }

    let mut own: BTreeMap<&str, &str> = BTreeMap::new();
    let mut seen = HashSet::new();
    let mut mailboxes: Vec<String> = Vec::new();
    for (line, name) in lines.iter().zip(&names) {
        let (local, rest) = line.split_once(':').ok_or_else(|| {
            format!("the address line {line:?} is not localpart: own or localpart: alias localpart")
        })?;
        let local = local.trim();
        if !seen.insert(local) {
            return Err(format!("the address {local} is in the table twice"));
        }
        if rest.trim() == "own" {
            if mailboxes.iter().any(|m| m == name) {
                return Err(format!(
                    "the mailbox {name} is named by two mailboxes; an alias shares a mailbox instead"
                ));
            }
            own.insert(local, name);
            mailboxes.push(name.clone());
        }
    }

    let mut addresses = Vec::new();
    for (line, name) in lines.iter().zip(&names) {
        let (local, rest) = line.split_once(':').ok_or_else(|| {
            format!("the address line {line:?} is not localpart: own or localpart: alias localpart")
        })?;
        let local = local.trim();
        if rest.trim() != "own" {
            let target = rest
                .trim()
                .strip_prefix("alias ")
                .map(str::trim)
                .unwrap_or_default();
            let shared = own.get(target).ok_or_else(|| {
                format!("the address {local} is an alias into {target}, which is not a mailbox in the table")
            })?;
            addresses.push(GroupAddress {
                address: local.to_string(),
                mailbox: (*shared).to_string(),
            });
            continue;
        }
        addresses.push(GroupAddress {
            address: local.to_string(),
            mailbox: name.clone(),
        });
    }
    Ok((addresses, mailboxes))
}

/// The account that owns the site. The community block names no site owner of
/// its own yet, so it is the applicant's account when the address table holds
/// it, and the first mailbox otherwise.
///
/// shortcut: the community block has no site-owner question yet, so the site is
/// the applicant's account when the table names it and the first mailbox
/// otherwise; add the question and read it here.
fn site_owner(record: &Record, mailboxes: &[String]) -> Result<String, String> {
    if mailboxes.iter().any(|m| m == &record.username) {
        return Ok(record.username.clone());
    }
    mailboxes.first().cloned().ok_or_else(|| {
        "the address table names no mailbox, so no account owns the site".to_string()
    })
}

/// The group record, when one is already there. A record that cannot be read or
/// parsed is an error rather than "no group": treating it as absent would let an
/// approval adopt accounts the record names.
pub async fn group_record(store: &Store, domain: &str) -> Result<Option<GroupRecord>, String> {
    let Some(text) = store
        .read_record(&format!("groups/{domain}"), "group.json")
        .await
    else {
        return Ok(None);
    };
    let record: GroupRecord = serde_json::from_str(&text)
        .map_err(|e| format!("groups/{domain}/group.json does not parse: {e}"))?;
    if record.version != 1 {
        return Err(format!(
            "groups/{domain}/group.json has version {}, which this build does not read",
            record.version
        ));
    }
    Ok(Some(record))
}

/// Refuse a mailbox name this group did not make. It runs before anything is
/// journaled or written, so a refusal records nothing; a retry finds its own
/// accounts named by the group record or by their group reference.
async fn check_group_names(
    cfg: &DrainConfig,
    store: &Store,
    domain: &str,
    mailboxes: &[String],
    record: Option<&GroupRecord>,
) -> Result<(), String> {
    for mailbox in mailboxes {
        name_allowed(cfg, mailbox).await?;
        let in_record = record
            .map(|g| g.accounts.iter().any(|a| a == mailbox))
            .unwrap_or(false);
        let existing = existing_account(store, mailbox).await;
        let in_account = existing
            .as_ref()
            .map(|a| a.group.as_deref() == Some(domain))
            .unwrap_or(false);
        if in_record || in_account {
            continue;
        }
        // A name a removed mailbox left is held for ninety days before the
        // group can reuse it. Both the approval and an add-mailbox pass here.
        if let Some(until) = name_held(store, mailbox).await? {
            return Err(format!(
                "the account name {mailbox} is held until {until}, so it cannot be reused yet"
            ));
        }
        if existing.is_some() {
            return Err(format!("the account name {mailbox} is already taken"));
        }
        if account_on_box(cfg, mailbox)? {
            return Err(format!(
                "the account name {mailbox} is already in use on this box"
            ));
        }
    }
    Ok(())
}

/// Apply one `provision-group` intent: the record, the accounts, the mail table
/// entries and the site owner's key. Everything is idempotent, so a retry after
/// a crash makes nothing twice.
pub async fn provision_group(
    cfg: &DrainConfig,
    store: &Store,
    value: &Value,
    file: &str,
) -> Result<(), String> {
    let intent: GroupIntent = serde_json::from_value(value.clone())
        .map_err(|e| format!("the group intent does not parse: {e}"))?;
    if intent.kind != "provision-group" {
        return Err(format!("kind {:?} is not a group intent", intent.kind));
    }
    if let Some(why) = validate::domain(&intent.domain) {
        return Err(format!("the domain {:?}: {why}", intent.domain));
    }
    if intent.mailboxes.is_empty() {
        return Err("the intent names no mailbox, so there is nothing to provision".to_string());
    }
    if !intent.mailboxes.iter().any(|m| m == &intent.site_owner) {
        return Err(format!(
            "the site owner {} is not one of the mailboxes",
            intent.site_owner
        ));
    }
    let mut mailboxes = HashSet::new();
    for mailbox in &intent.mailboxes {
        if !mailboxes.insert(mailbox.as_str()) {
            return Err(format!("the mailbox {mailbox} is named twice"));
        }
    }
    for address in &intent.addresses {
        if let Some(why) = validate::username_shape(&address.address) {
            return Err(format!("the address {:?}: {why}", address.address));
        }
        if !intent.mailboxes.iter().any(|m| m == &address.mailbox) {
            return Err(format!(
                "the address {}@{} points at {}, which is not a mailbox",
                address.address, intent.domain, address.mailbox
            ));
        }
    }
    let mut seen = HashSet::new();
    for address in &intent.addresses {
        if !seen.insert(address.address.as_str()) {
            return Err(format!(
                "the address {} is in the table twice",
                address.address
            ));
        }
    }

    // Every mailbox's key must be in hand before anything is made, so a missing
    // one cannot leave a half-made group whose mail bounces.
    let mut keys: BTreeMap<String, Vec<KeyRecord>> = BTreeMap::new();
    for mailbox in &intent.mailboxes {
        let mine: Vec<KeyRecord> = intent
            .mail_keys
            .iter()
            .filter(|k| &k.mailbox == mailbox)
            .cloned()
            .collect();
        if mine.is_empty() {
            return Err(format!(
                "the mailbox {mailbox} has no mail key, so its mail would bounce"
            ));
        }
        keys.insert(mailbox.clone(), mine);
    }

    // Names, before anything is written or journaled. A name this group did not
    // make is refused rather than adopted: the box and the account record are
    // both oracles, and a retry finds its own accounts named by the group record
    // or by their group reference.
    let record = group_record(store, &intent.domain).await?;
    check_group_names(
        cfg,
        store,
        &intent.domain,
        &intent.mailboxes,
        record.as_ref(),
    )
    .await?;

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

    // The record first: it is what tells a retry which accounts on the box are
    // this group's.
    let group = GroupRecord {
        version: 1,
        domain: intent.domain.clone(),
        name: intent.name.clone(),
        kind: intent.body_kind.clone(),
        payment: GroupPayment {
            rail: intent.payment.rail.clone(),
            no_charge: intent.payment.no_charge,
            paid_until: intent.payment.paid_until.clone(),
            stripe: intent.payment.stripe.clone(),
        },
        accounts: intent.mailboxes.clone(),
        site_owner: intent.site_owner.clone(),
    };
    write_group_record(store, &group).await?;

    // The mail tables before the accounts: provision-member.sh restarts smtpd
    // when it adds a new account's platform address, and that restart is what
    // makes these lines live.
    ensure_table_line(&cfg.mail_domains, &intent.domain, None)?;
    ensure_table_line(&cfg.dkim_domains, &intent.domain, None)?;
    for address in &intent.addresses {
        ensure_table_line(
            &cfg.virtuals,
            &format!("{}@{}", address.address, intent.domain),
            Some(&address.mailbox),
        )?;
    }

    let app_copy = application_copy(store, &intent.application.status_token).await?;

    // Every account and its keyring entry first. The public publish is a network
    // call to the forge, and it runs in a second loop so a forge outage cannot
    // leave a later mailbox uncreated while its virtual entry already accepts
    // mail.
    for mailbox in &intent.mailboxes {
        if let Some(mine) = keys.get(mailbox) {
            publish_mail_keys(cfg, mailbox, mine).await?;
        }
        if !account_on_box(cfg, mailbox)? {
            run_script_tolerating(cfg, "add-user.sh", &[mailbox], "already exists").await?;
        }
        // The block's upload key is the site owner's, and only theirs: it fills
        // the site tree and reaches the repositories, so it goes in the one
        // account named to own the site.
        if mailbox == &intent.site_owner && !intent.upload_key.trim().is_empty() {
            write_public_key(store, mailbox, &intent.upload_key).await?;
        }
        run_script(cfg, "provision-member.sh", &[mailbox]).await?;
        write_group_account(store, mailbox, &intent.domain, &intent.payment).await?;
        write_group_application(store, mailbox, app_copy.as_deref()).await?;
    }
    // The published set is what the drift check compares the keyring against.
    for mailbox in &intent.mailboxes {
        if let Some(mine) = keys.get(mailbox) {
            publish_mail_keys_publicly(cfg, mailbox, mine).await?;
        }
    }

    // The body's hosting, rooted in the site owner's own tree. The upload key
    // decides hosting the way it does for a member: provision-member.sh builds
    // no tree without one, so a group that left it empty has no site to serve
    // and the lanes would refuse.
    if !intent.upload_key.trim().is_empty() {
        run_script(
            cfg,
            "provision-group-web.sh",
            &[&intent.domain, &intent.site_owner],
        )
        .await?;
        run_script(
            cfg,
            "provision-group-capsule.sh",
            &[&intent.domain, &intent.site_owner],
        )
        .await?;
        run_script(
            cfg,
            "provision-group-acme.sh",
            &[&intent.domain, &intent.site_owner],
        )
        .await?;
        // New daemon files, so the index and reload pass runs, the same one a
        // person's hosting approval runs.
        run_script(cfg, "cron-apply.sh", &["--web"]).await?;
    }

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

/// The application's own copy, written into each mailbox's account so the block's
/// answers sit inside the ninety-day purge with the rest of the application. The
/// status link's end is stamped the way the person path's copy is.
async fn application_copy(store: &Store, token: &str) -> Result<Option<String>, String> {
    let Some(text) = store
        .read_record("applications", &format!("{token}.json"))
        .await
    else {
        return Ok(None);
    };
    let mut value: Value =
        serde_json::from_str(&text).map_err(|e| format!("the application record: {e}"))?;
    value["status_link_until"] = json!(util::after_days(7));
    let bytes = serde_json::to_string_pretty(&value)
        .map_err(|e| format!("cannot encode the application copy: {e}"))?;
    Ok(Some(bytes))
}

/// One mailbox's copy of the application, when the application record is still
/// there. A retry rewrites the same bytes.
async fn write_group_application(
    store: &Store,
    mailbox: &str,
    copy: Option<&str>,
) -> Result<(), String> {
    let Some(copy) = copy else {
        return Ok(());
    };
    store.ensure_dir(&format!("accounts/{mailbox}")).await?;
    store
        .write_record(
            &format!("accounts/{mailbox}"),
            "application.json",
            copy.as_bytes(),
        )
        .await
}

/// The mailbox's account record: a reference to its group and no payment block
/// of its own, which the group holds. A retry keeps the dates the first run
/// wrote, so applying the same intent twice changes nothing.
async fn write_group_account(
    store: &Store,
    mailbox: &str,
    domain: &str,
    payment: &GroupPayment,
) -> Result<(), String> {
    let existing = existing_account(store, mailbox).await;
    let now = util::filed_at();
    let account = Account {
        version: 1,
        username: mailbox.to_string(),
        state: "active".to_string(),
        decision: "approve".to_string(),
        decided_at: existing
            .as_ref()
            .map(|a| a.decided_at.clone())
            .unwrap_or_else(|| now.clone()),
        rail: if payment.no_charge {
            "no_charge".to_string()
        } else {
            payment.rail.clone()
        },
        no_charge: payment.no_charge,
        created_at: existing
            .as_ref()
            .map(|a| a.created_at.clone())
            .unwrap_or_else(|| now.clone()),
        // The group holds the payment state, so the mailbox's record has no
        // block for one at all rather than a paid-until that could be mistaken
        // for an unpaid person's.
        payment: None,
        legacy_payment: FlatPayment::default(),
        outside_address: None,
        certificates: Vec::new(),
        site_served: None,
        capsule_served: None,
        space_used: None,
        group: Some(domain.to_string()),
        closing_until: None,
    };
    let bytes = serde_json::to_vec_pretty(&account)
        .map_err(|e| format!("cannot encode the account: {e}"))?;
    store.ensure_dir(&format!("accounts/{mailbox}")).await?;
    store
        .write_record(&format!("accounts/{mailbox}"), "account.json", &bytes)
        .await
}

/// Write one group's record. The caller owns the directory name, which is the
/// validated domain, so a record can never land outside `groups/`.
async fn write_group_record(store: &Store, group: &GroupRecord) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(group)
        .map_err(|e| format!("cannot encode the group record: {e}"))?;
    store
        .ensure_dir(&format!("groups/{}", group.domain))
        .await?;
    store
        .write_record(&format!("groups/{}", group.domain), "group.json", &bytes)
        .await
}

/// Ensure one line is in a virtual table: a bare value when `value` is `None`
/// (a `mail_domains` line), and `name: value` otherwise (a `virtuals` entry). A
/// key already present with the same value is left alone; one present with a
/// different value is a refusal, because overruling it would silently redirect
/// somebody's mail. Written through a temporary in the same directory, so smtpd
/// never reads half a table.
fn ensure_table_line(path: &str, name: &str, value: Option<&str>) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}; run scripts/deploy-mail.sh first: {e}"))?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match value {
            None if line == name => return Ok(()),
            None => {}
            Some(want) => {
                let (key, have) = line.split_once(':').unwrap_or((line, ""));
                if key.trim() == name {
                    if have.trim() == want {
                        return Ok(());
                    }
                    return Err(format!(
                        "{path} already maps {name} to {}, not {want}",
                        have.trim()
                    ));
                }
            }
        }
    }
    let line = match value {
        Some(v) => format!("{name}: {v}"),
        None => name.to_string(),
    };
    // Append rather than rewrite. A rewrite reads the whole table and renames a
    // copy over it, so a line another drain pass appended between the read and
    // the rename is lost; two passes can overlap (cron does not lock, and one
    // approval runs subprocesses and a network call). One append cannot lose a
    // line. The newline guard is the same one deploy-mail.sh uses: a hand edit
    // may have left the last line unterminated.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open {path}: {e}"))?;
    let mut entry = String::new();
    if !text.is_empty() && !text.ends_with('\n') {
        entry.push('\n');
    }
    entry.push_str(&line);
    entry.push('\n');
    std::io::Write::write_all(&mut file, entry.as_bytes())
        .map_err(|e| format!("cannot append to {path}: {e}"))
}

/// The value a virtual table maps `name` to, or `None` when the key is absent.
fn table_value(path: &str, name: &str) -> Result<Option<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}; run scripts/deploy-mail.sh first: {e}"))?;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim() == name {
                return Ok(Some(value.trim().to_string()));
            }
        }
    }
    Ok(None)
}

/// How many addresses the body's domain has: every `<localpart>@<domain>` line,
/// mailboxes and aliases alike, which is the ten-address cap's count.
fn address_count(path: &str, domain: &str) -> Result<usize, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}; run scripts/deploy-mail.sh first: {e}"))?;
    let suffix = format!("@{domain}");
    Ok(text
        .lines()
        .filter(|line| {
            line.split_once(':')
                .map(|(key, _)| key.trim().ends_with(&suffix))
                .unwrap_or(false)
        })
        .count())
}

/// Rewrite a table through a temporary beside it, then rename it into place.
fn write_table(path: &str, text: &str) -> Result<(), String> {
    let candidate = format!("{path}.onboard.{}", std::process::id());
    std::fs::write(&candidate, text).map_err(|e| format!("cannot write {candidate}: {e}"))?;
    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("cannot set the mode on {candidate}: {e}"))?;
    std::fs::rename(&candidate, path).map_err(|e| format!("cannot replace {path}: {e}"))
}

/// Repoint an existing virtual entry, keeping every other line. A value that is
/// already right is left alone, so an upgrade intent applied twice changes
/// nothing. `ensure_table_line` refuses a different value on purpose (it must
/// not overrule a line somebody else made), so this is the explicit repoint.
///
/// shortcut: a rewrite can drop a line another pass appends between the read and
/// the rename; only the operator's own upgrade takes this path, and the drain
/// does not run two address changes at once.
fn repoint_table_line(path: &str, name: &str, want: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}; run scripts/deploy-mail.sh first: {e}"))?;
    let mut out = String::new();
    let mut found = false;
    for line in text.lines() {
        if let Some((key, have)) = line.split_once(':') {
            if key.trim() == name {
                if have.trim() == want {
                    return Ok(());
                }
                out.push_str(&format!("{name}: {want}\n"));
                found = true;
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if !found {
        return ensure_table_line(path, name, Some(want));
    }
    write_table(path, &out)
}

/// Drop every line for `domain` that points at `mailbox`. That is the mailbox's
/// own address and any alias into it, so no entry is left delivering nowhere.
/// Returns whether the table changed.
fn remove_addresses(path: &str, domain: &str, mailbox: &str) -> Result<bool, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}; run scripts/deploy-mail.sh first: {e}"))?;
    let suffix = format!("@{domain}");
    let mut out = String::new();
    let mut changed = false;
    for line in text.lines() {
        let remove = line
            .split_once(':')
            .map(|(key, value)| key.trim().ends_with(&suffix) && value.trim() == mailbox)
            .unwrap_or(false);
        if remove {
            changed = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if changed {
        write_table(path, &out)?;
    }
    Ok(changed)
}

/// A username's hold, while it still has time to run. The date is the record's;
/// a record that cannot be dated has no hold, so a broken file does not keep a
/// name held forever.
async fn name_held(store: &Store, username: &str) -> Result<Option<String>, String> {
    let Some(text) = store
        .read_record("holds", &format!("{username}.json"))
        .await
    else {
        return Ok(None);
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return Ok(None);
    };
    let Some(until) = value.get("until").and_then(Value::as_str) else {
        return Ok(None);
    };
    match OffsetDateTime::parse(until, &Rfc3339) {
        Ok(at) if at > OffsetDateTime::now_utc() => Ok(Some(until.to_string())),
        _ => Ok(None),
    }
}

/// Hold a closed account's name for ninety days. Written only when there is no
/// live hold, so a retry keeps the date the removal first set rather than
/// pushing the release out by another pass.
async fn hold_name(store: &Store, username: &str) -> Result<(), String> {
    if name_held(store, username).await?.is_some() {
        return Ok(());
    }
    let bytes = serde_json::to_vec_pretty(&json!({
        "username": username,
        "until": util::after_days(90),
    }))
    .map_err(|e| format!("cannot encode the hold: {e}"))?;
    store.ensure_dir("holds").await?;
    store
        .write_record("holds", &format!("{username}.json"), &bytes)
        .await
}

/// The three steps that close one mailbox: its name held for ninety days, its
/// stored upload key dropped, and scripts/delete-user.sh, which removes the box
/// account, its tree, its quota record and its store record. Shared by a
/// mailbox leaving a group and a whole group going, so the two cannot disagree
/// about what a closed account is. The caller removes the virtual entry first,
/// because it is the one that knows which table line belongs to the account.
async fn close_mailbox(cfg: &DrainConfig, store: &Store, username: &str) -> Result<(), String> {
    hold_name(store, username).await?;
    store.remove("keys", &format!("{username}.pub")).await?;
    run_script(cfg, "delete-user.sh", &[username]).await
}

/// The mail key a new mailbox carries, checked before anything is written: the
/// material must be there and must be the mailbox's own key.
fn address_key(intent: &GroupAddressIntent) -> Result<KeyRecord, String> {
    let Some(key) = intent.mail_key.as_ref() else {
        return Err(format!(
            "the mailbox {} has no mail key, so its mail would bounce",
            intent.mailbox
        ));
    };
    if !key.mailbox.is_empty() && key.mailbox != intent.mailbox {
        return Err(format!(
            "the mail key names {}, not {}",
            key.mailbox, intent.mailbox
        ));
    }
    if key.material.trim().is_empty() {
        return Err(format!("the mail key for {} is empty", intent.mailbox));
    }
    // The console carries whatever file the operator named. A private key, an
    // SSH key or a truncated block would reach the encryptor's keyring and
    // fail closed, so the shared check refuses it before the journal line.
    let checked = crate::keycheck::pgp_public_key(&key.material)
        .map_err(|e| format!("the mail key for {}: {e}", intent.mailbox))?;
    let mut key = key.clone();
    key.mailbox = intent.mailbox.clone();
    key.verdict = checked.verdict;
    Ok(key)
}

/// Apply one `group-address` intent: a change inside a body's group that must
/// not touch the price or the group's paid-until date. Every step is idempotent,
/// and every check runs before the journal line and the first write, so a
/// refused intent changes nothing.
pub async fn group_address(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    value: &Value,
    file: &str,
) -> Result<(), String> {
    let intent: GroupAddressIntent = serde_json::from_value(value.clone())
        .map_err(|e| format!("the address intent does not parse: {e}"))?;
    if intent.kind != "group-address" {
        return Err(format!("kind {:?} is not an address intent", intent.kind));
    }
    let site_owner = intent.site_owner.as_deref().unwrap_or("");
    if !sign::verify(
        key,
        &sign::address_payload(
            &intent.domain,
            &intent.action,
            &intent.address,
            &intent.mailbox,
            site_owner,
            intent
                .mail_key
                .as_ref()
                .map(|k| k.material.as_str())
                .unwrap_or(""),
        ),
        &intent.sig,
    ) {
        return Err("the address intent's signature does not verify".to_string());
    }
    if !ADDRESS_ACTIONS.contains(&intent.action.as_str()) {
        return Err(format!("{:?} is not an address change", intent.action));
    }
    if let Some(why) = validate::domain(&intent.domain) {
        return Err(format!("the domain {:?}: {why}", intent.domain));
    }
    let Some(mut group) = group_record(store, &intent.domain).await? else {
        return Err(format!(
            "there is no group for {}, so there is no address to change",
            intent.domain
        ));
    };
    if let Some(why) = validate::username_shape(&intent.mailbox) {
        return Err(format!("the mailbox {:?}: {why}", intent.mailbox));
    }
    if intent.action != "remove" {
        if let Some(why) = validate::username_shape(&intent.address) {
            return Err(format!("the address {:?}: {why}", intent.address));
        }
    }

    let entry = format!("{}@{}", intent.address, intent.domain);
    let current = match intent.action.as_str() {
        "remove" => None,
        _ => table_value(&cfg.virtuals, &entry)?,
    };
    let in_group = |mailbox: &str| group.accounts.iter().any(|a| a == mailbox);

    match intent.action.as_str() {
        "add-alias" => {
            if !in_group(&intent.mailbox) {
                return Err(format!(
                    "the alias {}@{} points at {}, which is not a mailbox in the group",
                    intent.address, intent.domain, intent.mailbox
                ));
            }
            match &current {
                Some(have) if have == &intent.mailbox => {}
                Some(have) => {
                    return Err(format!(
                        "{} already maps {entry} to {have}, not {}",
                        cfg.virtuals, intent.mailbox
                    ))
                }
                None if address_count(&cfg.virtuals, &intent.domain)? >= 10 => {
                    return Err(format!(
                        "{} already carries ten addresses, so {entry} cannot be added",
                        intent.domain
                    ))
                }
                None => {}
            }
        }
        "add-mailbox" => {
            address_key(&intent)?;
            if let Some(have) = &current {
                if have != &intent.mailbox {
                    return Err(format!(
                        "{} already maps {entry} to {have}, not {}",
                        cfg.virtuals, intent.mailbox
                    ));
                }
            }
            if !in_group(&intent.mailbox) {
                check_group_names(
                    cfg,
                    store,
                    &intent.domain,
                    std::slice::from_ref(&intent.mailbox),
                    Some(&group),
                )
                .await?;
            }
            // The cap counts new entries, whether or not the mailbox itself is
            // already in the group: a second address into an existing mailbox
            // still costs one of the ten.
            if current.is_none() && address_count(&cfg.virtuals, &intent.domain)? >= 10 {
                return Err(format!(
                    "{} already carries ten addresses, so {} cannot be added",
                    intent.domain, entry
                ));
            }
        }
        "upgrade" => {
            address_key(&intent)?;
            match &current {
                None => {
                    return Err(format!(
                        "{} is not an address in {}, so there is no alias to upgrade",
                        entry, intent.domain
                    ))
                }
                Some(have) if have == &intent.mailbox => {}
                Some(have) => {
                    if !in_group(have) {
                        return Err(format!(
                            "{} points at {have}, which is not a mailbox in the group",
                            entry
                        ));
                    }
                }
            }
            if !in_group(&intent.mailbox) {
                check_group_names(
                    cfg,
                    store,
                    &intent.domain,
                    std::slice::from_ref(&intent.mailbox),
                    Some(&group),
                )
                .await?;
            }
        }
        "remove" => {
            if group.site_owner == intent.mailbox {
                let Some(replacement) = intent.site_owner.as_deref() else {
                    return Err(format!(
                        "{} owns the site, so the intent must name the account that takes it",
                        intent.mailbox
                    ));
                };
                if replacement == intent.mailbox || !in_group(replacement) {
                    return Err(format!(
                        "the replacement site owner {replacement} is not another mailbox in the group"
                    ));
                }
            }
            let existing = existing_account(store, &intent.mailbox).await;
            let ours = existing
                .as_ref()
                .map(|a| a.group.as_deref() == Some(intent.domain.as_str()))
                .unwrap_or(false);
            if !in_group(&intent.mailbox) && !ours && account_on_box(cfg, &intent.mailbox)? {
                return Err(format!(
                    "the account {} is not a mailbox in {}",
                    intent.mailbox, intent.domain
                ));
            }
        }
        _ => unreachable!("the action was checked against ADDRESS_ACTIONS"),
    }

    let application = ApplicationRef {
        username: intent.mailbox.clone(),
        status_token: intent.domain.clone(),
    };
    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &application,
        "applying",
        None,
    )
    .await?;

    match intent.action.as_str() {
        "add-alias" => {
            ensure_table_line(&cfg.virtuals, &entry, Some(&intent.mailbox))?;
            // smtpd reads the table at start and has no reload verb, so the
            // alias does not deliver until it restarts.
            run_script(cfg, "reload-smtpd.sh", &[]).await?;
        }
        "add-mailbox" => {
            // The record first, as a group's own provisioning does: it is what
            // tells a retry that an account on the box is this group's.
            if !in_group(&intent.mailbox) {
                group.accounts.push(intent.mailbox.clone());
                write_group_record(store, &group).await?;
            }
            let key = address_key(&intent)?;
            ensure_table_line(&cfg.virtuals, &entry, Some(&intent.mailbox))?;
            publish_mail_keys(cfg, &intent.mailbox, std::slice::from_ref(&key)).await?;
            if !account_on_box(cfg, &intent.mailbox)? {
                run_script_tolerating(cfg, "add-user.sh", &[&intent.mailbox], "already exists")
                    .await?;
            }
            run_script(cfg, "provision-member.sh", &[&intent.mailbox]).await?;
            write_group_account(store, &intent.mailbox, &intent.domain, &group.payment).await?;
            publish_mail_keys_publicly(cfg, &intent.mailbox, std::slice::from_ref(&key)).await?;
        }
        "upgrade" => {
            if !in_group(&intent.mailbox) {
                group.accounts.push(intent.mailbox.clone());
                write_group_record(store, &group).await?;
            }
            let key = address_key(&intent)?;
            publish_mail_keys(cfg, &intent.mailbox, std::slice::from_ref(&key)).await?;
            if !account_on_box(cfg, &intent.mailbox)? {
                run_script_tolerating(cfg, "add-user.sh", &[&intent.mailbox], "already exists")
                    .await?;
            }
            run_script(cfg, "provision-member.sh", &[&intent.mailbox]).await?;
            write_group_account(store, &intent.mailbox, &intent.domain, &group.payment).await?;
            repoint_table_line(&cfg.virtuals, &entry, &intent.mailbox)?;
            // The repoint is a table rewrite after the builder's own restart,
            // and a retry that finds the account already made restarts nothing.
            // Without this the upgraded address keeps reaching the shared
            // mailbox.
            run_script(cfg, "reload-smtpd.sh", &[]).await?;
            publish_mail_keys_publicly(cfg, &intent.mailbox, std::slice::from_ref(&key)).await?;
        }
        "remove" => {
            // What this pass actually closes. A mistyped name that is neither in
            // the group nor on the box closes nothing, so it must not start a
            // ninety-day hold either.
            let closing = in_group(&intent.mailbox)
                || existing_account(store, &intent.mailbox).await.is_some()
                || account_on_box(cfg, &intent.mailbox)?;
            // Only a pass that still sees the departing mailbox owning the site
            // moves the upload key and the lanes. Once the group record names
            // the replacement, a retry must not copy anything: an intent that
            // merely named the sitting owner while removing somebody else would
            // otherwise hand that member's key to the site.
            let site_owner_leaving = group.site_owner == intent.mailbox;
            if site_owner_leaving {
                let replacement = intent
                    .site_owner
                    .as_deref()
                    .ok_or("the site owner is leaving without a replacement")?;
                let old_key = store
                    .read_record("keys", &format!("{}.pub", intent.mailbox))
                    .await;
                if let Some(material) = &old_key {
                    write_public_key(store, replacement, material).await?;
                }
                run_script(cfg, "provision-member.sh", &[replacement]).await?;
                group.site_owner = replacement.to_string();
            }
            group.accounts.retain(|a| a != &intent.mailbox);
            write_group_record(store, &group).await?;
            if remove_addresses(&cfg.virtuals, &intent.domain, &intent.mailbox)? {
                // delete-user.sh restarts smtpd only when it removed a line;
                // the lines have gone here, so this pass makes them live.
                run_script(cfg, "reload-smtpd.sh", &[]).await?;
            }
            // The box keyring entry stays, as delete-user.sh leaves it:
            // check-keyring-drift.sh reports a published key absent from the
            // box, and the published key's removal is the operator's step
            // (there is no unpublish path in this tree yet).
            if intent.site_owner.is_some() {
                // After the record names the replacement and before the old
                // tree goes: the vhost root must not point at a directory
                // delete-user.sh is about to remove.
                run_script(cfg, "cron-apply.sh", &["--web"]).await?;
            }
            if closing {
                close_mailbox(cfg, store, &intent.mailbox).await?;
            } else {
                store
                    .remove("keys", &format!("{}.pub", intent.mailbox))
                    .await?;
                run_script(cfg, "delete-user.sh", &[&intent.mailbox]).await?;
            }
        }
        _ => unreachable!("the action was checked against ADDRESS_ACTIONS"),
    }

    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &application,
        "applied",
        None,
    )
    .await?;
    store.remove("intents", file).await
}

/// Apply one `remove-group` intent: take a body's domain off the box whole.
///
/// The order is the deletion transition's. The host files go first through
/// scripts/remove-group.sh, then the index and reload pass, so nothing is
/// served from a tree the accounts' deletion is about to remove. The accounts
/// close through the same three steps a mailbox leaving a group takes, and the
/// group record is the last store write: while it is there a retry can still
/// find every account it has to close.
///
/// Idempotent on replay and after a partial crash. The journal is the marker: a
/// line that says `applied` means the domain is down, so the pass only clears
/// the record directory and the intent file. A crash before that line leaves
/// the group record in place, so the next pass finds its accounts again and
/// every step below is a no-op over what is already gone.
pub async fn remove_group(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    value: &Value,
    file: &str,
) -> Result<(), String> {
    let intent: GroupRemoveIntent = serde_json::from_value(value.clone())
        .map_err(|e| format!("the remove-group intent does not parse: {e}"))?;
    if intent.kind != "remove-group" {
        return Err(format!(
            "kind {:?} is not a remove-group intent",
            intent.kind
        ));
    }
    if !sign::verify(
        key,
        &sign::group_remove_payload(&intent.domain),
        &intent.sig,
    ) {
        return Err("the remove-group intent's signature does not verify".to_string());
    }
    if let Some(why) = validate::domain(&intent.domain) {
        return Err(format!("the domain {:?}: {why}", intent.domain));
    }

    // A replay whose transition finished: the domain is already down, so only
    // the record directory and the file can be left, and both may be gone.
    if journal_has(store, &intent.id, "applied").await {
        remove_group_record(store, &intent.domain).await?;
        return store.remove("intents", file).await;
    }

    let Some(group) = group_record(store, &intent.domain).await? else {
        return Err(format!(
            "there is no group for {}, so there is no domain to remove",
            intent.domain
        ));
    };
    let application = ApplicationRef {
        username: group.site_owner.clone(),
        status_token: intent.domain.clone(),
    };
    if !journal_has(store, &intent.id, "applying").await {
        journal(
            store,
            &cfg.release,
            &intent.id,
            &intent.kind,
            &application,
            "applying",
            None,
        )
        .await?;
    }

    // The mail tables, the generated blocks, the certificate material and the
    // queued order. Then the pass that rewrites the indexes and drops the
    // relayd keypair line the httpd file carried, which only the reload applies.
    run_script(cfg, "remove-group.sh", &[&intent.domain]).await?;
    run_script(cfg, "cron-apply.sh", &["--web"]).await?;

    for account in &group.accounts {
        close_mailbox(cfg, store, account).await?;
    }
    // After the accounts, so a crash between the two steps leaves the record
    // that names them and the retry finds the token again.
    close_group_tokens(store, &group.accounts).await?;

    journal(
        store,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &application,
        "applied",
        None,
    )
    .await?;
    remove_group_record(store, &intent.domain).await?;
    store.remove("intents", file).await
}

/// Remove the group's directory, record and all. A directory that is not there
/// reads as done, the same rule `Store::remove` applies to a file.
async fn remove_group_record(store: &Store, domain: &str) -> Result<(), String> {
    let dir = store.path(&format!("groups/{domain}"));
    match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove {}: {e}", dir.display())),
    }
}

/// Drop every token index entry that resolves to one of the group's accounts,
/// so the ledger rows keyed by those tokens no longer name an account. The scan
/// is by `TokenRecord.username` rather than by the filename, because the
/// directory also holds tokens that are not these accounts' and the record is
/// what says whose one is.
async fn close_group_tokens(store: &Store, accounts: &[String]) -> Result<(), String> {
    for name in store.list("tokens").await? {
        if !name.ends_with(".json") {
            continue;
        }
        let Some(text) = store.read_record("tokens", &name).await else {
            continue;
        };
        let Ok(token) = serde_json::from_str::<TokenRecord>(&text) else {
            continue;
        };
        if accounts.iter().any(|account| account == &token.username) {
            store.remove("tokens", &name).await?;
        }
    }
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

/// How often a group's published records are looked at. The drain runs every
/// minute, and a DNS query per group per minute is noise on the resolver and on
/// the body's authority: six hours notices an outage the same day and is far
/// inside the certificate queue's patience.
const DNS_CHECK_HOURS: i64 = 6;

/// Watch every group's zone for records that have stopped resolving.
///
/// The platform does not host a body's zone and cannot repair it. This sweep is
/// the whole of what it can do: a query, one notice to the DNS contact the
/// application gave or the accountable address otherwise, and a state file so
/// one outage is one mail rather than one per pass. It writes nothing outside
/// `groups/<domain>/dns-check.json`; the group record and the body's zone are
/// untouched.
pub async fn check_group_dns(cfg: &DrainConfig, store: &Store) -> Result<(), String> {
    let values = dns::Values::from(cfg);
    if let Err(e) = values.check() {
        // The approval already refuses a placeholder; a box that has one has no
        // published values to watch, and that is not a reason to hold the pass.
        eprintln!("kyriakon-onboard: {e}");
        return Ok(());
    }
    let now = OffsetDateTime::now_utc();
    for name in store.list("groups").await? {
        if name.starts_with('.') {
            continue;
        }
        let Some(text) = store
            .read_record(&format!("groups/{name}"), "group.json")
            .await
        else {
            continue;
        };
        let group: GroupRecord = match serde_json::from_str(&text) {
            Ok(group) => group,
            Err(e) => {
                eprintln!("kyriakon-onboard: groups/{name}/group.json does not parse: {e}");
                continue;
            }
        };
        // One group's bad record, failed write or refused notice is reported
        // and skipped: the other groups are still watched and the pass goes on.
        if let Err(e) = check_one_group(cfg, store, &values, &group, now).await {
            eprintln!("kyriakon-onboard: watching {}: {e}", group.domain);
        }
    }
    Ok(())
}

/// One group's due check and, on an outage, its one notice.
async fn check_one_group(
    cfg: &DrainConfig,
    store: &Store,
    values: &dns::Values,
    group: &GroupRecord,
    now: OffsetDateTime,
) -> Result<(), String> {
    let state: Option<Value> = store
        .read_record(&format!("groups/{}", group.domain), "dns-check.json")
        .await
        .and_then(|t| serde_json::from_str(&t).ok());
    let checked_at = state
        .as_ref()
        .and_then(|s| s.get("checked_at"))
        .and_then(Value::as_str)
        .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok());
    let was_broken = state
        .as_ref()
        .and_then(|s| s.get("broken"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let notified = state
        .as_ref()
        .and_then(|s| s.get("notified"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // A broken zone whose notice has not gone yet is retried on the next pass,
    // not six hours later: the state is written before the send so a crash
    // cannot lose the outage, and the notice itself is deduplicated.
    let pending = was_broken && !notified;
    if !pending && checked_at.is_some_and(|at| now - at < Duration::hours(DNS_CHECK_HOURS)) {
        return Ok(());
    }

    let broken = dns_broken(cfg, values, &group.domain).await?;
    let checked = util::filed_at();
    if !broken {
        write_dns_state(store, &group.domain, &checked, false, None, false).await?;
        return Ok(());
    }
    let outage = state
        .as_ref()
        .and_then(|s| s.get("outage"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| checked.clone());
    if !notified {
        // The outage is recorded before the message, so a crash between the two
        // retries the same subject and `notices.jsonl` suppresses the duplicate;
        // the state is the second write that closes it.
        write_dns_state(store, &group.domain, &checked, true, Some(&outage), false).await?;
        let to = dns_contact(store, group).await?;
        let subject = format!(
            "The DNS records for {} are not resolving ({outage})",
            group.domain
        );
        let body = format!(
            "One or more of the records in {domain}'s zone that the platform watches no \
             longer resolve. If the MX, A or AAAA row is the one missing, mail to {domain} \
             stops arriving and the website's certificate cannot renew.\n\n\
             The platform does not host the zone, cannot set a reverse record for it, \
             and cannot change it. Restore the MX, A, AAAA, SPF, DKIM and DMARC records \
             your approval email lists at your own DNS provider, and they will be \
             observed again on the next check. This notice is sent once per outage.\n",
            domain = group.domain
        );
        notice::send_account_notice(
            cfg,
            store,
            &group.site_owner,
            "dns.broken",
            &subject,
            &to,
            &body,
        )
        .await?;
    }
    write_dns_state(store, &group.domain, &checked, true, Some(&outage), true).await
}

/// One `groups/<domain>/dns-check.json`. `outage` is the moment the current
/// outage was first seen, and stays fixed across its retries so the notice's
/// subject is the same one each time.
async fn write_dns_state(
    store: &Store,
    domain: &str,
    checked_at: &str,
    broken: bool,
    outage: Option<&str>,
    notified: bool,
) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(&json!({
        "version": 1,
        "checked_at": checked_at,
        "broken": broken,
        "outage": outage,
        "notified": notified,
    }))
    .map_err(|e| format!("cannot encode the DNS check state: {e}"))?;
    store
        .write_record(&format!("groups/{domain}"), "dns-check.json", &bytes)
        .await
}

/// Whether any row the recipe names has stopped resolving, or a TXT answer no
/// longer carries the marker that says it is the record the recipe asks for.
/// The resolver is a configured command so the acceptance test never touches the
/// network; it is read-only by construction and the body's zone is not a file
/// this box can write.
async fn dns_broken(cfg: &DrainConfig, values: &dns::Values, domain: &str) -> Result<bool, String> {
    // The checks come from the recipe itself, so a row added to it (or a
    // rotated selector) is watched without a second list to edit.
    let recipe = dns::recipe(domain, values);
    for row in &recipe.rows {
        let names = match row.name.as_str() {
            "@" => vec![domain.to_string()],
            "@ and www" => vec![domain.to_string(), format!("www.{domain}")],
            name => vec![format!("{name}.{domain}")],
        };
        // A TXT row is matched by its leading tag ("v=spf1", "v=DKIM1;", ...),
        // so an unrelated string at the same name is not the record.
        let marker = (row.record_type == "TXT")
            .then(|| row.value.split_whitespace().next())
            .flatten();
        for name in names {
            // The options go after the name so a caller's own resolver stub can
            // read the type and name positionally; `+time`/`+tries` bound a
            // resolver that is not answering.
            let out = Command::new(&cfg.resolver)
                .args([
                    "+short",
                    row.record_type,
                    name.as_str(),
                    "+time=2",
                    "+tries=1",
                ])
                .output()
                .await
                .map_err(|e| format!("cannot run the resolver {}: {e}", cfg.resolver))?;
            if !out.status.success() {
                // No answer is not the body's zone being broken: dig exits
                // non-zero when it could not reach a server, and a name that
                // does not resolve answers successfully with nothing. Only the
                // second is an outage, so this is the platform's own failure.
                return Err(format!(
                    "the resolver {} could not answer {name} {}: {}",
                    cfg.resolver,
                    row.record_type,
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            let answer = String::from_utf8_lossy(&out.stdout);
            let answer = answer.trim();
            if answer.is_empty() {
                return Ok(true);
            }
            if marker.is_some_and(|m| !answer.contains(m)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Who a broken-DNS notice goes to: the contact the community block gave, kept
/// in the mailbox's retained application copy, and the accountable address
/// otherwise. The copy is inside the ninety-day purge, so an application already
/// cleared falls back rather than failing the sweep.
async fn dns_contact(store: &Store, group: &GroupRecord) -> Result<String, String> {
    let copy: Option<Value> = store
        .read_record(
            &format!("accounts/{}", group.site_owner),
            "application.json",
        )
        .await
        .and_then(|text| serde_json::from_str(&text).ok());
    if let Some(copy) = &copy {
        if let Some(contact) = copy
            .pointer("/answers/body_dns_contact")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|c| !c.is_empty())
        {
            if validate::address(contact).is_none() {
                return Ok(contact.to_string());
            }
        }
        if let Some(address) = copy
            .get("outside_address")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            if validate::address(address).is_none() {
                return Ok(address.to_string());
            }
        }
    }
    // The accountable fallback: the mailbox that owns the group's site, at the
    // body's own domain. Unlike the person path's `username@kyriakon.net`, this
    // is an address the platform actually delivers.
    Ok(format!("{}@{}", group.site_owner, group.domain))
}

/// The yearly note to an account approved without charge: nothing is due, and
/// the paid path is there if circumstances have changed. It falls due on the
/// creation anniversary, at most once a year, and the subject carries the year
/// because a notice is deduplicated on its type and subject. A group mailbox is
/// skipped: the group holds the payment, and a body's free permanence is the
/// own-domain tier's own question.
pub async fn free_anniversaries(cfg: &DrainConfig, store: &Store) -> Result<(), String> {
    let today = OffsetDateTime::now_utc().date();
    for username in store.list("accounts").await? {
        let Some(account) = existing_account(store, &username).await else {
            continue;
        };
        if !account.is_free() {
            continue;
        }
        let Ok(created) = OffsetDateTime::parse(&account.created_at, &Rfc3339) else {
            continue;
        };
        let created = created.date();
        // The first note falls due on the first anniversary, never at approval.
        if today.year() <= created.year() {
            continue;
        }
        let due = util::anniversary(created, today.year());
        if today < due {
            continue;
        }
        // The address the approval used: the one outside the platform, or the
        // member's mailbox. It was validated before it was written, and is
        // validated again here because it is about to become a mail header.
        let to = match account.outside_address.as_deref() {
            Some(addr) if validate::address(addr).is_none() => addr.to_string(),
            _ => format!("{username}@kyriakon.net"),
        };
        let subject = format!(
            "Your kyriakon.net account is free for another year ({})",
            due.year()
        );
        let body = format!(
            "Nothing is due for {username} this year.\n\n\
             The account was approved without charge, so there is no payment window and\n\
             no sum to send, and the account does not lapse. It carries the same 5 GB\n\
             allowance and the same acceptable use policy as any other account.\n\n\
             The paid path is there if circumstances have changed: write to\n\
             admin@kyriakon.net and we will send the payment instructions. There is\n\
             nothing to prove.\n"
        );
        // One account's refused notice is reported and skipped, the way the DNS
        // sweep treats one group's: it must not stop the pass's mail spool or
        // the DNS check behind it.
        if let Err(e) = notice::send_account_notice(
            cfg,
            store,
            &username,
            "free.anniversary",
            &subject,
            &to,
            &body,
        )
        .await
        {
            eprintln!("kyriakon-onboard: the free anniversary note for {username}: {e}");
        }
    }
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

/// The confirmation's subject, in the member-facing shape the decision mail
/// takes rather than the operator alert's component/event one.
fn confirmation_subject(username: &str) -> String {
    format!("Your application to kyriakon.net was confirmed ({username})")
}

/// The confirmation email. It repeats the two things the second checkbox
/// recorded, the version of every document accepted, and the 14-day right with
/// how to use it, in the words `docs/terms.md` uses.
fn confirmation_body(record: &Record) -> String {
    let mut out = String::from(
        "We are starting your account now, before the cancellation period ends:\n\
         digital content is supplied immediately, and this does not take your right\n\
         to cancel away.\n\n\
         You accepted:\n\n",
    );
    for acceptance in &record.acceptances {
        out.push_str(&format!(
            "  {}: {}\n",
            acceptance.document, acceptance.version
        ));
    }
    out.push_str(
        "\nYou have fourteen days to cancel, starting the day the contract is made. The\n\
         right is unconditional: you can cancel for any reason, or none. An email to\n\
         admin@kyriakon.net saying that you want to cancel is enough. We refund what\n\
         you paid in full, within fourteen days, in the rail you paid with, or as a\n\
         credit against the next year if you would rather.\n",
    );
    out
}

/// The rail's own payment instructions, one line each, in the words the
/// approval email and both account pages carry. Monero has no subaddress until
/// the operator's wallet makes one, so the line says that rather than leaving an
/// empty field for the member to wonder at.
pub fn rail_instructions(rail: &str, postal_address: &str, card_link: Option<&str>) -> Vec<String> {
    match rail {
        "cash" => vec![
            "Post the money to:".to_string(),
            postal_address.to_string(),
            "Write the reference on the envelope, or on a slip inside it.".to_string(),
        ],
        "monero" => vec![
            "Your Monero subaddress is not ready yet; it will follow in a second message."
                .to_string(),
            "The pound amount is what is owed; the quoted amount in Monero settles it.".to_string(),
        ],
        "card" => match card_link {
            Some(link) => vec![
                "Pay by card at this link, which carries your reference:".to_string(),
                link.to_string(),
            ],
            None => vec!["A card payment link will follow in a second message.".to_string()],
        },
        other => vec![format!(
            "The rail you chose, {other}, will be quoted to you."
        )],
    }
}

/// The card rail's Payment Link, keyed to one payment token.
///
/// The reference is the account's `KYR-` token, which is what the token index
/// joins to the account: the same join `credit()` uses. `client_reference_id`
/// is the one Payment Link parameter that carries it, and it is what
/// `checkout.session.completed` names the account by. A placeholder that
/// reached the box is refused rather than mailed, because a member cannot pay
/// at REPLACE_ME.
pub fn card_link(payment_link: &str, token: &str) -> Result<Option<String>, String> {
    if token.is_empty() {
        return Ok(None);
    }
    let link = payment_link.trim_end_matches(['&', '?']);
    if link.is_empty() || link.contains("REPLACE_ME") {
        return Err(
            "stripe_payment_link is not configured, so a card approval has no link to send"
                .to_string(),
        );
    }
    let joiner = if link.contains('?') { '&' } else { '?' };
    Ok(Some(format!("{link}{joiner}client_reference_id={token}")))
}

/// The decision email for an approval. The words are short because #333 owns
/// the notice copy; what matters here is that the token and the rail's own
/// instructions are on it, and that the free path says neither.
fn decision_body(
    cfg: &DrainConfig,
    username: &str,
    rail: &str,
    no_charge: bool,
    token: Option<&str>,
    window: &Option<Window>,
) -> Result<String, String> {
    if no_charge {
        return Ok(format!(
            "Your application for {username} has been approved, with no charge.\n\n\
             There is nothing to pay and no payment window. The account does not lapse.\n"
        ));
    }
    let token = token.ok_or("a charged approval has no token")?;
    let window = window.as_ref().ok_or("a charged approval has no window")?;
    let card_link = if rail == "card" {
        card_link(&cfg.stripe_payment_link, token)?
    } else {
        None
    };
    let mut out = format!(
        "Your application for {username} has been approved.\n\n\
         The amount is GBP {} for the year.\n\
         Your payment reference is {token}.\n",
        cfg.price_gbp
    );
    out.push('\n');
    for line in rail_instructions(rail, &cfg.postal_address, card_link.as_deref()) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(&format!(
        "\nThe money must arrive before {} or the account lapses: mail keeps arriving and\n\
         everything published stays up, and sending, uploading and pushing stop.\n\
         Nothing is deleted at that point.\n",
        &window.closes_at[..10]
    ));
    Ok(out)
}

/// How far a webhook's timestamp may be from this box's clock. Stripe's own
/// libraries default to five minutes, and the box runs NTP so the window means
/// something. A body older than this is a replay, not a delivery.
const WEBHOOK_TOLERANCE: i64 = 300;

/// Settle the Stripe events the handler wrote under `webhooks/`.
///
/// The handler holds no secret and verifies nothing: it stores the raw body and
/// the `Stripe-Signature` header and answers 2xx. This pass is the half with the
/// secret, so it is the half that decides. Each pair is verified over the exact
/// bytes received, inside five minutes of now, and against every `v1` value the
/// header carries (a rolled secret signs with two). A refusal is logged with the
/// file it names and both files are deleted; nothing else is written. A verified
/// event is deduplicated on its id and on `(type, object.id)`, applied, recorded
/// in `webhooks/processed.jsonl`, and only then removed.
///
/// An event that cannot be applied yet — the Stripe API unreachable for an
/// invoice's subscription — is left in place so the next pass tries again. The
/// date is never extended on trust.
pub async fn stripe_webhooks(cfg: &DrainConfig, store: &Store) -> Result<(), String> {
    // A box whose card rail is not configured yet has no secret, and a pass
    // with nothing to verify must not fail every minute. The first delivery
    // makes the missing secret loud.
    if !store
        .list("webhooks")
        .await?
        .iter()
        .any(|n| n.ends_with(".body"))
    {
        return Ok(());
    }
    let secret = sign::read_key(std::path::Path::new(&cfg.stripe_webhook_secret))?;
    let mut seen = processed_events(store).await;
    // A checkout that attaches a subscription is settled before the invoice
    // that names it, whatever order the two files were written in: Stripe does
    // not promise the order, and the invoice has no other way to find the
    // account. An invoice with no target yet is left for the next pass, so a
    // delivery that genuinely arrives first is not dropped.
    for checkout_first in [true, false] {
        for name in store.list("webhooks").await? {
            let Some(id) = name.strip_suffix(".body") else {
                continue;
            };
            let body = match tokio::fs::read(store.path(&format!("webhooks/{name}"))).await {
                Ok(body) => body,
                // A pair another iteration of this pass already settled.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    eprintln!("kyriakon-onboard: webhook {id} is unreadable: {e}");
                    remove_webhook(store, id).await?;
                    continue;
                }
            };
            let sig = store
                .read_record("webhooks", &format!("{id}.sig"))
                .await
                .unwrap_or_default();
            if let Err(why) = verify_webhook(
                &secret,
                &sig,
                &body,
                OffsetDateTime::now_utc().unix_timestamp(),
            ) {
                eprintln!("kyriakon-onboard: webhook {id} refused: {why}");
                remove_webhook(store, id).await?;
                continue;
            }
            let event: Value = match serde_json::from_slice(&body) {
                Ok(event) => event,
                Err(e) => {
                    eprintln!("kyriakon-onboard: webhook {id} is not JSON: {e}");
                    remove_webhook(store, id).await?;
                    continue;
                }
            };
            let event_id = event.get("id").and_then(Value::as_str).unwrap_or("");
            let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
            let object_id = event
                .pointer("/data/object/id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let is_checkout = kind == "checkout.session.completed";
            if is_checkout != checkout_first {
                continue;
            }
            if event_id.is_empty() || kind.is_empty() {
                eprintln!("kyriakon-onboard: webhook {id} names no event id or type");
                remove_webhook(store, id).await?;
                continue;
            }
            if seen.contains(&format!("event:{event_id}")) {
                remove_webhook(store, id).await?;
                continue;
            }
            if let Some(pair) = invoice_pair(kind, object_id) {
                if seen.contains(&pair) {
                    remove_webhook(store, id).await?;
                    continue;
                }
            }
            match settle_event(cfg, store, kind, &event).await {
                Ok(Settled::Applied) => {
                    let line = serde_json::json!({
                        "at": util::filed_at(),
                        "event": event_id,
                        "type": kind,
                        "object": object_id,
                    });
                    let bytes = serde_json::to_vec(&line)
                        .map_err(|e| format!("cannot encode the processed event: {e}"))?;
                    store.append("webhooks/processed.jsonl", &bytes).await?;
                    seen.insert(format!("event:{event_id}"));
                    if let Some(pair) = invoice_pair(kind, object_id) {
                        seen.insert(pair);
                    }
                    remove_webhook(store, id).await?;
                }
                // A valid event with nothing of ours in it settles nothing and
                // writes nothing; the pair is still removed so it is not retried.
                Ok(Settled::Ignored) => remove_webhook(store, id).await?,
                // The account this names is not known yet, which a checkout
                // still in the directory, or one arriving later, will change.
                Ok(Settled::Deferred) => {}
                Err(e) => {
                    eprintln!(
                        "kyriakon-onboard: webhook {id} ({kind}) could not be settled yet: {e}"
                    );
                }
            }
        }
    }
    Ok(())
}

/// Whether a `Stripe-Signature` header proves this body, and that the delivery
/// is recent. Accepts only `v1`: `v0` is the test-only older scheme. The
/// comparison is constant time through [`sign::verify_bytes`], and every `v1`
/// value is tried so a secret mid-roll verifies either way.
pub fn verify_webhook(secret: &[u8], header: &str, body: &[u8], now: i64) -> Result<(), String> {
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<&str> = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part
            .split_once('=')
            .ok_or_else(|| format!("the signature header carries {part:?} without a value"))?;
        match name {
            "t" => {
                timestamp = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| format!("the timestamp {value:?} is not a number"))?,
                );
            }
            "v1" => signatures.push(value),
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or("the signature header carries no t=")?;
    if signatures.is_empty() {
        return Err("the signature header carries no v1 signature".to_string());
    }
    if (now - timestamp).abs() > WEBHOOK_TOLERANCE {
        return Err(format!(
            "the timestamp {timestamp} is more than five minutes from {now}"
        ));
    }
    let mut payload = timestamp.to_string().into_bytes();
    payload.push(b'.');
    payload.extend_from_slice(body);
    if signatures
        .iter()
        .any(|sig| sign::verify_bytes(secret, &payload, sig))
    {
        Ok(())
    } else {
        Err("no v1 signature matches the body".to_string())
    }
}

async fn remove_webhook(store: &Store, id: &str) -> Result<(), String> {
    store.remove("webhooks", &format!("{id}.body")).await?;
    store.remove("webhooks", &format!("{id}.sig")).await
}

/// The one pair key the dedup uses: an invoice is one payment, so a second
/// `invoice.paid` for the same invoice (with a fresh event id) settles nothing.
/// Every other event type is deduplicated on its id alone: one subscription's
/// `updated` arrives many times, and each one is a state to record.
fn invoice_pair(kind: &str, object: &str) -> Option<String> {
    (kind == "invoice.paid" && !object.is_empty()).then(|| format!("invoice.paid:{object}"))
}

/// The event ids and `(type, object)` pairs already settled. One append-only
/// record, so a resend sees what an earlier pass did.
async fn processed_events(store: &Store) -> HashSet<String> {
    let mut seen = HashSet::new();
    for line in store.lines("webhooks/processed.jsonl").await {
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if let Some(event) = value.get("event").and_then(Value::as_str) {
            seen.insert(format!("event:{event}"));
        }
        if let (Some(kind), Some(object)) = (
            value.get("type").and_then(Value::as_str),
            value.get("object").and_then(Value::as_str),
        ) {
            if let Some(pair) = invoice_pair(kind, object) {
                seen.insert(pair);
            }
        }
    }
    seen
}

/// One account or group the card rail belongs to, with the payment block the
/// event changes.
enum BillingTarget {
    Account(Box<Account>),
    Group(Box<GroupRecord>),
}

impl BillingTarget {
    fn stripe(&self) -> &store::StripeBilling {
        match self {
            BillingTarget::Account(a) => a.payment.as_ref().map(|p| &p.stripe).unwrap_or(&EMPTY),
            BillingTarget::Group(g) => &g.payment.stripe,
        }
    }

    fn stripe_mut(&mut self) -> &mut store::StripeBilling {
        match self {
            BillingTarget::Account(a) => {
                &mut a.payment.as_mut().expect("a target has a payment").stripe
            }
            BillingTarget::Group(g) => &mut g.payment.stripe,
        }
    }

    /// The paid date, when one is set. A free or unpaid account has none.
    fn paid_until(&self) -> Option<&str> {
        match self {
            BillingTarget::Account(a) => a.payment.as_ref()?.paid_until.as_deref(),
            BillingTarget::Group(g) => g.payment.paid_until.as_deref(),
        }
    }

    /// A payment extends the date and marks the window paid. A group has no
    /// window: its single renewal sets the date the mailboxes share.
    fn set_paid_until(&mut self, date: String) -> Result<(), String> {
        match self {
            BillingTarget::Account(a) => {
                let payment = a
                    .payment
                    .as_mut()
                    .ok_or("the account has no payment block")?;
                payment.paid_until = Some(date);
                if let Some(window) = payment.window.as_mut() {
                    window.state = "paid".to_string();
                }
            }
            BillingTarget::Group(g) => g.payment.paid_until = Some(date),
        }
        Ok(())
    }

    async fn save(&self, store: &Store) -> Result<(), String> {
        match self {
            BillingTarget::Account(a) => {
                let bytes = serde_json::to_vec_pretty(a)
                    .map_err(|e| format!("cannot encode the account: {e}"))?;
                store
                    .write_record(&format!("accounts/{}", a.username), "account.json", &bytes)
                    .await
            }
            BillingTarget::Group(g) => write_group_record(store, g).await,
        }
    }

    /// The address a notice about this payment goes to: the member's outside
    /// address, or the mailbox the platform made. A group's notice goes to its
    /// site owner.
    async fn recipient(&self, store: &Store) -> String {
        let (username, outside) = match self {
            BillingTarget::Account(a) => (a.username.clone(), a.outside_address.clone()),
            BillingTarget::Group(g) => (
                g.site_owner.clone(),
                store
                    .read_record(&format!("accounts/{}", g.site_owner), "account.json")
                    .await
                    .and_then(|text| serde_json::from_str::<Account>(&text).ok())
                    .and_then(|a| a.outside_address),
            ),
        };
        outside.unwrap_or_else(|| format!("{username}@kyriakon.net"))
    }
}

static EMPTY: store::StripeBilling = store::StripeBilling {
    subscription: None,
    customer: None,
    status: None,
    current_period_end: None,
    next_payment_attempt: None,
    failed_attempts: 0,
    last_invoice: None,
};

/// A target named by an application or a subscription.
#[derive(Clone)]
enum TargetRef {
    Account(String),
    Group(String),
}

async fn load_target(store: &Store, target: &TargetRef) -> Result<Option<BillingTarget>, String> {
    match target {
        TargetRef::Account(username) => {
            let Some(text) = store
                .read_record(&format!("accounts/{username}"), "account.json")
                .await
            else {
                return Ok(None);
            };
            let account: Account = serde_json::from_str(&text)
                .map_err(|e| format!("the account {username} does not parse: {e}"))?;
            // A free approval has no payment block, so a card event is not its
            // to change.
            if account.payment.is_none() {
                return Ok(None);
            }
            Ok(Some(BillingTarget::Account(Box::new(account))))
        }
        TargetRef::Group(domain) => Ok(group_record(store, domain)
            .await?
            .map(|record| BillingTarget::Group(Box::new(record)))),
    }
}

/// The account or group a subscription belongs to, found by the id the checkout
/// event attached. Invoices name only the subscription, and the application
/// record may be long purged, so the subscription is the durable join.
async fn target_for_subscription(
    store: &Store,
    subscription: &str,
) -> Result<Option<TargetRef>, String> {
    for username in store.list("accounts").await? {
        let Some(text) = store
            .read_record(&format!("accounts/{username}"), "account.json")
            .await
        else {
            continue;
        };
        let Ok(account) = serde_json::from_str::<Account>(&text) else {
            continue;
        };
        if account
            .payment_state()
            .and_then(|p| p.stripe.subscription)
            .as_deref()
            == Some(subscription)
        {
            return Ok(Some(TargetRef::Account(username)));
        }
    }
    for domain in store.list("groups").await? {
        let Some(record) = group_record(store, &domain).await? else {
            continue;
        };
        if record.payment.stripe.subscription.as_deref() == Some(subscription) {
            return Ok(Some(TargetRef::Group(domain)));
        }
    }
    Ok(None)
}

/// What settling one event did. `Deferred` leaves the pair in `webhooks/` for
/// the next pass, because the account it names is not attached yet.
enum Settled {
    Applied,
    Ignored,
    Deferred,
}

async fn settle_event(
    cfg: &DrainConfig,
    store: &Store,
    kind: &str,
    event: &Value,
) -> Result<Settled, String> {
    let object = event
        .pointer("/data/object")
        .ok_or("the event carries no data.object")?;
    match kind {
        "checkout.session.completed" => checkout_completed(store, object).await,
        "invoice.paid" => invoice_paid(cfg, store, object).await,
        "invoice.payment_failed" => invoice_payment_failed(store, object).await,
        "invoice.payment_action_required" => {
            invoice_payment_action_required(cfg, store, object).await
        }
        "customer.subscription.updated" | "customer.subscription.deleted" => {
            subscription_changed(store, object, kind == "customer.subscription.deleted").await
        }
        "invoice.upcoming" => invoice_upcoming(store, object).await,
        // Everything else the endpoint is not subscribed to. A verified event of
        // an unknown type is not an error; it is simply not ours.
        _ => Ok(Settled::Ignored),
    }
}

/// The account a payment token names, through the index the credit path uses:
/// `tokens/<ref>.json` → username → `accounts/<username>/account.json`. Only a
/// card account's own token resolves; anything else, including a status token
/// or a token whose record names another token, is not a reference this rail
/// answers. The account must carry a payment block, because a free approval has
/// nothing to settle.
async fn account_for_payment_reference(
    store: &Store,
    reference: &str,
) -> Result<Option<Account>, String> {
    if !store::is_payment_token(reference) {
        return Ok(None);
    }
    let Some(join_text) = store
        .read_record("tokens", &format!("{reference}.json"))
        .await
    else {
        return Ok(None);
    };
    let Ok(join) = serde_json::from_str::<TokenRecord>(&join_text) else {
        return Ok(None);
    };
    if join.token != reference || validate::username_shape(&join.username).is_some() {
        return Ok(None);
    }
    let Some(text) = store
        .read_record(&format!("accounts/{}", join.username), "account.json")
        .await
    else {
        return Ok(None);
    };
    let Ok(account) = serde_json::from_str::<Account>(&text) else {
        return Ok(None);
    };
    let Some(payment) = account.payment_state() else {
        return Ok(None);
    };
    if account.rail != "card"
        || account.no_charge
        || payment.token_ref.as_deref() != Some(reference)
    {
        return Ok(None);
    }
    Ok(Some(account))
}

/// Write an account's record back after the webhook pass changed its payment
/// block.
async fn write_account(store: &Store, account: &Account) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(account)
        .map_err(|e| format!("cannot encode the account: {e}"))?;
    store
        .write_record(
            &format!("accounts/{}", account.username),
            "account.json",
            &bytes,
        )
        .await
}

/// Attach a subscription and its customer to an account, which is all a
/// checkout does. The date stays `invoice.paid`'s to set.
async fn attach_subscription(
    store: &Store,
    account: &mut Account,
    subscription: &str,
    customer: Option<&str>,
) -> Result<(), String> {
    let payment = account
        .payment
        .as_mut()
        .ok_or("the account has no payment block")?;
    payment.stripe.subscription = Some(subscription.to_string());
    payment.stripe.customer = customer.map(str::to_string);
    write_account(store, account).await
}

/// `checkout.session.completed`: the `client_reference_id` is the account's
/// `KYR-` token, and the subscription and customer are attached to the account
/// it indexes. Nothing else happens: `invoice.paid` owns the date, so a first
/// payment extends exactly one year and never two.
async fn checkout_completed(store: &Store, object: &Value) -> Result<Settled, String> {
    let Some(reference) = object
        .get("client_reference_id")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
    else {
        return Ok(Settled::Ignored);
    };
    let Some(subscription) = object.get("subscription").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(mut account) = account_for_payment_reference(store, reference).await? else {
        return Ok(Settled::Ignored);
    };
    let customer = object.get("customer").and_then(Value::as_str);
    attach_subscription(store, &mut account, subscription, customer).await?;
    Ok(Settled::Applied)
}

/// `invoice.paid`: retrieve the subscription and confirm it is `active`, then
/// extend the date one calendar year from the later of today and the date the
/// account already holds. The invoice id is the key the extension is idempotent
/// on, so a redelivery with a fresh event id settles nothing twice. A
/// subscription that is not active is recorded and does not move the date.
async fn invoice_paid(cfg: &DrainConfig, store: &Store, object: &Value) -> Result<Settled, String> {
    let Some(subscription) = object.get("subscription").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(invoice) = object.get("id").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    // The API, not the event: a paid invoice does not prove an active
    // subscription. An unreachable API is an error, which leaves the event for
    // the next pass rather than extending the date on trust. The same answer is
    // the repair path: a missed checkout leaves the subscription naming its
    // account in metadata, and that is how the attachment is made here.
    let subscription_json = retrieve_subscription(cfg, subscription).await?;
    let status = subscription_json
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    let period_end = period_end(&subscription_json);
    let customer = subscription_json.get("customer").and_then(Value::as_str);
    let target = match target_for_subscription(store, subscription).await? {
        Some(target) => target,
        None => {
            // A missed `checkout.session.completed` leaves no store record, so
            // the session the subscription came from is the repair: the list
            // filter names it, and its `client_reference_id` is the account's
            // token. A subscription with no session reference stays deferred.
            let session = retrieve_session(cfg, subscription).await?;
            let reference = card_reference(&session, &subscription_json);
            let Some(mut account) = account_for_payment_reference(store, reference).await? else {
                return Ok(Settled::Deferred);
            };
            attach_subscription(store, &mut account, subscription, customer).await?;
            TargetRef::Account(account.username.clone())
        }
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    {
        let stripe = billing.stripe_mut();
        stripe.status = Some(status.to_string());
        stripe.customer = customer.map(str::to_string);
        stripe.current_period_end = period_end;
        stripe.subscription = Some(subscription.to_string());
    }
    if status != "active" {
        billing.save(store).await?;
        return Ok(Settled::Applied);
    }
    if billing.stripe().last_invoice.as_deref() == Some(invoice) {
        // The date was saved on an earlier pass. The ledger line it opens may
        // still be missing if that pass died between the save and the append,
        // and the invoice id is the dedup key that finishes it once.
        if let BillingTarget::Account(account) = &billing {
            append_invoice_ledger(store, account, invoice, &cfg.price_gbp).await?;
        }
        billing.save(store).await?;
        return Ok(Settled::Applied);
    }
    let received = util::filed_at();
    let date = crate::billing::extend_paid_until(&received, billing.paid_until())?;
    billing.set_paid_until(date)?;
    billing.stripe_mut().last_invoice = Some(invoice.to_string());
    billing.stripe_mut().failed_attempts = 0;
    billing.stripe_mut().next_payment_attempt = None;
    billing.save(store).await?;
    if let BillingTarget::Account(account) = &billing {
        if let Some(payment) = &account.payment {
            write_payment_copy(store, &account.username, payment).await?;
        }
        append_invoice_ledger(store, account, invoice, &cfg.price_gbp).await?;
    }
    Ok(Settled::Applied)
}

/// The ledger line a paid card invoice opens. Without it a card payment has no
/// `seq`, and the refund path has nothing to reverse. A group has no token, so
/// its payment stays out of the ledger. The invoice id is the dedup key, which
/// is also what recovers a crash between the account write and this append.
/// Nothing here talks to Stripe: the card rail stays read-only towards it.
async fn append_invoice_ledger(
    store: &Store,
    account: &Account,
    invoice: &str,
    price_gbp: &str,
) -> Result<(), String> {
    let Some(payment) = account.payment.as_ref() else {
        return Ok(());
    };
    let Some(token) = payment.token_ref.as_deref() else {
        return Ok(());
    };
    if ledger_has_intent(store, invoice).await {
        return Ok(());
    }
    let line = json!({
        "version": 1,
        "seq": next_ledger_seq(store).await,
        "token": token,
        "kind": "payment",
        "rail": "card",
        "received_on": util::date_after_days(0),
        "amount_gbp": price_gbp,
        "applied_gbp": price_gbp,
        "paid_until_after": payment.paid_until.as_deref(),
        "amount_xmr": Value::Null,
        "rate_quoted": Value::Null,
        "rate_source": Value::Null,
        "rate_at": Value::Null,
        "txid": Value::Null,
        "intent": invoice,
        "note": Value::Null,
    });
    let encoded =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode the ledger: {e}"))?;
    store
        .append("ledger/payments.jsonl", encoded.as_bytes())
        .await
}

/// The current subscription from the Stripe API, through the one script that
/// holds the key. Read-only: the webhook path makes no Stripe writes.
async fn retrieve_subscription(cfg: &DrainConfig, subscription: &str) -> Result<Value, String> {
    if !subscription
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(format!("the subscription id {subscription:?} is not an id"));
    }
    let out = spawn_script(
        cfg,
        "stripe-api.sh",
        &["subscription", subscription, &cfg.stripe_api_key],
    )
    .await?;
    if !out.status.success() {
        return Err(script_error(cfg, "stripe-api.sh", &out));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("stripe-api.sh did not answer with a subscription: {e}"))
}

/// The Checkout Session a subscription came from, read through the same script.
/// The list is filtered by the subscription and bounded to one; an empty list or
/// an unreachable API is an error, so the event stays for the next pass.
async fn retrieve_session(cfg: &DrainConfig, subscription: &str) -> Result<Value, String> {
    if !subscription
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(format!("the subscription id {subscription:?} is not an id"));
    }
    let out = spawn_script(
        cfg,
        "stripe-api.sh",
        &["session", subscription, &cfg.stripe_api_key],
    )
    .await?;
    if !out.status.success() {
        return Err(script_error(cfg, "stripe-api.sh", &out));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("stripe-api.sh did not answer with a checkout session: {e}"))
}

/// The account reference a repaired payment carries: the session's own
/// `client_reference_id` first, then the metadata keys a Stripe object can hold
/// it under.
fn card_reference<'a>(session: &'a Value, subscription: &'a Value) -> &'a str {
    let pick = |value: &'a Value| {
        value
            .pointer("/client_reference_id")
            .or_else(|| value.pointer("/metadata/client_reference_id"))
            .or_else(|| value.pointer("/metadata/kyriakon_application"))
            .and_then(Value::as_str)
            .filter(|reference| !reference.is_empty())
    };
    pick(session).or_else(|| pick(subscription)).unwrap_or("")
}

/// `invoice.payment_failed`: record the attempt and the next retry on the
/// account, and nothing else. Stripe's own dunning email is the member's copy;
/// a platform copy would be a second mail about one failed attempt. The date
/// does not move: access is the paid date's, not a failed attempt's.
async fn invoice_payment_failed(store: &Store, object: &Value) -> Result<Settled, String> {
    let Some(subscription) = object.get("subscription").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(target) = target_for_subscription(store, subscription).await? else {
        return Ok(Settled::Deferred);
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    let next = object.get("next_payment_attempt").and_then(stamp);
    let attempts = object
        .get("attempt_count")
        .and_then(Value::as_u64)
        .unwrap_or(u64::from(billing.stripe().failed_attempts) + 1);
    {
        let stripe = billing.stripe_mut();
        stripe.failed_attempts = attempts.min(u64::from(u32::MAX)) as u32;
        stripe.next_payment_attempt = next;
    }
    billing.save(store).await?;
    Ok(Settled::Applied)
}

/// `invoice.payment_action_required`: the one card event the member must act
/// on, because the bank is waiting for authentication and no retry can settle
/// it. The attempt is recorded and one notice asks them to complete it.
async fn invoice_payment_action_required(
    cfg: &DrainConfig,
    store: &Store,
    object: &Value,
) -> Result<Settled, String> {
    let Some(subscription) = object.get("subscription").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(target) = target_for_subscription(store, subscription).await? else {
        return Ok(Settled::Deferred);
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    let invoice = object
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("an invoice");
    let attempts = object
        .get("attempt_count")
        .and_then(Value::as_u64)
        .unwrap_or(u64::from(billing.stripe().failed_attempts) + 1);
    {
        let stripe = billing.stripe_mut();
        stripe.failed_attempts = attempts.min(u64::from(u32::MAX)) as u32;
        stripe.next_payment_attempt = object.get("next_payment_attempt").and_then(stamp);
    }
    billing.save(store).await?;
    let owner = billing.notice_owner();
    let body = format!(
        "A card payment for your membership needs you to complete it: the bank has \
         asked for authentication and will not settle it on its own. Open the link in \
         your approval email and complete the payment there. Nothing has been deleted \
         and your access has not changed.\n\n\
         Invoice: {invoice}\n\
         Attempts so far: {attempts}\n"
    );
    notice::send_account_notice(
        cfg,
        store,
        &owner,
        "payment.action-required",
        &format!("Complete your card payment ({invoice})"),
        &billing.recipient(store).await,
        &body,
    )
    .await?;
    Ok(Settled::Applied)
}

impl BillingTarget {
    /// The account whose `notices.jsonl` records a notice about this target: a
    /// group's notices are its site owner's.
    fn notice_owner(&self) -> String {
        match self {
            BillingTarget::Account(a) => a.username.clone(),
            BillingTarget::Group(g) => g.site_owner.clone(),
        }
    }
}

/// `customer.subscription.updated` and `deleted`: reconcile the status and the
/// period end. A deletion stops renewal and never revokes a paid date.
async fn subscription_changed(
    store: &Store,
    object: &Value,
    deleted: bool,
) -> Result<Settled, String> {
    let Some(subscription) = object.get("id").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(target) = target_for_subscription(store, subscription).await? else {
        return Ok(Settled::Deferred);
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    let status = if deleted {
        "canceled"
    } else {
        object.get("status").and_then(Value::as_str).unwrap_or("")
    };
    let stripe = billing.stripe_mut();
    stripe.status = Some(status.to_string());
    stripe.current_period_end = period_end(object);
    if let Some(customer) = object.get("customer").and_then(Value::as_str) {
        stripe.customer = Some(customer.to_string());
    }
    billing.save(store).await?;
    Ok(Settled::Applied)
}

/// `invoice.upcoming`: record the period end the upcoming invoice names. Stripe
/// sends the annual reminder itself, with its own copy, so the platform sends
/// none; this event is a state fact and nothing more.
async fn invoice_upcoming(store: &Store, object: &Value) -> Result<Settled, String> {
    let Some(subscription) = object.get("subscription").and_then(Value::as_str) else {
        return Ok(Settled::Ignored);
    };
    let Some(target) = target_for_subscription(store, subscription).await? else {
        return Ok(Settled::Deferred);
    };
    let Some(mut billing) = load_target(store, &target).await? else {
        return Ok(Settled::Ignored);
    };
    billing.stripe_mut().current_period_end = period_end(object);
    billing.save(store).await?;
    Ok(Settled::Applied)
}

/// A Stripe unix timestamp as RFC 3339, or `None` where the field is absent or
/// null (an invoice with no next attempt yet).
fn stamp(value: &Value) -> Option<String> {
    let seconds = value.as_i64()?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// A subscription's or invoice's period end. Newer API versions moved it onto
/// the items, so both shapes are read.
fn period_end(value: &Value) -> Option<String> {
    value
        .get("current_period_end")
        .or_else(|| value.get("period_end"))
        .and_then(stamp)
        .or_else(|| {
            value
                .pointer("/items/data/0/current_period_end")
                .and_then(stamp)
        })
}

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
    fn a_free_accounts_note_falls_due_on_the_creation_day_clamped() {
        let leap = time::Date::from_calendar_date(2024, time::Month::February, 29).unwrap();
        // A common year has no 29 February, so the note falls due a day early
        // rather than being skipped for the year.
        assert_eq!(
            util::anniversary(leap, 2025),
            time::Date::from_calendar_date(2025, time::Month::February, 28).unwrap()
        );
        assert_eq!(
            util::anniversary(leap, 2028),
            time::Date::from_calendar_date(2028, time::Month::February, 29).unwrap()
        );
    }

    #[test]
    fn a_credit_applies_the_price_and_holds_the_rest() {
        // Within one percent, either side, is the price itself.
        assert_eq!(
            (
                credit_money(2000, 0, 1980).applied,
                credit_money(2000, 0, 1980).balance
            ),
            (2000, 0)
        );
        assert!(credit_money(2000, 0, 2020).paid);
        // Above it: the price is applied and the excess is held.
        let over = credit_money(2000, 0, 2500);
        assert_eq!((over.applied, over.balance, over.paid), (2000, 500, true));
        // A larger shortfall holds what arrived and moves nothing.
        let short = credit_money(2000, 0, 1979);
        assert_eq!((short.applied, short.balance, short.paid), (0, 1979, false));
        // A held balance is spent before the new money is counted.
        let spends = credit_money(2000, 500, 1500);
        assert_eq!(
            (spends.applied, spends.balance, spends.paid),
            (2000, 0, true)
        );
        let short_still = credit_money(2000, 500, 1000);
        assert_eq!(short_still.balance, 1500);
        assert!(!short_still.paid);
    }

    #[test]
    fn a_signed_credit_payload_covers_the_reason_and_the_fields_before_it() {
        let a = sign::credit_payload(
            "KYR-4F2M-9QH7-XT3B",
            "cash",
            "20.00",
            "2026-10-04",
            None,
            None,
            false,
            Some("posted twice"),
            None,
        );
        let b = sign::credit_payload(
            "KYR-4F2M-9QH7-XT3B",
            "cash",
            "20.00",
            "2026-10-04",
            None,
            None,
            false,
            Some("posted once"),
            None,
        );
        assert_ne!(a, b);
        assert!(a.contains("posted twice"));
        // The note is free text and last, so a note that carries a colon cannot
        // shift the fields before it into agreeing with another intent's.
        let c = sign::credit_payload(
            "",
            "cash",
            "20.00",
            "2026-10-04",
            None,
            None,
            false,
            None,
            Some("no token: envelope in book"),
        );
        assert!(c.contains("no token: envelope in book"));
        assert_ne!(c, a);
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
