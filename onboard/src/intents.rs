//! The intent loop: what makes a filed application move.
//!
//! Every pass reads `intents/*.json` in ULID order, which is the order they
//! were filed, revalidates each one, appends the journal line before carrying
//! the transition out, and deletes the intent file once it is done. An intent
//! whose kind this build does not implement is refused by name and left in
//! place, never silently dropped: a kind added by a later ticket waits here
//! until the ticket that understands it lands.

use serde_json::Value;
use time::OffsetDateTime;

use crate::config::DrainConfig;
use crate::sign;
use crate::store::{KeyRecord, Store};
use crate::transitions::{self, DecisionIntent};

/// One pass: every intent, then the sweeps. The drain is a single short-lived
/// process with no listener, so there is no loop inside it; cron runs it again
/// a minute later.
pub async fn run(cfg: &DrainConfig, store: &Store) -> Result<(), String> {
    // Read once, before anything is done: the review email's links are signed
    // with it. A missing or unreadable key is a misconfigured box, and it is
    // mailed once rather than on every pass.
    let key = match sign::read_key(std::path::Path::new(&cfg.approval_key)) {
        Ok(k) => k,
        Err(e) => {
            transitions::report_failure(cfg, store, "config", "config", &e).await;
            return Ok(());
        }
    };
    // The filenames are ULIDs, so a lexical sort is an age sort.
    for name in store.list("intents").await? {
        if !name.ends_with(".json") {
            continue;
        }
        let id = name.trim_end_matches(".json");
        // A failing intent backs off rather than being retried every minute, and
        // its error is mailed once rather than on every pass.
        if !transitions::due(store, id, OffsetDateTime::now_utc()).await {
            continue;
        }
        if let Err(e) = one(cfg, store, &key, &name).await {
            transitions::report_failure(cfg, store, id, "intent", &e).await;
        }
    }
    transitions::purge_declined(cfg, store).await?;
    // The key spool is read after the intents so a filed application is not
    // waiting behind a mailbox pass. The pass handles each message on its own:
    // one that cannot be dealt with is reported and left for the next run.
    crate::mailbox::run(cfg, store).await?;
    // The groups' own zones are watched last: a record that has stopped
    // resolving is the one thing about a body's domain the platform can see and
    // cannot repair, and it must not delay a filed application or a member's
    // mail. It is due-gated, so most passes do no DNS work.
    transitions::check_group_dns(cfg, store).await
}

/// One intent, dispatched by kind.
async fn one(cfg: &DrainConfig, store: &Store, key: &[u8], file: &str) -> Result<(), String> {
    // The listing is one snapshot, and a pass can delete a file another name in
    // that snapshot shares: an approval writes and applies its group intent in
    // the same pass, then removes it. A file that is gone reads as done, the
    // same rule store.remove uses, rather than as a failure the reviewer is
    // mailed about.
    let Some(text) = store.read_record("intents", file).await else {
        return Ok(());
    };
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("the intent does not parse: {e}"))?;
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    match kind.as_str() {
        "application" => transitions::filed_application(cfg, store, key, &text, file).await,
        "approve" | "provision" | "decline" => {
            let intent: DecisionIntent = serde_json::from_value(value)
                .map_err(|e| format!("the decision intent does not parse: {e}"))?;
            transitions::decision(cfg, store, key, intent, file).await
        }
        "set-password" => {
            let intent: transitions::PasswordIntent = serde_json::from_value(value.clone())
                .map_err(|e| format!("the password intent does not parse: {e}"))?;
            transitions::set_password(cfg, store, key, intent, file, &value).await
        }
        "provision-group" => transitions::provision_group(cfg, store, &value, file).await,
        "group-address" => transitions::group_address(cfg, store, key, &value, file).await,
        _ => transitions::refuse(cfg, store, file, &value).await,
    }
}

/// File one decision, as a link's click or the console does.
///
/// The handler holds no key and signs nothing: the signature travels in the link
/// the operator was sent, and the drain is the half that verifies it. The console
/// signs with the root-only key and passes its own. Both build the file here, so
/// the two callers cannot disagree about the shape the drain parses.
pub async fn file_decision(
    store: &Store,
    kind: &str,
    action: &str,
    username: &str,
    token: &str,
    sig: &str,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": kind,
        "filed_at": crate::util::filed_at(),
        "application": { "username": username, "status_token": token },
        "action": action,
        "sig": sig,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}

/// File one address change in a group, as `kyriakon-onboardctl address` does.
///
/// The signature is the console's, over `sign::address_payload` for exactly
/// these fields: `intents/` belongs to the unprivileged half, so the drain
/// carries an address change out only when the root-only key signed it.
#[allow(clippy::too_many_arguments)]
pub async fn file_group_address(
    store: &Store,
    domain: &str,
    action: &str,
    address: &str,
    mailbox: &str,
    mail_key: Option<&KeyRecord>,
    site_owner: Option<&str>,
    sig: &str,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "group-address",
        "filed_at": crate::util::filed_at(),
        "domain": domain,
        "action": action,
        "address": address,
        "mailbox": mailbox,
        "mail_key": mail_key,
        "site_owner": site_owner,
        "sig": sig,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}

/// File a password set through the member's one-time link.
///
/// The hash is the handler's and the signature is the link's. The drain checks
/// the signature before it applies anything, so a forged submission files an
/// intent that is refused, never a password.
pub async fn file_password(
    store: &Store,
    username: &str,
    token: &str,
    until: &str,
    sig: &str,
    hash: &str,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "set-password",
        "filed_at": crate::util::filed_at(),
        "application": { "username": username, "status_token": token },
        "until": until,
        "sig": sig,
        "hash": hash,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}
