//! The intent loop: what makes a filed application move.
//!
//! Every pass reads `intents/*.json` in ULID order, which is the order they
//! were filed, revalidates each one, appends the journal line before carrying
//! the transition out, and deletes the intent file once it is done. An intent
//! whose kind this build does not implement is refused by name and left in
//! place, never silently dropped: a kind added by a later ticket waits here
//! until the ticket that understands it lands.

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
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
    // The rate cache first, so a window opening later in this pass quotes from
    // it. It asks the source only when the cache is more than a day old, and a
    // failure is not the pass's: a stale cache is exactly what the quote falls
    // back to.
    let _ = crate::xmr::current(cfg, OffsetDateTime::now_utc()).await;
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
    transitions::purge_closing(cfg, store).await?;
    // The free accounts' yearly note, on the same pass: a free account never
    // lapses, and this is the one message it is sent each year.
    transitions::free_anniversaries(cfg, store).await?;
    // The prepaid member's own renewal note, thirty days before the date runs
    // out: the rails with no processor have nobody else to send one.
    transitions::prepaid_renewals(cfg, store).await?;
    // The space used, from the filesystem quota the handler cannot read. Due
    // gated to once an hour, so most passes do no quota work.
    transitions::refresh_space_used(cfg, store).await?;
    // A mail-key replacement whose 72-hour window has closed applies here, on
    // the same pass its record is read.
    transitions::mail_key_rotations(cfg, store).await?;
    // A payment window whose day has passed either finds its credit and stays
    // active, or lapses the account and starts the grace. One sweep, so a
    // member who paid on the last day is not lapsed by a later pass.
    transitions::window_sweep(cfg, store).await?;
    // A lapsed account's grace: the final notice at day 33, and the one
    // deletion transition when the 40 days end.
    transitions::grace_sweep(cfg, store).await?;
    // The key spool is read after the intents so a filed application is not
    // waiting behind a mailbox pass. The pass handles each message on its own:
    // one that cannot be dealt with is reported and left for the next run.
    crate::mailbox::run(cfg, store).await?;
    // The groups' own zones are watched last: a record that has stopped
    // resolving is the one thing about a body's domain the platform can see and
    // cannot repair, and it must not delay a filed application or a member's
    // mail. It is due-gated, so most passes do no DNS work.
    transitions::check_group_dns(cfg, store).await?;
    // The card rail's arriving events are settled after everything else: a
    // misconfigured signing secret must not hold up an approval, and an event
    // that cannot be applied yet is left for the next pass.
    transitions::stripe_webhooks(cfg, store).await
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
        "remove-group" => transitions::remove_group(cfg, store, key, &value, file).await,
        "close" => transitions::close_account(cfg, store, &value, file).await,
        "token-resend" => {
            let intent: transitions::ResendIntent = serde_json::from_value(value)
                .map_err(|e| format!("the token resend intent does not parse: {e}"))?;
            transitions::resend(cfg, store, key, intent, file).await
        }
        "credit" => {
            let intent: transitions::CreditIntent = serde_json::from_value(value.clone())
                .map_err(|e| format!("the credit intent does not parse: {e}"))?;
            transitions::credit(cfg, store, key, intent, file, &value).await
        }
        "window-extend" => {
            let intent: transitions::WindowExtendIntent = serde_json::from_value(value.clone())
                .map_err(|e| format!("the window extension intent does not parse: {e}"))?;
            transitions::window_extend(cfg, store, key, intent, file, &value).await
        }
        "reconcile-attribute" => {
            let intent: transitions::AttributeIntent = serde_json::from_value(value.clone())
                .map_err(|e| format!("the reconcile-attribute intent does not parse: {e}"))?;
            transitions::reconcile_attribute(cfg, store, key, intent, file, &value).await
        }
        "reconcile-return" => {
            let intent: transitions::ReturnIntent = serde_json::from_value(value.clone())
                .map_err(|e| format!("the reconcile-return intent does not parse: {e}"))?;
            transitions::reconcile_return(cfg, store, key, intent, file, &value).await
        }
        "refund" => {
            let intent: transitions::RefundIntent = serde_json::from_value(value.clone())
                .map_err(|e| format!("the refund intent does not parse: {e}"))?;
            transitions::refund(cfg, store, key, intent, file, &value).await
        }
        "export" => transitions::export_account(cfg, store, &value, file).await,
        "change-password" => transitions::change_password(cfg, store, &value, file).await,
        "upload-key" => transitions::upload_key(cfg, store, &value, file).await,
        "outside-address" => transitions::set_outside_address(cfg, store, &value, file).await,
        "serving" => transitions::set_serving(cfg, store, &value, file).await,
        "cancel-renewal" => transitions::cancel_renewal(cfg, store, &value, file).await,
        "mail-key" => transitions::mail_key(cfg, store, &value, file).await,
        _ => transitions::refuse(cfg, store, file, &value).await,
    }
}

/// File an export intent, as the account page's "Take my data out" does.
///
/// The body names the account and the session that asked for it, and nothing
/// else. The handler is unprivileged and `intents/` is writable by it, so the
/// drain re-proves the session against its server-side record before it writes
/// as root: the record's username must be the intent's and it must not have
/// expired. Nothing the caller supplies can widen the export past the account.
pub async fn file_export(store: &Store, session: &str, username: &str) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "export",
        "filed_at": crate::util::filed_at(),
        "username": username,
        "session": session,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}

/// File one of the account page's actions: the account, the session that filed
/// it, and the action's own fields.
///
/// The handler has authenticated the member and validated each field; the drain
/// revalidates all of them, because `intents/` belongs to the unprivileged half
/// and every one of these writes something as root. One writer for the six
/// actions keeps the envelope, the keys the drain reads before it dispatches,
/// from drifting between them.
pub async fn file_action(
    store: &Store,
    kind: &str,
    session: &str,
    username: &str,
    fields: serde_json::Value,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let mut intent = serde_json::json!({
        "id": id,
        "kind": kind,
        "filed_at": crate::util::filed_at(),
        "username": username,
        "session": session,
    });
    let serde_json::Value::Object(extra) = fields else {
        return Err("a page action's fields have to be an object".to_string());
    };
    intent
        .as_object_mut()
        .ok_or("the intent is not an object")?
        .extend(extra);
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
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

/// File one group removal, as `kyriakon-onboardctl group remove` does.
///
/// The signature is the console's, over `sign::group_remove_payload`, because
/// the transition deletes every account in the body and `intents/` belongs to
/// the unprivileged half.
pub async fn file_remove_group(store: &Store, domain: &str, sig: &str) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "remove-group",
        "filed_at": crate::util::filed_at(),
        "domain": domain,
        "sig": sig,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}

/// File a `token-resend`, as `kyriakon-onboardctl token resend` does. The token
/// is the account's own, read at the terminal, and the signature is over it, so
/// the drain re-sends nothing the console did not file and mints nothing.
pub async fn file_resend(
    store: &Store,
    username: &str,
    token: &str,
    sig: &str,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "token-resend",
        "filed_at": crate::util::filed_at(),
        "username": username,
        "token": token,
        "sig": sig,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}

/// File a manual credit, as `kyriakon-onboardctl credit` does. The token is the
/// account's own, resolved by the console before it signs, and the signature is
/// over every field the drain acts on: a credit moves a paid-until date, and
/// `intents/` is writable by the unprivileged handler.
#[allow(clippy::too_many_arguments)]
pub async fn file_credit(
    store: &Store,
    token: &str,
    rail: &str,
    amount_gbp: &str,
    received: &str,
    txid: Option<&str>,
    amount_xmr: Option<&str>,
    confirm_double: bool,
    override_reason: Option<&str>,
    note: Option<&str>,
    sig: &str,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "credit",
        "filed_at": crate::util::filed_at(),
        "token": token,
        "rail": rail,
        "amount_gbp": amount_gbp,
        "received": received,
        "txid": txid,
        "amount_xmr": amount_xmr,
        "confirm_double": confirm_double,
        "override_reason": override_reason,
        "note": note,
        "sig": sig,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}

/// File a `window-extend` intent, as `kyriakon-onboardctl window extend` does.
/// The token is validated here and the signature is over every field the drain
/// acts on, because the extension moves a lapse date and `intents/` belongs to
/// the unprivileged half.
pub async fn file_window_extend(
    store: &Store,
    token: &str,
    days: i64,
    reason: &str,
    sig: &str,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "window-extend",
        "filed_at": crate::util::filed_at(),
        "token": token,
        "days": days,
        "reason": reason,
        "sig": sig,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}

/// File one reconcile-attribute intent, as `kyriakon-onboardctl reconcile
/// attribute` does. The held id and the token are both validated shapes, and the
/// console signs them, because the transition writes a paid-until date and
/// `intents/` belongs to the unprivileged half.
pub async fn file_reconcile_attribute(
    store: &Store,
    item: &str,
    token: &str,
    confirm_double: bool,
    override_reason: Option<&str>,
    sig: &str,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "reconcile-attribute",
        "filed_at": crate::util::filed_at(),
        "item": item,
        "token": token,
        "confirm_double": confirm_double,
        "override_reason": override_reason,
        "sig": sig,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}

/// File one reconcile-return intent, as `kyriakon-onboardctl reconcile return`
/// does. The evidence is free text and signed last; nothing moves but the held
/// line's own state.
pub async fn file_reconcile_return(
    store: &Store,
    item: &str,
    note: &str,
    sig: &str,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "reconcile-return",
        "filed_at": crate::util::filed_at(),
        "item": item,
        "note": note,
        "sig": sig,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}

/// File a refund, as `kyriakon-onboardctl refund` does. A refund form carries
/// the money, the rail, the reason and the `--close`/`--excess` choice; a
/// settlement carries `settled_on` and nothing else. The token is the account's
/// own, resolved by the console before it signs, and the signature is over every
/// field the drain acts on: a refund writes the ledger and can close an account,
/// and `intents/` is writable by the unprivileged handler.
#[allow(clippy::too_many_arguments)]
pub async fn file_refund(
    store: &Store,
    token: &str,
    amount_gbp: Option<&str>,
    rail: Option<&str>,
    reason: Option<&str>,
    close: bool,
    excess: bool,
    rate: Option<&str>,
    settled_on: Option<&str>,
    sig: &str,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "refund",
        "filed_at": crate::util::filed_at(),
        "token": token,
        "amount_gbp": amount_gbp,
        "rail": rail,
        "reason": reason,
        "close": close,
        "excess": excess,
        "rate": rate,
        "settled_on": settled_on,
        "sig": sig,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}

/// Whether `id` names a live page session for `username`. The drain runs as
/// root and the session record lives under the handler's store, so this is the
/// one check that turns an unsigned intent into work for an authenticated
/// account. A session for another account and an expired session are refused
/// with the reason the journal records. The close intent is the first caller;
/// #498 reuses it.
pub async fn verify_session(store: &Store, id: &str, username: &str) -> Result<(), String> {
    if !crate::store::is_status_token(id) {
        return Err("the intent carries no usable session id".to_string());
    }
    let Some(text) = store.read_record("sessions", &format!("{id}.json")).await else {
        return Err("the session named by the intent has gone".to_string());
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("the session record does not parse: {e}"))?;
    let named = value.get("username").and_then(Value::as_str).unwrap_or("");
    if named != username {
        return Err(format!(
            "the session belongs to {named:?}, not {username:?}"
        ));
    }
    let expires = value
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or("the session record has no expiry")?;
    let expires = OffsetDateTime::parse(expires, &Rfc3339)
        .map_err(|e| format!("the session expiry does not parse: {e}"))?;
    if OffsetDateTime::now_utc() >= expires {
        return Err("the session named by the intent has expired".to_string());
    }
    Ok(())
}

/// File one `close` intent, as the account page does. The handler has
/// authenticated the member, writes the account name and the page session it
/// used, and nothing else. The drain verifies the session, owns the state write
/// and the seven-day window.
pub async fn file_close(store: &Store, username: &str, session: &str) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "close",
        "filed_at": crate::util::filed_at(),
        "username": username,
        "session": session,
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
/// The plaintext is the handler's and the signature is the link's. The drain
/// hashes the plaintext and checks the signature before it applies anything, so
/// a forged submission files an intent that is refused, never a password, and a
/// compromised handler cannot file a hash the member never typed.
pub async fn file_password(
    store: &Store,
    username: &str,
    token: &str,
    until: &str,
    sig: &str,
    password: &str,
) -> Result<String, String> {
    let id = ulid::Ulid::new().to_string();
    let intent = serde_json::json!({
        "id": id,
        "kind": "set-password",
        "filed_at": crate::util::filed_at(),
        "application": { "username": username, "status_token": token },
        "until": until,
        "sig": sig,
        "password": password,
    });
    let bytes =
        serde_json::to_vec_pretty(&intent).map_err(|e| format!("cannot encode the intent: {e}"))?;
    store
        .write_record("intents", &format!("{id}.json"), &bytes)
        .await?;
    Ok(id)
}
