//! The intent loop: what makes a filed application move.
//!
//! Every pass reads `intents/*.json` in ULID order, which is the order they
//! were filed, revalidates each one, appends the journal line before carrying
//! the transition out, and deletes the intent file once it is done. An intent
//! whose kind this build does not implement is refused by name and left in
//! place, never silently dropped: a kind added by a later ticket waits here
//! until the ticket that understands it lands.
//!
//! One type is the contract between the handler's directory and the drain's
//! root work: [`Intent`]. Its variant carries the payload, [`Intent::verify`]
//! says how the intent is authenticated, and [`Intent::apply`] carries it out.
//! `verify`'s match has no catch-all, so a verb cannot ship without answering
//! how it is proved — the hole `provision-group` came through before #506.

use serde_json::Value;
use time::OffsetDateTime;

use crate::config::DrainConfig;
use crate::journal::Journal;
use crate::sign;
use crate::store::{GroupAddressIntent, GroupIntent, GroupRemoveIntent, Store};
use crate::transitions::{
    self, AttributeIntent, CancelRenewalIntent, ChangePasswordIntent, CloseIntent, CreditIntent,
    DecisionIntent, ExportIntent, MailKeyIntent, OutsideAddressIntent, PasswordIntent,
    RefundIntent, ResendIntent, ReturnIntent, ServingIntent, UploadKeyIntent, WindowExtendIntent,
};

/// One pass: every intent, then the sweeps. The drain is a single short-lived
/// process with no listener, so there is no loop inside it; cron runs it again
/// a minute later.
pub async fn run(cfg: &DrainConfig, store: &Store) -> Result<(), String> {
    // Read once for the whole pass: every dedup, backoff and recovery query
    // below asks this index rather than opening the file again, and an
    // unreadable journal is an error here rather than an empty one (#513).
    let journal = Journal::load(store).await?;
    // Read once, before anything is done: the review email's links are signed
    // with it. A missing or unreadable key is a misconfigured box, and it is
    // mailed once rather than on every pass.
    let key = match sign::read_key(std::path::Path::new(&cfg.approval_key)) {
        Ok(k) => k,
        Err(e) => {
            transitions::report_failure(cfg, store, &journal, "config", "config", &e).await;
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
        if !transitions::due(&journal, id, OffsetDateTime::now_utc()) {
            continue;
        }
        if let Err(e) = one(cfg, store, &journal, &key, &name).await {
            transitions::report_failure(cfg, store, &journal, id, "intent", &e).await;
        }
    }
    // The login proofs are root's, so this is the half that clears the expired
    // ones; the handler cannot read the directory and does not try. After the
    // intents, so a close or export filed with a session that has just run out
    // reads as expired rather than as a missing proof.
    crate::session::prune_proofs(
        std::path::Path::new(&cfg.proof_dir),
        OffsetDateTime::now_utc(),
    )
    .await;
    transitions::purge_declined(cfg, store, &journal).await?;
    transitions::purge_closing(cfg, store, &journal).await?;
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
    transitions::mail_key_rotations(cfg, store, &journal).await?;
    // A payment window whose day has passed either finds its credit and stays
    // active, or lapses the account and starts the grace. One sweep, so a
    // member who paid on the last day is not lapsed by a later pass.
    transitions::window_sweep(cfg, store).await?;
    // A lapsed account's grace: the final notice at day 33, and the one
    // deletion transition when the 40 days end.
    transitions::grace_sweep(cfg, store, &journal).await?;
    // The key spool is read after the intents so a filed application is not
    // waiting behind a mailbox pass. The pass handles each message on its own:
    // one that cannot be dealt with is reported and left for the next run.
    crate::mailbox::run(cfg, store, &journal).await?;
    // The groups' own zones are watched last: a record that has stopped
    // resolving is the one thing about a body's domain the platform can see and
    // cannot repair, and it must not delay a filed application or a member's
    // mail. It is due-gated, so most passes do no DNS work.
    transitions::check_group_dns(cfg, store).await?;
    // The card rail's arriving events are settled after everything else: a
    // misconfigured signing secret must not hold up an approval, and an event
    // that cannot be applied yet is left for the next pass.
    transitions::stripe_webhooks(cfg, store, &journal).await
}

/// One intent file, deserialised once into its variant, proved, then applied.
async fn one(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    key: &[u8],
    file: &str,
) -> Result<(), String> {
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
    let intent = Intent::parse(&value)?;
    intent.run(cfg, store, journal, key, file, &value).await
}

/// One intent: the variant carries the payload, and the file it was read from
/// carries what the refusal paths need to rewrite or journal it.
///
/// Parsing is by `kind` and lives here, once: the transition a variant applies
/// takes the parsed payload, so no verb can be reached with a shape its own
/// verifier has not looked at.
#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum Intent {
    Application(crate::store::Intent),
    Decision(DecisionIntent),
    Password(PasswordIntent),
    ProvisionGroup(Box<GroupIntent>),
    GroupAddress(GroupAddressIntent),
    RemoveGroup(GroupRemoveIntent),
    Close(CloseIntent),
    Resend(ResendIntent),
    Credit(CreditIntent),
    WindowExtend(WindowExtendIntent),
    ReconcileAttribute(AttributeIntent),
    ReconcileReturn(ReturnIntent),
    Refund(RefundIntent),
    Export(ExportIntent),
    ChangePassword(ChangePasswordIntent),
    UploadKey(UploadKeyIntent),
    OutsideAddress(OutsideAddressIntent),
    Serving(ServingIntent),
    CancelRenewal(CancelRenewalIntent),
    MailKey(MailKeyIntent),
    /// A kind this build does not implement, carried as it was read: `verify`
    /// refuses it by name and leaves the file where a later ticket finds it.
    Unknown {
        kind: String,
        value: Value,
    },
}

impl Intent {
    /// The intent this file holds, by its `kind`. A kind this build does not
    /// implement is `Unknown` rather than an error, because it is left in place
    /// for the release that understands it.
    ///
    /// The parse error keeps the message the verb's own reader used, so a
    /// malformed intent is reported with the same words it always was.
    pub fn parse(value: &Value) -> Result<Intent, String> {
        let kind = value.get("kind").and_then(Value::as_str).unwrap_or("");
        let intent = match kind {
            "application" => Intent::Application(parsed(value, "the intent")?),
            "approve" | "provision" | "decline" => {
                Intent::Decision(parsed(value, "the decision intent")?)
            }
            "set-password" => Intent::Password(parsed(value, "the password intent")?),
            "provision-group" => {
                Intent::ProvisionGroup(Box::new(parsed(value, "the group intent")?))
            }
            "group-address" => Intent::GroupAddress(parsed(value, "the address intent")?),
            "remove-group" => Intent::RemoveGroup(parsed(value, "the remove-group intent")?),
            "close" => Intent::Close(parsed(value, "the close intent")?),
            "token-resend" => Intent::Resend(parsed(value, "the token resend intent")?),
            "credit" => Intent::Credit(parsed(value, "the credit intent")?),
            "window-extend" => Intent::WindowExtend(parsed(value, "the window extension intent")?),
            "reconcile-attribute" => {
                Intent::ReconcileAttribute(parsed(value, "the reconcile-attribute intent")?)
            }
            "reconcile-return" => {
                Intent::ReconcileReturn(parsed(value, "the reconcile-return intent")?)
            }
            "refund" => Intent::Refund(parsed(value, "the refund intent")?),
            "export" => Intent::Export(export_from(value)?),
            "change-password" => Intent::ChangePassword(parsed(value, "the password intent")?),
            "upload-key" => Intent::UploadKey(parsed(value, "the upload key intent")?),
            "outside-address" => Intent::OutsideAddress(parsed(value, "the address intent")?),
            "serving" => Intent::Serving(parsed(value, "the serving intent")?),
            "cancel-renewal" => Intent::CancelRenewal(parsed(value, "the renewal intent")?),
            "mail-key" => Intent::MailKey(parsed(value, "the mail key intent")?),
            other => Intent::Unknown {
                kind: other.to_string(),
                value: value.clone(),
            },
        };
        Ok(intent)
    }

    /// The `kind` this variant is filed under and parsed from. The writer stamps
    /// it, so a caller cannot file a `Close` under a verb it is not, and the
    /// round-trip test walks every variant through it.
    pub fn kind(&self) -> &str {
        match self {
            Intent::Application(_) => "application",
            // The three decisions are kinds of their own: `approve`, `provision`
            // and `decline` are what the dispatcher reads.
            Intent::Decision(intent) => &intent.kind,
            Intent::Password(_) => "set-password",
            Intent::ProvisionGroup(_) => "provision-group",
            Intent::GroupAddress(_) => "group-address",
            Intent::RemoveGroup(_) => "remove-group",
            Intent::Close(_) => "close",
            Intent::Resend(_) => "token-resend",
            Intent::Credit(_) => "credit",
            Intent::WindowExtend(_) => "window-extend",
            Intent::ReconcileAttribute(_) => "reconcile-attribute",
            Intent::ReconcileReturn(_) => "reconcile-return",
            Intent::Refund(_) => "refund",
            Intent::Export(_) => "export",
            Intent::ChangePassword(_) => "change-password",
            Intent::UploadKey(_) => "upload-key",
            Intent::OutsideAddress(_) => "outside-address",
            Intent::Serving(_) => "serving",
            Intent::CancelRenewal(_) => "cancel-renewal",
            Intent::MailKey(_) => "mail-key",
            Intent::Unknown { kind, .. } => kind,
        }
    }

    /// File this intent as `intents/<id>.json`, and hand back the id.
    ///
    /// The id, the kind and the filing time are the writer's: one writer for
    /// every verb keeps the envelope, and the `kind` the drain dispatches on,
    /// from drifting between builders. The payload's own fields are the wire
    /// the handler already writes, and the signature, where there is one,
    /// travels in them. The intent is borrowed so the drain's own approval can
    /// file it and carry it out through the same seam.
    pub async fn file(&self, store: &Store) -> Result<String, String> {
        let id = ulid::Ulid::new().to_string();
        let kind = self.kind().to_string();
        if matches!(self, Intent::Unknown { .. }) {
            return Err(format!("this build does not implement the kind {kind:?}"));
        }
        let mut value =
            serde_json::to_value(self).map_err(|e| format!("cannot encode the intent: {e}"))?;
        let object = value.as_object_mut().ok_or("the intent is not an object")?;
        object.insert("id".to_string(), id.clone().into());
        object.insert("kind".to_string(), kind.into());
        object.insert("filed_at".to_string(), crate::util::filed_at().into());
        let bytes = serde_json::to_vec_pretty(&value)
            .map_err(|e| format!("cannot encode the intent: {e}"))?;
        store
            .write_record("intents", &format!("{id}.json"), &bytes)
            .await?;
        Ok(id)
    }

    /// Prove then apply, as the pass does. A `verify` that settles the intent
    /// applies nothing.
    pub async fn run(
        self,
        cfg: &DrainConfig,
        store: &Store,
        journal: &Journal,
        key: &[u8],
        file: &str,
        value: &Value,
    ) -> Result<(), String> {
        if !self.verify(cfg, store, journal, key, file, value).await? {
            return Ok(());
        }
        self.apply(cfg, store, journal, key, file, value).await
    }

    /// Prove the intent is the authenticated party's, before anything is
    /// applied.
    ///
    /// There is no catch-all arm: a variant added without deciding what proves
    /// it does not compile. `Ok(false)` means the intent is settled — its
    /// refusal line is journalled and its file left for the operator or removed,
    /// as that verb's rule says — and the caller must not apply it. `Err` is a
    /// pass that failed, which backs off and is mailed once.
    ///
    /// The signature and session checks are the ones the transitions used to
    /// make themselves; every message and every journal outcome is the same.
    pub async fn verify(
        &self,
        cfg: &DrainConfig,
        store: &Store,
        journal: &Journal,
        key: &[u8],
        file: &str,
        value: &Value,
    ) -> Result<bool, String> {
        let proofs = std::path::Path::new(&cfg.proof_dir);
        match self {
            // The handler files it and the drain only queues a review: nothing
            // is written as root until a reviewer's signed decision, which the
            // `Decision` arm proves.
            Intent::Application(_) => Ok(true),
            Intent::Decision(intent) => {
                if !crate::store::is_status_token(&intent.application.status_token) {
                    return Err("the status token is not 128 bits of Crockford".to_string());
                }
                if let Some(why) = crate::validate::username_shape(&intent.application.username) {
                    return Err(format!("the username: {why}"));
                }
                let Some(decision) = transitions::decision_for_kind(&intent.kind) else {
                    return Err(format!("kind {:?} is not a decision", intent.kind));
                };
                if intent.action != decision.action {
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
                Ok(true)
            }
            Intent::Password(intent) => {
                // A re-filed copy of a settled intent is settled again, and a
                // refused one loses its plaintext.
                if journal.has(&intent.id, "refused") {
                    transitions::redact_password(store, file, value).await?;
                    return Ok(false);
                }
                if journal.has(&intent.id, "applied") {
                    // A crash between the `applied` line and the remove leaves
                    // the intent re-read on every pass: finish the remove.
                    store.remove("intents", file).await?;
                    return Ok(false);
                }
                // The handler files the plaintext and the drain hashes it: a
                // `hash` field is the old shape, where a handler with a valid
                // link chose the stored hash.
                let problem: Option<String> = if value.get("hash").is_some() {
                    Some("the intent carries a hash rather than a plaintext".to_string())
                } else if !sign::verify(
                    key,
                    &sign::password_payload(&intent.application.status_token, &intent.until),
                    &intent.sig,
                ) {
                    Some("the link's signature does not verify".to_string())
                } else if intent.until.as_str() < crate::util::date_after_days(0).as_str() {
                    Some("the link's date has passed".to_string())
                } else {
                    crate::password::validate(&intent.password).err()
                };
                match problem {
                    Some(why) => {
                        transitions::refuse_password(cfg, store, journal, file, value, &why)
                            .await?;
                        Ok(false)
                    }
                    None => Ok(true),
                }
            }
            Intent::ProvisionGroup(intent) => {
                if sign::verify(key, &sign::group_provision_payload(intent), &intent.sig) {
                    Ok(true)
                } else {
                    Err("the group intent's signature does not verify".to_string())
                }
            }
            Intent::GroupAddress(intent) => {
                let payload = sign::address_payload(
                    &intent.domain,
                    &intent.action,
                    &intent.address,
                    &intent.mailbox,
                    intent.site_owner.as_deref().unwrap_or(""),
                    intent
                        .mail_key
                        .as_ref()
                        .map(|k| k.material.as_str())
                        .unwrap_or(""),
                );
                if sign::verify(key, &payload, &intent.sig) {
                    Ok(true)
                } else {
                    Err("the address intent's signature does not verify".to_string())
                }
            }
            Intent::RemoveGroup(intent) => {
                if sign::verify(
                    key,
                    &sign::group_remove_payload(&intent.domain),
                    &intent.sig,
                ) {
                    Ok(true)
                } else {
                    Err("the remove-group intent's signature does not verify".to_string())
                }
            }
            Intent::Close(intent) => {
                // A close reports a name it cannot use as a pass failure, where
                // a page action refuses it; the session proof is shared.
                account_name(&intent.username)?;
                session_proved(
                    cfg,
                    store,
                    journal,
                    &intent.id,
                    &intent.kind,
                    &intent.username,
                    &intent.session,
                    file,
                )
                .await
            }
            Intent::Resend(intent) => {
                if sign::verify(
                    key,
                    &sign::resend_payload(&intent.username, &intent.token),
                    &intent.sig,
                ) {
                    Ok(true)
                } else {
                    Err("the token resend's signature does not verify".to_string())
                }
            }
            Intent::Credit(intent) => {
                let payload = sign::credit_payload(
                    &intent.token,
                    &intent.rail,
                    &intent.amount_gbp,
                    &intent.received,
                    intent.txid.as_deref(),
                    intent.amount_xmr.as_deref(),
                    intent.confirm_double,
                    intent.override_reason.as_deref(),
                    intent.note.as_deref(),
                );
                if sign::verify(key, &payload, &intent.sig) {
                    Ok(true)
                } else {
                    transitions::refuse_with(
                        cfg,
                        store,
                        journal,
                        file,
                        value,
                        "the credit intent's signature does not verify",
                    )
                    .await?;
                    Ok(false)
                }
            }
            Intent::WindowExtend(intent) => {
                if sign::verify(
                    key,
                    &sign::window_extend_payload(&intent.token, intent.days, &intent.reason),
                    &intent.sig,
                ) {
                    Ok(true)
                } else {
                    transitions::refuse_with(
                        cfg,
                        store,
                        journal,
                        file,
                        value,
                        "the window extension's signature does not verify",
                    )
                    .await?;
                    Ok(false)
                }
            }
            Intent::ReconcileAttribute(intent) => {
                let payload = sign::reconcile_attribute_payload(
                    &intent.item,
                    &intent.token,
                    intent.confirm_double,
                    intent.override_reason.as_deref(),
                );
                if sign::verify(key, &payload, &intent.sig) {
                    Ok(true)
                } else {
                    transitions::refuse_with(
                        cfg,
                        store,
                        journal,
                        file,
                        value,
                        "the reconcile-attribute intent's signature does not verify",
                    )
                    .await?;
                    Ok(false)
                }
            }
            Intent::ReconcileReturn(intent) => {
                if sign::verify(
                    key,
                    &sign::reconcile_return_payload(&intent.item, &intent.note),
                    &intent.sig,
                ) {
                    Ok(true)
                } else {
                    transitions::refuse_with(
                        cfg,
                        store,
                        journal,
                        file,
                        value,
                        "the reconcile-return intent's signature does not verify",
                    )
                    .await?;
                    Ok(false)
                }
            }
            Intent::Refund(intent) => {
                let payload = sign::refund_payload(
                    &intent.token,
                    intent.amount_gbp.as_deref().unwrap_or(""),
                    intent.rail.as_deref().unwrap_or(""),
                    intent.close,
                    intent.excess,
                    intent.rate.as_deref().unwrap_or(""),
                    intent.settled_on.as_deref().unwrap_or(""),
                    intent.reason.as_deref().unwrap_or(""),
                );
                if sign::verify(key, &payload, &intent.sig) {
                    Ok(true)
                } else {
                    transitions::refuse_with(
                        cfg,
                        store,
                        journal,
                        file,
                        value,
                        "the refund intent's signature does not verify",
                    )
                    .await?;
                    Ok(false)
                }
            }
            Intent::Export(intent) => {
                if let Some(why) = crate::validate::username_shape(&intent.username) {
                    return Err(format!(
                        "the export intent's username {:?}: {why}",
                        intent.username
                    ));
                }
                verify_session(store, proofs, &intent.session, &intent.username).await?;
                Ok(true)
            }
            // A page action is proved by the session the handler filed, and by
            // the account name being one an account record can name.
            Intent::ChangePassword(intent) => {
                if value.get("hash").is_some() {
                    transitions::refuse_page(
                        cfg,
                        store,
                        journal,
                        &intent.id,
                        &intent.kind,
                        &intent.username,
                        file,
                        "the intent carries a hash rather than a plaintext",
                    )
                    .await?;
                    return Ok(false);
                }
                page_proved(
                    cfg,
                    store,
                    journal,
                    &intent.id,
                    &intent.kind,
                    &intent.username,
                    &intent.session,
                    file,
                )
                .await
            }
            Intent::UploadKey(intent) => {
                page_proved(
                    cfg,
                    store,
                    journal,
                    &intent.id,
                    &intent.kind,
                    &intent.username,
                    &intent.session,
                    file,
                )
                .await
            }
            Intent::OutsideAddress(intent) => {
                page_proved(
                    cfg,
                    store,
                    journal,
                    &intent.id,
                    &intent.kind,
                    &intent.username,
                    &intent.session,
                    file,
                )
                .await
            }
            Intent::Serving(intent) => {
                page_proved(
                    cfg,
                    store,
                    journal,
                    &intent.id,
                    &intent.kind,
                    &intent.username,
                    &intent.session,
                    file,
                )
                .await
            }
            Intent::CancelRenewal(intent) => {
                page_proved(
                    cfg,
                    store,
                    journal,
                    &intent.id,
                    &intent.kind,
                    &intent.username,
                    &intent.session,
                    file,
                )
                .await
            }
            Intent::MailKey(intent) => {
                page_proved(
                    cfg,
                    store,
                    journal,
                    &intent.id,
                    &intent.kind,
                    &intent.username,
                    &intent.session,
                    file,
                )
                .await
            }
            Intent::Unknown { .. } => {
                transitions::refuse(cfg, store, journal, file, value).await?;
                Ok(false)
            }
        }
    }

    /// Carry the intent out. Only reached once `verify` has proved it, so the
    /// transitions behind these arms make no second proof of their own.
    pub async fn apply(
        self,
        cfg: &DrainConfig,
        store: &Store,
        journal: &Journal,
        key: &[u8],
        file: &str,
        value: &Value,
    ) -> Result<(), String> {
        match self {
            Intent::Application(intent) => {
                transitions::filed_application(cfg, store, journal, key, intent, file).await
            }
            Intent::Decision(intent) => {
                transitions::decision(cfg, store, journal, key, intent, file).await
            }
            Intent::Password(intent) => {
                transitions::set_password(cfg, store, journal, intent, file, value).await
            }
            Intent::ProvisionGroup(intent) => {
                transitions::provision_group(cfg, store, journal, *intent, file).await
            }
            Intent::GroupAddress(intent) => {
                transitions::group_address(cfg, store, journal, intent, file).await
            }
            Intent::RemoveGroup(intent) => {
                transitions::remove_group(cfg, store, journal, intent, file).await
            }
            Intent::Close(intent) => {
                transitions::close_account(cfg, store, journal, intent, file).await
            }
            Intent::Resend(intent) => transitions::resend(cfg, store, journal, intent, file).await,
            Intent::Credit(intent) => {
                transitions::credit(cfg, store, journal, intent, file, value).await
            }
            Intent::WindowExtend(intent) => {
                transitions::window_extend(cfg, store, journal, intent, file, value).await
            }
            Intent::ReconcileAttribute(intent) => {
                transitions::reconcile_attribute(cfg, store, journal, intent, file, value).await
            }
            Intent::ReconcileReturn(intent) => {
                transitions::reconcile_return(cfg, store, journal, intent, file, value).await
            }
            Intent::Refund(intent) => {
                transitions::refund(cfg, store, journal, intent, file, value).await
            }
            Intent::Export(intent) => {
                transitions::export_account(cfg, store, journal, intent, file).await
            }
            Intent::ChangePassword(intent) => {
                transitions::change_password(cfg, store, journal, intent, file).await
            }
            Intent::UploadKey(intent) => {
                transitions::upload_key(cfg, store, journal, intent, file).await
            }
            Intent::OutsideAddress(intent) => {
                transitions::set_outside_address(cfg, store, journal, intent, file).await
            }
            Intent::Serving(intent) => {
                transitions::set_serving(cfg, store, journal, intent, file).await
            }
            Intent::CancelRenewal(intent) => {
                transitions::cancel_renewal(cfg, store, journal, intent, file).await
            }
            Intent::MailKey(intent) => {
                transitions::mail_key(cfg, store, journal, intent, file).await
            }
            // `verify` refuses an unknown kind before this is reached.
            Intent::Unknown { kind, .. } => {
                Err(format!("this build does not implement the kind {kind:?}"))
            }
        }
    }
}

/// One de-serialisation, with the verb's own words for a bad shape.
fn parsed<T: serde::de::DeserializeOwned>(value: &Value, what: &str) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|e| format!("{what} does not parse: {e}"))
}

/// The export intent, read with the words its transition always used: the
/// account and the session are its claim, and a file missing either is refused
/// by name rather than as a serde object error.
fn export_from(value: &Value) -> Result<ExportIntent, String> {
    Ok(ExportIntent {
        id: value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        kind: "export".to_string(),
        filed_at: value
            .get("filed_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        username: value
            .get("username")
            .and_then(Value::as_str)
            .ok_or("the export intent names no account")?
            .to_string(),
        session: value
            .get("session")
            .and_then(Value::as_str)
            .ok_or("the export intent names no session")?
            .to_string(),
    })
}

/// The one rule for a name the drain turns into a path: only an account name
/// may be one, because an intent's username is a path component under the
/// store. `Err` carries the reason, worded for the journal.
fn account_name(username: &str) -> Result<(), String> {
    match crate::validate::username_shape(username) {
        Some(why) => Err(format!("the username {username:?}: {why}")),
        None => Ok(()),
    }
}

/// The page verbs' and close's one session proof: the record's proof names the
/// account. A mismatch, an expiry and a session that has gone are journalled as
/// a refusal and the file is removed; `Ok(false)` tells the caller nothing is
/// applied.
#[allow(clippy::too_many_arguments)]
async fn session_proved(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    id: &str,
    kind: &str,
    username: &str,
    session: &str,
    file: &str,
) -> Result<bool, String> {
    match verify_session(
        store,
        std::path::Path::new(&cfg.proof_dir),
        session,
        username,
    )
    .await
    {
        Ok(()) => Ok(true),
        Err(reason) => {
            transitions::settle_page(
                cfg,
                store,
                journal,
                id,
                kind,
                username,
                file,
                "refused",
                Some(&reason),
            )
            .await?;
            Ok(false)
        }
    }
}

/// A page action's proof: the account name rule, then the session. A refusal
/// journals its reason and removes the file, the way every page action's
/// refusal does.
#[allow(clippy::too_many_arguments)]
async fn page_proved(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    id: &str,
    kind: &str,
    username: &str,
    session: &str,
    file: &str,
) -> Result<bool, String> {
    if let Err(why) = account_name(username) {
        transitions::refuse_page(cfg, store, journal, id, kind, username, file, &why).await?;
        return Ok(false);
    }
    session_proved(cfg, store, journal, id, kind, username, session, file).await
}

/// Whether `id` names a live page session for `username`. The drain runs as
/// root and the session record lives under the handler's store, so this is the
/// one check that turns an unsigned intent into work for an authenticated
/// account. The record is not trusted: it only names the proof token that the
/// root-side login check minted in `proof_dir`, and that file's own username
/// and expiry decide. A forged record, a session for another account and an
/// expired one are refused with the reason the journal records.
pub async fn verify_session(
    store: &Store,
    proof_dir: &std::path::Path,
    id: &str,
    username: &str,
) -> Result<(), String> {
    if !crate::store::is_status_token(id) {
        return Err("the intent carries no usable session id".to_string());
    }
    let Some(text) = store.read_record("sessions", &format!("{id}.json")).await else {
        return Err("the session named by the intent has gone".to_string());
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("the session record does not parse: {e}"))?;
    let proof = value.get("proof").and_then(Value::as_str).unwrap_or("");
    crate::session::verify_proof(proof_dir, proof, username, OffsetDateTime::now_utc()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One pass, many intents, one read: the index is loaded once and nothing
    /// below it opens the file again. A second pass over the same files appends
    /// nothing, because the index carries the first pass's refusal.
    #[test]
    fn a_pass_reads_the_journal_once_however_many_intents_it_carries() {
        let dir = std::env::temp_dir().join(format!("onboard-journal-pass-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("intents")).unwrap();
        let mut cfg: DrainConfig =
            toml::from_str(include_str!("../../openbsd/etc/onboard/drain.toml")).unwrap();
        cfg.store_root = dir.to_str().unwrap().to_string();
        let store = Store::new_for_test(&cfg.store_root);
        for n in 0..5 {
            std::fs::write(
                dir.join(format!("intents/01H{n}.json")),
                format!(r#"{{"id":"intent-{n}","kind":"not-a-verb"}}"#),
            )
            .unwrap();
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let journal = Journal::load(&store).await.unwrap();
            let loaded = store.journal_reads();
            assert_eq!(loaded, 1, "the load reads the journal once");
            for pass in 0..2 {
                for name in store.list("intents").await.unwrap() {
                    if !name.ends_with(".json") {
                        continue;
                    }
                    let id = name.trim_end_matches(".json");
                    if !transitions::due(&journal, id, OffsetDateTime::now_utc()) {
                        continue;
                    }
                    one(&cfg, &store, &journal, b"key", &name).await.unwrap();
                }
                assert_eq!(
                    store.journal_reads(),
                    loaded,
                    "pass {pass} read the journal again"
                );
            }
        });
        let text = std::fs::read_to_string(dir.join("journal.jsonl")).unwrap();
        assert_eq!(
            text.lines().count(),
            5,
            "each refusal is written once, not once per pass: {text}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
