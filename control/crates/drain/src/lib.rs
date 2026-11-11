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
//! root work: [`Intent`]. Its variant carries the payload; [`verify`] and
//! [`apply`] in this module say how the intent is authenticated and carried out.
//! `verify`'s match has no catch-all, so a verb cannot ship without answering
//! how it is proved, the hole `provision-group` came through before #506.
//!
//! The wire payloads, [`DECISIONS`] and the rail constants live in
//! [`kyriakon_control_core::intent`], beside [`Intent`]: the enum and the shape it deserialises
//! are one contract.
use crate::transitions::Error;

pub mod mailbox;
pub mod prepaid;
pub mod transitions;

use serde_json::Value;

use kyriakon_control_core::intent::*;
use time::OffsetDateTime;

use kyriakon_control_core::account::sign;
use kyriakon_control_core::config::DrainConfig;
use kyriakon_control_core::store::journal::Journal;
use kyriakon_control_core::store::Store;

/// One pass: every intent, then the sweeps. The drain is a single short-lived
/// process with no listener, so there is no loop inside it; cron runs it again
/// a minute later.
pub async fn run(cfg: &DrainConfig, store: &Store) -> Result<(), Error> {
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
            transitions::report_failure(cfg, store, &journal, "config", "config", &Error::from(e))
                .await;
            return Ok(());
        }
    };
    // The rate cache first, so a window opening later in this pass quotes from
    // it. It asks the source only when the cache is more than a day old, and a
    // failure is not the pass's: a stale cache is exactly what the quote falls
    // back to.
    let _ = kyriakon_control_core::payments::xmr::current(cfg, OffsetDateTime::now_utc()).await;
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
    kyriakon_control_core::account::session::prune_proofs(
        std::path::Path::new(&cfg.proof_dir),
        OffsetDateTime::now_utc(),
    )
    .await;
    transitions::lifecycle::purge_declined(cfg, store, &journal).await?;
    // ADR 0005's application answers: the ninety days are counted from filing,
    // so this clears an approved application's copies and an abandoned record
    // away on the first pass after the window ends.
    transitions::lifecycle::purge_applications(cfg, store, &journal).await?;
    transitions::lifecycle::purge_closing(cfg, store, &journal).await?;
    // The free accounts' yearly note, on the same pass: a free account never
    // lapses, and this is the one message it is sent each year.
    transitions::lifecycle::free_anniversaries(cfg, store, &journal).await?;
    // The prepaid member's own renewal note, thirty days before the date runs
    // out: the rails with no processor have nobody else to send one.
    transitions::lifecycle::prepaid_renewals(cfg, store, &journal).await?;
    // The space used, from the filesystem quota the handler cannot read. Due
    // gated to once an hour, so most passes do no quota work.
    transitions::lifecycle::refresh_space_used(cfg, store, &journal).await?;
    // A mail-key replacement whose 72-hour window has closed applies here, on
    // the same pass its record is read.
    transitions::lifecycle::mail_key_rotations(cfg, store, &journal).await?;
    // A payment window whose day has passed either finds its credit and stays
    // active, or lapses the account and starts the grace. One sweep, so a
    // member who paid on the last day is not lapsed by a later pass.
    transitions::lifecycle::window_sweep(cfg, store, &journal).await?;
    // A lapsed account's grace: the final notice at day 33, and the one
    // deletion transition when the 40 days end.
    transitions::lifecycle::grace_sweep(cfg, store, &journal).await?;
    // The key spool is read after the intents so a filed application is not
    // waiting behind a mailbox pass. The pass handles each message on its own:
    // one that cannot be dealt with is reported and left for the next run.
    crate::mailbox::run(cfg, store, &journal).await?;
    // The groups' own zones are watched last: a record that has stopped
    // resolving is the one thing about a body's domain the platform can see and
    // cannot repair, and it must not delay a filed application or a member's
    // mail. It is due-gated, so most passes do no DNS work.
    transitions::lifecycle::check_group_dns(cfg, store, &journal).await?;
    // The card rail's arriving events are settled after everything else: a
    // misconfigured signing secret must not hold up an approval, and an event
    // that cannot be applied yet is left for the next pass.
    let stripe = transitions::stripe::stripe_webhooks(cfg, store, &journal).await;
    // Released holds go last, so the prune's rewrite of `journal.jsonl` is not
    // followed by an append that would use the loaded index's stale positions.
    // The sweep runs even when the card pass failed.
    let sweep = transitions::lifecycle::holds_sweep(store).await;
    stripe?;
    sweep
}

/// One intent file, deserialised once into its variant, proved, then applied.
async fn one(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    key: &[u8],
    file: &str,
) -> Result<(), Error> {
    // The listing is one snapshot, and a pass can delete a file another name in
    // that snapshot shares: an approval writes and applies its group intent in
    // the same pass, then removes it. A file that is gone reads as done, the
    // same rule store.remove uses, rather than as a failure the reviewer is
    // mailed about.
    let Some(text) = store.read_record("intents", file).await else {
        return Ok(());
    };
    let value: Value =
        serde_json::from_str(&text).map_err(|e| Error::context("the intent does not parse", e))?;
    let intent = Intent::parse(&value)?;
    run_intent(intent, cfg, store, journal, key, file, &value).await
}

/// Prove then apply, as the pass does. A `verify` that refuses the intent
/// hands its refusal to `settle`, which is the one place the line, the
/// dedup, the after-line work and the remove happen.
pub async fn run_intent(
    intent: Intent,
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    key: &[u8],
    file: &str,
    value: &Value,
) -> Result<(), Error> {
    if let Some(settlement) = verify(&intent, cfg, store, key, file, value).await? {
        let envelope = transitions::Envelope::of(value, file, intent.kind());
        return transitions::settle(
            cfg,
            store,
            journal,
            file,
            &envelope,
            disposition(&intent),
            async { Ok(settlement) },
        )
        .await;
    }
    apply(intent, cfg, store, journal, key, file, value).await
}

/// Prove the intent is the authenticated party's, before anything is
/// applied.
///
/// There is no catch-all arm: a variant added without deciding what proves
/// it does not compile. `Ok(None)` means the intent is proved and may be
/// applied. `Ok(Some(settlement))` is a refusal: the settlement is fed to
/// `settle`, which writes its one line and leaves or removes the file as
/// the verb's disposition says. `Err` is a pass that failed, which backs off
/// and is mailed once.
///
/// The signature and session checks are the ones the transitions used to
/// make themselves; every message and every journal outcome is the same.
pub async fn verify(
    intent: &Intent,
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    file: &str,
    value: &Value,
) -> Result<Option<transitions::Settlement>, Error> {
    let proofs = std::path::Path::new(&cfg.proof_dir);
    match intent {
        // The handler files it and the drain only queues a review: nothing
        // is written as root until a reviewer's signed decision, which the
        // `Decision` arm proves.
        Intent::Application(_) => Ok(None),
        Intent::Decision(intent) => {
            let token = intent.application.status_token.as_deref().ok_or_else(|| {
                Error::Failed("the status token is not 128 bits of Crockford".to_string())
            })?;
            if !kyriakon_control_core::store::is_status_token(token) {
                return Err(Error::Failed(
                    "the status token is not 128 bits of Crockford".to_string(),
                ));
            }
            if let Some(why) =
                kyriakon_control_core::flow::validate::username_shape(&intent.application.username)
            {
                return Err(Error::Failed(format!("the username: {why}")));
            }
            let Some(decision) = decision_for_kind(&intent.kind) else {
                return Err(Error::Failed(format!(
                    "kind {:?} is not a decision",
                    intent.kind
                )));
            };
            if intent.action != decision.action {
                return Err(Error::Failed(format!(
                    "the action {:?} does not match the kind {:?}",
                    intent.action, intent.kind
                )));
            }
            if !sign::verify(
                key,
                &sign::decide_payload(token, &intent.action),
                &intent.sig,
            ) {
                return Err(Error::Failed(
                    "the decision intent's signature does not verify".to_string(),
                ));
            }
            Ok(None)
        }
        Intent::Password(intent) => {
            // The handler files the plaintext and the drain hashes it: a
            // `hash` field is the old shape, where a handler with a valid
            // link chose the stored hash. `settle` owns the replay guards:
            // a settled intent never reaches this problem check again.
            let token = intent.application.status_token.as_deref().unwrap_or("");
            let problem: Option<String> = if value.get("hash").is_some() {
                Some("the intent carries a hash rather than a plaintext".to_string())
            } else if !sign::verify(
                key,
                &sign::password_payload(token, &intent.until),
                &intent.sig,
            ) {
                Some("the link's signature does not verify".to_string())
            } else if intent.until.as_str()
                < kyriakon_control_core::util::date_after_days(0).as_str()
            {
                Some("the link's date has passed".to_string())
            } else {
                kyriakon_control_core::account::password::validate(&intent.password)
                    .err()
                    .map(|e| e.to_string())
            };
            match problem {
                Some(why) => {
                    // The plaintext is revoked before the file is left in
                    // place, as every password refusal does; a failed
                    // redaction still leaves the refusal recorded, and the
                    // pass reports it.
                    Ok(Some(
                        match transitions::lifecycle::redact_password(store, file, value).await {
                            Ok(()) => transitions::Settlement::refused(why),
                            Err(failure) => transitions::Settlement::Refused {
                                reason: why,
                                failure: Some(failure),
                            },
                        },
                    ))
                }
                None => Ok(None),
            }
        }
        Intent::ProvisionGroup(intent) => {
            if sign::verify(key, &sign::group_provision_payload(intent), &intent.sig) {
                Ok(None)
            } else {
                Err(Error::Failed(
                    "the group intent's signature does not verify".to_string(),
                ))
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
                Ok(None)
            } else {
                Err(Error::Failed(
                    "the address intent's signature does not verify".to_string(),
                ))
            }
        }
        Intent::RemoveGroup(intent) => {
            if sign::verify(
                key,
                &sign::group_remove_payload(&intent.domain),
                &intent.sig,
            ) {
                Ok(None)
            } else {
                Err(Error::Failed(
                    "the remove-group intent's signature does not verify".to_string(),
                ))
            }
        }
        Intent::Close(intent) => {
            // A close reports a name it cannot use as a pass failure, where
            // a page action refuses it; the session proof is shared.
            account_name(&intent.username)?;
            session_proved(store, proofs, &intent.session, &intent.username).await
        }
        Intent::Resend(intent) => {
            if sign::verify(
                key,
                &sign::resend_payload(&intent.username, &intent.token),
                &intent.sig,
            ) {
                Ok(None)
            } else {
                Err(Error::Failed(
                    "the token resend's signature does not verify".to_string(),
                ))
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
                Ok(None)
            } else {
                Ok(Some(transitions::Settlement::refused(
                    "the credit intent's signature does not verify",
                )))
            }
        }
        Intent::WindowExtend(intent) => {
            if sign::verify(
                key,
                &sign::window_extend_payload(&intent.token, intent.days, &intent.reason),
                &intent.sig,
            ) {
                Ok(None)
            } else {
                Ok(Some(transitions::Settlement::refused(
                    "the window extension's signature does not verify",
                )))
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
                Ok(None)
            } else {
                Ok(Some(transitions::Settlement::refused(
                    "the reconcile-attribute intent's signature does not verify",
                )))
            }
        }
        Intent::ReconcileReturn(intent) => {
            if sign::verify(
                key,
                &sign::reconcile_return_payload(&intent.item, &intent.note),
                &intent.sig,
            ) {
                Ok(None)
            } else {
                Ok(Some(transitions::Settlement::refused(
                    "the reconcile-return intent's signature does not verify",
                )))
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
                Ok(None)
            } else {
                Ok(Some(transitions::Settlement::refused(
                    "the refund intent's signature does not verify",
                )))
            }
        }
        // A page action like the rest: an unusable name or session is the
        // handler's input refused, journalled once and removed, not a pass
        // that fails and retries forever.
        Intent::Export(intent) => {
            if let Some(why) =
                kyriakon_control_core::flow::validate::username_shape(&intent.username)
            {
                return Ok(Some(transitions::Settlement::refused(format!(
                    "the export intent's username {:?}: {why}",
                    intent.username
                ))));
            }
            session_proved(store, proofs, &intent.session, &intent.username).await
        }
        // A page action is proved by the session the handler filed, and by
        // the account name being one an account record can name.
        Intent::ChangePassword(intent) => {
            if value.get("hash").is_some() {
                return Ok(Some(transitions::Settlement::refused(
                    "the intent carries a hash rather than a plaintext",
                )));
            }
            page_proved(store, proofs, &intent.session, &intent.username).await
        }
        Intent::UploadKey(intent) => {
            page_proved(store, proofs, &intent.session, &intent.username).await
        }
        Intent::OutsideAddress(intent) => {
            page_proved(store, proofs, &intent.session, &intent.username).await
        }
        Intent::Serving(intent) => {
            page_proved(store, proofs, &intent.session, &intent.username).await
        }
        Intent::CancelRenewal(intent) => {
            page_proved(store, proofs, &intent.session, &intent.username).await
        }
        Intent::MailKey(intent) => {
            page_proved(store, proofs, &intent.session, &intent.username).await
        }
        Intent::Unknown { .. } => Ok(Some(transitions::Settlement::refused(
            "this build does not implement this kind; the intent is left in place",
        ))),
    }
}

/// Carry the intent out. Only reached once `verify` has proved it, so the
/// transitions behind these arms make no second proof of their own.
///
/// Every root verb is a body passed to `settle`: the dedup, the outcome
/// line and the remove are the combinator's, and a body that refuses says
/// so with the line it would have written.
pub async fn apply(
    intent: Intent,
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    key: &[u8],
    file: &str,
    value: &Value,
) -> Result<(), Error> {
    let kind = intent.kind().to_string();
    let envelope = transitions::Envelope::of(value, file, &kind);
    let disposition = disposition(&intent);
    transitions::settle(cfg, store, journal, file, &envelope, disposition, async {
        match intent {
            Intent::Application(intent) => {
                transitions::review::filed_application(cfg, store, journal, key, intent).await
            }
            Intent::Decision(intent) => {
                transitions::review::decision(cfg, store, journal, key, intent).await
            }
            Intent::Password(intent) => {
                transitions::lifecycle::set_password(cfg, store, intent, file, value).await
            }
            Intent::ProvisionGroup(intent) => {
                transitions::groups::provision_group(cfg, store, journal, *intent).await
            }
            Intent::GroupAddress(intent) => {
                transitions::groups::group_address(cfg, store, journal, intent).await
            }
            Intent::RemoveGroup(intent) => {
                transitions::groups::remove_group(cfg, store, journal, intent).await
            }
            Intent::Close(intent) => transitions::lifecycle::close_account(store, intent).await,
            Intent::Resend(intent) => transitions::review::resend(cfg, store, intent).await,
            Intent::Credit(intent) => {
                transitions::payments::credit(cfg, store, journal, intent).await
            }
            Intent::WindowExtend(intent) => {
                transitions::lifecycle::window_extend(store, intent).await
            }
            Intent::ReconcileAttribute(intent) => {
                transitions::payments::reconcile_attribute(cfg, store, journal, intent).await
            }
            Intent::ReconcileReturn(intent) => {
                transitions::payments::reconcile_return(store, intent).await
            }
            Intent::Refund(intent) => transitions::payments::refund(cfg, store, intent).await,
            Intent::Export(intent) => {
                transitions::lifecycle::export_account(cfg, store, intent, file).await
            }
            Intent::ChangePassword(intent) => {
                transitions::lifecycle::change_password(cfg, store, intent).await
            }
            Intent::UploadKey(intent) => {
                transitions::lifecycle::upload_key(cfg, store, intent).await
            }
            Intent::OutsideAddress(intent) => {
                transitions::lifecycle::set_outside_address(store, intent).await
            }
            Intent::Serving(intent) => {
                transitions::lifecycle::set_serving(cfg, store, intent).await
            }
            Intent::CancelRenewal(intent) => {
                transitions::lifecycle::cancel_renewal(cfg, store, intent).await
            }
            Intent::MailKey(intent) => transitions::lifecycle::mail_key(cfg, store, intent).await,
            // `verify` refuses an unknown kind before this is reached.
            Intent::Unknown { kind, .. } => Err(Error::Failed(format!(
                "this build does not implement the kind {kind:?}"
            ))),
        }
    })
    .await
}

/// What this verb's settlement owes beyond its body: the work its line must
/// precede, and what a refusal leaves of its file. Every variant is listed,
/// so a new one has to say both.
fn disposition(intent: &Intent) -> transitions::Disposition {
    // The verbs whose line and record cleanup cannot be one write name that
    // work here, once.
    let after = match intent {
        Intent::RemoveGroup(intent) => {
            transitions::AfterLine::RemoveGroupRecord(intent.domain.clone())
        }
        Intent::ReconcileAttribute(intent) => transitions::AfterLine::MarkAttributed {
            item: intent.item.clone(),
            token: intent.token.clone(),
        },
        Intent::Application(_)
        | Intent::Decision(_)
        | Intent::Password(_)
        | Intent::ProvisionGroup(_)
        | Intent::GroupAddress(_)
        | Intent::Close(_)
        | Intent::Resend(_)
        | Intent::Credit(_)
        | Intent::WindowExtend(_)
        | Intent::ReconcileReturn(_)
        | Intent::Refund(_)
        | Intent::Export(_)
        | Intent::ChangePassword(_)
        | Intent::UploadKey(_)
        | Intent::OutsideAddress(_)
        | Intent::Serving(_)
        | Intent::CancelRenewal(_)
        | Intent::MailKey(_)
        | Intent::Unknown { .. } => transitions::AfterLine::Nothing,
    };
    // A page action's refusal is the handler's own input, so its file goes;
    // every other verb keeps a refusal for the operator. A close is a page
    // action too, though its only refusal is the session proof's.
    let refusal = match intent {
        Intent::ChangePassword(_)
        | Intent::UploadKey(_)
        | Intent::OutsideAddress(_)
        | Intent::Serving(_)
        | Intent::CancelRenewal(_)
        | Intent::MailKey(_)
        | Intent::Close(_)
        | Intent::Export(_) => transitions::RefusalFile::Remove,
        Intent::Application(_)
        | Intent::Decision(_)
        | Intent::Password(_)
        | Intent::ProvisionGroup(_)
        | Intent::GroupAddress(_)
        | Intent::RemoveGroup(_)
        | Intent::Resend(_)
        | Intent::Credit(_)
        | Intent::WindowExtend(_)
        | Intent::ReconcileAttribute(_)
        | Intent::ReconcileReturn(_)
        | Intent::Refund(_)
        | Intent::Unknown { .. } => transitions::RefusalFile::Keep,
    };
    transitions::Disposition::new(after, refusal)
}

/// The one rule for a name the drain turns into a path: only an account name
/// may be one, because an intent's username is a path component under the
/// store. `Err` carries the reason, worded for the journal.
fn account_name(username: &str) -> Result<(), Error> {
    match kyriakon_control_core::flow::validate::username_shape(username) {
        Some(why) => Err(Error::Failed(format!("the username {username:?}: {why}"))),
        None => Ok(()),
    }
}

/// The page verbs' and close's one session proof: the record's proof names the
/// account. A mismatch, an expiry and a session that has gone are the refusal
/// this returns; `settle` records it once and removes the file.
async fn session_proved(
    store: &Store,
    proofs: &std::path::Path,
    session: &str,
    username: &str,
) -> Result<Option<transitions::Settlement>, Error> {
    match verify_session(store, proofs, session, username).await {
        Ok(()) => Ok(None),
        Err(reason) => Ok(Some(transitions::Settlement::refused(reason))),
    }
}

/// A page action's proof: the account name rule, then the session. A refusal is
/// the settlement the caller hands to `settle`.
async fn page_proved(
    store: &Store,
    proofs: &std::path::Path,
    session: &str,
    username: &str,
) -> Result<Option<transitions::Settlement>, Error> {
    if let Err(why) = account_name(username) {
        return Ok(Some(transitions::Settlement::refused(why)));
    }
    session_proved(store, proofs, session, username).await
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
) -> Result<(), Error> {
    if !kyriakon_control_core::store::is_status_token(id) {
        return Err(Error::Failed(
            "the intent carries no usable session id".to_string(),
        ));
    }
    let Some(text) = store.read_record("sessions", &format!("{id}.json")).await else {
        return Err(Error::Failed(
            "the session named by the intent has gone".to_string(),
        ));
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| Error::context("the session record does not parse", e))?;
    let proof = value.get("proof").and_then(Value::as_str).unwrap_or("");
    kyriakon_control_core::account::session::verify_proof(
        proof_dir,
        proof,
        username,
        OffsetDateTime::now_utc(),
    )
    .await
    .map_err(Error::from)
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
            toml::from_str(include_str!("../../../../openbsd/etc/onboard/drain.toml")).unwrap();
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
