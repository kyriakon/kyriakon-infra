//! The reviewer's half: a filed application's review mail, the three decisions,
//! the approval (person and body), the decline, the record lookups a decision
//! acts on, and the paid account's payment instructions re-sent on request.

use super::boxrun::{
    outside_address, publish_mail_keys, publish_mail_keys_publicly, recipient, run_script,
    run_script_tolerating, write_public_key,
};
use super::groups::{
    account_on_box, append_ledger, body_domain_refusal, check_group_names, group_addresses,
    group_record, name_allowed, name_held, site_owner, write_account_record,
};
use super::lifecycle::group_recipient;
use super::Error;
use super::{write_journal, Settlement};
use kyriakon_control_core::account::dns;
use kyriakon_control_core::account::sign;
use kyriakon_control_core::config::DrainConfig;
use kyriakon_control_core::flow::questions;
use kyriakon_control_core::flow::validate;
use kyriakon_control_core::intent::{DecisionIntent, ResendIntent, DECISIONS, RAILS};
use kyriakon_control_core::mail::notice;
use kyriakon_control_core::payments::rails::{card_link, rail_instructions};
use kyriakon_control_core::store::journal::Journal;
use kyriakon_control_core::store::{
    self, Account, ApplicationRef, FlatPayment, GroupIntent, GroupPayment, Intent, Monero,
    PasswordLink, Payment, Record, Store, TokenRecord, UploadKey, Window,
};
use kyriakon_control_core::util;
use serde_json::json;
use serde_json::Value;
use time::OffsetDateTime;

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
/// account exists, so this function returns without sending. The approval mail
/// to the mailbox the approval creates carries the same [`confirmation_body`],
/// which is how the durable-medium confirmation reaches an applicant who gave
/// no other address. The acceptances stay on the application record either way,
/// and the status page carries the decision and the password link, not this
/// letter.
async fn confirm(
    cfg: &DrainConfig,
    store: &Store,
    token: &str,
    record: &Record,
    no_charge: bool,
) -> Result<(), Error> {
    let Some(to) = outside_address(record)? else {
        // Nothing to send yet: the mailbox does not exist. `approval_body` puts
        // this letter on the approval mail that reaches the new mailbox.
        return Ok(());
    };
    // The stamp is a read-check-write of a record replaced by rename, so the
    // lock lives beside it; two drain passes on the same application could
    // otherwise both read it as unconfirmed. It is held across the send rather
    // than only the write: releasing it before the send would let the second
    // pass find the stamp and skip while a failed send is recorded as sent.
    let _lock = store.lock("applications/.confirmation.lock").await?;
    let mut live = application_record(store, token).await?;
    if live.confirmation_at.is_some() {
        return Ok(());
    }
    let subject = confirmation_subject(&live.username);
    let body = confirmation_body(cfg, &live, no_charge);
    live.confirmation_at = Some(util::filed_at());
    save_application(store, token, &live).await?;
    if let Err(e) = notice::enqueue(cfg, &to, &subject, &body).await {
        // The stamp goes back before the error, so a retry is a resend rather
        // than an approval that provisions with the letter lost.
        live.confirmation_at = None;
        save_application(store, token, &live).await?;
        return Err(Error::from(e));
    }
    Ok(())
}

/// Write the application record, handed to the handler's owner like every other
/// record in `applications/`.
async fn save_application(store: &Store, token: &str, record: &Record) -> Result<(), Error> {
    let bytes = serde_json::to_vec_pretty(record).map_err(|source| Error::Json {
        context: "encode the record",
        source,
    })?;
    let owner = store.dir_owner("applications");
    store
        .write_record_owned("applications", &format!("{token}.json"), &bytes, owner)
        .await
        .map_err(Error::from)
}

/// A filed application: one review email to the reviewer, carrying every answer,
/// the mail-key result, whether an upload key was supplied, the rail, whether no
/// charge was asked for, and three signed links.
pub async fn filed_application(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    key: &[u8],
    intent: Intent,
) -> Result<Settlement, Error> {
    if intent.kind != "application" {
        return Err(Error::Failed(format!(
            "kind {:?} is not an application",
            intent.kind
        )));
    }
    name_allowed(cfg, &intent.application.username).await?;
    let Some(token) = intent.application.status_token.as_deref() else {
        return Err(Error::Failed(
            "the status token is not 128 bits of Crockford".to_string(),
        ));
    };
    if !store::is_status_token(token) {
        return Err(Error::Failed(
            "the status token is not 128 bits of Crockford".to_string(),
        ));
    }
    if !RAILS.contains(&intent.rail.as_str()) {
        return Err(Error::Failed(format!(
            "the rail {:?} is not one of the four",
            intent.rail
        )));
    }

    // The links are signed from the record the approval will read, and the mail
    // shows those same values, so a rewrite between the mail and the click no
    // longer verifies. A record that is not there cannot be reviewed or
    // approved; failing here leaves the intent and the record for the next pass
    // rather than sending links that could never be carried out.
    let record = application_record(store, token).await?;

    // One review email per application, not per intent: the journal is the
    // record and it is written before the send, so a crash loses an email
    // rather than sending two.
    if journal.application_seen(token, "application", "review-sent") {
        // The line is the settlement; a crash left only the file.
        return Ok(Settlement::nothing());
    }
    write_journal(
        store,
        journal,
        &cfg.release,
        &intent.id,
        "application",
        &intent.application,
        "review-sent",
        None,
    )
    .await?;

    // The same subject shape as every other operator mail: the component, then
    // the event, with the application named in it. The token stays because two
    // applications from one username differ only by it, so the mailbox list is
    // where the operator can tell them apart before opening either.
    let subject = notice::operator_subject(
        "control",
        &format!(
            "application filed ({}, {})",
            intent.application.username,
            intent.application.status_token.as_deref().unwrap_or("")
        ),
    );
    let body = review_body(cfg, key, &record)?;
    notice::enqueue(cfg, &cfg.reviewer, &subject, &body).await?;
    // The `review-sent` line was written before the send, which is what keeps a
    // crash from sending twice; only the file is left to settle.
    Ok(Settlement::nothing())
}

/// The review email's body. Every field the ticket lists, and the three links
/// beside their `kyriakon-admin` equivalents.
///
/// Everything here comes from the record, not the intent, because the links are
/// signed over the record: the reviewer must see exactly the field values the
/// signature covers.
fn review_body(cfg: &DrainConfig, key: &[u8], record: &Record) -> Result<String, Error> {
    let token = record.status_token.as_str();
    let mut out = String::new();
    out.push_str(&format!("Application {}\n", record.username));
    out.push_str(&format!(
        "Filed {} by the {} front end\n",
        record.filed_at, record.front_end
    ));
    out.push_str(&format!("Question list {}\n", record.question_list));
    out.push_str(&format!("Rail: {}\n", record.rail));
    out.push_str(&format!(
        "No charge asked for: {}\n",
        if record.no_charge { "yes" } else { "no" }
    ));
    out.push_str(&format!(
        "Domain: {}\n",
        record.domain.as_deref().unwrap_or("none")
    ));
    out.push_str(&format!(
        "Address outside the platform: {}\n",
        record.outside_address.as_deref().unwrap_or("none")
    ));
    out.push_str(&format!(
        "Upload key: {}\n",
        if record.upload_key.is_some() {
            "supplied"
        } else {
            "not supplied"
        }
    ));

    if record.mail_keys.is_empty() {
        out.push_str("Mail key: none submitted\n");
    } else {
        out.push_str("Mail keys:\n");
        for k in &record.mail_keys {
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
    for (id, answer) in &record.answers {
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
    let username = &record.username;
    out.push_str("\nFrom a terminal\n");
    // The token is part of the command, not decoration: the console signs for
    // the application this token names, so a second application filed under the
    // same username cannot be what the terminal decision signs.
    out.push_str(&format!("  kyriakon-admin approve {username} {token}\n"));
    out.push_str(&format!(
        "  kyriakon-admin approve-free {username} {token}\n"
    ));
    out.push_str(&format!("  kyriakon-admin decline {username} {token}\n"));
    out.push_str(
        "\nOr by link, which works once. Each is 140 characters and the signature\n\
         is at the end, so a mail client that wraps a long line cuts it at the\n\
         wrap: open it as one unbroken line, or use the terminal form above.\n",
    );
    for d in DECISIONS.iter() {
        out.push_str(&format!(
            "\n  {}\n  {}\n",
            d.label,
            sign::decide_link(&cfg.base_url, key, record, d.action)?
        ));
    }
    Ok(out)
}

/// A decision intent: an approval with the charge, an approval without it, or a
/// decline. The signature over the application and the action, and the fields it
/// covers, are checked by `verify` before this runs; what is left is the
/// outcome the decided application takes.
pub async fn decision(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    key: &[u8],
    intent: DecisionIntent,
) -> Result<Settlement, Error> {
    match intent.kind.as_str() {
        "approve" => approve(cfg, store, journal, key, &intent, false).await,
        "provision" => approve(cfg, store, journal, key, &intent, true).await,
        "decline" => decline(cfg, store, journal, &intent).await,
        // Unreachable after the kind match the seam makes, kept so the dispatch
        // is total.
        other => Err(Error::Failed(format!("kind {other:?} is not a decision"))),
    }
}

/// The approval path, charged and without charge. `no_charge` is the free
/// outcome: no token, no window, no ledger line, and an account that never
/// lapses. The application's own answer is honoured too: an application that
/// asked for no charge is never charged by a charge-carrying intent.
async fn approve(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    key: &[u8],
    intent: &DecisionIntent,
    no_charge: bool,
) -> Result<Settlement, Error> {
    let token = intent
        .application
        .status_token
        .as_deref()
        .ok_or_else(|| Error::Failed("the decision names no status token".to_string()))?;
    let username = &intent.application.username;
    let record = application_record(store, token).await?;
    if record.username != *username {
        return Err(Error::Failed(
            "the intent's username is not the application's".to_string(),
        ));
    }
    let no_charge = no_charge || record.no_charge;
    if record.decided_at.is_some() {
        return Ok(Settlement::line(
            "already-decided",
            intent.application.clone(),
            Some("the application was already decided; nothing was carried out".to_string()),
        ));
    }

    // The signature is checked again against the record this approval will act
    // on, not only against the one `verify` read a moment before. Both halves of
    // the drain's read are handler-rewritable and the record can change between
    // them; this is the read whose name and keys are installed.
    if !sign::verify(
        key,
        &sign::decide_payload(&record, &intent.action),
        &intent.sig,
    ) {
        return Err(Error::Failed(
            "the decision intent's signature does not verify against this record".to_string(),
        ));
    }

    // A body's accounts are the address table's, not the applicant's: the person
    // path below would make one account for the accountable person and none of
    // the mailboxes. The whole application is one group intent instead.
    if record.domain.is_some() {
        return approve_group(cfg, store, journal, key, intent, &record, no_charge).await;
    }

    // The recipient is revalidated before anything is written or journaled, so a
    // record whose address could inject a header is refused rather than
    // half-applied.
    let to = recipient(&record, username)?;

    // Whether this application's own approval already began, and under which
    // name. A genuine retry has its own "applying" line; anything else holding
    // this name is not this application's. The line is root-written from the
    // signed decision, so the name it carries is the one the account was made
    // under, and a record rewritten to another name after the review mail cannot
    // adopt it. The check runs before any gate, so the rewrite cannot reach a
    // gate the first approval's line would excuse.
    let begun = journal.approval_started(token);
    if let Some(started) = begun.as_deref() {
        if started != record.username {
            return Err(Error::Failed(format!(
                "this application's approval began for {started}, not {}; the intent is left in place",
                record.username
            )));
        }
    }
    let retry = begun.is_some();
    let existing = store.account(username).await?;

    // An account record that this application never began is a second
    // application for a username that already has one. Nothing here is this
    // application's to reuse: not the payment token, not its window, and not its
    // ledger row, and an approval reached this way would rewrite the first
    // application's payment state, leaving the account and the ledger
    // disagreeing about what is owed. This is the replay rule for a different
    // reason: the click is recorded and the intent is dropped.
    if existing.is_some() && !retry {
        return Ok(Settlement::line("already-member", intent.application.clone(), Some("this username already has an account that this application did not make; nothing was carried out".to_string())));
    }

    // The held-back names are checked here, where the account would be made,
    // rather than where the intent is read: only an approval creates an account,
    // and a decline of a held-back name must still be carried out. They run on a
    // retry too: the retry is bound to the journal's name, and a name that
    // became reserved or held since that line was written is no longer one this
    // approval may install.
    name_allowed(cfg, username).await?;
    // A group mailbox that closed leaves the name held for ninety days, and
    // this is the other gate that can create an account. Without it a person
    // could take a name a removal had just held.
    if let Some(until) = name_held(store, username).await? {
        return Err(Error::Failed(format!(
            "the username {username} is held until {until}, so it cannot be reused yet"
        )));
    }

    // The box is the oracle and the record only a fast path. A name already on
    // the box that this application did not create is somebody else's, and it is
    // refused rather than adopted: the front end may not check existence at all,
    // so the drain must not silently take the account. The check runs before the
    // journal line, so a refusal records nothing and leaves the intent in place.
    let mut on_box = false;
    if existing.is_none() {
        on_box = account_on_box(cfg, username)?;
        if on_box && !retry {
            return Err(Error::Failed(format!(
                "the username {username} is already in use on this box and this application did not create it; the intent is left in place"
            )));
        }
    }

    // The key material is checked again here, before the journal line, because a
    // signature over whatever the handler wrote still installs a key that is not
    // a key: a private block, an SSH key or a truncated one would reach the
    // encryptor's keyring or the member's `authorized_keys`. The form and the
    // rotation path refuse the same shapes; this is the last path that can
    // create a mailbox, so it runs the same check rather than trusting the
    // record's own verdict field. It runs only when something would be
    // installed: the already-member and name refusals above make no account.
    for key in &record.mail_keys {
        let checked = kyriakon_control_core::mail::keycheck::pgp_public_key(&key.material)
            .map_err(|e| Error::context("the application's mail key", e))?;
        if let Some(why) = checked.refusal() {
            return Err(Error::Failed(format!(
                "the application's mail key cannot be used: {why}"
            )));
        }
    }
    if let Some(key) = record.upload_key.as_ref() {
        kyriakon_control_core::mail::keycheck::openssh_public_key(&key.material)
            .map_err(|e| Error::context("the application's upload key", e))?;
    }

    // The confirmation the spec promises goes out before the journal's
    // "applying" line and before any provisioning, so the record of what was
    // agreed exists before the service begins.
    confirm(cfg, store, token, &record, no_charge).await?;

    write_journal(
        store,
        journal,
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
    // The Monero quote is taken once, when the window opens, and honoured for
    // its fourteen days: a retry of the approval reuses the block already
    // written rather than re-quoting. A window that opened with no rate ever
    // fetched carries none at all, which is what leaves cash as the only
    // prepaid rail on the account page.
    let monero = if no_charge || record.rail != "monero" {
        None
    } else {
        match existing
            .as_ref()
            .and_then(|a| a.payment_state())
            .and_then(|p| p.monero)
        {
            Some(block) => Some(block),
            None => {
                kyriakon_control_core::payments::xmr::quote(
                    cfg,
                    OffsetDateTime::now_utc(),
                    &cfg.price_gbp,
                )
                .await
            }
        }
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
            monero,
        })
    };

    let upload_keys: Vec<UploadKey> = record
        .upload_key
        .as_ref()
        .filter(|key| !key.fingerprint.is_empty())
        .map(|key| {
            vec![UploadKey {
                fingerprint: key.fingerprint.clone(),
                added_at: now.clone(),
            }]
        })
        .unwrap_or_default();
    // provision-member.sh writes both daemon lanes when the application carried
    // an upload key, so the record says both are on rather than leaving the page
    // to read a lane nobody has turned off as off.
    let hosted = record.upload_key.is_some().then_some(true);

    // The link this approval mails and stores on the status page. The mailbox's
    // own record carries the same token, so `set_password` authorizes from the
    // account and a retry keeps the token and date the first pass put in the mail.
    let account_password_link = existing
        .as_ref()
        .and_then(|a| a.password_link.clone())
        .unwrap_or_else(|| PasswordLink {
            token: record.status_token.clone(),
            until: util::date_after_days(7),
        });
    // Signed and recorded with the account's own token, never the status token:
    // a reset between the first pass and a retry replaces the account's link, so
    // a link built from the status token would be one the drain refuses.
    let password_until = account_password_link.until.clone();
    let password_token = account_password_link.token.clone();

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
        site_served: hosted,
        capsule_served: hosted,
        space_used: None,
        upload_keys,
        mail_key: record
            .mail_keys
            .first()
            .map(|key| key.fingerprint.clone())
            .filter(|f| !f.is_empty()),
        // A retried approval must not cancel a rotation the member began after
        // the first pass; the window outlives the intent either way.
        rotation: existing.as_ref().and_then(|a| a.rotation.clone()),
        suspension_reason: None,
        password_link: Some(account_password_link),
        group: None,
        closing_until: None,
        grace_until: None,
    };
    store
        .ensure_dir_owned(
            &format!("accounts/{username}"),
            0o750,
            store.dir_owner("accounts"),
        )
        .await?;
    let account_bytes = serde_json::to_vec_pretty(&account).map_err(|source| Error::Json {
        context: "encode the account",
        source,
    })?;
    write_account_record(store, username, &account_bytes).await?;

    if let (Some(token), Some(window)) = (&token_ref, &window) {
        let join = TokenRecord {
            token: token.clone(),
            username: username.clone(),
            group: None,
            issued_at: now.clone(),
            window_closes_at: window.closes_at.clone(),
            state: "issued".to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&join).map_err(|source| Error::Json {
            context: "encode the token record",
            source,
        })?;
        store.ensure_dir("tokens").await?;
        store
            .write_record("tokens", &format!("{token}.json"), &bytes)
            .await?;
        append_ledger(store, token, &record.rail, &intent.id, &now, &cfg.price_gbp).await?;
    }

    // The account's own copy of the application, inside the 90-day purge, with
    // the status link's own end written on it.
    let mut app_copy: Value =
        serde_json::from_str(&store.filed_application_text(token).await?.ok_or_else(|| {
            Error::Failed("the application record vanished mid-approval".to_string())
        })?)
        .map_err(|e| Error::context("the application record does not parse", e))?;
    app_copy["status_link_until"] = json!(util::after_days(7));
    // The handler renders the status page as `_onboard` and cannot read the
    // root-owned account, so the payment block it shows is this copy, written
    // back into the record it does read. A free approval carries none, which is
    // also why an undecided application never shows one.
    if let Some(block) = &account.payment {
        app_copy["payment"] = serde_json::to_value(block).map_err(|source| Error::Json {
            context: "encode the payment block",
            source,
        })?;
    }
    let copy_bytes = serde_json::to_vec_pretty(&app_copy).map_err(|source| Error::Json {
        context: "encode the application copy",
        source,
    })?;
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
    let password_link = sign::password_link(
        &cfg.base_url,
        key,
        &password_token,
        &record.username,
        &password_until,
    )?;
    let body = approval_body(
        cfg,
        &record,
        no_charge,
        decision_body(
            cfg,
            &record.username,
            &record.rail,
            no_charge,
            token_ref.as_deref(),
            &window,
            account.payment.as_ref().and_then(|p| p.monero.as_ref()),
        )?,
        &password_until,
        &password_link,
    );
    let notice_type = if no_charge {
        "approval.free"
    } else {
        "approval.paid"
    };
    notice::send_account_notice_retryable(cfg, store, username, notice_type, &subject, &to, &body)
        .await?;

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
    Ok(Settlement::line(
        "applied",
        intent.application.clone(),
        None,
    ))
}

/// The approval of a body's application: the community block's addresses become
/// one `provision-group` intent, which is then applied in this pass. The intent
/// is written before it is applied, so a crash between the two leaves the work
/// for the next pass rather than losing it.
///
/// Its name is a fresh ULID, so the intent directory's lexical order stays the
/// order things were filed; a replay files a second intent whose apply finds its
/// own accounts and makes nothing twice.
#[allow(clippy::too_many_arguments)]
async fn approve_group(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    key: &[u8],
    intent: &DecisionIntent,
    record: &Record,
    no_charge: bool,
) -> Result<Settlement, Error> {
    let domain = record
        .domain
        .clone()
        .ok_or_else(|| Error::Failed("the application names no domain".to_string()))?;
    if let Some(why) = validate::domain(&domain) {
        return Err(Error::Failed(format!("the domain {domain:?}: {why}")));
    }
    // The platform's own domain is not a body's to claim: its approval would
    // shadow the operator's addresses and its later removal would take the
    // platform's tables, vhosts and certificate. A refusal, so the decision
    // settles rather than retrying forever.
    if let Some(reason) = body_domain_refusal(cfg, &domain).await? {
        return Ok(Settlement::refused(reason));
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
    if existing_group.is_some() && journal.approval_started(&record.status_token).is_none() {
        return Err(Error::Failed(format!(
            "the domain {domain} already has a group that this application did not make"
        )));
    }
    let (addresses, mailboxes) = group_addresses(record)?;
    let site_owner = site_owner(record, &mailboxes)?;
    // Every mailbox's key must be in hand before anything is journaled, so a
    // refusal records nothing and no intent is left for a name or a key the
    // applicant has to change.
    for mailbox in &mailboxes {
        if !record.mail_keys.iter().any(|k| &k.mailbox == mailbox) {
            return Err(Error::Failed(format!(
                "the mailbox {mailbox} has no mail key, so its mail would bounce"
            )));
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
    confirm(cfg, store, &record.status_token, record, no_charge).await?;

    write_journal(
        store,
        journal,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &intent.application,
        "applying",
        None,
    )
    .await?;

    // The one writer draws the ULID (the intent directory sorts by name, so
    // every name has to be one for a lexical sort to be an age sort) and stamps
    // the kind and filing time; the payload is built without its envelope.
    let mut group = GroupIntent {
        id: String::new(),
        kind: String::new(),
        filed_at: String::new(),
        application: ApplicationRef::application(
            record.username.clone(),
            record.status_token.clone(),
        ),
        domain: domain.clone(),
        name,
        body_kind,
        payment: GroupPayment {
            rail: if no_charge {
                "no_charge"
            } else {
                record.rail.as_str()
            }
            .to_string(),
            no_charge,
            token_ref: None,
            window: None,
            paid_until: None,
            stripe: Default::default(),
        },
        addresses,
        mailboxes: mailboxes.clone(),
        site_owner: site_owner.clone(),
        upload_key: record
            .upload_key
            .as_ref()
            .map(|k| k.material.clone())
            .unwrap_or_default(),
        mail_keys: record.mail_keys.clone(),
        sig: String::new(),
    };
    // The signature travels with the intent because `intents/` is the handler's
    // directory and `provision_group` creates system accounts as root. Every
    // field the transition acts on is in the payload, so a filed intent cannot
    // be edited between this write and the drain's next pass.
    group.sig = sign::sign(key, &sign::group_provision_payload(&group))?;
    let id = kyriakon_control_core::intent::Intent::ProvisionGroup(Box::new(group))
        .file(store)
        .await?;
    let filename = format!("{id}.json");
    // Carry out the bytes on disk, not the copy in memory: the file is what the
    // next pass would read, envelope included, so the payload the transition
    // acts on is the one the writer stamped.
    let text = store
        .read_record("intents", &filename)
        .await
        .ok_or_else(|| {
            Error::Failed(format!("the intent this pass filed at {filename} is gone"))
        })?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| Error::context("the intent this pass filed does not parse", e))?;
    let filed = kyriakon_control_core::intent::Intent::parse(&value)?;
    // The provision-group arm verifies or fails; it has no refusal of its own,
    // because the signature it checks is the one this pass just made. `run_intent`
    // is the seam the next pass would use, so the line and the remove are its.
    // Boxed: this file's own approval path reaches `apply`, which reaches the
    // group transition, so the future would otherwise be infinitely sized.
    Box::pin(crate::run_intent(
        filed, cfg, store, journal, key, &filename, &value,
    ))
    .await?;

    // The body's approval notice: the recipe is the whole point of it, because
    // mail and the website do not work until the body has published the records
    // itself. It is recorded before it is enqueued, so a crash between the two
    // loses an email rather than sending two on the retry. The payment the
    // approval opened is on the same mail: one token for the whole group, the
    // rail's own instructions and the date the money must arrive by.
    let written = group_record(store, &domain)
        .await?
        .ok_or_else(|| Error::Failed("the group record vanished mid-approval".to_string()))?;
    // The handler renders the status page as `_onboard` and cannot read the
    // root-owned group record, so the block it shows is this copy in the
    // application record, as the person path writes the account's.
    if !written.payment.no_charge {
        stamp_group_payment(store, &record.status_token, &written).await?;
    }
    let price = cfg.group_price_gbp.as_str();
    // A group on a cash rail has no Stripe link, and asking for one would fail
    // the approval of a body that never chose the card rail.
    let link = if written.payment.rail == "card" {
        card_link(
            &cfg.stripe_group_payment_link,
            written.payment.token_ref.as_deref().unwrap_or(""),
        )
        .map_err(|_| {
            Error::Failed(
                "stripe_group_payment_link is not configured, so a group card approval has no \
                 link to send"
                    .to_string(),
            )
        })?
    } else {
        None
    };
    let payment_note = match (&written.payment.token_ref, &written.payment.window) {
        (Some(token), Some(window)) if !written.payment.no_charge => format!(
            "\n\nThe amount is GBP {price} for the year, for the whole group. Your payment \
             reference is {token}.\n{}\
             \nThe money must arrive before {} or the whole group lapses: mail keeps \
             arriving and everything published stays up, and sending, uploading and \
             pushing stop. Nothing is deleted at that point.\n",
            rail_instructions(
                &written.payment.rail,
                &cfg.postal_address,
                link.as_deref(),
                None,
                price,
            )
            .join("\n"),
            &window.closes_at[..10.min(window.closes_at.len())]
        ),
        _ => "\n\nThe group was approved without charge: there is nothing to pay, no \
              payment window, and the group does not lapse.\n"
            .to_string(),
    };
    let recipe = dns::recipe(&domain, &values);
    // One link per mailbox the approval just made. The tokens were written onto
    // each account by the provision pass, so a retry of this approval mails the
    // same links rather than invalidating the ones already sent.
    let mut password_links: Vec<(String, String)> = Vec::new();
    for mailbox in &mailboxes {
        let account = store
            .account(mailbox)
            .await?
            .ok_or_else(|| Error::Failed(format!("the mailbox {mailbox} has no account record")))?;
        let link = account
            .password_link
            .ok_or_else(|| Error::Failed(format!("the mailbox {mailbox} has no password link")))?;
        password_links.push((
            mailbox.clone(),
            sign::password_link(&cfg.base_url, key, &link.token, mailbox, &link.until)?,
        ));
    }
    let subject = decision_subject("approved", &domain);
    let body = group_approval_body(
        cfg,
        record,
        written.payment.no_charge,
        &domain,
        &payment_note,
        &recipe.text(),
        &password_links,
    );
    notice::send_account_notice_retryable(
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
    Ok(Settlement::line(
        "applied",
        intent.application.clone(),
        None,
    ))
}

/// Put the body's payment block on the application record the status page
/// reads. The handler cannot read the root-owned group record, so the page
/// shows this copy, as `approve` copies the account's block. A free group has
/// no block anywhere, and its application record stays without one.
async fn stamp_group_payment(
    store: &Store,
    token: &str,
    group: &kyriakon_control_core::store::GroupRecord,
) -> Result<(), Error> {
    let text = store
        .filed_application_text(token)
        .await?
        .ok_or_else(|| Error::Failed("the application record is gone".to_string()))?;
    let mut record: Value =
        serde_json::from_str(&text).map_err(|e| Error::context("the application record", e))?;
    let block = Payment {
        token_ref: group.payment.token_ref.clone(),
        token_issued_at: Some(group.created_at.clone()),
        paid_until: group.payment.paid_until.clone(),
        window: group.payment.window.clone(),
        rail: Some(group.payment.rail.clone()),
        stripe: group.payment.stripe.clone(),
        ..Default::default()
    };
    record["payment"] = serde_json::to_value(block).map_err(|source| Error::Json {
        context: "encode the group payment block",
        source,
    })?;
    let bytes = serde_json::to_vec_pretty(&record).map_err(|source| Error::Json {
        context: "encode the application record",
        source,
    })?;
    // `applications/` belongs to the handler, so the drain hands the rewritten
    // record back to that directory's owner. A root-owned file would read as
    // missing to the process that renders the page.
    let owner = store.dir_owner("applications");
    store
        .write_record_owned("applications", &format!("{token}.json"), &bytes, owner)
        .await
        .map_err(Error::from)
}

/// The decline: no reason, a message that offers the way back, the application
/// held a week, and only a monastic decline says what is missing.
async fn decline(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: &DecisionIntent,
) -> Result<Settlement, Error> {
    let token = intent
        .application
        .status_token
        .as_deref()
        .ok_or_else(|| Error::Failed("the decision names no status token".to_string()))?;
    let username = &intent.application.username;
    let record = application_record(store, token).await?;
    if record.username != *username {
        return Err(Error::Failed(
            "the intent's username is not the application's".to_string(),
        ));
    }
    if record.decided_at.is_some() {
        return Ok(Settlement::line(
            "already-decided",
            intent.application.clone(),
            Some("the application was already decided; nothing was carried out".to_string()),
        ));
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
                return Err(Error::Failed(format!(
                    "the address outside the platform {addr:?}: {why}"
                )));
            }
            Some(addr.to_string())
        }
        None => None,
    };
    // An approval journals "applying" before it provisions and writes the
    // account record last, so a failure in between leaves a live OS account, its
    // Maildir, the keyring file and the virtuals line with no record. Every
    // sweep starts from `accounts/`, so a decline accepted over that would leave
    // an account nobody owns and a name no purge can release. Erase what the
    // approval made before the decision is recorded; a failure here fails the
    // decline and leaves its intent for the next pass rather than a decision
    // over a live account. A body's approval makes the group's mailboxes, not an
    // account of the site owner's, so that path is left to its own transition.
    let mut erased = false;
    if record.domain.is_none() && journal.approval_started(token) {
        erased = super::lifecycle::erase_half_made(cfg, store, journal, username).await?;
    }
    write_journal(
        store,
        journal,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &intent.application,
        "applying",
        erased.then_some("the failed approval's half-made account was erased first"),
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
    Ok(Settlement::line(
        "applied",
        intent.application.clone(),
        None,
    ))
}

/// The application record a decision acts on, or an error naming what is
/// missing. A decision intent for an application that is not on disk is refused
/// rather than creating anything.
async fn application_record(store: &Store, token: &str) -> Result<Record, Error> {
    store
        .application(token)
        .await?
        .ok_or_else(|| Error::Failed("there is no application for this token".to_string()))
}

/// Write the decision onto the application record. `password_link` is written
/// only when there is one: a decline has no account and so no password to set.
async fn mark_decided(
    store: &Store,
    token: &str,
    stage: &str,
    decided_at: &str,
    password_link: Option<String>,
) -> Result<(), Error> {
    let mut record = store.application(token).await?.ok_or_else(|| {
        Error::Failed("the application record vanished before it could be decided".to_string())
    })?;
    record.stage = stage.to_string();
    record.decided_at = Some(decided_at.to_string());
    record.password_link = password_link;
    let bytes = serde_json::to_vec_pretty(&record).map_err(|source| Error::Json {
        context: "encode the record",
        source,
    })?;
    // `applications/` belongs to the handler, so the drain hands the rewritten
    // record back to that directory's owner. A root-owned 0600 file would read
    // as missing to the unprivileged process that renders the status page, and
    // the link would answer as an unknown token for the week it should answer.
    let owner = store.dir_owner("applications");
    store
        .write_record_owned("applications", &format!("{token}.json"), &bytes, owner)
        .await
        .map_err(Error::from)
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
/// recorded, the version of every document accepted, the trader's identity and
/// address, the price and period, and the 14-day right with the model
/// cancellation form, in the words `docs/terms.md` uses.
///
/// Reg 16(2) and Schedule 2 want the identity and geographic address of the
/// trader, the price and how it is billed, and the cancellation right with the
/// Schedule 3 Part B form. The text here is the durable-medium copy of the
/// contract summary, so it is complete without the applicant opening the site.
fn confirmation_body(cfg: &DrainConfig, record: &Record, no_charge: bool) -> String {
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
    out.push_str(&format!(
        "\nThe contract is with kyriakon.net, run by Oliver Brotchie, a sole trader in\n\
         the United Kingdom, at {}. Contact: admin@kyriakon.net.\n\n",
        cfg.postal_address
    ));
    if no_charge {
        let what = if record.domain.is_some() {
            "the whole group"
        } else {
            "this account"
        };
        out.push_str(&format!(
            "There is no charge for {what} and no billing period.\n"
        ));
    } else {
        let price = if record.domain.is_some() {
            &cfg.group_price_gbp
        } else {
            &cfg.price_gbp
        };
        let what = if record.domain.is_some() {
            "the whole group"
        } else {
            "the account"
        };
        out.push_str(&format!(
            "The price is GBP {price} for one year, for {what}. The year starts on the day\n\
             we record your payment.\n"
        ));
    }
    out.push_str(
        "\nYou have fourteen days to cancel, starting the day the contract is made. The\n\
         right is unconditional: you can cancel for any reason, or none. An email to\n\
         admin@kyriakon.net saying that you want to cancel is enough. We refund what\n\
         you paid in full, within fourteen days, in the rail you paid with, or as a\n\
         credit against the next year if you would rather.\n",
    );
    out.push_str(&format!(
        "\nYou can cancel by writing, or with this form:\n\n\
         To Oliver Brotchie, {}, admin@kyriakon.net:\n\n\
         I give notice that I cancel my contract for the supply of a kyriakon.net account.\n\n\
         Ordered on: [date]\n\n\
         Name:\n\n\
         Address:\n\n\
         Signature (only if you send this on paper):\n\n\
         Date:\n",
        cfg.postal_address
    ));
    out
}

/// The approval mail's body: the decision and the password link, and — when the
/// applicant gave no address outside the platform — the durable-medium
/// confirmation, because [`confirm`] sends nothing to that applicant and this
/// mail is the first thing the new mailbox receives. With an outside address the
/// confirmation already left as its own earlier email, so appending it here
/// would deliver it twice.
fn approval_body(
    cfg: &DrainConfig,
    record: &Record,
    no_charge: bool,
    decision: String,
    password_until: &str,
    password_link: &str,
) -> String {
    let out = format!(
        "{decision}\n\nSet your mail password from this one-time link, which works until {password_until}:\n\n{password_link}\n\nIt works once. The same link is on your status page.\n"
    );
    with_confirmation(cfg, record, no_charge, out)
}

/// Appends the durable-medium confirmation when the applicant gave no address
/// outside the platform. Both approval mails call this, so the rule for when the
/// confirmation travels with an approval mail lives in one place.
fn with_confirmation(
    cfg: &DrainConfig,
    record: &Record,
    no_charge: bool,
    mut out: String,
) -> String {
    if record.outside_address.is_none() {
        out.push('\n');
        out.push_str(&confirmation_body(cfg, record, no_charge));
    }
    out
}

/// The body's approval mail: the payment note and the DNS recipe, plus the
/// durable-medium confirmation when no address outside the platform was given.
/// `group_recipient` falls back to the site owner's mailbox on the body's own
/// domain, so that mailbox is where the confirmation has to reach.
fn group_approval_body(
    cfg: &DrainConfig,
    record: &Record,
    no_charge: bool,
    domain: &str,
    payment_note: &str,
    recipe: &str,
    password_links: &[(String, String)],
) -> String {
    let mut out = format!(
        "Your application for {domain} has been approved. The mailboxes in the group are \
         ready to receive mail as soon as the records below are live.{payment_note}\n{recipe}"
    );
    if !password_links.is_empty() {
        out.push_str(
            "\nSet each mailbox's mail password from its own one-time link. Each link works \
             until its date, and once:\n\n",
        );
        for (mailbox, link) in password_links {
            out.push_str(&format!("{mailbox}: {link}\n"));
        }
    }
    with_confirmation(cfg, record, no_charge, out)
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
    monero: Option<&Monero>,
) -> Result<String, Error> {
    if no_charge {
        return Ok(format!(
            "Your application for {username} has been approved, with no charge.\n\n\
             There is nothing to pay and no payment window. The account does not lapse.\n"
        ));
    }
    let token =
        token.ok_or_else(|| Error::Failed("a charged approval has no token".to_string()))?;
    let window = window
        .as_ref()
        .ok_or_else(|| Error::Failed("a charged approval has no window".to_string()))?;
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
    for line in rail_instructions(
        rail,
        &cfg.postal_address,
        card_link.as_deref(),
        monero,
        &cfg.price_gbp,
    ) {
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

/// `kyriakon-admin token resend`: the same payment instructions again and nothing
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
    intent: ResendIntent,
) -> Result<Settlement, Error> {
    let username = intent.username.as_str();
    let account = store
        .account(username)
        .await?
        .ok_or_else(|| Error::Failed(format!("no account for {username}")))?;
    let Some(payment) = account.payment_state() else {
        return Err(Error::Failed(format!(
            "{username} was approved without charge, so there is no payment token to resend"
        )));
    };
    if payment.token_ref.as_deref() != Some(intent.token.as_str()) {
        return Err(Error::Failed(format!(
            "the token the resend names is not the one {username}'s account holds"
        )));
    }
    let body = decision_body(
        cfg,
        username,
        &account.rail,
        false,
        payment.token_ref.as_deref(),
        &payment.window,
        payment.monero.as_ref(),
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
        .account_application_text(username)
        .await?
        .and_then(|copy| serde_json::from_str::<Value>(&copy).ok())
        .and_then(|copy| {
            let status_token = copy.get("status_token")?.as_str()?.to_string();
            Some(ApplicationRef::application(
                username.to_string(),
                status_token,
            ))
        })
        .ok_or_else(|| Error::Failed(format!("no application record for {username}")))?;
    Ok(Settlement::line("applied", application, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kyriakon_control_core::store::Record;
    use serde_json::json;

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

    fn test_config() -> DrainConfig {
        let dir = std::env::temp_dir().join(format!("control-review-{}", std::process::id()));
        crate::transitions::test_support::quota_config(&dir)
    }

    fn approval_mail(cfg: &DrainConfig, record: &Record, no_charge: bool) -> String {
        approval_body(
            cfg,
            record,
            no_charge,
            "Your application for secretary has been approved.".to_string(),
            "2026-10-08",
            "https://signup.kyriakon.net/password/token",
        )
    }

    /// No outside address means `confirm` sent nothing, so the approval mail to
    /// the new mailbox has to carry the full durable-medium confirmation.
    #[test]
    fn a_no_address_approval_mail_carries_the_durable_confirmation() {
        let cfg = test_config();
        let body = approval_mail(&cfg, &record(&[]), false);
        assert!(body.contains("Set your mail password"), "{body}");
        assert!(body.contains("fourteen days to cancel"), "{body}");
        assert!(body.contains(&cfg.postal_address), "{body}");
        assert!(body.contains("GBP 20.00"), "{body}");
        assert!(
            body.contains("I give notice that I cancel my contract"),
            "{body}"
        );
    }

    /// With an outside address the confirmation left as its own earlier email;
    /// the approval mail must not deliver it a second time.
    #[test]
    fn an_outside_address_approval_mail_omits_the_confirmation() {
        let cfg = test_config();
        let mut record = record(&[]);
        record.outside_address = Some("member@example.invalid".to_string());
        let body = approval_mail(&cfg, &record, false);
        assert!(body.contains("Set your mail password"), "{body}");
        assert!(!body.contains("fourteen days to cancel"), "{body}");
        assert!(!body.contains("I give notice that I cancel"), "{body}");
    }

    #[test]
    fn a_no_charge_confirmation_says_there_is_no_charge() {
        let cfg = test_config();
        let body = confirmation_body(&cfg, &record(&[]), true);
        assert!(body.contains("no charge"), "{body}");
        assert!(body.contains("this account"), "{body}");
        assert!(!body.contains("GBP"), "{body}");
        let mut group = record(&[]);
        group.domain = Some("body.example".to_string());
        let body = confirmation_body(&cfg, &group, true);
        assert!(body.contains("no charge for the whole group"), "{body}");
    }

    #[test]
    fn a_group_confirmation_quotes_the_group_price() {
        let cfg = test_config();
        let mut record = record(&[]);
        record.domain = Some("body.example".to_string());
        let body = confirmation_body(&cfg, &record, false);
        assert!(body.contains("GBP 40.00"), "{body}");
        assert!(body.contains("the whole group"), "{body}");
    }

    /// `group_recipient` falls back to the site owner's mailbox on the body's
    /// domain, so a body with no outside address gets the same confirmation
    /// there, in its approval mail.
    #[test]
    fn a_group_approval_mail_carries_the_confirmation_when_there_is_no_outside_address() {
        let cfg = test_config();
        let mut record = record(&[]);
        record.domain = Some("body.example".to_string());
        let body = group_approval_body(
            &cfg,
            &record,
            false,
            "body.example",
            "\n\nThe amount is GBP 40.00 for the year, for the whole group.\n",
            "recipe text",
            &[],
        );
        assert!(body.contains("fourteen days to cancel"), "{body}");
        assert!(body.contains(&cfg.postal_address), "{body}");
        assert!(body.contains("GBP 40.00"), "{body}");
        assert!(
            body.contains("I give notice that I cancel my contract"),
            "{body}"
        );
    }
}
