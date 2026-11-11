//! Time passing: payment windows and their sweeps, the lapse and grace
//! notices, the account page's verbs, key rotations, and the daily sweeps over
//! DNS, quota, renewals, exports and purges.
//!
//! A sweep reports one unreadable record and goes on to the next; an intent's
//! body returns a [`Settlement`](super::Settlement) and the seam journals it.

use super::boxrun::{outside_address, publish_mail_keys, run_script, write_public_key};
use super::groups::{
    account_on_box, close_group_tokens, group_record, hold_name, remove_group_record,
    take_group_down, write_account_record, write_group_record, write_group_state,
};
use super::payments::{resolve_payment, token_join, write_payment_copy};
use super::Error;
use super::{due, report_failure, write_journal, Settlement};
use kyriakon_control_core::account::dns;
use kyriakon_control_core::config::DrainConfig;
use kyriakon_control_core::flow::validate;
use kyriakon_control_core::intent::{
    CancelRenewalIntent, ChangePasswordIntent, CloseIntent, ExportIntent, MailKeyIntent,
    OutsideAddressIntent, PasswordIntent, ServingIntent, UploadKeyIntent, WindowExtendIntent,
};
use kyriakon_control_core::mail::notice;
use kyriakon_control_core::payments::ledger::Ledger;
use kyriakon_control_core::payments::rails::rail_instructions;
use kyriakon_control_core::store::journal::Journal;
use kyriakon_control_core::store::{
    self, Account, ApplicationRef, GroupPayment, GroupRecord, Payment, Record, Store, UploadKey,
    Window,
};
use kyriakon_control_core::util;
use serde_json::json;
use serde_json::Value;
use std::collections::HashSet;
use time::format_description::well_known::Rfc3339;
use time::Duration;
use time::OffsetDateTime;
use tokio::process::Command;

/// The address a body's approval notice goes to. A body has no account of the
/// applicant's own, so the fallback is the site owner's mailbox on the body's
/// domain rather than the person path's `username@kyriakon.net`, which the drain
/// never makes for a body.
pub(super) fn group_recipient(
    record: &Record,
    site_owner: &str,
    domain: &str,
) -> Result<String, Error> {
    Ok(outside_address(record)?.unwrap_or_else(|| format!("{site_owner}@{domain}")))
}

/// The site owner's mailbox on the body's own domain. Unlike the person path's
/// `username@kyriakon.net`, the drain makes this address for a body, so it is
/// where a group's notices reach the site owner when they gave no other.
fn group_mailbox(group: &GroupRecord) -> String {
    format!("{}@{}", group.site_owner, group.domain)
}

/// One record a sweep could not read: report it through the drain's own failure
/// path and go on to the next record. `due` backs the report off, so a record
/// left damaged does not write a journal line every minute, and
/// [`report_failure`] mails one copy per distinct message.
pub(super) async fn report_record(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    kind: &str,
    name: &str,
    error: &Error,
) {
    let id = format!("{kind}:{name}");
    if !due(journal, &id, OffsetDateTime::now_utc()) {
        return;
    }
    report_failure(cfg, store, journal, &id, "record", error).await;
}

/// One account a sweep is about, or `None` when it is gone. A record that cannot
/// be read is reported and skipped, so one damaged account cannot stop another
/// account's lapse, deletion, rotation or notice.
async fn sweep_account(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    username: &str,
) -> Option<Account> {
    match store.account(username).await {
        Ok(account) => account,
        Err(e) => {
            report_record(cfg, store, journal, "account", username, &Error::from(e)).await;
            None
        }
    }
}

/// One group a sweep is about, with the same rule as [`sweep_account`].
async fn sweep_group(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    domain: &str,
) -> Option<GroupRecord> {
    match group_record(store, domain).await {
        Ok(group) => group,
        Err(e) => {
            report_record(cfg, store, journal, "group", domain, &e).await;
            None
        }
    }
}

/// One filed application a sweep is about, with the same rule as
/// [`sweep_account`].
async fn sweep_application(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    token: &str,
) -> Option<Record> {
    match store.application(token).await {
        Ok(record) => record,
        Err(e) => {
            report_record(cfg, store, journal, "application", token, &Error::from(e)).await;
            None
        }
    }
}

/// Apply a password set through a one-time link.
///
/// The link's signature, its date, the plaintext's validation and the one-use
/// replay checks are the seam's: `verify` refuses a submission that
/// cannot prove itself before this runs. What is left is the half the handler
/// cannot do at all: the plaintext is hashed here and nowhere else, the hash is
/// checked to be one this build made, and the record must still hold the link.
/// Applying it clears the link, so a replay finds nothing to apply and is
/// refused like any other spent link.
///
/// The remaining limit: a compromised handler chooses the plaintext it submits,
/// so it can still set a password it knows. It can no longer install a chosen
/// hash without a matching plaintext, which is the difference between a password
/// the member can reset and a login the member can never enter.
pub async fn set_password(
    cfg: &DrainConfig,
    store: &Store,
    intent: PasswordIntent,
    file: &str,
    value: &Value,
) -> Result<Settlement, Error> {
    let token =
        intent.application.status_token.as_deref().ok_or_else(|| {
            Error::Failed("the password intent names no status token".to_string())
        })?;
    let username = intent.application.username.as_str();
    let mut plain = intent.password;
    let hash = match kyriakon_control_core::account::password::make(&plain) {
        Ok(hash) if kyriakon_control_core::account::password::is_hash(&hash) => hash,
        Ok(_) => {
            return Ok(password_refusal(store, file, value, "the password did not hash").await);
        }
        Err(e) => return Ok(password_refusal(store, file, value, e).await),
    };
    // Overwrite the plaintext in place now it has been hashed; zero bytes are
    // still valid UTF-8, which is what `as_mut_vec` requires. The intent file
    // still holds a copy until the remove below, which is why that remove is the
    // pass's last act and runs on the success path only.
    unsafe { plain.as_mut_vec().fill(0) };
    let name = format!("{token}.json");
    let Some(text) = store.filed_application_text(token).await? else {
        return Ok(password_refusal(store, file, value, "the application record is gone").await);
    };
    // Read as a Value and edit one key: the record carries fields this build
    // does not model, and writing it back through the typed struct would drop
    // them.
    let mut record: Value = serde_json::from_str(&text)
        .map_err(|e| Error::context("the application record does not parse", e))?;
    if record.get("username").and_then(Value::as_str) != Some(username) {
        return Ok(password_refusal(store, file, value, "the intent names another account").await);
    }
    if record.get("password_link").is_none_or(Value::is_null) {
        return Ok(password_refusal(store, file, value, "the link has already been used").await);
    }
    run_script(cfg, "set-mail-password.sh", &[username, &hash]).await?;
    // One use: the record keeps no link, so the page stops answering.
    record["password_link"] = Value::Null;
    let bytes = serde_json::to_vec_pretty(&record).map_err(|source| Error::Json {
        context: "encode the application record",
        source,
    })?;
    // `applications/` belongs to the handler, which renders the status page as
    // _onboard: a root-owned record reads as missing to it.
    let owner = store.dir_owner("applications");
    store
        .write_record_owned("applications", &name, &bytes, owner)
        .await?;
    // The settlement, with the link cleared: `settle` appends it and removes
    // the file, which is why the remove is still the pass's last act.
    Ok(Settlement::applied(intent.application, None))
}

/// The password body's refusal: the plaintext is revoked from the file first,
/// because the file stays, and the refusal is what settles the intent. A failed
/// redaction still leaves the refusal recorded; the pass reports the failure so
/// the plaintext is not forgotten.
async fn password_refusal(
    store: &Store,
    file: &str,
    value: &Value,
    reason: impl ToString,
) -> Settlement {
    let reason = reason.to_string();
    match redact_password(store, file, value).await {
        Ok(()) => Settlement::refused(reason),
        Err(failure) => Settlement::Refused {
            reason,
            failure: Some(failure),
        },
    }
}

/// Remove a password intent's plaintext before its refusal leaves the file in
/// place. A refused intent is kept so the journal's line and the file agree, and
/// a retry is the operator's decision, but the plaintext must not stay in
/// `intents/` and every backup. The rewrite is the same atomic write, handed to
/// the directory's owner so the unprivileged handler can still read it.
pub(crate) async fn redact_password(store: &Store, file: &str, value: &Value) -> Result<(), Error> {
    let mut redacted = value.clone();
    let Some(object) = redacted.as_object_mut() else {
        return Ok(());
    };
    if object.remove("password").is_none() {
        return Ok(());
    }
    let bytes = serde_json::to_vec_pretty(&redacted).map_err(|source| Error::Json {
        context: "encode the intent",
        source,
    })?;
    let owner = store.dir_owner("intents");
    store
        .write_record_owned("intents", file, &bytes, owner)
        .await
        .map_err(Error::from)
}

/// Give an open payment window its one extension, as `kyriakon-admin window extend`
/// asks. The new close is fourteen days past the old one, and the counter makes
/// a second extension a refusal: the window is a courtesy, not a free tier.
pub async fn window_extend(store: &Store, intent: WindowExtendIntent) -> Result<Settlement, Error> {
    // A refusal is journaled once and the intent is left in place, as the credit
    // path does; a new intent is the way to change the answer.
    if !store::is_payment_token(&intent.token) {
        return Ok(Settlement::refused(
            "the window extension's token is not a payment token",
        ));
    }
    if intent.days != 14 {
        return Ok(Settlement::refused(
            "a window extension is fourteen days and no other number",
        ));
    }
    if intent.reason.trim().is_empty() {
        return Ok(Settlement::refused("the window extension gives no reason"));
    }
    // A group's token names the group's one window, and it takes the same one
    // extension under the same rule.
    let join = match token_join(store, &intent.token).await {
        Ok(join) => join,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    if let Some(domain) = join.as_ref().and_then(|j| j.group.clone()) {
        return extend_group_window(store, intent, &domain).await;
    }
    let (username, mut account, mut payment) = match resolve_payment(store, &intent.token).await {
        Ok(found) => found,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    let (paid_until, window) = (&payment.paid_until, &mut payment.window);
    let Some(window) = window.as_mut() else {
        return Ok(Settlement::refused(
            "the account has no payment window to extend",
        ));
    };
    let new_close = match extend_open_window(paid_until.as_deref(), window, intent.days) {
        Ok(close) => close,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    // Read the join before the account is written: a token record that cannot
    // be read fails here, with the window still unchanged for the retry.
    let mut join = store.token(&intent.token).await?;
    account.payment = Some(payment.clone());
    let bytes = serde_json::to_vec_pretty(&account).map_err(|source| Error::Json {
        context: "encode the account",
        source,
    })?;
    write_account_record(store, &username, &bytes).await?;
    write_payment_copy(store, &username, &payment).await?;
    // The token index carries the date the operator's list and any later lookup
    // sees, so keep it beside the account.
    if let Some(join) = join.as_mut() {
        join.window_closes_at = new_close.clone();
        let bytes = serde_json::to_vec_pretty(&join).map_err(|source| Error::Json {
            context: "encode the token record",
            source,
        })?;
        store
            .write_record("tokens", &format!("{}.json", intent.token), &bytes)
            .await?;
    }
    let application = store
        .account_application_text(&username)
        .await?
        .and_then(|copy| serde_json::from_str::<Value>(&copy).ok())
        .and_then(|copy| {
            Some(ApplicationRef::application(
                username.clone(),
                copy.get("status_token")?.as_str()?.to_string(),
            ))
        })
        .unwrap_or_else(|| ApplicationRef::account(username.clone()));
    Ok(Settlement::line(
        "applied",
        application.clone(),
        Some(format!(
            "the window now closes on {}",
            &new_close[..10.min(new_close.len())]
        )),
    ))
}

/// `window extend` for a group's token: the same fourteen days, the same one
/// extension, applied to the one window the whole body pays inside.
async fn extend_group_window(
    store: &Store,
    intent: WindowExtendIntent,
    domain: &str,
) -> Result<Settlement, Error> {
    let Some(mut group) = group_record(store, domain).await? else {
        return Ok(Settlement::refused(
            "the token resolves to a group that is gone",
        ));
    };
    let GroupPayment {
        paid_until, window, ..
    } = &mut group.payment;
    let Some(window) = window.as_mut() else {
        return Ok(Settlement::refused(
            "the group has no payment window to extend",
        ));
    };
    let new_close = match extend_open_window(paid_until.as_deref(), window, intent.days) {
        Ok(close) => close,
        Err(problem) => return Ok(Settlement::refused(&problem)),
    };
    // Read the join before the group is written, as the person path does.
    let mut join = store.token(&intent.token).await?;
    write_group_record(store, &group).await?;
    if let Some(join) = join.as_mut() {
        join.window_closes_at = new_close.clone();
        let bytes = serde_json::to_vec_pretty(&join).map_err(|source| Error::Json {
            context: "encode the token record",
            source,
        })?;
        store
            .write_record("tokens", &format!("{}.json", intent.token), &bytes)
            .await?;
    }
    Ok(Settlement::line(
        "applied",
        ApplicationRef::group(group.site_owner.clone(), domain.to_string()),
        Some(format!(
            "the group's window now closes on {}",
            &new_close[..10.min(new_close.len())]
        )),
    ))
}

/// Move one open window fourteen days on, once. Shared by an account's window
/// and a group's, so the one-extension rule cannot differ between them.
fn extend_open_window(
    paid_until: Option<&str>,
    window: &mut Window,
    days: i64,
) -> Result<String, Error> {
    if paid_until.is_some() || window.state != "open" {
        return Err(Error::Failed(
            "the payment window is not open, so it has nothing to extend".to_string(),
        ));
    }
    if window.extensions >= 1 {
        return Err(Error::Failed(
            "the payment window has already been extended once; a second extension is refused"
                .to_string(),
        ));
    }
    let Ok(closes) = OffsetDateTime::parse(&window.closes_at, &Rfc3339) else {
        return Err(Error::Failed(
            "the window's close date cannot be read".to_string(),
        ));
    };
    let closes = closes + Duration::days(days);
    window.closes_at = closes
        .replace_nanosecond(0)
        .unwrap_or(closes)
        .format(&Rfc3339)
        .unwrap_or_else(|_| window.closes_at.clone());
    window.extensions += 1;
    Ok(window.closes_at.clone())
}

/// Close every payment window whose day has passed. A window with a credit
/// leaves the account active; one without a credit lapses it into the lifecycle
/// state where mail stays readable and published work stays up, stops sending,
/// uploading and pushing through `lapse-user.sh`, and starts the same forty-day
/// grace the failed-renewal path uses. The window's own state is the dedup key,
/// so a second pass lapses nothing twice.
///
/// A closing or suspended account is left alone: its state is a decision of its
/// own, and the payment sweep must not overwrite it.
pub async fn window_sweep(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
) -> Result<(), Error> {
    let now = OffsetDateTime::now_utc();
    for username in store.list("accounts").await? {
        let Some(mut account) = sweep_account(cfg, store, journal, &username).await else {
            continue;
        };
        let Some(mut payment) = account.payment_state() else {
            continue;
        };
        let Some(window) = payment.window.as_ref() else {
            continue;
        };
        if window.state == "closed" {
            // The account already lapsed; the notice is re-offered because the
            // notice record, not the window, is what stops a duplicate.
            if account.state == "lapsed" {
                if let Err(e) = lapse_notice(cfg, store, &username, &account, &payment).await {
                    e.report(&format!("the lapse notice for {username}"));
                }
            }
            continue;
        }
        if window.state != "open" || account.state != "active" {
            continue;
        }
        let Ok(closes) = OffsetDateTime::parse(&window.closes_at, &Rfc3339) else {
            continue;
        };
        if now < closes {
            continue;
        }
        // A credit recorded before this pass is the member who paid on the last
        // day of the window: the date is set, so the window is closed as paid
        // and the account stays active.
        if payment.paid_until.is_some() {
            if let Some(window) = payment.window.as_mut() {
                window.state = "paid".to_string();
            }
            account.payment = Some(payment.clone());
            let bytes = serde_json::to_vec_pretty(&account).map_err(|source| Error::Json {
                context: "encode the account",
                source,
            })?;
            write_account_record(store, &username, &bytes).await?;
            write_payment_copy(store, &username, &payment).await?;
            continue;
        }
        // Stop the three access paths before the record says lapsed. A script
        // failure leaves the window open, so the next pass tries again rather
        // than the account reading lapsed while it still sends and pushes.
        if let Err(e) = run_script(cfg, "lapse-user.sh", &[username.as_str()]).await {
            Error::from(e).report(&format!("stopping access for {username}"));
            continue;
        }
        let Some(window) = payment.window.as_mut() else {
            continue;
        };
        window.state = "closed".to_string();
        account.state = "lapsed".to_string();
        account.grace_until = Some(util::date_after_days(40));
        account.payment = Some(payment.clone());
        let bytes = serde_json::to_vec_pretty(&account).map_err(|source| Error::Json {
            context: "encode the account",
            source,
        })?;
        write_account_record(store, &username, &bytes).await?;
        write_payment_copy(store, &username, &payment).await?;
        if let Err(e) = lapse_notice(cfg, store, &username, &account, &payment).await {
            e.report(&format!("the lapse notice for {username}"));
        }
    }

    // The groups' own windows. A group lapses whole: every mailbox it holds
    // stops sending, uploading and pushing, one notice goes to the body, and the
    // date every mailbox is restored from is the group's.
    for domain in store.list("groups").await? {
        let Some(mut group) = sweep_group(cfg, store, journal, &domain).await else {
            continue;
        };
        if group.payment.no_charge {
            continue;
        }
        let Some(window) = group.payment.window.clone() else {
            continue;
        };
        if window.state == "closed" {
            // The group already lapsed; the notice is re-offered because the
            // notice record, not the window, is what stops a duplicate.
            if let Err(e) = group_lapse_notice(cfg, store, journal, &group, &window).await {
                e.report(&format!("the lapse notice for {domain}"));
            }
            continue;
        }
        if window.state != "open" {
            continue;
        }
        let Ok(closes) = OffsetDateTime::parse(&window.closes_at, &Rfc3339) else {
            continue;
        };
        if now < closes {
            continue;
        }
        // A credit recorded before this pass is the body that paid on the last
        // day: the date is set, so the window is closed as paid and nothing
        // lapses.
        if group.payment.paid_until.is_some() {
            if let Some(window) = group.payment.window.as_mut() {
                window.state = "paid".to_string();
            }
            write_group_record(store, &group).await?;
            continue;
        }
        // Stop every mailbox before the group's record says lapsed, so the
        // record never reads lapsed while a mailbox still sends. A script
        // failure leaves the window open, and the next pass tries again. The
        // grace runs forty days from this pass, not from the close date, so a
        // sweep that runs late gives the body its whole forty days.
        let grace = util::date_after_days(40);
        let mut stopped = true;
        for mailbox in &group.accounts {
            if let Err(e) = run_script(cfg, "lapse-user.sh", &[mailbox.as_str()]).await {
                Error::from(e).report(&format!("stopping access for {mailbox} in {domain}"));
                stopped = false;
                continue;
            }
            let mut account = match store.account(mailbox).await {
                Ok(Some(account)) => account,
                Ok(None) => continue,
                Err(e) => {
                    report_record(cfg, store, journal, "account", mailbox, &Error::from(e)).await;
                    stopped = false;
                    continue;
                }
            };
            // A closing or suspended mailbox keeps its own state: the group's
            // lapse is not the decision that put it there.
            if account.state != "active" {
                continue;
            }
            account.state = "lapsed".to_string();
            account.grace_until = Some(grace.clone());
            let bytes = serde_json::to_vec_pretty(&account).map_err(|source| Error::Json {
                context: "encode the account",
                source,
            })?;
            write_account_record(store, mailbox, &bytes).await?;
        }
        if !stopped {
            continue;
        }
        if let Some(window) = group.payment.window.as_mut() {
            window.state = "closed".to_string();
        }
        group.grace_until = Some(grace.clone());
        write_group_record(store, &group).await?;
        if let Err(e) = group_lapse_notice(cfg, store, journal, &group, &window).await {
            e.report(&format!("the lapse notice for {domain}"));
        }
    }
    Ok(())
}

/// The group's one lapse notice, in the words the account pages use and on the
/// address the body's application gave. It is recorded against the site owner,
/// once for the group rather than once per mailbox.
async fn group_lapse_notice(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    group: &GroupRecord,
    window: &Window,
) -> Result<(), Error> {
    let Some(to) = group_notice_recipient(cfg, store, journal, group).await else {
        return Ok(());
    };
    let closes_on = &window.closes_at[..10.min(window.closes_at.len())];
    let token = group.payment.token_ref.as_deref().unwrap_or("");
    let grace = group.grace_until.clone().unwrap_or_default();
    let subject = format!(
        "Your kyriakon.net payment window for {} has closed",
        group.domain
    );
    let body = format!(
        "The payment window for {} closed on {closes_on} and no payment was recorded.\n\n\
         {}\n\n\
         Your payment reference is {token}.\n\n\
         The grace runs until {grace}, forty days from the lapse, and a final notice comes\n\
         seven days before every account in the group is deleted.\n",
        group.domain,
        kyriakon_control_core::account::LAPSE_NOTE
    );
    notice::send_account_notice(
        cfg,
        store,
        &group.site_owner,
        "group.lapsed",
        &subject,
        &to,
        &body,
    )
    .await?;
    Ok(())
}

/// The group grace's midpoint, thirty days before the deletion, once for the
/// body. The lapse notice opened the grace and the final notice closes it, so
/// this one gives the body a month's warning before anything is erased.
async fn group_grace_notice(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    group: &GroupRecord,
    grace: time::Date,
) -> Result<(), Error> {
    let Some(to) = group_notice_recipient(cfg, store, journal, group).await else {
        return Ok(());
    };
    let grace = util::date_string(grace);
    let token = group.payment.token_ref.as_deref().unwrap_or("");
    let subject = format!(
        "The grace for your kyriakon.net group for {} ends on {grace}",
        group.domain
    );
    let body = format!(
        "The payment window for {} closed and no payment has been recorded.\n\n\
         {}\n\n\
         The grace ends on {grace}, thirty days from this notice. After that every\n\
         account in the group is deleted automatically. Paying restores the whole group.\n\n\
         Your payment reference is {token}.\n",
        group.domain,
        kyriakon_control_core::account::LAPSE_NOTE
    );
    notice::send_account_notice(
        cfg,
        store,
        &group.site_owner,
        "group.grace",
        &subject,
        &to,
        &body,
    )
    .await?;
    Ok(())
}

/// The last notice before a lapsed group's grace ends, once for the body.
async fn group_final_notice(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    group: &GroupRecord,
    grace: time::Date,
) -> Result<(), Error> {
    let Some(to) = group_notice_recipient(cfg, store, journal, group).await else {
        return Ok(());
    };
    let grace = util::date_string(grace);
    let token = group.payment.token_ref.as_deref().unwrap_or("");
    let subject = format!(
        "Your kyriakon.net group for {} will be deleted in seven days",
        group.domain
    );
    let body = format!(
        "The payment window for {} closed and no payment was recorded.\n\n\
         Mail keeps arriving and stays readable, and everything the group published stays up,\n\
         but sending, uploading and pushing are stopped. Every account in the group is due to\n\
         be deleted on {grace}, seven days from this notice.\n\n\
         Your payment reference is {token}. If you have posted the money, write to\n\
         admin@kyriakon.net before that date.\n",
        group.domain
    );
    notice::send_account_notice(
        cfg,
        store,
        &group.site_owner,
        "group.final",
        &subject,
        &to,
        &body,
    )
    .await?;
    Ok(())
}

/// The lapse notice and the forty-day grace's own two events, run once per drain
/// pass after the windows: a final notice at `grace_until - 7` days, and the one
/// deletion transition at `grace_until`. The notice is deduplicated by its
/// `notices.jsonl` line, and the deletion is due-gated on the transition's own
/// journal id so a failed erase backs off rather than being retried every minute.
pub async fn grace_sweep(cfg: &DrainConfig, store: &Store, journal: &Journal) -> Result<(), Error> {
    let now = OffsetDateTime::now_utc();
    let today = now.date();
    for username in store.list("accounts").await? {
        let Some(account) = sweep_account(cfg, store, journal, &username).await else {
            continue;
        };
        // A group mailbox's grace is the group's: one conversation and one
        // deletion for the whole body, handled below.
        if account.group.is_some() {
            continue;
        }
        // A suspension runs the same clock as a lapse: the same final week and
        // the same deletion, with the reason carried into its final notice.
        if account.state != "lapsed" && account.state != "suspended" {
            continue;
        }
        let Some(grace_text) = account.grace_until.as_deref() else {
            continue;
        };
        let Some(grace) = util::parse_date(grace_text) else {
            continue;
        };
        if today >= grace {
            let id = format!("delete-{}-{}", username, account.created_at);
            if !due(journal, &id, now) {
                continue;
            }
            if let Err(e) = delete_account(cfg, store, journal, &username).await {
                report_failure(cfg, store, journal, &id, "delete", &e).await;
            }
            continue;
        }
        // The grace's own reminder, while a month of it is left. It is skipped
        // once the final notice's week has begun, which is behind this branch.
        if account.state == "lapsed"
            && today >= grace - Duration::days(30)
            && today < grace - Duration::days(7)
        {
            if let Err(e) = grace_notice(cfg, store, &username, &account).await {
                e.report(&format!("the grace notice for {username}"));
            }
        }
        if today >= grace - Duration::days(7) {
            let sent = if account.state == "suspended" {
                suspension_final_notice(cfg, store, &username, &account).await
            } else {
                final_notice(cfg, store, &username, &account).await
            };
            if let Err(e) = sent {
                e.report(&format!("the final notice for {username}"));
            }
        }
    }

    // The groups whose grace has ended: one final notice, then one deletion of
    // every account in the group, keyed on the group's own journal id so a
    // failed erase backs off.
    for domain in store.list("groups").await? {
        let group = match group_record(store, &domain).await {
            Ok(Some(group)) => group,
            Ok(None) => continue,
            Err(e) => {
                e.report(&format!("reading {domain}'s grace"));
                continue;
            }
        };
        if group.payment.no_charge {
            continue;
        }
        if group
            .payment
            .window
            .as_ref()
            .is_none_or(|window| window.state != "closed")
        {
            continue;
        }
        // The grace is the date the lapse wrote. A record that predates the
        // field has no grace to run, and a sweep that ran late does not get to
        // shorten it by measuring from the old close date.
        let Some(grace) = group.grace_until.as_deref().and_then(util::parse_date) else {
            continue;
        };
        if today >= grace {
            // The id carries the group's creation stamp, so a domain that is
            // removed and re-added gets its own deletion rather than matching
            // the first lifecycle's journal line.
            let id = format!("delete-group-{domain}-{}", group.created_at);
            if !due(journal, &id, now) {
                continue;
            }
            if let Err(e) = delete_group(cfg, store, journal, &group, &id).await {
                report_failure(cfg, store, journal, &id, "delete", &e).await;
            }
            continue;
        }
        if today >= grace - Duration::days(30) && today < grace - Duration::days(7) {
            if let Err(e) = group_grace_notice(cfg, store, journal, &group, grace).await {
                e.report(&format!("the grace notice for {domain}"));
            }
        }
        if today >= grace - Duration::days(7) {
            if let Err(e) = group_final_notice(cfg, store, journal, &group, grace).await {
                e.report(&format!("the final notice for {domain}"));
            }
        }
    }
    Ok(())
}

/// The contact address the member gave, when it validates as a mail header. It
/// is validated again because it becomes a mail header, and a record that
/// reached it from outside the drain is not trusted.
fn valid_contact(address: Option<&str>) -> Option<String> {
    address
        .filter(|addr| validate::address(addr).is_none())
        .map(str::to_string)
}

/// The address a lifecycle notice goes to: the contact the member gave, or the
/// mailbox that reaches them on the platform. A group mailbox's platform
/// address is its mailbox on the group's own domain.
fn notice_address(account: &Account) -> String {
    valid_contact(account.outside_address.as_deref()).unwrap_or_else(|| account.platform_address())
}

/// The address a group's lifecycle notice goes to: the site owner's account
/// first, then the application copy the approval left in their directory,
/// because provisioning writes a group mailbox's account without an outside
/// address of its own. Both are read through the typed accessors of #554, and
/// both are held to the same validation rule as a person's notice.
async fn group_notice_address(store: &Store, group: &GroupRecord) -> Result<String, Error> {
    let path = format!("accounts/{}/account.json", group.site_owner);
    let account = store
        .account(&group.site_owner)
        .await?
        .ok_or_else(|| Error::Failed(format!("{path} is missing")))?;
    if let Some(to) = valid_contact(account.outside_address.as_deref()) {
        return Ok(to);
    }
    let copy = store
        .account_application_text(&group.site_owner)
        .await?
        .and_then(|text| serde_json::from_str::<Record>(&text).ok());
    let from_copy = copy.and_then(|copy| valid_contact(copy.outside_address.as_deref()));
    Ok(from_copy.unwrap_or_else(|| account.platform_address()))
}

/// The recipient a group's lifecycle notice takes, or `None` when the site
/// owner's record cannot be read. The failure is reported against the owner
/// through the journal, which dedups the message and mails it once, and the
/// notice is skipped rather than sent to the platform address in the member's
/// place.
async fn group_notice_recipient(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    group: &GroupRecord,
) -> Option<String> {
    match group_notice_address(store, group).await {
        Ok(to) => Some(to),
        Err(e) => {
            report_record(
                cfg,
                store,
                journal,
                "account",
                &group.site_owner,
                &Error::Failed(format!(
                    "{e}, so {}'s group notice has no addressee",
                    group.domain
                )),
            )
            .await;
            None
        }
    }
}

/// The grace notice: the midpoint of the forty days, when thirty of them are
/// left. The lapse notice opened the grace and the final notice closes it, so
/// this one repeats what still works and what has stopped and gives the member
/// a month's warning before anything is deleted.
async fn grace_notice(
    cfg: &DrainConfig,
    store: &Store,
    username: &str,
    account: &Account,
) -> Result<(), Error> {
    let grace = account.grace_until.as_deref().unwrap_or("");
    let token = account
        .payment_state()
        .and_then(|payment| payment.token_ref)
        .unwrap_or_default();
    let to = notice_address(account);
    let subject = format!("Your kyriakon.net account's grace ends on {grace} ({username})");
    let body = format!(
        "The payment window for {username} closed and no payment has been recorded.\n\n\
         {}\n\n\
         The grace ends on {grace}, thirty days from this notice. After that the account\n\
         is deleted automatically. Paying restores it.\n\n\
         Your payment reference is {token}.\n",
        kyriakon_control_core::account::LAPSE_NOTE
    );
    notice::send_account_notice(cfg, store, username, "prepaid.grace", &subject, &to, &body)
        .await?;
    Ok(())
}

/// The end of a lapsed group's grace: the domain comes down and every account in
/// it closes, through the same steps a `remove-group` intent runs. The group
/// record is removed last, so a retry after a crash still finds the accounts it
/// has to close.
async fn delete_group(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    group: &GroupRecord,
    id: &str,
) -> Result<(), Error> {
    if journal.has(id, "applied") {
        return remove_group_record(store, &group.domain).await;
    }
    let application = ApplicationRef::group(group.site_owner.clone(), group.domain.clone());
    if !journal.has(id, "applying") {
        write_journal(
            store,
            journal,
            &cfg.release,
            id,
            "delete",
            &application,
            "applying",
            Some("the group's grace ended, so every account in it is being erased"),
        )
        .await?;
    }
    take_group_down(cfg, store, &group.domain).await?;
    write_journal(
        store,
        journal,
        &cfg.release,
        id,
        "delete",
        &application,
        "applied",
        Some("the domain and every account in it were removed; the ledger line stays"),
    )
    .await?;
    remove_group_record(store, &group.domain).await
}

/// The last notice before a lapsed account's grace ends. Its wording is #333's
/// to settle; what matters here is that it is sent once, seven days before the
/// deletion the same sweep performs.
async fn final_notice(
    cfg: &DrainConfig,
    store: &Store,
    username: &str,
    account: &Account,
) -> Result<(), Error> {
    let grace = account.grace_until.as_deref().unwrap_or("");
    let token = account
        .payment_state()
        .and_then(|payment| payment.token_ref)
        .unwrap_or_default();
    let to = notice_address(account);
    let subject = "Your kyriakon.net account will be deleted in seven days".to_string();
    let body = format!(
        "The payment window for {username} closed and no payment was recorded.\n\n\
         Mail keeps arriving and stays readable, and everything you published stays up, but\n\
         sending, uploading and pushing are stopped. The account is due to be deleted on\n\
         {grace}, seven days from this notice.\n\n\
         Your payment reference is {token}. If you have posted the money, write to\n\
         admin@kyriakon.net before that date.\n"
    );
    notice::send_account_notice(cfg, store, username, "prepaid.final", &subject, &to, &body)
        .await?;
    Ok(())
}

/// The last notice before a suspended account's grace ends. It names the reason
/// again and the way to answer it, because the member's one chance to stop the
/// deletion is to write before the date, and it is separate from the lapse's
/// final notice so neither night's sweep sends the other's words.
async fn suspension_final_notice(
    cfg: &DrainConfig,
    store: &Store,
    username: &str,
    account: &Account,
) -> Result<(), Error> {
    let grace = account.grace_until.as_deref().unwrap_or("");
    let reason = account.suspension_reason.as_deref().unwrap_or("");
    let to = notice_address(account);
    let subject = format!(
        "Your suspended kyriakon.net account is deleted in seven days: {reason} ({username})"
    );
    let body = format!(
        "The account {username} was suspended: {reason}\n\n\
         Outbound mail has stopped, and uploading to your site and pushing to git with\n\
         it. Inbound mail keeps arriving and stays readable, and your account page stays\n\
         open and shows this reason. The account is due to be deleted on {grace}, seven\n\
         days from this notice.\n\n\
         To answer it before then, reply to this message or write to\n\
         admin@kyriakon.net. A suspension the operator resolves is lifted with\n\
         `kyriakon-admin resume {username}` and the deletion does not run.\n"
    );
    notice::send_account_notice(
        cfg,
        store,
        username,
        "account.suspended.final",
        &subject,
        &to,
        &body,
    )
    .await?;
    Ok(())
}

/// The lapse notice. The words that say what still works and what stopped are
/// `account::LAPSE_NOTE`, the same constant both account pages render, so the mail
/// and the page cannot drift.
async fn lapse_notice(
    cfg: &DrainConfig,
    store: &Store,
    username: &str,
    account: &Account,
    payment: &Payment,
) -> Result<(), Error> {
    let window = payment
        .window
        .as_ref()
        .ok_or_else(|| Error::Failed("a lapsed account has no window".to_string()))?;
    let closes_on = &window.closes_at[..10.min(window.closes_at.len())];
    let token = payment.token_ref.as_deref().unwrap_or("");
    let grace = account.grace_until.as_deref().unwrap_or("");
    let to = notice_address(account);
    let subject = "Your kyriakon.net payment window has closed".to_string();
    let body = format!(
        "The payment window for {username} closed on {closes_on} and no payment was recorded.\n\n\
         {}\n\n\
         Your payment reference is {token}.\n\n\
         The grace runs until {grace}, forty days from the lapse, and a final notice comes\n\
         seven days before the end.\n",
        kyriakon_control_core::account::LAPSE_NOTE
    );
    notice::send_account_notice(cfg, store, username, "prepaid.lapsed", &subject, &to, &body)
        .await?;
    Ok(())
}

/// `kyriakon-admin suspend`: the AUP ladder's third rung, run now. It does the
/// runbook's suspension step: the shared lapse script stops sending, uploading
/// and pushing, the reason is written where the account page reads it, and the
/// notice carries the reason and how to answer. Taking the vhosts down stays the
/// operator's step, because it edits generated include files rather than the
/// account.
///
/// The access change comes before the record says suspended, as the lapse's
/// does: a script failure leaves the account as it was rather than reading
/// suspended while it still sends. A second run records nothing new, because the
/// notice is deduplicated on its type and subject.
pub async fn suspend(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    username: &str,
    reason: &str,
) -> Result<(), Error> {
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::Failed(format!("the username {username:?}: {why}")));
    }
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(Error::Failed(
            "a suspension needs a reason, in the words the member will read".to_string(),
        ));
    }
    let Some(mut account) = store.account(username).await? else {
        return Err(Error::Failed(format!("no account for {username}")));
    };
    // The id is the account's own, so a retry after a crash finishes the same
    // suspension rather than starting a second one.
    let id = format!("suspend-{username}-{}", account.created_at);
    let application = ApplicationRef::account(username.to_string());
    if !journal.has(&id, "applying") {
        write_journal(
            store,
            journal,
            &cfg.release,
            &id,
            "suspend",
            &application,
            "applying",
            Some(reason),
        )
        .await?;
    }
    run_script(cfg, "lapse-user.sh", &[username]).await?;
    account.state = "suspended".to_string();
    account.suspension_reason = Some(reason.to_string());
    // The suspension enters the same forty-day grace as a lapse. A retry of the
    // same suspension keeps the date it first set.
    if account.grace_until.is_none() {
        account.grace_until = Some(util::date_after_days(40));
    }
    let bytes = serde_json::to_vec_pretty(&account).map_err(|source| Error::Json {
        context: "encode the account",
        source,
    })?;
    write_account_record(store, username, &bytes).await?;
    if !journal.has(&id, "applied") {
        write_journal(
            store,
            journal,
            &cfg.release,
            &id,
            "suspend",
            &application,
            "applied",
            Some(&format!(
                "the grace ends on {}",
                account.grace_until.as_deref().unwrap_or("")
            )),
        )
        .await?;
    }
    let to = notice_address(&account);
    // The reason is in the subject, so a corrected reason is a new notice and a
    // rerun of the same one stays deduplicated.
    let subject = format!("Your kyriakon.net account is suspended: {reason} ({username})");
    let body = format!(
        "The account {username} has been suspended: {reason}\n\n\
         Outbound mail has stopped, and uploading to your site and pushing to git with\n\
         it. Inbound mail keeps arriving and stays readable, and your account page stays\n\
         open and shows this reason.\n\n\
         To answer it, reply to this message or write to admin@kyriakon.net. A suspension\n\
         that is not resolved enters the same forty-day grace as an unpaid account, and\n\
         that grace ends in deletion.\n"
    );
    notice::send_account_notice(
        cfg,
        store,
        username,
        "account.suspended",
        &subject,
        &to,
        &body,
    )
    .await?;
    Ok(())
}

/// `kyriakon-admin resume`: the inverse of a suspension. The three access paths come
/// back through the shared lapse script, the state returns to active, and the
/// reason and the grace it started are cleared, so a member who answered the
/// suspension is not deleted on a clock that no longer applies.
pub async fn resume(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    username: &str,
) -> Result<(), Error> {
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::Failed(format!("the username {username:?}: {why}")));
    }
    let Some(mut account) = store.account(username).await? else {
        return Err(Error::Failed(format!("no account for {username}")));
    };
    if account.state != "suspended" {
        return Err(Error::Failed(format!(
            "{username} is not suspended, so there is nothing to resume"
        )));
    }
    let id = format!("resume-{username}-{}", account.created_at);
    let application = ApplicationRef::account(username.to_string());
    write_journal(
        store,
        journal,
        &cfg.release,
        &id,
        "resume",
        &application,
        "applying",
        account.suspension_reason.as_deref(),
    )
    .await?;
    run_script(cfg, "lapse-user.sh", &["--restore", username]).await?;
    account.state = "active".to_string();
    account.suspension_reason = None;
    account.grace_until = None;
    let bytes = serde_json::to_vec_pretty(&account).map_err(|source| Error::Json {
        context: "encode the account",
        source,
    })?;
    write_account_record(store, username, &bytes).await?;
    write_journal(
        store,
        journal,
        &cfg.release,
        &id,
        "resume",
        &application,
        "applied",
        None,
    )
    .await?;
    Ok(())
}

/// The lifecycle's one deletion transition. `kyriakon-admin delete` calls it
/// directly, and a closing account reaches it through the drain's sweep, so an
/// erasure from the page and one from the console cannot take different paths.
///
/// The order is the runbook's: scripts/delete-user.sh removes the vhost files
/// and their indexes first, reloads the daemons, then the published tree, the
/// member's certificate, the OS account and home (Maildir and repositories),
/// the quota record and the store directory, and regenerates the finger page.
/// The keyring entry and the token index entry are the drain's and go after it:
/// the account record is what names the token, so removing the record first is
/// what makes the surviving ledger line unlinkable. The ledger line itself is
/// never touched.
///
/// Idempotent on a replay: the journal id carries the account's `created_at`, so
/// a name reused after the ninety-day hold gets its own deletion, and every step
/// treats an already-absent path as done. A retry after a partial pass can still
/// find the token by its `TokenRecord.username` even when `account.json` has
/// gone.
pub async fn delete_account(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    username: &str,
) -> Result<(), Error> {
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::Failed(format!("the username {username}: {why}")));
    }
    // The account record is read before the journal line so the answer can name
    // a refund from the token's ledger lines. A record that has already gone is
    // a retry: there is nothing left to answer, and the remaining cleanup below
    // still runs.
    let account = store.account(username).await?;
    // The id carries the account's creation stamp, so a name reused after the
    // ninety-day hold gets its own deletion rather than matching the first
    // lifecycle's journal line. Without it a second account with the same name
    // would read as already deleted.
    let Some(account) = account else {
        // The record has gone: a retry after a partial pass, or a name that is
        // not here. Only the publication cleanup can be left, and every step is
        // safe over an already-absent path.
        store.remove("keys", &format!("{username}.pub")).await?;
        remove_keyring_entry(cfg, username).await?;
        close_group_tokens(store, &[username.to_string()]).await?;
        return Ok(());
    };
    let id = format!("delete-{}-{}", username, account.created_at);
    if journal.has(&id, "applied") {
        return Ok(());
    }
    let application = ApplicationRef::account(username.to_string());
    if !journal.has(&id, "applying") {
        write_journal(
            store,
            journal,
            &cfg.release,
            &id,
            "delete",
            &application,
            "applying",
            Some("the account is being erased"),
        )
        .await?;
    }

    // The full answer goes into the journal, which outlives the account. The
    // store directory, including its `notices.jsonl`, is deleted below, so a
    // notice recorded there is not the durable copy. The notice itself is sent
    // only to the outside address when there is one: the member's own mailbox is
    // about to be removed, and a message enqueued to it would not be a reliable
    // answer.
    let refund = erasure_refund(store, &account).await?;
    let body = kyriakon_control_core::account::requests::erasure_answer(refund.as_deref());
    if !journal.has(&id, "erasure-answer") {
        write_journal(
            store,
            journal,
            &cfg.release,
            &id,
            "delete",
            &application,
            "erasure-answer",
            Some(&body),
        )
        .await?;
    }
    if let Some(to) = account.outside_address.as_deref() {
        notice::send_account_notice(
            cfg,
            store,
            username,
            "account.erasure",
            "Your kyriakon.net account is being erased",
            to,
            &body,
        )
        .await?;
    }

    hold_name(store, username).await?;
    store.remove("keys", &format!("{username}.pub")).await?;
    run_script(cfg, "delete-user.sh", &[username]).await?;
    // The box keyring entry goes now, not before the account: the encryptor
    // failing closed for a mailbox that still exists would bounce its mail.
    remove_keyring_entry(cfg, username).await?;
    close_group_tokens(store, &[username.to_string()]).await?;

    write_journal(
        store,
        journal,
        &cfg.release,
        &id,
        "delete",
        &application,
        "applied",
        Some("the account, its home and its store record were removed; the ledger line stays"),
    )
    .await
}

/// The refund fact the erasure answer carries: the token's recorded refund, or
/// nothing when the ledger has none. Read from the ledger rather than the
/// account because the refund is a ledger line and the account record is about
/// to go.
async fn erasure_refund(store: &Store, account: &Account) -> Result<Option<String>, Error> {
    let Some(token) = account.payment_state().and_then(|p| p.token_ref) else {
        return Ok(None);
    };
    let Some(refund) = Ledger::open(store).refunds(&token).await?.pop() else {
        return Ok(None);
    };
    let amount = refund
        .amount_gbp
        .as_deref()
        .map(|a| a.trim_start_matches('-'))
        .unwrap_or("0.00");
    let on = refund.received_on.as_deref().unwrap_or("an earlier date");
    Ok(Some(format!(
        "A refund of GBP {amount} was recorded on {on}; it is settled separately and is not affected by this closure."
    )))
}

/// Drop one account's published key from the box keyring. A missing directory or
/// file is already done, which is what makes a retry safe.
async fn remove_keyring_entry(cfg: &DrainConfig, username: &str) -> Result<(), Error> {
    let path = kyriakon_control_core::mail::keycheck::keyring_file(&cfg.keyring_dir, username);
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Failed(format!(
            "cannot remove {}: {e}",
            path.display()
        ))),
    }
}

/// Apply one `close` intent: put the account into `closing` with its seven-day
/// window. The deletion itself is the sweep's, so the account works normally
/// until the window ends and a replayed intent changes nothing. The session that
/// proves the request is `verify`'s.
pub async fn close_account(store: &Store, intent: CloseIntent) -> Result<Settlement, Error> {
    if intent.kind != "close" {
        return Err(Error::Failed(format!(
            "kind {:?} is not a close intent",
            intent.kind
        )));
    }
    let application = ApplicationRef::account(intent.username.clone());
    let Some(mut account) = store.account(&intent.username).await? else {
        // The account the handler authenticated has already gone. That is a
        // closed request, not new work.
        return Ok(account_gone(&intent.username));
    };
    // Every data-subject request gets one line, whether it arrived from the page
    // or the console. The id is the intent's, so a retry after the state write
    // sees the line already there rather than appending a second one.
    let today = util::date_after_days(0);
    let request = kyriakon_control_core::account::requests::NewRequest {
        username: &intent.username,
        kind: "erasure",
        received: &today,
        evidence: "the account page, with the mail password re-entered",
        identity: "password",
        note: Some("closure filed from the account page"),
        identity_at: None,
        fee_at: None,
        id: Some(&intent.id),
    };
    if let Err(e) = kyriakon_control_core::account::requests::record(store, request).await {
        if !matches!(&e, kyriakon_control_core::Error::Failed(message) if message.contains("already recorded"))
        {
            return Err(Error::from(e));
        }
    }
    if account.state == "closing" {
        return Ok(Settlement::line(
            "applied",
            application,
            Some("the account was already closing".to_string()),
        ));
    }
    account.state = "closing".to_string();
    account.closing_until = Some(util::date_after_days(7));
    let bytes = serde_json::to_vec_pretty(&account).map_err(|source| Error::Json {
        context: "encode the account",
        source,
    })?;
    write_account_record(store, &intent.username, &bytes).await?;
    Ok(Settlement::line(
        "applied",
        application.clone(),
        Some("the account is closing; the deletion runs when the seven days end".to_string()),
    ))
}

/// The settlement a page action files when the account it names has already
/// gone. The file goes with it, because there is nothing left to act on.
fn account_gone(username: &str) -> Settlement {
    Settlement::applied(
        ApplicationRef::account(username.to_string()),
        Some("the account had already gone".to_string()),
    )
}

/// Write an account record back, readable by the handler and owned the way the
/// directory's other records are.
async fn save_account(store: &Store, account: &Account) -> Result<(), Error> {
    let bytes = serde_json::to_vec_pretty(account).map_err(|source| Error::Json {
        context: "encode the account",
        source,
    })?;
    write_account_record(store, &account.username, &bytes).await
}

/// A password change from the account page. The handler had the current
/// password re-entered and checked it through `doveadm auth test`; it files the
/// new one as plaintext, and the drain hashes it here. An intent carrying a
/// `hash` is the old shape and is refused. `set-mail-password.sh` writes the
/// hash as root, which replaces the old hash and makes the old password stop
/// working.
pub async fn change_password(
    cfg: &DrainConfig,
    store: &Store,
    intent: ChangePasswordIntent,
) -> Result<Settlement, Error> {
    let Some(account) = store.account(&intent.username).await? else {
        return Ok(account_gone(&intent.username));
    };
    // The plaintext is checked and hashed here. It is overwritten before any
    // refusal removes the file, so a refusal leaves neither a file nor a buffer
    // holding it.
    let mut plain = intent.password;
    if let Err(why) = kyriakon_control_core::account::password::validate(&plain) {
        unsafe { plain.as_mut_vec().fill(0) };
        return Ok(Settlement::refused(&why));
    }
    let made = kyriakon_control_core::account::password::make(&plain);
    unsafe { plain.as_mut_vec().fill(0) };
    let hash = match made {
        Ok(hash) if kyriakon_control_core::account::password::is_hash(&hash) => hash,
        Ok(_) => {
            return Ok(Settlement::refused("the password did not hash"));
        }
        Err(e) => {
            return Ok(Settlement::refused(&e));
        }
    };
    run_script(cfg, "set-mail-password.sh", &[&account.username, &hash]).await?;
    Ok(Settlement::line(
        "applied",
        ApplicationRef::account(account.username.clone()),
        Some(
            "the stored hash is replaced, so the old password no longer authenticates".to_string(),
        ),
    ))
}

/// Add or remove the one upload key that serves sftp and git. Adding writes the
/// key where `provision-member.sh` reads it and rebuilds the member's upload
/// session; removing takes the store's copy and the authorized_keys line away
/// and leaves the published site and the mail alone.
pub async fn upload_key(
    cfg: &DrainConfig,
    store: &Store,
    intent: UploadKeyIntent,
) -> Result<Settlement, Error> {
    let Some(mut account) = store.account(&intent.username).await? else {
        return Ok(account_gone(&intent.username));
    };
    let now = util::filed_at();
    match intent.action.as_str() {
        "add" => {
            if let Err(why) =
                kyriakon_control_core::mail::keycheck::openssh_public_key(&intent.material)
            {
                return Ok(Settlement::refused(format!("the upload key: {why}")));
            }
            let Some(fingerprint) =
                kyriakon_control_core::mail::keycheck::openssh_fingerprint(&intent.material)
            else {
                return Ok(Settlement::refused(
                    "the upload key carries no key material",
                ));
            };
            write_public_key(store, &account.username, &intent.material).await?;
            run_script(cfg, "provision-member.sh", &[&account.username]).await?;
            // The record now holds a key, so the one derivation says which lanes
            // are on. provision-member.sh writes both daemon lanes; a lane the
            // member turned off is not turned back on by adding a key, so it is
            // removed again before the index pass, and the record keeps saying
            // so.
            account.upload_keys = vec![UploadKey {
                fingerprint,
                added_at: now,
            }];
            let (site, capsule) = account.serving();
            if !site {
                run_script(
                    cfg,
                    "provision-member-web.sh",
                    &["--remove", &account.username],
                )
                .await?;
            }
            if !capsule {
                run_script(
                    cfg,
                    "provision-member-capsule.sh",
                    &["--remove", &account.username],
                )
                .await?;
            }
            account.site_served = Some(site);
            account.capsule_served = Some(capsule);
            // The first key builds the tree and the two daemon files, so the
            // index and the reload are due exactly as they are at approval.
            run_script(cfg, "cron-apply.sh", &["--web"]).await?;
        }
        "remove" => {
            if !account
                .upload_keys
                .iter()
                .any(|key| key.fingerprint == intent.fingerprint)
            {
                return Ok(Settlement::refused("that key is not on the account"));
            }
            store
                .remove("keys", &format!("{}.pub", account.username))
                .await?;
            run_script(cfg, "remove-upload-key.sh", &[&account.username]).await?;
            account.upload_keys.clear();
        }
        other => {
            return Ok(Settlement::refused(format!(
                "{other:?} is not an upload-key action"
            )))
        }
    }
    save_account(store, &account).await?;
    Ok(Settlement::line(
        "applied",
        ApplicationRef::account(account.username.clone()),
        Some(format!("the upload key was {}", intent.action)),
    ))
}

/// Change or clear the contact and recovery address. The address is
/// revalidated here because it becomes a mail header, and the drain's notices
/// read it before they read anything else.
pub async fn set_outside_address(
    store: &Store,
    intent: OutsideAddressIntent,
) -> Result<Settlement, Error> {
    let Some(mut account) = store.account(&intent.username).await? else {
        return Ok(account_gone(&intent.username));
    };
    let address = intent.address.trim();
    let outside = if address.is_empty() {
        None
    } else {
        if let Some(why) = validate::address(address) {
            return Ok(Settlement::refused(format!(
                "the address outside the platform {address:?}: {why}"
            )));
        }
        Some(address.to_string())
    };
    let note = if outside.is_some() {
        "the contact and recovery address is set"
    } else {
        "the contact and recovery address is cleared"
    };
    account.outside_address = outside;
    save_account(store, &account).await?;
    Ok(Settlement::line(
        "applied",
        ApplicationRef::account(account.username.clone()),
        Some(note.to_string()),
    ))
}

/// Turn HTTP or gemini serving on or off. The two are independent: the drain
/// touches only the lane whose boolean changed, and one reload covers both
/// because it is a config write and not a service call.
pub async fn set_serving(
    cfg: &DrainConfig,
    store: &Store,
    intent: ServingIntent,
) -> Result<Settlement, Error> {
    let Some(mut account) = store.account(&intent.username).await? else {
        return Ok(account_gone(&intent.username));
    };
    // An unrecorded lane on a hosting member is serving: provision-member.sh
    // wrote it and nobody has turned it off. Comparing the effective value keeps
    // a save from removing a lane the page showed as on.
    let (site, capsule) = account.serving();
    let http_changed = site != intent.http;
    let gemini_changed = capsule != intent.gemini;
    if http_changed {
        if intent.http {
            run_script(cfg, "provision-member-web.sh", &[&account.username]).await?;
        } else {
            run_script(
                cfg,
                "provision-member-web.sh",
                &["--remove", &account.username],
            )
            .await?;
        }
    }
    if gemini_changed {
        if intent.gemini {
            run_script(cfg, "provision-member-capsule.sh", &[&account.username]).await?;
        } else {
            run_script(
                cfg,
                "provision-member-capsule.sh",
                &["--remove", &account.username],
            )
            .await?;
        }
    }
    if http_changed || gemini_changed {
        // Regenerates the two indexes from the files present, checks each
        // daemon and reloads it: one pass for a batch rather than one a lane.
        run_script(cfg, "cron-apply.sh", &["--web"]).await?;
    }
    account.site_served = Some(intent.http);
    account.capsule_served = Some(intent.gemini);
    save_account(store, &account).await?;
    Ok(Settlement::line(
        "applied",
        ApplicationRef::account(account.username.clone()),
        Some(format!(
            "serving is http {} and gemini {}",
            intent.http, intent.gemini
        )),
    ))
}

/// Stop the card subscription's yearly renewal. Stripe's
/// `cancel_at_period_end` runs to the period's end, and the paid-until date on
/// the account is what decides access, so nothing is shortened here.
pub async fn cancel_renewal(
    cfg: &DrainConfig,
    store: &Store,
    intent: CancelRenewalIntent,
) -> Result<Settlement, Error> {
    let Some(mut account) = store.account(&intent.username).await? else {
        return Ok(account_gone(&intent.username));
    };
    let Some(payment) = account.payment.as_mut() else {
        return Ok(Settlement::refused(
            "the account has no card subscription to cancel",
        ));
    };
    let Some(subscription) = payment.stripe.subscription.clone() else {
        return Ok(Settlement::refused(
            "the account has no card subscription to cancel",
        ));
    };
    if !payment.stripe.cancel_at_period_end {
        run_script(
            cfg,
            "stripe-api.sh",
            &["cancel", &subscription, &cfg.stripe_api_key],
        )
        .await?;
        payment.stripe.cancel_at_period_end = true;
        save_account(store, &account).await?;
    }
    Ok(Settlement::line(
        "applied",
        ApplicationRef::account(account.username.clone()),
        Some("the subscription stops renewing at the end of the period".to_string()),
    ))
}

/// The addresses a notice about this account goes to: its own platform
/// address, and the contact address when the member gave one. The platform
/// address is derived from the mailbox and its group's domain, so a body's
/// mailbox is not told to write to `@kyriakon.net`.
fn account_addresses(account: &Account) -> Vec<String> {
    let own = account.platform_address();
    let mut out = vec![own];
    if let Some(outside) = account.outside_address.as_deref() {
        if out.iter().all(|own| own != outside) {
            out.push(outside.to_string());
        }
    }
    out
}

/// One notice to every address the account holds. The record is deduplicated on
/// its type and subject, so the second address takes a type of its own: the
/// confirmation has to reach both channels, and a second copy of the same
/// subject is a different send rather than a retry. The request's own nonce is
/// part of the type too: a retry of one request stays deduplicated, while a
/// cancel followed by a new request for the same key warns again.
async fn rotation_notices(
    cfg: &DrainConfig,
    store: &Store,
    account: &Account,
    notice_type: &str,
    request: &str,
    subject: &str,
    body: &str,
) -> Result<(), Error> {
    for (i, to) in account_addresses(account).iter().enumerate() {
        let kind = if i == 0 {
            format!("{notice_type}.{request}")
        } else {
            format!("{notice_type}.{request}.outside")
        };
        notice::send_account_notice(cfg, store, &account.username, &kind, subject, to, body)
            .await?;
    }
    Ok(())
}

/// Whether `signature` is a detached signature by the key the box delivers
/// with, over `fingerprint`. A scratch homedir holds just that one key, so a
/// good signature is by the current key and by nothing else; `Ok(false)` is a
/// signature that does not verify, and `Err` is gpg failing to run at all.
async fn signed_by_current_key(
    cfg: &DrainConfig,
    key_file: &std::path::Path,
    fingerprint: &str,
    signature: &str,
) -> Result<bool, Error> {
    Ok(kyriakon_control_core::mail::keycheck::verify_signature(
        &cfg.gpg,
        key_file,
        fingerprint.as_bytes(),
        Some(signature.as_bytes()),
    )
    .await?
    .is_some())
}

/// Apply a pending rotation: the new key into the keyring delivery reads, the
/// fingerprint onto the account, the window cleared and the news sent to every
/// address. The published set is not touched here: scripts/publish-mail-key.sh
/// refuses to replace a key already on the default branch, because that is this
/// rotation, so the operator publishes it (the runbook's "Replace a member's
/// key"). scripts/deploy-mail.sh keeps the rotated keyring file until they do.
async fn apply_rotation(
    cfg: &DrainConfig,
    store: &Store,
    account: &mut Account,
    rotation: &store::Rotation,
) -> Result<(), Error> {
    let key = kyriakon_control_core::mail::keycheck::mail_key(String::new(), &rotation.material);
    if key.fingerprint != rotation.fingerprint {
        return Err(Error::Failed(format!(
            "the pending key's fingerprint is {} and the key reads as {}",
            rotation.fingerprint, key.fingerprint
        )));
    }
    publish_mail_keys(cfg, &account.username, std::slice::from_ref(&key)).await?;
    account.mail_key = Some(rotation.fingerprint.clone());
    account.rotation = None;
    save_account(store, account).await?;
    let body = format!(
        "The new mail key for {} is in use. Mail arriving from now is encrypted to it, \
         and mail delivered before it arrived stays readable with the key you held then. \
         If you did not ask for this, write to admin@kyriakon.net at once.",
        account.username
    );
    rotation_notices(
        cfg,
        store,
        account,
        "rotation.applied",
        &rotation.requested_at,
        &format!("Your new mail key is in use ({})", rotation.fingerprint),
        &body,
    )
    .await?;
    Ok(())
}

/// Start a mail-key replacement, or cancel one already waiting. A replacement
/// not signed by the current key waits out the window; the sweep below applies
/// it when the window closes, and the page's cancel clears it before then.
pub async fn mail_key(
    cfg: &DrainConfig,
    store: &Store,
    intent: MailKeyIntent,
) -> Result<Settlement, Error> {
    let Some(mut account) = store.account(&intent.username).await? else {
        return Ok(account_gone(&intent.username));
    };
    let application = ApplicationRef::account(account.username.clone());
    match intent.action.as_str() {
        "cancel" => {
            let Some(cancelled) = account.rotation.as_ref().map(|r| r.fingerprint.clone()) else {
                return Ok(Settlement::line(
                    "applied",
                    application.clone(),
                    Some("no replacement was pending".to_string()),
                ));
            };
            account.rotation = None;
            save_account(store, &account).await?;
            let body = "The replacement of your mail key was cancelled. The key in use is \
                        unchanged, and mail keeps arriving to it."
                .to_string();
            rotation_notices(
                cfg,
                store,
                &account,
                "rotation.cancelled",
                &intent.id,
                &format!("Your mail key replacement was cancelled ({cancelled})"),
                &body,
            )
            .await?;
            Ok(Settlement::line(
                "applied",
                application.clone(),
                Some("the pending replacement was cancelled".to_string()),
            ))
        }
        "replace" => {
            if let Err(why) =
                kyriakon_control_core::mail::keycheck::pgp_public_key(&intent.material)
            {
                return Ok(Settlement::refused(format!("the mail key: {why}")));
            }
            let Some(fingerprint) =
                kyriakon_control_core::mail::keycheck::pgp_fingerprint(&intent.material)
            else {
                return Ok(Settlement::refused("the mail key carries no key packet"));
            };
            if account.mail_key.as_deref() == Some(fingerprint.as_str()) {
                return Ok(Settlement::refused("that is the key already in use"));
            }
            let key_file = kyriakon_control_core::mail::keycheck::keyring_file(
                &cfg.keyring_dir,
                &account.username,
            );
            let signed = if intent.signature.trim().is_empty() {
                false
            } else {
                if !key_file.is_file() {
                    return Ok(Settlement::refused(
                        "the box holds no current key to verify a signature against",
                    ));
                }
                match signed_by_current_key(cfg, &key_file, &fingerprint, &intent.signature).await {
                    Ok(true) => true,
                    Ok(false) => {
                        return Ok(Settlement::refused(
                            "the signature does not verify against the key in use",
                        ))
                    }
                    Err(e) => return Err(e),
                }
            };
            let rotation = store::Rotation {
                fingerprint,
                material: intent.material.trim().to_string(),
                requested_at: util::filed_at(),
                applies_at: (OffsetDateTime::now_utc() + Duration::hours(72))
                    .format(&Rfc3339)
                    .map_err(|e| Error::context("cannot write the window's end", e))?,
            };
            account.rotation = Some(rotation.clone());
            if signed {
                apply_rotation(cfg, store, &mut account, &rotation).await?;
            } else {
                save_account(store, &account).await?;
                let body = format!(
                    "You asked to replace the mail key for {}. If you did make this request, \
                     nothing else is needed: the new key applies at {} and mail arriving after \
                     that is encrypted to it. If you did not, open your account page and cancel \
                     the replacement before then.",
                    account.username, rotation.applies_at
                );
                rotation_notices(
                    cfg,
                    store,
                    &account,
                    "rotation.pending",
                    &intent.id,
                    &format!(
                        "Confirm the replacement of your mail key ({})",
                        rotation.fingerprint
                    ),
                    &body,
                )
                .await?;
            }
            Ok(Settlement::line(
                "applied",
                application.clone(),
                Some(
                    (if signed {
                        "the replacement was signed by the current key and applied at once"
                    } else {
                        "the replacement waits out the 72-hour window"
                    })
                    .to_string(),
                ),
            ))
        }
        other => Ok(Settlement::refused(format!(
            "{other:?} is not a mail-key action"
        ))),
    }
}

/// Apply every mail-key replacement whose 72 hours have run out. The record's
/// own `rotation` is the dedup: applying it clears the field, so a pass that
/// finds nothing pending writes nothing.
pub async fn mail_key_rotations(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
) -> Result<(), Error> {
    for username in store.list("accounts").await? {
        let Some(mut account) = sweep_account(cfg, store, journal, &username).await else {
            continue;
        };
        let Some(rotation) = account.rotation.clone() else {
            continue;
        };
        let applies = OffsetDateTime::parse(&rotation.applies_at, &Rfc3339).map_err(|e| {
            Error::context(
                format!("the rotation window of {username} does not parse"),
                e,
            )
        })?;
        if OffsetDateTime::now_utc() < applies {
            continue;
        }
        let id = format!("rotation-{}", rotation.fingerprint);
        let application = ApplicationRef::account(username.clone());
        if !journal.has(&id, "applying") {
            write_journal(
                store,
                journal,
                &cfg.release,
                &id,
                "rotation",
                &application,
                "applying",
                Some("the pending mail key's window has ended"),
            )
            .await?;
        }
        apply_rotation(cfg, store, &mut account, &rotation).await?;
        write_journal(
            store,
            journal,
            &cfg.release,
            &id,
            "rotation",
            &application,
            "applied",
            Some("the new mail key is in the keyring"),
        )
        .await?;
    }
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
pub async fn check_group_dns(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
) -> Result<(), Error> {
    let values = dns::Values::from(cfg);
    if let Err(e) = values.check() {
        // The approval already refuses a placeholder; a box that has one has no
        // published values to watch, and that is not a reason to hold the pass.
        Error::from(e).report("the DNS values");
        return Ok(());
    }
    let now = OffsetDateTime::now_utc();
    for name in store.list("groups").await? {
        if name.starts_with('.') {
            continue;
        }
        let Some(group) = sweep_group(cfg, store, journal, &name).await else {
            continue;
        };
        // One group's bad record, failed write or refused notice is reported
        // and skipped: the other groups are still watched and the pass goes on.
        if let Err(e) = check_one_group(cfg, store, &values, &group, now).await {
            e.report(&format!("watching {}", group.domain));
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
) -> Result<(), Error> {
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
) -> Result<(), Error> {
    let bytes = serde_json::to_vec_pretty(&json!({
        "version": 1,
        "checked_at": checked_at,
        "broken": broken,
        "outage": outage,
        "notified": notified,
    }))
    .map_err(|source| Error::Json {
        context: "encode the DNS check state",
        source,
    })?;
    store
        .write_record(&format!("groups/{domain}"), "dns-check.json", &bytes)
        .await
        .map_err(Error::from)
}

/// Whether any row the recipe names has stopped resolving, or a TXT answer no
/// longer carries the marker that says it is the record the recipe asks for.
/// The resolver is a configured command so the acceptance test never touches the
/// network; it is read-only by construction and the body's zone is not a file
/// this box can write.
async fn dns_broken(cfg: &DrainConfig, values: &dns::Values, domain: &str) -> Result<bool, Error> {
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
                .map_err(|e| {
                    Error::context(format!("cannot run the resolver {}", cfg.resolver), e)
                })?;
            if !out.status.success() {
                // No answer is not the body's zone being broken: dig exits
                // non-zero when it could not reach a server, and a name that
                // does not resolve answers successfully with nothing. Only the
                // second is an outage, so this is the platform's own failure.
                return Err(Error::Failed(format!(
                    "the resolver {} could not answer {name} {}: {}",
                    cfg.resolver,
                    row.record_type,
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
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
pub(super) async fn dns_contact(store: &Store, group: &GroupRecord) -> Result<String, Error> {
    let copy: Option<Value> = store
        .account_application_text(&group.site_owner)
        .await?
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
    Ok(group_mailbox(group))
}

/// How often the space-used sweep runs, in hours. It reads the filesystem
/// quota with `repquota`, which is a whole-filesystem report rather than one
/// account's read, so doing it every minute would be one process a minute for a
/// number that moves slowly. The same due-gated shape as the DNS sweep, on a
/// state file of its own.
const QUOTA_CHECK_HOURS: i64 = 1;

/// Record each account's used space from the filesystem quota. The account page
/// shows it against the 5 GB soft and 5.5 GB hard allowance, and the handler
/// cannot read the quota: repquota needs root. The output is column-aligned
/// text, so the parse is narrow and a report it cannot read changes nothing;
/// a filesystem with quotas off prints nothing and is the same no-op, which is
/// the state the research found on the box before quotas were enabled.
pub async fn refresh_space_used(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
) -> Result<(), Error> {
    // A pass with no accounts has nothing to record, so it writes neither the
    // report nor the state. That keeps a store that has never been provisioned
    // byte-identical across a pass, which the sweep tests rely on.
    if store.list("accounts").await?.is_empty() {
        return Ok(());
    }
    let now = OffsetDateTime::now_utc();
    let state: Option<Value> = store
        .read_record("", "quota-check.json")
        .await
        .and_then(|text| serde_json::from_str(&text).ok());
    let checked_at = state
        .as_ref()
        .and_then(|s| s.get("checked_at"))
        .and_then(Value::as_str)
        .and_then(|stamp| OffsetDateTime::parse(stamp, &Rfc3339).ok());
    if checked_at.is_some_and(|at| now - at < Duration::hours(QUOTA_CHECK_HOURS)) {
        return Ok(());
    }

    let report = match Command::new(&cfg.repquota)
        .arg("-u")
        .arg(&cfg.quota_mount)
        .output()
        .await
    {
        Ok(out) => out,
        Err(e) => {
            // No repquota on this box, or no permission: the same no-op the
            // other sweeps take, and the state still moves so the error is not
            // printed every minute.
            Error::Failed(format!("cannot read the quota with {}: {e}", cfg.repquota))
                .report("the quota report");
            write_quota_state(store).await?;
            return Ok(());
        }
    };
    if !report.status.success() {
        Error::Failed(format!("{} exited {}", cfg.repquota, report.status))
            .report("the quota report");
        write_quota_state(store).await?;
        return Ok(());
    }

    let usage = parse_repquota(&String::from_utf8_lossy(&report.stdout));
    let mut recorded: HashSet<String> = HashSet::new();
    for (username, used_kb) in &usage {
        let Some(mut account) = sweep_account(cfg, store, journal, username).await else {
            // A uid with no account record is somebody else's, and this sweep
            // writes nothing about it.
            continue;
        };
        let bytes = used_kb.saturating_mul(1024);
        if account.space_used == Some(bytes) {
            recorded.insert(username.clone());
            continue;
        }
        account.space_used = Some(bytes);
        let encoded = serde_json::to_vec_pretty(&account).map_err(|source| Error::Json {
            context: "encode the account",
            source,
        })?;
        match write_account_record(store, username, &encoded).await {
            Ok(()) => {
                recorded.insert(username.clone());
            }
            Err(e) => e.report(&format!("recording {username}'s quota")),
        }
    }

    // The group's figure is the sum of its mailboxes' used bytes, computed from
    // the accounts this pass just read. A group none of whose accounts appeared
    // in the report is left alone: an empty or unrelated report must not write a
    // zero over a real figure.
    for name in store.list("groups").await? {
        // One bad group record is reported and skipped: the other groups, and
        // the sweeps after this one, still run.
        let Some(mut group) = sweep_group(cfg, store, journal, &name).await else {
            continue;
        };
        if !group
            .accounts
            .iter()
            .any(|mailbox| recorded.contains(mailbox))
        {
            continue;
        }
        let mut total = 0u64;
        let mut seen = false;
        let mut readable = true;
        for mailbox in &group.accounts {
            match store.account(mailbox).await {
                Ok(Some(account)) => {
                    total = total.saturating_add(account.space_used.unwrap_or(0));
                    seen = true;
                }
                Ok(None) => {}
                Err(e) => {
                    report_record(cfg, store, journal, "account", mailbox, &Error::from(e)).await;
                    readable = false;
                    break;
                }
            }
        }
        // A mailbox that could not be read leaves the sum incomplete, so the
        // group keeps its last figure rather than recording a wrong one.
        if !readable || !seen || group.space_used == Some(total) {
            continue;
        }
        group.space_used = Some(total);
        let encoded = serde_json::to_vec_pretty(&group).map_err(|source| Error::Json {
            context: "encode the group record",
            source,
        })?;
        if let Err(e) = write_group_state(store, &name, &encoded).await {
            e.report(&format!("recording {name}'s quota"));
        }
    }
    write_quota_state(store).await
}

/// One OpenBSD `repquota -u` report as `(username, used KB)`.
///
/// The table is two header lines and then one row per uid:
///
///```text
///                        KByte limits               File limits
///User            used    soft    hard  grace    used  soft  hard  grace
///alice             --    1024 5242880 5767168        --    10     0     0
///```
///
/// The two characters after the name are the block and inode over-soft-limit
/// flags, written with no space between them. A name that fills the ten-column
/// field carries them with no separating space, so the pair is recognised at
/// the end of the first token before the name and the used figure are read. A
/// report of another shape (`quota -v`'s `Disk quotas for user` blocks, an empty
/// table, `***` verbose lines) yields nothing rather than a guess.
pub fn parse_repquota(report: &str) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for line in report.lines() {
        let text = line.trim();
        if text.is_empty()
            || text.starts_with("KByte")
            || text.starts_with("User ")
            || text.starts_with("***")
        {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(first) = fields.first() else {
            continue;
        };
        let (name, next) = if first.len() > 2 && over_limit_flags(&first[first.len() - 2..]) {
            (&first[..first.len() - 2], 1)
        } else if fields.len() > 2 && over_limit_flags(fields[1]) {
            (*first, 2)
        } else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if let Some(used) = fields.get(next).and_then(|field| field.parse::<u64>().ok()) {
            out.push((name.to_string(), used));
        }
    }
    out
}

/// The two over-limit markers `repquota` prints before the used figure.
fn over_limit_flags(field: &str) -> bool {
    field.len() == 2 && field.bytes().all(|b| b == b'+' || b == b'-')
}

/// The sweep's own due stamp, root-only at the store root. It carries the time
/// alone: the figures are on the accounts, where the page reads them.
async fn write_quota_state(store: &Store) -> Result<(), Error> {
    let state = json!({ "version": 1, "checked_at": util::filed_at() });
    let bytes = serde_json::to_vec_pretty(&state).map_err(|source| Error::Json {
        context: "encode the quota state",
        source,
    })?;
    store
        .write_record("", "quota-check.json", &bytes)
        .await
        .map_err(Error::from)
}

/// The yearly note to an account approved without charge: nothing is due, and
/// the paid path is there if circumstances have changed. It falls due on the
/// creation anniversary, at most once a year, and the subject carries the year
/// because a notice is deduplicated on its type and subject. A group mailbox is
/// skipped: the group holds the payment, and a body's free permanence is the
/// own-domain tier's own question.
pub async fn free_anniversaries(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
) -> Result<(), Error> {
    let today = OffsetDateTime::now_utc().date();
    for username in store.list("accounts").await? {
        let Some(account) = sweep_account(cfg, store, journal, &username).await else {
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
        let Some(due) = util::anniversary(created, today.year()) else {
            continue;
        };
        if today < due {
            continue;
        }
        // The address the approval used: the one outside the platform, or the
        // member's mailbox. It was validated before it was written, and is
        // validated again here because it is about to become a mail header.
        let to = notice_address(&account);
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
            Error::from(e).report(&format!("the free anniversary note for {username}"));
        }
    }
    Ok(())
}

/// The thirty-day note before a prepaid membership runs out. A card account is
/// skipped: Stripe's subscription sends its own upcoming-invoice reminder, and
/// the platform has no second copy to add. The notice falls due on the account's
/// own `paid_until - 30`, at most once per date because the subject carries it.
/// Only an active account is reminded; one already lapsed is the grace sweep's.
pub async fn prepaid_renewals(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
) -> Result<(), Error> {
    let today = OffsetDateTime::now_utc().date();
    for username in store.list("accounts").await? {
        let Some(account) = sweep_account(cfg, store, journal, &username).await else {
            continue;
        };
        if account.state != "active" || account.group.is_some() {
            continue;
        }
        let Some(payment) = account.payment_state() else {
            continue;
        };
        let Some(paid_until) = payment.paid_until.as_deref() else {
            continue;
        };
        let rail = payment.rail.as_deref().unwrap_or(&account.rail);
        if rail == "card" {
            continue;
        }
        // A paid-until date is written as a day by a credit and as a timestamp
        // by the card rail, so only its date part is read.
        let Some(until) = util::parse_date(paid_until.get(..10).unwrap_or(paid_until)) else {
            continue;
        };
        if today < until - Duration::days(30) || today >= until {
            continue;
        }
        // What is still owed: a held overpayment is spent before the member is
        // asked for the price again.
        let amount = match (util::pence(&cfg.price_gbp), payment.balance_gbp.as_deref()) {
            (Ok(price), Some(balance)) => util::pence(balance)
                .map(|balance| util::gbp((price - balance).max(0)))
                .unwrap_or_else(|_| cfg.price_gbp.clone()),
            _ => cfg.price_gbp.clone(),
        };
        // The rail's own words, so a cash-in-hand member is not told to post an
        // envelope and a Monero member sees the same instructions as the page.
        let how = rail_instructions(
            rail,
            &cfg.postal_address,
            None,
            payment.monero.as_ref(),
            &amount,
        )
        .join("\n");
        let token = payment.token_ref.as_deref().unwrap_or("");
        let to = notice_address(&account);
        let subject = format!("Your kyriakon.net membership runs out on {paid_until} ({username})");
        let body = format!(
            "The membership for {username} is paid until {paid_until}.\n\n\
             To renew it for another year, send GBP {amount}:\n\n{how}\n\n\
             Your payment reference is {token}.\n\n\
             Nothing is deleted when the date passes. Write to admin@kyriakon.net to\n\
             arrange the renewal or if you have already sent the money; the renewal is\n\
             handled by the operator, and no automatic deletion runs from this date.\n"
        );
        if let Err(e) = notice::send_account_notice(
            cfg,
            store,
            &username,
            "prepaid.renewal",
            &subject,
            &to,
            &body,
        )
        .await
        {
            Error::from(e).report(&format!("the renewal note for {username}"));
        }
    }

    // The groups' own thirty-day note, once for the body. A card group is
    // Stripe's to remind, and a free group has no date to run out.
    for domain in store.list("groups").await? {
        let group = match group_record(store, &domain).await {
            Ok(Some(group)) => group,
            Ok(None) => continue,
            Err(e) => {
                e.report(&format!("reading {domain}'s renewal"));
                continue;
            }
        };
        if group.payment.no_charge || group.payment.rail == "card" {
            continue;
        }
        let Some(paid_until) = group.payment.paid_until.as_deref() else {
            continue;
        };
        let Some(until) = util::parse_date(paid_until.get(..10).unwrap_or(paid_until)) else {
            continue;
        };
        if today < until - Duration::days(30) || today >= until {
            continue;
        }
        let token = group.payment.token_ref.as_deref().unwrap_or("");
        let price = cfg.group_price_gbp.as_str();
        let subject = format!("Your kyriakon.net group for {domain} runs out on {paid_until}");
        let body = format!(
            "The membership for {domain} is paid until {paid_until}, and covers every\n\
             mailbox in the group.\n\n\
             To renew it for another year, send GBP {price} for the whole group. Your\n\
             payment reference is {token}.\n\n\
             Nothing is deleted when the date passes. Write to admin@kyriakon.net to\n\
             arrange the renewal or if you have already sent the money; the renewal is\n\
             handled by the operator, and no automatic deletion runs from this date.\n"
        );
        let to = match dns_contact(store, &group).await {
            Ok(to) => to,
            Err(e) => {
                e.report(&format!("the renewal note for {domain}"));
                continue;
            }
        };
        if let Err(e) = notice::send_account_notice(
            cfg,
            store,
            &group.site_owner,
            "group.renewal",
            &subject,
            &to,
            &body,
        )
        .await
        {
            Error::from(e).report(&format!("the renewal note for {domain}"));
        }
    }
    Ok(())
}

/// Release every username hold whose ninety days have run, and the journal
/// lines that name the released account with it. Run once per drain pass, last,
/// so no append after the rewrite reads the loaded index's stale line
/// positions.
///
/// A line written after the hold ended belongs to a later account that reused
/// the released name, not to the one being released, so only lines inside the
/// hold are dropped. A hold that cannot be read is left alone: releasing a name
/// the platform cannot see the end of is worse than keeping it.
pub async fn holds_sweep(store: &Store) -> Result<(), Error> {
    let now = OffsetDateTime::now_utc();
    let mut expired: Vec<(String, OffsetDateTime)> = Vec::new();
    for name in store.list("holds").await? {
        let Some(username) = name.strip_suffix(".json") else {
            continue;
        };
        let value = match store.hold(username).await {
            Ok(Some(value)) => value,
            Ok(None) => continue,
            Err(e) => {
                e.report(&format!("reading {username}'s hold"));
                continue;
            }
        };
        let Some(until) = value.get("until").and_then(Value::as_str) else {
            continue;
        };
        let Ok(at) = OffsetDateTime::parse(until, &Rfc3339) else {
            continue;
        };
        if at > now {
            continue;
        }
        expired.push((username.to_string(), at));
    }
    if expired.is_empty() {
        return Ok(());
    }

    // The lines go before the hold files: a crash between the two then leaves a
    // hold the next pass retries, never journal lines with no hold left to
    // release them.
    {
        let log = store.log("journal.jsonl");
        let _guard = log.lock().await?;
        let mut kept = String::new();
        let mut dropped = false;
        for line in log.raw_lines().await? {
            let named = serde_json::from_str::<store::JournalLine>(&line)
                .ok()
                .is_some_and(|entry| {
                    expired.iter().any(|(username, until)| {
                        entry.application.username == username.as_str()
                            && OffsetDateTime::parse(&entry.at, &Rfc3339)
                                .is_ok_and(|at| at < *until)
                    })
                });
            if named {
                dropped = true;
                continue;
            }
            kept.push_str(&line);
            kept.push('\n');
        }
        if dropped {
            store.rewrite_log("journal.jsonl", kept.as_bytes()).await?;
        }
    }
    for (username, _) in &expired {
        store.remove("holds", &format!("{username}.json")).await?;
    }
    Ok(())
}

/// Carry out one export intent: the page's "Take my data out", filed by the
/// handler with the account the session belongs to and nothing else. The session
/// that proves it is `verify`'s.
///
/// The bundle is written into the member's own chroot and the ready notice is
/// appended in the same pass, and the request's line is closed with the bundle's
/// path so the page's own ask does not stay open. The journal line names the
/// application the account was approved from when the copy is still inside ADR
/// 0005's purge; an export after the purge has no status token left to name and
/// journals none.
pub async fn export_account(
    cfg: &DrainConfig,
    store: &Store,
    intent: ExportIntent,
    file: &str,
) -> Result<Settlement, Error> {
    let username = intent.username.as_str();
    let id = if intent.id.is_empty() {
        file.trim_end_matches(".json").to_string()
    } else {
        intent.id.clone()
    };
    // The spec records one `requests.jsonl` line per data-subject request, and
    // a page-filed export is one. It is written before the answer, keyed by the
    // intent's own id so a retry after a failed pass does not append a second
    // request for the same ask.
    let existing = store
        .log(&format!("accounts/{username}/requests.jsonl"))
        .jsonl::<kyriakon_control_core::account::requests::RequestLine>()
        .await?
        .into_iter()
        .find(|line| line.id == id);
    // The day the request is answered. A retry reads the recorded line's own
    // receipt date, so the same pass that finishes the export closes the same
    // line on the same day rather than moving the date the answer carries.
    let received = existing
        .as_ref()
        .map(|line| line.received.clone())
        .unwrap_or_else(|| {
            kyriakon_control_core::util::date_string(
                kyriakon_control_core::account::requests::today(),
            )
        });
    if existing.is_none() {
        kyriakon_control_core::account::requests::record(
            store,
            kyriakon_control_core::account::requests::NewRequest {
                username,
                kind: "access",
                received: &received,
                // The session is the page's whole claim, and it was opened by
                // the password check the runbook names.
                evidence: "the account page's password check",
                identity: "password",
                note: Some("export filed from the account page"),
                identity_at: None,
                fee_at: None,
                id: Some(id.as_str()),
            },
        )
        .await?;
    }
    let status_token = store
        .account_application_text(username)
        .await?
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|copy| {
            copy.get("status_token")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let bundle = kyriakon_control_core::account::export::deliver(cfg, store, username).await?;
    // Record the delivery and close the line it answers, so the page's own
    // export is not left open in the operator's docket. A pass that delivered
    // and closed but crashed before its journal line is replayed by the next
    // pass: the line is already closed, which is the same fact rather than a
    // second request.
    kyriakon_control_core::account::requests::set_bundle(store, &id, username, &bundle).await?;
    if existing.as_ref().is_none_or(|line| line.done.is_none()) {
        kyriakon_control_core::account::requests::close(
            store,
            &id,
            &received,
            "delivered to the member's export directory",
        )
        .await?;
    }
    let application = ApplicationRef::application(username.to_string(), status_token);
    Ok(Settlement::line(
        "applied",
        application.clone(),
        Some(format!("the bundle is at {bundle}")),
    ))
}

/// Clear away every declined application whose week is up, and release the
/// username. Run once per drain pass, after the intents: this is what carries
/// the decline's week out without the application being touched again.
pub async fn purge_declined(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
) -> Result<(), Error> {
    let now = OffsetDateTime::now_utc();
    for name in store.list("applications").await? {
        if !name.ends_with(".json") {
            continue;
        }
        let Some(record) =
            sweep_application(cfg, store, journal, name.trim_end_matches(".json")).await
        else {
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
            Error::Failed(format!(
                "declined record {name} has no usable username; skipped"
            ))
            .report("the purge sweep");
            continue;
        }
        let app = ApplicationRef::application(record.username.clone(), record.status_token.clone());
        let purge_id = format!("purge-{}", record.status_token);
        // A purge that keeps failing backs off, and its error is mailed once,
        // through the same rule the intents use.
        if !due(journal, &purge_id, now) {
            continue;
        }
        // The journal line goes before the transition, as it does for an intent,
        // and once: a pass that already released the name does not release it
        // again, and a crash after the line still clears the record away.
        if !journal.has(&purge_id, "purged") {
            if !journal.has(&purge_id, "applying") {
                write_journal(
                    store,
                    journal,
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
            let taken = match store.account(&record.username).await {
                Ok(Some(_)) => true,
                Ok(None) => account_on_box(cfg, &record.username)?,
                Err(e) => {
                    // The account holding the name cannot be read, so the purge
                    // cannot tell whether releasing the name would take an
                    // account with it. Report and leave the application for the
                    // next pass rather than release on a guess.
                    report_record(
                        cfg,
                        store,
                        journal,
                        "account",
                        &record.username,
                        &Error::from(e),
                    )
                    .await;
                    continue;
                }
            };
            if !taken {
                if let Err(e) = run_script(cfg, "delete-user.sh", &[&record.username]).await {
                    report_failure(cfg, store, journal, &purge_id, "decline", &Error::from(e))
                        .await;
                    continue;
                }
            }
            write_journal(
                store,
                journal,
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

/// Run the one deletion transition for every account whose seven-day closing
/// window has ended. Run once per drain pass after the intents: a page closure
/// only sets `closing`, and this is what carries the window out without the
/// account being touched again.
///
/// The journal id is the transition's own (`delete-<username>-<created_at>`), so
/// a failed pass backs off and mails the operator once through the same rule the
/// intents use, and a pass that already erased the account finds no record and
/// does nothing.
pub async fn purge_closing(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
) -> Result<(), Error> {
    let today = util::date_after_days(0);
    for username in store.list("accounts").await? {
        if validate::username_shape(&username).is_some() {
            continue;
        }
        let Some(account) = sweep_account(cfg, store, journal, &username).await else {
            continue;
        };
        if account.state != "closing" {
            continue;
        }
        // A closing record without a date is not a window this pass can close;
        // leaving it visible is better than deleting on a guess.
        let Some(until) = account.closing_until.as_deref() else {
            continue;
        };
        if until > today.as_str() {
            continue;
        }
        let id = format!("delete-{}-{}", username, account.created_at);
        if !due(journal, &id, OffsetDateTime::now_utc()) {
            continue;
        }
        if let Err(e) = delete_account(cfg, store, journal, &username).await {
            report_failure(cfg, store, journal, &id, "delete", &e).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transitions::test_support::quota_config;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_free_accounts_note_falls_due_on_the_creation_day_clamped() {
        let leap = time::Date::from_calendar_date(2024, time::Month::February, 29).unwrap();
        // A common year has no 29 February, so the note falls due a day early
        // rather than being skipped for the year.
        assert_eq!(
            util::anniversary(leap, 2025).unwrap(),
            time::Date::from_calendar_date(2025, time::Month::February, 28).unwrap()
        );
        assert_eq!(
            util::anniversary(leap, 2028).unwrap(),
            time::Date::from_calendar_date(2028, time::Month::February, 29).unwrap()
        );
    }

    /// OpenBSD `repquota -u` output as the sweep reads it: two header lines and
    /// one row per uid, with the two over-limit markers between the name and the
    /// used figure. A `quota -v` block, which uses `Disk quotas for user`, and an
    /// empty table both yield nothing rather than a guess.
    #[test]
    fn a_repquota_report_yields_each_members_used_blocks() {
        let report = "                        KByte limits               File limits\n\
                      User            used    soft    hard  grace    used  soft  hard  grace\n\
                      alice             --   1024 5242880 5767168        --    10     0     0\n\
                      secretary         --    512 5242880 5767168        --     3     0     0\n";
        assert_eq!(
            parse_repquota(report),
            [("alice".to_string(), 1024), ("secretary".to_string(), 512)]
        );
        // A name that fills the ten-column field carries the markers with no
        // separating space.
        assert_eq!(
            parse_repquota(
                "User used soft hard grace used soft hard grace\n\
                 averylonguser--   2048 5242880 5767168        --     1     0     0\n"
            ),
            [("averylonguser".to_string(), 2048)]
        );
        // `quota -v`'s per-user blocks are another report entirely.
        assert!(parse_repquota(
            "Disk quotas for user alice (uid 1001):\n\
             Filesystem blocks quota limit grace files quota limit grace\n\
             /dev/sd1l 1024 5242880 5767168 10 0 0\n"
        )
        .is_empty());
        assert!(parse_repquota("").is_empty());
        assert!(parse_repquota("no quota table here\n").is_empty());
    }

    fn fixture_account(store_dir: &std::path::Path, username: &str) {
        let dir = store_dir.join(format!("accounts/{username}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("account.json"),
            serde_json::to_vec_pretty(&json!({
                "version": 1, "username": username, "state": "active",
                "decision": "approve", "decided_at": "2026-10-01T09:00:00Z",
                "rail": "cash", "no_charge": false,
                "created_at": "2026-10-01T09:00:00Z"
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn repquota_stub(dir: &std::path::Path, body: &str) -> String {
        let path = dir.join("bin/repquota");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n{body}",
                dir.join("repquota.args").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn the_quota_sweep_records_usage_once_an_hour_and_shrugs_at_a_bad_report() {
        let dir = std::env::temp_dir().join(format!("onboard-quota-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::create_dir_all(dir.join("store")).unwrap();
        fixture_account(&dir.join("store"), "alice");
        fixture_account(&dir.join("store"), "secretary");
        let group_dir = dir.join("store/groups/parish.example");
        std::fs::create_dir_all(&group_dir).unwrap();
        std::fs::write(
            group_dir.join("group.json"),
            serde_json::to_vec_pretty(&json!({
                "version": 1, "domain": "parish.example", "name": "Parish",
                "kind": "parish",
                "payment": {"rail": "cash", "no_charge": false, "paid_until": null},
                "accounts": ["alice", "secretary"], "site_owner": "alice"
            }))
            .unwrap(),
        )
        .unwrap();
        let cfg = quota_config(&dir);
        let store = Store::new_for_test(&cfg.store_root);
        let journal = Journal::load(&store).await.unwrap();
        // The sweep takes `-u` and the mount the config names.
        cfg_script(
            &dir,
            "printf '%s\\n' 'User used soft hard grace used soft hard grace' 'alice -- 1024 5242880 5767168 -- 10 0 0' 'secretary -- 512 5242880 5767168 -- 3 0 0'\n",
        );

        refresh_space_used(&cfg, &store, &journal).await.unwrap();
        assert_eq!(
            store.account("alice").await.unwrap().unwrap().space_used,
            Some(1024 * 1024)
        );
        assert_eq!(
            store
                .account("secretary")
                .await
                .unwrap()
                .unwrap()
                .space_used,
            Some(512 * 1024)
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("repquota.args")).unwrap(),
            "-u /home\n"
        );
        // The group holds the sum of its mailboxes' figures.
        let group = group_record(&store, "parish.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(group.space_used, Some((1024 + 512) * 1024));

        // The hour's cache: a second pass does not run the report again.
        cfg_script(
            &dir,
            "printf '%s\\n' 'User used soft hard grace used soft hard grace' 'alice -- 2048 5242880 5767168 -- 10 0 0'\n",
        );
        refresh_space_used(&cfg, &store, &journal).await.unwrap();
        assert_eq!(
            store.account("alice").await.unwrap().unwrap().space_used,
            Some(1024 * 1024)
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("repquota.args"))
                .unwrap()
                .lines()
                .count(),
            1
        );

        // A report the parse cannot follow, on a fresh state, is a no-op rather
        // than a zero written over a real figure.
        std::fs::remove_file(store.path("quota-check.json")).unwrap();
        cfg_script(&dir, "printf 'no quota table here\\n'\n");
        refresh_space_used(&cfg, &store, &journal).await.unwrap();
        assert_eq!(
            store.account("alice").await.unwrap().unwrap().space_used,
            Some(1024 * 1024)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Overwrite the fixture report without rebuilding the config.
    fn cfg_script(dir: &std::path::Path, body: &str) {
        repquota_stub(dir, body);
    }
}
