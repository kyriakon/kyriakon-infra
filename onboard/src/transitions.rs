//! The drain's settlement seam: one intent file, one proved body, one journal
//! line, one remove.
//!
//! [`settle`] is the only writer of an intent's outcome. A body lives in the
//! module that owns its job — [`payments`], [`groups`], [`lifecycle`],
//! [`review`] or [`stripe`] — and returns a [`Settlement`]; the dedup, the
//! after-line work and the file's disposition stay here. The retry schedule and
//! the failure report are the other half of the same seam.

use crate::config::DrainConfig;
use crate::journal::Journal;
use crate::notice;
use crate::store::{ApplicationRef, JournalLine, Store};
use crate::util;
use serde_json::Value;
use std::future::Future;
use time::Duration;
use time::OffsetDateTime;

pub mod groups;
pub mod lifecycle;
pub mod payments;
pub mod review;
pub mod stripe;

/// Append one journal line. The caller writes this before the transition, which
/// is the whole point of the journal, and again on completion so an approval that
/// finished and one that died midway do not read alike. The index takes the line
/// too, so a query later in the same pass sees it.
#[allow(clippy::too_many_arguments)]
async fn write_journal(
    store: &Store,
    journal: &Journal,
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
    journal.append(store, &line).await
}

/// The intent file's own words: the id and kind the journal line carries, and
/// the application it names. Read from the file the pass holds, so the seam's
/// refusal and the body's settlement name the same intent.
pub struct Envelope {
    pub id: String,
    pub kind: String,
    pub application: ApplicationRef,
}

impl Envelope {
    /// The envelope of one intent file. A file missing its id or its
    /// application is still journalled under what it does say, exactly as the
    /// refusal path has always read it.
    pub fn of(value: &Value, file: &str, kind: &str) -> Self {
        Envelope {
            id: value
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| file.trim_end_matches(".json").to_string()),
            kind: kind.to_string(),
            // A page action names its account at the top level rather than in an
            // `application` block, and its refusal is journalled under it: the
            // subject is whichever the file carries.
            application: value
                .get("application")
                .and_then(|a| serde_json::from_value::<ApplicationRef>(a.clone()).ok())
                .unwrap_or_else(|| {
                    ApplicationRef::account(
                        value.get("username").and_then(Value::as_str).unwrap_or(""),
                    )
                }),
        }
    }
}

/// What a root verb's body settled as.
#[derive(Debug)]
pub enum Settlement {
    /// The journal line the intent takes, and the application it names. The
    /// file goes once the line is written. `after` is work the line itself
    /// owes, beyond what the dispatcher names for the verb.
    Line {
        outcome: &'static str,
        application: ApplicationRef,
        note: Option<String>,
        after: Option<AfterLine>,
    },
    /// The work left nothing to journal: only the file remained of it, as on a
    /// replay whose line the crashed pass had already written.
    Nothing,
    /// The intent is refused. The journal records it once under the file's own
    /// envelope, with this reason, and the file stays for the operator or is
    /// removed, exactly as `Disposition.refusal` says. A refusal runs no
    /// after-line work: the refused line is the whole settlement. `failure` is
    /// work that failed while refusing, such as a plaintext redaction; the
    /// refusal is still recorded, and the pass reports it.
    Refused {
        reason: String,
        failure: Option<String>,
    },
}

impl Settlement {
    /// The intent was carried out.
    pub fn applied(application: ApplicationRef, note: Option<String>) -> Self {
        Settlement::Line {
            outcome: "applied",
            application,
            note,
            after: None,
        }
    }

    /// An outcome of the verb's own, such as a page action whose account has
    /// already gone: the line is still the settlement, and the file goes.
    ///
    /// A refusal is not one of these: `Settlement::refused` is the only way to
    /// say it, because a `Line` with that outcome ignores `Disposition.refusal`
    /// and would remove a file the operator's verb meant to keep.
    pub fn line(outcome: &'static str, application: ApplicationRef, note: Option<String>) -> Self {
        debug_assert_ne!(outcome, "refused", "use Settlement::refused, not a line");
        Settlement::Line {
            outcome,
            application,
            note,
            after: None,
        }
    }

    pub fn nothing() -> Self {
        Settlement::Nothing
    }

    pub fn refused(reason: impl ToString) -> Self {
        Settlement::Refused {
            reason: reason.to_string(),
            failure: None,
        }
    }

    /// Work this settlement owes after its own line, which the dispatcher
    /// cannot name because only the body knows what it is.
    pub fn with_after(self, after: AfterLine) -> Self {
        match self {
            Settlement::Line {
                outcome,
                application,
                note,
                after: None,
            } => Settlement::Line {
                outcome,
                application,
                note,
                after: Some(after),
            },
            other => other,
        }
    }
}

/// What a verb still owes after its outcome line: work that must not precede
/// the line, because a repeat would no longer find what it acts on, and that
/// must also run on a pass that finds the line and the file a crash left behind.
#[derive(Debug)]
pub enum AfterLine {
    Nothing,
    /// Take a removed domain's record directory away.
    RemoveGroupRecord(String),
    /// Mark a held payment as attributed to its token.
    MarkAttributed {
        item: String,
        token: String,
    },
    /// Print a line only once the settlement is journalled, so a retried pass
    /// that found the line does not print it again.
    Print(String),
}

async fn finish(store: &Store, after: AfterLine) -> Result<(), String> {
    match after {
        AfterLine::Nothing => Ok(()),
        AfterLine::RemoveGroupRecord(domain) => groups::remove_group_record(store, &domain).await,
        AfterLine::MarkAttributed { item, token } => {
            payments::mark_attributed(store, &item, &token).await
        }
        AfterLine::Print(text) => {
            println!("{text}");
            Ok(())
        }
    }
}

/// What a refusal leaves of the intent file. A page action's refusal is the
/// handler's own input refused in the drain, so its file goes; every other
/// refusal is kept for the operator to read, as `refuse` leaves an unknown
/// kind.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RefusalFile {
    Keep,
    Remove,
}

/// What the dispatcher names for a verb before its body runs: the work owed
/// after its line, and what a refusal leaves of its file.
pub struct Disposition {
    pub after: AfterLine,
    pub refusal: RefusalFile,
}

impl Disposition {
    pub fn new(after: AfterLine, refusal: RefusalFile) -> Self {
        Disposition { after, refusal }
    }
}

/// The one settlement path: dedup, the verb's body, its outcome line, the
/// after-line work, the remove.
///
/// An intent the journal already settled is not work. An `applied` line whose
/// file survived the crash between the two is finished here by removing the
/// file; any other outcome line the journal already carries is not appended
/// again, and the file is finished the same way. A `refused` line leaves the
/// file for the operator, except for a page action, whose refusal is the
/// handler's own input. The body does the work, writes the `applying` line
/// where the verb has one, and returns what the intent settled as.
pub async fn settle<F>(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    file: &str,
    envelope: &Envelope,
    disposition: Disposition,
    body: F,
) -> Result<(), String>
where
    F: Future<Output = Result<Settlement, String>>,
{
    if journal.has(&envelope.id, "applied") {
        finish(store, disposition.after).await?;
        return store.remove("intents", file).await;
    }
    if journal.has(&envelope.id, "refused") {
        // A refusal ran no after-line work when it was written, so a replay
        // runs none either. The file disposition still applies.
        return match disposition.refusal {
            RefusalFile::Keep => Ok(()),
            RefusalFile::Remove => store.remove("intents", file).await,
        };
    }
    match body.await? {
        Settlement::Line {
            outcome,
            application,
            note,
            after: more,
        } => {
            // A crash between the line and the remove leaves the file. Any
            // outcome line already in the journal is that line, so it is not
            // appended a second time; only the remove and the after-line work
            // remain.
            if !journal.has(&envelope.id, outcome) {
                write_journal(
                    store,
                    journal,
                    &cfg.release,
                    &envelope.id,
                    &envelope.kind,
                    &application,
                    outcome,
                    note.as_deref(),
                )
                .await?;
            }
            finish(store, disposition.after).await?;
            if let Some(more) = more {
                finish(store, more).await?;
            }
            store.remove("intents", file).await
        }
        Settlement::Nothing => {
            finish(store, disposition.after).await?;
            store.remove("intents", file).await
        }
        Settlement::Refused { reason, failure } => {
            // The prologue has already returned on a refused line, so this one
            // is new. A refusal runs no after-line work: the held line, the
            // removed record and the rest stay as the refusal found them, and
            // the refused line is the whole settlement.
            write_journal(
                store,
                journal,
                &cfg.release,
                &envelope.id,
                &envelope.kind,
                &envelope.application,
                "refused",
                Some(&reason),
            )
            .await?;
            if disposition.refusal == RefusalFile::Remove {
                store.remove("intents", file).await?;
            }
            match failure {
                Some(failure) => Err(failure),
                None => Ok(()),
            }
        }
    }
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

/// Record a failed pass and say whether it is a new one worth mailing. The same
/// message as the last failure is the same event, so the operator is not mailed
/// it again; a different message is. This is the notices path's rule, applied to
/// the drain's own output: record first, and let the record stop the duplicate.
pub async fn note_failure(
    store: &Store,
    journal: &Journal,
    release: &str,
    id: &str,
    kind: &str,
    message: &str,
) -> Result<bool, String> {
    let (_, _, previous) = journal.failures(id);
    write_journal(
        store,
        journal,
        release,
        id,
        kind,
        &ApplicationRef::default(),
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
pub async fn report_failure(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    id: &str,
    kind: &str,
    message: &str,
) {
    let fresh = note_failure(store, journal, &cfg.release, id, kind, message)
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
pub fn due(journal: &Journal, id: &str, now: OffsetDateTime) -> bool {
    let (failures, last, _) = journal.failures(id);
    match last {
        None => true,
        Some(last) => now >= last + Duration::minutes(retry_after_minutes(failures)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;

    use crate::intents::RefundIntent;
    use crate::sign;
    use crate::store::{GroupIntent, Record};
    use serde_json::json;

    use super::groups::{ensure_table_line, group_record, TableLock};
    use super::lifecycle::{parse_repquota, refresh_space_used};
    use super::payments::{credit_money, settle_refund};
    use super::review::{decision_subject, decline_body};

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

    /// The `provision-group` payload covers every field the transition acts on:
    /// changing any one of them changes the payload, so a signature made for one
    /// body cannot be replayed with another's mailbox, key or payment.
    #[test]
    fn a_group_payload_covers_every_field_the_drain_acts_on() {
        let base = json!({
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "kind": "provision-group",
            "filed_at": "2026-11-01T09:00:00Z",
            "application": {"username": "warden", "status_token": "abcdefghjkmnpqrstvwxyz0123"},
            "domain": "parish.example",
            "name": "Parish of Example",
            "body_kind": "parish",
            "payment": {"rail": "cash", "no_charge": false, "paid_until": null},
            "addresses": [{"address": "secretary", "mailbox": "parish-secretary"}],
            "mailboxes": ["parish-secretary"],
            "site_owner": "parish-secretary",
            "upload_key": "ssh-ed25519 AAAA first@example",
            "mail_keys": [{"mailbox": "parish-secretary", "fingerprint": "1111 2222",
                           "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n",
                           "verdict": "works"}],
            "sig": "",
        });
        let payload = |value: &Value| {
            let intent: GroupIntent = serde_json::from_value(value.clone()).unwrap();
            sign::group_provision_payload(&intent)
        };
        let original = payload(&base);
        let changes = [
            ("domain", json!("other.example")),
            ("name", json!("Another Parish")),
            ("body_kind", json!("monastery")),
            (
                "payment",
                json!({"rail": "card", "no_charge": false, "paid_until": null}),
            ),
            (
                "payment",
                json!({"rail": "cash", "no_charge": true, "paid_until": null}),
            ),
            (
                "payment",
                json!({"rail": "cash", "no_charge": false, "paid_until": "2027-01-01"}),
            ),
            (
                "addresses",
                json!([{"address": "office", "mailbox": "parish-secretary"}]),
            ),
            ("mailboxes", json!(["parish-office"])),
            ("site_owner", json!("parish-office")),
            ("upload_key", json!("ssh-ed25519 AAAA second@example")),
            (
                "mail_keys",
                json!([{"mailbox": "parish-secretary", "fingerprint": "3333 4444",
                        "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nyy\n",
                        "verdict": "works"}]),
            ),
            (
                "application",
                json!({"username": "other", "status_token": "abcdefghjkmnpqrstvwxyz0123"}),
            ),
            (
                "application",
                json!({"username": "warden", "status_token": "fedcba98765432100123456789"}),
            ),
        ];
        for (field, value) in changes {
            let mut changed = base.clone();
            changed[field] = value.clone();
            assert_ne!(original, payload(&changed), "changing {field} to {value}");
        }

        // Every payment field the transition copies into the group record: the
        // token reference, the window's four fields and the Stripe block's
        // eight. The base payment carries none of them, so a field missing from
        // the payload leaves these two payloads equal.
        let with_payment = |payment: Value| {
            let mut changed = base.clone();
            changed["payment"] = payment;
            payload(&changed)
        };
        let base_payment = base["payment"].clone();
        for (label, value) in [
            ("token_ref", json!("KYR-AAAA-BBBB-CCCC")),
            ("paid_until", json!("2027-01-01")),
            ("no_charge", json!(true)),
            ("rail", json!("card")),
        ] {
            let mut payment = base_payment.clone();
            payment[label] = value;
            assert_ne!(original, with_payment(payment), "payment.{label}");
        }

        let window = json!({"opened_at": "2026-11-01T09:00:00Z",
                            "closes_at": "2026-11-15T09:00:00Z",
                            "state": "open", "extensions": 0});
        let mut with_window = base_payment.clone();
        with_window["window"] = window.clone();
        let windowed = with_payment(with_window);
        assert_ne!(original, windowed, "payment.window presence");
        for (label, value) in [
            ("opened_at", json!("2026-10-01T09:00:00Z")),
            ("closes_at", json!("2026-11-20T09:00:00Z")),
            ("state", json!("paid")),
            ("extensions", json!(1)),
        ] {
            let mut changed = window.clone();
            changed[label] = value;
            let mut payment = base_payment.clone();
            payment["window"] = changed;
            assert_ne!(windowed, with_payment(payment), "payment.window.{label}");
        }

        for (label, value) in [
            ("subscription", json!("sub_example")),
            ("customer", json!("cus_example")),
            ("status", json!("active")),
            ("cancel_at_period_end", json!(true)),
            ("current_period_end", json!("2027-01-01T00:00:00Z")),
            ("next_payment_attempt", json!("2026-12-01T00:00:00Z")),
            ("failed_attempts", json!(2)),
            ("last_invoice", json!("in_example")),
        ] {
            let mut stripe = json!({});
            stripe[label] = value;
            let mut payment = base_payment.clone();
            payment["stripe"] = stripe;
            assert_ne!(original, with_payment(payment), "payment.stripe.{label}");
        }
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
            util::anniversary(leap, 2025).unwrap(),
            time::Date::from_calendar_date(2025, time::Month::February, 28).unwrap()
        );
        assert_eq!(
            util::anniversary(leap, 2028).unwrap(),
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

    /// The lock the shell takes is `<table>.lock` with the owner's pid inside, so
    /// this asserts the Rust side uses that path and file, and that dropping the
    /// guard releases it. That shared shape is what lets a drain append and a
    /// deploy's table_set exclude each other.
    #[test]
    fn the_mail_table_lock_is_a_pid_directory_beside_the_table() {
        let dir = std::env::temp_dir().join(format!("onboard-table-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let table = dir.join("virtuals");
        std::fs::write(&table, "hello: oliver\n").unwrap();
        let path = table.to_str().unwrap();

        let lock = TableLock::acquire(path).unwrap();
        let lock_dir = dir.join("virtuals.lock");
        assert!(
            lock_dir.is_dir(),
            "the lock is a directory beside the table"
        );
        assert_eq!(
            std::fs::read_to_string(lock_dir.join("pid"))
                .unwrap()
                .trim(),
            std::process::id().to_string(),
            "the owner pid is inside, which is what the shell reads"
        );
        drop(lock);
        assert!(!lock_dir.exists(), "releasing removes the directory");
        drop(TableLock::acquire(path).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A lock whose owner is gone is reaped rather than left to wedge every
    /// later writer, which is the shell's rule too.
    #[test]
    fn a_stale_mail_table_lock_is_reaped() {
        let dir = std::env::temp_dir().join(format!("onboard-table-reap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let table = dir.join("mail_domains");
        std::fs::write(&table, "kyriakon.net\n").unwrap();
        let lock_dir = dir.join("mail_domains.lock");
        std::fs::create_dir(&lock_dir).unwrap();
        std::fs::write(lock_dir.join("pid"), "999999\n").unwrap();

        let lock = TableLock::acquire(table.to_str().unwrap()).unwrap();
        assert_eq!(
            std::fs::read_to_string(lock_dir.join("pid"))
                .unwrap()
                .trim(),
            std::process::id().to_string()
        );
        drop(lock);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Three writers at once, the case the lock exists for: every appended line
    /// is in the table afterwards, with no candidate left beside it. The retry is
    /// in whole seconds, so the count is kept under the five-second wait.
    #[test]
    fn concurrent_table_appends_all_land() {
        let dir = std::env::temp_dir().join(format!("onboard-table-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let table = dir.join("virtuals");
        std::fs::write(&table, "hello: oliver\n").unwrap();
        let path = table.to_str().unwrap().to_string();

        let mut handles = Vec::new();
        for i in 0..3 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                ensure_table_line(&path, &format!("user{i}"), Some("mailbox"))
            }));
        }
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        let text = std::fs::read_to_string(&table).unwrap();
        assert_eq!(text.lines().count(), 4, "{text}");
        assert!(!dir.join("virtuals.lock").exists());
        std::fs::remove_dir_all(&dir).unwrap();
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

    fn quota_config(dir: &std::path::Path) -> DrainConfig {
        DrainConfig {
            store_root: dir.join("store").to_str().unwrap().to_string(),
            reserved: dir.join("reserved").to_str().unwrap().to_string(),
            scripts: dir.join("bin").to_str().unwrap().to_string(),
            sendmail: dir.join("bin/enqueuer.sh").to_str().unwrap().to_string(),
            passwd: dir.join("passwd").to_str().unwrap().to_string(),
            mail_domains: dir.join("mail_domains").to_str().unwrap().to_string(),
            virtuals: dir.join("virtuals").to_str().unwrap().to_string(),
            dkim_domains: dir.join("dkim_domains").to_str().unwrap().to_string(),
            approval_key: dir.join("key").to_str().unwrap().to_string(),
            keyring_dir: dir.join("keyring").to_str().unwrap().to_string(),
            stripe_webhook_secret: String::new(),
            stripe_api_key: String::new(),
            stripe_payment_link: String::new(),
            keyring_publish_token: String::new(),
            reviewer: "reviewer@example.invalid".to_string(),
            from: "kyriakon <hello@example.invalid>".to_string(),
            base_url: "https://signup.kyriakon.net".to_string(),
            price_gbp: "20.00".to_string(),
            group_price_gbp: "40.00".to_string(),
            postal_address: "1 Example Street".to_string(),
            mail_dir: dir.join("mail").to_str().unwrap().to_string(),
            release: "2026-10-10 abc1234".to_string(),
            mail_host: "mail.kyriakon.net".to_string(),
            ipv4: "192.0.2.10".to_string(),
            ipv6: "2001:db8::10".to_string(),
            dkim_selector: "mail".to_string(),
            dkim_public_key: "v=DKIM1; k=rsa; p=example".to_string(),
            dmarc_rua: "mailto:dmarc@kyriakon.net".to_string(),
            resolver: dir.join("bin/dig").to_str().unwrap().to_string(),
            repquota: dir.join("bin/repquota").to_str().unwrap().to_string(),
            quota_mount: "/home".to_string(),
            rates: dir
                .join("store/rates/xmr-gbp.json")
                .to_str()
                .unwrap()
                .to_string(),
            rate_endpoint: "https://rates.example.invalid/simple/price".to_string(),
            rates_fetch: dir.join("bin/curl").to_str().unwrap().to_string(),
            gpg: "gpg".to_string(),
            proof_dir: dir.join("logins").to_str().unwrap().to_string(),
            public_root: dir.join("home/www").to_str().unwrap().to_string(),
        }
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

    /// Whether the ledger lock can be taken without waiting. `false` means a
    /// descriptor in this process holds it.
    fn ledger_lock_is_free(path: &std::path::Path) -> bool {
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
        else {
            return false;
        };
        let fd = file.as_raw_fd();
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            unsafe { libc::flock(fd, libc::LOCK_UN) };
            true
        } else {
            false
        }
    }

    /// A settlement releases the ledger lock with its write. The journal line
    /// that follows is not part of the ledger, so a second writer must be able
    /// to take the lock while the line is being appended: here the append blocks
    /// on a pipe nobody reads yet, which holds the settlement exactly there.
    #[test]
    fn a_settlement_journals_with_the_ledger_lock_released() {
        use std::ffi::CString;
        use std::io::Read;
        use std::time::{Duration, Instant};

        let dir = std::env::temp_dir().join(format!("onboard-settle-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("store");
        std::fs::create_dir_all(root.join("ledger")).unwrap();
        let root_text = root.to_str().unwrap().to_string();
        let token = "KYR-AAAA-BBBB-CCCC";
        let ledger = root.join("ledger/payments.jsonl");
        std::fs::write(
            &ledger,
            format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "version": 1,
                    "seq": 7,
                    "token": token,
                    "kind": "refund",
                    "rail": "cash",
                    "received_on": "2026-11-04",
                    "amount_gbp": "-5.00",
                    "applied_gbp": "-5.00",
                    "refund_of": 1,
                }))
                .unwrap()
            ),
        )
        .unwrap();
        // The journal is a pipe, so its append waits for a reader: the state of
        // the lock is observable at that point rather than a race. The index is
        // loaded first, while the file is still missing (an empty journal), so
        // the settlement's append is what blocks on the pipe.
        let journal = {
            let store = Store::new_for_test(&root_text);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(Journal::load(&store)).unwrap()
        };
        let journal_path = root.join("journal.jsonl");
        let c_path = CString::new(journal_path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let value = json!({
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "kind": "refund",
            "token": token,
            "settled_on": "2026-11-05",
            "sig": "",
        });
        let intent: RefundIntent = serde_json::from_value(value.clone()).unwrap();
        let thread_dir = dir.clone();
        let settle = std::thread::spawn(move || {
            let cfg = quota_config(&thread_dir);
            let store = Store::new_for_test(&root_text);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(settle(
                &cfg,
                &store,
                &journal,
                "settle.json",
                &Envelope::of(&value, "settle.json", "refund"),
                Disposition::new(AfterLine::Nothing, RefusalFile::Keep),
                settle_refund(&store, &intent, "2026-11-05"),
            ))
        });

        // Wait for the ledger write, which is the step the guard covers.
        let wrote = || {
            std::fs::read_to_string(&ledger)
                .map(|text| text.contains("settled_on"))
                .unwrap_or(false)
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !wrote() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(wrote(), "the settlement never wrote the ledger");

        // The append is now waiting on the pipe. The lock must be free: a
        // retry covers the instant between the write and the guard's drop.
        let lock_path = root.join("ledger/payments.jsonl.lock");
        let mut free = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if ledger_lock_is_free(&lock_path) {
                free = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        // Unblock the append and let the settlement finish either way, so a
        // failure reads as an assertion rather than a hang.
        let read_journal = {
            let journal = journal_path.clone();
            std::thread::spawn(move || {
                let mut text = String::new();
                std::fs::File::open(&journal)
                    .and_then(|mut f| f.read_to_string(&mut text))
                    .map(|_| text)
            })
        };
        let settled = settle.join().unwrap();
        read_journal.join().unwrap().unwrap();

        assert!(
            free,
            "the ledger lock is still held while the settlement journals"
        );
        assert!(settled.is_ok(), "{settled:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A line the settlement cannot read is an error, never a line it skips to
    /// settle an older refund in its place.
    #[tokio::test]
    async fn a_corrupt_ledger_line_is_an_error_on_the_settlement_path() {
        let dir =
            std::env::temp_dir().join(format!("onboard-settle-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ledger")).unwrap();
        let ledger = dir.join("ledger/payments.jsonl");
        let line = json!({
            "version": 1,
            "seq": 7,
            "token": "KYR-AAAA-BBBB-CCCC",
            "kind": "refund",
            "rail": "cash",
            "received_on": "2026-11-04",
            "amount_gbp": "-5.00",
            "refund_of": 1,
        });
        std::fs::write(&ledger, format!("{line}\nnot json\n")).unwrap();
        let store = Store::new_for_test(dir.to_str().unwrap());
        let intent = RefundIntent {
            token: "KYR-AAAA-BBBB-CCCC".to_string(),
            ..Default::default()
        };
        let error = settle_refund(&store, &intent, "2026-11-04")
            .await
            .expect_err("a line that does not parse must fail the settlement");
        assert!(error.contains("line 2 does not parse"), "{error}");
        assert_eq!(
            std::fs::read_to_string(&ledger).unwrap(),
            format!("{line}\nnot json\n")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A refusal is one line however many passes read the file, and the file
    /// stays for the operator: the dedup and the line are `settle`'s, not each
    /// verb's.
    #[test]
    fn a_refused_intent_is_recorded_once_and_kept() {
        let dir =
            std::env::temp_dir().join(format!("onboard-settle-refused-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = quota_config(&dir);
        std::fs::create_dir_all(dir.join("store/intents")).unwrap();
        std::fs::write(dir.join("store/intents/settle.json"), "{}").unwrap();
        let store = Store::new_for_test(&cfg.store_root);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let journal = runtime.block_on(Journal::load(&store)).unwrap();
        let value = json!({ "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "kind": "window-extend" });
        let envelope = Envelope::of(&value, "settle.json", "window-extend");

        for _ in 0..2 {
            runtime
                .block_on(settle(
                    &cfg,
                    &store,
                    &journal,
                    "settle.json",
                    &envelope,
                    Disposition::new(AfterLine::Nothing, RefusalFile::Keep),
                    async { Ok(Settlement::refused("the window extension gives no reason")) },
                ))
                .unwrap();
        }

        let text = std::fs::read_to_string(dir.join("store/journal.jsonl")).unwrap();
        assert_eq!(
            text.matches("\"outcome\":\"refused\"").count(),
            1,
            "a second pass refused it again: {text}"
        );
        assert!(
            text.contains("the window extension gives no reason"),
            "{text}"
        );
        assert!(
            dir.join("store/intents/settle.json").exists(),
            "a refusal keeps its file for the operator"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A crash between the outcome line and the remove leaves the file, and for
    /// a removal its record too. The next pass finishes both, runs no body, and
    /// appends nothing.
    #[test]
    fn a_line_left_behind_finishes_the_after_work_once() {
        let dir =
            std::env::temp_dir().join(format!("onboard-settle-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = quota_config(&dir);
        std::fs::create_dir_all(dir.join("store/intents")).unwrap();
        std::fs::create_dir_all(dir.join("store/groups/parish.example")).unwrap();
        std::fs::write(dir.join("store/groups/parish.example/group.json"), "{}").unwrap();
        std::fs::write(dir.join("store/intents/settle.json"), "{}").unwrap();
        std::fs::write(
            dir.join("store/journal.jsonl"),
            "{\"version\":1,\"at\":\"2026-11-04T09:00:00Z\",\"intent\":\"01HZZZZZZZZZZZZZZZZZZZZZZZ\",\"kind\":\"remove-group\",\"release\":\"test\",\"application\":{\"username\":\"secretary\",\"status_token\":\"parish.example\"},\"outcome\":\"applied\"}\n",
        )
        .unwrap();
        let store = Store::new_for_test(&cfg.store_root);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let journal = runtime.block_on(Journal::load(&store)).unwrap();
        let value = json!({
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "kind": "remove-group",
            "domain": "parish.example",
        });
        let envelope = Envelope::of(&value, "settle.json", "remove-group");

        runtime
            .block_on(settle(
                &cfg,
                &store,
                &journal,
                "settle.json",
                &envelope,
                Disposition::new(
                    AfterLine::RemoveGroupRecord("parish.example".to_string()),
                    RefusalFile::Keep,
                ),
                async { Err("the body ran on a settled intent".to_string()) },
            ))
            .unwrap();

        assert!(
            !dir.join("store/groups/parish.example").exists(),
            "the record a crashed remove-group left behind was not removed"
        );
        assert!(
            !dir.join("store/intents/settle.json").exists(),
            "an applied intent was left in place"
        );
        let text = std::fs::read_to_string(dir.join("store/journal.jsonl")).unwrap();
        assert_eq!(
            text.matches("\"outcome\":\"applied\"").count(),
            1,
            "a second applied line was appended: {text}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// A page action's refusal removes its file even when the refusal line is
    /// all a crashed pass left behind; an operator-kept refusal does not.
    #[test]
    fn a_refusal_disposition_decides_the_file() {
        let dir =
            std::env::temp_dir().join(format!("onboard-settle-refusal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = quota_config(&dir);
        std::fs::create_dir_all(dir.join("store/intents")).unwrap();
        let store = Store::new_for_test(&cfg.store_root);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        for (id, refusal) in [
            ("01J00000000000000000PAGEREFUSED", RefusalFile::Remove),
            ("01J00000000000000000KEPTREFUSED", RefusalFile::Keep),
        ] {
            std::fs::write(dir.join(format!("store/intents/{id}.json")), "{}").unwrap();
            std::fs::write(
                dir.join("store/journal.jsonl"),
                format!(
                    "{{\"version\":1,\"at\":\"2026-11-04T09:00:00Z\",\"intent\":\"{id}\",\"kind\":\"set-password\",\"release\":\"test\",\"application\":{{\"username\":\"secretary\",\"status_token\":\"\"}},\"outcome\":\"refused\"}}\n"
                ),
            )
            .unwrap();
            let journal = runtime.block_on(Journal::load(&store)).unwrap();
            let value = json!({ "id": id, "kind": "set-password" });
            let envelope = Envelope::of(&value, &format!("{id}.json"), "set-password");
            runtime
                .block_on(settle(
                    &cfg,
                    &store,
                    &journal,
                    &format!("{id}.json"),
                    &envelope,
                    Disposition::new(AfterLine::Nothing, refusal),
                    async { Err("the body ran on a settled intent".to_string()) },
                ))
                .unwrap();
            let left = dir.join(format!("store/intents/{id}.json"));
            match refusal {
                RefusalFile::Remove => assert!(
                    !left.exists(),
                    "a page refusal left its file for a crashed pass to replay"
                ),
                RefusalFile::Keep => {
                    assert!(left.exists(), "an operator-kept refusal lost its file")
                }
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An outcome other than `applied`/`refused`, left by a crash between its
    /// line and the remove, is not appended a second time; only the remove
    /// remains.
    #[test]
    fn an_outcome_line_left_behind_is_not_appended_again() {
        let dir =
            std::env::temp_dir().join(format!("onboard-settle-outcome-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = quota_config(&dir);
        std::fs::create_dir_all(dir.join("store/intents")).unwrap();
        let store = Store::new_for_test(&cfg.store_root);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let value = json!({ "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "kind": "close" });
        let envelope = Envelope::of(&value, "settle.json", "close");

        for _ in 0..2 {
            std::fs::write(dir.join("store/intents/settle.json"), "{}").unwrap();
            let journal = runtime.block_on(Journal::load(&store)).unwrap();
            runtime
                .block_on(settle(
                    &cfg,
                    &store,
                    &journal,
                    "settle.json",
                    &envelope,
                    Disposition::new(AfterLine::Nothing, RefusalFile::Keep),
                    async {
                        Ok(Settlement::line(
                            "already-decided",
                            ApplicationRef::account("secretary".to_string()),
                            None,
                        ))
                    },
                ))
                .unwrap();
        }

        let text = std::fs::read_to_string(dir.join("store/journal.jsonl")).unwrap();
        assert_eq!(
            text.matches("\"outcome\":\"already-decided\"").count(),
            1,
            "a second outcome line was appended: {text}"
        );
        assert!(
            !dir.join("store/intents/settle.json").exists(),
            "the settled intent was left in place"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A held payment's attribution is after-line work: a pass that finds the
    /// applied line and the intent file still marks the held line attributed,
    /// then removes the file, and appends nothing.
    #[test]
    fn a_surviving_line_still_marks_the_held_item() {
        let dir =
            std::env::temp_dir().join(format!("onboard-settle-attrib-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = quota_config(&dir);
        std::fs::create_dir_all(dir.join("store/intents")).unwrap();
        std::fs::create_dir_all(dir.join("store/ledger")).unwrap();
        std::fs::write(
            dir.join("store/ledger/unattributed.jsonl"),
            "{\"version\":1,\"id\":\"UN-3K7QW2M9\",\"kind\":\"held\",\"state\":\"held\",\"rail\":\"cash\",\"amount_gbp\":\"20.00\",\"received_on\":\"2026-10-04\",\"intent\":\"01HZZZZZZZZZZZZZZZZZZZZZZZ\",\"note\":\"the envelope\"}\n",
        )
        .unwrap();
        std::fs::write(dir.join("store/intents/settle.json"), "{}").unwrap();
        std::fs::write(
            dir.join("store/journal.jsonl"),
            "{\"version\":1,\"at\":\"2026-11-04T09:00:00Z\",\"intent\":\"01HZZZZZZZZZZZZZZZZZZZZZZZ\",\"kind\":\"reconcile-attribute\",\"release\":\"test\",\"application\":{\"username\":\"secretary\",\"status_token\":\"\"},\"outcome\":\"applied\"}\n",
        )
        .unwrap();
        let store = Store::new_for_test(&cfg.store_root);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let journal = runtime.block_on(Journal::load(&store)).unwrap();
        let value = json!({
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "kind": "reconcile-attribute",
        });
        let envelope = Envelope::of(&value, "settle.json", "reconcile-attribute");

        runtime
            .block_on(settle(
                &cfg,
                &store,
                &journal,
                "settle.json",
                &envelope,
                Disposition::new(
                    AfterLine::MarkAttributed {
                        item: "UN-3K7QW2M9".to_string(),
                        token: "KYR-AAAA-BBBB-CCCC".to_string(),
                    },
                    RefusalFile::Keep,
                ),
                async { Err("the body ran on a settled intent".to_string()) },
            ))
            .unwrap();

        let held = runtime.block_on(store.held()).unwrap();
        assert_eq!(held.len(), 1, "{held:?}");
        assert_eq!(held[0].state, "attributed", "{held:?}");
        assert_eq!(held[0].attributed_to.as_deref(), Some("KYR-AAAA-BBBB-CCCC"));
        assert!(!dir.join("store/intents/settle.json").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
