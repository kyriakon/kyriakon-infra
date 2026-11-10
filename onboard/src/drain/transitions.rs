//! The drain's settlement seam: one intent file, one proved body, one journal
//! line, one remove.
//!
//! [`settle`] is the only writer of an intent's outcome. A body lives in the
//! module that owns its job, one of [`payments`], [`groups`], [`lifecycle`],
//! [`review`] or [`stripe`], and returns a [`Settlement`]. The dedup, the
//! after-line work and the file's disposition stay here. The retry schedule and
//! the failure report are the other half of the same seam.

use crate::config::DrainConfig;
use crate::mail::notice;
use crate::store::journal::Journal;
use crate::store::{ApplicationRef, JournalLine, Store};
use crate::util;
use serde_json::Value;
use std::future::Future;
use time::Duration;
use time::OffsetDateTime;

pub mod boxrun;
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
mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drain::transitions::test_support::quota_config;
    use serde_json::json;

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
