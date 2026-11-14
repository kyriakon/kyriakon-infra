//! The journal, indexed once for a pass.
//!
//! `journal.jsonl` stays the record: every append still lands in the file, in
//! order. This is what a pass asks of it — whether an id has an outcome, whether
//! it has any line, how often it has failed and when, whether a review mark
//! stands, and the values a credit recorded — so the six readers that used to
//! open and scan the file, several times per intent, ask an index instead.
//!
//! Loaded once per pass by [`kyriakon_control_drain::run`]. [`Journal::append`] writes
//! the line and updates the index, so a query later in the same pass sees it.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::store::{CreditProgress, Error, JournalLine, Store};

/// The journal's lines, indexed by intent id. The index is behind a lock only
/// because [`Journal::append`] takes `&self`; it is never held across an await.
pub struct Journal {
    index: Mutex<Index>,
}

#[derive(Default)]
struct Index {
    /// The number of lines indexed so far, which is the next line's position.
    lines: usize,
    /// Intent id → the outcomes recorded for it.
    outcomes: HashMap<String, HashSet<String>>,
    /// Intent id → the failed passes recorded against it.
    failures: HashMap<String, Failure>,
    /// Intent id → the positions of its failed lines, in file order.
    failed_at: HashMap<String, Vec<usize>>,
    /// (status token, kind, outcome) → (position, intent id) for each line.
    marks: HashMap<(String, String, String), Vec<(usize, String)>>,
    /// Status token → the username its approval began under.
    started: HashMap<String, String>,
    /// Status token → the covered fields its review mail described.
    reviews: HashMap<String, crate::account::sign::Reviewed>,
    /// Intent id → the progress its first `applying` credit line carried.
    credits: HashMap<String, CreditProgress>,
}

#[derive(Default, Clone)]
struct Failure {
    count: u32,
    last: Option<OffsetDateTime>,
    message: Option<String>,
}

impl Index {
    fn remember(&mut self, at: usize, line: &JournalLine) {
        self.lines = at + 1;
        self.outcomes
            .entry(line.intent.clone())
            .or_default()
            .insert(line.outcome.clone());
        if line.outcome == "failed" {
            let failure = self.failures.entry(line.intent.clone()).or_default();
            failure.count += 1;
            if let Ok(when) = OffsetDateTime::parse(&line.at, &Rfc3339) {
                failure.last = Some(when);
            }
            if line.note.is_some() {
                failure.message = line.note.clone();
            }
            self.failed_at
                .entry(line.intent.clone())
                .or_default()
                .push(at);
        }
        if line.outcome == "applying" && (line.kind == "approve" || line.kind == "provision") {
            if let Some(token) = line.application.status_token.as_deref() {
                // The first line wins: it names the account the approval began,
                // and a later retry under a rewritten record must not replace
                // it. The line is root-written from the signed decision.
                self.started
                    .entry(token.to_string())
                    .or_insert_with(|| line.application.username.clone());
            }
        }
        if line.outcome == "review-sent" {
            if let (Some(token), Some(review)) = (
                line.application.status_token.as_deref(),
                line.review.clone(),
            ) {
                // The first mail wins: the mark is written before the send and
                // an application is mailed once, so a later line for the same
                // token cannot describe a different record as the reviewed one.
                self.reviews.entry(token.to_string()).or_insert(review);
            }
        }
        if line.outcome == "applying" {
            if let Some(credit) = line.credit.clone() {
                self.credits.entry(line.intent.clone()).or_insert(credit);
            }
        }
        // Only a real capability token is a mark's key. An old line that put a
        // group domain in this field is not one, and indexing it would make the
        // review mail's dedup hold a name where a token is expected.
        if let Some(token) = line.application.status_token.as_deref() {
            if crate::store::is_status_token(token) {
                self.marks
                    .entry((token.to_string(), line.kind.clone(), line.outcome.clone()))
                    .or_default()
                    .push((at, line.intent.clone()));
            }
        }
    }
}

impl Journal {
    /// Read the journal once. A missing file is an empty journal; an unreadable
    /// one, or a line that does not parse, is an error: dedup that read an
    /// unreadable record as empty would fail open, which is #513.
    pub async fn load(store: &Store) -> Result<Journal, Error> {
        let mut index = Index::default();
        store
            .log("journal.jsonl")
            .jsonl_each(|at, line: &JournalLine| index.remember(at, line))
            .await?;
        Ok(Journal {
            index: Mutex::new(index),
        })
    }

    /// Append one line, then index it so a query later in the same pass sees
    /// it. The file is written first: the record is the truth.
    pub async fn append(&self, store: &Store, line: &JournalLine) -> Result<(), Error> {
        let encoded = serde_json::to_string(line).map_err(|source| Error::Encode {
            what: "a journal line",
            source,
        })?;
        store
            .log("journal.jsonl")
            .append(encoded.as_bytes())
            .await?;
        let mut index = self.lock();
        let at = index.lines;
        index.remember(at, line);
        Ok(())
    }

    /// Whether the journal already holds a line for this intent id with this
    /// outcome.
    pub fn has(&self, id: &str, outcome: &str) -> bool {
        self.lock()
            .outcomes
            .get(id)
            .is_some_and(|outcomes| outcomes.contains(outcome))
    }

    /// The failed passes recorded for an id: how many, when the last was, and
    /// what it said.
    pub fn failures(&self, id: &str) -> (u32, Option<OffsetDateTime>, Option<String>) {
        let index = self.lock();
        index.failures.get(id).map_or((0, None, None), |failure| {
            (failure.count, failure.last, failure.message.clone())
        })
    }

    /// Whether a review mark for this application stands: a line of this kind
    /// and outcome whose intent has not failed since it was written.
    ///
    /// Used for the review email, whose dedup key is the application and not the
    /// intent: a re-filed application must not be mailed twice either. The mark
    /// is written before the send on purpose, so a crash loses an email rather
    /// than sending two; a returned error is not a crash and leaves a `failed`
    /// line for its own intent, so a failure counts only when it comes after the
    /// mark. Order is the file's own: several lines of one pass share a
    /// timestamp.
    pub fn application_seen(&self, token: &str, kind: &str, outcome: &str) -> bool {
        let index = self.lock();
        let key = (token.to_string(), kind.to_string(), outcome.to_string());
        index.marks.get(&key).is_some_and(|marks| {
            marks.iter().any(|(at, id)| {
                !index
                    .failed_at
                    .get(id)
                    .is_some_and(|failed| failed.iter().any(|f| f > at))
            })
        })
    }

    /// The username this application's approval began under, if it began. The
    /// journal records "applying" after the name check and before provisioning,
    /// so a name that is on the box and has that line is one this application
    /// made, and the retry continues with it rather than refusing it as taken.
    ///
    /// The name is returned rather than a bare bool. The record in
    /// `applications/<token>.json` belongs to the unprivileged handler, and a
    /// retry that trusted a token-keyed yes would let a record rewritten to
    /// another name adopt the account this application made under the first.
    /// The caller compares the two and refuses the rewrite.
    ///
    /// The kind is matched as well. Three transitions write that word for a token:
    /// the approval, the decline and the purge. Without the kind, a decline that
    /// could not finish would make a later approval of the same application believe
    /// the account on the box was its own, and it would adopt a name this
    /// application never made.
    pub fn approval_started(&self, token: &str) -> Option<String> {
        self.lock().started.get(token).cloned()
    }

    /// The fields this application's review mail described, if a release that
    /// records them wrote its `review-sent` line. The console compares the
    /// record against them before signing, because the record belongs to the
    /// handler and can be rewritten after the mail.
    pub fn reviewed(&self, token: &str) -> Option<crate::account::sign::Reviewed> {
        self.lock().reviews.get(token).cloned()
    }

    /// The values a credit recorded on its `applying` line, if it has got that
    /// far.
    pub fn credit_progress(&self, id: &str) -> Option<CreditProgress> {
        self.lock().credits.get(id).cloned()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Index> {
        // The index is only ever held for a lookup or one insertion, so a panic
        // poisoning it leaves nothing half-written to protect against.
        self.index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Action, ApplicationRef};

    fn store(name: &str) -> (Store, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("onboard-journal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (Store::new_for_test(dir.to_str().unwrap()), dir)
    }

    /// A capability token from the production alphabet, not a string that only
    /// looks like one, so the index's shape check is exercised.
    const TOKEN: &str = "0123456789abcdefghjkmnpqrs";

    fn line(id: &str, kind: &str, outcome: &str, note: Option<&str>) -> JournalLine {
        line_for(
            id,
            kind,
            outcome,
            note,
            ApplicationRef::application("member", TOKEN),
        )
    }

    fn line_for(
        id: &str,
        kind: &str,
        outcome: &str,
        note: Option<&str>,
        application: ApplicationRef,
    ) -> JournalLine {
        JournalLine {
            version: 1,
            at: "2026-11-04T00:00:00Z".to_string(),
            intent: id.to_string(),
            kind: kind.to_string(),
            release: "test".to_string(),
            application,
            outcome: outcome.to_string(),
            note: note.map(str::to_string),
            review: None,
            credit: None,
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// The index answers what the six scans answered, and an append is visible
    /// to the queries that follow it in the same pass.
    #[test]
    fn append_updates_the_index_and_the_queries_read_it() {
        let (store, dir) = store("append");
        runtime().block_on(async {
            let journal = Journal::load(&store).await.unwrap();
            assert!(!journal.has("01H", "applied"));
            journal
                .append(&store, &line("01H", "credit", "applied", None))
                .await
                .unwrap();
            assert!(journal.has("01H", "applied"));
            assert!(journal.application_seen(TOKEN, "credit", "applied"));
            journal
                .append(
                    &store,
                    &line(
                        "01H",
                        "credit",
                        "failed",
                        Some("the ledger would not write"),
                    ),
                )
                .await
                .unwrap();
            let (count, last, message) = journal.failures("01H");
            assert_eq!(count, 1);
            assert!(last.is_some());
            assert_eq!(message.as_deref(), Some("the ledger would not write"));
            assert!(
                !journal.application_seen(TOKEN, "credit", "applied"),
                "a failure after the mark unseats it, as the scan did"
            );
        });
        // The file is the record: a fresh load answers the same.
        let reloaded = runtime().block_on(Journal::load(&store)).unwrap();
        assert!(reloaded.has("01H", "failed"));
        assert_eq!(reloaded.failures("01H").0, 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A failed line is the reason the next pass retries, not a settlement.
    #[test]
    fn a_failed_line_is_not_a_settlement() {
        let (store, dir) = store("failed");
        runtime().block_on(async {
            let journal = Journal::load(&store).await.unwrap();
            journal
                .append(&store, &line("01H", "credit", "failed", Some("boom")))
                .await
                .unwrap();
            assert!(!journal.has("01H", "applied"));
            assert_eq!(journal.failures("01H").0, 1);
        });
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An unreadable journal is an error at load, not an empty journal: dedup
    /// that read it as empty would fail open (#513).
    #[test]
    fn an_unreadable_journal_is_an_error() {
        let (store, dir) = store("unreadable");
        // A directory where the record should be: every read of it fails.
        std::fs::create_dir_all(dir.join("journal.jsonl")).unwrap();
        let err = match runtime().block_on(Journal::load(&store)) {
            Ok(_) => panic!("an unreadable journal loaded as empty"),
            Err(e) => e,
        };
        assert!(
            matches!(&err, Error::Io { action: Action::Read, path, .. } if path.ends_with("journal.jsonl")),
            "{err}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An old journal wrote `status_token` as a plain string, sometimes a group
    /// domain there. Every such line still loads and dedups by intent id, and
    /// only a real token reaches the marks index.
    #[test]
    fn an_old_string_status_token_still_loads_and_only_tokens_are_indexed() {
        let (store, dir) = store("old-shape");
        let text = format!(
            "{{\"version\":1,\"at\":\"2026-11-04T00:00:00Z\",\"intent\":\"01H\",\"kind\":\"application\",\"release\":\"old\",\"application\":{{\"username\":\"warden\",\"status_token\":\"{TOKEN}\"}},\"outcome\":\"review-sent\"}}\n\
             {{\"version\":1,\"at\":\"2026-11-04T00:00:01Z\",\"intent\":\"01J\",\"kind\":\"provision-group\",\"release\":\"old\",\"application\":{{\"username\":\"warden\",\"status_token\":\"parish.example\"}},\"outcome\":\"applied\"}}\n\
             {{\"version\":1,\"at\":\"2026-11-04T00:00:02Z\",\"intent\":\"01K\",\"kind\":\"set-password\",\"release\":\"old\",\"application\":{{\"username\":\"secretary\",\"status_token\":\"\"}},\"outcome\":\"refused\"}}\n"
        );
        std::fs::write(dir.join("journal.jsonl"), text).unwrap();
        let journal = runtime().block_on(Journal::load(&store)).unwrap();
        assert!(
            journal.has("01H", "review-sent"),
            "an old string token still dedups"
        );
        assert!(journal.application_seen(TOKEN, "application", "review-sent"));
        assert!(
            journal.has("01J", "applied"),
            "a group line that put its domain in the token field still loads"
        );
        assert!(
            !journal.application_seen("parish.example", "provision-group", "applied"),
            "a domain is not a capability token and is not indexed as one"
        );
        assert!(journal.has("01K", "refused"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A group subject and a page subject write their own fields: no domain and
    /// no blank is ever stored as the token.
    #[test]
    fn a_group_and_a_page_subject_store_no_token_field() {
        let (store, dir) = store("truthful");
        runtime().block_on(async {
            let journal = Journal::load(&store).await.unwrap();
            journal
                .append(
                    &store,
                    &line_for(
                        "01H",
                        "provision-group",
                        "applied",
                        None,
                        ApplicationRef::group("warden", "parish.example"),
                    ),
                )
                .await
                .unwrap();
            journal
                .append(
                    &store,
                    &line_for(
                        "01J",
                        "set-password",
                        "applied",
                        None,
                        ApplicationRef::account("secretary"),
                    ),
                )
                .await
                .unwrap();
        });
        let text = std::fs::read_to_string(dir.join("journal.jsonl")).unwrap();
        assert!(
            !text.contains("status_token"),
            "a non-token subject wrote a token field: {text}"
        );
        assert!(
            text.contains("\"domain\":\"parish.example\""),
            "the group's subject lost its domain: {text}"
        );
        assert!(
            text.contains("\"username\":\"secretary\""),
            "the page's subject lost its account: {text}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An approval's `applying` line is indexed with the name it began under,
    /// which is what lets a retry refuse a record rewritten to another account.
    /// The first name wins, and a decline's line is not an approval.
    #[test]
    fn an_applying_line_remembers_the_name_the_approval_began_under() {
        let (store, dir) = store("started");
        runtime().block_on(async {
            let journal = Journal::load(&store).await.unwrap();
            assert_eq!(journal.approval_started(TOKEN), None);
            journal
                .append(
                    &store,
                    &line_for(
                        "01H",
                        "approve",
                        "applying",
                        None,
                        ApplicationRef::application("secretary", TOKEN),
                    ),
                )
                .await
                .unwrap();
            assert_eq!(
                journal.approval_started(TOKEN).as_deref(),
                Some("secretary")
            );
            // A later line cannot rename the account the approval began; the
            // account was made under the first name.
            journal
                .append(
                    &store,
                    &line_for(
                        "01J",
                        "provision",
                        "applying",
                        None,
                        ApplicationRef::application("www", TOKEN),
                    ),
                )
                .await
                .unwrap();
            assert_eq!(
                journal.approval_started(TOKEN).as_deref(),
                Some("secretary"),
                "a later name replaced the one the approval began under"
            );
            // A decline's "applying" line is not an approval.
            let declined = "0123456789abcdefghjkmnpqrt";
            journal
                .append(
                    &store,
                    &line_for(
                        "01K",
                        "decline",
                        "applying",
                        None,
                        ApplicationRef::application("www", declined),
                    ),
                )
                .await
                .unwrap();
            assert_eq!(
                journal.approval_started(declined),
                None,
                "a decline began an approval"
            );
        });
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The review line's covered fields are indexed by token, so the console can
    /// compare a record against what the mail described. An older line without
    /// them answers `None`, and a later line cannot replace the first.
    #[test]
    fn a_review_line_remembers_the_fields_the_mail_described() {
        use crate::account::sign::Reviewed;
        let (store, dir) = store("reviewed");
        runtime().block_on(async {
            let journal = Journal::load(&store).await.unwrap();
            assert_eq!(journal.reviewed(TOKEN), None);
            let reviewed = Reviewed {
                no_charge: false,
                rail: "cash".to_string(),
                domain: String::new(),
                outside_address: String::new(),
                answers: "aa".to_string(),
                keys: "bb".to_string(),
            };
            let mut first = line("01H", "application", "review-sent", None);
            first.review = Some(reviewed.clone());
            journal.append(&store, &first).await.unwrap();
            assert_eq!(journal.reviewed(TOKEN), Some(reviewed.clone()));
            let mut later = line("01J", "application", "review-sent", None);
            later.review = Some(Reviewed {
                no_charge: true,
                ..reviewed.clone()
            });
            journal.append(&store, &later).await.unwrap();
            assert_eq!(
                journal.reviewed(TOKEN),
                Some(reviewed),
                "a later line replaced the fields the mail described"
            );
        });
        std::fs::remove_dir_all(dir).unwrap();
    }
}
