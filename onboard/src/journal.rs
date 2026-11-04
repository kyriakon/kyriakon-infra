//! The journal, indexed once for a pass.
//!
//! `journal.jsonl` stays the record: every append still lands in the file, in
//! order. This is what a pass asks of it — whether an id has an outcome, whether
//! it has any line, how often it has failed and when, whether a review mark
//! stands, and the values a credit recorded — so the six readers that used to
//! open and scan the file, several times per intent, ask an index instead.
//!
//! Loaded once per pass by [`crate::intents::run`]. [`Journal::append`] writes
//! the line and updates the index, so a query later in the same pass sees it.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::store::{CreditProgress, JournalLine, Store};

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
    /// Intent ids with at least one line that is not a failure.
    seen: HashSet<String>,
    /// Intent id → the failed passes recorded against it.
    failures: HashMap<String, Failure>,
    /// Intent id → the positions of its failed lines, in file order.
    failed_at: HashMap<String, Vec<usize>>,
    /// (status token, kind, outcome) → (position, intent id) for each line.
    marks: HashMap<(String, String, String), Vec<(usize, String)>>,
    /// Status tokens whose approval has an `applying` line.
    started: HashSet<String>,
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
        if line.outcome != "failed" {
            self.seen.insert(line.intent.clone());
        }
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
            self.started.insert(line.application.status_token.clone());
        }
        if line.outcome == "applying" {
            if let Some(credit) = line.credit.clone() {
                self.credits.entry(line.intent.clone()).or_insert(credit);
            }
        }
        if !line.application.status_token.is_empty() {
            self.marks
                .entry((
                    line.application.status_token.clone(),
                    line.kind.clone(),
                    line.outcome.clone(),
                ))
                .or_default()
                .push((at, line.intent.clone()));
        }
    }
}

impl Journal {
    /// Read the journal once. A missing file is an empty journal; an unreadable
    /// one, or a line that does not parse, is an error: dedup that read an
    /// unreadable record as empty would fail open, which is #513.
    pub async fn load(store: &Store) -> Result<Journal, String> {
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
    pub async fn append(&self, store: &Store, line: &JournalLine) -> Result<(), String> {
        let encoded = serde_json::to_string(line)
            .map_err(|e| format!("cannot encode a journal line: {e}"))?;
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

    /// Whether this id has any line that is not a failure. A failed line is the
    /// reason the next pass retries, not a settlement.
    pub fn seen(&self, id: &str) -> bool {
        self.lock().seen.contains(id)
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

    /// Whether this application's approval already began. The journal records
    /// "applying" after the name check and before provisioning, so a name that is
    /// on the box and has that line is one this application made, and the retry
    /// continues with it rather than refusing it as taken.
    ///
    /// The kind is matched as well. Three transitions write that word for a token:
    /// the approval, the decline and the purge. Without the kind, a decline that
    /// could not finish would make a later approval of the same application believe
    /// the account on the box was its own, and it would adopt a name this
    /// application never made.
    pub fn approval_started(&self, token: &str) -> bool {
        self.lock().started.contains(token)
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
