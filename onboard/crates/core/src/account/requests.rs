//! The data-subject request record: one line per request in the account's store
//! directory, and the one-month clock that line carries.
//!
//! The spec is `docs/planning/specs/data-subject-requests.md`, "What gets
//! recorded". The console writes through here now; the page's export and close
//! intents write through the same functions when the drain carries them, so a
//! page-filed request and a scripted one cannot produce different lines.

use serde::{Deserialize, Serialize};
use time::{Date, Month, OffsetDateTime};

use crate::flow::validate;
use crate::store::Store;
use crate::Error;

/// The kinds the spec names. A portability request is recorded as `access`,
/// which is the pair the spec treats as one answer; the other two are separate.
const KINDS: [&str; 3] = ["access", "erasure", "rectification"];

/// The routes that establish who is asking. `password` is the page's check
/// against the system account; `mail-key` is a signed message from the
/// account's own platform address.
const IDENTITIES: [&str; 2] = ["password", "mail-key"];

/// What "nearly due" means in `request list`: the deletion path's own seven-day
/// wait, the only window the spec gives a number for.
const NEARLY_DUE_DAYS: i64 = 7;

/// One line of `accounts/<username>/requests.jsonl`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RequestLine {
    pub version: u32,
    /// A ULID: the handle `request close` takes and the line's own identity.
    pub id: String,
    pub username: String,
    pub kind: String,
    /// `YYYY-MM-DD`, the day the request arrived.
    pub received: String,
    /// What established who was asking: the page's password check, or a signed
    /// message from the account's own address.
    pub evidence: String,
    /// Which route established it: `password` or `mail-key`. Absent on lines
    /// written before the field existed, so those still read.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity: String,
    /// The latest of receipt, the identity information asked for, and any fee:
    /// Article 12A's "relevant time".
    pub relevant: String,
    /// One calendar month from `relevant`, `YYYY-MM-DD`.
    pub due: String,
    /// Two further months beyond `due`, where a complex request was extended
    /// under Article 12A. Absent until `request extend`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_until: Option<String>,
    /// The day the extension was decided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_at: Option<String>,
    /// Why the request is complex enough for the extra two months.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_at: Option<String>,
    /// What was done, and on what date. Absent until `request close`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub done: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub done_at: Option<String>,
    /// How an export was delivered, where there was one. `onboardctl export
    /// --request <id>` fills it through `set_bundle`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
}

impl RequestLine {
    /// The answer date in force: the extension's date where there is one.
    pub fn effective_due(&self) -> &str {
        self.extended_until.as_deref().unwrap_or(&self.due)
    }

    /// How the request stands, read from the date in force, so `request list`
    /// and its counts cannot use the superseded clock.
    pub fn state(&self, today: Date) -> Result<DueState, Error> {
        Ok(due_state(parse_date(self.effective_due())?, today))
    }
}

/// What `record` is given, kept as one value because the call has more fields
/// than a positional signature can carry legibly.
pub struct NewRequest<'a> {
    pub username: &'a str,
    pub kind: &'a str,
    pub received: &'a str,
    pub evidence: &'a str,
    /// The route that established the sender: `password` or `mail-key`. A
    /// record without one is refused.
    pub identity: &'a str,
    pub note: Option<&'a str>,
    pub identity_at: Option<&'a str>,
    pub fee_at: Option<&'a str>,
    /// The id a retry reuses. Absent on a first record, where the module draws
    /// a ULID; present, an id already in the account's file is refused rather
    /// than appended a second time.
    pub id: Option<&'a str>,
}

/// Today in UTC. One function so `list` and its tests read the same clock.
pub fn today() -> Date {
    OffsetDateTime::now_utc().date()
}

/// `YYYY-MM-DD`, the form every date in this record takes.
pub fn parse_date(value: &str) -> Result<Date, Error> {
    let bad = || format!("{value:?} is not a date in YYYY-MM-DD");
    if value.len() != 10 || !value.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return Err(Error::Failed(bad()));
    }
    let year: i32 = value[0..4].parse().map_err(|_| Error::Failed(bad()))?;
    let month: u8 = value[5..7].parse().map_err(|_| Error::Failed(bad()))?;
    let day: u8 = value[8..10].parse().map_err(|_| Error::Failed(bad()))?;
    let month = Month::try_from(month).map_err(|_| Error::Failed(bad()))?;
    Date::from_calendar_date(year, month, day).map_err(|_| Error::Failed(bad()))
}

fn format_date(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// `months` calendar months later, clamping the day to the target month's
/// length: the 31st of January answers by the 28th of February, and by the 29th
/// in a leap year. Article 12's month is a calendar month, not thirty days.
/// `None` when the target is off the end of the calendar, so a record holding
/// 9999 is refused rather than panicking the console.
fn months_after(date: Date, months: u8) -> Option<Date> {
    let index = date.year() * 12 + i32::from(u8::from(date.month())) - 1 + i32::from(months);
    let year = index.div_euclid(12);
    let month = Month::try_from((index.rem_euclid(12) + 1) as u8).ok()?;
    let last = month.length(year);
    Date::from_calendar_date(year, month, date.day().min(last)).ok()
}

fn one_month_after(date: Date) -> Option<Date> {
    months_after(date, 1)
}

/// The day the clock starts: the latest of receipt, the identity information
/// asked for, and any fee. Article 12A's "relevant time".
fn relevant_time(received: Date, identity_at: Option<Date>, fee_at: Option<Date>) -> Date {
    [Some(received), identity_at, fee_at]
        .into_iter()
        .flatten()
        .max()
        .expect("receipt is always present")
}

/// How a request stands against its answer day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DueState {
    Open,
    NearlyDue,
    Overdue,
}

/// The state `request list` prints. Overdue is separate from nearly due, so the
/// summary cannot call a lapsed request merely close.
pub fn due_state(due: Date, today: Date) -> DueState {
    let days = (due - today).whole_days();
    if days < 0 {
        DueState::Overdue
    } else if days <= NEARLY_DUE_DAYS {
        DueState::NearlyDue
    } else {
        DueState::Open
    }
}

fn account_dir(username: &str) -> String {
    format!("accounts/{username}")
}

/// The answer an erasure request carries, shown by the page when the closure is
/// filed and journalled by the deletion transition. It names the three things
/// that outlive the account, because silence would read as an instant and total
/// delete, and it states the refund position beside them.
///
/// `refund` is the ledger's own sentence where a refund line exists; `None` says
/// plainly that closing does not refund anything by itself.
pub fn erasure_answer(refund: Option<&str>) -> String {
    let refund = refund.unwrap_or(
        "No refund is due: closing the account does not itself refund money already paid. A refund is a separate decision and would be recorded on its own.",
    );
    format!(
        "Your account and the data the platform holds about it are being erased.\n\
         \n\
         Three things outlive the account, and you should know them.\n\
         \n\
         The backup repository keeps a copy of your home directory until its snapshot expires. It is content-addressed and cannot delete one member's files, so your home can survive there for about seven months.\n\
         \n\
         The payment ledger keeps one dated line for each payment: the amount, the date, the rail and the paid-until date, with no username, contact address or name. That line survives, and it no longer resolves to you.\n\
         \n\
         Your username is held for 90 days and then released, so nobody else can take it in that time.\n\
         \n\
         {refund}\n"
    )
}

fn record_path(username: &str) -> String {
    format!("{}/requests.jsonl", account_dir(username))
}

/// Read one account's request lines. The reader's rule is the store's: a missing
/// file is an empty record, and a record that cannot be read or parsed is an
/// error, because a record the command cannot see must not read as a clear
/// docket.
async fn read_all(store: &Store, username: &str) -> Result<Vec<RequestLine>, Error> {
    store
        .log(&record_path(username))
        .jsonl()
        .await
        .map_err(Error::from)
}

/// Append one request line and return it, so the caller can print the due date.
pub async fn record(store: &Store, request: NewRequest<'_>) -> Result<RequestLine, Error> {
    if let Some(why) = validate::username_shape(request.username) {
        return Err(Error::Failed(format!(
            "the username {:?}: {why}",
            request.username
        )));
    }
    if !KINDS.contains(&request.kind) {
        return Err(Error::Failed(format!(
            "the kind {:?} is not one of {}",
            request.kind,
            KINDS.join(", ")
        )));
    }
    let evidence = request.evidence.trim();
    if evidence.is_empty() {
        return Err(Error::Failed(
            "the evidence that established who was asking is needed".to_string(),
        ));
    }
    let identity = request.identity.trim();
    if !IDENTITIES.contains(&identity) {
        return Err(Error::Failed(format!(
            "the identity route {identity:?} is not one of {}",
            IDENTITIES.join(", ")
        )));
    }
    // A request is recorded against an account, never into a directory a
    // mistyped name would create.
    if store.account(request.username).await?.is_none() {
        return Err(Error::Failed(format!(
            "no account for {}",
            request.username
        )));
    }

    let id = match request.id {
        Some(raw) => ulid::Ulid::from_string(raw)
            .map_err(|e| Error::context(format!("the id {raw:?}"), e))?
            .to_string(),
        None => ulid::Ulid::new().to_string(),
    };
    let received = parse_date(request.received)?;
    let identity_at = request.identity_at.map(parse_date).transpose()?;
    let fee_at = request.fee_at.map(parse_date).transpose()?;
    let relevant = relevant_time(received, identity_at, fee_at);
    let due = one_month_after(relevant).ok_or_else(|| {
        Error::Failed(format!(
            "the answer due after {} has no date in the calendar",
            format_date(relevant)
        ))
    })?;

    let line = RequestLine {
        version: 1,
        id,
        username: request.username.to_string(),
        kind: request.kind.to_string(),
        received: format_date(received),
        evidence: evidence.to_string(),
        identity: identity.to_string(),
        relevant: format_date(relevant),
        due: format_date(due),
        extended_until: None,
        extended_at: None,
        extended_reason: None,
        note: request
            .note
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_string),
        identity_at: identity_at.map(format_date),
        fee_at: fee_at.map(format_date),
        done: None,
        done_at: None,
        bundle: None,
    };
    let path = record_path(&line.username);
    let log = store.log(&path);
    let _guard = log.lock().await?;
    // A retry that carries an id must not write the same request twice. The
    // read is under the record's own lock, which the append also takes, so it
    // sees a record that another process lands first.
    if request.id.is_some() {
        let existing = log.jsonl::<RequestLine>().await?;
        if existing.iter().any(|l| l.id == line.id) {
            return Err(Error::Failed(format!(
                "request {} is already recorded",
                line.id
            )));
        }
    }
    let bytes =
        serde_json::to_vec(&line).map_err(|e| Error::context("cannot write the request", e))?;
    log.append_while_locked(&_guard, &bytes).await?;
    Ok(line)
}

/// The account whose record holds one request id. The read happens before the
/// lock, and again under it in `rewrite`.
async fn find_account(store: &Store, id: &str) -> Result<String, Error> {
    let mut found: Option<String> = None;
    for username in store.list("accounts").await? {
        if !read_all(store, &username).await?.iter().any(|l| l.id == id) {
            continue;
        }
        if found.is_some() {
            return Err(Error::Failed(format!(
                "request {id} appears in more than one account"
            )));
        }
        found = Some(username);
    }
    found.ok_or_else(|| Error::Failed(format!("no request with id {id}")))
}

/// Rewrite one request's line under the record's lock, through `change`.
///
/// The file is one line per request, not one line per event, so a change
/// rewrites that request's line and leaves the others as they were. This is one
/// of the three writes `Store::rewrite_log` exists for, and the whole read and
/// write happen under the record's lock, so a concurrent append is not dropped.
async fn rewrite(
    store: &Store,
    id: &str,
    change: impl FnOnce(&mut RequestLine) -> Result<(), Error>,
) -> Result<RequestLine, Error> {
    let username = find_account(store, id).await?;
    let path = record_path(&username);
    let log = store.log(&path);
    let _guard = log.lock().await?;
    let mut lines = log.jsonl::<RequestLine>().await?;
    let at = lines
        .iter()
        .position(|l| l.id == id)
        .ok_or_else(|| Error::Failed(format!("no request with id {id}")))?;
    change(&mut lines[at])?;

    let mut bytes = String::new();
    for line in &lines {
        bytes.push_str(
            &serde_json::to_string(line)
                .map_err(|e| Error::context("cannot write the request record", e))?,
        );
        bytes.push('\n');
    }
    store
        .rewrite_log(&record_path(&username), bytes.as_bytes())
        .await?;
    Ok(lines[at].clone())
}

/// Record how an export was delivered on the request's own line, under the same
/// lock a close takes. The account is checked against the line the id names, so
/// a mistyped id cannot write one member's delivery onto another's request.
pub async fn set_bundle(
    store: &Store,
    id: &str,
    username: &str,
    bundle: &str,
) -> Result<RequestLine, Error> {
    rewrite(store, id, |line| {
        if line.username != username {
            return Err(Error::Failed(format!(
                "the request {id} belongs to {}, not {username}",
                line.username
            )));
        }
        line.bundle = Some(bundle.to_string());
        Ok(())
    })
    .await
}

/// Write what was done onto the request's own line, and return the closed line.
pub async fn close(
    store: &Store,
    id: &str,
    done_at: &str,
    done: &str,
) -> Result<RequestLine, Error> {
    let done = done.trim().to_string();
    if done.is_empty() {
        return Err(Error::Failed("what was done is needed".to_string()));
    }
    let done_at = format_date(parse_date(done_at)?);
    rewrite(store, id, |line| {
        if line.done.is_some() {
            return Err(Error::Failed(format!("request {id} is already closed")));
        }
        line.done = Some(done);
        line.done_at = Some(done_at);
        Ok(())
    })
    .await
}

/// Record Article 12A's two further months on the request's own line.
///
/// The extra period runs from the current answer date, so the total does not
/// pass three months from the relevant time, and a second extension is refused
/// rather than letting the clock move again.
pub async fn extend(
    store: &Store,
    id: &str,
    reason: &str,
    extended_at: Option<&str>,
) -> Result<RequestLine, Error> {
    let reason = reason.trim().to_string();
    if reason.is_empty() {
        return Err(Error::Failed(
            "the reason for the extension is needed".to_string(),
        ));
    }
    let decided = match extended_at {
        Some(value) => parse_date(value)?,
        None => today(),
    };
    let at = format_date(decided);
    rewrite(store, id, |line| {
        if line.done.is_some() {
            return Err(Error::Failed(format!("request {id} is closed")));
        }
        if line.extended_until.is_some() {
            return Err(Error::Failed(format!("request {id} is already extended")));
        }
        // The extension is Article 12A's two further months inside the answer
        // period, so a decision that predates receipt or lands after the answer
        // was due is not one: recording it would move a clock that had already
        // run out, and `request list` would stop showing the deadline missed.
        let received = parse_date(&line.received)?;
        let due = parse_date(&line.due)?;
        if decided < received || decided > due {
            return Err(Error::Failed(format!(
                "the extension is decided on {}, but the request runs from {} to {}",
                format_date(decided),
                line.received,
                line.due
            )));
        }
        line.extended_until = Some(format_date(months_after(due, 2).ok_or_else(|| {
            Error::Failed(format!(
                "the extension of {} has no date in the calendar",
                format_date(due)
            ))
        })?));
        line.extended_at = Some(at);
        line.extended_reason = Some(reason);
        Ok(())
    })
    .await
}

/// Every request still open, earliest answer due first.
pub async fn open(store: &Store) -> Result<Vec<RequestLine>, Error> {
    let mut out = Vec::new();
    for username in store.list("accounts").await? {
        for line in read_all(store, &username).await? {
            if line.done.is_none() {
                out.push(line);
            }
        }
    }
    out.sort_by(|a, b| {
        a.effective_due()
            .cmp(b.effective_due())
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn d(s: &str) -> Date {
        parse_date(s).unwrap()
    }

    /// A store with one account, and a fresh directory per test.
    fn temp_store(name: &str) -> (Store, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("onboard-requests-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("accounts/alice")).unwrap();
        std::fs::write(
            dir.join("accounts/alice/account.json"),
            r#"{"version":1,"username":"alice","state":"active","decision":"approve",
                "decided_at":"2026-01-01T00:00:00Z","rail":"no_charge","no_charge":true,
                "created_at":"2026-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        (Store::new(dir.to_str().unwrap()), dir)
    }

    fn new_request<'a>(kind: &'a str, received: &'a str) -> NewRequest<'a> {
        NewRequest {
            username: "alice",
            kind,
            received,
            evidence: "signed message from the account address",
            identity: "mail-key",
            note: None,
            identity_at: None,
            fee_at: None,
            id: None,
        }
    }

    #[test]
    fn one_calendar_month_clamps_to_the_shorter_months_last_day() {
        assert_eq!(one_month_after(d("2026-10-22")).unwrap(), d("2026-11-22"));
        assert_eq!(one_month_after(d("2026-12-15")).unwrap(), d("2027-01-15"));
        assert_eq!(one_month_after(d("2026-01-31")).unwrap(), d("2026-02-28"));
        assert_eq!(one_month_after(d("2024-01-31")).unwrap(), d("2024-02-29"));
        assert_eq!(one_month_after(d("2026-03-31")).unwrap(), d("2026-04-30"));
        assert_eq!(one_month_after(d("2026-08-31")).unwrap(), d("2026-09-30"));
    }

    #[test]
    fn the_clock_starts_at_the_latest_relevant_time() {
        assert_eq!(
            one_month_after(relevant_time(d("2026-10-01"), None, None)).unwrap(),
            d("2026-11-01")
        );
        assert_eq!(
            one_month_after(relevant_time(d("2026-10-01"), Some(d("2026-10-09")), None)).unwrap(),
            d("2026-11-09")
        );
        // The fee arrived last, so the clock starts there, not at receipt.
        assert_eq!(
            relevant_time(
                d("2026-10-01"),
                Some(d("2026-10-09")),
                Some(d("2026-10-20"))
            ),
            d("2026-10-20")
        );
        assert_eq!(
            one_month_after(relevant_time(
                d("2026-10-01"),
                Some(d("2026-10-09")),
                Some(d("2026-10-20"))
            ))
            .unwrap(),
            d("2026-11-20")
        );
    }

    #[test]
    fn two_calendar_months_clamp_only_the_month_they_land_in() {
        assert_eq!(months_after(d("2026-12-31"), 2).unwrap(), d("2027-02-28"));
        // Clamping at each step would give 28 March: February's 28th is not a
        // day to count two calendar months from.
        assert_eq!(months_after(d("2026-01-31"), 2).unwrap(), d("2026-03-31"));
        assert_eq!(months_after(d("2026-11-30"), 2).unwrap(), d("2027-01-30"));
        assert_eq!(months_after(d("2028-01-31"), 2).unwrap(), d("2028-03-31"));
        // Off the end of the calendar: refused, not a panic.
        assert_eq!(months_after(d("9999-11-30"), 2), None);
    }

    #[tokio::test]
    async fn extend_moves_the_due_by_two_months_and_records_why() {
        let (store, dir) = temp_store("extend");
        let line = record(&store, new_request("access", "2026-11-30"))
            .await
            .unwrap();
        assert_eq!(line.due, "2026-12-30");

        let extended = extend(&store, &line.id, " complex request ", Some("2026-12-01"))
            .await
            .unwrap();
        assert_eq!(extended.due, "2026-12-30", "the original clock is kept");
        assert_eq!(extended.extended_until.as_deref(), Some("2027-02-28"));
        assert_eq!(extended.extended_at.as_deref(), Some("2026-12-01"));
        assert_eq!(extended.extended_reason.as_deref(), Some("complex request"));
        assert_eq!(extended.effective_due(), "2027-02-28");

        // The extension is written onto that line, not appended as an event.
        let lines = read_all(&store, "alice").await.unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], extended);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn an_extension_decided_outside_the_requests_month_is_refused() {
        let (store, dir) = temp_store("extend-window");
        let line = record(&store, new_request("access", "2026-10-01"))
            .await
            .unwrap();
        assert_eq!(line.due, "2026-11-01");

        for at in ["2026-09-30", "2026-11-02"] {
            let err = extend(&store, &line.id, "complex", Some(at))
                .await
                .unwrap_err();
            assert!(
                matches!(&err, Error::Failed(message) if message.contains("the request runs from")),
                "{at}: {err}"
            );
        }
        // The day it is due is still inside the month; the day after is not.
        extend(&store, &line.id, "complex", Some("2026-11-01"))
            .await
            .unwrap();
        let lines = read_all(&store, "alice").await.unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].extended_at.as_deref(), Some("2026-11-01"));
        assert_eq!(lines[0].extended_until.as_deref(), Some("2027-01-01"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_second_extension_and_a_closed_request_are_refused() {
        let (store, dir) = temp_store("extend-refusals");
        let first = record(&store, new_request("access", "2026-10-01"))
            .await
            .unwrap();
        extend(&store, &first.id, "complex", Some("2026-10-02"))
            .await
            .unwrap();
        let err = extend(&store, &first.id, "again", Some("2026-10-03"))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Failed(message) if message.contains("already extended")),
            "{err}"
        );

        let closed = record(&store, new_request("erasure", "2026-10-01"))
            .await
            .unwrap();
        close(&store, &closed.id, "2026-10-04", "done")
            .await
            .unwrap();
        let err = extend(&store, &closed.id, "complex", Some("2026-10-05"))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Failed(message) if message.contains("is closed")),
            "{err}"
        );

        let fresh = record(&store, new_request("rectification", "2026-10-01"))
            .await
            .unwrap();
        let err = extend(&store, &fresh.id, "  ", Some("2026-10-05"))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Failed(message) if message.contains("reason")),
            "{err}"
        );

        // No refusal moved a clock or appended a line.
        let lines = read_all(&store, "alice").await.unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].extended_until.as_deref(), Some("2027-01-01"));
        assert_eq!(lines[2], fresh);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn open_orders_and_states_by_the_extended_date() {
        let (store, dir) = temp_store("extend-order");
        let extended = record(&store, new_request("access", "2026-10-01"))
            .await
            .unwrap();
        let plain = record(&store, new_request("erasure", "2026-10-10"))
            .await
            .unwrap();
        let extended = extend(&store, &extended.id, "complex request", Some("2026-10-15"))
            .await
            .unwrap();
        assert_eq!(extended.extended_until.as_deref(), Some("2027-01-01"));

        let open = open(&store).await.unwrap();
        assert_eq!(
            open.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
            vec![plain.id.as_str(), extended.id.as_str()],
            "the extended request is no longer the first due"
        );

        // On 2026-11-05 the original date has passed but the extension has
        // not, so the list must read the extended date, not the superseded one.
        let today = d("2026-11-05");
        assert_eq!(due_state(d(&extended.due), today), DueState::Overdue);
        assert_eq!(extended.state(today).unwrap(), DueState::Open);
        assert_eq!(plain.state(today).unwrap(), DueState::NearlyDue);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_date_that_is_not_a_day_is_refused() {
        for bad in [
            "2026-02-30",
            "2026-13-01",
            "22-10-2026",
            "2026-1-1",
            "today",
            "",
        ] {
            assert!(parse_date(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[tokio::test]
    async fn record_appends_one_line_holding_the_clock_and_the_evidence() {
        let (store, dir) = temp_store("record");
        let line = record(&store, new_request("access", "2026-10-22"))
            .await
            .unwrap();
        assert_eq!(line.due, "2026-11-22");
        assert_eq!(line.relevant, "2026-10-22");
        assert_eq!(line.version, 1);
        let raw = store
            .log("accounts/alice/requests.jsonl")
            .jsonl::<RequestLine>()
            .await
            .unwrap();
        assert_eq!(raw, vec![line]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn record_with_a_later_identity_or_fee_moves_the_due_date() {
        let (store, dir) = temp_store("record-later");
        let mut request = new_request("erasure", "2026-10-01");
        request.identity_at = Some("2026-10-09");
        request.fee_at = Some("2026-10-20");
        let line = record(&store, request).await.unwrap();
        assert_eq!(line.relevant, "2026-10-20");
        assert_eq!(line.due, "2026-11-20");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn record_refuses_an_account_that_does_not_exist() {
        let (store, dir) = temp_store("record-no-account");
        let mut request = new_request("access", "2026-10-22");
        request.username = "nobody";
        let err = record(&store, request).await.unwrap_err();
        assert!(
            matches!(&err, Error::Failed(message) if message.contains("no account for nobody")),
            "{err}"
        );
        assert!(!dir.join("accounts/nobody").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn record_refuses_an_unknown_kind_and_a_missing_evidence() {
        let (store, dir) = temp_store("record-refusals");
        let err = record(&store, new_request("portability", "2026-10-22"))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Failed(message) if message.contains("access, erasure, rectification")),
            "{err}"
        );
        let mut request = new_request("access", "2026-10-22");
        request.evidence = "  ";
        assert!(record(&store, request).await.is_err());
        assert!(store
            .log("accounts/alice/requests.jsonl")
            .jsonl::<RequestLine>()
            .await
            .unwrap()
            .is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn record_refuses_a_missing_or_unknown_identity_route() {
        let (store, dir) = temp_store("record-identity");
        for identity in ["", "  ", "session-cookie"] {
            let mut request = new_request("access", "2026-10-22");
            request.identity = identity;
            let err = record(&store, request).await.unwrap_err();
            assert!(
                matches!(&err, Error::Failed(message) if message.contains("identity route")),
                "{identity:?}: {err}"
            );
        }
        assert!(store
            .log("accounts/alice/requests.jsonl")
            .jsonl::<RequestLine>()
            .await
            .unwrap()
            .is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn record_persists_the_route_that_established_the_sender() {
        let (store, dir) = temp_store("record-identity-persist");
        let line = record(&store, new_request("access", "2026-10-22"))
            .await
            .unwrap();
        assert_eq!(line.identity, "mail-key");
        // The route is on the line the next reader sees, not only in the return.
        let raw = store
            .log("accounts/alice/requests.jsonl")
            .raw_lines()
            .await
            .unwrap();
        assert!(raw[0].contains("\"identity\":\"mail-key\""), "{}", raw[0]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_line_written_before_the_identity_field_still_reads_and_lists() {
        let (store, dir) = temp_store("old-line");
        std::fs::write(
            dir.join("accounts/alice/requests.jsonl"),
            "{\"version\":1,\"id\":\"01ARZ3NDEKTSV4RRFFQ69G5FAV\",\
             \"username\":\"alice\",\"kind\":\"access\",\
             \"received\":\"2026-10-01\",\"evidence\":\"the account page\",\
             \"relevant\":\"2026-10-01\",\"due\":\"2026-11-01\"}\n",
        )
        .unwrap();
        let open = open(&store).await.unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].identity, "");
        assert_eq!(open[0].kind, "access");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn close_writes_onto_the_requests_own_line_and_leaves_the_others() {
        let (store, dir) = temp_store("close");
        let first = record(&store, new_request("access", "2026-10-01"))
            .await
            .unwrap();
        let second = record(&store, new_request("rectification", "2026-10-02"))
            .await
            .unwrap();

        let closed = close(&store, &first.id, "2026-10-05", "collected over sftp")
            .await
            .unwrap();
        assert_eq!(closed.done.as_deref(), Some("collected over sftp"));
        assert_eq!(closed.done_at.as_deref(), Some("2026-10-05"));

        let lines = store
            .log("accounts/alice/requests.jsonl")
            .jsonl::<RequestLine>()
            .await
            .unwrap();
        assert_eq!(
            lines.len(),
            2,
            "closing rewrites the line, it does not append"
        );
        assert_eq!(lines[0].id, first.id);
        assert_eq!(lines[0].done.as_deref(), Some("collected over sftp"));
        assert_eq!(lines[1], second, "the other request is untouched");

        // The clock does not move, and a closed request cannot be closed twice.
        assert_eq!(lines[0].due, first.due);
        assert!(close(&store, &first.id, "2026-10-06", "again")
            .await
            .is_err());
        assert!(close(&store, "not-a-request", "2026-10-06", "nothing")
            .await
            .is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn open_lists_the_unclosed_requests_earliest_answer_first() {
        let (store, dir) = temp_store("open");
        let late = record(&store, new_request("access", "2026-11-01"))
            .await
            .unwrap();
        let soon = record(&store, new_request("erasure", "2026-10-02"))
            .await
            .unwrap();
        let closed = record(&store, new_request("rectification", "2026-10-03"))
            .await
            .unwrap();
        close(&store, &closed.id, "2026-10-04", "corrected")
            .await
            .unwrap();

        let open = open(&store).await.unwrap();
        assert_eq!(
            open.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
            vec![soon.id.as_str(), late.id.as_str()]
        );
        assert!(open.iter().all(|l| l.done.is_none()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_list_separates_overdue_from_nearly_due() {
        let today = d("2026-10-22");
        assert_eq!(due_state(d("2026-10-21"), today), DueState::Overdue);
        assert_eq!(due_state(d("2026-10-22"), today), DueState::NearlyDue);
        assert_eq!(due_state(d("2026-10-29"), today), DueState::NearlyDue);
        assert_eq!(due_state(d("2026-10-30"), today), DueState::Open);
    }

    #[tokio::test]
    async fn an_unreadable_record_is_an_error_not_an_empty_docket() {
        let (store, dir) = temp_store("unreadable");
        // A directory where the file belongs. The read fails for every user,
        // including root, so the test does not depend on file permissions.
        std::fs::create_dir_all(dir.join("accounts/alice/requests.jsonl")).unwrap();
        let err = open(&store).await.unwrap_err();
        assert!(matches!(&err, Error::Store(_)), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_retry_with_the_same_id_does_not_write_a_second_line() {
        let (store, dir) = temp_store("record-retry");
        let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let mut first = new_request("access", "2026-10-22");
        first.id = Some(id);
        let line = record(&store, first).await.unwrap();
        assert_eq!(line.id, id);

        let mut again = new_request("access", "2026-10-22");
        again.id = Some(id);
        let err = record(&store, again).await.unwrap_err();
        assert!(
            matches!(&err, Error::Failed(message) if message.contains("already recorded")),
            "{err}"
        );
        assert_eq!(read_all(&store, "alice").await.unwrap().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_erasure_answer_names_the_surviving_facts_and_the_refund() {
        let answer = erasure_answer(Some(
            "A refund of GBP 20.00 was recorded on 2026-10-04; it is settled separately.",
        ));
        assert!(answer.contains("about seven months"), "{answer}");
        assert!(answer.contains("ledger"), "{answer}");
        assert!(answer.contains("no username"), "{answer}");
        assert!(answer.contains("90 days"), "{answer}");
        assert!(answer.contains("GBP 20.00"), "{answer}");
        assert!(answer.contains("refund"), "{answer}");
        // The no-refund form still names the refund position plainly.
        let none = erasure_answer(None);
        assert!(none.contains("No refund is due"), "{none}");
        assert!(!none.contains("GBP 20.00"), "{none}");
    }
}
