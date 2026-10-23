//! The data-subject request record: one line per request in the account's store
//! directory, and the one-month clock that line carries.
//!
//! The spec is `docs/planning/specs/data-subject-requests.md`, "What gets
//! recorded". The console writes through here now; the page's export and close
//! intents write through the same functions when the drain carries them, so a
//! page-filed request and a scripted one cannot produce different lines.

use std::io::ErrorKind;
use std::os::unix::io::AsRawFd;

use serde::{Deserialize, Serialize};
use time::{Date, Month, OffsetDateTime};

use crate::store::Store;
use crate::validate;

/// The kinds the spec names. A portability request is recorded as `access`,
/// which is the pair the spec treats as one answer; the other two are separate.
const KINDS: [&str; 3] = ["access", "erasure", "rectification"];

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
    /// The latest of receipt, the identity information asked for, and any fee:
    /// Article 12A's "relevant time".
    pub relevant: String,
    /// One calendar month from `relevant`, `YYYY-MM-DD`.
    pub due: String,
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
    /// How an export was delivered, where there was one. The export ticket
    /// fills it; the console has no flag for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
}

/// What `record` is given, kept as one value because the call has more fields
/// than a positional signature can carry legibly.
pub struct NewRequest<'a> {
    pub username: &'a str,
    pub kind: &'a str,
    pub received: &'a str,
    pub evidence: &'a str,
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
pub fn parse_date(value: &str) -> Result<Date, String> {
    let bad = || format!("{value:?} is not a date in YYYY-MM-DD");
    if value.len() != 10 || !value.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return Err(bad());
    }
    let year: i32 = value[0..4].parse().map_err(|_| bad())?;
    let month: u8 = value[5..7].parse().map_err(|_| bad())?;
    let day: u8 = value[8..10].parse().map_err(|_| bad())?;
    let month = Month::try_from(month).map_err(|_| bad())?;
    Date::from_calendar_date(year, month, day).map_err(|_| bad())
}

fn format_date(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// One calendar month later, clamping the day to the shorter month: the 31st of
/// January answers by the 28th of February, and by the 29th in a leap year.
/// Article 12's month is a calendar month, not thirty days.
fn one_month_after(date: Date) -> Date {
    let (year, month) = if date.month() == Month::December {
        (date.year() + 1, Month::January)
    } else {
        (date.year(), date.month().next())
    };
    let last = month.length(year);
    Date::from_calendar_date(year, month, date.day().min(last))
        .expect("a day clamped to the month's own length is in the month")
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

fn record_path(username: &str) -> String {
    format!("{}/requests.jsonl", account_dir(username))
}

/// The request record's exclusive lock. The console and the drain are different
/// processes, and a close reads every line and writes them back, so a record
/// appended between the read and the write would be lost without this. The lock
/// is held for one small read or write, so blocking a runtime thread that long
/// is fine.
///
/// The lock lives in a file of its own rather than on `requests.jsonl`: the
/// close replaces that file by rename, and a lock on the replaced inode would
/// stop guarding the path the moment the rename landed.
async fn lock(store: &Store, username: &str) -> Result<tokio::fs::File, String> {
    let path = store.path(&format!("{}/.requests.lock", account_dir(username)));
    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).mode(0o600);
    let file = opts
        .open(&path)
        .await
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!(
            "cannot lock {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

/// Append one request line and return it, so the caller can print the due date.
pub async fn record(store: &Store, request: NewRequest<'_>) -> Result<RequestLine, String> {
    if let Some(why) = validate::username_shape(request.username) {
        return Err(format!("the username {:?}: {why}", request.username));
    }
    if !KINDS.contains(&request.kind) {
        return Err(format!(
            "the kind {:?} is not one of {}",
            request.kind,
            KINDS.join(", ")
        ));
    }
    let evidence = request.evidence.trim();
    if evidence.is_empty() {
        return Err("the evidence that established who was asking is needed".to_string());
    }
    // A request is recorded against an account, never into a directory a
    // mistyped name would create.
    if store
        .read_record(&account_dir(request.username), "account.json")
        .await
        .is_none()
    {
        return Err(format!("no account for {}", request.username));
    }

    let id = match request.id {
        Some(raw) => ulid::Ulid::from_string(raw)
            .map_err(|e| format!("the id {raw:?}: {e}"))?
            .to_string(),
        None => ulid::Ulid::new().to_string(),
    };
    let received = parse_date(request.received)?;
    let identity_at = request.identity_at.map(parse_date).transpose()?;
    let fee_at = request.fee_at.map(parse_date).transpose()?;
    let relevant = relevant_time(received, identity_at, fee_at);
    let due = one_month_after(relevant);

    let line = RequestLine {
        version: 1,
        id,
        username: request.username.to_string(),
        kind: request.kind.to_string(),
        received: format_date(received),
        evidence: evidence.to_string(),
        relevant: format_date(relevant),
        due: format_date(due),
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
    let _guard = lock(store, request.username).await?;
    // A retry that carries an id must not write the same request twice. The
    // read is under the lock, so it sees a record that another process lands
    // first.
    if request.id.is_some() {
        let existing = read_all(store, request.username).await?;
        if existing.iter().any(|l| l.id == line.id) {
            return Err(format!("request {} is already recorded", line.id));
        }
    }
    let bytes = serde_json::to_vec(&line).map_err(|e| format!("cannot write the request: {e}"))?;
    store.append(&record_path(&line.username), &bytes).await?;
    Ok(line)
}

/// Read one account's request lines. A missing file is an empty record; any
/// other read error is an error, because a record the command cannot see must
/// not read as a clear docket.
async fn read_all(store: &Store, username: &str) -> Result<Vec<RequestLine>, String> {
    let path = record_path(username);
    let abs = store.path(&path);
    let text = match tokio::fs::read_to_string(&abs).await {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", abs.display())),
    };
    let mut out = Vec::new();
    for (i, line) in text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .enumerate()
    {
        out.push(
            serde_json::from_str(line)
                .map_err(|e| format!("{path}: line {} does not parse: {e}", i + 1))?,
        );
    }
    Ok(out)
}

/// The account whose record holds one request id. The read happens before the
/// lock, and again under it in `close`.
async fn find_account(store: &Store, id: &str) -> Result<String, String> {
    let mut found: Option<String> = None;
    for username in store.list("accounts").await? {
        if !read_all(store, &username).await?.iter().any(|l| l.id == id) {
            continue;
        }
        if found.is_some() {
            return Err(format!("request {id} appears in more than one account"));
        }
        found = Some(username);
    }
    found.ok_or_else(|| format!("no request with id {id}"))
}

/// Write what was done onto the request's own line, and return the closed line.
///
/// The file is one line per request, not one line per event, so closing rewrites
/// that request's line and leaves the others as they were. The rewrite goes by
/// rename (the store's own write), so a reader never sees a half file, and the
/// whole read and write happen under the record's lock, so a concurrent record
/// is not dropped.
pub async fn close(
    store: &Store,
    id: &str,
    done_at: &str,
    done: &str,
) -> Result<RequestLine, String> {
    let done = done.trim();
    if done.is_empty() {
        return Err("what was done is needed".to_string());
    }
    let done_at = parse_date(done_at)?;
    let username = find_account(store, id).await?;
    let _guard = lock(store, &username).await?;
    let mut lines = read_all(store, &username).await?;
    let at = lines
        .iter()
        .position(|l| l.id == id)
        .ok_or_else(|| format!("no request with id {id}"))?;
    if lines[at].done.is_some() {
        return Err(format!("request {id} is already closed"));
    }
    lines[at].done = Some(done.to_string());
    lines[at].done_at = Some(format_date(done_at));

    let mut bytes = String::new();
    for line in &lines {
        bytes.push_str(
            &serde_json::to_string(line)
                .map_err(|e| format!("cannot write the request record: {e}"))?,
        );
        bytes.push('\n');
    }
    store
        .write_record(&account_dir(&username), "requests.jsonl", bytes.as_bytes())
        .await?;
    Ok(lines[at].clone())
}

/// Every request still open, earliest answer due first.
pub async fn open(store: &Store) -> Result<Vec<RequestLine>, String> {
    let mut out = Vec::new();
    for username in store.list("accounts").await? {
        for line in read_all(store, &username).await? {
            if line.done.is_none() {
                out.push(line);
            }
        }
    }
    out.sort_by(|a, b| a.due.cmp(&b.due).then_with(|| a.id.cmp(&b.id)));
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
        std::fs::write(dir.join("accounts/alice/account.json"), "{}").unwrap();
        (Store::new(dir.to_str().unwrap()), dir)
    }

    fn new_request<'a>(kind: &'a str, received: &'a str) -> NewRequest<'a> {
        NewRequest {
            username: "alice",
            kind,
            received,
            evidence: "signed message from the account address",
            note: None,
            identity_at: None,
            fee_at: None,
            id: None,
        }
    }

    #[test]
    fn one_calendar_month_clamps_to_the_shorter_months_last_day() {
        assert_eq!(one_month_after(d("2026-10-22")), d("2026-11-22"));
        assert_eq!(one_month_after(d("2026-12-15")), d("2027-01-15"));
        assert_eq!(one_month_after(d("2026-01-31")), d("2026-02-28"));
        assert_eq!(one_month_after(d("2024-01-31")), d("2024-02-29"));
        assert_eq!(one_month_after(d("2026-03-31")), d("2026-04-30"));
        assert_eq!(one_month_after(d("2026-08-31")), d("2026-09-30"));
    }

    #[test]
    fn the_clock_starts_at_the_latest_relevant_time() {
        assert_eq!(
            one_month_after(relevant_time(d("2026-10-01"), None, None)),
            d("2026-11-01")
        );
        assert_eq!(
            one_month_after(relevant_time(d("2026-10-01"), Some(d("2026-10-09")), None)),
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
            )),
            d("2026-11-20")
        );
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
        let raw = store.lines("accounts/alice/requests.jsonl").await;
        assert_eq!(raw.len(), 1);
        assert_eq!(serde_json::from_str::<RequestLine>(&raw[0]).unwrap(), line);
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
        assert!(err.contains("no account for nobody"), "{err}");
        assert!(!dir.join("accounts/nobody").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn record_refuses_an_unknown_kind_and_a_missing_evidence() {
        let (store, dir) = temp_store("record-refusals");
        let err = record(&store, new_request("portability", "2026-10-22"))
            .await
            .unwrap_err();
        assert!(err.contains("access, erasure, rectification"), "{err}");
        let mut request = new_request("access", "2026-10-22");
        request.evidence = "  ";
        assert!(record(&store, request).await.is_err());
        assert!(store
            .lines("accounts/alice/requests.jsonl")
            .await
            .is_empty());
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

        let lines: Vec<RequestLine> = store
            .lines("accounts/alice/requests.jsonl")
            .await
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
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
        assert!(err.contains("cannot read"), "{err}");
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
        assert!(err.contains("already recorded"), "{err}");
        assert_eq!(read_all(&store, "alice").await.unwrap().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
