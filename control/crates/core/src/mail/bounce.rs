//! Delivery-status reports: the one report this platform gets that a notice did
//! not arrive.
//!
//! Every notice leaves with `bounce@kyriakon.net` as its envelope sender, and
//! `openbsd/etc/smtpd.conf` delivers that address to a plaintext Maildir the
//! drain reads. A DSN is parsed conservatively: it must be a delivery-status
//! report for a **failed** recipient with a **permanent** (5.x.x) status, and it
//! must carry the subject of the message we sent. A soft bounce is the sender's
//! queue still trying, and ordinary mail to the bounce address is not a report;
//! neither moves anything.
//!
//! The record it writes is on the notice line itself, because that line is
//! already the audit of what was sent and where. `every_address_failed` then
//! answers the deletion sweep's question: did a lifecycle notice to every
//! address this account has reach nobody? The drain latches that answer on the
//! account, because the platform gets no successful-delivery report and a later
//! unmarked attempt is not evidence that the address works.

use std::collections::BTreeMap;

use crate::store::{Delivery, Notice, Store};
use crate::util;
use crate::Error;

/// One permanent delivery failure, as a DSN reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bounce {
    /// The address the report says failed.
    pub recipient: String,
    /// The DSN's `Status`, e.g. `5.1.1`.
    pub status: String,
    /// The subject of the message we sent, from the returned original.
    pub subject: String,
}

/// Parse one message as a permanent-failure DSN. Anything else is `None`: a
/// soft bounce, a delayed report, a plain message to the bounce address, or a
/// report for a recipient whose status class is not permanent.
pub fn parse(raw: &str) -> Option<Bounce> {
    let raw = raw.replace("\r\n", "\n");
    let lower = raw.to_ascii_lowercase();
    // The outer report says what it is. A message that does not is not read at
    // all, so a body line quoting `Status:` cannot turn it into a bounce.
    if !lower.contains("report-type=delivery-status") || !lower.contains("message/delivery-status")
    {
        return None;
    }
    let report_at = lower.find("message/delivery-status")?;
    // The per-recipient fields run from that part to the returned original. Only
    // the first recipient block is read, because every notice goes to one
    // address; a report naming several is not one this platform sent.
    let original_at = lower[report_at..]
        .find("message/rfc822")
        .map(|at| report_at + at)
        .unwrap_or(raw.len());
    let report = &raw[report_at..original_at];
    if !field(report, "action")?.eq_ignore_ascii_case("failed") {
        return None;
    }
    let status = field(report, "status")?;
    if !permanent(&status) {
        return None;
    }
    let final_recipient = field(report, "final-recipient")?;
    let recipient = match final_recipient.split_once(';') {
        Some((kind, address)) if kind.trim().eq_ignore_ascii_case("rfc822") => address.trim(),
        // An `unknown` or `utf-8` recipient is not the rfc822 address the notice
        // recorded, and guessing at one is how a wrong account gets marked.
        Some(_) => return None,
        None => final_recipient.trim(),
    };
    if crate::flow::validate::address(recipient).is_some() {
        return None;
    }
    let subject = field(returned_headers(&raw[original_at..])?, "subject")?;
    if subject.is_empty() {
        return None;
    }
    Some(Bounce {
        recipient: recipient.to_string(),
        status,
        subject,
    })
}

/// The headers of the returned original message: the part's content starts
/// after its own blank line, and the header block ends at the next one. Reading
/// only the header block keeps a `Subject:` in the quoted body out.
fn returned_headers(part: &str) -> Option<&str> {
    let body = part.split_once("\n\n")?.1;
    Some(body.split_once("\n\n").map_or(body, |(headers, _)| headers))
}

/// Whether a DSN status is a permanent failure. The parser has already narrowed
/// it; this is the check that keeps the record's meaning in one place.
fn permanent(status: &str) -> bool {
    let mut bytes = status.trim().bytes();
    matches!(bytes.next(), Some(b'5'))
        && matches!(bytes.next(), Some(b'.'))
        && status
            .trim()
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.')
}

/// One header's value from a header block, unfolded. A continuation line starts
/// with a space or a tab; the value is joined with one space, which is enough
/// for a subject and a status.
fn field(block: &str, name: &str) -> Option<String> {
    let mut lines = block.lines().peekable();
    while let Some(line) = lines.next() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case(name) {
            let mut value = value.trim().to_string();
            while let Some(next) = lines.peek() {
                if !(next.starts_with(' ') || next.starts_with('\t')) {
                    break;
                }
                let next = lines.next().unwrap_or_default();
                value.push(' ');
                value.push_str(next.trim());
            }
            return Some(value);
        }
    }
    None
}

/// Record a permanent failure on every notice that matches: the most recent
/// notice to that recipient carrying that subject in each account's history. A
/// contact address may be shared and a subject may be shared, so more than one
/// account can match, and marking one while deleting the other unseen is the
/// failure this exists to stop. An empty list means no notice matched and the
/// report moves nothing.
pub async fn record(store: &Store, bounce: &Bounce) -> Result<Vec<String>, Error> {
    let mut marked = Vec::new();
    for username in store.list("accounts").await? {
        if mark(store, &username, bounce).await? {
            marked.push(username);
        }
    }
    Ok(marked)
}

/// Mark one account's notice line, under the record's own lock so an append
/// that lands meanwhile is either seen or follows the rewrite rather than being
/// dropped. The line is the last match by file order: a resend to the same
/// address is the later decision, and the older failure stays as history.
async fn mark(store: &Store, username: &str, bounce: &Bounce) -> Result<bool, Error> {
    let path = format!("accounts/{username}/notices.jsonl");
    let log = store.log(&path);
    let _lock = log.lock().await?;
    let mut lines = log.raw_lines().await?;
    let mut found = None;
    for (index, line) in lines.iter().enumerate() {
        let Ok(notice) = serde_json::from_str::<Notice>(line) else {
            continue;
        };
        if notice.to.eq_ignore_ascii_case(&bounce.recipient) && notice.subject == bounce.subject {
            found = Some((index, notice));
        }
    }
    let Some((index, mut notice)) = found else {
        return Ok(false);
    };
    notice.delivery = Some(Delivery {
        status: bounce.status.clone(),
        at: util::filed_at(),
    });
    lines[index] =
        serde_json::to_string(&notice).map_err(|e| Error::context("cannot encode a notice", e))?;
    let mut bytes = lines.join("\n");
    if !bytes.is_empty() {
        bytes.push('\n');
    }
    store
        .rewrite_log_mode(&path, bytes.as_bytes(), store.dir_owner("accounts"), 0o640)
        .await?;
    Ok(true)
}

/// The notice types that open, carry and close the account's own grace clock.
/// Only these answer whether a channel reached the member before the account is
/// deleted: a password link or a test message that bounced says nothing about
/// the final notice. A group's lifecycle is the site owner's notice but the
/// group's own clock, so it is not read here; the group deletion path is not
/// this sweep's member-account gate.
const LIFECYCLE: [&str; 5] = [
    "prepaid.lapsed",
    "prepaid.grace",
    "prepaid.final",
    "account.suspended",
    "account.suspended.final",
];

/// Whether **every** address a lifecycle notice went to has reported a
/// permanent failure: no channel reached the member, so the grace clock stops
/// rather than running out into a deletion nobody was told about.
///
/// Any failure at the address counts, not only the latest notice's. The
/// platform gets no successful-delivery report, so a later notice with no
/// report is not evidence that an address that already hard-bounced works; the
/// operator's resend is what says a channel does, and it clears the latched stop
/// on the account.
///
/// An account with no lifecycle notice at all reads `false`: the notice has not
/// gone out yet, and the sweep's own final-notice branch is what sends it.
pub async fn every_address_failed(store: &Store, username: &str) -> Result<bool, Error> {
    let notices: Vec<Notice> = store
        .log(&format!("accounts/{username}/notices.jsonl"))
        .jsonl()
        .await?;
    let mut failed: BTreeMap<String, bool> = BTreeMap::new();
    for notice in notices {
        if !LIFECYCLE.contains(&notice.notice_type.as_str()) {
            continue;
        }
        let reported = notice.delivery.as_ref().is_some_and(Delivery::permanent);
        *failed
            .entry(notice.to.to_ascii_lowercase())
            .or_insert(false) |= reported;
    }
    Ok(!failed.is_empty() && failed.values().all(|failed| *failed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    const HARD: &str = "From: MAILER-DAEMON@mail.example\n\
To: bounce@kyriakon.net\n\
Subject: Undelivered Mail Returned to Sender\n\
MIME-Version: 1.0\n\
Content-Type: multipart/report; report-type=delivery-status; boundary=\"b1\"\n\
\n\
--b1\n\
Content-Type: text/plain\n\
\n\
The mail could not be delivered.\n\
--b1\n\
Content-Type: message/delivery-status\n\
\n\
Reporting-MTA: dns; mail.example\n\
\n\
Final-Recipient: rfc822; secretary@example.invalid\n\
Original-Recipient: rfc822; secretary@example.invalid\n\
Action: failed\n\
Status: 5.1.1\n\
Diagnostic-Code: smtp; 550 5.1.1 no such mailbox\n\
\n\
--b1\n\
Content-Type: message/rfc822\n\
\n\
From: kyriakon <hello@kyriakon.net>\n\
To: secretary@example.invalid\n\
Subject: Your kyriakon.net account will be deleted in seven days\n\
\n\
The body.\n\
--b1--\n";

    #[test]
    fn a_permanent_failure_is_read_with_its_recipient_and_subject() {
        assert_eq!(
            parse(HARD),
            Some(Bounce {
                recipient: "secretary@example.invalid".to_string(),
                status: "5.1.1".to_string(),
                subject: "Your kyriakon.net account will be deleted in seven days".to_string(),
            })
        );
        // A subject folded over two lines is one subject.
        let folded = HARD.replace(
            "Subject: Your kyriakon.net account will be deleted in seven days",
            "Subject: Your kyriakon.net account\n will be deleted in seven days",
        );
        assert_eq!(
            parse(&folded).map(|b| b.subject),
            Some("Your kyriakon.net account will be deleted in seven days".to_string())
        );
    }

    #[test]
    fn a_soft_bounce_delay_or_ordinary_mail_moves_nothing() {
        assert_eq!(parse(&HARD.replace("Status: 5.1.1", "Status: 4.4.1")), None);
        assert_eq!(
            parse(&HARD.replace("Action: failed", "Action: delayed")),
            None
        );
        assert_eq!(parse(&HARD.replace("Status: 5.1.1", "Status: 2.0.0")), None);
        // A receipt is not a delivery-status report, even when its body talks
        // about a status.
        assert_eq!(
            parse("From: hello@kyriakon.net\nSubject: Received\n\nStatus: 5.1.1\n"),
            None
        );
        // A report for a recipient type this platform cannot name is not read.
        assert_eq!(
            parse(&HARD.replace(
                "Final-Recipient: rfc822; secretary@example.invalid",
                "Final-Recipient: unknown; secretary@example.invalid"
            )),
            None
        );
    }

    async fn account(store: &Store, username: &str, notices: &str) {
        store
            .ensure_dir_owned(
                &format!("accounts/{username}"),
                0o750,
                store.dir_owner("accounts"),
            )
            .await
            .unwrap();
        std::fs::write(
            store.path(&format!("accounts/{username}/notices.jsonl")),
            notices,
        )
        .unwrap();
    }

    fn notice_line(kind: &str, subject: &str, to: &str) -> String {
        format!(
            "{{\"version\":1,\"at\":\"2026-11-12T09:00:00Z\",\"type\":\"{kind}\",\"subject\":\"{subject}\",\"to\":\"{to}\"}}\n"
        )
    }

    #[tokio::test]
    async fn a_bounce_marks_the_notice_and_every_failed_address_stops_the_clock() {
        let dir = std::env::temp_dir().join(format!("control-bounce-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("store/accounts")).unwrap();
        let store = Store::new_for_test(dir.join("store").to_str().unwrap());
        account(
            &store,
            "secretary",
            &notice_line(
                "prepaid.final",
                "Your kyriakon.net account will be deleted in seven days",
                "secretary@example.invalid",
            ),
        )
        .await;
        assert!(!every_address_failed(&store, "secretary").await.unwrap());
        assert_eq!(
            record(&store, &parse(HARD).unwrap()).await.unwrap(),
            vec!["secretary".to_string()]
        );
        assert!(every_address_failed(&store, "secretary").await.unwrap());
        let written =
            std::fs::read_to_string(dir.join("store/accounts/secretary/notices.jsonl")).unwrap();
        assert!(
            written.contains("\"delivery\":{\"status\":\"5.1.1\""),
            "{written}"
        );
        // A later attempt at the same address, with no report, is not evidence
        // the address works: the failure stands until the operator resends.
        let mut text = written.clone();
        text.push_str(&notice_line(
            "prepaid.final",
            "Your kyriakon.net account will be deleted in seven days",
            "secretary@example.invalid",
        ));
        std::fs::write(dir.join("store/accounts/secretary/notices.jsonl"), text).unwrap();
        assert!(every_address_failed(&store, "secretary").await.unwrap());
        // A report for a recipient or subject no notice carries marks nothing.
        let mut other = parse(HARD).unwrap();
        other.recipient = "warden@example.invalid".to_string();
        assert!(record(&store, &other).await.unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn one_address_reached_keeps_the_clock_running() {
        let dir = std::env::temp_dir().join(format!("control-bounce-two-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("store/accounts")).unwrap();
        let store = Store::new_for_test(dir.join("store").to_str().unwrap());
        account(
            &store,
            "secretary",
            &notice_line(
                "prepaid.lapsed",
                "Your kyriakon.net account will be deleted in seven days",
                "secretary@example.invalid",
            ),
        )
        .await;
        assert_eq!(
            record(&store, &parse(HARD).unwrap()).await.unwrap(),
            vec!["secretary".to_string()]
        );
        assert!(every_address_failed(&store, "secretary").await.unwrap());
        // The same account's newer notice at another address, with no report,
        // is a channel that has not failed.
        let mut text =
            std::fs::read_to_string(dir.join("store/accounts/secretary/notices.jsonl")).unwrap();
        text.push_str(&notice_line(
            "prepaid.lapsed",
            "Your kyriakon.net account will be deleted in seven days",
            "secretary@kyriakon.net",
        ));
        std::fs::write(dir.join("store/accounts/secretary/notices.jsonl"), text).unwrap();
        assert!(!every_address_failed(&store, "secretary").await.unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }
}
