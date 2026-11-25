//! Delivery-status reports: the one report this platform gets that a notice did
//! not arrive.
//!
//! Every notice leaves with `bounce@kyriakon.net` as its envelope sender, and
//! `openbsd/etc/smtpd.conf` delivers that address to a plaintext Maildir the
//! drain reads. A DSN is parsed conservatively: it must be a delivery-status
//! report for a **failed** recipient with a **permanent** (5.x.x) status, and
//! the returned original must carry the Message-ID this platform minted and
//! recorded on the notice line. A soft bounce is the sender's queue still
//! trying, ordinary mail to the bounce address is not a report, and a report
//! without our marker is not ours; none of them moves anything.
//!
//! The record it writes is on the notice line itself, because that line is
//! already the audit of what was sent and where. `every_address_failed` then
//! answers the operator's question: did a lifecycle notice to every address this
//! account has reach nobody? A report is unauthenticated inbound mail — anyone
//! can quote a notice's Message-ID — so the drain records it and alerts, and
//! only `kyriakon-admin notice stop` holds the account. The platform gets no
//! successful-delivery report, and a later unmarked attempt is not evidence that
//! the address works.

use std::collections::BTreeMap;

use super::notice::{LIFECYCLE, MESSAGE_ID_DOMAIN};
use super::Error;
use crate::store::{is_permanent_status, Delivery, Notice, Store};
use crate::util;

/// One permanent delivery failure, as a DSN reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bounce {
    /// The address the report says failed.
    pub recipient: String,
    /// The DSN's `Status`, e.g. `5.1.1`.
    pub status: String,
    /// The local part of the recorded Message-ID, from the returned original.
    pub id: String,
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
    if !is_permanent_status(&status) {
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
    let id = message_id(returned_headers(&raw[original_at..])?)?;
    Some(Bounce {
        recipient: recipient.to_string(),
        status,
        id,
    })
}

/// The local part of the Message-ID on the returned original, when it is the
/// shape this platform mints: `<26 crockford characters@kyriakon.net>`. A report
/// that drops or changes the marker is not a report for a notice we sent.
fn message_id(headers: &str) -> Option<String> {
    let value = field(headers, "message-id")?;
    let value = value.trim();
    let inner = value.strip_prefix('<')?.strip_suffix('>')?;
    let (local, domain) = inner.split_once('@')?;
    if domain.contains('@') || !domain.eq_ignore_ascii_case(MESSAGE_ID_DOMAIN) {
        return None;
    }
    crate::store::is_status_token(local).then(|| local.to_string())
}

/// The headers of the returned original message: the part's content starts
/// after its own blank line, and the header block ends at the next one. Reading
/// only the header block keeps a `Subject:` in the quoted body out.
fn returned_headers(part: &str) -> Option<&str> {
    let body = part.split_once("\n\n")?.1;
    Some(body.split_once("\n\n").map_or(body, |(headers, _)| headers))
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

/// Record a permanent failure on every notice that matches the report's
/// Message-ID and recipient. An id is minted per send, so two accounts cannot
/// share one; a contact address can be shared, which is why the recipient is
/// checked as well. An empty list means no notice matched and the report moves
/// nothing.
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
/// dropped. A line that cannot be parsed is an error, not a skip: the report
/// may be the match, and deleting it on a guess is the failure this exists to
/// stop. The report stays in the spool for the operator.
async fn mark(store: &Store, username: &str, bounce: &Bounce) -> Result<bool, Error> {
    let path = format!("accounts/{username}/notices.jsonl");
    let log = store.log(&path);
    let _lock = log.lock().await?;
    let mut lines = log.raw_lines().await?;
    let mut found = None;
    for (index, line) in lines.iter().enumerate() {
        let notice: Notice =
            serde_json::from_str(line).map_err(|source| Error::NoticeLineNotParsed {
                username: username.to_string(),
                line: index + 1,
                source,
            })?;
        if !notice.id.is_empty()
            && notice.id == bounce.id
            && notice.to.eq_ignore_ascii_case(&bounce.recipient)
        {
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
        serde_json::to_string(&notice).map_err(|source| Error::EncodeNotice { source })?;
    let mut bytes = lines.join("\n");
    if !bytes.is_empty() {
        bytes.push('\n');
    }
    store
        .rewrite_log_mode(&path, bytes.as_bytes(), store.dir_owner("accounts"), 0o640)
        .await?;
    Ok(true)
}

/// The most recent lifecycle notice with a permanent failure, if any. It is the
/// same predicate `every_address_failed` uses, so `notice stop` names the line
/// the sweep's answer came from instead of re-deriving it.
pub async fn last_failure(store: &Store, username: &str) -> Result<Option<Notice>, Error> {
    let notices: Vec<Notice> = store
        .log(&format!("accounts/{username}/notices.jsonl"))
        .jsonl()
        .await?;
    Ok(notices.into_iter().rev().find(|notice| {
        LIFECYCLE.contains(&notice.notice_type.as_str())
            && notice.delivery.as_ref().is_some_and(Delivery::permanent)
    }))
}

/// Whether **every** address a lifecycle notice went to has reported a
/// permanent failure: no channel demonstrably reached the member, so this is
/// the evidence `kyriakon-admin notice stop` requires before it holds the grace
/// clock. The types are [`LIFECYCLE`] in `notice`, shared with every send site.
///
/// Any failure at the address counts, not only the latest notice's. The
/// platform gets no successful-delivery report, so a later notice with no
/// report is not evidence that an address that already hard-bounced works; the
/// operator reads this answer before `notice stop`, and `notice resend` clears
/// the hold once a channel works.
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

    /// A 26-character Crockford token, the shape the platform mints.
    const ID: &str = "0123456789abcdefghjkmnpqrs";

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
Message-ID: <0123456789abcdefghjkmnpqrs@kyriakon.net>\n\
\n\
The body.\n\
--b1--\n";

    #[test]
    fn a_permanent_failure_is_read_with_its_recipient_and_marker() {
        assert_eq!(
            parse(HARD),
            Some(Bounce {
                recipient: "secretary@example.invalid".to_string(),
                status: "5.1.1".to_string(),
                id: ID.to_string(),
            })
        );
        // A marker that is not the platform's shape, or is not from its domain,
        // is not read at all.
        let other_domain = HARD.replace(
            "Message-ID: <0123456789abcdefghjkmnpqrs@kyriakon.net>",
            "Message-ID: <0123456789abcdefghjkmnpqrs@example.invalid>",
        );
        assert_eq!(parse(&other_domain), None);
        let short = HARD.replace(
            "Message-ID: <0123456789abcdefghjkmnpqrs@kyriakon.net>",
            "Message-ID: <abc@kyriakon.net>",
        );
        assert_eq!(parse(&short), None);
        // A report that drops the marker is not a report for one of ours.
        let dropped = HARD.replace(
            "Message-ID: <0123456789abcdefghjkmnpqrs@kyriakon.net>\n",
            "",
        );
        assert_eq!(parse(&dropped), None);
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

    fn notice_line(kind: &str, subject: &str, to: &str, id: &str) -> String {
        format!(
            "{{\"version\":1,\"at\":\"2026-11-12T09:00:00Z\",\"type\":\"{kind}\",\"subject\":\"{subject}\",\"id\":\"{id}\",\"to\":\"{to}\"}}\n"
        )
    }

    /// A valid marker that no notice in these tests carries.
    const OTHER_ID: &str = "9876543210zyxwvtsrqpnmgkhj";

    #[tokio::test]
    async fn a_report_with_a_changed_marker_latches_nothing() {
        let dir =
            std::env::temp_dir().join(format!("control-bounce-marker-{}", std::process::id()));
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
                ID,
            ),
        )
        .await;
        // A forged report can name the recipient and the known subject; it
        // cannot name the 128-bit marker the notice left with.
        let forged = HARD.replace(ID, OTHER_ID);
        let report = parse(&forged).expect("the forged report is well formed");
        assert_eq!(report.id, OTHER_ID);
        assert!(record(&store, &report).await.unwrap().is_empty());
        assert!(!every_address_failed(&store, "secretary").await.unwrap());
        assert!(
            !std::fs::read_to_string(dir.join("store/accounts/secretary/notices.jsonl"))
                .unwrap()
                .contains("\"delivery\""),
            "the forged report marked the notice"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_corrupt_notice_line_keeps_the_report_for_the_operator() {
        let dir =
            std::env::temp_dir().join(format!("control-bounce-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("store/accounts")).unwrap();
        let store = Store::new_for_test(dir.join("store").to_str().unwrap());
        account(&store, "secretary", "{\"version\":1,\"type\":\n").await;
        let error = record(&store, &parse(HARD).unwrap())
            .await
            .expect_err("a corrupt line must not be skipped");
        assert!(error.to_string().contains("is not a notice"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
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
                ID,
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
            OTHER_ID,
        ));
        std::fs::write(dir.join("store/accounts/secretary/notices.jsonl"), text).unwrap();
        assert!(every_address_failed(&store, "secretary").await.unwrap());
        // A report for a recipient no notice carries marks nothing.
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
                ID,
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
            OTHER_ID,
        ));
        std::fs::write(dir.join("store/accounts/secretary/notices.jsonl"), text).unwrap();
        assert!(!every_address_failed(&store, "secretary").await.unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }
}
