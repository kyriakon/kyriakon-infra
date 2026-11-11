//! Tests for the portal module.

use super::{portal_answer, portal_file, portal_line, SLOW_STATUS};
use crate::responder::test_support::*;
use crate::responder::Error;
use kyriakon_control_core::store::Record;
use kyriakon_control_core::{ipc, store};
use std::collections::BTreeMap;

#[tokio::test]
async fn a_portal_status_read_answers_with_the_stage_and_never_an_answer() {
    let (app, dir) = handler("portal-stage").await;
    stage_application(
        &dir,
        &decided(
            "received",
            None,
            Some("https://signup.kyriakon.net/password/secret"),
        ),
    );

    let answer = portal_answer(&app, "203.0.113.10", TOKEN).await;
    assert_eq!(answer, ipc::Answer::Stage("received".to_string()));
    let line = answer.line();
    // The status path's one promise: no answer, contact address or key.
    assert!(!line.contains("secretary"), "{line}");
    assert!(!line.contains("password"), "{line}");
    assert!(!line.contains("signup.kyriakon.net"), "{line}");
}

#[tokio::test]
async fn a_portal_read_of_an_unknown_token_reads_as_one_that_expired() {
    let (app, dir) = handler("portal-expired").await;
    let unknown = portal_answer(&app, "203.0.113.10", TOKEN).await;
    assert!(matches!(unknown, ipc::Answer::Notice(_)), "{unknown:?}");

    stage_application(
        &dir,
        &decided("decided: declined", Some("2026-10-01T09:00:00Z"), None),
    );
    let expired = portal_answer(&app, "203.0.113.10", TOKEN).await;
    assert_eq!(
        unknown.line(),
        expired.line(),
        "the two reads are one reply"
    );
}

#[tokio::test]
async fn a_portal_status_read_is_rate_limited_by_address() {
    let (app, _dir) = handler("portal-rate").await;
    for _ in 0..kyriakon_control_core::flow::rate::REQUESTS_PER_MINUTE {
        let _ = portal_answer(&app, "203.0.113.10", TOKEN).await;
    }
    let refused = portal_answer(&app, "203.0.113.10", TOKEN).await;
    assert_eq!(refused, ipc::Answer::Notice(SLOW_STATUS.to_string()));
    // Another address still reads.
    assert!(matches!(
        portal_answer(&app, "203.0.113.11", TOKEN).await,
        ipc::Answer::Notice(_)
    ));
}

/// The portal line is bounded on the wire: a request past the bound is refused
/// before it becomes an unbounded allocation.
#[tokio::test]
async fn portal_lines_are_bounded_and_a_close_is_not_an_error() {
    let mut reader = tokio::io::BufReader::new(&b"abcdef\n"[..]);
    assert_eq!(
        portal_line(&mut reader, 6).await.unwrap(),
        Some("abcdef\n".to_string())
    );

    let mut reader = tokio::io::BufReader::new(&b"abcdefg\n"[..]);
    let why = portal_line(&mut reader, 6).await.unwrap_err();
    assert!(matches!(&why, Error::Line { limit: 6, .. }), "{why}");

    let mut reader = tokio::io::BufReader::new(&b"abc"[..]);
    assert_eq!(portal_line(&mut reader, 6).await.unwrap(), None);
}

/// The portal's completed application: the handler validates it with the web
/// form's rules, files one application and one intent, and the token it returns
/// reads back the stage.
#[tokio::test]
async fn the_portal_files_one_application_and_its_token_reads_the_stage() {
    let (app, dir) = handler("portal-file").await;
    let form: BTreeMap<String, String> = body_answers()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let body = serde_json::to_string(&form).unwrap();

    let reply = portal_file(&app, "203.0.113.10", &body).await;
    let token = ipc::parse_file_answer(&reply).unwrap();
    assert!(store::is_status_token(&token), "{token}");

    let text =
        std::fs::read_to_string(dir.join("applications").join(format!("{token}.json"))).unwrap();
    let record: Record = serde_json::from_str(&text).unwrap();
    assert_eq!(record.front_end, "tui");
    assert_eq!(record.username, "theophilus");
    assert_eq!(
        record.mail_keys.len(),
        1,
        "the mailbox's key did not reach the record"
    );
    assert_eq!(
        std::fs::read_dir(dir.join("intents")).unwrap().count(),
        1,
        "one application is one intent"
    );
    assert_eq!(
        portal_answer(&app, "203.0.113.10", &token).await,
        ipc::Answer::Stage("received".to_string())
    );
}

/// A bug in the portal cannot become a filed record the web form would have
/// refused: the handler runs the same checks again and files nothing.
#[tokio::test]
async fn the_portal_refuses_an_application_the_web_form_would_refuse() {
    let (app, dir) = handler("portal-file-refused").await;
    let mut form: BTreeMap<String, String> = body_answers()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    form.insert("username".to_string(), "Not A Username".to_string());

    let reply = portal_file(&app, "203.0.113.10", &serde_json::to_string(&form).unwrap()).await;
    assert!(reply.starts_with("ERR "), "{reply}");
    assert_eq!(
        std::fs::read_dir(dir.join("applications")).unwrap().count(),
        0
    );
    assert_eq!(std::fs::read_dir(dir.join("intents")).unwrap().count(), 0);
}

// The environment traps: what each front-end sends, and what is read from it.
