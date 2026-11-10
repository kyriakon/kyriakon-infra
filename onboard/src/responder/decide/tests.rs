//! Tests for the decide module.

use crate::responder::test_support::*;
use crate::responder::*;

/// A decision link names what it would do and files nothing. The link is in an
/// email, and everything that fetches a URL it is sent would otherwise decide for
/// the operator.
#[tokio::test]
async fn a_decision_link_opens_a_page_instead_of_deciding() {
    let (app, dir) = handler("decide-get").await;
    stage_application(&dir, &decided("received", None, None));

    let (code, page) = ask(
        &app,
        &httpd_get(&format!("/decide/{TOKEN}"), "action=approve&sig=deadbeef"),
    )
    .await;
    assert_eq!(code, 200);
    assert!(page.contains("approve, with the charge"), "{page}");
    assert!(
        page.contains("secretary"),
        "the application is named: {page}"
    );
    assert!(
        page.contains("name=\"sig\" value=\"deadbeef\""),
        "the signature is carried into the form: {page}"
    );
    assert!(
        page.contains("Cache-Control: no-store\r\n"),
        "the page carries a capability and is not cached: {page}"
    );
    assert_eq!(intent_files(&dir).len(), 0, "a GET files nothing");
}

/// The click is what files it, in the shape the drain parses.
#[tokio::test]
async fn the_click_files_one_decision_the_drain_can_parse() {
    let (app, dir) = handler("decide-post").await;
    stage_application(&dir, &decided("received", None, None));

    let body = encoded(&[("action", "approve-free"), ("sig", "abc123")]);
    let (code, page) = ask(&app, &httpd_post(&format!("/decide/{TOKEN}"), &body)).await;
    assert_eq!(code, 200);
    assert!(page.contains("Filed"), "{page}");

    let files = intent_files(&dir);
    assert_eq!(files.len(), 1, "one intent: {files:?}");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&files[0]).unwrap()).unwrap();
    assert_eq!(
        v["kind"], "provision",
        "without the charge is the kind the drain dispatches"
    );
    assert_eq!(v["action"], "approve-free");
    assert_eq!(
        v["sig"], "abc123",
        "the signature is passed through untouched"
    );
    assert_eq!(v["application"]["username"], "secretary");
    assert_eq!(v["application"]["status_token"], TOKEN);
}

/// A link that names no decision, or a token that names no application, files
/// nothing and says nothing about which of the two it was for a dead token.
#[tokio::test]
async fn a_decision_link_that_names_nothing_is_refused() {
    let (app, dir) = handler("decide-bad").await;
    stage_application(&dir, &decided("received", None, None));

    let (code, page) = ask(
        &app,
        &httpd_get("/decide/not-a-token", "action=approve&sig=x"),
    )
    .await;
    assert_eq!(code, 200, "a dead token is a page, not an error");
    assert!(page.contains(UNKNOWN_TOKEN), "{page}");

    let (code, _) = ask(
        &app,
        &httpd_get(&format!("/decide/{TOKEN}"), "action=promote&sig=x"),
    )
    .await;
    assert_eq!(code, 403, "an action the platform has no decision for");

    let (code, _) = ask(
        &app,
        &httpd_get(&format!("/decide/{TOKEN}"), "action=approve"),
    )
    .await;
    assert_eq!(code, 403, "a link with no signature");

    assert_eq!(
        intent_files(&dir).len(),
        0,
        "a link that names nothing files nothing"
    );
}

/// The one-time password page files the plaintext for the drain to hash, never
/// a hash the handler chose.
#[tokio::test]
async fn the_password_page_files_the_plaintext_and_not_a_hash() {
    let (app, dir) = handler("password-plaintext").await;
    let until = crate::util::date_after_days(7);
    stage_application(
        &dir,
        &decided(
            "received",
            None,
            Some("https://signup.example.invalid/password/x"),
        ),
    );
    let body = encoded(&[
        ("until", until.as_str()),
        ("sig", "00"),
        ("password", "correct horse battery"),
        ("confirm", "correct horse battery"),
    ]);
    let (code, _) = ask(&app, &httpd_post(&format!("/password/{TOKEN}"), &body)).await;
    assert_eq!(code, 200);
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "set-password");
    assert_eq!(intent["password"], "correct horse battery");
    assert!(intent.get("hash").is_none(), "{intent}");
}
