//! Tests for the status module.

use super::super::UNKNOWN_TOKEN;
use super::{payment_for, status_page};
use crate::responder::test_support::*;
use kyriakon_control_core::account::LAPSE_NOTE;
use kyriakon_control_core::store::Record;

/// A closed window is the same fact on both front ends: the handler reads the
/// record's payment block and the web page and the capsule say the closure, the
/// lapse's own words, and no amount. The token is a code and never a link.
#[tokio::test]
async fn a_lapsed_application_says_the_window_closed_on_both_front_ends() {
    let (app, dir) = handler("status-lapsed").await;
    let mut record = decided("approved: an account was made", None, None);
    record.rail = "cash".into();
    record.no_charge = false;
    record.payment = Some(
        serde_json::from_value(serde_json::json!({
            "token_ref": "KYR-4F2M-9QH7-XT3B",
            "window": {"opened_at": "2026-10-02T09:00:00Z",
                       "closes_at": "2026-10-16T09:00:00Z",
                       "state": "closed", "extensions": 0}
        }))
        .expect("a payment block the record could hold"),
    );
    stage_application(&dir, &record);

    let (code, html) = ask(&app, &httpd_get(&format!("status/{TOKEN}"), "")).await;
    assert_eq!(code, 200);
    let (_, gemtext) = ask(&app, &gmid_get(&format!("status/{TOKEN}"), "")).await;
    for body in [&html, &gemtext] {
        assert!(
            body.contains("Lapsed: the payment window closed on 2026-10-16"),
            "{body}"
        );
        assert!(body.contains(LAPSE_NOTE), "{body}");
        assert!(
            !body.contains("Amount: GBP"),
            "a closed window quotes no amount: {body}"
        );
    }
    // The token is a code and every link is somewhere else: no `href` in the
    // page names it, so a pay link carrying it in its query fails here.
    assert!(
        html.contains("<code>KYR-4F2M-9QH7-XT3B</code>"),
        "the token is shown as a code: {html}"
    );
    for attribute in html.split("href=\"").skip(1) {
        let target = attribute.split('"').next().unwrap_or("");
        assert!(
            !target.contains("KYR-4F2M-9QH7-XT3B"),
            "the payment token is never a link: {html}"
        );
    }
}

#[tokio::test]
async fn the_status_page_answers_for_seven_days_after_a_decision() {
    let (app, dir) = handler("status-window").await;
    stage_application(&dir, &decided("received", None, None));
    let (code, page) = ask(&app, &httpd_get(&format!("/status/{TOKEN}"), "")).await;
    assert_eq!(code, 200);
    assert!(page.contains("Cache-Control: no-store\r\n"), "{page}");
    assert!(page.contains("Referrer-Policy: no-referrer\r\n"), "{page}");
    assert!(page.contains("Stage</td><td>received"), "{page}");

    let (code, _) = ask(&app, &httpd_get("/status/not-a-token", "")).await;
    assert_eq!(
        code, 200,
        "a token that is not one reads as unknown, not as an error"
    );
}

#[test]
fn a_decided_application_answers_for_seven_days_and_then_reads_as_unknown() {
    let now = at("2026-10-05T09:00:00Z");
    // Filed and not yet decided: the link answers.
    let filed = status_page(Some(decided("received", None, None)), None, now);
    assert_eq!(filed.notice, "");
    assert_eq!(filed.stage, "received");

    // Decided inside the window: answers, with the drain's own word for the
    // stage, and the link it wrote.
    let inside = status_page(
        Some(decided(
            "decided: an account without charge",
            Some("2026-10-01T09:00:00Z"),
            Some("https://signup.kyriakon.net/password/abcdefghjkmnpqrstvwxyz"),
        )),
        None,
        now,
    );
    assert_eq!(inside.notice, "");
    assert_eq!(inside.stage, "decided: an account without charge");
    assert_eq!(
        inside.password_link.as_deref(),
        Some("https://signup.kyriakon.net/password/abcdefghjkmnpqrstvwxyz")
    );

    // A record without a password link renders none.
    let without = status_page(Some(decided("received", None, None)), None, now);
    assert_eq!(without.password_link, None);

    // Past the window the record's page is the unknown-token page, byte for byte,
    // so a live token cannot be told from a dead one.
    let password_link = Some("https://signup.kyriakon.net/password/abcdefghjkmnpqrstvwxyz");
    let expired = status_page(
        Some(decided(
            "decided: an account on the paid tier",
            Some("2026-10-01T09:00:00Z"),
            password_link,
        )),
        None,
        at("2026-10-08T09:00:01Z"),
    );
    let unknown = status_page(None, None, now);
    assert_eq!(expired.notice, UNKNOWN_TOKEN);
    assert_eq!(expired.stage, "");
    assert_eq!(expired.filed_at, "");
    assert_eq!(
        expired.password_link, None,
        "an expired link renders no password link either"
    );
    assert_eq!(
        (expired.notice, expired.stage, expired.filed_at),
        (unknown.notice, unknown.stage, unknown.filed_at)
    );
}

/// The card pages show the same keyed Payment Link the approval email carried,
/// rather than promising one in a later message. The status page and both
/// account pages share this PaymentView, so one check covers the three.
#[tokio::test]
async fn the_card_pages_carry_the_keyed_payment_link() {
    let (app, _dir) = handler("card-link").await;
    let record: Record = serde_json::from_str(
        r#"{"username":"secretary","status_token":"abcdefghjkmnpqrstvwxyz0123",
            "filed_at":"2026-10-01T09:00:00Z","front_end":"web","stage":"decided",
            "answers":{},"mail_keys":[],"rail":"card","no_charge":false,
            "acceptances":[],"question_list":"2026-10-13 test",
            "payment":{"token_ref":"KYR-AAAA-BBBB-CCCC",
                       "token_issued_at":"2026-10-02T09:00:00Z","paid_until":null,
                       "window":{"opened_at":"2099-10-02T09:00:00Z",
                                 "closes_at":"2099-10-16T09:00:00Z",
                                 "state":"open","extensions":0}}}"#,
    )
    .unwrap();
    let view = payment_for(&app, Some(&record)).expect("a paid approval has a block");
    let text = view.instructions.join("\n");
    assert!(
        text.contains("client_reference_id=KYR-AAAA-BBBB-CCCC"),
        "the link is keyed to the account's token: {text}"
    );
    assert!(
        !text.contains("subscription_data"),
        "only the supported Payment Link parameters are used: {text}"
    );
}

/// A body's status page shows the group Payment Link, keyed to the group's
/// token. A record with a `domain` is a body's application, and a body's year is
/// its own price, so the account link would bill the wrong amount.
#[tokio::test]
async fn a_group_status_page_carries_the_group_payment_link() {
    let (app, _dir) = handler("group-card-link").await;
    let record: Record = serde_json::from_str(
        r#"{"username":"warden","status_token":"abcdefghjkmnpqrstvwxyz0123",
            "filed_at":"2026-10-01T09:00:00Z","front_end":"web","stage":"decided",
            "domain":"parish.example",
            "answers":{},"mail_keys":[],"rail":"card","no_charge":false,
            "acceptances":[],"question_list":"2026-10-13 test",
            "payment":{"token_ref":"KYR-AAAA-BBBB-CCCC",
                       "token_issued_at":"2026-10-02T09:00:00Z","paid_until":null,
                       "window":{"opened_at":"2099-10-02T09:00:00Z",
                                 "closes_at":"2099-10-16T09:00:00Z",
                                 "state":"open","extensions":0}}}"#,
    )
    .unwrap();
    let view = payment_for(&app, Some(&record)).expect("a paid group approval has a block");
    let text = view.instructions.join("\n");
    assert!(
        text.contains(
            "https://buy.stripe.com/test_group_example?client_reference_id=KYR-AAAA-BBBB-CCCC"
        ),
        "the page carried the group link: {text}"
    );
    assert!(
        !text.contains("https://buy.stripe.com/test_example?client_reference_id="),
        "the page carried the account link: {text}"
    );
}
