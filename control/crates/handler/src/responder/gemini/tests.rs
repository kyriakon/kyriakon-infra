//! Tests for the gemini module.

use super::super::{FrontEnd, MAX_BODY, UNKNOWN_TOKEN};
use super::capsule_value;
use crate::capsule;
use crate::fastcgi::{self};
use crate::responder::connection::read;
use crate::responder::test_support::*;
use kyriakon_control_core::config::HOST;
use kyriakon_control_core::flow::applicant::flow_path;
use kyriakon_control_core::flow::questions;
use std::collections::BTreeMap;

#[tokio::test]
async fn gmid_asks_for_the_capsule_and_gets_the_catalogue() {
    let (app, _dir) = handler("gmid-catalogue").await;
    // The path gmid sends for the capsule's front page: every leading slash
    // stripped, which is why the route table is written against that form.
    let (code, body) = ask(&app, &gmid_get("", "")).await;
    assert_eq!(code, 20);
    assert!(body.starts_with("20 text/gemini\r\n"));
    assert!(
        body.contains("=> gemini://mail.kyriakon.net/ Mail: zero-access mail"),
        "{body}"
    );
}

/// The join the ticket is about: the hash decides, and a match is the member
/// on both the catalogue and the reading half.
#[tokio::test]
async fn a_pinned_certificate_answers_as_the_member() {
    let (app, dir) = handler("gmid-pinned").await;
    file_account(&dir);
    let pinned = test_certificate(PINNED, "CN=alice");

    let (code, body) = ask(&app, &gmid_certificate("", "", &pinned)).await;
    assert_eq!(code, 20);
    assert!(
        body.contains("=> gemini://alice.kyriakon.net/ A website"),
        "the member's own host, not the pattern: {body}"
    );
    assert!(!body.contains("gemini://<name>.kyriakon.net/"), "{body}");

    let (code, body) = ask(&app, &gmid_certificate("account", "", &pinned)).await;
    assert_eq!(code, 20);
    assert!(body.contains("State: active"), "{body}");
    assert!(body.contains("Site: serving"), "{body}");
    assert!(body.contains("Capsule: serving"), "{body}");
    assert!(body.contains("Space used: 412 MB"), "{body}");
    assert!(
        body.contains("Application approved, account opened."),
        "{body}"
    );
    assert!(body.contains("alice@kyriakon.net"), "{body}");
    assert!(
        !body.contains("DNS records"),
        "an account with no group carries no recipe: {body}"
    );
    // The fixture was approved without charge, and both account pages say so
    // from the account they read rather than from a page-only flag.
    assert!(
        body.contains("This account is free: nothing is due, and it does not lapse."),
        "{body}"
    );
    let cookie = signed_in(&app, "alice").await;
    let (code, web) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
    assert_eq!(code, 200);
    assert!(
        web.contains("This account is free: nothing is due, and it does not lapse."),
        "{web}"
    );
    assert!(
        !web.contains("Payment"),
        "no block for a free account: {web}"
    );

    // The catalogue's account row reaches the page that answered it.
    let (_, catalogue) = ask(&app, &gmid_certificate("", "", &pinned)).await;
    assert!(
        catalogue.contains("=> gemini://signup.kyriakon.net/account Your account"),
        "{catalogue}"
    );
}

/// The ordinary visitor's pages, with the visitor's own fingerprint and no
/// claim about whether the hash is pinned.
#[tokio::test]
async fn a_certificate_that_matches_nothing_answers_as_a_stranger() {
    let (app, dir) = handler("gmid-unpinned").await;
    file_account(&dir);
    let stray = test_certificate(OTHER, "CN=alice");

    let (code, body) = ask(&app, &gmid_certificate("", "", &stray)).await;
    assert_eq!(code, 20, "a page, not a refusal");
    assert!(
        body.contains("=> gemini://<name>.kyriakon.net/ A website"),
        "the stranger's hosts: {body}"
    );
    assert!(!body.contains("alice.kyriakon.net"), "{body}");
    assert!(
        body.contains("SHA256:fedcba98"),
        "the visitor's own fingerprint: {body}"
    );
    assert!(
        body.contains("https://signup.kyriakon.net/account"),
        "{body}"
    );
    assert!(body.contains("terminal"), "{body}");

    // The account route is a page for a stranger too, and is not the member's.
    let (code, body) = ask(&app, &gmid_certificate("account", "", &stray)).await;
    assert_eq!(code, 20);
    assert!(!body.contains("State: active"), "{body}");
    assert!(
        !body.contains("Application approved, account opened."),
        "{body}"
    );
    assert!(body.contains("SHA256:fedcba98"), "{body}");

    // A visitor with no certificate reads the same page without a fingerprint.
    let (code, body) = ask(&app, &gmid_get("account", "")).await;
    assert_eq!(code, 20);
    assert!(!body.contains("SHA256:"), "{body}");
}

/// The no-oracle rule: whatever the visitor asks for with an unmatched
/// certificate, no page carries the word for an unknown certificate.
#[tokio::test]
async fn no_page_calls_an_unmatched_certificate_unknown() {
    let (app, dir) = handler("gmid-no-oracle").await;
    file_account(&dir);
    let stray = test_certificate(OTHER, "CN=alice");
    let status = format!("status/{TOKEN}");
    for path in ["", "account", status.as_str()] {
        let (code, body) = ask(&app, &gmid_certificate(path, "", &stray)).await;
        assert_eq!(code, 20, "{path}: a page, not a refusal");
        let lower = body.to_lowercase();
        for tell in [
            "unknown",
            "not recognised",
            "not recognized",
            "unrecognised",
        ] {
            assert!(!lower.contains(tell), "{path} says {tell:?}: {body}");
        }
    }
}

/// The subject and issuer are what the request carried: they are recorded, and
/// a certificate that claims a member's subject without a pinned hash is still
/// a stranger. The hash alone names the member, in both directions.
#[tokio::test]
async fn the_subject_and_issuer_are_recorded_and_never_trusted() {
    let (app, dir) = handler("gmid-untrusted").await;
    file_account(&dir);

    // The claim is alice's; the hash is not.
    let claimed = test_certificate(OTHER, "CN=alice");
    let bytes = gmid_certificate("", "", &claimed);
    let request = fastcgi::read_request(&mut &bytes[..], MAX_BODY)
        .await
        .unwrap()
        .unwrap();
    let incoming = read(FrontEnd::Gemini, &request);
    let recorded = incoming
        .certificate
        .as_ref()
        .expect("a certificate was sent");
    assert_eq!(recorded.subject, "CN=alice");
    assert_eq!(recorded.issuer, "CN=alice");
    assert_eq!(recorded.hash, OTHER);
    assert_eq!(recorded.not_before, "2026-01-01T00:00:00Z");
    assert_eq!(recorded.not_after, "2036-01-01T00:00:00Z");
    let (_, body) = ask(&app, &bytes).await;
    assert!(!body.contains("=> gemini://alice.kyriakon.net/"), "{body}");

    // The hash is alice's; the subject claims otherwise.
    let impostor = test_certificate(PINNED, "CN=mallory");
    let (_, body) = ask(&app, &gmid_certificate("", "", &impostor)).await;
    assert!(
        body.contains("=> gemini://alice.kyriakon.net/ A website"),
        "the hash names the member, not the subject: {body}"
    );

    // Without a certificate the request carries none, whatever the empty
    // `AUTH_TYPE` says.
    let bytes = gmid_get("", "");
    let request = fastcgi::read_request(&mut &bytes[..], MAX_BODY)
        .await
        .unwrap()
        .unwrap();
    assert!(read(FrontEnd::Gemini, &request).certificate.is_none());
}

/// The reading half changes nothing: the page is rendered, and every record
/// the handler could write is exactly as it was.
#[tokio::test]
async fn the_reading_half_files_nothing() {
    let (app, dir) = handler("gmid-reads").await;
    file_account(&dir);
    let before = std::fs::read(dir.join("accounts/alice/account.json")).unwrap();
    let filed_before = filed(&dir);

    let pinned = test_certificate(PINNED, "CN=alice");
    let (code, _) = ask(&app, &gmid_certificate("account", "", &pinned)).await;
    assert_eq!(code, 20);
    assert_eq!(filed(&dir), filed_before, "the read filed nothing");
    assert_eq!(
        std::fs::read(dir.join("accounts/alice/account.json")).unwrap(),
        before,
        "the account record is unchanged"
    );
}

#[tokio::test]
async fn the_capsule_serves_each_mirrored_page_as_gemtext() {
    let (app, _dir) = handler("gmid-pages").await;
    for (route, file, _) in capsule::PAGES {
        let (code, body) = ask(&app, &gmid_get(route, "")).await;
        assert_eq!(code, 20, "{route} answers with a page: {body}");
        assert!(body.starts_with("20 text/gemini\r\n"), "{body}");
        assert!(
            body.contains(&format!("# {file}")),
            "{route} serves the staged file: {body}"
        );
    }
}

#[tokio::test]
async fn the_acceptances_page_carries_three_acceptances_and_the_release() {
    let (app, _dir) = handler("gmid-acceptances").await;
    let (code, body) = ask(&app, &gmid_get(capsule::ACCEPTANCES, "")).await;
    assert_eq!(code, 20, "{body}");
    assert!(body.starts_with("20 text/gemini\r\n"), "{body}");
    for document in [
        "I accept the terms of service.",
        "I accept the acceptable use policy.",
        "I accept the privacy notice.",
    ] {
        assert!(body.contains(document), "{document} is on the page: {body}");
    }
    assert_eq!(
        body.matches("* I accept ").count(),
        3,
        "one acceptance per document: {body}"
    );
    assert!(
        body.contains("2026-10-13 test"),
        "the release the page was generated from: {body}"
    );
}

#[tokio::test]
async fn the_front_page_names_the_web_form_and_the_pages_that_stay_over_https() {
    let (app, _dir) = handler("gmid-front").await;
    let (code, body) = ask(&app, &gmid_get("", "")).await;
    assert_eq!(code, 20, "{body}");
    assert!(
        body.contains("The web form at https://signup.kyriakon.net/ is the other way in"),
        "the browser is named as the other way in: {body}"
    );
    assert!(
        body.contains("The refusal list and the threat model stay published over HTTPS"),
        "the two pages that are not mirrored are named: {body}"
    );
    assert!(
        body.contains(&format!("=> gemini://{HOST}/keys Making a key")),
        "the walkthrough is linked from the front page: {body}"
    );
}

#[tokio::test]
async fn a_gemini_request_for_an_unknown_token_reads_as_one_that_expired() {
    let (app, dir) = handler("gmid-token").await;
    let (code, unknown_body) = ask(&app, &gmid_get(&format!("status/{TOKEN}"), "")).await;
    assert_eq!(code, 20, "a token that names nothing is still a page");
    assert!(unknown_body.contains(UNKNOWN_TOKEN), "{unknown_body}");

    // A decided application past its window reads byte for byte the same.
    stage_application(
        &dir,
        &decided(
            "decided: an account without charge",
            Some("2026-10-01T09:00:00Z"),
            None,
        ),
    );
    let (_, expired_body) = ask(&app, &gmid_get(&format!("status/{TOKEN}"), "")).await;
    assert!(expired_body.contains(UNKNOWN_TOKEN), "{expired_body}");
    assert_eq!(expired_body, unknown_body, "the two reads are one page");
}

// The portal's one read: the stage, or the same notice for every token that
// names nothing.

/// The token from the 30 that opens a draft.
fn draft_token(redirect: &str) -> String {
    let url = redirect
        .lines()
        .next()
        .expect("a reply line")
        .strip_prefix("30 ")
        .expect("a redirect");
    url.split('/')
        .nth(4)
        .expect(".../apply/<token>/1")
        .to_string()
}

#[tokio::test]
async fn a_capsule_draft_asks_the_first_question() {
    let (app, _dir) = handler("capsule-first").await;
    let (code, redirect) = ask(&app, &gmid_get("apply", "")).await;
    assert_eq!(code, 30, "{redirect}");
    let token = draft_token(&redirect);

    let (code, page) = ask(&app, &gmid_get(&format!("apply/{token}/1"), "")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.starts_with("10 question 1 of "), "{page}");
    assert!(page.contains("Username"), "{page}");
    assert!(page.contains("under 1024 bytes"), "{page}");
}

#[tokio::test]
async fn a_capsule_answer_advances_the_cursor_once() {
    let (app, dir) = handler("capsule-answer").await;
    let (_, redirect) = ask(&app, &gmid_get("apply", "")).await;
    let token = draft_token(&redirect);

    let (code, redirect) = ask(&app, &gmid_get(&format!("apply/{token}/1"), "secretary")).await;
    assert_eq!(code, 30, "{redirect}");
    assert!(
        redirect.contains(&format!("/apply/{token}/2")),
        "{redirect}"
    );
    let draft = read_draft(&dir, &token);
    assert_eq!(draft.answers["username"], "secretary");
    assert_eq!(draft.cursor, 1);

    // The same page and answer again: a redirect to the cursor, and no second
    // advance.
    let (code, redirect) = ask(&app, &gmid_get(&format!("apply/{token}/1"), "secretary")).await;
    assert_eq!(code, 30, "{redirect}");
    assert!(
        redirect.contains(&format!("/apply/{token}/2")),
        "{redirect}"
    );
    assert_eq!(read_draft(&dir, &token).cursor, 1);
}

#[tokio::test]
async fn a_capsule_branch_answer_changes_the_counter() {
    let (app, dir) = handler("capsule-branch").await;
    let (_, redirect) = ask(&app, &gmid_get("apply", "")).await;
    let token = draft_token(&redirect);
    ask(&app, &gmid_get(&format!("apply/{token}/1"), "secretary")).await;
    ask(&app, &gmid_get(&format!("apply/{token}/2"), "body")).await;

    let total = flow_path(&app.questions, &read_draft(&dir, &token).answers).len();
    let (code, page) = ask(&app, &gmid_get(&format!("apply/{token}/3"), "")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains(&format!("question 3 of {total}.")), "{page}");
    assert!(page.contains("The body's name"), "{page}");
}

#[tokio::test]
async fn a_required_capsule_answer_is_reasked_with_the_reason() {
    let (app, dir) = handler("capsule-required").await;
    let (_, redirect) = ask(&app, &gmid_get("apply", "")).await;
    let token = draft_token(&redirect);

    let (code, page) = ask(&app, &gmid_get(&format!("apply/{token}/1"), ".")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains("a username is needed"), "{page}");
    assert_eq!(read_draft(&dir, &token).cursor, 0);
    assert!(!read_draft(&dir, &token).answers.contains_key("username"));
}

#[tokio::test]
async fn an_optional_capsule_answer_of_a_full_stop_is_empty() {
    let (app, dir) = handler("capsule-skip").await;
    let (_, redirect) = ask(&app, &gmid_get("apply", "")).await;
    let token = draft_token(&redirect);
    ask(&app, &gmid_get(&format!("apply/{token}/1"), "secretary")).await;
    ask(&app, &gmid_get(&format!("apply/{token}/2"), "person")).await;

    let (code, _) = ask(&app, &gmid_get(&format!("apply/{token}/3"), ".")).await;
    assert_eq!(code, 30);
    let draft = read_draft(&dir, &token);
    assert_eq!(draft.answers["address_outside"], "");
    assert_eq!(draft.cursor, 3);
}

#[test]
fn the_capsule_query_decoding_is_the_gemini_one() {
    assert_eq!(capsule_value("line1%0D%0Aline2"), "line1\nline2");
    assert_eq!(capsule_value("line1%0Aline2"), "line1\nline2");
    assert_eq!(capsule_value("line1\r\nline2"), "line1\nline2");
    assert_eq!(capsule_value("a+b"), "a+b");
    assert_eq!(capsule_value("a\rb"), "a\rb");
    // Validation trims with `str::trim`, so the padding the capsule stores is
    // the padding that was checked; a bare CR inside the answer is still kept.
    assert_eq!(capsule_value("line%0D"), "line");
    assert_eq!(capsule_value("line%0Dmore"), "line\rmore");
    assert_eq!(capsule_value("."), "");
}

#[test]
fn the_capsule_adds_the_blessing_only_on_the_monastic_path() {
    let list = questions::shipped().unwrap();
    let mut answers = BTreeMap::new();
    answers.insert("whose".to_string(), "person".to_string());
    answers.insert("orders".to_string(), "layman".to_string());
    assert!(!flow_path(&list, &answers)
        .iter()
        .any(|p| p.q.id == "blessing"));
    answers.insert("orders".to_string(), "monk".to_string());
    assert!(flow_path(&list, &answers)
        .iter()
        .any(|p| p.q.id == "blessing"));
}

#[tokio::test]
async fn a_capsule_body_with_mismatched_address_and_name_lists_is_reasked() {
    let (app, dir) = handler("capsule-body-mismatch").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "body".to_string());
    record
        .answers
        .insert("body_addresses".to_string(), "a: own\nb: own".to_string());
    record.cursor = 8;
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let (code, page) = ask(&app, &gmid_get(&format!("apply/{TOKEN}/9"), "a")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains("2 addresses and 1 account names"), "{page}");
    let draft = read_draft(&dir, TOKEN);
    assert_eq!(draft.cursor, 8);
    assert!(!draft.answers.contains_key("body_account_names"));
}

#[tokio::test]
async fn a_capsule_body_key_page_names_one_mailbox_and_the_mail_route() {
    let (app, dir) = handler("capsule-key-pages").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "body".to_string());
    record
        .answers
        .insert("body_domain".to_string(), "parish.example".to_string());
    record.answers.insert(
        "body_addresses".to_string(),
        "secretary: own\nhall: alias secretary".to_string(),
    );
    record.answers.insert(
        "body_account_names".to_string(),
        "secretary\nhall".to_string(),
    );
    let path = flow_path(&app.questions, &record.answers);
    let first = path
        .iter()
        .position(|p| p.mailbox.is_some())
        .expect("the first key page");
    record.cursor = first;
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let (code, page) = ask(&app, &gmid_get(&format!("apply/{TOKEN}/{}", first + 1), "")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains("secretary@parish.example"), "{page}");
    assert!(page.contains("apply@kyriakon.net"), "{page}");
    assert!(
        page.contains("gemini://signup.kyriakon.net/keys"),
        "the walkthrough is named on every key page: {page}"
    );
    assert!(
        page.contains(TOKEN),
        "the subject carries the draft's token: {page}"
    );
    assert!(
        page.lines().next().unwrap().len() < 1024,
        "the reply header stays inside gmid's limit: {page}"
    );

    let (code, redirect) = ask(
        &app,
        &gmid_get(&format!("apply/{TOKEN}/{}", first + 1), GOOD_KEY),
    )
    .await;
    assert_eq!(code, 30, "{redirect}");
    let draft = read_draft(&dir, TOKEN);
    assert_eq!(draft.mail_keys.len(), 1);
    assert_eq!(draft.mail_keys[0].mailbox, "secretary");
    assert!(!draft.mail_keys[0].fingerprint.is_empty());

    let (code, page) = ask(&app, &gmid_get(&format!("apply/{TOKEN}/{}", first + 2), "")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains("hall@parish.example"), "{page}");
}

#[tokio::test]
async fn a_capsule_person_key_page_names_their_address() {
    let (app, _dir) = handler("capsule-person-key").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    let path = flow_path(&app.questions, &record.answers);
    let index = path
        .iter()
        .position(|p| p.q.id == "mail_key")
        .expect("the key page");
    record.cursor = index;
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let (code, page) = ask(&app, &gmid_get(&format!("apply/{TOKEN}/{}", index + 1), "")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains("secretary@kyriakon.net"), "{page}");
    assert!(page.contains("apply@kyriakon.net"), "{page}");
    assert!(
        page.contains("gemini://signup.kyriakon.net/keys"),
        "the walkthrough is named on every key page: {page}"
    );
}

#[tokio::test]
async fn a_capsule_upload_key_page_names_the_walkthrough() {
    let (app, _dir) = handler("capsule-upload-key").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    let path = flow_path(&app.questions, &record.answers);
    let index = path
        .iter()
        .position(|p| p.q.id == "upload_key")
        .expect("the upload key page");
    record.cursor = index;
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let (code, page) = ask(&app, &gmid_get(&format!("apply/{TOKEN}/{}", index + 1), "")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains("gemini://signup.kyriakon.net/keys"), "{page}");
}

#[tokio::test]
async fn a_mailed_key_answers_the_capsule_key_page() {
    let (app, dir) = handler("capsule-key-mailed").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "body".to_string());
    record
        .answers
        .insert("body_domain".to_string(), "parish.example".to_string());
    record.answers.insert(
        "body_account_names".to_string(),
        "secretary\nhall".to_string(),
    );
    record
        .mail_keys
        .push(kyriakon_control_core::mail::keycheck::mail_key(
            "secretary".to_string(),
            "secretary@parish.example",
            GOOD_KEY,
        ));
    let path = flow_path(&app.questions, &record.answers);
    let first = path
        .iter()
        .position(|p| p.mailbox.is_some())
        .expect("the first key page");
    record.cursor = first;
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let (code, redirect) = ask(&app, &gmid_get(&format!("apply/{TOKEN}/{}", first + 1), "")).await;
    assert_eq!(
        code, 30,
        "the mailed key advances past its page: {redirect}"
    );
    assert!(
        redirect.contains(&format!("/apply/{TOKEN}/{}", first + 2)),
        "{redirect}"
    );
    assert_eq!(read_draft(&dir, TOKEN).cursor, first + 1);
}

/// A mailed key reaches the application the way the spec describes: the body's
/// two mailboxes keep their order, and the material is the block that arrived by
/// mail rather than an empty answer.
#[tokio::test]
async fn a_mailed_key_is_in_the_filed_application_in_mailbox_order() {
    let (app, dir) = handler("capsule-mail-files").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record.answers = body_answers()
        .into_iter()
        .map(|(id, value)| (id.to_string(), value.to_string()))
        .collect();
    record
        .answers
        .insert("body_domain".into(), "parish.example".into());
    record.answers.insert(
        "body_addresses".into(),
        "secretary: own\nhall: alias secretary".into(),
    );
    record
        .answers
        .insert("body_account_names".into(), "secretary\nhall".into());
    record.answers.remove("body_mail_key");
    record
        .mail_keys
        .push(kyriakon_control_core::mail::keycheck::mail_key(
            "secretary".into(),
            "secretary@parish.example",
            GOOD_KEY,
        ));
    record
        .mail_keys
        .push(kyriakon_control_core::mail::keycheck::mail_key(
            "hall".into(),
            "hall@parish.example",
            GOOD_KEY,
        ));
    record.cursor = flow_path(&app.questions, &record.answers).len();
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let (code, page) = ask(&app, &gmid_get(&format!("apply/{TOKEN}/1"), "")).await;
    assert_eq!(code, 20, "{page}");
    let filed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("applications").join(format!("{TOKEN}.json"))).unwrap(),
    )
    .unwrap();
    let keys = filed["mail_keys"].as_array().expect("the filed keys");
    assert_eq!(keys.len(), 2, "{filed}");
    assert_eq!(keys[0]["mailbox"], "secretary", "{filed}");
    assert_eq!(keys[1]["mailbox"], "hall", "{filed}");
    assert!(
        keys[0]["material"]
            .as_str()
            .is_some_and(|m| m.contains("BEGIN PGP PUBLIC KEY BLOCK")),
        "{filed}"
    );
}

#[tokio::test]
async fn two_capsule_drafts_do_not_write_to_each_other() {
    let (app, dir) = handler("capsule-isolation").await;
    let (_, first) = ask(&app, &gmid_get("apply", "")).await;
    let (_, second) = ask(&app, &gmid_get("apply", "")).await;
    let first = draft_token(&first);
    let second = draft_token(&second);

    ask(&app, &gmid_get(&format!("apply/{first}/1"), "alice")).await;
    assert_eq!(read_draft(&dir, &first).answers["username"], "alice");
    assert!(!read_draft(&dir, &second).answers.contains_key("username"));
}

#[tokio::test]
async fn a_complete_capsule_draft_files_the_application() {
    let (app, dir) = handler("capsule-file").await;
    let answers: BTreeMap<String, String> = body_answers()
        .into_iter()
        .map(|(id, value)| (id.to_string(), value.to_string()))
        .collect();
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record.answers = answers;
    record.cursor = flow_path(&app.questions, &record.answers).len();
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let (code, page) = ask(&app, &gmid_get(&format!("apply/{TOKEN}/1"), "")).await;
    assert_eq!(code, 20, "{page}");
    assert!(page.contains("# Application filed"), "{page}");
    assert!(dir
        .join("applications")
        .join(format!("{TOKEN}.json"))
        .exists());
    assert_eq!(intent_files(&dir).len(), 1);
    assert!(!dir.join("drafts").join(format!("{TOKEN}.json")).exists());
}

/// A submission whose intent cannot be written leaves no application record:
/// the record alone is never reviewed and never purged, and the applicant
/// retries under a fresh token.
#[tokio::test]
async fn a_failed_intent_write_leaves_no_application_record() {
    let (app, dir) = handler("capsule-intent-failure").await;
    let answers: BTreeMap<String, String> = body_answers()
        .into_iter()
        .map(|(id, value)| (id.to_string(), value.to_string()))
        .collect();
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record.answers = answers;
    record.cursor = flow_path(&app.questions, &record.answers).len();
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    // A regular file where the intents directory should be makes the second
    // write fail while the application write succeeds.
    std::fs::remove_dir_all(dir.join("intents")).unwrap();
    std::fs::write(dir.join("intents"), b"not a directory").unwrap();

    let (code, page) = ask(&app, &gmid_get(&format!("apply/{TOKEN}/1"), "")).await;
    assert_eq!(code, 40, "{page}");
    assert_eq!(
        std::fs::read_dir(dir.join("applications")).unwrap().count(),
        0,
        "the record outlived the intent it was filed with"
    );
}
