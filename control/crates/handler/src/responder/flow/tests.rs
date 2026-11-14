//! Tests for the flow module.

use super::{application_problems, build_record};
use crate::fastcgi::fixture;
use crate::responder::test_support::*;
use kyriakon_control_core::flow::applicant::{body_cross_checks, label};
use kyriakon_control_core::flow::questions;
use std::collections::BTreeMap;

#[tokio::test]
async fn the_branch_question_opens_the_block_by_being_answered() {
    let (app, _dir) = handler("branch").await;

    // The page as it opens: a person's, with no community block on it and the
    // branch its own form carries recorded as a person's.
    let (_, fresh) = ask(&app, &httpd_get("/", "")).await;
    assert!(fresh.contains("name=\"branch\" value=\"person\""));
    assert!(!fresh.contains("id=\"body_name\""));

    // Answering for a body: the form's own continuation posts the answers back and
    // the page comes back with the block open, holding them.
    let body = encoded(&[("username", "theophilus"), ("whose", "body")]);
    let (_, answered) = ask(&app, &httpd_post("/", &body)).await;
    assert!(answered.contains("id=\"body_name\""), "the block is open");
    assert!(answered.contains("name=\"branch\" value=\"body\""));
    assert!(
        answered.contains("value=\"theophilus\""),
        "what was already typed comes back"
    );

    // Answering for a person closes it again.
    let body = encoded(&[("whose", "person")]);
    let (_, closed) = ask(&app, &httpd_post("/", &body)).await;
    assert!(!closed.contains("id=\"body_name\""));
    assert!(closed.contains("name=\"branch\" value=\"person\""));
}

/// An acceptance answer is carried by its checkbox and nothing else, so a page
/// rebuilt from a submission has to put the tick back. Without that, an
/// applicant who ticked the terms and pressed continue was handed back an
/// unticked box and then refused for an answer they had given.
#[tokio::test]
async fn an_accepted_terms_tick_comes_back_on_the_next_render() {
    let (app, _dir) = handler("acceptance").await;
    let ticked = "id=\"accept_terms\" name=\"accept_terms\" value=\"yes\" checked";

    let body = encoded(&[
        ("username", "theophilus"),
        ("accept_terms", "yes"),
        ("whose", "body"),
    ]);
    let (_, answered) = ask(&app, &httpd_post("/", &body)).await;
    assert!(
        answered.contains(ticked),
        "the tick the applicant gave comes back: {answered}"
    );

    // A page nobody gave the answer to does not invent one.
    let (_, fresh) = ask(&app, &httpd_get("/", "")).await;
    assert!(
        !fresh.contains(ticked),
        "an unticked box stays unticked: {fresh}"
    );
}

#[tokio::test]
async fn a_body_submission_that_was_shown_the_block_is_filed() {
    let (app, dir) = handler("body-filed").await;

    // The block is opened the way an applicant opens it, by answering the branch
    // question, and the page that comes back is the one submitted to.
    let body = encoded(&[("whose", "body")]);
    let (_, page) = ask(&app, &httpd_post("/", &body)).await;
    let answers = body_answers();
    assert!(page.contains("id=\"body_name\""), "the block is open");
    assert!(
        !page.contains("name=\"mail_key\""),
        "a body is not shown the person's key"
    );
    for (id, _) in &answers {
        assert!(
            page.contains(&format!("name=\"{id}\"")),
            "{id} is on the page"
        );
    }
    for q in questions::shown(&app.questions, false)
        .iter()
        .filter(|q| q.required)
    {
        assert!(
            page.contains(&format!("name=\"{}\"", q.id)),
            "the required question {} is on the page",
            q.id
        );
    }

    // Submitting it is not a refusal for a question the page did not show, and it
    // files the application.
    let (code, _) = ask(&app, &httpd_post("/apply", &encoded(&answers))).await;
    assert_eq!(
        code, 200,
        "a body applicant who filled in the block is not refused"
    );
    assert_eq!(
        std::fs::read_dir(dir.join("applications")).unwrap().count(),
        1,
        "one application, filed"
    );
}

#[tokio::test]
async fn an_answer_the_page_did_not_carry_is_shown_rather_than_refused() {
    let (app, dir) = handler("body-unshown").await;

    // The select was changed to a body without opening the block, so the page the
    // applicant was shown was the person's: the body's questions are ones they
    // have never seen. The handler renders that page for them instead of refusing
    // for answers they were not asked for.
    let body = encoded(&[
        ("branch", "person"),
        ("whose", "body"),
        ("username", "theophilus"),
        ("rail", "no_charge"),
        ("accept_terms", "yes"),
    ]);
    let (code, page) = ask(&app, &httpd_post("/apply", &body)).await;
    assert_eq!(code, 200);
    assert!(page.contains("id=\"body_name\""), "the block is open");
    assert!(page.contains("name=\"branch\" value=\"body\""));
    assert_eq!(
        std::fs::read_dir(dir.join("applications")).unwrap().count(),
        0,
        "nothing is filed from a submission that was refused the page"
    );
}

#[tokio::test]
async fn a_submission_that_is_not_from_this_form_is_refused_whatever_it_names() {
    let (app, dir) = handler("cross-origin").await;
    let answers = encoded(&body_answers());
    // A POST from another origin, to the submission route and to a route that
    // does not exist: both are refused, before a route is chosen.
    for path in ["/apply", "/nope"] {
        let bytes = fixture::httpd(
            &[
                ("REQUEST_METHOD", "POST"),
                ("REQUEST_URI", path),
                ("CONTENT_TYPE", "application/x-www-form-urlencoded"),
                ("HTTP_ORIGIN", "https://elsewhere.example"),
                ("REMOTE_ADDR", "127.0.0.1"),
            ],
            answers.as_bytes(),
        );
        let (code, page) = ask(&app, &bytes).await;
        assert_eq!(code, 403, "{path}");
        assert!(page.contains("A submission has to come from this form"));
    }
    assert_eq!(
        std::fs::read_dir(dir.join("applications")).unwrap().count(),
        0
    );
}

#[test]
fn key_blocks_splits_one_per_mailbox() {
    let two = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAA\n-----END PGP PUBLIC KEY BLOCK-----\n\n-----BEGIN PGP PUBLIC KEY BLOCK-----\nBBB\n-----END PGP PUBLIC KEY BLOCK-----\n";
    assert_eq!(kyriakon_control_core::mail::keycheck::blocks(two).len(), 2);
    assert!(kyriakon_control_core::mail::keycheck::blocks("nothing here").is_empty());
}

#[test]
fn the_body_addresses_are_counted_against_its_account_names() {
    let mut errors = Vec::new();
    let mut form = BTreeMap::new();
    form.insert(
        "body_addresses".into(),
        "secretary: own\nhall: alias secretary".into(),
    );
    form.insert("body_account_names".into(), "secretary".into());
    body_cross_checks(&form, &mut errors);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("2 addresses and 1 account names")),
        "{errors:?}"
    );

    errors.clear();
    form.insert("body_account_names".into(), "secretary\nhall".into());
    body_cross_checks(&form, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
}

/// The second checkbox is the immediate-supply request and the digital-content
/// acknowledgement, recorded where the application already keeps acceptances.
/// Ticking it adds the fourth entry; leaving it unticked adds nothing, so the
/// record is the evidence of what the applicant actually agreed to.
#[tokio::test]
async fn the_second_checkbox_is_recorded_beside_the_documents() {
    let (app, _dir) = handler("accept-supply").await;
    let mut form: BTreeMap<String, String> = body_answers()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    form.insert("accept_supply".to_string(), "yes".to_string());
    let record = build_record(&app, &form, true, TOKEN, "web").unwrap();
    let documents: Vec<&str> = record
        .acceptances
        .iter()
        .map(|a| a.document.as_str())
        .collect();
    assert_eq!(
        documents,
        [
            "terms",
            "aup",
            "privacy",
            "immediate supply and the digital-content acknowledgement",
        ],
        "the second checkbox is recorded with the three documents"
    );

    form.remove("accept_supply");
    let record = build_record(&app, &form, true, TOKEN, "web").unwrap();
    assert_eq!(
        record.acceptances.len(),
        3,
        "an unticked box records no acceptance"
    );
}

/// A value the page never offers is refused, not filed. The acceptance boxes
/// carry `yes` and nothing else, and the record quotes every acceptance as
/// given, so a hand-crafted `no` would file a refusal as consent; the records
/// question offers yes or no, so a `maybe` is refused too. The answer the page
/// does carry is still filed.
#[tokio::test]
async fn an_answer_the_page_does_not_offer_is_refused_rather_than_filed() {
    let (app, dir) = handler("answer-shape").await;
    let filed = || std::fs::read_dir(dir.join("applications")).unwrap().count();

    for (id, value, why) in [
        ("accept_terms", "no", "this has to be accepted"),
        ("accept_supply", "no", "this has to be accepted"),
        ("body_records", "maybe", "answer yes or no"),
    ] {
        let answers: Vec<(&str, &str)> = body_answers()
            .into_iter()
            .map(|(k, v)| if k == id { (k, value) } else { (k, v) })
            .collect();
        let (code, page) = ask(&app, &httpd_post("/apply", &encoded(&answers))).await;
        assert_eq!(code, 422, "{id}={value} is refused: {page}");
        assert!(page.contains(why), "{id}={value}: {page}");
        assert_eq!(filed(), 0, "{id}={value} files nothing");
    }

    let (code, _) = ask(&app, &httpd_post("/apply", &encoded(&body_answers()))).await;
    assert_eq!(code, 200, "yes is the answer the page offers");
    assert_eq!(filed(), 1);
}

/// A padded `yes` is the answer the page offers: the check trims it, and the
/// record must read it the same way, or the acknowledgement the applicant gave
/// is silently dropped from the trail.
#[tokio::test]
async fn a_padded_yes_records_the_acceptance_it_names() {
    let (app, dir) = handler("answer-padded").await;
    let answers: Vec<(&str, &str)> = body_answers()
        .into_iter()
        .map(|(k, v)| {
            if k == "accept_supply" {
                (k, " yes")
            } else {
                (k, v)
            }
        })
        .collect();
    let (code, page) = ask(&app, &httpd_post("/apply", &encoded(&answers))).await;
    assert_eq!(code, 200, "{page}");
    let entry = std::fs::read_dir(dir.join("applications"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let record = std::fs::read_to_string(entry.path()).unwrap();
    assert!(
        record.contains("immediate supply"),
        "the trimmed acceptance is recorded: {record}"
    );
}

/// The form validates the trimmed answer, so the filed record must carry that
/// same value: a stored trailing space made the drain refuse an application the
/// form had accepted, and hid the space in the review mail.
#[tokio::test]
async fn a_whitespace_bearing_answer_is_filed_trimmed() {
    let (app, dir) = handler("answer-trimmed").await;
    let answers: Vec<(&str, &str)> = body_answers()
        .into_iter()
        .map(|(k, v)| match k {
            "whose" => (k, " body "),
            "username" => (k, " theophilus "),
            "body_domain" => (k, "example.invalid "),
            _ => (k, v),
        })
        .collect();
    let (code, page) = ask(&app, &httpd_post("/apply", &encoded(&answers))).await;
    assert_eq!(code, 200, "{page}");
    let entry = std::fs::read_dir(dir.join("applications"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let record = std::fs::read_to_string(entry.path()).unwrap();
    assert!(record.contains("\"username\": \"theophilus\""), "{record}");
    assert!(
        record.contains("\"domain\": \"example.invalid\""),
        "{record}"
    );
    assert!(record.contains("\"whose\": \"body\""), "{record}");
    assert!(!record.contains("\"theophilus \""), "{record}");
}

/// `orders` is compared as validation compares it, so a padded monastic answer
/// still requires the blessing the monastic path requires.
#[tokio::test]
async fn a_padded_monastic_answer_still_requires_the_blessing() {
    let (app, _dir) = handler("monastic-padded").await;
    let mut form: BTreeMap<String, String> = body_answers()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    form.insert("orders".to_string(), "monk ".to_string());
    form.insert("blessing".to_string(), String::new());
    let errors = application_problems(&app, &form);
    assert!(
        errors.iter().any(|e| e.contains("blessing")),
        "the monastic blessing is still required: {errors:?}"
    );
}

/// A duplicated account name is refused at the form rather than filed as two
/// key records under one mailbox.
#[tokio::test]
async fn a_duplicate_account_name_is_refused_at_the_form() {
    let (app, dir) = handler("duplicate-name").await;
    let answers: Vec<(&str, &str)> = body_answers()
        .into_iter()
        .map(|(k, v)| match k {
            "body_addresses" => (k, "secretary: own\nhall: alias secretary"),
            "body_account_names" => (k, "secretary\nsecretary"),
            _ => (k, v),
        })
        .collect();
    let (code, page) = ask(&app, &httpd_post("/apply", &encoded(&answers))).await;
    assert_eq!(code, 422, "{page}");
    assert!(
        page.contains("secretary") && page.contains("twice"),
        "the refusal names the duplicate: {page}"
    );
    assert_eq!(
        std::fs::read_dir(dir.join("applications")).unwrap().count(),
        0
    );
}

/// A person's key record has no mailbox, so the expected identity comes from
/// the username answer. Without that, a display name or outside address was
/// filed with verdict "works" and the review email never showed it.
#[tokio::test]
async fn a_persons_key_is_checked_against_the_username() {
    let (app, _dir) = handler("person-uid").await;
    let key = std::fs::read_to_string(format!(
        "{}/../../../docs/planning/prototypes/keygen-spike/fixtures/generated-clean.asc",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut form = BTreeMap::new();
    form.insert("username".to_string(), "alice".to_string());
    form.insert("whose".to_string(), "person".to_string());
    form.insert("mail_key".to_string(), key);
    let record = build_record(&app, &form, false, TOKEN, "web").unwrap();
    assert_eq!(record.mail_keys.len(), 1);
    assert!(
        record.mail_keys[0].verdict.contains("User ID"),
        "{}",
        record.mail_keys[0].verdict
    );
}

#[test]
fn a_front_end_is_web_tui_or_capsule_and_nothing_else() {
    let mut form = BTreeMap::new();
    // The web form posts no such field, so its absence is the web form.
    assert_eq!(label(&form).unwrap(), "web");
    for v in ["web", "tui", "capsule"] {
        form.insert("front_end".to_string(), v.to_string());
        assert_eq!(label(&form).unwrap(), v);
    }
    for v in ["", "Capsule", "capsule ", "ssh", "http"] {
        form.insert("front_end".to_string(), v.to_string());
        assert!(label(&form).is_err(), "{v:?} should be refused");
    }
}
