//! Tests for the flow module.

use crate::fcgi::fixture;
use crate::questions;
use crate::responder::test_support::*;
use crate::responder::*;
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
    assert_eq!(crate::keycheck::blocks(two).len(), 2);
    assert!(crate::keycheck::blocks("nothing here").is_empty());
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
