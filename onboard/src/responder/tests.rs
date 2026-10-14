//! The responder's tests: the fixture check the ticket asks for, and the checks
//! the routes carried before the transport changed.
//!
//! The fixture is a request as the front-end that would send it writes one, into
//! `fcgi::read_request`, through the routes, and out as the bytes the front-end
//! would read. That is the only check either front-end gets without the box: no
//! httpd and no gmid runs here, so a fixture with the environment each one builds
//! is what stands in for them.

use super::*;
use crate::fcgi::fixture;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;

/// The status token the fixtures use, 26 Crockford characters.
const TOKEN: &str = "abcdefghjkmnpqrstvwxyz0123";

/// A responder over a store under a temporary directory, reading the tracked
/// catalogue and the tracked reserved names. The question list is the crate's own,
/// so it comes with the build rather than from a path.
async fn handler(name: &str) -> (App, PathBuf) {
    let dir = std::env::temp_dir().join(format!("onboard-responder-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["applications", "intents"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cfg = config::Config {
        store_root: dir.to_str().unwrap().to_string(),
        reserved: crate_dir.join("../reserved-usernames.txt").to_str().unwrap().to_string(),
        catalogue: crate_dir
            .join("../openbsd/etc/onboard/catalogue.toml")
            .to_str()
            .unwrap()
            .to_string(),
        httpd_socket: String::new(),
        gemini_socket: String::new(),
        release: "2026-10-13 test".to_string(),
    };
    (App::load(cfg).await.unwrap(), dir)
}

/// One request through the responder: the fixture in, the code and the bytes a
/// front-end reads back out.
async fn answer(app: &App, bytes: &[u8]) -> (u16, String) {
    let request = fcgi::read_request(&mut &bytes[..], MAX_BODY)
        .await
        .expect("the fixture is a request")
        .expect("the fixture is one request");
    let outcome = respond(app, &request).await;
    let (body, last) = fixture::reply(&fcgi::reply_bytes(&outcome.reply, request.id()));
    assert_eq!(last, fixture::END, "the reply is finished rather than truncated");
    (
        outcome.reply.code(),
        String::from_utf8_lossy(&body).into_owned(),
    )
}

/// The request httpd builds for a GET, with the address relayd set.
fn httpd_get(path: &str, query: &str) -> Vec<u8> {
    fixture::httpd(
        &[
            ("REQUEST_METHOD", "GET"),
            ("REQUEST_URI", path),
            ("QUERY_STRING", query),
            ("HTTP_HOST", "signup.kyriakon.net"),
            ("SERVER_NAME", "signup.kyriakon.net"),
            ("SERVER_PORT", "8080"),
            ("REMOTE_ADDR", "127.0.0.1"),
            ("HTTP_X_FORWARDED_FOR", "203.0.113.10"),
            ("SERVER_SOFTWARE", "OpenBSD httpd"),
        ],
        b"",
    )
}

/// The request httpd builds for a form post.
fn httpd_post(path: &str, body: &str) -> Vec<u8> {
    let length = body.len().to_string();
    fixture::httpd(
        &[
            ("REQUEST_METHOD", "POST"),
            ("REQUEST_URI", path),
            ("QUERY_STRING", ""),
            ("CONTENT_TYPE", "application/x-www-form-urlencoded"),
            ("CONTENT_LENGTH", &length),
            ("HTTP_HOST", "signup.kyriakon.net"),
            ("HTTP_ORIGIN", OWN_ORIGIN),
            ("HTTP_SEC_FETCH_SITE", "same-origin"),
            ("REMOTE_ADDR", "127.0.0.1"),
            ("HTTP_X_FORWARDED_FOR", "203.0.113.10"),
        ],
        body.as_bytes(),
    )
}

/// The request gmid builds: the path already decoded and cleaned with no leading
/// slash, the query still percent-encoded, and no forwarded header of any kind.
fn gmid_get(path: &str, query: &str) -> Vec<u8> {
    fixture::gmid(&[
        ("GATEWAY_INTERFACE", "CGI/1.1"),
        ("REQUEST_METHOD", "GET"),
        ("GEMINI_URL_PATH", path),
        ("QUERY_STRING", query),
        // gmid sends these and the responder opens nothing from them: they name
        // gmid's own root joined to the path, which is a location inside its
        // chroot rather than anything this service may read.
        ("PATH_INFO", ""),
        ("SCRIPT_NAME", ""),
        ("PATH_TRANSLATED", "/home/www/status"),
        ("SERVER_NAME", "SIGNUP.KYRIAKON.NET"),
        ("SERVER_PORT", "1965"),
        ("SERVER_PROTOCOL", "GEMINI"),
        ("SERVER_SOFTWARE", "gmid/2.1.1"),
        ("REMOTE_ADDR", "203.0.113.10"),
        ("AUTH_TYPE", ""),
    ])
}

/// A record of the shape the store holds, as the drain leaves one when it decides.
/// The fields the drain owns are the caller's.
fn decided(stage: &str, decided_at: Option<&str>, password_link: Option<&str>) -> Record {
    let mut r: Record = serde_json::from_str(
        r#"{"username": "secretary", "status_token": "00000000000000000000000000",
             "filed_at": "2026-10-01T09:00:00Z", "front_end": "tui", "stage": "received",
             "answers": {}, "mail_keys": [], "rail": "no_charge", "no_charge": true,
             "acceptances": [], "question_list": "2026-10-01 1a2b3c4"}"#,
    )
    .expect("a record the store could hold");
    r.status_token = TOKEN.to_string();
    r.stage = stage.to_string();
    r.decided_at = decided_at.map(str::to_string);
    r.password_link = password_link.map(str::to_string);
    r
}

fn at(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &Rfc3339).unwrap()
}

/// A filed application in the store the fixtures read.
fn file_application(dir: &Path, record: &Record) {
    let path = dir.join("applications").join(format!("{}.json", record.status_token));
    std::fs::write(path, serde_json::to_vec_pretty(record).unwrap()).unwrap();
}

/// The answers the body's page asks for, and nothing a body's page does not
/// carry: no mail_key, no upload_key, no monastic blessing.
fn body_answers() -> Vec<(&'static str, &'static str)> {
    [
        ("branch", "body"),
        ("whose", "body"),
        ("username", "theophilus"),
        ("body_name", "The Parish of Example"),
        ("body_kind", "parish"),
        ("vat", ""),
        ("body_domain", "example.invalid"),
        ("body_records", "yes"),
        ("body_addresses", "secretary: own"),
        ("body_account_names", "secretary"),
        ("body_mail_key", GOOD_KEY),
        ("body_upload_key", ""),
        ("body_dns_contact", ""),
        ("address_outside", ""),
        ("address_ack", ""),
        ("rail", "no_charge"),
        ("diocese", ""),
        ("orders", ""),
        ("blessing", ""),
        ("cannot_pay", ""),
        ("intended_use", ""),
        ("anything_else", ""),
        ("accept_terms", "yes"),
    ]
    .into_iter()
    .collect()
}

/// A public key block with the structure of a key that can be encrypted to.
const GOOD_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
mAYEAAAAABK4BgQAAAAAEg==\n-----END PGP PUBLIC KEY BLOCK-----\n";

/// The body of a form post, percent-encoded the way a browser sends one.
fn encoded(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// The fixture check the ticket asks for, one front-end at a time.

#[tokio::test]
async fn a_page_httpd_asks_for_comes_back_as_http() {
    let (app, _dir) = handler("httpd-form").await;
    let (code, body) = answer(&app, &httpd_get("/", "")).await;

    assert_eq!(code, 200);
    assert!(body.starts_with("Status: 200 OK\r\n"), "{body}");
    assert!(
        body.contains("Content-Type: text/html; charset=utf-8\r\n"),
        "the page is served as what it is: {body}"
    );
    assert!(body.contains("action=\"/apply\""), "the form is on the page");
    assert!(body.contains("name=\"branch\" value=\"person\""), "{body}");
    assert!(body.contains("How you will pay"), "the shared question list is rendered");
    assert!(
        !body.contains("Cache-Control"),
        "the form is not a capability in a URL"
    );
}

#[tokio::test]
async fn a_page_gmid_asks_for_comes_back_as_gemini() {
    let (app, dir) = handler("gmid-status").await;
    file_application(&dir, &decided("received", None, None));

    let (code, body) = answer(&app, &gmid_get(&format!("status/{TOKEN}"), "")).await;

    assert_eq!(code, 20, "a filed application answers");
    assert!(body.starts_with("20 text/gemini\r\n"), "{body}");
    assert!(
        body.contains("Received: 2026-10-01T09:00:00Z. A person reads every application."),
        "{body}"
    );
    assert!(body.contains("Stage: received"), "{body}");
    assert!(!body.contains("<!doctype html>"), "a gemini client reads gemtext");
}

#[tokio::test]
async fn gmid_asks_for_the_capsule_and_gets_the_catalogue() {
    let (app, _dir) = handler("gmid-catalogue").await;
    // The path gmid sends for the capsule's front page: every leading slash
    // stripped, which is why the route table is written against that form.
    let (code, body) = answer(&app, &gmid_get("", "")).await;
    assert_eq!(code, 20);
    assert!(body.starts_with("20 text/gemini\r\n"));
    assert!(
        body.contains("=> gemini://mail.kyriakon.net/ Mail: zero-access mail"),
        "{body}"
    );
}

#[tokio::test]
async fn a_path_neither_front_end_serves_is_refused_in_its_own_way() {
    let (app, _dir) = handler("refusals").await;
    let (code, body) = answer(&app, &httpd_get("/nonsense", "")).await;
    assert_eq!(code, 404);
    assert!(body.starts_with("Status: 404 Not Found\r\n"), "{body}");

    let (code, _body) = answer(&app, &httpd_post("/account", "username=x")).await;
    assert_eq!(code, 405, "the account page is not a submission");

    let (code, body) = answer(&app, &gmid_get("nonsense", "")).await;
    assert_eq!(code, 51, "a capsule page that does not exist");
    assert!(body.starts_with("51 Not found\r\n"), "{body}");
}

#[tokio::test]
async fn a_gemini_request_for_an_unknown_token_reads_as_one_that_expired() {
    let (app, dir) = handler("gmid-token").await;
    let (code, unknown_body) = answer(&app, &gmid_get(&format!("status/{TOKEN}"), "")).await;
    assert_eq!(code, 20, "a token that names nothing is still a page");
    assert!(unknown_body.contains(UNKNOWN_TOKEN), "{unknown_body}");

    // A decided application past its window reads byte for byte the same.
    file_application(
        &dir,
        &decided(
            "decided: an account without charge",
            Some("2026-10-01T09:00:00Z"),
            None,
        ),
    );
    let (_, expired_body) = answer(&app, &gmid_get(&format!("status/{TOKEN}"), "")).await;
    assert!(expired_body.contains(UNKNOWN_TOKEN), "{expired_body}");
    assert_eq!(expired_body, unknown_body, "the two reads are one page");
}

// The environment traps: what each front-end sends, and what is read from it.

#[tokio::test]
async fn the_gemini_environment_is_read_as_gmid_builds_it() {
    let (app, _dir) = handler("gmid-env").await;
    let bytes = gmid_get(&format!("status/{TOKEN}"), "answer=%0Aline&plus=+");
    let request = fcgi::read_request(&mut &bytes[..], MAX_BODY)
        .await
        .unwrap()
        .unwrap();

    // The path arrives with no leading slash and is not re-encoded; a request for
    // the same page written with slashes and with percent-encoding answers it.
    let incoming = read(FrontEnd::Gemini, &request);
    assert_eq!(incoming.path, format!("status/{TOKEN}"));
    assert_eq!(incoming.addr, "203.0.113.10");
    // REMOTE_ADDR is the socket peer and is the key, because gmid sends no
    // forwarded header at all.
    assert_eq!(incoming.key, Key::V4(Ipv4Addr::new(203, 0, 113, 10)));

    // A certificate is not required for anything here, and AUTH_TYPE is present
    // and empty rather than absent: nothing tests for a variable, so nothing
    // changes.
    assert_eq!(request.get("AUTH_TYPE"), Some(""));
    let (code, _) = answer(&app, &bytes).await;
    assert_eq!(code, 20, "an anonymous visit reads the same page");
}

#[tokio::test]
async fn the_web_environment_is_read_as_httpd_builds_it() {
    let (app, _dir) = handler("httpd-env").await;
    let bytes = httpd_get("/status/abc%64efghjkmnpqrstvwxyz0123", "");
    let request = fcgi::read_request(&mut &bytes[..], MAX_BODY)
        .await
        .unwrap()
        .unwrap();
    let incoming = read(FrontEnd::Httpd, &request);

    // The request URI is percent-decoded here, and the query is cut off before
    // the decoding.
    assert_eq!(incoming.path, format!("status/{TOKEN}"));
    // The socket peer is relayd, so the key is the header relayd set: the last
    // element, which a client cannot choose because the relay replaces the value
    // rather than appending to it.
    assert_eq!(incoming.key, Key::V4(Ipv4Addr::new(203, 0, 113, 10)));

    let bytes = fixture::httpd(
        &[
            ("REQUEST_METHOD", "GET"),
            ("REQUEST_URI", "/?branch=body"),
            ("QUERY_STRING", "branch=body"),
            ("HTTP_X_FORWARDED_FOR", "192.0.2.9, 203.0.113.10"),
            ("REMOTE_ADDR", "127.0.0.1"),
        ],
        b"",
    );
    let request = fcgi::read_request(&mut &bytes[..], MAX_BODY)
        .await
        .unwrap()
        .unwrap();
    let incoming = read(FrontEnd::Httpd, &request);
    assert_eq!(incoming.path, "", "the query is not part of the path");
    assert_eq!(incoming.key, Key::V4(Ipv4Addr::new(203, 0, 113, 10)));
    let (code, body) = answer(&app, &bytes).await;
    assert_eq!(code, 200);
    assert!(body.contains("id=\"body_name\""), "the body block is open");
}

#[test]
fn a_form_field_is_decoded_and_a_plus_is_a_space() {
    let f = fields("username=theo+philus&cannot_pay=one%0Atwo&accept_terms=yes");
    assert_eq!(f.get("username").unwrap(), "theo philus");
    assert_eq!(f.get("cannot_pay").unwrap(), "one\ntwo");
    assert_eq!(f.get("accept_terms").unwrap(), "yes");
    assert!(fields("").is_empty());
}

// The routes the service carried before the transport changed.

#[tokio::test]
async fn the_branch_question_opens_the_block_by_being_answered() {
    let (app, _dir) = handler("branch").await;

    // The page as it opens: a person's, with no community block on it and the
    // branch its own form carries recorded as a person's.
    let (_, fresh) = answer(&app, &httpd_get("/", "")).await;
    assert!(fresh.contains("name=\"branch\" value=\"person\""));
    assert!(!fresh.contains("id=\"body_name\""));

    // Answering for a body: the form's own continuation posts the answers back and
    // the page comes back with the block open, holding them.
    let body = encoded(&[("username", "theophilus"), ("whose", "body")]);
    let (_, answered) = answer(&app, &httpd_post("/", &body)).await;
    assert!(answered.contains("id=\"body_name\""), "the block is open");
    assert!(answered.contains("name=\"branch\" value=\"body\""));
    assert!(
        answered.contains("value=\"theophilus\""),
        "what was already typed comes back"
    );

    // Answering for a person closes it again.
    let body = encoded(&[("whose", "person")]);
    let (_, closed) = answer(&app, &httpd_post("/", &body)).await;
    assert!(!closed.contains("id=\"body_name\""));
    assert!(closed.contains("name=\"branch\" value=\"person\""));
}

#[tokio::test]
async fn a_body_submission_that_was_shown_the_block_is_filed() {
    let (app, dir) = handler("body-filed").await;

    // The block is opened the way an applicant opens it, by answering the branch
    // question, and the page that comes back is the one submitted to.
    let body = encoded(&[("whose", "body")]);
    let (_, page) = answer(&app, &httpd_post("/", &body)).await;
    let answers = body_answers();
    assert!(page.contains("id=\"body_name\""), "the block is open");
    assert!(
        !page.contains("name=\"mail_key\""),
        "a body is not shown the person's key"
    );
    for (id, _) in &answers {
        assert!(page.contains(&format!("name=\"{id}\"")), "{id} is on the page");
    }
    for q in questions::shown(&app.questions, false).iter().filter(|q| q.required) {
        assert!(
            page.contains(&format!("name=\"{}\"", q.id)),
            "the required question {} is on the page",
            q.id
        );
    }

    // Submitting it is not a refusal for a question the page did not show, and it
    // files the application.
    let (code, _) = answer(&app, &httpd_post("/apply", &encoded(&answers))).await;
    assert_eq!(code, 200, "a body applicant who filled in the block is not refused");
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
    let (code, page) = answer(&app, &httpd_post("/apply", &body)).await;
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
        let (code, page) = answer(&app, &bytes).await;
        assert_eq!(code, 403, "{path}");
        assert!(page.contains("A submission has to come from this form"));
    }
    assert_eq!(std::fs::read_dir(dir.join("applications")).unwrap().count(), 0);

}

#[tokio::test]
async fn a_submission_whose_body_overruns_the_cap_is_refused() {
    let (app, dir) = handler("too-large").await;
    let long = format!("anything_else={}", "x".repeat(MAX_BODY + 1));
    let (code, _) = answer(&app, &httpd_post("/apply", &long)).await;
    assert_eq!(code, 413);
    assert_eq!(std::fs::read_dir(dir.join("applications")).unwrap().count(), 0);
}

#[tokio::test]
async fn a_body_that_is_not_a_form_post_is_refused() {
    let (app, _dir) = handler("wrong-type").await;
    let bytes = fixture::httpd(
        &[
            ("REQUEST_METHOD", "POST"),
            ("REQUEST_URI", "/apply"),
            ("CONTENT_TYPE", "text/plain"),
            ("HTTP_ORIGIN", OWN_ORIGIN),
            ("REMOTE_ADDR", "127.0.0.1"),
        ],
        b"username=theophilus",
    );
    let (code, _) = answer(&app, &bytes).await;
    assert_eq!(code, 415);
}

#[tokio::test]
async fn the_counters_refuse_the_sixty_first_request_and_the_sixth_draft() {
    let (app, _dir) = handler("counters").await;
    // Every request from one address is counted, whatever route it names.
    for i in 0..rate::REQUESTS_PER_MINUTE {
        let (code, _) = answer(&app, &httpd_get("/", "")).await;
        assert_eq!(code, 200, "request {i} was refused");
    }
    let (code, page) = answer(&app, &httpd_get("/", "")).await;
    assert_eq!(code, 429);
    assert!(page.contains("Wait a minute and try again."));

    // The gemini front-end is counted the same way and refuses in its own status.
    let (app, _dir) = handler("counters-gemini").await;
    for _ in 0..rate::REQUESTS_PER_MINUTE {
        answer(&app, &gmid_get("", "")).await;
    }
    let (code, body) = answer(&app, &gmid_get("", "")).await;
    assert_eq!(code, 44, "gemini's own slow down");
    assert!(body.starts_with("44 Too many requests"), "{body}");
}

#[tokio::test]
async fn the_status_page_answers_for_seven_days_after_a_decision() {
    let (app, dir) = handler("status-window").await;
    file_application(&dir, &decided("received", None, None));
    let (code, page) = answer(&app, &httpd_get(&format!("/status/{TOKEN}"), "")).await;
    assert_eq!(code, 200);
    assert!(page.contains("Cache-Control: no-store\r\n"), "{page}");
    assert!(page.contains("Referrer-Policy: no-referrer\r\n"), "{page}");
    assert!(page.contains("Stage</td><td>received"), "{page}");

    let (code, _) = answer(&app, &httpd_get("/status/not-a-token", "")).await;
    assert_eq!(code, 200, "a token that is not one reads as unknown, not as an error");
}

#[test]
fn a_decided_application_answers_for_seven_days_and_then_reads_as_unknown() {
    let now = at("2026-10-05T09:00:00Z");
    // Filed and not yet decided: the link answers.
    let filed = status_page(Some(decided("received", None, None)), now);
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
        now,
    );
    assert_eq!(inside.notice, "");
    assert_eq!(inside.stage, "decided: an account without charge");
    assert_eq!(
        inside.password_link.as_deref(),
        Some("https://signup.kyriakon.net/password/abcdefghjkmnpqrstvwxyz")
    );

    // A record without a password link renders none.
    let without = status_page(Some(decided("received", None, None)), now);
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
        at("2026-10-08T09:00:01Z"),
    );
    let unknown = status_page(None, now);
    assert_eq!(expired.notice, UNKNOWN_TOKEN);
    assert_eq!(expired.stage, "");
    assert_eq!(expired.filed_at, "");
    assert_eq!(expired.password_link, None, "an expired link renders no password link either");
    assert_eq!(
        (expired.notice, expired.stage, expired.filed_at),
        (unknown.notice, unknown.stage, unknown.filed_at)
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

#[test]
fn key_blocks_splits_one_per_mailbox() {
    let two = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAA\n-----END PGP PUBLIC KEY BLOCK-----\n\n-----BEGIN PGP PUBLIC KEY BLOCK-----\nBBB\n-----END PGP PUBLIC KEY BLOCK-----\n";
    assert_eq!(key_blocks(two).len(), 2);
    assert!(key_blocks("nothing here").is_empty());
}

#[test]
fn a_submission_must_come_from_this_form() {
    let request = |env: &[(&str, &str)]| {
        let bytes = fixture::httpd(env, b"");
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async { fcgi::read_request(&mut &bytes[..], MAX_BODY).await.unwrap().unwrap() })
    };
    assert!(
        own_origin(&request(&[("REQUEST_METHOD", "POST")])),
        "a client that is not a browser is allowed"
    );
    assert!(own_origin(&request(&[("HTTP_ORIGIN", OWN_ORIGIN)])));
    assert!(!own_origin(&request(&[("HTTP_ORIGIN", "https://elsewhere.example")])));
    assert!(!own_origin(&request(&[("HTTP_SEC_FETCH_SITE", "cross-site")])));
    assert!(own_origin(&request(&[("HTTP_SEC_FETCH_SITE", "same-origin")])));
}

#[test]
fn the_body_addresses_are_counted_against_its_account_names() {
    let mut errors = Vec::new();
    let mut form = BTreeMap::new();
    form.insert("body_addresses".into(), "secretary: own\nhall: alias secretary".into());
    form.insert("body_account_names".into(), "secretary".into());
    body_cross_checks(&form, &mut errors);
    assert!(errors.iter().any(|e| e.contains("2 addresses and 1 account names")), "{errors:?}");

    errors.clear();
    form.insert("body_account_names".into(), "secretary\nhall".into());
    body_cross_checks(&form, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
}
