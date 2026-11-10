//! Tests for the connection module.

use crate::fcgi::{self, fixture};
use crate::rate::Key;
use crate::responder::test_support::*;
use crate::responder::*;
use std::net::Ipv4Addr;

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

    // An anonymous request carries no AUTH_TYPE at all, which is what gmid sends.
    assert_eq!(request.get("AUTH_TYPE"), None);
    let (code, _) = ask(&app, &bytes).await;
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
    let (code, body) = ask(&app, &bytes).await;
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
async fn a_submission_whose_body_overruns_the_cap_is_refused() {
    let (app, dir) = handler("too-large").await;
    let long = format!("anything_else={}", "x".repeat(MAX_BODY + 1));
    let (code, _) = ask(&app, &httpd_post("/apply", &long)).await;
    assert_eq!(code, 413);
    assert_eq!(
        std::fs::read_dir(dir.join("applications")).unwrap().count(),
        0
    );
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
    let (code, _) = ask(&app, &bytes).await;
    assert_eq!(code, 415);
}

#[test]
fn a_submission_must_come_from_this_form() {
    let request = |env: &[(&str, &str)]| {
        let bytes = fixture::httpd(env, b"");
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                fcgi::read_request(&mut &bytes[..], MAX_BODY)
                    .await
                    .unwrap()
                    .unwrap()
            })
    };
    assert!(
        own_origin(&request(&[("REQUEST_METHOD", "POST")])),
        "a client that is not a browser is allowed"
    );
    assert!(own_origin(&request(&[("HTTP_ORIGIN", OWN_ORIGIN)])));
    assert!(!own_origin(&request(&[(
        "HTTP_ORIGIN",
        "https://elsewhere.example"
    )])));
    assert!(!own_origin(&request(&[(
        "HTTP_SEC_FETCH_SITE",
        "cross-site"
    )])));
    assert!(own_origin(&request(&[(
        "HTTP_SEC_FETCH_SITE",
        "same-origin"
    )])));
}
