//! Tests for the connection module.

use super::super::{FrontEnd, MAX_BODY, OWN_ORIGIN};
use super::{fields, read};
use crate::fastcgi::{self, fixture};
use crate::responder::flow::own_origin;
use crate::responder::test_support::*;
use kyriakon_control_core::flow::rate::Key;
use std::net::Ipv4Addr;

#[tokio::test]
async fn the_gemini_environment_is_read_as_gmid_builds_it() {
    let (app, _dir) = handler("gmid-env").await;
    let bytes = gmid_get(&format!("status/{TOKEN}"), "answer=%0Aline&plus=+");
    let request = fastcgi::read_request(&mut &bytes[..], MAX_BODY)
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
    let request = fastcgi::read_request(&mut &bytes[..], MAX_BODY)
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
    let request = fastcgi::read_request(&mut &bytes[..], MAX_BODY)
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
                fastcgi::read_request(&mut &bytes[..], MAX_BODY)
                    .await
                    .unwrap()
                    .unwrap()
            })
    };
    assert!(
        own_origin(&request(&[("REQUEST_METHOD", "POST")]), false),
        "a client that is not a browser is allowed on the application route"
    );
    assert!(own_origin(&request(&[("HTTP_ORIGIN", OWN_ORIGIN)]), true));
    assert!(!own_origin(
        &request(&[("HTTP_ORIGIN", "https://elsewhere.example")]),
        true
    ));
    assert!(!own_origin(
        &request(&[("HTTP_SEC_FETCH_SITE", "cross-site")]),
        false
    ));
    assert!(own_origin(
        &request(&[("HTTP_SEC_FETCH_SITE", "same-origin")]),
        false
    ));
}

/// The browser matrix #704 was opened with, replayed through the guard. Each row
/// is what a real client sent for a form POST from a page on a sibling subdomain,
/// and whether that client also attached the host-only `SameSite=Lax` session
/// cookie: Chromium 150 and 156 and WebKit as installed on this workstation, plus
/// `curl`. The rows that carry the cookie are the attack; a session route must
/// refuse every one of them.
#[test]
fn a_client_that_withholds_its_origin_reaches_no_session() {
    let request = |env: &[(&str, &str)]| {
        let bytes = fixture::httpd(env, b"");
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                fastcgi::read_request(&mut &bytes[..], MAX_BODY)
                    .await
                    .unwrap()
                    .unwrap()
            })
    };
    // (what sent it, Origin, Sec-Fetch-Site, application route, session route)
    type Row<'a> = (&'a str, Option<&'a str>, Option<&'a str>, bool, bool);
    let rows: &[Row<'_>] = &[
        (
            "this page's own form, cookie attached",
            Some(OWN_ORIGIN),
            Some("same-origin"),
            true,
            true,
        ),
        (
            "sibling subdomain, top-level form, cookie attached",
            Some("https://alice.kyriakon.net"),
            Some("same-site"),
            false,
            false,
        ),
        (
            // WebKit 27.2 attached the cookie and sent no Sec-Fetch-Site;
            // Chromium sent none either and withheld the cookie.
            "sandboxed allow-forms frame, no Sec-Fetch-Site, cookie attached",
            Some("null"),
            None,
            true,
            false,
        ),
        (
            "sandboxed allow-forms frame, same-site, cookie attached",
            Some("null"),
            Some("same-site"),
            true,
            false,
        ),
        (
            "sandboxed allow-forms frame, cross-site",
            Some("null"),
            Some("cross-site"),
            false,
            false,
        ),
        ("data: document", Some("null"), None, true, false),
        (
            "in-app browser, as the old comment described it",
            Some("null"),
            Some("same-origin"),
            true,
            false,
        ),
        ("curl, no browser headers at all", None, None, true, false),
    ];
    for (what, origin, site, application, session) in rows {
        let mut env = vec![("REQUEST_METHOD", "POST")];
        if let Some(origin) = origin {
            env.push(("HTTP_ORIGIN", *origin));
        }
        if let Some(site) = site {
            env.push(("HTTP_SEC_FETCH_SITE", *site));
        }
        let request = request(&env);
        assert_eq!(
            own_origin(&request, false),
            *application,
            "{what}: the application route"
        );
        assert_eq!(
            own_origin(&request, true),
            *session,
            "{what}: a session route"
        );
    }
}

/// The matrix's WebKit row, end to end: the front end refuses a `null` Origin on
/// every route that acts on the session, before the handler reads the cookie the
/// browser attached, and still answers the applicant form from a client that has
/// no origin to name.
#[tokio::test]
async fn a_null_origin_reaches_no_session_route_but_still_reaches_the_form() {
    let (app, _dir) = handler("null-origin").await;
    let cookie = signed_in(&app, "alice").await;

    for path in ["account/upload-key", "account/close", "account", "logout"] {
        let (code, page) = ask(
            &app,
            &httpd_post_from(path, "", Some("null"), None, Some(&cookie)),
        )
        .await;
        assert_eq!(code, 403, "{path}: {page}");
        assert!(page.contains("own page"), "{path}: {page}");
    }
    // A client that sends no Origin at all is refused on a session route too: the
    // cookie is the identity, and only this page's own origin may carry it.
    let (code, page) = ask(
        &app,
        &httpd_post_from("account/upload-key", "", None, None, Some(&cookie)),
    )
    .await;
    assert_eq!(code, 403, "{page}");
    assert!(page.contains("own page"), "{page}");

    // The application route keeps the client the fallback was written for.
    for (path, body) in [("apply", "username=theophilus"), ("", "whose=body")] {
        let (code, page) = ask(&app, &httpd_post_from(path, body, Some("null"), None, None)).await;
        assert_ne!(code, 403, "{path}: {page}");
    }
}

/// The path is decoded before it reaches the log, so a client can put a newline
/// in it. The audit line is one request per line: a control character is
/// replaced, and the forged line never reaches stderr.
#[test]
fn a_control_character_in_the_path_never_forges_a_log_line() {
    let incoming = crate::responder::Incoming {
        path: "status/x\nkyriakon-control: httpd /status/forged 200 198.51.100.7".to_string(),
        query: String::new(),
        key: Key::V4(Ipv4Addr::new(203, 0, 113, 10)),
        addr: "203.0.113.10".to_string(),
        certificate: None,
    };
    let outcome = super::outcome(
        incoming,
        crate::fastcgi::Reply::Gemini {
            status: 20,
            meta: "text/gemini".to_string(),
            body: String::new(),
        },
    );
    assert!(!outcome.route.contains('\n'), "{}", outcome.route);
    assert!(
        !outcome.route.chars().any(char::is_control),
        "{}",
        outcome.route
    );
    assert_eq!(
        outcome.route,
        "/status/x?kyriakon-control: httpd /status/forged 200 198.51.100.7"
    );
}
