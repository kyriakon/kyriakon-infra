//! Tests for the connection module.

use super::super::route::{Method, ROUTES};
use super::super::{FrontEnd, MAX_BODY, OWN_ORIGIN};
use super::{fields, read};
use crate::fastcgi::{self, fixture};
use crate::responder::flow::{own_origin, Reaches};
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

/// One request built from httpd's environment, as the front end reads it.
fn httpd_request(env: &[(&str, &str)]) -> fastcgi::Request {
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
}

#[test]
fn a_submission_must_come_from_this_form() {
    assert!(
        own_origin(&httpd_request(&[("REQUEST_METHOD", "POST")]), Reaches::Form),
        "a client that is not a browser is allowed on the application route"
    );
    assert!(own_origin(
        &httpd_request(&[("HTTP_ORIGIN", OWN_ORIGIN)]),
        Reaches::Session
    ));
    assert!(!own_origin(
        &httpd_request(&[("HTTP_ORIGIN", "https://elsewhere.example")]),
        Reaches::Session
    ));
    assert!(!own_origin(
        &httpd_request(&[("HTTP_SEC_FETCH_SITE", "cross-site")]),
        Reaches::Form
    ));
    assert!(own_origin(
        &httpd_request(&[("HTTP_SEC_FETCH_SITE", "same-origin")]),
        Reaches::Form
    ));
}

/// #761: a cross-site login is a login CSRF, which leaves the victim signed in to
/// the attacker's account. The login takes no cookie, so it keeps the
/// `Sec-Fetch-Site` fallback, but only a signal that says this page: a client
/// that sends neither header cannot be told apart from the sandboxed frame.
#[test]
fn a_login_must_name_itself_as_this_page() {
    // The refusal #761 is about: a sandboxed frame's `null` and no Fetch
    // Metadata, and a client that sends no browser headers at all.
    for env in [
        vec![("HTTP_ORIGIN", "null")],
        vec![
            ("HTTP_ORIGIN", "null"),
            ("HTTP_SEC_FETCH_SITE", "same-site"),
        ],
        vec![("HTTP_SEC_FETCH_SITE", "cross-site")],
        vec![],
    ] {
        assert!(
            !own_origin(&httpd_request(&env), Reaches::Login),
            "a login from {env:?} is not this page's"
        );
    }
    // The ordinary submit: this site's own Origin, the page's own Fetch
    // Metadata, or the user following a link to the form.
    for env in [
        vec![("HTTP_ORIGIN", OWN_ORIGIN)],
        vec![("HTTP_SEC_FETCH_SITE", "same-origin")],
        vec![("HTTP_SEC_FETCH_SITE", "none")],
    ] {
        assert!(
            own_origin(&httpd_request(&env), Reaches::Login),
            "a login from {env:?} is this page's"
        );
    }
}

/// The browser matrix #704 was opened with, replayed through the guard.
///
/// *Observed* rows are what a recording endpoint logged for a form POST from a
/// page on a sibling subdomain (`evil.lvh.me`) to this site (`signup.lvh.me`) in
/// Chromium 150 and 156, WebKit 27.2 and `curl`. WebKit attached the host-only
/// `SameSite=Lax` session cookie on every opaque-origin row; Chromium on none of
/// them. Neither browser sent a `Sec-Fetch-*` header on any request, so every
/// observed row's `Sec-Fetch-Site` is absent: a row that names one is
/// *fabricated*, and only walks the fallback's branches, which no local client
/// reached. This site's own form is *not recorded* — the matrix had no page on
/// this site — and the in-app row is the *premise* the old comment rested on,
/// never run, because no device or WebView was available here. The rows that
/// carry the cookie are the attack; a session route must refuse every one of
/// them.
#[test]
fn a_client_that_withholds_its_origin_reaches_no_session() {
    const SIBLING: &str = "https://alice.kyriakon.net";
    // (what sent it, Origin, Sec-Fetch-Site, application route, session route)
    type Row<'a> = (&'a str, Option<&'a str>, Option<&'a str>, bool, bool);
    let rows: &[Row<'_>] = &[
        (
            "observed: sibling subdomain, top-level form, cookie attached",
            Some(SIBLING),
            None,
            false,
            false,
        ),
        (
            // WebKit attached the cookie and sent no Sec-Fetch-Site; Chromium sent
            // none either and withheld the cookie.
            "observed: sandbox allow-forms, user click, cookie attached",
            Some("null"),
            None,
            true,
            false,
        ),
        (
            "observed: sandbox allow-forms, target=_top, cookie attached",
            Some("null"),
            None,
            true,
            false,
        ),
        (
            "observed: sandbox allow-scripts allow-forms, script submit",
            Some("null"),
            None,
            true,
            false,
        ),
        (
            "observed: sandbox allow-forms allow-same-origin",
            Some(SIBLING),
            None,
            false,
            false,
        ),
        (
            // No cookie: the document is opaque and Chromium never had one to
            // attach. WebKit's row carried one and is the branch above.
            "observed: data: document",
            Some("null"),
            None,
            true,
            false,
        ),
        (
            "observed: blob: document made by the attacker page",
            Some(SIBLING),
            None,
            false,
            false,
        ),
        (
            "observed: curl, no browser headers at all",
            None,
            None,
            true,
            false,
        ),
        (
            "not recorded: this site's own form, cookie attached",
            Some(OWN_ORIGIN),
            None,
            true,
            true,
        ),
        (
            "fabricated: blank Origin and same-site",
            Some("null"),
            Some("same-site"),
            true,
            false,
        ),
        (
            "fabricated: blank Origin and cross-site",
            Some("null"),
            Some("cross-site"),
            false,
            false,
        ),
        (
            "fabricated: absent Origin and same-origin",
            None,
            Some("same-origin"),
            true,
            false,
        ),
        (
            "fabricated: absent Origin and same-site",
            None,
            Some("same-site"),
            true,
            false,
        ),
        (
            "fabricated: absent Origin and none",
            None,
            Some("none"),
            true,
            false,
        ),
        (
            "fabricated: absent Origin and cross-site",
            None,
            Some("cross-site"),
            false,
            false,
        ),
        (
            "premise: in-app browser, as the old comment described it",
            Some("null"),
            Some("same-origin"),
            true,
            false,
        ),
    ];
    for (what, origin, site, application, session) in rows {
        let mut env = vec![("REQUEST_METHOD", "POST")];
        if let Some(origin) = origin {
            env.push(("HTTP_ORIGIN", *origin));
        }
        if let Some(site) = site {
            env.push(("HTTP_SEC_FETCH_SITE", *site));
        }
        let request = httpd_request(&env);
        assert_eq!(
            own_origin(&request, Reaches::Form),
            *application,
            "{what}: the application route"
        );
        assert_eq!(
            own_origin(&request, Reaches::Session),
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

    // Read from the table rather than listed here, so a route added later is
    // covered without a test edit. A prefix row such as `account/` is posted as
    // its own path: the guard answers before a route is chosen, so nothing has to
    // be invented for it.
    let mut checked = 0;
    for row in ROUTES
        .iter()
        .filter(|row| row.method == Method::Post && row.handler.takes_session())
    {
        // `null` is the WebKit row; no Origin at all is the client that sends no
        // browser headers, and the cookie is the identity for both.
        for origin in [Some("null"), None] {
            let (code, page) = ask(
                &app,
                &httpd_post_from(row.path, "", origin, None, Some(&cookie)),
            )
            .await;
            assert_eq!(code, 403, "{} with origin {origin:?}: {page}", row.path);
            assert!(page.contains("own page"), "{}: {page}", row.path);
            checked += 1;
        }
    }
    assert!(checked > 0, "the table names no session route");

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
