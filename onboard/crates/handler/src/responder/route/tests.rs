//! Tests for the route module.

use super::super::FrontEnd;
use super::{Fronts, Handler, Method, Resolution, Route, ROUTES};
use crate::capsule;
use crate::responder::test_support::*;
use kyriakon_onboard_core::flow::rate;

#[tokio::test]
async fn a_page_httpd_asks_for_comes_back_as_http() {
    let (app, _dir) = handler("httpd-form").await;
    let (code, body) = ask(&app, &httpd_get("/", "")).await;

    assert_eq!(code, 200);
    assert!(body.starts_with("Status: 200 OK\r\n"), "{body}");
    assert!(
        body.contains("Content-Type: text/html; charset=utf-8\r\n"),
        "the page is served as what it is: {body}"
    );
    assert!(
        body.contains("action=\"/apply\""),
        "the form is on the page"
    );
    assert!(body.contains("name=\"branch\" value=\"person\""), "{body}");
    assert!(
        body.contains("How you will pay"),
        "the shared question list is rendered"
    );
    assert!(
        !body.contains("Cache-Control"),
        "the form is not a capability in a URL"
    );
}

#[tokio::test]
async fn a_page_gmid_asks_for_comes_back_as_gemini() {
    let (app, dir) = handler("gmid-status").await;
    stage_application(&dir, &decided("received", None, None));

    let (code, body) = ask(&app, &gmid_get(&format!("status/{TOKEN}"), "")).await;

    assert_eq!(code, 20, "a filed application answers");
    assert!(body.starts_with("20 text/gemini\r\n"), "{body}");
    assert!(
        body.contains("Received: 2026-10-01T09:00:00Z. A person reads every application."),
        "{body}"
    );
    assert!(body.contains("Stage: received"), "{body}");
    assert!(
        !body.contains("<!doctype html>"),
        "a gemini client reads gemtext"
    );
}

#[tokio::test]
async fn a_path_neither_front_end_serves_is_refused_in_its_own_way() {
    let (app, _dir) = handler("refusals").await;
    let (code, body) = ask(&app, &httpd_get("/nonsense", "")).await;
    assert_eq!(code, 404);
    assert!(body.starts_with("Status: 404 Not Found\r\n"), "{body}");

    let (code, _body) = ask(&app, &httpd_post("/nonsense", "")).await;
    assert_eq!(code, 404, "an unserved path answers 404 to a post too");

    let (code, body) = ask(&app, &gmid_get("nonsense", "")).await;
    assert_eq!(code, 51, "a capsule page that does not exist");
    assert!(body.starts_with("51 Not found\r\n"), "{body}");
}

/// The path and the method a row is asked for: a subtree row gets one path under
/// it, and a row's own method is what the web front end would send for it.
fn probe(row: &Route) -> (String, &'static str) {
    let path = match row.path {
        "status/" | "decide/" | "password/" => format!("{}{TOKEN}", row.path),
        "apply/" => format!("{}{TOKEN}/1", row.path),
        "account/" => format!("{}password", row.path),
        other => other.to_string(),
    };
    let method = match row.method {
        Method::Post => "POST",
        Method::Get | Method::Any => "GET",
    };
    (path, method)
}

/// The table is the only route list: every row is reached by each front end it
/// names and by no other, and a second row claiming one front end's path and
/// method fails here, because the first is the only one reached.
#[test]
fn every_row_is_reached_by_the_front_ends_it_names() {
    for row in ROUTES {
        assert!(
            !(row.fronts.serves(FrontEnd::Httpd) && row.method == Method::Any),
            "{} checks a method on the web front end, so it cannot be `Any`",
            row.path
        );
        let (path, method) = probe(row);
        for front in [FrontEnd::Httpd, FrontEnd::Gemini] {
            let reached = match super::route(front, &path, method) {
                Resolution::Row(found, _) => Some(found),
                Resolution::WrongMethod | Resolution::Missing => None,
            };
            if row.fronts.serves(front) {
                assert_eq!(
                    reached,
                    Some(row),
                    "{front:?} does not reach the {:?} row for {path}",
                    row.path
                );
            } else {
                assert_ne!(
                    reached,
                    Some(row),
                    "{front:?} reaches the {:?} row, which is not its front end",
                    row.path
                );
            }
        }
    }
}

/// A mirrored page is a row in the table beside its line in `capsule::PAGES`,
/// because the route, the staged file and the link label must name one page.
/// This is the test that keeps the two lists the same list.
#[test]
fn every_staged_page_is_a_mirrored_row_and_nothing_else_is() {
    let rows: Vec<&str> = ROUTES
        .iter()
        .filter(|row| row.handler == Handler::Mirrored)
        .map(|row| row.path)
        .collect();
    let staged: Vec<&str> = capsule::PAGES.iter().map(|(route, _, _)| *route).collect();
    assert_eq!(rows, staged);
    for row in ROUTES.iter().filter(|row| row.handler == Handler::Mirrored) {
        assert_eq!(
            row.fronts,
            Fronts::Gemini,
            "{} is gemtext and has no HTML rendering",
            row.path
        );
    }
    assert!(
        ROUTES
            .iter()
            .any(|row| row.handler == Handler::Acceptances && row.path == capsule::ACCEPTANCES),
        "the acceptances page is a route too"
    );
}

/// Every row the table gives both front ends answers on both: this is the check
/// the two chains could not make, and a row added without its capsule rendering
/// answers 51 here.
#[tokio::test]
async fn every_shared_row_answers_on_both_front_ends() {
    let (app, _dir) = handler("route-table-both").await;
    for row in ROUTES.iter().filter(|row| row.fronts == Fronts::Both) {
        let (path, method) = probe(row);
        let request = if method == "POST" {
            httpd_post(&format!("/{path}"), "")
        } else {
            httpd_get(&format!("/{path}"), "")
        };
        let (code, _) = ask(&app, &request).await;
        assert_ne!(code, 404, "httpd does not reach /{path}");
        let (code, _) = ask(&app, &gmid_get(&path, "")).await;
        assert_ne!(code, 51, "gmid does not reach /{path}");
    }
}

/// A row that serves one front end is that front end's: the web answers its 404
/// for a capsule-only page, and the capsule answers its 51 wherever the table
/// says it serves no path. A page therefore cannot be added on one side alone.
#[tokio::test]
async fn protocol_only_rows_are_refused_by_the_other_front_end() {
    let (app, _dir) = handler("route-table-only").await;
    for row in ROUTES.iter().filter(|row| row.fronts == Fronts::Gemini) {
        let (path, _) = probe(row);
        let (code, body) = ask(&app, &httpd_get(&format!("/{path}"), "")).await;
        assert_eq!(code, 404, "httpd serves /{path}: {body}");
    }
    for row in ROUTES.iter().filter(|row| row.fronts == Fronts::Httpd) {
        let (path, method) = probe(row);
        let request = if method == "POST" {
            httpd_post(&format!("/{path}"), "")
        } else {
            httpd_get(&format!("/{path}"), "")
        };
        let (code, _) = ask(&app, &request).await;
        assert_ne!(code, 404, "httpd does not reach /{path}");
        // The root's POST row shares its path with the shared GET row, so the
        // capsule serves that path; it cannot serve the row, which is what
        // `every_row_is_reached_by_the_front_ends_it_names` checks.
        let served = ROUTES
            .iter()
            .any(|other| other.fronts.serves(FrontEnd::Gemini) && other.matches(&path).is_some());
        let (code, _) = ask(&app, &gmid_get(&path, "")).await;
        assert_eq!(
            code == 51,
            !served,
            "gmid answers {code} for /{path}, which the table gives it: {served}"
        );
    }
}

#[tokio::test]
async fn the_counters_refuse_the_sixty_first_request_and_the_sixth_draft() {
    let (app, _dir) = handler("counters").await;
    // Every request from one address is counted, whatever route it names.
    for i in 0..rate::REQUESTS_PER_MINUTE {
        let (code, _) = ask(&app, &httpd_get("/", "")).await;
        assert_eq!(code, 200, "request {i} was refused");
    }
    let (code, page) = ask(&app, &httpd_get("/", "")).await;
    assert_eq!(code, 429);
    assert!(page.contains("Wait a minute and try again."));

    // The gemini front-end is counted the same way and refuses in its own status.
    let (app, _dir) = handler("counters-gemini").await;
    for _ in 0..rate::REQUESTS_PER_MINUTE {
        ask(&app, &gmid_get("", "")).await;
    }
    let (code, body) = ask(&app, &gmid_get("", "")).await;
    assert_eq!(code, 44, "gemini's own slow down");
    assert!(body.starts_with("44 Too many requests"), "{body}");
}
