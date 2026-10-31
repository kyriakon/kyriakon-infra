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
    let dir = fixture_dir(name);
    // The deploy stages these from `scripts/render-docs.sh --gemini`; the
    // fixture writes one file per route so the startup read sees the same shape.
    for (_, file, _) in capsule::PAGES {
        std::fs::write(
            dir.join("pages").join(file),
            format!("# {file}\n\nA mirrored page.\n"),
        )
        .unwrap();
    }
    (App::load(handler_config(&dir)).await.unwrap(), dir)
}

/// The store and page directories, empty, for a test that stages its own pages.
fn fixture_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onboard-responder-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["applications", "intents", "pages"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    dir
}

/// The configuration every fixture handler loads: the tracked catalogue and
/// reserved names, the crate's question list, and the pages under `dir`.
fn handler_config(dir: &Path) -> config::Config {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    config::Config {
        store_root: dir.to_str().unwrap().to_string(),
        reserved: crate_dir
            .join("../reserved-usernames.txt")
            .to_str()
            .unwrap()
            .to_string(),
        catalogue: crate_dir
            .join("../openbsd/etc/onboard/catalogue.toml")
            .to_str()
            .unwrap()
            .to_string(),
        pages: dir.join("pages").to_str().unwrap().to_string(),
        httpd_socket: String::new(),
        gemini_socket: String::new(),
        portal_socket: String::new(),
        titan_listener: "127.0.0.1:0".to_string(),
        mail_host: "mail.kyriakon.net".to_string(),
        ipv4: "192.0.2.10".to_string(),
        ipv6: "2001:db8::10".to_string(),
        dkim_selector: "mail".to_string(),
        dkim_public_key: "v=DKIM1; k=rsa; p=example".to_string(),
        dmarc_rua: "mailto:dmarc@kyriakon.net".to_string(),
        release: "2026-10-13 test".to_string(),
        price_gbp: "20.00".to_string(),
        postal_address: "1 Example Street, Example".to_string(),
        stripe_payment_link: "https://buy.stripe.com/test_example".to_string(),
    }
}

/// A staging run that missed a page stops the handler rather than leaving a
/// route that answers 51 for a document the capsule promises.
#[tokio::test]
async fn the_handler_refuses_to_start_without_a_staged_page() {
    let dir = fixture_dir("missing-page");
    for (route, file, _) in capsule::PAGES {
        if *route == "aup" {
            continue;
        }
        std::fs::write(dir.join("pages").join(file), "# ok\n").unwrap();
    }
    let Err(err) = App::load(handler_config(&dir)).await else {
        panic!("the handler started without a page");
    };
    assert!(err.contains("aup.gmi"), "{err}");
}

/// An empty staged file is the same failure as a missing one: the page exists
/// and says nothing, which a reader would take for the document.
#[tokio::test]
async fn the_handler_refuses_an_empty_staged_page() {
    let dir = fixture_dir("empty-page");
    for (route, file, _) in capsule::PAGES {
        let body = if *route == "privacy" {
            String::new()
        } else {
            "# ok\n".to_string()
        };
        std::fs::write(dir.join("pages").join(file), body).unwrap();
    }
    let Err(err) = App::load(handler_config(&dir)).await else {
        panic!("the handler started on an empty page");
    };
    assert!(err.contains("privacy.gmi"), "{err}");
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
    assert_eq!(
        last,
        fixture::END,
        "the reply is finished rather than truncated"
    );
    (
        outcome.reply.code(),
        String::from_utf8_lossy(&body).into_owned(),
    )
}

/// The request httpd builds for a GET, with the address relayd set.
fn httpd_get(path: &str, query: &str) -> Vec<u8> {
    httpd_get_as(path, query, None)
}

/// A GET httpd authenticated, which is the one thing `REMOTE_USER` means. The
/// account page's login is its own ticket's; this is the environment it will
/// pass when it lands.
fn httpd_get_as(path: &str, query: &str, user: Option<&str>) -> Vec<u8> {
    let mut env = vec![
        ("REQUEST_METHOD", "GET"),
        ("REQUEST_URI", path),
        ("QUERY_STRING", query),
        ("HTTP_HOST", "signup.kyriakon.net"),
        ("SERVER_NAME", "signup.kyriakon.net"),
        ("SERVER_PORT", "8080"),
        ("REMOTE_ADDR", "127.0.0.1"),
        ("HTTP_X_FORWARDED_FOR", "203.0.113.10"),
        ("SERVER_SOFTWARE", "OpenBSD httpd"),
    ];
    if let Some(user) = user {
        env.push(("REMOTE_USER", user));
    }
    fixture::httpd(&env, b"")
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

/// The gmid environment, with whatever a certificate adds appended. gmid sends
/// `AUTH_TYPE` only when the client presented a certificate: an anonymous
/// request omits it, and the certificate fixture below adds it.
fn gmid_env(path: &str, query: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut env = vec![
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
    ];
    env.extend_from_slice(extra);
    fixture::gmid(&env)
}

/// The request gmid builds: the path already decoded and cleaned with no leading
/// slash, the query still percent-encoded, and no forwarded header of any kind.
fn gmid_get(path: &str, query: &str) -> Vec<u8> {
    gmid_env(path, query, &[])
}

/// The request gmid builds when the client presented a certificate.
fn gmid_certificate(path: &str, query: &str, certificate: &Certificate) -> Vec<u8> {
    gmid_env(
        path,
        query,
        &[
            ("AUTH_TYPE", "CERTIFICATE"),
            ("REMOTE_USER", &certificate.subject),
            ("TLS_CLIENT_ISSUER", &certificate.issuer),
            ("TLS_CLIENT_HASH", &certificate.hash),
            ("TLS_CLIENT_NOT_BEFORE", &certificate.not_before),
            ("TLS_CLIENT_NOT_AFTER", &certificate.not_after),
        ],
    )
}

/// A certificate as gmid would describe one: `SHA256:` and the lowercase digest,
/// with a subject and issuer that are the same claim on a self-signed one.
fn certificate(hash: &str, subject: &str) -> Certificate {
    Certificate {
        hash: hash.to_string(),
        subject: subject.to_string(),
        issuer: subject.to_string(),
        not_before: "2026-01-01T00:00:00Z".to_string(),
        not_after: "2036-01-01T00:00:00Z".to_string(),
    }
}

/// The hash Alice's account pins, and one that it does not.
const PINNED: &str = "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER: &str = "SHA256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// An account in the store: the pinned certificate, the four facts the reading
/// half renders, and one notice. The handler only ever reads these files.
fn file_account(dir: &Path) {
    let pinned = PINNED;
    let record = format!(
        r#"{{"version": 1, "username": "alice", "state": "active",
            "decision": "approve", "decided_at": "2026-09-30T09:00:00Z",
            "rail": "no_charge", "no_charge": true,
            "created_at": "2026-09-30T09:00:00Z", "paid_until": null,
            "certificates": [{{"hash": "{pinned}", "subject": "CN=alice",
                "issuer": "CN=alice",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2036-01-01T00:00:00Z"}}],
            "site_served": true, "capsule_served": true,
            "space_used": 432013312}}"#
    );
    let account = dir.join("accounts/alice");
    std::fs::create_dir_all(&account).unwrap();
    std::fs::write(account.join("account.json"), record).unwrap();
    std::fs::write(
        account.join("notices.jsonl"),
        "{\"version\":1,\"at\":\"2026-09-30T09:00:00Z\",\"type\":\"approval.free\",\
         \"subject\":\"Application approved, account opened.\",\
         \"to\":\"alice@kyriakon.net\"}\n",
    )
    .unwrap();
}

/// An account that belongs to a body's group, with the group record the handler
/// reads to generate the recipe. The certificate is the pinned one.
fn file_group_account(dir: &Path) {
    let pinned = PINNED;
    let record = format!(
        r#"{{"version": 1, "username": "parish-secretary", "state": "active",
            "decision": "approve", "decided_at": "2026-09-30T09:00:00Z",
            "rail": "cash", "no_charge": false,
            "created_at": "2026-09-30T09:00:00Z",
            "group": "parish.example",
            "certificates": [{{"hash": "{pinned}", "subject": "CN=parish-secretary",
                "issuer": "CN=parish-secretary",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2036-01-01T00:00:00Z"}}],
            "site_served": true, "capsule_served": true,
            "space_used": 432013312}}"#
    );
    let account = dir.join("accounts/parish-secretary");
    std::fs::create_dir_all(&account).unwrap();
    std::fs::write(account.join("account.json"), record).unwrap();
    let group = dir.join("groups/parish.example");
    std::fs::create_dir_all(&group).unwrap();
    std::fs::write(
        group.join("group.json"),
        r#"{"version": 1, "domain": "parish.example", "name": "Parish of Example",
            "kind": "parish", "payment": {"rail": "cash", "no_charge": false,
            "paid_until": null}, "accounts": ["parish-secretary"],
            "site_owner": "parish-secretary"}"#,
    )
    .unwrap();
}

/// The bytes of every record the handler writes, so a read can be shown to have
/// filed nothing.
fn filed(dir: &Path) -> usize {
    ["intents", "applications", "drafts"]
        .iter()
        .map(|sub| {
            std::fs::read_dir(dir.join(sub))
                .map(|rd| rd.count())
                .unwrap_or(0)
        })
        .sum()
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
    let path = dir
        .join("applications")
        .join(format!("{}.json", record.status_token));
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
        ("accept_supply", "yes"),
    ]
    .into_iter()
    .collect()
}

/// A real clean key from the generator, because the shared check parses the
/// block in full: the old two-packet stub passed only the structural reading.
const GOOD_KEY: &str =
    include_str!("../../../docs/planning/prototypes/keygen-spike/fixtures/generated-clean.asc");

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
    file_application(&dir, &decided("received", None, None));

    let (code, body) = answer(&app, &gmid_get(&format!("status/{TOKEN}"), "")).await;

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

/// The join the ticket is about: the hash decides, and a match is the member
/// on both the catalogue and the reading half.
#[tokio::test]
async fn a_pinned_certificate_answers_as_the_member() {
    let (app, dir) = handler("gmid-pinned").await;
    file_account(&dir);
    let pinned = certificate(PINNED, "CN=alice");

    let (code, body) = answer(&app, &gmid_certificate("", "", &pinned)).await;
    assert_eq!(code, 20);
    assert!(
        body.contains("=> gemini://alice.kyriakon.net/ A website"),
        "the member's own host, not the pattern: {body}"
    );
    assert!(!body.contains("gemini://<name>.kyriakon.net/"), "{body}");

    let (code, body) = answer(&app, &gmid_certificate("account", "", &pinned)).await;
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
    let (code, web) = answer(&app, &httpd_get_as("account", "", Some("alice"))).await;
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
    let (_, catalogue) = answer(&app, &gmid_certificate("", "", &pinned)).await;
    assert!(
        catalogue.contains("=> gemini://signup.kyriakon.net/account Your account"),
        "{catalogue}"
    );
}

/// A mailbox account's `group` resolves to the group record, and the recipe it
/// carries is the same on both account pages.
#[tokio::test]
async fn a_group_member_reads_the_same_recipe_on_both_account_pages() {
    let (app, dir) = handler("group-account-recipe").await;
    file_group_account(&dir);
    let pinned = certificate(PINNED, "CN=parish-secretary");
    let needles = [
        "10 mail.kyriakon.net.",
        "192.0.2.10",
        "2001:db8::10",
        "v=spf1 mx ip6:2001:db8::10 -all",
        "mail._domainkey",
        "v=DKIM1; k=rsa; p=example",
        "v=DMARC1; p=none; rua=mailto:dmarc@kyriakon.net",
        "does not host your zone",
    ];

    let (code, capsule) = answer(&app, &gmid_certificate("account", "", &pinned)).await;
    assert_eq!(code, 20);
    let (code, web) = answer(&app, &httpd_get_as("account", "", Some("parish-secretary"))).await;
    assert_eq!(code, 200);
    for needle in needles {
        assert!(
            capsule.contains(needle),
            "the capsule misses {needle:?}: {capsule}"
        );
        assert!(
            web.contains(needle),
            "the web page misses {needle:?}: {web}"
        );
    }

    // A web request that names no authenticated member is the page it was, and
    // never another member's recipe.
    let (_, anonymous) = answer(&app, &httpd_get("account", "")).await;
    assert!(!anonymous.contains("mail._domainkey"), "{anonymous}");
}

/// The ordinary visitor's pages, with the visitor's own fingerprint and no
/// claim about whether the hash is pinned.
#[tokio::test]
async fn a_certificate_that_matches_nothing_answers_as_a_stranger() {
    let (app, dir) = handler("gmid-unpinned").await;
    file_account(&dir);
    let stray = certificate(OTHER, "CN=alice");

    let (code, body) = answer(&app, &gmid_certificate("", "", &stray)).await;
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
    let (code, body) = answer(&app, &gmid_certificate("account", "", &stray)).await;
    assert_eq!(code, 20);
    assert!(!body.contains("State: active"), "{body}");
    assert!(
        !body.contains("Application approved, account opened."),
        "{body}"
    );
    assert!(body.contains("SHA256:fedcba98"), "{body}");

    // A visitor with no certificate reads the same page without a fingerprint.
    let (code, body) = answer(&app, &gmid_get("account", "")).await;
    assert_eq!(code, 20);
    assert!(!body.contains("SHA256:"), "{body}");
}

/// The no-oracle rule: whatever the visitor asks for with an unmatched
/// certificate, no page carries the word for an unknown certificate.
#[tokio::test]
async fn no_page_calls_an_unmatched_certificate_unknown() {
    let (app, dir) = handler("gmid-no-oracle").await;
    file_account(&dir);
    let stray = certificate(OTHER, "CN=alice");
    let status = format!("status/{TOKEN}");
    for path in ["", "account", status.as_str()] {
        let (code, body) = answer(&app, &gmid_certificate(path, "", &stray)).await;
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
    let claimed = certificate(OTHER, "CN=alice");
    let bytes = gmid_certificate("", "", &claimed);
    let request = fcgi::read_request(&mut &bytes[..], MAX_BODY)
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
    let (_, body) = answer(&app, &bytes).await;
    assert!(!body.contains("=> gemini://alice.kyriakon.net/"), "{body}");

    // The hash is alice's; the subject claims otherwise.
    let impostor = certificate(PINNED, "CN=mallory");
    let (_, body) = answer(&app, &gmid_certificate("", "", &impostor)).await;
    assert!(
        body.contains("=> gemini://alice.kyriakon.net/ A website"),
        "the hash names the member, not the subject: {body}"
    );

    // Without a certificate the request carries none, whatever the empty
    // `AUTH_TYPE` says.
    let bytes = gmid_get("", "");
    let request = fcgi::read_request(&mut &bytes[..], MAX_BODY)
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

    let pinned = certificate(PINNED, "CN=alice");
    let (code, _) = answer(&app, &gmid_certificate("account", "", &pinned)).await;
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
        let (code, body) = answer(&app, &gmid_get(route, "")).await;
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
    let (code, body) = answer(&app, &gmid_get(capsule::ACCEPTANCES, "")).await;
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
    let (code, body) = answer(&app, &gmid_get("", "")).await;
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

// The portal's one read: the stage, or the same notice for every token that
// names nothing.

#[tokio::test]
async fn a_portal_status_read_answers_with_the_stage_and_never_an_answer() {
    let (app, dir) = handler("portal-stage").await;
    file_application(
        &dir,
        &decided(
            "received",
            None,
            Some("https://signup.kyriakon.net/password/secret"),
        ),
    );

    let answer = portal_answer(&app, "203.0.113.10", TOKEN).await;
    assert_eq!(answer, portal_ipc::Answer::Stage("received".to_string()));
    let line = answer.line();
    // The status path's one promise: no answer, contact address or key.
    assert!(!line.contains("secretary"), "{line}");
    assert!(!line.contains("password"), "{line}");
    assert!(!line.contains("signup.kyriakon.net"), "{line}");
}

#[tokio::test]
async fn a_portal_read_of_an_unknown_token_reads_as_one_that_expired() {
    let (app, dir) = handler("portal-expired").await;
    let unknown = portal_answer(&app, "203.0.113.10", TOKEN).await;
    assert!(
        matches!(unknown, portal_ipc::Answer::Notice(_)),
        "{unknown:?}"
    );

    file_application(
        &dir,
        &decided("decided: declined", Some("2026-10-01T09:00:00Z"), None),
    );
    let expired = portal_answer(&app, "203.0.113.10", TOKEN).await;
    assert_eq!(
        unknown.line(),
        expired.line(),
        "the two reads are one reply"
    );
}

#[tokio::test]
async fn a_portal_status_read_is_rate_limited_by_address() {
    let (app, _dir) = handler("portal-rate").await;
    for _ in 0..crate::rate::REQUESTS_PER_MINUTE {
        let _ = portal_answer(&app, "203.0.113.10", TOKEN).await;
    }
    let refused = portal_answer(&app, "203.0.113.10", TOKEN).await;
    assert_eq!(refused, portal_ipc::Answer::Notice(SLOW_STATUS.to_string()));
    // Another address still reads.
    assert!(matches!(
        portal_answer(&app, "203.0.113.11", TOKEN).await,
        portal_ipc::Answer::Notice(_)
    ));
}

/// The portal line is bounded on the wire: a request past the bound is refused
/// before it becomes an unbounded allocation.
#[tokio::test]
async fn portal_lines_are_bounded_and_a_close_is_not_an_error() {
    let mut reader = tokio::io::BufReader::new(&b"abcdef\n"[..]);
    assert_eq!(
        portal_line(&mut reader, 6).await.unwrap(),
        Some("abcdef\n".to_string())
    );

    let mut reader = tokio::io::BufReader::new(&b"abcdefg\n"[..]);
    let why = portal_line(&mut reader, 6).await.unwrap_err();
    assert!(why.contains("longer than 6"), "{why}");

    let mut reader = tokio::io::BufReader::new(&b"abc"[..]);
    assert_eq!(portal_line(&mut reader, 6).await.unwrap(), None);
}

/// The portal's completed application: the handler validates it with the web
/// form's rules, files one application and one intent, and the token it returns
/// reads back the stage.
#[tokio::test]
async fn the_portal_files_one_application_and_its_token_reads_the_stage() {
    let (app, dir) = handler("portal-file").await;
    let form: BTreeMap<String, String> = body_answers()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let body = serde_json::to_string(&form).unwrap();

    let reply = portal_file(&app, "203.0.113.10", &body).await;
    let token = portal_ipc::parse_file_answer(&reply).unwrap();
    assert!(store::is_status_token(&token), "{token}");

    let text =
        std::fs::read_to_string(dir.join("applications").join(format!("{token}.json"))).unwrap();
    let record: Record = serde_json::from_str(&text).unwrap();
    assert_eq!(record.front_end, "tui");
    assert_eq!(record.username, "theophilus");
    assert_eq!(
        record.mail_keys.len(),
        1,
        "the mailbox's key did not reach the record"
    );
    assert_eq!(
        std::fs::read_dir(dir.join("intents")).unwrap().count(),
        1,
        "one application is one intent"
    );
    assert_eq!(
        portal_answer(&app, "203.0.113.10", &token).await,
        portal_ipc::Answer::Stage("received".to_string())
    );
}

/// A bug in the portal cannot become a filed record the web form would have
/// refused: the handler runs the same checks again and files nothing.
#[tokio::test]
async fn the_portal_refuses_an_application_the_web_form_would_refuse() {
    let (app, dir) = handler("portal-file-refused").await;
    let mut form: BTreeMap<String, String> = body_answers()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    form.insert("username".to_string(), "Not A Username".to_string());

    let reply = portal_file(&app, "203.0.113.10", &serde_json::to_string(&form).unwrap()).await;
    assert!(reply.starts_with("ERR "), "{reply}");
    assert_eq!(
        std::fs::read_dir(dir.join("applications")).unwrap().count(),
        0
    );
    assert_eq!(std::fs::read_dir(dir.join("intents")).unwrap().count(), 0);
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

    // An anonymous request carries no AUTH_TYPE at all, which is what gmid sends.
    assert_eq!(request.get("AUTH_TYPE"), None);
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
    let (_, answered) = answer(&app, &httpd_post("/", &body)).await;
    assert!(
        answered.contains(ticked),
        "the tick the applicant gave comes back: {answered}"
    );

    // A page nobody gave the answer to does not invent one.
    let (_, fresh) = answer(&app, &httpd_get("/", "")).await;
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
    let (_, page) = answer(&app, &httpd_post("/", &body)).await;
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
    let (code, _) = answer(&app, &httpd_post("/apply", &encoded(&answers))).await;
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
    assert_eq!(
        std::fs::read_dir(dir.join("applications")).unwrap().count(),
        0
    );
}

#[tokio::test]
async fn a_submission_whose_body_overruns_the_cap_is_refused() {
    let (app, dir) = handler("too-large").await;
    let long = format!("anything_else={}", "x".repeat(MAX_BODY + 1));
    let (code, _) = answer(&app, &httpd_post("/apply", &long)).await;
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
    assert_eq!(crate::keycheck::blocks(two).len(), 2);
    assert!(crate::keycheck::blocks("nothing here").is_empty());
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

/// The intent files the handler wrote, sorted.
fn intent_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v: Vec<std::path::PathBuf> = std::fs::read_dir(dir.join("intents"))
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

/// A decision link names what it would do and files nothing. The link is in an
/// email, and everything that fetches a URL it is sent would otherwise decide for
/// the operator.
#[tokio::test]
async fn a_decision_link_opens_a_page_instead_of_deciding() {
    let (app, dir) = handler("decide-get").await;
    file_application(&dir, &decided("received", None, None));

    let (code, page) = answer(
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
    file_application(&dir, &decided("received", None, None));

    let body = encoded(&[("action", "approve-free"), ("sig", "abc123")]);
    let (code, page) = answer(&app, &httpd_post(&format!("/decide/{TOKEN}"), &body)).await;
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
    file_application(&dir, &decided("received", None, None));

    let (code, page) = answer(
        &app,
        &httpd_get("/decide/not-a-token", "action=approve&sig=x"),
    )
    .await;
    assert_eq!(code, 200, "a dead token is a page, not an error");
    assert!(page.contains(UNKNOWN_TOKEN), "{page}");

    let (code, _) = answer(
        &app,
        &httpd_get(&format!("/decide/{TOKEN}"), "action=promote&sig=x"),
    )
    .await;
    assert_eq!(code, 403, "an action the platform has no decision for");

    let (code, _) = answer(
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

fn read_draft(dir: &Path, token: &str) -> crate::draft::Draft {
    serde_json::from_str(
        &std::fs::read_to_string(dir.join("drafts").join(format!("{token}.json")))
            .expect("the draft is on disk"),
    )
    .expect("the draft parses")
}

#[tokio::test]
async fn a_capsule_draft_asks_the_first_question() {
    let (app, _dir) = handler("capsule-first").await;
    let (code, redirect) = answer(&app, &gmid_get("apply", "")).await;
    assert_eq!(code, 30, "{redirect}");
    let token = draft_token(&redirect);

    let (code, page) = answer(&app, &gmid_get(&format!("apply/{token}/1"), "")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.starts_with("10 question 1 of "), "{page}");
    assert!(page.contains("Username"), "{page}");
    assert!(page.contains("under 1024 bytes"), "{page}");
}

#[tokio::test]
async fn a_capsule_answer_advances_the_cursor_once() {
    let (app, dir) = handler("capsule-answer").await;
    let (_, redirect) = answer(&app, &gmid_get("apply", "")).await;
    let token = draft_token(&redirect);

    let (code, redirect) = answer(&app, &gmid_get(&format!("apply/{token}/1"), "secretary")).await;
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
    let (code, redirect) = answer(&app, &gmid_get(&format!("apply/{token}/1"), "secretary")).await;
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
    let (_, redirect) = answer(&app, &gmid_get("apply", "")).await;
    let token = draft_token(&redirect);
    answer(&app, &gmid_get(&format!("apply/{token}/1"), "secretary")).await;
    answer(&app, &gmid_get(&format!("apply/{token}/2"), "body")).await;

    let total = flow_path(&app.questions, &read_draft(&dir, &token).answers).len();
    let (code, page) = answer(&app, &gmid_get(&format!("apply/{token}/3"), "")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains(&format!("question 3 of {total}.")), "{page}");
    assert!(page.contains("The body's name"), "{page}");
}

#[tokio::test]
async fn a_required_capsule_answer_is_reasked_with_the_reason() {
    let (app, dir) = handler("capsule-required").await;
    let (_, redirect) = answer(&app, &gmid_get("apply", "")).await;
    let token = draft_token(&redirect);

    let (code, page) = answer(&app, &gmid_get(&format!("apply/{token}/1"), ".")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains("a username is needed"), "{page}");
    assert_eq!(read_draft(&dir, &token).cursor, 0);
    assert!(!read_draft(&dir, &token).answers.contains_key("username"));
}

#[tokio::test]
async fn an_optional_capsule_answer_of_a_full_stop_is_empty() {
    let (app, dir) = handler("capsule-skip").await;
    let (_, redirect) = answer(&app, &gmid_get("apply", "")).await;
    let token = draft_token(&redirect);
    answer(&app, &gmid_get(&format!("apply/{token}/1"), "secretary")).await;
    answer(&app, &gmid_get(&format!("apply/{token}/2"), "person")).await;

    let (code, _) = answer(&app, &gmid_get(&format!("apply/{token}/3"), ".")).await;
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
    assert_eq!(capsule_value("line%0D"), "line\r");
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
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "body".to_string());
    record
        .answers
        .insert("body_addresses".to_string(), "a: own\nb: own".to_string());
    record.cursor = 8;
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let (code, page) = answer(&app, &gmid_get(&format!("apply/{TOKEN}/9"), "a")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains("2 addresses and 1 account names"), "{page}");
    let draft = read_draft(&dir, TOKEN);
    assert_eq!(draft.cursor, 8);
    assert!(!draft.answers.contains_key("body_account_names"));
}

#[tokio::test]
async fn a_capsule_body_key_page_names_one_mailbox_and_the_mail_route() {
    let (app, dir) = handler("capsule-key-pages").await;
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
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
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let (code, page) = answer(&app, &gmid_get(&format!("apply/{TOKEN}/{}", first + 1), "")).await;
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

    let (code, redirect) = answer(
        &app,
        &gmid_get(&format!("apply/{TOKEN}/{}", first + 1), GOOD_KEY),
    )
    .await;
    assert_eq!(code, 30, "{redirect}");
    let draft = read_draft(&dir, TOKEN);
    assert_eq!(draft.mail_keys.len(), 1);
    assert_eq!(draft.mail_keys[0].mailbox, "secretary");
    assert!(!draft.mail_keys[0].fingerprint.is_empty());

    let (code, page) = answer(&app, &gmid_get(&format!("apply/{TOKEN}/{}", first + 2), "")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains("hall@parish.example"), "{page}");
}

#[tokio::test]
async fn a_capsule_person_key_page_names_their_address() {
    let (app, _dir) = handler("capsule-person-key").await;
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
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
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let (code, page) = answer(&app, &gmid_get(&format!("apply/{TOKEN}/{}", index + 1), "")).await;
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
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
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
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let (code, page) = answer(&app, &gmid_get(&format!("apply/{TOKEN}/{}", index + 1), "")).await;
    assert_eq!(code, 10, "{page}");
    assert!(page.contains("gemini://signup.kyriakon.net/keys"), "{page}");
}

#[tokio::test]
async fn a_mailed_key_answers_the_capsule_key_page() {
    let (app, dir) = handler("capsule-key-mailed").await;
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
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
        .push(crate::keycheck::mail_key("secretary".to_string(), GOOD_KEY));
    let path = flow_path(&app.questions, &record.answers);
    let first = path
        .iter()
        .position(|p| p.mailbox.is_some())
        .expect("the first key page");
    record.cursor = first;
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let (code, redirect) =
        answer(&app, &gmid_get(&format!("apply/{TOKEN}/{}", first + 1), "")).await;
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
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
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
        .push(crate::keycheck::mail_key("secretary".into(), GOOD_KEY));
    record
        .mail_keys
        .push(crate::keycheck::mail_key("hall".into(), GOOD_KEY));
    record.cursor = flow_path(&app.questions, &record.answers).len();
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let (code, page) = answer(&app, &gmid_get(&format!("apply/{TOKEN}/1"), "")).await;
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
    let (_, first) = answer(&app, &gmid_get("apply", "")).await;
    let (_, second) = answer(&app, &gmid_get("apply", "")).await;
    let first = draft_token(&first);
    let second = draft_token(&second);

    answer(&app, &gmid_get(&format!("apply/{first}/1"), "alice")).await;
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
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
    record.answers = answers;
    record.cursor = flow_path(&app.questions, &record.answers).len();
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let (code, page) = answer(&app, &gmid_get(&format!("apply/{TOKEN}/1"), "")).await;
    assert_eq!(code, 20, "{page}");
    assert!(page.contains("# Application filed"), "{page}");
    assert!(dir
        .join("applications")
        .join(format!("{TOKEN}.json"))
        .exists());
    assert_eq!(intent_files(&dir).len(), 1);
    assert!(!dir.join("drafts").join(format!("{TOKEN}.json")).exists());
}

/// One Titan exchange: the request line (and any PROXY line) and a body, put in
/// front of the handler together. The leftover count is what the handler did not
/// read, which is how a refusal proves it left the body alone.
async fn titan_exchange(app: &App, head: &str, body: &[u8]) -> (u16, String, usize) {
    let mut request = head.as_bytes().to_vec();
    request.extend_from_slice(body);
    let mut reader = &request[..];
    let (reply, _address) = titan_answer(&mut reader, app, Some("203.0.113.10"))
        .await
        .expect("the request is readable");
    (
        reply.code(),
        String::from_utf8_lossy(&reply.head()).into_owned(),
        reader.len(),
    )
}

#[tokio::test]
async fn a_titan_upload_naming_no_live_draft_is_refused_before_the_body() {
    let (app, _dir) = handler("titan-unknown-token").await;
    let body = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot read\n";
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 51, "{reply}");
    assert_eq!(
        leftover,
        body.len(),
        "the body is left on the stream: {reply}"
    );
}

#[tokio::test]
async fn a_titan_upload_over_the_cap_is_refused_before_the_body() {
    let (app, _dir) = handler("titan-over-cap").await;
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let body = b"not read";
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};token={TOKEN}\r\n",
        MAX_TITAN_BODY + 1
    );
    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 59, "{reply}");
    assert_eq!(
        leftover,
        body.len(),
        "the body is left on the stream: {reply}"
    );
}

#[tokio::test]
async fn a_titan_upload_files_the_key_and_the_mail_verdict() {
    let (app, dir) = handler("titan-files").await;
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let body = GOOD_KEY.as_bytes();
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};mime=application/pgp-keys;token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 20, "{reply}");
    assert_eq!(leftover, 0, "the whole body is read: {reply}");

    let draft = read_draft(&dir, TOKEN);
    assert_eq!(draft.mail_keys.len(), 1);
    let filed = &draft.mail_keys[0];
    let expected = crate::keycheck::mail_key("secretary".to_string(), GOOD_KEY);
    assert_eq!(filed.mailbox, "secretary");
    assert_eq!(filed.material, expected.material);
    assert_eq!(filed.fingerprint, expected.fingerprint);
    assert_eq!(
        filed.verdict, expected.verdict,
        "the Titan route records the verdict the mail route records"
    );
}

#[tokio::test]
async fn a_second_titan_upload_is_refused_and_the_first_key_stays() {
    let (app, dir) = handler("titan-second").await;
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let body = GOOD_KEY.as_bytes();
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, _) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 20, "{reply}");
    let first = read_draft(&dir, TOKEN);
    assert_eq!(first.mail_keys.len(), 1);
    let fingerprint = first.mail_keys[0].fingerprint.clone();

    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 59, "{reply}");
    assert_eq!(
        leftover,
        body.len(),
        "the second body is left on the stream: {reply}"
    );
    let after = read_draft(&dir, TOKEN);
    assert_eq!(
        after.mail_keys.len(),
        1,
        "the second upload does not add a key"
    );
    assert_eq!(after.mail_keys[0].fingerprint, fingerprint);
}

#[tokio::test]
async fn a_titan_request_reads_the_proxy_line_and_the_request_line() {
    let (app, _dir) = handler("titan-proxy").await;
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let body = GOOD_KEY.as_bytes();
    let head = format!(
        "PROXY TCP4 198.51.100.7 192.0.2.1 34567 7081\r\n\
         titan://signup.kyriakon.net:1966/key;size={};token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 20, "{reply}");
    assert_eq!(leftover, 0);
    assert_eq!(
        proxy_address("PROXY TCP4 198.51.100.7 192.0.2.1 34567 7081"),
        Some("198.51.100.7".to_string())
    );
    assert_eq!(proxy_address("PROXY UNKNOWN\r"), None);
}

/// A body draft's flow has one key page per mailbox, and Titan fills the next
/// one each time: two mailboxes take two uploads, and the third has nothing left
/// to fill.
#[tokio::test]
async fn a_body_draft_takes_one_key_per_mailbox_over_titan() {
    let (app, dir) = handler("titan-body").await;
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
    for (key, value) in [
        ("whose", "body"),
        ("body_addresses", "secretary: own\nhall: own"),
        ("body_account_names", "secretary\nhall"),
    ] {
        record.answers.insert(key.to_string(), value.to_string());
    }
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let body = GOOD_KEY.as_bytes();
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, _) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 20, "{reply}");
    let (code, reply, _) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 20, "{reply}");
    let filed = read_draft(&dir, TOKEN);
    let mut boxes: Vec<&str> = filed.mail_keys.iter().map(|k| k.mailbox.as_str()).collect();
    boxes.sort_unstable();
    assert_eq!(boxes, vec!["hall", "secretary"], "{:?}", filed.mail_keys);

    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 59, "{reply}");
    assert!(
        reply.contains("Every mailbox"),
        "the third upload is refused by the draft's state: {reply}"
    );
    assert_eq!(leftover, body.len(), "the refusal reads no body: {reply}");
    assert_eq!(read_draft(&dir, TOKEN).mail_keys.len(), 2);
}

/// A zero-byte upload is a link being opened, so it answers and files nothing.
#[tokio::test]
async fn a_zero_byte_titan_navigation_opens_without_filing() {
    let (app, dir) = handler("titan-zero").await;
    let mut record = crate::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    crate::draft::save(&app.store, &mut record).await.unwrap();

    let head = format!("titan://signup.kyriakon.net:1966/key;size=0;token={TOKEN}\r\n");
    let (code, reply, leftover) = titan_exchange(&app, &head, b"").await;
    assert_eq!(code, 20, "{reply}");
    assert_eq!(leftover, 0, "{reply}");
    assert!(read_draft(&dir, TOKEN).mail_keys.is_empty());
}

#[test]
fn titan_parameters_are_read_or_refused() {
    let upload = titan_params("titan://signup.kyriakon.net/key;size=12;mime=text/plain;token=abc")
        .expect("a well-formed line parses");
    assert_eq!(upload.size, Some(12));
    assert_eq!(upload.token.as_deref(), Some("abc"));

    assert_eq!(
        titan_params("titan://signup.kyriakon.net/key;size=twelve").unwrap_err(),
        "Size is not a number"
    );
    assert_eq!(
        titan_params("titan://signup.kyriakon.net/key;size=1;mode=x").unwrap_err(),
        "Unknown titan parameter"
    );
    assert_eq!(
        titan_params("gemini://signup.kyriakon.net/key;size=1").unwrap_err(),
        "Not a titan request"
    );
}

/// A Stripe delivery is stored exactly as it arrived, raw body and signature
/// header, for the drain to verify. Nothing is parsed here and nothing is
/// refused for coming from Stripe rather than this form.
#[tokio::test]
async fn a_webhook_post_stores_the_raw_body_and_the_signature_header() {
    let (app, dir) = handler("webhook-intake").await;
    let body = b"{\"id\":\"evt_1\",\"type\":\"invoice.paid\",\"note\":\"a&b=c\"}";
    let header = "t=1760000000,v1=abcdef";
    let length = body.len().to_string();
    let request = fixture::httpd(
        &[
            ("REQUEST_METHOD", "POST"),
            ("REQUEST_URI", "/stripe/webhook"),
            ("CONTENT_TYPE", "application/json"),
            ("CONTENT_LENGTH", &length),
            ("HTTP_STRIPE_SIGNATURE", header),
            ("REMOTE_ADDR", "127.0.0.1"),
        ],
        body,
    );
    let (code, _) = answer(&app, &request).await;
    assert_eq!(code, 200, "a stored delivery is acknowledged at once");

    let mut bodies = Vec::new();
    let mut sigs = Vec::new();
    for entry in std::fs::read_dir(dir.join("webhooks")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{name} is readable by its owner only");
        if name.ends_with(".body") {
            bodies.push(entry.path());
        } else if name.ends_with(".sig") {
            sigs.push(entry.path());
        }
    }
    assert_eq!(bodies.len(), 1, "{bodies:?}");
    assert_eq!(sigs.len(), 1, "{sigs:?}");
    assert_eq!(std::fs::read(&bodies[0]).unwrap(), body);
    assert_eq!(std::fs::read(&sigs[0]).unwrap(), header.as_bytes());
}

/// A request that is not a signed POST is refused without writing: the handler
/// no longer answers a webhook's path with a page, and it never stores one it
/// could not verify later.
#[tokio::test]
async fn a_webhook_that_is_not_a_signed_post_writes_nothing() {
    let (app, dir) = handler("webhook-refused").await;
    let body = b"{}";

    let get = fixture::httpd(
        &[
            ("REQUEST_METHOD", "GET"),
            ("REQUEST_URI", "/stripe/webhook"),
            ("REMOTE_ADDR", "127.0.0.1"),
        ],
        b"",
    );
    let (code, _) = answer(&app, &get).await;
    assert_eq!(code, 405, "only a POST is a delivery");

    let unsigned = fixture::httpd(
        &[
            ("REQUEST_METHOD", "POST"),
            ("REQUEST_URI", "/stripe/webhook"),
            ("CONTENT_TYPE", "application/json"),
            ("CONTENT_LENGTH", "2"),
            ("REMOTE_ADDR", "127.0.0.1"),
        ],
        body,
    );
    let (code, _) = answer(&app, &unsigned).await;
    assert_eq!(code, 400, "a delivery with no signature is refused");

    let written = std::fs::read_dir(dir.join("webhooks"))
        .map(|rd| rd.count())
        .unwrap_or(0);
    assert_eq!(written, 0, "a refused delivery writes no file");
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
                       "window":{"opened_at":"2026-10-02T09:00:00Z",
                                 "closes_at":"2026-10-16T09:00:00Z",
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
