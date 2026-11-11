//! The responder's test fixtures: the request as each front-end writes one,
//! the handler they drive, and the store records they stage.
//!
//! The fixture is a request into `fastcgi::read_request`, through the routes, and
//! out as the bytes the front-end would read.

use super::connection::respond;
use super::*;
use crate::fastcgi::{self, fixture};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::capsule;
use kyriakon_control_core::store::{Certificate, Record};
use kyriakon_control_core::{account::session, config};

/// The status token the fixtures use, 26 Crockford characters.
pub(crate) const TOKEN: &str = "abcdefghjkmnpqrstvwxyz0123";

/// A responder over a store under a temporary directory, reading the tracked
/// catalogue and the tracked reserved names. The question list is the crate's own,
/// so it comes with the build rather than from a path.
pub(crate) async fn handler(name: &str) -> (App, PathBuf) {
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
pub(crate) fn fixture_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onboard-responder-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["applications", "intents", "pages", "proofs"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    dir
}

/// The configuration every fixture handler loads: the tracked catalogue and
/// reserved names, the crate's question list, and the pages under `dir`.
pub(crate) fn handler_config(dir: &Path) -> config::Config {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    config::Config {
        store_root: dir.to_str().unwrap().to_string(),
        reserved: crate_dir
            .join("reserved-usernames.txt")
            .to_str()
            .unwrap()
            .to_string(),
        catalogue: crate_dir
            .join("openbsd/etc/onboard/catalogue.toml")
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
        proof_dir: dir.join("proofs").to_str().unwrap().to_string(),
    }
}

/// One request through the responder: the fixture in, the code and the bytes a
/// front-end reads back out.
pub(crate) async fn ask(app: &App, bytes: &[u8]) -> (u16, String) {
    let request = fastcgi::read_request(&mut &bytes[..], MAX_BODY)
        .await
        .expect("the fixture is a request")
        .expect("the fixture is one request");
    let outcome = respond(app, &request).await;
    let (body, last) = fixture::reply(&fastcgi::reply_bytes(&outcome.reply, request.id()));
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
pub(crate) fn httpd_get(path: &str, query: &str) -> Vec<u8> {
    httpd_get_as(path, query, None)
}

/// The request httpd builds for a GET when the browser presents an account-page
/// session cookie.
pub(crate) fn httpd_get_session(path: &str, query: &str, cookie: &str) -> Vec<u8> {
    fixture::httpd(
        &[
            ("REQUEST_METHOD", "GET"),
            ("REQUEST_URI", path),
            ("QUERY_STRING", query),
            ("HTTP_HOST", "signup.kyriakon.net"),
            ("SERVER_NAME", "signup.kyriakon.net"),
            ("SERVER_PORT", "8080"),
            ("HTTP_COOKIE", &format!("{}={cookie}", session::COOKIE)),
            ("REMOTE_ADDR", "127.0.0.1"),
            ("HTTP_X_FORWARDED_FOR", "203.0.113.10"),
            ("SERVER_SOFTWARE", "OpenBSD httpd"),
        ],
        b"",
    )
}

/// A GET that claims a member in `REMOTE_USER` and carries no session. Nothing
/// authenticates httpd's `REMOTE_USER` on this hostname, and the page must not
/// read it as an identity.
pub(crate) fn httpd_get_as(path: &str, query: &str, user: Option<&str>) -> Vec<u8> {
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

/// One root-written login proof, as `scripts/kyriakon-authcheck.sh` mints it: a
/// random token, the username and an expiry. The fixture writes it because no
/// test runs the real checker through `doas`.
pub(crate) fn mint_proof(app: &App, username: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let token = format!("{:064x}", NEXT.fetch_add(1, Ordering::Relaxed));
    let expires = OffsetDateTime::now_utc().unix_timestamp() + 3600;
    std::fs::create_dir_all(&app.cfg.proof_dir).unwrap();
    std::fs::write(
        Path::new(&app.cfg.proof_dir).join(&token),
        format!("{{\"username\":\"{username}\",\"expires\":{expires}}}\n"),
    )
    .unwrap();
    token
}

/// A session record for `username` in the fixture store, returning the cookie
/// value the browser would carry.
pub(crate) async fn signed_in(app: &App, username: &str) -> String {
    let proof = mint_proof(app, username);
    session::open(&app.store, username, &proof, OffsetDateTime::now_utc())
        .await
        .expect("the fixture store takes a session")
}

/// The request httpd builds for a form post.
pub(crate) fn httpd_post(path: &str, body: &str) -> Vec<u8> {
    httpd_post_with(path, body, None)
}

/// The request httpd builds for a form post that carries a session cookie.
/// A form post has no other identity: `REMOTE_USER` is not authenticated on
/// this hostname, so the helper offers no way to claim one.
pub(crate) fn httpd_post_with(path: &str, body: &str, cookie: Option<&str>) -> Vec<u8> {
    let length = body.len().to_string();
    let cookie_header;
    let mut env = vec![
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
    ];
    if let Some(cookie) = cookie {
        cookie_header = format!("{}={cookie}", session::COOKIE);
        env.push(("HTTP_COOKIE", &cookie_header));
    }
    fixture::httpd(&env, body.as_bytes())
}

/// The gmid environment, with whatever a certificate adds appended. gmid sends
/// `AUTH_TYPE` only when the client presented a certificate: an anonymous
/// request omits it, and the certificate fixture below adds it.
pub(crate) fn gmid_env(path: &str, query: &str, extra: &[(&str, &str)]) -> Vec<u8> {
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
pub(crate) fn gmid_get(path: &str, query: &str) -> Vec<u8> {
    gmid_env(path, query, &[])
}

/// The request gmid builds when the client presented a certificate.
pub(crate) fn gmid_certificate(path: &str, query: &str, certificate: &Certificate) -> Vec<u8> {
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
pub(crate) fn test_certificate(hash: &str, subject: &str) -> Certificate {
    Certificate {
        hash: hash.to_string(),
        subject: subject.to_string(),
        issuer: subject.to_string(),
        not_before: "2026-01-01T00:00:00Z".to_string(),
        not_after: "2036-01-01T00:00:00Z".to_string(),
    }
}

/// The hash Alice's account pins, and one that it does not.
pub(crate) const PINNED: &str =
    "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub(crate) const OTHER: &str =
    "SHA256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// An account in the store: the pinned certificate, the four facts the reading
/// half renders, and one notice. The handler only ever reads these files.
pub(crate) fn file_account(dir: &Path) {
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

/// An account with one token-keyed payment, so the closure can read the date
/// and amount the answer names.
pub(crate) fn file_payment(
    dir: &Path,
    username: &str,
    token: &str,
    received_on: &str,
    amount: &str,
) {
    amend_account(dir, username, |value| {
        value["payment"] = serde_json::json!({
            "token_ref": token,
            "rail": "cash",
            "paid_until": null
        });
        value["rail"] = serde_json::json!("cash");
        value["no_charge"] = serde_json::json!(false);
    });
    let ledger = dir.join("ledger");
    std::fs::create_dir_all(&ledger).unwrap();
    let line = serde_json::json!({
        "version": 1,
        "seq": 1,
        "token": token,
        "kind": "payment",
        "rail": "cash",
        "amount_gbp": amount,
        "applied_gbp": amount,
        "received_on": received_on,
        "paid_until_after": "2027-10-04"
    });
    std::fs::write(
        ledger.join("payments.jsonl"),
        format!("{}\n", serde_json::to_string(&line).unwrap()),
    )
    .unwrap();
}

/// An account that belongs to a body's group, with the group record the handler
/// reads to generate the recipe. The certificate is the pinned one.
pub(crate) fn file_group_account(dir: &Path) {
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
            "paid_until": "2027-01-01"}, "accounts": ["parish-secretary"],
            "space_used": 1073741824,
            "site_owner": "parish-secretary"}"#,
    )
    .unwrap();
}

/// The bytes of every record the handler writes, so a read can be shown to have
/// filed nothing.
pub(crate) fn filed(dir: &Path) -> usize {
    ["intents", "applications", "drafts"]
        .iter()
        .map(|sub| {
            std::fs::read_dir(dir.join(sub))
                .map(|rd| rd.count())
                .unwrap_or(0)
        })
        .sum()
}

/// The one intent a page action filed, as the drain will read it. A test that
/// lets the route file a second one is testing the wrong thing, so this is
/// strict about the count.
pub(crate) fn filed_intent(dir: &Path) -> serde_json::Value {
    let mut intents: Vec<PathBuf> = std::fs::read_dir(dir.join("intents"))
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    assert_eq!(intents.len(), 1, "one intent, not {}", intents.len());
    serde_json::from_str(&std::fs::read_to_string(intents.remove(0)).unwrap()).unwrap()
}

/// A record of the shape the store holds, as the drain leaves one when it decides.
/// The fields the drain owns are the caller's.
pub(crate) fn decided(
    stage: &str,
    decided_at: Option<&str>,
    password_link: Option<&str>,
) -> Record {
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

pub(crate) fn at(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &Rfc3339).unwrap()
}

/// A filed application in the store the fixtures read.
pub(crate) fn stage_application(dir: &Path, record: &Record) {
    let path = dir
        .join("applications")
        .join(format!("{}.json", record.status_token));
    std::fs::write(path, serde_json::to_vec_pretty(record).unwrap()).unwrap();
}

/// The answers the body's page asks for, and nothing a body's page does not
/// carry: no mail_key, no upload_key, no monastic blessing.
pub(crate) fn body_answers() -> Vec<(&'static str, &'static str)> {
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
pub(crate) const GOOD_KEY: &str = include_str!(
    "../../../../../docs/planning/prototypes/keygen-spike/fixtures/generated-clean.asc"
);

/// The body of a form post, percent-encoded the way a browser sends one.
pub(crate) fn encoded(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub(crate) fn percent_encode(value: &str) -> String {
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

/// A fixture account's record, changed in place: the tests below set one fact
/// each so the page is read against the record rather than against a page-only
/// flag.
pub(crate) fn amend_account(
    dir: &Path,
    username: &str,
    amend: impl FnOnce(&mut serde_json::Value),
) {
    let path = dir.join(format!("accounts/{username}/account.json"));
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    amend(&mut value);
    std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

/// The intent files the handler wrote, sorted.
pub(crate) fn intent_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v: Vec<std::path::PathBuf> = std::fs::read_dir(dir.join("intents"))
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

pub(crate) fn read_draft(dir: &Path, token: &str) -> kyriakon_control_core::store::draft::Draft {
    serde_json::from_str(
        &std::fs::read_to_string(dir.join("drafts").join(format!("{token}.json")))
            .expect("the draft is on disk"),
    )
    .expect("the draft parses")
}

/// A fake `kyriakon-authcheck`: it checks one password and prints a proof.
pub(crate) fn checker(name: &str, password: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("onboard-auth-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("kyriakon-authcheck");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nread -r given\n[ \"$given\" = '{password}' ] || exit 1\n\
             printf '%s\\n' '{}'\n",
            "ab".repeat(32)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}
