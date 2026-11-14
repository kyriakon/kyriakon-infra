//! Tests for the account module.

use crate::responder::test_support::*;
use crate::responder::*;
use kyriakon_control_core::{account::session, mail::keycheck};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

/// A mailbox account's `group` resolves to the group record, and the recipe it
/// carries is the same on both account pages.
#[tokio::test]
async fn a_group_member_reads_the_same_recipe_on_both_account_pages() {
    let (app, dir) = handler("group-account-recipe").await;
    file_group_account(&dir);
    let pinned = test_certificate(PINNED, "CN=parish-secretary");
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

    let (code, capsule) = ask(&app, &gmid_certificate("account", "", &pinned)).await;
    assert_eq!(code, 20);
    let cookie = signed_in(&app, "parish-secretary").await;
    let (code, web) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
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

    // Any mailbox holder sees the body's billing and state, which live on the
    // group's own record rather than being copied per account.
    for page in [&capsule, &web] {
        assert!(page.contains("Parish of Example"), "{page}");
        assert!(page.contains("parish.example"), "{page}");
        assert!(page.contains("Paid until 2027-01-01"), "{page}");
        assert!(page.contains("Rail: cash"), "{page}");
        assert!(
            page.contains(
                "Space used by the group: 1.0 GB of its 1 mailbox, 5 GB soft and 5.5 GB hard each"
            ),
            "{page}"
        );
    }

    // A web request that names no authenticated member is the page it was, and
    // never another member's recipe.
    let (_, anonymous) = ask(&app, &httpd_get("account", "")).await;
    assert!(!anonymous.contains("mail._domainkey"), "{anonymous}");

    // While the group's year is unpaid, any mailbox holder sees the one payment
    // reference and the day its window closes, because the billing lives on the
    // group rather than on their account.
    let path = dir.join("groups/parish.example/group.json");
    let mut group: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    group["payment"]["paid_until"] = serde_json::Value::Null;
    group["payment"]["token_ref"] = serde_json::json!("KYR-AAAA-BBBB-CCCC");
    group["payment"]["window"] = serde_json::json!({
        "opened_at": "2026-10-01T09:00:00Z",
        "closes_at": "2026-10-15T09:00:00Z",
        "state": "open",
        "extensions": 0
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&group).unwrap()).unwrap();
    let (_, capsule) = ask(&app, &gmid_certificate("account", "", &pinned)).await;
    let (_, web) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
    for page in [&capsule, &web] {
        assert!(page.contains("KYR-AAAA-BBBB-CCCC"), "{page}");
        assert!(page.contains("closes on 2026-10-15"), "{page}");
        assert!(page.contains("lapses together"), "{page}");
    }
}

/// A group record that is there and does not parse fails the page rather than
/// leaving the payment block out: an absent block reads as a group that owes
/// nothing.
#[tokio::test]
async fn a_corrupt_group_record_fails_the_account_pages() {
    let (app, dir) = handler("corrupt-group-record").await;
    file_group_account(&dir);
    std::fs::write(
        dir.join("groups/parish.example/group.json"),
        b"{\"version\": 1, \"domain\": \"parish.exa",
    )
    .unwrap();
    let pinned = test_certificate(PINNED, "CN=parish-secretary");

    let (code, body) = ask(&app, &gmid_certificate("account", "", &pinned)).await;
    assert_eq!(code, 50, "the capsule dropped the block: {body}");

    let cookie = signed_in(&app, "parish-secretary").await;
    let (code, body) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
    assert_eq!(code, 500, "the page dropped the block: {body}");
}

/// The login route. A correct password sets a signed, HttpOnly, SameSite cookie
/// with the twelve-hour lifetime; a wrong one comes back as the login page with
/// no cookie at all.
#[tokio::test]
async fn a_correct_mail_password_opens_a_session_and_a_wrong_one_does_not() {
    let (mut app, _dir) = handler("login").await;
    app.auth = session::Authenticator {
        program: checker("login-admits", "right horse battery"),
        args: Vec::new(),
    };

    let (code, body) = ask(
        &app,
        &httpd_post("/login", "username=alice&password=right+horse+battery"),
    )
    .await;
    assert_eq!(code, 303, "{body}");
    let set_cookie = body
        .split("Set-Cookie: ")
        .nth(1)
        .and_then(|rest| rest.split(['\r', '\n']).next())
        .expect("a session cookie is set");
    for flag in [
        "__Host-kyriakon_session=",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=43200",
        "Secure",
    ] {
        assert!(
            set_cookie.contains(flag),
            "the cookie misses {flag}: {set_cookie}"
        );
    }
    assert!(
        !set_cookie.contains("Domain"),
        "the cookie is host-only: {set_cookie}"
    );
    assert!(body.contains("Cache-Control: no-store"), "{body}");
    assert!(body.contains("Referrer-Policy: no-referrer"), "{body}");

    // The cookie it set opens the account page, and a wrong password sets
    // nothing and comes back as the login page.
    let cookie = body
        .split("Set-Cookie: __Host-kyriakon_session=")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .expect("the cookie value");
    let (code, _) = ask(&app, &httpd_get_session("account", "", cookie)).await;
    assert_eq!(code, 200);

    let (code, wrong) = ask(
        &app,
        &httpd_post("/login", "username=alice&password=wrong+horse+battery"),
    )
    .await;
    assert_eq!(code, 200);
    assert!(!wrong.contains("Set-Cookie"), "{wrong}");
    assert!(wrong.contains("did not match"), "{wrong}");
    assert!(wrong.contains("Cache-Control: no-store"), "{wrong}");
    assert!(wrong.contains("Referrer-Policy: no-referrer"), "{wrong}");

    // The login page a request with no session is shown is not cacheable
    // either: it is the same page the refusal renders.
    let (code, page) = ask(&app, &httpd_get("account", "")).await;
    assert_eq!(code, 200);
    assert!(page.contains("Cache-Control: no-store"), "{page}");
    assert!(page.contains("Referrer-Policy: no-referrer"), "{page}");
}

/// #804: the login hands the checker the source the request came from, because
/// the throttle refuses a (name, source) pair rather than a name anyone can read
/// out of `keys/`. The source is the address the rate counters key on: relayd's
/// own forwarded value for the web front-end, never a header the client wrote.
#[tokio::test]
async fn a_login_gives_the_checker_the_observed_source() {
    let (mut app, _dir) = handler("login-source").await;
    let (program, log) = checker_logging("login-source", "right horse battery");
    app.auth = session::Authenticator {
        program,
        args: Vec::new(),
    };

    let (code, body) = ask(
        &app,
        &httpd_post("/login", "username=alice&password=right+horse+battery"),
    )
    .await;
    assert_eq!(code, 303, "{body}");
    let logged = std::fs::read_to_string(&log).expect("the checker ran");
    let args: Vec<&str> = logged.split_whitespace().collect();
    assert_eq!(
        args.len(),
        3,
        "username, proof directory, source: {logged:?}"
    );
    assert_eq!(args[0], "alice");
    assert_eq!(
        args[2], "203.0.113.10",
        "the source is the address relayd observed, not httpd's peer: {logged:?}"
    );
}

/// #761: a login that cannot name itself as this page is refused before the
/// password is read, so the reply carries no session cookie. These are the rows
/// an attacker can drive; the same-origin submit above is the ordinary path.
#[tokio::test]
async fn a_login_from_another_origin_opens_no_session() {
    let (mut app, _dir) = handler("login-origin").await;
    app.auth = session::Authenticator {
        program: checker("login-origin", "right horse battery"),
        args: Vec::new(),
    };
    for (origin, site, what) in [
        (
            Some("null"),
            None,
            "a sandboxed frame with no Fetch Metadata",
        ),
        (None, Some("cross-site"), "a page on another site"),
        (None, None, "a client with no browser headers"),
    ] {
        let (code, body) = ask(
            &app,
            &httpd_post_from(
                "/login",
                "username=alice&password=right+horse+battery",
                origin,
                site,
                None,
            ),
        )
        .await;
        assert_eq!(code, 403, "{what}: {body}");
        assert!(!body.contains("Set-Cookie"), "{what}: {body}");
    }
}

/// A checker the closure tests run directly. It lives here rather than in a
/// shared helper because the closure tests are the only ones this branch adds,
/// and the account-page branch owns the login fixture.
fn closure_checker(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onboard-closure-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("kyriakon-authcheck");
    std::fs::write(
        &path,
        "#!/bin/sh
read -r given
[ \"$given\" = 'right horse battery' ] || exit 1
printf '%s\\n' 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'
",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// The page closure asks for the password again, files exactly one intent
/// carrying the session it used, and a wrong or empty password files nothing.
#[tokio::test]
async fn a_page_closure_requires_the_password_and_files_one_intent() {
    let (mut app, dir) = handler("close-password").await;
    file_account(&dir);
    app.auth = session::Authenticator {
        program: closure_checker("close"),
        args: Vec::new(),
    };
    let cookie = signed_in(&app, "alice").await;

    for body in ["password=wrong+horse+battery", "password="] {
        let (code, refused) = ask(
            &app,
            &httpd_post_with("/account/close", body, Some(&cookie)),
        )
        .await;
        assert_eq!(code, 403, "{refused}");
        assert!(refused.contains("did not match"), "{refused}");
        assert_eq!(filed(&dir), 0, "a refused closure filed something");
    }

    let (code, page) = ask(
        &app,
        &httpd_post_with(
            "/account/close",
            "password=right+horse+battery",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert!(page.contains("about seven months"), "{page}");
    assert_eq!(filed(&dir), 1, "the closure filed one intent");

    let name = std::fs::read_dir(dir.join("intents"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let intent: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(name).unwrap()).unwrap();
    assert_eq!(intent["kind"], serde_json::json!("close"), "{intent}");
    assert_eq!(intent["username"], serde_json::json!("alice"), "{intent}");
    assert_eq!(
        intent["session"],
        serde_json::json!(cookie.split('.').next().unwrap()),
        "{intent}"
    );
}

/// A closure inside the 14-day cancellation right names the refund; one outside
/// it says no refund is due.
#[tokio::test]
async fn a_closure_names_the_refund_only_inside_fourteen_days() {
    let (mut app, dir) = handler("close-refund-inside").await;
    file_account(&dir);
    file_payment(
        &dir,
        "alice",
        "KYR-AAAA-BBBB-CCCC",
        &kyriakon_control_core::util::date_after_days(-3),
        "20.00",
    );
    app.auth = session::Authenticator {
        program: closure_checker("refund-inside"),
        args: Vec::new(),
    };
    let cookie = signed_in(&app, "alice").await;
    let (code, page) = ask(
        &app,
        &httpd_post_with(
            "/account/close",
            "password=right+horse+battery",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert!(page.contains("refund of GBP 20.00"), "{page}");

    let (mut app, dir) = handler("close-refund-outside").await;
    file_account(&dir);
    file_payment(
        &dir,
        "alice",
        "KYR-AAAA-BBBB-CCCC",
        &kyriakon_control_core::util::date_after_days(-30),
        "20.00",
    );
    app.auth = session::Authenticator {
        program: closure_checker("refund-outside"),
        args: Vec::new(),
    };
    let cookie = signed_in(&app, "alice").await;
    let (code, page) = ask(
        &app,
        &httpd_post_with(
            "/account/close",
            "password=right+horse+battery",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert!(page.contains("No refund is due"), "{page}");
    assert!(!page.contains("GBP 20.00"), "{page}");
}

/// The ledger belongs to root and the handler runs as `_onboard`, so the read
/// can fail for every paying member. The refund line on the page is an estimate,
/// so an unreadable ledger shows none rather than failing the Close: the drain's
/// erasure answer, which reads as root, is the authoritative one.
#[tokio::test]
async fn a_closure_is_filed_even_when_the_ledger_cannot_be_read() {
    let (mut app, dir) = handler("close-refund-unreadable").await;
    file_account(&dir);
    file_payment(
        &dir,
        "alice",
        "KYR-AAAA-BBBB-CCCC",
        &kyriakon_control_core::util::date_after_days(-3),
        "20.00",
    );
    // A directory where the ledger belongs: the path cannot be read as a file,
    // whether or not the process is root.
    let ledger = dir.join("ledger/payments.jsonl");
    std::fs::remove_file(&ledger).unwrap();
    std::fs::create_dir(&ledger).unwrap();

    app.auth = session::Authenticator {
        program: closure_checker("refund-unreadable"),
        args: Vec::new(),
    };
    let cookie = signed_in(&app, "alice").await;
    let (code, page) = ask(
        &app,
        &httpd_post_with(
            "/account/close",
            "password=right+horse+battery",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert!(!page.contains("GBP 20.00"), "{page}");
    // The closure was filed: one close intent is on disk for the account.
    let filed: Vec<serde_json::Value> = std::fs::read_dir(dir.join("intents"))
        .unwrap()
        .flatten()
        .map(|entry| serde_json::from_str(&std::fs::read_to_string(entry.path()).unwrap()).unwrap())
        .collect();
    assert_eq!(filed.len(), 1, "{filed:?}");
    assert_eq!(filed[0]["kind"].as_str(), Some("close"), "{filed:?}");
    assert_eq!(filed[0]["username"].as_str(), Some("alice"), "{filed:?}");
}

/// The closing page offers the cancellation the terms promise. The POST files
/// one cancel-close intent carrying the session, an account that is not closing
/// is refused and files nothing, and the page shows the control the terms name.
#[tokio::test]
async fn the_closing_page_files_one_cancel_close_intent() {
    let (app, dir) = handler("cancel-close").await;
    file_account(&dir);
    amend_account(&dir, "alice", |account| {
        account["state"] = serde_json::json!("closing");
        account["closing_until"] =
            serde_json::json!(kyriakon_control_core::util::date_after_days(7));
    });
    let cookie = signed_in(&app, "alice").await;

    // The page carries the control beside the banner that says it is closing.
    let (code, page) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
    assert_eq!(code, 200, "{page}");
    assert!(page.contains("/account/cancel-close"), "{page}");
    assert!(page.contains("Cancel the closure"), "{page}");

    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/cancel-close", "", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert!(page.contains("The closure is cancelled"), "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "cancel-close", "{intent}");
    assert_eq!(intent["username"], "alice", "{intent}");
    assert_eq!(
        intent["session"],
        serde_json::json!(cookie.split_once('.').unwrap().0),
        "{intent}"
    );

    // An account that is not closing has nothing to cancel, and the refusal
    // files no second intent.
    amend_account(&dir, "alice", |account| {
        account["state"] = serde_json::json!("active");
        account["closing_until"] = serde_json::Value::Null;
    });
    let (code, body) = ask(
        &app,
        &httpd_post_with("/account/cancel-close", "", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 403, "{body}");
    assert!(body.contains("not closing"), "{body}");
    assert_eq!(filed(&dir), 1, "a refusal filed a second intent");
}

/// No key admits anyone, and neither does a header the front-end did not
/// authenticate: a request naming a member in `REMOTE_USER` with no session gets
/// the login page.
#[tokio::test]
async fn no_key_and_no_remote_user_admits_a_member() {
    let (app, dir) = handler("no-key-admits").await;
    file_account(&dir);
    let (code, body) = ask(&app, &httpd_get_as("account", "", Some("alice"))).await;
    assert_eq!(code, 200);
    assert!(body.contains("Log in with your mail password"), "{body}");
    assert!(
        !body.contains("Application approved, account opened."),
        "{body}"
    );

    // The mail password is the only credential; a key presented as one is
    // refused like any other wrong password.
    let (mut app, _dir) = handler("no-key-password").await;
    app.auth = session::Authenticator {
        program: checker("login-key", "right horse battery"),
        args: Vec::new(),
    };
    let (code, body) = ask(
        &app,
        &httpd_post(
            "/login",
            "username=alice&password=SHA256%3A0123456789abcdef",
        ),
    )
    .await;
    assert_eq!(code, 200);
    assert!(!body.contains("Set-Cookie"), "{body}");
}

/// The read-only view: the quota against the published allowance, the address
/// outside the platform, the upload key fingerprints and dates, and every
/// notice with the address it went to.
#[tokio::test]
async fn the_account_page_shows_the_quota_keys_and_every_notice() {
    let (app, dir) = handler("account-facts").await;
    file_account(&dir);
    amend_account(&dir, "alice", |value| {
        value["outside_address"] = serde_json::json!("alice@example.invalid");
        value["upload_keys"] = serde_json::json!([
            {"fingerprint": "SHA256:AAAAexamplekey", "added_at": "2026-10-02T09:00:00Z"}
        ]);
    });
    let mut notices = std::fs::read_to_string(dir.join("accounts/alice/notices.jsonl")).unwrap();
    notices.push_str(
        "{\"version\":1,\"at\":\"2026-10-03T09:00:00Z\",\"type\":\"prepaid.receipt\",\
         \"subject\":\"Receipt for your payment.\",\"to\":\"alice@example.invalid\"}\n",
    );
    std::fs::write(dir.join("accounts/alice/notices.jsonl"), notices).unwrap();

    let cookie = signed_in(&app, "alice").await;
    let (code, body) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
    assert_eq!(code, 200);
    assert!(body.contains("Cache-Control: no-store"), "{body}");
    assert!(body.contains("Referrer-Policy: no-referrer"), "{body}");
    assert!(
        body.contains("412 MB of the 5 GB soft and 5.5 GB hard allowance"),
        "{body}"
    );
    assert!(body.contains("alice@example.invalid"), "{body}");
    assert!(body.contains("SHA256:AAAAexamplekey"), "{body}");
    assert!(body.contains("2026-10-02"), "the key's date: {body}");
    assert!(
        body.contains("Application approved, account opened."),
        "{body}"
    );
    assert!(body.contains("Receipt for your payment."), "{body}");
    assert!(
        body.contains("alice@kyriakon.net") && body.contains("alice@example.invalid"),
        "both addresses are listed: {body}"
    );
}

/// A session record whose username is not a name the platform could have made
/// is refused before any store path is built from it.
#[tokio::test]
async fn a_session_username_outside_the_charset_is_refused_before_a_path_is_built() {
    let (app, _dir) = handler("session-shape").await;
    for bad in ["../alice", "alice/..", "Alice", "alice\u{0}"] {
        let proof = mint_proof(&app, bad);
        let cookie = session::open(&app.store, bad, &proof, OffsetDateTime::now_utc())
            .await
            .unwrap();
        let (code, body) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
        assert_eq!(code, 200, "{bad}");
        assert!(
            body.contains("Log in with your mail password"),
            "{bad} reached a page: {body}"
        );
    }
}

/// A suspended page stays open, with the reason, so the member can read it and
/// answer it.
#[tokio::test]
async fn a_suspended_account_still_opens_with_its_reason() {
    let (app, dir) = handler("suspended").await;
    file_account(&dir);
    amend_account(&dir, "alice", |value| {
        value["state"] = serde_json::json!("suspended");
        value["suspension_reason"] =
            serde_json::json!("Outbound mail from this account broke the acceptable use policy.");
    });
    let cookie = signed_in(&app, "alice").await;
    let (code, body) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
    assert_eq!(code, 200);
    assert!(body.contains("This account is suspended"), "{body}");
    assert!(body.contains("broke the acceptable use policy"), "{body}");
}

/// "Take my data out" files an export intent for the account the request is
/// authenticated as, and changes nothing else a member holds. A request with no
/// authenticated account files nothing.
#[tokio::test]
async fn the_account_pages_export_action_files_an_intent_for_the_session_account() {
    let (app, dir) = handler("account-export").await;
    file_account(&dir);
    let before = std::fs::read(dir.join("accounts/alice/account.json")).unwrap();

    let cookie = signed_in(&app, "alice").await;
    let (code, body) = ask(
        &app,
        &httpd_post_with("account", "action=export", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert!(body.contains("Your data export is on its way"), "{body}");

    let intents: Vec<PathBuf> = std::fs::read_dir(dir.join("intents"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    assert_eq!(intents.len(), 1, "one intent was filed");
    let filed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&intents[0]).unwrap()).unwrap();
    assert_eq!(filed["kind"], "export");
    assert_eq!(filed["username"], "alice");
    assert_eq!(
        filed["session"],
        cookie.split('.').next().unwrap(),
        "the session the drain will verify"
    );
    // The account directory is the drain's to change, not this route's.
    assert_eq!(
        std::fs::read(dir.join("accounts/alice/account.json")).unwrap(),
        before
    );

    // Without a session there is nobody the export could belong to, so nothing
    // is filed.
    let (code, _) = ask(&app, &httpd_post("account", "action=export")).await;
    assert_eq!(code, 403);
    assert_eq!(
        std::fs::read_dir(dir.join("intents")).unwrap().count(),
        1,
        "no second intent"
    );
}

/// The test-mail button files one session-proved intent for the account the
/// session names. A request with no session files nothing.
#[tokio::test]
async fn the_test_mail_button_files_an_intent_for_the_session_account() {
    let (app, dir) = handler("account-test-mail").await;
    file_account(&dir);
    amend_account(&dir, "alice", |value| {
        value["mail_key"] = serde_json::json!("AAAA");
    });
    let cookie = signed_in(&app, "alice").await;

    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/test-mail", "", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert!(page.contains("Your test message is on its way"), "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "test-mail");
    assert_eq!(intent["username"], "alice");
    assert_eq!(
        intent["session"],
        cookie.split('.').next().unwrap(),
        "the session the drain will verify"
    );

    // No session, no account to send to.
    let (code, _) = ask(&app, &httpd_post("/account/test-mail", "")).await;
    assert_eq!(code, 403);
    assert_eq!(filed(&dir), 1, "an intent was filed without a session");
}

/// Without a recorded mail key there is nothing to encrypt to, so the route
/// refuses rather than filing a message delivery could not address.
#[tokio::test]
async fn the_test_mail_button_needs_a_recorded_mail_key() {
    let (app, dir) = handler("account-test-mail-no-key").await;
    file_account(&dir);
    let cookie = signed_in(&app, "alice").await;

    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/test-mail", "", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 403, "{page}");
    assert!(page.contains("has not recorded a mail key"), "{page}");
    assert_eq!(filed(&dir), 0, "an intent was filed without a key");
}

/// The notice record is the day's dedup. Another day's notice, and today's date
/// under another subject, both leave the route free; today's own notice refuses
/// it rather than filing a second send.
#[tokio::test]
async fn the_test_mail_button_reads_the_day_from_the_notice_record() {
    let (app, dir) = handler("account-test-mail-day").await;
    file_account(&dir);
    amend_account(&dir, "alice", |value| {
        value["mail_key"] = serde_json::json!("AAAA");
    });
    let cookie = signed_in(&app, "alice").await;
    let today = kyriakon_control_core::util::filed_at();

    // Yesterday's notice, with yesterday's subject, does not count.
    add_test_mail_notice(&dir, "2026-01-01T09:00:00Z", None);
    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/test-mail", "", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert_eq!(filed(&dir), 1, "an earlier day blocked today's test");

    // Today's date under another subject is not this test's notice either.
    add_test_mail_notice(&dir, &today, Some("Another subject entirely"));
    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/test-mail", "", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert_eq!(
        filed(&dir),
        2,
        "a notice for another subject blocked the test"
    );

    // Today's own notice is the one message the day gets.
    add_test_mail_notice(&dir, &today, None);
    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/test-mail", "", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 403, "{page}");
    assert!(page.contains("already gone out today"), "{page}");
    assert_eq!(filed(&dir), 2, "a second intent was filed for the day");
}

/// Append one notice line, as the drain records it before it enqueues a
/// message. The subject defaults to the day's own test subject so a caller can
/// make it differ.
fn add_test_mail_notice(dir: &Path, at: &str, subject: Option<&str>) {
    let day = at.get(..10).unwrap_or(at);
    let subject = subject
        .map(str::to_string)
        .unwrap_or_else(|| kyriakon_control_core::mail::notice::test_mail_subject(day));
    let line = serde_json::json!({
        "version": 1,
        "at": at,
        "type": "test-mail",
        "subject": subject,
        "to": "alice@kyriakon.net",
    });
    let path = dir.join("accounts/alice/notices.jsonl");
    let mut notices = std::fs::read_to_string(&path).unwrap();
    notices.push_str(&format!("{line}\n"));
    std::fs::write(&path, notices).unwrap();
}

/// The password form re-enters the current password whatever the session's age,
/// and files one intent carrying the new hash and nothing else. A wrong current
/// password, a short new one and a mismatched pair all file nothing.
#[tokio::test]
async fn the_password_form_requires_the_current_password_and_files_one_intent() {
    let (mut app, dir) = handler("account-password").await;
    file_account(&dir);
    app.auth = session::Authenticator {
        program: checker("account-password", "right horse battery"),
        args: Vec::new(),
    };
    let cookie = signed_in(&app, "alice").await;

    for body in [
        "password=&new_password=twelve+chars%21&confirm_password=twelve+chars%21",
        "password=wrong+horse+battery&new_password=twelve+chars%21&confirm_password=twelve+chars%21",
        "password=right+horse+battery&new_password=short&confirm_password=short",
        "password=right+horse+battery&new_password=twelve+chars%21&confirm_password=other+chars%21",
    ] {
        let (code, refused) = ask(
            &app,
            &httpd_post_with("/account/password", body, Some(&cookie)),
        )
        .await;
        assert_eq!(code, 403, "{body}: {refused}");
        assert_eq!(filed(&dir), 0, "{body} filed something");
    }

    let (code, page) = ask(
        &app,
        &httpd_post_with(
            "/account/password",
            "password=right+horse+battery&new_password=a+long+new+password&confirm_password=a+long+new+password",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert!(page.contains("Your password is changing"), "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "change-password");
    assert_eq!(intent["username"], "alice");
    assert_eq!(
        intent["session"],
        cookie.split('.').next().unwrap(),
        "the session the drain will verify"
    );
    assert_eq!(
        intent["password"], "a long new password",
        "the drain hashes the plaintext, so the handler files it"
    );
    assert!(intent.get("hash").is_none(), "{intent}");
}

/// The upload key form adds one key and removes the one on the account; a line
/// that is not a bare OpenSSH key, and a fingerprint the account does not carry,
/// are both refused before anything is filed.
#[tokio::test]
async fn the_upload_key_forms_add_and_remove_the_one_key() {
    const UPLOAD: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample secretary@example";
    let (app, dir) = handler("account-upload-key").await;
    file_account(&dir);
    let fingerprint = keycheck::openssh_fingerprint(UPLOAD).unwrap();
    amend_account(&dir, "alice", |value| {
        value["upload_keys"] = serde_json::json!([
            {"fingerprint": fingerprint, "added_at": "2026-10-02T09:00:00Z"}
        ]);
    });
    let cookie = signed_in(&app, "alice").await;

    let (code, refused) = ask(
        &app,
        &httpd_post_with(
            "/account/upload-key",
            "action=add&key=not+a+key",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 403, "{refused}");
    let (code, _) = ask(
        &app,
        &httpd_post_with(
            "/account/upload-key",
            "action=remove&fingerprint=SHA256%3Anot-on-the-account",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 403);
    assert_eq!(filed(&dir), 0, "a refused key filed something");

    // A form whose action is missing or is not one this route carries out is a
    // refusal, not a method the route does not have.
    for body in ["action=rename", ""] {
        let (code, _) = ask(
            &app,
            &httpd_post_with("/account/upload-key", body, Some(&cookie)),
        )
        .await;
        assert_eq!(code, 403, "{body:?}");
    }
    assert_eq!(filed(&dir), 0);

    let body = format!("action=add&key={}", UPLOAD.replace(' ', "%20"));
    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/upload-key", &body, Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "upload-key");
    assert_eq!(intent["action"], "add");
    assert_eq!(intent["material"], UPLOAD);

    // The removal names the fingerprint, which is what the page shows.
    std::fs::remove_dir_all(dir.join("intents")).unwrap();
    std::fs::create_dir_all(dir.join("intents")).unwrap();
    let encoded = fingerprint.replace(':', "%3A");
    let (code, page) = ask(
        &app,
        &httpd_post_with(
            "/account/upload-key",
            &format!("action=remove&fingerprint={encoded}"),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "upload-key");
    assert_eq!(intent["action"], "remove");
    assert_eq!(intent["fingerprint"], fingerprint);
}

/// The contact address form files a set or a clear, and refuses anything that
/// is not one address.
#[tokio::test]
async fn the_address_form_sets_and_clears_the_contact_address() {
    let (app, dir) = handler("account-address").await;
    file_account(&dir);
    let cookie = signed_in(&app, "alice").await;

    let (code, _) = ask(
        &app,
        &httpd_post_with(
            "/account/address",
            "address=two%40at%40example.invalid",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 403);
    assert_eq!(filed(&dir), 0);

    let (code, page) = ask(
        &app,
        &httpd_post_with(
            "/account/address",
            "address=alice%40example.invalid",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "outside-address");
    assert_eq!(intent["address"], "alice@example.invalid");

    std::fs::remove_dir_all(dir.join("intents")).unwrap();
    std::fs::create_dir_all(dir.join("intents")).unwrap();
    let (code, _) = ask(
        &app,
        &httpd_post_with("/account/address", "address=", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200);
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "outside-address");
    assert_eq!(
        intent["address"], "",
        "an empty field is the clear, not a refusal"
    );
}

/// The two serving checkboxes are independent: an absent box is off, and the
/// intent carries both booleans so the drain can leave the other lane alone.
#[tokio::test]
async fn the_serving_form_carries_two_independent_booleans() {
    let (app, dir) = handler("account-serving").await;
    file_account(&dir);
    let cookie = signed_in(&app, "alice").await;

    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/serving", "gemini=on", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "serving");
    assert_eq!(intent["http"], serde_json::json!(false), "{intent}");
    assert_eq!(intent["gemini"], serde_json::json!(true), "{intent}");
}

/// The renewal control is filed only when the account holds a card
/// subscription; a prepaid or free account is told there is nothing to stop.
#[tokio::test]
async fn the_renewal_control_needs_a_card_subscription() {
    let (app, dir) = handler("account-renewal-none").await;
    file_account(&dir);
    let cookie = signed_in(&app, "alice").await;
    let (code, refused) = ask(
        &app,
        &httpd_post_with("/account/renewal", "action=cancel", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 403, "{refused}");
    assert_eq!(filed(&dir), 0);

    let (app, dir) = handler("account-renewal-card").await;
    file_account(&dir);
    amend_account(&dir, "alice", |value| {
        value["rail"] = serde_json::json!("card");
        value["no_charge"] = serde_json::json!(false);
        value["payment"] = serde_json::json!({
            "paid_until": "2027-10-02",
            "stripe": {"subscription": "sub_example", "status": "active"}
        });
    });
    let cookie = signed_in(&app, "alice").await;
    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/renewal", "action=cancel", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "cancel-renewal");
}

/// A card-paying group's renewal control belongs to its site owner: that
/// mailbox sees the control and files the cancel, and another mailbox in the
/// body is offered nothing and refused.
#[tokio::test]
async fn a_group_site_owner_stops_the_groups_renewal_and_another_mailbox_cannot() {
    let (app, dir) = handler("group-renewal").await;
    file_group_account(&dir);
    let path = dir.join("groups/parish.example/group.json");
    let mut group: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    group["payment"]["rail"] = serde_json::json!("card");
    group["payment"]["stripe"] = serde_json::json!({
        "subscription": "sub_example",
        "customer": "cus_example",
        "status": "active"
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&group).unwrap()).unwrap();
    let cookie = signed_in(&app, "parish-secretary").await;

    let (code, page) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
    assert_eq!(code, 200, "{page}");
    assert!(page.contains("Stop the yearly renewal"), "{page}");
    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/renewal", "action=cancel", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert_eq!(filed_intent(&dir)["kind"], "cancel-renewal");

    // The body names another site owner, so this mailbox is not the one that
    // may stop its card.
    std::fs::remove_dir_all(dir.join("intents")).unwrap();
    std::fs::create_dir_all(dir.join("intents")).unwrap();
    group["site_owner"] = serde_json::json!("parish-warden");
    std::fs::write(&path, serde_json::to_vec_pretty(&group).unwrap()).unwrap();
    let (_, page) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
    assert!(!page.contains("Stop the yearly renewal"), "{page}");
    let (code, refused) = ask(
        &app,
        &httpd_post_with("/account/renewal", "action=cancel", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 403, "{refused}");
    assert_eq!(filed(&dir), 0);
}

/// The mail key form rejects a block that is not a public key, a key approval
/// would refuse, and the key already in use, and files both a replacement and a
/// cancel.
#[tokio::test]
async fn the_mail_key_form_starts_and_cancels_a_replacement() {
    let (app, dir) = handler("account-mail-key").await;
    file_account(&dir);
    let key = std::fs::read_to_string(format!(
        "{}/../../../docs/planning/prototypes/keygen-spike/fixtures/generated-clean.asc",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let fingerprint = keycheck::pgp_fingerprint(&key).unwrap();
    amend_account(&dir, "alice", |value| {
        value["mail_key"] = serde_json::json!(fingerprint);
    });
    let cookie = signed_in(&app, "alice").await;

    let (code, _) = ask(
        &app,
        &httpd_post_with(
            "/account/mail-key",
            "action=replace&key=not+a+key",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(code, 403);
    // The key already in use is not a replacement.
    let body = format!("action=replace&key={}", url_encode(&key));
    let (code, refused) = ask(
        &app,
        &httpd_post_with("/account/mail-key", &body, Some(&cookie)),
    )
    .await;
    assert_eq!(code, 403, "{refused}");
    assert_eq!(filed(&dir), 0);

    // A cancel with nothing pending is refused rather than filed.
    let (code, _) = ask(
        &app,
        &httpd_post_with("/account/mail-key", "action=cancel", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 403);
    assert_eq!(filed(&dir), 0);

    // A different key and an empty signature starts the window.
    amend_account(&dir, "alice", |value| {
        value["mail_key"] = serde_json::json!("AAAA");
    });
    let body = format!("action=replace&key={}", url_encode(&key));
    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/mail-key", &body, Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "mail-key");
    assert_eq!(intent["action"], "replace");
    assert_eq!(intent["signature"], "");
    assert_eq!(intent["material"], key.trim());

    // With a replacement waiting, the cancel files.
    std::fs::remove_dir_all(dir.join("intents")).unwrap();
    std::fs::create_dir_all(dir.join("intents")).unwrap();
    amend_account(&dir, "alice", |value| {
        value["rotation"] = serde_json::json!({
            "fingerprint": "AAAA",
            "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
            "requested_at": "2026-10-02T09:00:00Z",
            "applies_at": "2026-10-05T09:00:00Z"
        });
    });
    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/mail-key", "action=cancel", Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "mail-key");
    assert_eq!(intent["action"], "cancel");
}

/// A key the drain would refuse is refused at the page, with the reason, and
/// no intent is filed: a settlement refusal runs no after-line work, so the
/// member would otherwise never be told.
#[tokio::test]
async fn the_mail_key_form_refuses_a_key_delivery_cannot_use() {
    let (app, dir) = handler("account-mail-key-refused").await;
    file_account(&dir);
    amend_account(&dir, "alice", |value| {
        value["mail_key"] = serde_json::json!("AAAA");
    });
    let cookie = signed_in(&app, "alice").await;

    for (fixture, why) in [
        ("gpg-future-expiry.asc", "expires at"),
        (
            "gpg-future-expiry-subkey.asc",
            "encryption subkey expires at",
        ),
        ("gpg-aead.asc", "AEAD"),
        (
            "gpg-no-encryption-subkey.asc",
            "no encryption-capable subkey",
        ),
    ] {
        let key = std::fs::read_to_string(format!(
            "{}/../../../docs/planning/prototypes/keygen-spike/fixtures/{fixture}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let body = format!("action=replace&key={}", url_encode(&key));
        let (code, page) = ask(
            &app,
            &httpd_post_with("/account/mail-key", &body, Some(&cookie)),
        )
        .await;
        assert_eq!(code, 403, "{fixture}: {page}");
        assert!(page.contains(why), "{fixture}: {page}");
        assert_eq!(filed(&dir), 0, "{fixture}: an intent was filed");
    }
}

/// A block the key crate cannot parse is an advisory, not a finding: the page
/// shows the warning and files the intent, because approval warns and proceeds
/// and a parser gap must not stop a rotation.
#[tokio::test]
async fn the_mail_key_form_warns_but_files_an_uninspected_key() {
    let (app, dir) = handler("account-mail-key-uninspected").await;
    file_account(&dir);
    amend_account(&dir, "alice", |value| {
        value["mail_key"] = serde_json::json!("AAAA");
    });
    let cookie = signed_in(&app, "alice").await;
    // Framing and a public key packet, and nothing the parser can read, which
    // is `GOOD_KEY` in the acceptance suite's fixtures.
    let key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
               mAYEAAAAABK4BgQAAAAAEg==\n-----END PGP PUBLIC KEY BLOCK-----\n";
    let body = format!("action=replace&key={}", url_encode(key));
    let (code, page) = ask(
        &app,
        &httpd_post_with("/account/mail-key", &body, Some(&cookie)),
    )
    .await;
    assert_eq!(code, 200, "{page}");
    assert!(page.contains("could not be inspected"), "{page}");
    let intent = filed_intent(&dir);
    assert_eq!(intent["kind"], "mail-key");
    assert_eq!(intent["material"], key.trim());
}

/// A value for an `application/x-www-form-urlencoded` body, so a pasted key
/// block with newlines and `+` characters survives the round trip.
fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The page offers each action, and a waiting replacement carries its cancel.
#[tokio::test]
async fn the_account_page_offers_every_action() {
    let (app, dir) = handler("account-actions-page").await;
    file_account(&dir);
    amend_account(&dir, "alice", |value| {
        value["site_served"] = serde_json::json!(true);
        value["capsule_served"] = serde_json::json!(false);
        value["upload_keys"] = serde_json::json!([
            {"fingerprint": "SHA256:AAAAexamplekey", "added_at": "2026-10-02T09:00:00Z"}
        ]);
        value["mail_key"] = serde_json::json!("AAAA");
        value["rotation"] = serde_json::json!({
            "fingerprint": "BBBB",
            "material": "key",
            "requested_at": "2026-10-02T09:00:00Z",
            "applies_at": "2026-10-05T09:00:00Z"
        });
    });
    let cookie = signed_in(&app, "alice").await;
    let (code, body) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
    assert_eq!(code, 200);
    for action in [
        "/account/password",
        "/account/upload-key",
        "/account/address",
        "/account/serving",
        "/account/mail-key",
        "/account/test-mail",
    ] {
        assert!(body.contains(action), "{action} is missing: {body}");
    }
    assert!(body.contains("BBBB"), "the pending key: {body}");
    assert!(body.contains("Cancel the replacement"), "{body}");
    assert!(
        body.contains(r#"name="gemini"#) && !body.contains(r#"name="gemini" checked"#),
        "the two checkboxes carry their own state: {body}"
    );

    // Without a recorded key there is nothing to encrypt a test message to, so
    // the control is absent rather than a button that always refuses.
    amend_account(&dir, "alice", |value| {
        value["mail_key"] = serde_json::Value::Null;
    });
    let (_, body) = ask(&app, &httpd_get_session("account", "", &cookie)).await;
    assert!(!body.contains("/account/test-mail"), "{body}");
}
