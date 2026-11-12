//! Erasure: the console's delete and the page's close reach the lifecycle's one
//! deletion transition, and the ledger line survives without a name.

use crate::common::*;

/// A delete-user.sh that does what the real script does to the fixture tree, so
/// the transition's call and the removals it owns are both visible. The script's
/// own self-test covers the ordering and the real paths.
fn fake_delete_user(fix: &Fix) {
    let log = fix.path("scripts.log");
    let passwd = fix.path("passwd");
    let base = fix.dir.to_str().unwrap().to_string();
    fix.script(
        "delete-user.sh",
        &format!(
            "#!/bin/sh\n\
             echo \"delete-user.sh $*\" >> '{log}'\n\
             grep -v \"^$1:\" '{passwd}' > '{passwd}.del' || true\n\
             mv '{passwd}.del' '{passwd}'\n\
             rm -rf '{base}/store/accounts/'\"$1\"\n\
             rm -rf '{base}/home/'\"$1\" '{base}/home/www/'\"$1\"'.kyriakon.net'\n\
             rm -f '{base}/host/httpd.d/'\"$1\"'.kyriakon.net.conf' \\\n\
                   '{base}/host/gmid.d/'\"$1\"'.kyriakon.net.conf' \\\n\
                   '{base}/host/acme-client.d/'\"$1\"'.kyriakon.net.conf' \\\n\
                   '{base}/host/ssl/'\"$1\"'.kyriakon.net.fullchain.pem' \\\n\
                   '{base}/host/ssl/private/'\"$1\"'.kyriakon.net.key'\n\
             echo \"quota-apply --clear $1\" >> '{log}'\n\
             echo gen-finger-page >> '{log}'\n"
        ),
    );
}

/// The console runs the deletion transition directly: the account, its home,
/// its published tree, its vhosts and certificate, its keyring entry and its
/// token index entry go, while the ledger's dated line stays and names nobody.
#[test]
fn the_console_delete_removes_the_account_and_leaves_the_ledger_unlinkable() {
    let fix = Fix::new("erasure-ctl");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_credit(&fix, &token);
    // A recorded cancellation refund, so the erasure answer has to name it.
    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "20.00",
        "--rail",
        "cash",
        "--reason",
        "cancelled inside 14 days",
        "--close",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    // The artefacts the real script removes, and one other account's keyring
    // entry that must stay.
    let home = fix.dir.join("home/secretary/Maildir/new");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("message"), "ciphertext").unwrap();
    let public = fix.dir.join("home/www/secretary.kyriakon.net/www");
    std::fs::create_dir_all(&public).unwrap();
    let host = fix.dir.join("host");
    for file in [
        "httpd.d/secretary.kyriakon.net.conf",
        "gmid.d/secretary.kyriakon.net.conf",
        "acme-client.d/secretary.kyriakon.net.conf",
        "ssl/secretary.kyriakon.net.fullchain.pem",
        "ssl/private/secretary.kyriakon.net.key",
    ] {
        std::fs::write(host.join(file), "x").unwrap();
    }
    let keyring = fix.dir.join("keyring");
    std::fs::create_dir_all(&keyring).unwrap();
    std::fs::write(keyring.join("secretary.asc"), "public key").unwrap();
    std::fs::write(keyring.join("treasurer.asc"), "public key").unwrap();
    // The answer has an address that outlives the account to go to.
    let mut account = fix.account("secretary");
    account["outside_address"] = json!("secretary@example.invalid");
    std::fs::write(
        fix.dir.join("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();
    fake_delete_user(&fix);
    assert!(fix.dir.join(format!("store/tokens/{token}.json")).exists());

    let ledger_before = fix.read("ledger/payments.jsonl");
    let out = fix.ctl(&["delete", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("deleted secretary"), "{}", body(&out));

    assert!(
        !fix.passwd_file().contains("secretary:"),
        "{}",
        fix.passwd_file()
    );
    assert!(!fix.dir.join("home/secretary").exists(), "the home stayed");
    assert!(!public.exists(), "the published tree stayed");
    for file in [
        "httpd.d/secretary.kyriakon.net.conf",
        "gmid.d/secretary.kyriakon.net.conf",
        "acme-client.d/secretary.kyriakon.net.conf",
        "ssl/secretary.kyriakon.net.fullchain.pem",
        "ssl/private/secretary.kyriakon.net.key",
    ] {
        assert!(!host.join(file).exists(), "{file} stayed");
    }
    assert!(
        !fix.dir.join("store/accounts/secretary").exists(),
        "the store record stayed"
    );
    assert!(
        !fix.dir.join(format!("store/tokens/{token}.json")).exists(),
        "the token index entry stayed"
    );
    assert!(
        !keyring.join("secretary.asc").exists(),
        "the keyring entry stayed"
    );
    assert!(
        keyring.join("treasurer.asc").exists(),
        "another account's keyring entry went"
    );
    let log = fix.scripts_log();
    assert!(log.contains("delete-user.sh secretary"), "{log}");
    assert!(log.contains("quota-apply --clear secretary"), "{log}");
    assert!(log.contains("gen-finger-page"), "{log}");

    // The ledger is unchanged and still resolves to the token alone.
    assert_eq!(fix.read("ledger/payments.jsonl"), ledger_before);
    let ledger = fix.read("ledger/payments.jsonl");
    assert!(ledger.contains(&token), "{ledger}");
    assert!(ledger.contains("\"amount_gbp\":\"20.00\""), "{ledger}");
    assert!(ledger.contains("\"paid_until_after\""), "{ledger}");
    for word in ["secretary", "example.invalid", "@"] {
        assert!(!ledger.contains(word), "the ledger names {word}: {ledger}");
    }

    // The name is held, and the durable answer is the journal line, which
    // outlives the account and its notices file.
    // The hold is ninety days out; the seconds differ by the time between the
    // deletion and this check, so the date is what is compared.
    let hold: Value = serde_json::from_str(&fix.read("holds/secretary.json")).unwrap();
    assert_eq!(hold["username"], json!("secretary"));
    let until = hold["until"].as_str().unwrap();
    assert!(
        until.starts_with(&kyriakon_control_core::util::date_after_days(90)),
        "{until}"
    );
    let journal = fix.journal();
    assert!(journal.contains("\"kind\":\"delete\""), "{journal}");
    assert!(journal.contains("\"outcome\":\"applied\""), "{journal}");
    assert!(
        journal.contains("\"outcome\":\"erasure-answer\""),
        "{journal}"
    );
    for fact in ["about seven months", "ledger", "no username", "90 days"] {
        assert!(
            journal.contains(fact),
            "the answer misses {fact}: {journal}"
        );
    }
    assert!(
        journal.contains("GBP 20.00"),
        "the refund fact is missing: {journal}"
    );
    // The notice goes to the outside address that survives the mailbox.
    let sent = fix.sent();
    assert!(sent.contains("To: secretary@example.invalid"), "{sent}");
    assert!(sent.contains("about seven months"), "{sent}");
}

/// The page's close and the console's delete end in the same transition: the
/// page files a close intent, the drain sets the seven-day window and deletes
/// when it ends, and both paths journal and run `delete-user.sh` identically.
#[test]
fn the_page_close_and_the_console_delete_end_in_the_same_transition() {
    let page = Fix::new("erasure-page-close");
    let token = approved_paid(&page, "secretary", "cash");
    let id = page.file_close("secretary");
    assert!(
        page.dir.join(format!("store/intents/{id}.json")).exists(),
        "the page's close intent was not filed"
    );
    assert!(page.drain().status.success());
    let account = page.account("secretary");
    assert_eq!(account["state"], json!("closing"), "{account}");
    assert_eq!(
        account["closing_until"],
        json!(kyriakon_control_core::util::date_after_days(7)),
        "{account}"
    );
    assert!(
        !page.scripts_log().contains("delete-user.sh"),
        "the page deleted inside the seven-day window: {}",
        page.scripts_log()
    );
    let requests = page.read("accounts/secretary/requests.jsonl");
    let request: Value = serde_json::from_str(requests.lines().next().unwrap()).unwrap();
    assert_eq!(request["kind"], json!("erasure"), "{request}");
    assert_eq!(request["username"], json!("secretary"), "{request}");
    assert!(
        request["evidence"]
            .as_str()
            .unwrap()
            .contains("password re-entered"),
        "{request}"
    );
    assert_eq!(request["identity"], "password", "{request}");

    // The window ends.
    let mut account = account;
    account["closing_until"] = json!(kyriakon_control_core::util::date_after_days(-1));
    std::fs::write(
        page.dir.join("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();
    assert!(page.drain().status.success());
    assert!(page.scripts_log().contains("delete-user.sh secretary"));
    assert!(
        !page.dir.join("store/accounts/secretary").exists(),
        "the page's closing sweep left the account"
    );
    assert!(
        !page.dir.join(format!("store/tokens/{token}.json")).exists(),
        "the page's closing sweep left the token index"
    );
    let page_journal = page.journal();
    assert!(
        page_journal.contains("\"intent\":\"delete-secretary-"),
        "{page_journal}"
    );
    assert!(
        page_journal.contains("\"kind\":\"delete\""),
        "{page_journal}"
    );

    // The console's path on the same fixture shape.
    let console = Fix::new("erasure-console-same");
    approved_paid(&console, "secretary", "cash");
    fake_delete_user(&console);
    let out = console.ctl(&["delete", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let console_journal = console.journal();
    assert!(
        console_journal.contains("\"intent\":\"delete-secretary-"),
        "{console_journal}"
    );
    assert!(
        console_journal.contains("\"kind\":\"delete\""),
        "{console_journal}"
    );
    assert!(console.scripts_log().contains("delete-user.sh secretary"));
    // The record has gone but the journal line remains, so a retry is accepted
    // rather than refused as an unknown name.
    let again = console.ctl(&["delete", "secretary"]);
    assert!(again.status.success(), "{}", body(&again));
}

/// Closing a card-paying account stops the subscription when the closure is
/// filed, and the deletion that follows sends no second cancel.
#[test]
fn closing_a_card_account_stops_its_subscription_once() {
    let fix = Fix::new("erasure-close-card");
    fix.card_account("secretary", Some("2027-10-02"));
    fix.file_close("secretary");
    assert!(fix.drain().status.success());

    let log = fix.scripts_log();
    assert_eq!(
        log.matches("stripe-api.sh cancel sub_example").count(),
        1,
        "{log}"
    );
    let account = fix.account("secretary");
    assert_eq!(
        account["payment"]["stripe"]["cancel_at_period_end"],
        json!(true),
        "{account}"
    );
    assert_eq!(
        account["payment"]["paid_until"], "2027-10-02",
        "the paid period is not shortened: {account}"
    );

    // The seven days end: the deletion finds the flag and sends nothing.
    let mut account = account;
    account["closing_until"] = json!(kyriakon_control_core::util::date_after_days(-1));
    std::fs::write(
        fix.dir.join("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();
    assert!(fix.drain().status.success());
    assert!(
        !fix.dir.join("store/accounts/secretary").exists(),
        "the closing sweep left the account"
    );
    assert_eq!(
        fix.scripts_log()
            .matches("stripe-api.sh cancel sub_example")
            .count(),
        1,
        "the deletion cancelled a subscription already stopped: {}",
        fix.scripts_log()
    );
}

/// The console's deletion of a card-paying account stops the subscription
/// before the record goes, and an already-canceled one calls no processor.
#[test]
fn deleting_a_card_account_stops_its_subscription() {
    let live = Fix::new("erasure-delete-card");
    live.card_account("secretary", Some("2027-10-02"));
    let out = live.ctl(&["delete", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let log = live.scripts_log();
    assert_eq!(
        log.matches("stripe-api.sh cancel sub_example").count(),
        1,
        "{log}"
    );
    assert!(!live.dir.join("store/accounts/secretary").exists());
    assert!(
        !live
            .dir
            .join("store/tokens/KYR-AAAA-BBBB-CCCC.json")
            .exists(),
        "the token index entry stayed"
    );

    let stopped = Fix::new("erasure-delete-card-canceled");
    stopped.card_account("secretary", Some("2027-10-02"));
    stopped.amend_account("secretary", |account| {
        account["payment"]["stripe"]["status"] = json!("canceled");
    });
    let out = stopped.ctl(&["delete", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !stopped.scripts_log().contains("stripe-api.sh"),
        "a canceled subscription called the processor: {}",
        stopped.scripts_log()
    );
    assert!(!stopped.dir.join("store/accounts/secretary").exists());
}

/// A close intent whose session belongs to another account, or has expired, is
/// refused and changes nothing.
#[test]
fn a_close_intent_without_a_matching_live_session_is_refused() {
    let fix = Fix::new("erasure-forged-session");
    approved_paid(&fix, "secretary", "cash");

    // A live session for another account. The session record names a different
    // username, which is enough for the verifier even if that account is absent.
    let other = fix.open_session("treasurer");
    fix.file_close_with_session("secretary", Fix::session_id(&other));
    assert!(fix.drain().status.success());
    assert_eq!(fix.account("secretary")["state"], json!("active"));
    assert!(
        !fix.dir
            .join("store/accounts/secretary/requests.jsonl")
            .exists(),
        "a refused intent wrote a request line"
    );
    let journal = fix.journal();
    assert!(journal.contains("\"outcome\":\"refused\""), "{journal}");
    assert!(journal.contains("belongs to"), "{journal}");

    // A session for the right account, expired.
    let cookie = fix.open_session("secretary");
    fix.expire_session(&cookie);
    fix.file_close_with_session("secretary", Fix::session_id(&cookie));
    assert!(fix.drain().status.success());
    assert_eq!(fix.account("secretary")["state"], json!("active"));
    let journal = fix.journal();
    assert!(journal.contains("\"outcome\":\"refused\""), "{journal}");
    assert!(journal.contains("expired"), "{journal}");

    // A record the handler wrote itself, naming a well-formed token no login
    // ever minted: there is no root-written proof behind it, so it is refused.
    let cookie = fix.open_session("secretary");
    let id = Fix::session_id(&cookie).to_string();
    let path = fix.dir.join("store/sessions").join(format!("{id}.json"));
    let mut record: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    record["proof"] = json!("0".repeat(64));
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let forged_intent = fix.file_close_with_session("secretary", &id);
    assert!(fix.drain().status.success());
    assert_eq!(fix.account("secretary")["state"], json!("active"));
    let journal = fix.journal();
    assert!(
        journal.lines().any(|line| line.contains(&forged_intent)
            && line.contains("refused")
            && line.contains("not one this box minted")),
        "{journal}"
    );
}

/// A name with no account record and no deletion journal line is not an account
/// the service made, so the console refuses rather than printing "deleted".
#[test]
fn the_console_refuses_a_name_with_no_account_and_no_deletion() {
    let fix = Fix::new("erasure-unknown");
    let out = fix.ctl(&["delete", "nobody"]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(
        body(&out).contains("no account for nobody"),
        "{}",
        body(&out)
    );
    assert!(!fix.dir.join("store/holds/nobody.json").exists());
}

/// Once the 90-day hold has run its course, the hold file and the journal lines
/// the deleted account owns go, while a live hold, another account's lines and
/// another applicant's line for the same username stay byte for byte. A retried
/// deletion's failure line is removed with the account's own lines.
#[test]
fn an_expired_hold_and_its_journal_lines_are_released() {
    let fix = Fix::new("erasure-hold-release");
    approved_paid(&fix, "secretary", "cash");
    approved_paid(&fix, "treasurer", "cash");
    fake_delete_user(&fix);
    let application: Value =
        serde_json::from_str(&fix.read("accounts/secretary/application.json")).unwrap();
    let own_token = application["status_token"]
        .as_str()
        .expect("the approved account keeps its application token")
        .to_string();
    assert!(fix.ctl(&["delete", "secretary"]).status.success());
    assert!(fix.ctl(&["delete", "treasurer"]).status.success());
    let hold: Value = serde_json::from_str(&fix.read("holds/secretary.json")).unwrap();
    assert_eq!(hold["token"], own_token.as_str(), "{hold}");

    // Find the account's own deletion id, and the lines it names.
    let journal = fix.journal();
    let delete_id = journal
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|entry| entry["kind"] == "delete" && entry["application"]["username"] == "secretary")
        .and_then(|entry| entry["intent"].as_str().map(str::to_string))
        .expect("the deletion journalled an intent id");

    // A later applicant asks for the still-held name; their line carries another
    // application token. The account's own delete failure carries no username,
    // only the intent id, as the drain's failure lines do.
    const FOREIGN: &str = "0123456789abcdefghjkmnpqrt";
    let foreign = json!({
        "version": 1,
        "at": "2020-01-01T00:00:00Z",
        "intent": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "kind": "approve",
        "release": "test",
        "application": {"username": "secretary", "status_token": FOREIGN},
        "outcome": "applied",
    });
    let failed = json!({
        "version": 1,
        "at": "2020-01-01T00:00:00Z",
        "intent": delete_id,
        "kind": "delete",
        "release": "test",
        "application": {"username": ""},
        "outcome": "failed",
        "note": "delete-user.sh failed",
    });

    // Ninety days pass for one name: its own lines are dated in the past, while
    // the other name's hold and lines keep today's date.
    let aged_hold = json!({
        "username": "secretary",
        "until": "2020-06-01T00:00:00Z",
        "token": own_token,
    });
    std::fs::write(
        fix.dir.join("store/holds/secretary.json"),
        serde_json::to_vec(&aged_hold).unwrap(),
    )
    .unwrap();
    let mut aged = String::new();
    for line in journal.lines() {
        let mut entry: Value = serde_json::from_str(line).unwrap();
        if entry["application"]["username"] == "secretary" {
            entry["at"] = json!("2020-01-01T00:00:00Z");
        }
        aged.push_str(&serde_json::to_string(&entry).unwrap());
        aged.push('\n');
    }
    aged.push_str(&serde_json::to_string(&foreign).unwrap());
    aged.push('\n');
    aged.push_str(&serde_json::to_string(&failed).unwrap());
    aged.push('\n');
    std::fs::write(fix.dir.join("store/journal.jsonl"), &aged).unwrap();

    let kept: Vec<String> = aged
        .lines()
        .filter(|line| {
            let entry: Value = serde_json::from_str(line).unwrap();
            entry["application"]["username"] == "treasurer"
                || entry["application"]["status_token"] == FOREIGN
        })
        .map(str::to_string)
        .collect();
    assert!(!kept.is_empty(), "the fixture has no other account's lines");

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir.join("store/holds/secretary.json").exists(),
        "the expired hold stayed"
    );
    assert!(
        fix.dir.join("store/holds/treasurer.json").exists(),
        "the live hold went"
    );
    let after: Vec<String> = fix.journal().lines().map(str::to_string).collect();
    assert_eq!(after, kept, "a journal line was not kept byte for byte");
    assert!(
        fix.journal().contains(FOREIGN),
        "another applicant's line was removed: {}",
        fix.journal()
    );
    assert!(
        !fix.journal().contains("delete-user.sh failed"),
        "the account's delete failure survived: {}",
        fix.journal()
    );
    assert!(
        fix.journal().ends_with('\n'),
        "the journal lost its newline"
    );
}

/// Releasing `parish` must not take `parish-secretary`'s deletion lines with
/// it: the id after `delete-<username>-` has to be its RFC 3339 creation stamp.
#[test]
fn releasing_a_username_leaves_a_longer_username_alone() {
    let fix = Fix::new("erasure-prefix-hold");
    approved_paid(&fix, "parish", "cash");
    approved_paid(&fix, "parish-secretary", "cash");
    fake_delete_user(&fix);
    assert!(fix.ctl(&["delete", "parish"]).status.success());
    assert!(fix.ctl(&["delete", "parish-secretary"]).status.success());
    let parish_delete = fix
        .journal()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|entry| entry["kind"] == "delete" && entry["application"]["username"] == "parish")
        .and_then(|entry| entry["intent"].as_str().map(str::to_string))
        .expect("parish's deletion id");

    // Ninety days pass for `parish`, and the longer name's deletion line is
    // dated inside that window too, so only the exact-id match can save it.
    std::fs::write(
        fix.dir.join("store/holds/parish.json"),
        br#"{"username":"parish","until":"2020-06-01T00:00:00Z"}"#,
    )
    .unwrap();
    let mut aged = String::new();
    for line in fix.journal().lines() {
        let mut entry: Value = serde_json::from_str(line).unwrap();
        let longer = entry["intent"]
            .as_str()
            .is_some_and(|id| id.starts_with("delete-parish-"));
        if entry["application"]["username"] == "parish" || longer {
            entry["at"] = json!("2020-01-01T00:00:00Z");
        }
        aged.push_str(&serde_json::to_string(&entry).unwrap());
        aged.push('\n');
    }
    std::fs::write(fix.dir.join("store/journal.jsonl"), &aged).unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!fix.dir.join("store/holds/parish.json").exists());
    let after = fix.journal();
    assert!(
        !after.lines().any(|line| {
            serde_json::from_str::<Value>(line).unwrap()["intent"] == parish_delete.as_str()
        }),
        "parish's own deletion line stayed: {after}"
    );
    assert!(
        after.contains("delete-parish-secretary-"),
        "the longer name's deletion line was removed: {after}"
    );
}

/// A hold written before the token was recorded keeps its token-bearing lines
/// where the account copy is gone, which is the exception the notice names, and
/// still releases the account-scoped lines it can identify.
#[test]
fn a_tokenless_hold_keeps_token_bearing_lines_where_the_copy_is_gone() {
    let fix = Fix::new("erasure-hold-no-token");
    approved_paid(&fix, "secretary", "cash");
    fake_delete_user(&fix);
    let application: Value =
        serde_json::from_str(&fix.read("accounts/secretary/application.json")).unwrap();
    let own_token = application["status_token"].as_str().unwrap().to_string();
    assert!(fix.ctl(&["delete", "secretary"]).status.success());
    let delete_id = fix
        .journal()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|entry| entry["kind"] == "delete" && entry["application"]["username"] == "secretary")
        .and_then(|entry| entry["intent"].as_str().map(str::to_string))
        .expect("the deletion journalled an intent id");

    // A build before this release wrote no token, and the account copy has gone
    // with the deletion.
    std::fs::write(
        fix.dir.join("store/holds/secretary.json"),
        br#"{"username":"secretary","until":"2020-06-01T00:00:00Z"}"#,
    )
    .unwrap();
    let failed = json!({
        "version": 1,
        "at": "2020-01-01T00:00:00Z",
        "intent": delete_id,
        "kind": "delete",
        "release": "test",
        "application": {"username": ""},
        "outcome": "failed",
        "note": "delete-user.sh failed",
    });
    let mut aged = String::new();
    for line in fix.journal().lines() {
        let mut entry: Value = serde_json::from_str(line).unwrap();
        if entry["application"]["username"] == "secretary" {
            entry["at"] = json!("2020-01-01T00:00:00Z");
        }
        aged.push_str(&serde_json::to_string(&entry).unwrap());
        aged.push('\n');
    }
    aged.push_str(&serde_json::to_string(&failed).unwrap());
    aged.push('\n');
    std::fs::write(fix.dir.join("store/journal.jsonl"), &aged).unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!fix.dir.join("store/holds/secretary.json").exists());
    let after = fix.journal();
    assert!(
        after.lines().any(|line| {
            serde_json::from_str::<Value>(line).unwrap()["application"]["status_token"]
                == own_token.as_str()
        }),
        "the token-bearing line went although the copy is gone: {after}"
    );
    assert!(
        !after.contains("delete-user.sh failed"),
        "the account's delete failure survived: {after}"
    );
    assert!(
        !after.contains("about seven months"),
        "the account-scoped erasure answer survived: {after}"
    );
}
