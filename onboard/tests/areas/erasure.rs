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

    // The name is held, and the answer names the four surviving facts.
    // The hold is ninety days out; the seconds differ by the time between the
    // deletion and this check, so the date is what is compared.
    let hold: Value = serde_json::from_str(&fix.read("holds/secretary.json")).unwrap();
    assert_eq!(hold["username"], json!("secretary"));
    let until = hold["until"].as_str().unwrap();
    assert!(
        until.starts_with(&kyriakon_onboard::util::date_after_days(90)),
        "{until}"
    );
    let sent = fix.sent();
    assert!(sent.contains("being erased"), "{sent}");
    assert!(sent.contains("about seven months"), "{sent}");
    assert!(sent.contains("ledger"), "{sent}");
    assert!(sent.contains("no username"), "{sent}");
    assert!(sent.contains("90 days"), "{sent}");
    assert!(
        sent.contains("GBP 20.00"),
        "the refund fact is missing: {sent}"
    );
    let journal = fix.journal();
    assert!(journal.contains("\"kind\":\"delete\""), "{journal}");
    assert!(journal.contains("\"outcome\":\"applied\""), "{journal}");
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
        json!(kyriakon_onboard::util::date_after_days(7)),
        "{account}"
    );
    assert!(
        !page.scripts_log().contains("delete-user.sh"),
        "the page deleted inside the seven-day window: {}",
        page.scripts_log()
    );

    // The window ends.
    let mut account = account;
    account["closing_until"] = json!(kyriakon_onboard::util::date_after_days(-1));
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
}
