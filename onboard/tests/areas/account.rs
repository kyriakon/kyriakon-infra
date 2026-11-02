//! The account page's actions: each one files an intent the drain carries out,
//! and the drain owns every write an action finally makes. The handler's half is
//! in `src/responder/tests.rs`; these are the effects.

use crate::common::*;

/// One check's script stub: it logs its name and arguments, so a test sees the
/// call the transition made and in what order.
fn logging_script(fix: &Fix, name: &str) -> String {
    let log = fix.path("scripts.log");
    fix.script(name, &format!("#!/bin/sh\necho \"{name} $*\" >> '{log}'\n"));
    log
}

/// A real PGP public key block from the key-check fixtures, for a replacement.
fn replacement_key() -> String {
    std::fs::read_to_string(format!(
        "{}/../docs/planning/prototypes/keygen-spike/fixtures/gpg-aead.asc",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// A throwaway signing keypair in a temporary GNUPGHOME, with its public key and
/// a detached armored signature over `payload`. The private key never enters the
/// repository, and the homedir is removed with the temp directory.
fn signing_key(payload: &str) -> (String, String) {
    // A short path on purpose: gpg's agent socket lives under the homedir, and a
    // UNIX socket path is bounded, so the per-user temp directory's own long
    // path fails to connect the agent before key generation begins.
    let home = std::path::PathBuf::from("/tmp").join(format!("ks{}", ulid()));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = "kyriakon page <page@example.invalid>";
    let gpg = |args: &[&str]| {
        std::process::Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(args)
            .output()
            .expect("gpg is on PATH")
    };
    let gen = gpg(&[
        "--batch",
        "--no-tty",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--quick-generate-key",
        uid,
        "rsa2048",
        "sign",
        "0",
    ]);
    assert!(
        gen.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&gen.stderr)
    );
    let export = gpg(&["--batch", "--no-tty", "--armor", "--export", uid]);
    assert!(export.status.success(), "the key could not be exported");
    let public = String::from_utf8(export.stdout).unwrap();

    let message = home.join("payload");
    std::fs::write(&message, payload).unwrap();
    let sign = gpg(&[
        "--batch",
        "--no-tty",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--armor",
        "--detach-sign",
        message.to_str().unwrap(),
    ]);
    assert!(
        sign.status.success(),
        "signing failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );
    let signature = std::fs::read_to_string(home.join("payload.asc")).expect("the signature file");
    (public, signature)
}

/// A password change files one intent and the drain replaces the stored hash
/// with the new one, so the old password stops authenticating. A hash this build
/// did not make is refused and never reaches `usermod`.
#[test]
fn a_password_change_replaces_the_stored_hash_and_refuses_a_bad_one() {
    let fix = Fix::new("account-password");
    fix.page_account("alice", json!({}));
    let log = logging_script(&fix, "set-mail-password.sh");
    let hash = kyriakon_onboard::password::make("a long new password").unwrap();
    assert!(kyriakon_onboard::password::matches(
        "a long new password",
        &hash
    ));
    assert!(!kyriakon_onboard::password::matches("old password", &hash));

    fix.file_page_action("change-password", "alice", json!({"hash": hash}));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "the applied intent is removed");
    let written = std::fs::read_to_string(&log).unwrap();
    assert!(
        written.contains(&format!("set-mail-password.sh alice {hash}")),
        "the hash the handler made is what usermod is given: {written}"
    );
    assert!(fix.journal().contains("\"outcome\":\"applied\""));

    // A line `usermod -p` would take but this build did not make is refused
    // before the script runs.
    fix.file_page_action("change-password", "alice", json!({"hash": "not a hash"}));
    assert!(fix.drain().status.success());
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        written,
        "a malformed hash reached usermod"
    );
    assert!(fix.journal().contains("\"outcome\":\"refused\""));
    assert!(fix.intents().is_empty());
}

/// One upload key serves sftp and git. Adding it writes the key the builder
/// reads and rebuilds the member; removing it takes both the store's copy and
/// the authorized_keys line away, and a key the account does not carry is
/// refused.
#[test]
fn an_upload_key_is_added_and_removed_for_both_sessions() {
    let fix = Fix::new("account-upload-key");
    fix.page_account("alice", json!({}));
    logging_script(&fix, "provision-member.sh");
    logging_script(&fix, "cron-apply.sh");
    logging_script(&fix, "remove-upload-key.sh");
    let fingerprint = kyriakon_onboard::keycheck::openssh_fingerprint(UPLOAD_KEY).unwrap();

    fix.file_page_action(
        "upload-key",
        "alice",
        json!({"action": "add", "material": UPLOAD_KEY}),
    );
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.read("keys/alice.pub").trim(),
        UPLOAD_KEY,
        "the key the builder reads is written"
    );
    assert!(fix.scripts_log().contains("provision-member.sh alice"));
    assert!(
        fix.scripts_log().contains("cron-apply.sh --web"),
        "the new vhosts are indexed and the daemons reloaded"
    );
    let account = fix.account("alice");
    assert_eq!(account["upload_keys"][0]["fingerprint"], json!(fingerprint));
    assert!(
        account["upload_keys"][0]["added_at"].is_string(),
        "the page shows the day the key was added: {account}"
    );

    // A key that is not on the account is refused and nothing is removed.
    fix.file_page_action(
        "upload-key",
        "alice",
        json!({"action": "remove", "fingerprint": "SHA256:not-this-one"}),
    );
    assert!(fix.drain().status.success());
    assert!(
        !fix.read("keys/alice.pub").is_empty(),
        "the key is still there"
    );
    assert!(fix.journal().contains("\"outcome\":\"refused\""));

    fix.file_page_action(
        "upload-key",
        "alice",
        json!({"action": "remove", "fingerprint": fingerprint}),
    );
    assert!(fix.drain().status.success());
    assert!(
        fix.read("keys/alice.pub").is_empty(),
        "the store's copy is gone"
    );
    assert!(fix.scripts_log().contains("remove-upload-key.sh alice"));
    assert!(
        fix.account("alice")
            .get("upload_keys")
            .is_none_or(Value::is_null),
        "the page no longer lists a key"
    );
}

/// The contact and recovery address is changed and cleared from the page, and
/// an address the form could not have accepted is refused by the drain too.
#[test]
fn the_contact_address_is_set_and_cleared_by_the_page() {
    let fix = Fix::new("account-address");
    fix.page_account("alice", json!({}));

    fix.file_page_action(
        "outside-address",
        "alice",
        json!({"address": "alice@example.invalid"}),
    );
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.account("alice")["outside_address"],
        json!("alice@example.invalid")
    );

    fix.file_page_action(
        "outside-address",
        "alice",
        json!({"address": "not an address"}),
    );
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.account("alice")["outside_address"],
        json!("alice@example.invalid"),
        "a refused address changes nothing"
    );

    fix.file_page_action("outside-address", "alice", json!({"address": ""}));
    assert!(fix.drain().status.success());
    assert!(
        fix.account("alice")
            .get("outside_address")
            .is_none_or(Value::is_null),
        "an empty field clears the address"
    );
}

/// Turning one lane off removes that lane's generated include and reloads once,
/// and leaves the other lane alone. Turning it back on regenerates it.
#[test]
fn turning_http_off_removes_only_the_web_include() {
    let fix = Fix::new("account-serving");
    fix.page_account(
        "alice",
        json!({"site_served": true, "capsule_served": true}),
    );
    logging_script(&fix, "provision-member-web.sh");
    logging_script(&fix, "provision-member-capsule.sh");
    logging_script(&fix, "cron-apply.sh");

    fix.file_page_action("serving", "alice", json!({"http": false, "gemini": true}));
    assert!(fix.drain().status.success());
    assert!(fix
        .scripts_log()
        .contains("provision-member-web.sh --remove alice"));
    assert!(
        !fix.scripts_log().contains("provision-member-capsule.sh"),
        "the lane that did not change is not touched: {}",
        fix.scripts_log()
    );
    assert!(fix.scripts_log().contains("cron-apply.sh --web"));
    let account = fix.account("alice");
    assert_eq!(account["site_served"], json!(false));
    assert_eq!(account["capsule_served"], json!(true));

    fix.file_page_action("serving", "alice", json!({"http": true, "gemini": true}));
    assert!(fix.drain().status.success());
    assert!(fix.scripts_log().contains("provision-member-web.sh alice"));
    assert_eq!(fix.account("alice")["site_served"], json!(true));
    assert_eq!(fix.account("alice")["capsule_served"], json!(true));
}

/// Stopping the yearly renewal sets `cancel_at_period_end` through the one API
/// write, and a prepaid or free account, which has no subscription, is refused.
#[test]
fn stopping_a_card_renewal_sets_the_flag_and_a_prepaid_account_is_refused() {
    let fix = Fix::new("account-renewal");
    fix.card_account("alice", Some("2027-10-02"));
    logging_script(&fix, "stripe-api.sh");
    fix.file_page_action("cancel-renewal", "alice", json!({}));
    assert!(fix.drain().status.success());
    assert!(
        fix.scripts_log()
            .contains("stripe-api.sh cancel sub_example"),
        "{}",
        fix.scripts_log()
    );
    assert_eq!(
        fix.account("alice")["payment"]["stripe"]["cancel_at_period_end"],
        json!(true)
    );
    assert_eq!(
        fix.account("alice")["payment"]["paid_until"],
        json!("2027-10-02"),
        "the paid period is not shortened"
    );

    let fix = Fix::new("account-renewal-prepaid");
    fix.page_account("alice", json!({}));
    logging_script(&fix, "stripe-api.sh");
    fix.file_page_action("cancel-renewal", "alice", json!({}));
    assert!(fix.drain().status.success());
    assert!(
        !fix.scripts_log().contains("stripe-api.sh"),
        "a prepaid account calls no processor"
    );
    assert!(fix.journal().contains("\"outcome\":\"refused\""));
}

/// A replacement not signed by the current key waits, warns every address the
/// account holds, can be cancelled, and applies when its window closes.
#[test]
fn a_mail_key_replacement_waits_out_its_window_and_can_be_cancelled() {
    let fix = Fix::new("account-rotation-pending");
    fix.page_account(
        "alice",
        json!({"mail_key": "AAAA", "outside_address": "alice@example.invalid"}),
    );
    let key = replacement_key();
    let fingerprint = kyriakon_onboard::keycheck::pgp_fingerprint(&key).unwrap();

    fix.file_page_action(
        "mail-key",
        "alice",
        json!({"action": "replace", "material": key, "signature": ""}),
    );
    assert!(fix.drain().status.success());
    let account = fix.account("alice");
    assert_eq!(account["rotation"]["fingerprint"], json!(fingerprint));
    assert_eq!(
        account["mail_key"],
        json!("AAAA"),
        "the key in use does not change before the window closes"
    );
    assert!(
        account["rotation"]["applies_at"].as_str().unwrap()
            > kyriakon_onboard::util::filed_at().as_str(),
        "the window is ahead: {account}"
    );
    let sent = fix.sent();
    assert!(
        sent.contains("alice@kyriakon.net") && sent.contains("alice@example.invalid"),
        "the warning goes to every address held: {sent}"
    );
    assert!(sent.contains("Confirm the replacement of your mail key"));

    // The page cancels it inside the window.
    fix.file_page_action("mail-key", "alice", json!({"action": "cancel"}));
    assert!(fix.drain().status.success());
    assert!(
        fix.account("alice")
            .get("rotation")
            .is_none_or(Value::is_null),
        "the pending replacement is cleared"
    );
    assert!(fix.sent().contains("was cancelled"));

    // A fresh request applies when its 72 hours end, on the next pass.
    fix.file_page_action(
        "mail-key",
        "alice",
        json!({"action": "replace", "material": key, "signature": ""}),
    );
    assert!(fix.drain().status.success());
    fix.amend_account("alice", |account| {
        account["rotation"]["applies_at"] = json!("2020-01-01T00:00:00Z");
    });
    assert!(fix.drain().status.success());
    let account = fix.account("alice");
    assert_eq!(account["mail_key"], json!(fingerprint));
    assert!(
        account.get("rotation").is_none_or(Value::is_null),
        "the window is spent"
    );
    assert_eq!(
        std::fs::read_to_string(fix.dir.join("keyring/alice.asc"))
            .unwrap()
            .trim(),
        key.trim(),
        "the keyring file delivery reads is the new key"
    );
}

/// A replacement signed by the current key applies at once; one signed by a key
/// that is not the current one is refused and starts no window.
#[test]
fn a_mail_key_replacement_signed_by_the_current_key_applies_at_once() {
    let fix = Fix::new("account-rotation-signed");
    let key = replacement_key();
    let fingerprint = kyriakon_onboard::keycheck::pgp_fingerprint(&key).unwrap();

    let (public, signature) = signing_key(&fingerprint);
    let current = kyriakon_onboard::keycheck::pgp_fingerprint(&public).unwrap();
    fix.page_account("alice", json!({"mail_key": current}));
    fix.mail_key("alice", &public);

    fix.file_page_action(
        "mail-key",
        "alice",
        json!({"action": "replace", "material": key, "signature": signature}),
    );
    assert!(fix.drain().status.success());
    let account = fix.account("alice");
    assert_eq!(
        account["mail_key"],
        json!(fingerprint),
        "intents: {:?}\njournal: {}",
        fix.intents(),
        fix.journal()
    );
    assert!(
        account.get("rotation").is_none_or(Value::is_null),
        "a signed request skips the window: {account}"
    );
    assert_eq!(
        std::fs::read_to_string(fix.dir.join("keyring/alice.asc"))
            .unwrap()
            .trim(),
        key.trim()
    );

    // A signature made with a different key is not the current key's, so
    // nothing changes.
    let fix = Fix::new("account-rotation-forged");
    let (public, _) = signing_key("another fingerprint");
    let current = kyriakon_onboard::keycheck::pgp_fingerprint(&public).unwrap();
    fix.page_account("alice", json!({"mail_key": current}));
    fix.mail_key("alice", &public);
    let (_, wrong) = signing_key("a different fingerprint");
    fix.file_page_action(
        "mail-key",
        "alice",
        json!({"action": "replace", "material": key, "signature": wrong}),
    );
    assert!(fix.drain().status.success());
    let account = fix.account("alice");
    assert_eq!(account["mail_key"], json!(current));
    assert!(
        account.get("rotation").is_none_or(Value::is_null),
        "a signature that does not verify starts no window: {account}"
    );
    assert!(fix.journal().contains("\"outcome\":\"refused\""));
}
