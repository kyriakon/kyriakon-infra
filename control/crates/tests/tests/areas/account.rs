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

/// A real PGP public key block from the key-check fixtures, for a replacement:
/// the generator's own clean key, since a replacement must pass the same check
/// approval does.
fn replacement_key() -> String {
    let path =
        repo_root().join("docs/planning/prototypes/keygen-spike/fixtures/generated-clean.asc");
    std::fs::read_to_string(path).unwrap()
}

/// A fixture by file name, for a key whose verdict is the point of the test.
fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        repo_root()
            .join("docs/planning/prototypes/keygen-spike/fixtures")
            .join(name),
    )
    .unwrap()
}

/// A throwaway signing keypair in a temporary GNUPGHOME, with its public key, a
/// detached armored signature over `payload`, and `payload` as a clearsigned
/// message. The private key never enters the repository, and the homedir is
/// removed with the temp directory.
fn signing_key(payload: &str) -> (String, String, String) {
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
        "--output",
        home.join("payload.sig").to_str().unwrap(),
        "--detach-sign",
        message.to_str().unwrap(),
    ]);
    assert!(
        sign.status.success(),
        "signing failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );
    let clear = gpg(&[
        "--batch",
        "--no-tty",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--output",
        home.join("payload.signed").to_str().unwrap(),
        "--clearsign",
        message.to_str().unwrap(),
    ]);
    assert!(
        clear.status.success(),
        "clearsigning failed: {}",
        String::from_utf8_lossy(&clear.stderr)
    );
    let signature = std::fs::read_to_string(home.join("payload.sig")).expect("the signature file");
    let clearsigned =
        std::fs::read_to_string(home.join("payload.signed")).expect("the clearsigned message");
    (public, signature, clearsigned)
}

/// A password change files the plaintext and the drain hashes it, so the stored
/// hash is one the member typed. An intent carrying a handler-made hash is the
/// old shape and is refused before the script runs.
#[test]
fn a_password_change_hashes_the_plaintext_and_refuses_a_hash() {
    let fix = Fix::new("account-password");
    fix.page_account("alice", json!({}));
    let log = logging_script(&fix, "set-mail-password.sh");

    fix.file_page_action(
        "change-password",
        "alice",
        json!({"password": "a long new password"}),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "the applied intent is removed");
    let written = std::fs::read_to_string(&log).unwrap();
    let hash = written
        .strip_prefix("set-mail-password.sh alice ")
        .unwrap_or("")
        .trim();
    assert!(
        kyriakon_control_core::account::password::is_hash(hash),
        "{written}"
    );
    assert!(kyriakon_control_core::account::password::matches(
        "a long new password",
        hash
    ));
    assert!(!written.contains("a long new password"), "{written}");
    assert!(fix.journal().contains("\"outcome\":\"applied\""));

    // The old shape: a hash the handler chose, even a valid one, is refused.
    let chosen =
        kyriakon_control_core::account::password::make("a password the member never typed")
            .unwrap();
    fix.file_page_action("change-password", "alice", json!({"hash": chosen}));
    assert!(fix.drain().status.success());
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        written,
        "a handler-made hash reached usermod"
    );
    assert!(
        fix.journal()
            .contains("the intent carries a hash rather than a plaintext"),
        "{}",
        fix.journal()
    );
    assert!(fix.intents().is_empty(), "the refused intent is settled");
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
    let fingerprint =
        kyriakon_control_core::mail::keycheck::openssh_fingerprint(UPLOAD_KEY).unwrap();

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

/// The page session is a file the handler writes, so it cannot prove a name
/// outside the charset. Without the drain's own shape check, a forged session
/// naming `alice/../bob` reaches bob's record through the store's path join.
#[test]
fn a_forged_session_username_is_refused_and_writes_nothing() {
    let fix = Fix::new("account-forged-name");
    fix.page_account("bob", json!({}));
    let cookie = fix.open_session("alice");
    let id = Fix::session_id(&cookie).to_string();
    let path = fix.dir.join("store/sessions").join(format!("{id}.json"));
    let mut session: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    session["username"] = json!("alice/../bob");
    std::fs::write(&path, serde_json::to_vec_pretty(&session).unwrap()).unwrap();

    let before = fix.read("accounts/bob/account.json");
    let intent = ulid();
    fix.write_intent(
        &intent,
        &json!({
            "id": intent,
            "kind": "outside-address",
            "filed_at": "2026-10-02T09:00:00Z",
            "username": "alice/../bob",
            "session": id,
            "address": "evil@example.invalid",
        }),
    );
    assert!(fix.drain().status.success());
    assert!(fix.intents().is_empty(), "the refused intent is settled");
    assert!(fix.journal().contains("\"outcome\":\"refused\""));
    assert_eq!(
        fix.read("accounts/bob/account.json"),
        before,
        "nothing reached the record the traversal names"
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

/// The record can say nothing about a lane while the lane serves, because
/// provision-member.sh wrote it. The save compares the effective value, so a
/// lane that is on and submitted on is not reprovisioned, and a lane already
/// recorded off and submitted off is not removed again.
#[test]
fn saving_a_serving_form_touches_no_lane_that_did_not_change() {
    let fix = Fix::new("account-serving-saved");
    fix.page_account(
        "alice",
        json!({
            "capsule_served": false,
            "upload_keys": [{"fingerprint": "SHA256:example", "added_at": "2026-10-02T09:00:00Z"}],
        }),
    );
    logging_script(&fix, "provision-member-web.sh");
    logging_script(&fix, "provision-member-capsule.sh");
    logging_script(&fix, "cron-apply.sh");

    fix.file_page_action("serving", "alice", json!({"http": true, "gemini": false}));
    assert!(fix.drain().status.success());
    assert!(
        !fix.scripts_log().contains("provision-member"),
        "no lane changed: {}",
        fix.scripts_log()
    );
    assert!(
        !fix.scripts_log().contains("cron-apply.sh"),
        "nothing changed, so there is nothing to reload: {}",
        fix.scripts_log()
    );
    let account = fix.account("alice");
    assert_eq!(account["site_served"], json!(true));
    assert_eq!(account["capsule_served"], json!(false));
}

/// Adding an upload key builds the member again, and provision-member.sh writes
/// both lanes. A lane the member turned off is removed again, so replacing a key
/// does not turn serving back on.
#[test]
fn adding_an_upload_key_keeps_a_lane_the_member_turned_off_off() {
    let fix = Fix::new("account-upload-key-serving");
    fix.page_account(
        "alice",
        json!({"site_served": false, "capsule_served": true}),
    );
    let log = logging_script(&fix, "provision-member.sh");
    fix.script(
        "provision-member-web.sh",
        &format!("#!/bin/sh\necho \"provision-member-web.sh $*\" >> '{log}'\n"),
    );
    fix.script(
        "provision-member-capsule.sh",
        &format!("#!/bin/sh\necho \"provision-member-capsule.sh $*\" >> '{log}'\n"),
    );
    fix.script(
        "cron-apply.sh",
        &format!("#!/bin/sh\necho \"cron-apply.sh $*\" >> '{log}'\n"),
    );

    fix.file_page_action(
        "upload-key",
        "alice",
        json!({"action": "add", "material": UPLOAD_KEY}),
    );
    assert!(fix.drain().status.success());
    let log = fix.scripts_log();
    assert!(log.contains("provision-member.sh alice"), "{log}");
    assert!(
        log.contains("provision-member-web.sh --remove alice"),
        "the lane the member turned off stays off: {log}"
    );
    assert!(
        !log.contains("provision-member-capsule.sh --remove"),
        "the lane that is on is left alone: {log}"
    );
    let provisioned = log.find("provision-member.sh alice").unwrap();
    let removed = log.find("provision-member-web.sh --remove alice").unwrap();
    let reloaded = log.find("cron-apply.sh --web").unwrap();
    assert!(
        provisioned < removed && removed < reloaded,
        "the removal comes after the rebuild and before the index pass: {log}"
    );
    let account = fix.account("alice");
    assert_eq!(account["site_served"], json!(false));
    assert_eq!(account["capsule_served"], json!(true));
}

/// A lane the record says nothing about is on once the account holds an upload
/// key, because provision-member.sh wrote it. Adding the first key records both
/// lanes on and removes neither, and a key already on the account with an
/// unrecorded lane leaves it on.
#[test]
fn an_unrecorded_lane_with_an_upload_key_is_on() {
    let fix = Fix::new("account-upload-key-unrecorded");
    fix.page_account("alice", json!({}));
    let log = logging_script(&fix, "provision-member.sh");
    for script in [
        "provision-member-web.sh",
        "provision-member-capsule.sh",
        "cron-apply.sh",
    ] {
        fix.script(
            script,
            &format!("#!/bin/sh\necho \"{script} $*\" >> '{log}'\n"),
        );
    }

    fix.file_page_action(
        "upload-key",
        "alice",
        json!({"action": "add", "material": UPLOAD_KEY}),
    );
    assert!(fix.drain().status.success());
    let log = fix.scripts_log();
    assert!(log.contains("provision-member.sh alice"), "{log}");
    assert!(!log.contains("--remove"), "no lane was recorded off: {log}");
    let account = fix.account("alice");
    assert_eq!(account["site_served"], json!(true), "{account}");
    assert_eq!(account["capsule_served"], json!(true), "{account}");

    // A second key finds an unrecorded lane that already serves: nothing is
    // removed, and the record keeps saying on.
    fix.amend_account("alice", |account| {
        account["site_served"] = Value::Null;
    });
    let before = fix.scripts_log().len();
    fix.file_page_action(
        "upload-key",
        "alice",
        json!({"action": "add", "material": UPLOAD_KEY}),
    );
    assert!(fix.drain().status.success());
    let log = &fix.scripts_log()[before..];
    assert!(
        !log.contains("--remove"),
        "the unrecorded lane stays on: {log}"
    );
    assert_eq!(
        fix.account("alice")["site_served"],
        json!(true),
        "{:?}",
        fix.account("alice")
    );
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

/// A card-paying group's site owner stops the body's renewal from the account
/// page: the flag is written on the group, not on the mailbox, and another
/// mailbox in the body is refused.
#[test]
fn a_group_site_owner_stops_the_groups_renewal() {
    let fix = Fix::new("account-group-renewal");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());
    let path = fix.dir.join("store/groups/parish.example/group.json");
    let mut group: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    group["payment"]["rail"] = json!("card");
    group["payment"]["stripe"] = json!({
        "subscription": SUBSCRIPTION,
        "customer": "cus_example",
        "status": "active"
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&group).unwrap()).unwrap();

    fix.file_page_action("cancel-renewal", "parish-secretary", json!({}));
    assert!(fix.drain().status.success());
    let log = fix.scripts_log();
    assert_eq!(
        log.matches("stripe-api.sh cancel sub_example").count(),
        1,
        "{log}"
    );
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(
        group["payment"]["stripe"]["cancel_at_period_end"],
        json!(true),
        "{group}"
    );
    assert!(
        fix.account("parish-secretary")["payment"].is_null(),
        "the flag went on the mailbox"
    );

    // The body names another site owner: this mailbox may not stop its card.
    let mut group = group;
    group["site_owner"] = json!("parish-warden");
    group["payment"]["stripe"]["cancel_at_period_end"] = json!(false);
    std::fs::write(&path, serde_json::to_vec_pretty(&group).unwrap()).unwrap();
    fix.file_page_action("cancel-renewal", "parish-secretary", json!({}));
    assert!(fix.drain().status.success());
    assert!(
        fix.journal().contains("only the group's site owner"),
        "{}",
        fix.journal()
    );
    assert_eq!(
        fix.scripts_log()
            .matches("stripe-api.sh cancel sub_example")
            .count(),
        1,
        "a non-owner cancelled the group: {}",
        fix.scripts_log()
    );
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
    let fingerprint = kyriakon_control_core::mail::keycheck::pgp_fingerprint(&key).unwrap();

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
            > kyriakon_control_core::util::filed_at().as_str(),
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
    // A new request for the same key warns again: the record deduplicates on the
    // request, so only a retry of one request stays quiet.
    assert_eq!(
        fix.sent()
            .matches("Confirm the replacement of your mail key")
            .count(),
        4,
        "two requests, two addresses each: {}",
        fix.sent()
    );
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
    let fingerprint = kyriakon_control_core::mail::keycheck::pgp_fingerprint(&key).unwrap();

    let (public, signature, _) = signing_key(&fingerprint);
    let current = kyriakon_control_core::mail::keycheck::pgp_fingerprint(&public).unwrap();
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
    // The operator hears about the rotation when it applies, so they publish
    // keys/<username>.asc before check-keyring-drift.sh's seven-day window ends.
    let sent = fix.sent();
    assert!(
        sent.contains("kyriakon: keyring: mail key rotated"),
        "{sent}"
    );
    assert!(
        sent.contains("alice") && sent.contains(&fingerprint),
        "the alert names the username and fingerprint: {sent}"
    );
    assert!(sent.contains("keys/alice.asc"), "{sent}");

    // A signature made with a different key is not the current key's, so
    // nothing changes.
    let fix = Fix::new("account-rotation-forged");
    let (public, _, _) = signing_key("another fingerprint");
    let current = kyriakon_control_core::mail::keycheck::pgp_fingerprint(&public).unwrap();
    fix.page_account("alice", json!({"mail_key": current}));
    fix.mail_key("alice", &public);
    let (_, wrong, _) = signing_key("a different fingerprint");
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

/// A replacement carrying a verdict other than "works" is refused, so a key
/// that would stop delivery cannot enter the keyring from `/account`. The key
/// in use and the keyring file stay as they were.
#[test]
fn a_mail_key_replacement_refuses_an_expiring_or_aead_key() {
    let fix = Fix::new("account-rotation-refused");
    let clean = replacement_key();
    let current = kyriakon_control_core::mail::keycheck::pgp_fingerprint(&clean).unwrap();
    fix.page_account("alice", json!({"mail_key": current}));
    fix.mail_key("alice", &clean);
    let before = std::fs::read_to_string(fix.dir.join("keyring/alice.asc")).unwrap();

    for (name, key) in [
        ("expiring", fixture("gpg-future-expiry.asc")),
        ("AEAD", fixture("gpg-aead.asc")),
    ] {
        fix.file_page_action(
            "mail-key",
            "alice",
            json!({"action": "replace", "material": key, "signature": ""}),
        );
        assert!(fix.drain().status.success());
        let account = fix.account("alice");
        assert_eq!(account["mail_key"], json!(current), "{name}: {account}");
        assert!(
            account.get("rotation").is_none_or(Value::is_null),
            "{name}: a refused key starts no window: {account}"
        );
        assert!(
            fix.journal().contains("\"outcome\":\"refused\"")
                && fix.journal().contains("the mail key: The key"),
            "{name}: {}",
            fix.journal()
        );
        assert!(
            !fix.journal().contains("the signature does not verify"),
            "{name}: the verdict is checked before the signature: {}",
            fix.journal()
        );
    }

    assert_eq!(
        std::fs::read_to_string(fix.dir.join("keyring/alice.asc")).unwrap(),
        before,
        "the keyring file is unchanged"
    );
}

/// The mail-key route: a detached signature or a clearsigned message over the
/// account's own platform address verifies against the keyring entry, prints the
/// signing key's fingerprint, and writes no request line.
#[test]
fn request_verify_accepts_the_keyring_key_over_the_accounts_own_address() {
    let fix = Fix::new("request-verify-key");
    let message = "From: Alice <alice@kyriakon.net>\nTo: admin@kyriakon.net\n\
                   Subject: my data\n\nPlease send me a copy.\n";
    let (public, detached, clearsigned) = signing_key(message);
    let fingerprint = kyriakon_control_core::mail::keycheck::pgp_fingerprint(&public).unwrap();
    fix.page_account("alice", json!({}));
    fix.mail_key("alice", &public);

    let message_path = fix.path("message.eml");
    std::fs::write(&message_path, message).unwrap();
    let signature_path = fix.path("message.asc");
    std::fs::write(&signature_path, &detached).unwrap();
    let out = fix.ctl(&[
        "request",
        "verify",
        "--username",
        "alice",
        "--message",
        &message_path,
        "--signature",
        &signature_path,
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&fingerprint),
        "the verified fingerprint is printed: {}",
        body(&out)
    );

    // The clearsigned form carries its own signature and needs no flag.
    let clearsigned_path = fix.path("message-signed.eml");
    std::fs::write(&clearsigned_path, &clearsigned).unwrap();
    let out = fix.ctl(&[
        "request",
        "verify",
        "--username",
        "alice",
        "--message",
        &clearsigned_path,
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains(&fingerprint));

    // A group mailbox's own address is at the group's domain, not kyriakon.net.
    let group_message = "From: alice@example.org\n\nPlease send me a copy.\n";
    let (public, detached, _) = signing_key(group_message);
    fix.page_account("alice", json!({"group": "example.org"}));
    fix.mail_key("alice", &public);
    std::fs::write(&message_path, group_message).unwrap();
    std::fs::write(&signature_path, &detached).unwrap();
    let out = fix.ctl(&[
        "request",
        "verify",
        "--username",
        "alice",
        "--message",
        &message_path,
        "--signature",
        &signature_path,
    ]);
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        !fix.dir.join("store/accounts/alice/requests.jsonl").exists(),
        "verification wrote a request line"
    );
}

/// The check refuses a missing keyring entry, a signature by another key, a
/// message from the outside contact address, and one from another domain.
#[test]
fn request_verify_refuses_a_wrong_signer_from_or_missing_keyring_entry() {
    let fix = Fix::new("request-verify-refusals");
    let own = "From: alice@kyriakon.net\n\nPlease send me a copy.\n";
    let (keyring, keyring_signature, _) = signing_key(own);
    fix.page_account("alice", json!({"outside_address": "alice@example.invalid"}));
    let message_path = fix.path("message.eml");
    std::fs::write(&message_path, own).unwrap();
    let signature_path = fix.path("signature.asc");
    std::fs::write(&signature_path, &keyring_signature).unwrap();

    let verify = [
        "request",
        "verify",
        "--username",
        "alice",
        "--message",
        &message_path,
        "--signature",
        &signature_path,
    ];
    let out = fix.ctl(&verify);
    assert!(!out.status.success());
    assert!(body(&out).contains("holds no key"), "{}", body(&out));

    fix.mail_key("alice", &keyring);

    // A signature made with another key over the same text.
    let (_, wrong_signature, _) = signing_key(own);
    std::fs::write(&signature_path, &wrong_signature).unwrap();
    let out = fix.ctl(&verify);
    assert!(!out.status.success());
    assert!(body(&out).contains("does not verify"), "{}", body(&out));

    // The account's outside contact address, correctly signed.
    let outside = "From: alice@example.invalid\n\nPlease send me a copy.\n";
    let (_, outside_signature, _) = signing_key(outside);
    std::fs::write(&message_path, outside).unwrap();
    std::fs::write(&signature_path, &outside_signature).unwrap();
    let out = fix.ctl(&verify);
    assert!(!out.status.success());
    let refusal = body(&out);
    assert!(refusal.contains("outside contact address"), "{refusal}");
    assert!(refusal.contains("password route"), "{refusal}");

    // Another domain is not the account's own address even when signed.
    let other = "From: alice@other.example\n\nPlease send me a copy.\n";
    let (_, other_signature, _) = signing_key(other);
    std::fs::write(&message_path, other).unwrap();
    std::fs::write(&signature_path, &other_signature).unwrap();
    let out = fix.ctl(&verify);
    assert!(!out.status.success());
    assert!(
        body(&out).contains("not the account's own address"),
        "{}",
        body(&out)
    );

    assert!(
        !fix.dir.join("store/accounts/alice/requests.jsonl").exists(),
        "a refused check wrote a request line"
    );
}

/// An unsigned message is refused: there is nothing to verify against the key.
#[test]
fn request_verify_refuses_an_unsigned_message() {
    let fix = Fix::new("request-verify-unsigned");
    fix.page_account("alice", json!({}));
    fix.mail_key("alice", GOOD_KEY);
    let message_path = fix.path("message.eml");
    std::fs::write(&message_path, "From: alice@kyriakon.net\n\nPlease.\n").unwrap();
    let out = fix.ctl(&[
        "request",
        "verify",
        "--username",
        "alice",
        "--message",
        &message_path,
    ]);
    assert!(!out.status.success());
    assert!(body(&out).contains("not clearsigned"), "{}", body(&out));
}

/// The record names the route that established the sender. A record without one,
/// or with a route outside the two, is refused and writes nothing.
#[test]
fn request_record_requires_and_persists_the_identity_route() {
    let fix = Fix::new("request-record-identity");
    fix.page_account("alice", json!({}));
    let record = |identity: Option<&str>| {
        let mut args = vec![
            "request",
            "record",
            "--username",
            "alice",
            "--kind",
            "access",
            "--received",
            "2026-10-01",
            "--evidence",
            "the account page",
        ];
        if let Some(identity) = identity {
            args.extend(["--identity", identity]);
        }
        fix.ctl(&args)
    };

    let out = record(None);
    assert!(!out.status.success());
    assert!(body(&out).contains("--identity"), "{}", body(&out));
    let out = record(Some("session-cookie"));
    assert!(!out.status.success());
    assert!(body(&out).contains("identity route"), "{}", body(&out));
    assert!(fix.read("accounts/alice/requests.jsonl").is_empty());

    let out = record(Some("mail-key"));
    assert!(out.status.success(), "{}", body(&out));
    let line: Value = serde_json::from_str(
        fix.read("accounts/alice/requests.jsonl")
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(line["identity"], "mail-key", "{line}");
}

/// A line written before the field existed names no route, and `request list`
/// says so rather than printing an empty one.
#[test]
fn request_list_marks_a_legacy_line_unrecorded() {
    let fix = Fix::new("request-list-unrecorded");
    fix.page_account("alice", json!({}));
    std::fs::create_dir_all(fix.dir.join("store/accounts/alice")).unwrap();
    std::fs::write(
        fix.dir.join("store/accounts/alice/requests.jsonl"),
        "{\"version\":1,\"id\":\"01ARZ3NDEKTSV4RRFFQ69G5FAV\",\
         \"username\":\"alice\",\"kind\":\"access\",\"received\":\"2026-10-01\",\
         \"evidence\":\"the account page\",\"relevant\":\"2026-10-01\",\
         \"due\":\"2026-11-01\"}\n",
    )
    .unwrap();
    let out = fix.ctl(&["request", "list"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("identity unrecorded"), "{}", body(&out));
}
