use crate::common::*;

/// One filed application produces one review email carrying every answer, the
/// mail-key result, upload-key presence, the rail, the no-charge flag and three
/// signed links.
#[test]
fn a_filed_application_produces_one_review_email() {
    let fix = Fix::new("review");
    let record = fix.filed(
        "secretary",
        "cash",
        &[
            ("rail", "cash"),
            ("cannot_pay", "I have no money"),
            ("intended_use", "For parish mail"),
        ],
    );
    fix.file_application(&record);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    // One message, to the reviewer.
    assert_eq!(sent.matches("Subject:").count(), 1, "{}", body(&out));
    assert!(sent.contains("To: reviewer@example.invalid"), "{sent}");
    // The subject says what happened, in the shape every operator mail carries,
    // so a crowded mailbox can be triaged from the list.
    assert!(
        sent.contains("Subject: kyriakon: control: application filed (secretary,"),
        "{sent}"
    );
    // Every answer, keyed by its question id.
    assert!(sent.contains("cannot_pay: I have no money"), "{sent}");
    assert!(sent.contains("intended_use: For parish mail"), "{sent}");
    // The mail-key result and the upload-key presence.
    assert!(sent.contains("1111 2222 3333 4444"), "{sent}");
    assert!(sent.contains("works"), "{sent}");
    assert!(sent.contains("Upload key: supplied"), "{sent}");
    // The rail and the no-charge flag.
    assert!(sent.contains("Rail: cash"), "{sent}");
    assert!(sent.contains("No charge asked for: no"), "{sent}");
    // Three signed links, and the kyriakon-admin equivalents.
    assert_eq!(sent.matches("/decide/").count(), 3, "{sent}");
    assert_eq!(sent.matches("sig=").count(), 3, "{sent}");
    assert!(sent.contains("action=approve&"), "{sent}");
    assert!(sent.contains("action=approve-free&"), "{sent}");
    assert!(sent.contains("action=decline&"), "{sent}");
    assert!(
        sent.contains("\n  kyriakon-admin approve secretary\n"),
        "{sent}"
    );
    assert!(
        sent.contains("\n  kyriakon-admin approve-free secretary\n"),
        "{sent}"
    );
    assert!(
        sent.contains("\n  kyriakon-admin decline secretary\n"),
        "{sent}"
    );
    // Each decision link is on a line of its own, so a client that wraps at a
    // fixed width has a chance of keeping the URL whole; and the terminal form
    // is printed before them, because it cannot be wrapped at all.
    let lines: Vec<&str> = sent.lines().collect();
    let link_lines = lines
        .iter()
        .filter(|l| l.trim_start().starts_with("https://") && l.contains("/decide/"))
        .count();
    assert_eq!(link_lines, 3, "{sent}");
    let terminal = sent.find("kyriakon-admin approve-free").unwrap();
    let first_link = sent.find("/decide/").unwrap();
    assert!(terminal < first_link, "the terminal form comes first");

    // The intent is consumed.
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
}

/// A password set through the one-time link is applied once, and only with a
/// signature over the link's own token, account and date. The drain hashes the plaintext
/// it is given, the record stops holding the link, and a replay or a forged
/// signature is refused without the script being run.
#[test]
fn a_password_link_applies_once_and_only_when_signed() {
    let fix = Fix::new("password");
    let log = fix.path("password.log");
    fix.script(
        "set-mail-password.sh",
        &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\n"),
    );
    let key = sign::read_key(std::path::Path::new(&fix.path("key"))).unwrap();
    let until = kyriakon_control_core::util::date_after_days(7);

    let mut record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    record["password_link"] = json!(format!(
        "https://signup.example.invalid/password/{TOKEN}?until={until}&sig=x"
    ));
    std::fs::write(
        fix.path(&format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();

    let sig = sign::sign(&key, &sign::password_payload(TOKEN, "secretary", &until)).unwrap();
    let intent = json!({
        "id": "01J00000000000000000PASSWORD",
        "kind": "set-password",
        "filed_at": "2026-10-21T09:00:00Z",
        "application": { "username": "secretary", "status_token": TOKEN },
        "until": until,
        "sig": sig,
        "password": "correct horse battery",
    });
    fix.write_intent("01J00000000000000000PASSWORD", &intent);
    let out = fix.drain();
    assert!(
        out.status.success(),
        "status {:?}\nstdout: {}\nstderr: {}",
        out.status,
        body(&out),
        String::from_utf8_lossy(&out.stderr)
    );

    // The script ran once, with the account and a hash of the plaintext the
    // intent carried, and never the plaintext itself.
    let written = std::fs::read_to_string(&log).unwrap_or_default();
    let installed = written.strip_prefix("secretary ").unwrap_or("").trim();
    assert!(
        kyriakon_control_core::account::password::is_hash(installed),
        "journal: {}",
        std::fs::read_to_string(fix.path("store/journal.jsonl")).unwrap_or_default()
    );
    assert!(
        kyriakon_control_core::account::password::matches("correct horse battery", installed),
        "{written}"
    );
    assert!(!written.contains("correct horse"), "{written}");

    // The link is spent: the record no longer carries it.
    let after: Value = serde_json::from_str(
        &std::fs::read_to_string(fix.path(&format!("store/applications/{TOKEN}.json"))).unwrap(),
    )
    .unwrap();
    assert!(after["password_link"].is_null(), "{after}");
    // And the intent is removed once it is applied, as every transition does:
    // leaving it makes every later pass re-read it.
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    // And the fields this build does not model survive the write: the record
    // carries the answers and the rest, and losing them would be silent.
    assert!(after["answers"].is_object(), "{after}");
    assert_eq!(after["status_token"], json!(TOKEN), "{after}");
    assert!(
        std::fs::read_to_string(fix.path("store/journal.jsonl"))
            .unwrap_or_default()
            .contains("\"outcome\":\"applied\""),
        "the journal should record the apply"
    );

    // A replay of the same intent is caught by the journal's own dedup, a fresh
    // click on a spent link by the record, and a forged signature by the key.
    // None of the three runs the script again.
    fix.write_intent("01J00000000000000000PASSWORD", &intent);
    let mut fresh = intent.clone();
    fresh["id"] = json!("01J00000000000000000SPENT");
    fix.write_intent("01J00000000000000000SPENT", &fresh);
    let mut forged = intent.clone();
    forged["id"] = json!("01J00000000000000000FORGED");
    forged["sig"] = json!("00".repeat(32));
    fix.write_intent("01J00000000000000000FORGED", &forged);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let written = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(written.lines().count(), 1, "{written}");
    let journal = std::fs::read_to_string(fix.path("store/journal.jsonl")).unwrap_or_default();
    assert!(
        journal.contains("the link has already been used"),
        "{journal}"
    );
    assert!(
        journal.contains("the link's signature does not verify"),
        "{journal}"
    );
}

/// A signature the drain issued for one account does not set another's
/// password. The handler can rewrite the application copy and file the intent
/// under any name, so the account the signature covers is the intent's own:
/// an intent that names another account fails verification, and one whose
/// record was rewritten is refused by the record check. Neither runs
/// `set-mail-password.sh`.
#[test]
fn a_password_link_cannot_be_pointed_at_another_account() {
    let fix = Fix::new("password-repointed");
    let log = fix.path("password.log");
    fix.script(
        "set-mail-password.sh",
        &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\n"),
    );
    let key = sign::read_key(std::path::Path::new(&fix.path("key"))).unwrap();
    let until = kyriakon_control_core::util::date_after_days(7);
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    // The link and signature the drain issued for the filed account.
    let username = record["username"].as_str().unwrap();
    let link = sign::password_link(
        "https://signup.example.invalid",
        &key,
        TOKEN,
        username,
        &until,
    )
    .unwrap();
    // Take the signature from the link the production code issued, so the
    // link's own payload is what the drain verifies.
    let sig = link
        .split("sig=")
        .nth(1)
        .expect("the issued link carries its signature")
        .to_string();
    let rewrite_record = |username: &str| {
        let mut copy = record.clone();
        copy["username"] = json!(username);
        copy["password_link"] = json!(link);
        std::fs::write(
            fix.path(&format!("store/applications/{TOKEN}.json")),
            serde_json::to_vec_pretty(&copy).unwrap(),
        )
        .unwrap();
    };
    let file_intent = |id: &str, username: &str| {
        fix.write_intent(
            id,
            &json!({
                "id": id,
                "kind": "set-password",
                "filed_at": "2026-10-21T09:00:00Z",
                "application": { "username": username, "status_token": TOKEN },
                "until": until,
                "sig": sig,
                "password": "correct horse battery",
            }),
        );
    };

    // The handler points the captured signature at a victim by naming the
    // victim in the intent and rewriting the record to match.
    rewrite_record("victim");
    file_intent("01J00000000000000000TAKEOVER", "victim");
    // And the other half: the intent keeps the signed name and the record was
    // rewritten, so the drain's record check is what refuses.
    file_intent("01J00000000000000000RELABEL", username);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !std::path::Path::new(&log).exists(),
        "the script ran for another account: {}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    assert_eq!(fix.intents().len(), 2, "a refusal is not a settlement");
    let journal = fix.journal();
    assert!(
        journal.contains("the link's signature does not verify"),
        "{journal}"
    );
    assert!(
        journal.contains("the intent names another account"),
        "{journal}"
    );
    // Nothing was applied, so the link is still live on the record.
    let after: Value = serde_json::from_str(
        &std::fs::read_to_string(fix.path(&format!("store/applications/{TOKEN}.json"))).unwrap(),
    )
    .unwrap();
    assert!(!after["password_link"].is_null(), "{after}");
}

/// A `set-password` intent that carries a hash is refused even under a valid
/// link signature: the drain hashes the plaintext, so a handler that holds a
/// valid link cannot install a hash of its own choosing.
#[test]
fn a_password_intent_carrying_a_hash_is_refused() {
    let fix = Fix::new("password-hash-refused");
    let log = fix.path("password.log");
    fix.script(
        "set-mail-password.sh",
        &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\n"),
    );
    let key = sign::read_key(std::path::Path::new(&fix.path("key"))).unwrap();
    let until = kyriakon_control_core::util::date_after_days(7);
    let mut record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    record["password_link"] = json!(format!(
        "https://signup.example.invalid/password/{TOKEN}?until={until}&sig=x"
    ));
    std::fs::write(
        fix.path(&format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();

    let sig = sign::sign(&key, &sign::password_payload(TOKEN, "secretary", &until)).unwrap();
    let chosen =
        kyriakon_control_core::account::password::make("a password the member never typed")
            .unwrap();
    let base = json!({
        "kind": "set-password",
        "filed_at": "2026-10-21T09:00:00Z",
        "application": { "username": "secretary", "status_token": TOKEN },
        "until": until,
        "sig": sig,
    });
    // The old shape: a hash and no plaintext.
    let mut hash_only = base.clone();
    hash_only["id"] = json!("01J00000000000000000HASHONLY");
    hash_only["hash"] = json!(chosen);
    fix.write_intent("01J00000000000000000HASHONLY", &hash_only);
    // The swap: a valid plaintext beside a hash of the handler's choosing.
    let mut swap = base.clone();
    swap["id"] = json!("01J00000000000000000HASHSWAP");
    swap["password"] = json!("correct horse battery");
    swap["hash"] = json!(chosen);
    fix.write_intent("01J00000000000000000HASHSWAP", &swap);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!std::path::Path::new(&log).exists(), "the script ran");
    assert!(
        fix.journal().matches("carries a hash").count() == 2,
        "{}",
        fix.journal()
    );
    assert_eq!(fix.intents().len(), 2, "a refusal is not a settlement");
    // The link is still live: nothing was applied.
    let after: Value = serde_json::from_str(
        &std::fs::read_to_string(fix.path(&format!("store/applications/{TOKEN}.json"))).unwrap(),
    )
    .unwrap();
    assert!(!after["password_link"].is_null(), "{after}");
}

/// A refused plaintext intent stays on disk because a refusal is not a
/// settlement, but it carries no password value for a backup to find.
#[test]
fn a_refused_password_intent_keeps_no_plaintext() {
    let fix = Fix::new("password-refused-plaintext");
    let key = sign::read_key(std::path::Path::new(&fix.path("key"))).unwrap();
    let until = "2020-01-01";
    let mut record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    record["password_link"] = json!(format!(
        "https://signup.example.invalid/password/{TOKEN}?until={until}&sig=x"
    ));
    std::fs::write(
        fix.path(&format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    let sig = sign::sign(&key, &sign::password_payload(TOKEN, "secretary", until)).unwrap();
    fix.write_intent(
        "01J00000000000000000EXPIRED",
        &json!({
            "id": "01J00000000000000000EXPIRED",
            "kind": "set-password",
            "filed_at": "2026-10-21T09:00:00Z",
            "application": { "username": "secretary", "status_token": TOKEN },
            "until": until,
            "sig": sig,
            "password": "correct horse battery",
        }),
    );

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents(), vec!["01J00000000000000000EXPIRED.json"]);
    let text = fix.read("intents/01J00000000000000000EXPIRED.json");
    assert!(!text.contains("correct horse battery"), "{text}");
    let filed: Value = serde_json::from_str(&text).unwrap();
    assert!(filed.get("password").is_none(), "{filed}");
    assert_eq!(filed["kind"], "set-password", "{filed}");
    assert!(
        fix.journal().contains("the link's date has passed"),
        "{}",
        fix.journal()
    );
}

/// A crash between the `applied` journal line and the intent's removal leaves
/// the file re-read on every pass. The next pass finishes the remove, and does
/// not journal a second `applied` line.
#[test]
fn an_applied_password_intent_left_behind_is_removed_on_the_next_pass() {
    let fix = Fix::new("password-applied-cleanup");
    let id = "01J00000000000000000APPLIED";
    fix.write_intent(
        id,
        &json!({
            "id": id,
            "kind": "set-password",
            "filed_at": "2026-10-21T09:00:00Z",
            "application": { "username": "secretary", "status_token": TOKEN },
            "until": "2026-10-28",
            "sig": "00".repeat(32),
            "password": "correct horse battery",
        }),
    );
    // The line the crashed pass wrote before it could remove the file.
    std::fs::write(
        fix.path("store/journal.jsonl"),
        format!(
            "{{\"version\":1,\"at\":\"2026-10-21T09:00:00Z\",\"intent\":\"{id}\",\"kind\":\"set-password\",\"release\":\"test\",\"application\":{{\"username\":\"secretary\",\"status_token\":\"{TOKEN}\"}},\"outcome\":\"applied\"}}\n"
        ),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.intents().is_empty(),
        "the applied intent was left in place: {:?}",
        fix.intents()
    );
    assert_eq!(
        fix.journal().matches("\"outcome\":\"applied\"").count(),
        1,
        "a second applied line was appended: {}",
        fix.journal()
    );
}

/// A click on an already-decided application changes nothing in the store and
/// sends nothing, and the journal records that it was seen.
/// The decision email carries the one-time password link, not only the status
/// page: the spec asks for both, and the member whose mailbox has no password
/// yet cannot read the mail that was sent to it.
#[test]
fn an_approval_email_carries_the_password_link() {
    let fix = Fix::new("password-in-mail");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    let key = sign::read_key(std::path::Path::new(&fix.path("key"))).unwrap();
    let sig = sign::sign(&key, &sign::decide_payload(TOKEN, "approve-free")).unwrap();
    fix.write_decision("provision", "approve-free", &sig, "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let sent = fix.sent();
    assert!(sent.contains("/password/"), "{sent}");
    assert!(sent.contains("works once"), "{sent}");
}

/// After a failed pass and its backoff, the next pass applies the intent: a
/// failed journal line is the reason to retry, not a settlement.
#[test]
fn a_failed_password_pass_is_retried_after_the_backoff() {
    let fix = Fix::new("password-retry");
    let log = fix.path("password.log");
    fix.script(
        "set-mail-password.sh",
        &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\n"),
    );
    let key = sign::read_key(std::path::Path::new(&fix.path("key"))).unwrap();
    let until = kyriakon_control_core::util::date_after_days(7);
    let mut record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    record["password_link"] = json!("https://signup.example.invalid/password/x");
    std::fs::write(
        fix.path(&format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    let sig = sign::sign(&key, &sign::password_payload(TOKEN, "secretary", &until)).unwrap();
    fix.write_intent(
        "01J00000000000000000RETRY",
        &json!({
            "id": "01J00000000000000000RETRY",
            "kind": "set-password",
            "filed_at": "2026-10-21T09:00:00Z",
            "application": { "username": "secretary", "status_token": TOKEN },
            "until": until,
            "sig": sig,
            "password": "correct horse battery",
        }),
    );
    std::fs::write(
        fix.path("store/journal.jsonl"),
        format!(
            "{{\"version\":1,\"at\":\"2020-01-01T00:00:00Z\",\"intent\":\"01J00000000000000000RETRY\",\"kind\":\"intent\",\"release\":\"test\",\"application\":{{\"username\":\"secretary\",\"status_token\":\"{TOKEN}\"}},\"outcome\":\"failed\",\"note\":\"an earlier pass\"}}\n"
        ),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("secretary"),
        "the script should have run"
    );
}

#[test]
fn a_replayed_approval_changes_nothing() {
    let fix = Fix::new("replay");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success(), "first approve");
    let after_first = fix.snapshot();
    let sent_after_first = fix.sent().matches("Subject:").count();

    // The same click again.
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    // The application, the account, the token and the ledger are untouched.
    let after_second = fix.snapshot();
    let touching: Vec<_> = after_first
        .keys()
        .chain(after_second.keys())
        .filter(|k| !k.ends_with("journal.jsonl"))
        .filter(|k| after_first.get(*k) != after_second.get(*k))
        .collect();
    assert!(touching.is_empty(), "changed: {touching:?}");
    // No second decision email.
    assert_eq!(fix.sent().matches("Subject:").count(), sent_after_first);
    // The journal records that the replay was seen.
    assert!(
        fix.journal().contains("already-decided"),
        "{}",
        fix.journal()
    );
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
}

/// A free account never lapses, carries no payment block, and is sent one note a
/// year on the creation anniversary. The console counts free accounts only:
/// a paid account and a group mailbox are not free accounts of their own.
#[test]
fn a_free_account_gets_one_note_a_year_and_the_console_counts_it() {
    let fix = Fix::new("free-anniversary");
    let record = fix.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("provision", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    // Approved this year: no anniversary has fallen due, so no note.
    assert!(
        !fix.sent().contains("free for another year"),
        "{}",
        fix.sent()
    );

    // Age the account past an anniversary, as a year of running would.
    let mut account = fix.account("secretary");
    account["created_at"] = json!("2019-01-01T09:00:00Z");
    std::fs::write(
        fix.dir.join("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let sent = fix.sent();
    assert!(sent.contains("free for another year"), "{sent}");
    assert!(
        sent.contains("Nothing is due for secretary this year."),
        "{sent}"
    );
    let notices = fix.read("accounts/secretary/notices.jsonl");
    assert_eq!(notices.matches("free.anniversary").count(), 1, "{notices}");

    // A paid account, and a group mailbox whose group was approved without
    // charge, are not free accounts of their own: the sweep skips both, so the
    // second pass still sends one note, and the console counts one account.
    for (name, group, payment) in [
        (
            "paid",
            Value::Null,
            json!({"token_ref": "KYR-AAAA-BBBB-CCCC", "paid_until": null}),
        ),
        ("parish", json!("parish.example"), Value::Null),
    ] {
        let dir = fix.dir.join(format!("store/accounts/{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        let account = json!({
            "version": 1, "username": name, "state": "active",
            "decision": "approve", "decided_at": "2019-01-01T09:00:00Z",
            "rail": if group.is_null() { "cash" } else { "no_charge" },
            "no_charge": !group.is_null(), "created_at": "2019-01-01T09:00:00Z",
            "payment": payment, "group": group,
        });
        std::fs::write(
            dir.join("account.json"),
            serde_json::to_vec_pretty(&account).unwrap(),
        )
        .unwrap();
    }
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.sent().matches("free for another year").count(),
        1,
        "one note a year, and none for the paid account or the group mailbox"
    );
    assert_eq!(fix.account("secretary")["state"], json!("active"));
    assert!(!notices.contains("lapsed"), "{notices}");

    let out = fix.ctl(&["free"]);
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(body(&out).trim(), "1 account without charge");
}

/// A mail path that refuses one account's note does not fail the pass: the key
/// spool and the DNS check behind the sweep still run, as they do after the
/// other sweeps' per-item failures.
#[test]
fn a_refused_free_note_does_not_fail_the_pass() {
    let fix = Fix::new("free-anniversary-refused");
    fix.enqueuer_fails();
    let dir = fix.dir.join("store/accounts/secretary");
    std::fs::create_dir_all(&dir).unwrap();
    let account = json!({
        "version": 1, "username": "secretary", "state": "active",
        "decision": "approve", "decided_at": "2019-01-01T09:00:00Z",
        "rail": "no_charge", "no_charge": true,
        "created_at": "2019-01-01T09:00:00Z",
    });
    std::fs::write(
        dir.join("account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // The notice is recorded before the send, so the refusal is visible and the
    // year is not mailed twice by a later pass.
    assert!(fix
        .read("accounts/secretary/notices.jsonl")
        .contains("free.anniversary"));
}

/// An application that asked for no charge is never charged, even by the
/// charge-carrying intent: the reviewer's own button and the applicant's answer
/// both have to say pay before a token is drawn.
#[test]
fn an_application_that_asked_for_no_charge_is_never_charged() {
    let fix = Fix::new("safety");
    let record = fix.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let account = fix.account("secretary");
    assert!(account.get("payment").is_none(), "{account}");
    assert!(
        fix.read("ledger/payments.jsonl").is_empty(),
        "nothing owed, no ledger line"
    );
}

/// The three decision verbs write the intent the drain reads, and `show` reads
/// one application back.
#[test]
fn admin_files_a_decision_and_shows_the_application() {
    let fix = Fix::new("ctl");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);

    let out = fix.ctl(&["approve", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());
    let intent: Value =
        serde_json::from_str(&fix.read(&format!("intents/{}", fix.intents()[0]))).unwrap();
    assert_eq!(intent["kind"], json!("approve"));
    assert_eq!(intent["application"]["username"], json!("secretary"));
    assert_eq!(intent["application"]["status_token"], json!(TOKEN));
    // Every decision intent is signed: the drain refuses one that is not.
    assert_eq!(intent["action"], json!("approve"));
    let sig = intent["sig"].as_str().unwrap();
    assert!(
        sign::verify(
            b"the approval key",
            &sign::decide_payload(TOKEN, "approve"),
            sig
        ),
        "{intent}"
    );

    // approve-free files the no-charge kind; decline files a decline.
    for (verb, kind) in [("approve-free", "provision"), ("decline", "decline")] {
        for name in fix.intents() {
            std::fs::remove_file(fix.dir.join("store/intents").join(name)).unwrap();
        }
        let out = fix.ctl(&[verb, "secretary"]);
        assert!(out.status.success(), "{}", body(&out));
        let names = fix.intents();
        assert_eq!(names.len(), 1, "{}", body(&out));
        let v: Value = serde_json::from_str(&fix.read(&format!("intents/{}", names[0]))).unwrap();
        assert_eq!(v["kind"], json!(kind), "{verb} should file {kind}");
    }

    let out = fix.ctl(&["show", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(text.contains("application secretary"), "{text}");
    assert!(text.contains("cash"), "{text}");

    // A verb the console does not know is refused, and an unknown username
    // names nothing.
    assert!(!fix.ctl(&["purge", "secretary"]).status.success());
    assert!(!fix.ctl(&["approve", "nobody"]).status.success());
    let _ = record;
}

/// A decline purges nothing on the first run; the run after its week clears the
/// application away and releases the username.
#[test]
fn a_decline_purges_after_its_week_and_releases_the_username() {
    let fix = Fix::new("decline");
    // The applicant gave an address outside the platform, so the decline is
    // mailed. Without one nothing is sent, which the next test covers.
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("decline", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    // The first run decides and holds; nothing is purged.
    assert!(
        fix.dir
            .join(format!("store/applications/{TOKEN}.json"))
            .exists(),
        "a fresh decline is held for its week"
    );
    assert!(fix.sent().contains("was declined"), "{}", fix.sent());
    assert!(
        !fix.scripts_log().contains("delete-user.sh"),
        "nothing is released before the week: {}",
        fix.scripts_log()
    );

    // Move the decision a week back, as a week of cron would, and run again.
    let mut app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    app["decided_at"] = json!("2026-09-01T00:00:00Z");
    std::fs::write(
        fix.dir.join(format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&app).unwrap(),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        !fix.dir
            .join(format!("store/applications/{TOKEN}.json"))
            .exists(),
        "the week past, the application is cleared away"
    );
    assert!(
        fix.scripts_log().contains("delete-user.sh secretary"),
        "the username is released: {}",
        fix.scripts_log()
    );
    let _ = record;
}

/// Move a stored record's `filed_at` into the past, as the calendar does
/// between passes.
fn age_filed_at(fix: &Fix, rel: &str, days: i64) {
    let path = fix.dir.join("store").join(rel);
    let mut record: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let old = OffsetDateTime::now_utc() - time::Duration::days(days);
    record["filed_at"] = json!(old
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap());
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
}

/// ADR 0005's ninety days: an approved application's answers are cleared from
/// the mailbox's copy and the token record on the first pass after the window,
/// while `account.json` keeps the payment and the outside address. The token is
/// journalled once, and a second pass adds no line.
#[test]
fn an_approved_applications_answers_purge_after_ninety_days() {
    let fix = Fix::new("purge-approved");
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash"), ("cannot_pay", "I have no money")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let copy = "accounts/secretary/application.json";
    let token = format!("applications/{TOKEN}.json");
    assert!(
        fix.dir.join("store").join(copy).exists(),
        "the approval copies the application into the account"
    );
    age_filed_at(&fix, copy, 100);
    age_filed_at(&fix, &token, 100);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir.join("store").join(copy).exists(),
        "the mailbox's copy still holds the answers"
    );
    assert!(
        !fix.dir.join("store").join(&token).exists(),
        "the token record still holds the answers"
    );
    let account = fix.account("secretary");
    assert_eq!(
        account["outside_address"],
        json!("applicant@example.invalid"),
        "{account}"
    );
    assert!(
        account["payment"].is_object(),
        "the payment block stays with the account: {account}"
    );

    let line = format!("\"intent\":\"purge-{TOKEN}\"");
    let counted = || fix.journal().matches(&line).count();
    assert_eq!(counted(), 2, "applying and purged, once: {}", fix.journal());
    assert!(
        fix.journal().contains("\"kind\":\"purge\""),
        "{}",
        fix.journal()
    );

    // A retry over the cleared store adds nothing.
    assert!(fix.drain().status.success());
    assert_eq!(counted(), 2, "{}", fix.journal());
}

/// Inside the window the answers stay: the boundary is the ninetieth day, and
/// nothing is purged before it ends.
#[test]
fn an_approved_applications_answers_are_kept_inside_ninety_days() {
    let fix = Fix::new("purge-inside");
    approved_paid(&fix, "secretary", "cash");
    let copy = "accounts/secretary/application.json";
    let token = format!("applications/{TOKEN}.json");
    age_filed_at(&fix, copy, 10);
    age_filed_at(&fix, &token, 10);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.dir.join("store").join(copy).exists(),
        "the answers were purged inside the window"
    );
    assert!(
        fix.dir.join("store").join(&token).exists(),
        "the token record was purged inside the window"
    );
    assert!(
        !fix.journal()
            .contains(&format!("\"intent\":\"purge-{TOKEN}\"")),
        "{}",
        fix.journal()
    );
}

/// An application that was never decided is abandoned after the window: its
/// record goes and its username is released when nothing holds it. A record
/// whose filing date cannot be read is left alone, because the boundary cannot
/// be proved.
#[test]
fn an_abandoned_application_purges_after_ninety_days_and_releases_the_username() {
    let fix = Fix::new("purge-abandoned");
    let record = fix.filed_with("secretary", "cash", &[("rail", "cash")], None, None);
    let path = fix.dir.join(format!("store/applications/{TOKEN}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    age_filed_at(&fix, &format!("applications/{TOKEN}.json"), 100);

    let mut undated = record.clone();
    undated["status_token"] = json!(OTHER_TOKEN);
    undated["filed_at"] = json!("last Tuesday");
    let undated_path = fix
        .dir
        .join(format!("store/applications/{OTHER_TOKEN}.json"));
    std::fs::write(&undated_path, serde_json::to_vec_pretty(&undated).unwrap()).unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!path.exists(), "the abandoned record was not purged");
    assert!(
        undated_path.exists(),
        "the undated record was purged on a guess"
    );
    assert!(
        fix.scripts_log().contains("delete-user.sh secretary"),
        "the username is released: {}",
        fix.scripts_log()
    );
    let line = format!("\"intent\":\"purge-{TOKEN}\"");
    assert_eq!(fix.journal().matches(&line).count(), 2, "{}", fix.journal());
    assert!(
        !fix.journal()
            .contains(&format!("\"intent\":\"purge-{OTHER_TOKEN}\"")),
        "{}",
        fix.journal()
    );

    // A retry adds no line and runs no second release.
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.scripts_log()
            .matches("delete-user.sh secretary")
            .count(),
        1,
        "{}",
        fix.scripts_log()
    );
    assert_eq!(fix.journal().matches(&line).count(), 2, "{}", fix.journal());
}

/// A decided application whose mailbox copy is gone (the account was deleted
/// before the window) is purged from the token directory too, without releasing
/// its name: a release is the abandoned record's. A decided record inside the
/// window stays.
#[test]
fn a_decided_application_with_no_mailbox_copy_purges_after_ninety_days() {
    let fix = Fix::new("purge-decided");
    approved_paid(&fix, "secretary", "cash");
    // The account goes before the window, leaving the token record with no
    // mailbox copy to reach it.
    std::fs::remove_dir_all(fix.dir.join("store/accounts/secretary")).unwrap();
    age_filed_at(&fix, &format!("applications/{TOKEN}.json"), 100);

    // A decided record inside the window, for a name no account holds. Written
    // directly: `Fix::filed` also writes the fixture to `applications/<TOKEN>`,
    // which would replace the aged record above.
    let young = json!({
        "username": "almoner",
        "status_token": OTHER_TOKEN,
        "filed_at": kyriakon_control_core::util::after_days(-10),
        "front_end": "web",
        "stage": "decided: an account without charge",
        "decided_at": kyriakon_control_core::util::after_days(-10),
        "answers": {},
        "mail_keys": [],
        "rail": "no_charge",
        "no_charge": true,
        "acceptances": [],
        "question_list": "2026-08-01 abc1234",
    });
    std::fs::write(
        fix.dir
            .join(format!("store/applications/{OTHER_TOKEN}.json")),
        serde_json::to_vec_pretty(&young).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir
            .join(format!("store/applications/{TOKEN}.json"))
            .exists(),
        "the decided record with no mailbox copy was not purged"
    );
    assert!(
        fix.dir
            .join(format!("store/applications/{OTHER_TOKEN}.json"))
            .exists(),
        "a decided record inside the window was purged"
    );
    let line = format!("\"intent\":\"purge-{TOKEN}\"");
    assert_eq!(fix.journal().matches(&line).count(), 2, "{}", fix.journal());
    assert!(
        !fix.scripts_log().contains("delete-user.sh secretary"),
        "a decided record's name was released: {}",
        fix.scripts_log()
    );
    assert!(
        !fix.journal()
            .contains(&format!("\"intent\":\"purge-{OTHER_TOKEN}\"")),
        "{}",
        fix.journal()
    );
}

/// An approval writes `mark_decided` last, so a failed pass leaves the record at
/// `received` with its intent still queued. The purge must leave it alone and
/// let the retry finish, and take it once the intent is gone.
#[test]
fn a_received_application_with_a_queued_decision_is_kept() {
    let fix = Fix::new("purge-queued");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    // The approval fails at provisioning, so its intent backs off in place and
    // the record is still `received`.
    fix.provision_fails();
    let intent = fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());
    assert!(
        fix.intents().contains(&format!("{intent}.json")),
        "{:?}",
        fix.intents()
    );

    age_filed_at(&fix, &format!("applications/{TOKEN}.json"), 100);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.dir
            .join(format!("store/applications/{TOKEN}.json"))
            .exists(),
        "the record was purged from under a queued approval"
    );
    assert!(
        !fix.journal()
            .contains(&format!("\"intent\":\"purge-{TOKEN}\"")),
        "{}",
        fix.journal()
    );

    // The intent gone, the abandoned record purges.
    std::fs::remove_file(fix.dir.join("store/intents").join(format!("{intent}.json"))).unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir
            .join(format!("store/applications/{TOKEN}.json"))
            .exists(),
        "the abandoned record was kept after its intent went"
    );
}

/// `kyriakon-admin show` still reports an account once the ninety-day sweep has
/// taken its application record: the application is optional, the state and
/// payment are not.
#[test]
fn show_reports_an_account_whose_application_was_purged() {
    let fix = Fix::new("show-purged");
    let token_ref = approved_paid(&fix, "secretary", "cash");
    age_filed_at(&fix, "accounts/secretary/application.json", 100);
    age_filed_at(&fix, &format!("applications/{TOKEN}.json"), 100);
    assert!(fix.drain().status.success());
    assert!(!fix
        .dir
        .join(format!("store/applications/{TOKEN}.json"))
        .exists());

    let out = fix.ctl(&["show", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(text.contains("application secretary purged"), "{text}");
    assert!(text.contains("account secretary"), "{text}");
    assert!(text.contains("state    active"), "{text}");
    assert!(text.contains(&token_ref), "{text}");
}

/// A group's application copy is written into every mailbox. The purge clears
/// all of them and the shared token record, journaling the token once, and
/// leaves the group and mailbox records alone.
#[test]
fn a_groups_application_copy_in_every_mailbox_purges_once() {
    let fix = Fix::new("purge-group");
    let mut record = fix.filed_body("warden");
    record["answers"]["body_addresses"] = json!("secretary: own\nrector: own");
    record["answers"]["body_account_names"] = json!("parish-secretary\nparish-office");
    // Each mailbox needs its own key before an approval will start, and the
    // record on disk is the one an approval reads: `filed_body` has already
    // written it, so the mutation is written back too.
    record["mail_keys"] = json!([
        {
            "mailbox": "parish-secretary",
            "fingerprint": "1111 2222 3333 4444",
            "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
            "verdict": "works",
        },
        {
            "mailbox": "parish-office",
            "fingerprint": "5555 6666 7777 8888",
            "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
            "verdict": "works",
        },
    ]);
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    for mailbox in ["parish-secretary", "parish-office"] {
        let copy = format!("accounts/{mailbox}/application.json");
        assert!(
            fix.dir.join("store").join(&copy).exists(),
            "{mailbox} has no copy"
        );
        age_filed_at(&fix, &copy, 100);
    }
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    for mailbox in ["parish-secretary", "parish-office"] {
        assert!(
            !fix.dir
                .join("store")
                .join(format!("accounts/{mailbox}/application.json"))
                .exists(),
            "{mailbox}'s copy survived the purge"
        );
        assert!(
            fix.dir
                .join("store")
                .join(format!("accounts/{mailbox}/account.json"))
                .exists(),
            "{mailbox}'s account was touched"
        );
    }
    assert!(!fix
        .dir
        .join(format!("store/applications/{TOKEN}.json"))
        .exists());
    assert!(fix
        .dir
        .join("store/groups/parish.example/group.json")
        .exists());
    assert_eq!(
        fix.journal()
            .matches(&format!("\"intent\":\"purge-{TOKEN}\""))
            .count(),
        2,
        "{}",
        fix.journal()
    );
}

/// Running the drain twice over one `intents/` directory leaves the same store
/// and sends no notice twice. The second pass is made to re-read the same intent,
/// the state a run that died before it deleted the file leaves, so the pass
/// reaches the dedup rather than merely seeing an empty directory.
#[test]
fn two_runs_over_one_intent_directory_send_nothing_twice() {
    let fix = Fix::new("twice");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    let id = fix.file_application(&record);
    let intent = fix.read(&format!("intents/{id}.json"));

    assert!(fix.drain().status.success());
    let after_first = fix.snapshot();
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "one review email"
    );

    // The same intent again, as a crash before the delete leaves it: the second
    // pass re-reads it and must find the application already reviewed.
    std::fs::write(
        fix.dir.join("store/intents").join(format!("{id}.json")),
        &intent,
    )
    .unwrap();
    assert!(fix.drain().status.success());
    let after_second = fix.snapshot();

    assert_eq!(
        after_first, after_second,
        "the second run changed the store"
    );
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "no second review email"
    );
    assert!(
        fix.intents().is_empty(),
        "the re-read intent is consumed: {:?}",
        fix.intents()
    );
}

/// A kind this build does not implement is refused by name and left in place,
/// and two runs record the refusal once.
#[test]
fn an_unimplemented_kind_is_left_in_place_and_refused_once() {
    let fix = Fix::new("unknown");
    let id = ulid();
    fix.write_intent(
        &id,
        &json!({
            "id": id,
            "kind": "future-kind",
            "filed_at": "2026-10-02T09:00:00Z",
            "application": {"username": "secretary", "status_token": TOKEN},
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // Left in place, the second run sees it again.
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(fix.journal().contains("refused"), "{}", fix.journal());
    assert!(fix.journal().contains("future-kind"), "{}", fix.journal());

    assert!(fix.drain().status.success());
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    // The refusal is recorded once, not once per run.
    assert_eq!(
        fix.journal().matches("refused").count(),
        1,
        "{}",
        fix.journal()
    );
}

/// A link the review email carried is the one the drain accepts, and a tampered
/// signature changes nothing: the click is verified against the same key, and
/// the application is decided only when it verifies.
#[test]
fn a_signed_link_decides_and_a_tampered_one_does_not() {
    let fix = Fix::new("signature");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());

    // Pull the approve link out of the message the drain just sent.
    let sent = fix.sent();
    let marker = format!("/decide/{TOKEN}?action=approve&sig=");
    let start = sent.find(&marker).expect(&sent) + marker.len();
    let sig: String = sent[start..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    assert_eq!(sig.len(), 64, "{sig}");

    // A tampered signature is refused and the application is untouched.
    let tampered = format!("{}0", &sig[..63]);
    let id = ulid();
    fix.write_intent(
        &id,
        &json!({
            "id": id, "kind": "approve", "filed_at": "2026-10-02T09:00:00Z",
            "application": {"username": "secretary", "status_token": TOKEN},
            "action": "approve", "sig": tampered,
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "a tampered signature must not decide the application"
    );
    std::fs::remove_file(fix.dir.join("store/intents").join(format!("{id}.json"))).unwrap();

    // The signature the email actually carried is accepted.
    let id = ulid();
    fix.write_intent(
        &id,
        &json!({
            "id": id, "kind": "approve", "filed_at": "2026-10-02T09:00:00Z",
            "application": {"username": "secretary", "status_token": TOKEN},
            "action": "approve", "sig": sig,
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
}

/// The approval runs the two provisioning scripts in the order the spec fixes.
#[test]
fn an_approval_provisions_with_add_user_first() {
    let fix = Fix::new("provision");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());

    let log = fix.scripts_log();
    let add = log.find("add-user.sh secretary").expect(&log);
    let member = log.find("provision-member.sh secretary").expect(&log);
    assert!(add < member, "add-user.sh comes first: {log}");
    // The lanes wrote the member's daemon files, so the web index and reload
    // pass runs for a hosting member.
    assert!(
        log.contains("cron-apply.sh --web"),
        "the web index and reload should run: {log}"
    );
    // The account holds its own copy of the application and its notices.
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    assert!(fix
        .dir
        .join("store/accounts/secretary/application.json")
        .exists());
    assert!(!fix.read("accounts/secretary/notices.jsonl").is_empty());
    // The completion line is written, so a finished approval does not read like
    // one that died midway.
    assert!(fix.journal().contains("\"applied\""), "{}", fix.journal());
}

/// The confirmation reaches the enqueuer before add-user.sh runs: the envelope
/// is the record of what was agreed, and it must exist before the service does.
#[test]
fn the_confirmation_leaves_before_add_user() {
    let fix = Fix::new("confirmation-order");
    add_user_asks_whether_the_confirmation_left(&fix);
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let log = fix.scripts_log();
    assert!(
        log.contains("confirmation-seen"),
        "add-user.sh ran before the confirmation left: {log}"
    );
    assert!(!log.contains("confirmation-missing"), "{log}");
}

/// A retry after a failed provisioning sends no second confirmation: the stamp
/// is written before the enqueue, so a crash costs an email rather than a
/// duplicate.
#[test]
fn a_retried_approval_sends_no_second_confirmation() {
    let fix = Fix::new("confirmation-retry");
    fix.provision_fails();
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.sent().matches("was confirmed").count(),
        1,
        "the first run sends one: {}",
        fix.sent()
    );
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());

    // The builder works on the retry, as in `a_retried_approval_completes`.
    fix.age_failures();
    fix.provision_requires_key();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    assert_eq!(
        fix.sent().matches("was confirmed").count(),
        1,
        "the retry sends no second confirmation: {}",
        fix.sent()
    );
}

/// A confirmation the enqueuer refuses is not recorded as sent: the approval
/// stops before provisioning, the stamp goes back, and the retry sends it. A
/// stamp left behind would provision the applicant with the letter lost.
#[test]
fn a_confirmation_that_cannot_be_sent_is_not_recorded_as_sent() {
    let fix = Fix::new("confirmation-send-fails");
    let sent = fix.path("sent");
    fix.script(
        "enqueuer.sh",
        &format!(
            "#!/bin/sh\nmsg=$(cat)\ncase \"$msg\" in\n*'cancellation period ends'*) echo 'the mail path is broken' >&2; exit 1;;\nesac\nprintf '%s' \"$msg\" >> '{sent}'\n"
        ),
    );
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());

    // No account was made, and the application does not claim the letter left.
    assert!(
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "an approval whose confirmation failed must not provision"
    );
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(app.get("confirmation_at").is_none(), "{app}");
    assert!(!fix.sent().contains("was confirmed"), "{}", fix.sent());

    // With the mail path back, the retry sends the confirmation once and goes on.
    fix.enqueuer_works();
    fix.age_failures();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.sent().matches("was confirmed").count(),
        1,
        "{}",
        fix.sent()
    );
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
}

/// With no outside address the confirmation travels inside the approval mail,
/// so a failed approval enqueue must not leave that notice recorded as sent: the
/// retry would read it as delivered and the confirmation would be lost. The
/// failed line comes back, and the retry sends the approval once with the
/// confirmation in it.
#[test]
fn a_no_address_confirmation_that_cannot_be_sent_is_resent_on_the_retry() {
    let fix = Fix::new("confirmation-none-send-fails");
    let sent = fix.path("sent");
    fix.script(
        "enqueuer.sh",
        &format!(
            "#!/bin/sh\nmsg=$(cat)\ncase \"$msg\" in\n*'has been approved'*) echo 'the mail path is broken' >&2; exit 1;;\nesac\nprintf '%s' \"$msg\" >> '{sent}'\n"
        ),
    );
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());

    // Provisioning happened, but no notice claims the approval mail left.
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    assert!(
        !fix.read("accounts/secretary/notices.jsonl")
            .contains("approval.paid"),
        "{}",
        fix.read("accounts/secretary/notices.jsonl")
    );
    assert!(!fix.sent().contains("was approved"), "{}", fix.sent());

    // With the mail path back, the retry sends the approval once, and the
    // confirmation is in it.
    fix.enqueuer_works();
    fix.age_failures();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let sent = fix.sent();
    assert_eq!(sent.matches("was approved").count(), 1, "{sent}");
    assert!(sent.contains("digital content"), "{sent}");
    assert!(sent.contains("fourteen days"), "{sent}");
    assert!(
        sent.contains("I give notice that I cancel my contract"),
        "{sent}"
    );
    assert_eq!(
        fix.sent().matches("was confirmed").count(),
        0,
        "the confirmation travels in the approval mail: {sent}"
    );
    assert!(
        fix.read("accounts/secretary/notices.jsonl")
            .contains("approval.paid"),
        "{}",
        fix.read("accounts/secretary/notices.jsonl")
    );
    assert!(fix
        .read(&format!("applications/{TOKEN}.json"))
        .contains("approved: an account was made"));
}

/// The upload key the application carried is written where `provision-member.sh`
/// reads it before that script runs, so an approval completes against the real
/// script's contract rather than only against a stub that ignores the key.
#[test]
fn an_approval_writes_the_upload_key_the_builder_reads() {
    let fix = Fix::new("keyfile");
    fix.provision_requires_key();
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).is_empty(),
        "the approval reported an error: {}",
        body(&out)
    );
    let key = fix.read("keys/secretary.pub");
    assert!(key.contains(UPLOAD_KEY), "{key}");
    assert!(
        fix.scripts_log().contains("provision-member.sh secretary"),
        "{}",
        fix.scripts_log()
    );
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    // provision-member.sh wrote both lanes, so the record says both are on and
    // the page does not show a member's working site as off.
    let account = stored_account(&fix, "secretary");
    assert_eq!(account.site_served, Some(true));
    assert_eq!(account.capsule_served, Some(true));
}

/// The space-used sweep reads the quota report once and records it on the
/// account, which is the figure the account page shows against the 5 GB. The
/// second pass inside the hour reads nothing, so the report is cached.
#[test]
fn the_drain_records_space_used_from_the_quota_report() {
    let fix = Fix::new("quota-sweep");
    let record = fix.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    fix.repquota(Some(
        "printf 'User used soft hard grace used soft hard grace\n\
         secretary -- 4096 5242880 5767168 -- 10 0 0\n'",
    ));
    // The filing pass had no account yet, so it wrote no hour stamp. Remove one
    // if a later pass left it, so this pass reads the report afresh.
    let _ = std::fs::remove_file(fix.path("store/quota-check.json"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).is_empty(),
        "the sweep reported an error: {}",
        body(&out)
    );
    let account = stored_account(&fix, "secretary");
    assert_eq!(
        account.space_used,
        Some(4096 * 1024),
        "the used blocks are recorded in bytes"
    );
}

/// An approval publishes the member's mail key into the box keyring the
/// encrypting LMTP reads, named for the localpart and at the mode deploy-mail
/// installs the tracked keys with, before anything can deliver.
#[test]
fn an_approval_publishes_the_mail_key_to_the_keyring() {
    let fix = Fix::new("keyring");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let path = fix.dir.join("keyring/secretary.asc");
    let published = std::fs::read_to_string(&path).expect("the key is in the keyring");
    assert!(
        published.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "{published}"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644,
        "the keyring file carries the mode deploy-mail installs"
    );
}

/// An approval offers the member's mail key to the published set through the
/// script the box owns, after the keyring entry and after the member is built:
/// the keyring is what delivers, so nothing about the publish comes before
/// either, and the forge is never on a path the member waits on.
#[test]
fn an_approval_offers_the_mail_key_for_publication() {
    let fix = Fix::new("publish");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let log = fix.scripts_log();
    let offered = log
        .lines()
        .find(|l| l.starts_with("publish-mail-key.sh "))
        .unwrap_or_else(|| panic!("the mail key was not offered to the published set: {log}"));
    assert_eq!(
        offered,
        format!(
            "publish-mail-key.sh secretary {} {}",
            fix.path("keyring/secretary.asc"),
            fix.path("keyring-token"),
        ),
        "the member, the key file and the token are what the script is handed"
    );
    let member = log.find("provision-member.sh secretary").expect(&log);
    let published = log.find("publish-mail-key.sh").expect(&log);
    assert!(
        member < published,
        "the member is built before the publish: {log}"
    );
}

/// A publish that fails is reported with the member and the key, holds the
/// approval back from its record and its notice rather than from mail, and is
/// retried without touching the keyring file: the seven days the drift check
/// allows an unpublished key are the age of that file, so a retry that rewrote
/// it would restart the window forever.
#[test]
fn a_failed_publish_is_reported_and_retried_without_touching_the_key() {
    let fix = Fix::new("publish-fails");
    fix.publish_fails();
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // The failure is mailed, not printed, and the mail names the member and the
    // key: the drain's alert is where a failure report goes now.
    let sent = fix.sent();
    assert!(sent.contains("publish-mail-key.sh"), "{sent}");
    assert!(
        sent.contains("secretary"),
        "the failure names the member: {sent}"
    );
    assert!(
        sent.contains("1111 2222 3333 4444"),
        "the failure names the key: {sent}"
    );
    assert!(
        body(&out).is_empty(),
        "a mailed failure is not printed as well: {}",
        body(&out)
    );

    // The member is live: the key is in the keyring and delivery works. What is
    // held back is the account record and the notice.
    let key = fix.dir.join("keyring/secretary.asc");
    let written = std::fs::metadata(&key)
        .expect("an approval that fails to publish still serves the key")
        .modified()
        .unwrap();
    assert!(
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "an approval whose publish failed is not finished"
    );
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());

    // The retry moves the backoff out of the way the way a real minute would. It
    // tries the publish again, reports nothing new, and leaves the key alone.
    fix.age_failures();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.scripts_log().matches("publish-mail-key.sh").count(),
        2,
        "the publish is retried: {}",
        fix.scripts_log()
    );
    assert_eq!(
        std::fs::metadata(&key).unwrap().modified().unwrap(),
        written,
        "the keyring file was rewritten, which restarts the drift check's seven days"
    );
    assert_eq!(
        fix.intents().len(),
        1,
        "the intent stays until the publish succeeds"
    );
}

/// An application with no mail key is refused rather than approved into an
/// account whose mail bounces: delivery fails closed without a key.
#[test]
fn an_application_with_no_mail_key_is_refused() {
    let fix = Fix::new("no-mail-key");
    let mut record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    record["mail_keys"] = json!([]);
    std::fs::write(
        fix.dir.join(format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "an account with no mail key must not be made"
    );
    assert!(fix.sent().contains("no mail key"), "{}", fix.sent());
    assert_eq!(fix.intents().len(), 1, "the intent is left in place");
    assert!(
        !fix.dir.join("keyring/secretary.asc").exists(),
        "nothing was published for a keyless application"
    );
}

/// An application with no upload key is still built: mail is unconditional, and
/// the builder is what writes the member's address and allowance. The key file
/// is written only when the application carried one.
#[test]
fn an_approval_without_an_upload_key_still_builds_the_member() {
    let fix = Fix::new("mail-only");
    let record = fix.filed_with("secretary", "cash", &[("rail", "cash")], None, None);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // The builder that writes the member's address and allowance ran, with no
    // key to build hosting from. That is the address path, which every member
    // takes, mail-only included, and it is where provision-member.sh restarts
    // smtpd; only the web lanes and the public tree wait on a key.
    assert!(
        fix.scripts_log().contains("provision-member.sh secretary"),
        "{}",
        fix.scripts_log()
    );
    assert_eq!(
        fix.scripts_log().matches("provision-member.sh").count(),
        1,
        "the builder runs once, address path included: {}",
        fix.scripts_log()
    );
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    assert!(
        fix.names("keys").is_empty(),
        "no key, no key file: {:?}",
        fix.names("keys")
    );
    // No vhost files were written, so the web reload does not run and prints
    // nothing.
    assert!(
        !fix.scripts_log().contains("cron-apply.sh"),
        "a mail-only member has no web files to index: {}",
        fix.scripts_log()
    );
    // No upload key means no lane was written, so the record says nothing about
    // serving rather than claiming a lane is off.
    let account = stored_account(&fix, "secretary");
    assert_eq!(account.site_served, None);
    assert_eq!(account.capsule_served, None);
}

/// A retry completes after a run that died at the builder. The box holds the
/// account the first run made and the journal shows this application started it,
/// so the retry skips add-user.sh, which is not idempotent, and finishes.
#[test]
fn a_retried_approval_completes() {
    let fix = Fix::new("retry");
    // The first run's builder fails, leaving the account half-made: add-user.sh
    // ran and made the box account, no account.json exists, and the intent stays.
    fix.provision_fails();
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());
    assert!(
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "the first run must fail at the builder"
    );
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());
    assert!(
        fix.passwd_file().contains("secretary:"),
        "the box should hold the name the first run made: {}",
        fix.passwd_file()
    );

    // The builder works on the retry; the box oracle and the journal say the
    // account is this application's, so add-user.sh is not run again. The
    // backoff is moved out of the way the way a real minute would.
    fix.age_failures();
    fix.provision_requires_key();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "the retry did not complete: {}",
        body(&out)
    );
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert_eq!(
        fix.scripts_log().matches("add-user.sh").count(),
        1,
        "add-user.sh ran once, not once per pass: {}",
        fix.scripts_log()
    );
}

/// A failing intent is mailed once rather than every pass, and is not retried
/// again inside its backoff window. A stuck intent therefore costs the operator
/// one mail, not one a minute. The mail is the report, so the run prints nothing:
/// cron mails a job's output under a subject of its own, and that copy would be
/// the same news under a subject naming neither the component nor the event.
#[test]
fn a_failing_intent_reports_once_and_backs_off() {
    let fix = Fix::new("stuck");
    // An approve intent for an application that is not on disk: a failure the
    // drain cannot get past on its own.
    fix.decide("approve", "secretary");

    let first = fix.drain();
    assert!(first.status.success(), "{}", body(&first));
    let sent = fix.sent();
    assert!(
        sent.contains("Subject: kyriakon: control: drain failed"),
        "{sent}"
    );
    assert!(sent.contains("there is no application"), "{sent}");
    // The subject names the intent and the body says what to do about it, so the
    // mail is readable without the journal.
    assert!(sent.contains("what to do:"), "{sent}");
    assert!(sent.contains("run: kyriakon-control-drain"), "{sent}");
    assert_eq!(sent.matches("Subject:").count(), 1, "{}", body(&first));
    assert!(
        body(&first).is_empty(),
        "a mailed alert is not printed as well: {}",
        body(&first)
    );
    assert_eq!(
        fix.intents().len(),
        1,
        "the intent is left in place: {:?}",
        fix.intents()
    );
    assert!(fix.journal().contains("\"failed\""), "{}", fix.journal());

    // Inside the backoff window the intent is not retried and nothing is mailed.
    let second = fix.drain();
    assert!(second.status.success(), "{}", body(&second));
    assert!(
        body(&second).is_empty(),
        "a backed-off failure is silent: {}",
        body(&second)
    );
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "one mail, not one a pass"
    );
    assert_eq!(
        fix.journal().matches("\"failed\"").count(),
        1,
        "{}",
        fix.journal()
    );

    let third = fix.drain();
    assert!(
        body(&third).is_empty(),
        "still inside the minute: {}",
        body(&third)
    );
}

/// A drain that cannot mail its alert prints it instead, subject and all. The
/// fallback is what covers the day the mail path is the broken thing: cron still
/// mails what a job prints, so the operator gets the subject even when the
/// enqueuer is what failed.
#[test]
fn an_alert_the_box_cannot_mail_is_printed_instead() {
    let fix = Fix::new("no-mail");
    fix.enqueuer_fails();
    fix.decide("approve", "secretary");

    // The printed alert is the process's stderr, so this is one of the tests
    // that must drive the binary.
    let out = fix.drain_binary();
    assert!(out.status.success(), "{}", body(&out));
    let printed = String::from_utf8_lossy(&out.stderr);
    assert!(
        printed.contains("kyriakon: control: drain failed"),
        "{printed}"
    );
    assert!(printed.contains("there is no application"), "{printed}");
    assert!(printed.contains("could not be mailed"), "{printed}");
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "the alert is one message: {}",
        body(&out)
    );
}

/// A box whose approval key is missing is misconfigured rather than idle. It is
/// mailed once under the same subject every drain failure carries, because a
/// silence here reads exactly like a drain with nothing to do.
#[test]
fn a_missing_approval_key_is_mailed_as_the_drains_own_configuration() {
    let fix = Fix::new("nokey");
    fix.file_application(&fix.filed("secretary", "cash", &[("rail", "cash")]));
    std::fs::remove_file(fix.path("key")).unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let sent = fix.sent();
    assert!(
        sent.contains("Subject: kyriakon: control: drain failed"),
        "{sent}"
    );
    assert!(sent.contains("its own configuration"), "{sent}");
    assert_eq!(sent.matches("Subject:").count(), 1, "{}", body(&out));
    assert!(
        body(&out).is_empty(),
        "mailed, so not printed: {}",
        body(&out)
    );
}

/// An approval whose username is already on the box without this application
/// having started it is refused rather than adopting somebody else's account,
/// and the refusal names the name and leaves the intent in place.
#[test]
fn an_approval_for_a_name_the_box_already_has_is_refused() {
    let fix = Fix::new("taken");
    fix.set_passwd("secretary:x:1000:1000::/home/secretary:/sbin/nologin\n");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "an account the application did not make must not be adopted"
    );
    // The refusal is mailed, and it names the name: which account is which is the
    // operator's decision, so the mail says which name is in use. Nothing is
    // printed for a failure that was mailed.
    let sent = fix.sent();
    assert!(
        sent.contains("Subject: kyriakon: control: drain failed")
            && sent.contains("secretary")
            && sent.contains("in use"),
        "the refusal names what it found: {sent}"
    );
    assert!(
        body(&out).is_empty(),
        "mailed, so not printed: {}",
        body(&out)
    );
    // Nothing was run against the box's account: no add-user, no builder, no
    // release.
    assert!(fix.scripts_log().is_empty(), "{}", fix.scripts_log());
    assert!(
        fix.passwd_file().contains("secretary:"),
        "the box account is untouched"
    );
    assert_eq!(fix.intents().len(), 1, "the intent is left in place");
}

/// The purge leaves a name the box holds alone, whether or not this service
/// wrote a record for it, and clears the declined application away.
#[test]
fn a_purge_leaves_a_name_the_box_holds_alone() {
    let fix = Fix::new("purge-box");
    fix.set_passwd("secretary:x:1000:1000::/home/secretary:/sbin/nologin\n");
    let declined = json!({
        "username": "secretary",
        "status_token": TOKEN,
        "filed_at": "2026-08-01T09:00:00Z",
        "front_end": "web",
        "stage": "declined: no reason given",
        "decided_at": "2026-09-01T00:00:00Z",
        "answers": {},
        "mail_keys": [],
        "rail": "cash",
        "no_charge": false,
        "acceptances": [],
        "question_list": "2026-08-01 abc1234",
    });
    std::fs::write(
        fix.dir.join(format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&declined).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!fix
        .dir
        .join(format!("store/applications/{TOKEN}.json"))
        .exists());
    assert!(
        !fix.scripts_log().contains("delete-user.sh"),
        "the box account's name was released: {}",
        fix.scripts_log()
    );
    assert!(
        fix.passwd_file().contains("secretary:"),
        "the box account is untouched"
    );
}

/// A filed application journals its one `review-sent` line before the send and
/// settles with the remove alone; the settlement must not append a second line
/// for the same application.
#[test]
fn a_filed_application_journals_one_review_line() {
    let fix = Fix::new("review-once");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert_eq!(
        fix.journal().matches("\"outcome\":\"review-sent\"").count(),
        1,
        "the settlement appended the review line a second time: {}",
        fix.journal()
    );
    assert_eq!(
        fix.sent()
            .matches("Subject: kyriakon: control: application filed")
            .count(),
        1,
        "the review was sent twice: {}",
        fix.sent()
    );
}

/// A decision intent with no signature, and one whose signature is over another
/// action, are both refused: `intents/` belongs to the unprivileged half, so an
/// unsigned decision would be root provisioning driven by a file it wrote.
#[test]
fn a_decision_without_a_good_signature_is_refused() {
    let fix = Fix::new("unsigned");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());

    // No action and no signature at all.
    let id = ulid();
    fix.write_intent(
        &id,
        &json!({
            "id": id, "kind": "approve", "filed_at": "2026-10-02T09:00:00Z",
            "application": {"username": "secretary", "status_token": TOKEN},
        }),
    );
    assert!(fix.drain().status.success());
    assert!(
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "an unsigned decision must not provision anything"
    );

    // A signature over a different action than the kind carries.
    let id = ulid();
    fix.write_intent(
        &id,
        &json!({
            "id": id, "kind": "approve", "filed_at": "2026-10-02T09:00:00Z",
            "application": {"username": "secretary", "status_token": TOKEN},
            "action": "decline", "sig": fix.sign_action("decline"),
        }),
    );
    assert!(fix.drain().status.success());
    assert!(
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "a signature over the wrong action must not decide the application"
    );
    // Both are left in place, not silently dropped.
    assert_eq!(fix.intents().len(), 2, "{:?}", fix.intents());
}

/// The record the drain rewrites stays readable by the handler: it keeps the
/// mode and the owner of the directory the handler owns, so the status link goes
/// on answering for its seven days.
#[test]
fn a_decided_record_keeps_the_handler_directorys_owner_and_mode() {
    let fix = Fix::new("owner");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());

    let file = std::fs::metadata(fix.dir.join(format!("store/applications/{TOKEN}.json"))).unwrap();
    let dir = std::fs::metadata(fix.dir.join("store/applications")).unwrap();
    assert_eq!(file.mode() & 0o777, 0o600, "the record stays 0600");
    assert_eq!(
        file.uid(),
        dir.uid(),
        "and owned like the directory it lives in"
    );
    assert_eq!(
        file.gid(),
        dir.gid(),
        "and its group is the directory's group"
    );
}

/// The purge clears a declined application away but never releases a username a
/// live account holds: the front end does not check whether a name is taken, so
/// an approved account and a declined application can share one.
#[test]
fn a_purge_never_releases_a_name_an_account_holds() {
    let fix = Fix::new("collision");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());

    // A second application for the same username, for another token, declined a
    // week and more ago.
    let declined = json!({
        "username": "secretary",
        "status_token": OTHER_TOKEN,
        "filed_at": "2026-08-01T09:00:00Z",
        "front_end": "web",
        "stage": "declined: no reason given",
        "decided_at": "2026-09-01T00:00:00Z",
        "answers": {},
        "mail_keys": [],
        "rail": "cash",
        "no_charge": false,
        "acceptances": [],
        "question_list": "2026-08-01 abc1234",
    });
    std::fs::write(
        fix.dir
            .join(format!("store/applications/{OTHER_TOKEN}.json")),
        serde_json::to_vec_pretty(&declined).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // The declined application is cleared away, the live account is untouched,
    // and no release script ran for a name that is in use.
    assert!(!fix
        .dir
        .join(format!("store/applications/{OTHER_TOKEN}.json"))
        .exists());
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    assert!(
        !fix.scripts_log().contains("delete-user.sh"),
        "a live account's name was released: {}",
        fix.scripts_log()
    );
}

/// The review email is the only copy of the answers and of the links, and the
/// marker that stops a second one is written before the send. A send that
/// returns an error is not a crash, so the next pass must send it, and must not
/// send a second copy once one has gone.
#[test]
fn a_review_email_that_could_not_be_sent_goes_on_the_next_pass() {
    let fix = Fix::new("review-retry");
    fix.enqueuer_fails();
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    fix.drain();

    assert!(fix.journal().contains("review-sent"), "{}", fix.journal());
    assert!(
        fix.sent().is_empty(),
        "the box could not mail, so nothing was sent: {}",
        fix.sent()
    );
    assert_eq!(
        fix.intents().len(),
        1,
        "the intent is left in place: {:?}",
        fix.intents()
    );

    // The mail path works again, and the backoff is what holds the retry back.
    fix.enqueuer_works();
    fix.age_failures();
    fix.drain();
    assert!(
        fix.sent().contains("secretary"),
        "the review email went out on the retry: {}",
        fix.sent()
    );
    assert_eq!(
        fix.intents().len(),
        0,
        "and the intent is cleared: {:?}",
        fix.intents()
    );

    // A re-filed application is not mailed a second time.
    fix.file_application(&record);
    fix.drain();
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "one review email per application: {}",
        fix.sent()
    );
}

/// A decline's own record is what stops a second mail, and it is written after
/// the send, so a send that failed cannot leave a decision saying the applicant
/// had been told when nothing reached them.
#[test]
fn a_decline_that_could_not_be_sent_goes_on_the_next_pass() {
    let fix = Fix::new("decline-retry");
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    fix.drain();
    fix.decide("decline", "secretary");
    fix.enqueuer_fails();
    fix.drain();

    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(
        app["decided_at"].is_null(),
        "nothing claims the applicant was told: {app}"
    );
    assert_eq!(
        fix.intents().len(),
        1,
        "the intent is left in place: {:?}",
        fix.intents()
    );

    fix.enqueuer_works();
    fix.age_failures();
    fix.drain();
    assert!(
        fix.sent().contains("was declined"),
        "the notice went out on the retry: {}",
        fix.sent()
    );
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(
        !app["decided_at"].is_null(),
        "and the decision is recorded after it: {app}"
    );
    assert_eq!(
        fix.intents().len(),
        0,
        "the intent is cleared: {:?}",
        fix.intents()
    );
}

// --- the apply@ key spool ------------------------------------------------

/// A key mailed to apply@ is filed against the draft its subject names, with
/// the fingerprint and verdict the handler would have recorded, and the spool
/// is empty afterwards.
#[test]
fn a_mailed_key_is_filed_against_the_draft_and_the_spool_empties() {
    let fix = Fix::new("mail-key");
    fix.write_draft(TOKEN, &[("username", "secretary"), ("whose", "person")]);
    fix.mail("one", "applicant@example.invalid", TOKEN, GOOD_KEY);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.names("mail/new").is_empty(), "the spool is drained");

    let draft: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    let key = &draft["mail_keys"][0];
    assert_eq!(key["mailbox"], "secretary");
    assert!(
        !key["fingerprint"].as_str().unwrap_or_default().is_empty(),
        "the fingerprint is computed over the mailed material: {draft}"
    );
    assert!(
        !key["verdict"].as_str().unwrap_or_default().is_empty(),
        "the verdict is recorded: {draft}"
    );
}

/// A draft that recorded an address outside the platform takes its mailed key
/// only from that address: another sender cannot replace the key the approval
/// will encrypt future mail to.
#[test]
fn a_mailed_key_from_another_address_does_not_replace_the_drafts_key() {
    let fix = Fix::new("mail-key-wrong-sender");
    fix.write_draft(
        TOKEN,
        &[
            ("username", "secretary"),
            ("whose", "person"),
            ("address_outside", "applicant@example.invalid"),
        ],
    );
    fix.mail("one", "applicant@example.invalid", TOKEN, GOOD_KEY);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let before: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    let key = before["mail_keys"][0].clone();
    assert_eq!(key["mailbox"], "secretary");

    const OTHER_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
                             mAYEAAAAABK4BgQAAAAAEQ==\n\
                             -----END PGP PUBLIC KEY BLOCK-----\n";
    fix.mail("two", "attacker@example.invalid", TOKEN, OTHER_KEY);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let after: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    assert_eq!(
        after["mail_keys"],
        json!([key]),
        "the key was replaced by another sender"
    );
    assert!(
        fix.sent().contains("did not come from the address"),
        "{}",
        fix.sent()
    );
}

/// A draft holds one key per mailbox: a second mailed key is refused rather than
/// replacing the first, even when the draft recorded no outside address to
/// compare the sender against. Nothing in smtpd.conf authenticates the sender,
/// so the refusal is the control.
#[test]
fn a_second_mailed_key_does_not_replace_the_first() {
    let fix = Fix::new("mail-key-second");
    fix.write_draft(TOKEN, &[("username", "secretary"), ("whose", "person")]);
    fix.mail("one", "applicant@example.invalid", TOKEN, GOOD_KEY);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let before: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    let key = before["mail_keys"][0].clone();

    const OTHER_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
                             mAYEAAAAABK4BgQAAAAAEQ==\n\
                             -----END PGP PUBLIC KEY BLOCK-----\n";
    fix.mail("two", "attacker@example.invalid", TOKEN, OTHER_KEY);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let after: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    assert_eq!(after["mail_keys"], json!([key]), "the key was replaced");
    assert!(
        fix.sent().contains("already filed"),
        "the second sender is told why it was refused: {}",
        fix.sent()
    );
}

/// The web form files a person's key under no mailbox; a mailed key takes the
/// account's name. They are the same mailbox, so the mailed key must not replace
/// the form's.
#[test]
fn a_mailed_key_does_not_replace_a_key_the_form_filed() {
    let fix = Fix::new("mail-key-form-first");
    fix.write_draft(TOKEN, &[("username", "secretary"), ("whose", "person")]);
    fix.mail("one", "applicant@example.invalid", TOKEN, GOOD_KEY);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    // Re-file the key the way the web form does: under no mailbox.
    let path = fix.dir.join("store/drafts").join(format!("{TOKEN}.json"));
    let mut draft: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    draft["mail_keys"][0]["mailbox"] = json!("");
    std::fs::write(&path, serde_json::to_vec_pretty(&draft).unwrap()).unwrap();
    let key = draft["mail_keys"][0].clone();

    const OTHER_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
                             mAYEAAAAABK4BgQAAAAAEQ==\n\
                             -----END PGP PUBLIC KEY BLOCK-----\n";
    fix.mail("two", "attacker@example.invalid", TOKEN, OTHER_KEY);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let after: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    assert_eq!(
        after["mail_keys"],
        json!([key]),
        "the form's key was replaced"
    );
    assert!(
        fix.sent().contains("already filed"),
        "the sender is told why it was refused: {}",
        fix.sent()
    );
}

/// One collision does not take the message's other blocks with it: a mailbox
/// with no key yet still gets the key, and the reply names only the refused one.
#[test]
fn a_colliding_block_does_not_discard_the_others() {
    let fix = Fix::new("mail-key-partition");
    fix.write_draft(
        TOKEN,
        &[
            ("whose", "body"),
            ("body_domain", "parish.example"),
            ("body_account_names", "secretary\nhall"),
        ],
    );
    fix.mail(
        "one",
        "applicant@example.invalid",
        TOKEN,
        &format!("secretary\n{GOOD_KEY}"),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    const HALL_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
                            mAYEAAAAABK4BgQAAAAAEQ==\n\
                            -----END PGP PUBLIC KEY BLOCK-----\n";
    fix.mail(
        "two",
        "applicant@example.invalid",
        TOKEN,
        &format!("secretary\n{GOOD_KEY}\nhall\n{HALL_KEY}"),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let after: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    let names: Vec<&str> = after["mail_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["mailbox"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["secretary", "hall"], "the fresh block was filed");
    assert!(
        fix.sent().contains("A key for secretary is already filed"),
        "the reply names the refused mailbox: {}",
        fix.sent()
    );
}

/// The address the draft recorded still files its key, including when the From
/// header carries a display name.
#[test]
fn a_mailed_key_from_the_recorded_address_is_filed() {
    let fix = Fix::new("mail-key-right-sender");
    fix.write_draft(
        TOKEN,
        &[
            ("username", "secretary"),
            ("whose", "person"),
            ("address_outside", "applicant@example.invalid"),
        ],
    );
    fix.mail(
        "one",
        "Applicant <applicant@example.invalid>",
        TOKEN,
        GOOD_KEY,
    );

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let draft: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    assert_eq!(draft["mail_keys"][0]["mailbox"], "secretary");
    assert!(
        !draft["mail_keys"][0]["fingerprint"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "{draft}"
    );
    assert!(fix.sent().is_empty(), "{}", fix.sent());
}

/// A body with more than one mailbox and an unlabelled block is refused, and
/// the reply names the mailboxes the message failed to label.
#[test]
fn an_unlabelled_key_for_two_mailboxes_is_refused_by_name() {
    let fix = Fix::new("mail-unlabelled");
    fix.write_draft(
        TOKEN,
        &[
            ("whose", "body"),
            ("body_domain", "parish.example"),
            ("body_account_names", "secretary\nhall"),
        ],
    );
    fix.mail("one", "applicant@example.invalid", TOKEN, GOOD_KEY);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let sent = fix.sent();
    assert!(sent.contains("secretary"), "{sent}");
    assert!(sent.contains("hall"), "{sent}");
    let draft: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    assert!(
        draft["mail_keys"].as_array().is_none_or(|k| k.is_empty()),
        "nothing was filed: {draft}"
    );
}

/// A token that no longer resolves gets one reply with a fresh link and creates
/// no draft. The second message from the same sender is not answered again.
#[test]
fn a_key_for_a_dead_token_gets_one_reply_and_files_no_draft() {
    let fix = Fix::new("mail-dead-token");
    fix.mail("one", "applicant@example.invalid", OTHER_TOKEN, GOOD_KEY);
    fix.mail("two", "applicant@example.invalid", OTHER_TOKEN, GOOD_KEY);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let drafts: Vec<String> = fix
        .names("drafts")
        .into_iter()
        .filter(|n| n.ends_with(".json"))
        .collect();
    assert!(drafts.is_empty(), "a mail creates no draft: {drafts:?}");
    assert_eq!(
        fix.sent()
            .matches("Subject: Your Kyriakon application key")
            .count(),
        1,
        "one reply per sender:\n{}",
        fix.sent()
    );
    assert!(fix.sent().contains("gemini://signup.kyriakon.net/apply"));
    assert!(fix.names("mail/new").is_empty());
}

/// A message with no key block is not answered at all.
#[test]
fn mail_without_a_key_block_is_not_answered() {
    let fix = Fix::new("mail-no-key");
    fix.mail("one", "applicant@example.invalid", TOKEN, "hello");

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.sent().is_empty(), "{}", fix.sent());
    assert!(fix.names("mail/new").is_empty());
}

/// A TXT answer without the record's marker is not the record: an unrelated
/// string at the SPF, DKIM or DMARC name is an outage.
#[test]
fn a_txt_without_its_marker_is_an_outage() {
    for unmarked in ["SPF", "DKIM", "DMARC"] {
        let fix = Fix::new(&format!("group-dns-unmarked-{unmarked}"));
        fix.resolver_with(None, Some(unmarked));
        fix.file_group(
            "parish.example",
            "parish-secretary",
            &[("secretary", "parish-secretary")],
            &["parish-secretary"],
            None,
        );
        let out = fix.drain();
        assert!(out.status.success(), "{unmarked}: {}", body(&out));
        assert_eq!(
            fix.sent()
                .matches("Subject: The DNS records for parish.example are not resolving")
                .count(),
            1,
            "an unmarked {unmarked} answer was not reported:\n{}",
            fix.sent()
        );
    }
}

/// A forge outage does not stop the rest of the body: every account and table
/// line is made first, and the publish is retried from the intent next pass.
#[test]
fn a_forge_outage_still_makes_every_mailbox() {
    let fix = Fix::new("group-publish-fails");
    fix.publish_fails();
    let mut record = fix.filed_body("warden");
    record["answers"]["body_addresses"] = json!("secretary: own\noffice: own");
    record["answers"]["body_account_names"] = json!("parish-secretary\nparish-office");
    record["mail_keys"] = json!([
        {
            "mailbox": "parish-secretary",
            "fingerprint": "1111 2222 3333 4444",
            "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
            "verdict": "works"
        },
        {
            "mailbox": "parish-office",
            "fingerprint": "5555 6666 7777 8888",
            "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nyy\n-----END PGP PUBLIC KEY BLOCK-----",
            "verdict": "works"
        }
    ]);
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let passwd = fix.passwd_file();
    assert!(passwd.contains("parish-secretary:"), "{passwd}");
    assert!(passwd.contains("parish-office:"), "{passwd}");
    let virtuals = fix.table("virtuals");
    for address in ["secretary", "office"] {
        assert!(
            virtuals.contains(&format!("{address}@parish.example: parish-")),
            "{virtuals}"
        );
    }
    assert!(
        fix.dir
            .join("store/accounts/parish-office/account.json")
            .exists(),
        "the later mailbox was made"
    );
    assert!(
        fix.failed_note().contains("publish-mail-key.sh"),
        "{}",
        fix.failed_note()
    );
    assert!(!fix.intents().is_empty(), "the intent waits for the retry");
}

/// Removing a mailbox takes its account, key and every entry pointing at it,
/// and leaves the group's paid-until date and every other account byte for
/// byte. The closed name is held for ninety days.
#[test]
fn removing_a_mailbox_takes_exactly_its_account_and_entries() {
    let fix = Fix::new("group-remove-mailbox");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
            ("desk", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        None,
    );
    assert!(fix.drain().status.success());
    // The group's renewal date is the group's: set one and make sure removal
    // does not move it.
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["payment"]["paid_until"] = json!("2027-03-01T00:00:00Z");
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    let other = fix.read("accounts/parish-secretary/account.json");

    fix.file_address("parish.example", "remove", "", "parish-office", None, None);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    assert!(
        !fix.passwd_file().contains("parish-office:"),
        "{}",
        fix.passwd_file()
    );
    assert!(
        !fix.dir.join("store/accounts/parish-office").exists(),
        "the account record stayed"
    );
    assert!(
        fix.dir.join("keyring/parish-office.asc").exists(),
        "the box keyring entry stays until the published key goes, as delete-user.sh leaves it"
    );
    let virtuals = fix.table("virtuals");
    assert!(
        !virtuals.contains("office@parish.example") && !virtuals.contains("desk@parish.example"),
        "an entry was left pointing at the removed mailbox: {virtuals}"
    );
    assert!(
        virtuals.contains("secretary@parish.example: parish-secretary"),
        "{virtuals}"
    );

    let after: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(after["accounts"], json!(["parish-secretary"]));
    assert_eq!(
        after["payment"]["paid_until"], "2027-03-01T00:00:00Z",
        "the group's renewal date moved"
    );
    assert_eq!(
        fix.read("accounts/parish-secretary/account.json"),
        other,
        "another account changed"
    );
    assert_eq!(fix.names("holds"), vec!["parish-office.json"]);
    assert!(fix.scripts_log().contains("delete-user.sh parish-office"));
}

/// A valid signature does not cover a swapped mail key: the material is hashed
/// into the payload, so changing it while keeping `sig` is refused and nothing
/// is installed or published.
#[test]
fn a_swapped_mail_key_is_refused() {
    let fix = Fix::new("group-address-key-swap");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let id = fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    let mut filed: Value = serde_json::from_str(&fix.read(&format!("intents/{id}.json"))).unwrap();
    filed["mail_key"]["material"] =
        json!("-----BEGIN PGP PUBLIC KEY BLOCK-----\nattacker\n-----END PGP PUBLIC KEY BLOCK-----");
    std::fs::write(
        fix.dir.join("store/intents").join(format!("{id}.json")),
        serde_json::to_vec_pretty(&filed).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("signature does not verify"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.dir.join("keyring/parish-office.asc").exists(),
        "the swapped key reached the keyring"
    );
    assert!(!fix.passwd_file().contains("parish-office:"));
}

/// A hold that has run out no longer blocks the name, once the account record
/// has gone with the removal.
#[test]
fn an_expired_hold_releases_the_name() {
    let fix = Fix::new("group-hold-expired");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        None,
    );
    assert!(fix.drain().status.success());
    fix.file_address("parish.example", "remove", "", "parish-office", None, None);
    assert!(fix.drain().status.success());
    assert!(!fix.dir.join("store/accounts/parish-office").exists());
    assert_eq!(fix.names("holds"), vec!["parish-office.json"]);

    std::fs::write(
        fix.dir.join("store/holds/parish-office.json"),
        br#"{"username":"parish-office","until":"2020-01-01T00:00:00Z"}"#,
    )
    .unwrap();
    fix.file_address(
        "parish.example",
        "add-mailbox",
        "desk",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());
    assert!(fix.passwd_file().contains("parish-office:"));
    assert!(fix.dir.join("store/accounts/parish-office").exists());
    assert!(fix
        .table("virtuals")
        .contains("desk@parish.example: parish-office"));
}

/// A suspension records the reason where the account page reads it, stops the
/// three access paths through the shared lapse script, and sends one notice that
/// names the reason and how to answer it. Running it twice sends one notice.
#[test]
fn a_suspension_records_the_reason_and_sends_one_notice() {
    let fix = Fix::new("suspend-notice");
    let _token = approved_paid(&fix, "secretary", "cash");
    let reason = "Published material is outside the acceptable use policy.";
    let out = fix.ctl(&["suspend", "secretary", "--reason", reason]);
    assert!(out.status.success(), "{}", body(&out));

    let account = fix.account("secretary");
    assert_eq!(account["state"], json!("suspended"), "{account}");
    assert_eq!(account["suspension_reason"], json!(reason), "{account}");
    assert!(
        fix.scripts_log().contains("lapse-user.sh secretary"),
        "the access paths stop through the shared script: {}",
        fix.scripts_log()
    );
    let sent = fix.sent();
    assert!(sent.contains(reason), "the notice names the reason: {sent}");
    assert!(
        sent.contains("admin@kyriakon.net") && sent.contains("answer"),
        "the notice says how to answer: {sent}"
    );
    let notices = fix.read("accounts/secretary/notices.jsonl");
    assert_eq!(
        notices.matches("account.suspended").count(),
        1,
        "one notice: {notices}"
    );

    // The same transition twice sends one notice and leaves the account as it is.
    let out = fix.ctl(&["suspend", "secretary", "--reason", reason]);
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.account("secretary")["state"], json!("suspended"));
    assert_eq!(
        fix.read("accounts/secretary/notices.jsonl")
            .matches("account.suspended")
            .count(),
        1,
        "still one notice"
    );
}

/// A suspension starts the same forty-day grace as a lapse, journals itself, and
/// its final week sends the suspension's own notice naming the reason and how to
/// answer. `resume` brings the account back and clears the clock.
#[test]
fn a_suspension_starts_the_grace_and_resume_clears_it() {
    let fix = Fix::new("suspend-grace");
    let _token = approved_paid(&fix, "secretary", "cash");
    let reason = "Published material is outside the acceptable use policy.";
    let out = fix.ctl(&["suspend", "secretary", "--reason", reason]);
    assert!(out.status.success(), "{}", body(&out));

    let account = fix.account("secretary");
    assert_eq!(account["state"], json!("suspended"), "{account}");
    assert_eq!(
        account["grace_until"],
        json!(kyriakon_control_core::util::date_after_days(40)),
        "the suspension promises a grace, so it starts the same one: {account}"
    );
    assert!(
        fix.journal().contains("suspend-secretary-"),
        "{}",
        fix.journal()
    );
    assert!(
        fix.journal().contains("\"applying\""),
        "the suspension journals before it acts: {}",
        fix.journal()
    );

    // The final week: the suspension's own notice, naming the reason and the
    // way to answer, and not the payment lapse's words.
    let mut account = fix.account("secretary");
    account["grace_until"] = json!(kyriakon_control_core::util::date_after_days(6));
    std::fs::write(
        fix.dir.join("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();
    assert!(fix.drain().status.success());
    let notices = fix.read("accounts/secretary/notices.jsonl");
    assert_eq!(
        notices.matches("account.suspended.final").count(),
        1,
        "{notices}"
    );
    assert!(notices.contains(reason), "the reason again: {notices}");
    assert!(
        fix.sent().contains("admin@kyriakon.net"),
        "how to answer: {}",
        fix.sent()
    );
    assert!(
        !notices.contains("will be deleted in seven days"),
        "the payment lapse's final notice is not the suspension's: {notices}"
    );

    // Resume: the access paths come back, the state is active, and the reason
    // and grace are gone.
    let out = fix.ctl(&["resume", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let account = fix.account("secretary");
    assert_eq!(account["state"], json!("active"), "{account}");
    assert!(account.get("suspension_reason").is_none(), "{account}");
    assert!(account.get("grace_until").is_none(), "{account}");
    assert!(
        fix.scripts_log()
            .contains("lapse-user.sh --restore secretary"),
        "{}",
        fix.scripts_log()
    );
    assert!(
        fix.journal().contains("resume-secretary-"),
        "{}",
        fix.journal()
    );

    // A resumed account is not deleted on the old clock.
    assert!(fix.drain().status.success());
    assert!(fix.dir.join("store/accounts/secretary").exists());

    // A suspension left unanswered runs out: the deletion transition erases it.
    let out = fix.ctl(&["suspend", "secretary", "--reason", reason]);
    assert!(out.status.success(), "{}", body(&out));
    let mut account = fix.account("secretary");
    account["grace_until"] = json!(kyriakon_control_core::util::date_after_days(-1));
    std::fs::write(
        fix.dir.join("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir.join("store/accounts/secretary").exists(),
        "the suspended account's grace ended and it was not deleted"
    );
    assert!(
        fix.journal().contains("delete-secretary-"),
        "{}",
        fix.journal()
    );
}

/// A corrupt account record is reported and skipped, not read as an account
/// that has gone: the healthy account beside it still lapses on time, and the
/// failure is mailed once rather than every minute.
#[test]
fn a_corrupt_account_record_is_reported_without_stopping_another_sweep() {
    let fix = Fix::new("corrupt-account-sweep");
    approved_paid(&fix, "secretary", "cash");
    let mut account = fix.account("secretary");
    account["payment"]["window"]["closes_at"] = json!("2020-01-01T00:00:00Z");
    std::fs::write(
        fix.path("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();

    // A second account whose record a later write damages. The sweep lists it,
    // so it reaches the broken file before it reaches the healthy window.
    fix.page_account("broken", json!({}));
    std::fs::write(
        fix.path("store/accounts/broken/account.json"),
        b"{\"version\": 1, \"username\": \"brok",
    )
    .unwrap();

    let out = fix.drain();
    assert!(
        out.status.success(),
        "one damaged record stopped the pass: {}",
        body(&out)
    );

    // The healthy account settles: the closed window lapsed it.
    let account = fix.account("secretary");
    assert_eq!(account["state"], json!("lapsed"), "{account}");
    assert_eq!(
        account["payment"]["window"]["state"],
        json!("closed"),
        "{account}"
    );
    assert!(
        fix.scripts_log().contains("lapse-user.sh secretary"),
        "{}",
        fix.scripts_log()
    );

    // The damaged record is named once, journalled and mailed once.
    let sent = fix.sent();
    assert!(
        sent.contains("accounts/broken/account.json does not parse"),
        "{sent}"
    );
    assert_eq!(
        sent.matches("accounts/broken/account.json does not parse")
            .count(),
        1,
        "{sent}"
    );
    assert!(
        fix.journal()
            .contains("accounts/broken/account.json does not parse"),
        "{}",
        fix.journal()
    );
}

/// `show` and `approve` name the corrupt application record and the parse
/// error, rather than reporting that there is no application for the name.
#[test]
fn a_corrupt_application_record_is_named_by_show_and_approve() {
    let fix = Fix::new("corrupt-application");
    fix.filed("alice", "cash", &[("rail", "cash")]);
    std::fs::write(
        fix.path(&format!("store/applications/{TOKEN}.json")),
        b"{\"username\": \"alice\", \"status_to",
    )
    .unwrap();

    for args in [["show", "alice"], ["approve", "alice"]] {
        let out = fix.ctl(&args);
        let text = body(&out);
        assert!(!out.status.success(), "{}: {text}", args.join(" "));
        assert!(
            text.contains(&format!("applications/{TOKEN}.json does not parse")),
            "{}: {text}",
            args.join(" ")
        );
        assert!(
            !text.contains("no application for alice"),
            "{}: {text}",
            args.join(" ")
        );
    }
}

/// A corrupt application is reported and skipped; the declined application
/// beside it still purges on the same pass.
#[test]
fn a_corrupt_application_does_not_stop_another_applications_purge() {
    let fix = Fix::new("corrupt-application-purge");
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("decline", "secretary");
    assert!(fix.drain().status.success());

    // Move the decision a week back, as a week of cron would.
    let mut app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    app["decided_at"] = json!("2026-09-01T00:00:00Z");
    std::fs::write(
        fix.path(&format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&app).unwrap(),
    )
    .unwrap();
    // An unrelated record that sorts before it and does not parse.
    std::fs::write(
        fix.path("store/applications/000-broken.json"),
        b"{\"username\": \"nobody",
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !std::path::Path::new(&fix.path(&format!("store/applications/{TOKEN}.json"))).exists(),
        "the healthy decline was not purged"
    );
    assert!(
        fix.scripts_log().contains("delete-user.sh secretary"),
        "{}",
        fix.scripts_log()
    );
    assert!(
        fix.sent()
            .contains("applications/000-broken.json does not parse"),
        "{}",
        fix.sent()
    );
}

/// The application scan cannot tell a corrupt file's username, so it fails with
/// the file named rather than reporting that the requested name has none.
#[test]
fn a_corrupt_application_beside_the_requested_one_is_named_by_show() {
    let fix = Fix::new("corrupt-application-sibling");
    fix.filed("alice", "cash", &[("rail", "cash")]);
    std::fs::write(fix.path("store/applications/000-broken.json"), b"{not json").unwrap();

    let out = fix.ctl(&["show", "alice"]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(
        body(&out).contains("applications/000-broken.json does not parse"),
        "{}",
        body(&out)
    );
    assert!(
        !body(&out).contains("no application for alice"),
        "{}",
        body(&out)
    );
}

/// A declinee whose account record is damaged is reported and left for the next
/// pass; the healthy account whose closing window has ended is still deleted in
/// the same pass.
#[test]
fn a_damaged_declinee_does_not_stop_a_healthy_closing_deletion() {
    let fix = Fix::new("purge-declined-damaged");
    fix.page_account(
        "secretary",
        json!({
            "state": "closing",
            "closing_until": kyriakon_control_core::util::date_after_days(-1),
        }),
    );
    // A declined application whose week is up, for a name whose account record
    // is damaged: the purge cannot tell whether releasing the name would take an
    // account with it.
    let record = fix.filed("broken", "cash", &[("rail", "cash")]);
    let mut app = record.clone();
    app["stage"] = json!("declined");
    app["decided_at"] = json!("2026-09-01T00:00:00Z");
    fix.rewrite_record(&app);
    std::fs::create_dir_all(fix.dir.join("store/accounts/broken")).unwrap();
    std::fs::write(
        fix.dir.join("store/accounts/broken/account.json"),
        b"{\"version\": 1, \"username\": \"brok",
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    // The healthy closing account is gone.
    assert!(
        !fix.dir.join("store/accounts/secretary").exists(),
        "the healthy closing account was not deleted"
    );
    assert!(
        fix.scripts_log().contains("delete-user.sh secretary"),
        "{}",
        fix.scripts_log()
    );
    // The damaged declinee is named once and its application is kept for the
    // pass after the record is fixed.
    assert!(
        std::path::Path::new(&fix.path(&format!("store/applications/{TOKEN}.json"))).exists(),
        "the damaged declinee's application was purged on a guess"
    );
    let sent = fix.sent();
    assert!(
        sent.contains("accounts/broken/account.json does not parse"),
        "{sent}"
    );
    assert!(
        fix.journal()
            .contains("accounts/broken/account.json does not parse"),
        "{}",
        fix.journal()
    );
}

/// A self-service export from the account page closes its own request line: the
/// bundle's path, the day it was delivered and what was done are on the same
/// line, and the operator's docket does not list the member's own ask as open or
/// overdue. A retry after a crash before the journal line finishes the same
/// line rather than appending a second request.
#[test]
fn a_page_export_records_and_closes_its_request_line() {
    let fix = Fix::new("data-export-request-closed");
    fix.member_tree("secretary");
    approved_paid(&fix, "secretary", "cash");
    let id = fix.file_page_action("export", "secretary", json!({}));
    let filed = fix.read(&format!("intents/{id}.json"));
    assert!(fix.drain().status.success());

    let record = fix.read("accounts/secretary/requests.jsonl");
    let lines: Vec<Value> = record
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 1, "{record}");
    let line = &lines[0];
    assert_eq!(line["id"], id.as_str());
    assert_eq!(line["kind"], "access");
    assert_eq!(line["done_at"], line["received"], "{line}");
    assert_eq!(
        line["done"], "delivered to the member's export directory",
        "{line}"
    );
    assert!(
        line["bundle"].as_str().unwrap().contains("export/"),
        "{line}"
    );
    let out = fix.ctl(&["request", "list"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("no open requests"), "{}", body(&out));

    // A pass that delivered and closed but crashed before its journal line:
    // the intent and its request line are already there, so the retry delivers
    // again and leaves the close alone.
    let journal = fix.journal();
    let kept: String = journal
        .lines()
        .filter(|line| !line.contains(&format!("\"intent\":\"{id}\"")))
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(fix.dir.join("store/journal.jsonl"), kept).unwrap();
    std::fs::write(
        fix.dir.join("store/intents").join(format!("{id}.json")),
        filed,
    )
    .unwrap();
    // One export per second names one directory.
    std::thread::sleep(std::time::Duration::from_secs(1));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.journal().contains("\"outcome\":\"failed\""),
        "{}",
        fix.journal()
    );
    let record = fix.read("accounts/secretary/requests.jsonl");
    let again: Vec<Value> = record
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(again.len(), 1, "the retry appended a request: {record}");
    assert_eq!(again[0]["done_at"], line["done_at"], "{record}");
    let out = fix.ctl(&["request", "list"]);
    assert!(body(&out).contains("no open requests"), "{}", body(&out));
}

/// A delivery that slips past the day the request was recorded closes on the
/// day it was delivered, so a late answer does not read as on time.
#[test]
fn a_delayed_export_closes_on_the_day_it_delivers() {
    let fix = Fix::new("data-export-delayed-close");
    fix.member_tree("secretary");
    approved_paid(&fix, "secretary", "cash");
    let id = fix.file_page_action("export", "secretary", json!({}));
    // The request was filed two days before this pass delivers it.
    let out = fix.ctl(&[
        "request",
        "record",
        "--username",
        "secretary",
        "--kind",
        "access",
        "--received",
        "2020-01-01",
        "--evidence",
        "the account page's password check",
        "--identity",
        "password",
        "--id",
        &id,
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let record = fix.read("accounts/secretary/requests.jsonl");
    let line: Value = serde_json::from_str(record.lines().next().unwrap()).unwrap();
    assert_eq!(line["received"], "2020-01-01", "{line}");
    assert_eq!(
        line["done_at"],
        kyriakon_control_core::util::date_after_days(0),
        "{line}"
    );
    assert_ne!(line["done_at"], "2020-01-01", "{line}");
}
