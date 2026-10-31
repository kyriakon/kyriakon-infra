use crate::common::*;

/// A free account that gave an address outside the platform has its yearly note
/// sent there, not to the mailbox it may no longer read.
#[test]
fn a_free_note_goes_to_the_outside_address_when_there_is_one() {
    let fix = Fix::new("free-anniversary-outside");
    let dir = fix.dir.join("store/accounts/secretary");
    std::fs::create_dir_all(&dir).unwrap();
    let account = json!({
        "version": 1, "username": "secretary", "state": "active",
        "decision": "approve", "decided_at": "2019-01-01T09:00:00Z",
        "rail": "no_charge", "no_charge": true,
        "created_at": "2019-01-01T09:00:00Z",
        "outside_address": "warden@example.invalid",
    });
    std::fs::write(
        dir.join("account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();

    assert!(fix.drain().status.success());
    let notices = fix.read("accounts/secretary/notices.jsonl");
    assert!(notices.contains("free.anniversary"), "{notices}");
    assert!(notices.contains("warden@example.invalid"), "{notices}");
    assert!(!notices.contains("secretary@kyriakon.net"), "{notices}");
}

/// The confirmation the spec promises: to the address the applicant gave,
/// restating both things the second checkbox recorded and quoting every document
/// with its version, before the account exists.
#[test]
fn an_approval_sends_the_confirmation_to_the_outside_address() {
    let fix = Fix::new("confirmation");
    let mut record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    record["acceptances"] = json!([
        {"document": "terms", "version": "2026-10-01 abc1234"},
        {"document": "privacy", "version": "2026-09-01 def5678"},
    ]);
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    assert_eq!(
        sent.matches("Subject: Your application to kyriakon.net was confirmed")
            .count(),
        1,
        "{sent}"
    );
    assert!(sent.contains("To: applicant@example.invalid"), "{sent}");
    assert!(sent.contains("digital content"), "{sent}");
    assert!(sent.contains("terms: 2026-10-01 abc1234"), "{sent}");
    assert!(sent.contains("privacy: 2026-09-01 def5678"), "{sent}");
    assert!(sent.contains("fourteen days"), "{sent}");
    assert!(sent.contains("admin@kyriakon.net"), "{sent}");
    assert!(
        sent.contains("cancel for any reason, or none"),
        "the right is stated plainly: {sent}"
    );

    // The stamp is on the application record, where a retry reads it.
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(app["confirmation_at"].is_string(), "{app}");
}

/// An approval with no address outside the platform sends no confirmation and
/// still provisions: before the account exists there is no mailbox to reach, so
/// the status page is the applicant's record instead.
#[test]
fn an_approval_without_an_outside_address_sends_no_confirmation() {
    let fix = Fix::new("confirmation-none");
    add_user_asks_whether_the_confirmation_left(&fix);
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    let log = fix.scripts_log();
    assert!(
        log.contains("confirmation-missing"),
        "a confirmation left before provisioning: {log}"
    );
    assert!(!fix.sent().contains("digital content"), "{}", fix.sent());
    assert!(
        !fix.sent().contains("was confirmed"),
        "no confirmation was sent: {}",
        fix.sent()
    );
}

/// A body's approval sends the applicant the same confirmation before any of the
/// body's accounts exist, as the person path does.
#[test]
fn a_body_approval_sends_the_confirmation() {
    let fix = Fix::new("group-confirmation");
    let mut record = fix.filed_body("warden");
    record["outside_address"] = json!("warden@example.invalid");
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    assert_eq!(sent.matches("was confirmed").count(), 1, "{sent}");
    assert!(sent.contains("To: warden@example.invalid"), "{sent}");
    assert!(sent.contains("terms: 2026-10-01 abc1234"), "{sent}");
    assert!(sent.contains("fourteen days"), "{sent}");
}

/// An address the applicant wrote cannot become a second recipient or a header
/// line when the decision email is built.
#[test]
fn an_address_that_could_inject_a_header_is_refused() {
    for (i, bad) in ["x,attacker@evil.example", "x\nBcc: attacker@evil.example"]
        .iter()
        .enumerate()
    {
        let fix = Fix::new(&format!("address-{i}"));
        let record = fix.filed_with(
            "secretary",
            "cash",
            &[("rail", "cash")],
            Some(bad),
            Some((UPLOAD_KEY, "works")),
        );
        fix.file_application(&record);
        assert!(fix.drain().status.success());
        fix.decide("approve", "secretary");
        let out = fix.drain();
        assert!(out.status.success(), "{}", body(&out));
        assert!(
            !fix.dir
                .join("store/accounts/secretary/account.json")
                .exists(),
            "{bad:?} must not decide the application"
        );
        assert!(
            !fix.sent()
                .lines()
                .any(|l| l.starts_with("To:") && l.contains("attacker")),
            "an injected recipient became a header: {}",
            fix.sent()
        );
        assert_eq!(
            fix.intents().len(),
            1,
            "the intent is left for the reviewer"
        );
    }
}

/// A decline with no address outside the platform sends nothing: no mailbox was
/// created for it, so the status link is the channel, and the decision is still
/// recorded on the application.
#[test]
fn a_decline_with_no_outside_address_sends_nothing() {
    let fix = Fix::new("decline-silent");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "the review email"
    );

    fix.decide("decline", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "no decline email was sent"
    );
    assert!(!fix.sent().contains("declined"), "{}", fix.sent());
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(app["decided_at"].is_string(), "{app}");
    assert!(
        app["stage"].as_str().unwrap().starts_with("declined"),
        "{app}"
    );
}

/// A body's key page is one page per mailbox, so the message has to say which
/// mailbox each block belongs to. Two labelled blocks file both.
#[test]
fn two_labelled_keys_for_a_body_are_both_filed() {
    let fix = Fix::new("mail-body-keys");
    fix.write_draft(
        TOKEN,
        &[
            ("whose", "body"),
            ("body_domain", "parish.example"),
            ("body_account_names", "secretary\nhall"),
        ],
    );
    let message = format!("secretary@parish.example\n{GOOD_KEY}\nhall@parish.example\n{GOOD_KEY}");
    fix.mail("one", "applicant@example.invalid", TOKEN, &message);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.names("mail/new").is_empty());

    let draft: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    let keys = draft["mail_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "{draft}");
    assert_eq!(keys[0]["mailbox"], "secretary");
    assert_eq!(keys[1]["mailbox"], "hall");
}

/// A live token files its key even when the message has no usable From. The
/// reply address is only needed on the paths that answer.
#[test]
fn a_key_with_no_reply_address_is_still_filed() {
    let fix = Fix::new("mail-no-from");
    fix.write_draft(TOKEN, &[("username", "secretary"), ("whose", "person")]);
    fix.mail("one", "", TOKEN, GOOD_KEY);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.sent().is_empty(), "nothing to answer: {}", fix.sent());
    let draft: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    assert_eq!(draft["mail_keys"][0]["mailbox"], "secretary", "{draft}");
}

/// One `provision-group` intent makes the group record, the mailbox account, the
/// two virtual entries, the mail domain line and the site owner's upload key.
#[test]
fn a_group_intent_provisions_its_record_accounts_and_addresses() {
    let fix = Fix::new("group");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-secretary"),
        ],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(group["domain"], "parish.example");
    assert_eq!(group["name"], "Parish of Example");
    assert_eq!(group["kind"], "parish");
    assert_eq!(group["accounts"], json!(["parish-secretary"]));
    assert_eq!(group["site_owner"], "parish-secretary");
    assert_eq!(group["payment"]["rail"], "cash");
    assert_eq!(group["payment"]["no_charge"], false);

    // The account is the mailbox's, with a group reference and no paid-until
    // field of its own.
    let account = fix.account("parish-secretary");
    assert_eq!(account["group"], "parish.example");
    assert!(account.get("payment").is_none(), "{account}");
    assert!(
        fix.passwd_file().contains("parish-secretary:"),
        "{}",
        fix.passwd_file()
    );

    // One mail domain line and one virtual entry per address, on the body's
    // domain rather than the platform's.
    let domains = fix.table("mail_domains");
    assert_eq!(
        domains.lines().filter(|l| *l == "parish.example").count(),
        1,
        "{domains}"
    );
    let virtuals = fix.table("virtuals");
    for address in ["secretary", "office"] {
        let key = format!("{address}@parish.example:");
        assert_eq!(
            virtuals.lines().filter(|l| l.starts_with(&key)).count(),
            1,
            "{virtuals}"
        );
        assert!(
            virtuals.contains(&format!("{key} parish-secretary")),
            "{virtuals}"
        );
    }

    // The block's upload key is where provision-member.sh reads it.
    let key = fix.read("keys/parish-secretary.pub");
    assert!(key.contains(UPLOAD_KEY), "{key}");

    let log = fix.scripts_log();
    assert!(log.contains("add-user.sh parish-secretary"), "{log}");
    assert!(
        log.contains("provision-member.sh parish-secretary"),
        "{log}"
    );
    // The body's hosting is the domain's, not the site owner's member name, and
    // every lane is given the account whose tree the vhosts root.
    for lane in [
        "provision-group-web.sh",
        "provision-group-capsule.sh",
        "provision-group-acme.sh",
    ] {
        assert!(
            log.contains(&format!("{lane} parish.example parish-secretary")),
            "{lane} did not run with the domain and site owner: {log}"
        );
    }
    assert!(log.contains("cron-apply.sh --web"), "{log}");
}

/// The same intent applied a second time leaves one account, one virtual entry
/// per address, one public tree and one upload key: the property a retry after a
/// crash depends on.
#[test]
fn a_group_intent_applied_twice_leaves_one_of_each() {
    let fix = Fix::new("group-twice");
    let id = fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-secretary"),
        ],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());

    // The same intent again, as a crash before the delete leaves it.
    fix.write_group(
        &id,
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-secretary"),
        ],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert_eq!(
        fix.scripts_log().matches("add-user.sh").count(),
        1,
        "add-user.sh ran once, not once per pass: {}",
        fix.scripts_log()
    );
    assert_eq!(
        fix.passwd_file()
            .lines()
            .filter(|l| l.starts_with("parish-secretary:"))
            .count(),
        1,
        "{}",
        fix.passwd_file()
    );
    let virtuals = fix.table("virtuals");
    for address in ["secretary", "office"] {
        assert_eq!(
            virtuals
                .lines()
                .filter(|l| l.starts_with(&format!("{address}@parish.example:")))
                .count(),
            1,
            "{virtuals}"
        );
    }
    assert_eq!(
        fix.table("mail_domains")
            .lines()
            .filter(|l| *l == "parish.example")
            .count(),
        1
    );
    assert_eq!(fix.names("accounts"), vec!["parish-secretary"]);
    // The key file holds one key, and the tree is the builder's to keep
    // idempotent: it ran against the same account, not a second one.
    let key = fix.read("keys/parish-secretary.pub");
    assert_eq!(
        key.lines().filter(|l| !l.trim().is_empty()).count(),
        1,
        "{key}"
    );
    assert_eq!(
        fix.scripts_log()
            .matches("provision-member.sh parish-secretary")
            .count(),
        2,
        "the builder is idempotent, so a retry runs it again"
    );
}

/// A group whose account name is held back, or already taken, is refused and
/// the intent stays in place for the operator to fix.
#[test]
fn a_group_intent_for_a_reserved_name_is_refused() {
    let fix = Fix::new("group-reserved");
    fix.reserve("parish-secretary");
    let id = fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("parish-secretary"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.dir
            .join("store/groups/parish.example/group.json")
            .exists(),
        "a refused group makes no record"
    );
    assert!(!fix.passwd_file().contains("parish-secretary:"));
}

#[test]
fn a_group_intent_for_a_taken_name_is_refused() {
    let fix = Fix::new("group-taken");
    // An account made some other way: the box has it and the store does not.
    fix.set_passwd("parish-secretary:x:1000:1000::/home/parish-secretary:/sbin/nologin\n");
    let id = fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("already in use on this box"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.dir
            .join("store/groups/parish.example/group.json")
            .exists(),
        "a refused group makes no record"
    );
}

/// The approval of a body's application files and applies the group intent in
/// the same pass: the mailboxes are the address table's, and the applicant's own
/// username is not made into an account.
#[test]
fn a_body_approval_makes_the_group_and_its_mailboxes() {
    let fix = Fix::new("group-approval");
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(group["accounts"], json!(["parish-secretary"]));
    assert_eq!(group["site_owner"], "parish-secretary");
    assert_eq!(group["kind"], "parish");
    assert_eq!(group["payment"]["rail"], "cash");

    assert!(fix
        .dir
        .join("store/accounts/parish-secretary/account.json")
        .exists());
    assert!(
        !fix.dir.join("store/accounts/warden/account.json").exists(),
        "the accountable person is not a mailbox"
    );
    assert!(fix
        .table("virtuals")
        .contains("office@parish.example: parish-secretary"));
    assert!(fix.passwd_file().contains("parish-secretary:"));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    // The application is decided, so a replay changes nothing.
    assert!(fix.journal().contains("\"applied\""), "{}", fix.journal());
}

/// A box whose deploy left a recipe placeholder refuses a body's approval
/// before the journal line and before any account or table is made.
#[test]
fn an_approval_with_a_placeholder_dns_value_makes_nothing() {
    let fix = Fix::new("group-dns-placeholder");
    let cfg = std::fs::read_to_string(fix.config())
        .unwrap()
        .replace("ipv4 = \"192.0.2.10\"", "ipv4 = \"REPLACE_ME_IPV4\"");
    std::fs::write(fix.config(), cfg).unwrap();
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        !fix.dir
            .join("store/groups/parish.example/group.json")
            .exists(),
        "a refused approval makes no group record"
    );
    assert!(
        !fix.dir
            .join("store/accounts/parish-secretary/account.json")
            .exists(),
        "and no mailbox account"
    );
    assert!(!fix.passwd_file().contains("parish-secretary:"));
    assert!(!fix.table("mail_domains").contains("parish.example"));
}

/// A body's approval carries the DNS recipe, generated from its own domain and
/// the platform's published values, because mail and the website do not work
/// until the body creates those records.
#[test]
fn a_body_approval_email_carries_the_dns_recipe() {
    let fix = Fix::new("group-dns-recipe-email");
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    for needle in [
        "10 mail.kyriakon.net.",
        "192.0.2.10",
        "2001:db8::10",
        "v=spf1 mx ip6:2001:db8::10 -all",
        "mail._domainkey",
        "v=DKIM1; k=rsa; p=examplepublickey",
        "v=DMARC1; p=none; rua=mailto:dmarc@kyriakon.net",
        "does not host your zone",
        "cannot set a reverse DNS record for parish.example",
        "can only observe your records",
    ] {
        assert!(sent.contains(needle), "{needle:?} missing:\n{sent}");
    }
    // A body has no account of the applicant's own, so the fallback is the site
    // owner's mailbox on the body's domain.
    assert!(
        sent.contains("To: parish-secretary@parish.example"),
        "{sent}"
    );
}

/// A broken zone is notified once per outage to the application's DNS contact,
/// the state records that it was, and the group record is not touched.
#[test]
fn a_broken_zone_notifies_the_dns_contact_once() {
    let fix = Fix::new("group-dns-broken");
    fix.resolver(Some("MX"));
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let group = fix.read("groups/parish.example/group.json");
    let subject = "Subject: The DNS records for parish.example are not resolving";
    let sent = fix.sent();
    assert_eq!(
        sent.matches(subject).count(),
        1,
        "one notice per outage:\n{sent}"
    );
    assert!(sent.contains("To: warden@example.invalid"), "{sent}");
    assert!(
        fix.dir
            .join("store/groups/parish.example/dns-check.json")
            .exists(),
        "the check is recorded"
    );
    let notices = fix.read("accounts/parish-secretary/notices.jsonl");
    assert!(
        notices.contains("\"type\":\"dns.broken\""),
        "the account records the notice: {notices}"
    );
    let queries = fix
        .scripts_log()
        .lines()
        .filter(|l| l.starts_with("dig "))
        .count();
    assert_eq!(
        queries, 1,
        "the first record that answers nothing stops the check"
    );

    // The next pass is not due, so it neither queries nor sends again, and the
    // group record still carries no DNS values.
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.sent().matches(subject).count(),
        1,
        "a second pass sends none:\n{}",
        fix.sent()
    );
    assert_eq!(
        fix.scripts_log()
            .lines()
            .filter(|l| l.starts_with("dig "))
            .count(),
        1,
        "not due, so the resolver is not run again"
    );
    assert_eq!(fix.read("groups/parish.example/group.json"), group);
}

/// With no DNS contact in the application copy, the notice goes to the
/// accountable address the applicant gave.
#[test]
fn a_broken_zone_falls_back_to_the_accountable_address() {
    let fix = Fix::new("group-dns-fallback");
    fix.resolver(Some("MX"));
    let mut record = fix.filed_body("warden");
    record["answers"]["body_dns_contact"] = json!("");
    record["outside_address"] = json!("warden@example.invalid");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    assert_eq!(
        sent.matches("Subject: The DNS records for parish.example are not resolving")
            .count(),
        1,
        "{sent}"
    );
    assert!(sent.contains("To: warden@example.invalid"), "{sent}");
}

/// Every row the recipe publishes is observed: a missing `www` name, AAAA, SPF,
/// DKIM or DMARC record is an outage even when the MX and apex A still answer.
#[test]
fn each_missing_recipe_row_is_an_outage() {
    for missing in [
        "MX",
        "A-apex",
        "A-www",
        "AAAA-apex",
        "AAAA-www",
        "SPF",
        "DKIM",
        "DMARC",
    ] {
        let fix = Fix::new(&format!("group-dns-missing-{missing}"));
        fix.resolver(Some(missing));
        fix.file_group(
            "parish.example",
            "parish-secretary",
            &[("secretary", "parish-secretary")],
            &["parish-secretary"],
            None,
        );
        let out = fix.drain();
        assert!(out.status.success(), "{missing}: {}", body(&out));
        assert_eq!(
            fix.sent()
                .matches("Subject: The DNS records for parish.example are not resolving")
                .count(),
            1,
            "{missing} was not reported as an outage:\n{}",
            fix.sent()
        );
    }
}

/// A complete set of the rows the recipe names is not an outage.
#[test]
fn a_complete_recipe_sends_no_dns_notice() {
    let fix = Fix::new("group-dns-complete");
    fix.resolver(None);
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.sent().contains("not resolving"),
        "a healthy zone was reported:\n{}",
        fix.sent()
    );
}

/// A resolver that cannot answer says nothing about the body's zone. It must not
/// mail the contact to repair a zone that may be healthy, and it must not record
/// an observation it did not make.
#[test]
fn a_resolver_that_cannot_answer_is_not_an_outage() {
    let fix = Fix::new("group-dns-resolver-down");
    fix.script("dig", "#!/bin/sh\nexit 1\n");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.sent().contains("not resolving"),
        "a failed lookup was reported as the zone's fault:\n{}",
        fix.sent()
    );
    assert!(
        !fix.dir
            .join("store/groups/parish.example/dns-check.json")
            .exists(),
        "a check that did not run was recorded"
    );
}

/// One group's unreadable record is reported and skipped; the other groups are
/// still watched and the pass carries on.
#[test]
fn one_bad_group_record_does_not_stop_the_sweep() {
    let fix = Fix::new("group-dns-bad-record");
    fix.resolver(Some("MX"));
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    let bad = fix.dir.join("store/groups/broken.example");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("group.json"), "not json").unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.sent()
            .matches("Subject: The DNS records for parish.example are not resolving")
            .count(),
        1,
        "the healthy group was not watched after the bad record:\n{}",
        fix.sent()
    );
}

/// An application the form accepts can be approved: the alias line names its own
/// account, and the address shares the mailbox its `own` target names.
#[test]
fn a_body_alias_may_name_itself_and_shares_the_mailbox() {
    let fix = Fix::new("group-alias-name");
    let mut record = fix.filed_body("warden");
    record["answers"]["body_account_names"] = json!("parish-secretary\nparish-office");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.journal().contains("\"failed\""),
        "an aliased body was refused: {}",
        fix.journal()
    );

    let virtuals = fix.table("virtuals");
    assert!(
        virtuals.contains("office@parish.example: parish-secretary"),
        "{virtuals}"
    );
    assert!(
        !fix.passwd_file().contains("parish-office:"),
        "the alias names no account: {}",
        fix.passwd_file()
    );
}

/// A virtual table line that already points elsewhere is a refusal, and the
/// drain does not overrule it.
#[test]
fn a_conflicting_virtual_line_is_refused() {
    let fix = Fix::new("group-conflict");
    std::fs::write(
        fix.path("virtuals"),
        "office@parish.example: somebody-else\n",
    )
    .unwrap();
    let id = fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("office", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    assert!(
        fix.failed_note().contains("already maps"),
        "{}",
        fix.failed_note()
    );
    assert!(
        fix.table("virtuals")
            .contains("office@parish.example: somebody-else"),
        "{}",
        fix.table("virtuals")
    );
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
}

/// An address table that cannot be read is a refusal before the approval begins:
/// no journal line and no group record.
#[test]
fn a_body_whose_addresses_do_not_form_a_table_is_refused_before_the_journal() {
    let fix = Fix::new("group-bad-table");
    let mut record = fix.filed_body("warden");
    record["answers"]["body_addresses"] = json!("office: alias nobody");
    record["answers"]["body_account_names"] = json!("parish-secretary");
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        fix.failed_note().contains("not a mailbox in the table"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.journal().contains("\"applying\""),
        "a refusal began an approval: {}",
        fix.journal()
    );
    assert!(
        !fix.dir
            .join("store/groups/parish.example/group.json")
            .exists(),
        "a refused table made a record"
    );
}

/// Adding an alias writes one virtual entry pointing at a mailbox in the group.
/// It creates no account, key, allowance or hosting, and the group record's
/// accounts and payment are untouched.
#[test]
fn an_alias_added_to_a_group_writes_one_entry_and_no_account() {
    let fix = Fix::new("group-add-alias");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());
    let passwd = fix.passwd_file();
    let group = fix.read("groups/parish.example/group.json");
    let accounts = fix.names("accounts");
    let scripts = fix.scripts_log();

    fix.file_address(
        "parish.example",
        "add-alias",
        "office",
        "parish-secretary",
        None,
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    let virtuals = fix.table("virtuals");
    assert_eq!(
        virtuals
            .lines()
            .filter(|l| l.starts_with("office@parish.example:"))
            .count(),
        1,
        "{virtuals}"
    );
    assert!(
        virtuals.contains("office@parish.example: parish-secretary"),
        "{virtuals}"
    );
    assert_eq!(fix.passwd_file(), passwd, "an alias made an account");
    assert_eq!(fix.names("accounts"), accounts);
    assert!(
        !fix.dir.join("keyring/office.asc").exists(),
        "an alias made a key"
    );
    assert_eq!(
        fix.read("groups/parish.example/group.json"),
        group,
        "an alias changed the group record"
    );
    let log = fix.scripts_log();
    assert_eq!(
        log.matches("reload-smtpd.sh").count(),
        1,
        "the alias was not made live: {log}"
    );
    assert_eq!(
        log.matches("add-user.sh").count(),
        scripts.matches("add-user.sh").count(),
        "an alias made an account: {log}"
    );
    assert_eq!(
        log.matches("provision-member.sh").count(),
        scripts.matches("provision-member.sh").count(),
        "an alias built a member: {log}"
    );
}

/// Adding a mailbox creates its account, installs its key and points its entry
/// at it. The group gains the account and keeps everything else.
#[test]
fn a_mailbox_added_to_a_group_gets_an_account_key_and_entry() {
    let fix = Fix::new("group-add-mailbox");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    assert!(
        fix.passwd_file().contains("parish-office:"),
        "{}",
        fix.passwd_file()
    );
    let key = std::fs::read_to_string(fix.dir.join("keyring/parish-office.asc"))
        .expect("the mailbox's key is on the box");
    assert!(key.contains("BEGIN PGP PUBLIC KEY BLOCK"), "{key}");
    assert_eq!(fix.account("parish-office")["group"], "parish.example");

    let virtuals = fix.table("virtuals");
    assert!(
        virtuals.contains("office@parish.example: parish-office"),
        "{virtuals}"
    );
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(
        group["accounts"],
        json!(["parish-secretary", "parish-office"])
    );

    let log = fix.scripts_log();
    assert!(log.contains("add-user.sh parish-office"), "{log}");
    assert!(log.contains("provision-member.sh parish-office"), "{log}");
    assert!(log.contains("publish-mail-key.sh parish-office"), "{log}");
}

/// Upgrading an alias makes the account and key and repoints the entry. The
/// address already existed, so the count does not move.
#[test]
fn upgrading_an_alias_repoints_it_without_changing_the_count() {
    let fix = Fix::new("group-upgrade-alias");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-secretary"),
        ],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());
    let before = fix
        .table("virtuals")
        .lines()
        .filter(|l| l.ends_with("@parish.example: parish-secretary"))
        .count();
    assert_eq!(before, 2);

    fix.file_address(
        "parish.example",
        "upgrade",
        "office",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    let virtuals = fix.table("virtuals");
    assert!(
        virtuals.contains("office@parish.example: parish-office"),
        "{virtuals}"
    );
    assert!(
        !virtuals.contains("office@parish.example: parish-secretary"),
        "{virtuals}"
    );
    assert_eq!(
        virtuals
            .lines()
            .filter(|l| l.ends_with("@parish.example: parish-secretary")
                || l.ends_with("@parish.example: parish-office"))
            .count(),
        2,
        "the upgrade changed the address count: {virtuals}"
    );
    assert!(fix.passwd_file().contains("parish-office:"));
    assert!(fix.dir.join("keyring/parish-office.asc").exists());
    let log = fix.scripts_log();
    let built = log
        .rfind("provision-member.sh parish-office")
        .expect("the upgraded mailbox was built");
    let reload = log
        .rfind("reload-smtpd.sh")
        .expect("the repointed entry was made live");
    assert!(
        built < reload,
        "the repoint was not reloaded after the builder: {log}"
    );
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(
        group["accounts"],
        json!(["parish-secretary", "parish-office"])
    );
}

/// A removal intent that names the sitting site owner while closing somebody
/// else must not move the site's key on a retry: the state below is what a crash
/// after the group write leaves, and the departing mailbox's own key is still in
/// the store. Copying it would give that member the body's upload key.
#[test]
fn retrying_a_non_owner_removal_does_not_take_the_sites_key() {
    let fix = Fix::new("group-remove-retry");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    let office_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOffice example";
    std::fs::write(fix.dir.join("store/keys/parish-office.pub"), office_key).unwrap();

    // The crash point: the group record no longer lists the mailbox and its
    // virtual line is gone, but its account and keys are still there.
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["accounts"] = json!(["parish-secretary"]);
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    let virtuals: Vec<String> = fix
        .table("virtuals")
        .lines()
        .filter(|l| !l.starts_with("office@"))
        .map(str::to_string)
        .collect();
    std::fs::write(fix.dir.join("virtuals"), virtuals.join("\n") + "\n").unwrap();

    fix.file_address(
        "parish.example",
        "remove",
        "",
        "parish-office",
        None,
        Some("parish-secretary"),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.read("keys/parish-secretary.pub").trim(),
        UPLOAD_KEY.trim(),
        "the departing mailbox's key replaced the site's"
    );
    let after: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(after["site_owner"], "parish-secretary");
    assert_eq!(after["accounts"], json!(["parish-secretary"]));
}

/// The same address intent handed to the drain again changes nothing: one
/// account, one entry, one key.
#[test]
fn an_address_intent_applied_twice_changes_nothing() {
    let fix = Fix::new("group-address-twice");
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
    assert!(fix.drain().status.success());
    let intent = fix.read(&format!("intents/{id}.json"));
    let group = fix.read("groups/parish.example/group.json");
    let passwd = fix.passwd_file();
    let virtuals = fix.table("virtuals");
    let account = fix.read("accounts/parish-office/account.json");

    // The file back, as a crash before the delete would leave it.
    std::fs::write(
        fix.dir.join("store/intents").join(format!("{id}.json")),
        intent,
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert_eq!(fix.read("groups/parish.example/group.json"), group);
    assert_eq!(fix.passwd_file(), passwd);
    assert_eq!(fix.table("virtuals"), virtuals);
    assert_eq!(fix.read("accounts/parish-office/account.json"), account);
    assert_eq!(
        fix.scripts_log()
            .matches("add-user.sh parish-office")
            .count(),
        1,
        "{}",
        fix.scripts_log()
    );
    assert_eq!(
        fix.names("accounts"),
        vec!["parish-office", "parish-secretary"]
    );
}

/// The ten-address cap counts mailboxes and aliases together: an eleventh
/// address is refused before anything is written or journaled as applying.
#[test]
fn the_eleventh_address_is_refused() {
    let fix = Fix::new("group-eleven");
    let names = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"];
    let addresses: Vec<(&str, &str)> = names.iter().map(|n| (*n, "parish-secretary")).collect();
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &addresses,
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.table("virtuals")
            .lines()
            .filter(|l| l.ends_with("@parish.example: parish-secretary"))
            .count(),
        10
    );

    let id = fix.file_address(
        "parish.example",
        "add-alias",
        "office",
        "parish-secretary",
        None,
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("ten addresses"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.table("virtuals").contains("office@parish.example"),
        "{}",
        fix.table("virtuals")
    );
    assert!(
        !fix.journal()
            .lines()
            .any(|l| l.contains("\"kind\":\"group-address\"")
                && l.contains("\"outcome\":\"applying\"")),
        "a refused eleventh address began: {}",
        fix.journal()
    );
}

/// Removing a body's domain takes the whole name down: the mail tables, the
/// generated blocks and certificate material the queue names, every account in
/// the group, their token index entries and the group record. The ledger and an
/// account outside the group are untouched.
#[test]
fn a_group_removal_takes_the_domain_down_and_closes_its_accounts() {
    let fix = Fix::new("group-remove");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-secretary"),
            ("warden", "parish-warden"),
        ],
        &["parish-secretary", "parish-warden"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());

    // An account outside the group, with its own token and table line. A
    // removal that swept the table by account rather than by domain would take
    // it too.
    let mut passwd = fix.passwd_file();
    passwd.push_str("bob:x:1002:1002::/home/bob:/sbin/nologin\n");
    std::fs::write(fix.path("passwd"), passwd).unwrap();
    std::fs::create_dir_all(fix.dir.join("store/accounts/bob")).unwrap();
    std::fs::write(
        fix.dir.join("store/accounts/bob/account.json"),
        serde_json::to_vec_pretty(&json!({"username": "bob", "state": "active"})).unwrap(),
    )
    .unwrap();
    std::fs::write(fix.dir.join("store/keys/bob.pub"), "ssh-ed25519 AAAA bob\n").unwrap();
    fix.write_token("tokbob", "bob");
    let mut virtuals = fix.table("virtuals");
    virtuals.push_str("bob@kyriakon.net: bob\n");
    std::fs::write(fix.path("virtuals"), virtuals).unwrap();
    fix.write_token("toksecretary", "parish-secretary");
    fix.write_token("tokwarden", "parish-warden");

    // The generated blocks, the certificate material and the queued order, as
    // the lanes and the queue would have left them, plus a second body's files
    // that must survive.
    for path in [
        "httpd.d/parish.example.conf",
        "gmid.d/parish.example.conf",
        "acme-client.d/parish.example.conf",
        "ssl/parish.example.fullchain.pem",
        "ssl/parish.example.crt",
        "ssl/private/parish.example.key",
        "ssl/capsule-parish.example.cnf",
        "ssl/capsule-parish.example.crt",
        "ssl/private/capsule-parish.example.key",
        "queue/pending/parish.example",
        "httpd.d/other.example.conf",
        "queue/pending/other.example",
    ] {
        std::fs::write(fix.host(path), b"generated\n").unwrap();
    }
    std::fs::create_dir_all(fix.dir.join("store/ledger")).unwrap();
    let ledger = "{\"token\":\"toksecretary\",\"amount_gbp\":\"20.00\"}\n";
    std::fs::write(fix.dir.join("store/ledger/payments.jsonl"), ledger).unwrap();

    let id = fix.file_remove_group("parish.example");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.intents().is_empty(),
        "{:?}\n{}",
        fix.intents(),
        fix.journal()
    );
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    // The mail tables no longer name the domain, and the platform's own lines
    // and the other account's address are still there.
    let domains = fix.table("mail_domains");
    assert!(!domains.lines().any(|l| l == "parish.example"), "{domains}");
    assert!(domains.lines().any(|l| l == "kyriakon.net"), "{domains}");
    let dkim = fix.table("dkim_domains");
    assert!(!dkim.lines().any(|l| l == "parish.example"), "{dkim}");
    assert!(dkim.lines().any(|l| l == "kyriakon.net"), "{dkim}");
    let virtuals = fix.table("virtuals");
    assert!(!virtuals.contains("parish.example"), "{virtuals}");
    assert!(virtuals.contains("bob@kyriakon.net: bob"), "{virtuals}");

    // The generated blocks and certificate material went, and the other body's
    // stayed.
    for path in [
        "httpd.d/parish.example.conf",
        "gmid.d/parish.example.conf",
        "acme-client.d/parish.example.conf",
        "ssl/parish.example.fullchain.pem",
        "ssl/parish.example.crt",
        "ssl/private/parish.example.key",
        "ssl/capsule-parish.example.cnf",
        "ssl/capsule-parish.example.crt",
        "ssl/private/capsule-parish.example.key",
        "queue/pending/parish.example",
    ] {
        assert!(!fix.host(path).exists(), "{path} was left");
    }
    assert!(fix.host("httpd.d/other.example.conf").exists());
    assert!(fix.host("queue/pending/other.example").exists());

    // Every account in the group closed: the box account, its stored key, its
    // hold, its store record and its token. The account outside the group did
    // not.
    let passwd = fix.passwd_file();
    assert!(!passwd.contains("parish-secretary:"), "{passwd}");
    assert!(!passwd.contains("parish-warden:"), "{passwd}");
    assert!(passwd.contains("bob:"), "{passwd}");
    assert_eq!(fix.names("accounts"), vec!["bob"]);
    assert!(!fix.dir.join("store/keys/parish-secretary.pub").exists());
    assert!(!fix.dir.join("store/keys/parish-warden.pub").exists());
    assert!(fix.dir.join("store/keys/bob.pub").exists());
    assert_eq!(
        fix.names("holds"),
        vec!["parish-secretary.json", "parish-warden.json"]
    );
    assert_eq!(fix.names("tokens"), vec!["tokbob.json"]);

    // The group record and its directory went; the ledger and the journal stay.
    assert!(!fix.dir.join("store/groups/parish.example").exists());
    assert_eq!(
        std::fs::read_to_string(fix.dir.join("store/ledger/payments.jsonl")).unwrap(),
        ledger
    );
    assert_eq!(
        fix.journal()
            .matches(&format!("\"intent\":\"{id}\""))
            .count(),
        2,
        "the journal does not hold exactly the two lines: {}",
        fix.journal()
    );

    // The host half runs before the pass that regenerates the indexes, and the
    // accounts close after it, the order the deletion transition uses.
    let log = fix.scripts_log();
    let host_at = log.find("remove-group.sh parish.example").unwrap();
    assert!(
        log[host_at..].contains("cron-apply.sh --web"),
        "the index pass did not follow the host removal: {log}"
    );
    assert!(
        log[host_at..].contains("delete-user.sh parish-secretary")
            && log[host_at..].contains("delete-user.sh parish-warden"),
        "the accounts did not close after the host removal: {log}"
    );
}

/// The same removal intent handed to the drain again changes nothing: no second
/// journal line, no script run, and the store is byte for byte what it was.
#[test]
fn a_remove_group_intent_applied_twice_changes_nothing() {
    let fix = Fix::new("group-remove-twice");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());
    fix.write_token("toksecretary", "parish-secretary");

    let id = fix.file_remove_group("parish.example");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let store = fix.snapshot();
    let log = fix.scripts_log();

    // The file back, as a crash before the delete would leave it.
    fix.write_remove_group(&id, "parish.example");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert_eq!(fix.snapshot(), store, "a replay changed the store");
    assert_eq!(fix.scripts_log(), log, "a replay ran a script");
    assert_eq!(
        fix.journal()
            .matches(&format!("\"intent\":\"{id}\""))
            .count(),
        2,
        "a replay journaled again: {}",
        fix.journal()
    );
}

/// A removal for a domain with no group record is refused and changes nothing:
/// no table line, no script, no account and no group.
#[test]
fn a_removal_for_a_domain_that_is_not_a_group_is_refused() {
    let fix = Fix::new("group-remove-missing");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());
    let tables = (
        fix.table("mail_domains"),
        fix.table("dkim_domains"),
        fix.table("virtuals"),
    );
    let accounts = fix.names("accounts");
    let log = fix.scripts_log();

    let id = fix.file_remove_group("other.example");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note()
            .contains("there is no group for other.example"),
        "{}",
        fix.failed_note()
    );
    assert_eq!(
        (
            fix.table("mail_domains"),
            fix.table("dkim_domains"),
            fix.table("virtuals")
        ),
        tables,
        "a refused removal changed a table"
    );
    assert_eq!(fix.names("accounts"), accounts);
    assert_eq!(fix.scripts_log(), log, "a refused removal ran a script");
    assert!(fix.dir.join("store/groups/parish.example").exists());
}

/// The console takes `group remove`, signs the domain, and refuses a name that
/// could not be a body's domain before it files anything.
#[test]
fn the_console_files_a_group_removal_and_refuses_a_bad_domain() {
    let fix = Fix::new("group-remove-console");

    let out = fix.ctl(&["group", "remove", "Parish.Example"]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("lowercase"), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());

    let out = fix.ctl(&["group", "remove", "parish.example"]);
    assert!(out.status.success(), "{}", body(&out));
    let intents = fix.intents();
    assert_eq!(intents.len(), 1, "{intents:?}");
    let intent: Value =
        serde_json::from_str(&fix.read(&format!("intents/{}", intents[0]))).unwrap();
    assert_eq!(intent["kind"], "remove-group");
    assert_eq!(intent["domain"], "parish.example");
    let sig = intent["sig"].as_str().unwrap();
    assert!(sign::verify(
        b"the approval key",
        &sign::group_remove_payload("parish.example"),
        sig
    ));
}

/// A departing site owner hands the upload key and the generated roots to a
/// replacement before the account is deleted. Without a replacement the intent
/// is refused and nothing moves.
#[test]
fn a_departing_site_owner_must_name_a_replacement() {
    let fix = Fix::new("group-site-owner");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    assert!(fix.dir.join("store/keys/parish-secretary.pub").exists());

    let refused = fix.file_address(
        "parish.example",
        "remove",
        "",
        "parish-secretary",
        None,
        None,
    );
    assert!(fix.drain().status.success());
    assert_eq!(fix.intents(), vec![format!("{refused}.json")]);
    assert!(
        fix.failed_note().contains("owns the site"),
        "{}",
        fix.failed_note()
    );
    assert!(
        fix.passwd_file().contains("parish-secretary:"),
        "a refused removal deleted the owner"
    );

    std::fs::remove_file(
        fix.dir
            .join("store/intents")
            .join(format!("{refused}.json")),
    )
    .unwrap();
    fix.file_address(
        "parish.example",
        "remove",
        "",
        "parish-secretary",
        None,
        Some("parish-office"),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(
        fix.journal()
            .lines()
            .any(|l| l.contains("\"kind\":\"group-address\"")
                && l.contains("\"outcome\":\"applied\"")),
        "{}",
        fix.journal()
    );

    assert!(!fix.passwd_file().contains("parish-secretary:"));
    let moved = fix.read("keys/parish-office.pub");
    assert!(moved.contains(UPLOAD_KEY), "{moved}");
    assert!(
        !fix.dir.join("store/keys/parish-secretary.pub").exists(),
        "the old owner kept the upload key"
    );
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(group["site_owner"], "parish-office");
    assert_eq!(group["accounts"], json!(["parish-office"]));

    let log = fix.scripts_log();
    let builder = log
        .rfind("provision-member.sh parish-office")
        .expect("the replacement was built");
    let delete = log
        .rfind("delete-user.sh parish-secretary")
        .expect("the old owner was deleted");
    assert!(builder < delete, "the replacement was built first: {log}");
    assert!(log.contains("cron-apply.sh --web"), "{log}");
}

/// The console files a signed address intent the drain then applies, which is
/// the operator's path when there is no account page for it yet.
#[test]
fn the_console_files_an_address_intent() {
    let fix = Fix::new("group-ctl-address");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let out = fix.ctl(&[
        "address",
        "--domain",
        "parish.example",
        "--action",
        "add-alias",
        "--address",
        "office",
        "--mailbox",
        "parish-secretary",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let intents = fix.intents();
    assert_eq!(intents.len(), 1, "{intents:?}");
    let filed: Value = serde_json::from_str(&fix.read(&format!("intents/{}", intents[0]))).unwrap();
    assert_eq!(filed["kind"], "group-address");
    assert_eq!(filed["action"], "add-alias");

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix
        .table("virtuals")
        .contains("office@parish.example: parish-secretary"));
}

/// An address intent without the root key's signature changes nothing:
/// `intents/` is writable by the unprivileged handler, and this one would
/// otherwise create or remove a root account.
#[test]
fn an_address_intent_with_a_bad_signature_is_refused() {
    let fix = Fix::new("group-address-sig");
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
    filed["sig"] = json!("00");
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
        !fix.table("virtuals").contains("office@parish.example"),
        "{}",
        fix.table("virtuals")
    );
    assert!(!fix.passwd_file().contains("parish-office:"));
}

/// The cap counts a new entry even when the mailbox it points at is already in
/// the group: adding a second address to an existing mailbox is still the
/// eleventh address.
#[test]
fn a_second_address_on_an_existing_mailbox_still_counts() {
    let fix = Fix::new("group-eleven-existing");
    let names = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"];
    let addresses: Vec<(&str, &str)> = names.iter().map(|n| (*n, "parish-secretary")).collect();
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &addresses,
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let id = fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-secretary",
        Some(GOOD_KEY),
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("ten addresses"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.table("virtuals").contains("office@parish.example"),
        "{}",
        fix.table("virtuals")
    );
}
