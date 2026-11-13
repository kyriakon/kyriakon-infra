use crate::common::*;

/// One of the key-check fixtures, by file name, for a key whose verdict is the
/// point of the test.
fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        repo_root()
            .join("docs/planning/prototypes/keygen-spike/fixtures")
            .join(name),
    )
    .unwrap()
}

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

/// An approval with no address outside the platform sends no separate
/// confirmation before the account exists, and the approval mail to the new
/// mailbox carries the durable-medium confirmation instead. That mail is the
/// durable medium, so it has to carry the Schedule 2 particulars in
/// `docs/terms.md`: the trader and the geographic address, the price and
/// period, and the cancellation form.
#[test]
fn an_approval_without_an_outside_address_carries_the_confirmation() {
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
        "no confirmation left before provisioning: {log}"
    );
    let sent = fix.sent();
    assert!(sent.contains("To: secretary@kyriakon.net"), "{sent}");
    assert!(sent.contains("1 Example Street, Example"), "{sent}");
    assert!(sent.contains("GBP 20.00 for one year"), "{sent}");
    assert!(sent.contains("digital content"), "{sent}");
    assert!(sent.contains("fourteen days"), "{sent}");
    assert!(
        sent.contains("I give notice that I cancel my contract"),
        "{sent}"
    );
    assert!(
        !sent.contains("was confirmed"),
        "the confirmation travels in the approval mail, not a second one: {sent}"
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

/// A body with no address outside the platform gets the durable-medium
/// confirmation in its approval mail, at the site owner's mailbox on the body's
/// own domain, and no separate confirmation mail.
#[test]
fn a_body_approval_without_an_outside_address_carries_the_confirmation() {
    let fix = Fix::new("group-confirmation-none");
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    assert_eq!(sent.matches("was confirmed").count(), 0, "{sent}");
    assert!(
        sent.contains("To: parish-secretary@parish.example"),
        "{sent}"
    );
    assert!(sent.contains("digital content"), "{sent}");
    assert!(sent.contains("fourteen days"), "{sent}");
    assert!(
        sent.contains("I give notice that I cancel my contract"),
        "{sent}"
    );
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
    // spamd greylists any destination whose domain has no line here and traps
    // the rest, so the body's domain has to arrive with the mail route.
    let allowed = fix.table("spamd.alloweddomains");
    assert_eq!(
        allowed.lines().filter(|l| *l == "@parish.example").count(),
        1,
        "{allowed}"
    );
    assert!(allowed.lines().any(|l| l == "@kyriakon.net"), "{allowed}");
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
    // Each address is also a sender the mailbox may submit as, on the mailbox's
    // own line of the senders mapping: without it it is refused at MAIL FROM
    // until the next deploy.
    let mail_from = fix.table("mail_from");
    assert!(
        mail_from.contains("parish-secretary: secretary@parish.example,office@parish.example"),
        "{mail_from}"
    );
    assert_eq!(mail_from.lines().count(), 1, "{mail_from}");

    // The block's upload key is where provision-member.sh reads it.
    let key = fix.read("keys/parish-secretary.pub");
    assert!(key.contains(UPLOAD_KEY), "{key}");

    let log = fix.scripts_log();
    assert!(
        log.contains("reload-spamd.sh"),
        "spamd was not restarted for the new allow list line: {log}"
    );
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

    // The same intent again, as a crash between the applied line and the
    // remove leaves it: the second pass finishes the remove and does no work.
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
    assert_eq!(
        fix.table("spamd.alloweddomains")
            .lines()
            .filter(|l| *l == "@parish.example")
            .count(),
        1,
        "{}",
        fix.table("spamd.alloweddomains")
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
        1,
        "the intent is settled, so the second pass does no work: {}",
        fix.scripts_log()
    );
}

/// A group whose second mailbox cannot be made exposes no mail route for either
/// mailbox. The tables are written only after every account and keyring entry is
/// in place, so a partial failure leaves nothing smtpd will accept and then
/// bounce at LMTP, and a retry starts from accounts it can find.
#[test]
fn a_group_whose_second_mailbox_fails_exposes_no_mail_route() {
    let fix = Fix::new("group-partial");
    // The builder works for the first mailbox and refuses the second, the shape
    // a missing keyring entry or a failed add-user.sh leaves behind.
    let log = fix.path("scripts.log");
    fix.script(
        "provision-member.sh",
        &format!(
            "#!/bin/sh\necho \"provision-member.sh $*\" >> '{log}'\n\
             [ \"$1\" = parish-secretary ] || {{ echo 'builder refused' >&2; exit 1; }}\n"
        ),
    );
    let id = fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        Some(UPLOAD_KEY),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    // The intent is not settled: it stays for the retry, with the failure.
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("builder refused"),
        "{}",
        fix.failed_note()
    );

    // No route is live, and nothing names the body's domain yet.
    assert!(
        fix.table("virtuals").is_empty(),
        "a mailbox was exposed before it existed: {}",
        fix.table("virtuals")
    );
    assert!(
        fix.table("mail_from").is_empty(),
        "an address was sendable before its mailbox existed: {}",
        fix.table("mail_from")
    );
    assert!(
        !fix.table("mail_domains").contains("parish.example"),
        "{}",
        fix.table("mail_domains")
    );
    assert!(
        !fix.table("dkim_domains").contains("parish.example"),
        "{}",
        fix.table("dkim_domains")
    );
    assert!(
        !fix.table("spamd.alloweddomains")
            .contains("@parish.example"),
        "{}",
        fix.table("spamd.alloweddomains")
    );

    // What the pass did make is where a retry looks for it: the accounts and
    // the keyring entries, which a second pass finds rather than makes again.
    assert!(
        fix.passwd_file().contains("parish-secretary:"),
        "{}",
        fix.passwd_file()
    );
    assert!(fix.dir.join("keyring/parish-secretary.asc").exists());
    assert!(fix.dir.join("keyring/parish-office.asc").exists());
    assert!(
        fix.scripts_log()
            .contains("provision-member.sh parish-office"),
        "the second mailbox was not attempted: {}",
        fix.scripts_log()
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
    assert!(
        fix.table("mail_from")
            .contains("parish-secretary: secretary@parish.example,office@parish.example"),
        "the alias cannot be submitted as: {}",
        fix.table("mail_from")
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
        scripts.matches("reload-smtpd.sh").count() + 1,
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
    // The new mailbox carries a one-time password link of its own, delivered
    // with `kyriakon-admin password reset` if this address intent did not carry
    // it to the member.
    assert!(
        fix.account("parish-office")["password_link"]["token"].is_string(),
        "{}",
        fix.account("parish-office")
    );
    // The intent carried a fingerprint the signature does not cover, so the
    // record must show the one computed from the material.
    let computed = kyriakon_control_core::mail::keycheck::pgp_fingerprint(GOOD_KEY).unwrap();
    assert_eq!(
        fix.account("parish-office")["mail_key"],
        json!(computed),
        "{}",
        fix.journal()
    );

    let virtuals = fix.table("virtuals");
    assert!(
        virtuals.contains("office@parish.example: parish-office"),
        "{virtuals}"
    );
    assert!(
        fix.table("mail_from")
            .contains("parish-office: office@parish.example"),
        "the new mailbox cannot be submitted as: {}",
        fix.table("mail_from")
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

/// A key the shared check refuses (here an AEAD advert) never reaches the
/// keyring or the account record, exactly as the web form and the rotation
/// path refuse it. The intent stays for the backoff and nothing is written.
#[test]
fn a_group_address_key_the_check_refuses_is_not_installed() {
    let fix = Fix::new("group-address-aead");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let aead = fixture("gpg-aead.asc");
    let id = fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-office",
        Some(&aead),
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    let failed = fix.failed_note();
    assert!(failed.contains("cannot be used"), "{failed}");
    assert!(failed.contains("AEAD"), "{failed}");

    assert!(
        !fix.dir.join("keyring/parish-office.asc").exists(),
        "a refused key reached the keyring"
    );
    assert!(
        !fix.dir
            .join("store/accounts/parish-office/account.json")
            .exists(),
        "a refused key reached an account record"
    );
    assert!(!fix.passwd_file().contains("parish-office:"));
    assert!(!fix.table("virtuals").contains("office@parish.example"));
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
    assert!(
        fix.account("parish-office")["password_link"]["token"].is_string(),
        "{}",
        fix.account("parish-office")
    );
    // The sender identity follows the route: the upgraded address submits as
    // its new mailbox, not the shared one, and the new mailbox had no line
    // before this pass.
    assert_eq!(
        fix.table("mail_from"),
        "parish-secretary: secretary@parish.example\nparish-office: office@parish.example\n",
        "the address did not move to the upgraded mailbox's own line"
    );
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

    // The departing address's sender identity goes with its route, and the
    // mailbox that stays keeps its own.
    let mail_from = fix.table("mail_from");
    assert!(
        !mail_from.contains("office@parish.example"),
        "the removed address can still be submitted as: {mail_from}"
    );
    assert!(
        mail_from.contains("parish-secretary: secretary@parish.example"),
        "the remaining mailbox lost its sender identity: {mail_from}"
    );
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
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "username": "bob",
            "state": "active",
            "decision": "approve",
            "decided_at": "2026-10-01T09:00:00Z",
            "rail": "no_charge",
            "no_charge": true,
            "created_at": "2026-10-01T09:00:00Z"
        }))
        .unwrap(),
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
    let allowed = fix.table("spamd.alloweddomains");
    assert!(
        !allowed.lines().any(|l| l == "@parish.example"),
        "{allowed}"
    );
    assert!(allowed.lines().any(|l| l == "@kyriakon.net"), "{allowed}");
    let virtuals = fix.table("virtuals");
    assert!(!virtuals.contains("parish.example"), "{virtuals}");
    assert!(virtuals.contains("bob@kyriakon.net: bob"), "{virtuals}");
    let mail_from = fix.table("mail_from");
    assert!(
        !mail_from.contains("parish.example"),
        "a removed body's addresses can still be submitted as: {mail_from}"
    );

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

/// A card-paying group's removal stops the body's subscription before its token
/// goes, once, and an already-canceled one calls no processor.
#[test]
fn a_group_removal_stops_the_bodys_subscription() {
    let fix = Fix::new("group-remove-cancel");
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

    fix.file_remove_group("parish.example");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let log = fix.scripts_log();
    assert_eq!(
        log.matches("stripe-api.sh cancel sub_example").count(),
        1,
        "{log}"
    );
    assert!(
        !fix.dir.join("store/groups/parish.example").exists(),
        "the group record stayed"
    );
    assert!(!log.contains("failed"), "{log}");

    // The subscription was already canceled, so the processor is not asked.
    let stopped = Fix::new("group-remove-canceled");
    stopped.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(stopped.drain().status.success());
    let path = stopped.dir.join("store/groups/parish.example/group.json");
    let mut group: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    group["payment"]["stripe"] = json!({
        "subscription": SUBSCRIPTION,
        "status": "canceled"
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&group).unwrap()).unwrap();

    stopped.file_remove_group("parish.example");
    let out = stopped.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !stopped.scripts_log().contains("stripe-api.sh"),
        "a canceled subscription called the processor: {}",
        stopped.scripts_log()
    );
    assert!(!stopped.dir.join("store/groups/parish.example").exists());
}

/// A lapsed card group's grace ends through `delete_group`: the subscription is
/// stopped there, and the flag that write saves keeps the same pass's
/// `take_group_down` from sending a second cancel.
#[test]
fn a_lapsed_card_group_stops_its_subscription_once() {
    let fix = Fix::new("group-lapse-cancel");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
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
    group["payment"]["window"]["state"] = json!("closed");
    group["grace_until"] = json!(kyriakon_control_core::util::date_after_days(-1));
    std::fs::write(&path, serde_json::to_vec_pretty(&group).unwrap()).unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let log = fix.scripts_log();
    assert_eq!(
        log.matches("stripe-api.sh cancel sub_example").count(),
        1,
        "{log}"
    );
    assert!(
        !fix.dir.join("store/groups/parish.example").exists(),
        "the lapsed group stayed: {}",
        fix.journal()
    );
}

/// A removal for a domain with no group record is settled as refused, not a
/// failure that retries: no intent is left behind, and nothing changes -- no
/// table line, no script, no account and no group.
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
        fix.table("spamd.alloweddomains"),
        fix.table("virtuals"),
    );
    let accounts = fix.names("accounts");
    let log = fix.scripts_log();

    let id = fix.file_remove_group("other.example");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        fix.intents().is_empty(),
        "a refused removal left its intent armed: {:?}",
        fix.intents()
    );
    let journal = fix.journal();
    assert!(
        journal.contains(&format!("\"intent\":\"{id}\",\"kind\":\"remove-group\"")),
        "{journal}"
    );
    assert!(
        journal.contains("there is no group for other.example"),
        "{journal}"
    );
    assert!(
        !journal.contains("\"outcome\":\"failed\""),
        "a missing group failed the pass: {journal}"
    );
    assert_eq!(
        (
            fix.table("mail_domains"),
            fix.table("dkim_domains"),
            fix.table("spamd.alloweddomains"),
            fix.table("virtuals")
        ),
        tables,
        "a refused removal changed a table"
    );
    assert_eq!(fix.names("accounts"), accounts);
    assert_eq!(fix.scripts_log(), log, "a refused removal ran a script");
    assert!(fix.dir.join("store/groups/parish.example").exists());
}

/// A body cannot claim the platform's own domain, or a name under it: the
/// approval settles as refused before the journal's applying line, no script
/// runs and no virtual entry is made.
#[test]
fn a_body_that_claims_the_platforms_own_domain_is_refused() {
    for (case, domain) in [
        ("group-platform-domain", "kyriakon.net"),
        ("group-platform-subdomain", "mail.kyriakon.net"),
    ] {
        let fix = Fix::new(case);
        let mut record = fix.filed_body("warden");
        record["domain"] = json!(domain);
        record["answers"]["body_domain"] = json!(domain);
        fix.rewrite_record(&record);
        fix.file_application(&record);
        assert!(fix.drain().status.success());
        fix.decide("approve", "warden");
        let out = fix.drain();
        assert!(out.status.success(), "{domain}: {}", body(&out));

        let journal = fix.journal();
        assert!(
            journal.contains(&format!("{domain} is the platform's own domain")),
            "{domain} was not refused in the journal: {journal}"
        );
        assert!(
            !journal.contains("\"outcome\":\"applying\""),
            "{domain}: a refused approval began: {journal}"
        );
        assert!(
            !fix.scripts_log().contains("provision"),
            "{domain}: a refused approval ran a script: {}",
            fix.scripts_log()
        );
        assert_eq!(
            fix.table("virtuals"),
            "",
            "{domain}: a refused approval made a virtual entry"
        );
        assert_eq!(
            fix.table("mail_domains"),
            "kyriakon.net\n",
            "{domain}: a refused approval changed the platform's domain table"
        );
        assert!(!fix.dir.join("store/groups").join(domain).exists());
    }
}

/// `group remove` for the platform's own domain, or a name under it, settles as
/// refused and leaves the platform's mail tables and certificate material
/// alone: the removal would otherwise delete every `*@kyriakon.net` entry and
/// the platform's own certificate.
#[test]
fn a_removal_of_the_platforms_own_domain_is_refused() {
    let fix = Fix::new("group-platform-remove");
    std::fs::write(
        fix.path("virtuals"),
        "abuse@kyriakon.net: warden\nadmin@kyriakon.net: warden\nbob@parish.example: bob\n",
    )
    .unwrap();
    std::fs::write(
        fix.path("mail_from"),
        "warden: abuse@kyriakon.net,admin@kyriakon.net\n",
    )
    .unwrap();
    let platform_files = [
        "httpd.d/kyriakon.net.conf",
        "gmid.d/kyriakon.net.conf",
        "acme-client.d/kyriakon.net.conf",
        "ssl/kyriakon.net.fullchain.pem",
        "ssl/private/kyriakon.net.key",
        "httpd.d/mail.kyriakon.net.conf",
        "ssl/mail.kyriakon.net.fullchain.pem",
    ];
    for path in platform_files {
        std::fs::write(fix.host(path), b"generated\n").unwrap();
    }
    let tables = (
        fix.table("mail_domains"),
        fix.table("dkim_domains"),
        fix.table("virtuals"),
        fix.table("mail_from"),
    );

    for domain in ["kyriakon.net", "mail.kyriakon.net"] {
        fix.file_remove_group(domain);
    }
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let journal = fix.journal();
    for domain in ["kyriakon.net", "mail.kyriakon.net"] {
        assert!(
            journal.contains(&format!("{domain} is the platform's own domain")),
            "{domain} was not refused: {journal}"
        );
    }
    assert!(
        !journal.contains("\"outcome\":\"failed\""),
        "a platform removal failed the pass: {journal}"
    );
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert_eq!(
        (
            fix.table("mail_domains"),
            fix.table("dkim_domains"),
            fix.table("virtuals"),
            fix.table("mail_from")
        ),
        tables,
        "a refused platform removal changed a table"
    );
    for path in platform_files {
        assert!(fix.host(path).exists(), "{path} was removed");
    }
    assert!(
        !fix.scripts_log().contains("remove-group.sh"),
        "a refused platform removal ran the removal script: {}",
        fix.scripts_log()
    );
}

/// A second removal filed after the first took the group down settles as
/// refused, leaves no intent behind and does not retry, so a group made on that
/// domain later is not taken down by the stale signed removal.
#[test]
fn a_stale_removal_settles_refused_and_spares_a_later_group() {
    let fix = Fix::new("group-remove-stale");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    // The first removal takes the group down; the second, filed in the state a
    // second `group remove` leaves behind, finds no record.
    fix.file_remove_group("parish.example");
    assert!(fix.drain().status.success());
    assert!(
        !fix.dir.join("store/groups/parish.example").exists(),
        "the first removal did not take the group down"
    );
    let stale = fix.file_remove_group("parish.example");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let journal = fix.journal();
    assert!(
        journal.contains(&format!("\"intent\":\"{stale}\",\"kind\":\"remove-group\""))
            && journal.contains("there is no group for parish.example"),
        "the stale removal did not settle refused: {journal}"
    );
    assert!(
        !journal.contains("\"outcome\":\"failed\""),
        "the stale removal keeps retrying: {journal}"
    );
    assert!(
        fix.intents().is_empty(),
        "the stale removal was left armed: {:?}",
        fix.intents()
    );

    // A later pass has nothing to do, and would have retried a failure.
    let lines = journal.lines().count();
    let log = fix.scripts_log();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.journal().lines().count(), lines, "the seam retried");
    assert_eq!(fix.scripts_log(), log, "a later pass ran a script");

    // A new body on the same domain is not the stale removal's to delete.
    fix.file_group(
        "parish.example",
        "parish-office",
        &[("office", "parish-office")],
        &["parish-office"],
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.dir
            .join("store/groups/parish.example/group.json")
            .exists(),
        "the stale removal deleted a later group: {}",
        fix.journal()
    );
    assert!(fix.table("mail_domains").contains("parish.example"));
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
    for lane in [
        "provision-group-web.sh",
        "provision-group-capsule.sh",
        "provision-group-acme.sh",
    ] {
        assert!(
            log.contains(&format!("{lane} parish.example parish-office")),
            "{lane} did not re-root the site at the replacement: {log}"
        );
    }
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

/// A `--key-file` that is not a public key block is refused at the console:
/// filing it would create the mailbox with junk as its key and leave the page
/// showing a blank fingerprint.
#[test]
fn the_console_refuses_a_mail_key_that_is_not_a_public_key() {
    let fix = Fix::new("group-ctl-key-junk");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let path = fix.path("certificate.pem");
    std::fs::write(
        &path,
        "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let out = fix.ctl(&[
        "address",
        "--domain",
        "parish.example",
        "--action",
        "add-mailbox",
        "--address",
        "office",
        "--mailbox",
        "parish-office",
        "--key-file",
        &path,
    ]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("public key block"), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.passwd_file().contains("parish-office:"));
}

/// A `--key-file` the shared check refuses is refused at the console too, so
/// the console cannot file a mailbox the pages would have refused.
#[test]
fn the_console_refuses_a_mail_key_the_check_refuses() {
    let fix = Fix::new("group-ctl-key-aead");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let path = fix.path("mail.asc");
    std::fs::write(&path, fixture("gpg-aead.asc")).unwrap();
    let out = fix.ctl(&[
        "address",
        "--domain",
        "parish.example",
        "--action",
        "add-mailbox",
        "--address",
        "office",
        "--mailbox",
        "parish-office",
        "--key-file",
        &path,
    ]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("cannot be used"), "{}", body(&out));
    assert!(body(&out).contains("AEAD"), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
}

/// The same console path with a real public key computes the fingerprint and
/// files the change the drain then applies.
#[test]
fn the_console_files_a_validated_mail_key() {
    let fix = Fix::new("group-ctl-key-good");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let path = fix.path("mail.asc");
    std::fs::write(&path, GOOD_KEY).unwrap();
    let out = fix.ctl(&[
        "address",
        "--domain",
        "parish.example",
        "--action",
        "add-mailbox",
        "--address",
        "office",
        "--mailbox",
        "parish-office",
        "--key-file",
        &path,
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let intents = fix.intents();
    assert_eq!(intents.len(), 1, "{intents:?}");
    let filed: Value = serde_json::from_str(&fix.read(&format!("intents/{}", intents[0]))).unwrap();
    let expected = kyriakon_control_core::mail::keycheck::mail_key(
        "parish-office".to_string(),
        "parish-office@kyriakon.net",
        GOOD_KEY,
    );
    assert!(!expected.fingerprint.is_empty());
    assert_eq!(
        filed["mail_key"]["fingerprint"],
        json!(expected.fingerprint)
    );
    assert_eq!(filed["mail_key"]["verdict"], json!(expected.verdict));

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.passwd_file().contains("parish-office:"));
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

/// A `provision-group` intent the approval did not sign, or signed over other
/// fields, is refused before any account: `intents/` is the handler's directory,
/// and the transition creates system accounts as root.
#[test]
fn an_unsigned_or_wrongly_signed_group_intent_creates_no_account() {
    let fix = Fix::new("group-intent-sig");
    let unsigned = fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    // The fixture files a correctly signed intent; take the signature away.
    let path = fix
        .dir
        .join("store/intents")
        .join(format!("{unsigned}.json"));
    let mut filed: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    filed["sig"] = json!("");
    std::fs::write(&path, serde_json::to_vec_pretty(&filed).unwrap()).unwrap();

    // Signed for one domain, then filed for another: the payload the drain
    // rebuilds does not match.
    let forged = fix.file_group(
        "other.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    let path = fix.dir.join("store/intents").join(format!("{forged}.json"));
    let mut filed: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    filed["domain"] = json!("parish.example");
    std::fs::write(&path, serde_json::to_vec_pretty(&filed).unwrap()).unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // `intents()` sorts by name, and two ULIDs filed in the same millisecond
    // can sort in either order, so compare the same sorted order.
    let mut expected = vec![format!("{unsigned}.json"), format!("{forged}.json")];
    expected.sort();
    assert_eq!(
        fix.intents(),
        expected,
        "a refused intent stays for the operator"
    );
    assert!(
        fix.passwd_file().is_empty(),
        "a refused intent made an account: {}",
        fix.passwd_file()
    );
    assert!(!fix.dir.join("store/groups").exists());
    let journal = fix.journal();
    for id in [&unsigned, &forged] {
        let count = journal
            .lines()
            .filter(|l| {
                l.contains(&format!("\"intent\":\"{id}\"")) && l.contains("\"outcome\":\"failed\"")
            })
            .count();
        assert_eq!(count, 1, "one journal line for {id}: {journal}");
        assert!(journal.contains("signature does not verify"), "{journal}");
    }
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

/// The group's payment state: one rail, one token, one window and one date on
/// the group, and nothing of the sort on a mailbox in it.
#[test]
fn a_charged_group_holds_one_token_and_one_window_and_no_account_does() {
    let fix = Fix::new("group-payment");
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let token = group["payment"]["token_ref"]
        .as_str()
        .expect("a charged group draws one token");
    assert!(
        kyriakon_control_core::store::is_payment_token(token),
        "{token}"
    );
    assert_eq!(
        group["payment"]["window"]["state"],
        json!("open"),
        "{group}"
    );
    assert!(
        group["payment"]["window"]["closes_at"].is_string(),
        "{group}"
    );
    assert!(group["payment"]["paid_until"].is_null(), "{group}");

    // The index resolves the token to the group, not to one of its accounts.
    let join: Value = serde_json::from_str(&fix.read(&format!("tokens/{token}.json"))).unwrap();
    assert_eq!(join["group"], json!("parish.example"), "{join}");
    assert_eq!(join["token"], json!(token), "{join}");

    // The approval opened one ledger line, keyed by the group's token.
    let opens: Vec<Value> = ledger_lines(&fix)
        .into_iter()
        .filter(|line| line["kind"] == json!("window_open"))
        .collect();
    assert_eq!(opens.len(), 1, "{opens:?}");
    assert_eq!(opens[0]["token"], json!(token), "{opens:?}");

    // The mailbox references its group and holds no payment block at all.
    let account = fix.account("parish-secretary");
    assert_eq!(account["group"], json!("parish.example"), "{account}");
    assert!(account.get("payment").is_none(), "{account}");
    assert!(
        !fix.read("accounts/parish-secretary/account.json")
            .contains("paid_until"),
        "a mailbox holds no paid-until date"
    );

    // The approval mail carries the token and the group's own price, so the
    // body can pay the right sum for the domain.
    assert!(
        fix.sent().contains(&format!("reference is {token}")),
        "{}",
        fix.sent()
    );
    assert!(
        fix.sent().contains("GBP 40.00"),
        "the approval names the group's price, not a person's: {}",
        fix.sent()
    );
}

/// A free group has no token, no window and no date, and never lapses: no sweep
/// gives it one.
#[test]
fn a_free_group_has_no_token_no_window_and_never_lapses() {
    let fix = Fix::new("group-free");
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("provision", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(group["payment"]["no_charge"], json!(true), "{group}");
    assert!(group["payment"]["token_ref"].is_null(), "{group}");
    assert!(group["payment"].get("window").is_none(), "{group}");
    assert!(group["payment"]["paid_until"].is_null(), "{group}");
    assert!(fix.names("tokens").is_empty(), "{:?}", fix.names("tokens"));
    assert!(payment_lines(&fix).is_empty(), "{:?}", payment_lines(&fix));

    // A year of passes later nothing has lapsed: a free group has no window to
    // close and no grace to run out.
    let before = fix.read("groups/parish.example/group.json");
    assert!(fix.drain().status.success());
    assert_eq!(fix.read("groups/parish.example/group.json"), before);
    assert_eq!(
        fix.account("parish-secretary")["state"],
        json!("active"),
        "a free group's mailbox does not lapse"
    );
}

/// A free group has no token, so the console's one resolver refuses a credit
/// and a refund by any of its mailboxes' names, and neither files an intent.
#[test]
fn a_console_credit_or_refund_by_a_free_groups_mailbox_is_refused() {
    let fix = Fix::new("group-free-console");
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("provision", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let out = fix.ctl(&[
        "credit",
        "--username",
        "parish-secretary",
        "--rail",
        "cash",
        "--amount",
        "40.00",
        "--received",
        "2026-10-20",
    ]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(
        body(&out).contains("approved without charge"),
        "{}",
        body(&out)
    );

    let out = fix.ctl(&[
        "refund",
        "--username",
        "parish-secretary",
        "--amount",
        "10.00",
        "--rail",
        "cash",
        "--reason",
        "unused",
        "--close",
    ]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(
        body(&out).contains("approved without charge"),
        "{}",
        body(&out)
    );

    let out = fix.ctl(&["payment", "show", "--username", "parish-secretary"]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(
        body(&out).contains("approved without charge"),
        "{}",
        body(&out)
    );

    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
}

/// A prepaid credit keyed by the group's token writes exactly one date, on the
/// group. The ledger line is keyed by the same token and the receipt is one.
#[test]
fn a_group_credit_writes_one_date_on_the_group_alone() {
    let fix = Fix::new("group-credit");
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
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let token = group["payment"]["token_ref"].as_str().unwrap().to_string();

    // The operator's console takes the mailbox's name and resolves it to the
    // group's one token.
    let out = fix.ctl(&[
        "credit",
        "--username",
        "parish-secretary",
        "--rail",
        "cash",
        "--amount",
        "40.00",
        "--received",
        "2026-10-20",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let date = group["payment"]["paid_until"]
        .as_str()
        .expect("the credit sets the group's date")
        .to_string();
    let expected =
        kyriakon_control_core::payments::billing::extend_paid_until("2026-10-20", None).unwrap();
    assert_eq!(&date[..10], &expected[..10], "{date}");
    assert_eq!(
        group["payment"]["window"]["state"],
        json!("paid"),
        "{group}"
    );

    for mailbox in ["parish-secretary", "parish-office"] {
        let raw = fix.read(&format!("accounts/{mailbox}/account.json"));
        assert!(!raw.contains("paid_until"), "{mailbox} holds a date: {raw}");
        assert_eq!(
            fix.account(mailbox)["group"],
            json!("parish.example"),
            "{mailbox}"
        );
    }
    let payments = payment_lines(&fix);
    assert_eq!(payments.len(), 1, "{payments:?}");
    assert_eq!(payments[0]["token"], json!(token), "{payments:?}");
    assert_eq!(payments[0]["applied_gbp"], json!("40.00"), "{payments:?}");
    assert!(
        fix.sent().contains("whole group is paid until"),
        "one receipt for the body: {}",
        fix.sent()
    );

    // The console reads the group's payment through a mailbox name, the same
    // join the page uses.
    let shown = fix.ctl(&["payment", "show", "--username", "parish-office"]);
    assert!(shown.status.success(), "{}", body(&shown));
    let text = body(&shown);
    assert!(text.contains(&format!("token    {token}")), "{text}");
    assert!(text.contains(&format!("paid     {date}")), "{text}");

    // A second credit is a renewal: without --confirm-double it is refused, so
    // a copied token cannot buy another year.
    let before = fix.read("groups/parish.example/group.json");
    let refused = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "40.00",
        "--received",
        "2026-10-21",
    ]);
    assert!(refused.status.success(), "{}", body(&refused));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.read("groups/parish.example/group.json"),
        before,
        "the refused renewal moves nothing"
    );
    assert!(
        fix.journal().contains("already credited"),
        "{}",
        fix.journal()
    );

    // With the operator's word, the renewal extends the group's date by one
    // year from the date the group already holds, not from today.
    let renewal = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "40.00",
        "--received",
        "2026-10-21",
        "--confirm-double",
    ]);
    assert!(renewal.status.success(), "{}", body(&renewal));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let renewed = group["payment"]["paid_until"].as_str().unwrap();
    let expected =
        kyriakon_control_core::payments::billing::extend_paid_until("2026-10-21", Some(&date))
            .unwrap();
    assert_eq!(&renewed[..10], &expected[..10], "{renewed}");
    assert_eq!(payment_lines(&fix).len(), 2, "{:?}", payment_lines(&fix));
    for mailbox in ["parish-secretary", "parish-office"] {
        assert!(
            !fix.read(&format!("accounts/{mailbox}/account.json"))
                .contains("paid_until"),
            "{mailbox} holds a date after the renewal"
        );
    }
}

/// A card renewal: the checkout's reference is the group's token, and the
/// invoice writes one date on the group. The mailboxes hold none.
#[test]
fn a_card_renewal_writes_one_date_on_the_group() {
    let fix = Fix::new("group-card");
    let mut record = fix.filed_body("warden");
    record["rail"] = json!("card");
    record["answers"]["rail"] = json!("card");
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let token = group["payment"]["token_ref"].as_str().unwrap().to_string();
    assert_eq!(group["payment"]["rail"], json!("card"), "{group}");
    assert!(
        fix.sent().contains(&format!("client_reference_id={token}")),
        "the approval mail keys the link to the group's token: {}",
        fix.sent()
    );

    fix.webhook(
        "evt_01_checkout",
        "checkout.session.completed",
        json!({
            "id": "cs_example",
            "client_reference_id": token,
            "subscription": SUBSCRIPTION,
            "customer": "cus_example",
        }),
    );
    fix.webhook(
        "evt_02_invoice",
        "invoice.paid",
        invoice_with("in_group_first", 4_000, 1_790_000_000),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let date = group["payment"]["paid_until"]
        .as_str()
        .expect("the invoice sets the group's date")
        .to_string();
    let expected = kyriakon_control_core::payments::billing::extend_paid_until(
        &kyriakon_control_core::util::filed_at(),
        None,
    )
    .unwrap();
    assert_eq!(&date[..10], &expected[..10], "one year, not two: {date}");
    assert_eq!(
        group["payment"]["stripe"]["subscription"],
        json!(SUBSCRIPTION),
        "{group}"
    );
    assert_eq!(
        group["payment"]["window"]["state"],
        json!("paid"),
        "{group}"
    );

    let payments = payment_lines(&fix);
    assert_eq!(payments.len(), 1, "{payments:?}");
    assert_eq!(payments[0]["token"], json!(token), "{payments:?}");
    assert_eq!(payments[0]["rail"], json!("card"), "{payments:?}");
    let raw = fix.read("accounts/parish-secretary/account.json");
    assert!(!raw.contains("paid_until"), "{raw}");
}

/// A lapse takes every mailbox in the group at once, one notice runs against the
/// body rather than one per mailbox, and the group's window is what recorded it.
#[test]
fn a_group_lapse_takes_every_mailbox_and_one_conversation_of_notices() {
    let fix = Fix::new("group-lapse");
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

    // The window closed ten days ago and the sweep did not run then. The lapse
    // is due now, and the grace is forty days from this pass rather than from
    // the old close date, so a missed sweep never shortens it.
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let closes = kyriakon_control_core::util::after_days(-10);
    group["payment"]["window"]["closes_at"] = json!(closes);
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let grace = kyriakon_control_core::util::date_after_days(40);
    let from_close = kyriakon_control_core::util::date_string(
        kyriakon_control_core::util::parse_date(&closes[..10]).unwrap() + time::Duration::days(40),
    );
    assert_ne!(
        grace, from_close,
        "the two dates have to differ to prove it"
    );
    for mailbox in ["parish-secretary", "parish-office"] {
        let account = fix.account(mailbox);
        assert_eq!(account["state"], json!("lapsed"), "{mailbox}: {account}");
        assert_eq!(account["grace_until"], json!(grace), "{mailbox}: {account}");
    }
    let log = fix.scripts_log();
    for mailbox in ["parish-secretary", "parish-office"] {
        assert!(
            log.contains(&format!("lapse-user.sh {mailbox}")),
            "{mailbox} still sends: {log}"
        );
    }
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(
        group["payment"]["window"]["state"],
        json!("closed"),
        "{group}"
    );
    assert_eq!(group["grace_until"], json!(grace), "{group}");

    // One line on the site owner's record, and none on the other mailbox's.
    let notices = fix.read("accounts/parish-secretary/notices.jsonl");
    assert_eq!(notices.matches("group.lapsed").count(), 1, "{notices}");
    assert!(
        !fix.read("accounts/parish-office/notices.jsonl")
            .contains("group.lapsed"),
        "one conversation for the body, not one per mailbox"
    );

    // A second pass sends nothing twice.
    assert!(fix.drain().status.success());
    let notices = fix.read("accounts/parish-secretary/notices.jsonl");
    assert_eq!(notices.matches("group.lapsed").count(), 1, "{notices}");
}

/// A group lapse settles even when its account list names a mailbox the box no
/// longer has: the deleted name is skipped instead of failing the script, and
/// the remaining mailboxes lapse and the window closes.
#[test]
fn a_group_lapse_skips_a_mailbox_the_box_no_longer_has() {
    let fix = Fix::new("group-lapse-missing-mailbox");
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

    // The console's delete removes the box account and the store record, but
    // not the group's list: the sweep has to survive a record that still names
    // the deleted mailbox.
    let out = fix.ctl(&["delete", "parish-office"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(!fix.passwd_file().contains("parish-office:"));
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert!(
        group["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|mailbox| mailbox == "parish-office"),
        "the fixture has to leave the stale name for the sweep: {group}"
    );

    let mut group = group;
    group["payment"]["window"]["closes_at"] = json!(kyriakon_control_core::util::after_days(-10));
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(
        group["payment"]["window"]["state"],
        json!("closed"),
        "the group's window never closed: {group}"
    );
    assert_eq!(
        fix.account("parish-secretary")["state"],
        json!("lapsed"),
        "the remaining mailbox still sends"
    );
    assert!(
        !fix.scripts_log().contains("lapse-user.sh parish-office"),
        "the deleted mailbox was handed to the script: {}",
        fix.scripts_log()
    );
}

/// Closing one mailbox of a group drops its name from the group record, so the
/// record and the box agree once the seven-day window ends.
#[test]
fn closing_a_group_mailbox_drops_it_from_the_group_record() {
    let fix = Fix::new("group-close-prune");
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

    fix.file_close("parish-office");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.account("parish-office")["state"], json!("closing"));
    assert!(
        fix.passwd_file().contains("parish-office:"),
        "the box account stays for the seven-day window"
    );
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(
        group["accounts"],
        json!(["parish-secretary"]),
        "the closing name was left in the group: {group}"
    );
}

/// Every group lifecycle notice follows the address the site owner gave outside
/// the platform, read from the durable account record the ninety-day purge of
/// the application copy does not touch.
#[test]
fn a_group_notice_follows_the_site_owners_outside_address() {
    let fix = Fix::new("group-notice-outside");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    fix.amend_account("parish-secretary", |account| {
        account["outside_address"] = json!("warden@example.invalid");
    });
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["payment"]["window"]["closes_at"] = json!(kyriakon_control_core::util::after_days(-10));
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    assert!(fix.drain().status.success());

    let notices = fix.read("accounts/parish-secretary/notices.jsonl");
    let notice = |kind: &str| {
        notices
            .lines()
            .find(|line| line.contains(kind))
            .unwrap_or_else(|| panic!("{kind} is not recorded: {notices}"))
            .to_string()
    };
    let lapsed = notice("group.lapsed");
    assert!(lapsed.contains("warden@example.invalid"), "{lapsed}");
    assert!(
        !lapsed.contains("parish-secretary@parish.example"),
        "{lapsed}"
    );

    // The grace's midpoint, then its final week, on the same address.
    for days in [29, 6] {
        let mut group: Value =
            serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
        group["grace_until"] = json!(kyriakon_control_core::util::date_after_days(days));
        std::fs::write(
            fix.dir.join("store/groups/parish.example/group.json"),
            serde_json::to_vec_pretty(&group).unwrap(),
        )
        .unwrap();
        assert!(fix.drain().status.success());
    }
    let notices = fix.read("accounts/parish-secretary/notices.jsonl");
    for kind in ["group.grace", "group.final"] {
        let line = notices
            .lines()
            .find(|line| line.contains(kind))
            .unwrap_or_else(|| panic!("{kind} is not recorded: {notices}"));
        assert!(line.contains("warden@example.invalid"), "{line}");
        assert!(!line.contains("parish-secretary@parish.example"), "{line}");
    }
}

/// With no address outside the platform the group notices still reach the site
/// owner at their mailbox on the group's own domain.
#[test]
fn a_group_notice_without_an_outside_address_goes_to_the_platform_mailbox() {
    let fix = Fix::new("group-notice-platform");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    fix.amend_account("parish-secretary", |account| {
        account["outside_address"] = Value::Null;
    });
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["payment"]["window"]["closes_at"] = json!(kyriakon_control_core::util::after_days(-10));
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    assert!(fix.drain().status.success());

    let notices = fix.read("accounts/parish-secretary/notices.jsonl");
    let lapsed = notices
        .lines()
        .find(|line| line.contains("group.lapsed"))
        .unwrap_or_else(|| panic!("group.lapsed is not recorded: {notices}"))
        .to_string();
    assert!(
        lapsed.contains("parish-secretary@parish.example"),
        "{lapsed}"
    );
}

/// A group made through the approval flow has no outside address on its site
/// owner's account record. The address the application gave is still the one
/// its lifecycle notices use, read from the copy the approval left behind.
#[test]
fn a_group_made_by_approval_notices_the_address_the_application_gave() {
    let fix = Fix::new("group-notice-approval");
    let mut record = fix.filed_body("warden");
    record["outside_address"] = json!("secretary@example.invalid");
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    assert!(fix.drain().status.success());

    let account = fix.account("parish-secretary");
    assert!(account["outside_address"].is_null(), "{account}");

    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["payment"]["window"]["closes_at"] = json!(kyriakon_control_core::util::after_days(-10));
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    assert!(fix.drain().status.success());

    let notices = fix.read("accounts/parish-secretary/notices.jsonl");
    let lapsed = notices
        .lines()
        .find(|line| line.contains("group.lapsed"))
        .unwrap_or_else(|| panic!("group.lapsed is not recorded: {notices}"));
    assert!(lapsed.contains("secretary@example.invalid"), "{lapsed}");
    assert!(
        !lapsed.contains("parish-secretary@parish.example"),
        "{lapsed}"
    );
}

/// A site owner's record that is missing or cannot be read is journalled and
/// mailed once, naming the record, rather than printed every pass or sent to
/// the platform address in the member's place.
#[test]
fn a_missing_or_unreadable_site_owner_record_is_reported_once() {
    fn remove_the_record(fix: &Fix) {
        std::fs::remove_file(fix.dir.join("store/accounts/parish-secretary/account.json")).unwrap();
    }
    fn truncate_the_record(fix: &Fix) {
        std::fs::write(
            fix.dir.join("store/accounts/parish-secretary/account.json"),
            b"{\"version\": 1, \"username\": \"parish-sec",
        )
        .unwrap();
    }

    /// One way a site owner's record can be unreadable, and the line the
    /// report about it must carry.
    struct Damage {
        case: &'static str,
        apply: fn(&Fix),
        phrase: &'static str,
    }

    let damaged = [
        Damage {
            case: "missing",
            apply: remove_the_record,
            phrase: "accounts/parish-secretary/account.json is missing",
        },
        Damage {
            case: "corrupt",
            apply: truncate_the_record,
            phrase: "accounts/parish-secretary/account.json does not parse",
        },
    ];
    for Damage {
        case,
        apply,
        phrase,
    } in damaged
    {
        let fix = Fix::new(&format!("group-notice-{case}"));
        fix.file_group(
            "parish.example",
            "parish-secretary",
            &[("secretary", "parish-secretary")],
            &["parish-secretary"],
            Some(UPLOAD_KEY),
        );
        assert!(fix.drain().status.success());
        // The window is already closed, so the pass offers the lapse notice
        // without stopping the mailboxes first.
        let mut group: Value =
            serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
        group["payment"]["window"]["state"] = json!("closed");
        std::fs::write(
            fix.dir.join("store/groups/parish.example/group.json"),
            serde_json::to_vec_pretty(&group).unwrap(),
        )
        .unwrap();
        apply(&fix);

        // The binary, because cron mails what a job prints.
        let out = fix.drain_binary();
        assert!(out.status.success(), "{case}: {}", body(&out));
        let printed = body(&out);
        assert!(
            !printed.contains("the lapse notice for parish.example"),
            "{case}: the record failure is printed every pass: {printed}"
        );

        // One journal line and one mail for the owner's record. A corrupt
        // record is reported by the account sweep before the group loop, so the
        // notice's own report dedups to that line; a missing record is one no
        // sweep visits, so the notice's line carries the group's name too.
        assert_eq!(
            fix.journal().matches(phrase).count(),
            1,
            "{case}: {}",
            fix.journal()
        );
        assert_eq!(
            fix.journal()
                .matches("\"intent\":\"account:parish-secretary\"")
                .count(),
            1,
            "{case}: {}",
            fix.journal()
        );
        if case == "missing" {
            assert!(
                fix.journal()
                    .contains("parish.example's group notice has no addressee"),
                "{case}: {}",
                fix.journal()
            );
        }
        assert_eq!(
            fix.sent().matches(phrase).count(),
            1,
            "{case}: {}",
            fix.sent()
        );

        // Nothing was sent in the record's place, and a second pass repeats
        // neither the report nor the notice.
        assert!(
            !fix.read("accounts/parish-secretary/notices.jsonl")
                .contains("group.lapsed"),
            "{case}: a notice was recorded for a record it could not read"
        );
        assert!(
            !fix.sent()
                .contains("payment window for parish.example has closed"),
            "{case}: the notice fell back to the platform address: {}",
            fix.sent()
        );
        assert!(fix.drain_binary().status.success());
        assert_eq!(
            fix.journal().matches(phrase).count(),
            1,
            "{case}: a second pass reported again"
        );
        assert_eq!(
            fix.sent().matches(phrase).count(),
            1,
            "{case}: a second pass mailed again"
        );
    }
}

/// The grace's final notice comes once for the body, seven days before the
/// deletion, and the deletion closes every account in the group and takes the
/// domain down.
#[test]
fn a_group_grace_ends_in_one_deletion_of_every_account() {
    let fix = Fix::new("group-grace");
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
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    // The lapse already wrote the window closed. Twenty-nine days of grace
    // left is the midpoint: the grace notice is due, the final is not.
    group["payment"]["window"]["state"] = json!("closed");
    group["grace_until"] = json!(kyriakon_control_core::util::date_after_days(29));
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    assert!(fix.drain().status.success());
    let notices = fix.read("accounts/parish-secretary/notices.jsonl");
    assert_eq!(notices.matches("group.grace").count(), 1, "{notices}");
    assert!(
        !notices.contains("group.final"),
        "the final notice waits for its week: {notices}"
    );

    // Six days left: the final notice is due, once for the body.
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["grace_until"] = json!(kyriakon_control_core::util::date_after_days(6));
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    assert!(fix.drain().status.success());
    let notices = fix.read("accounts/parish-secretary/notices.jsonl");
    assert_eq!(notices.matches("group.final").count(), 1, "{notices}");
    assert!(
        notices.contains("seven days"),
        "the final notice names the date: {notices}"
    );
    assert!(
        !fix.read("accounts/parish-office/notices.jsonl")
            .contains("group.final"),
        "one final notice for the body"
    );

    // Past the grace: one deletion of every account and the domain.
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["grace_until"] = json!(kyriakon_control_core::util::date_after_days(-1));
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    for mailbox in ["parish-secretary", "parish-office"] {
        assert!(
            !fix.dir.join(format!("store/accounts/{mailbox}")).exists(),
            "{mailbox}'s record stayed"
        );
        assert!(
            !fix.passwd_file().contains(&format!("{mailbox}:")),
            "{mailbox} is still on the box: {}",
            fix.passwd_file()
        );
    }
    assert!(
        !fix.dir.join("store/groups/parish.example").exists(),
        "the group record stayed"
    );
    assert!(fix.names("tokens").is_empty(), "{:?}", fix.names("tokens"));
    let log = fix.scripts_log();
    assert!(
        log.contains("remove-group.sh parish.example"),
        "the domain came down: {log}"
    );
    assert!(
        fix.journal().contains("delete-group-parish.example"),
        "{}",
        fix.journal()
    );
}

/// The tier's own price: a group year is GBP 40, a GBP 20 credit is refused as
/// short with the ledger and the window untouched, and the approval mail names
/// the group's figure rather than a person's.
#[test]
fn a_group_year_is_forty_pounds_and_twenty_is_refused_as_short() {
    let fix = Fix::new("group-price");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let token = group["payment"]["token_ref"].as_str().unwrap().to_string();

    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-20",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert!(group["payment"]["paid_until"].is_null(), "{group}");
    assert_eq!(
        group["payment"]["window"]["state"],
        json!("open"),
        "{group}"
    );
    assert!(
        fix.journal().contains("GBP 20.00 is not enough"),
        "{}",
        fix.journal()
    );
    assert!(payment_lines(&fix).is_empty(), "{:?}", payment_lines(&fix));

    // The group's own price buys the year.
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "40.00",
        "--received",
        "2026-10-20",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert!(group["payment"]["paid_until"].is_string(), "{group}");
    let payments = payment_lines(&fix);
    assert_eq!(payments.len(), 1, "{payments:?}");
    assert_eq!(payments[0]["amount_gbp"], json!("40.00"), "{payments:?}");
    assert_eq!(payments[0]["applied_gbp"], json!("40.00"), "{payments:?}");
}

/// A body on the cash rail has no Stripe link, and its approval must not ask for
/// one: a box with no Payment Link configured still approves a cash group.
#[test]
fn a_cash_group_approval_does_not_need_a_stripe_link() {
    let fix = Fix::new("group-cash-nolink");
    let path = fix.config();
    let cfg = std::fs::read_to_string(&path).unwrap().replace(
        "stripe_payment_link = \"https://buy.stripe.com/test_example\"",
        "stripe_payment_link = \"\"",
    );
    std::fs::write(&path, cfg).unwrap();

    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.dir.join("store/groups/parish.example").exists(),
        "the group was not made"
    );
    assert!(
        !fix.journal()
            .contains("stripe_payment_link is not configured"),
        "{}",
        fix.journal()
    );
}

/// A card invoice after a group lapse brings every mailbox back: the renewal and
/// the prepaid credit share one restore loop.
#[test]
fn a_card_renewal_restores_a_lapsed_groups_mailboxes() {
    let fix = Fix::new("group-card-restore");
    let mut record = fix.filed_body("warden");
    record["rail"] = json!("card");
    record["answers"]["rail"] = json!("card");
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.dir.join("store/groups/parish.example").exists(),
        "the group was not approved: {}",
        fix.journal()
    );

    // The lapse stopped the mailbox; the invoice has not arrived yet.
    let mailbox = "parish-secretary";
    let mut account = fix.account(mailbox);
    account["state"] = json!("lapsed");
    account["grace_until"] = json!(kyriakon_control_core::util::date_after_days(10));
    std::fs::write(
        fix.dir
            .join(format!("store/accounts/{mailbox}/account.json")),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();
    let path = fix.dir.join("store/groups/parish.example/group.json");
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["grace_until"] = json!(kyriakon_control_core::util::date_after_days(10));
    group["payment"]["window"]["state"] = json!("closed");
    std::fs::write(&path, serde_json::to_vec_pretty(&group).unwrap()).unwrap();
    let token = group["payment"]["token_ref"].as_str().unwrap().to_string();
    fix.webhook(
        "evt_01_checkout",
        "checkout.session.completed",
        json!({
            "id": "cs_example",
            "client_reference_id": token,
            "subscription": SUBSCRIPTION,
            "customer": "cus_example",
        }),
    );
    fix.webhook(
        "evt_02_invoice",
        "invoice.paid",
        invoice_with("in_group_restore", 4_000, 1_790_000_000),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = fix.account(mailbox);
    assert_eq!(account["state"], json!("active"), "{mailbox}: {account}");
    assert!(account.get("grace_until").is_none(), "{mailbox}: {account}");
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert!(
        group.get("grace_until").is_none(),
        "the group kept its deletion date: {group}"
    );
    assert!(
        fix.scripts_log()
            .contains(&format!("lapse-user.sh --restore {mailbox}")),
        "{mailbox} was not restored: {}",
        fix.scripts_log()
    );
}

/// A held Monero payment can be attributed to a group's token: the item being
/// attributed is not a second sighting of its own transaction id.
#[test]
fn a_held_payment_can_be_attributed_to_a_group() {
    let fix = Fix::new("group-reconcile");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let token = group["payment"]["token_ref"].as_str().unwrap().to_string();

    let out = fix.ctl(&[
        "credit",
        "--rail",
        "monero",
        "--amount",
        "40.00",
        "--received",
        "2026-10-04",
        "--txid",
        TXID,
        "--note",
        "wallet main address, no token",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let held = held_lines(&fix);
    assert_eq!(held.len(), 1, "{held:?}");
    let id = held[0]["id"].as_str().unwrap().to_string();

    let out = fix.ctl(&["reconcile", "attribute", &id, "--token", &token]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.journal().contains("is already held"),
        "the group refused its own held item: {}",
        fix.journal()
    );
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(
        group["payment"]["paid_until"],
        json!("2027-10-04"),
        "{group}"
    );
    let held = held_lines(&fix);
    assert_eq!(held[0]["state"], json!("attributed"), "{held:?}");
    assert_eq!(held[0]["attributed_to"], json!(token), "{held:?}");
}

/// A domain removed and later re-added gets its own deletion: the journal id
/// carries the group's creation stamp, so the second lapse is not read as the
/// first one already applied.
#[test]
fn a_readded_group_gets_its_own_deletion() {
    let fix = Fix::new("group-readd");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["created_at"] = json!("2020-01-01T00:00:00Z");
    group["grace_until"] = json!(kyriakon_control_core::util::date_after_days(-1));
    group["payment"]["window"]["state"] = json!("closed");
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    assert!(fix.drain().status.success());
    assert!(
        !fix.dir.join("store/groups/parish.example").exists(),
        "the first group stayed"
    );
    assert!(
        fix.journal()
            .contains("delete-group-parish.example-2020-01-01T00:00:00Z"),
        "{}",
        fix.journal()
    );

    // The same domain, a new body: fresh names, because the first body's are
    // held for ninety days.
    fix.file_group(
        "parish.example",
        "newclerk",
        &[("secretary", "newclerk")],
        &["newclerk"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let stamp = group["created_at"].as_str().unwrap().to_string();
    assert_ne!(stamp, "2020-01-01T00:00:00Z", "{group}");
    group["grace_until"] = json!(kyriakon_control_core::util::date_after_days(-1));
    group["payment"]["window"]["state"] = json!("closed");
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir.join("store/groups/parish.example").exists(),
        "the second group stayed: the reused journal id hid the deletion"
    );
    assert!(
        fix.journal()
            .contains(&format!("delete-group-parish.example-{stamp}")),
        "{}",
        fix.journal()
    );
}

/// Closing the site owner's account does not remove the group's token: it is
/// indexed under that name but pays for the whole body.
#[test]
fn closing_a_site_owner_leaves_the_groups_token_alone() {
    let fix = Fix::new("group-token-owner");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let token = group["payment"]["token_ref"].as_str().unwrap().to_string();

    let out = fix.ctl(&["delete", "parish-secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.dir.join(format!("store/tokens/{token}.json")).exists(),
        "the group's token went with one of its mailboxes"
    );
    assert!(
        fix.dir.join("store/groups/parish.example").exists(),
        "the group went with one of its mailboxes"
    );
}

/// A group's card decision email carries the group's own Payment Link, keyed to
/// the group's token: a body's year is its own price.
#[test]
fn a_group_on_the_card_rail_receives_the_group_payment_link() {
    let fix = Fix::new("group-card-link");
    let mut record = fix.filed_body("warden");
    record["rail"] = json!("card");
    record["answers"]["rail"] = json!("card");
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    let token = group["payment"]["token_ref"].as_str().unwrap();
    let sent = fix.sent();
    assert!(
        sent.contains(&format!(
            "https://buy.stripe.com/test_group_example?client_reference_id={token}"
        )),
        "the group's approval did not carry the group link: {sent}"
    );
    assert!(
        !sent.contains(&format!(
            "https://buy.stripe.com/test_example?client_reference_id={token}"
        )),
        "the group's approval carried the account link: {sent}"
    );

    // The status page reads the application record, so the body's block has to
    // be there and not only on the root-owned group record.
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert_eq!(app["payment"]["token_ref"], json!(token), "{app}");
}

/// A group invoice below the group's year, in another currency, or for nothing
/// does not extend the group's date, even with the group's token on it.
#[test]
fn a_group_invoice_below_the_price_extends_nothing() {
    let fix = Fix::new("group-underpaid");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    let path = fix.dir.join("store/groups/parish.example/group.json");
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["payment"]["rail"] = json!("card");
    group["payment"]["stripe"]["subscription"] = json!(SUBSCRIPTION);
    std::fs::write(&path, serde_json::to_vec_pretty(&group).unwrap()).unwrap();
    let mut usd = invoice_with("in_group_usd", 4_000, 1_790_000_000);
    usd["currency"] = json!("usd");

    for (event, object) in [
        (
            "evt_group_zero",
            invoice_with("in_group_zero", 0, 1_790_000_000),
        ),
        (
            "evt_group_under",
            invoice_with("in_group_under", 3_999, 1_790_000_000),
        ),
        ("evt_group_usd", usd),
    ] {
        fix.webhook(event, "invoice.paid", object);
        let out = fix.drain();
        assert!(out.status.success(), "{}", body(&out));
        let group: Value =
            serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
        assert!(
            group["payment"]["paid_until"].is_null(),
            "{event} moved the group's date: {group}"
        );
    }
    assert!(payment_lines(&fix).is_empty(), "{:?}", payment_lines(&fix));
}

/// An address change for a domain with no group record settles as refused
/// rather than failing: a signed intent left armed would land on a later group
/// with the same domain, and a failure line keeps retrying it every pass.
#[test]
fn an_address_change_for_a_missing_group_settles_as_refused() {
    let fix = Fix::new("address-no-group");
    fix.file_address(
        "parish.example",
        "remove",
        "",
        "parish-secretary",
        None,
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let journal = fix.journal();
    assert!(journal.contains("\"outcome\":\"refused\""), "{journal}");
    assert!(journal.contains("no group for parish.example"), "{journal}");
    assert!(!journal.contains("\"outcome\":\"failed\""), "{journal}");
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
}
