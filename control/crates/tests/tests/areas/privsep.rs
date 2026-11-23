use crate::common::*;

/// Write the journal line an approval leaves before it provisions, binding the
/// token to the person application's username.
fn approval_started(fix: &Fix, username: &str) {
    std::fs::write(
        fix.path("store/journal.jsonl"),
        format!(
            "{{\"version\":1,\"at\":\"2026-10-02T09:00:00Z\",\"intent\":\"01H\",\"kind\":\"approve\",\"release\":\"test\",\"application\":{{\"username\":\"{username}\",\"status_token\":\"{TOKEN}\"}},\"outcome\":\"applying\"}}\n"
        ),
    )
    .unwrap();
}

/// A group mailbox already holds the name. A retry of a person approval under
/// that name must not adopt the group's account and overwrite it.
#[test]
fn a_person_approval_retry_refuses_a_group_mailbox_with_the_same_name() {
    let fix = Fix::new("privsep-retry-group-account");
    fix.file_group(
        "parish.example",
        "clash",
        &[("secretary", "clash")],
        &["clash"],
        None,
    );
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.account("clash")["group"],
        json!("parish.example"),
        "the fixture did not make a group mailbox"
    );

    let record = fix.filed("clash", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    approval_started(&fix, "clash");
    let sig = fix.sign_action_for("approve", "clash");
    fix.write_decision("approve", "approve", &sig, "clash");
    assert!(fix.drain().status.success());

    assert!(
        fix.failed_note().contains("belongs to a group"),
        "{}",
        fix.failed_note()
    );
    assert_eq!(
        fix.account("clash")["group"],
        json!("parish.example"),
        "a person retry took the group mailbox: {}",
        fix.account("clash")
    );
}

/// A decline's half-made recovery erases only the account its approval began
/// for a person. A group mailbox under that name is another transition's.
#[test]
fn a_person_decline_refuses_to_erase_a_group_mailbox() {
    let fix = Fix::new("privsep-decline-group-account");
    fix.file_group(
        "parish.example",
        "clash",
        &[("secretary", "clash")],
        &["clash"],
        None,
    );
    assert!(fix.drain().status.success());

    let record = fix.filed("clash", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    approval_started(&fix, "clash");
    let sig = fix.sign_action_for("decline", "clash");
    fix.write_decision("decline", "decline", &sig, "clash");
    assert!(fix.drain().status.success());

    assert_eq!(
        fix.account("clash")["group"],
        json!("parish.example"),
        "a person decline erased the group mailbox: {}",
        fix.account("clash")
    );
}
