//! The console parsing and formatting tests.

use super::*;
use crate::payments::ledger::{csv_cell, export_section, payment_columns, tax_year, Section};
use crate::requests::{header_from, message_from};
use kyriakon_control_core::payments::ledger::RefundTail;

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn flags_read_pairs_and_refuse_a_bad_shape() {
    let map = flags(
        &args(&["--username", "alice", "--kind", "access"]),
        &["username", "kind"],
    )
    .unwrap();
    assert_eq!(map["username"], "alice");
    assert_eq!(map["kind"], "access");

    assert!(matches!(
        flags(&args(&["--nope", "x"]), &["username"]).unwrap_err(),
        Error::Failed(message) if message.contains("unknown flag")
    ));
    assert!(matches!(
        flags(
            &args(&["--username", "a", "--username", "b"]),
            &["username"]
        )
        .unwrap_err(),
        Error::Failed(message) if message.contains("given twice")
    ));
    assert!(matches!(
        flags(&args(&["--username"]), &["username"]).unwrap_err(),
        Error::Failed(message) if message.contains("needs a value")
    ));
    assert!(matches!(
        flags(&args(&["alice"]), &["username"]).unwrap_err(),
        Error::Failed(message) if message.contains("unexpected argument")
    ));
}

#[test]
fn one_username_takes_exactly_one_valid_name() {
    let show = args(&["show", "alice"]);
    assert_eq!(one_username(&show).unwrap(), "alice");
    assert!(one_username(&args(&["show"])).is_err());
    assert!(one_username(&args(&["show", "alice", "extra"])).is_err());
    assert!(matches!(
        one_username(&args(&["show", "Alice"])).unwrap_err(),
        Error::Failed(message) if message.contains("starts with")
    ));
}

#[test]
fn a_decision_takes_a_username_and_a_token() {
    let token = "0123456789abcdefghjkmnpqrs";
    let argv = args(&["approve", "alice", token]);
    let (username, parsed) = application_args(&argv).unwrap();
    assert_eq!((username, parsed), ("alice", token));
    // The token is not optional: the console will not guess which application
    // the operator read.
    assert!(application_args(&args(&["approve", "alice"])).is_err());
    assert!(application_args(&args(&["approve"])).is_err());
    assert!(application_args(&args(&["approve", "alice", token, "extra"])).is_err());
    assert!(matches!(
        application_args(&args(&["approve", "Alice", token])).unwrap_err(),
        Error::Failed(message) if message.contains("starts with")
    ));
}

#[test]
fn a_tax_year_is_six_april_to_five_april_in_either_spelling() {
    let (start, end) = tax_year("2026-27").unwrap();
    assert_eq!(start.to_string(), "2026-04-06");
    assert_eq!(end.to_string(), "2027-04-05");
    assert_eq!(tax_year("2026-2027").unwrap(), (start, end));

    // The two spellings agree across the century's end, where the
    // two-digit form wraps and the four-digit one does not.
    let (start, end) = tax_year("2099-00").unwrap();
    assert_eq!(start.to_string(), "2099-04-06");
    assert_eq!(end.to_string(), "2100-04-05");
    assert_eq!(tax_year("2099-2100").unwrap(), (start, end));

    for bad in [
        "2026-28",
        "2026-2026",
        "2026-26",
        "2026-2",
        "2026",
        "26-27",
        "2026-27-1",
        "abcd-ef",
    ] {
        assert!(tax_year(bad).is_err(), "{bad:?} was accepted");
    }
}

fn export_refund(received_on: &str, settled_on: Option<&str>) -> LedgerLine {
    let mut line = LedgerLine::empty("KYR-AAAA-BBBB-CCCC", "refund", "cash");
    line.received_on = Some(received_on.to_string());
    line.amount_gbp = Some("-20.00".to_string());
    line.applied_gbp = Some("-20.00".to_string());
    line.refund = Some(RefundTail {
        refund_of: Some(3),
        settled_on: settled_on.map(str::to_string),
        refund_basis: Some("recorded_xmr".to_string()),
        rate_refund: Some("410.00".to_string()),
    });
    line
}

#[test]
fn a_refund_is_taxed_in_the_year_it_was_paid_not_the_year_it_was_filed() {
    let refund = export_refund("2026-04-01", Some("2026-04-08"));
    let (start, end) = tax_year("2025-26").unwrap();
    assert_eq!(
        export_section(&refund, start, end),
        Section::Elsewhere,
        "a refund paid after 5 April is not a deduction in the closing year"
    );
    let (start, end) = tax_year("2026-27").unwrap();
    assert_eq!(export_section(&refund, start, end), Section::Takings);
}

#[test]
fn an_unsettled_refund_is_listed_apart_and_never_counts_as_takings() {
    let unsettled = export_refund("2026-04-01", None);
    for year in ["2025-26", "2026-27"] {
        let (start, end) = tax_year(year).unwrap();
        assert_ne!(
            export_section(&unsettled, start, end),
            Section::Takings,
            "{year} took an unpaid refund as a negative row"
        );
    }
    let (start, end) = tax_year("2025-26").unwrap();
    assert_eq!(
        export_section(&unsettled, start, end),
        Section::UnsettledRefund
    );
}

#[test]
fn the_export_carries_the_refund_basis_and_both_rates() {
    let columns = payment_columns();
    let names: Vec<&str> = columns.iter().map(|(name, _)| *name).collect();
    for name in [
        "refund_basis",
        "rate_refund",
        "rate_received",
        "rate_received_source",
        "rate_received_at",
    ] {
        assert!(names.contains(&name), "{name} is not an export column");
    }
    let value = |name: &str, line: &LedgerLine| {
        (columns
            .iter()
            .find(|(column, _)| *column == name)
            .unwrap()
            .1)(line)
    };
    let refund = export_refund("2026-04-01", Some("2026-04-08"));
    assert_eq!(value("refund_basis", &refund), "recorded_xmr");
    assert_eq!(value("rate_refund", &refund), "410.00");

    let mut payment = LedgerLine::empty("KYR-AAAA-BBBB-CCCC", "payment", "monero");
    payment.rate_received = Some("409.44".to_string());
    payment.rate_received_source = Some("coingecko".to_string());
    payment.rate_received_at = Some("2026-10-01T09:00:00Z".to_string());
    assert_eq!(value("rate_received", &payment), "409.44");
    assert_eq!(value("rate_received_source", &payment), "coingecko");
    assert_eq!(value("rate_received_at", &payment), "2026-10-01T09:00:00Z");
}

#[test]
fn a_csv_cell_is_quoted_only_when_it_has_to_be() {
    assert_eq!(csv_cell("cash"), "cash");
    assert_eq!(csv_cell("20.00"), "20.00");
    assert_eq!(csv_cell("a,b"), "\"a,b\"");
    assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
    assert_eq!(csv_cell("a\nb"), "\"a\nb\"");
    assert_eq!(csv_cell("a\rb"), "\"a\rb\"");
    assert_eq!(csv_cell(""), "");
}

const SIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n\
                          From: Alice <alice@kyriakon.net>\n\nPlease send me a copy.\n\
                          -----BEGIN PGP SIGNATURE-----\n\nAAAA\n\
                          -----END PGP SIGNATURE-----\n";

#[test]
fn a_delivered_message_takes_its_from_outside_the_armour() {
    let message = format!(
        "From: Alice <alice@kyriakon.net>\nTo: admin@kyriakon.net\n\
             Subject: my data\n\n{SIGNED}"
    );
    assert_eq!(message_from(&message).unwrap(), "alice@kyriakon.net");
}

#[test]
fn a_folded_from_header_is_unfolded() {
    let message = "From: A Long Name\n <alice@kyriakon.net>\nTo: admin@kyriakon.net\n\nPlease.\n";
    assert_eq!(message_from(message).unwrap(), "alice@kyriakon.net");
}

#[test]
fn an_outer_from_that_differs_from_the_armour_is_refused() {
    let message = format!("From: attacker@evil.example\nTo: admin@kyriakon.net\n\n{SIGNED}");
    let err = message_from(&message).unwrap_err();
    assert!(
        matches!(&err, Error::Failed(message) if message.contains("attacker@evil.example") && message.contains("alice@kyriakon.net")),
        "{err}"
    );
}

#[test]
fn a_quoted_signed_request_under_another_from_is_refused() {
    let message = format!(
        "From: attacker@evil.example\nTo: admin@kyriakon.net\nSubject: fwd\n\n\
             Here is their signed request:\n\n{SIGNED}"
    );
    let err = message_from(&message).unwrap_err();
    assert!(
        matches!(&err, Error::Failed(message) if message.contains("but the clearsigned one is alice@kyriakon.net")),
        "{err}"
    );
}

/// The `From:` of a delivered message is its sender's to write. It is kept as
/// sent, so the comparison with the account's address reads the real value, and
/// the escape is dropped when the refusal is printed.
#[test]
fn an_escape_in_a_from_header_never_reaches_the_terminal() {
    let hostile = "\x1b[2J\x1b]0;pwned\x07 attacker@evil.example";
    assert!(header_from("From: \x1b[2Jattacker@evil.example\n\n")
        .unwrap()
        .unwrap()
        .contains('\x1b'));
    let message = format!("From: {hostile}\r\nSubject: hi\r\n\r\n{SIGNED}");
    let err = message_from(&message).unwrap_err();
    let printed = util::report_lines(&err, "verifying a request").join("\n");
    assert!(!printed.chars().any(char::is_control), "{printed:?}");
    assert!(printed.contains("attacker@evil.example"), "{printed:?}");
}

/// `delete` accepts a journal line only when the id is `delete-<name>-` plus an
/// RFC 3339 time, the shape the transition writes. A hyphenated account's line
/// (`delete-bo-x-…`) must not make `delete bo` claim an erasure that never ran.
#[test]
fn a_deletion_line_owns_only_its_own_account() {
    assert!(account::owns_delete("delete-bo-2024-01-01T00:00:00Z", "bo"));
    assert!(!account::owns_delete(
        "delete-bo-x-2024-01-01T00:00:00Z",
        "bo"
    ));
    assert!(account::owns_delete(
        "delete-bo-x-2024-01-01T00:00:00Z",
        "bo-x"
    ));
    assert!(!account::owns_delete("delete-bo-", "bo"));
    assert!(!account::owns_delete("delete-bo-not-a-time", "bo"));
    assert!(!account::owns_delete("account:bo", "bo"));
}
