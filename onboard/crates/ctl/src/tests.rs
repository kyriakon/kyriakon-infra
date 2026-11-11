//! The console parsing and formatting tests.

use super::*;
use crate::payments::ledger::{csv_cell, tax_year};
use crate::requests::message_from;

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
