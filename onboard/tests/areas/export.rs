use crate::common::*;

/// The export prints the tax year's dated lines and nothing else: a credit
/// outside the year is absent, the approval's undated `window_open` row is
/// absent, and no row carries a name, an address or a free-text note.
#[test]
fn the_export_prints_only_the_tax_year_and_never_a_name() {
    let fix = Fix::new("ledger-export-year");
    let inside = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &inside,
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let outside = approved_paid(&fix, "treasurer", "cash-hand");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &outside,
        "--rail",
        "cash-hand",
        "--amount",
        "20.00",
        "--received",
        "2026-04-05",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let out = fix.ctl(&[
        "ledger",
        "export",
        "--tax-year",
        "2026-27",
        "--format",
        "csv",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let csv = String::from_utf8_lossy(&out.stdout).into_owned();
    let keyed: Vec<&str> = csv.lines().take_while(|line| !line.is_empty()).collect();
    assert_eq!(keyed[0], EXPORT_HEADER, "{csv}");
    assert_eq!(
        keyed.len(),
        2,
        "one credit is in the year, one is not: {csv}"
    );

    let row: Vec<&str> = keyed[1].split(',').collect();
    assert_eq!(row[1], inside, "{csv}");
    assert_eq!(row[2], "payment", "{csv}");
    assert_eq!(row[3], "cash", "{csv}");
    assert_eq!(row[4], "2026-10-04", "{csv}");
    assert_eq!(row[5], "20.00", "{csv}");
    assert_eq!(row[6], "20.00", "{csv}");
    assert_eq!(row[7], "2027-10-04", "{csv}");

    assert!(!csv.contains(&outside), "{csv}");
    assert!(!csv.contains("secretary"), "{csv}");
    assert!(!csv.contains("treasurer"), "{csv}");
    assert!(!csv.contains('@'), "{csv}");
}

/// A refund is a negative line of its own, naming the `seq` it reverses, and
/// the free-text note stays out of the export.
#[test]
fn the_export_prints_a_refund_as_a_negative_row_naming_its_seq() {
    let fix = Fix::new("ledger-export-refund");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let credit_seq = payment_lines(&fix)[0]["seq"].as_u64().unwrap();

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "20.00",
        "--rail",
        "cash",
        "--reason",
        "secretary, cancelled inside 14 days",
        "--close",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let out = fix.ctl(&["refund", "--token", &token, "--settled", "2026-11-05"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let refund_seq = refund_lines(&fix)[0]["seq"].as_u64().unwrap();

    let out = fix.ctl(&[
        "ledger",
        "export",
        "--tax-year",
        "2026-27",
        "--format",
        "csv",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let csv = String::from_utf8_lossy(&out.stdout).into_owned();
    let row = csv
        .lines()
        .find(|line| line.starts_with(&format!("{refund_seq},")))
        .expect("the refund's row");
    let cells: Vec<&str> = row.split(',').collect();
    assert_eq!(cells[1], token, "{csv}");
    assert_eq!(cells[2], "refund", "{csv}");
    assert_eq!(cells[5], "-20.00", "{csv}");
    assert_eq!(cells[10], credit_seq.to_string(), "refund_of: {csv}");
    assert_eq!(cells[11], "2026-11-05", "settled_on: {csv}");
    assert!(!csv.contains("cancelled"), "{csv}");
    assert!(!csv.contains("secretary"), "{csv}");
}

/// Held money is not income and is not keyed, so it follows the keyed rows
/// under its own marker and header. A returned line, and a held line outside
/// the year, stay out; no keyed row loses its token. The ids come from the
/// commands that produce them, never a hand-typed `UN-` string.
#[test]
fn the_export_puts_held_money_after_its_own_marker() {
    let fix = Fix::new("ledger-export-held");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    // One held envelope, one returned envelope and one held payment from last
    // year. Each is filed and applied through the real console and drain.
    for (received, note) in [
        ("2026-10-08", "no token on the envelope"),
        ("2026-10-09", "returned envelope"),
        ("2026-04-05", "last year's post"),
    ] {
        let out = fix.ctl(&[
            "credit",
            "--rail",
            "cash",
            "--amount",
            "20.00",
            "--received",
            received,
            "--note",
            note,
        ]);
        assert!(out.status.success(), "{}", body(&out));
        assert!(fix.drain().status.success());
    }
    let held_id = held_lines(&fix)
        .iter()
        .find(|line| line["received_on"] == json!("2026-10-08"))
        .and_then(|line| line["id"].as_str())
        .expect("the held envelope has an id")
        .to_string();
    let returned_id = held_lines(&fix)
        .iter()
        .find(|line| line["received_on"] == json!("2026-10-09"))
        .and_then(|line| line["id"].as_str())
        .expect("the returned envelope has an id")
        .to_string();
    let out = fix.ctl(&[
        "reconcile",
        "return",
        &returned_id,
        "--note",
        "posted back 2026-10-10, receipt in book",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let out = fix.ctl(&[
        "ledger",
        "export",
        "--tax-year",
        "2026-27",
        "--format",
        "csv",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let csv = String::from_utf8_lossy(&out.stdout).into_owned();
    let (keyed, held) = csv
        .split_once("\n\n# unattributed\n")
        .expect("the held section is after a blank line");

    assert!(
        keyed.contains(&token),
        "the keyed row kept its token: {csv}"
    );
    assert!(!keyed.contains("UN-"), "held money is not keyed: {csv}");

    let mut lines = held.lines();
    assert_eq!(lines.next(), Some("id,rail,received_on,amount_gbp"));
    let rows: Vec<&str> = lines.collect();
    assert_eq!(
        rows,
        vec![format!("{held_id},cash,2026-10-08,20.00")],
        "a returned line and a held line from another year stay out: {csv}"
    );
    assert!(!csv.contains(&returned_id), "{csv}");
    assert!(!csv.contains("no token on the envelope"), "{csv}");
}

/// The export reads both ledgers strictly: a line that does not parse is a
/// failure, not a year with less money in it.
#[test]
fn the_export_refuses_a_ledger_it_cannot_read() {
    let fix = Fix::new("ledger-export-corrupt");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let export = |fix: &Fix| {
        fix.ctl(&[
            "ledger",
            "export",
            "--tax-year",
            "2026-27",
            "--format",
            "csv",
        ])
    };
    for rel in ["ledger/payments.jsonl", "ledger/unattributed.jsonl"] {
        let path = fix.dir.join("store").join(rel);
        let before = std::fs::read_to_string(&path).unwrap_or_default();
        std::fs::write(&path, format!("{before}{{not json}}\n")).unwrap();
        let out = export(&fix);
        assert!(!out.status.success(), "{rel} was read as empty");
        assert!(
            body(&out).contains("does not parse"),
            "{rel}: {}",
            body(&out)
        );
        std::fs::write(&path, before).unwrap();
    }
}

/// A year it cannot read and a format it does not print are refused; an empty
/// or missing ledger prints the headers and no rows.
#[test]
fn the_export_refuses_a_bad_year_and_a_format_that_is_not_csv() {
    let fix = Fix::new("ledger-export-refuses");
    for bad in ["2026-28", "2026-2028", "2026", "abcd-ef"] {
        let out = fix.ctl(&["ledger", "export", "--tax-year", bad, "--format", "csv"]);
        assert!(!out.status.success(), "{bad:?} was accepted");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--tax-year"),
            "{bad:?}: {}",
            body(&out)
        );
    }
    let out = fix.ctl(&[
        "ledger",
        "export",
        "--tax-year",
        "2026-27",
        "--format",
        "json",
    ]);
    assert!(
        !out.status.success(),
        "a format that is not csv was accepted"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not csv"),
        "{}",
        body(&out)
    );
    let out = fix.ctl(&["ledger", "export", "--tax-year", "2026-27"]);
    assert!(!out.status.success(), "--format is required");

    let out = fix.ctl(&[
        "ledger",
        "export",
        "--tax-year",
        "2026-27",
        "--format",
        "csv",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{EXPORT_HEADER}\n\n# unattributed\nid,rail,received_on,amount_gbp\n"),
        "a missing ledger reads as empty"
    );
}
