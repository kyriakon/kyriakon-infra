use crate::common::*;

/// A cancellation refund names the credit's `seq`, closes the account for seven
/// days, leaves `paid_until` alone, says when it will be settled, and a second
/// identical refund is refused naming the first.
#[test]
fn a_cash_cancellation_refund_is_posted_back_and_closes_the_account() {
    let fix = Fix::new("refund-cash-close");
    let token = approved_paid(&fix, "secretary", "cash");
    let credit = cash_credit(&fix, &token);
    let credit_seq = credit["seq"].as_u64().unwrap();
    let paid_until = fix.account("secretary")["payment"]["paid_until"].clone();

    let out = fix.ctl(&[
        "refund",
        "--username",
        "secretary",
        "--amount",
        "20.00",
        "--rail",
        "cash",
        "--reason",
        "cancelled inside 14 days",
        "--close",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let today = kyriakon_onboard::util::date_after_days(0);
    let refunds = refund_lines(&fix);
    assert_eq!(refunds.len(), 1, "{refunds:?}");
    let refund = &refunds[0];
    assert_eq!(refund["token"], json!(token));
    assert_eq!(refund["rail"], json!("cash"));
    assert_eq!(refund["amount_gbp"], json!("-20.00"));
    assert_eq!(refund["applied_gbp"], json!("-20.00"));
    assert_eq!(refund["refund_of"], json!(credit_seq));
    assert_eq!(refund["received_on"], json!(today));
    assert_eq!(refund["note"], json!("cancelled inside 14 days"));
    assert!(refund["settled_on"].is_null(), "{refund}");
    let refund_seq = refund["seq"].as_u64().unwrap();

    let account = fix.account("secretary");
    assert_eq!(account["state"], json!("closing"), "{account}");
    assert_eq!(
        account["closing_until"],
        json!(kyriakon_onboard::util::date_after_days(7)),
        "{account}"
    );
    assert_eq!(
        account["payment"]["paid_until"], paid_until,
        "a refund leaves paid_until alone: {account}"
    );

    // The notice states the settlement date, and the cash path holds no bank
    // detail at all.
    let notices = fix.read("accounts/secretary/notices.jsonl");
    assert!(notices.contains("prepaid.refund"), "{notices}");
    let sent = fix.sent();
    let settled_by = kyriakon_onboard::util::date_after_days(14);
    assert!(
        sent.contains("posted back"),
        "cash goes back as post: {sent}"
    );
    assert!(
        sent.contains(&settled_by),
        "the notice names the settlement date: {sent}"
    );
    for word in ["sort code", "account number", "iban", "bank"] {
        assert!(
            !sent.to_lowercase().contains(word),
            "the cash path names {word}: {sent}"
        );
    }

    // The same refund again: refused, naming the first line's seq and date.
    let out = fix.ctl(&[
        "refund",
        "--username",
        "secretary",
        "--amount",
        "20.00",
        "--rail",
        "cash",
        "--reason",
        "cancelled inside 14 days",
        "--close",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(refund_lines(&fix).len(), 1, "a second line was written");
    let journal = fix.journal();
    assert!(
        journal.contains(&format!(
            "an identical refund is already recorded at ledger seq {refund_seq} on {today}"
        )),
        "{journal}"
    );
}

/// An excess refund gives back held overpayment. It takes that money out of
/// `balance_gbp`, touches neither the account's state nor its paid-until date,
/// and the refunded money cannot then buy access.
#[test]
fn an_excess_refund_spends_the_held_balance_and_leaves_the_state_alone() {
    let fix = Fix::new("refund-excess");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "30.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let credit = payment_lines(&fix).remove(0);
    let before = fix.account("secretary");
    assert_eq!(before["payment"]["balance_gbp"], json!("10.00"), "{before}");

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "10.00",
        "--rail",
        "cash",
        "--reason",
        "overpaid on a duplicate envelope",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let refunds = refund_lines(&fix);
    assert_eq!(refunds.len(), 1, "{refunds:?}");
    assert_eq!(refunds[0]["amount_gbp"], json!("-10.00"));
    assert_eq!(refunds[0]["refund_of"], credit["seq"]);
    let after = fix.account("secretary");
    assert_eq!(after["state"], before["state"], "{after}");
    assert_eq!(
        after["payment"]["paid_until"], before["payment"]["paid_until"],
        "{after}"
    );
    assert!(
        after.get("closing_until").is_none(),
        "an excess refund closes nothing: {after}"
    );
    assert!(
        after["payment"]["balance_gbp"].is_null(),
        "the refunded balance is still spendable: {after}"
    );

    // The refunded money is gone: the next GBP 10.00 is a shortfall, so the
    // paid-until date does not move.
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "10.00",
        "--received",
        "2027-10-05",
        "--confirm-double",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.account("secretary")["payment"]["paid_until"],
        json!("2027-10-04"),
        "the refunded balance bought a year"
    );
}

/// Refunds of one payment sum to no more than the payment, whatever their
/// sizes. The balance check alone can miss a balance that is larger than one
/// payment, so the sum is checked across lines naming the same `refund_of`.
#[test]
fn refunds_of_one_payment_cannot_exceed_it() {
    let fix = Fix::new("refund-sum");
    let token = approved_paid(&fix, "secretary", "cash");
    let credit = cash_credit(&fix, &token);
    // Make the balance larger than the payment, so the balance cap alone would
    // let the second refund through.
    let mut account = fix.account("secretary");
    account["payment"]["balance_gbp"] = json!("100.00");
    std::fs::write(
        fix.dir.join("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "15.00",
        "--rail",
        "cash",
        "--reason",
        "partial excess",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    assert_eq!(refund_lines(&fix).len(), 1);

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "10.00",
        "--rail",
        "cash",
        "--reason",
        "the rest of the excess",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let refunds = refund_lines(&fix);
    assert_eq!(
        refunds.len(),
        1,
        "two refunds exceeded the payment: {refunds:?}"
    );
    assert_eq!(refunds[0]["refund_of"], credit["seq"]);
    assert!(
        fix.journal().contains("would exceed the GBP 20.00"),
        "{}",
        fix.journal()
    );
}

/// Two refunds of the same amount are two notices. The notices record dedups
/// on (type, subject), so the subject carries the ledger seq.
#[test]
fn two_refunds_of_one_amount_send_two_notices() {
    let fix = Fix::new("refund-notices");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_credit(&fix, &token);
    // Refund the first payment, then take a second payment of the same amount
    // and refund it too. Only the ledger seq makes the two notices distinct.
    for received in ["2026-10-04", "2026-10-05"] {
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

        let out = fix.ctl(&[
            "credit",
            "--token",
            &token,
            "--rail",
            "cash",
            "--amount",
            "20.00",
            "--received",
            received,
            "--confirm-double",
        ]);
        assert!(out.status.success(), "{}", body(&out));
        assert!(fix.drain().status.success());
    }
    let refunds = refund_lines(&fix);
    assert_eq!(refunds.len(), 2, "{refunds:?}");
    let notices = fix.read("accounts/secretary/notices.jsonl");
    assert_eq!(
        notices.matches("prepaid.refund").count(),
        2,
        "a second same-amount refund was deduplicated away: {notices}"
    );
    for line in &refunds {
        let seq = line["seq"].as_u64().unwrap();
        assert!(
            notices.contains(&format!("refund {seq}")),
            "the notice does not name refund {seq}: {notices}"
        );
    }
}

/// A refund never leaves on a rail other than the one the payment arrived on.
#[test]
fn a_refund_on_the_wrong_rail_is_refused() {
    let fix = Fix::new("refund-rail");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_credit(&fix, &token);

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "20.00",
        "--rail",
        "monero",
        "--reason",
        "cancelled inside 14 days",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(refund_lines(&fix).is_empty(), "{:?}", refund_lines(&fix));
    let journal = fix.journal();
    assert!(journal.contains("the payment arrived by cash"), "{journal}");
    assert!(
        !fix.read("accounts/secretary/notices.jsonl")
            .contains("prepaid.refund"),
        "a refused refund sends no notice"
    );
}

/// A Monero refund returns the XMR recorded on the receipt line; with `--rate`
/// it records the sterling basis and the rate instead, and the ledger shows
/// which of the two it was.
#[test]
fn a_monero_refund_returns_the_recorded_xmr_or_names_the_sterling_rate() {
    let fix = Fix::new("refund-monero-xmr");
    let token = approved_paid(&fix, "secretary", "monero");
    monero_credit(&fix, &token);
    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "20.00",
        "--rail",
        "monero",
        "--reason",
        "cancelled inside 14 days",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let refunds = refund_lines(&fix);
    assert_eq!(refunds.len(), 1, "{refunds:?}");
    assert_eq!(refunds[0]["amount_xmr"], json!("0.048847"), "{refunds:?}");
    assert_eq!(refunds[0]["refund_basis"], json!("recorded_xmr"));
    assert!(refunds[0]["rate_refund"].is_null(), "{refunds:?}");

    let rated = Fix::new("refund-monero-rate");
    let token = approved_paid(&rated, "secretary", "monero");
    monero_credit(&rated, &token);
    let out = rated.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "20.00",
        "--rail",
        "monero",
        "--reason",
        "member asked for sterling",
        "--excess",
        "--rate",
        "409.44",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = rated.drain();
    assert!(out.status.success(), "{}", body(&out));

    let refunds = refund_lines(&rated);
    assert_eq!(refunds.len(), 1, "{refunds:?}");
    assert_eq!(refunds[0]["amount_xmr"], json!("0.048847"), "{refunds:?}");
    assert_eq!(refunds[0]["refund_basis"], json!("sterling"));
    assert_eq!(refunds[0]["rate_refund"], json!("409.44"));
}

/// `--settled` completes the newest unsettled refund line and nothing else; a
/// settlement with no such line is refused.
#[test]
fn a_settlement_rewrites_only_settled_on_and_a_second_finds_none() {
    let fix = Fix::new("refund-settled");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_credit(&fix, &token);
    let out = fix.ctl(&[
        "refund", "--token", &token, "--amount", "5.00", "--rail", "cash", "--reason", "overpaid",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let before = refund_lines(&fix).remove(0);
    let lines_before = ledger_lines(&fix).len();

    let out = fix.ctl(&[
        "refund",
        "--username",
        "secretary",
        "--settled",
        "2026-11-05",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let refunds = refund_lines(&fix);
    assert_eq!(
        refunds.len(),
        1,
        "the settlement appended a line: {refunds:?}"
    );
    assert_eq!(ledger_lines(&fix).len(), lines_before, "a line was added");
    assert_eq!(refunds[0]["settled_on"], json!("2026-11-05"));
    for field in [
        "seq",
        "token",
        "kind",
        "rail",
        "received_on",
        "amount_gbp",
        "applied_gbp",
        "paid_until_after",
        "amount_xmr",
        "txid",
        "intent",
        "note",
        "refund_of",
        "refund_basis",
    ] {
        assert_eq!(
            refunds[0][field], before[field],
            "the settlement moved {field}: {refunds:?}"
        );
    }

    // Nothing is left unsettled, so a second settlement is refused and the
    // first date stays.
    let out = fix.ctl(&[
        "refund",
        "--username",
        "secretary",
        "--settled",
        "2026-11-06",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        refund_lines(&fix)[0]["settled_on"],
        json!("2026-11-05"),
        "a refused settlement moved the date"
    );
    let journal = fix.journal();
    assert!(journal.contains("no unsettled refund"), "{journal}");
}

/// A paid card invoice opens a `kind:"payment"`, `rail:"card"` ledger line, so a
/// card refund has a `seq` to name; the refund prints the `refund-<seq>`
/// idempotency key for the human Stripe step.
#[test]
fn a_card_invoice_appends_a_line_and_a_card_refund_names_it() {
    let fix = Fix::new("card-ledger-refund");
    fix.card_account("secretary", None);
    fix.webhook("evt_card", "invoice.paid", invoice("in_card"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let payments = payment_lines(&fix);
    assert_eq!(payments.len(), 1, "{payments:?}");
    assert_eq!(payments[0]["kind"], json!("payment"));
    assert_eq!(payments[0]["rail"], json!("card"));
    assert_eq!(payments[0]["token"], json!("KYR-AAAA-BBBB-CCCC"));
    assert_eq!(payments[0]["amount_gbp"], json!("20.00"));
    assert_eq!(payments[0]["applied_gbp"], json!("20.00"));
    assert_eq!(
        payments[0]["received_on"],
        json!("2026-09-21"),
        "the invoice's paid date, not the drain's clock"
    );
    assert_eq!(payments[0]["intent"], json!("in_card"));
    assert_eq!(
        payments[0]["paid_until_after"],
        fix.account("secretary")["payment"]["paid_until"]
    );

    // A crash between the account save and the append leaves no line; the
    // invoice id is the dedup key that finishes it on the next pass.
    std::fs::write(fix.dir.join("store/ledger/payments.jsonl"), "").unwrap();
    std::fs::remove_file(fix.dir.join("store/webhooks/processed.jsonl")).unwrap();
    fix.webhook("evt_card", "invoice.paid", invoice("in_card"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let payments = payment_lines(&fix);
    assert_eq!(
        payments.len(),
        1,
        "the recovery appended twice: {payments:?}"
    );
    assert_eq!(payments[0]["intent"], json!("in_card"));
    let paid_seq = payments[0]["seq"].as_u64().unwrap();

    let out = fix.ctl(&[
        "refund",
        "--username",
        "secretary",
        "--amount",
        "20.00",
        "--rail",
        "card",
        "--reason",
        "cancelled inside 14 days",
        "--close",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let refunds = refund_lines(&fix);
    assert_eq!(refunds.len(), 1, "{refunds:?}");
    assert_eq!(refunds[0]["rail"], json!("card"));
    assert_eq!(refunds[0]["refund_of"], json!(paid_seq));
    let refund_seq = refunds[0]["seq"].as_u64().unwrap();
    assert!(
        fix.journal()
            .contains(&format!("Idempotency-Key refund-{refund_seq}")),
        "{}",
        fix.journal()
    );
}
