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

    let today = kyriakon_control_core::util::date_after_days(0);
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
        json!(kyriakon_control_core::util::date_after_days(7)),
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
    let settled_by = kyriakon_control_core::util::date_after_days(14);
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

/// Money that bought time does not come back as excess: an `--excess` refund is
/// capped at the part of the payment that never bought time, and the refusal
/// names the amount that arrived and the amount that was applied.
#[test]
fn an_excess_refund_of_applied_money_is_refused() {
    let fix = Fix::new("refund-excess-applied");
    let token = approved_paid(&fix, "secretary", "cash");
    let credit = cash_credit(&fix, &token);
    assert_eq!(credit["applied_gbp"], json!("20.00"), "{credit}");
    let before = fix.account("secretary");
    assert_eq!(
        before["payment"]["paid_until"],
        json!("2027-10-04"),
        "{before}"
    );

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "20.00",
        "--rail",
        "cash",
        "--reason",
        "asked for the money back",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(refund_lines(&fix).is_empty(), "{:?}", refund_lines(&fix));
    let journal = fix.journal();
    assert!(
        journal.contains("that never bought time (GBP 20.00 arrived, GBP 20.00 of it was applied)"),
        "{journal}"
    );
    let after = fix.account("secretary");
    assert_eq!(
        after["payment"]["paid_until"],
        json!("2027-10-04"),
        "{after}"
    );
    assert!(after["payment"]["balance_gbp"].is_null(), "{after}");
    assert_eq!(after["state"], before["state"], "{after}");
}

/// An overpayment is refundable only up to the part that never bought time: a
/// penny more than that is refused and changes nothing, and the excess itself
/// comes back with the paid-until date left alone.
#[test]
fn an_excess_refund_is_capped_at_the_overpayment() {
    let fix = Fix::new("refund-excess-cap");
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
    assert_eq!(credit["applied_gbp"], json!("20.00"), "{credit}");
    let before = fix.account("secretary");
    assert_eq!(before["payment"]["balance_gbp"], json!("10.00"), "{before}");

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "10.01",
        "--rail",
        "cash",
        "--reason",
        "a penny too much",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    assert!(refund_lines(&fix).is_empty(), "{:?}", refund_lines(&fix));
    assert!(
        fix.journal()
            .contains("more than the GBP 10.00 of ledger seq"),
        "{}",
        fix.journal()
    );
    let after = fix.account("secretary");
    assert_eq!(after["payment"]["balance_gbp"], json!("10.00"), "{after}");
    assert_eq!(
        after["payment"]["paid_until"],
        json!("2027-10-04"),
        "{after}"
    );

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
    assert!(fix.drain().status.success());
    let refunds = refund_lines(&fix);
    assert_eq!(refunds.len(), 1, "{refunds:?}");
    assert_eq!(refunds[0]["amount_gbp"], json!("-10.00"));
    assert_eq!(refunds[0]["refund_of"], credit["seq"]);
    let after = fix.account("secretary");
    assert!(after["payment"]["balance_gbp"].is_null(), "{after}");
    assert_eq!(
        after["payment"]["paid_until"],
        json!("2027-10-04"),
        "{after}"
    );
    assert_eq!(after["state"], before["state"], "{after}");
}

/// A payment that applied nothing — a shortfall, or a duplicate the ledger
/// holds — is refundable in full as excess, because none of it bought time.
#[test]
fn an_excess_refund_of_a_payment_that_applied_nothing_is_the_full_amount() {
    let fix = Fix::new("refund-excess-applied-zero");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "10.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let credit = payment_lines(&fix).remove(0);
    assert_eq!(credit["applied_gbp"], json!("0.00"), "{credit}");
    let before = fix.account("secretary");
    assert!(before["payment"]["paid_until"].is_null(), "{before}");
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
        "duplicate envelope returned",
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
    assert!(after["payment"]["balance_gbp"].is_null(), "{after}");
    assert!(after["payment"]["paid_until"].is_null(), "{after}");
    assert_eq!(after["state"], before["state"], "{after}");
}

/// An `--excess` refund on a payment line with no applied figure is refused:
/// an old or truncated line is unknown, not fully unapplied, and a refund must
/// not treat the whole payment as held money.
#[test]
fn an_excess_refund_of_a_line_with_no_applied_figure_is_refused() {
    let fix = Fix::new("refund-excess-no-applied");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_credit(&fix, &token);
    let path = fix.dir.join("store/ledger/payments.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines = Vec::new();
    for line in text.lines() {
        let mut value: Value = serde_json::from_str(line).unwrap();
        if value["kind"] == json!("payment") {
            value.as_object_mut().unwrap().remove("applied_gbp");
        }
        lines.push(serde_json::to_string(&value).unwrap());
    }
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let out = fix.ctl(&[
        "refund", "--token", &token, "--amount", "5.00", "--rail", "cash", "--reason", "overpaid",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(refund_lines(&fix).is_empty(), "{:?}", refund_lines(&fix));
    assert!(
        fix.journal()
            .contains("records no applied amount, so an --excess refund cannot tell"),
        "{}",
        fix.journal()
    );
}

/// The one-percent tolerance can apply the price to money slightly below it, so
/// the unapplied part is negative. The refusal names GBP 0.00 rather than a
/// negative amount, and no excess refund can pass it.
#[test]
fn an_excess_refund_of_a_rounded_up_shortfall_shows_zero() {
    let fix = Fix::new("refund-excess-band");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "19.80",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let credit = payment_lines(&fix).remove(0);
    assert_eq!(credit["amount_gbp"], json!("19.80"), "{credit}");
    assert_eq!(credit["applied_gbp"], json!("20.00"), "{credit}");
    let before = fix.account("secretary");
    assert_eq!(
        before["payment"]["paid_until"],
        json!("2027-10-04"),
        "{before}"
    );

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "1.00",
        "--rail",
        "cash",
        "--reason",
        "asked for it back",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(refund_lines(&fix).is_empty(), "{:?}", refund_lines(&fix));
    let journal = fix.journal();
    assert!(
        journal.contains(&format!(
            "more than the GBP 0.00 of ledger seq {} that never bought time (GBP 19.80 arrived, GBP 20.00 of it was applied)",
            credit["seq"]
        )),
        "{journal}"
    );
    assert!(
        !journal.contains("0.-"),
        "the refusal printed a negative amount: {journal}"
    );
    let after = fix.account("secretary");
    assert_eq!(
        after["payment"]["paid_until"],
        json!("2027-10-04"),
        "{after}"
    );
}

/// Refunds of one payment sum to no more than its unapplied part, whatever
/// their sizes: the per-refund check alone lets two partial refunds overshoot.
/// The sums are checked across lines naming the same `refund_of`.
#[test]
fn excess_refunds_of_one_payment_cannot_exceed_the_unapplied_part() {
    let fix = Fix::new("refund-sum");
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

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "5.00",
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
        "6.00",
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
        "two refunds exceeded the excess: {refunds:?}"
    );
    assert_eq!(refunds[0]["refund_of"], credit["seq"]);
    assert!(
        fix.journal()
            .contains("would exceed the GBP 10.00 that never bought time"),
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
        "--close",
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
        "--close",
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
    cash_overpayment(&fix, &token);
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
        "--seq",
        &before["seq"].as_u64().unwrap().to_string(),
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
    assert_eq!(
        refunds[0]["settled_on"],
        json!("2026-11-05"),
        "journal: {}",
        fix.journal()
    );
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
        "--seq",
        &before["seq"].as_u64().unwrap().to_string(),
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
    assert!(
        journal.contains("was already settled on 2026-11-05"),
        "{journal}"
    );
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
    std::fs::remove_file(fix.dir.join("store/verified/processed.jsonl")).unwrap();
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
    // The cancellation refund closes the account, so the card stops once and
    // the flag is saved with the closing state.
    let log = fix.scripts_log();
    assert_eq!(
        log.matches("stripe-api.sh cancel sub_example").count(),
        1,
        "{log}"
    );
    assert_eq!(
        fix.account("secretary")["payment"]["stripe"]["cancel_at_period_end"],
        json!(true)
    );
    assert!(
        fix.journal()
            .contains(&format!("Idempotency-Key refund-{refund_seq}")),
        "{}",
        fix.journal()
    );
}

/// A group's fee is one payment of the whole price, applied in full, so there
/// is no unapplied part for `--excess` to return. The refusal names the
/// payment and the applied part, and points at the transition that ends the
/// group and its year.
#[test]
fn a_group_excess_refund_is_capped_and_names_group_remove() {
    let fix = Fix::new("group-refund");
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
        "40.00",
        "--received",
        "2026-10-20",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let credit = payment_lines(&fix).remove(0);
    assert_eq!(credit["applied_gbp"], json!("40.00"), "{credit}");
    let credit_seq = credit["seq"].as_u64().unwrap();
    let paid_until = serde_json::from_str::<Value>(&fix.read("groups/parish.example/group.json"))
        .unwrap()["payment"]["paid_until"]
        .clone();

    // A mailbox name resolves to the group's token, and the whole fee cannot
    // come back as excess.
    let out = fix.ctl(&[
        "refund",
        "--username",
        "parish-secretary",
        "--amount",
        "40.00",
        "--rail",
        "cash",
        "--reason",
        "the year ended early",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    // The token form reaches the same cap with a partial amount.
    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "10.00",
        "--rail",
        "cash",
        "--reason",
        "overpaid for the group",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(refund_lines(&fix).is_empty(), "{:?}", refund_lines(&fix));
    let journal = fix.journal();
    assert!(
        journal.contains(&format!(
            "an --excess refund is GBP 40.00, more than the GBP 0.00 of ledger seq {credit_seq} that never bought time (GBP 40.00 arrived, GBP 40.00 of it was applied)"
        )),
        "{journal}"
    );
    assert!(
        journal.contains("an --excess refund is GBP 10.00, more than the GBP 0.00 of ledger seq"),
        "{journal}"
    );

    // The group's date and state are the refusal's to leave alone.
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(group["payment"]["paid_until"], paid_until, "{group}");
    assert_eq!(
        group["payment"]["window"]["state"],
        json!("paid"),
        "{group}"
    );

    // `--close` is not a group transition either, and names the way out.
    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "40.00",
        "--rail",
        "cash",
        "--reason",
        "cancel the group",
        "--close",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(refund_lines(&fix).is_empty(), "{:?}", refund_lines(&fix));
    let journal = fix.journal();
    assert!(
        journal.contains("a group has no closing state, so --close cannot cancel one"),
        "{journal}"
    );
    assert!(
        journal.contains("group remove"),
        "the refusal names the transition that ends a group: {journal}"
    );
}

/// A card invoice above the year's price buys one year and holds the rest: the
/// applied figure is the price, not the invoice's total, so the overpayment can
/// come back as excess and the year stays.
#[test]
fn a_card_overpayment_is_refundable_as_excess() {
    let fix = Fix::new("card-refund-excess");
    fix.card_account("secretary", None);
    fix.webhook(
        "evt_card_over",
        "invoice.paid",
        invoice_with("in_card_over", 2500, 1_790_000_000),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let payments = payment_lines(&fix);
    assert_eq!(payments.len(), 1, "{payments:?}");
    assert_eq!(payments[0]["amount_gbp"], json!("25.00"), "{payments:?}");
    assert_eq!(payments[0]["applied_gbp"], json!("20.00"), "{payments:?}");
    let paid_seq = payments[0]["seq"].as_u64().unwrap();
    let before = fix.account("secretary");
    let paid_until = before["payment"]["paid_until"].clone();
    assert!(!paid_until.is_null(), "{before}");

    let out = fix.ctl(&[
        "refund",
        "--username",
        "secretary",
        "--amount",
        "5.00",
        "--rail",
        "card",
        "--reason",
        "invoice was higher than the year",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let refunds = refund_lines(&fix);
    assert_eq!(refunds.len(), 1, "{refunds:?}");
    assert_eq!(refunds[0]["amount_gbp"], json!("-5.00"), "{refunds:?}");
    assert_eq!(refunds[0]["refund_of"], json!(paid_seq), "{refunds:?}");
    assert_eq!(refunds[0]["rail"], json!("card"), "{refunds:?}");
    let after = fix.account("secretary");
    assert_eq!(
        after["payment"]["paid_until"], paid_until,
        "the excess refund moved the year: {after}"
    );
    assert!(after["payment"]["balance_gbp"].is_null(), "{after}");
}

/// An earlier refund whose amount cannot be read is not counted as zero: the
/// next refund is refused, because the sum it would join is unknown rather than
/// smaller than it is.
#[test]
fn an_unreadable_refund_amount_refuses_the_next_refund() {
    let fix = Fix::new("refund-unreadable-sum");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_overpayment(&fix, &token);

    let out = fix.ctl(&[
        "refund", "--token", &token, "--amount", "5.00", "--rail", "cash", "--reason", "overpaid",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    assert_eq!(refund_lines(&fix).len(), 1);

    // The recorded amount is unreadable, as a hand-edited ledger line is.
    let path = fix.dir.join("store/ledger/payments.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines = Vec::new();
    for line in text.lines() {
        let mut value: Value = serde_json::from_str(line).unwrap();
        if value["kind"] == json!("refund") {
            value["amount_gbp"] = json!("not money");
        }
        lines.push(serde_json::to_string(&value).unwrap());
    }
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "3.00",
        "--rail",
        "cash",
        "--reason",
        "the rest of the excess",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        refund_lines(&fix).len(),
        1,
        "a refund joined a sum it could not read: {:?}",
        refund_lines(&fix)
    );
    assert!(
        fix.journal().contains("cannot be read"),
        "the refusal does not name the unreadable line: {}",
        fix.journal()
    );
}

/// A credit and a refund keep exactly the ledger key set the accountant's sheet
/// and every older reader expect. A payment omits the refund block; a refund
/// carries all four of its fields, null included.
#[test]
fn a_credit_and_a_refund_keep_the_recorded_key_shape() {
    let fix = Fix::new("refund-ledger-keys");
    let token = approved_paid(&fix, "secretary", "cash");
    let credit = cash_overpayment(&fix, &token);
    let out = fix.ctl(&[
        "refund", "--token", &token, "--amount", "5.00", "--rail", "cash", "--reason", "overpaid",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let refund = refund_lines(&fix).remove(0);

    let keys = |value: &Value| {
        value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        keys(&credit),
        [
            "amount_gbp",
            "amount_xmr",
            "applied_gbp",
            "intent",
            "kind",
            "note",
            "paid_until_after",
            "rail",
            "rate_at",
            "rate_quoted",
            "rate_source",
            "received_on",
            "seq",
            "token",
            "txid",
            "version",
        ],
        "{credit}"
    );
    assert_eq!(
        keys(&refund),
        [
            "amount_gbp",
            "amount_xmr",
            "applied_gbp",
            "intent",
            "kind",
            "note",
            "paid_until_after",
            "rail",
            "rate_at",
            "rate_quoted",
            "rate_refund",
            "rate_source",
            "received_on",
            "refund_basis",
            "refund_of",
            "seq",
            "settled_on",
            "token",
            "txid",
            "version",
        ],
        "{refund}"
    );
    // The nulls are part of the shape: a reader that distinguishes an absent
    // field from a null one would read these differently.
    for field in [
        "rate_quoted",
        "rate_source",
        "rate_at",
        "txid",
        "settled_on",
    ] {
        assert!(refund[field].is_null(), "{field}: {refund}");
    }
    assert_eq!(refund["amount_gbp"], json!("-5.00"));
    assert_eq!(refund["applied_gbp"], json!("-5.00"));
}

/// A credit and its full refund net to zero in the ledger: the negative line is
/// the payment reversed, not a second movement of its own.
#[test]
fn a_credit_and_a_full_refund_net_to_zero() {
    let fix = Fix::new("refund-net-zero");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_credit(&fix, &token);
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

    let total: i64 = payment_lines(&fix)
        .iter()
        .chain(refund_lines(&fix).iter())
        .map(|line| {
            let text = line["amount_gbp"].as_str().unwrap();
            let sign = if text.starts_with('-') { -1 } else { 1 };
            sign * kyriakon_control_core::util::pence(text.trim_start_matches('-')).unwrap()
        })
        .sum();
    assert_eq!(total, 0, "the ledger does not net to zero");
}

/// A closure a refund paid out cannot be cancelled: the money and the year both
/// went back, so the member cannot restore them by cancelling the closure
/// (#871). The record carries the refusal even when the intent is filed by hand.
#[test]
fn a_refunded_closure_cannot_be_cancelled() {
    let fix = Fix::new("refund-close-cancel");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_credit(&fix, &token);
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
    assert!(fix.drain().status.success());

    let account = fix.account("secretary");
    assert_eq!(account["state"], json!("closing"), "{account}");
    assert_eq!(account["closing_refunded"], json!(true), "{account}");

    fix.file_page_action("cancel-close", "secretary", json!({}));
    assert!(fix.drain().status.success());
    let account = fix.account("secretary");
    assert_eq!(
        account["state"],
        json!("closing"),
        "a refunded closure was cancelled: {account}"
    );
    assert!(
        fix.journal()
            .contains("paid out by a refund, so it cannot be cancelled"),
        "{}",
        fix.journal()
    );
}

/// An excess refund writes the balance before the ledger line. A failed append
/// keeps the intent for the retry, and the retry reads the journal's recorded
/// balance instead of subtracting the amount a second time (#872).
#[test]
fn an_excess_refund_whose_append_fails_does_not_deduct_twice() {
    use std::os::unix::fs::PermissionsExt;

    let fix = Fix::new("refund-excess-retry");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_overpayment(&fix, &token);
    let ledger = fix.dir.join("store/ledger/payments.jsonl");
    let mode = std::fs::metadata(&ledger).unwrap().permissions().mode();
    std::fs::set_permissions(&ledger, std::fs::Permissions::from_mode(0o444)).unwrap();

    let out = fix.ctl(&[
        "refund", "--token", &token, "--amount", "4.00", "--rail", "cash", "--reason", "overpaid",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.failed_note().contains("payments"),
        "the failed append was not reported: {}",
        fix.failed_note()
    );
    assert_eq!(
        fix.account("secretary")["payment"]["balance_gbp"],
        json!("1.00"),
        "the first pass did not write the reduced balance"
    );
    assert_eq!(refund_lines(&fix).len(), 0, "the append succeeded");
    assert_eq!(fix.intents().len(), 1, "the failed intent did not stay");

    std::fs::set_permissions(&ledger, std::fs::Permissions::from_mode(mode)).unwrap();
    fix.age_failures();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.account("secretary")["payment"]["balance_gbp"],
        json!("1.00"),
        "the retry deducted the refund a second time"
    );
    let refunds = refund_lines(&fix);
    assert_eq!(refunds.len(), 1, "{refunds:?}");
    assert_eq!(refunds[0]["amount_gbp"], json!("-4.00"), "{refunds:?}");
}

/// A partial Monero refund returns the same fraction of the recorded coin that
/// it returns in sterling, and its basis says the figure was scaled (#873).
#[test]
fn a_partial_monero_refund_scales_the_recorded_xmr() {
    let fix = Fix::new("refund-monero-partial");
    let token = approved_paid(&fix, "secretary", "monero");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "monero",
        "--amount",
        "20.50",
        "--received",
        "2026-10-04",
        "--txid",
        TXID,
        "--xmr",
        "0.050000",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let out = fix.ctl(&[
        "refund", "--token", &token, "--amount", "0.50", "--rail", "monero", "--reason",
        "overpaid", "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let refunds = refund_lines(&fix);
    assert_eq!(refunds.len(), 1, "{refunds:?}");
    assert_eq!(refunds[0]["amount_gbp"], json!("-0.50"), "{refunds:?}");
    // 0.050000 XMR of a 20.50 payment is 0.001219 XMR for 0.50, rounded down at
    // the six decimals the wallet prints.
    assert_eq!(refunds[0]["amount_xmr"], json!("0.001219"), "{refunds:?}");
    assert_eq!(
        refunds[0]["refund_basis"],
        json!("recorded_xmr_partial"),
        "{refunds:?}"
    );
}

/// A settlement names the refund's ledger sequence. Settling the newer refund
/// and running the same command again finds that line already settled instead
/// of walking back onto an older one (#880).
#[test]
fn a_repeated_settlement_does_not_settle_an_older_refund() {
    let fix = Fix::new("refund-settle-two");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_overpayment(&fix, &token);
    for amount in ["3.00", "2.00"] {
        let out = fix.ctl(&[
            "refund", "--token", &token, "--amount", amount, "--rail", "cash", "--reason",
            "overpaid", "--excess",
        ]);
        assert!(out.status.success(), "{}", body(&out));
        assert!(fix.drain().status.success());
    }
    let refunds = refund_lines(&fix);
    assert_eq!(refunds.len(), 2, "{refunds:?}");
    let newest = refunds[1]["seq"].as_u64().unwrap().to_string();

    for date in ["2026-11-05", "2026-11-05"] {
        let out = fix.ctl(&[
            "refund",
            "--token",
            &token,
            "--settled",
            date,
            "--seq",
            &newest,
        ]);
        assert!(out.status.success(), "{}", body(&out));
        assert!(fix.drain().status.success());
    }

    let refunds = refund_lines(&fix);
    assert_eq!(refunds[1]["settled_on"], json!("2026-11-05"), "{refunds:?}");
    assert!(
        refunds[0]["settled_on"].is_null(),
        "the repeated settlement stamped the older refund: {refunds:?}"
    );
    assert!(
        fix.journal().contains("was already settled on 2026-11-05"),
        "{}",
        fix.journal()
    );
}

/// A member refunded a held overpayment can still close and cancel later. The
/// refund line is not a paid-out closure, and this release's close records the
/// prior state that proves it.
#[test]
fn an_excess_refund_does_not_block_a_later_close_and_cancel() {
    let fix = Fix::new("refund-excess-then-cancel");
    let token = approved_paid(&fix, "secretary", "cash");
    cash_overpayment(&fix, &token);
    let out = fix.ctl(&[
        "refund", "--token", &token, "--amount", "2.00", "--rail", "cash", "--reason", "overpaid",
        "--excess",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    fix.file_close("secretary");
    assert!(fix.drain().status.success());
    assert_eq!(fix.account("secretary")["state"], json!("closing"));

    fix.file_page_action("cancel-close", "secretary", json!({}));
    assert!(fix.drain().status.success());
    let account = fix.account("secretary");
    assert_eq!(
        account["state"],
        json!("active"),
        "an excess refund blocked the cancellation: {account}"
    );
    assert!(
        !fix.journal()
            .contains("the closure was paid out by a refund, so it cannot be cancelled"),
        "{}",
        fix.journal()
    );
}
