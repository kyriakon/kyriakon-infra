use crate::common::*;

/// A card ledger line carries what the invoice paid and when, not the
/// configured price and the drain's clock: an invoice on 10 September is a
/// September line for GBP 25.00, even though the drain runs in October and the
/// year's price is GBP 20.00. What the year bought is the price, so `applied`
/// is 20.00 and the 5.00 above it stays an overpayment.
#[test]
fn a_card_ledger_line_uses_the_invoice_amount_and_paid_date() {
    let fix = Fix::new("card-ledger-invoice");
    fix.card_account("secretary", None);
    fix.webhook(
        "evt_card",
        "invoice.paid",
        invoice_with("in_discount", 2_500, 1_789_000_000),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let payments = payment_lines(&fix);
    assert_eq!(payments.len(), 1, "{payments:?}");
    assert_eq!(payments[0]["amount_gbp"], json!("25.00"), "{payments:?}");
    assert_eq!(payments[0]["applied_gbp"], json!("20.00"), "{payments:?}");
    assert_eq!(
        payments[0]["received_on"],
        json!("2026-09-10"),
        "{payments:?}"
    );
}

#[test]
fn a_webhook_that_does_not_verify_leaves_the_store_untouched() {
    let fix = Fix::new("webhook-verify");
    fix.card_account("secretary", None);
    let before = fix.account("secretary");

    let event = json!({
        "id": "evt_refused",
        "type": "invoice.paid",
        "data": {"object": invoice("in_refused")},
    });
    let bytes = serde_json::to_vec(&event).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // No signature at all.
    fix.webhook_raw("01-no-signature", &bytes, "");
    // A signature that is not over this body.
    fix.webhook_raw("02-wrong-signature", &bytes, &format!("t={now},v1=0000"));
    // A correct signature whose timestamp is an hour old: a replay.
    let stale = now - 3600;
    let mut payload = stale.to_string().into_bytes();
    payload.push(b'.');
    payload.extend_from_slice(&bytes);
    let sig = sign::sign_bytes(WEBHOOK_SECRET, &payload).unwrap();
    fix.webhook_raw("03-stale", &bytes, &format!("t={stale},v1={sig}"));

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert_eq!(
        fix.account("secretary"),
        before,
        "a refused webhook changes no record"
    );
    assert_eq!(paid_until(&fix, "secretary"), None);
    assert!(
        fix.webhooks().is_empty(),
        "the refused pairs are cleared: {:?}",
        fix.webhooks()
    );
    assert!(
        fix.read("verified/processed.jsonl").is_empty(),
        "a refused event is not recorded as settled"
    );
    assert!(
        fix.read("verified/evt_refused.json").is_empty(),
        "a refused first sight was recorded as verified"
    );
}

#[test]
fn a_delivery_received_inside_the_window_survives_a_late_pass() {
    let fix = Fix::new("webhook-late-pass");
    fix.card_account("secretary", None);
    // The handler took this ten minutes ago; the pass reaches it only now. The
    // recency guard is measured from the arrival, so a delayed pass settles it
    // instead of deleting a genuine payment.
    let received = OffsetDateTime::now_utc().unix_timestamp() - 600;
    fix.webhook_at(
        "evt_late_pass",
        "invoice.paid",
        invoice("in_late_pass"),
        received,
    );

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        paid_until(&fix, "secretary").is_some(),
        "the late pass deleted a delivery that arrived in time"
    );
    assert!(fix.webhooks().is_empty(), "{:?}", fix.webhooks());
    assert!(
        fix.read("verified/processed.jsonl")
            .contains("evt_late_pass"),
        "the settled payment was not journalled"
    );
}

#[test]
fn a_delivery_with_no_arrival_stamp_uses_when_it_was_stored() {
    let fix = Fix::new("webhook-old-queue");
    fix.card_account("secretary", None);
    // A pair queued by a handler that predates the arrival stamp: its body's
    // mtime is the only record of when it arrived, and a later pass must use
    // it rather than treat the delivery as late.
    let received = OffsetDateTime::now_utc().unix_timestamp() - 600;
    fix.webhook_at(
        "evt_old_queue",
        "invoice.paid",
        invoice("in_old_queue"),
        received,
    );
    let dir = fix.dir.join("store/webhooks");
    std::fs::remove_file(dir.join("evt_old_queue.at")).unwrap();
    std::fs::File::options()
        .write(true)
        .open(dir.join("evt_old_queue.body"))
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(received as u64))
        .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        paid_until(&fix, "secretary").is_some(),
        "an old queue entry was deleted for being late"
    );
    assert!(fix.webhooks().is_empty(), "{:?}", fix.webhooks());
}

#[test]
fn a_delivery_stale_against_its_arrival_is_still_refused() {
    let fix = Fix::new("webhook-stale-arrival");
    fix.card_account("secretary", None);
    let event = json!({
        "id": "evt_stale_arrival",
        "type": "invoice.paid",
        "data": {"object": invoice("in_stale_arrival")},
    });
    let bytes = serde_json::to_vec(&event).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    // Received an hour ago carrying a timestamp two hours old: the header is
    // stale against its own arrival, so this is a replay and not a delivery.
    let received = now - 3600;
    let stale = now - 7200;
    let mut payload = stale.to_string().into_bytes();
    payload.push(b'.');
    payload.extend_from_slice(&bytes);
    let sig = sign::sign_bytes(WEBHOOK_SECRET, &payload).unwrap();
    fix.webhook_raw("evt_stale_arrival", &bytes, &format!("t={stale},v1={sig}"));
    std::fs::write(
        fix.dir.join("store/webhooks/evt_stale_arrival.at"),
        received.to_string(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert_eq!(paid_until(&fix, "secretary"), None);
    assert!(fix.webhooks().is_empty(), "{:?}", fix.webhooks());
    assert!(
        fix.read("verified/processed.jsonl").is_empty(),
        "a replayed event was recorded as settled"
    );
}

#[test]
fn a_replayed_event_id_or_invoice_extends_nothing() {
    let fix = Fix::new("webhook-replay");
    fix.card_account("secretary", None);

    fix.webhook("evt_paid", "invoice.paid", invoice("in_first"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let first = paid_until(&fix, "secretary").expect("the payment sets a date");
    let account = fix.account("secretary");

    // The same event id.
    fix.webhook("evt_paid", "invoice.paid", invoice("in_first"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.account("secretary"),
        account,
        "a replay changes nothing"
    );

    // A fresh event id carrying the same invoice: the (type, object) key sees
    // that it is one payment.
    fix.webhook("evt_paid_again", "invoice.paid", invoice("in_first"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        paid_until(&fix, "secretary").as_deref(),
        Some(first.as_str())
    );
    assert_eq!(
        fix.read("verified/processed.jsonl").lines().count(),
        1,
        "one payment is recorded once"
    );
}

#[test]
fn a_first_payment_with_a_checkout_and_an_invoice_extends_one_year() {
    let fix = Fix::new("webhook-first");
    let record = fix.filed("secretary", "card", &[("rail", "card")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        paid_until(&fix, "secretary"),
        None,
        "approval opens a window"
    );
    let token = fix.account("secretary")["payment"]["token_ref"]
        .as_str()
        .expect("a paid approval draws a token")
        .to_string();
    assert!(
        fix.sent().contains(&format!("client_reference_id={TOKEN}")),
        "the approval email keys the link to the application's identifier: {}",
        fix.sent()
    );
    assert!(
        !fix.sent().contains(&format!("client_reference_id={token}")),
        "the payment token reached the link: {}",
        fix.sent()
    );

    // Both events of a first payment, the invoice filed first to prove the pass
    // settles the checkout before it. The reference is the application's
    // identifier, which is what the approval email carried.
    fix.webhook(
        "evt_00_invoice",
        "invoice.paid",
        invoice("in_first_payment"),
    );
    fix.webhook(
        "evt_01_checkout",
        "checkout.session.completed",
        json!({
            "id": "cs_example",
            "client_reference_id": TOKEN,
            "subscription": SUBSCRIPTION,
            "customer": "cus_example",
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let date = paid_until(&fix, "secretary").expect("the payment sets a date");
    let expected = kyriakon_control_core::payments::billing::extend_paid_until(
        &kyriakon_control_core::util::filed_at(),
        None,
    )
    .unwrap();
    assert_eq!(
        &date[..10],
        &expected[..10],
        "one calendar year, not two: {date}"
    );
    let account = fix.account("secretary");
    assert_eq!(
        account["payment"]["stripe"]["subscription"], SUBSCRIPTION,
        "the checkout attached the subscription: {account}"
    );
    // The status page renders the application copy, so the date is there too.
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert_eq!(app["payment"]["paid_until"], date);
}

#[test]
fn cancel_at_period_end_keeps_the_period_and_deletion_revokes_nothing() {
    let fix = Fix::new("webhook-cancel");
    fix.card_account("secretary", Some("2027-10-04T00:00:00Z"));

    fix.webhook(
        "evt_updated",
        "customer.subscription.updated",
        json!({
            "id": SUBSCRIPTION,
            "status": "active",
            "customer": "cus_example",
            "current_period_end": 1_790_000_000,
            "cancel_at_period_end": true,
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let account = fix.account("secretary");
    assert_eq!(
        account["payment"]["paid_until"], "2027-10-04T00:00:00Z",
        "cancelling stops renewal and keeps the paid period: {account}"
    );
    assert_eq!(account["payment"]["stripe"]["status"], "active");
    assert_eq!(
        account["payment"]["stripe"]["cancel_at_period_end"],
        json!(true),
        "the event's own flag is recorded: {account}"
    );

    fix.webhook(
        "evt_deleted",
        "customer.subscription.deleted",
        json!({
            "id": SUBSCRIPTION,
            "status": "canceled",
            "customer": "cus_example",
            "current_period_end": 1_790_000_000,
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let account = fix.account("secretary");
    assert_eq!(
        account["payment"]["paid_until"], "2027-10-04T00:00:00Z",
        "deletion never revokes a paid date: {account}"
    );
    assert_eq!(account["payment"]["stripe"]["status"], "canceled");
    assert_eq!(
        account["payment"]["stripe"]["cancel_at_period_end"],
        json!(true),
        "a deleted subscription renews nothing: {account}"
    );
}

/// A disputed charge and a refund are the operator's to answer: each one is
/// settled rather than ignored, the alert names the charge, and the settled
/// line keeps the object's own reference. Nothing about access moves either
/// way.
#[test]
fn a_dispute_and_a_refund_alert_the_operator_instead_of_being_ignored() {
    let fix = Fix::new("webhook-charge-operator");
    fix.card_account("secretary", Some("2027-10-04T00:00:00Z"));
    // Stripe's shapes: a dispute's object is the dispute, which names its
    // charge; a refund's object is the charge, whose total is not the money
    // that came back. The refund here is partial.
    fix.webhook(
        "evt_dispute",
        "charge.dispute.created",
        json!({"id": "dp_example", "charge": "ch_example", "amount": 2_000}),
    );
    fix.webhook(
        "evt_refunded",
        "charge.refunded",
        json!({"id": "ch_example", "amount": 2_000, "amount_refunded": 500}),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    for kind in ["charge.dispute.created", "charge.refunded"] {
        assert!(sent.contains(kind), "{kind} was not alerted: {sent}");
    }
    assert!(
        sent.contains("dispute dp_example on charge ch_example"),
        "the dispute alert names the dispute and its charge: {sent}"
    );
    assert!(
        sent.contains("500 minor units refunded"),
        "the refund alert names what came back, not the charge total: {sent}"
    );
    assert!(
        !sent.contains("2000 minor units"),
        "a partial refund was reported as the charge total: {sent}"
    );
    assert!(sent.contains("To: reviewer@example.invalid"), "{sent}");

    let processed = fix.read("verified/processed.jsonl");
    for line in [
        "charge.dispute.created",
        "charge.refunded",
        "dp_example",
        "ch_example",
    ] {
        assert!(
            processed.contains(line),
            "{line} is not journalled: {processed}"
        );
    }
    assert!(
        fix.webhooks().is_empty(),
        "an alerted event was left for a retry: {:?}",
        fix.webhooks()
    );
    assert_eq!(
        fix.account("secretary")["payment"]["paid_until"],
        "2027-10-04T00:00:00Z",
        "a dispute or refund moved the date"
    );
}

#[test]
fn past_due_with_a_future_date_keeps_access() {
    let fix = Fix::new("webhook-past-due");
    fix.card_account("secretary", Some("2027-10-04T00:00:00Z"));
    fix.stripe_subscription("past_due", 1_790_000_000);

    fix.webhook("evt_past_due", "invoice.paid", invoice("in_past_due"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = fix.account("secretary");
    assert_eq!(
        account["payment"]["paid_until"], "2027-10-04T00:00:00Z",
        "a paid invoice on a non-active subscription does not extend: {account}"
    );
    assert_eq!(
        account["payment"]["stripe"]["status"], "past_due",
        "the retrieval's status is recorded: {account}"
    );
    assert!(
        fix.webhooks().is_empty(),
        "the event is settled rather than retried: {:?}",
        fix.webhooks()
    );
}

#[test]
fn an_invoice_waits_for_an_unreachable_api_and_extends_on_the_next_pass() {
    let fix = Fix::new("webhook-retry");
    fix.card_account("secretary", None);
    fix.stripe_unreachable();

    fix.webhook("evt_retry", "invoice.paid", invoice("in_retry"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        paid_until(&fix, "secretary"),
        None,
        "the date is never extended on trust"
    );
    assert!(
        fix.webhooks()
            .iter()
            .any(|n| n.starts_with("evt_retry.body")),
        "the event is left for the next pass: {:?}",
        fix.webhooks()
    );

    fix.stripe_subscription("active", 1_790_000_000);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        paid_until(&fix, "secretary").is_some(),
        "the retry settles the payment"
    );
    assert!(fix.webhooks().is_empty(), "{:?}", fix.webhooks());
}

#[test]
fn a_deferred_event_survives_past_the_timestamp_window() {
    let fix = Fix::new("webhook-deferred-verified");
    fix.card_account("secretary", None);
    fix.stripe_unreachable();

    fix.webhook("evt_deferred", "invoice.paid", invoice("in_deferred"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.webhooks()
            .iter()
            .any(|n| n.starts_with("evt_deferred.body")),
        "the deferred pair was not kept: {:?}",
        fix.webhooks()
    );
    assert!(
        !fix.read("verified/evt_deferred.json").is_empty(),
        "the first sight was not recorded"
    );

    // The same delivery, now carrying a timestamp an hour old: this pass's
    // clock is well past the five-minute tolerance, as the pass after a failed
    // settlement is. The recorded id is the proof, so the pair is not late.
    let bytes = std::fs::read(fix.dir.join("store/webhooks/evt_deferred.body")).unwrap();
    let stale = OffsetDateTime::now_utc().unix_timestamp() - 3600;
    let mut payload = stale.to_string().into_bytes();
    payload.push(b'.');
    payload.extend_from_slice(&bytes);
    let sig = sign::sign_bytes(WEBHOOK_SECRET, &payload).unwrap();
    std::fs::write(
        fix.dir.join("store/webhooks/evt_deferred.sig"),
        format!("t={stale},v1={sig}"),
    )
    .unwrap();

    fix.stripe_subscription("active", 1_790_000_000);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        paid_until(&fix, "secretary").is_some(),
        "the deferred payment was lost to the clock"
    );
    assert!(fix.webhooks().is_empty(), "{:?}", fix.webhooks());
    assert!(
        fix.read("verified/evt_deferred.json").is_empty(),
        "the record outlived the event it proved"
    );
    assert!(
        fix.read("verified/processed.jsonl")
            .contains("evt_deferred"),
        "the settled payment was not journalled"
    );
}

/// A signature file that exists but cannot be read is a transient fault: the
/// pass reports it and keeps the delivery, rather than deleting the one copy
/// Stripe will not send again.
#[test]
fn an_unreadable_signature_keeps_the_delivery() {
    let fix = Fix::new("webhook-unreadable-sig");
    fix.card_account("secretary", None);
    fix.webhook(
        "evt_unreadable_sig",
        "invoice.paid",
        invoice("in_unreadable_sig"),
    );
    let sig = fix.dir.join("store/webhooks/evt_unreadable_sig.sig");
    std::fs::remove_file(&sig).unwrap();
    std::fs::create_dir(&sig).unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.webhooks()
            .iter()
            .any(|n| n.starts_with("evt_unreadable_sig.body")),
        "the unreadable signature deleted the delivery: {:?}",
        fix.webhooks()
    );
    assert!(sig.is_dir(), "the unreadable signature file was replaced");
}

/// A check that fails after the delivery was proven once leaves the pair for
/// the retry rather than deleting a money-bearing event.
#[test]
fn a_verification_error_does_not_drop_a_proven_pair() {
    let fix = Fix::new("webhook-verify-retry");
    fix.card_account("secretary", None);
    fix.stripe_unreachable();

    fix.webhook(
        "evt_verify_retry",
        "invoice.paid",
        invoice("in_verify_retry"),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.read("verified/evt_verify_retry.json").is_empty(),
        "the first sight was not recorded"
    );

    // The signature on disk no longer matches what it signed: a secret mid-roll
    // or a damaged header. The event was proven once, so the pair stays.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    std::fs::write(
        fix.dir.join("store/webhooks/evt_verify_retry.sig"),
        format!("t={now},v1=0000"),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.webhooks()
            .iter()
            .any(|n| n.starts_with("evt_verify_retry.body")),
        "the proven pair was deleted: {:?}",
        fix.webhooks()
    );
    assert!(
        !fix.read("verified/evt_verify_retry.json").is_empty(),
        "the proof was deleted with the failed check"
    );
    assert_eq!(
        paid_until(&fix, "secretary"),
        None,
        "an unverified event extended the date"
    );
}

#[test]
fn a_valid_event_with_no_matching_application_writes_nothing() {
    let fix = Fix::new("webhook-unknown");
    let before = fix.snapshot();

    // A well-formed token that names no application.
    fix.webhook(
        "evt_unknown",
        "checkout.session.completed",
        json!({
            "id": "cs_unknown",
            "client_reference_id": "zzzzzzzzzzzzzzzzzzzzzzzzzz",
            "subscription": SUBSCRIPTION,
            "customer": "cus_example",
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let after = fix.snapshot();
    let touching: Vec<_> = before
        .keys()
        .chain(after.keys())
        .filter(|k| !k.starts_with("webhooks/"))
        // The drain refreshes the rate cache before it looks at any event: the
        // cache itself and the stamp for a failed attempt are named exactly, so
        // a third file appearing under `rates/` still fails this check.
        .filter(|k| *k != "rates/xmr-gbp.json" && *k != "rates/xmr-gbp.json.attempt")
        // A lock file is not a record: the drain's pass lock and the
        // per-record locks a rewrite or an append takes are named, not content.
        .filter(|k| !k.ends_with(".lock"))
        .filter(|k| before.get(*k) != after.get(*k))
        .collect();
    assert!(touching.is_empty(), "changed: {touching:?}");
    assert!(fix.webhooks().is_empty(), "{:?}", fix.webhooks());
    assert!(
        fix.read("verified/processed.jsonl").is_empty(),
        "nothing of ours was settled"
    );
}

/// A missed checkout is repaired from the Checkout Session the invoice's
/// subscription came from: no `checkout.session.completed` ever arrived, the
/// session list names the account's token, and the invoice still attaches the
/// subscription and sets exactly one year.
#[test]
fn an_invoice_with_no_checkout_repairs_the_attachment_from_the_session() {
    let fix = Fix::new("webhook-repair");
    fix.card_account("secretary", None);
    // The account exists with its token index, but no subscription yet: this is
    // the state a delivery gap leaves.
    let path = fix.dir.join("store/accounts/secretary/account.json");
    let mut account: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let token = account["payment"]["token_ref"]
        .as_str()
        .expect("a card account holds its token")
        .to_string();
    account["payment"]["stripe"]["subscription"] = Value::Null;
    std::fs::write(&path, serde_json::to_vec_pretty(&account).unwrap()).unwrap();
    fix.application_record(TOKEN, "secretary", &token);
    // The handler's copy is not consulted for a legacy status token either: the
    // root-owned account's application_ref is what resolves it.
    fix.amend_application(TOKEN, |record| {
        record["payment"]["token_ref"] = json!("KYR-ZZZZ-ZZZZ-ZZZZ");
    });

    fix.stripe_session_repair(TOKEN);
    fix.webhook("evt_repair", "invoice.paid", invoice("in_repair"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = fix.account("secretary");
    let date = paid_until(&fix, "secretary").expect("the repaired payment sets a date");
    let expected = kyriakon_control_core::payments::billing::extend_paid_until(
        &kyriakon_control_core::util::filed_at(),
        None,
    )
    .unwrap();
    assert_eq!(
        &date[..10],
        &expected[..10],
        "exactly one year from the repair: {account}"
    );
    assert_eq!(
        account["payment"]["stripe"]["subscription"], SUBSCRIPTION,
        "the subscription is attached from the session: {account}"
    );
}

/// A session with no reference cannot name an account, so the invoice is left
/// in place rather than guessed at.
#[test]
fn a_session_with_no_reference_leaves_the_invoice_deferred() {
    let fix = Fix::new("webhook-no-reference");
    fix.card_account("secretary", None);
    let path = fix.dir.join("store/accounts/secretary/account.json");
    let mut account: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    account["payment"]["stripe"]["subscription"] = Value::Null;
    std::fs::write(&path, serde_json::to_vec_pretty(&account).unwrap()).unwrap();

    fix.stripe_session_without_reference();
    fix.webhook(
        "evt_no_reference",
        "invoice.paid",
        invoice("in_no_reference"),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert_eq!(
        paid_until(&fix, "secretary"),
        None,
        "nothing is extended without a reference"
    );
    assert!(
        fix.webhooks()
            .iter()
            .any(|n| n.starts_with("evt_no_reference.body")),
        "the event is left for a later delivery: {:?}",
        fix.webhooks()
    );
}

/// Only `invoice.paid` is deduplicated on its object. A second subscription
/// update and a second failed attempt carry the same object and different event
/// ids, and both are states to record.
#[test]
fn repeated_subscription_and_failure_events_are_each_applied() {
    let fix = Fix::new("webhook-repeat");
    fix.card_account("secretary", Some("2027-10-04T00:00:00Z"));

    fix.webhook(
        "evt_updated_1",
        "customer.subscription.updated",
        json!({"id": SUBSCRIPTION, "status": "past_due", "customer": "cus_example"}),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.account("secretary")["payment"]["stripe"]["status"],
        "past_due"
    );

    fix.webhook(
        "evt_updated_2",
        "customer.subscription.updated",
        json!({"id": SUBSCRIPTION, "status": "active", "customer": "cus_example"}),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.account("secretary")["payment"]["stripe"]["status"],
        "active",
        "the second update is applied"
    );

    fix.webhook(
        "evt_failed_1",
        "invoice.payment_failed",
        json!({"id": "in_failed", "subscription": SUBSCRIPTION, "attempt_count": 1}),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.account("secretary")["payment"]["stripe"]["failed_attempts"],
        1
    );

    fix.webhook(
        "evt_failed_2",
        "invoice.payment_failed",
        json!({"id": "in_failed", "subscription": SUBSCRIPTION, "attempt_count": 2}),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.account("secretary")["payment"]["stripe"]["failed_attempts"],
        2,
        "the second failed attempt is recorded"
    );
}

/// An authentication demand is the one card event the member must act on: the
/// attempt is recorded and one notice asks them to finish the payment.
#[test]
fn payment_action_required_records_the_attempt_and_asks_once() {
    let fix = Fix::new("webhook-action");
    fix.card_account("secretary", None);

    fix.webhook(
        "evt_action",
        "invoice.payment_action_required",
        json!({
            "id": "in_action",
            "subscription": SUBSCRIPTION,
            "attempt_count": 2,
            "next_payment_attempt": Value::Null,
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = fix.account("secretary");
    assert_eq!(
        account["payment"]["stripe"]["failed_attempts"], 2,
        "the attempt is recorded: {account}"
    );
    let notices = fix.read("accounts/secretary/notices.jsonl");
    assert!(
        notices.contains("payment.action-required"),
        "the notice is recorded: {notices}"
    );
    assert!(
        fix.sent()
            .contains("Complete your card payment (in_action)"),
        "the member is asked to act: {}",
        fix.sent()
    );
}

/// A missing webhook secret is a misconfigured box, not a failed pass: the
/// delivery stays for the pass that can verify it, the pass exits 0, and the
/// mail is sent once rather than every minute. The delivery is already old by
/// the time the secret arrives, and the first pass with a secret still settles
/// it: recency is measured from the arrival, not from that pass's clock.
#[test]
fn a_missing_webhook_secret_is_mailed_once_and_keeps_the_delivery() {
    let fix = Fix::new("webhook-no-secret");
    fix.card_account("secretary", None);
    let received = OffsetDateTime::now_utc().unix_timestamp() - 3600;
    fix.webhook_at(
        "evt_no_secret",
        "invoice.paid",
        invoice("in_no_secret"),
        received,
    );
    std::fs::remove_file(fix.path("stripe")).unwrap();

    for _ in 0..2 {
        let out = fix.drain();
        assert!(out.status.success(), "{}", body(&out));
    }

    let sent = fix.sent();
    assert!(
        sent.contains("Subject: kyriakon: control: drain failed"),
        "{sent}"
    );
    assert_eq!(
        sent.matches("config stripe-secret").count(),
        1,
        "a second pass mailed the same failure: {sent}"
    );
    assert_eq!(
        sent.matches("card deliveries remain unapplied").count(),
        1,
        "the surviving queue was not surfaced once: {sent}"
    );
    assert!(
        fix.webhooks()
            .iter()
            .any(|n| n.starts_with("evt_no_secret.body")),
        "the delivery was dropped: {:?}",
        fix.webhooks()
    );

    // The box is configured, and the first pass that can verify the hour-old
    // delivery settles it rather than deleting it for being late.
    std::fs::write(fix.path("stripe"), [WEBHOOK_SECRET, b"\n"].concat()).unwrap();
    std::fs::set_permissions(fix.path("stripe"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        paid_until(&fix, "secretary").is_some(),
        "the queued delivery was deleted once a secret could verify it"
    );
    assert!(fix.webhooks().is_empty(), "{:?}", fix.webhooks());
}

/// A link mailed before the change carried the payment token, and those links
/// are already in inboxes. A checkout naming one still attaches the
/// subscription, because Stripe charges it either way and refusing it would take
/// the money and grant nothing. The window closes with the last pre-release
/// window; no link minted since carries a token.
#[test]
fn a_checkout_naming_a_payment_token_still_settles_the_old_link() {
    let fix = Fix::new("webhook-kyr-reference");
    fix.card_account("secretary", None);
    let path = fix.dir.join("store/accounts/secretary/account.json");
    let mut account: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let token = account["payment"]["token_ref"]
        .as_str()
        .expect("a card account holds its token")
        .to_string();
    account["payment"]["stripe"]["subscription"] = Value::Null;
    std::fs::write(&path, serde_json::to_vec_pretty(&account).unwrap()).unwrap();

    fix.webhook(
        "evt_kyr",
        "checkout.session.completed",
        json!({
            "id": "cs_example",
            "client_reference_id": token,
            "subscription": SUBSCRIPTION,
            "customer": "cus_example",
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let account = fix.account("secretary");
    assert_eq!(
        account["payment"]["stripe"]["subscription"], SUBSCRIPTION,
        "the old link's checkout attached nothing: {account}"
    );
}

/// A reference of neither shape names nothing, so the checkout is settled as
/// nobody's: no subscription is attached and no record changes.
#[test]
fn a_checkout_naming_no_known_reference_settles_nothing() {
    let fix = Fix::new("webhook-bad-reference");
    fix.card_account("secretary", None);
    let before = fix.account("secretary");
    fix.webhook(
        "evt_bad",
        "checkout.session.completed",
        json!({
            "id": "cs_example",
            "client_reference_id": "cs_example?not-a-reference",
            "subscription": SUBSCRIPTION,
            "customer": "cus_example",
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.account("secretary"),
        before,
        "a reference of neither shape settled"
    );
}

/// An account record that is there and does not parse is drift, not an account
/// that is gone: the webhook names the record, the checkout is left for the next
/// pass, and the sweeps before it carry on with the other accounts.
#[test]
fn a_corrupt_account_record_keeps_the_checkout_and_reports() {
    let fix = Fix::new("webhook-corrupt-account");
    fix.card_account("secretary", None);
    let token = fix.account("secretary")["payment"]["token_ref"]
        .as_str()
        .expect("a card account holds its token")
        .to_string();
    let path = fix.dir.join("store/accounts/secretary/account.json");
    std::fs::write(&path, b"{\"version\": 1, \"username\": \"secre").unwrap();
    fix.application_record(TOKEN, "secretary", &token);
    fix.webhook(
        "evt_corrupt",
        "checkout.session.completed",
        json!({
            "id": "cs_corrupt",
            "client_reference_id": TOKEN,
            "subscription": SUBSCRIPTION,
            "customer": "cus_example",
        }),
    );

    // The binary, because the report is the line it prints for cron to mail.
    let out = fix.drain_binary();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        body(&out).contains("webhook evt_corrupt (checkout.session.completed)")
            && body(&out).contains("accounts/secretary/account.json does not parse"),
        "the delivery is not reported: {}",
        body(&out)
    );
    assert!(
        fix.webhooks()
            .iter()
            .any(|n| n.starts_with("evt_corrupt.body")),
        "the delivery was deleted: {:?}",
        fix.webhooks()
    );
    assert!(
        fix.read("verified/processed.jsonl").is_empty(),
        "the delivery was recorded as settled"
    );
}

/// A subscription scan that meets a damaged account reports the record and
/// keeps the invoice for the next pass, rather than failing with no journal,
/// backoff or mail.
#[test]
fn a_damaged_account_fails_an_invoice_visibly_and_keeps_it() {
    let fix = Fix::new("webhook-damaged-scan");
    fix.card_account("secretary", None);
    // Sorts before the healthy account, so the scan reaches it first. It could
    // own the subscription, so the event cannot be settled as ignored.
    std::fs::create_dir_all(fix.dir.join("store/accounts/aaa-broken")).unwrap();
    std::fs::write(
        fix.dir.join("store/accounts/aaa-broken/account.json"),
        b"{\"version\": 1, \"username\": \"aaa-brok",
    )
    .unwrap();
    fix.webhook("evt_damaged", "invoice.paid", invoice("in_damaged"));

    // The binary, because the per-event report is the line it prints.
    let out = fix.drain_binary();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        body(&out).contains("webhook evt_damaged (invoice.paid) could not be settled yet")
            && body(&out).contains("accounts/aaa-broken/account.json does not parse"),
        "the event is not reported against the record: {}",
        body(&out)
    );
    assert!(
        fix.sent()
            .contains("accounts/aaa-broken/account.json does not parse"),
        "the record failure was not mailed: {}",
        fix.sent()
    );
    assert!(
        fix.journal()
            .contains("accounts/aaa-broken/account.json does not parse"),
        "{}",
        fix.journal()
    );
    assert!(
        fix.webhooks()
            .iter()
            .any(|n| n.starts_with("evt_damaged.body")),
        "the delivery was deleted: {:?}",
        fix.webhooks()
    );
    assert!(
        fix.read("verified/processed.jsonl").is_empty(),
        "the delivery was recorded as settled"
    );
}

/// A card payment during the grace period brings a lapsed account back: the
/// same restore a prepaid credit runs, the deletion date cleared, and the next
/// grace sweep with nothing to delete.
#[test]
fn a_card_payment_restores_a_lapsed_account() {
    let fix = Fix::new("card-lapsed-restore");
    fix.card_account("secretary", None);
    let mut account = fix.account("secretary");
    account["state"] = json!("lapsed");
    account["grace_until"] = json!(kyriakon_control_core::util::date_after_days(40));
    account["payment"]["window"]["state"] = json!("closed");
    std::fs::write(
        fix.dir.join("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();

    fix.webhook("evt_paid", "invoice.paid", invoice("in_lapsed"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = fix.account("secretary");
    assert_eq!(account["state"], json!("active"), "{account}");
    assert!(account.get("grace_until").is_none(), "{account}");
    assert!(account["payment"]["paid_until"].is_string(), "{account}");
    assert!(
        fix.scripts_log()
            .contains("lapse-user.sh --restore secretary"),
        "the lapsed account was not restored: {}",
        fix.scripts_log()
    );

    // The next pass's grace sweep sees an active account: nothing is deleted or
    // noticed.
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.account("secretary")["state"], json!("active"));
    assert!(
        fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "a paid account was deleted"
    );
}

/// #1001: a card event that moves no date used to restore a lapsed account, so
/// a failed attempt cleared the grace and the operator's notice hold and the
/// deletion clock restarted. It records the attempt and changes nothing else.
#[test]
fn a_failed_invoice_does_not_restore_a_lapsed_account() {
    let fix = Fix::new("card-failed-no-restore");
    fix.card_account("secretary", None);
    let grace = kyriakon_control_core::util::date_after_days(40);
    fix.amend_account("secretary", |account| {
        account["state"] = json!("lapsed");
        account["grace_until"] = json!(grace);
        account["notice_stopped"] = json!({
            "address": "secretary@example.org",
            "status": "5.1.1",
            "at": "2026-11-01T09:00:00Z",
        });
        account["payment"]["window"]["state"] = json!("closed");
    });

    fix.webhook("evt_failed", "invoice.payment_failed", invoice("in_failed"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = fix.account("secretary");
    assert_eq!(account["state"], json!("lapsed"), "{account}");
    assert_eq!(account["grace_until"], json!(grace), "{account}");
    assert_eq!(
        account["notice_stopped"]["status"],
        json!("5.1.1"),
        "a failed invoice cleared the operator's notice hold: {account}"
    );
    assert_eq!(
        account["payment"]["stripe"]["failed_attempts"],
        json!(1),
        "the failed attempt was not recorded: {account}"
    );
    assert!(
        !fix.scripts_log()
            .contains("lapse-user.sh --restore secretary"),
        "a failed invoice restored access: {}",
        fix.scripts_log()
    );
}

/// A zero-amount, foreign-currency or under-price invoice is not a year: the
/// date stays where it was and no payment line opens.
#[test]
fn an_invoice_below_the_price_extends_nothing() {
    let fix = Fix::new("card-underpaid");
    fix.card_account("secretary", Some("2027-10-04T00:00:00Z"));
    let paid = paid_until(&fix, "secretary");
    let mut usd = invoice_with("in_usd", 2_000, 1_790_000_000);
    usd["currency"] = json!("usd");

    for (event, object) in [
        ("evt_zero", invoice_with("in_zero", 0, 1_790_000_000)),
        ("evt_under", invoice_with("in_under", 1_999, 1_790_000_000)),
        ("evt_usd", usd),
    ] {
        fix.webhook(event, "invoice.paid", object);
        let out = fix.drain();
        assert!(out.status.success(), "{}", body(&out));
        assert_eq!(
            paid_until(&fix, "secretary"),
            paid,
            "{event} moved the paid-until date"
        );
    }
    assert!(payment_lines(&fix).is_empty(), "{:?}", payment_lines(&fix));
    assert!(
        fix.webhooks().is_empty(),
        "a refused invoice was left for a retry: {:?}",
        fix.webhooks()
    );
    let sent = fix.sent();
    assert!(
        sent.contains("invoice in_zero") && sent.contains("the configured price_gbp is 20.00"),
        "the operator was not told about the refused invoice: {sent}"
    );
    assert!(
        sent.contains("no year was added"),
        "the alert does not say nothing was extended: {sent}"
    );
}

/// #902: a payment that arrived before the grace-date pass is applied before
/// the sweep deletes the account, so the member who paid is not erased.
#[test]
fn a_payment_on_the_grace_date_is_applied_before_the_sweep_deletes() {
    let fix = Fix::new("card-grace-order");
    fix.card_account("secretary", Some("2026-01-01"));
    fix.amend_account("secretary", |account| {
        account["state"] = json!("lapsed");
        account["grace_until"] = json!(kyriakon_control_core::util::date_after_days(0));
        account["payment"]["window"]["state"] = json!("closed");
    });
    fix.webhook("evt_grace_paid", "invoice.paid", invoice("in_grace_paid"));

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        fix.dir.join("store/accounts/secretary").exists(),
        "the account was deleted before its queued payment was applied"
    );
    assert!(
        !fix.scripts_log().contains("delete-user.sh secretary"),
        "{}",
        fix.scripts_log()
    );
    let account = fix.account("secretary");
    assert_eq!(account["state"], json!("active"), "{account}");
    assert!(account["grace_until"].is_null(), "{account}");
    assert!(
        paid_until(&fix, "secretary").is_some(),
        "the queued payment did not credit the account: {account}"
    );
    assert!(
        fix.read("verified/processed.jsonl")
            .contains("evt_grace_paid"),
        "the payment was not settled"
    );
    assert!(fix.webhooks().is_empty(), "{:?}", fix.webhooks());
}

/// The application record is the handler's, and after the approval its payment
/// block is a handler-writable redirect. The webhook pass resolves the status
/// token through the root-only `reviewed/` snapshot instead, so a rewrite after
/// the approval cannot attach the subscription or the year to another account.
#[test]
fn a_record_rewritten_after_approval_cannot_redirect_a_card_payment() {
    let fix = Fix::new("card-snapshot-redirect");
    let record = fix.filed("secretary", "card", &[("rail", "card")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());
    let secretary_token = fix.account("secretary")["payment"]["token_ref"]
        .as_str()
        .unwrap()
        .to_string();
    // A second account with its own token, the target a redirected payment
    // would land on.
    let warden_token = approved_paid(&fix, "warden", "card");
    assert_ne!(secretary_token, warden_token);

    // The handler rewrites the application record after the approval. The
    // payment block it names is the other account's.
    fix.amend_application(TOKEN, |record| {
        record["payment"]["token_ref"] = json!(warden_token);
    });

    fix.webhook(
        "evt_snapshot_checkout",
        "checkout.session.completed",
        json!({
            "id": "cs_example",
            "client_reference_id": TOKEN,
            "subscription": SUBSCRIPTION,
            "customer": "cus_example",
        }),
    );
    fix.webhook(
        "evt_snapshot_invoice",
        "invoice.paid",
        invoice("in_snapshot_redirect"),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        paid_until(&fix, "secretary").is_some(),
        "the payment did not follow the root snapshot: {}",
        fix.account("secretary")
    );
    assert_eq!(
        paid_until(&fix, "warden"),
        None,
        "a handler rewrite redirected the payment: {}",
        fix.account("warden")
    );
    assert_eq!(
        fix.account("warden")["payment"]["stripe"]["subscription"],
        Value::Null,
        "the redirected subscription was attached: {}",
        fix.account("warden")
    );
}

/// A symlink or a FIFO planted in a handler-owned directory is refused without
/// the root pass following it or hanging on it. `O_NOFOLLOW` answers the link,
/// `O_NONBLOCK` does not wait for a FIFO writer, and the descriptor's metadata
/// refuses anything that is not a regular file.
#[test]
fn a_symlink_or_fifo_in_a_handler_directory_is_refused_without_hanging() {
    let fix = Fix::new("handler-trap");
    let webhooks = fix.dir.join("store/webhooks");
    let intents = fix.dir.join("store/intents");
    std::fs::create_dir_all(&webhooks).unwrap();
    std::fs::create_dir_all(&intents).unwrap();

    let target = fix.dir.join("real-body.json");
    std::fs::write(&target, b"{\"id\":\"evt_link\",\"type\":\"invoice.paid\"}").unwrap();
    std::os::unix::fs::symlink(&target, webhooks.join("evt_link.body")).unwrap();

    let fifo = webhooks.join("evt_fifo.body");
    let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

    let intent_fifo = intents.join("01HZZZZZZZZZZZZZZZZZZZZZZZ.json");
    let intent_c = std::ffi::CString::new(intent_fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(intent_c.as_ptr(), 0o600) }, 0);

    let out = fix.drain();
    let text = body(&out);
    assert!(
        text.contains("non-regular file") || text.contains("symlink"),
        "the pass did not name the planted trap: {text}"
    );
    // Nothing read through the traps, and the pass removed neither the traps
    // nor the application state behind them. A trap may fail the pass, but it
    // must not be followed and must not settle anything.
    assert!(
        !fix.sent().contains("evt_link") && !fix.sent().contains("evt_fifo"),
        "a trapped webhook was settled: {}",
        fix.sent()
    );
    assert!(
        fix.names("accounts").is_empty(),
        "{:?}",
        fix.names("accounts")
    );
    assert!(fix.read("verified/processed.jsonl").is_empty());
}
