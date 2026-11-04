use crate::common::*;

/// A card ledger line carries what the invoice paid and when, not the
/// configured price and the drain's clock: a discount on 10 September is a
/// September line for GBP 15.00, even though the drain runs in October.
#[test]
fn a_card_ledger_line_uses_the_invoice_amount_and_paid_date() {
    let fix = Fix::new("card-ledger-invoice");
    fix.card_account("secretary", None);
    fix.webhook(
        "evt_card",
        "invoice.paid",
        invoice_with("in_discount", 1_500, 1_789_000_000),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let payments = payment_lines(&fix);
    assert_eq!(payments.len(), 1, "{payments:?}");
    assert_eq!(payments[0]["amount_gbp"], json!("15.00"), "{payments:?}");
    assert_eq!(payments[0]["applied_gbp"], json!("15.00"), "{payments:?}");
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
        fix.read("webhooks/processed.jsonl").is_empty(),
        "a refused event is not recorded as settled"
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
        fix.read("webhooks/processed.jsonl").lines().count(),
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
        fix.sent().contains(&format!("client_reference_id={token}")),
        "the approval email keys the link to the account's token: {}",
        fix.sent()
    );

    // Both events of a first payment, the invoice filed first to prove the pass
    // settles the checkout before it. The reference is the account's `KYR-`
    // token, which is what the approval email carried.
    fix.webhook("00-invoice", "invoice.paid", invoice("in_first_payment"));
    fix.webhook(
        "01-checkout",
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

    let date = paid_until(&fix, "secretary").expect("the payment sets a date");
    let expected =
        kyriakon_onboard::billing::extend_paid_until(&kyriakon_onboard::util::filed_at(), None)
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
        fix.read("webhooks/processed.jsonl").is_empty(),
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
    account["payment"]["stripe"]["subscription"] = Value::Null;
    std::fs::write(&path, serde_json::to_vec_pretty(&account).unwrap()).unwrap();

    fix.stripe_session_repair("KYR-AAAA-BBBB-CCCC");
    fix.webhook("evt_repair", "invoice.paid", invoice("in_repair"));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = fix.account("secretary");
    let date = paid_until(&fix, "secretary").expect("the repaired payment sets a date");
    let expected =
        kyriakon_onboard::billing::extend_paid_until(&kyriakon_onboard::util::filed_at(), None)
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
/// mail is sent once rather than every minute.
#[test]
fn a_missing_webhook_secret_is_mailed_once_and_keeps_the_delivery() {
    let fix = Fix::new("webhook-no-secret");
    fix.card_account("secretary", None);
    fix.webhook("evt_no_secret", "invoice.paid", invoice("in_no_secret"));
    std::fs::remove_file(fix.path("stripe")).unwrap();

    for _ in 0..2 {
        let out = fix.drain();
        assert!(out.status.success(), "{}", body(&out));
    }

    let sent = fix.sent();
    assert!(
        sent.contains("Subject: kyriakon: onboard: drain failed"),
        "{sent}"
    );
    assert!(sent.contains("config stripe-secret"), "{sent}");
    assert_eq!(
        sent.matches("Subject:").count(),
        1,
        "a second pass mailed the same failure: {sent}"
    );
    assert!(
        fix.webhooks()
            .iter()
            .any(|n| n.starts_with("evt_no_secret.body")),
        "the delivery was dropped: {:?}",
        fix.webhooks()
    );
}

/// An account record that is there and does not parse is drift, not an account
/// that is gone: the webhook names the record, the checkout is left for the next
/// pass, and the sweeps before it carry on with the other accounts.
#[test]
fn a_corrupt_account_record_keeps_the_checkout_and_reports() {
    let fix = Fix::new("webhook-corrupt-account");
    fix.card_account("secretary", None);
    let path = fix.dir.join("store/accounts/secretary/account.json");
    std::fs::write(&path, b"{\"version\": 1, \"username\": \"secre").unwrap();
    fix.webhook(
        "evt_corrupt",
        "checkout.session.completed",
        json!({
            "id": "cs_corrupt",
            "client_reference_id": "KYR-AAAA-BBBB-CCCC",
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
        fix.read("webhooks/processed.jsonl").is_empty(),
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
        fix.read("webhooks/processed.jsonl").is_empty(),
        "the delivery was recorded as settled"
    );
}
