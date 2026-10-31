use crate::common::*;

/// A paid approval draws a token from the OS randomness, opens a window with a
/// null `paid_until` and writes it into the account; an approval without charge
/// writes no token and no ledger line.
#[test]
fn a_paid_approval_writes_a_token_and_a_no_charge_approval_does_not() {
    let paid = Fix::new("paid");
    let record = paid.filed("secretary", "monero", &[("rail", "monero")]);
    paid.file_application(&record);
    assert!(paid.drain().status.success());
    paid.decide("approve", "secretary");
    let out = paid.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = paid.account("secretary");
    let payment = &account["payment"];
    let token = payment["token_ref"]
        .as_str()
        .expect("a paid approval writes a token");
    assert!(token.starts_with("KYR-"), "{token}");
    assert_eq!(token.len(), 18, "{token}");
    assert!(
        payment["token_issued_at"].is_string(),
        "the block records when the token was drawn: {account}"
    );
    assert!(payment["paid_until"].is_null(), "{}", account);
    assert!(
        !payment["window"].is_null(),
        "a paid approval opens a window"
    );
    // The fields are the spec's `payment.*` and nothing beside them: a top-level
    // copy would be a second place to keep one fact.
    for flat in ["token_ref", "token_issued_at", "paid_until", "window"] {
        assert!(
            account.get(flat).is_none(),
            "{flat} is top-level: {account}"
        );
    }
    // The join and the ledger line, keyed by the token and holding no username.
    assert!(paid.read(&format!("tokens/{token}.json")).contains(token));
    let ledger = paid.read("ledger/payments.jsonl");
    assert_eq!(ledger.lines().count(), 1, "{ledger}");
    assert!(ledger.contains(token), "{ledger}");
    assert!(
        !ledger.contains("secretary"),
        "the ledger holds no username: {ledger}"
    );
    // The password link is written for the account that has no password.
    let app: Value =
        serde_json::from_str(&paid.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(
        app["password_link"]
            .as_str()
            .unwrap()
            .contains("/password/"),
        "{app}"
    );

    // The free path: no token, no window, no ledger line.
    let free = Fix::new("free");
    let record = free.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    free.file_application(&record);
    assert!(free.drain().status.success());
    free.decide("provision", "secretary");
    let out = free.drain();
    assert!(out.status.success(), "{}", body(&out));
    let account = free.account("secretary");
    assert!(
        account.get("payment").is_none(),
        "a free account has no payment block at all: {account}"
    );
    assert_eq!(account["no_charge"], json!(true));
    assert!(
        free.read("ledger/payments.jsonl").is_empty(),
        "no ledger line without money"
    );
    assert!(free.names("tokens").is_empty(), "no token without a charge");
}

/// `show` names a window only where the account has one. A charged approval
/// opens a window, so its output carries it and the date it closes; a no-charge
/// approval has none and its output says so instead, rather than naming a window
/// the member would watch for in vain.
#[test]
fn show_names_a_window_only_when_the_account_has_one() {
    let charged = Fix::new("show-charged");
    let record = charged.filed("secretary", "monero", &[("rail", "monero")]);
    charged.file_application(&record);
    assert!(charged.drain().status.success());
    charged.decide("approve", "secretary");
    let out = charged.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = charged.account("secretary");
    let window = &account["payment"]["window"];
    let opened = window["opened_at"]
        .as_str()
        .expect("a charged approval opens a window");
    let closes = window["closes_at"].as_str().unwrap();
    let out = charged.ctl(&["show", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(
        text.contains("  paid     null: the window is open"),
        "{text}"
    );
    assert!(
        text.contains(&format!("  window   {opened} to {closes}")),
        "{text}"
    );

    let free = Fix::new("show-free");
    let record = free.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    free.file_application(&record);
    assert!(free.drain().status.success());
    free.decide("provision", "secretary");
    let out = free.drain();
    assert!(out.status.success(), "{}", body(&out));

    let out = free.ctl(&["show", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(!text.contains("window"), "no window exists to name: {text}");
    assert!(
        text.contains("  paid     none: no charge was made, so nothing expires"),
        "the line should say what is true: {text}"
    );
}

/// The token is a bearer secret with a lifetime: the status page and both account
/// pages show it in full while the account is unpaid, the amount and the window
/// beside it, and a credit's date replaces it there. The paid state below is
/// written by hand; the credit path itself is exercised by the credit tests.
#[test]
fn the_token_shows_while_unpaid_and_the_date_replaces_it() {
    let fix = Fix::new("token-display");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let now = OffsetDateTime::now_utc();
    let post = "1 Example Street, Example";
    let account = stored_account(&fix, "secretary");
    let payment = account.payment_state().expect("a paid approval's block");
    let token = payment.token_ref.clone().expect("a paid approval's token");
    let closes_at = payment.window.as_ref().unwrap().closes_at.clone();
    let closes_on = closes_at[..10].to_string();

    let view = |account: &store::Account| {
        let block = account.payment_state().expect("a paid approval's block");
        page::payment(
            &account.state,
            &account.rail,
            &block,
            "20.00",
            post,
            None,
            now,
        )
    };

    // The status page reads the copy the drain wrote into the application
    // record, which is the only payment state the unprivileged handler can see.
    let application: Record =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    let block = application
        .payment
        .clone()
        .expect("the drain copied the block onto the application");
    let status_view = page::payment(
        "active",
        &application.rail,
        &block,
        "20.00",
        post,
        None,
        now,
    );
    let status = responder::status_page(Some(application.clone()), Some(status_view), now);
    let html = status.render().unwrap();
    assert!(html.contains(&token), "{html}");
    assert!(html.contains("GBP 20.00"), "{html}");
    assert!(html.contains(&closes_on), "{html}");
    assert!(
        !token_is_a_link(&html, &token),
        "the token is in a URL: {html}"
    );
    let gemtext = capsule::status(&status);
    assert!(gemtext.contains(&token), "{gemtext}");
    assert!(gemtext.contains(&closes_on), "{gemtext}");
    assert!(
        !token_is_a_link(&gemtext, &token),
        "the token is in a link: {gemtext}"
    );

    // The account page, web and gemini: the block above the catalogue, with the
    // rail and the instructions a member has to act on.
    let web = page::account(&[], Some("secretary"), None, Some(view(&account)), false)
        .render()
        .unwrap();
    assert!(web.contains(&token), "{web}");
    assert!(web.contains("Rail: cash"), "{web}");
    assert!(web.contains(post), "{web}");
    assert!(web.contains("GBP 20.00"), "{web}");
    assert!(
        !token_is_a_link(&web, &token),
        "the token is in a URL: {web}"
    );
    let gemini = capsule::account(&account, &[], None, Some(&view(&account)));
    assert!(gemini.contains(&token), "{gemini}");
    assert!(gemini.contains(post), "{gemini}");
    assert!(
        !token_is_a_link(&gemini, &token),
        "the token is in a link: {gemini}"
    );

    // The credit: `paid_until` set, the window closed. Written by hand because
    // the credit path does not exist yet.
    let mut paid = fix.account("secretary");
    paid["payment"]["paid_until"] = json!("2027-10-04T00:00:00Z");
    paid["payment"]["window"]["state"] = json!("paid");
    std::fs::write(
        fix.dir.join("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&paid).unwrap(),
    )
    .unwrap();

    let account = stored_account(&fix, "secretary");
    let paid = view(&account);
    assert_eq!(paid.paid_until.as_deref(), Some("2027-10-04T00:00:00Z"));
    assert_eq!(paid.token, None, "a paid account shows no token");
    assert_eq!(paid.rail, "cash", "the rail stays visible");
    // A credit updates the application record's copy too (#300), so the status
    // page shows the date rather than the token.
    let mut application: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    application["payment"]["paid_until"] = json!("2027-10-04T00:00:00Z");
    application["payment"]["window"]["state"] = json!("paid");
    let application: Record = serde_json::from_value(application).unwrap();
    let block = application.payment.clone().unwrap();
    let paid = page::payment(
        "active",
        &application.rail,
        &block,
        "20.00",
        post,
        None,
        now,
    );
    let status = responder::status_page(Some(application), Some(paid), now);
    let html = status.render().unwrap();
    assert!(html.contains("Paid until 2027-10-04T00:00:00Z"), "{html}");
    assert!(!html.contains(&token), "the token is back: {html}");
    let gemtext = capsule::status(&status);
    assert!(gemtext.contains("Paid until 2027-10-04"), "{gemtext}");
    assert!(!gemtext.contains(&token), "the token is back: {gemtext}");
    let paid = view(&account);
    let web = page::account(&[], Some("secretary"), None, Some(paid), false)
        .render()
        .unwrap();
    assert!(web.contains("Paid until 2027-10-04T00:00:00Z"), "{web}");
    assert!(!web.contains(&token), "the token is back: {web}");
    assert!(web.contains("Rail: cash"), "{web}");

    // A free account has no payment block at all, on either page.
    let free = Fix::new("token-display-free");
    let record = free.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    free.file_application(&record);
    assert!(free.drain().status.success());
    free.decide("provision", "secretary");
    let out = free.drain();
    assert!(out.status.success(), "{}", body(&out));
    let account = stored_account(&free, "secretary");
    assert!(account.payment_state().is_none());
    assert!(account.is_free());
    let web = page::account(&[], Some("secretary"), None, None, account.is_free())
        .render()
        .unwrap();
    assert!(
        !web.contains("Payment"),
        "a free account has no block: {web}"
    );
    assert!(
        web.contains("This account is free: nothing is due, and it does not lapse."),
        "the page says why there is no block: {web}"
    );
    let gemini = capsule::account(&account, &[], None, None);
    assert!(
        !gemini.contains("Payment"),
        "a free account has no block: {gemini}"
    );
    assert!(
        gemini.contains("This account is free: nothing is due, and it does not lapse."),
        "{gemini}"
    );
}

/// The date arithmetic every credit runs: one calendar year from the later of
/// the day the money was received and the date already paid to. The existing
/// dates make the second credit a renewal, which is why those cases pass
/// `--confirm-double`.
#[test]
fn a_credit_extends_from_the_later_of_the_received_day_and_the_existing_date() {
    let cases = [
        ("credit-inside-window", None, "2026-10-04", "2027-10-04"),
        (
            "credit-after-lapse",
            Some("2025-01-01"),
            "2026-10-04",
            "2027-10-04",
        ),
        (
            "credit-renew-early",
            Some("2027-06-01"),
            "2026-10-04",
            "2028-06-01",
        ),
        ("credit-leap-day", None, "2028-02-29", "2029-02-28"),
    ];
    for (name, before, received, expected) in cases {
        let fix = Fix::new(name);
        let token = approved_paid(&fix, "secretary", "cash");
        if let Some(before) = before {
            set_paid_until(&fix, "secretary", before);
        }
        let mut args = vec![
            "credit",
            "--token",
            token.as_str(),
            "--rail",
            "cash",
            "--amount",
            "20.00",
            "--received",
            received,
        ];
        if before.is_some() {
            args.push("--confirm-double");
        }
        let out = fix.ctl(&args);
        assert!(out.status.success(), "{name}: {}", body(&out));
        let out = fix.drain();
        assert!(out.status.success(), "{name}: {}", body(&out));

        let account = fix.account("secretary");
        assert_eq!(
            account["payment"]["paid_until"],
            json!(expected),
            "{name}: {account}"
        );
        assert_eq!(
            account["payment"]["window"]["state"],
            json!("paid"),
            "{name}: the window closes with the credit: {account}"
        );

        // The status page reads the application copy, which must carry the same
        // block rather than the token.
        let app: Value =
            serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
        assert_eq!(
            app["payment"]["paid_until"],
            json!(expected),
            "{name}: {app}"
        );
        assert_eq!(app["payment"]["window"]["state"], json!("paid"), "{name}");
    }
}

/// One intent applied twice leaves one ledger line and one year, which is the
/// property that has to hold when the drain is restarted mid-write.
#[test]
fn a_credit_applied_twice_leaves_one_line_and_one_year() {
    let fix = Fix::new("credit-idempotent");
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

    let names = fix.intents();
    assert_eq!(names.len(), 1, "{names:?}");
    let replay = std::fs::read_to_string(fix.dir.join("store/intents").join(&names[0])).unwrap();
    assert!(fix.drain().status.success());
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    let settled = fix.read("ledger/payments.jsonl");

    // File the very same intent again: its own id is on the ledger line.
    std::fs::write(fix.dir.join("store/intents").join(&names[0]), &replay).unwrap();
    assert!(fix.drain().status.success());
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert_eq!(
        fix.read("ledger/payments.jsonl"),
        settled,
        "the replay appended a line"
    );
    assert_eq!(payment_lines(&fix).len(), 1, "{}", settled);
    assert_eq!(
        fix.account("secretary")["payment"]["paid_until"],
        json!("2027-10-04"),
        "the replay added a second year"
    );
    assert_eq!(
        fix.read("accounts/secretary/notices.jsonl")
            .matches("prepaid.receipt")
            .count(),
        1,
        "the replay sent a second receipt"
    );
}

/// Every credit appends the next `seq`, and the line holds no username, contact
/// address or name: the token is the only join.
#[test]
fn each_credit_appends_the_next_seq_and_never_a_username() {
    let fix = Fix::new("credit-seq");
    let token = approved_paid(&fix, "secretary", "cash");
    for (received, confirm) in [("2026-10-04", false), ("2026-10-04", true)] {
        let mut args = vec![
            "credit",
            "--token",
            token.as_str(),
            "--rail",
            "cash",
            "--amount",
            "20.00",
            "--received",
            received,
        ];
        if confirm {
            args.push("--confirm-double");
        }
        let out = fix.ctl(&args);
        assert!(out.status.success(), "{}", body(&out));
        let out = fix.drain();
        assert!(out.status.success(), "{}", body(&out));
    }

    let lines = ledger_lines(&fix);
    let seqs: Vec<u64> = lines
        .iter()
        .map(|line| line["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![1, 2, 3], "{lines:?}");
    let payments = payment_lines(&fix);
    assert_eq!(payments.len(), 2, "{lines:?}");
    assert_eq!(payments[0]["paid_until_after"], json!("2027-10-04"));
    assert_eq!(payments[1]["paid_until_after"], json!("2028-10-04"));
    for payment in &payments {
        assert_eq!(payment["token"], json!(token));
        assert_eq!(payment["kind"], json!("payment"));
        assert_eq!(payment["rail"], json!("cash"));
        assert_eq!(payment["received_on"], json!("2026-10-04"));
        assert_eq!(payment["amount_gbp"], json!("20.00"));
        assert_eq!(payment["applied_gbp"], json!("20.00"));
        assert!(payment["amount_xmr"].is_null());
        assert!(payment["rate_quoted"].is_null());
        assert!(payment["rate_source"].is_null());
        assert!(payment["rate_at"].is_null());
        assert!(payment["txid"].is_null());
        assert!(payment["intent"].as_str().is_some_and(|id| !id.is_empty()));
        assert!(payment["note"].is_null());
    }
    let ledger = fix.read("ledger/payments.jsonl");
    assert!(!ledger.contains("secretary"), "{ledger}");
    assert!(!ledger.contains('@'), "{ledger}");
}

/// One percent either side is the price; a larger shortfall holds what arrived
/// and does not move the date; an overpayment is held and spent first.
#[test]
fn a_credit_tolerates_one_percent_and_holds_the_rest() {
    // Within one percent is taken as the price.
    let inside = Fix::new("credit-tolerance");
    let token = approved_paid(&inside, "secretary", "cash");
    let out = inside.ctl(&[
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
    assert!(inside.drain().status.success());
    assert_eq!(
        inside.account("secretary")["payment"]["paid_until"],
        json!("2027-10-04")
    );
    assert_eq!(payment_lines(&inside)[0]["applied_gbp"], json!("20.00"));
    assert!(inside.account("secretary")["payment"]
        .get("balance_gbp")
        .is_none());

    // A larger shortfall holds what arrived, and the top-up spends it first.
    let short = Fix::new("credit-shortfall");
    let token = approved_paid(&short, "secretary", "cash");
    let out = short.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "15.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(short.drain().status.success());
    let account = short.account("secretary");
    assert!(
        account["payment"]["paid_until"].is_null(),
        "a shortfall moves no date: {account}"
    );
    assert_eq!(account["payment"]["balance_gbp"], json!("15.00"));
    assert_eq!(account["payment"]["window"]["state"], json!("open"));
    assert_eq!(payment_lines(&short)[0]["applied_gbp"], json!("0.00"));

    let out = short.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "5.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(short.drain().status.success());
    let account = short.account("secretary");
    assert_eq!(account["payment"]["paid_until"], json!("2027-10-04"));
    assert!(account["payment"].get("balance_gbp").is_none());
    assert_eq!(payment_lines(&short).len(), 2);
    assert_eq!(payment_lines(&short)[1]["applied_gbp"], json!("20.00"));

    // An excess inside the band is still held: the band absorbs a shortfall,
    // not money that arrived.
    let over_small = Fix::new("credit-overpay-small");
    let token = approved_paid(&over_small, "secretary", "cash");
    let out = over_small.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "20.10",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(over_small.drain().status.success());
    let account = over_small.account("secretary");
    assert_eq!(account["payment"]["paid_until"], json!("2027-10-04"));
    assert_eq!(account["payment"]["balance_gbp"], json!("0.10"));
    assert_eq!(payment_lines(&over_small)[0]["applied_gbp"], json!("20.00"));

    // An overpayment is held, and the next credit spends it before money.
    let over = Fix::new("credit-overpay");
    let token = approved_paid(&over, "secretary", "cash");
    let out = over.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "25.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(over.drain().status.success());
    let account = over.account("secretary");
    assert_eq!(account["payment"]["paid_until"], json!("2027-10-04"));
    assert_eq!(account["payment"]["balance_gbp"], json!("5.00"));

    // The second credit is a renewal and is refused without the operator
    // saying so, naming the date the first one reached.
    let out = over.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "15.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(over.drain().status.success());
    assert_eq!(
        payment_lines(&over).len(),
        1,
        "a renewal without --confirm-double was applied"
    );
    assert!(
        over.journal().contains("2027-10-04"),
        "the refusal does not name the first credit's date: {}",
        over.journal()
    );

    let out = over.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "15.00",
        "--received",
        "2026-10-04",
        "--confirm-double",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(over.drain().status.success());
    let account = over.account("secretary");
    assert_eq!(account["payment"]["paid_until"], json!("2028-10-04"));
    assert!(account["payment"].get("balance_gbp").is_none());
    assert_eq!(payment_lines(&over)[1]["applied_gbp"], json!("20.00"));
}

/// One Monero transaction credits once: the second credit naming the same txid
/// is refused with the first line's date and `seq`, and malformed Monero fields
/// are refused before anything is written.
#[test]
fn a_monero_transaction_is_credited_once_and_bad_monero_fields_are_refused() {
    let fix = Fix::new("credit-txid");
    let token = approved_paid(&fix, "secretary", "monero");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "monero",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--txid",
        TXID,
        "--xmr",
        "0.048847",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let first = payment_lines(&fix);
    assert_eq!(first.len(), 1, "{:?}", first);
    assert_eq!(first[0]["txid"], json!(TXID));
    assert_eq!(first[0]["amount_xmr"], json!("0.048847"));
    let first_seq = first[0]["seq"].as_u64().unwrap();

    // The same transaction again, with the renewal flag that would otherwise
    // let it through: the txid is the reason it is refused.
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "monero",
        "--amount",
        "20.00",
        "--received",
        "2027-10-04",
        "--txid",
        TXID,
        "--xmr",
        "0.048847",
        "--confirm-double",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        payment_lines(&fix).len(),
        1,
        "a second credit for one transaction was applied"
    );
    assert_eq!(
        fix.account("secretary")["payment"]["paid_until"],
        json!("2027-10-04"),
        "a refused transaction moved the date"
    );
    let journal = fix.journal();
    assert!(journal.contains(TXID), "{journal}");
    assert!(journal.contains("2026-10-04"), "{journal}");
    assert!(
        journal.contains(&format!("ledger seq {first_seq}")),
        "{journal}"
    );

    // A txid that is not 64 hex, and an XMR amount that is not decimal, are
    // refused before the token is even resolved.
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "monero",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--txid",
        "not-a-txid",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    assert!(
        fix.journal().contains("64 hexadecimal"),
        "{}",
        fix.journal()
    );
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "monero",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--txid",
        TXID,
        "--xmr",
        "0.1.2",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    assert!(
        fix.journal().contains("decimal amount"),
        "{}",
        fix.journal()
    );
    assert_eq!(payment_lines(&fix).len(), 1);
}

/// A shortfall is recorded, shown on every payment view as what remains, and
/// acknowledged by a receipt that names both the money received and the money
/// still owed.
#[test]
fn a_shortfall_is_shown_and_quoted_back_and_receipted() {
    let fix = Fix::new("credit-shortfall-visible");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "15.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let account = fix.account("secretary");
    assert!(account["payment"]["paid_until"].is_null(), "{account}");
    assert_eq!(
        account["payment"]["balance_gbp"],
        json!("15.00"),
        "{account}"
    );

    let now = OffsetDateTime::now_utc();
    let post = "1 Example Street, Example";
    let stored = stored_account(&fix, "secretary");
    let block = stored.payment_state().expect("a paid approval's block");
    let view = page::payment(
        &stored.state,
        &stored.rail,
        &block,
        "20.00",
        post,
        None,
        now,
    );
    assert_eq!(view.amount, "5.00", "the page re-quotes the remainder");
    assert_eq!(view.balance.as_deref(), Some("15.00"));

    // The account page, web and capsule.
    let web = page::account(&[], Some("secretary"), None, Some(view), false)
        .render()
        .unwrap();
    assert!(web.contains("Amount: GBP 5.00"), "{web}");
    assert!(web.contains("Received so far: GBP 15.00"), "{web}");
    let capsule_block = stored.payment_state().expect("a paid approval's block");
    let capsule_view = page::payment(
        &stored.state,
        &stored.rail,
        &capsule_block,
        "20.00",
        post,
        None,
        now,
    );
    let gemtext = capsule::account(&stored, &[], None, Some(&capsule_view));
    assert!(gemtext.contains("Amount: GBP 5.00"), "{gemtext}");
    assert!(gemtext.contains("Received so far: GBP 15.00"), "{gemtext}");

    // The status page, web and capsule, from the copy the handler reads.
    let application: Record =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    let block = application
        .payment
        .clone()
        .expect("the drain copied the block onto the application");
    let status_view = page::payment(
        "active",
        &application.rail,
        &block,
        "20.00",
        post,
        None,
        now,
    );
    assert_eq!(status_view.amount, "5.00");
    let status = responder::status_page(Some(application), Some(status_view), now);
    let html = status.render().unwrap();
    assert!(html.contains("Amount: GBP 5.00"), "{html}");
    assert!(html.contains("Received so far: GBP 15.00"), "{html}");
    let gemtext = capsule::status(&status);
    assert!(gemtext.contains("Amount: GBP 5.00"), "{gemtext}");
    assert!(gemtext.contains("Received so far: GBP 15.00"), "{gemtext}");

    // The receipt names both what arrived and what remains.
    let sent = fix.sent();
    assert!(sent.contains("GBP 15.00"), "{sent}");
    assert!(sent.contains("GBP 5.00"), "{sent}");
    assert!(
        fix.read("accounts/secretary/notices.jsonl")
            .contains("prepaid.receipt"),
        "{}",
        fix.read("accounts/secretary/notices.jsonl")
    );
}

/// A crash between the account write and the ledger append leaves an `applying`
/// journal line and the written account. Replaying the intent finishes the
/// ledger line from those values and does not extend the date again.
#[test]
fn a_credit_recovers_a_ledger_line_lost_after_the_account_write() {
    let fix = Fix::new("credit-recovery");
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
    let names = fix.intents();
    assert_eq!(names.len(), 1, "{names:?}");
    let replay = std::fs::read_to_string(fix.dir.join("store/intents").join(&names[0])).unwrap();
    assert!(fix.drain().status.success());
    assert_eq!(payment_lines(&fix).len(), 1);
    let id = names[0].trim_end_matches(".json").to_string();

    // A crash after the account write and before the append leaves the line
    // missing. The account still carries the credit.
    let ledger = fix.read("ledger/payments.jsonl");
    let kept: String = ledger
        .lines()
        .filter(|line| !line.contains("\"kind\":\"payment\""))
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(fix.dir.join("store/ledger/payments.jsonl"), kept).unwrap();
    assert!(payment_lines(&fix).is_empty());

    std::fs::write(fix.dir.join("store/intents").join(&names[0]), &replay).unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    let lines = payment_lines(&fix);
    assert_eq!(lines.len(), 1, "the line was not rebuilt: {lines:?}");
    assert_eq!(lines[0]["intent"], json!(id));
    assert_eq!(
        fix.account("secretary")["payment"]["paid_until"],
        json!("2027-10-04"),
        "recovery extended the date a second year"
    );
    assert_eq!(
        fix.read("accounts/secretary/notices.jsonl")
            .matches("prepaid.receipt")
            .count(),
        1,
        "recovery sent a second receipt"
    );
}

/// A credit past the 24-month ceiling is refused and journals why; a reason
/// given with `--override` lets it through and lands on the journal line.
#[test]
fn a_credit_past_the_ceiling_is_refused_until_an_override_names_a_reason() {
    let fix = Fix::new("credit-ceiling");
    let token = approved_paid(&fix, "secretary", "cash");
    set_paid_until(&fix, "secretary", "2028-10-04");
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
        "--confirm-double",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    assert!(
        payment_lines(&fix).is_empty(),
        "a refused credit writes no ledger line: {}",
        fix.read("ledger/payments.jsonl")
    );
    assert_eq!(
        fix.account("secretary")["payment"]["paid_until"],
        json!("2028-10-04"),
        "a refused credit moves no date"
    );
    let journal = fix.journal();
    assert!(journal.contains("24 months"), "{journal}");
    assert!(journal.contains("refused"), "{journal}");
    assert_eq!(
        fix.intents().len(),
        1,
        "a refusal leaves the intent in place: {:?}",
        fix.intents()
    );

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
        "--confirm-double",
        "--override",
        "member prepaid two years",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.account("secretary")["payment"]["paid_until"],
        json!("2029-10-04")
    );
    assert_eq!(payment_lines(&fix).len(), 1);
    assert!(
        fix.journal().contains("member prepaid two years"),
        "the override reason is not in the journal: {}",
        fix.journal()
    );
}

/// The console refuses what it cannot credit: two references, no account, an
/// account with no token, a rail it does not record. A username is resolved to
/// the token before the intent is filed.
#[test]
fn the_credit_console_resolves_a_username_and_refuses_what_it_cannot_credit() {
    let fix = Fix::new("credit-console");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    let base = [
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ];

    let mut args = vec!["credit", "--username", "secretary"];
    args.extend(base);
    let out = fix.ctl(&args);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("no account"), "{}", body(&out));

    fix.decide("provision", "secretary");
    assert!(fix.drain().status.success());
    let mut args = vec!["credit", "--username", "secretary"];
    args.extend(base);
    let out = fix.ctl(&args);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("no payment token"), "{}", body(&out));

    let paid = Fix::new("credit-console-paid");
    let token = approved_paid(&paid, "secretary", "cash");
    let out = paid.ctl(&[
        "credit",
        "--token",
        &token,
        "--username",
        "secretary",
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("not both"), "{}", body(&out));

    let out = paid.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "card",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("not one of"), "{}", body(&out));

    let out = paid.ctl(&[
        "credit",
        "--username",
        "secretary",
        "--rail",
        "cash-hand",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(paid.drain().status.success());
    let line = &payment_lines(&paid)[0];
    assert_eq!(line["token"], json!(token));
    assert_eq!(line["rail"], json!("cash-hand"));
}

/// A credit with no token is held in the unattributed queue: no payment line, no
/// paid-until date and no receipt. `reconcile list` shows it, `reconcile
/// attribute` turns it into an ordinary credit one year from the held date, and a
/// second attribute is refused.
#[test]
fn a_tokenless_credit_is_held_and_reconcile_attribute_credits_it_once() {
    let fix = Fix::new("reconcile-attribute");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--note",
        "no token on the envelope",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let held = held_lines(&fix);
    assert_eq!(held.len(), 1, "{held:?}");
    let line = &held[0];
    assert_eq!(line["state"], json!("held"), "{line}");
    assert_eq!(line["kind"], json!("held"), "{line}");
    assert_eq!(line["rail"], json!("cash"), "{line}");
    assert_eq!(line["amount_gbp"], json!("20.00"), "{line}");
    assert_eq!(line["received_on"], json!("2026-10-04"), "{line}");
    assert_eq!(line["note"], json!("no token on the envelope"), "{line}");
    assert!(line["amount_xmr"].is_null(), "{line}");
    assert!(line["txid"].is_null(), "{line}");
    let id = line["id"]
        .as_str()
        .expect("a held line carries its id")
        .to_string();
    assert!(store::is_unattributed_id(&id), "{id}");
    // No member is named, nothing was credited, and no receipt went out.
    let queue = fix.read("ledger/unattributed.jsonl");
    assert!(!queue.contains("secretary"), "{queue}");
    assert!(payment_lines(&fix).is_empty(), "{:?}", payment_lines(&fix));
    assert!(
        fix.account("secretary")["payment"]["paid_until"].is_null(),
        "a held payment moved the date"
    );
    assert!(
        !fix.read("accounts/secretary/notices.jsonl")
            .contains("prepaid.receipt"),
        "a held payment sent a receipt"
    );

    // `reconcile list` shows what is held, with its money, date and note.
    let out = fix.ctl(&["reconcile", "list"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(text.contains(&id), "{text}");
    assert!(text.contains("20.00"), "{text}");
    assert!(text.contains("no token on the envelope"), "{text}");

    // Attribute it: one payment line keyed by the token, one year from the held
    // date, one receipt, and the held line marked attributed to the token.
    let out = fix.ctl(&["reconcile", "attribute", &id, "--token", &token]);
    assert!(out.status.success(), "{}", body(&out));
    let names = fix.intents();
    assert_eq!(names.len(), 1, "{names:?}");
    let attribute_id = names[0].trim_end_matches(".json").to_string();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.account("secretary")["payment"]["paid_until"],
        json!("2027-10-04")
    );
    assert_eq!(
        fix.account("secretary")["payment"]["window"]["state"],
        json!("paid")
    );
    let payments = payment_lines(&fix);
    assert_eq!(payments.len(), 1, "{payments:?}");
    assert_eq!(payments[0]["token"], json!(token), "{payments:?}");
    assert_eq!(payments[0]["received_on"], json!("2026-10-04"));
    assert_eq!(payments[0]["amount_gbp"], json!("20.00"));
    assert_eq!(payments[0]["intent"], json!(attribute_id));
    let marked = held_lines(&fix);
    assert_eq!(marked[0]["state"], json!("attributed"), "{marked:?}");
    assert_eq!(marked[0]["attributed_to"], json!(token), "{marked:?}");
    assert!(marked[0]["attributed_at"].as_str().is_some(), "{marked:?}");
    assert_eq!(
        fix.read("accounts/secretary/notices.jsonl")
            .matches("prepaid.receipt")
            .count(),
        1,
        "attributing sent no receipt, or sent two"
    );

    // A second attribute of the same item is refused: it is no longer held, and
    // no second year is added.
    let out = fix.ctl(&["reconcile", "attribute", &id, "--token", &token]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        payment_lines(&fix).len(),
        1,
        "a second attribute was applied"
    );
    assert_eq!(
        fix.account("secretary")["payment"]["paid_until"],
        json!("2027-10-04"),
        "a refused attribute moved the date"
    );
    assert!(
        fix.journal().contains("not held"),
        "the refusal does not say the item is not held: {}",
        fix.journal()
    );
}

/// One Monero transaction is one payment. Holding it and then crediting it, or
/// the reverse, is refused from either side; the queue and the ledger are two
/// records of the same money, not two payments.
#[test]
fn a_monero_transaction_is_not_both_held_and_credited() {
    // Held first, then a token credit naming the same transaction.
    let held_first = Fix::new("txid-held-first");
    let token = approved_paid(&held_first, "secretary", "cash");
    let out = held_first.ctl(&[
        "credit",
        "--rail",
        "monero",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--note",
        "no subaddress on the transfer",
        "--txid",
        TXID,
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(held_first.drain().status.success());
    assert_eq!(held_lines(&held_first).len(), 1);

    let out = held_first.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "monero",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--txid",
        TXID,
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(held_first.drain().status.success());
    assert!(
        payment_lines(&held_first).is_empty(),
        "the same transaction was credited after being held: {:?}",
        payment_lines(&held_first)
    );
    assert!(
        held_first.journal().contains("already held"),
        "{}",
        held_first.journal()
    );
    assert_eq!(held_lines(&held_first).len(), 1, "a second held line");

    // Credited first, then a tokenless hold naming the same transaction.
    let credited_first = Fix::new("txid-credited-first");
    let token = approved_paid(&credited_first, "secretary", "cash");
    let out = credited_first.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "monero",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--txid",
        TXID,
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(credited_first.drain().status.success());
    assert_eq!(payment_lines(&credited_first).len(), 1);

    let out = credited_first.ctl(&[
        "credit",
        "--rail",
        "monero",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--note",
        "found in the wallet",
        "--txid",
        TXID,
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(credited_first.drain().status.success());
    assert!(
        held_lines(&credited_first).is_empty(),
        "a credited transaction was held again: {:?}",
        held_lines(&credited_first)
    );
    assert!(
        credited_first.journal().contains("already credited"),
        "{}",
        credited_first.journal()
    );
}

/// A held payment found after the token has already been credited is a renewal,
/// when the operator says so. The acknowledgement travels through the attribute
/// intent, and the item is marked attributed rather than left in the queue.
#[test]
fn a_held_payment_can_be_attributed_as_a_renewal() {
    let fix = Fix::new("attribute-renewal");
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

    let out = fix.ctl(&[
        "credit",
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-05",
        "--note",
        "second envelope, token read later",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let id = held_lines(&fix)[0]["id"].as_str().unwrap().to_string();

    // Without the acknowledgement the renewal is refused and the item stays
    // held, so the operator can file it with the flag rather than losing it.
    let out = fix.ctl(&["reconcile", "attribute", &id, "--token", &token]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    assert_eq!(payment_lines(&fix).len(), 1, "a renewal without the flag");
    assert_eq!(held_lines(&fix)[0]["state"], json!("held"));

    let out = fix.ctl(&[
        "reconcile",
        "attribute",
        &id,
        "--token",
        &token,
        "--confirm-double",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.account("secretary")["payment"]["paid_until"],
        json!("2028-10-04")
    );
    assert_eq!(payment_lines(&fix).len(), 2, "{:?}", payment_lines(&fix));
    assert_eq!(held_lines(&fix)[0]["state"], json!("attributed"));
}

/// `payment show` prints the rail, the paid-until date and the token-keyed
/// ledger lines, and a corrupt ledger is an error rather than an empty history.
#[test]
fn payment_show_prints_the_rail_date_and_ledger_lines() {
    let fix = Fix::new("payment-show");
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

    let out = fix.ctl(&["payment", "show", "--username", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(text.contains("account secretary"), "{text}");
    assert!(text.contains("rail     cash"), "{text}");
    assert!(text.contains("paid     2027-10-04"), "{text}");
    assert!(text.contains(&format!("ledger for {token}")), "{text}");
    assert!(text.contains("payment"), "{text}");
    assert!(text.contains("2026-10-04"), "{text}");
    assert!(text.contains("20.00"), "{text}");

    // A corrupt line is not an empty ledger.
    let path = fix.dir.join("store/ledger/payments.jsonl");
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("{not json}\n");
    std::fs::write(&path, text).unwrap();
    let out = fix.ctl(&["payment", "show", "--username", "secretary"]);
    assert!(!out.status.success(), "a corrupt ledger was read as empty");
    assert!(body(&out).contains("does not parse"), "{}", body(&out));
}

/// `reconcile return` closes a held item with the evidence, keeping what the
/// operator first wrote down, and writes no payment line.
#[test]
fn a_reconcile_return_closes_the_held_item_with_its_evidence() {
    let fix = Fix::new("reconcile-return");
    let out = fix.ctl(&[
        "credit",
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--note",
        "postmark unreadable",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let id = held_lines(&fix)[0]["id"]
        .as_str()
        .expect("a held line carries its id")
        .to_string();

    let out = fix.ctl(&[
        "reconcile",
        "return",
        &id,
        "--note",
        "posted back 2026-10-08, receipt in book",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let held = held_lines(&fix);
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0]["state"], json!("returned"), "{held:?}");
    assert!(held[0]["returned_at"].as_str().is_some(), "{held:?}");
    let note = held[0]["note"].as_str().expect("the note is kept");
    assert!(note.contains("postmark unreadable"), "{note}");
    assert!(
        note.contains("posted back 2026-10-08, receipt in book"),
        "{note}"
    );
    assert!(payment_lines(&fix).is_empty(), "{:?}", payment_lines(&fix));

    // The queue no longer offers it.
    let out = fix.ctl(&["reconcile", "list"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("nothing held"), "{}", body(&out));
}

/// `prepaid list --window open` shows the token, username, rail, close date and
/// days left; `--expiring` narrows it; and a credited window, whose state is
/// `paid`, is not listed at all.
#[test]
fn prepaid_list_shows_an_open_window_and_narrows_and_drops_a_credited_one() {
    let fix = Fix::new("prepaid-list");
    let token = approved_paid(&fix, "secretary", "cash");
    let closes_at = fix.account("secretary")["payment"]["window"]
        .get("closes_at")
        .and_then(Value::as_str)
        .expect("a paid approval opens a window")
        .to_string();
    let closes_on = closes_at[..10].to_string();

    let out = fix.ctl(&["prepaid", "list", "--window", "open"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(text.contains("1 open window(s)"), "{text}");
    assert!(text.contains(&token), "{text}");
    assert!(text.contains("secretary"), "{text}");
    assert!(text.contains("cash"), "{text}");
    assert!(text.contains(&closes_on), "{text}");
    let closes =
        OffsetDateTime::parse(&closes_at, &time::format_description::well_known::Rfc3339).unwrap();
    let days_left = (closes.date() - OffsetDateTime::now_utc().date()).whole_days();
    assert!(
        text.contains(&format!("{days_left} days left")),
        "expected {days_left} days left: {text}"
    );

    // The window closes fourteen days after the approval, so three days keeps
    // nothing and the window's own count keeps it.
    let out = fix.ctl(&["prepaid", "list", "--window", "open", "--expiring", "3"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("0 open window(s)"), "{}", body(&out));
    let out = fix.ctl(&["prepaid", "list", "--window", "open", "--expiring", "14"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(body(&out).contains(&token), "{}", body(&out));

    // Only the open window is a legal question.
    let out = fix.ctl(&["prepaid", "list", "--window", "closed"]);
    assert!(!out.status.success(), "{}", body(&out));
    let out = fix.ctl(&["prepaid", "list", "--window", "open", "--expiring", "-1"]);
    assert!(!out.status.success(), "{}", body(&out));

    // A credit closes the window with state `paid`, so the pass stops listing it.
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
    let out = fix.ctl(&["prepaid", "list", "--window", "open"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !body(&out).contains(&token),
        "a credited window was listed: {}",
        body(&out)
    );
}

/// A hand payment is the one rail keyed by a name, so the console refuses one
/// with no name; and a note is only for money with no token.
#[test]
fn the_console_refuses_a_tokenless_cash_hand_payment() {
    let fix = Fix::new("credit-note-cash-hand");
    let out = fix.ctl(&[
        "credit",
        "--rail",
        "cash-hand",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--note",
        "handed over in the street",
    ]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("username"), "{}", body(&out));

    // A note and a token together is two answers to one question.
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
        "--note",
        "posted twice",
    ]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("--note"), "{}", body(&out));
}

/// A filed application carries no payment state, which is what stops a status
/// link showing an account's token to an applicant who typed that account's
/// name: the block arrives only with the approval that made the account.
#[test]
fn a_filed_application_carries_no_payment_state() {
    let fix = Fix::new("status-unapproved");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());

    let filed: Record =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(filed.decided_at.is_none(), "the drain decided nothing");
    assert!(
        filed.payment.is_none(),
        "{:?}",
        filed.payment.as_ref().map(|p| &p.token_ref)
    );
}

/// A status token that resolves to nothing reads exactly as it reads today, and
/// a decided application past its seven days reads the same: no stage, no token,
/// no payment state.
#[test]
fn a_status_token_that_resolves_to_nothing_carries_no_payment() {
    let fix = Fix::new("status-unknown");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let now = OffsetDateTime::now_utc();
    let record: Record =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    let block = record.payment.clone().expect("the drain's copy");
    let payment = page::payment(
        "active",
        &record.rail,
        &block,
        "20.00",
        "1 Example Street, Example",
        None,
        now,
    );

    // Past the seven days the record's page is the unknown-token page, and the
    // payment block goes with it even when one is handed in.
    let later = now + time::Duration::days(8);
    let expired = responder::status_page(Some(record), Some(payment), later);
    let unknown = responder::status_page(None, None, now);
    assert!(
        expired.payment.is_none(),
        "{:?}",
        expired.payment.as_ref().map(|p| &p.token)
    );
    assert_eq!(
        expired.render().unwrap(),
        unknown.render().unwrap(),
        "an expired link reads as an unknown one"
    );
    assert_eq!(capsule::status(&expired), capsule::status(&unknown));
}

/// `onboardctl token resend` sends the same token again and mints nothing: one
/// file under `tokens/`, one token in the account, and the member's mail holding
/// the instructions one more time. A second resend sends a second copy, because
/// a member asking twice is the whole point of the verb.
#[test]
fn a_token_resend_sends_the_same_token_and_mints_nothing() {
    let fix = Fix::new("resend");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let token = stored_account(&fix, "secretary")
        .payment_state()
        .and_then(|p| p.token_ref)
        .expect("a paid approval's token");
    let tokens_before = fix.names("tokens");
    assert_eq!(
        tokens_before,
        vec![format!("{token}.json")],
        "{tokens_before:?}"
    );
    let sent_before = fix.sent().matches(&token).count();
    let mails_before = fix.sent().matches("Subject:").count();

    let out = fix.ctl(&["token", "resend", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());

    // The same string, one more time, and nothing new minted.
    let sent = fix.sent();
    assert_eq!(sent.matches("Subject:").count(), mails_before + 1);
    assert_eq!(sent.matches(&token).count(), sent_before + 1, "{sent}");
    assert_eq!(
        fix.names("tokens"),
        tokens_before,
        "a second token was written"
    );
    assert_eq!(
        stored_account(&fix, "secretary")
            .payment_state()
            .and_then(|p| p.token_ref)
            .as_deref(),
        Some(token.as_str())
    );
    assert!(fix
        .read("accounts/secretary/notices.jsonl")
        .contains("prepaid.instructions"));

    // A second resend sends a second copy rather than being deduplicated: the
    // member asked again.
    let out = fix.ctl(&["token", "resend", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        mails_before + 2,
        "{}",
        fix.sent()
    );
    assert_eq!(fix.names("tokens").len(), 1);

    // A free account has no token to resend, and the console says so now rather
    // than filing an intent the drain would refuse.
    let free = Fix::new("resend-free");
    let record = free.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    free.file_application(&record);
    assert!(free.drain().status.success());
    free.decide("provision", "secretary");
    let out = free.drain();
    assert!(out.status.success(), "{}", body(&out));
    let out = free.ctl(&["token", "resend", "secretary"]);
    assert!(!out.status.success());
    assert!(body(&out).contains("without charge"), "{}", body(&out));
    assert!(free.intents().is_empty(), "{:?}", free.intents());
}

/// Criterion (d): the token is a bearer secret, so the drain's own output never
/// carries it. Cron mails what the drain prints, and that log is read by more
/// people than the member's mail is.
#[test]
fn the_drain_prints_no_payment_token() {
    let fix = Fix::new("token-logs");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    // Filing prints the review mail's path and nothing of the account's.
    assert!(!body(&fix.drain()).contains("KYR-"));
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let token = stored_account(&fix, "secretary")
        .payment_state()
        .and_then(|p| p.token_ref)
        .expect("a paid approval's token");
    assert!(
        !body(&out).contains(&token),
        "the approval printed the token: {}",
        body(&out)
    );
    // A later pass over the same store prints none either, and the resend's
    // console output names the intent and not the token.
    assert!(!body(&fix.drain()).contains("KYR-"));
    let out = fix.ctl(&["token", "resend", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(!body(&out).contains(&token), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!body(&out).contains(&token), "{}", body(&out));
}

/// The drain is the second gate for the names the platform holds back. The
/// handler refuses one when an application is filed, and the half that creates
/// the account as root cannot take the other half's word for it.
#[test]
fn an_application_for_a_held_back_name_is_refused() {
    let fix = Fix::new("reserved-filed");
    let record = fix.filed("signup", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    fix.drain();

    assert!(fix.journal().contains("held back"), "{}", fix.journal());
    assert!(
        fix.failed_note().contains("signup"),
        "the failure names the name that was held back: {}",
        fix.failed_note()
    );
    assert_eq!(
        fix.intents().len(),
        1,
        "the intent is left in place: {:?}",
        fix.intents()
    );
    assert!(
        fix.passwd_file().is_empty(),
        "no account was made: {}",
        fix.passwd_file()
    );
    assert!(!fix.dir.join("store/accounts/signup").exists());
}

/// A name held back after the application was filed stops the approval, because
/// that is where an account would be made. The list's own header tells a
/// maintainer to add a new platform hostname to it, which is exactly this.
#[test]
fn an_approval_for_a_name_held_back_since_filing_is_refused() {
    let fix = Fix::new("reserved-approve");
    let record = fix.filed("theophilus", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    fix.drain();
    fix.reserve("theophilus");
    fix.decide("approve", "theophilus");
    fix.drain();

    assert!(fix.journal().contains("held back"), "{}", fix.journal());
    assert!(
        fix.failed_note().contains("theophilus"),
        "the failure names the name that was held back: {}",
        fix.failed_note()
    );
    assert!(
        !fix.dir.join("store/accounts/theophilus").exists(),
        "no account was made"
    );
    assert!(fix.passwd_file().is_empty(), "{}", fix.passwd_file());
}

/// The same check must not sit where the intent is read, or a decline of a
/// held-back name could never be carried out and the application would sit
/// undecided for ever.
#[test]
fn a_decline_of_a_held_back_name_is_still_carried_out() {
    let fix = Fix::new("reserved-decline");
    let record = fix.filed_with(
        "theophilus",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    fix.drain();
    fix.reserve("theophilus");
    fix.decide("decline", "theophilus");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        fix.sent().contains("was declined"),
        "the applicant is told: {}",
        fix.sent()
    );
    assert!(
        !fix.journal().contains("held back"),
        "a decline is not an admission: {}",
        fix.journal()
    );
}

/// A second application for a username that already has an account is not the
/// first application's to inherit. The first approval drew a payment token,
/// opened a window and wrote a ledger row, and approving the second must not
/// rewrite the account from that state, which would leave the account and the
/// ledger disagreeing about what is owed.
#[test]
fn a_second_application_does_not_reuse_the_first_approvals_payment() {
    let fix = Fix::new("second-application");
    let first = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&first);
    fix.drain();
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let token = fix.account("secretary")["payment"]["token_ref"].clone();
    let ledger = fix.read("ledger/payments.jsonl");
    assert!(
        !ledger.is_empty(),
        "the first approval opened a window: {ledger}"
    );

    // The same person applies again, later, and that application is approved.
    let second = json!({
        "username": "secretary",
        "status_token": OTHER_TOKEN,
        "filed_at": "2026-10-05T09:00:00Z",
        "front_end": "web",
        "stage": "received",
        "outside_address": null,
        "answers": {"rail": "cash"},
        "mail_keys": [{
            "mailbox": "",
            "fingerprint": "1111 2222 3333 4444",
            "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
            "verdict": "works",
        }],
        "upload_key": null,
        "rail": "cash",
        "no_charge": false,
        "acceptances": [{"document": "terms", "version": "2026-10-01 abc1234"}],
        "question_list": "2026-10-01 abc1234",
    });
    std::fs::write(
        fix.dir
            .join(format!("store/applications/{OTHER_TOKEN}.json")),
        serde_json::to_vec_pretty(&second).unwrap(),
    )
    .unwrap();
    fix.file_application(&second);
    fix.drain();
    // The console looks the application up by username and takes the newest, which
    // is how the operator reaches a second application for one person.
    let out = fix.ctl(&["approve", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        fix.journal().contains("already-member"),
        "{}",
        fix.journal()
    );
    assert_eq!(
        fix.intents().len(),
        0,
        "the second intent is cleared: {:?}",
        fix.intents()
    );
    assert_eq!(
        fix.account("secretary")["payment"]["token_ref"],
        token,
        "the first approval's token is untouched"
    );
    assert_eq!(
        fix.read("ledger/payments.jsonl"),
        ledger,
        "and no second window was opened and no second row written"
    );
}

/// A name a removed mailbox left cannot be reused inside ninety days, on an
/// add-mailbox or on a new group's approval.
#[test]
fn a_closed_username_is_held_for_ninety_days() {
    let fix = Fix::new("group-hold");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        None,
    );
    assert!(fix.drain().status.success());
    fix.file_address("parish.example", "remove", "", "parish-office", None, None);
    assert!(fix.drain().status.success());
    assert_eq!(fix.names("holds"), vec!["parish-office.json"]);

    let id = fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    assert!(fix.drain().status.success());
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("held until"),
        "{}",
        fix.failed_note()
    );
    assert!(!fix.passwd_file().contains("parish-office:"));

    // The approval gate reads the same hold. A different domain, so the name is
    // not already this group's account and the check reaches the hold.
    std::fs::write(
        fix.dir.join("store/holds/parish-secretary.json"),
        br#"{"username":"parish-secretary","until":"2099-01-01T00:00:00Z"}"#,
    )
    .unwrap();
    let mut record = fix.filed_body("warden");
    record["domain"] = json!("other.example");
    record["answers"]["body_domain"] = json!("other.example");
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    assert!(fix.drain().status.success());
    assert!(
        fix.failed_note().contains("held until"),
        "{}",
        fix.failed_note()
    );
}

/// The hold is not only a group rule: a person's approval creates an account
/// too, so a closed group mailbox's name cannot be taken by an applicant.
#[test]
fn a_person_cannot_take_a_held_group_name() {
    let fix = Fix::new("person-held");
    std::fs::create_dir_all(fix.dir.join("store/holds")).unwrap();
    std::fs::write(
        fix.dir.join("store/holds/theophilus.json"),
        br#"{"username":"theophilus","until":"2099-01-01T00:00:00Z"}"#,
    )
    .unwrap();
    let record = fix.filed("theophilus", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "theophilus");
    assert!(fix.drain().status.success());
    assert!(
        fix.failed_note().contains("held until"),
        "{}",
        fix.failed_note()
    );
    assert!(!fix.dir.join("store/accounts/theophilus").exists());
    assert!(fix.passwd_file().is_empty(), "{}", fix.passwd_file());
}
