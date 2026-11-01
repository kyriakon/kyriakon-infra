use crate::common::*;

/// A mainnet subaddress: 95 base58 characters beginning with `8`, the shape the
/// operator's wallet prints.
fn subaddress(tag: char) -> String {
    format!("8{}", tag.to_string().repeat(94))
}

fn view(fix: &Fix, username: &str) -> page::PaymentView {
    let account = stored_account(fix, username);
    let block = account.payment_state().expect("a paid approval's block");
    page::payment(
        &account.state,
        &account.rail,
        &block,
        "20.00",
        "1 Example Street, Example",
        None,
        OffsetDateTime::now_utc(),
    )
}

/// The window's quote is `price ÷ rate` rounded up to six places, taken once at
/// the opening and held: the source is asked once, the cache is written once, and
/// a later rate does not move the number the member was shown. The page says the
/// address is not ready until the wallet pass records one, then shows it with the
/// quote and the rate, and the pound amount is the one owed.
#[test]
fn a_monero_window_is_quoted_once_and_the_page_shows_the_address_quote_and_rate() {
    let fix = Fix::new("monero-quote");
    fix.rate_source(Some("409.44"));
    approved_paid(&fix, "secretary", "monero");

    let account = fix.account("secretary");
    let monero = &account["payment"]["monero"];
    assert_eq!(monero["quote_xmr"], json!("0.048848"), "{account}");
    assert_eq!(monero["rate_gbp_per_xmr"], json!("409.44"), "{account}");
    assert_eq!(monero["rate_source"], json!("coingecko"), "{account}");
    assert!(
        monero["rate_at"].as_str().is_some_and(|at| at.len() >= 20),
        "the quote records when the rate was fetched: {account}"
    );
    assert!(monero.get("stale").is_none(), "a fresh quote is not stale");
    assert!(
        monero.get("address").is_none(),
        "no wallet pass has recorded an address yet: {account}"
    );
    assert_eq!(fix.rate_fetches(), 1, "the source is asked once");
    assert_eq!(fix.rate_cache()["rate_gbp_per_xmr"], json!("409.44"));

    // A rate the source answered later does not re-quote an open window.
    fix.rate_source(Some("512.34"));
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.rate_fetches(),
        1,
        "the fresh cache is used, not the source"
    );
    assert_eq!(
        fix.account("secretary")["payment"]["monero"]["quote_xmr"],
        json!("0.048848")
    );

    // Before the address exists the page says so rather than showing a blank.
    let before = view(&fix, "secretary").instructions.join("\n");
    assert!(before.contains("not ready"), "{before}");
    assert!(before.contains("0.048848 XMR"), "{before}");
    assert!(before.contains("GBP 409.44 per XMR"), "{before}");
    assert!(
        before.contains("The pound amount is what is owed"),
        "{before}"
    );

    // The wallet pass records the subaddress; the account page and the status
    // page's copy both carry it.
    let address = subaddress('A');
    let out = fix.ctl(&["monero", "address", "secretary", &address]);
    assert!(out.status.success(), "{}", body(&out));
    let account = fix.account("secretary");
    assert_eq!(account["payment"]["monero"]["address"], json!(address));
    assert_eq!(
        fix.rate_fetches(),
        1,
        "recording an address asks nothing new"
    );
    let application: Value = serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json")))
        .expect("the application copy parses");
    assert_eq!(
        application["payment"]["monero"]["address"],
        json!(address),
        "the status page's copy carries the address too"
    );

    let view = view(&fix, "secretary");
    let instructions = view.instructions.join("\n");
    assert!(instructions.contains(&address), "{instructions}");
    assert!(instructions.contains("0.048848 XMR"), "{instructions}");
    assert!(!instructions.contains("not ready"), "{instructions}");
    let account = stored_account(&fix, "secretary");
    let gemini = capsule::account(&account, &[], None, Some(&view));
    assert!(gemini.contains(&address), "{gemini}");
    assert!(gemini.contains("0.048848"), "{gemini}");
    let web = page::account(&[], Some("secretary"), None, Some(view), false)
        .render()
        .unwrap();
    assert!(web.contains(&address), "{web}");
    assert!(web.contains("0.048848"), "{web}");

    // The same address again is a replay that says so; a different one is
    // refused, because a subaddress is never rotated or reused.
    let out = fix.ctl(&["monero", "address", "secretary", &address]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("already"), "{}", body(&out));
    let other = subaddress('B');
    let out = fix.ctl(&["monero", "address", "secretary", &other]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("never rotated"), "{}", body(&out));
    assert_eq!(
        fix.account("secretary")["payment"]["monero"]["address"],
        json!(address),
        "the refused address was not written"
    );
}

/// The address command refuses a value that cannot be a member's subaddress, and
/// an account that has no Monero rail to record one against.
#[test]
fn the_address_command_refuses_another_rails_address_and_a_wrong_shape() {
    let fix = Fix::new("monero-address-refusals");
    approved_paid(&fix, "secretary", "cash");
    let address = subaddress('A');
    let out = fix.ctl(&["monero", "address", "secretary", &address]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("cash rail"), "{}", body(&out));
    assert!(
        fix.account("secretary")["payment"].get("monero").is_none(),
        "a refused record writes no block"
    );

    let free = Fix::new("monero-address-free");
    let record = free.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    free.file_application(&record);
    assert!(free.drain().status.success());
    free.decide("provision", "secretary");
    assert!(free.drain().status.success());
    let out = free.ctl(&["monero", "address", "secretary", &address]);
    assert!(!out.status.success(), "{}", body(&out));
    assert!(body(&out).contains("without charge"), "{}", body(&out));

    // A standard address begins with `4`, a truncated paste is short, and a
    // character outside base58 is not a wallet's output.
    let monero = Fix::new("monero-address-shape");
    approved_paid(&monero, "secretary", "monero");
    for bad in [
        format!("4{}", "A".repeat(94)),
        "8AAAAAAAA".to_string(),
        format!("8{}", "0".repeat(94)),
    ] {
        let out = monero.ctl(&["monero", "address", "secretary", &bad]);
        assert!(!out.status.success(), "{bad}: {}", body(&out));
    }
}

/// With the source unreachable and a cache present the quote is taken from the
/// cache and marked stale, the cache is not rewritten, and the page hides the
/// Monero block rather than quoting a member from a rate it cannot refresh.
#[test]
fn a_stale_rate_marks_the_quote_and_hides_the_monero_block() {
    let fix = Fix::new("monero-stale");
    fix.rate_source(None);
    fix.write_rate_cache("409.44", "2026-01-01T00:00:00Z");
    approved_paid(&fix, "secretary", "monero");

    let account = fix.account("secretary");
    let monero = &account["payment"]["monero"];
    assert_eq!(monero["stale"], json!(true), "{account}");
    assert_eq!(monero["quote_xmr"], json!("0.048848"), "{account}");
    let cached = fix.rate_cache();
    assert_eq!(cached["rate_gbp_per_xmr"], json!("409.44"));
    assert_eq!(
        cached["fetched_at"],
        json!("2026-01-01T00:00:00Z"),
        "a failed fetch does not rewrite the cache"
    );

    let instructions = view(&fix, "secretary").instructions.join("\n");
    assert!(
        instructions.contains("cash by post is the only prepaid rail"),
        "{instructions}"
    );
    assert!(instructions.contains("1 Example Street"), "{instructions}");
    assert!(!instructions.contains("0.048848"), "{instructions}");
    assert!(!instructions.contains("subaddress"), "{instructions}");
}

/// No rate ever fetched: the window opens with cash as the only prepaid rail.
/// Nothing is quoted, no cache appears, and the page says what the member can do.
#[test]
fn no_rate_ever_fetched_opens_the_window_with_cash_only() {
    let fix = Fix::new("monero-no-rate");
    fix.rate_source(None);
    approved_paid(&fix, "secretary", "monero");

    let account = fix.account("secretary");
    assert!(
        account["payment"].get("monero").is_none(),
        "no rate, no quote, no block: {account}"
    );
    assert!(
        !fix.dir.join("store/rates/xmr-gbp.json").exists(),
        "no rate ever fetched writes no cache"
    );
    let instructions = view(&fix, "secretary").instructions.join("\n");
    assert!(
        instructions.contains("cash by post is the only prepaid rail"),
        "{instructions}"
    );
    assert!(instructions.contains("1 Example Street"), "{instructions}");
    assert_eq!(
        fix.rate_fetches(),
        1,
        "the failed attempt is not retried at once"
    );
}

/// The drain writes the cache at most once every twenty-four hours: a fresh one
/// is used without asking the source, a stale one is refetched and replaced, and
/// the refetch is not repeated on the next pass.
#[test]
fn the_rate_cache_is_written_at_most_once_every_twenty_four_hours() {
    let fix = Fix::new("monero-cache");
    fix.rate_source(Some("512.34"));
    fix.write_rate_cache("409.44", &kyriakon_onboard::util::filed_at());
    assert!(fix.drain().status.success());
    assert_eq!(fix.rate_fetches(), 0, "a fresh cache asks nothing");
    assert_eq!(
        fix.rate_cache()["rate_gbp_per_xmr"],
        json!("409.44"),
        "a fresh cache is not rewritten"
    );

    fix.write_rate_cache("409.44", "2026-01-01T00:00:00Z");
    assert!(fix.drain().status.success());
    assert_eq!(fix.rate_fetches(), 1, "a stale cache asks once");
    assert_eq!(fix.rate_cache()["rate_gbp_per_xmr"], json!("512.34"));
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.rate_fetches(),
        1,
        "the cache just written is inside its day"
    );
}

/// A Monero payment the quote absorbs in full is one percent either side, and
/// anything above the price lands in `payment.balance_gbp`. The ledger line
/// carries the rate that produced the quote, its source and when it was fetched.
#[test]
fn a_monero_payment_within_one_percent_is_paid_and_an_excess_is_held() {
    let fix = Fix::new("monero-credit-band");
    fix.rate_source(Some("409.44"));
    let token = approved_paid(&fix, "secretary", "monero");
    let today = kyriakon_onboard::util::date_after_days(0);
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "monero",
        "--amount",
        "19.80",
        "--received",
        &today,
        "--txid",
        TXID,
        "--xmr",
        "0.048847",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = fix.account("secretary");
    assert!(
        account["payment"]["paid_until"].is_string(),
        "a payment within one percent is the price: {account}"
    );
    assert!(account["payment"].get("balance_gbp").is_none(), "{account}");
    let line = payment_lines(&fix).remove(0);
    assert_eq!(line["rate_quoted"], json!("409.44"), "{line}");
    assert_eq!(line["rate_source"], json!("coingecko"), "{line}");
    assert!(
        line["rate_at"].as_str().is_some_and(|at| at.len() >= 20),
        "the ledger records when the quoted rate was fetched: {line}"
    );
    assert_eq!(line["amount_xmr"], json!("0.048847"), "{line}");
    assert_eq!(line["txid"], json!(TXID), "{line}");

    let over = Fix::new("monero-credit-excess");
    over.rate_source(Some("409.44"));
    let token = approved_paid(&over, "secretary", "monero");
    let out = over.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "monero",
        "--amount",
        "20.50",
        "--received",
        &today,
        "--txid",
        TXID,
        "--xmr",
        "0.050000",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(over.drain().status.success());
    let account = over.account("secretary");
    assert_eq!(
        account["payment"]["balance_gbp"],
        json!("0.50"),
        "{account}"
    );
}
