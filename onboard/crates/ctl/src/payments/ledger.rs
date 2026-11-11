//! One job of the operator console.

use crate::*;

/// `ledger export --tax-year <year> --format csv`: the year's lines for the
/// accountant. It reads `ledger/payments.jsonl` in place and prints; nothing is
/// written, because the ledger is the record and the file is never purged. The
/// held money in `ledger/unattributed.jsonl` is not income until it is
/// attributed, so it follows the keyed rows in a section of its own rather than
/// as a row without a token.
pub(crate) async fn ledger(store: &Store, args: &[String]) -> Result<(), String> {
    let rest = match args {
        [verb, rest @ ..] if verb == "export" => rest,
        _ => return Err(usage()),
    };
    let flags = flags(rest, &["tax-year", "format"])?;
    let (start, end) = tax_year(need(&flags, "tax-year")?)?;
    let format = need(&flags, "format")?;
    if format != "csv" {
        return Err(format!("--format {format:?} is not csv"));
    }
    let columns = payment_columns();
    println!(
        "{}",
        columns
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(",")
    );

    let mut rows = Vec::new();
    for line in Ledger::open(store).lines().await? {
        if in_tax_year(line.received_on.as_deref(), start, end) {
            rows.push(line);
        }
    }
    rows.sort_by_key(|line| line.seq);
    for line in rows {
        let cells: Vec<String> = columns
            .iter()
            .map(|(_, value)| csv_cell(&value(&line)))
            .collect();
        println!("{}", cells.join(","));
    }

    println!();
    println!("# unattributed");
    println!("id,rail,received_on,amount_gbp");
    for row in store
        .log("ledger/unattributed.jsonl")
        .jsonl::<Value>()
        .await?
    {
        if row["state"].as_str() != Some("held")
            || !in_tax_year(row.get("received_on").and_then(Value::as_str), start, end)
        {
            continue;
        }
        let cells: Vec<String> = ["id", "rail", "received_on", "amount_gbp"]
            .iter()
            .map(|field| csv_cell(&cell(&row[*field])))
            .collect();
        println!("{}", cells.join(","));
    }
    Ok(())
}

/// Whether a ledger row's `received_on` falls in the half-open-by-year tax
/// window it is exported for. A row with no date, such as the approval's
/// `window_open`, is not in any year.
pub(crate) fn in_tax_year(received_on: Option<&str>, start: time::Date, end: time::Date) -> bool {
    received_on
        .and_then(util::parse_date)
        .is_some_and(|date| date >= start && date <= end)
}

/// A tax year's bounds: the `YYYY-YY` or `YYYY-YYYY` spelling, 6 April to the
/// following 5 April inclusive. The second year is not accepted on trust: a
/// mistyped pair would quietly export a different year's money.
pub(crate) fn tax_year(s: &str) -> Result<(time::Date, time::Date), String> {
    let refuse = || {
        format!("--tax-year {s:?} is not YYYY-YY or YYYY-YYYY, or its years are not consecutive")
    };
    let (first, second) = s.split_once('-').ok_or_else(refuse)?;
    if first.len() != 4 || !first.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refuse());
    }
    let year: i32 = first.parse().map_err(|_| refuse())?;
    let next = year.checked_add(1).ok_or_else(refuse)?;
    let second_ok = match second.len() {
        2 => {
            second.bytes().all(|b| b.is_ascii_digit())
                && second.parse::<i32>().map_err(|_| refuse())? == next.rem_euclid(100)
        }
        4 => {
            second.bytes().all(|b| b.is_ascii_digit())
                && second.parse::<i32>().map_err(|_| refuse())? == next
        }
        _ => return Err(refuse()),
    };
    if !second_ok {
        return Err(refuse());
    }
    let start =
        time::Date::from_calendar_date(year, time::Month::April, 6).map_err(|_| refuse())?;
    let end = time::Date::from_calendar_date(next, time::Month::April, 5).map_err(|_| refuse())?;
    Ok((start, end))
}

/// One ledger value as the CSV cell it prints as. A missing or null field is an
/// empty cell; a number keeps its own spelling.
pub(crate) fn cell(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// The payments section's columns, in the order the accountant's sheet takes.
/// The header and the cells both come from this list, so they cannot drift.
pub(crate) fn payment_columns() -> [PaymentColumn; 15] {
    [
        ("seq", |line| line.seq.to_string()),
        ("token", |line| line.token.clone()),
        ("kind", |line| line.kind.clone()),
        ("rail", |line| line.rail.clone()),
        ("received_on", |line| {
            line.received_on.clone().unwrap_or_default()
        }),
        ("amount_gbp", |line| {
            line.amount_gbp.clone().unwrap_or_default()
        }),
        ("applied_gbp", |line| {
            line.applied_gbp.clone().unwrap_or_default()
        }),
        ("paid_until_after", |line| {
            line.paid_until_after.clone().unwrap_or_default()
        }),
        ("amount_xmr", |line| {
            line.amount_xmr.clone().unwrap_or_default()
        }),
        ("txid", |line| line.txid.clone().unwrap_or_default()),
        ("refund_of", |line| {
            line.refund_of().map(|n| n.to_string()).unwrap_or_default()
        }),
        ("settled_on", |line| {
            line.settled_on().unwrap_or_default().to_string()
        }),
        ("rate_quoted", |line| {
            line.rate_quoted.clone().unwrap_or_default()
        }),
        ("rate_source", |line| {
            line.rate_source.clone().unwrap_or_default()
        }),
        ("rate_at", |line| line.rate_at.clone().unwrap_or_default()),
    ]
}

/// RFC 4180: a comma, a quote or a line break in a cell puts the whole cell in
/// quotes, and a quote inside it is doubled. The ledger's free text can carry
/// any of the three, though the export never prints `note`.
pub(crate) fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
