//! The times the store's own records carry: when an application was filed, and
//! when its status link stops answering. One module, so the timestamp crate can
//! move without touching anything else.

use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, OffsetDateTime};

/// The hold after a decision, which is the drain's: it clears the application
/// away seven days after it decides, and the status page stops with it.
const STATUS_WINDOW_DAYS: i64 = 7;

/// The time an application was filed, RFC 3339 in UTC, second precision. Second
/// precision matches the timestamps the store's other records carry and keeps
/// the JSON stable to read; the ULID beside it already holds milliseconds.
pub fn filed_at() -> String {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// A timestamp `days` from now, RFC 3339 UTC to the second. The window's close,
/// the status link's end and the one-time password link's expiry all come from
/// here, so there is one arithmetic and one format for the three.
pub fn after_days(days: i64) -> String {
    let then = OffsetDateTime::now_utc() + Duration::days(days);
    then.replace_nanosecond(0)
        .unwrap_or(then)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// A date `days` from now, `YYYY-MM-DD`. An RFC 3339 timestamp begins with the
/// date, so the two cannot drift.
pub fn date_after_days(days: i64) -> String {
    after_days(days)[..10].to_string()
}

/// The whole days from today to the date an RFC 3339 stamp names, which is what
/// the account page counts a payment window down with. `None` for a stamp that
/// cannot be read, so a record with a broken date shows no countdown rather than
/// a fabricated one.
pub fn days_left(stamp: &str, now: OffsetDateTime) -> Option<i64> {
    let then = OffsetDateTime::parse(stamp, &Rfc3339).ok()?;
    Some((then.date() - now.date()).whole_days())
}

/// Whether the status link of a decided application still answers. `decided_at`
/// is the field the drain sets when it decides; the handler writes nothing
/// there and reads it only for this. Seven days after the decision the link
/// stops, and it stops the same way for every token, so the path is never an
/// oracle for whether one exists.
///
/// A decision stamped in a shape that cannot be read is closed rather than
/// open: the drain writes RFC 3339, and a record whose decision cannot be dated
/// is one this page cannot answer for.
pub fn link_answers(decided_at: &str, now: OffsetDateTime) -> bool {
    match OffsetDateTime::parse(decided_at, &Rfc3339) {
        Ok(d) => now < d + Duration::days(STATUS_WINDOW_DAYS),
        Err(_) => false,
    }
}

/// The same day in `year`, clamped to the month's length. 29 February becomes
/// 28 February in a common year, which is the clamp the prepaid spec fixes for a
/// payment's anniversary and the free account's yearly note.
pub fn anniversary(date: Date, year: i32) -> Date {
    let last = date.month().length(year);
    Date::from_calendar_date(year, date.month(), date.day().min(last))
        .expect("a day clamped to the month's length is in the month")
}

/// The paid-until date a credit sets: one calendar year after the later of the
/// day it was recorded and the date already paid to. A renewal paid early keeps
/// the full year, and a payment after a lapse runs from the day it is recorded.
pub fn paid_until_after(received: Date, before: Option<Date>) -> Date {
    let start = before.map_or(received, |b| b.max(received));
    anniversary(start, start.year() + 1)
}

/// The farthest a credit may reach: twenty-four months past the day it was
/// recorded. Anything beyond is a mistyped amount or the same envelope twice,
/// and the operator needs `--override` to mean it.
pub fn credit_ceiling(received: Date) -> Date {
    anniversary(received, received.year() + 2)
}

/// A `YYYY-MM-DD` date, which is the form a credit's `--received` and the
/// ledger's date fields carry. A timestamp is refused: the fields are dates, and
/// accepting one shape here and writing another is how two records come to
/// disagree.
pub fn parse_date(s: &str) -> Option<Date> {
    if s.len() != 10 {
        return None;
    }
    OffsetDateTime::parse(&format!("{s}T00:00:00Z"), &Rfc3339)
        .ok()
        .map(|t| t.date())
}

pub fn date_string(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// A pounds amount as integer pence. Amounts are decimal strings, never floats:
/// money is added and compared in pence, and this is the one parser both the
/// console and the drain use. At most two decimal places, because a penny is the
/// smallest unit of the ledger.
pub fn pence(s: &str) -> Result<i64, String> {
    let (pounds, fraction) = s.split_once('.').unwrap_or((s, ""));
    if pounds.is_empty()
        || pounds.len() > 9
        || !pounds.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 2
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!("{s:?} is not an amount in pounds"));
    }
    let whole: i64 = pounds
        .parse()
        .map_err(|_| format!("{s:?} is not an amount in pounds"))?;
    let pennies: i64 = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<2}")
            .parse()
            .map_err(|_| format!("{s:?} is not an amount in pounds"))?
    };
    Ok(whole * 100 + pennies)
}

/// Integer pence as the decimal string a record carries.
pub fn gbp(pence: i64) -> String {
    format!("{}.{:02}", pence / 100, pence % 100)
}

#[cfg(test)]
mod tests {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    fn at(s: &str) -> OffsetDateTime {
        OffsetDateTime::parse(s, &Rfc3339).unwrap()
    }

    #[test]
    fn the_link_stops_seven_days_after_a_decision() {
        let decided = "2026-10-01T09:00:00Z";
        assert!(super::link_answers(decided, at("2026-10-01T09:00:00Z")));
        assert!(super::link_answers(decided, at("2026-10-08T08:59:59Z")));
        // The seven days are elapsed at the second the seventh day ends.
        assert!(!super::link_answers(decided, at("2026-10-08T09:00:00Z")));
        assert!(!super::link_answers(decided, at("2026-10-09T09:00:00Z")));
        // A decision that cannot be dated is closed, not open.
        assert!(!super::link_answers(
            "last Tuesday",
            at("2026-10-01T09:00:00Z")
        ));
    }

    #[test]
    fn filed_at_is_rfc3339_utc_to_the_second() {
        let t = super::filed_at();
        assert_eq!(t.len(), 20, "{t}");
        assert!(t.ends_with('Z'), "{t}");
        // YYYY-MM-DDTHH:MM:SSZ with digits and the two separators where they belong.
        assert_eq!(t.as_bytes()[4], b'-');
        assert_eq!(t.as_bytes()[7], b'-');
        assert_eq!(t.as_bytes()[10], b'T');
        assert_eq!(t.as_bytes()[13], b':');
        assert_eq!(t.as_bytes()[16], b':');
    }

    #[test]
    fn after_days_moves_by_whole_days_and_date_is_its_first_ten() {
        let week = super::after_days(7);
        let date = super::date_after_days(7);
        assert_eq!(date.len(), 10, "{date}");
        assert!(week.starts_with(&date), "{week} {date}");
        // Seven days after today is seven days after today, so the date differs
        // from today's by the same span.
        assert_ne!(date, super::date_after_days(0));
    }

    fn date(s: &str) -> time::Date {
        super::parse_date(s).unwrap()
    }

    #[test]
    fn a_credit_extends_from_the_later_of_today_and_the_existing_date() {
        // Paying inside the window: nothing is paid yet, so a full year from the
        // day the credit is recorded.
        assert_eq!(
            super::paid_until_after(date("2026-10-04"), None),
            date("2027-10-04")
        );
        // Paying after a lapse: the old date is behind today, so the year runs
        // from today rather than from the date that ran out.
        assert_eq!(
            super::paid_until_after(date("2026-10-04"), Some(date("2025-01-01"))),
            date("2027-10-04")
        );
        // Renewing before the date: the year runs from the later existing date,
        // so paying early loses nothing.
        assert_eq!(
            super::paid_until_after(date("2026-10-04"), Some(date("2027-06-01"))),
            date("2028-06-01")
        );
        // 29 February lands on 28 February in the common year that follows.
        assert_eq!(
            super::paid_until_after(date("2028-02-29"), None),
            date("2029-02-28")
        );
    }

    #[test]
    fn the_ceiling_is_twenty_four_months_past_the_recorded_day() {
        assert_eq!(
            super::credit_ceiling(date("2026-10-04")),
            date("2028-10-04")
        );
        assert_eq!(
            super::credit_ceiling(date("2028-02-29")),
            date("2030-02-28")
        );
    }

    #[test]
    fn dates_are_yyyy_mm_dd_and_nothing_else() {
        assert_eq!(super::date_string(date("2026-10-04")), "2026-10-04");
        assert!(super::parse_date("2026-10-04").is_some());
        assert!(super::parse_date("2026-10-04T00:00:00Z").is_none());
        assert!(super::parse_date("2026-2-4").is_none());
        assert!(super::parse_date("2026-02-30").is_none());
    }

    #[test]
    fn pounds_are_parsed_and_written_as_pence() {
        assert_eq!(super::pence("20.00"), Ok(2000));
        assert_eq!(super::pence("20"), Ok(2000));
        assert_eq!(super::pence("0.05"), Ok(5));
        assert_eq!(super::pence("19.8"), Ok(1980));
        assert!(super::pence("20.001").is_err());
        assert!(super::pence("-20.00").is_err());
        assert!(super::pence("twenty").is_err());
        assert_eq!(super::gbp(2000), "20.00");
        assert_eq!(super::gbp(5), "0.05");
    }
}
