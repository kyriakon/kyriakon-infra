//! The times the store's own records carry: when an application was filed, and
//! when its status link stops answering. One module, so the timestamp crate can
//! move without touching anything else.

use crate::Error;
use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, OffsetDateTime};

/// The hold after a decision, which is the drain's: it clears the application
/// away seven days after it decides, and the status page stops with it.
const STATUS_WINDOW_DAYS: i64 = 7;

/// The time an application was filed, RFC 3339 in UTC, second precision. Second
/// precision matches the timestamps the store's other records carry and keeps
/// the JSON stable to read; the ULID beside it already holds milliseconds.
pub fn filed_at() -> String {
    stamp(OffsetDateTime::now_utc())
}

/// The same RFC 3339 timestamp to the second, for a caller that already holds
/// the instant. One format for the store's records, so a stamp written by the
/// rate cache reads like the one beside it in a ledger line.
pub fn stamp(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Text safe to write to a terminal: every control character becomes `?`.
///
/// A message header reaches an operator's screen through [`report`] or [`log`],
/// and the header is a member's to write: an escape would let it clear the
/// screen, retitle the window or fill the clipboard over OSC 52. Replacing the
/// character rather than deleting it keeps the rest of the line where the reader
/// expects it, and one character for one character keeps a line's width.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if terminal_safe(c) { c } else { '?' })
        .collect()
}

/// Whether a character may reach a terminal. Controls are the escapes, and the
/// invisible formatters are the rest: a bidirectional override or isolate would
/// let a stored name display as another account's, and Unicode's line and
/// paragraph separators would break a record's one line into two. The set is
/// the Cf, Zl and Zp categories.
fn terminal_safe(c: char) -> bool {
    !c.is_control()
        && !matches!(c,
            '\u{00ad}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}')
}

/// Text safe to put in a mail body: every character [`clean`] replaces, except
/// that a newline and a tab survive so a multi-line answer still reads as the
/// applicant wrote it. One predicate with [`clean`], so a character stripped
/// from a console line is stripped from a mail body too.
pub fn clean_body(text: &str) -> String {
    text.chars()
        .map(|c| {
            if matches!(c, '\n' | '\t') || terminal_safe(c) {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// The lines one failure prints: the error under the service prefix, then each
/// source that says something the line already printed does not. A wrapper whose
/// `Display` delegates to its source would otherwise print the same sentence
/// twice, and cron mails the drain's stderr. Cleaned, since an error message can
/// quote what a member sent.
pub fn report_lines(error: &(dyn std::error::Error + 'static), context: &str) -> Vec<String> {
    let mut lines = vec![format!("kyriakon-control: {context}: {error}")];
    let mut last = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if text != last {
            lines.push(format!("kyriakon-control:   caused by: {text}"));
            last = text;
        }
        source = cause.source();
    }
    lines.iter().map(|line| clean(line)).collect()
}

/// Print [`report_lines`]. The one reporting function: a journal note, an alert
/// body and a binary's last line all go through here.
pub fn report(error: &(dyn std::error::Error + 'static), context: &str) {
    for line in report_lines(error, context) {
        eprintln!("{line}");
    }
}

/// Print one access or startup line. The same one place writes the service's
/// stderr, so a log line and a failure report cannot drift onto different
/// streams.
pub fn log(line: &str) {
    eprintln!("{}", clean(line));
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
///
/// `None` when `year` is off the end of the calendar: the date arithmetic is
/// fed a date an intent or a record carries, and a hand-written 9999 must be
/// refused rather than panic the pass.
pub fn anniversary(date: Date, year: i32) -> Option<Date> {
    let last = date.month().length(year);
    Date::from_calendar_date(year, date.month(), date.day().min(last)).ok()
}

/// The paid-until date a credit sets: one calendar year after the later of the
/// day it was recorded and the date already paid to. A renewal paid early keeps
/// the full year, and a payment after a lapse runs from the day it is recorded.
/// `None` when that year is off the end of the calendar.
pub fn paid_until_after(received: Date, before: Option<Date>) -> Option<Date> {
    let start = before.map_or(received, |b| b.max(received));
    anniversary(start, start.year() + 1)
}

/// The farthest a credit may reach: twenty-four months past the day it was
/// recorded. Anything beyond is a mistyped amount or the same envelope twice,
/// and the operator needs `--override` to mean it. `None` when that day is off
/// the end of the calendar.
pub fn credit_ceiling(received: Date) -> Option<Date> {
    anniversary(received, received.year() + 2)
}

/// Whether a credit's `--received` date is more than twenty-four months ahead
/// of `today`, which is the ceiling `credit_ceiling` measures from. A date
/// beyond it is a mistyped year, and it is refused here, at both ends that file
/// and that drain an intent, so the arithmetic never sees one.
pub fn received_beyond_window(received: Date, today: Date) -> bool {
    credit_ceiling(today).is_none_or(|ceiling| received > ceiling)
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
pub fn pence(s: &str) -> Result<i64, Error> {
    let (pounds, fraction) = s.split_once('.').unwrap_or((s, ""));
    if pounds.is_empty()
        || pounds.len() > 9
        || !pounds.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 2
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::Failed(format!("{s:?} is not an amount in pounds")));
    }
    let whole: i64 = pounds
        .parse()
        .map_err(|source| Error::context(format!("{s:?} is not an amount in pounds"), source))?;
    let pennies: i64 = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<2}")
            .parse()
            .map_err(|source| Error::context(format!("{s:?} is not an amount in pounds"), source))?
    };
    Ok(whole * 100 + pennies)
}

/// Integer pence as the decimal string a record carries.
pub fn gbp(pence: i64) -> String {
    format!("{}.{:02}", pence / 100, pence % 100)
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    #[derive(Debug)]
    struct Inner;
    impl fmt::Display for Inner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("same text")
        }
    }
    impl std::error::Error for Inner {}

    #[derive(Debug)]
    struct Wrapper(Inner);
    impl fmt::Display for Wrapper {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.fmt(f)
        }
    }
    impl std::error::Error for Wrapper {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn a_wrapper_is_reported_once() {
        assert_eq!(
            super::report_lines(&Wrapper(Inner), "context"),
            vec!["kyriakon-control: context: same text"]
        );
    }

    #[derive(Debug)]
    struct Hostile;
    impl fmt::Display for Hostile {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("the message is from \x1b]52;c;cG93bmVk\x07a\r\n@evil.example")
        }
    }
    impl std::error::Error for Hostile {}

    #[test]
    fn a_terminal_line_loses_its_control_characters() {
        // A plain value keeps its width and its text.
        assert_eq!(super::clean("Re: my data"), "Re: my data");
        // ESC, BEL, CR, LF, a C1 control and DEL each become one `?`.
        assert_eq!(
            super::clean("a\x1b]52;c;cG93bmVk\x07b\rc\nd\u{9b}e\u{7f}f"),
            "a?]52;c;cG93bmVk?b?c?d?e?f"
        );
        // A bidi override cannot reorder a name, and a line separator cannot
        // split the one line a record's field prints as.
        assert_eq!(super::clean("ali\u{202e}ce\u{2028}bob"), "ali?ce?bob");
        assert_eq!(
            super::report_lines(&Hostile, "verifying a request"),
            vec![
                "kyriakon-control: verifying a request: the message is from ?]52;c;cG93bmVk?a??@evil.example"
            ]
        );
    }

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
            super::paid_until_after(date("2026-10-04"), None).unwrap(),
            date("2027-10-04")
        );
        // Paying after a lapse: the old date is behind today, so the year runs
        // from today rather than from the date that ran out.
        assert_eq!(
            super::paid_until_after(date("2026-10-04"), Some(date("2025-01-01"))).unwrap(),
            date("2027-10-04")
        );
        // Renewing before the date: the year runs from the later existing date,
        // so paying early loses nothing.
        assert_eq!(
            super::paid_until_after(date("2026-10-04"), Some(date("2027-06-01"))).unwrap(),
            date("2028-06-01")
        );
        // 29 February lands on 28 February in the common year that follows.
        assert_eq!(
            super::paid_until_after(date("2028-02-29"), None).unwrap(),
            date("2029-02-28")
        );
    }

    #[test]
    fn the_ceiling_is_twenty_four_months_past_the_recorded_day() {
        assert_eq!(
            super::credit_ceiling(date("2026-10-04")).unwrap(),
            date("2028-10-04")
        );
        assert_eq!(
            super::credit_ceiling(date("2028-02-29")).unwrap(),
            date("2030-02-28")
        );
    }

    #[test]
    fn a_year_off_the_end_of_the_calendar_is_none_rather_than_a_panic() {
        assert_eq!(super::anniversary(date("9999-01-01"), 10000), None);
        assert_eq!(super::paid_until_after(date("9999-01-01"), None), None);
        assert_eq!(super::credit_ceiling(date("9998-01-01")), None);
    }

    #[test]
    fn a_received_date_more_than_two_years_ahead_is_outside_the_window() {
        let today = date("2026-11-03");
        assert!(!super::received_beyond_window(date("2028-11-03"), today));
        assert!(super::received_beyond_window(date("2028-11-04"), today));
        assert!(super::received_beyond_window(date("9999-01-01"), today));
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
        assert_eq!(super::pence("20.00").unwrap(), 2000);
        assert_eq!(super::pence("20").unwrap(), 2000);
        assert_eq!(super::pence("0.05").unwrap(), 5);
        assert_eq!(super::pence("19.8").unwrap(), 1980);
        assert!(super::pence("20.001").is_err());
        assert!(super::pence("-20.00").is_err());
        assert!(super::pence("twenty").is_err());
        assert_eq!(super::gbp(2000), "20.00");
        assert_eq!(super::gbp(5), "0.05");
    }
}
