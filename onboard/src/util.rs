//! The times the store's own records carry: when an application was filed, and
//! when its status link stops answering. One module, so the timestamp crate can
//! move without touching anything else.

use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

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
        assert!(!super::link_answers("last Tuesday", at("2026-10-01T09:00:00Z")));
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
}
