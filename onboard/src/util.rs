//! The filing time. One function, so the timestamp crate can move without
//! touching anything else.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

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

#[cfg(test)]
mod tests {
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
