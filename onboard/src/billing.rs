//! The date arithmetic the paid rails share.
//!
//! A paid-until date is extended by one calendar year, counted from the later of
//! the payment's own receipt and the date the account already holds. A calendar
//! year and not 365 days: a member who pays in March pays again in March. The
//! one edge is 29 February, which has no 29 February to land on in a common
//! year; it becomes 28 February, so the date never moves earlier by more than a
//! day and never skips a year.
//!
//! `util::paid_until_after` is the arithmetic itself, shared with the manual
//! credit path; this is the stamp-shaped front to it, because a Stripe event
//! carries an RFC 3339 timestamp while a store record carries a date. Both
//! rails write and read the same `YYYY-MM-DD` shape, so a member who pays by
//! card and then by post never has one rail refuse the other's date.

use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime};

use crate::util;

/// The date a payment takes access to: one calendar year after the later of
/// `received` and `before`, as `YYYY-MM-DD`. Each may be a store date or an
/// RFC 3339 stamp, which is how a Stripe event's timestamp meets a record's
/// date. `before` is `None` for an account that has not been paid yet.
pub fn extend_paid_until(received: &str, before: Option<&str>) -> Result<String, String> {
    let received = day(received)?;
    let before = before.map(day).transpose()?;
    Ok(util::date_string(util::paid_until_after(received, before)))
}

/// The day a stamp names: a store date, or the date part of an RFC 3339 stamp.
/// Anything else is an error rather than a guess.
fn day(stamp: &str) -> Result<Date, String> {
    util::parse_date(stamp)
        .or_else(|| {
            OffsetDateTime::parse(stamp, &Rfc3339)
                .ok()
                .map(|t| t.date())
        })
        .ok_or_else(|| format!("the date {stamp:?} is not YYYY-MM-DD or RFC 3339"))
}

#[cfg(test)]
mod tests {
    use super::extend_paid_until;

    #[test]
    fn a_first_payment_takes_one_year() {
        assert_eq!(
            extend_paid_until("2026-10-31T12:00:00Z", None).unwrap(),
            "2027-10-31"
        );
    }

    #[test]
    fn a_renewal_extends_the_date_it_finds_and_not_today() {
        assert_eq!(
            extend_paid_until("2027-09-01T00:00:00Z", Some("2027-10-04")).unwrap(),
            "2028-10-04"
        );
    }

    #[test]
    fn a_late_payment_counts_from_the_day_it_arrived() {
        assert_eq!(
            extend_paid_until("2027-11-02T00:00:00Z", Some("2027-10-04T00:00:00Z")).unwrap(),
            "2028-11-02"
        );
    }

    #[test]
    fn a_leap_day_lands_on_the_twenty_eighth() {
        assert_eq!(
            extend_paid_until("2028-02-29T09:30:00Z", None).unwrap(),
            "2029-02-28"
        );
        // And the leap day is still the later of the two.
        assert_eq!(
            extend_paid_until("2027-01-01T00:00:00Z", Some("2028-02-29T00:00:00Z")).unwrap(),
            "2029-02-28"
        );
    }

    #[test]
    fn a_date_that_cannot_be_read_is_an_error_not_a_guess() {
        assert!(extend_paid_until("last Tuesday", None).is_err());
        assert!(extend_paid_until("2026-10-31T00:00:00Z", Some("soon")).is_err());
    }
}
