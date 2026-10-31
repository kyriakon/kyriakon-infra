//! The operator's prepaid view: the payment windows still open, which are the
//! ones worth an email before they lapse.
//!
//! `onboardctl prepaid list` is the first command of the weekly pass. It reads
//! the accounts rather than an index beside them, because a window whose
//! account cannot be read must not appear as one closing on a date nobody
//! computed; an unreadable account is named on stderr and left out.

use time::OffsetDateTime;

use crate::store::{Account, Store};
use crate::util;

/// One open window, as the console prints it.
pub struct OpenWindow {
    pub token: String,
    pub username: String,
    pub rail: String,
    /// `YYYY-MM-DD`, the day the window closes.
    pub closes_on: String,
    pub days_left: i64,
}

/// Every account whose payment window is open and still carries a token, sorted
/// by the date it closes and then by username, so two windows closing the same
/// day read in a stable order. A window with no readable close date is left out:
/// a fabricated countdown is worse than a missing row.
pub async fn open_windows(store: &Store, now: OffsetDateTime) -> Result<Vec<OpenWindow>, String> {
    let mut out = Vec::new();
    for username in store.list("accounts").await? {
        let Some(text) = store
            .read_record(&format!("accounts/{username}"), "account.json")
            .await
        else {
            eprintln!(
                "kyriakon-onboard: accounts/{username}/account.json is unreadable, not listed"
            );
            continue;
        };
        let account: Account = match serde_json::from_str(&text) {
            Ok(account) => account,
            Err(e) => {
                eprintln!(
                    "kyriakon-onboard: accounts/{username}/account.json does not parse, not listed: {e}"
                );
                continue;
            }
        };
        let Some(payment) = account.payment_state() else {
            continue;
        };
        let Some(window) = payment.window else {
            continue;
        };
        if window.state != "open" {
            continue;
        }
        let Some(token) = payment.token_ref else {
            continue;
        };
        let Some(days_left) = util::days_left(&window.closes_at, now) else {
            continue;
        };
        out.push(OpenWindow {
            token,
            username,
            rail: payment.rail.unwrap_or_else(|| account.rail.clone()),
            closes_on: window.closes_at[..10.min(window.closes_at.len())].to_string(),
            days_left,
        });
    }
    out.sort_by(|a, b| {
        a.closes_on
            .cmp(&b.closes_on)
            .then_with(|| a.username.cmp(&b.username))
    });
    Ok(out)
}

/// The rows `--expiring N` keeps: the windows closing within `N` days. A
/// window that closed earlier today and has not been swept is kept too, because
/// the operator's pass is what decides whether it lapsed for a reason.
pub fn closes_within(days_left: i64, expiring: Option<i64>) -> bool {
    expiring.is_none_or(|days| days_left <= days)
}

#[cfg(test)]
mod tests {
    use super::closes_within;

    #[test]
    fn expiring_narrows_to_the_windows_closing_within_n_days() {
        // No --expiring is every open window, including one already past its
        // close date that a sweep has not reached.
        assert!(closes_within(-1, None));
        assert!(closes_within(14, None));
        // The bound is inclusive: "within three days" keeps the third day.
        assert!(closes_within(3, Some(3)));
        assert!(closes_within(0, Some(3)));
        assert!(closes_within(-1, Some(3)));
        assert!(!closes_within(4, Some(3)));
    }
}
