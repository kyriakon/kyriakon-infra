//! The account's standing and the transitions between the states.
//!
//! `account.json` keeps the one word it always wrote: `active`, `lapsed`,
//! `suspended` or `closing`. [`Standing`] is that word as a type, so a caller
//! cannot invent a fifth one. A closing record also carries when the seven days
//! end, the state it will return to if the member cancels, and whether a refund
//! paid the closure out; [`AccountState`] is those fields as one value, built
//! from the record by [`Account::lifecycle`].
//!
//! The transitions live here, not in the drain: cancelling a closure restores
//! the state the record held before it and refuses a refunded closure; a resume
//! reports the state it actually leaves, active or lapsed. A caller that writes
//! the fields itself can skip either rule, so it does not get to.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::Error;
use crate::store::Account;
use crate::util;

/// The account's own word, as the record writes it. `closing` is the one
/// standing with fields of its own, and they sit beside it on the record.
/// `held` is an approval without the immediate-supply request: the record
/// exists, nothing has been made on the box yet, and the hold date on the
/// account says when the drain may supply it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    Held,
    Active,
    Lapsed,
    Suspended,
    Closing,
}

impl Standing {
    pub fn word(self) -> &'static str {
        match self {
            Standing::Held => "held",
            Standing::Active => "active",
            Standing::Lapsed => "lapsed",
            Standing::Suspended => "suspended",
            Standing::Closing => "closing",
        }
    }
}

impl fmt::Display for Standing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.word())
    }
}

/// The window's own state, `open`, `closed` or `paid`, as a type. The wire
/// words are unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowState {
    Open,
    Closed,
    Paid,
}

impl WindowState {
    pub fn word(self) -> &'static str {
        match self {
            WindowState::Open => "open",
            WindowState::Closed => "closed",
            WindowState::Paid => "paid",
        }
    }
}

impl fmt::Display for WindowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.word())
    }
}

/// One account standing with the closing details beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountState {
    Held,
    Active,
    Lapsed,
    Suspended,
    Closing {
        /// The state the closure will return to if the member cancels.
        prior_state: Standing,
        /// The closure came from a `refund --close`; the money and the year
        /// went back, so cancelling would restore both without a payment.
        refund_closed: bool,
        /// The last day of the seven-day window, `YYYY-MM-DD`.
        until: String,
    },
}

impl AccountState {
    pub fn word(&self) -> &'static str {
        match self {
            AccountState::Held => "held",
            AccountState::Active => "active",
            AccountState::Lapsed => "lapsed",
            AccountState::Suspended => "suspended",
            AccountState::Closing { .. } => "closing",
        }
    }

    /// Cancel a closure: the recorded prior state comes back, never a flat
    /// `active`. A closure paid out by a refund is refused, because the refund
    /// line and the cancelled closure together would leave the member with the
    /// money and the year.
    pub fn cancel_close(&self) -> Result<Standing, Error> {
        let AccountState::Closing {
            prior_state,
            refund_closed,
            until,
        } = self
        else {
            return Err(Error::NotClosing);
        };
        if *refund_closed {
            return Err(Error::ClosureRefunded);
        }
        if util::parse_date(until).is_none() {
            return Err(Error::ClosingDateUnreadable);
        }
        if *prior_state == Standing::Closing {
            return Err(Error::ClosureFromClosure);
        }
        Ok(*prior_state)
    }

    /// Resume a suspension, reporting what the account actually becomes. An
    /// unpaid account stays lapsed; the resume does not undo the payment lapse.
    pub fn resume(&self, payment_lapsed: bool) -> Result<Standing, Error> {
        match self {
            AccountState::Suspended => Ok(if payment_lapsed {
                Standing::Lapsed
            } else {
                Standing::Active
            }),
            _ => Err(Error::NotSuspended),
        }
    }
}

impl Account {
    /// The record's standing with the closing details as one value.
    pub fn lifecycle(&self) -> AccountState {
        match self.state {
            Standing::Held => AccountState::Held,
            Standing::Active => AccountState::Active,
            Standing::Lapsed => AccountState::Lapsed,
            Standing::Suspended => AccountState::Suspended,
            Standing::Closing => AccountState::Closing {
                prior_state: self.closing_prior_state(),
                refund_closed: self.closing_refunded,
                until: self.closing_until.clone().unwrap_or_default(),
            },
        }
    }

    /// The state a closure began from. A record written before the field
    /// existed is read from the facts the record still holds: a suspension
    /// reason, or a payment window that closed with nothing recorded. A window
    /// still open is an active account; a closed one is a lapse. Reading the
    /// facts fails closed, because the fallback can never promote a lapsed
    /// account to active (#892).
    pub fn closing_prior_state(&self) -> Standing {
        if let Some(prior) = self.closing_prior_state {
            return prior;
        }
        if self.suspension_reason.is_some() {
            return Standing::Suspended;
        }
        // A group mailbox has no block of its own, so the record that carried a
        // lapse is the grace date. Without this a closure written by an earlier
        // release would cancel to active and stop the deletion clock.
        if self.payment_state().is_none() && self.grace_until.is_some() {
            return Standing::Lapsed;
        }
        let lapsed = self.payment_state().is_some_and(|payment| {
            payment.paid_until.is_none()
                && payment
                    .window
                    .as_ref()
                    .is_some_and(|window| window.state == WindowState::Closed)
        });
        if lapsed {
            Standing::Lapsed
        } else {
            Standing::Active
        }
    }

    /// Enter `closing`: the prior state, the last day and whether a refund paid
    /// the closure out are written together so a cancellation cannot guess one
    /// of them.
    pub fn enter_closing(&mut self, prior_state: Standing, until: String) {
        self.state = Standing::Closing;
        self.closing_until = Some(until);
        self.closing_prior_state = Some(prior_state);
        self.closing_refunded = false;
    }

    /// Cancel a closure, restoring the prior state. The group and application
    /// records are the transition's, not the state machine's.
    pub fn cancel_close(&mut self) -> Result<Standing, Error> {
        let prior = self.lifecycle().cancel_close()?;
        self.state = prior;
        self.closing_until = None;
        self.closing_prior_state = None;
        self.closing_refunded = false;
        Ok(prior)
    }

    /// Suspend the account, recording the words the member reads. The access
    /// paths are the transition's, before this write.
    pub fn suspend(&mut self, reason: &str) {
        self.state = Standing::Suspended;
        self.suspension_reason = Some(reason.to_string());
    }

    /// Resume a suspension: the returned standing is what the record now says.
    /// An unpaid account stays lapsed rather than regaining access with a
    /// closed window, so resolving a suspension does not undo the lapse.
    pub fn resume(&mut self, payment_lapsed: bool) -> Result<Standing, Error> {
        let standing = self.lifecycle().resume(payment_lapsed)?;
        self.state = standing;
        self.suspension_reason = None;
        if standing == Standing::Active {
            self.grace_until = None;
            self.notice_stopped = None;
        }
        Ok(standing)
    }

    /// Lapse the account and start the grace the record carries.
    pub fn lapse(&mut self, grace_until: String) {
        self.state = Standing::Lapsed;
        self.grace_until = Some(grace_until);
    }

    /// A payment after a lapse brings the account back. A closing or suspended
    /// account keeps its own state: the payment is recorded, and the decision
    /// that put it there is not the payment's to overturn.
    pub fn restore_after_payment(&mut self) {
        if self.state == Standing::Lapsed {
            self.state = Standing::Active;
            self.grace_until = None;
            self.notice_stopped = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every state reads its existing wire word and writes it back, and a
    /// closing record keeps the fields the closure needs.
    #[test]
    fn every_record_state_reads_and_writes_the_same_wire_word() {
        let records = [
            ("held", None, None, None, AccountState::Held),
            ("active", None, None, None, AccountState::Active),
            ("lapsed", None, None, None, AccountState::Lapsed),
            ("suspended", None, None, None, AccountState::Suspended),
            (
                "closing",
                Some("2026-12-01"),
                Some("lapsed"),
                Some(true),
                AccountState::Closing {
                    prior_state: Standing::Lapsed,
                    refund_closed: true,
                    until: "2026-12-01".to_string(),
                },
            ),
        ];
        for (word, closing_until, prior, refunded, expected) in records {
            let mut value = serde_json::json!({
                "version": 1,
                "username": "secretary",
                "state": word,
                "decision": "approve",
                "decided_at": "2026-10-01T09:00:00Z",
                "rail": "no_charge",
                "no_charge": true,
                "created_at": "2026-10-01T09:00:00Z",
            });
            if let Some(until) = closing_until {
                value["closing_until"] = serde_json::json!(until);
            }
            if let Some(prior) = prior {
                value["closing_prior_state"] = serde_json::json!(prior);
            }
            if let Some(refunded) = refunded {
                value["closing_refunded"] = serde_json::json!(refunded);
            }
            let account: Account = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(account.lifecycle(), expected, "{word}");
            let written = serde_json::to_value(&account).unwrap();
            assert_eq!(written["state"], value["state"], "the wire word moved");
        }
    }

    /// A closure remembers the standing it came from, and cancelling restores
    /// it rather than promoting a lapse to active.
    #[test]
    fn a_closure_returns_to_the_state_it_came_from() {
        assert_eq!(
            AccountState::Closing {
                prior_state: Standing::Lapsed,
                refund_closed: false,
                until: "2026-12-01".to_string(),
            }
            .cancel_close()
            .unwrap(),
            Standing::Lapsed
        );
        assert_eq!(
            AccountState::Closing {
                prior_state: Standing::Active,
                refund_closed: false,
                until: "2026-12-01".to_string(),
            }
            .cancel_close()
            .unwrap(),
            Standing::Active
        );
    }

    /// A refunded closure cannot be cancelled, and neither can a record whose
    /// closing date cannot be read.
    #[test]
    fn an_illegal_cancellation_is_refused() {
        let refunded = AccountState::Closing {
            prior_state: Standing::Active,
            refund_closed: true,
            until: "2026-12-01".to_string(),
        };
        assert!(refunded.cancel_close().is_err());
        let broken = AccountState::Closing {
            prior_state: Standing::Active,
            refund_closed: false,
            until: "not a date".to_string(),
        };
        assert!(broken.cancel_close().is_err());
        assert!(AccountState::Active.cancel_close().is_err());
        assert!(AccountState::Lapsed.cancel_close().is_err());
    }

    /// A suspension takes both published lanes down in the model the page and
    /// the capsule read, and the upload keys do not put them back.
    #[test]
    fn a_suspended_account_serves_nothing() {
        let mut account: Account = serde_json::from_value(serde_json::json!({
            "version": 1,
            "username": "alice",
            "state": "active",
            "decision": "approve",
            "decided_at": "2026-10-01T09:00:00Z",
            "rail": "no_charge",
            "no_charge": true,
            "created_at": "2026-10-01T09:00:00Z",
            "site_served": true,
            "capsule_served": true,
            "upload_keys": [{ "fingerprint": "AAAA", "added_at": "2026-10-01" }]
        }))
        .unwrap();
        assert_eq!(account.serving(), (true, true));
        account.suspend("test");
        assert_eq!(account.serving(), (false, false));
        account.resume(false).unwrap();
        assert_eq!(account.serving(), (true, true));
        // A held account has no box account and no vhost, so neither lane is
        // served even though the application carried an upload key.
        account.state = Standing::Held;
        assert_eq!(account.serving(), (false, false));
    }

    /// An old closure of a group mailbox has no payment block; the grace date
    /// is the lapse it recorded, so cancelling returns to lapsed rather than
    /// restoring access and stopping the deletion clock.
    #[test]
    fn an_old_group_mailbox_closure_returns_to_lapsed() {
        let mut account: Account = serde_json::from_value(serde_json::json!({
            "version": 1,
            "username": "parish-secretary",
            "state": "closing",
            "decision": "approve",
            "decided_at": "2026-10-01T09:00:00Z",
            "rail": "cash",
            "no_charge": false,
            "created_at": "2026-10-01T09:00:00Z",
            "group": "parish.example",
            "closing_until": "2026-12-01",
            "grace_until": "2027-01-01",
        }))
        .unwrap();
        assert_eq!(
            account.closing_prior_state(),
            Standing::Lapsed,
            "a group mailbox with a grace date read as active"
        );
        assert_eq!(account.cancel_close().unwrap(), Standing::Lapsed);
        assert_eq!(account.state, Standing::Lapsed);
    }

    /// A resume reports the state the account is actually left in.
    #[test]
    fn a_resume_reports_active_or_lapsed() {
        assert_eq!(
            AccountState::Suspended.resume(false).unwrap(),
            Standing::Active
        );
        assert_eq!(
            AccountState::Suspended.resume(true).unwrap(),
            Standing::Lapsed
        );
        assert!(AccountState::Active.resume(false).is_err());
        assert!(AccountState::Closing {
            prior_state: Standing::Active,
            refund_closed: false,
            until: "2026-12-01".to_string(),
        }
        .resume(false)
        .is_err());
    }
}
