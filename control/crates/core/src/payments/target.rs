//! The one payment block, whichever record holds it.
//!
//! A person's payment lives on `Account.payment`; a body's lives on
//! `GroupRecord.payment`. The fields are nearly the same set, but the records
//! are different shapes, and before this module every transition wrote one or
//! the other by hand: credit, refund, window extension and the card rail each
//! had two paths that could drift. [`PaymentTarget`] is the one place that
//! knows both, so the arithmetic and the state change are written once.
//!
//! The ledger is unchanged and still keyed by the payment token (ADR 0009);
//! this type never names a username in a ledger line.

use crate::account::state::{Standing, WindowState};
use crate::store::{
    Account, ApplicationRef, GroupRecord, Monero, Payment, Store, StripeBilling, Window,
};
use crate::{util, Error};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// One record's payment block, borrowed for the length of a transition.
pub enum PaymentTarget<'a> {
    Account(&'a mut Account),
    Group(&'a mut GroupRecord),
}

impl<'a> PaymentTarget<'a> {
    pub fn account(account: &'a mut Account) -> Self {
        // A record written before the payment block existed keeps its token,
        // window and dates in the flat fields. Fold them in before anything
        // reads the block, or a credit would journal, fail to find a block to
        // set, and save a record with the token erased while the ledger holds
        // the money.
        if account.payment.is_none() {
            account.payment = account.payment_state();
        }
        PaymentTarget::Account(account)
    }

    pub fn group(group: &'a mut GroupRecord) -> Self {
        PaymentTarget::Group(group)
    }

    pub fn is_group(&self) -> bool {
        matches!(self, PaymentTarget::Group(_))
    }

    /// The payment token the ledger row is keyed by.
    pub fn token(&self) -> Option<&str> {
        match self {
            PaymentTarget::Account(account) => account.payment.as_ref()?.token_ref.as_deref(),
            PaymentTarget::Group(group) => group.payment.token_ref.as_deref(),
        }
    }

    pub fn paid_until(&self) -> Option<&str> {
        match self {
            PaymentTarget::Account(account) => account.payment.as_ref()?.paid_until.as_deref(),
            PaymentTarget::Group(group) => group.payment.paid_until.as_deref(),
        }
    }

    pub fn window(&self) -> Option<&Window> {
        match self {
            PaymentTarget::Account(account) => account.payment.as_ref()?.window.as_ref(),
            PaymentTarget::Group(group) => group.payment.window.as_ref(),
        }
    }

    pub fn window_state(&self) -> Option<WindowState> {
        self.window().map(|window| window.state)
    }

    pub fn balance(&self) -> Result<Option<&str>, Error> {
        match self {
            PaymentTarget::Account(account) => Ok(account
                .payment
                .as_ref()
                .and_then(|payment| payment.balance_gbp.as_deref())),
            // A group's year is one payment and it holds no balance.
            PaymentTarget::Group(_) => Ok(None),
        }
    }

    pub fn stripe(&self) -> StripeBilling {
        match self {
            PaymentTarget::Account(account) => account
                .payment
                .as_ref()
                .map(|payment| payment.stripe.clone())
                .unwrap_or_default(),
            PaymentTarget::Group(group) => group.payment.stripe.clone(),
        }
    }

    pub fn monero(&self) -> Option<&Monero> {
        match self {
            PaymentTarget::Account(account) => account.payment.as_ref()?.monero.as_ref(),
            PaymentTarget::Group(group) => group.payment.monero.as_ref(),
        }
    }

    /// The block as an account's, for the page, the console and the application
    /// copy. A group has no token-issue date, no held balance and no
    /// application reference.
    pub fn block(&self) -> Option<Payment> {
        match self {
            PaymentTarget::Account(account) => account.payment.clone(),
            PaymentTarget::Group(group) => Some(group.payment.as_payment()),
        }
    }

    /// The name the console prints: a person's username or a body's domain.
    pub fn label(&self) -> &str {
        match self {
            PaymentTarget::Account(account) => &account.username,
            PaymentTarget::Group(group) => &group.domain,
        }
    }

    /// The account a notice is recorded against, and the application a
    /// settlement names. A group's is its site owner, with the domain beside it.
    pub fn application(&self) -> ApplicationRef {
        match self {
            PaymentTarget::Account(account) => ApplicationRef::account(account.username.clone()),
            PaymentTarget::Group(group) => {
                ApplicationRef::group(group.site_owner.clone(), group.domain.clone())
            }
        }
    }

    pub fn set_balance(&mut self, balance: Option<String>) {
        if let PaymentTarget::Account(account) = self {
            if let Some(payment) = account.payment.as_mut() {
                payment.balance_gbp = balance;
            }
        }
    }

    /// The group record, when this is a body's target. The mailbox restore loop
    /// needs the list of mailboxes the group's one payment brings back.
    pub fn group_ref(&self) -> Option<&GroupRecord> {
        match self {
            PaymentTarget::Group(group) => Some(group),
            PaymentTarget::Account(_) => None,
        }
    }

    /// Write the changed block back under the record's own lock. `restore`
    /// marks a paid account that was lapsed when the pass read it; the update
    /// repeats the check under the lock, because a console suspension can land
    /// between the two.
    pub async fn save(&self, store: &Store, restore: bool) -> Result<(), Error> {
        match self {
            PaymentTarget::Account(account) => {
                let username = account.username.clone();
                let payment = account.payment.clone();
                // A closure is the one standing this write owns. A credit or an
                // excess refund leaves the state alone, so a console suspension
                // that landed between the read and the lock is not undone.
                let closing = (account.state == Standing::Closing).then(|| {
                    (
                        account.closing_until.clone(),
                        account.closing_prior_state,
                        account.closing_refunded,
                    )
                });
                store
                    .update_account(&username, move |current| {
                        let Some(account) = current.as_mut() else {
                            return Ok::<(), Error>(());
                        };
                        if let Some(payment) = payment.clone() {
                            account.payment = Some(payment);
                        }
                        if let Some((until, prior, refunded)) = closing.clone() {
                            account.state = Standing::Closing;
                            account.closing_until = until;
                            account.closing_prior_state = prior;
                            account.closing_refunded = refunded;
                        }
                        if restore && account.state == Standing::Lapsed {
                            account.restore_after_payment();
                        }
                        Ok::<(), Error>(())
                    })
                    .await
            }
            PaymentTarget::Group(group) => {
                let domain = group.domain.clone();
                let payment = group.payment.clone();
                let grace = group.grace_until.clone();
                store
                    .update_group(&domain, move |current| {
                        if let Some(group) = current.as_mut() {
                            group.payment = payment.clone();
                            group.grace_until = grace.clone();
                        }
                        Ok::<(), Error>(())
                    })
                    .await
            }
        }
    }

    pub fn set_rail(&mut self, rail: &str) {
        match self {
            PaymentTarget::Account(account) => {
                if let Some(payment) = account.payment.as_mut() {
                    payment.rail = Some(rail.to_string());
                }
            }
            PaymentTarget::Group(group) => group.payment.rail = rail.to_string(),
        }
    }

    /// The one extension an open window is given: fourteen days, once. The
    /// counter, the close date and the paid date are read together, so an
    /// account and a body cannot disagree about when the courtesy is spent.
    pub fn extend_window(&mut self, days: i64) -> Result<String, Error> {
        let paid_until = self.paid_until().map(str::to_string);
        let window = match self {
            PaymentTarget::Account(account) => account
                .payment
                .as_mut()
                .and_then(|payment| payment.window.as_mut()),
            PaymentTarget::Group(group) => group.payment.window.as_mut(),
        }
        .ok_or_else(|| Error::Failed("the payment has no window to extend".to_string()))?;
        if paid_until.is_some() || window.state != WindowState::Open {
            return Err(Error::Failed(
                "the payment window is not open, so it has nothing to extend".to_string(),
            ));
        }
        if window.extensions >= 1 {
            return Err(Error::Failed(
                "the payment window has already been extended once; a second extension is refused"
                    .to_string(),
            ));
        }
        let closes = OffsetDateTime::parse(&window.closes_at, &Rfc3339)
            .map_err(|_| Error::Failed("the window's close date cannot be read".to_string()))?;
        let moved = closes + Duration::days(days);
        window.closes_at = moved
            .replace_nanosecond(0)
            .unwrap_or(moved)
            .format(&Rfc3339)
            .map_err(|_| Error::Failed("the window's close date cannot be written".to_string()))?;
        window.extensions += 1;
        Ok(window.closes_at.clone())
    }

    /// A credit's date, and the window it closes: setting the date is also what
    /// hides the token, so the two are written together.
    pub fn set_paid_until(&mut self, date: String) -> Result<(), Error> {
        match self {
            PaymentTarget::Account(account) => {
                let payment = account
                    .payment
                    .as_mut()
                    .ok_or_else(|| Error::Failed("the account has no payment block".to_string()))?;
                payment.paid_until = Some(date);
                if let Some(window) = payment.window.as_mut() {
                    window.state = WindowState::Paid;
                }
            }
            PaymentTarget::Group(group) => {
                group.payment.paid_until = Some(date);
                if let Some(window) = group.payment.window.as_mut() {
                    window.state = WindowState::Paid;
                }
            }
        }
        Ok(())
    }

    /// An excess refund's balance, or an error when the record has none to
    /// spend. A group's excess never took time, so it has no balance field.
    pub fn spend_balance(&mut self, amount: i64) -> Result<Option<String>, Error> {
        let PaymentTarget::Account(account) = self else {
            return Ok(None);
        };
        let payment = account
            .payment
            .as_mut()
            .ok_or_else(|| Error::Failed("the account has no payment block".to_string()))?;
        let balance = match payment.balance_gbp.as_deref() {
            Some(text) => util::pence(text)
                .map_err(|e| Error::Failed(format!("the account's balance cannot be read: {e}")))?,
            None => 0,
        };
        let left = (balance - amount).max(0);
        payment.balance_gbp = (left > 0).then(|| util::gbp(left));
        Ok(payment.balance_gbp.clone())
    }

    /// Whether the block's balance is already the one an interrupted refund
    /// recorded. That is the witness a retry reads before subtracting again.
    pub fn balance_is(&self, after: Option<&str>) -> bool {
        self.balance().ok().flatten() == after
    }

    /// Close an account for the seven days a cancellation refund gives. A group
    /// has no closing state; ending a body is `group remove`.
    pub fn enter_closing(&mut self, until: String, refund_closed: bool) -> Result<(), Error> {
        let PaymentTarget::Account(account) = self else {
            return Err(Error::Failed(
                "a group has no closing state, so --close cannot cancel one; end the group with `kyriakon-admin group remove <domain>`"
                    .to_string(),
            ));
        };
        let prior = match account.lifecycle() {
            crate::account::state::AccountState::Closing { prior_state, .. } => prior_state,
            _ => account.state,
        };
        account.enter_closing(prior, until);
        account.closing_refunded = refund_closed;
        Ok(())
    }

    /// Clear the grace and notice stop a payment ends. The standing change is
    /// [`Account::restore_after_payment`], which a closing or suspended account
    /// keeps.
    pub fn clear_grace(&mut self) {
        match self {
            PaymentTarget::Account(account) => {
                account.grace_until = None;
                account.notice_stopped = None;
            }
            PaymentTarget::Group(group) => group.grace_until = None,
        }
    }

    /// Record that the card subscription stops at the period's end, after the
    /// rail has accepted the cancellation.
    pub fn cancel_card(&mut self) {
        match self {
            PaymentTarget::Account(account) => {
                if let Some(payment) = account.payment.as_mut() {
                    payment.stripe.cancel_at_period_end = true;
                }
            }
            PaymentTarget::Group(group) => group.payment.stripe.cancel_at_period_end = true,
        }
    }

    /// Whether a payment should restore the account: it lapsed, and the restore
    /// script is the transition's to run before this becomes active.
    pub fn is_lapsed(&self) -> bool {
        match self {
            PaymentTarget::Account(account) => account.state == Standing::Lapsed,
            PaymentTarget::Group(_) => false,
        }
    }

    /// Whether the record is in ordinary service. A payment clears the grace
    /// clock only then: a suspended or closing account keeps the clock the other
    /// decision started.
    pub fn is_active(&self) -> bool {
        match self {
            PaymentTarget::Account(account) => account.state == Standing::Active,
            PaymentTarget::Group(_) => true,
        }
    }

    pub fn restore_after_payment(&mut self) {
        if let PaymentTarget::Account(account) = self {
            account.restore_after_payment();
        }
    }

    /// Record a Monero subaddress, one per person or body. The same address
    /// again is a replay; a different one is refused rather than rotated,
    /// because the first may already have been sent a payment.
    pub fn set_monero_address(&mut self, address: &str) -> Result<bool, Error> {
        let block = match self {
            PaymentTarget::Account(account) => account
                .payment
                .as_mut()
                .ok_or_else(|| Error::Failed("the account has no payment block".to_string()))?
                .monero
                .get_or_insert_with(Default::default),
            PaymentTarget::Group(group) => {
                group.payment.monero.get_or_insert_with(Default::default)
            }
        };
        match block.address.as_deref() {
            Some(existing) if existing == address => Ok(false),
            Some(existing) => Err(Error::Failed(format!(
                "the Monero subaddress is already {existing}; a subaddress is never rotated or reused"
            ))),
            None => {
                block.address = Some(address.to_string());
                Ok(true)
            }
        }
    }

    pub fn rail(&self) -> Result<String, Error> {
        match self {
            PaymentTarget::Account(account) => Ok(account.rail.clone()),
            PaymentTarget::Group(group) => Ok(group.payment.rail.clone()),
        }
    }

    /// Write the block into the status page's own record, so the handler can
    /// show a renewal it cannot read the root-owned record for.
    pub async fn sync_application_copy(
        &self,
        store: &Store,
        application_token: &str,
    ) -> Result<(), Error> {
        match self {
            PaymentTarget::Account(account) => {
                let Some(payment) = account.payment.as_ref() else {
                    return Ok(());
                };
                store
                    .write_payment_copy(&account.username, payment)
                    .await
                    .map_err(Error::from)
            }
            PaymentTarget::Group(group) => store
                .write_filed_payment(application_token, &group.payment.as_payment())
                .await
                .map_err(Error::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::state::Standing;

    fn group(paid_until: Option<&str>) -> GroupRecord {
        GroupRecord {
            version: 1,
            domain: "parish.example".to_string(),
            name: "Parish".to_string(),
            kind: "parish".to_string(),
            payment: crate::store::GroupPayment {
                rail: "cash".to_string(),
                paid_until: paid_until.map(str::to_string),
                token_ref: Some("KYR-AAAA-BBBB-CCCC".to_string()),
                ..Default::default()
            },
            accounts: vec!["secretary".to_string()],
            site_owner: "secretary".to_string(),
            space_used: None,
            grace_until: None,
            created_at: String::new(),
        }
    }

    /// A group's block reads as an account's for the page, with the fields a
    /// group really has and none of the ones it does not.
    #[test]
    fn a_group_block_reads_as_a_payment() {
        let mut group = group(Some("2027-10-01"));
        let target = PaymentTarget::group(&mut group);
        let payment = target.block().unwrap();
        assert_eq!(payment.paid_until.as_deref(), Some("2027-10-01"));
        assert_eq!(payment.rail.as_deref(), Some("cash"));
        assert!(payment.balance_gbp.is_none());
        assert!(payment.monero.is_none());
    }

    /// The state a payment changes is the same on both records.
    #[test]
    fn a_credit_sets_the_date_and_marks_the_window_paid_on_both() {
        let mut group = group(None);
        group.payment.window = Some(Window {
            opened_at: "2026-10-01T00:00:00Z".to_string(),
            closes_at: "2026-10-15T00:00:00Z".to_string(),
            state: WindowState::Open,
            extensions: 0,
        });
        let mut target = PaymentTarget::group(&mut group);
        target.set_paid_until("2027-10-01".to_string()).unwrap();
        assert_eq!(target.window_state(), Some(WindowState::Paid));
        assert_eq!(target.paid_until(), Some("2027-10-01"));
    }

    /// A group has no balance to spend, and no closing state to enter.
    #[test]
    fn a_group_refuses_the_account_only_moves() {
        let mut group = group(None);
        let mut target = PaymentTarget::group(&mut group);
        assert_eq!(target.spend_balance(500).unwrap(), None);
        assert!(target
            .enter_closing("2026-12-01".to_string(), false)
            .is_err());
    }

    /// The Monero address is written where the block lives, and a second
    /// different address is refused rather than rotated.
    #[test]
    fn a_monero_address_is_permanent_on_the_block() {
        let mut group = group(None);
        let mut target = PaymentTarget::group(&mut group);
        assert!(target.set_monero_address("8example").unwrap());
        assert!(!target.set_monero_address("8example").unwrap());
        assert!(target.set_monero_address("8other").is_err());
        assert_eq!(
            target.monero().unwrap().address.as_deref(),
            Some("8example")
        );
    }

    /// A record whose token and dates live only in the flat fields is folded
    /// into a block when the target is made, so the write cannot erase them.
    #[test]
    fn a_flat_payment_record_is_folded_into_a_block() {
        let mut account: Account = serde_json::from_value(serde_json::json!({
            "version": 1,
            "username": "secretary",
            "state": "active",
            "decision": "approve",
            "decided_at": "2026-10-01T09:00:00Z",
            "rail": "cash",
            "no_charge": false,
            "created_at": "2026-10-01T09:00:00Z",
            "token_ref": "KYR-AAAA-BBBB-CCCC",
            "paid_until": "2027-10-01",
            "window": {
                "opened_at": "2026-10-01T00:00:00Z",
                "closes_at": "2026-10-15T00:00:00Z",
                "state": "open",
                "extensions": 0
            }
        }))
        .unwrap();
        let _target = PaymentTarget::account(&mut account);
        let payment = account.payment.expect("the flat fields became a block");
        assert_eq!(payment.token_ref.as_deref(), Some("KYR-AAAA-BBBB-CCCC"));
        assert_eq!(payment.paid_until.as_deref(), Some("2027-10-01"));
        assert!(payment.window.is_some());
    }

    #[test]
    fn an_account_closure_keeps_its_prior_state() {
        let mut account: Account = serde_json::from_value(serde_json::json!({
            "version": 1,
            "username": "secretary",
            "state": "lapsed",
            "decision": "approve",
            "decided_at": "2026-10-01T09:00:00Z",
            "rail": "cash",
            "no_charge": false,
            "created_at": "2026-10-01T09:00:00Z",
            "payment": { "paid_until": null }
        }))
        .unwrap();
        let mut target = PaymentTarget::account(&mut account);
        target
            .enter_closing("2026-12-01".to_string(), false)
            .unwrap();
        assert_eq!(
            account.lifecycle(),
            crate::account::state::AccountState::Closing {
                prior_state: Standing::Lapsed,
                refund_closed: false,
                until: "2026-12-01".to_string(),
            }
        );
    }
}
