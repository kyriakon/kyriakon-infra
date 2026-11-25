//! The payments area's error: one variant per failure state, the fields the
//! sentence needs, and the cause kept for `source()`.
//!
//! The five submodules share this one enum because they answer to one caller:
//! the money transitions and the console treat a refused credit, refund or
//! quote alike. The variant names the state, not the module, and `Display`
//! composes the operator sentence here rather than at the site.
//!
//! The outcomes stay separate: [`super::ledger::Settlement`] is what a
//! settlement found, not a failure, and is untouched by this enum.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;

use crate::store;
use crate::util;

#[derive(Debug)]
pub enum Error {
    /// A store read or write failed.
    Store(store::Error),

    // ---- the paid-until arithmetic ----
    /// The year after a date has no date in the calendar.
    YearAfterNone { date: String },
    /// A stamp is neither a store date nor RFC 3339.
    DateNotIsoOrRfc3339 { stamp: String },

    // ---- the ledger ----
    /// A ledger line could not be encoded.
    EncodeLedger { source: serde_json::Error },
    /// A payment line carries no amount to reverse.
    PaymentLineNoAmount,
    /// A refund line carries no amount to read.
    RefundNoAmount { seq: u64 },
    /// A refund line's amount cannot be read.
    RefundUnreadable { seq: u64, source: util::Error },
    /// A ledger line did not parse.
    ParseLine {
        path: &'static str,
        line: usize,
        source: serde_json::Error,
    },
    /// The named ledger sequence belongs to another token.
    ForeignToken { seq: u64 },
    /// The named ledger sequence is not a refund.
    NotRefund { seq: u64, kind: String },
    /// The refund line chosen for settlement did not parse as a record.
    RefundLineNotParsed { source: serde_json::Error },

    // ---- the card rail ----
    /// No card payment link is configured.
    StripeLinkUnconfigured,

    // ---- the payment block ----
    /// The target has no window to extend.
    NoWindow,
    /// The window is not open.
    WindowNotOpen,
    /// The window has already had its one extension.
    AlreadyExtended,
    /// The window's close date cannot be read.
    WindowCloseUnreadable,
    /// The window's close date cannot be written.
    WindowCloseUnwritable,
    /// The account record carries no payment block.
    NoPaymentBlock,
    /// The account's balance cannot be read.
    BalanceUnreadable { source: util::Error },
    /// A group has no closing state to cancel.
    GroupCannotClose,
    /// The Monero subaddress is already set to another value.
    AddressAlready { existing: String },

    // ---- the rate and its quote ----
    /// A rate is not a positive decimal amount.
    RateNotPositive { rate: String },
    /// A rate carries more than twelve decimal places.
    RateTooManyDecimals,
    /// The price and rate overflow the quote.
    QuoteOverflow,
    /// The rate fetch could not be run.
    RateFetchRun { path: PathBuf, source: io::Error },
    /// The rate fetch task did not finish.
    RateFetchDidNotFinish { source: tokio::task::JoinError },
    /// The rate fetch ran and failed.
    RateFetchExited {
        program: String,
        endpoint: String,
        status: ExitStatus,
        stderr: String,
    },
    /// The rate answer did not parse.
    ParseRateAnswer { source: serde_json::Error },
    /// The rate answer carries no `monero.gbp` price.
    NoMoneroPrice { endpoint: String },
    /// The rate answer's price is not a decimal.
    InvalidRate { endpoint: String, rate: String },
    /// The rate cache's directory could not be made.
    CreateRatesDir { path: PathBuf, source: io::Error },
    /// The rate cache could not be encoded.
    EncodeRate { source: serde_json::Error },
    /// The rate cache could not be written.
    WriteRate { path: String, source: io::Error },
    /// The rate cache could not be renamed into place.
    RenameRate { path: String, source: io::Error },
    /// The attempt stamp's directory could not be made.
    CreateAttemptDir { path: PathBuf, source: io::Error },
    /// The attempt stamp could not be written.
    WriteAttempt { path: String, source: io::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Store(error) => error.fmt(f),
            Error::YearAfterNone { date } => {
                write!(f, "the year after {date} has no date in the calendar")
            }
            Error::DateNotIsoOrRfc3339 { stamp } => {
                write!(f, "the date {stamp:?} is not YYYY-MM-DD or RFC 3339")
            }
            Error::EncodeLedger { source } => {
                write!(f, "cannot encode the ledger: {source}")
            }
            Error::PaymentLineNoAmount => f.write_str("a payment line carries no amount"),
            Error::RefundNoAmount { seq } => {
                write!(f, "the refund at ledger seq {seq} has no amount")
            }
            Error::RefundUnreadable { seq, source } => {
                write!(f, "the refund at ledger seq {seq} cannot be read: {source}")
            }
            Error::ParseLine { path, line, source } => {
                write!(f, "{path}: line {line} does not parse: {source}")
            }
            Error::ForeignToken { seq } => {
                write!(f, "ledger seq {seq} belongs to another payment token")
            }
            Error::NotRefund { seq, kind } => {
                write!(f, "ledger seq {seq} is a {kind}, not a refund")
            }
            Error::RefundLineNotParsed { source } => {
                write!(f, "the refund line does not parse: {source}")
            }
            Error::StripeLinkUnconfigured => f.write_str(
                "stripe_payment_link is not configured, so a card approval has no link to send",
            ),
            Error::NoWindow => f.write_str("the payment has no window to extend"),
            Error::WindowNotOpen => {
                f.write_str("the payment window is not open, so it has nothing to extend")
            }
            Error::AlreadyExtended => f.write_str(
                "the payment window has already been extended once; a second extension is refused",
            ),
            Error::WindowCloseUnreadable => f.write_str("the window's close date cannot be read"),
            Error::WindowCloseUnwritable => {
                f.write_str("the window's close date cannot be written")
            }
            Error::NoPaymentBlock => f.write_str("the account has no payment block"),
            Error::BalanceUnreadable { source } => {
                write!(f, "the account's balance cannot be read: {source}")
            }
            Error::GroupCannotClose => f.write_str(
                "a group has no closing state, so --close cannot cancel one; end the group with \
                 `kyriakon-admin group remove <domain>`",
            ),
            Error::AddressAlready { existing } => write!(
                f,
                "the Monero subaddress is already {existing}; a subaddress is never rotated or \
                 reused"
            ),
            Error::RateNotPositive { rate } => {
                write!(f, "the rate {rate:?} is not a positive decimal amount")
            }
            Error::RateTooManyDecimals => f.write_str("the rate has too many decimals"),
            Error::QuoteOverflow => f.write_str("the price and rate overflow the quote"),
            Error::RateFetchRun { path, source } => {
                write!(f, "cannot run the rate fetch {}: {source}", path.display())
            }
            Error::RateFetchDidNotFinish { source } => {
                write!(f, "the rate fetch did not finish: {source}")
            }
            Error::RateFetchExited {
                program,
                endpoint,
                status,
                stderr,
            } => write!(f, "{program} {endpoint} exited {status}: {stderr}"),
            Error::ParseRateAnswer { source } => {
                write!(f, "cannot parse the rate answer: {source}")
            }
            Error::NoMoneroPrice { endpoint } => {
                write!(f, "{endpoint} answered no monero.gbp price")
            }
            Error::InvalidRate { endpoint, rate } => write!(
                f,
                "{endpoint} answered a rate that is not a decimal: {rate}"
            ),
            Error::CreateRatesDir { path, source } => {
                write!(f, "cannot make {}: {source}", path.display())
            }
            Error::EncodeRate { source } => {
                write!(f, "cannot encode the rate: {source}")
            }
            Error::WriteRate { path, source } => {
                write!(f, "cannot write {path}: {source}")
            }
            Error::RenameRate { path, source } => {
                write!(f, "cannot rename {path}: {source}")
            }
            Error::CreateAttemptDir { path, source } => {
                write!(f, "cannot make {}: {source}", path.display())
            }
            Error::WriteAttempt { path, source } => {
                write!(f, "cannot write {path}: {source}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Store(error) => Some(error),
            Error::EncodeLedger { source }
            | Error::ParseLine { source, .. }
            | Error::RefundLineNotParsed { source }
            | Error::ParseRateAnswer { source }
            | Error::EncodeRate { source } => Some(source),
            Error::RefundUnreadable { source, .. } | Error::BalanceUnreadable { source } => {
                Some(source)
            }
            Error::RateFetchRun { source, .. }
            | Error::CreateRatesDir { source, .. }
            | Error::WriteRate { source, .. }
            | Error::RenameRate { source, .. }
            | Error::CreateAttemptDir { source, .. }
            | Error::WriteAttempt { source, .. } => Some(source),
            Error::RateFetchDidNotFinish { source } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    pub fn report(&self, context: &str) {
        crate::util::report(self, context);
    }
}

impl From<store::Error> for Error {
    fn from(error: store::Error) -> Self {
        Error::Store(error)
    }
}
