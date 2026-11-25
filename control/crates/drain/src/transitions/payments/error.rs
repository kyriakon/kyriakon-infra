//! The money-in area's error: one variant per failure state and the fields the
//! sentence needs.
//!
//! Credits, refunds and the held-payment queue share this enum because they
//! answer to one caller: the operator reads the journal line or the console
//! reply and acts on it. The variant names the state, not the function, and
//! `Display` composes the sentence here rather than at the site.

use std::fmt;

use kyriakon_control_core::flow::Reason;

/// A payments transition's failure. The fields are the values the sentence
/// names, so a caller can read the state back without parsing the text.
#[derive(Debug)]
pub enum Error {
    /// The configured price is not more than zero.
    PriceNotPositive { field: &'static str },
    /// The token's group domain does not pass the platform's domain rules.
    GroupDomainInvalid { domain: String, source: Reason },
    /// The credit names a rail that is not one this path accepts.
    CreditRailUnknown,
    /// The credit's token is not the shape of a payment token.
    CreditTokenShape,
    /// The credit's received date is not `YYYY-MM-DD`.
    CreditReceivedDateShape,
    /// The credit's received date is too far ahead.
    CreditReceivedTooFar { received: String },
    /// The credit's transaction id is not a Monero txid.
    CreditTxidShape,
    /// The credit's XMR amount is not a decimal amount.
    CreditXmrShape,
    /// A rate was given on a credit that is not a Monero credit.
    CreditRateWithoutMonero,
    /// The credit's rate is not a positive decimal amount.
    CreditRateShape { rate: String },
    /// The credit's amount is not more than zero.
    CreditAmountNotPositive,
    /// The token record names a token other than the one asked for.
    TokenRecordNamesOther,
    /// The token is not in the index.
    TokenNotIndexed,
    /// The token belongs to a group, whose payment is held on the group record.
    TokenBelongsToGroup,
    /// The token resolves to an account that is gone.
    TokenAccountGone,
    /// The account carries no payment block.
    AccountNoPayment,
    /// The token is not the one the account's payment block holds.
    TokenNotHeld,
    /// A payment line in the ledger carries no amount.
    PaymentLineNoAmount,
    /// An identical refund is already in the ledger.
    RefundAlreadyRecorded { seq: u64, on: String },
    /// Refunds of one payment would exceed the ceiling.
    RefundExceedsCeiling {
        seq: u64,
        total: String,
        amount: String,
        ceiling: String,
        what: &'static str,
    },
    /// A held line the operator names is not held.
    HeldNotHeld { item: String, state: String },
    /// A returned line cannot be attributed.
    HeldReturned { id: String },
    /// No held payment carries the id the intent names.
    HeldMissing { id: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PriceNotPositive { field } => {
                write!(f, "the drain's configured {field} must be more than zero")
            }
            Error::GroupDomainInvalid { domain, source } => {
                write!(f, "the token's group domain {domain:?}: {source}")
            }
            Error::CreditRailUnknown => {
                f.write_str("the credit names a rail that is not cash, cash-hand or monero")
            }
            Error::CreditTokenShape => {
                f.write_str("the credit's token is not the shape of a payment token")
            }
            Error::CreditReceivedDateShape => {
                f.write_str("the credit's received date is not YYYY-MM-DD")
            }
            Error::CreditReceivedTooFar { received } => write!(
                f,
                "the credit's received date {received} is more than two years ahead"
            ),
            Error::CreditTxidShape => {
                f.write_str("the credit's transaction id is not 64 hexadecimal characters")
            }
            Error::CreditXmrShape => f.write_str("the credit's XMR amount is not a decimal amount"),
            Error::CreditRateWithoutMonero => {
                f.write_str("a --rate is only a monero credit's receipt-date rate")
            }
            Error::CreditRateShape { rate } => write!(
                f,
                "the credit's rate {rate:?} is not a positive decimal amount"
            ),
            Error::CreditAmountNotPositive => {
                f.write_str("the credit's amount must be more than zero")
            }
            Error::TokenRecordNamesOther => {
                f.write_str("the token record does not name this token")
            }
            Error::TokenNotIndexed => f.write_str(
                "the token is not in the index; an unattributed payment belongs in the queue",
            ),
            Error::TokenBelongsToGroup => f.write_str(
                "the token belongs to a group, whose payment is held on the group's record",
            ),
            Error::TokenAccountGone => f.write_str("the token resolves to an account that is gone"),
            Error::AccountNoPayment => f.write_str("the account carries no payment block"),
            Error::TokenNotHeld => {
                f.write_str("the token is not the one the account's payment block holds")
            }
            Error::PaymentLineNoAmount => f.write_str("a payment line carries no amount"),
            Error::RefundAlreadyRecorded { seq, on } => write!(
                f,
                "an identical refund is already recorded at ledger seq {seq} on {on}"
            ),
            Error::RefundExceedsCeiling {
                seq,
                total,
                amount,
                ceiling,
                what,
            } => write!(
                f,
                "refunds of ledger seq {seq} already total GBP {total}; another GBP {amount} \
                 would exceed the GBP {ceiling} {what}"
            ),
            Error::HeldNotHeld { item, state } => {
                write!(f, "{item} is {state}, not held")
            }
            Error::HeldReturned { id } => {
                write!(f, "{id} was returned, so it cannot be attributed")
            }
            Error::HeldMissing { id } => write!(f, "no held payment with id {id}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::GroupDomainInvalid { source, .. } => Some(source),
            _ => None,
        }
    }
}
