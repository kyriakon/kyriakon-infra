//! The card rail's error: one variant per failure state, the fields the
//! sentence needs, and the cause kept for `source()`.
//!
//! The webhook pass and the apply paths share this enum because they answer to
//! one caller: the operator reads the journal line or the console reply and
//! acts on it. The variant names the state, not the function, and `Display`
//! composes the sentence here rather than at the site.

use std::fmt;

/// A card transition's failure. The fields are the values the sentence names,
/// so a caller can read the state back without parsing the text.
#[derive(Debug)]
pub enum Error {
    /// The event names no id or type, so there is nothing to settle.
    NoEventIdOrType,
    /// The delivery's timestamp is not within the replay window of its arrival.
    TimestampOutOfWindow { timestamp: i64, arrived: i64 },
    /// A signature header part carries no value.
    SignaturePartWithoutValue { part: String },
    /// The signature header carries no `t=` timestamp.
    NoSignatureTimestamp,
    /// The signature header carries no `v1` signature.
    NoSignature,
    /// No `v1` signature matches the signed payload.
    NoMatchingSignature,
    /// The event carries no `data.object`.
    NoEventObject,
    /// The configured price is not more than zero.
    PriceNotPositive { field: &'static str },
    /// The paid invoice says nothing about its amount.
    InvoiceNoAmount,
    /// The paid invoice says nothing about when it was paid.
    InvoiceNoPaidTimestamp,
    /// The subscription id is not the safe shape an id has.
    SubscriptionIdShape { subscription: String },
    /// The Stripe API script did not answer with a subscription.
    SubscriptionUnreadable { source: serde_json::Error },
    /// The Stripe API script did not answer with a checkout session.
    SessionUnreadable { source: serde_json::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoEventIdOrType => f.write_str("names no event id or type"),
            Error::TimestampOutOfWindow { timestamp, arrived } => write!(
                f,
                "the timestamp {timestamp} is more than five minutes from its arrival {arrived}"
            ),
            Error::SignaturePartWithoutValue { part } => {
                write!(f, "the signature header carries {part:?} without a value")
            }
            Error::NoSignatureTimestamp => f.write_str("the signature header carries no t="),
            Error::NoSignature => f.write_str("the signature header carries no v1 signature"),
            Error::NoMatchingSignature => f.write_str("no v1 signature matches the body"),
            Error::NoEventObject => f.write_str("the event carries no data.object"),
            Error::PriceNotPositive { field } => {
                write!(f, "the drain's configured {field} must be more than zero")
            }
            Error::InvoiceNoAmount => f.write_str("the paid invoice carries no amount_paid"),
            Error::InvoiceNoPaidTimestamp => {
                f.write_str("the paid invoice carries no paid timestamp")
            }
            Error::SubscriptionIdShape { subscription } => {
                write!(f, "the subscription id {subscription:?} is not an id")
            }
            Error::SubscriptionUnreadable { source } => write!(
                f,
                "stripe-api.sh did not answer with a subscription: {source}"
            ),
            Error::SessionUnreadable { source } => write!(
                f,
                "stripe-api.sh did not answer with a checkout session: {source}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::SubscriptionUnreadable { source } => Some(source),
            Error::SessionUnreadable { source } => Some(source),
            _ => None,
        }
    }
}
