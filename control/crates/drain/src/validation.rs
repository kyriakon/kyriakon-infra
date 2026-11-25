//! The drain's own revalidation of a filed intent: the shape checks the
//! handler's file is put through before any transition runs, and the session
//! proof the page verbs carry.
//!
//! These are not account or store failures; they are the pass deciding whether
//! an intent is one this build may act on. The variant names the state and
//! `Display` composes the sentence here.

use std::fmt;

use kyriakon_control_core::flow::Reason;

/// An intent the drain will not carry out as filed.
#[derive(Debug)]
pub enum Error {
    /// The intent's status token is absent or not the 128-bit shape.
    BadStatusToken,
    /// The username does not pass the platform's own name rules.
    InvalidUsername { username: String, source: Reason },
    /// The intent's kind is not one of the decision kinds.
    NotADecision { kind: String },
    /// The action is not the one the intent's kind carries.
    ActionMismatch { action: String, kind: String },
    /// No application record exists for the token the decision names.
    NoApplication,
    /// The decision's username is not the application record's.
    ForeignApplication,
    /// A signed intent's signature does not verify. `what` is the intent's own
    /// name for itself, such as `the token resend's`.
    SignatureInvalid { what: &'static str },
    /// The intent names no usable session id.
    SessionIdShape,
    /// The session the intent names has been removed.
    SessionGone,
    /// The session record was opened after the intent was filed.
    SessionOpenedLater,
    /// The intent or its session carries no filing time this build can compare.
    NoFilingTime,
    /// This build does not implement the intent's kind.
    UnknownKind { kind: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadStatusToken => f.write_str("the status token is not 128 bits of Crockford"),
            Error::InvalidUsername { username, source } => {
                write!(f, "the username {username:?}: {source}")
            }
            Error::NotADecision { kind } => write!(f, "kind {kind:?} is not a decision"),
            Error::ActionMismatch { action, kind } => {
                write!(f, "the action {action:?} does not match the kind {kind:?}")
            }
            Error::NoApplication => f.write_str("there is no application for this token"),
            Error::ForeignApplication => {
                f.write_str("the intent's username is not the application's")
            }
            Error::SignatureInvalid { what } => {
                write!(f, "{what} signature does not verify")
            }
            Error::SessionIdShape => f.write_str("the intent carries no usable session id"),
            Error::SessionGone => f.write_str("the session named by the intent has gone"),
            Error::SessionOpenedLater => {
                f.write_str("the session was opened after the intent was filed")
            }
            Error::NoFilingTime => {
                f.write_str("the intent or its session carries no comparable filing time")
            }
            Error::UnknownKind { kind } => {
                write!(f, "this build does not implement the kind {kind:?}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::InvalidUsername { source, .. } => Some(source),
            _ => None,
        }
    }
}
