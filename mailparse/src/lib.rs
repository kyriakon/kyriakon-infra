//! Strict parsing for the message formats the mail path reads.
//!
//! Every parser here has one job and one line-ending rule. A line ends at LF,
//! at CRLF, or at a bare CR, and the header split, the header spans, and the
//! multipart walk all use it. A message is therefore read from the bytes as
//! they arrived, never after a normalising step that could disagree with the
//! parser next to it.
//!
//! The crate has no dependencies: the encryptor and the control plane link it
//! without gaining one. The control core reads armour framing, clearsigned
//! message headers and their line endings through it.

mod message;

pub use message::{
    boundary_param, headers, lines, parse_address_list, split_message, walk_multipart, Header,
    Line, Lines, Mailbox, Message, Multipart, Part,
};

use std::fmt;

/// A byte stream that does not have the strict shape the caller asked for.
///
/// The reason is a fixed sentence rather than the offending bytes: callers log
/// it, and the bytes are the sender's to choose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed(&'static str);

impl Malformed {
    pub(crate) const fn new(why: &'static str) -> Self {
        Self(why)
    }

    /// The fixed sentence describing what the parser could not read.
    pub fn reason(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed message: {}", self.0)
    }
}

impl std::error::Error for Malformed {}
