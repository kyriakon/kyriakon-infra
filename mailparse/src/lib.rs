//! Strict parsing for the message formats the mail path reads.
//!
//! Every parser here has one job and one line-ending rule. A line ends at LF,
//! at CRLF, or at a bare CR, and the header split, the header spans, and the
//! multipart walk all use it. A message is therefore read from the bytes as
//! they arrived, never after a normalising step that could disagree with the
//! parser next to it.
//!
//! The crate has no dependencies: the encryptor links it without gaining one,
//! and the control plane depends on it by path rather than through a workspace
//! lockfile.

mod address;
mod header;
mod mime;

pub use address::{parse_address_list, Mailbox};
pub use header::{headers, lines, split_message, Header, Line, Lines, Message};
pub use mime::{boundary_param, walk_multipart, Part};

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
