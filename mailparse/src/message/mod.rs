//! The message formats the mail path reads.
//!
//! The three parsers share one line-ending rule, defined in [`header`]. Each
//! keeps its own job: split a message into headers and body, read a mailbox
//! list from a header value, and walk an RFC 2046 multipart body.

mod address;
mod header;
mod mime;

pub use address::{parse_address_list, Mailbox};
pub use header::{headers, lines, split_message, Header, Line, Lines, Message};
pub use mime::{boundary_param, walk_multipart, Multipart, Part};
