//! One member's state and actions: signing links, sessions, passwords, data
//! requests, exports, and the DNS recipe a body publishes.

pub mod dns;
pub mod export;
pub mod password;
pub mod requests;
pub mod session;
pub mod sign;

/// The lapse's own words, shared by the page, the capsule and the notice: mail
/// stays readable and published work stays up; sending, uploading and pushing
/// stop; nothing is deleted at that point.
pub const LAPSE_NOTE: &str = "Mail keeps arriving and stays readable, and everything you \
published stays up. Sending, uploading and pushing have stopped. Nothing is deleted at \
this point. If you have posted the money, write to admin@kyriakon.net.";
