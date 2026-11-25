//! Money: the ledger, the calendar arithmetic, and the rate the Monero rail
//! quotes from, and the instructions a member is shown for each rail.

pub mod billing;
mod error;
pub mod ledger;
pub mod rails;
pub mod target;
pub mod xmr;

pub use error::Error;
