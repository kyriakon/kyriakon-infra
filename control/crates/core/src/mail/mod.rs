//! Messages and the keys that prove them: notifying, and reading a submitted
//! key.

pub mod bounce;
mod error;
pub mod keycheck;
pub mod notice;
pub mod pgp;
pub mod table;

pub use error::Error;
