//! The onboarding core: the store, the configuration, the intent contract, the
//! shared flow, the account and money sections, and the IPC request.
//!
//! Every package that makes up the service depends on this one and on nothing
//! else of the service. The handler writes intents; the drain applies them; the
//! terminal and the console read the same catalogue, questions and records.

pub mod account;
pub mod config;
pub mod error;
pub mod flow;
pub mod intent;
pub mod ipc;
pub mod mail;
pub mod payments;
pub mod store;
pub mod util;

pub use error::Error;
