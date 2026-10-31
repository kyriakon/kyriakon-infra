//! The onboarding crate, as a library so the three programs that make up the
//! service share one implementation of the store, the configuration, the
//! signing, the notices and the transitions.
//!
//! The split is the spec's: the handler (`kyriakon-onboard`) holds no privilege
//! and writes intents; the drain (`kyriakon-onboard-drain`) runs as root and
//! applies them; `kyriakon-onboardctl` gives the reviewer the same three
//! decisions at a terminal. Everything they share lives here, so a second
//! reader of the store, a second signer or a second notice path cannot drift
//! from the first.

pub mod billing;
pub mod capsule;
pub mod catalogue;
pub mod config;
pub mod dns;
pub mod draft;
pub mod fcgi;
pub mod intents;
pub mod keycheck;
pub mod mailbox;
pub mod notice;
pub mod page;
pub mod password;
pub mod portal;
pub mod portal_ipc;
pub mod prepaid;
pub mod questions;
pub mod rate;
pub mod requests;
pub mod responder;
pub mod sign;
pub mod store;
pub mod transitions;
pub mod util;
pub mod validate;
