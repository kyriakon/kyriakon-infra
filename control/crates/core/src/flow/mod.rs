//! The shared application vocabulary: the question list, its validation, the
//! service catalogue, and the per-address counters.

pub mod applicant;
pub mod catalogue;
mod error;
pub mod questions;
pub mod rate;
pub mod validate;

pub use error::{Error, Reason};
