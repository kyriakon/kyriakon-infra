//! The drain's acceptance criteria, one source area per module.
//!
//! The areas are modules, not separate test binaries: Cargo runs one test
//! binary's tests in parallel, so a split into binaries would make the full
//! suite slower. The files under `areas/` keep the source navigable, and the
//! fast loop filters one module at a time:
//! `cargo test --test drain -- prepaid`.

mod common;

#[path = "areas/card.rs"]
mod card;
#[path = "areas/export.rs"]
mod export;
#[path = "areas/group.rs"]
mod group;
#[path = "areas/lifecycle.rs"]
mod lifecycle;
#[path = "areas/prepaid.rs"]
mod prepaid;
#[path = "areas/refund.rs"]
mod refund;
