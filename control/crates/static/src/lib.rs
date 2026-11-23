//! The member content server: what is published under `/home/www`.
//!
//! Both front ends hand a member's vhost here rather than serving the tree
//! themselves. Neither daemon can refuse a symlink: a member who plants one in
//! their own writable root reaches every other member's tree, and the `.git`
//! block both configs carry matches the request path, never the resolved file
//! (#815).
//!
//! The path is resolved here, one component at a time, from the member's own root
//! with `O_NOFOLLOW`: a link is a refusal, not a way out, and no component may
//! begin with a dot, so `.git` is unreachable under every spelling. The front
//! ends still terminate TLS and decide which host, and therefore which root, a
//! request belongs to; this crate is given that root and may not leave it.

mod mime;
mod resolve;
pub mod sandbox;

pub use mime::media_type;
pub use resolve::{open, Refusal, Served};
