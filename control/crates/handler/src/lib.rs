//! The handler's library: the responder, the HTML and gemtext renderings, and
//! the FastCGI wire it shares with the other front ends through the core. The
//! terminal and the console are their own packages.

pub mod capsule;
pub mod page;
pub mod responder;

pub use kyriakon_control_core::fastcgi;
