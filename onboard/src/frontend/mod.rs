//! Everything a client talks to: the FastCGI wire, the responder, the HTML and
//! gemtext renderings, the portal's request, and the terminal.

pub mod capsule;
pub mod fastcgi;
pub mod ipc;
pub mod page;
pub mod responder;
pub mod tui;
