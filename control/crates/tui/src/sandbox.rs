//! The portal's narrowed view.
//!
//! The terminal reads the catalogue and the reserved names it was started with,
//! holds one session lock under `state`, and reaches the handler over its portal
//! socket. Nothing else is named: a session cannot read the store, a member's
//! mail or another account's tree. On OpenBSD the calls are enforced; elsewhere
//! `restrict` is a no-op so the crate's tests drive the same code on a
//! workstation.

use std::path::Path;

use kyriakon_control_core::config::Config;
use kyriakon_control_core::sandbox;

/// Unveil the files the portal opens, lock the list, probe the read paths, and
/// pledge. `tty` is true only when the full-screen mode will call `tcsetattr`:
/// the plain mode is a line reader and gives up the promise rather than carry
/// a terminal operation it never makes.
pub fn restrict(cfg: &Config, state: &Path, tty: bool) -> Result<(), sandbox::Error> {
    let state = sandbox::path(state, "state")?;
    sandbox::unveil(&cfg.catalogue, "r")?;
    sandbox::unveil(&cfg.reserved, "r")?;
    sandbox::unveil(state, "rwc")?;
    sandbox::unveil(&cfg.portal_socket, "rw")?;
    // `authlog` writes AUTH events through syslog, and syslog connects to this
    // socket. It is a write-only entry, so it is not probed.
    sandbox::unveil("/dev/log", "w")?;
    sandbox::lock()?;
    sandbox::probe(&cfg.catalogue)?;
    sandbox::probe(&cfg.reserved)?;
    sandbox::pledge(if tty {
        "stdio rpath wpath cpath flock unix tty"
    } else {
        "stdio rpath wpath cpath flock unix"
    })
}
