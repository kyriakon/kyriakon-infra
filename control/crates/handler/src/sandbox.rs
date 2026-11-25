//! The responder's narrowed view.
//!
//! The handler starts after its configuration, catalogue and capsule pages have
//! been read, so this list is what a request and the login check can still
//! reach: the store it renders and files under, the login check's fixed program,
//! and the kernel pool its capability tokens come from. The three unix sockets
//! and the Titan TCP listener are bound before this runs, so their paths are not
//! entries.
//!
//! A compromised handler cannot read `/etc/ssl`, `/home`, a member's mail or the
//! login proofs: none of them is named, and once the list is locked no later
//! call can add one. The proof directory is only ever an argv value here; the
//! checker `doas` starts is a new program after `execve`, with its own view and
//! its own root rights.

use kyriakon_control_core::account::session;
use kyriakon_control_core::config::Config;
use kyriakon_control_core::sandbox;

/// The promises a request uses: stdio for the connection it already holds,
/// rpath/wpath/cpath/fattr for the store records and their modes, unix for the
/// three unix listeners, inet for the Titan accept, proc/exec for the login
/// check, and flock for the store locks. The handler appends no record, but it
/// does take a lock: `draft::save` and the update/purge paths take
/// `drafts/.lock`, and `session::open` and `session::close` take
/// `sessions/.<id>.lock`. It only reads `notices.jsonl`. `/dev/urandom` is
/// opened directly for a capability token, hence no reliance on getentropy
/// alone.
const PROMISES: &str = "stdio rpath wpath cpath fattr flock unix inet proc exec";

pub fn restrict(cfg: &Config) -> Result<(), String> {
    sandbox::unveil(&cfg.store_root, "rwc")?;
    sandbox::unveil("/dev/urandom", "r")?;
    sandbox::unveil("/dev/null", "rw")?;
    sandbox::unveil(session::DOAS, "x")?;
    sandbox::unveil(session::AUTHCHECK, "x")?;
    sandbox::lock()?;
    sandbox::probe(&cfg.store_root)?;
    sandbox::probe("/dev/urandom")?;
    sandbox::pledge(PROMISES)
}
