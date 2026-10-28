//! The onboarding drain: the root-side program that applies the intents the
//! handler files.
//!
//! It runs from root's crontab every minute, as a single short-lived process
//! with no listener and no loop of its own: it reads `intents/` in ULID order,
//! carries each transition out, and exits. Everything it does as root it does by
//! calling the repository's own scripts, whose paths come from its config so
//! that a test can point the whole service at stubs.
//!
//! Usage:
//!
//!   kyriakon-onboard-drain [--config PATH]
//!
//! The config defaults to `/etc/kyriakon/onboard/drain.toml`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kyriakon_onboard::config::DrainConfig;
use kyriakon_onboard::intents;
use kyriakon_onboard::store::Store;

const DEFAULT_CONFIG: &str = "/etc/kyriakon/onboard/drain.toml";

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut cfg_path = PathBuf::from(DEFAULT_CONFIG);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => match args.next() {
                Some(p) => cfg_path = PathBuf::from(p),
                None => {
                    eprintln!("kyriakon-onboard-drain: --config needs a path");
                    return ExitCode::FAILURE;
                }
            },
            other => {
                eprintln!(
                    "kyriakon-onboard-drain: unknown argument {other:?}; \
                     usage: kyriakon-onboard-drain [--config PATH]"
                );
                return ExitCode::FAILURE;
            }
        }
    }
    match run(&cfg_path).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kyriakon-onboard-drain: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cfg_path: &Path) -> Result<(), String> {
    let cfg = DrainConfig::load(cfg_path)?;
    let store = Store::new(&cfg.store_root);
    let _lock = match pass_lock(&store)? {
        Some(lock) => lock,
        // Another pass is running and will carry this tick's work; every intent
        // is idempotent and the next minute tries again.
        None => return Ok(()),
    };
    intents::run(&cfg, &store).await
}

/// One pass at a time. cron starts the drain every minute, and a pass that runs
/// long (a forge publish, a slow sendmail) would otherwise overlap the next:
/// two read-modify-write passes on the virtual table or a group record can drop
/// the other's line, and the intent that wrote it is already deleted. The lock
/// is held for the process's life and released by the kernel however it exits.
fn pass_lock(store: &Store) -> Result<Option<std::fs::File>, String> {
    use std::os::unix::io::AsRawFd;
    let path = store.path(".drain.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // SAFETY: `file` owns a valid descriptor for the duration of the call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(None);
    }
    Err(format!("cannot lock {}: {error}", path.display()))
}
