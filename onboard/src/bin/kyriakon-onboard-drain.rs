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
    intents::run(&cfg, &store).await
}
