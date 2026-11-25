//! The drain: the root-side program that applies the intents the
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
//!   kyriakon-control-drain [--config PATH]
//!   kyriakon-control-drain mail-table <verb> <table> ...
//!
//! `mail-table` is the one writer of the five `/etc/mail` tables. The shell
//! scripts run it rather than carrying their own writer; the verbs are
//! `add`, `set`, `drop`, `map-add`, `check` and `regenerate` (rebuild
//! `mail_from` from passwd and the virtual table, under the lock). `check`
//! answers absent, same or different with the same parse `set` uses.
//!
//! The config defaults to `/etc/kyriakon/onboard/drain.toml`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kyriakon_control_core::config::DrainConfig;
use kyriakon_control_core::mail::table::{DropMode, Lookup, Table};
use kyriakon_control_core::store::Store;
use kyriakon_control_drain::transitions::Error;
use kyriakon_control_drain::usage;

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
                    Error::from(usage::Error::ConfigPathMissing).report("the drain");
                    return ExitCode::FAILURE;
                }
            },
            "mail-table" => return mail_table(args.collect()),
            other => {
                Error::from(usage::Error::UnknownArgument {
                    argument: other.to_string(),
                })
                .report("the drain");
                return ExitCode::FAILURE;
            }
        }
    }
    match run(&cfg_path).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            e.report("the drain");
            ExitCode::FAILURE
        }
    }
}

/// Exit codes the scripts act on: 0 changed, 1 unchanged, 2 failed. `add`,
/// `set` and `regenerate` return 0 on success whether or not they changed the
/// file; `drop` and `map-add` use 1 for "nothing to do". `check` prints its
/// answer and returns 0, because all three answers are a successful read.
fn mail_table(args: Vec<String>) -> ExitCode {
    match run_mail_table(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            e.report("the mail table");
            ExitCode::from(2)
        }
    }
}

fn run_mail_table(args: &[String]) -> Result<u8, Error> {
    let (verb, rest) = args
        .split_first()
        .ok_or(usage::Error::MailTableVerbMissing)?;
    let (path, rest) = rest
        .split_first()
        .ok_or(usage::Error::MailTableArgumentMissing)?;
    let table = Table::at(path).map_err(Error::from)?;
    let changed = |change: kyriakon_control_core::mail::table::Change| {
        if change.changed {
            0
        } else {
            1
        }
    };
    match verb.as_str() {
        "add" => {
            let (name, rest) = rest
                .split_first()
                .ok_or(usage::Error::MailTableArgumentMissing)?;
            let value = rest.first().map(String::as_str);
            let change = table.ensure(name, value).map_err(Error::from)?;
            println!("{}", if change.added { "added" } else { "present" });
            Ok(0)
        }
        "set" => {
            let line = rest.first().ok_or(usage::Error::MailTableArgumentMissing)?;
            let change = table.set(line).map_err(Error::from)?;
            println!(
                "{}",
                if change.added {
                    "added"
                } else if change.changed {
                    "set"
                } else {
                    "unchanged"
                }
            );
            Ok(0)
        }
        "check" => {
            let line = rest.first().ok_or(usage::Error::MailTableArgumentMissing)?;
            match table.check(line).map_err(Error::from)? {
                Lookup::Absent => println!("absent"),
                Lookup::Same => println!("same"),
                Lookup::Different(value) => println!("different {value}"),
            }
            Ok(0)
        }
        "drop" => {
            let (how, rest) = rest
                .split_first()
                .ok_or(usage::Error::MailTableArgumentMissing)?;
            let text = rest.first().ok_or(usage::Error::MailTableArgumentMissing)?;
            let how = DropMode::parse(how).map_err(Error::from)?;
            Ok(changed(table.drop(how, text).map_err(Error::from)?))
        }
        "map-add" => {
            let (key, rest) = rest
                .split_first()
                .ok_or(usage::Error::MailTableArgumentMissing)?;
            let value = rest.first().ok_or(usage::Error::MailTableArgumentMissing)?;
            Ok(changed(table.map_add(key, value).map_err(Error::from)?))
        }
        "regenerate" => {
            let (passwd, rest) = rest
                .split_first()
                .ok_or(usage::Error::MailTableArgumentMissing)?;
            let (virtuals, rest) = rest
                .split_first()
                .ok_or(usage::Error::MailTableArgumentMissing)?;
            let domain = rest.first().ok_or(usage::Error::MailTableArgumentMissing)?;
            let change = table
                .regenerate_senders(Path::new(passwd), Path::new(virtuals), domain)
                .map_err(Error::from)?;
            println!(
                "{}",
                if change.changed {
                    "replaced"
                } else {
                    "unchanged"
                }
            );
            Ok(0)
        }
        _ => Err(usage::Error::MailTableVerbUnknown.into()),
    }
}

async fn run(cfg_path: &Path) -> Result<(), Error> {
    let cfg = DrainConfig::load(cfg_path)?;
    // Read the config first, then cut the pass's file view and syscall set to
    // what the transitions in this crate use. Nothing below may widen it.
    kyriakon_control_drain::sandbox::restrict(&cfg)?;
    let store = Store::new(&cfg.store_root);
    // One pass at a time. cron starts the drain every minute, and a pass that
    // runs long (a forge publish, a slow sendmail) would otherwise overlap the
    // next: two read-modify-write passes on the virtual table or a group record
    // can drop the other's line, and the intent that wrote it is already
    // deleted. A tick that finds the lock held is skipped: every intent is
    // idempotent and the next minute tries again.
    let _lock = match store.try_lock(".drain.lock").await? {
        Some(lock) => lock,
        // Another pass is running and will carry this tick's work.
        None => return Ok(()),
    };
    kyriakon_control_drain::run(&cfg, &store).await
}
