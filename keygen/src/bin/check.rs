//! `keygen-check`: read one armoured public key block on stdin and print the
//! shared check's verdict on stdout.
//!
//! The control plane runs this as a process so it does not link `pgp`. The
//! protocol is one line per value, because findings are fixed sentences the
//! crate itself writes and contain no newline:
//!
//! ```text
//! ok
//! <finding>
//! ```
//!
//! or `uninspected` when the block does not parse. Both are exit 0; a non-zero
//! exit is a usage or I/O failure, which core treats as uninspected too.
//!
//! The clock is an argument rather than read here, matching the library and
//! keeping the verdict on the caller's clock.

use std::io::Read;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// A public key block is a few kilobytes; the cap is a memory bound on a
/// process that reads an HTTP form field, not a key-size limit.
const MAX_INPUT: usize = 1 << 20;

fn usage() -> ExitCode {
    eprintln!("usage: keygen-check [--now-secs <seconds>]");
    ExitCode::from(2)
}

fn system_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let mut now = system_now();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--now-secs" => match args.next().and_then(|v| v.parse().ok()) {
                Some(seconds) => now = seconds,
                None => return usage(),
            },
            "--help" | "-h" => {
                println!("usage: keygen-check [--now-secs <seconds>]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("keygen-check: unknown argument {other}");
                return usage();
            }
        }
    }

    let mut input = Vec::new();
    let stdin = std::io::stdin();
    if let Err(e) = stdin
        .lock()
        .take(MAX_INPUT as u64 + 1)
        .read_to_end(&mut input)
    {
        eprintln!("keygen-check: cannot read stdin: {e}");
        return ExitCode::from(2);
    }
    if input.len() > MAX_INPUT {
        eprintln!("keygen-check: input is larger than {MAX_INPUT} bytes");
        return ExitCode::from(2);
    }

    let Ok(text) = std::str::from_utf8(&input) else {
        println!("uninspected");
        return ExitCode::SUCCESS;
    };
    match keygen::check_public_key(text, now) {
        Ok(findings) => {
            println!("ok");
            for finding in findings {
                println!("{finding}");
            }
        }
        Err(_) => println!("uninspected"),
    }
    ExitCode::SUCCESS
}
