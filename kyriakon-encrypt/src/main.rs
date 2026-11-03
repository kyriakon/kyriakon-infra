//! kyriakon-encrypt CLI.
//!
//! `encrypt --user <localpart> [--keyring DIR] [--gpg-home DIR]` reads an
//! RFC 5322 message on stdin and writes RFC 3156 PGP/MIME ciphertext to
//! stdout. The Dovecot save path runs exactly this, so the exit status is the
//! save's success and a non-zero one must never store the message.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use kyriakon_encrypt::{encrypt, DEFAULT_GPG_HOME, DEFAULT_KEYRING};

fn usage() -> ! {
    eprintln!(
        "usage: kyriakon-encrypt encrypt --user <localpart> [--keyring DIR] [--gpg-home DIR]"
    );
    std::process::exit(2);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("encrypt") {
        usage();
    }
    let cfg = parse_flags(&args[1..]);
    let Some(user) = cfg.user else { usage() };
    let mut input = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() {
        eprintln!("kyriakon-encrypt: cannot read message from stdin");
        return ExitCode::FAILURE;
    }
    match encrypt(&user, &cfg.keyring, &cfg.gpg_home, &input) {
        // Exit 0 promises the caller every ciphertext byte reached stdout, so a
        // failed write is a failed save rather than a short armour stored.
        Ok(out) => match std::io::stdout().write_all(&out) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("kyriakon-encrypt: write ciphertext: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("kyriakon-encrypt: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Command-line config. One struct so every flag is parsed exactly once.
struct Config {
    user: Option<String>,
    keyring: PathBuf,
    gpg_home: PathBuf,
}

/// Parse `--user`, `--keyring`, `--gpg-home` (order-independent).
fn parse_flags(args: &[String]) -> Config {
    let mut cfg = Config {
        user: None,
        keyring: PathBuf::from(DEFAULT_KEYRING),
        gpg_home: PathBuf::from(DEFAULT_GPG_HOME),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--user" => {
                cfg.user = args.get(i + 1).cloned();
                i += 2;
            }
            "--keyring" => {
                if let Some(dir) = args.get(i + 1) {
                    cfg.keyring = PathBuf::from(dir);
                }
                i += 2;
            }
            "--gpg-home" => {
                if let Some(dir) = args.get(i + 1) {
                    cfg.gpg_home = PathBuf::from(dir);
                }
                i += 2;
            }
            _ => usage(),
        }
    }
    cfg
}
