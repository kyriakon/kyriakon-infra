//! kyriakon-encrypt CLI.
//!
//! Two modes:
//! - `encrypt --user <localpart> [--keyring DIR]` — read RFC 5322 message on
//!   stdin, write RFC 3156 PGP/MIME ciphertext to stdout. The test seam, and
//!   the same path the daemon serves.
//! - `serve [--socket PATH] [--keyring DIR]` — long-lived daemon on a unix
//!   socket for the Dovecot C shim.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use kyriakon_encrypt::{encrypt, serve, DEFAULT_KEYRING, DEFAULT_SOCKET};

fn usage() -> ! {
    eprintln!(
        "usage: kyriakon-encrypt encrypt --user <localpart> [--keyring DIR]\n\
         \x20      kyriakon-encrypt serve [--socket PATH] [--keyring DIR]"
    );
    std::process::exit(2);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("encrypt") => {
            let (user, keyring) = parse_flags(&args[1..], true);
            let mut input = Vec::new();
            if std::io::stdin().read_to_end(&mut input).is_err() {
                eprintln!("kyriakon-encrypt: cannot read message from stdin");
                return ExitCode::FAILURE;
            }
            match encrypt(&user, &keyring, &input) {
                Ok(out) => {
                    std::io::stdout().write_all(&out).ok();
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("kyriakon-encrypt: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("serve") => {
            let (_, keyring) = parse_flags(&args[1..], false);
            let socket = args
                .iter()
                .skip(1)
                .position(|a| a == "--socket")
                .map(|i| PathBuf::from(&args[i + 2]))
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
            match serve(&socket, &keyring) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("kyriakon-encrypt: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => usage(),
    }
}

/// Parse `--user` and `--keyring` (order-independent). `need_user` is true
/// for `encrypt` (user is mandatory); `serve` ignores `--user`.
fn parse_flags(args: &[String], need_user: bool) -> (String, PathBuf) {
    let mut user = None;
    let mut keyring = PathBuf::from(DEFAULT_KEYRING);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--user" => {
                user = args.get(i + 1).cloned();
                i += 2;
            }
            "--keyring" => {
                if let Some(dir) = args.get(i + 1) {
                    keyring = PathBuf::from(dir);
                }
                i += 2;
            }
            "--socket" => {
                // Consumed by serve's own --socket handling; skip value here.
                i += 2;
            }
            _ => usage(),
        }
    }
    if need_user {
        if let Some(u) = user {
            return (u, keyring);
        }
        usage();
    }
    (user.unwrap_or_default(), keyring)
}
