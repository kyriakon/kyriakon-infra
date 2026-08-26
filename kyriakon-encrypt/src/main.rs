//! kyriakon-encrypt CLI.
//!
//! Two modes:
//! - `encrypt --user <localpart> [--keyring DIR] [--gpg-home DIR]` — read an
//!   RFC 5322 message on stdin, write RFC 3156 PGP/MIME ciphertext to stdout.
//!   The test seam, and the same path the daemon serves.
//! - `serve [--socket PATH] [--keyring DIR] [--gpg-home DIR]` — long-lived
//!   daemon on a unix socket for the Dovecot C shim.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use kyriakon_encrypt::{encrypt, serve, DEFAULT_GPG_HOME, DEFAULT_KEYRING, DEFAULT_SOCKET};

fn usage() -> ! {
    eprintln!(
        "usage: kyriakon-encrypt encrypt --user <localpart> [--keyring DIR] [--gpg-home DIR]\n\
         \x20      kyriakon-encrypt serve [--socket PATH] [--keyring DIR] [--gpg-home DIR]"
    );
    std::process::exit(2);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = parse_flags(&args[1..]);
    match args.first().map(String::as_str) {
        Some("encrypt") => {
            let Some(user) = cfg.user else { usage() };
            let mut input = Vec::new();
            if std::io::stdin().read_to_end(&mut input).is_err() {
                eprintln!("kyriakon-encrypt: cannot read message from stdin");
                return ExitCode::FAILURE;
            }
            match encrypt(&user, &cfg.keyring, &cfg.gpg_home, &input) {
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
            let socket = cfg.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
            match serve(&socket, &cfg.keyring, &cfg.gpg_home) {
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

/// Command-line config. One struct so every flag is parsed exactly once;
/// modes read only the fields they document.
struct Config {
    user: Option<String>,
    keyring: PathBuf,
    socket: Option<PathBuf>,
    gpg_home: PathBuf,
}

/// Parse `--user`, `--keyring`, `--socket`, `--gpg-home` (order-independent).
fn parse_flags(args: &[String]) -> Config {
    let mut cfg = Config {
        user: None,
        keyring: PathBuf::from(DEFAULT_KEYRING),
        socket: None,
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
            "--socket" => {
                cfg.socket = args.get(i + 1).map(PathBuf::from);
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
