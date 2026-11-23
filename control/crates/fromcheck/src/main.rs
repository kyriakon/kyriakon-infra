//! `kyriakon-fromcheck`: the OpenSMTPD filter that refuses a `From:` header the
//! session may not use. Installed as `/usr/local/libexec/filter-fromcheck` and
//! named by `openbsd/etc/smtpd.conf`'s `proc-exec`.
//!
//! Usage: `kyriakon-fromcheck -t /etc/mail/mail_from -a kyriakon.net
//! -a mail.kyriakon.net`. The table and the domains are the same values the
//! listeners' `senders` option reads.

use std::io::{self, BufRead, BufWriter, Write};
use std::process::ExitCode;

use kyriakon_control_fromcheck::{Filter, Policy};

/// The paths and domains one invocation was given.
struct Args {
    table: String,
    domains: Vec<String>,
}

enum Parsed {
    Run(Args),
    Help,
    Usage,
}

fn usage() {
    eprintln!("usage: kyriakon-fromcheck -t <mail_from table> -a <domain> [-a <domain> ...]");
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Parsed {
    let mut table = None;
    let mut domains = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-t" => match args.next() {
                Some(path) => table = Some(path),
                None => return Parsed::Usage,
            },
            "-a" => match args.next() {
                Some(domain) => domains.push(domain),
                None => return Parsed::Usage,
            },
            "-h" | "--help" => return Parsed::Help,
            _ => return Parsed::Usage,
        }
    }
    match table {
        Some(table) if domains.iter().any(|domain| !domain.is_empty()) => {
            Parsed::Run(Args { table, domains })
        }
        _ => Parsed::Usage,
    }
}

/// The filter reads the table once and then only its stdin and stdout. On
/// OpenBSD that is the whole program: unveil the one file, lock the list, read
/// it, then pledge the syscalls stdio needs. The pledge comes after the policy
/// is built so the hash maps can seed from the kernel first. Elsewhere the
/// calls do not exist and this is a no-op, so the crate's tests run on a
/// workstation.
#[cfg(target_os = "openbsd")]
mod sandbox {
    use std::ffi::CString;

    pub fn unveil_table(table: &str) -> Result<(), String> {
        let path = CString::new(table)
            .map_err(|_| format!("unveil {table:?}: the path contains a NUL"))?;
        let read = CString::new("r").expect("the unveil mode has no NUL");
        if unsafe { libc::unveil(path.as_ptr(), read.as_ptr()) } == -1 {
            return Err(format!(
                "unveil {table}: {}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) } == -1 {
            return Err(format!("unveil lock: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn pledge_stdio() -> Result<(), String> {
        let promises = CString::new("stdio rpath").expect("the promise list has no NUL");
        if unsafe { libc::pledge(promises.as_ptr(), std::ptr::null()) } == -1 {
            return Err(format!("pledge: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "openbsd"))]
mod sandbox {
    pub fn unveil_table(_table: &str) -> Result<(), String> {
        Ok(())
    }

    pub fn pledge_stdio() -> Result<(), String> {
        Ok(())
    }
}

fn main() -> ExitCode {
    let (table, domains) = match parse_args(std::env::args().skip(1)) {
        Parsed::Run(args) => (args.table, args.domains),
        Parsed::Help => {
            usage();
            return ExitCode::SUCCESS;
        }
        Parsed::Usage => {
            usage();
            return ExitCode::from(64);
        }
    };
    if let Err(error) = sandbox::unveil_table(&table) {
        eprintln!("kyriakon-fromcheck: {error}");
        return ExitCode::FAILURE;
    }
    let entries = match std::fs::read(&table) {
        Ok(entries) => entries,
        Err(error) => {
            // A filter that cannot read its policy must be visibly dead rather
            // than answer every message as unknown.
            eprintln!("kyriakon-fromcheck: cannot read {table}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut filter = Filter::new(Policy::parse(&entries, &domains));
    if let Err(error) = sandbox::pledge_stdio() {
        eprintln!("kyriakon-fromcheck: {error}");
        return ExitCode::FAILURE;
    }

    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    let mut line = Vec::new();
    loop {
        line.clear();
        match input.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                let answer = filter.handle(&line);
                if !answer.is_empty()
                    && output
                        .write_all(&answer)
                        .and_then(|_| output.flush())
                        .is_err()
                {
                    // smtpd closed the pipe: there is no one left to answer.
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                eprintln!("kyriakon-fromcheck: cannot read the protocol: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Parsed {
        parse_args(args.iter().map(|arg| arg.to_string()))
    }

    #[test]
    fn the_table_and_every_domain_are_kept() {
        match parse(&[
            "-t",
            "/etc/mail/mail_from",
            "-a",
            "kyriakon.net",
            "-a",
            "mail.kyriakon.net",
        ]) {
            Parsed::Run(args) => {
                assert_eq!(args.table, "/etc/mail/mail_from");
                assert_eq!(args.domains, ["kyriakon.net", "mail.kyriakon.net"]);
            }
            _ => panic!("a complete command line is a run"),
        }
    }

    #[test]
    fn a_missing_table_or_domain_is_usage() {
        assert!(matches!(parse(&["-a", "kyriakon.net"]), Parsed::Usage));
        assert!(matches!(
            parse(&["-t", "/etc/mail/mail_from"]),
            Parsed::Usage
        ));
        assert!(matches!(
            parse(&["-t", "/etc/mail/mail_from", "-a"]),
            Parsed::Usage
        ));
        assert!(matches!(parse(&["--unknown"]), Parsed::Usage));
    }

    #[test]
    fn help_is_not_an_error() {
        assert!(matches!(parse(&["--help"]), Parsed::Help));
        assert!(matches!(parse(&["-h"]), Parsed::Help));
    }
}
