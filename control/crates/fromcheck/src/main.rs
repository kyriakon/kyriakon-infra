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

fn usage() {
    eprintln!("usage: kyriakon-fromcheck -t <mail_from table> -a <domain> [-a <domain> ...]");
}

fn main() -> ExitCode {
    let mut table = None;
    let mut domains = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-t" => match args.next() {
                Some(path) => table = Some(path),
                None => {
                    usage();
                    return ExitCode::from(64);
                }
            },
            "-a" => match args.next() {
                Some(domain) => domains.push(domain),
                None => {
                    usage();
                    return ExitCode::from(64);
                }
            },
            "-h" | "--help" => {
                usage();
                return ExitCode::SUCCESS;
            }
            _ => {
                usage();
                return ExitCode::from(64);
            }
        }
    }
    let Some(table) = table else {
        usage();
        return ExitCode::from(64);
    };
    if domains.iter().all(|domain| domain.is_empty()) {
        usage();
        return ExitCode::from(64);
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
