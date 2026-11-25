//! The binary's argument parsing: one variant per missing or unknown argument.
//!
//! The usage lines are the contract the shell scripts and the operator read, so
//! they print exactly as before; the variant is what a caller or a test can
//! name instead of matching the text.

use std::fmt;

/// The `mail-table` usage line, printed for every missing or unknown argument.
const MAIL_TABLE_USAGE: &str = "usage: kyriakon-control-drain mail-table \
     <add|set|check|drop|map-add|regenerate> <table> ...";

/// A command line the binary cannot read.
#[derive(Debug)]
pub enum Error {
    /// `--config` was given with no path after it.
    ConfigPathMissing,
    /// An argument is not a command this binary knows.
    UnknownArgument { argument: String },
    /// The `mail-table` command was given no verb.
    MailTableVerbMissing,
    /// A `mail-table` verb was given fewer arguments than it takes.
    MailTableArgumentMissing,
    /// The `mail-table` command named a verb this binary does not know.
    MailTableVerbUnknown,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ConfigPathMissing => f.write_str("--config needs a path"),
            Error::UnknownArgument { argument } => write!(
                f,
                "unknown argument {argument:?}; usage: kyriakon-control-drain [--config PATH]"
            ),
            Error::MailTableVerbMissing
            | Error::MailTableArgumentMissing
            | Error::MailTableVerbUnknown => f.write_str(MAIL_TABLE_USAGE),
        }
    }
}

impl std::error::Error for Error {}
