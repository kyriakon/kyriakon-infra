//! The store's error: what a caller can act on, and the source it came from.
//!
//! The variants name the operation, because that is what the caller chooses
//! between: a read that must not be mistaken for an empty record, a write the
//! store refuses before touching disk, and a record that did not parse. The
//! fields carry the path and the source, never a sentence assembled here.

use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    /// The store refused a write before touching disk: an append-only name, a
    /// record mode the handler could not read, or a symlink at a temporary.
    Refused(String),
    /// An I/O operation failed. `NotFound` is handled by the caller as an
    /// absent record, never as this.
    Io {
        action: Action,
        path: PathBuf,
        source: std::io::Error,
    },
    /// A record did not parse as its type.
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// One line of an append-only record did not parse.
    ParseLine {
        path: PathBuf,
        line: usize,
        source: serde_json::Error,
    },
    /// A value could not be encoded. `what` is the record's noun, e.g. "the
    /// draft" or "a journal line".
    Encode {
        what: &'static str,
        source: serde_json::Error,
    },
}

/// What the failed I/O operation was. The caller acts on the operation; the
/// path and source are the facts it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Open,
    Create,
    Place,
    Append,
    Remove,
    Lock,
    Chown,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Refused(message) => f.write_str(message),
            Error::Io {
                action,
                path,
                source,
            } => match action {
                Action::Read => write!(f, "cannot read {}: {source}", path.display()),
                Action::Open => write!(f, "cannot open {}: {source}", path.display()),
                Action::Create => write!(f, "cannot create {}: {source}", path.display()),
                Action::Place => {
                    write!(f, "cannot place a record in {}: {source}", path.display())
                }
                Action::Append => write!(f, "cannot append to {}: {source}", path.display()),
                Action::Remove => {
                    write!(f, "cannot remove a record in {}: {source}", path.display())
                }
                Action::Lock => write!(f, "cannot lock {}: {source}", path.display()),
                Action::Chown => {
                    write!(f, "cannot hand {} to its owner: {source}", path.display())
                }
            },
            Error::Parse { path, source } => {
                write!(f, "{} does not parse: {source}", path.display())
            }
            Error::ParseLine { path, line, source } => write!(
                f,
                "{}: line {line} does not parse: {source}",
                path.display()
            ),
            Error::Encode { what, source } => write!(f, "cannot encode {what}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Refused(_) => None,
            Error::Io { source, .. } => Some(source),
            Error::Parse { source, .. }
            | Error::ParseLine { source, .. }
            | Error::Encode { source, .. } => Some(source),
        }
    }
}

impl Error {
    /// Print this error and its chain under the service's prefix. The one
    /// reporting function: a journal note, an alert body and a binary's last
    /// line all go through here instead of formatting a sentence at the site.
    pub fn report(&self, context: &str) {
        eprintln!("kyriakon-onboard: {context}: {self}");
        let mut source = std::error::Error::source(self);
        while let Some(cause) = source {
            eprintln!("kyriakon-onboard:   caused by: {cause}");
            source = cause.source();
        }
    }
}

/// A caller that has not converted yet still returns `Result<_, String>`. The
/// bridge keeps the tree compiling; step 5 deletes it and converts the callers.
impl From<Error> for String {
    fn from(error: Error) -> String {
        error.to_string()
    }
}
