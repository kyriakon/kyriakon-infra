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
    /// A read failed. `NotFound` is handled by the caller as an absent record,
    /// never as this.
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A lock file or the kernel pool could not be opened.
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A directory or record could not be created.
    Create {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A record could not be placed by rename.
    Place {
        dir: PathBuf,
        source: std::io::Error,
    },
    /// An append could not be written or synced.
    Append {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A record could not be removed.
    Remove {
        dir: PathBuf,
        source: std::io::Error,
    },
    /// An exclusive or non-blocking lock could not be taken.
    Lock {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A descriptor could not be handed to the directory's owner.
    Chown {
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Refused(message) => f.write_str(message),
            Error::Read { path, source } => write!(f, "cannot read {}: {source}", path.display()),
            Error::Open { path, source } => write!(f, "cannot open {}: {source}", path.display()),
            Error::Create { path, source } => {
                write!(f, "cannot create {}: {source}", path.display())
            }
            Error::Place { dir, source } => {
                write!(f, "cannot place a record in {}: {source}", dir.display())
            }
            Error::Append { path, source } => {
                write!(f, "cannot append to {}: {source}", path.display())
            }
            Error::Remove { dir, source } => {
                write!(f, "cannot remove a record in {}: {source}", dir.display())
            }
            Error::Lock { path, source } => write!(f, "cannot lock {}: {source}", path.display()),
            Error::Chown { path, source } => {
                write!(f, "cannot hand {} to its owner: {source}", path.display())
            }
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
            Error::Read { source, .. }
            | Error::Open { source, .. }
            | Error::Create { source, .. }
            | Error::Place { source, .. }
            | Error::Append { source, .. }
            | Error::Remove { source, .. }
            | Error::Lock { source, .. }
            | Error::Chown { source, .. } => Some(source),
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

    /// Whether the message carries a phrase. Temporary while callers that only
    /// inspected prose are converted to match the variant.
    pub fn contains(&self, pattern: &str) -> bool {
        self.to_string().contains(pattern)
    }
}

/// A caller that has not converted yet still returns `Result<_, String>`. The
/// bridge keeps the tree compiling; step 5 deletes it and converts the callers.
impl From<Error> for String {
    fn from(error: Error) -> String {
        error.to_string()
    }
}
