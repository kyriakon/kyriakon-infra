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
    /// A symlink sits where a record is read.
    SymlinkAtRecord { path: PathBuf },
    /// A symlink or another special file sits where a record is read.
    NotRegularFile { path: PathBuf },
    /// A record name is not one component inside its directory.
    BadRecordName { name: String },
    /// A record the unprivileged handler reads was about to be written without
    /// the group read bit.
    UnreadableByHandler { name: String },
    /// `notices.jsonl`, which the account page lists, was about to be appended
    /// without the group read bit.
    NoticeUnreadableByHandler,
    /// A `.jsonl` name was handed to the record writer.
    AppendOnlyName { name: String },
    /// The record appeared between the caller's read and the write lock.
    AppearedWhileCreating { name: String },
    /// A symlink sits at the temporary a record is placed through.
    SymlinkAtTemporary { path: PathBuf },
    /// A symlink or another special file sits where a log is appended.
    SymlinkAtAppend { path: PathBuf },
    /// A lock is not a regular file with one link.
    LockNotRegularFile { path: PathBuf },
    /// A record's `version` is one this build does not read.
    UnsupportedVersion {
        name: String,
        version: serde_json::Value,
        supported: u64,
    },
    /// A name the store listed has no record behind it.
    ListedAccountMissing { name: String },
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
    Chmod,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SymlinkAtRecord { path } => {
                write!(
                    f,
                    "a symlink is planted at {}; it is not read",
                    path.display()
                )
            }
            Error::NotRegularFile { path } => write!(
                f,
                "a symlink or non-regular file is planted at {}; it is not read",
                path.display()
            ),
            Error::BadRecordName { name } => write!(
                f,
                "{name:?} is not a record name; it must be one component inside its directory"
            ),
            Error::UnreadableByHandler { name } => write!(
                f,
                "{name} is read by the unprivileged handler; write it 0640 through \
                 write_account_record or write_group_state"
            ),
            Error::NoticeUnreadableByHandler => {
                f.write_str("notices.jsonl is read by the unprivileged handler; append it 0640")
            }
            Error::AppendOnlyName { name } => write!(
                f,
                "{name} is an append-only record; Store::rewrite_log is the one write \
                 that completes a line already recorded"
            ),
            Error::AppearedWhileCreating { name } => {
                write!(f, "{name} appeared while it was being created; retry")
            }
            Error::SymlinkAtTemporary { path } => write!(
                f,
                "a symlink is planted at {}; a record is not written through it",
                path.display()
            ),
            Error::SymlinkAtAppend { path } => write!(
                f,
                "a symlink or non-regular file is planted at {}; an append is not written through it",
                path.display()
            ),
            Error::LockNotRegularFile { path } => write!(
                f,
                "the lock {} is not a regular file with one link; it is not used",
                path.display()
            ),
            Error::UnsupportedVersion {
                name,
                version,
                supported,
            } => write!(
                f,
                "{name} is version {version}; this build reads version {supported}"
            ),
            Error::ListedAccountMissing { name } => {
                write!(f, "the account {name} is missing, not counted")
            }
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
                Action::Chmod => write!(f, "cannot set the mode of {}: {source}", path.display()),
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
            Error::Io { source, .. } => Some(source),
            Error::Parse { source, .. }
            | Error::ParseLine { source, .. }
            | Error::Encode { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    /// Print this error and its chain under the service's prefix. The one
    /// reporting function: a journal note, an alert body and a binary's last
    /// line all go through here instead of formatting a sentence at the site.
    pub fn report(&self, context: &str) {
        crate::util::report(self, context);
    }
}
