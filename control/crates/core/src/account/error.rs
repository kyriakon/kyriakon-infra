//! The account area's error: one variant per failure state, the fields the
//! sentence needs, and the cause kept for `source()`.
//!
//! The seven submodules share this one enum because they answer to one caller:
//! the account page, the console and the drain all treat a refused account
//! action alike. The variant names the state, not the module, and `Display`
//! composes the operator sentence here rather than at the site.

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::store;

#[derive(Debug)]
pub enum Error {
    /// The store failed while reading or writing an account record.
    Store(store::Error),
    /// The payment ledger failed. The ledger's own error is still flat until
    /// #1012, so it is wrapped whole and forwarded unchanged.
    Ledger(Box<crate::Error>),
    /// The ready notice could not be sent. The mail error is still flat until
    /// #1012, so it is wrapped whole and forwarded unchanged.
    Notice(Box<crate::Error>),
    /// The bundle could not be encrypted. The mail error is still flat until
    /// #1012, so it is wrapped whole and forwarded unchanged.
    Encrypt(Box<crate::Error>),

    // ---- the DNS recipe a body publishes ----
    /// A value the deploy should have substituted is empty.
    EmptyRecipeValue { name: &'static str },
    /// A value is still the tracked file's `REPLACE_ME` placeholder.
    PlaceholderRecipeValue { name: &'static str, value: String },

    // ---- the one-time password ----
    /// A password is shorter than the minimum.
    PasswordTooShort { min: usize },
    /// A password is longer than bcrypt reads.
    PasswordTooLong { max: usize },
    /// A password carries a control character.
    PasswordControlCharacter,
    /// bcrypt did not hash the password.
    HashPassword { source: bcrypt::BcryptError },

    // ---- the written export ----
    /// The box's passwd file could not be read.
    ReadPasswd { path: PathBuf, source: io::Error },
    /// A member's uid or gid in the passwd file is not a number.
    MemberFieldNotNumber {
        username: String,
        field: &'static str,
        path: PathBuf,
    },
    /// A member named by the export is not in the passwd file.
    MemberMissing { username: String, path: PathBuf },
    /// No account record exists for the member.
    NoAccount { username: String },
    /// `accounts/<username>/account.json` did not parse.
    AccountRecordParse {
        username: String,
        source: serde_json::Error,
    },
    /// A path could not be read.
    ReadPath { path: PathBuf, source: io::Error },
    /// A path could not be created.
    CreatePath { path: PathBuf, source: io::Error },
    /// The bundle's stamp directory already exists or could not be made.
    CreateExportStamp { path: PathBuf, source: io::Error },
    /// A bundle file already exists or could not be created exclusively.
    CreateBundleFile { path: PathBuf, source: io::Error },
    /// A mode could not be set on a path.
    SetMode { path: PathBuf, source: io::Error },
    /// A bundle file could not be written.
    WritePath { path: PathBuf, source: io::Error },
    /// A bundle file could not be synced.
    SyncPath { path: PathBuf, source: io::Error },
    /// A bundle path could not be handed to its member.
    HandTo {
        path: PathBuf,
        uid: u32,
        gid: u32,
        source: io::Error,
    },
    /// The export directory is a symlink or a file, not a directory.
    NotDirectory { path: PathBuf },
    /// The export directory belongs to another uid.
    WrongOwner {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    /// A bundle path component is not one directory name.
    BundleComponent { component: String },
    /// The member's tree is not a directory.
    TreeNotDirectory { path: PathBuf },
    /// The member's tree is absent.
    TreeMissing { path: PathBuf, source: io::Error },
    /// The member's published mail key could not be read.
    ReadMailKey {
        username: String,
        path: PathBuf,
        source: io::Error,
    },
    /// The username does not fit the platform's shape.
    UsernameShape { username: String, why: String },
    /// A member has no published key to mail an export to.
    NoMailKey { username: String, path: PathBuf },

    // ---- data-subject requests ----
    /// A date is not `YYYY-MM-DD`.
    DateNotIso { value: String },
    /// A request kind is not one the module accepts.
    UnknownKind {
        kind: String,
        allowed: &'static [&'static str],
    },
    /// A request names no evidence of who was asking.
    MissingEvidence,
    /// An identity route is not one the module accepts.
    UnknownIdentity {
        identity: String,
        allowed: &'static [&'static str],
    },
    /// A request id is not a ULID.
    BadId {
        id: String,
        source: ulid::DecodeError,
    },
    /// The answer due after a date has no date in the calendar.
    NoDueDate { after: String },
    /// A retry carries a request id that is already recorded.
    AlreadyRecorded { id: String },
    /// One request id appears in more than one account.
    AppearsTwice { id: String },
    /// No account holds the request id.
    NoRequest { id: String },
    /// The request belongs to another member.
    WrongRequestAccount {
        id: String,
        owner: String,
        username: String,
    },
    /// A close records no work.
    MissingDone,
    /// The request already carries a close.
    AlreadyClosed { id: String },
    /// The request is closed, so it cannot be extended.
    Closed { id: String },
    /// The request already carries an extension.
    AlreadyExtended { id: String },
    /// An extension records no reason.
    MissingExtensionReason,
    /// The extension's decision date is outside the request's run.
    ExtensionOutside {
        decided: String,
        from: String,
        due: String,
    },
    /// The extended date has no date in the calendar.
    NoExtensionDate { due: String },
    /// A request line could not be encoded.
    WriteRequest { source: serde_json::Error },
    /// A rewritten request record could not be encoded.
    WriteRequestRecord { source: serde_json::Error },

    // ---- sessions ----
    /// The session's token is not the shape the login check mints.
    ProofNotMinted,
    /// The session's proof file is missing or unreadable.
    ProofNotOurs,
    /// The proof names another member.
    ProofBelongsTo { found: String, username: String },
    /// The proof's expiry has passed.
    ProofExpired,
    /// A session timestamp could not be formatted.
    StampSession { source: time::error::Format },
    /// The session record could not be encoded.
    EncodeSession { source: serde_json::Error },
    /// The login check could not be started.
    RunLoginCheck { path: PathBuf, source: io::Error },

    // ---- signing ----
    /// The signing key is not owned by root.
    KeyNotRootOwned { path: PathBuf },
    /// The signing key is readable by group or others.
    KeyReadableByOthers { path: PathBuf },
    /// The signing key file is empty.
    EmptyKey { path: PathBuf },
    /// HMAC rejected the key.
    KeyHmac { source: hmac::digest::InvalidLength },

    // ---- standing transitions ----
    /// The account is not closing.
    NotClosing,
    /// The closure was paid out by a refund.
    ClosureRefunded,
    /// The recorded closing date cannot be read.
    ClosingDateUnreadable,
    /// The record says the closure began from a closure.
    ClosureFromClosure,
    /// The account is not suspended.
    NotSuspended,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Store(error) => error.fmt(f),
            Error::Ledger(error) | Error::Notice(error) | Error::Encrypt(error) => error.fmt(f),
            Error::EmptyRecipeValue { name } => {
                write!(f, "the DNS recipe's {name} is empty")
            }
            Error::PlaceholderRecipeValue { name, value } => write!(
                f,
                "the DNS recipe's {name} is still the placeholder {value:?}"
            ),
            Error::PasswordTooShort { min } => write!(f, "Use at least {min} characters."),
            Error::PasswordTooLong { max } => write!(f, "Use at most {max} characters."),
            Error::PasswordControlCharacter => f.write_str("Use printable characters only."),
            Error::HashPassword { source } => write!(f, "cannot hash the password: {source}"),
            Error::ReadPasswd { path, source } => {
                write!(f, "cannot read the account list {}: {source}", path.display())
            }
            Error::MemberFieldNotNumber {
                username,
                field,
                path,
            } => write!(
                f,
                "the {field} for {username} in {} is not a number",
                path.display()
            ),
            Error::MemberMissing { username, path } => write!(
                f,
                "{username} is not in {}, so the export has no owner to hand the bundle to",
                path.display()
            ),
            Error::NoAccount { username } => write!(f, "no account for {username}"),
            Error::AccountRecordParse { username, source } => write!(
                f,
                "accounts/{username}/account.json does not parse: {source}"
            ),
            Error::ReadPath { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Error::CreatePath { path, source } => {
                write!(f, "cannot create {}: {source}", path.display())
            }
            Error::CreateExportStamp { path, source } => write!(
                f,
                "cannot create {}: {source}; the export directory must not already exist",
                path.display()
            ),
            Error::CreateBundleFile { path, source } => write!(
                f,
                "cannot create {}: {source}; the export does not write over or through an existing name",
                path.display()
            ),
            Error::SetMode { path, source } => {
                write!(f, "cannot set the mode on {}: {source}", path.display())
            }
            Error::WritePath { path, source } => {
                write!(f, "cannot write {}: {source}", path.display())
            }
            Error::SyncPath { path, source } => {
                write!(f, "cannot sync {}: {source}", path.display())
            }
            Error::HandTo {
                path,
                uid,
                gid,
                source,
            } => write!(
                f,
                "cannot hand {} to {uid}:{gid}: {source}",
                path.display()
            ),
            Error::NotDirectory { path } => write!(
                f,
                "{} is not a directory, but a symlink or a file planted in the member's tree; refusing to write the export",
                path.display()
            ),
            Error::WrongOwner {
                path,
                found,
                expected,
            } => write!(
                f,
                "{} is owned by uid {found}, not uid {expected}, the process writing the export; refusing",
                path.display()
            ),
            Error::BundleComponent { component } => write!(
                f,
                "the bundle path component {component:?} is not one directory"
            ),
            Error::TreeNotDirectory { path } => write!(
                f,
                "the member's tree {} is not a directory; refusing to write the export",
                path.display()
            ),
            Error::TreeMissing { path, source } => write!(
                f,
                "the member's tree {} is not there: {source}",
                path.display()
            ),
            Error::ReadMailKey {
                username,
                path,
                source,
            } => write!(
                f,
                "no mail key for {username} at {}: {source}; the account's own key belongs in the export",
                path.display()
            ),
            Error::UsernameShape { username, why } => {
                write!(f, "the username {username:?}: {why}")
            }
            Error::NoMailKey { username, path } => write!(
                f,
                "no public key for {username} at {}, so the written part cannot be sent encrypted.\n\n{}",
                path.display(),
                super::export::reachable()
            ),
            Error::DateNotIso { value } => {
                write!(f, "{value:?} is not a date in YYYY-MM-DD")
            }
            Error::UnknownKind { kind, allowed } => write!(
                f,
                "the kind {kind:?} is not one of {}",
                allowed.join(", ")
            ),
            Error::MissingEvidence => {
                f.write_str("the evidence that established who was asking is needed")
            }
            Error::UnknownIdentity { identity, allowed } => write!(
                f,
                "the identity route {identity:?} is not one of {}",
                allowed.join(", ")
            ),
            Error::BadId { id, source } => write!(f, "the id {id:?}: {source}"),
            Error::NoDueDate { after } => write!(
                f,
                "the answer due after {after} has no date in the calendar"
            ),
            Error::AlreadyRecorded { id } => {
                write!(f, "request {id} is already recorded")
            }
            Error::AppearsTwice { id } => {
                write!(f, "request {id} appears in more than one account")
            }
            Error::NoRequest { id } => write!(f, "no request with id {id}"),
            Error::WrongRequestAccount {
                id,
                owner,
                username,
            } => write!(
                f,
                "the request {id} belongs to {owner}, not {username}"
            ),
            Error::MissingDone => f.write_str("what was done is needed"),
            Error::AlreadyClosed { id } => write!(f, "request {id} is already closed"),
            Error::Closed { id } => write!(f, "request {id} is closed"),
            Error::AlreadyExtended { id } => {
                write!(f, "request {id} is already extended")
            }
            Error::MissingExtensionReason => {
                f.write_str("the reason for the extension is needed")
            }
            Error::ExtensionOutside {
                decided,
                from,
                due,
            } => write!(
                f,
                "the extension is decided on {decided}, but the request runs from {from} to {due}"
            ),
            Error::NoExtensionDate { due } => write!(
                f,
                "the extension of {due} has no date in the calendar"
            ),
            Error::WriteRequest { source } => {
                write!(f, "cannot write the request: {source}")
            }
            Error::WriteRequestRecord { source } => {
                write!(f, "cannot write the request record: {source}")
            }
            Error::ProofNotMinted => {
                f.write_str("the session carries no proof this box minted")
            }
            Error::ProofNotOurs => {
                f.write_str("the session's proof is not one this box minted")
            }
            Error::ProofBelongsTo { found, username } => {
                write!(f, "the session belongs to {found:?}, not {username:?}")
            }
            Error::ProofExpired => {
                f.write_str("the session named by the intent has expired")
            }
            Error::StampSession { source } => {
                write!(f, "cannot stamp the session: {source}")
            }
            Error::EncodeSession { source } => {
                write!(f, "cannot encode the session: {source}")
            }
            Error::RunLoginCheck { path, source } => write!(
                f,
                "cannot run the login check {}: {source}",
                path.display()
            ),
            Error::KeyNotRootOwned { path } => {
                write!(f, "{} is not owned by root", path.display())
            }
            Error::KeyReadableByOthers { path } => write!(
                f,
                "{} is readable by group or others; it must be 0600",
                path.display()
            ),
            Error::EmptyKey { path } => write!(f, "{} is empty", path.display()),
            Error::KeyHmac { source } => write!(f, "cannot key the HMAC: {source}"),
            Error::NotClosing => f.write_str(
                "the account is not closing, so there is no closure to cancel",
            ),
            Error::ClosureRefunded => {
                f.write_str("the closure was paid out by a refund, so it cannot be cancelled")
            }
            Error::ClosingDateUnreadable => f.write_str(
                "the closing date cannot be read, so the closure cannot be cancelled",
            ),
            Error::ClosureFromClosure => {
                f.write_str("the record says the closure began from a closure")
            }
            Error::NotSuspended => f.write_str(
                "the account is not suspended, so there is nothing to resume",
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Store(error) => Some(error),
            Error::Ledger(error) | Error::Notice(error) | Error::Encrypt(error) => Some(error),
            Error::HashPassword { source } => Some(source),
            Error::ReadPasswd { source, .. }
            | Error::ReadPath { source, .. }
            | Error::CreatePath { source, .. }
            | Error::CreateExportStamp { source, .. }
            | Error::CreateBundleFile { source, .. }
            | Error::SetMode { source, .. }
            | Error::WritePath { source, .. }
            | Error::SyncPath { source, .. }
            | Error::HandTo { source, .. }
            | Error::TreeMissing { source, .. }
            | Error::ReadMailKey { source, .. }
            | Error::RunLoginCheck { source, .. } => Some(source),
            Error::AccountRecordParse { source, .. }
            | Error::WriteRequest { source }
            | Error::WriteRequestRecord { source }
            | Error::EncodeSession { source } => Some(source),
            Error::BadId { source, .. } => Some(source),
            Error::StampSession { source } => Some(source),
            Error::KeyHmac { source } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    pub fn report(&self, context: &str) {
        crate::util::report(self, context);
    }
}

impl From<store::Error> for Error {
    fn from(error: store::Error) -> Self {
        Error::Store(error)
    }
}
