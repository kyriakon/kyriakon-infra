//! The mail area's error: one variant per failure state, the fields the
//! sentence needs, and the cause kept for `source()`.
//!
//! The five submodules share this one enum because they answer to one caller:
//! the drain, the handler and the console all treat a refused key, table or
//! notice alike. The variant names the state, not the module, and `Display`
//! composes the operator sentence here rather than at the site.
//!
//! Free text a peer wrote stays a `String`: gpg's stderr and the platform
//! parser's fixed reason are values, not sentences this crate assembles.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;

use crate::store;

#[derive(Debug)]
pub enum Error {
    /// A store read or write failed.
    Store(store::Error),

    // ---- an upload key's shape ----
    /// The account page was handed no upload key at all.
    UploadKeyMissing,
    /// The line is not one of the four OpenSSH public-key forms.
    NotOpenSshKey,
    /// The line names a kind but carries no key blob.
    UploadKeyNoMaterial,
    /// The upload key's blob is not base64.
    UploadKeyNotDecodable,

    // ---- the enqueuer ----
    /// The configured enqueuer could not be started.
    StartEnqueuer { program: String, source: io::Error },
    /// Writing the message to the enqueuer's stdin failed.
    WriteEnqueuer { program: String, source: io::Error },
    /// Closing the enqueuer's stdin failed.
    CloseEnqueuer { program: String, source: io::Error },
    /// Waiting for the enqueuer failed.
    WaitEnqueuer { program: String, source: io::Error },
    /// The enqueuer ran and failed.
    EnqueuerExited { program: String, status: ExitStatus },
    /// A notice line could not be encoded.
    EncodeNotice { source: serde_json::Error },

    // ---- gpg's scratch home ----
    /// The scratch GNUPGHOME could not be created.
    CreateScratchHome { path: PathBuf, source: io::Error },
    /// The scratch GNUPGHOME could not be made owner-only.
    SetScratchMode { path: PathBuf, source: io::Error },
    /// gpg could not import the key file it was given.
    ImportKey { path: PathBuf, stderr: String },

    // ---- gpg's runner ----
    /// gpg could not be started.
    RunGpg { program: String, source: io::Error },
    /// The child's stdout pipe was absent.
    GpgNoStdout,
    /// The child's stderr pipe was absent.
    GpgNoStderr,
    /// Waiting for gpg failed.
    WaitGpg { program: String, source: io::Error },
    /// gpg's stdout could not be drained.
    ReadGpgOutput { program: String, source: io::Error },
    /// gpg's stderr could not be drained.
    ReadGpgError { program: String, source: io::Error },
    /// The message could not be written to gpg's stdin.
    WriteGpg { source: io::Error },
    /// gpg ran past the deadline and was stopped.
    GpgTimedOut { program: String, seconds: u64 },
    /// A signature file could not be written before gpg read it.
    WriteSignature { path: PathBuf, source: io::Error },

    // ---- armour framing ----
    /// The material is not framed as an armoured public key block.
    NotArmoured,
    /// More than one armour block was submitted for one key.
    MultipleArmourBlocks,
    /// The armoured block has no end line.
    ArmourNoEnd,
    /// The armour body is not base64.
    KeyBase64NotDecodable,
    /// The packet headers are a structure this check does not read.
    PacketStructureUnreadable,
    /// The block carries no public key packet.
    NoPublicKeyPacket,
    /// The block carries more than one primary public key.
    MultiplePrimaryKeys,
    /// No fingerprint is defined for the key packet.
    FingerprintUncomputable,
    /// The armoured block carries no key material at all.
    ArmourNoMaterial,

    // ---- clearsigned messages ----
    /// The signature does not verify against the expected key.
    ClearsignedDoesNotVerify,
    /// gpg verified the message but reported no signing fingerprint.
    NoSigningFingerprint,
    /// The verified plaintext is not UTF-8.
    ClearsignedNotUtf8,
    /// The message's headers could not be split from its body.
    HeadersUnreadable {
        source: kyriakon_mailparse::Malformed,
    },
    /// The clearsigned marker is inside a header line.
    MarkerInsideHeader,
    /// The clearsigned block carries a second begin marker before its end.
    SecondSignedMarker,
    /// The clearsigned block has no end line.
    SignedBlockNoEnd,
    /// Text no signature covers sits before the clearsigned block.
    UnsignedText { line: usize, text: String },
    /// The message carries more than one `From:` header.
    MultipleFromHeaders,
    /// The `From:` header holds no address.
    FromHeaderNoAddress,
    /// gpg refused to encrypt to the key file.
    Encrypt { path: PathBuf, stderr: String },

    // ---- the mail tables ----
    /// A file name is not one of the five tables this writer owns.
    UnknownTable { name: String },
    /// A drop mode is not one the writer accepts.
    UnknownDropMode { mode: String },
    /// The table already maps the key elsewhere.
    AlreadyMapped {
        path: PathBuf,
        key: String,
        have: String,
        want: String,
    },
    /// The table already carries the key in the other shape.
    OtherShape { path: PathBuf, key: String },
    /// A drop was given no text to match.
    EmptyDropText,
    /// The platform domain is not a domain.
    PlatformDomain { why: String },
    /// The passwd file could not be read.
    ReadPasswd { path: PathBuf, source: io::Error },
    /// The virtual table could not be read for the sender mapping.
    ReadVirtuals { path: PathBuf, source: io::Error },
    /// A table could not be read.
    ReadTable { path: PathBuf, source: io::Error },
    /// The table's lock file could not be opened.
    OpenLock { path: PathBuf, source: io::Error },
    /// The table's lock could not be taken.
    LockTable { path: PathBuf, source: io::Error },
    /// The table path has no directory to place a candidate in.
    TableNoDirectory { path: PathBuf },
    /// A sibling candidate table could not be created.
    CreateCandidate { path: PathBuf, source: io::Error },
    /// A sibling candidate table could not be written.
    WriteCandidate { path: PathBuf, source: io::Error },
    /// A sibling candidate table's mode could not be set.
    ModeCandidate { path: PathBuf, source: io::Error },
    /// A sibling candidate table could not be synced.
    SyncCandidate { path: PathBuf, source: io::Error },
    /// The candidate could not replace the table.
    ReplaceTable { path: PathBuf, source: io::Error },
    /// A key carries a character a table key cannot.
    NotTableKey { key: String },
    /// A sender line's key is an address, not an account.
    AddressAsSenderKey { key: String },
    /// A mail-domain or DKIM key carries an `@`.
    NotBareDomain { key: String },
    /// An allow-list entry is not an `@domain`.
    NotAllowListEntry { key: String },
    /// An allow-list entry carries more than one `@`.
    NotOneDomain { key: String },
    /// A table value is empty.
    EmptyTableValue,
    /// A virtuals value is an address, not a delivery account.
    NotDeliveryAccount { value: String },
    /// A value carries whitespace or a control character.
    ValueWhitespace { value: String },
    /// A sender list names no address.
    EmptySenderList,
    /// A sender-list value is not an address.
    NotAddress { value: String },

    // ---- delivery-status reports ----
    /// A notice line did not parse.
    NoticeLineNotParsed {
        username: String,
        line: usize,
        source: serde_json::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Store(error) => error.fmt(f),
            Error::UploadKeyMissing => f.write_str("an upload key is needed"),
            Error::NotOpenSshKey => f.write_str("this is not an OpenSSH public key"),
            Error::UploadKeyNoMaterial => f.write_str("the upload key has no key material"),
            Error::UploadKeyNotDecodable => {
                f.write_str("the upload key's material does not decode")
            }
            Error::StartEnqueuer { program, source } => {
                write!(f, "cannot start {program}: {source}")
            }
            Error::WriteEnqueuer { program, source } => {
                write!(f, "cannot write to {program}: {source}")
            }
            Error::CloseEnqueuer { program, source } => {
                write!(f, "cannot close {program}: {source}")
            }
            Error::WaitEnqueuer { program, source } => {
                write!(f, "cannot wait for {program}: {source}")
            }
            Error::EnqueuerExited { program, status } => {
                write!(f, "{program} exited {status}")
            }
            Error::EncodeNotice { source } => {
                write!(f, "cannot encode a notice: {source}")
            }
            Error::CreateScratchHome { path, source } => {
                write!(f, "cannot create {}: {source}", path.display())
            }
            Error::SetScratchMode { path, source } => {
                write!(f, "cannot set the mode on {}: {source}", path.display())
            }
            Error::ImportKey { path, stderr } => {
                write!(f, "gpg could not read {}: {stderr}", path.display())
            }
            Error::RunGpg { program, source } => {
                write!(f, "cannot run {program}: {source}")
            }
            Error::GpgNoStdout => f.write_str("gpg has no stdout"),
            Error::GpgNoStderr => f.write_str("gpg has no stderr"),
            Error::WaitGpg { program, source } => {
                write!(f, "cannot wait for {program}: {source}")
            }
            Error::ReadGpgOutput { program, source } => {
                write!(f, "cannot read {program}'s output: {source}")
            }
            Error::ReadGpgError { program, source } => {
                write!(f, "cannot read {program}'s error: {source}")
            }
            Error::WriteGpg { source } => write!(f, "cannot write to gpg: {source}"),
            Error::GpgTimedOut { program, seconds } => write!(
                f,
                "{program} did not finish within {seconds} seconds and was stopped"
            ),
            Error::WriteSignature { path, source } => {
                write!(f, "cannot write {}: {source}", path.display())
            }
            Error::NotArmoured => f.write_str("this is not an armoured PGP public key block"),
            Error::MultipleArmourBlocks => {
                f.write_str("the material is more than one armoured key block; submit one key")
            }
            Error::ArmourNoEnd => f.write_str("the armoured block has no end line"),
            Error::KeyBase64NotDecodable => f.write_str("the key's base64 does not decode"),
            Error::PacketStructureUnreadable => {
                f.write_str("the key's packet structure cannot be read")
            }
            Error::NoPublicKeyPacket => f.write_str("the block carries no public key packet"),
            Error::MultiplePrimaryKeys => {
                f.write_str("the block carries more than one primary public key; submit one key")
            }
            Error::FingerprintUncomputable => {
                f.write_str("the key's fingerprint cannot be computed")
            }
            Error::ArmourNoMaterial => f.write_str("the armoured block carries no key material"),
            Error::ClearsignedDoesNotVerify => f.write_str(
                "the clearsigned message's signature does not verify against the expected key, \
                 so there is no verified text to show",
            ),
            Error::NoSigningFingerprint => f.write_str(
                "gpg verified the clearsigned message but reported no signing fingerprint",
            ),
            Error::ClearsignedNotUtf8 => {
                f.write_str("the clearsigned message's verified plaintext is not UTF-8")
            }
            Error::HeadersUnreadable { source } => {
                write!(f, "the message's headers cannot be read: {source}")
            }
            Error::MarkerInsideHeader => f.write_str(
                "the clearsigned marker is inside a header line; it must be a line of its own \
                 after the blank line",
            ),
            Error::SecondSignedMarker => {
                f.write_str("the clearsigned block carries a second marker before its end")
            }
            Error::SignedBlockNoEnd => f.write_str("the clearsigned block has no end line"),
            Error::UnsignedText { line, text } => write!(
                f,
                "the message has unsigned text before the clearsigned block, at line {line}: \
                 {text:?}"
            ),
            Error::MultipleFromHeaders => f.write_str("the message has more than one From: header"),
            Error::FromHeaderNoAddress => {
                f.write_str("the message's From: header holds no address")
            }
            Error::Encrypt { path, stderr } => {
                write!(f, "gpg refused to encrypt to {}: {stderr}", path.display())
            }
            Error::UnknownTable { name } => {
                write!(f, "{name:?} is not one of the mail tables this writer owns")
            }
            Error::UnknownDropMode { mode } => {
                write!(f, "{mode:?} is not exact, prefix, suffix or value-suffix")
            }
            Error::AlreadyMapped {
                path,
                key,
                have,
                want,
            } => write!(
                f,
                "{} already maps {key} to {have}, not {want}",
                path.display()
            ),
            Error::OtherShape { path, key } => {
                write!(f, "{} has {key} in the other shape already", path.display())
            }
            Error::EmptyDropText => f.write_str("the drop text is empty"),
            Error::PlatformDomain { why } => write!(f, "the platform domain: {why}"),
            Error::ReadPasswd { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Error::ReadVirtuals { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Error::ReadTable { path, source } => write!(
                f,
                "cannot read {}; run scripts/deploy-mail.sh first: {source}",
                path.display()
            ),
            Error::OpenLock { path, source } => {
                write!(f, "cannot open {}: {source}", path.display())
            }
            Error::LockTable { path, source } => {
                write!(f, "cannot lock {}: {source}", path.display())
            }
            Error::TableNoDirectory { path } => {
                write!(f, "{} has no directory", path.display())
            }
            Error::CreateCandidate { path, source } => {
                write!(f, "cannot create {}: {source}", path.display())
            }
            Error::WriteCandidate { path, source } => {
                write!(f, "cannot write {}: {source}", path.display())
            }
            Error::ModeCandidate { path, source } => {
                write!(f, "cannot mode {}: {source}", path.display())
            }
            Error::SyncCandidate { path, source } => {
                write!(f, "cannot sync {}: {source}", path.display())
            }
            Error::ReplaceTable { path, source } => {
                write!(f, "cannot replace {}: {source}", path.display())
            }
            Error::NotTableKey { key } => write!(f, "{key:?} is not a table key"),
            Error::AddressAsSenderKey { key } => write!(
                f,
                "{key:?} is an address; a sender line's key is an account"
            ),
            Error::NotBareDomain { key } => {
                write!(f, "{key:?} is not a bare domain")
            }
            Error::NotAllowListEntry { key } => {
                write!(f, "{key:?} is not an @domain allow-list entry")
            }
            Error::NotOneDomain { key } => write!(f, "{key:?} is not an @domain"),
            Error::EmptyTableValue => f.write_str("an empty table value"),
            Error::NotDeliveryAccount { value } => {
                write!(f, "{value:?} is not a delivery account")
            }
            Error::ValueWhitespace { value } => {
                write!(f, "{value:?} carries whitespace")
            }
            Error::EmptySenderList => f.write_str("an empty sender list"),
            Error::NotAddress { value } => write!(f, "{value:?} is not an address"),
            Error::NoticeLineNotParsed {
                username,
                line,
                source,
            } => write!(
                f,
                "accounts/{username}/notices.jsonl line {line} is not a notice: {source}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Store(error) => Some(error),
            Error::StartEnqueuer { source, .. }
            | Error::WriteEnqueuer { source, .. }
            | Error::CloseEnqueuer { source, .. }
            | Error::WaitEnqueuer { source, .. }
            | Error::CreateScratchHome { source, .. }
            | Error::SetScratchMode { source, .. }
            | Error::RunGpg { source, .. }
            | Error::WaitGpg { source, .. }
            | Error::ReadGpgOutput { source, .. }
            | Error::ReadGpgError { source, .. }
            | Error::WriteGpg { source }
            | Error::WriteSignature { source, .. }
            | Error::ReadPasswd { source, .. }
            | Error::ReadVirtuals { source, .. }
            | Error::ReadTable { source, .. }
            | Error::OpenLock { source, .. }
            | Error::LockTable { source, .. }
            | Error::CreateCandidate { source, .. }
            | Error::WriteCandidate { source, .. }
            | Error::ModeCandidate { source, .. }
            | Error::SyncCandidate { source, .. }
            | Error::ReplaceTable { source, .. } => Some(source),
            Error::EncodeNotice { source } | Error::NoticeLineNotParsed { source, .. } => {
                Some(source)
            }
            Error::HeadersUnreadable { source } => Some(source),
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
