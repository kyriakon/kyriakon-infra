//! The lifecycle area's error: one variant per failure state, the fields the
//! sentence needs, and the cause kept for `source()`.
//!
//! The sweep and the account page share this enum because they answer to one
//! caller: an operator reads the journal line or the console reply and acts on
//! it. The variant names the state, not the function, and `Display` composes
//! the sentence here rather than at the site.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;

use kyriakon_control_core::account::state::Standing;
use time::error::Parse as TimeParse;

use crate::transitions::Error as Transitions;

#[derive(Debug)]
pub enum Error {
    // ---- the record a verb names ----
    /// No account record exists for the name.
    NoAccount { username: String },
    /// No group record exists for the domain.
    NoGroup { domain: String },
    /// The account record the transition needs is absent.
    AccountRecordMissing { username: String },
    /// A name is not a valid account name.
    InvalidUsername { username: String, why: String },
    /// A name is not a valid domain.
    InvalidDomain { domain: String, why: String },
    /// An address is not a valid mail address.
    InvalidAddress { address: String, why: String },

    // ---- restarting a grace clock ----
    /// The account is in a standing with no grace clock to restart.
    NoGraceClock {
        username: String,
        standing: Standing,
    },
    /// The account owns more than one lapsed group, so the notice needs a name.
    SeveralLapsedGroups {
        username: String,
        domains: Vec<String>,
    },
    /// The group belongs to another site owner.
    NotOwnGroup { domain: String, username: String },
    /// The group asked for no charge, so it has no grace clock.
    NoCharge { domain: String },
    /// The group's payment window is not closed, so it has no grace clock.
    WindowNotClosed { domain: String },
    /// The group has no grace date to restart.
    NoGraceDate { domain: String },
    /// The account is not suspended, so there is nothing to resume.
    NotSuspended { username: String },
    /// A suspension was asked for without the reason the member will read.
    SuspensionReasonEmpty,
    /// The notices to the account have not all hard-bounced, so there is no
    /// delivery report to hold the grace clock on.
    NoHardBounce { username: String },
    /// A lapsed account has no payment window to describe.
    LapsedNoWindow,

    // ---- a date in a record that does not parse ----
    /// The account's payment window close date does not parse.
    WindowCloseDateUnreadable { closes_at: String, username: String },
    /// The group's payment window close date does not parse.
    GroupWindowCloseDateUnreadable { closes_at: String, domain: String },
    /// The account's grace date does not parse.
    GraceDateUnreadable { grace: String, username: String },
    /// The group's grace date does not parse.
    GroupGraceDateUnreadable { grace: String, domain: String },

    // ---- a group notice with no addressee ----
    /// The site owner's record is gone, so the group has no addressee.
    SiteOwnerGone { owner: String, domain: String },
    /// The site owner's address could not be read, so the group notice has no
    /// addressee. The wrapped transition error is forwarded unchanged.
    NoAddressee {
        domain: String,
        source: Box<Transitions>,
    },

    // ---- an intent of the wrong kind ----
    /// The file is not a close intent.
    NotCloseIntent { kind: String },
    /// The file is not a cancel-close intent.
    NotCancelCloseIntent { kind: String },
    /// The password intent carries no status token.
    PasswordNoStatusToken,

    // ---- a key replacement ----
    /// The pending key's fingerprint is not the one the material reads as.
    FingerprintMismatch { pending: String, read: String },

    // ---- files, scripts and the platform ----
    /// A keyring file could not be removed.
    RemoveFile { path: PathBuf, source: io::Error },
    /// A keyring file could not be read.
    ReadKeyFile { path: PathBuf, source: io::Error },
    /// The pending rotation's window does not parse.
    RotationWindowUnparseable { username: String, source: TimeParse },
    /// The resolver command could not be started.
    RunResolver { resolver: String, source: io::Error },
    /// The resolver ran but could not answer the record.
    ResolverUnavailable {
        resolver: String,
        name: String,
        record_type: String,
        stderr: String,
    },
    /// The quota report command could not be started.
    ReadQuota { repquota: String, source: io::Error },
    /// The quota report command ran and failed.
    QuotaExited {
        repquota: String,
        status: ExitStatus,
    },

    // ---- the purge sweeps ----
    /// The record's token names another file, so the record is skipped.
    ApplicationNamesAnotherToken { name: String },
    /// A declined record's username is not usable, so the record is skipped.
    DeclinedNoUsername { name: String },
    /// An abandoned application's username is not usable, so it is skipped.
    ApplicationNoUsername { name: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoAccount { username } => write!(f, "no account for {username}"),
            Error::NoGroup { domain } => write!(f, "no group for {domain}"),
            Error::AccountRecordMissing { username } => {
                write!(f, "accounts/{username}/account.json is missing")
            }
            Error::InvalidUsername { username, why } => {
                write!(f, "the username {username:?}: {why}")
            }
            Error::InvalidDomain { domain, why } => write!(f, "the domain {domain:?}: {why}"),
            Error::InvalidAddress { address, why } => {
                write!(f, "the address {address:?}: {why}")
            }
            Error::NoGraceClock { username, standing } => write!(
                f,
                "{username} is {standing}, so it has no grace clock to restart"
            ),
            Error::SeveralLapsedGroups { username, domains } => write!(
                f,
                "{username} owns more than one lapsed group ({}); name one with --group",
                domains.join(", ")
            ),
            Error::NotOwnGroup { domain, username } => write!(
                f,
                "{domain} is not {username}'s group, so this account cannot clear its stop"
            ),
            Error::NoCharge { domain } => {
                write!(
                    f,
                    "{domain} has no charge, so it has no grace clock to restart"
                )
            }
            Error::WindowNotClosed { domain } => write!(
                f,
                "{domain}'s payment window is not closed, so it has no grace clock to restart"
            ),
            Error::NoGraceDate { domain } => {
                write!(
                    f,
                    "{domain} has no grace date, so it has no clock to restart"
                )
            }
            Error::NotSuspended { username } => {
                write!(
                    f,
                    "{username} is not suspended, so there is nothing to resume"
                )
            }
            Error::SuspensionReasonEmpty => {
                f.write_str("a suspension needs a reason, in the words the member will read")
            }
            Error::NoHardBounce { username } => write!(
                f,
                "the lifecycle notices to {username} have not all hard-bounced, so there is no \
                 delivery report to hold it on"
            ),
            Error::LapsedNoWindow => f.write_str("a lapsed account has no window"),
            Error::WindowCloseDateUnreadable {
                closes_at,
                username,
            } => write!(
                f,
                "the payment window's close date {closes_at:?} cannot be read, so {username} was \
                 not swept"
            ),
            Error::GroupWindowCloseDateUnreadable { closes_at, domain } => write!(
                f,
                "the group's payment window close date {closes_at:?} cannot be read, so {domain} \
                 was not swept"
            ),
            Error::GraceDateUnreadable { grace, username } => write!(
                f,
                "the grace date {grace:?} cannot be read, so {username} was not swept"
            ),
            Error::GroupGraceDateUnreadable { grace, domain } => write!(
                f,
                "the group's grace date {grace:?} cannot be read, so {domain} was not swept"
            ),
            Error::SiteOwnerGone { owner, domain } => write!(
                f,
                "the site owner record for {owner} is gone, so the group {domain} has no \
                 addressee; its member accounts are deleted under their own notices before the \
                 group record goes"
            ),
            Error::NoAddressee { domain, source } => {
                write!(f, "{source}, so {domain}'s group notice has no addressee")
            }
            Error::NotCloseIntent { kind } => {
                write!(f, "kind {kind:?} is not a close intent")
            }
            Error::NotCancelCloseIntent { kind } => {
                write!(f, "kind {kind:?} is not a cancel-close intent")
            }
            Error::PasswordNoStatusToken => {
                f.write_str("the password intent names no status token")
            }
            Error::FingerprintMismatch { pending, read } => write!(
                f,
                "the pending key's fingerprint is {pending} and the key reads as {read}"
            ),
            Error::RemoveFile { path, source } => {
                write!(f, "cannot remove {}: {source}", path.display())
            }
            Error::ReadKeyFile { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Error::RotationWindowUnparseable { username, source } => write!(
                f,
                "the rotation window of {username} does not parse: {source}"
            ),
            Error::RunResolver { resolver, source } => {
                write!(f, "cannot run the resolver {resolver}: {source}")
            }
            Error::ResolverUnavailable {
                resolver,
                name,
                record_type,
                stderr,
            } => write!(
                f,
                "the resolver {resolver} could not answer {name} {record_type}: {stderr}"
            ),
            Error::ReadQuota { repquota, source } => {
                write!(f, "cannot read the quota with {repquota}: {source}")
            }
            Error::QuotaExited { repquota, status } => {
                write!(f, "{repquota} exited {status}")
            }
            Error::ApplicationNamesAnotherToken { name } => {
                write!(f, "application {name} names another token; skipped")
            }
            Error::DeclinedNoUsername { name } => {
                write!(f, "declined record {name} has no usable username; skipped")
            }
            Error::ApplicationNoUsername { name } => {
                write!(f, "application {name} has no usable username; skipped")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::NoAddressee { source, .. } => Some(source.as_ref()),
            Error::RemoveFile { source, .. } => Some(source),
            Error::ReadKeyFile { source, .. } => Some(source),
            Error::RotationWindowUnparseable { source, .. } => Some(source),
            Error::RunResolver { source, .. } => Some(source),
            Error::ReadQuota { source, .. } => Some(source),
            _ => None,
        }
    }
}
