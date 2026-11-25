//! The groups area's error: one variant per failure state, the fields the
//! sentence needs, and the cause kept for `source()`.
//!
//! Provisioning, the address change and the removal share this enum because
//! they answer to one caller: an operator reads the journal line or the console
//! reply and acts on it. The variant names the state, not the function, and
//! `Display` composes the sentence here rather than at the site.

use std::fmt;
use std::io;
use std::path::PathBuf;

use kyriakon_control_core::flow::Reason;
use kyriakon_control_core::mail::Error as Mail;

/// A group transition's failure. The fields are the values the sentence names,
/// so a caller can read the state back without parsing the text.
#[derive(Debug)]
pub enum Error {
    // ---- the address table a body is made of ----
    /// The table is not a list of `localpart: own` and `localpart: alias target`.
    AddressTable { source: Reason },
    /// The table's line count does not match the account-name count.
    AddressNameCount { addresses: usize, names: usize },
    /// A line is not `localpart: own` or `localpart: alias localpart`.
    AddressLine { line: String },
    /// Two lines name the same localpart.
    AddressTwice { address: String },
    /// Two `own` lines share one account name.
    MailboxNamedByTwo { mailbox: String },
    /// An alias points at a localpart no `own` line makes.
    AliasTargetMissing { address: String, target: String },

    // ---- the site owner ----
    /// The table names no mailbox at all, so no account owns the site.
    NoMailbox,
    /// The site owner the intent names is not one of its mailboxes.
    SiteOwnerNotMailbox { owner: String },
    /// The site owner is leaving and the intent names no account to take it.
    SiteOwnerNeedsReplacement { mailbox: String },
    /// The replacement site owner is not another mailbox in the group.
    ReplacementNotMailbox { replacement: String },
    /// The site owner is leaving at apply time with no replacement left.
    NoReplacement,

    // ---- a mailbox name the group may not take ----
    /// A removed mailbox's name is held for ninety days.
    NameHeld { mailbox: String, until: String },
    /// The account name is already in the store.
    NameTaken { mailbox: String },
    /// The name is already in use on the box, made by somebody else.
    NameInUseOnBox { mailbox: String },
    /// The username does not pass the platform's own name rules.
    InvalidUsername { username: String, source: Reason },
    /// The mailbox name does not pass the platform's own name rules.
    InvalidMailbox { mailbox: String, source: Reason },

    // ---- an intent of the wrong shape ----
    /// The file is not a `provision-group` intent.
    NotAGroupIntent { kind: String },
    /// The file is not a `group-address` intent.
    NotAnAddressIntent { kind: String },
    /// The file is not a `remove-group` intent.
    NotARemoveGroupIntent { kind: String },
    /// The action is not one of the address changes.
    NotAnAddressChange { action: String },

    // ---- the domain and its mail ----
    /// The platform's own domain cannot be read from `mail_domains`.
    NoPlatformDomain { path: String },
    /// The domain does not pass the platform's own domain rules.
    InvalidDomain { domain: String, source: Reason },
    /// The intent names no mailbox, so there is nothing to make.
    NoMailboxToProvision,
    /// One mailbox is named more than once.
    MailboxNamedTwice { mailbox: String },
    /// The address does not pass the platform's own localpart rules.
    InvalidAddress { address: String, source: Reason },
    /// An address points at a mailbox the intent does not name.
    AddressPointsOutside {
        address: String,
        domain: String,
        mailbox: String,
    },
    /// The group record's version is not one this build reads.
    GroupVersion { domain: String, version: u32 },
    /// The account is not a mailbox in this group's record.
    AccountNotMailbox { mailbox: String, domain: String },

    // ---- a mail key ----
    /// A mailbox has no mail key, so its mail would bounce.
    MailboxNoMailKey { mailbox: String },
    /// A mailbox has more than the one key it may carry.
    MailboxSeveralKeys { mailbox: String, keys: usize },
    /// The key material does not parse.
    MailKeyUnreadable { mailbox: String, source: Mail },
    /// The key names a mailbox other than the one it is for.
    MailKeyNamesOther { mailbox: String, named: String },
    /// The key material is empty.
    MailKeyEmpty { mailbox: String },
    /// The shared check refuses the key.
    MailKeyUnusable { mailbox: String, source: Reason },
    /// No fingerprint can be derived from the material.
    MailKeyNoFingerprint { mailbox: String },

    // ---- the address change against the tables ----
    /// The alias points at a mailbox the group does not hold.
    AliasPointsOutside {
        address: String,
        domain: String,
        mailbox: String,
    },
    /// The virtual table maps the address to another mailbox.
    AddressPointsOther {
        path: String,
        entry: String,
        have: String,
        mailbox: String,
    },
    /// The domain already carries the ten addresses the cap allows.
    AddressCapReached { domain: String, entry: String },
    /// The address is not in the domain, so there is no alias to upgrade.
    NotAnAddressToUpgrade { entry: String, domain: String },
    /// The address points at a mailbox the group does not hold.
    AddressPointsOutsideGroup { entry: String, mailbox: String },

    // ---- records a pass needs and cannot find ----
    /// No account record exists for the mailbox.
    MailboxNoAccountRecord { mailbox: String },
    /// The group intent names no application status token.
    NoApplicationToken,
    /// The account went between this pass's read and its lock.
    AccountVanishedMidWrite { mailbox: String },

    // ---- files and the platform ----
    /// The passwd file could not be read.
    ReadPasswd { path: String, source: io::Error },
    /// The application copy does not parse.
    ApplicationUnreadable { source: serde_json::Error },
    /// The group's directory could not be removed.
    RemoveGroupDir { path: PathBuf, source: io::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AddressTable { source } => write!(f, "the address table: {source}"),
            Error::AddressNameCount { addresses, names } => write!(
                f,
                "{addresses} addresses and {names} account names; there is one name per address"
            ),
            Error::AddressLine { line } => write!(
                f,
                "the address line {line:?} is not localpart: own or localpart: alias localpart"
            ),
            Error::AddressTwice { address } => {
                write!(f, "the address {address} is in the table twice")
            }
            Error::MailboxNamedByTwo { mailbox } => write!(
                f,
                "the mailbox {mailbox} is named by two mailboxes; an alias shares a mailbox \
                 instead"
            ),
            Error::AliasTargetMissing { address, target } => write!(
                f,
                "the address {address} is an alias into {target}, which is not a mailbox in the \
                 table"
            ),
            Error::NoMailbox => {
                f.write_str("the address table names no mailbox, so no account owns the site")
            }
            Error::SiteOwnerNotMailbox { owner } => {
                write!(f, "the site owner {owner} is not one of the mailboxes")
            }
            Error::SiteOwnerNeedsReplacement { mailbox } => write!(
                f,
                "{mailbox} owns the site, so the intent must name the account that takes it"
            ),
            Error::ReplacementNotMailbox { replacement } => write!(
                f,
                "the replacement site owner {replacement} is not another mailbox in the group"
            ),
            Error::NoReplacement => f.write_str("the site owner is leaving without a replacement"),
            Error::NameHeld { mailbox, until } => write!(
                f,
                "the account name {mailbox} is held until {until}, so it cannot be reused yet"
            ),
            Error::NameTaken { mailbox } => {
                write!(f, "the account name {mailbox} is already taken")
            }
            Error::NameInUseOnBox { mailbox } => {
                write!(
                    f,
                    "the account name {mailbox} is already in use on this box"
                )
            }
            Error::InvalidUsername { username, source } => {
                write!(f, "the username {username}: {source}")
            }
            Error::InvalidMailbox { mailbox, source } => {
                write!(f, "the mailbox {mailbox:?}: {source}")
            }
            Error::NotAGroupIntent { kind } => {
                write!(f, "kind {kind:?} is not a group intent")
            }
            Error::NotAnAddressIntent { kind } => {
                write!(f, "kind {kind:?} is not an address intent")
            }
            Error::NotARemoveGroupIntent { kind } => {
                write!(f, "kind {kind:?} is not a remove-group intent")
            }
            Error::NotAnAddressChange { action } => {
                write!(f, "{action:?} is not an address change")
            }
            Error::NoPlatformDomain { path } => write!(
                f,
                "{path} has no first line, so the platform's own domain is unknown"
            ),
            Error::InvalidDomain { domain, source } => {
                write!(f, "the domain {domain:?}: {source}")
            }
            Error::NoMailboxToProvision => {
                f.write_str("the intent names no mailbox, so there is nothing to provision")
            }
            Error::MailboxNamedTwice { mailbox } => {
                write!(f, "the mailbox {mailbox} is named twice")
            }
            Error::InvalidAddress { address, source } => {
                write!(f, "the address {address:?}: {source}")
            }
            Error::AddressPointsOutside {
                address,
                domain,
                mailbox,
            } => write!(
                f,
                "the address {address}@{domain} points at {mailbox}, which is not a mailbox"
            ),
            Error::GroupVersion { domain, version } => write!(
                f,
                "groups/{domain}/group.json has version {version}, which this build does not read"
            ),
            Error::AccountNotMailbox { mailbox, domain } => {
                write!(f, "the account {mailbox} is not a mailbox in {domain}")
            }
            Error::MailboxNoMailKey { mailbox } => write!(
                f,
                "the mailbox {mailbox} has no mail key, so its mail would bounce"
            ),
            Error::MailboxSeveralKeys { mailbox, keys } => write!(
                f,
                "the mailbox {mailbox} has {keys} keys; there is one key per mailbox"
            ),
            Error::MailKeyUnreadable { mailbox, source } => {
                write!(f, "the mail key for {mailbox}: {source}")
            }
            Error::MailKeyNamesOther { mailbox, named } => {
                write!(f, "the mail key names {named}, not {mailbox}")
            }
            Error::MailKeyEmpty { mailbox } => {
                write!(f, "the mail key for {mailbox} is empty")
            }
            Error::MailKeyUnusable { mailbox, source } => {
                write!(f, "the mail key for {mailbox} cannot be used: {source}")
            }
            Error::MailKeyNoFingerprint { mailbox } => write!(
                f,
                "the mail key for {mailbox} has no fingerprint this build can derive"
            ),
            Error::AliasPointsOutside {
                address,
                domain,
                mailbox,
            } => write!(
                f,
                "the alias {address}@{domain} points at {mailbox}, which is not a mailbox in the \
                 group"
            ),
            Error::AddressPointsOther {
                path,
                entry,
                have,
                mailbox,
            } => write!(f, "{path} already maps {entry} to {have}, not {mailbox}"),
            Error::AddressCapReached { domain, entry } => write!(
                f,
                "{domain} already carries ten addresses, so {entry} cannot be added"
            ),
            Error::NotAnAddressToUpgrade { entry, domain } => write!(
                f,
                "{entry} is not an address in {domain}, so there is no alias to upgrade"
            ),
            Error::AddressPointsOutsideGroup { entry, mailbox } => write!(
                f,
                "{entry} points at {mailbox}, which is not a mailbox in the group"
            ),
            Error::MailboxNoAccountRecord { mailbox } => {
                write!(f, "the mailbox {mailbox} has no account record")
            }
            Error::NoApplicationToken => f.write_str("the group intent names no application token"),
            Error::AccountVanishedMidWrite { mailbox } => write!(
                f,
                "{mailbox} went while its group mailbox was being written"
            ),
            Error::ReadPasswd { path, source } => {
                write!(f, "cannot read {path}: {source}")
            }
            Error::ApplicationUnreadable { source } => {
                write!(f, "the application record: {source}")
            }
            Error::RemoveGroupDir { path, source } => {
                write!(f, "cannot remove {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::MailKeyUnreadable { source, .. } => Some(source),
            Error::AddressTable { source } => Some(source),
            Error::InvalidUsername { source, .. }
            | Error::InvalidMailbox { source, .. }
            | Error::InvalidDomain { source, .. }
            | Error::InvalidAddress { source, .. }
            | Error::MailKeyUnusable { source, .. } => Some(source),
            Error::ReadPasswd { source, .. } => Some(source),
            Error::ApplicationUnreadable { source } => Some(source),
            Error::RemoveGroupDir { source, .. } => Some(source),
            _ => None,
        }
    }
}
