//! The review area's error: one variant per failure state, the fields the
//! sentence needs, and the cause kept for `source()`.
//!
//! The review and the decision paths share this enum because they answer to one
//! caller: the operator reads the journal line or the console reply and acts on
//! it. The variant names the state, not the function, and `Display` composes
//! the sentence here rather than at the site.

use std::fmt;

use kyriakon_control_core::payments::Error as Payments;

#[derive(Debug)]
pub enum Error {
    // ---- an intent of the wrong shape ----
    /// The file is not an application intent.
    NotAnApplication { kind: String },
    /// The application's status token is absent or not 128 bits of Crockford.
    StatusTokenInvalid,
    /// The application's rail is not one the platform supports.
    UnknownRail { rail: String },
    /// The file is not a decision intent.
    NotADecision { kind: String },
    /// The decision intent names no status token.
    DecisionNoStatusToken,

    // ---- a decision the record no longer agrees with ----
    /// The decision's username is not the application record's.
    IntentUsernameMismatch,
    /// The decision's signature does not verify against the record acted on.
    SignatureDoesNotVerify,
    /// This application's approval began under another name.
    ApprovalBeganForOtherName { started: String, username: String },

    // ---- a name the approval may not take ----
    /// The name is a group's mailbox, not this application's person account.
    AccountBelongsToGroup { username: String },
    /// A removed group holds the name for ninety days.
    NameHeld { username: String, until: String },
    /// Somebody else's account already holds the name on the box.
    NameInUseOnBox { username: String },

    // ---- the application's keys ----
    /// A mail key names a mailbox other than the account being approved.
    MailKeyNamesOtherMailbox { mailbox: String, username: String },
    /// A mail key is not usable as a key.
    MailKeyUnusable { why: String },

    // ---- the record an approval acts on ----
    /// The application record is gone after the approval began.
    ApplicationRecordVanishedMidApproval,
    /// A supplied account carries no password link to mail.
    NoPasswordLink,
    /// A body's application names no domain.
    ApplicationNoDomain,
    /// A body's domain is not a domain.
    InvalidDomain { domain: String, why: String },
    /// A group already exists that this application did not make.
    GroupExistsNotMade { domain: String },
    /// A group mailbox has no mail key, so its mail would bounce.
    MailboxNoMailKey { mailbox: String },

    // ---- the group approval ----
    /// The group intent this pass filed is gone.
    FiledIntentGone { filename: String },
    /// The group record is gone after the approval began.
    GroupRecordVanishedMidApproval,
    /// A group card approval has no configured Stripe link.
    GroupCardLink { source: Payments },
    /// A group mailbox has no account record to read its link from.
    MailboxNoAccountRecord { mailbox: String },
    /// A group mailbox has no password link to mail.
    MailboxNoPasswordLink { mailbox: String },

    // ---- supplying a held account ----
    /// A held account has no hold date.
    HeldAccountNoHoldDate,
    /// The held account's hold date does not parse.
    HoldDateUnreadable { hold: String },
    /// A held account has no application copy to supply it from.
    HeldAccountNoApplication { username: String },
    /// The approval copy under a name names another account.
    ApprovalCopyNamesOther { username: String, named: String },

    // ---- a decline ----
    /// The address outside the platform is not a mail address.
    InvalidOutsideAddress { address: String, why: String },

    // ---- the record a verb names ----
    /// No application exists for the token.
    NoApplicationForToken,
    /// The application record is gone when the decision tries to write it.
    ApplicationVanishedBeforeDecision,

    // ---- a charged approval's payment block ----
    /// A charged approval has no payment block.
    ChargedApprovalNoPayment,
    /// A charged approval has no payment token.
    ChargedApprovalNoToken,
    /// A charged approval has no payment window.
    ChargedApprovalNoWindow,

    // ---- `token resend` ----
    /// No account record exists for the name.
    NoAccount { username: String },
    /// A free account has no payment token to resend.
    NoChargeNoToken { username: String },
    /// The resend names a token the account does not hold.
    TokenMismatch { username: String },
    /// No application record exists for the account.
    NoApplicationRecord { username: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAnApplication { kind } => {
                write!(f, "kind {kind:?} is not an application")
            }
            Error::StatusTokenInvalid => {
                f.write_str("the status token is not 128 bits of Crockford")
            }
            Error::UnknownRail { rail } => {
                write!(f, "the rail {rail:?} is not one of the four")
            }
            Error::NotADecision { kind } => write!(f, "kind {kind:?} is not a decision"),
            Error::DecisionNoStatusToken => f.write_str("the decision names no status token"),
            Error::IntentUsernameMismatch => {
                f.write_str("the intent's username is not the application's")
            }
            Error::SignatureDoesNotVerify => {
                f.write_str("the decision intent's signature does not verify against this record")
            }
            Error::ApprovalBeganForOtherName { started, username } => write!(
                f,
                "this application's approval began for {started}, not {username}; the intent is \
                 left in place"
            ),
            Error::AccountBelongsToGroup { username } => write!(
                f,
                "the account {username} belongs to a group, not to this application; the intent \
                 is left in place"
            ),
            Error::NameHeld { username, until } => write!(
                f,
                "the username {username} is held until {until}, so it cannot be reused yet"
            ),
            Error::NameInUseOnBox { username } => write!(
                f,
                "the username {username} is already in use on this box and this application did \
                 not create it; the intent is left in place"
            ),
            Error::MailKeyNamesOtherMailbox { mailbox, username } => write!(
                f,
                "the application's mail key names the mailbox {mailbox:?}, not the account \
                 {username}"
            ),
            Error::MailKeyUnusable { why } => {
                write!(f, "the application's mail key cannot be used: {why}")
            }
            Error::ApplicationRecordVanishedMidApproval => {
                f.write_str("the application record vanished mid-approval")
            }
            Error::NoPasswordLink => f.write_str("a supplied account has no password link"),
            Error::ApplicationNoDomain => f.write_str("the application names no domain"),
            Error::InvalidDomain { domain, why } => {
                write!(f, "the domain {domain:?}: {why}")
            }
            Error::GroupExistsNotMade { domain } => write!(
                f,
                "the domain {domain} already has a group that this application did not make"
            ),
            Error::MailboxNoMailKey { mailbox } => write!(
                f,
                "the mailbox {mailbox} has no mail key, so its mail would bounce"
            ),
            Error::FiledIntentGone { filename } => {
                write!(f, "the intent this pass filed at {filename} is gone")
            }
            Error::GroupRecordVanishedMidApproval => {
                f.write_str("the group record vanished mid-approval")
            }
            Error::GroupCardLink { .. } => f.write_str(
                "stripe_group_payment_link is not configured, so a group card approval has no \
                 link to send",
            ),
            Error::MailboxNoAccountRecord { mailbox } => {
                write!(f, "the mailbox {mailbox} has no account record")
            }
            Error::MailboxNoPasswordLink { mailbox } => {
                write!(f, "the mailbox {mailbox} has no password link")
            }
            Error::HeldAccountNoHoldDate => f.write_str("a held account has no hold date"),
            Error::HoldDateUnreadable { hold } => {
                write!(f, "the hold date {hold:?} cannot be read")
            }
            Error::HeldAccountNoApplication { username } => write!(
                f,
                "the held account {username} has no application copy to supply it from"
            ),
            Error::ApprovalCopyNamesOther { username, named } => {
                write!(f, "the approval copy under {username} names {named}")
            }
            Error::InvalidOutsideAddress { address, why } => {
                write!(f, "the address outside the platform {address:?}: {why}")
            }
            Error::NoApplicationForToken => f.write_str("there is no application for this token"),
            Error::ApplicationVanishedBeforeDecision => {
                f.write_str("the application record vanished before it could be decided")
            }
            Error::ChargedApprovalNoPayment => {
                f.write_str("a charged approval has no payment block")
            }
            Error::ChargedApprovalNoToken => f.write_str("a charged approval has no token"),
            Error::ChargedApprovalNoWindow => f.write_str("a charged approval has no window"),
            Error::NoAccount { username } => write!(f, "no account for {username}"),
            Error::NoChargeNoToken { username } => write!(
                f,
                "{username} was approved without charge, so there is no payment token to resend"
            ),
            Error::TokenMismatch { username } => write!(
                f,
                "the token the resend names is not the one {username}'s account holds"
            ),
            Error::NoApplicationRecord { username } => {
                write!(f, "no application record for {username}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::GroupCardLink { source } => Some(source),
            _ => None,
        }
    }
}
