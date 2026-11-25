//! The console's error: the command line, a refusal, the store, and the few
//! I/O edges the operator sees.
//!
//! One variant per failure state, the fields the sentence needs, and the cause
//! kept for `source()`. `Display` composes the operator's sentence here rather
//! than at the site, so a log line or a test reads the variant and its data.

use std::fmt;
use std::io;
use std::path::PathBuf;

use kyriakon_control_core::account;
use kyriakon_control_core::config;
use kyriakon_control_core::intent;
use kyriakon_control_core::mail;
use kyriakon_control_core::store;
use kyriakon_control_core::util;

#[derive(Debug)]
pub enum Error {
    // ---- the command line ----
    /// The command line is not one the console reads; the usage is printed.
    Usage,
    /// `--config` was given with no path after it.
    ConfigPathMissing,
    /// An argument is not a `--flag value` pair.
    UnexpectedArgument { argument: String },
    /// A flag the subcommand does not take.
    UnknownFlag { flag: String },
    /// A flag with no value after it.
    NeedsValue { flag: String },
    /// The same flag twice, where a typo would silently replace a value.
    Duplicate { flag: String },
    /// A flag the subcommand needs was not given.
    MissingFlag { flag: String },

    // ---- a value a record or the command names ----
    /// A name is not a valid account name.
    InvalidUsername { username: String, why: String },
    /// A domain is not a valid domain.
    InvalidDomain { domain: String, why: String },
    /// A mailbox name is not a valid account name.
    InvalidMailbox { mailbox: String, why: String },
    /// An address localpart is not a valid one.
    InvalidAddress { address: String, why: String },
    /// A site owner is not a valid account name.
    InvalidSiteOwner { owner: String, why: String },
    /// A pasted Monero address is not a subaddress.
    InvalidMoneroAddress { address: String, why: String },
    /// An address action the intent vocabulary does not know.
    UnknownAction { action: String },

    // ---- the account a verb names ----
    /// No account record exists for the name.
    NoAccount { username: String },
    /// No application record exists for the name.
    NoApplication { username: String },
    /// A resume left the account lapsed because its payment window is closed.
    ResumeLeftLapsed { username: String },

    // ---- an address change ----
    /// A removal may not also name the one address to keep.
    AddressOnRemoval {
        address: String,
        mailbox: String,
        domain: String,
    },
    /// A removal was asked for without the confirmation switch.
    ConfirmRequired { mailbox: String, domain: String },
    /// `--confirm-remove` was given on a change that adds something.
    ConfirmOnlyForRemove,
    /// A non-removal change carries no `--address`.
    AddressMissing,
    /// The mail key file could not be read.
    MailKeyUnreadable { path: PathBuf, source: io::Error },
    /// The mail key file is empty.
    MailKeyEmpty { path: PathBuf },
    /// The mail key block does not parse.
    MailKeyInvalid { path: PathBuf, source: mail::Error },
    /// The mail key parses but does not meet the page's own conditions.
    MailKeyRefused { mailbox: String, why: String },
    /// The mail key carries no key packet.
    MailKeyNoPacket { path: PathBuf },
    /// A new mailbox was filed without its public key.
    MailKeyMissing,

    // ---- a decision ----
    /// The token is not the status-token shape the store mints.
    NotStatusToken { token: String },
    /// No application record exists at the token.
    NoApplicationAtToken { token: String },
    /// The application at the token names another account.
    TokenForOtherUser {
        token: String,
        actual: String,
        expected: String,
    },
    /// The application record changed after the review mail.
    RecordChanged { changed: String },

    // ---- the payment block a verb resolves ----
    /// The account was approved without charge, so it has no payment token.
    NoChargeToken { username: String },
    /// The account holds no payment token.
    NoPaymentToken { username: String },
    /// No group record exists for the domain.
    NoGroup { domain: String },
    /// The group holds no payment token.
    GroupNoPaymentToken { domain: String },
    /// The token is not the payment-token shape the store mints.
    NotPaymentToken { token: String },
    /// Both a token and a username were given where one is needed.
    TokenAndUsername,
    /// Neither a token nor a username was given.
    TokenOrUsernameMissing,
    /// `--note` is present but empty.
    NoteEmpty,
    /// `--note` was given with a token or a username.
    NoteWithToken,
    /// Neither a token, a username nor a note names the payment.
    AccountReferenceMissing,

    // ---- a credit ----
    /// A rail the credit vocabulary does not know.
    UnknownCreditRail { rail: String },
    /// A hand payment was given a note instead of a username.
    CashHandWithNote,
    /// The amount is zero.
    AmountNotPositive,
    /// The amount is not sterling.
    AmountUnreadable { source: util::Error },
    /// The received date is not `YYYY-MM-DD`.
    ReceivedInvalid { received: String },
    /// The received date is beyond the drain's ceiling.
    ReceivedBeyondWindow { received: String },
    /// The transaction id is not a Monero one.
    TxidInvalid,
    /// The Monero amount is not a decimal amount.
    XmrInvalid,
    /// A rate was given on a rail other than Monero.
    CreditRateOnlyMonero,
    /// The rate is not a positive decimal amount.
    RateInvalid { rate: String },

    // ---- a refund ----
    /// A settlement was given a flag that belongs to a refund.
    SettledFlagNotAllowed { name: &'static str },
    /// A settlement was given `--close` or `--excess`.
    SettledWithClosing,
    /// The settlement date is not `YYYY-MM-DD`.
    SettledInvalid { settled: String },
    /// A settlement names no ledger sequence.
    SettlementSeqMissing,
    /// The ledger sequence is not a number.
    SeqUnreadable,
    /// The ledger sequence is zero.
    SeqZero,
    /// A rail the refund vocabulary does not know.
    UnknownRefundRail { rail: String },
    /// The refund reason is empty.
    RefundReasonEmpty,
    /// Both or neither of `--close` and `--excess`.
    CloseOrExcess,
    /// A rate was given on a rail other than Monero.
    RefundRateOnlyMonero,
    /// The rate is zero.
    RateNotPositive,
    /// The rate is not sterling.
    RateUnreadable { source: util::Error },

    // ---- a window extension ----
    /// `--window` asked for anything but the open windows.
    WindowNotOpen { window: String },
    /// `--days` is not a whole number.
    DaysUnreadable,
    /// The one extension is fourteen days and no other number.
    WindowNotFourteen,
    /// The extension reason is empty.
    WindowReasonEmpty,

    // ---- a Monero subaddress ----
    /// A group approved without charge has no Monero rail.
    GroupNoCharge { domain: String },
    /// A group chose another rail and has no Monero subaddress.
    GroupRailNotMonero { domain: String, rail: String },
    /// An account approved without charge has no Monero rail.
    NoChargeMonero { username: String },
    /// An account chose another rail and has no Monero subaddress.
    RailNotMonero { username: String, rail: String },

    // ---- the ledger export ----
    /// The export format is not csv.
    FormatNotCsv { format: String },
    /// The tax year is not the accepted spelling.
    TaxYearInvalid { value: String },

    // ---- prepaid and reconcile ----
    /// `--expiring` is not a whole number of days.
    ExpiringInvalid { text: String },
    /// A held item's id is not the unattributed shape.
    NotUnattributedId { item: String },
    /// A return was filed with no evidence.
    ReturnNoteEmpty,

    // ---- a data-subject request ----
    /// The message file could not be read.
    ReadMessage { path: PathBuf, source: io::Error },
    /// The detached signature file could not be read.
    ReadSignature { path: PathBuf, source: io::Error },
    /// The box holds no keyring entry for the account.
    NoKeyringKey { username: String, path: PathBuf },
    /// The keyring entry could not be read.
    ReadKeyring { path: PathBuf, source: io::Error },
    /// The keyring entry is not one usable certificate.
    KeyringUnusable {
        username: String,
        source: mail::Error,
    },
    /// The signature does not verify against the keyring entry.
    SignatureMismatch { username: String },
    /// The message carries no `From:` header.
    NoFrom,
    /// The message is neither clearsigned nor accompanied by its signature.
    NotClearsigned,
    /// The message is from the account's outside contact address.
    SenderOutside { from: String, own: String },
    /// The message is from neither of the account's addresses.
    SenderOther { from: String, own: String },
    /// The outer `From:` and the clearsigned one disagree.
    FromMismatch { outer: String, armour: String },
    /// A request line's date does not parse.
    RequestStateUnreadable { id: String, source: account::Error },

    // ---- wrapped areas ----
    /// The store failed.
    Store(store::Error),
    /// The configuration failed.
    Config(config::Error),
    /// A core read or parse failed.
    Core(kyriakon_control_core::Error),
    /// A drain transition refused or failed.
    Drain(kyriakon_control_drain::transitions::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage => f.write_str(&crate::usage()),
            Error::ConfigPathMissing => f.write_str("--config needs a path"),
            Error::UnexpectedArgument { argument } => {
                write!(f, "unexpected argument {argument:?}\n{}", crate::usage())
            }
            Error::UnknownFlag { flag } => {
                write!(f, "unknown flag {flag:?}\n{}", crate::usage())
            }
            Error::NeedsValue { flag } => write!(f, "{flag} needs a value"),
            Error::Duplicate { flag } => write!(f, "{flag} is given twice"),
            Error::MissingFlag { flag } => write!(f, "--{flag} is needed"),

            Error::InvalidUsername { username, why } => {
                write!(f, "the username {username:?}: {why}")
            }
            Error::InvalidDomain { domain, why } => write!(f, "the domain {domain:?}: {why}"),
            Error::InvalidMailbox { mailbox, why } => {
                write!(f, "the mailbox {mailbox:?}: {why}")
            }
            Error::InvalidAddress { address, why } => {
                write!(f, "the address {address:?}: {why}")
            }
            Error::InvalidSiteOwner { owner, why } => {
                write!(f, "the site owner {owner:?}: {why}")
            }
            Error::InvalidMoneroAddress { address, why } => {
                write!(f, "the address {address:?} {why}")
            }
            Error::UnknownAction { action } => write!(
                f,
                "--action {action:?} is not one of {:?}\n{}",
                intent::ADDRESS_ACTIONS,
                crate::usage()
            ),

            Error::NoAccount { username } => write!(f, "no account for {username}"),
            Error::NoApplication { username } => write!(f, "no application for {username}"),
            Error::ResumeLeftLapsed { username } => write!(
                f,
                "{username} is no longer suspended but stays lapsed: the payment window is closed, \
                 so no access was restored. A payment or `kyriakon-admin window extend` is what \
                 brings it back"
            ),

            Error::AddressOnRemoval {
                address,
                mailbox,
                domain,
            } => write!(
                f,
                "--address cannot be given with --action remove: the removal closes the mailbox \
                 {mailbox}@{domain}, not the address {address}@{domain}, which would be ignored"
            ),
            Error::ConfirmRequired { mailbox, domain } => write!(
                f,
                "removing {mailbox}@{domain} deletes its account, home and Maildir, quota record, \
                 git repositories, published tree and store record; give --confirm-remove to file it"
            ),
            Error::ConfirmOnlyForRemove => {
                f.write_str("--confirm-remove is only for --action remove")
            }
            Error::AddressMissing => f.write_str("--address is needed for this change"),
            Error::MailKeyUnreadable { path, source } => {
                write!(f, "cannot read the mail key {}: {source}", path.display())
            }
            Error::MailKeyEmpty { path } => {
                write!(f, "the mail key {} is empty", path.display())
            }
            Error::MailKeyInvalid { path, source } => {
                write!(f, "the mail key {}: {source}", path.display())
            }
            Error::MailKeyRefused { mailbox, why } => {
                write!(f, "the mail key for {mailbox} cannot be used: {why}")
            }
            Error::MailKeyNoPacket { path } => {
                write!(f, "the mail key {}: it carries no key packet", path.display())
            }
            Error::MailKeyMissing => f.write_str("--key-file is needed for a new mailbox"),

            Error::NotStatusToken { token } => write!(
                f,
                "the token {token:?} is not a status token (26 Crockford characters)"
            ),
            Error::NoApplicationAtToken { token } => {
                write!(f, "no application at token {token}")
            }
            Error::TokenForOtherUser {
                token,
                actual,
                expected,
            } => write!(
                f,
                "the application at token {token} is for {actual}, not {expected}"
            ),
            Error::RecordChanged { changed } => write!(
                f,
                "the application record changed after the review mail: {changed}. Nothing was \
                 signed; read the application again and check it against the mail before deciding"
            ),

            Error::NoChargeToken { username } => write!(
                f,
                "{username} was approved without charge, so there is no payment token"
            ),
            Error::NoPaymentToken { username } => {
                write!(f, "{username} has no payment token")
            }
            Error::NoGroup { domain } => write!(f, "no group record for {domain}"),
            Error::GroupNoPaymentToken { domain } => {
                write!(f, "the group {domain} has no payment token")
            }
            Error::NotPaymentToken { token } => {
                write!(f, "the token {token:?} is not a payment token")
            }
            Error::TokenAndUsername => {
                f.write_str("give either --token or --username, not both")
            }
            Error::TokenOrUsernameMissing => f.write_str("give --token or --username"),
            Error::NoteEmpty => f.write_str("--note is empty"),
            Error::NoteWithToken => f.write_str(
                "--note is for a payment with no token: give neither --token nor --username",
            ),
            Error::AccountReferenceMissing => {
                f.write_str("give --token, --username or --note")
            }

            Error::UnknownCreditRail { rail } => write!(
                f,
                "--rail {rail:?} is not one of {}",
                intent::CREDIT_RAILS.join(", ")
            ),
            Error::CashHandWithNote => f.write_str(
                "cash in hand is credited against a username; give --username, not --note",
            ),
            Error::AmountNotPositive => f.write_str("--amount must be more than zero"),
            Error::AmountUnreadable { source } => write!(f, "--amount: {source}"),
            Error::ReceivedInvalid { received } => {
                write!(f, "--received {received:?} is not YYYY-MM-DD")
            }
            Error::ReceivedBeyondWindow { received } => {
                write!(f, "--received {received:?} is more than two years ahead")
            }
            Error::TxidInvalid => f.write_str("--txid is not 64 hexadecimal characters"),
            Error::XmrInvalid => f.write_str("--xmr is not a decimal amount"),
            Error::CreditRateOnlyMonero => {
                f.write_str("--rate is only a monero credit's receipt-date rate")
            }
            Error::RateInvalid { rate } => {
                write!(f, "--rate {rate:?} is not a positive decimal amount")
            }

            Error::SettledFlagNotAllowed { name } => {
                write!(f, "--settled takes no --{name}")
            }
            Error::SettledWithClosing => f.write_str("--settled takes no --close or --excess"),
            Error::SettledInvalid { settled } => {
                write!(f, "--settled {settled:?} is not YYYY-MM-DD")
            }
            Error::SettlementSeqMissing => f.write_str("--settled needs --seq <ledger seq>"),
            Error::SeqUnreadable => f.write_str("--seq is not a ledger sequence"),
            Error::SeqZero => f.write_str("--seq must be a ledger sequence"),
            Error::UnknownRefundRail { rail } => write!(
                f,
                "--rail {rail:?} is not one of {}",
                intent::REFUND_RAILS.join(", ")
            ),
            Error::RefundReasonEmpty => f.write_str("--reason must say why the money is going back"),
            Error::CloseOrExcess => f.write_str("give exactly one of --close or --excess"),
            Error::RefundRateOnlyMonero => {
                f.write_str("--rate is only a monero refund paid in sterling")
            }
            Error::RateNotPositive => f.write_str("--rate must be more than zero"),
            Error::RateUnreadable { source } => write!(f, "--rate: {source}"),

            Error::WindowNotOpen { window } => write!(
                f,
                "--window {window:?} is not open; only the open windows are listed"
            ),
            Error::DaysUnreadable => f.write_str("--days is not a whole number"),
            Error::WindowNotFourteen => {
                f.write_str("a window extension is fourteen days and no other number")
            }
            Error::WindowReasonEmpty => {
                f.write_str("--reason must say why the window is being extended")
            }

            Error::GroupNoCharge { domain } => write!(
                f,
                "the group {domain} was approved without charge, so it has no Monero rail"
            ),
            Error::GroupRailNotMonero { domain, rail } => write!(
                f,
                "the group {domain} chose the {rail} rail, so it has no Monero subaddress to record"
            ),
            Error::NoChargeMonero { username } => write!(
                f,
                "{username} was approved without charge, so it has no Monero rail"
            ),
            Error::RailNotMonero { username, rail } => write!(
                f,
                "{username} chose the {rail} rail, so it has no Monero subaddress to record"
            ),

            Error::FormatNotCsv { format } => {
                write!(f, "--format {format:?} is not csv")
            }
            Error::TaxYearInvalid { value } => write!(
                f,
                "--tax-year {value:?} is not YYYY-YY or YYYY-YYYY, or its years are not consecutive"
            ),

            Error::ExpiringInvalid { text } => {
                write!(f, "--expiring {text:?} is not a whole number of days")
            }
            Error::NotUnattributedId { item } => {
                write!(f, "the held item {item:?} is not an unattributed payment id")
            }
            Error::ReturnNoteEmpty => {
                f.write_str("--note is empty; name the evidence the return was made on")
            }

            Error::ReadMessage { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Error::ReadSignature { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Error::NoKeyringKey { username, path } => write!(
                f,
                "the box holds no key for {username} at {}",
                path.display()
            ),
            Error::ReadKeyring { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Error::KeyringUnusable { username, source } => {
                write!(f, "the keyring entry for {username}: {source}")
            }
            Error::SignatureMismatch { username } => write!(
                f,
                "the signature does not verify against {username}'s keyring entry"
            ),
            Error::NoFrom => f.write_str("the message has no From: header"),
            Error::NotClearsigned => f.write_str(
                "the message is not clearsigned; pass --signature with its detached signature or \
                 export the message clearsigned from the client",
            ),
            Error::SenderOutside { from, own } => write!(
                f,
                "the message is from {from}, the account's outside contact address; ask for a \
                 message from {own} signed with the mail key, or for the password route on the \
                 account page"
            ),
            Error::SenderOther { from, own } => write!(
                f,
                "the message is from {from}, not the account's own address {own}"
            ),
            Error::FromMismatch { outer, armour } => write!(
                f,
                "the message's own From: is {outer} but the clearsigned one is {armour}"
            ),
            Error::RequestStateUnreadable { id, source } => {
                write!(f, "request {id}: {source}")
            }

            Error::Store(error) => error.fmt(f),
            Error::Config(error) => error.fmt(f),
            Error::Core(error) => error.fmt(f),
            Error::Drain(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::MailKeyUnreadable { source, .. }
            | Error::ReadMessage { source, .. }
            | Error::ReadSignature { source, .. }
            | Error::ReadKeyring { source, .. } => Some(source),
            Error::MailKeyInvalid { source, .. } | Error::KeyringUnusable { source, .. } => {
                Some(source)
            }
            Error::AmountUnreadable { source } | Error::RateUnreadable { source } => Some(source),
            Error::RequestStateUnreadable { source, .. } => Some(source),
            Error::Store(error) => Some(error),
            Error::Config(error) => Some(error),
            Error::Core(error) => Some(error),
            Error::Drain(error) => Some(error),
            _ => None,
        }
    }
}

impl Error {
    pub fn report(&self, context: &str) {
        kyriakon_control_core::util::report(self, context);
    }
}

impl From<store::Error> for Error {
    fn from(error: store::Error) -> Self {
        Error::Store(error)
    }
}

impl From<config::Error> for Error {
    fn from(error: config::Error) -> Self {
        Error::Config(error)
    }
}

impl From<kyriakon_control_core::Error> for Error {
    fn from(error: kyriakon_control_core::Error) -> Self {
        Error::Core(error)
    }
}

impl From<kyriakon_control_core::account::Error> for Error {
    fn from(error: kyriakon_control_core::account::Error) -> Self {
        Error::Core(kyriakon_control_core::Error::Account(error))
    }
}
impl From<kyriakon_control_core::flow::Error> for Error {
    fn from(error: kyriakon_control_core::flow::Error) -> Self {
        Error::Core(kyriakon_control_core::Error::Flow(error))
    }
}
impl From<kyriakon_control_core::intent::Error> for Error {
    fn from(error: kyriakon_control_core::intent::Error) -> Self {
        Error::Core(kyriakon_control_core::Error::Intent(error))
    }
}
impl From<kyriakon_control_core::ipc::Error> for Error {
    fn from(error: kyriakon_control_core::ipc::Error) -> Self {
        Error::Core(kyriakon_control_core::Error::Ipc(error))
    }
}
impl From<kyriakon_control_core::util::Error> for Error {
    fn from(error: kyriakon_control_core::util::Error) -> Self {
        Error::Core(kyriakon_control_core::Error::Util(error))
    }
}
impl From<kyriakon_control_core::mail::Error> for Error {
    fn from(error: kyriakon_control_core::mail::Error) -> Self {
        Error::Core(kyriakon_control_core::Error::Mail(error))
    }
}
impl From<kyriakon_control_core::payments::Error> for Error {
    fn from(error: kyriakon_control_core::payments::Error) -> Self {
        Error::Core(kyriakon_control_core::Error::Payments(error))
    }
}

impl From<kyriakon_control_drain::transitions::Error> for Error {
    fn from(error: kyriakon_control_drain::transitions::Error) -> Self {
        Error::Drain(error)
    }
}
