//! The flow area's error: the vocabulary files, their tokens, the applicant's
//! label, and the validators' refusals.
//!
//! A malformed token names the value; a malformed entry wraps the token error
//! with the service or question id it belongs to, so the build says which entry
//! to look at rather than which function returned. A refused answer is a
//! [`Reason`], so a caller stores the state and `Display` writes the sentence.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// A front-end label is not one the crate reads.
    UnknownFrontEnd { value: String },
    /// A catalogue state is not one the crate has a word for.
    UnknownState { value: String },
    /// A catalogue action is not one the crate has a word for.
    UnknownAction { value: String },
    /// A question answer type is not one the crate has a word for.
    UnknownAnswerType { value: String },
    /// A question branch is not one the crate has a word for.
    UnknownBranch { value: String },
    /// A `maxlen:` validation carries no number.
    MaxLenNotNumber { value: String },
    /// A validation rule is not one the crate has a word for.
    UnknownValidation { value: String },
    /// The catalogue file did not parse.
    Catalogue { source: toml::de::Error },
    /// The question list did not parse.
    QuestionList { source: toml::de::Error },
    /// A catalogue entry has an empty required field.
    EmptyService { id: String },
    /// A choice question offers no choices.
    ChoiceWithoutChoices { id: String },
    /// A choice question carries a validation string beside its choices.
    ChoiceWithValidation { id: String },
    /// A choice has an empty value or label.
    EmptyChoice { id: String },
    /// A question of another kind carries choices.
    ChoicesOnOther { id: String, kind: &'static str },
    /// A catalogue entry's token or shape is wrong.
    Service { id: String, source: Box<Error> },
    /// A question's token or shape is wrong.
    Question { id: String, source: Box<Error> },
    /// A body names one account twice.
    DuplicateAccountName { name: String },
    /// A body requests more than the allowed number of mailboxes.
    TooManyAccountNames,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownFrontEnd { value } => write!(f, "unknown front_end {value:?}"),
            Error::UnknownState { value } => write!(f, "unknown state {value:?}"),
            Error::UnknownAction { value } => write!(f, "unknown action {value:?}"),
            Error::UnknownAnswerType { value } => write!(f, "unknown answer type {value:?}"),
            Error::UnknownBranch { value } => write!(f, "unknown branch {value:?}"),
            Error::MaxLenNotNumber { value } => {
                write!(f, "maxlen needs a number, got {value:?}")
            }
            Error::UnknownValidation { value } => write!(f, "unknown validation {value:?}"),
            Error::Catalogue { source } => write!(f, "the catalogue: {source}"),
            Error::QuestionList { source } => write!(f, "the question list: {source}"),
            Error::EmptyService { id } => write!(
                f,
                "the service {id:?} has an empty id, name, summary or host"
            ),
            Error::ChoiceWithoutChoices { id } => {
                write!(f, "the question {id:?} is a choice with no choices")
            }
            Error::ChoiceWithValidation { id } => write!(
                f,
                "the question {id:?} is a choice, so its validation is its choices"
            ),
            Error::EmptyChoice { id } => write!(
                f,
                "the question {id:?} has a choice with an empty value or label"
            ),
            Error::ChoicesOnOther { id, kind } => {
                write!(f, "the question {id:?} is a {kind} carrying choices")
            }
            Error::Service { id, source } => write!(f, "the service {id:?}: {source}"),
            Error::Question { id, source } => write!(f, "the question {id:?}: {source}"),
            Error::DuplicateAccountName { name } => {
                write!(f, "the account name {name:?} is given twice")
            }
            Error::TooManyAccountNames => {
                write!(
                    f,
                    "up to {} account names",
                    super::questions::BODY_MAILBOX_LIMIT
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Catalogue { source } | Error::QuestionList { source } => Some(source),
            Error::Service { source, .. } | Error::Question { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// Why one answer or record field was refused. Each variant is one rule, and
/// the fields are the values its sentence names, so a caller can read the
/// refusal back without parsing the text.
#[derive(Debug)]
pub enum Reason {
    // ---- the answer's presence and type ----
    /// A required answer is empty.
    Required,
    /// A required username answer is empty.
    UsernameRequired,
    /// A yes/no question offers only yes and no.
    YesNo,
    /// A required acceptance is not ticked.
    AcceptanceRequired,
    /// An optional acceptance carries a value the page does not offer.
    AcceptanceOptional,

    // ---- free text ----
    /// A free-text answer carries a control or invisible character.
    FreeTextControl,
    /// A single-line answer carries a control or invisible character.
    SingleLineControl,
    /// An answer is longer than the limit.
    MaxLength { limit: usize },
    /// A choice answer is not one of the offered values.
    ChoiceNotOffered,

    // ---- a key ----
    /// The shared key check refused the submitted key.
    KeyRefused { verdict: String },
    /// The key material did not parse.
    KeyUnusable { source: Box<crate::mail::Error> },

    // ---- a username ----
    /// The name is reserved by the platform.
    UsernameHeld,
    /// A username is longer than the limit.
    UsernameTooLong { limit: usize },
    /// A username does not start with a letter or a digit.
    UsernameFirst,
    /// A username carries a character outside its charset.
    UsernameCharset,
    /// A username does not end with a letter or a digit.
    UsernameLast,
    /// A list names one username twice.
    UsernameTwice { name: String },
    /// A list has more names than a body can request.
    TooManyAccountNames,
    /// A list's line is refused, and the sentence names the line.
    UsernameNamed { name: String, source: Box<Reason> },

    // ---- a domain ----
    /// A domain is longer than the limit.
    DomainTooLong { limit: usize },
    /// A domain carries an empty label.
    DomainEmptyLabel,
    /// A domain label is longer than the limit.
    DomainLabelTooLong { limit: usize },
    /// A domain label carries a character outside its charset.
    DomainLabelCharset { label: String },
    /// A domain label begins or ends with a hyphen.
    DomainLabelHyphen { label: String },
    /// A domain has fewer than two labels.
    DomainTooFewLabels,
    /// A domain's last label is not two or more letters.
    DomainLastLabel { label: String },

    // ---- an address localpart ----
    /// An address localpart is empty.
    LocalpartRequired,
    /// An address localpart is longer than the limit.
    LocalpartTooLong { limit: usize },
    /// An address localpart does not start with a letter or a digit.
    LocalpartFirst,
    /// An address localpart carries a character outside its charset.
    LocalpartCharset,

    // ---- the body's address list ----
    /// The address list carries more than ten lines.
    AddressLinesTooMany { count: usize },
    /// A line is not `localpart: own` or `localpart: alias localpart`.
    AddressLineMalformed { line: String },
    /// A line's localpart is refused, and the sentence names the line.
    AddressLineNamed { line: String, source: Box<Reason> },
    /// A line's alias target is refused, and the sentence names the line and
    /// the target.
    AddressLineTarget {
        line: String,
        target: String,
        source: Box<Reason>,
    },

    // ---- an address outside the platform ----
    /// The value is not exactly one `local@domain`.
    OutsideAddress,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Required => f.write_str("this is needed"),
            Reason::UsernameRequired => f.write_str("a username is needed"),
            Reason::YesNo => f.write_str("answer yes or no"),
            Reason::AcceptanceRequired => f.write_str("this has to be accepted"),
            Reason::AcceptanceOptional => {
                f.write_str("answer yes to accept, or leave it unticked")
            }
            Reason::FreeTextControl => f.write_str("without control or invisible characters"),
            Reason::SingleLineControl => {
                f.write_str("one line, without control or invisible characters")
            }
            Reason::MaxLength { limit } => write!(f, "at most {limit} characters"),
            Reason::ChoiceNotOffered => f.write_str("choose one of the answers offered"),
            Reason::KeyRefused { verdict } => f.write_str(verdict),
            Reason::KeyUnusable { source } => source.fmt(f),
            Reason::UsernameHeld => f.write_str("that name is held back by the platform"),
            Reason::UsernameTooLong { limit } => {
                write!(f, "a username is at most {limit} characters")
            }
            Reason::UsernameFirst => {
                f.write_str("a username starts with a lowercase letter or a digit")
            }
            Reason::UsernameCharset => {
                f.write_str("a username is lowercase letters, digits and hyphen")
            }
            Reason::UsernameLast => {
                f.write_str("a username ends with a lowercase letter or a digit")
            }
            Reason::UsernameTwice { name } => write!(f, "the name {name:?} is given twice"),
            Reason::TooManyAccountNames => Error::TooManyAccountNames.fmt(f),
            Reason::UsernameNamed { name, source } => write!(f, "the name {name:?}: {source}"),
            Reason::DomainTooLong { limit } => {
                write!(f, "a domain is at most {limit} characters")
            }
            Reason::DomainEmptyLabel => f.write_str("a domain has no empty labels"),
            Reason::DomainLabelTooLong { limit } => {
                write!(f, "a domain label is at most {limit} characters")
            }
            Reason::DomainLabelCharset { label } => write!(
                f,
                "the domain label {label:?} is not lowercase letters, digits and hyphen"
            ),
            Reason::DomainLabelHyphen { label } => {
                write!(f, "the domain label {label:?} begins or ends with a hyphen")
            }
            Reason::DomainTooFewLabels => {
                f.write_str("a domain has at least two labels, like theirparish.example")
            }
            Reason::DomainLastLabel { label } => write!(
                f,
                "the domain's last label {label:?} must be two or more letters, like theirparish.example"
            ),
            Reason::LocalpartRequired => f.write_str("an address localpart is needed"),
            Reason::LocalpartTooLong { limit } => {
                write!(f, "an address localpart is at most {limit} characters")
            }
            Reason::LocalpartFirst => {
                f.write_str("an address localpart starts with a lowercase letter or a digit")
            }
            Reason::LocalpartCharset => f.write_str(
                "an address localpart is lowercase letters, digits, dot, underscore and hyphen",
            ),
            Reason::AddressLinesTooMany { count } => {
                write!(f, "up to ten addresses, {count} given")
            }
            Reason::AddressLineMalformed { line } => write!(
                f,
                "the address line {line:?} is not localpart: own or localpart: alias localpart"
            ),
            Reason::AddressLineNamed { line, source } => {
                write!(f, "the address line {line:?}: {source}")
            }
            Reason::AddressLineTarget {
                line,
                target,
                source,
            } => write!(
                f,
                "the address line {line:?}: the alias target {target:?} {source}"
            ),
            Reason::OutsideAddress => {
                f.write_str("an address outside this platform is one, like someone@example.invalid")
            }
        }
    }
}

impl std::error::Error for Reason {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Reason::KeyUnusable { source } => Some(source.as_ref()),
            Reason::UsernameNamed { source, .. }
            | Reason::AddressLineNamed { source, .. }
            | Reason::AddressLineTarget { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
