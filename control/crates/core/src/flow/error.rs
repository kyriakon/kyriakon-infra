//! The flow area's error: the vocabulary files, their tokens, and the
//! applicant's label.
//!
//! A malformed token names the value; a malformed entry wraps the token error
//! with the service or question id it belongs to, so the build says which entry
//! to look at rather than which function returned.

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
