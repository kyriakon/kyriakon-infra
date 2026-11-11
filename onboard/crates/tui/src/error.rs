//! The portal's error: the terminal's own I/O, the session lock, and the two
//! IPC calls, kept apart from the text the reader sees.

use std::fmt;

use kyriakon_onboard_core::config;
use kyriakon_onboard_core::store;
use kyriakon_onboard_core::Error as CoreError;

#[derive(Debug)]
pub enum Error {
    /// The portal refuses the session for the reason the reader sees.
    Refused(String),
    /// A failure with no more specific case yet.
    Failed(String),
    /// The store failed.
    Store(store::Error),
    /// The configuration failed.
    Config(config::Error),
    /// A core read or parse failed.
    Core(CoreError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Refused(message) | Error::Failed(message) => f.write_str(message),
            Error::Store(error) => error.fmt(f),
            Error::Config(error) => error.fmt(f),
            Error::Core(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Refused(_) | Error::Failed(_) => None,
            Error::Store(error) => Some(error),
            Error::Config(error) => Some(error),
            Error::Core(error) => Some(error),
        }
    }
}

impl Error {
    pub fn report(&self, context: &str) {
        kyriakon_onboard_core::util::report(self, context);
    }

    /// Temporary while the remaining tests are converted to variants.
    pub fn contains(&self, pattern: &str) -> bool {
        self.to_string().contains(pattern)
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

impl From<CoreError> for Error {
    fn from(error: CoreError) -> Self {
        Error::Core(error)
    }
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Error::Failed(message)
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Error::Failed(message.to_string())
    }
}
