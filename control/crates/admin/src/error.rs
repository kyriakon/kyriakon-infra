//! The console's error: usage, a refusal, the store, and the few I/O edges the
//! operator sees.

use std::fmt;

use kyriakon_control_core::config;
use kyriakon_control_core::store;

#[derive(Debug)]
pub enum Error {
    /// A failure with no more specific case yet.
    Failed(String),
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
            Error::Failed(message) => f.write_str(message),
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
            Error::Failed(_) => None,
            Error::Store(error) => Some(error),
            Error::Config(error) => Some(error),
            Error::Core(error) => Some(error),
            Error::Drain(error) => Some(error),
        }
    }
}

impl Error {
    pub fn report(&self, context: &str) {
        kyriakon_control_core::util::report(self, context);
    }

    pub fn context(
        context: impl Into<String>,
        source: impl Into<kyriakon_control_core::Source>,
    ) -> Self {
        Error::Core(kyriakon_control_core::Error::context(context, source))
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

impl From<kyriakon_control_drain::transitions::Error> for Error {
    fn from(error: kyriakon_control_drain::transitions::Error) -> Self {
        Error::Drain(error)
    }
}
