//! The console's error: usage, a refusal, the store, and the few I/O edges the
//! operator sees.

use std::fmt;

use kyriakon_onboard_core::config;
use kyriakon_onboard_core::store;

#[derive(Debug)]
pub enum Error {
    /// A failure with no more specific case yet.
    Failed(String),
    /// The store failed.
    Store(store::Error),
    /// The configuration failed.
    Config(config::Error),
    /// A core read or parse failed.
    Core(kyriakon_onboard_core::Error),
    /// A drain transition refused or failed.
    Drain(kyriakon_onboard_drain::transitions::Error),
    /// A failure whose context is the value the caller needs, with its source.
    Context {
        context: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Failed(message) => f.write_str(message),
            Error::Store(error) => error.fmt(f),
            Error::Config(error) => error.fmt(f),
            Error::Core(error) => error.fmt(f),
            Error::Drain(error) => error.fmt(f),
            Error::Context { context, source } => write!(f, "{context}: {source}"),
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
            Error::Context { source, .. } => Some(source.as_ref()),
        }
    }
}

impl Error {
    pub fn report(&self, context: &str) {
        kyriakon_onboard_core::util::report(self, context);
    }

    pub fn context(
        context: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Error::Context {
            context: context.into(),
            source: Box::new(source),
        }
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

impl From<kyriakon_onboard_core::Error> for Error {
    fn from(error: kyriakon_onboard_core::Error) -> Self {
        Error::Core(error)
    }
}

impl From<kyriakon_onboard_drain::transitions::Error> for Error {
    fn from(error: kyriakon_onboard_drain::transitions::Error) -> Self {
        Error::Drain(error)
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
