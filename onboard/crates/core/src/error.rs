//! The core's shared error for the account, mail, flow, payment and IPC
//! modules. `store` and `config` keep their own enums because every other
//! module converts through them; the rest name the few cases their callers act
//! on here.

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::config;
use crate::store;

#[derive(Debug)]
pub enum Error {
    /// A request or record the core refuses, in the words the caller shows.
    Refused(String),
    /// A failure with no more specific case yet.
    Failed(String),
    /// The store failed.
    Store(store::Error),
    /// The configuration failed.
    Config(config::Error),
    /// A file or socket operation failed.
    Io {
        what: &'static str,
        path: Option<PathBuf>,
        source: io::Error,
    },
    /// A JSON record did not encode or parse.
    Json {
        what: &'static str,
        source: serde_json::Error,
    },
    /// One line of an append-only record did not parse.
    ParseLine {
        path: &'static str,
        line: usize,
        source: serde_json::Error,
    },
    /// A failure whose context is the value the caller needs, with its source.
    Context {
        context: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Refused(message) | Error::Failed(message) => f.write_str(message),
            Error::Store(error) => error.fmt(f),
            Error::Config(error) => error.fmt(f),
            Error::Io {
                what,
                path: Some(path),
                source,
            } => write!(f, "cannot {what} {}: {source}", path.display()),
            Error::Io {
                what,
                path: None,
                source,
            } => write!(f, "cannot {what}: {source}"),
            Error::Json { what, source } => write!(f, "cannot {what}: {source}"),
            Error::ParseLine { path, line, source } => {
                write!(f, "{path}: line {line} does not parse: {source}")
            }
            Error::Context { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Refused(_) | Error::Failed(_) => None,
            Error::Store(error) => Some(error),
            Error::Config(error) => Some(error),
            Error::Io { source, .. } => Some(source),
            Error::Json { source, .. } => Some(source),
            Error::ParseLine { source, .. } => Some(source),
            Error::Context { source, .. } => Some(source.as_ref()),
        }
    }
}

impl Error {
    pub fn report(&self, context: &str) {
        crate::util::report(self, context);
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

impl From<serde_json::Error> for Error {
    fn from(source: serde_json::Error) -> Self {
        Error::Json {
            what: "the record",
            source,
        }
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
