//! The responder's error: what the reply layer can tell apart, with the source
//! kept for the log.
//!
//! `Lookup` is separate from `Store` only because the capsule's account and
//! group pages answer an unreadable record as a permanent failure (50), while a
//! draft or form failure is temporary (40). The variant names that decision so
//! no handler picks a status by hand.

use std::fmt;
use std::io;
use std::path::PathBuf;

use kyriakon_onboard_core::config;
use kyriakon_onboard_core::store;

#[derive(Debug)]
pub enum Error {
    /// Startup could not read the configuration, questions, catalogue or pages.
    /// No request can be answered, so this never reaches the reply mapper.
    Startup(String),
    /// The store failed while reading or writing a form record.
    Store(store::Error),
    /// The configuration failed.
    Config(config::Error),
    /// An account or group lookup failed. The capsule answers this one as a
    /// permanent failure; a form's store failure is temporary.
    Lookup(store::Error),
    /// A request the handler refuses: a bad parameter, not a server fault.
    Refused(String),
    /// A line exceeded its bound.
    Line { what: &'static str, limit: usize },
    /// A socket or file operation failed.
    Io {
        what: &'static str,
        path: Option<PathBuf>,
        source: io::Error,
    },
    /// A record could not be encoded.
    Encode {
        what: &'static str,
        source: serde_json::Error,
    },
    /// A core read or parse failed.
    Core(kyriakon_onboard_core::Error),
    /// The FastCGI record did not parse.
    Fastcgi(crate::fastcgi::Error),
    /// A failure from a boundary that has not converted yet.
    Failed(String),
    /// A failure whose context is what the operator needs, with its source.
    Context {
        context: String,
        source: Box<kyriakon_onboard_core::Source>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Startup(message) | Error::Refused(message) | Error::Failed(message) => {
                f.write_str(message)
            }
            Error::Store(error) => error.fmt(f),
            Error::Core(error) => error.fmt(f),
            Error::Fastcgi(error) => error.fmt(f),
            Error::Config(error) => error.fmt(f),
            Error::Lookup(error) => error.fmt(f),
            Error::Line { what, limit } => write!(f, "{what} is longer than {limit} bytes"),
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
            Error::Encode { what, source } => write!(f, "cannot {what}: {source}"),
            Error::Context { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Startup(_) | Error::Refused(_) | Error::Failed(_) | Error::Line { .. } => None,
            Error::Store(error) | Error::Lookup(error) => Some(error),
            Error::Core(error) => Some(error),
            Error::Fastcgi(error) => Some(error),
            Error::Config(error) => Some(error),
            Error::Io { source, .. } => Some(source),
            Error::Encode { source, .. } => Some(source),
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
        source: impl Into<kyriakon_onboard_core::Source>,
    ) -> Self {
        Error::Context {
            context: context.into(),
            source: Box::new(source.into()),
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

impl From<crate::fastcgi::Error> for Error {
    fn from(error: crate::fastcgi::Error) -> Self {
        Error::Fastcgi(error)
    }
}

impl From<kyriakon_onboard_core::Error> for Error {
    fn from(error: kyriakon_onboard_core::Error) -> Self {
        Error::Core(error)
    }
}
