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
        source: Box<Source>,
        suffix: &'static str,
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
            Error::Context {
                context,
                source,
                suffix,
            } => write!(f, "{context}: {source}{suffix}"),
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

    pub fn context(context: impl Into<String>, source: impl Into<Source>) -> Self {
        Error::Context {
            context: context.into(),
            source: Box::new(source.into()),
            suffix: "",
        }
    }

    pub fn context_with_suffix(
        context: impl Into<String>,
        source: impl Into<Source>,
        suffix: &'static str,
    ) -> Self {
        Error::Context {
            context: context.into(),
            source: Box::new(source.into()),
            suffix,
        }
    }
}

/// The concrete error a [`Error::Context`] carries. One enum rather than a
/// boxed trait object, so the source stays a known type and the acceptance
/// rule against a boxed trait object holds.
#[derive(Debug)]
pub enum Source {
    Io(io::Error),
    Json(serde_json::Error),
    Toml(toml::de::Error),
    TimeFormat(time::error::Format),
    TimeParse(time::error::Parse),
    TimeComponent(time::error::ComponentRange),
    Ulid(ulid::DecodeError),
    Hmac(hmac::digest::InvalidLength),
    Bcrypt(bcrypt::BcryptError),
    ParseInt(std::num::ParseIntError),
    Utf8(std::string::FromUtf8Error),
    Core(Box<Error>),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Io(e) => e.fmt(f),
            Source::Json(e) => e.fmt(f),
            Source::Toml(e) => e.fmt(f),
            Source::TimeFormat(e) => e.fmt(f),
            Source::TimeParse(e) => e.fmt(f),
            Source::TimeComponent(e) => e.fmt(f),
            Source::Ulid(e) => e.fmt(f),
            Source::Hmac(e) => e.fmt(f),
            Source::Bcrypt(e) => e.fmt(f),
            Source::ParseInt(e) => e.fmt(f),
            Source::Utf8(e) => e.fmt(f),
            Source::Core(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Source {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Source::Io(e) => Some(e),
            Source::Json(e) => Some(e),
            Source::Toml(e) => Some(e),
            Source::TimeFormat(e) => Some(e),
            Source::TimeParse(e) => Some(e),
            Source::TimeComponent(e) => Some(e),
            Source::Ulid(e) => Some(e),
            Source::Hmac(e) => Some(e),
            Source::Bcrypt(e) => Some(e),
            Source::ParseInt(e) => Some(e),
            Source::Utf8(e) => Some(e),
            Source::Core(e) => Some(e),
        }
    }
}

impl From<io::Error> for Source {
    fn from(e: io::Error) -> Self {
        Source::Io(e)
    }
}
impl From<serde_json::Error> for Source {
    fn from(e: serde_json::Error) -> Self {
        Source::Json(e)
    }
}
impl From<toml::de::Error> for Source {
    fn from(e: toml::de::Error) -> Self {
        Source::Toml(e)
    }
}
impl From<time::error::Format> for Source {
    fn from(e: time::error::Format) -> Self {
        Source::TimeFormat(e)
    }
}
impl From<time::error::Parse> for Source {
    fn from(e: time::error::Parse) -> Self {
        Source::TimeParse(e)
    }
}
impl From<time::error::ComponentRange> for Source {
    fn from(e: time::error::ComponentRange) -> Self {
        Source::TimeComponent(e)
    }
}
impl From<ulid::DecodeError> for Source {
    fn from(e: ulid::DecodeError) -> Self {
        Source::Ulid(e)
    }
}
impl From<hmac::digest::InvalidLength> for Source {
    fn from(e: hmac::digest::InvalidLength) -> Self {
        Source::Hmac(e)
    }
}
impl From<bcrypt::BcryptError> for Source {
    fn from(e: bcrypt::BcryptError) -> Self {
        Source::Bcrypt(e)
    }
}
impl From<std::num::ParseIntError> for Source {
    fn from(e: std::num::ParseIntError) -> Self {
        Source::ParseInt(e)
    }
}
impl From<std::string::FromUtf8Error> for Source {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Source::Utf8(e)
    }
}
impl From<Error> for Source {
    fn from(e: Error) -> Self {
        Source::Core(Box::new(e))
    }
}
impl From<store::Error> for Source {
    fn from(e: store::Error) -> Self {
        Source::Core(Box::new(Error::Store(e)))
    }
}
impl From<config::Error> for Source {
    fn from(e: config::Error) -> Self {
        Source::Core(Box::new(Error::Config(e)))
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
