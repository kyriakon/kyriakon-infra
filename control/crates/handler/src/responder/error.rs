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

use kyriakon_control_core::config;
use kyriakon_control_core::intent;
use kyriakon_control_core::store;

#[derive(Debug)]
pub enum Error {
    /// Startup was given a command this build does not serve.
    UnknownCommand { command: String },
    /// Startup was given no command at all.
    NoCommand,
    /// `--config` was given without the path that follows it.
    MissingConfigPath,
    /// Startup was given an argument it does not know.
    UnknownArgument { argument: String },
    /// The shipped question list parsed to nothing, so no form exists to serve.
    NoQuestions { path: &'static str },
    /// The catalogue parsed to nothing, so the menu promises no service.
    NoServices { path: &'static str },
    /// A mirrored page exists and holds only whitespace.
    EmptyPage { path: String },
    /// The sandbox refused the narrowed view.
    Restrict {
        source: kyriakon_control_core::sandbox::Error,
    },
    /// The store failed while reading or writing a form record.
    Store(store::Error),
    /// The configuration failed.
    Config(config::Error),
    /// An account or group lookup failed. The capsule answers this one as a
    /// permanent failure; a form's store failure is temporary.
    Lookup(store::Error),
    /// The handler refused a request it cannot serve: a protocol fault, not a
    /// server fault.
    Refused(Refusal),
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
    /// An intent passed validation but the store could not file it. `what` is
    /// the intent's noun.
    Filed {
        what: &'static str,
        source: intent::Error,
    },
    /// The Titan connection's reply deadline passed.
    TitanTimeout,
    /// A core read or parse failed.
    Core(kyriakon_control_core::Error),
    /// The FastCGI record did not parse.
    Fastcgi(crate::fastcgi::Error),
    /// A failure whose context is what the operator needs, with its source.
    Context {
        context: &'static str,
        source: Box<kyriakon_control_core::Source>,
    },
}

/// Why the handler refuses a request it cannot serve. The sentence is a constant
/// per variant, because a refusal reaches the client and an internal error's
/// text never does.
#[derive(Debug)]
pub enum Refusal {
    /// The portal closed after a file request, before sending the body.
    PortalClosedBeforeApplication,
    /// The portal's line is neither a file nor a status request.
    PortalNoStatusRequest,
    /// The Titan request line ended before its newline.
    TitanLineCutShort,
}

impl Refusal {
    /// The sentence the client reads, and the only description of the failure.
    pub fn message(&self) -> &'static str {
        match self {
            Refusal::PortalClosedBeforeApplication => {
                "the portal closed before sending the application"
            }
            Refusal::PortalNoStatusRequest => "the portal sent no status request",
            Refusal::TitanLineCutShort => "the titan request line was cut short",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownCommand { command } => write!(
                f,
                "unknown command {command:?}; usage: kyriakon-control serve [--config PATH]"
            ),
            Error::NoCommand => f.write_str("usage: kyriakon-control serve [--config PATH]"),
            Error::MissingConfigPath => f.write_str("--config needs a path"),
            Error::UnknownArgument { argument } => write!(f, "unknown argument {argument:?}"),
            Error::NoQuestions { path } => write!(f, "{path} has no questions"),
            Error::NoServices { path } => write!(f, "{path} has no services"),
            Error::EmptyPage { path } => write!(f, "{path} is empty"),
            Error::Restrict { source } => source.fmt(f),
            Error::Refused(refusal) => refusal.fmt(f),
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
            Error::Filed { what, source } => write!(f, "{what} could not be filed: {source}"),
            Error::TitanTimeout => f.write_str("the titan reply timed out"),
            Error::Context { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::UnknownCommand { .. }
            | Error::NoCommand
            | Error::MissingConfigPath
            | Error::UnknownArgument { .. }
            | Error::NoQuestions { .. }
            | Error::NoServices { .. }
            | Error::EmptyPage { .. }
            | Error::Refused(_)
            | Error::Line { .. }
            | Error::TitanTimeout => None,
            Error::Store(error) | Error::Lookup(error) => Some(error),
            Error::Restrict { source } => Some(source),
            Error::Core(error) => Some(error),
            Error::Fastcgi(error) => Some(error),
            Error::Config(error) => Some(error),
            Error::Io { source, .. } => Some(source),
            Error::Encode { source, .. } => Some(source),
            Error::Filed { source, .. } => Some(source),
            Error::Context { source, .. } => Some(source.as_ref()),
        }
    }
}

impl Error {
    pub fn report(&self, context: &str) {
        kyriakon_control_core::util::report(self, context);
    }

    pub fn context(
        context: &'static str,
        source: impl Into<kyriakon_control_core::Source>,
    ) -> Self {
        Error::Context {
            context,
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
