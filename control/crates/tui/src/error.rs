//! The portal's error: the terminal's own I/O, the session lock, and the two
//! IPC calls, kept apart from the text the reader sees.

use std::fmt;
use std::io;
use std::path::PathBuf;

use kyriakon_control_core::config;
use kyriakon_control_core::store;
use kyriakon_control_core::Error as CoreError;

#[derive(Debug)]
pub enum Error {
    /// `-c` was given without the command sshd supplied.
    MissingForcedCommand,
    /// `--config` was given without the path that follows it.
    MissingConfigPath,
    /// `--state` was given without the path that follows it.
    MissingStatePath,
    /// The command line named an argument this build does not serve.
    UnknownArgument { argument: String },
    /// A session file or terminal operation failed. `what` is the verb, and
    /// `path` the file where the operation names one.
    Io {
        what: &'static str,
        path: Option<PathBuf>,
        source: io::Error,
    },
    /// The catalogue parsed to nothing, so there is no menu to draw.
    NoServices { path: &'static str },
    /// The session reached its lifetime limit.
    SessionTooLong,
    /// The session went idle past its limit.
    SessionIdle,
    /// The terminal sent bytes that are not UTF-8.
    InputNotText,
    /// The sandbox refused the narrowed view. `reason` is that boundary's own
    /// text, which names the call and the path it refused.
    Restrict { reason: String },
    /// The store failed.
    Store(store::Error),
    /// The configuration failed.
    Config(config::Error),
    /// A core read or parse failed.
    Core(CoreError),
    /// A scripted status read was not scripted. Present only in tests.
    #[cfg(test)]
    NoStatusScripted,
    /// The session asked for a status its source never serves. Present only in
    /// tests.
    #[cfg(test)]
    StatusNotAsked,
    /// The session filed when its source files nothing. Present only in tests.
    #[cfg(test)]
    FilesNothing,
}

/// Why the portal refuses a session before it opens. The reader sees the
/// sentence `Display` writes, and nothing else.
#[derive(Debug)]
pub enum Refusal {
    /// Every session slot this address may hold is taken.
    Busy,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Busy => f.write_str(crate::TOO_MANY),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingForcedCommand => f.write_str("-c needs the command sshd supplied"),
            Error::MissingConfigPath => f.write_str("--config needs a path"),
            Error::MissingStatePath => f.write_str("--state needs a path"),
            Error::UnknownArgument { argument } => write!(
                f,
                "unknown argument {argument:?}; usage: kyriakon-control-tui \
                 [-c COMMAND] [--config PATH] [--state PATH] [--plain | --full]"
            ),
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
            Error::NoServices { path } => {
                write!(f, "{path} names no services, so there is nothing to show")
            }
            Error::SessionTooLong => f.write_str("the session has reached its maximum length"),
            Error::SessionIdle => f.write_str("the session was idle for too long"),
            Error::InputNotText => f.write_str("the session's input is not text"),
            Error::Restrict { reason } => f.write_str(reason),
            Error::Store(error) => error.fmt(f),
            Error::Config(error) => error.fmt(f),
            Error::Core(error) => error.fmt(f),
            #[cfg(test)]
            Error::NoStatusScripted => f.write_str("no status was scripted"),
            #[cfg(test)]
            Error::StatusNotAsked => f.write_str("this session asks no status"),
            #[cfg(test)]
            Error::FilesNothing => f.write_str("this session files nothing"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::Store(error) => Some(error),
            Error::Config(error) => Some(error),
            Error::Core(error) => Some(error),
            Error::MissingForcedCommand
            | Error::MissingConfigPath
            | Error::MissingStatePath
            | Error::UnknownArgument { .. }
            | Error::NoServices { .. }
            | Error::SessionTooLong
            | Error::SessionIdle
            | Error::InputNotText
            | Error::Restrict { .. } => None,
            #[cfg(test)]
            Error::NoStatusScripted | Error::StatusNotAsked | Error::FilesNothing => None,
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
        Error::Core(CoreError::context(context, source))
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

impl From<kyriakon_control_core::account::Error> for Error {
    fn from(error: kyriakon_control_core::account::Error) -> Self {
        Error::Core(CoreError::Account(error))
    }
}
impl From<kyriakon_control_core::flow::Error> for Error {
    fn from(error: kyriakon_control_core::flow::Error) -> Self {
        Error::Core(CoreError::Flow(error))
    }
}
impl From<kyriakon_control_core::intent::Error> for Error {
    fn from(error: kyriakon_control_core::intent::Error) -> Self {
        Error::Core(CoreError::Intent(error))
    }
}
impl From<kyriakon_control_core::ipc::Error> for Error {
    fn from(error: kyriakon_control_core::ipc::Error) -> Self {
        Error::Core(CoreError::Ipc(error))
    }
}
impl From<kyriakon_control_core::util::Error> for Error {
    fn from(error: kyriakon_control_core::util::Error) -> Self {
        Error::Core(CoreError::Util(error))
    }
}
impl From<kyriakon_control_core::mail::Error> for Error {
    fn from(error: kyriakon_control_core::mail::Error) -> Self {
        Error::Core(CoreError::Mail(error))
    }
}
impl From<kyriakon_control_core::payments::Error> for Error {
    fn from(error: kyriakon_control_core::payments::Error) -> Self {
        Error::Core(CoreError::Payments(error))
    }
}
