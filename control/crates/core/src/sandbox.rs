//! The one wrapper over OpenBSD's `unveil(2)` and `pledge(2)`.
//!
//! Each binary states its own policy beside itself and calls these primitives,
//! so the drain, the responders and the terminal share one spelling of a failed
//! call. The encryptor keeps its own small declaration of the same three calls,
//! because that crate keeps no dependency of its own. On a workstation every
//! function is a no-op, so the acceptance suite still runs the real binaries on
//! Linux and macOS.
//!
//! A failure is returned to the caller rather than ignored: a process that
//! started with half a list would fail later as an unexplained `ENOENT`, so the
//! message names the path (or `pledge`) and the errno text.

use std::fmt;
use std::path::{Path, PathBuf};

/// A sandbox call the process would not allow: the call, the path, and the
/// kernel's own text.
#[derive(Debug)]
pub enum Error {
    /// A configured path is not UTF-8.
    PathNotUtf8 { what: &'static str, path: PathBuf },
    /// A path contains a NUL and cannot be a C string.
    NullPath { call: &'static str, path: String },
    /// `unveil(2)` refused a path.
    Unveil {
        path: String,
        source: std::io::Error,
    },
    /// `unveil(2)` refused to lock the list.
    Lock { source: std::io::Error },
    /// `access(2)` found no rule for a path the process reads.
    ProbeUncovered { path: String },
    /// `access(2)` refused a path the process reads.
    Probe {
        path: String,
        source: std::io::Error,
    },
    /// `pledge(2)` refused the promise set.
    Pledge { source: std::io::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PathNotUtf8 { what, path } => {
                write!(f, "the {what} path is not UTF-8: {}", path.display())
            }
            Error::NullPath { call, path } => {
                write!(f, "{call} {path:?}: the path contains a NUL")
            }
            Error::Unveil { path, source } => write!(f, "unveil {path}: {source}"),
            Error::Lock { source } => write!(f, "unveil (lock): {source}"),
            Error::ProbeUncovered { path } => write!(
                f,
                "unveil {path} (probe): no rule covers this path after the list was locked"
            ),
            Error::Probe { path, source } => write!(f, "unveil {path} (probe): {source}"),
            Error::Pledge { source } => write!(f, "pledge: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Unveil { source, .. }
            | Error::Lock { source }
            | Error::Probe { source, .. }
            | Error::Pledge { source } => Some(source),
            Error::PathNotUtf8 { .. } | Error::NullPath { .. } | Error::ProbeUncovered { .. } => {
                None
            }
        }
    }
}

/// A configured path as the `&str` the syscalls take, naming it when it is not
/// UTF-8 rather than formatting a sentence at each call site.
pub fn path<'a>(path: &'a Path, what: &'static str) -> Result<&'a str, Error> {
    path.to_str().ok_or_else(|| Error::PathNotUtf8 {
        what,
        path: path.to_path_buf(),
    })
}

/// `unveil(path, permissions)`, with the path and errno text in the error.
#[cfg(target_os = "openbsd")]
pub fn unveil(path: &str, permissions: &str) -> Result<(), Error> {
    let c_path = std::ffi::CString::new(path).map_err(|_| Error::NullPath {
        call: "unveil",
        path: path.to_string(),
    })?;
    let c_permissions = std::ffi::CString::new(permissions).expect("the unveil modes have no NUL");
    if unsafe { libc::unveil(c_path.as_ptr(), c_permissions.as_ptr()) } == -1 {
        return Err(Error::Unveil {
            path: path.to_string(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// The no-op for a workstation, where `unveil(2)` does not exist.
#[cfg(not(target_os = "openbsd"))]
pub fn unveil(_path: &str, _permissions: &str) -> Result<(), Error> {
    Ok(())
}

/// Lock the list: after this no later unveil can widen the view and a path not
/// named is invisible. Strongly recommended by `unveil(2)`.
#[cfg(target_os = "openbsd")]
pub fn lock() -> Result<(), Error> {
    if unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) } == -1 {
        return Err(Error::Lock {
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
pub fn lock() -> Result<(), Error> {
    Ok(())
}

/// `access(path, R_OK)` after the list is locked. A path the list omitted has no
/// rule, so the call fails and the process stops with its name instead of
/// surfacing later as a missing file a sweep reads as empty. Exec targets cannot
/// be probed this way: `access(2)` is a read operation and an `x`-only rule
/// refuses it.
#[cfg(target_os = "openbsd")]
pub fn probe(path: &str) -> Result<(), Error> {
    let c_path = std::ffi::CString::new(path).map_err(|_| Error::NullPath {
        call: "unveil (probe)",
        path: path.to_string(),
    })?;
    if unsafe { libc::access(c_path.as_ptr(), libc::R_OK) } == -1 {
        let source = std::io::Error::last_os_error();
        // ENOENT here is not a missing file: the unveil that named this path
        // would have failed on that. It is the shape of "no rule covers this
        // path", which is the omission the probe exists to report.
        if source.raw_os_error() == Some(libc::ENOENT) {
            return Err(Error::ProbeUncovered {
                path: path.to_string(),
            });
        }
        return Err(Error::Probe {
            path: path.to_string(),
            source,
        });
    }
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
pub fn probe(_path: &str) -> Result<(), Error> {
    Ok(())
}

/// `pledge(promises, NULL)`: the syscall set the process may use from here on.
/// The exec promise set stays NULL, so a child starts with no pledge of its own
/// and its own reads are its own business.
#[cfg(target_os = "openbsd")]
pub fn pledge(promises: &str) -> Result<(), Error> {
    let promises = std::ffi::CString::new(promises).expect("the promise list has no NUL");
    if unsafe { libc::pledge(promises.as_ptr(), std::ptr::null()) } == -1 {
        return Err(Error::Pledge {
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
pub fn pledge(_promises: &str) -> Result<(), Error> {
    Ok(())
}

#[cfg(all(test, target_os = "openbsd"))]
mod tests {
    use super::*;

    /// A failed unveil names the path and the reason, which is what an operator
    /// needs to fix the configuration.
    #[test]
    fn a_failed_unveil_names_the_path_and_the_errno() {
        let error = unveil("/nonexistent-kyriakon-unveil-probe/child", "r").unwrap_err();
        assert!(
            matches!(&error, Error::Unveil { path, .. } if path == "/nonexistent-kyriakon-unveil-probe/child"),
            "{error}"
        );
        assert!(
            error.to_string().contains("No such file or directory"),
            "{error}"
        );
    }

    /// A probe that cannot reach its path names the path and says the list
    /// missed it, and one that can reach its path passes.
    #[test]
    fn a_probe_names_the_path_and_the_missing_rule() {
        let error = probe("/nonexistent-kyriakon-probe/child").unwrap_err();
        assert!(
            matches!(&error, Error::ProbeUncovered { path } if path == "/nonexistent-kyriakon-probe/child"),
            "{error}"
        );
        // A readable path must pass, or the probe would fail every process on a
        // correctly configured box.
        probe("/").unwrap();
    }
}
