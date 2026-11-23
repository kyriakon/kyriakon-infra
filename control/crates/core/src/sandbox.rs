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

/// `unveil(path, permissions)`, with the path and errno text in the error.
#[cfg(target_os = "openbsd")]
pub fn unveil(path: &str, permissions: &str) -> Result<(), String> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| format!("unveil {path:?}: the path contains a NUL"))?;
    let c_permissions = std::ffi::CString::new(permissions).expect("the unveil modes have no NUL");
    if unsafe { libc::unveil(c_path.as_ptr(), c_permissions.as_ptr()) } == -1 {
        return Err(format!(
            "unveil {path}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// The no-op for a workstation, where `unveil(2)` does not exist.
#[cfg(not(target_os = "openbsd"))]
pub fn unveil(_path: &str, _permissions: &str) -> Result<(), String> {
    Ok(())
}

/// Lock the list: after this no later unveil can widen the view and a path not
/// named is invisible. Strongly recommended by `unveil(2)`.
#[cfg(target_os = "openbsd")]
pub fn lock() -> Result<(), String> {
    if unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) } == -1 {
        return Err(format!(
            "unveil (lock): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
pub fn lock() -> Result<(), String> {
    Ok(())
}

/// `access(path, R_OK)` after the list is locked. A path the list omitted has no
/// rule, so the call fails and the process stops with its name instead of
/// surfacing later as a missing file a sweep reads as empty. Exec targets cannot
/// be probed this way: `access(2)` is a read operation and an `x`-only rule
/// refuses it.
#[cfg(target_os = "openbsd")]
pub fn probe(path: &str) -> Result<(), String> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| format!("unveil {path:?} (probe): the path contains a NUL"))?;
    if unsafe { libc::access(c_path.as_ptr(), libc::R_OK) } == -1 {
        let source = std::io::Error::last_os_error();
        // ENOENT here is not a missing file: the unveil that named this path
        // would have failed on that. It is the shape of "no rule covers this
        // path", which is the omission the probe exists to report.
        if source.raw_os_error() == Some(libc::ENOENT) {
            return Err(format!(
                "unveil {path} (probe): no rule covers this path after the list was locked"
            ));
        }
        return Err(format!("unveil {path} (probe): {source}"));
    }
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
pub fn probe(_path: &str) -> Result<(), String> {
    Ok(())
}

/// `pledge(promises, NULL)`: the syscall set the process may use from here on.
/// The exec promise set stays NULL, so a child starts with no pledge of its own
/// and its own reads are its own business.
#[cfg(target_os = "openbsd")]
pub fn pledge(promises: &str) -> Result<(), String> {
    let promises = std::ffi::CString::new(promises).expect("the promise list has no NUL");
    if unsafe { libc::pledge(promises.as_ptr(), std::ptr::null()) } == -1 {
        return Err(format!("pledge: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
pub fn pledge(_promises: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(all(test, target_os = "openbsd"))]
mod tests {
    use super::*;

    /// A failed unveil names the path and the reason, which is what an operator
    /// needs to fix the configuration.
    #[test]
    fn a_failed_unveil_names_the_path_and_the_errno() {
        let message = unveil("/nonexistent-kyriakon-unveil-probe/child", "r").unwrap_err();
        assert!(
            message.contains("/nonexistent-kyriakon-unveil-probe/child"),
            "{message}"
        );
        assert!(message.contains("No such file or directory"), "{message}");
    }

    /// A probe that cannot reach its path names the path and says the list
    /// missed it, and one that can reach its path passes.
    #[test]
    fn a_probe_names_the_path_and_the_missing_rule() {
        let message = probe("/nonexistent-kyriakon-probe/child").unwrap_err();
        assert!(
            message.contains("/nonexistent-kyriakon-probe/child"),
            "{message}"
        );
        assert!(message.contains("no rule covers this path"), "{message}");
        // A readable path must pass, or the probe would fail every process on a
        // correctly configured box.
        probe("/").unwrap();
    }
}
