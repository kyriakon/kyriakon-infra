//! The encryptor's narrowed view.
//!
//! The process reads one armoured certificate under `keyring`, writes gpg's
//! scratch homedir, and executes `/usr/local/bin/gpg`. The child starts after
//! `execve` with no unveils of its own, so nothing gpg reads or writes needs an
//! entry here. Nothing else is named: an inbound message cannot make the
//! encryptor open a member's mail, the store or a key it was not given.
//!
//! The crate keeps no dependency of its own, so the three system calls are
//! declared here rather than through `libc`. On a workstation every call is a
//! no-op, so the crate's tests run unchanged on Linux and macOS.

use std::path::Path;

/// Unveil the certificate and scratch directory, lock the list, probe the paths
/// the process itself reads, and pledge what encrypting needs: stdio for the
/// two pipes, rpath for the certificate, wpath/cpath/fattr for the scratch
/// directory and its mode, and proc/exec for gpg.
pub fn restrict(keyring: &Path, gpg_home: &Path) -> Result<(), String> {
    let keyring = utf8(keyring, "keyring")?;
    let gpg_home = utf8(gpg_home, "gpg home")?;
    #[cfg(target_os = "openbsd")]
    {
        unveil(keyring, "r")?;
        unveil(gpg_home, "rwc")?;
        unveil("/usr/local/bin/gpg", "rx")?;
        // `list_packets` gives gpg `Stdio::null()`: the parent opens this.
        unveil("/dev/null", "rw")?;
        lock()?;
        probe(keyring)?;
        probe(gpg_home)?;
        pledge("stdio rpath wpath cpath fattr proc exec")
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        let _ = (keyring, gpg_home);
        Ok(())
    }
}

fn utf8<'a>(path: &'a Path, what: &str) -> Result<&'a str, String> {
    path.to_str()
        .ok_or_else(|| format!("the {what} path is not UTF-8: {}", path.display()))
}

#[cfg(target_os = "openbsd")]
mod ffi {
    use std::ffi::c_int;

    extern "C" {
        pub fn unveil(path: *const std::ffi::c_char, permissions: *const std::ffi::c_char)
            -> c_int;
        pub fn pledge(
            promises: *const std::ffi::c_char,
            execpromises: *const std::ffi::c_char,
        ) -> c_int;
        pub fn access(path: *const std::ffi::c_char, mode: c_int) -> c_int;
    }

    /// `R_OK` from `unistd.h`.
    pub const R_OK: c_int = 4;
}

#[cfg(target_os = "openbsd")]
fn unveil(path: &str, permissions: &str) -> Result<(), String> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| format!("unveil {path:?}: the path contains a NUL"))?;
    let permissions = std::ffi::CString::new(permissions).expect("the unveil modes have no NUL");
    if unsafe { ffi::unveil(c_path.as_ptr(), permissions.as_ptr()) } == -1 {
        return Err(format!(
            "unveil {path}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "openbsd")]
fn lock() -> Result<(), String> {
    if unsafe { ffi::unveil(std::ptr::null(), std::ptr::null()) } == -1 {
        return Err(format!(
            "unveil (lock): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "openbsd")]
fn probe(path: &str) -> Result<(), String> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| format!("unveil {path:?} (probe): the path contains a NUL"))?;
    if unsafe { ffi::access(c_path.as_ptr(), ffi::R_OK) } == -1 {
        let source = std::io::Error::last_os_error();
        if source.raw_os_error() == Some(2) {
            return Err(format!(
                "unveil {path} (probe): no rule covers this path after the list was locked"
            ));
        }
        return Err(format!("unveil {path} (probe): {source}"));
    }
    Ok(())
}

#[cfg(target_os = "openbsd")]
fn pledge(promises: &str) -> Result<(), String> {
    let promises = std::ffi::CString::new(promises).expect("the promise list has no NUL");
    if unsafe { ffi::pledge(promises.as_ptr(), std::ptr::null()) } == -1 {
        return Err(format!("pledge: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}
