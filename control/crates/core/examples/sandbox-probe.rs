//! Prove a locked unveil list and a pledge are enforced by the kernel.
//!
//! `sandbox-probe path` unveils a harmless directory, locks the list, then tries
//! to read `/etc/passwd`, which the list did not name. `sandbox-probe syscall`
//! pledges `stdio` and tries `chmod(2)`, which that promise does not carry: the
//! kernel kills the process with `SIGABRT`. The verification script checks both,
//! so a wrapper that silently ignored a failure would fail the OpenBSD VM job.
//!
//! Elsewhere this is a no-op: unveil(2) and pledge(2) do not exist on a
//! workstation.

use std::ffi::CString;
use std::process::ExitCode;

use kyriakon_control_core::sandbox;

fn main() -> ExitCode {
    if !cfg!(target_os = "openbsd") {
        println!("skip: not OpenBSD");
        return ExitCode::SUCCESS;
    }
    match std::env::args().nth(1).as_deref() {
        Some("path") => path(),
        Some("syscall") => syscall(),
        _ => {
            eprintln!("usage: sandbox-probe path|syscall");
            ExitCode::from(64)
        }
    }
}

/// A path the locked list did not name must be unreachable.
fn path() -> ExitCode {
    if let Err(error) = sandbox::unveil("/tmp", "rwc").and_then(|()| sandbox::lock()) {
        eprintln!("sandbox-probe: {error}");
        return ExitCode::FAILURE;
    }
    match std::fs::read("/etc/passwd") {
        Ok(_) => {
            eprintln!("sandbox-probe: a forbidden path was readable");
            ExitCode::FAILURE
        }
        Err(error) => {
            println!("blocked: /etc/passwd ({error})");
            ExitCode::SUCCESS
        }
    }
}

/// A syscall outside the pledged set must abort the process. Reaching the line
/// after it means pledge did nothing.
fn syscall() -> ExitCode {
    if let Err(error) = sandbox::pledge("stdio") {
        eprintln!("sandbox-probe: {error}");
        return ExitCode::FAILURE;
    }
    let path = CString::new("/etc/passwd").expect("no NUL");
    unsafe {
        libc::chmod(path.as_ptr(), 0o600);
    }
    eprintln!("sandbox-probe: a forbidden syscall returned");
    ExitCode::FAILURE
}
