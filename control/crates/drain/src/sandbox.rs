//! The drain's narrowed filesystem and syscall view.
//!
//! The drain runs as root from cron with no listener and a one-pass lifetime,
//! so the one place to cut what a compromised pass could reach is its first
//! statement: unveil every path a pass opens, lock the list, then pledge the
//! syscall set the pass needs.
//!
//! [`restrict`] is called after the config is read (the config file itself is
//! read before the list exists) and before the store is touched. On OpenBSD it
//! unveils and pledges; elsewhere it is a no-op, so the acceptance suite and
//! `cargo test` still run on Linux and macOS.
//!
//! Every path below names the call site that opens it. A path a later transition
//! adds will fail with `EACCES` (the wrong mode) or `ENOENT` (no rule), and the
//! store and script errors already carry the path, so the failure names what is
//! missing rather than losing the intent.

use crate::transitions::Error;
use kyriakon_control_core::config::DrainConfig;

/// The promises a full pass needs, one per operation the pass performs:
///
/// * `stdio`: the baseline for read/write on open files, mmap, poll, wait4,
///   kqueue, timers and signals, which the tokio runtime and every child wait
///   use. It also lets libc open `/etc/localtime` and `/dev/null` itself.
/// * `rpath`: `read_to_string`/`read_dir` of the store, `/etc/passwd`, the mail
///   tables, the approval key and the keyring.
/// * `wpath`: writing the rate cache, the mail tables, store records, proofs and
///   the export bundle.
/// * `cpath`: creating, renaming and removing those files, the `<table>.lock`
///   directories and the store's intent/record removals.
/// * `fattr`: `set_permissions` on the rate cache, the table temp file and the
///   keyring `.asc`; `chown` on the export's files.
/// * `flock`: `Store::try_lock`'s `.drain.lock` and the ledger's
///   `payments.jsonl.lock`.
/// * `proc`: fork for every `Command`, and `wait4` on the child.
/// * `exec`: `execve` of the configured scripts, `sendmail`, `gpg`, `dig`,
///   `repquota` and `curl`.
///
/// Not present, because nothing in a pass asks for it: `inet` and `dns` (the
/// network calls are the `curl` and `dig` children, which start unpledged),
/// `unix` (no socket), `getpw` (the account list is read as a file, not through
/// `getpwnam`), `dpath` (no device or fifo), `id` (the drain never changes uid),
/// and `prot_exec` (the binary is linked with a non-lazy PLT).
#[cfg(target_os = "openbsd")]
const PROMISES: &str = "stdio rpath wpath cpath fattr flock proc exec";

/// Narrow the pass's file view to the paths it opens, then its syscalls.
///
/// Called once, before the first pass. A failure is fatal: a pass that starts
/// with half a list would fail later with an unexplained `ENOENT`, so the
/// error names the path (or `pledge`) and its errno text instead.
#[cfg(target_os = "openbsd")]
pub fn restrict(cfg: &DrainConfig) -> Result<(), Error> {
    // The store root, read/written/created/removed: `Store::try_lock` in the
    // binary, `Journal::load` in `run`, and every transition record under it.
    unveil(&cfg.store_root, "rwc")?;
    // The reserved names, read by the approval before it creates an account.
    unveil(&cfg.reserved, "r")?;
    // The box's account list, read to refuse a name that is already in use.
    unveil(&cfg.passwd, "r")?;
    // The HMAC key every review and password link is signed and verified with.
    unveil(&cfg.approval_key, "r")?;
    // The privileged scripts, exec'd by `transitions::boxrun::spawn_script`.
    // Execute only: the child starts with no unveils, so its own reads need no
    // entry here.
    unveil(&cfg.scripts, "x")?;
    // The enqueuer every notice runs through (`core::mail::notice`).
    unveil(&cfg.sendmail, "x")?;
    // The OpenPGP binary `keycheck::verify_signature` runs for an upload key.
    unveil(&cfg.gpg, "x")?;
    // The resolver `check_group_dns` runs, which needs no entry of its own for
    // `/etc/resolv.conf`: it is a different process after `execve`.
    unveil(&cfg.resolver, "x")?;
    // The quota reporter `refresh_space_used` runs.
    unveil(&cfg.repquota, "x")?;
    // The HTTPS client the rate cache is fetched with.
    unveil(&cfg.rates_fetch, "x")?;
    // The box keyring: `boxrun::write_public_key` writes an approved member's
    // `.asc`, and the export reads it back.
    unveil(&cfg.keyring_dir, "rwc")?;
    // The login proofs: `session::prune_proofs` reads and removes the expired
    // ones.
    unveil(&cfg.proof_dir, "rwc")?;
    // The plaintext Maildir `mailbox::run` reads and removes messages from.
    unveil(&cfg.mail_dir, "rwc")?;
    // The delivery-status spool `mailbox::bounces` reads and removes.
    unveil(&cfg.bounce_dir, "rwc")?;
    // The members' published trees the export writes its bundle under.
    unveil(&cfg.public_root, "rwc")?;
    // Stripe's signing secret, read at the top of the webhook pass. The API key
    // and the keyring publish token are not here: the drain passes their paths
    // as argv to `stripe-api.sh` and `publish-mail-key.sh`, which read them
    // after `execve` has dropped this process's unveils.
    unveil(&cfg.stripe_webhook_secret, "r")?;
    // The five mail tables. Each is rewritten through a sibling
    // `<name>.onboard.<pid>` and guarded by a `<name>.lock` directory whose
    // `pid` file is read back on a stale lock, so the containing directory
    // needs read, write and create. The files themselves are covered by it.
    for table in [
        &cfg.mail_domains,
        &cfg.virtuals,
        &cfg.mail_from,
        &cfg.dkim_domains,
        &cfg.spamd_alloweddomains,
    ] {
        unveil(parent_of(table)?, "rwc")?;
    }
    // The rate cache's directory: the cache is written through `<name>.new`
    // and a failed fetch is stamped in `<name>.attempt` beside it.
    unveil(parent_of(&cfg.rates)?, "rwc")?;
    // The export's scratch directory is made under the process's temp
    // directory, with gpg's homedir inside it.
    unveil(&temp_dir()?, "rwc")?;
    // `keycheck::verify_signature` names `/tmp` literally for the scratch
    // homedir a mail-key signature is checked in, whatever `TMPDIR` says.
    unveil("/tmp", "rwc")?;
    // `Stdio::null` opens this in the parent for an enqueued notice's stdout
    // and stderr and for a session check's stderr.
    unveil("/dev/null", "rw")?;
    // `store::status_token` reads sixteen bytes from the kernel pool for every
    // notice id and capability token; it opens this path itself.
    unveil("/dev/urandom", "r")?;

    // Lock the list: after this, no later unveil can widen the view and a path
    // not named above is invisible. Strongly recommended by unveil(2), and the
    // only state a pass cannot undo.
    if unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) } == -1 {
        return Err(failure("unveil (lock)", std::io::Error::last_os_error()));
    }

    // The exec promise set is NULL on purpose: the scripts and helpers are
    // themselves OpenBSD programs with their own pledge or none, and forcing
    // this pass's file view on a `/root/bin` script would fail its own reads.
    let promises = std::ffi::CString::new(PROMISES).expect("the promise list has no NUL");
    if unsafe { libc::pledge(promises.as_ptr(), std::ptr::null()) } == -1 {
        return Err(failure("pledge", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// The no-op for a workstation: the acceptance suite runs the real binaries on
/// Linux and macOS, where neither system call exists.
#[cfg(not(target_os = "openbsd"))]
pub fn restrict(_cfg: &DrainConfig) -> Result<(), Error> {
    Ok(())
}

/// `unveil(path, permissions)`, with the path and errno text in the error.
#[cfg(target_os = "openbsd")]
fn unveil(path: &str, permissions: &str) -> Result<(), Error> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| Error::Failed(format!("unveil {path:?}: the path contains a NUL")))?;
    let c_permissions = std::ffi::CString::new(permissions).expect("the unveil modes have no NUL");
    if unsafe { libc::unveil(c_path.as_ptr(), c_permissions.as_ptr()) } == -1 {
        return Err(failure(
            &format!("unveil {path}"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "openbsd")]
fn failure(what: &str, source: std::io::Error) -> Error {
    Error::Failed(format!("{what}: {source}"))
}

/// The directory an atomic rewrite creates its temp file and lock in.
#[cfg(target_os = "openbsd")]
fn parent_of(path: &str) -> Result<&str, Error> {
    std::path::Path::new(path)
        .parent()
        .and_then(|parent| parent.to_str())
        .filter(|parent| !parent.is_empty())
        .ok_or_else(|| Error::Failed(format!("{path} has no directory to unveil")))
}

#[cfg(target_os = "openbsd")]
fn temp_dir() -> Result<String, Error> {
    std::env::temp_dir()
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| Error::Failed("the temp directory is not UTF-8".to_string()))
}

#[cfg(all(test, target_os = "openbsd"))]
mod tests {
    use super::*;

    /// A failed unveil names the path and the reason, which is what the
    /// operator in cron mail needs to fix the config.
    #[test]
    fn a_failed_unveil_names_the_path_and_the_errno() {
        let error = unveil("/nonexistent-kyriakon-unveil-probe/child", "r").unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("/nonexistent-kyriakon-unveil-probe/child"),
            "{message}"
        );
        assert!(message.contains("No such file or directory"), "{message}");
    }
}
