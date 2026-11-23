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
//! Every path below names the call site that opens it. Once the list is locked,
//! each path the pass reads itself, configured or hardcoded, is probed, so an
//! entry this list forgot fails the pass at startup with the path and its errno
//! rather than surfacing later as an empty spool. Exec targets are not probed:
//! `access(2)` is a read operation and an `x`-only rule refuses it. `unveil`
//! fails on a target that does not exist, and a missing entry fails at `execve`.
//! A path only a child opens after `execve` is not probed for the same reason.
//! The rate cache file is lazy (the first run creates it), so its directory is
//! probed instead.

use crate::transitions::Error;
use kyriakon_control_core::config::DrainConfig;
#[cfg(target_os = "openbsd")]
use kyriakon_control_core::sandbox;

/// The promises a full pass needs, one per operation the pass performs:
///
/// * `stdio`: read, write and control of the descriptors this process already
///   holds, plus mmap, poll, wait4, kqueue, timers and signals, which the tokio
///   runtime and every child wait use. Opening a path is unveil's business:
///   `/dev/null` is an unveil entry below, and `/etc/localtime` is never opened.
/// * `rpath`: `read_to_string`/`read_dir` of the store, `/etc/passwd`, the mail
///   tables, the approval key and the keyring.
/// * `wpath`: writing the rate cache, the mail tables, store records, proofs and
///   the export bundle.
/// * `cpath`: creating, renaming and removing those files, the `<table>.lock`
///   directories and the store's intent/record removals.
/// * `fattr`: `set_permissions` on the rate cache, the table temp file, the
///   keyring `.asc` and every directory `ensure_dir_owned` repairs.
/// * `chown`: changing the owner, which `fattr` alone refuses with `EPERM`:
///   `export::write_tree` hands each bundle file to the member's uid, and
///   `Store::ensure_dir_owned` hands `accounts/<name>/` to the store's owner.
/// * `flock`: `Store::try_lock`'s `.drain.lock` and the ledger's
///   `payments.jsonl.lock`.
/// * `proc`: fork for every `Command`, and `wait4` on the child.
/// * `exec`: `execve` of the configured scripts, `sendmail`, `gpg`, `dig`,
///   `repquota`, `curl` and `/bin/kill`, the last for the stale-lock liveness
///   check.
///
/// Not present, because nothing in a pass asks for it: `inet` and `dns` (the
/// network calls are the `curl` and `dig` children, which start unpledged),
/// `unix` (no socket), `getpw` (the account list is read as a file, not through
/// `getpwnam`), `dpath` (no device or fifo), `id` (the drain never changes uid),
/// and `prot_exec` (the binary is linked with a non-lazy PLT).
#[cfg(target_os = "openbsd")]
const PROMISES: &str = "stdio rpath wpath cpath fattr chown flock proc exec";

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
    // The OpenPGP binary `mail::pgp` runs for a key check or a signature.
    unveil(&cfg.gpg, "x")?;
    // The resolver `check_group_dns` runs, which needs no entry of its own for
    // `/etc/resolv.conf`: it is a different process after `execve`.
    unveil(&cfg.resolver, "x")?;
    // The quota reporter `refresh_space_used` runs.
    unveil(&cfg.repquota, "x")?;
    // The HTTPS client the rate cache is fetched with.
    unveil(&cfg.rates_fetch, "x")?;
    // The liveness check `groups::stale_table_lock` runs on a `<table>.lock`
    // owner's pid. The path is a literal in that function rather than a config
    // value because `/bin/kill` is base-system, and without this entry the check
    // reads a failed spawn as "the owner is alive", so a stale lock is never
    // reaped and every table write fails forever.
    unveil("/bin/kill", "x")?;
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
    // The scratch directories a journal pass and a transition make under the
    // process's temp directory.
    unveil(&temp_dir()?, "rwc")?;
    // `mail::pgp::run_gpg` names `/tmp` literally for the scratch homedir a key
    // is imported into, whatever `TMPDIR` says.
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
    sandbox::lock().map_err(Error::Failed)?;

    // With the list locked, a read path named above is reachable and one that
    // is not fails with `ENOENT`. Probe every path the pass reads here, before
    // the pledge, so a missing entry is a startup failure that names the path
    // instead of a later `ENOENT` that a sweep reads as an empty spool.
    probe_pass_paths(cfg)?;

    // The exec promise set is NULL on purpose: the scripts and helpers are
    // themselves OpenBSD programs with their own pledge or none, and forcing
    // this pass's file view on a `/root/bin` script would fail its own reads.
    sandbox::pledge(PROMISES).map_err(Error::Failed)?;
    Ok(())
}

/// The no-op for a workstation: the acceptance suite runs the real binaries on
/// Linux and macOS, where neither system call exists.
#[cfg(not(target_os = "openbsd"))]
pub fn restrict(_cfg: &DrainConfig) -> Result<(), Error> {
    Ok(())
}

/// The policy's spelling of the shared wrapper: the drain's error is
/// `Failed`, so one mapping turns a refused call into the pass's own failure.
#[cfg(target_os = "openbsd")]
fn unveil(path: &str, permissions: &str) -> Result<(), Error> {
    sandbox::unveil(path, permissions).map_err(Error::Failed)
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

/// Every read path the pass opens after `restrict` returns, checked once the
/// list is locked. Kept separate from the unveil calls on purpose: a path listed
/// here but not unveiled is exactly the omission this catches.
#[cfg(target_os = "openbsd")]
fn probe_pass_paths(cfg: &DrainConfig) -> Result<(), Error> {
    for path in [
        cfg.store_root.as_str(),
        cfg.reserved.as_str(),
        cfg.passwd.as_str(),
        cfg.approval_key.as_str(),
        cfg.stripe_webhook_secret.as_str(),
        cfg.keyring_dir.as_str(),
        cfg.proof_dir.as_str(),
        cfg.mail_dir.as_str(),
        cfg.bounce_dir.as_str(),
        cfg.public_root.as_str(),
    ] {
        probe(path)?;
    }
    // The tables and the rate cache are opened through their directory, which
    // is what the unveil above names. The cache file itself is created on the
    // first pass and is deliberately not probed.
    for table in [
        &cfg.mail_domains,
        &cfg.virtuals,
        &cfg.mail_from,
        &cfg.dkim_domains,
        &cfg.spamd_alloweddomains,
    ] {
        probe(parent_of(table)?)?;
    }
    probe(parent_of(&cfg.rates)?)?;
    probe(&temp_dir()?)?;
    for path in ["/tmp", "/dev/null", "/dev/urandom"] {
        probe(path)?;
    }
    // The exec targets are deliberately absent. `access(2)` is a read
    // operation, so it is refused by an `x`-only rule, and probing them would
    // fail every pass. `unveil` itself already fails on a target that does not
    // exist; a target whose entry is missing fails at `execve` with `ENOENT`,
    // which the fixture catches for `/bin/kill` through the stale lock.
    Ok(())
}

/// The policy's spelling of the shared probe.
#[cfg(target_os = "openbsd")]
fn probe(path: &str) -> Result<(), Error> {
    sandbox::probe(path).map_err(Error::Failed)
}
