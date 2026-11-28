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
//! `access(2)` is a read operation and an `x`-only rule refuses it. A missing
//! parent directory fails at `unveil`, and a missing entry fails at `execve`.
//! A path only a child opens after `execve` is not probed for the same reason.
//! The webhook secret is probed only when it exists: a box without one is a
//! valid box, and `unveil` remembers a non-directory by name.
//! The rate cache file is lazy (the first run creates it), so its directory is
//! probed instead.

use std::fmt;

use crate::transitions::Error as Transitions;
use kyriakon_control_core::config::DrainConfig;
#[cfg(target_os = "openbsd")]
use kyriakon_control_core::sandbox;

/// A sandbox policy the pass could not install.
///
/// The kernel's own text is the reason on the syscall variants: it names the
/// path and the errno, which is what an operator needs to fix the policy.
#[derive(Debug)]
pub enum Error {
    /// `unveil(2)` refused a path.
    Unveil {
        source: kyriakon_control_core::sandbox::Error,
    },
    /// `unveil(2)` refused to lock the list.
    Lock {
        source: kyriakon_control_core::sandbox::Error,
    },
    /// `access(2)` refused a path the pass reads.
    Probe {
        source: kyriakon_control_core::sandbox::Error,
    },
    /// `pledge(2)` refused the syscall set.
    Pledge {
        source: kyriakon_control_core::sandbox::Error,
    },
    /// A configured path has no directory to unveil.
    NoParent { path: String },
    /// The temp directory is not UTF-8.
    TempDirNotUtf8,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unveil { source }
            | Error::Lock { source }
            | Error::Probe { source }
            | Error::Pledge { source } => source.fmt(f),
            Error::NoParent { path } => write!(f, "{path} has no directory to unveil"),
            Error::TempDirNotUtf8 => f.write_str("the temp directory is not UTF-8"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Unveil { source }
            | Error::Lock { source }
            | Error::Probe { source }
            | Error::Pledge { source } => Some(source),
            Error::NoParent { .. } | Error::TempDirNotUtf8 => None,
        }
    }
}

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
///   files and the store's intent/record removals.
/// * `fattr`: `set_permissions` on the rate cache, the table temp file, the
///   keyring `.asc` and every directory `ensure_dir_owned` repairs.
/// * `chown`: changing the owner, which `fattr` alone refuses with `EPERM`:
///   `export::write_tree` hands each bundle file to the member's uid, and
///   `Store::ensure_dir_owned` hands `accounts/<name>/` to the store's owner.
/// * `flock`: `Store::try_lock`'s `.drain.lock`, the ledger's
///   `payments.jsonl.lock` and the mail table's `<table>.lock`.
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
const PROMISES: &str = "stdio rpath wpath cpath fattr chown flock proc exec";

/// Narrow the pass's file view to the paths it opens, then its syscalls.
///
/// Called once, before the first pass. A failure is fatal: a pass that starts
/// with half a list would fail later with an unexplained `ENOENT`, so the
/// error names the path (or `pledge`) and its errno text instead.
#[cfg(target_os = "openbsd")]
pub fn restrict(cfg: &DrainConfig) -> Result<(), Transitions> {
    // A box whose card rail is not configured yet has no signing secret, and
    // `transitions::stripe` reports that rather than failing the pass. Stat it
    // before the first unveil: after that a missing file and an unveiled one
    // both answer `ENOENT`, so the probe below cannot tell them apart.
    let webhook_secret_present = std::path::Path::new(&cfg.stripe_webhook_secret).exists();
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
    // The key checker, a separate build root run as a process so this half does
    // not link the parser. Its spawn path and this unveiled path are one string,
    // named before the list is locked; a configured parent directory that is
    // missing fails startup rather than every check falling back to advisory.
    kyriakon_control_core::mail::pgp::configure_keygen_check(&cfg.keygen_check);
    unveil(&cfg.keygen_check, "x")?;
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
    // after `execve` has dropped this process's unveils. This succeeds on a
    // missing final component and fails on a missing directory, which keeps
    // the startup diagnostic; only the probe is conditional.
    unveil(&cfg.stripe_webhook_secret, "r")?;
    // The five mail tables. Each is replaced through a sibling candidate and a
    // `<name>.lock` kernel-flock file, so the containing directory needs read,
    // write and create. The files themselves are covered by it.
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
    sandbox::lock().map_err(|source| Error::Lock { source })?;

    // With the list locked, a read path named above is reachable and one that
    // is not fails with `ENOENT`. Probe every path the pass reads here, before
    // the pledge, so a missing entry is a startup failure that names the path
    // instead of a later `ENOENT` that a sweep reads as an empty spool.
    probe_pass_paths(cfg)?;
    if webhook_secret_present {
        probe(&cfg.stripe_webhook_secret)?;
    }

    // The exec promise set is NULL on purpose: the scripts and helpers are
    // themselves OpenBSD programs with their own pledge or none, and forcing
    // this pass's file view on a `/root/bin` script would fail its own reads.
    sandbox::pledge(PROMISES).map_err(|source| Error::Pledge { source })?;
    Ok(())
}

/// The no-op for a workstation: the acceptance suite runs the real binaries on
/// Linux and macOS, where neither system call exists.
#[cfg(not(target_os = "openbsd"))]
pub fn restrict(_cfg: &DrainConfig) -> Result<(), Transitions> {
    Ok(())
}

/// The policy's spelling of the shared wrapper: one local variant per refused
/// call, so the pass reads which call failed without parsing the kernel's text.
#[cfg(target_os = "openbsd")]
fn unveil(path: &str, permissions: &str) -> Result<(), Transitions> {
    sandbox::unveil(path, permissions).map_err(|source| Transitions::from(Error::Unveil { source }))
}

/// The directory an atomic rewrite creates its temp file and lock in.
#[cfg(target_os = "openbsd")]
fn parent_of(path: &str) -> Result<&str, Transitions> {
    let parent = std::path::Path::new(path)
        .parent()
        .and_then(|parent| parent.to_str())
        .filter(|parent| !parent.is_empty())
        .ok_or_else(|| Error::NoParent {
            path: path.to_string(),
        })?;
    Ok(parent)
}

#[cfg(target_os = "openbsd")]
fn temp_dir() -> Result<String, Transitions> {
    Ok(std::env::temp_dir()
        .to_str()
        .map(str::to_string)
        .ok_or(Error::TempDirNotUtf8)?)
}

/// Every always-present read path the pass opens after `restrict` returns,
/// checked once the list is locked. Kept separate from the unveil calls on
/// purpose: a path listed here but not unveiled is exactly the omission this
/// catches. The webhook secret is the caller's, because its absence is valid.
#[cfg(target_os = "openbsd")]
fn probe_pass_paths(cfg: &DrainConfig) -> Result<(), Transitions> {
    for path in [
        cfg.store_root.as_str(),
        cfg.reserved.as_str(),
        cfg.passwd.as_str(),
        cfg.approval_key.as_str(),
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
    // fail every pass. A target whose entry is missing fails at `execve` with
    // `ENOENT`, which the fixture catches for a configured script.
    Ok(())
}

/// The policy's spelling of the shared probe.
#[cfg(target_os = "openbsd")]
fn probe(path: &str) -> Result<(), Transitions> {
    sandbox::probe(path).map_err(|source| Transitions::from(Error::Probe { source }))
}
