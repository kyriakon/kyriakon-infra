//! Zero-access mail encryptor.
//!
//! Turns an RFC 5322 message into whole-message RFC 3156 PGP/MIME ciphertext.
//! The OpenPGP engine is GnuPG; this crate only resolves the keyring, drives
//! gpg, and wraps the result in the `multipart/encrypted` envelope. No private
//! key is ever touched — encryption is to public certs only.
//!
//! Keyring: a directory of `<base-localpart>.asc` armored public certs, the
//! on-box sync of the git-tracked published set. Recipients with a `+tag`
//! resolve to the base localpart.
//!
//! Fail-closed: no key file for the recipient => error, and the caller never
//! sees plaintext.
//!
//! Socket protocol (daemon): one request per connection. Request = `<user>\n`
//! followed by the raw message; message end is the client's half-close (EOF).
//! Response = ciphertext only on success; on error the connection is closed
//! with no bytes written, so the caller (C shim) fails the save and never
//! writes plaintext.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

/// On-box keyring location — sync of the git-tracked published key set.
pub const DEFAULT_KEYRING: &str = "/etc/kyriakon/keys";
/// Daemon socket; the Dovecot C shim talks to us here.
pub const DEFAULT_SOCKET: &str = "/var/run/kyriakon/encrypt.sock";
/// gpg homedir. gpg writes pubring.kbx/random_seed here even with
/// `--recipient-file`, so it must be a writable, private dir — never a user's
/// `$HOME`. Provision owns it and keeps it out of any account path.
pub const DEFAULT_GPG_HOME: &str = "/var/run/kyriakon/gpg";

#[derive(Debug)]
pub enum Error {
    /// Recipient base localpart is empty or contains characters outside
    /// `[A-Za-z0-9._-]` — anything else could escape the keyring directory.
    InvalidUser(String),
    /// No `<base-localpart>.asc` in the keyring.
    MissingKey(String),
    /// gpg failed (bad key file, expired/revoked key, ...).
    Gpg(String),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidUser(u) => write!(f, "invalid recipient localpart: {u:?}"),
            Error::MissingKey(b) => write!(f, "no public key for {b:?} in keyring"),
            Error::Gpg(e) => write!(f, "gpg failed: {e}"),
            Error::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// Strip a `+tag` to the base localpart and validate it. The charset check is
/// a trust-boundary guard: the user string is joined into a keyring path.
pub fn base_localpart(user: &str) -> Result<&str, Error> {
    let base = user.split('+').next().unwrap_or("");
    if base.is_empty()
        || !base
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(Error::InvalidUser(user.to_string()));
    }
    Ok(base)
}

/// Encrypt `input` (an RFC 5322 message) to `user`'s public cert in
/// `keyring`, returning the RFC 3156 `multipart/encrypted` envelope. The
/// message bytes — headers and body — are encrypted verbatim. `gpg_home` is
/// the writable dir gpg uses for its scratch keybox/seed.
pub fn encrypt(
    user: &str,
    keyring: &Path,
    gpg_home: &Path,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    let base = base_localpart(user)?;
    let key = keyring.join(format!("{base}.asc"));
    if !key.is_file() {
        return Err(Error::MissingKey(base.to_string()));
    }
    let armor = armored_ciphertext(&key, gpg_home, input)?;
    Ok(rfc3156_envelope(&make_boundary(), &armor))
}

fn armored_ciphertext(key: &Path, gpg_home: &Path, input: &[u8]) -> Result<Vec<u8>, Error> {
    ensure_gpg_home(gpg_home)?;
    // --recipient-file reads the armored cert directly: no key import, no
    // trustdb, and the keyring file stays the single source. --homedir points
    // gpg at the daemon's writable scratch dir (gpg writes pubring.kbx and
    // random_seed even for --recipient-file). --no-options ignores any user
    // gpg.conf (e.g. a default-key).
    let mut child = Command::new("gpg")
        .args([
            "--batch",
            "--no-tty",
            "--no-options",
            "--encrypt",
            "--armor",
            "--no-encrypt-to",
            "--recipient-file",
        ])
        .arg(key)
        .arg("--homedir")
        .arg(gpg_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Gpg(format!("cannot spawn gpg: {e}")))?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(input)
        .map_err(|e| Error::Gpg(format!("cannot write to gpg: {e}")))?;
    let out = child
        .wait_with_output()
        .map_err(|e| Error::Gpg(format!("cannot wait for gpg: {e}")))?;
    if !out.status.success() {
        return Err(Error::Gpg(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(out.stdout)
}

/// Create the gpg scratch dir (0700). Idempotent; run per message because a
/// save-path daemon can't assume external setup completed.
fn ensure_gpg_home(gpg_home: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(gpg_home)
        .map_err(|e| Error::Gpg(format!("cannot create gpg homedir: {e}")))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(gpg_home, std::fs::Permissions::from_mode(0o700)).ok();
    Ok(())
}

/// RFC 3156 §4 envelope: `multipart/encrypted` with the `Version: 1` part and
/// the armored ciphertext as `application/octet-stream`.
fn rfc3156_envelope(boundary: &str, armor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(armor.len() + 256);
    out.extend_from_slice(
        format!(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\n\
             \tboundary=\"{boundary}\"\n\
             MIME-Version: 1.0\n\
             \n\
             This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156).\n\
             \n\
             --{boundary}\n\
             Content-Type: application/pgp-encrypted\n\
             \n\
             Version: 1\n\
             \n\
             --{boundary}\n\
             Content-Type: application/octet-stream\n\
             \n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(armor);
    out.extend_from_slice(format!("\n--{boundary}--\n").as_bytes());
    out
}

/// Unique-per-message boundary: pid + monotonic-ish nanos. Only needs to be
/// unique within the message, not globally.
fn make_boundary() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("kyriakon-{}-{nanos:x}", std::process::id())
}

/// Run the daemon: serve one request per connection on `socket`.
/// Returns only when the listener fails (socket dir missing, bind error).
pub fn serve(socket: &Path, keyring: &Path, gpg_home: &Path) -> Result<(), Error> {
    // Stale socket from a previous crash; safe to remove because bind would
    // fail on it, and a live daemon would make bind fail anyway.
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let keyring = keyring.to_path_buf();
                let gpg_home = gpg_home.to_path_buf();
                thread::spawn(move || handle_conn(stream, &keyring, &gpg_home));
            }
            Err(e) => eprintln!("kyriakon-encrypt: accept: {e}"),
        }
    }
    Ok(())
}

fn handle_conn(mut stream: UnixStream, keyring: &Path, gpg_home: &Path) {
    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).is_err() {
        return;
    }
    let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
        eprintln!("kyriakon-encrypt: request missing user line");
        return;
    };
    let user = String::from_utf8_lossy(&buf[..nl]);
    match encrypt(&user, keyring, gpg_home, &buf[nl + 1..]) {
        Ok(out) => {
            if stream.write_all(&out).is_err() {
                eprintln!("kyriakon-encrypt: write response: client gone");
            }
        }
        Err(e) => {
            // Fail-closed: no bytes written, caller must treat empty response
            // as a failed save. Never emit plaintext on the wire.
            eprintln!("kyriakon-encrypt: {user}: {e}");
        }
    }
}
