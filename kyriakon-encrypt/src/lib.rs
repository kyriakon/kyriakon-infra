//! Zero-access mail encryptor.
//!
//! Turns an RFC 5322 message into whole-message RFC 3156 PGP/MIME ciphertext.
//! The OpenPGP engine is GnuPG; this crate only resolves the keyring, drives
//! gpg, and wraps the result in the `multipart/encrypted` envelope. No private
//! key is ever touched - encryption is to public certs only.
//!
//! Keyring: a directory of `<base-localpart>.asc` armored public certs, the
//! on-box sync of the git-tracked published set. Recipients with a `+tag`
//! resolve to the base localpart.
//!
//! Fail-closed: no key file for the recipient => error, and the caller never
//! sees plaintext.
//!
//! Input that is already an envelope of ours for that recipient is returned
//! unchanged, so a client re-uploading a message cannot have it encrypted twice.
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

/// On-box keyring location - sync of the git-tracked published key set.
pub const DEFAULT_KEYRING: &str = "/etc/kyriakon/keys";
/// Daemon socket; the Dovecot C shim talks to us here.
pub const DEFAULT_SOCKET: &str = "/var/run/kyriakon/encrypt.sock";
/// gpg homedir. gpg writes pubring.kbx/random_seed here even with
/// `--recipient-file`, so it must be a writable, private dir - never a user's
/// `$HOME`. Provision owns it and keeps it out of any account path.
pub const DEFAULT_GPG_HOME: &str = "/var/run/kyriakon/gpg";

#[derive(Debug)]
pub enum Error {
    /// Recipient base localpart is empty or contains characters outside
    /// `[A-Za-z0-9._-]` - anything else could escape the keyring directory.
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
/// message bytes - headers and body - are encrypted verbatim. `gpg_home` is
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
    if already_encrypted(input, &key, gpg_home) {
        return Ok(input.to_vec());
    }
    let payload = protected_payload(input);
    let armor = armored_ciphertext(&key, gpg_home, &payload)?;
    Ok(rfc3156_envelope(&make_boundary(), &armor, input))
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

/// The first line of every envelope this crate produces. The Dovecot C shim
/// carries the same string as KYRIAKON_MARKER for its save_finish backstop, so
/// the two have to stay in step.
const ENVELOPE_MARKER: &str =
    "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";";

/// Whether `input` is already an envelope this crate built for the recipient of
/// `cert`, in which case it is saved as it stands rather than encrypted again.
///
/// A second encryption does not lose the message, but it breaks it: the store
/// holds a ciphertext whose payload is another envelope, so a client decrypts
/// once and shows an encrypted blob where the mail should be. A client that
/// files a message by re-uploading it on the save path did that on the live box.
///
/// The marker alone cannot be trusted to mean ciphertext, since a sender could
/// mail a file that begins with it and have plaintext written to the store as
/// though it were encrypted. So the input has to name a key of the recipient's
/// own cert in a public-key encrypted session key packet. Ciphertext addressed
/// to another key, a copy of the cert carried inline, and a stream gpg cannot
/// parse all fall through to normal encryption.
fn already_encrypted(input: &[u8], cert: &Path, gpg_home: &Path) -> bool {
    if !input.starts_with(ENVELOPE_MARKER.as_bytes()) {
        return false;
    }
    let Ok(cert_packets) = std::fs::read(cert) else {
        return false;
    };
    let ours = cert_key_ids(&list_packets(&cert_packets, gpg_home));
    if ours.is_empty() {
        return false;
    }
    message_key_ids(&list_packets(input, gpg_home))
        .iter()
        .any(|id| ours.contains(id))
}

/// Long key ids of the public key packets in a dump of a cert: its primary key
/// and any subkeys. These sit on a line of their own with no packet-type
/// prefix, which is what separates them from ids mentioned inside signature
/// packets on the same line as the packet.
fn cert_key_ids(packets: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(packets)
        .lines()
        .filter(|line| !line.trim_start().starts_with(':'))
        .filter_map(|line| line.trim().strip_prefix("keyid:").map(str::trim))
        .filter_map(long_key_id)
        .collect()
}

/// Long key ids from the public-key encrypted session key packets of a dump:
/// one per recipient, and present only where the stream really is ciphertext
/// addressed to a key. A stream that mentions a key anywhere else yields
/// nothing, which is what keeps a message carrying a copy of a cert from being
/// mistaken for ciphertext.
fn message_key_ids(packets: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(packets)
        .lines()
        .filter(|line| line.trim_start().starts_with(":pubkey enc packet:"))
        .filter_map(|line| line.split("keyid").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(long_key_id)
        .collect()
}

fn long_key_id(id: &str) -> Option<String> {
    (id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_string())
}

/// `gpg --list-packets` over `input`. Inspection only, and best effort: a
/// stream gpg cannot parse produces no output, which the caller reads as "not
/// our ciphertext" and encrypts as usual rather than failing the save.
///
/// The exit status is deliberately ignored. gpg prints the packet listing and
/// then exits non-zero for a message it cannot decrypt, which is every message
/// here: the daemon's gpg homedir holds no secret key, by design. Treating that
/// status as fatal discards the listing and the caller sees no recipients at
/// all.
fn list_packets(input: &[u8], gpg_home: &Path) -> Vec<u8> {
    if ensure_gpg_home(gpg_home).is_err() {
        return Vec::new();
    }
    let spawned = Command::new("gpg")
        .args([
            "--batch",
            "--no-tty",
            "--no-options",
            "--list-packets",
            "--homedir",
        ])
        .arg(gpg_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else {
        return Vec::new();
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(input).is_err() {
            return Vec::new();
        }
    }
    match child.wait_with_output() {
        Ok(out) => out.stdout,
        Err(_) => Vec::new(),
    }
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

/// (headers, separator, body) of an RFC 5322 message: the header block without
/// its terminating empty line, that empty line itself, and everything after it.
/// A message with no empty line has no body.
fn split_message(msg: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let mut pos = 0;
    while pos < msg.len() {
        let Some(off) = msg[pos..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let nl = pos + off;
        let line_end = if nl > pos && msg[nl - 1] == b'\r' {
            nl - 1
        } else {
            nl
        };
        if line_end == pos {
            return (&msg[..pos], &msg[pos..=nl], &msg[nl + 1..]);
        }
        pos = nl + 1;
    }
    (msg, b"", b"")
}

/// The span of every header in a block: its lowercase name, and the byte range
/// covering it plus any folded continuation lines, excluding the final line
/// ending. A line that is neither a header nor a continuation is folded into
/// the preceding header, so a message that is only being rewritten never loses
/// bytes.
fn header_spans(block: &[u8]) -> Vec<(String, usize, usize)> {
    let mut spans: Vec<(String, usize, usize)> = Vec::new();
    let mut pos = 0;
    while pos < block.len() {
        let (line_end, next) = match block[pos..].iter().position(|&b| b == b'\n') {
            Some(off) => {
                let nl = pos + off;
                let line_end = if nl > pos && block[nl - 1] == b'\r' {
                    nl - 1
                } else {
                    nl
                };
                (line_end, nl + 1)
            }
            None => (block.len(), block.len()),
        };
        let line = &block[pos..line_end];
        let name = match line.first() {
            Some(b' ') | Some(b'\t') => None,
            _ => line
                .iter()
                .position(|&b| b == b':')
                .map(|c| String::from_utf8_lossy(&line[..c]).to_ascii_lowercase()),
        };
        match name {
            Some(name) => spans.push((name, pos, line_end)),
            None => {
                if let Some(last) = spans.last_mut() {
                    last.2 = line_end;
                }
            }
        }
        pos = next;
    }
    spans
}

/// Line ending to synthesize with, matching the message rather than guessing.
fn nl_style(msg: &[u8]) -> &'static [u8] {
    if msg.contains(&b'\r') {
        b"\r\n"
    } else {
        b"\n"
    }
}

/// The cryptographic payload: the message as received, with
/// `protected-headers="v1"` added to its Content-Type.
///
/// The whole message, headers included, stays inside the ciphertext. That
/// parameter is how a client is told where the real headers are: Thunderbird,
/// K-9 and others read them back after decrypting and display the real Subject
/// instead of the wrapper's placeholder (Protected Headers for Cryptographic
/// E-mail, draft-autocrypt-lamps-protected-headers). Without it the placeholder
/// is all a client can show for every message.
fn protected_payload(msg: &[u8]) -> Vec<u8> {
    let (block, sep, body) = split_message(msg);
    let mut out = Vec::with_capacity(msg.len() + 64);

    match header_spans(block)
        .into_iter()
        .find(|(name, _, _)| name == "content-type")
    {
        Some((_, _, end)) => {
            out.extend_from_slice(&block[..end]);
            // A parameter list that already ends in ';' must not gain an empty
            // parameter, so add the separator only when it is missing.
            if block[..end].iter().rev().find(|b| !b.is_ascii_whitespace()) == Some(&b';') {
                out.extend_from_slice(b" protected-headers=\"v1\"");
            } else {
                out.extend_from_slice(b"; protected-headers=\"v1\"");
            }
            out.extend_from_slice(&block[end..]);
        }
        None => {
            // No Content-Type at all, so the RFC 2045 default applies. Naming it
            // changes nothing about how the body reads and gives the parameter a
            // home.
            out.extend_from_slice(block);
            if !block.is_empty() {
                out.extend_from_slice(nl_style(block));
            }
            out.extend_from_slice(
                b"Content-Type: text/plain; charset=us-ascii; protected-headers=\"v1\"",
            );
            out.extend_from_slice(nl_style(block));
        }
    }

    if sep.is_empty() {
        out.extend_from_slice(nl_style(block));
    } else {
        out.extend_from_slice(sep);
    }
    out.extend_from_slice(body);
    out
}

/// The wrapper keeps the envelope-level who and when: these are what the mail
/// store cannot hide anyway, since mail is routed on them and they appear in
/// the SMTP logs (docs/threat-model.md, "Correspondence metadata"), and clients
/// read the sender and date from them. Everything else stays in the payload.
const EXPOSED_HEADERS: [&str; 6] = ["from", "to", "cc", "reply-to", "date", "message-id"];

/// RFC 3156 section 4 envelope: `multipart/encrypted` with the `Version: 1` part
/// and the armored ciphertext as `application/octet-stream`.
///
/// The wrapper carries the exposed headers and a Subject placeholder, never the
/// real subject: the mail store holds this in the clear and must not reveal
/// correspondence content. The placeholder keeps a client from showing an empty
/// subject before it decrypts, and `protected_payload` is what lets it replace
/// the placeholder with the real one afterwards.
fn rfc3156_envelope(boundary: &str, armor: &[u8], msg: &[u8]) -> Vec<u8> {
    let (block, _, _) = split_message(msg);
    let mut out = Vec::with_capacity(armor.len() + msg.len().min(4096) + 512);
    out.extend_from_slice(
        format!(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\n\
             \tboundary=\"{boundary}\"\n"
        )
        .as_bytes(),
    );
    for (name, start, end) in header_spans(block) {
        if EXPOSED_HEADERS.contains(&name.as_str()) {
            out.extend_from_slice(&block[start..end]);
            out.push(b'\n');
        }
    }
    out.extend_from_slice(
        format!(
            "Subject: ...\n\
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

    // Dovecot's save path runs as the mailbox user, not as root, so a socket
    // only root can write to fails closed on every delivery. Set the mode here
    // rather than rely on umask, which rc.subr does not control. Any local
    // account can then ask for encryption, which exposes nothing: the keyring
    // it encrypts to is world-readable (/etc/kyriakon/keys/*.asc, 0644).
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"From: alice@example.invalid\n\
        To: bob@example.invalid\n\
        Subject: hello\n\
        Date: Mon, 1 Jan 2024 00:00:00 +0000\n\
        Content-Type: text/plain; charset=utf-8\n\
        \n\
        body line\n";

    fn payload(msg: &[u8]) -> String {
        String::from_utf8_lossy(&protected_payload(msg)).into_owned()
    }

    #[test]
    fn payload_marks_the_content_type_protected() {
        let p = payload(MESSAGE);
        assert!(
            p.contains("Content-Type: text/plain; charset=utf-8; protected-headers=\"v1\"\n"),
            "{p}"
        );
        // Headers and body both survive: the payload is still the whole message.
        assert!(p.contains("Subject: hello\n"), "{p}");
        assert!(p.ends_with("\n\nbody line\n"), "{p}");
    }

    #[test]
    fn payload_adds_a_content_type_when_there_is_none() {
        let p = payload(b"From: a@b\nSubject: x\n\nbody\n");
        assert!(
            p.contains("Content-Type: text/plain; charset=us-ascii; protected-headers=\"v1\"\n"),
            "{p}"
        );
        assert!(p.ends_with("\n\nbody\n"), "{p}");
    }

    #[test]
    fn payload_keeps_a_folded_content_type_intact() {
        let p = payload(
            b"Subject: x\r\nContent-Type: multipart/mixed;\r\n\tboundary=\"b\"\r\n\r\nparts\r\n",
        );
        assert!(
            p.contains("boundary=\"b\"; protected-headers=\"v1\"\r\n"),
            "{p}"
        );
        assert!(!p.contains(";;"), "empty parameter introduced:\n{p}");
        assert!(p.ends_with("\r\n\r\nparts\r\n"), "{p}");
    }

    #[test]
    fn payload_terminates_headers_when_the_message_has_no_blank_line() {
        let p = payload(b"Subject: x\n");
        assert!(p.contains("protected-headers=\"v1\"\n\n"), "{p}");
    }

    #[test]
    fn envelope_exposes_transport_metadata_only() {
        let env = String::from_utf8_lossy(&rfc3156_envelope("b", b"ARMOR", MESSAGE)).into_owned();
        assert!(
            env.starts_with("Content-Type: multipart/encrypted;"),
            "{env}"
        );
        assert!(env.contains("From: alice@example.invalid\n"), "{env}");
        assert!(
            env.contains("Date: Mon, 1 Jan 2024 00:00:00 +0000\n"),
            "{env}"
        );
        assert!(env.contains("Subject: ...\n"), "{env}");
        assert!(
            !env.contains("Subject: hello"),
            "the real subject must stay in the payload:\n{env}"
        );
        assert!(!env.contains("body line"), "the body leaked:\n{env}");
        assert!(
            !env.contains("Content-Type: text/plain"),
            "the payload's Content-Type leaked:\n{env}"
        );
    }

    #[test]
    fn only_session_key_packets_count_as_being_addressed_to_a_key() {
        // A cert: the key id is on a line of its own, under the key packet.
        let cert = b":public key packet:\n\
            \tversion 4, algo 1, created 0, expires 0\n\
            \tkeyid: DC81B0FDFE212297\n\
            :signature packet: algo 1, keyid DC81B0FDFE212297\n";
        assert_eq!(cert_key_ids(cert), vec!["DC81B0FDFE212297".to_string()]);
        // A message carrying that cert inline mentions the key and is still not
        // ciphertext for it. Skipping on a mention would store the message in
        // the clear.
        assert!(message_key_ids(cert).is_empty());

        // Real ciphertext names its recipient in the session key packet.
        let msg = b":pubkey enc packet: version 3, algo 1, keyid DC81B0FDFE212297\n\
            \tdata: [3070 bits]\n\
            :encrypted data packet:\n\
            \tlength: unknown\n\
            \tmdc_method: 2\n";
        assert_eq!(message_key_ids(msg), vec!["DC81B0FDFE212297".to_string()]);
        assert!(cert_key_ids(msg).is_empty());
    }
}
