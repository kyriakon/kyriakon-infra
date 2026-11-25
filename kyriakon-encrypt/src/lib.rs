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
//! Input that is already an RFC 3156 envelope to that recipient is rebuilt
//! from its verified ciphertext rather than encrypted again, so a client
//! re-uploading a message cannot have it encrypted twice and inbound PGP/MIME
//! mail keeps its single layer.
//!
//! The Dovecot shim runs `kyriakon-encrypt encrypt` and reads the ciphertext
//! from its stdout: exit status carries failure, so a gpg error or a write cut
//! short is a failed save and plaintext is never stored.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kyriakon_mailparse::{boundary_param, headers, lines, split_message, walk_multipart, Part};

/// On-box keyring location - sync of the git-tracked published key set.
pub const DEFAULT_KEYRING: &str = "/etc/kyriakon/keys";
/// Default gpg homedir for a check run by hand. gpg writes pubring.kbx and
/// random_seed here even with `--recipient-file`, so it must be a writable,
/// private dir, never a user's `$HOME`. The save path does not use it: the
/// plugin passes a fresh 0700 directory per message.
pub const DEFAULT_GPG_HOME: &str = "/var/run/kyriakon/gpg";

#[derive(Debug)]
pub enum Error {
    /// Recipient base localpart is not a single DNS label: empty, more than 31
    /// characters, or outside `[a-z0-9-]` / beginning or ending with a hyphen.
    InvalidUser {
        localpart: String,
    },
    /// No `<base-localpart>.asc` in the keyring.
    MissingKey {
        localpart: String,
    },
    /// gpg ran and refused the message. `stderr` is gpg's own diagnostic.
    Gpg {
        stderr: String,
    },
    /// The message has no empty line this parser accepts, and its header block
    /// is not all headers. Reading it as headers could copy text from an
    /// unrecognised body into the clear wrapper, so the save is refused.
    Malformed {
        source: kyriakon_mailparse::Malformed,
    },
    /// gpg could not be started, waited for, or written to.
    GpgIo {
        what: &'static str,
        source: io::Error,
    },
    /// gpg's stdin writer thread panicked before it finished.
    GpgWriterPanicked,
    /// The gpg scratch directory could not be created.
    GpgHome {
        path: PathBuf,
        source: io::Error,
    },
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidUser { localpart } => {
                write!(f, "invalid recipient localpart: {localpart:?}")
            }
            Error::MissingKey { localpart } => {
                write!(f, "no public key for {localpart:?} in keyring")
            }
            Error::Gpg { stderr } => write!(f, "gpg failed: {stderr}"),
            Error::Malformed { source } => {
                write!(f, "refusing malformed message: {}", source.reason())
            }
            Error::GpgIo { what, source } => write!(f, "cannot {what} gpg: {source}"),
            Error::GpgWriterPanicked => f.write_str("the gpg stdin writer panicked"),
            Error::GpgHome { path, source } => {
                write!(
                    f,
                    "cannot create the gpg homedir {}: {source}",
                    path.display()
                )
            }
            Error::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Malformed { source } => Some(source),
            Error::GpgIo { source, .. } => Some(source),
            Error::GpgHome { source, .. } => Some(source),
            Error::Io(e) => Some(e),
            Error::InvalidUser { .. }
            | Error::MissingKey { .. }
            | Error::Gpg { .. }
            | Error::GpgWriterPanicked => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<kyriakon_mailparse::Malformed> for Error {
    fn from(e: kyriakon_mailparse::Malformed) -> Self {
        Error::Malformed { source: e }
    }
}

/// Strip a `+tag` to the base localpart and validate it as a single DNS label:
/// 1-31 lowercase letters, digits and interior hyphens. The charset check is a
/// trust-boundary guard: the user string is joined into a keyring path.
pub fn base_localpart(user: &str) -> Result<&str, Error> {
    let base = user.split('+').next().unwrap_or("");
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let ok = !base.is_empty()
        && base.len() <= 31
        && base.bytes().all(|b| alnum(b) || b == b'-')
        && alnum(base.as_bytes()[0])
        && alnum(base.as_bytes()[base.len() - 1]);
    if !ok {
        return Err(Error::InvalidUser {
            localpart: base.to_string(),
        });
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
        return Err(Error::MissingKey {
            localpart: base.to_string(),
        });
    }
    let message = split_message(input)?;
    let (block, sep, body) = (message.headers, message.separator, message.body);
    if let Some(armor) = already_encrypted(input, &key, gpg_home) {
        return Ok(rfc3156_envelope(&make_boundary(), armor, block));
    }
    let payload = protected_payload(block, sep, body);
    let armor = armored_ciphertext(&key, gpg_home, &payload)?;
    Ok(rfc3156_envelope(&make_boundary(), &armor, block))
}

fn armored_ciphertext(key: &Path, gpg_home: &Path, input: &[u8]) -> Result<Vec<u8>, Error> {
    ensure_gpg_home(gpg_home)?;
    // --recipient-file reads the armored cert directly: no key import, no
    // trustdb, and the keyring file stays the single source. --homedir points
    // gpg at the caller's writable scratch dir (gpg writes pubring.kbx and
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
        .map_err(|e| Error::GpgIo {
            what: "spawn",
            source: e,
        })?;
    let stdin = child.stdin.take().expect("stdin piped");
    // gpg writes as it reads, and its armour outgrows the ~64 KiB pipe on any
    // message past ~200 KiB: writing all of stdin here before draining stdout
    // deadlocks the two. The write owns its own thread; this one drains.
    let (out, written) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            let mut stdin = stdin;
            stdin.write_all(input)
        });
        let out = child.wait_with_output();
        (out, writer.join())
    });
    let out = out.map_err(|e| Error::GpgIo {
        what: "wait for",
        source: e,
    })?;
    if !out.status.success() {
        // gpg's own complaint, not the EPIPE its early exit gives the writer.
        return Err(Error::Gpg {
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    written
        .map_err(|_| Error::GpgWriterPanicked)?
        .map_err(|e| Error::GpgIo {
            what: "write to",
            source: e,
        })?;
    Ok(out.stdout)
}

/// The first line of every envelope this crate produces: the one definition,
/// written by `rfc3156_envelope`. The gate finds the Content-Type by name
/// instead, because inbound mail carries transport headers before it.
const ENVELOPE_MARKER: &str =
    "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";";

/// The RFC 3156 preamble the builder writes before the first boundary. It is
/// a human-readable notice, not content: the envelope gate accepts whatever a
/// sender's client put there and the rebuild replaces it.
const ENVELOPE_PREAMBLE: &str = "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156).";

/// A bare armoured message: no armor header comment, a base64 body and a
/// checksum line, as gpg emits it. Shared by the tests and the envelope fuzz
/// target, which both need a ciphertext these parsers accept.
#[cfg(any(test, feature = "fuzz"))]
const ARMOR: &[u8] = b"-----BEGIN PGP MESSAGE-----\n\
    \n\
    YWJjZA==\n\
    =abcd\n\
    -----END PGP MESSAGE-----\n";

/// The verified armoured ciphertext of `input` when it is already an RFC 3156
/// envelope to the recipient of `cert`, in which case the caller rebuilds the
/// outer message around it instead of encrypting again.
///
/// A second encryption does not lose the message, but it breaks it: the store
/// holds a ciphertext whose payload is another envelope, so a client decrypts
/// once and shows an encrypted blob where the mail should be. A client that
/// files a message by re-uploading it on the save path did that on the live box.
/// Inbound PGP/MIME from an external sender arrives the same way, behind
/// `Return-Path` and `Received` headers and under its own preamble, and must
/// keep its single layer too.
///
/// The marker alone cannot be trusted to mean ciphertext, since a sender could
/// mail a message that begins with it - a forwarded mail, say, whose attachment
/// is ciphertext for this recipient - and have the plaintext written to the
/// store as though it were encrypted. So the outer MIME has to be the RFC 3156
/// shape (`envelope_ciphertext`), the ciphertext part has to be an armoured PGP
/// message and its packets have to be encrypted, and the key id is read from
/// those packets alone. Ciphertext addressed to another key, a copy of the cert
/// carried inline, a stream gpg cannot parse, and anything whose parts do not
/// match all fall through to normal encryption.
fn already_encrypted<'a>(input: &'a [u8], cert: &Path, gpg_home: &Path) -> Option<&'a [u8]> {
    let ciphertext = envelope_ciphertext(input)?;
    let packets = list_packets(ciphertext, gpg_home)?;
    if !is_ciphertext_packets(&packets) {
        return None;
    }
    let cert_packets = std::fs::read(cert).ok()?;
    let ours = cert_key_ids(&list_packets(&cert_packets, gpg_home)?);
    if ours.is_empty() {
        return None;
    }
    message_key_ids(&packets)
        .iter()
        .any(|id| ours.contains(id))
        .then_some(ciphertext)
}

/// The armoured ciphertext of `input` when it is an RFC 3156 envelope: a
/// `multipart/encrypted` Content-Type anywhere in the outer header block
/// (inbound mail arrives behind `Return-Path` and `Received`), any preamble,
/// exactly two parts, the first `application/pgp-encrypted` with `Version: 1`,
/// the second `application/octet-stream` whose body is nothing but a bare
/// ASCII-armoured PGP message. Anything else is not ciphertext to keep: a
/// message that merely mentions the wrapper is a message to encrypt.
fn envelope_ciphertext(input: &[u8]) -> Option<&[u8]> {
    let message = split_message(input).ok()?;
    if message.separator.is_empty() {
        return None;
    }
    let header = headers(message.headers)
        .into_iter()
        .find(|header| header.is("content-type"))?;
    let value = header.value(message.headers);
    if media_type(value)? != "multipart/encrypted" {
        return None;
    }
    let boundary = boundary_param(value)?;
    let multipart = walk_multipart(message.body, &boundary).ok()?;
    // The builder ends at the closing delimiter. An epilogue is readable text
    // the store would keep in the clear, so it is not this wrapper's shape.
    if multipart
        .epilogue
        .iter()
        .any(|byte| !matches!(byte, b'\n' | b'\r'))
    {
        return None;
    }
    let [version, ciphertext] = multipart.parts.as_slice() else {
        return None;
    };
    if !is_version_part(version) {
        return None;
    }
    armored_message(part_body(ciphertext)?)
}

/// The type/subtype of a Content-Type value, lowercased and without
/// parameters.
fn media_type(value: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(value).ok()?.trim_start();
    let end = value
        .find(|c: char| c == ';' || c.is_ascii_whitespace())
        .unwrap_or(value.len());
    Some(value[..end].to_ascii_lowercase())
}

/// Whether a part is the RFC 3156 version part: `application/pgp-encrypted`
/// with exactly `Version: 1` as its body.
fn is_version_part(part: &Part<'_>) -> bool {
    if part.separator.is_empty() {
        return false;
    }
    let Some(header) = headers(part.headers)
        .into_iter()
        .find(|header| header.is("content-type"))
    else {
        return false;
    };
    let Some(media_type) = media_type(header.value(part.headers)) else {
        return false;
    };
    media_type == "application/pgp-encrypted" && part.body.trim_ascii_end() == b"Version: 1"
}

/// The bytes of a MIME part whose Content-Type is `application/octet-stream`,
/// including the line ending before the closing delimiter. The armour ends with
/// that newline, and gpg will not parse an armour that lacks it.
fn part_body<'a>(part: &Part<'a>) -> Option<&'a [u8]> {
    let header = headers(part.headers)
        .into_iter()
        .find(|header| header.is("content-type"))?;
    (media_type(header.value(part.headers))?.as_str() == "application/octet-stream")
        .then_some(part.body_with_ending)
}

/// The bare ASCII-armoured PGP message in a MIME part body, when the body is
/// nothing else. Leading blank lines are tolerated; armor header comments are
/// not, because the rebuild writes none and accepting them would drop bytes a
/// sender put there. The returned slice runs from the BEGIN line through the
/// END line's line ending, ready to be wrapped again; gpg will not parse an
/// armour that does not end in a newline.
fn armored_message(body: &[u8]) -> Option<&[u8]> {
    const BEGIN: &str = "-----BEGIN PGP MESSAGE-----";
    const END: &str = "-----END PGP MESSAGE-----";

    let mut body_lines = lines(body);
    let begin = loop {
        let line = body_lines.next()?;
        if line.text.is_empty() {
            continue;
        }
        if line.text == BEGIN.as_bytes() {
            break line.start;
        }
        return None;
    };
    // The line after BEGIN must be blank: a header comment belongs to the
    // clear text the store must not keep.
    if !body_lines.next()?.text.is_empty() {
        return None;
    }
    let mut data = false;
    loop {
        let line = body_lines.next()?;
        if line.text == END.as_bytes() {
            if !data || body[line.next..].iter().any(|b| !b.is_ascii_whitespace()) {
                return None;
            }
            return Some(&body[begin..line.next]);
        }
        let base64 = line
            .text
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        if line.text.is_empty() || !base64 {
            return None;
        }
        data = true;
    }
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

/// Whether a `gpg --list-packets` dump is ciphertext: it carries an encrypted
/// data or session-key packet and no literal data packet anywhere. A stream
/// that pairs a session-key packet with a literal packet is a message dressed
/// as ciphertext, and storing it in the clear would leak it. The save path
/// asks gpg in a secretless homedir, so gpg cannot descend into encrypted data
/// and a legitimate envelope shows no literal packet. Reject on any literal
/// line rather than trusting indentation, which gpg does not keep consistent
/// once it can decrypt.
fn is_ciphertext_packets(packets: &[u8]) -> bool {
    let mut encrypted = false;
    for line in String::from_utf8_lossy(packets).lines() {
        if line.starts_with(":literal data packet:") {
            return false;
        }
        if line.starts_with(":encrypted data packet:")
            || line.starts_with(":symkey enc packet:")
            // AEAD-encrypted data is a distinct packet tag, listed as `:ocb
            // encrypted packet:`; a key that advertises AEAD still receives
            // ciphertext this crate must not encrypt again.
            || line.starts_with(":ocb encrypted packet:")
        {
            encrypted = true;
        }
    }
    encrypted
}

/// Cap on the packet listing read from gpg. A listing is a few short lines per
/// packet; a stream that needs more is built to amplify (a compressed packet
/// inflates to thousands of tiny packets, ~14x their size per line), not a
/// message. Well past any legitimate PGP/MIME part.
const PACKET_LISTING_CAP: usize = 1 << 20;

/// How long gpg gets to finish a listing. A stream that cannot be listed in
/// this long is a stall attempt, not a message.
const PACKET_LISTING_TIMEOUT: Duration = Duration::from_secs(5);

/// Read at most `PACKET_LISTING_CAP` bytes from `reader`. `None` when the
/// stream carries more: that is an amplifying listing, not a packet dump, and
/// reading it is what #823 exploited.
fn read_listing(mut reader: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    // One byte past the cap is enough to tell an oversized listing apart from
    // one that exactly fills it.
    reader
        .by_ref()
        .take(PACKET_LISTING_CAP as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() <= PACKET_LISTING_CAP).then_some(out)
}

/// `gpg --list-packets` over `input`, bounded in both bytes and time. `None`
/// means no usable listing: gpg could not be run, the listing ran past
/// `PACKET_LISTING_CAP` (the child is killed at the cap), or it did not finish
/// within `PACKET_LISTING_TIMEOUT` (the child is killed). Inspection only, and
/// best effort: every `None` reads as "not our ciphertext", so the caller
/// encrypts the message as usual rather than failing the save.
///
/// The exit status is deliberately ignored. gpg prints the packet listing and
/// then exits non-zero for a message it cannot decrypt, which is every message
/// here: the encryptor's gpg homedir holds no secret key, by design. Treating that
/// status as fatal discards the listing and the caller sees no recipients at
/// all.
fn list_packets(input: &[u8], gpg_home: &Path) -> Option<Vec<u8>> {
    if ensure_gpg_home(gpg_home).is_err() {
        return None;
    }
    let mut child = Command::new("gpg")
        .args([
            "--batch",
            "--no-tty",
            "--no-options",
            "--list-packets",
            // A listing never needs an agent, and starting one per message
            // costs the save path a socket connect and a daemon. With a
            // secretless homedir gpg would otherwise stall on that connect
            // before printing anything.
            "--no-autostart",
            "--homedir",
        ])
        .arg(gpg_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdin = child.stdin.take();
    let stdout = child.stdout.take()?;
    // Same pipe-buffer hazard as `armored_ciphertext`: gpg lists packets while
    // it reads, so the write must not block this thread's drain. Best effort
    // throughout, so both failures stay silent.
    std::thread::scope(|scope| {
        let writer = stdin.map(|mut stdin| {
            scope.spawn(move || {
                let _ = stdin.write_all(input);
            })
        });
        let (tx, rx) = std::sync::mpsc::channel();
        scope.spawn(move || {
            let _ = tx.send(read_listing(stdout));
        });
        let out = match rx.recv_timeout(PACKET_LISTING_TIMEOUT) {
            Ok(Some(out)) => Some(out),
            // Over the cap or unreadable, or too slow: gpg is still writing
            // into a pipe nobody drains, so it has to go before it is reaped.
            Ok(None) | Err(_) => {
                let _ = child.kill();
                None
            }
        };
        let _ = child.wait();
        if let Some(writer) = writer {
            let _ = writer.join();
        }
        out
    })
}

/// Create the gpg scratch dir (0700). Idempotent. The CLI calls it before
/// narrowing its view, because `unveil` cannot name a directory that does not
/// exist; the save path calls it per message because it cannot assume external
/// setup completed.
pub fn ensure_gpg_home(gpg_home: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(gpg_home).map_err(|e| Error::GpgHome {
        path: gpg_home.to_path_buf(),
        source: e,
    })?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(gpg_home, std::fs::Permissions::from_mode(0o700)).ok();
    Ok(())
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
///
/// Takes the one `split_message` result the caller already holds, so the
/// payload and the wrapper cannot be built from different header blocks.
fn protected_payload(block: &[u8], sep: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(block.len() + sep.len() + body.len() + 64);

    match headers(block)
        .into_iter()
        .find(|header| header.is("content-type"))
    {
        Some(header) => {
            let end = header.end();
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
            // home. It goes first, and directly: `block` already ends with its
            // last line's newline, so appending a second one after it ends the
            // header block, which puts this line in the body for every parser
            // that is strict about where headers stop. Cron's mail, which is
            // composed without a Content-Type, arrived that way: the client
            // showed the real Subject and then the Content-Type line as text.
            out.extend_from_slice(
                b"Content-Type: text/plain; charset=us-ascii; protected-headers=\"v1\"",
            );
            out.extend_from_slice(nl_style(block));
            out.extend_from_slice(block);
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
/// the placeholder with the real one afterwards. `block` is the header block
/// from the same `split_message` call that produced the payload.
fn rfc3156_envelope(boundary: &str, armor: &[u8], block: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(armor.len() + block.len().min(4096) + 512);
    out.extend_from_slice(format!("{ENVELOPE_MARKER}\n\tboundary=\"{boundary}\"\n").as_bytes());
    for header in headers(block) {
        if EXPOSED_HEADERS.iter().any(|name| header.is(name)) {
            out.extend_from_slice(&block[header.start()..header.end()]);
            out.push(b'\n');
        }
    }
    out.extend_from_slice(b"Subject: ...\nMIME-Version: 1.0\n\n");
    out.extend_from_slice(format!("{ENVELOPE_PREAMBLE}\n\n").as_bytes());
    out.extend_from_slice(
        format!(
            "--{boundary}\n\
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

/// Entry points for the fuzz targets in `fuzz/`, behind the `fuzz` feature so
/// the parsers stay private in every other build.
///
/// The save path parses whatever an SMTP client sent, and the parsing is byte
/// indexing in this file rather than a crate's, so it is the part a fuzzer can
/// find a panic in. Nothing here shells out to gpg: the listings that do are
/// covered by tests, not by libFuzzer.
#[cfg(feature = "fuzz")]
#[doc(hidden)]
pub mod fuzz {
    use super::*;

    /// Every pure parse a message goes through: the header split, the header
    /// spans, the payload rewrite, the gate that decides a re-uploaded message
    /// is already ciphertext, and the recipient guard on the save path.
    pub fn message(input: &[u8]) {
        let _ = nl_style(input);
        let _ = envelope_ciphertext(input);
        if let Ok(message) = split_message(input) {
            let _ = headers(message.headers);
            let payload = protected_payload(message.headers, message.separator, message.body);
            let _ = rfc3156_envelope("fuzz-boundary", &[], message.headers);
            if let Ok(payload) = split_message(&payload) {
                let _ = rfc3156_envelope("fuzz-boundary", &[], payload.headers);
            }
        }
        let _ = base_localpart(&String::from_utf8_lossy(input));
    }

    /// A wrapper this crate built must read back as the ciphertext it wraps,
    /// whatever the message was. The build and the gate have to agree, or a
    /// re-uploaded message is encrypted a second time.
    pub fn envelope(input: &[u8]) {
        let Ok(message) = split_message(input) else {
            return;
        };
        let wrapper = rfc3156_envelope("fuzz-boundary", ARMOR, message.headers);
        assert_eq!(envelope_ciphertext(&wrapper), Some(ARMOR));
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
        let message = split_message(msg).expect("test message splits");
        String::from_utf8_lossy(&protected_payload(
            message.headers,
            message.separator,
            message.body,
        ))
        .into_owned()
    }

    /// The wrapper the save path builds around `armor` for `msg`, from the same
    /// split that produces the payload.
    fn built_with(boundary: &str, armor: &[u8], msg: &[u8]) -> Vec<u8> {
        let message = split_message(msg).expect("test message splits");
        rfc3156_envelope(boundary, armor, message.headers)
    }

    fn built(armor: &[u8], msg: &[u8]) -> Vec<u8> {
        built_with("b", armor, msg)
    }

    #[test]
    fn base_localpart_is_a_single_dns_label_of_at_most_31_characters() {
        // The same boundary names as `validate::username_shape` and
        // `valid_localpart`: the localpart is an account name, a mail localpart
        // and a DNS label at once.
        let thirty_one = "a".repeat(31);
        let thirty_two = "a".repeat(32);
        let tagged = format!("{thirty_one}+tag");
        for value in [
            "a",
            "7",
            "a-b",
            "a1-2b",
            thirty_one.as_str(),
            "alice+tag",
            tagged.as_str(),
        ] {
            assert!(base_localpart(value).is_ok(), "{value}");
        }
        assert_eq!(base_localpart("alice+tag").unwrap(), "alice");
        assert_eq!(base_localpart(&tagged).unwrap(), thirty_one.as_str());
        for value in [
            "",
            "+tag",
            "Alice",
            "a.b",
            "a_b",
            "a-",
            "-a",
            thirty_two.as_str(),
        ] {
            assert!(base_localpart(value).is_err(), "{value}");
        }
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
        // The whole header block, in order and unbroken: the synthesized line is
        // a header the client can see, not the first line of the body.
        assert_eq!(
            p,
            "Content-Type: text/plain; charset=us-ascii; protected-headers=\"v1\"\n\
             From: a@b\n\
             Subject: x\n\
             \n\
             body\n",
            "{p}"
        );
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
        // The message ends inside its header block, so the blank line that ends
        // it has to be added: without one, the synthesized Content-Type would be
        // indistinguishable from the body. It must come after both headers, not
        // after the first.
        let p = payload(b"Subject: x\n");
        assert_eq!(
            p,
            "Content-Type: text/plain; charset=us-ascii; protected-headers=\"v1\"\n\
             Subject: x\n\
             \n",
            "{p}"
        );
    }

    #[test]
    fn envelope_exposes_transport_metadata_only() {
        let env = String::from_utf8_lossy(&built(ARMOR, MESSAGE)).into_owned();
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
    fn a_colonless_line_is_not_folded_into_the_header_above_it() {
        // Anything an exposed span covers is copied into the unencrypted
        // wrapper. A line with no colon is not a header, so it belongs to no
        // span, while a real continuation still travels with its header.
        let msg = b"To: bob@example.invalid,\n\
            \tcarol@example.invalid\n\
            smuggled plaintext\n\
            Date: Mon, 1 Jan 2024 00:00:00 +0000\n\
            \n\
            body\n";
        let env = String::from_utf8_lossy(&built(ARMOR, msg)).into_owned();
        assert!(!env.contains("smuggled plaintext"), "{env}");
        assert!(
            env.contains("To: bob@example.invalid,\n\tcarol@example.invalid\n"),
            "{env}"
        );
        assert!(
            env.contains("Date: Mon, 1 Jan 2024 00:00:00 +0000\n"),
            "{env}"
        );
        // Nothing is lost: the payload still carries the whole block.
        let p = payload(msg);
        assert!(p.contains("smuggled plaintext\n"), "{p}");
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

    fn envelope() -> Vec<u8> {
        built(ARMOR, MESSAGE)
    }

    /// A 618-byte armoured message: a compressed packet (algo 1, raw deflate)
    /// holding 200,000 two-byte packets. `gpg --list-packets` emits about
    /// 18 MB for it, the amplification #823 measured. Deflating needs a
    /// compressor, so the fixture is a file rather than built in the test.
    const PACKET_BOMB: &str = include_str!("../tests/fixtures/packet-bomb.asc");

    /// A reader that yields at most `left` bytes, counting what was read.
    struct Counting {
        left: usize,
        read: usize,
    }

    impl std::io::Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.left);
            buf[..n].fill(b'x');
            self.left -= n;
            self.read += n;
            Ok(n)
        }
    }

    #[test]
    fn a_packet_listing_is_read_only_up_to_the_cap() {
        let mut under = Counting {
            left: PACKET_LISTING_CAP,
            read: 0,
        };
        assert_eq!(
            read_listing(&mut under).map(|listing| listing.len()),
            Some(PACKET_LISTING_CAP)
        );
        assert_eq!(under.read, PACKET_LISTING_CAP);

        // Four caps of output: an amplifying stream. Only one byte past the
        // cap is read, and the answer is "no listing" rather than megabytes of
        // packets to scan.
        let mut over = Counting {
            left: PACKET_LISTING_CAP * 4,
            read: 0,
        };
        assert_eq!(read_listing(&mut over), None);
        assert_eq!(over.read, PACKET_LISTING_CAP + 1);
    }

    #[test]
    fn a_compressed_packet_bomb_is_not_ciphertext() {
        let home = std::env::temp_dir().join(format!(
            "ke{}-{:x}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let bomb = PACKET_BOMB.as_bytes();
        // Without gpg on the host, every listing returns None and the bomb
        // assertion below would pass without reading anything. A real packet
        // must list, or this test is not testing the cap.
        assert!(
            list_packets(ARMOR, &home).is_some(),
            "gpg must be available to judge the bomb"
        );
        // gpg emits ~18 MB for this part; at the cap there is no listing to
        // judge, so the decision is "not our ciphertext" and the message is
        // encrypted as usual.
        assert!(
            list_packets(bomb, &home).is_none(),
            "an over-cap listing must not be read"
        );
        let envelope = built(bomb, MESSAGE);
        assert!(
            already_encrypted(&envelope, Path::new("no-such-cert"), &home).is_none(),
            "a packet bomb is encrypted, not kept as ciphertext"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn an_envelope_yields_its_ciphertext_part() {
        // The envelope's own ciphertext part comes back as the armour alone, so
        // the key-id scan sees ciphertext and nothing else.
        assert_eq!(envelope_ciphertext(&envelope()), Some(ARMOR));
    }

    #[test]
    fn only_the_exposed_headers_reach_the_wrapper() {
        // The wrapper is what the mail store keeps in the clear, so a header
        // outside EXPOSED_HEADERS that lands there is correspondence content
        // handed to the provider. The sentinel proves each hidden header and
        // the body stayed in the payload; the exposed six are proved present,
        // because routing and the client's sender and date read them. Every
        // line ending a client can send gets the same answer.
        const SENTINEL: &str = "SENTINEL-7f3c";
        let exposed = [
            ("From", "alice@example.invalid"),
            ("To", "bob@example.invalid"),
            ("Cc", "carol@example.invalid"),
            ("Reply-To", "alice@example.invalid"),
            ("Date", "Mon, 1 Jan 2024 00:00:00 +0000"),
            ("Message-ID", "<id@example.invalid>"),
        ];
        let hidden = [
            format!("Subject: {SENTINEL}-subject"),
            format!("Bcc: {SENTINEL}-bcc"),
            format!("X-Custom: {SENTINEL}-custom"),
            format!("Content-Type: text/plain;\n\tboundary={SENTINEL}-folded"),
        ];

        for (sep, blank) in [("\n", "\n"), ("\r\n", "\r\n"), ("\r", "\r\r")] {
            // The hidden headers go at every position among the exposed ones: a
            // header that leaks only when it follows another is still a leak.
            for at in 0..=exposed.len() {
                let mut msg = String::new();
                for (name, value) in &exposed[..at] {
                    msg.push_str(&format!("{name}: {value}{sep}"));
                }
                for line in &hidden {
                    msg.push_str(&line.replace('\n', sep));
                    msg.push_str(sep);
                }
                for (name, value) in &exposed[at..] {
                    msg.push_str(&format!("{name}: {value}{sep}"));
                }
                msg.push_str(&format!("{blank}body {SENTINEL}-body{sep}"));

                let wrapper = String::from_utf8_lossy(&built(ARMOR, msg.as_bytes())).into_owned();
                for (name, value) in &exposed {
                    assert!(
                        wrapper.contains(&format!("{name}: {value}")),
                        "{name} is missing from the wrapper ({sep:?}, hidden at {at}):\n{wrapper}"
                    );
                }
                assert!(
                    !wrapper.contains(SENTINEL),
                    "a header or the body leaked into the wrapper ({sep:?}, hidden at {at}):\n{wrapper}"
                );

                let p = payload(msg.as_bytes());
                for marker in ["-subject", "-bcc", "-custom", "-folded", "-body"] {
                    assert!(
                        p.contains(&format!("{SENTINEL}{marker}")),
                        "{marker} is missing from the payload ({sep:?}, hidden at {at}):\n{p}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_bare_cr_separator_does_not_leak_a_colon_bearing_body_line() {
        // The separator is a bare CR. An LF-only split left the whole message in
        // the header block, so `header_spans` read this body line as a second
        // From and copied it into the clear wrapper.
        let msg = b"From: a@b\rSubject: s\r\rFrom: SECRET-BODY-TEXT\r\n";
        let env = String::from_utf8_lossy(&built(ARMOR, msg)).into_owned();
        assert!(!env.contains("SECRET-BODY-TEXT"), "the body leaked:\n{env}");
        assert!(env.contains("From: a@b\n"), "{env}");
        let p = payload(msg);
        assert!(p.contains("From: SECRET-BODY-TEXT\r\n"), "{p}");
    }

    #[test]
    fn a_cr_only_message_does_not_leak_a_colon_bearing_body_line() {
        // A whole message with no LF at all: the old split saw one line, so the
        // From after the empty CR line counted as a header and was exposed.
        let msg = b"From: a@b\rSubject: s\r\rFrom: CR-ONLY-SECRET\rbody text\r";
        let env = String::from_utf8_lossy(&built(ARMOR, msg)).into_owned();
        assert!(!env.contains("CR-ONLY-SECRET"), "the body leaked:\n{env}");
        assert!(env.contains("From: a@b\n"), "{env}");
        let p = payload(msg);
        assert!(p.contains("From: CR-ONLY-SECRET\rbody text\r"), "{p}");
    }

    #[test]
    fn a_message_whose_only_separator_is_unrecognised_is_refused() {
        // No empty line this rule accepts, and not every line is a header: the
        // From may be body text behind a separator the parser cannot see.
        // Reading it as headers would copy that span outside the ciphertext, so
        // the save fails closed instead.
        let msg = b"not a header\rFrom: SECRET-BODY-TEXT\r";
        assert!(matches!(
            split_message(msg).map_err(Error::from),
            Err(Error::Malformed { .. })
        ));
        // A message that ends in its header block is still encrypted as before.
        assert!(split_message(b"From: a@b\rSubject: s\r").is_ok());
    }

    #[test]
    fn a_message_that_only_begins_with_the_marker_is_not_an_envelope() {
        // A plaintext message whose first line is the marker and whose body
        // carries a whole envelope as an attachment. It names the recipient's
        // key inside the attachment, which is not enough: the outer message is
        // not the two-part shape, so it must be encrypted, not stored in clear.
        let mut msg =
            b"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\n\
            \tboundary=\"outer\"\n\
            From: a@example.invalid\n\
            Subject: forwarded\n\
            MIME-Version: 1.0\n\
            Content-Type: multipart/mixed; boundary=\"fwd\"\n\
            \n\
            --fwd\n\
            Content-Type: text/plain\n\
            \n\
            the plaintext body\n\
            --fwd\n\
            Content-Type: message/rfc822\n\
            \n"
            .to_vec();
        msg.extend_from_slice(&envelope());
        msg.extend_from_slice(b"\n--fwd--\n");
        assert_eq!(envelope_ciphertext(&msg), None);
    }

    #[test]
    fn a_truncated_or_trailing_junk_envelope_is_not_an_envelope() {
        let whole = envelope();
        // The closing boundary is the end of the message: without it, half an
        // armour looks like an envelope, and with anything after it, it is not
        // the shape this crate builds.
        let cut = whole.len() - b"\n--b--\n".len();
        assert_eq!(envelope_ciphertext(&whole[..cut]), None);

        let mut junk = whole.clone();
        junk.extend_from_slice(b"epilogue\n");
        assert_eq!(envelope_ciphertext(&junk), None);
    }

    #[test]
    fn an_inbound_envelope_is_recognised_through_transport_headers_and_preamble() {
        // smtpd puts Return-Path and Received before Content-Type, the client
        // puts a plaintext Subject among them, and it writes its own preamble.
        // All of it is ordinary inbound PGP/MIME and must keep one layer.
        let msg = format!(
            "Return-Path: <sender@example.invalid>\n\
             Received: from mx.example.invalid by kyriakon.net\n\
             Subject: plaintext subject\n\
             Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\n\
             \tboundary=\"in\"\n\
             MIME-Version: 1.0\n\
             \n\
             A sender's own notice.\n\
             \n\
             --in\n\
             Content-Type: application/pgp-encrypted\n\
             \n\
             Version: 1\n\
             \n\
             --in\n\
             Content-Type: application/octet-stream\n\
             \n\
             {}\n\
             --in--\n",
            String::from_utf8_lossy(ARMOR)
        );
        assert_eq!(envelope_ciphertext(msg.as_bytes()), Some(ARMOR));

        // Saving it rebuilds the outer message around that ciphertext, so the
        // transport headers, the sender's subject and its preamble are gone and
        // the ciphertext is untouched.
        let saved = built_with("n", ARMOR, msg.as_bytes());
        let text = String::from_utf8_lossy(&saved);
        assert!(text.starts_with(ENVELOPE_MARKER), "{text}");
        assert!(text.contains("Subject: ...\n"), "{text}");
        for leaked in [
            "plaintext subject",
            "Return-Path",
            "Received:",
            "sender's own notice",
        ] {
            assert!(!text.contains(leaked), "{leaked} leaked:\n{text}");
        }
        assert!(
            text.contains(String::from_utf8_lossy(ARMOR).as_ref()),
            "{text}"
        );
    }

    #[test]
    fn an_envelope_with_only_bare_cr_line_endings_is_recognised() {
        // The armour scan must use the same line rule as the header split, or
        // an all-CR envelope is encrypted a second time.
        let lf = format!(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\n\
             \tboundary=\"b\"\n\
             MIME-Version: 1.0\n\
             \n\
             --b\n\
             Content-Type: application/pgp-encrypted\n\
             \n\
             Version: 1\n\
             \n\
             --b\n\
             Content-Type: application/octet-stream\n\
             \n\
             {}\n\
             --b--\n",
            String::from_utf8_lossy(ARMOR)
        );
        let bare_cr = lf.replace('\n', "\r");
        let armor_cr = String::from_utf8_lossy(ARMOR).replace('\n', "\r");
        assert_eq!(
            envelope_ciphertext(bare_cr.as_bytes()),
            Some(armor_cr.as_bytes())
        );
    }

    #[test]
    fn resaving_strips_plaintext_headers_around_the_ciphertext() {
        // A message of the builder's own shape carrying a plaintext Subject and
        // custom headers in the outer block and inside both parts. Everything
        // outside the ciphertext part is stored in the clear, so only the
        // rebuilt wrapper may survive.
        let msg = format!(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\n\
             \tboundary=\"b\"\n\
             Subject: plaintext subject\n\
             X-Custom: plaintext outer header\n\
             MIME-Version: 1.0\n\
             \n\
             {}\n\
             \n\
             --b\n\
             Content-Type: application/pgp-encrypted\n\
             X-Version: plaintext version header\n\
             \n\
             Version: 1\n\
             \n\
             --b\n\
             Content-Type: application/octet-stream\n\
             Subject: plaintext part header\n\
             \n\
             {}\n\
             --b--\n",
            ENVELOPE_PREAMBLE,
            String::from_utf8_lossy(ARMOR)
        );
        let ciphertext = envelope_ciphertext(msg.as_bytes()).expect("recognised");
        assert_eq!(ciphertext, ARMOR);

        let saved = built_with("n", ciphertext, msg.as_bytes());
        let text = String::from_utf8_lossy(&saved);
        assert!(text.contains("Subject: ...\n"), "{text}");
        for leaked in [
            "plaintext subject",
            "X-Custom",
            "X-Version",
            "plaintext part header",
        ] {
            assert!(!text.contains(leaked), "{leaked} leaked:\n{text}");
        }
    }

    #[test]
    fn a_session_key_packet_with_a_literal_packet_is_not_ciphertext() {
        // A packet stream that names the recipient's key and carries real
        // encrypted data, then appends a literal (unencrypted) message. The
        // literal packet is the only thing that rejects it.
        let dressed = b":pubkey enc packet: version 3, algo 1, keyid DC81B0FDFE212297\n\
            \tdata: [3070 bits]\n\
            :encrypted data packet:\n\
            \tlength: unknown\n\
            \tmdc_method: 2\n\
            :literal data packet:\n\
            \tmode b (62), created 0, name=\"\", raw data: 5 bytes\n";
        assert!(!is_ciphertext_packets(dressed));

        let encrypted = b":pubkey enc packet: version 3, algo 1, keyid DC81B0FDFE212297\n\
            \tdata: [3070 bits]\n\
            :encrypted data packet:\n\
            \tlength: unknown\n\
            \tmdc_method: 2\n";
        assert!(is_ciphertext_packets(encrypted));
        assert!(is_ciphertext_packets(
            b":symkey enc packet: version 4, cipher 9, aead 1, symkey algo 9\n\
              :encrypted data packet:\n"
        ));
        // gpg 2.4 lists AEAD-encrypted data as `:ocb encrypted packet:`.
        assert!(is_ciphertext_packets(
            b":pubkey enc packet: version 3, algo 1, keyid DC81B0FDFE212297\n\
              :ocb encrypted packet: cipher=9 aead=2 cb=16\n\
              \tlength: 241\n"
        ));
        // Whatever else the dump holds, a literal packet makes it a message.
        assert!(!is_ciphertext_packets(
            b":pubkey enc packet: version 3, algo 1, keyid DC81B0FDFE212297\n\
              :ocb encrypted packet: cipher=9 aead=2 cb=16\n\
              :literal data packet:\n"
        ));
        assert!(!is_ciphertext_packets(b":literal data packet:\n"));
        assert!(!is_ciphertext_packets(b""));
    }

    #[test]
    fn an_armour_with_header_comments_or_trailing_text_is_not_ciphertext_to_keep() {
        // Armor header comments would be dropped by the rebuild, so they are
        // not accepted as ciphertext: the message is encrypted instead.
        let commented = b"-----BEGIN PGP MESSAGE-----\n\
            Version: test\n\
            \n\
            YWJjZA==\n\
            -----END PGP MESSAGE-----\n";
        assert_eq!(armored_message(commented), None);

        let trailing = b"-----BEGIN PGP MESSAGE-----\n\
            \n\
            YWJjZA==\n\
            -----END PGP MESSAGE-----\n\
            not part of the armour\n";
        assert_eq!(armored_message(trailing), None);
    }
}
