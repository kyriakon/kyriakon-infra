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
//! The Dovecot shim runs `kyriakon-encrypt encrypt` and reads the ciphertext
//! from its stdout: exit status carries failure, so a gpg error or a write cut
//! short is a failed save and plaintext is never stored.

use std::fmt;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// The first line of every envelope this crate produces: the one definition,
/// written by `rfc3156_envelope` and required by the envelope gate.
const ENVELOPE_MARKER: &str =
    "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";";

/// The RFC 3156 preamble the builder writes before the first boundary. The
/// envelope gate accepts only this text, because everything before the first
/// part is stored in the clear: a sender that puts anything else there has
/// written a message to encrypt, not ciphertext to keep.
const ENVELOPE_PREAMBLE: &str = "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156).";

/// Whether `input` is already an envelope this crate built for the recipient of
/// `cert`, in which case it is saved as it stands rather than encrypted again.
///
/// A second encryption does not lose the message, but it breaks it: the store
/// holds a ciphertext whose payload is another envelope, so a client decrypts
/// once and shows an encrypted blob where the mail should be. A client that
/// files a message by re-uploading it on the save path did that on the live box.
///
/// The marker alone cannot be trusted to mean ciphertext, since a sender could
/// mail a message that begins with it - a forwarded mail, say, whose attachment
/// is ciphertext for this recipient - and have the plaintext written to the
/// store as though it were encrypted. So the outer MIME has to be the RFC 3156
/// shape this crate builds (`envelope_ciphertext`), and the key id is read from
/// that envelope's ciphertext part alone. Ciphertext addressed to another key,
/// a copy of the cert carried inline, a stream gpg cannot parse, and anything
/// whose parts do not match all fall through to normal encryption.
fn already_encrypted(input: &[u8], cert: &Path, gpg_home: &Path) -> bool {
    let Some(ciphertext) = envelope_ciphertext(input) else {
        return false;
    };
    let Ok(cert_packets) = std::fs::read(cert) else {
        return false;
    };
    let ours = cert_key_ids(&list_packets(&cert_packets, gpg_home));
    if ours.is_empty() {
        return false;
    }
    message_key_ids(&list_packets(ciphertext, gpg_home))
        .iter()
        .any(|id| ours.contains(id))
}

/// The armoured ciphertext body of `input` when it is the envelope this crate
/// builds: the marker Content-Type first, the builder's preamble, exactly two
/// parts, the first `application/pgp-encrypted` with `Version: 1`, the second
/// `application/octet-stream`, and the message ending at the closing boundary.
/// Anything else is not our envelope: a message that merely begins with the
/// marker is a message to encrypt, not ciphertext to keep.
fn envelope_ciphertext(input: &[u8]) -> Option<&[u8]> {
    if !input.starts_with(ENVELOPE_MARKER.as_bytes()) {
        return None;
    }
    let (block, sep, body) = split_message(input);
    if sep.is_empty() {
        return None;
    }
    let (name, start, end) = header_spans(block).into_iter().next()?;
    if name != "content-type" {
        return None;
    }
    let boundary = boundary_param(&block[start..end])?;
    let (version, ciphertext) = two_parts(strip_preamble(body)?, &boundary)?;
    if !is_version_part(version) {
        return None;
    }
    part_body(ciphertext)
}

/// Strip the builder's preamble and the blank line after it. A client that
/// re-uploads a stored message may send CRLF, so either ending is accepted;
/// the line itself has to match.
fn strip_preamble(body: &[u8]) -> Option<&[u8]> {
    let rest = body.strip_prefix(ENVELOPE_PREAMBLE.as_bytes())?;
    let rest = rest
        .strip_prefix(b"\r\n")
        .or_else(|| rest.strip_prefix(b"\n"))?;
    rest.strip_prefix(b"\r\n")
        .or_else(|| rest.strip_prefix(b"\n"))
}

/// The `boundary` parameter of a Content-Type header, unquoted.
fn boundary_param(header: &[u8]) -> Option<String> {
    let value = header_value(header)?;
    value.split(';').skip(1).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        (!value.is_empty()).then(|| value.to_string())
    })
}

/// The value of a header span, from after the colon.
fn header_value(header: &[u8]) -> Option<&str> {
    let colon = header.iter().position(|&b| b == b':')?;
    std::str::from_utf8(&header[colon + 1..]).ok()
}

/// The type/subtype of a Content-Type header, lowercased and without
/// parameters.
fn media_type(header: &[u8]) -> Option<String> {
    let value = header_value(header)?.trim_start();
    let end = value
        .find(|c: char| c == ';' || c.is_ascii_whitespace())
        .unwrap_or(value.len());
    Some(value[..end].to_ascii_lowercase())
}

/// The two parts of a multipart body that starts at the opening delimiter and
/// ends at the closing one, with nothing after it.
fn two_parts<'a>(body: &'a [u8], boundary: &str) -> Option<(&'a [u8], &'a [u8])> {
    let delim = format!("--{boundary}");
    let close = format!("--{boundary}--");
    let (delim, close) = (delim.as_bytes(), close.as_bytes());

    let (line, mut pos) = next_line(body, 0)?;
    if line != delim {
        return None;
    }
    let first_start = pos;
    let mut first_end = None;
    let mut second_start = 0;
    let mut parts = 0;
    while let Some((line, next)) = next_line(body, pos) {
        if line == delim {
            parts += 1;
            if parts > 1 {
                return None; // a third part
            }
            first_end = Some(pos);
            second_start = next;
        } else if line == close {
            parts += 1;
            if parts != 2 {
                return None;
            }
            if body[next..].iter().any(|b| !matches!(b, b'\n' | b'\r')) {
                return None;
            }
            return Some((&body[first_start..first_end?], &body[second_start..pos]));
        }
        pos = next;
    }
    None
}

/// Whether a part is the RFC 3156 version part: `application/pgp-encrypted`
/// with exactly `Version: 1` as its body.
fn is_version_part(part: &[u8]) -> bool {
    let (block, sep, body) = split_message(part);
    if sep.is_empty() {
        return false;
    }
    let Some((_, start, end)) = header_spans(block)
        .into_iter()
        .find(|(name, _, _)| name == "content-type")
    else {
        return false;
    };
    let Some(media_type) = media_type(&block[start..end]) else {
        return false;
    };
    media_type == "application/pgp-encrypted" && body.trim_ascii_end() == b"Version: 1"
}

/// The body of a MIME part whose Content-Type is `application/octet-stream`.
fn part_body(part: &[u8]) -> Option<&[u8]> {
    let (block, sep, body) = split_message(part);
    if sep.is_empty() {
        return None;
    }
    let (_, start, end) = header_spans(block)
        .into_iter()
        .find(|(name, _, _)| name == "content-type")?;
    (media_type(&block[start..end])?.as_str() == "application/octet-stream").then_some(body)
}

/// One line of `block` from `pos`, without its line ending, and the offset of
/// the line after it. `None` past the end.
fn next_line(block: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    if pos >= block.len() {
        return None;
    }
    match block[pos..].iter().position(|&b| b == b'\n') {
        Some(off) => {
            let nl = pos + off;
            let end = if nl > pos && block[nl - 1] == b'\r' {
                nl - 1
            } else {
                nl
            };
            Some((&block[pos..end], nl + 1))
        }
        None => Some((&block[pos..], block.len())),
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

/// `gpg --list-packets` over `input`. Inspection only, and best effort: a
/// stream gpg cannot parse produces no output, which the caller reads as "not
/// our ciphertext" and encrypts as usual rather than failing the save.
///
/// The exit status is deliberately ignored. gpg prints the packet listing and
/// then exits non-zero for a message it cannot decrypt, which is every message
/// here: the encryptor's gpg homedir holds no secret key, by design. Treating that
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

/// Create the gpg scratch dir (0700). Idempotent; run per message because the
/// save path cannot assume external setup completed.
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
/// the placeholder with the real one afterwards.
fn rfc3156_envelope(boundary: &str, armor: &[u8], msg: &[u8]) -> Vec<u8> {
    let (block, _, _) = split_message(msg);
    let mut out = Vec::with_capacity(armor.len() + msg.len().min(4096) + 512);
    out.extend_from_slice(format!("{ENVELOPE_MARKER}\n\tboundary=\"{boundary}\"\n").as_bytes());
    for (name, start, end) in header_spans(block) {
        if EXPOSED_HEADERS.contains(&name.as_str()) {
            out.extend_from_slice(&block[start..end]);
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

    fn envelope() -> Vec<u8> {
        rfc3156_envelope("b", b"ARMOR", MESSAGE)
    }

    #[test]
    fn an_envelope_yields_its_ciphertext_part() {
        // The envelope's own ciphertext part comes back as the armour alone, so
        // the key-id scan sees ciphertext and nothing else.
        assert_eq!(envelope_ciphertext(&envelope()), Some(&b"ARMOR\n"[..]));
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
}
