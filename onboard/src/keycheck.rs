//! Structural checks on a submitted key: armour framing, base64, and the packet
//! structure, and the fingerprint of the material either way.
//!
//! The three conditions that decide whether mail can actually be delivered to a
//! key (an encryption-capable subkey, no AEAD preference, not expired) are the
//! `keygen-spike` crate's, called here so the terminal and the page's WASM build
//! return the same verdict from one implementation rather than from two copies
//! of the rules. The verdict recorded is the crate's, not a value the client
//! sends. This module refuses only something that is not a public key block at
//! all, and never a key merely because the crate would warn about it: the spec
//! warns and proceeds, because a heuristic refusal turns a guarantee into a
//! support queue.
//!
//! The fingerprints are the exception to that division of labour, and they are
//! hashes rather than checks: a number that names material it was not computed
//! from reads as a number that disagrees with the key on the box. So the
//! fingerprint is computed here, over the material the record carries, in the
//! two shapes the two keys have. They decide nothing.

use std::time::{SystemTime, UNIX_EPOCH};

use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::store::KeyRecord;

const BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const END: &str = "-----END PGP PUBLIC KEY BLOCK-----";

#[derive(Debug)]
pub struct Checked {
    /// "works", or the one structural warning worth recording.
    pub verdict: String,
}

struct Packet {
    tag: u8,
    body: Vec<u8>,
}

/// Inspect an armoured PGP public key block. `Err` is the refusal reason; the
/// verdict is the shared crate's reading of the three conditions, joined when
/// more than one trips.
pub fn pgp_public_key(value: &str) -> Result<Checked, String> {
    let findings = pgp_findings(value)?;
    Ok(Checked {
        verdict: if findings.is_empty() {
            "works".to_string()
        } else {
            findings.join("; ")
        },
    })
}

/// The three-condition inspection, from the crate the page builds to WASM, with
/// the framing check that decides whether the material is a public key block at
/// all. The conditions themselves are not repeated here.
pub fn pgp_findings(value: &str) -> Result<Vec<String>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("a public key is needed".to_string());
    }
    if !value.contains(BEGIN) || !value.contains(END) {
        return Err("this is not an armoured PGP public key block".to_string());
    }
    let body = armour_body(value)?;
    let raw = base64_decode(&body).ok_or("the key's base64 does not decode")?;
    let packets = packets(&raw).ok_or("the key's packet structure cannot be read")?;
    if !packets.iter().any(|p| p.tag == 6) {
        return Err("the block carries no public key packet".to_string());
    }
    // The framing above is the only thing that may refuse a key. A parser that
    // cannot read a well-framed block is a gap in this check, not a verdict on
    // the key, and the spec says a shape the platform cannot verify warns and
    // proceeds, because a refusal would turn a support question into a lost
    // application. The warning says what happened so the reviewer reads it.
    match keygen_spike::check_public_key(value, now_secs()) {
        Ok(findings) => Ok(findings),
        Err(_) => Ok(vec![
            "The key could not be inspected automatically, so a person will check it \
             against the key on the box. The application can still be filed."
                .to_string(),
        ]),
    }
}

/// The clock the crate asks its caller for, because `SystemTime::now()` panics
/// on wasm32 and the browser supplies its own.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Inspect an OpenSSH public key: the shape sftp and git will accept. A shape
/// check only; the mail check does not apply to an upload key.
///
/// The four forms are the ones `scripts/provision-member.sh` writes into
/// `authorized_keys`, named here in the same shape so the two lists can be read
/// against each other. They were two different rules: this one took any kind
/// beginning `ssh-`, so a line the box refuses at provisioning time passed the
/// form, and the approval was half applied, leaving an account with no sftp and
/// no git.
pub fn openssh_public_key(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("an upload key is needed".to_string());
    }
    let mut parts = value.split_whitespace();
    let kind = parts.next().unwrap_or("");
    let known = kind == "ssh-ed25519"
        || kind == "ssh-rsa"
        || kind
            .strip_prefix("ecdsa-sha2-nistp")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        || kind
            .strip_prefix("sk-")
            .and_then(|rest| rest.strip_suffix("@openssh.com"))
            .is_some_and(|middle| {
                !middle.is_empty()
                    && middle
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            });
    if !known {
        return Err("this is not an OpenSSH public key".to_string());
    }
    let blob = parts.next().ok_or("the upload key has no key material")?;
    if base64_decode(blob).is_none_or(|b| b.is_empty()) {
        return Err("the upload key's material does not decode".to_string());
    }
    Ok(())
}

/// The OpenPGP fingerprint of the first public key packet in an armoured block,
/// in the upper-case hex gpg prints: the SHA-1 of the version 4 packet's framing
/// (`0x99`, the packet's length, the packet) or the SHA-256 of a version 6 one
/// (`0x9b`, a four-byte length, the packet), which is RFC 9580's own definition.
/// `None` when the block carries no key packet or one of a version with no
/// fingerprint defined here, which is not a number to guess at.
pub fn pgp_fingerprint(value: &str) -> Option<String> {
    let body = armour_body(value).ok()?;
    let raw = base64_decode(&body)?;
    let key = packets(&raw)?.into_iter().find(|p| p.tag == 6)?;
    let version = key.body.first().copied()?;
    let len = key.body.len();
    let mut framed = Vec::with_capacity(len + 5);
    let digest = match version {
        4 => {
            framed.push(0x99);
            framed.extend_from_slice(&u16::try_from(len).ok()?.to_be_bytes());
            framed.extend_from_slice(&key.body);
            Sha1::digest(&framed).to_vec()
        }
        6 => {
            framed.push(0x9b);
            framed.extend_from_slice(&u32::try_from(len).ok()?.to_be_bytes());
            framed.extend_from_slice(&key.body);
            Sha256::digest(&framed).to_vec()
        }
        _ => return None,
    };
    Some(digest.iter().map(|b| format!("{b:02X}")).collect())
}

/// Split a key answer into armoured blocks, one per mailbox. The handler's two
/// front-ends and the drain's mail route all take a paste that may carry more
/// than one block, so the split is one function rather than three copies.
pub fn blocks(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_block = false;
    for line in value.lines() {
        let t = line.trim();
        if t.starts_with(BEGIN) {
            in_block = true;
            cur.clear();
        }
        if in_block {
            cur.push_str(line);
            cur.push('\n');
        }
        if t.starts_with(END) && in_block {
            in_block = false;
            out.push(cur.trim().to_string());
        }
    }
    out
}

/// The record for one mail key, with the fingerprint and the verdict computed
/// over the material rather than taken from the client. A block that does not
/// parse is still recorded: the spec warns and proceeds, and the verdict says
/// what the check found.
pub fn mail_key(mailbox: String, material: &str) -> KeyRecord {
    record(mailbox, material, Kind::Mail)
}

/// The record for one upload key. The mail check does not apply to it.
pub fn upload_key(material: &str) -> KeyRecord {
    record(String::new(), material, Kind::Upload)
}

enum Kind {
    Mail,
    Upload,
}

fn record(mailbox: String, material: &str, kind: Kind) -> KeyRecord {
    let verdict = pgp_public_key(material)
        .map(|c| c.verdict)
        .unwrap_or_else(|_| "unchecked".to_string());
    let fingerprint = match kind {
        Kind::Mail => pgp_fingerprint(material),
        Kind::Upload => openssh_fingerprint(material),
    }
    .unwrap_or_default();
    KeyRecord {
        mailbox,
        fingerprint,
        material: material.trim().to_string(),
        verdict,
    }
}

/// The OpenSSH fingerprint `ssh-keygen -l` prints: `SHA256:` and the unpadded
/// base64 of the key blob's SHA-256. `None` when the line has no key material to
/// hash.
pub fn openssh_fingerprint(value: &str) -> Option<String> {
    let blob = value.split_whitespace().nth(1)?;
    let raw = base64_decode(blob)?;
    Some(format!("SHA256:{}", base64_encode(&Sha256::digest(&raw))))
}

/// Standard base64 without padding, which is the form OpenSSH prints a
/// fingerprint in.
fn base64_encode(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(A[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(A[n as usize & 63] as char);
        }
    }
    out
}

/// The base64 body of an armoured block: everything between the armour headers
/// (and the blank line after them) and the checksum or END line.
fn armour_body(value: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut started = false;
    for line in value.lines() {
        let line = line.trim_end();
        if !started {
            if line.trim_start().starts_with(BEGIN) {
                started = true;
            }
            continue;
        }
        let t = line.trim();
        if t.starts_with(END) || t.starts_with('=') {
            break;
        }
        if t.is_empty() || t.contains(':') {
            continue;
        }
        out.push_str(t);
    }
    if out.is_empty() {
        return Err("the armoured block carries no key material".to_string());
    }
    Ok(out)
}

/// Walk the packet headers. `None` if a header is malformed or a partial length
/// is met, which is a structure this check does not read.
fn packets(raw: &[u8]) -> Option<Vec<Packet>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        let b = raw[i];
        if b & 0x80 == 0 {
            return None;
        }
        let (tag, len, hdr) = if b & 0x40 != 0 {
            // New-format header.
            let tag = b & 0x3f;
            let l1 = *raw.get(i + 1)? as usize;
            if l1 < 192 {
                (tag, l1, 2usize)
            } else if l1 < 224 {
                let l2 = *raw.get(i + 2)? as usize;
                (tag, ((l1 - 192) << 8) + l2 + 192, 3usize)
            } else if l1 == 255 {
                let l = u32::from_be_bytes([
                    *raw.get(i + 2)?,
                    *raw.get(i + 3)?,
                    *raw.get(i + 4)?,
                    *raw.get(i + 5)?,
                ]);
                (tag, l as usize, 6usize)
            } else {
                return None; // partial body length
            }
        } else {
            // Old-format header.
            let tag = (b >> 2) & 0x0f;
            let lt = b & 0x03;
            match lt {
                0 => (tag, *raw.get(i + 1)? as usize, 2usize),
                1 => (
                    tag,
                    u16::from_be_bytes([*raw.get(i + 1)?, *raw.get(i + 2)?]) as usize,
                    3usize,
                ),
                2 => {
                    let l = u32::from_be_bytes([
                        *raw.get(i + 1)?,
                        *raw.get(i + 2)?,
                        *raw.get(i + 3)?,
                        *raw.get(i + 4)?,
                    ]);
                    (tag, l as usize, 5usize)
                }
                _ => return None, // indeterminate length
            }
        };
        let start = i.checked_add(hdr)?;
        let end = start.checked_add(len)?;
        if end > raw.len() {
            return None;
        }
        out.push(Packet {
            tag,
            body: raw[start..end].to_vec(),
        });
        i = end;
    }
    Some(out)
}

/// Standard base64, padding optional at the end, whitespace ignored. `None` on
/// any character outside the alphabet or a length that cannot decode.
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut n = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        buf = (buf << 6) | u32::from(val(c)?);
        n += 1;
        if n == 4 {
            out.extend_from_slice(&[(buf >> 16) as u8, (buf >> 8) as u8, buf as u8]);
            buf = 0;
            n = 0;
        }
    }
    match n {
        0 => {}
        2 => out.push((buf >> 4) as u8),
        3 => {
            out.push((buf >> 10) as u8);
            out.push((buf >> 2) as u8);
        }
        // A single trailing character is six bits, which is not a byte, and is
        // not valid base64.
        _ => return None,
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A public key packet (tag 6, algo 18 ECDH) and a public subkey packet
    // (tag 14, algo 18): 16 bytes, the smallest thing with the structure of a
    // key. The fingerprint test below reads it; the three-condition checks use
    // the fixtures the prototype tested, because those rules live in its crate.
    const GOOD: &str = "mAYEAAAAABK4BgQAAAAAEg==";
    // One signature packet (tag 2, algo 18), no key packet at all.
    const NO_KEY: &str = "iAYEAAAAABI=";

    // The prototype's four fixtures, which its CLI and the page's WASM build both
    // check. The expired-subkey fixture is made by gpg 2.5.24 with a faked 2020
    // clock and a one-day subkey; gpg's export includes it.
    const CLEAN: &str =
        include_str!("../../docs/planning/prototypes/keygen-spike/fixtures/generated-clean.asc");
    const AEAD: &str =
        include_str!("../../docs/planning/prototypes/keygen-spike/fixtures/gpg-aead.asc");
    const NO_ENCRYPTION: &str = include_str!(
        "../../docs/planning/prototypes/keygen-spike/fixtures/gpg-no-encryption-subkey.asc"
    );
    const EXPIRED_SUBKEY: &str =
        include_str!("../../docs/planning/prototypes/keygen-spike/fixtures/gpg-expired-subkey.asc");

    fn armoured(b64: &str) -> String {
        format!("{BEGIN}\n\n{b64}\n={END}\n")
    }

    #[test]
    fn the_generators_own_key_checks_clean() {
        let c = pgp_public_key(CLEAN).unwrap();
        assert_eq!(c.verdict, "works");
    }

    #[test]
    fn each_condition_carries_its_own_message_and_never_refuses() {
        let aead = pgp_public_key(AEAD).expect("a warning is not a refusal");
        assert!(aead.verdict.contains("AEAD"), "{}", aead.verdict);
        assert!(aead.verdict.contains("Remove AEAD"), "{}", aead.verdict);

        let no_encryption = pgp_public_key(NO_ENCRYPTION).expect("a warning is not a refusal");
        assert!(
            no_encryption
                .verdict
                .contains("no encryption-capable subkey"),
            "{}",
            no_encryption.verdict
        );

        let expired = pgp_public_key(EXPIRED_SUBKEY).expect("a warning is not a refusal");
        assert!(
            expired.verdict.contains("encryption subkey expired"),
            "{}",
            expired.verdict
        );
    }

    #[test]
    fn framing_and_base64_are_refused_with_a_reason() {
        assert!(pgp_public_key("hello").unwrap_err().contains("armoured"));
        let bad = armoured("not base64 !!!");
        assert!(pgp_public_key(&bad).unwrap_err().contains("base64"));
    }

    #[test]
    fn a_block_with_no_public_key_packet_is_refused() {
        let e = pgp_public_key(&armoured(NO_KEY)).unwrap_err();
        assert!(e.contains("public key packet"), "{e}");
    }

    #[test]
    fn a_framed_block_the_parser_cannot_read_warns_and_proceeds() {
        // `GOOD` has the framing and a public key packet, and nothing the
        // parser can understand. A refusal here would lose an application over
        // a gap in the check, so it is a warning with a reader named.
        let c = pgp_public_key(&armoured(GOOD)).expect("a warning is not a refusal");
        assert!(
            c.verdict.contains("could not be inspected"),
            "{}",
            c.verdict
        );
    }

    #[test]
    fn an_openssh_key_is_checked_for_shape() {
        assert!(openssh_public_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host").is_ok());
        assert!(openssh_public_key("-----BEGIN PGP PUBLIC KEY BLOCK-----").is_err());
        assert!(openssh_public_key("ssh-ed25519 notbase64!!!").is_err());
    }

    /// The four forms are the ones `scripts/provision-member.sh` writes into
    /// `authorized_keys`, and this list and that one are meant to be read against
    /// each other. The crate used to take any kind beginning `ssh-`, so a line the
    /// box refuses at provisioning time passed the form, and the approval was half
    /// applied: an account with no sftp and no git.
    #[test]
    fn the_upload_key_forms_are_the_four_the_box_accepts() {
        for good in [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host",
            "ssh-rsa AAAAC3NzaC1yc2EAAAA user@host",
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAA user@host",
            "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAA user@host",
        ] {
            assert!(
                openssh_public_key(good).is_ok(),
                "{good} should be accepted"
            );
        }
        for bad in [
            // A certificate line begins `ssh-` exactly as the first form does.
            "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQAAA user@host",
            "ssh-dss AAAAB3NzaC1kc3MAAA user@host",
            "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYAAA user@host",
            "ecdsa-sha2-nistp256x AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAA user@host",
            // A resident key without the suffix the box wants.
            "sk-ssh-ed25519 AAAAGnNrLXNzaCAAA user@host",
        ] {
            assert!(openssh_public_key(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn base64_round_trips() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64_decode("mAYEAAAAABK4BgQAAAAAEg==").unwrap().len(), 16);
        assert!(base64_decode("!!!!").is_none());
    }

    #[test]
    fn a_v4_fingerprint_is_the_hash_of_the_framed_key_packet() {
        // GOOD's key packet is six bytes: version 4, four bytes of creation time,
        // algorithm 18. Its fingerprint is the SHA-1 of 0x99, that length in two
        // bytes, and those six bytes, which is the number gpg prints for the same
        // packet.
        assert_eq!(
            pgp_fingerprint(&armoured(GOOD)).as_deref(),
            Some("E6EC346E2ADF3273FC2427550A3E4823302ED1D3")
        );
        // Not a key at all, and a packet of no version: no number to give.
        assert_eq!(pgp_fingerprint("hello"), None);
        assert_eq!(pgp_fingerprint(&armoured(NO_KEY)), None);
    }

    #[test]
    fn an_ssh_fingerprint_is_the_one_ssh_keygen_prints() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEneyKlmR58gWNLesodiRodRAss6LnzTWOXQZDDTwgqE test@example";
        assert_eq!(
            openssh_fingerprint(line).as_deref(),
            Some("SHA256:AKJY00Q0wyarJib298vyVjNrGBFRYqsPeWcBluZNRQU"),
            "ssh-keygen -lf prints this for the same key"
        );
        assert_eq!(openssh_fingerprint("ssh-ed25519"), None);
    }
}
