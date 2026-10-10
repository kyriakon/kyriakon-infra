//! Structural checks on a submitted key: armour framing, base64, and the packet
//! structure. No cryptography.
//!
//! The three conditions that decide whether mail can actually be delivered to a
//! key (an encryption-capable subkey, no AEAD preference, not expired) are
//! decided in the browser by the walkthrough (#176, #185), which posts the key's
//! fingerprint beside the material. The verdict recorded here is this module's
//! own structural reading, not a value the client sends. It refuses only
//! something that is not a public key block at all, and never a key merely
//! because the browser would warn about it: the spec warns and proceeds, because
//! a heuristic refusal turns a guarantee into a support queue.

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

/// Inspect an armoured PGP public key block. `Err` is the refusal reason.
pub fn pgp_public_key(value: &str) -> Result<Checked, String> {
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
    let encrypts = packets
        .iter()
        .any(|p| matches!(p.tag, 6 | 14) && encryption_algorithm(p));
    Ok(Checked {
        verdict: if encrypts {
            "works".to_string()
        } else {
            "no encryption subkey".to_string()
        },
    })
}

/// Inspect an OpenSSH public key: the shape sftp and git will accept. A shape
/// check only; the mail check does not apply to an upload key.
pub fn openssh_public_key(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("an upload key is needed".to_string());
    }
    let mut parts = value.split_whitespace();
    let kind = parts.next().unwrap_or("");
    let known = kind.starts_with("ssh-")
        || kind.starts_with("ecdsa-sha2-")
        || kind.starts_with("sk-");
    if !known {
        return Err("this is not an OpenSSH public key".to_string());
    }
    let blob = parts.next().ok_or("the upload key has no key material")?;
    if base64_decode(blob).is_none_or(|b| b.is_empty()) {
        return Err("the upload key's material does not decode".to_string());
    }
    Ok(())
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
                let l = u32::from_be_bytes([*raw.get(i + 2)?, *raw.get(i + 3)?, *raw.get(i + 4)?, *raw.get(i + 5)?]);
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
                    let l = u32::from_be_bytes([*raw.get(i + 1)?, *raw.get(i + 2)?, *raw.get(i + 3)?, *raw.get(i + 4)?]);
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

/// A public-key or public-subkey packet whose algorithm can encrypt to it. RSA
/// (1, 2, 3), ElGamal (16) and ECDH (18) can; DSA, ECDSA and EdDSA are signing
/// algorithms.
fn encryption_algorithm(p: &Packet) -> bool {
    let algo = match p.body.first().copied() {
        // Version 4 and 5: version, four bytes of creation time, then algorithm.
        Some(4) | Some(5) => p.body.get(5).copied(),
        // Version 2 and 3: version, time, two bytes of validity, then algorithm.
        Some(2) | Some(3) => p.body.get(7).copied(),
        _ => None,
    };
    matches!(algo, Some(1..=3) | Some(16) | Some(18))
}

/// Standard base64, padding optional at the end, whitespace ignored. `None` on
/// any character outside the alphabet or a length that cannot decode.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
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
            out.extend_from_slice(&[
                (buf >> 16) as u8,
                (buf >> 8) as u8,
                buf as u8,
            ]);
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
    // key that can be encrypted to.
    const GOOD: &str = "mAYEAAAAABK4BgQAAAAAEg==";
    // One signature packet (tag 2, algo 18), no key packet at all.
    const NO_KEY: &str = "iAYEAAAAABI=";

    fn armoured(b64: &str) -> String {
        format!("{BEGIN}\n\n{b64}\n={END}\n")
    }

    #[test]
    fn a_key_with_an_encryption_packet_passes() {
        let c = pgp_public_key(&armoured(GOOD)).unwrap();
        assert_eq!(c.verdict, "works");
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
    fn a_key_without_an_encryption_packet_is_a_warning_not_a_refusal() {
        // Tag 6, algorithm 17 (DSA), the one signing algorithm the old format
        // could carry beside RSA.
        let sign_only = base64_of(&[0x98, 0x06, 0x04, 0, 0, 0, 0, 17]);
        let c = pgp_public_key(&armoured(&sign_only)).unwrap();
        assert_eq!(c.verdict, "no encryption subkey");
    }

    #[test]
    fn an_openssh_key_is_checked_for_shape() {
        assert!(openssh_public_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host").is_ok());
        assert!(openssh_public_key("-----BEGIN PGP PUBLIC KEY BLOCK-----").is_err());
        assert!(openssh_public_key("ssh-ed25519 notbase64!!!").is_err());
    }

    #[test]
    fn base64_round_trips() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64_decode("mAYEAAAAABK4BgQAAAAAEg==").unwrap().len(), 16);
        assert!(base64_decode("!!!!").is_none());
    }

    fn base64_of(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if chunk.len() > 2 { A[n as usize & 63] as char } else { '=' });
        }
        out
    }
}
