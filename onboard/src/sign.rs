//! The signing the review email and the one-time password link rest on.
//!
//! Both links are HMAC-SHA256 over a canonical payload, keyed from the
//! root-only file `scripts/deploy-onboard.sh` installs as
//! `/etc/kyriakon/onboard/approval-signing-key`. The drain signs and the drain
//! verifies: the handler only passes a click through as an intent, so the key
//! never leaves root and the unprivileged half never holds it.
//!
//! HMAC rather than a public-key signature because the verifier is the signer.
//! The one thing a signature would add is verification by a party that does not
//! hold the key, and there is no such party here: the links are checked by the
//! same root process that made them, moments later. An HMAC is one small
//! dependency pair rather than a keypair to store, rotate and publish, and it
//! gives exactly the property the links need, which is that a link cannot be
//! fabricated without the key and that a signature from one application cannot
//! be replayed against another.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The three decisions a review link can carry, and the three the drain's
/// dispatch table names. `approve` is a charged approval and `approve-free` the
/// same decision without charge, which is why they are two actions rather than
/// an action with a flag: the link's whole payload is what is signed, and an
/// action that is one string is one thing to read.
pub const ACTIONS: [&str; 3] = ["approve", "approve-free", "decline"];

/// The key file, as the operator installed it. A trailing newline is the shape
/// a `printf` or an `install` of a generated secret leaves, and it is not part
/// of the key: stripping it here is what lets the same secret be written either
/// way. An empty file is an error rather than an empty key, because an empty
/// key would sign every application with nothing.
pub fn read_key(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(0);
    let key = bytes[..end].to_vec();
    if key.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(key)
}

/// The signature of one payload, lowercase hex. Infallible in practice: HMAC
/// accepts a key of any length, and the error path is kept so a caller writes
/// `?` rather than an `unwrap` on a value the OS randomness feeds.
pub fn sign(key: &[u8], payload: &str) -> Result<String, String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| format!("cannot key the HMAC: {e}"))?;
    mac.update(payload.as_bytes());
    Ok(hex(&mac.finalize().into_bytes()))
}

/// Whether a signature is the one this key makes for this payload. The compare
/// is over the recomputed signature byte by byte and not with `==`, so the time
/// it takes does not tell a caller how much of a guess was right.
pub fn verify(key: &[u8], payload: &str, sig: &str) -> bool {
    match sign(key, payload) {
        Ok(want) => constant_eq(want.as_bytes(), sig.as_bytes()),
        Err(_) => false,
    }
}

/// The payload a review link signs: the application it decides and the decision
/// it carries. Both halves are in it, so a link for one application cannot be
/// replayed against another even if a token were reused.
pub fn decide_payload(token: &str, action: &str) -> String {
    format!("decide:{token}:{action}")
}

/// The payload the one-time password link signs. The date is in the payload so
/// the expiry is covered by the signature and not merely beside it.
pub fn password_payload(token: &str, until: &str) -> String {
    format!("password:{token}:{until}")
}

/// One decision link, pointing at the handler's click-through path.
pub fn decide_link(
    base: &str,
    key: &[u8],
    token: &str,
    action: &str,
) -> Result<String, String> {
    let sig = sign(key, &decide_payload(token, action))?;
    Ok(format!("{base}/decide/{token}?action={action}&sig={sig}"))
}

/// The one-time password link, the same mechanism as the review links.
pub fn password_link(
    base: &str,
    key: &[u8],
    token: &str,
    until: &str,
) -> Result<String, String> {
    let sig = sign(key, &password_payload(token, until))?;
    Ok(format!("{base}/password/{token}?until={until}&sig={sig}"))
}

fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(D[(b >> 4) as usize] as char);
        out.push(D[(b & 15) as usize] as char);
    }
    out
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_is_stable_and_keyed() {
        let a = sign(b"k", "decide:tok:approve").unwrap();
        let b = sign(b"k", "decide:tok:approve").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "{a}");
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // A different key and a different payload each give a different one.
        assert_ne!(a, sign(b"k2", "decide:tok:approve").unwrap());
        assert_ne!(a, sign(b"k", "decide:tok:decline").unwrap());
    }

    #[test]
    fn a_signature_verifies_only_for_its_own_payload() {
        let key = b"the approval key";
        let payload = decide_payload("tok", "approve");
        let sig = sign(key, &payload).unwrap();
        assert!(verify(key, &payload, &sig));
        // A signature for one application does not verify against another, so a
        // link cannot be replayed across applications.
        assert!(!verify(key, &decide_payload("tok2", "approve"), &sig));
        assert!(!verify(key, &decide_payload("tok", "decline"), &sig));
        assert!(!verify(b"other key", &payload, &sig));
        // A truncated or padded signature is refused rather than panicking.
        assert!(!verify(key, &payload, ""));
        assert!(!verify(key, &payload, &format!("{sig}0")));
    }

    #[test]
    fn a_key_file_is_read_without_its_trailing_newline() {
        let dir = std::env::temp_dir().join(format!("onboard-sign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        std::fs::write(&path, b"secret\n").unwrap();
        assert_eq!(read_key(&path).unwrap(), b"secret");
        std::fs::write(&path, b"secret").unwrap();
        assert_eq!(read_key(&path).unwrap(), b"secret");
        std::fs::write(&path, b"\n").unwrap();
        assert!(read_key(&path).is_err(), "an empty key is refused");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_links_put_the_token_in_the_path_and_the_signature_in_the_query() {
        let key = b"k";
        let link = decide_link("https://signup.kyriakon.net", key, "tok", "approve-free").unwrap();
        assert_eq!(
            link,
            format!(
                "https://signup.kyriakon.net/decide/tok?action=approve-free&sig={}",
                sign(key, "decide:tok:approve-free").unwrap()
            )
        );
        let pw = password_link("https://signup.kyriakon.net", key, "tok", "2026-10-20").unwrap();
        assert!(pw.contains("/password/tok?until=2026-10-20&sig="), "{pw}");
    }
}
