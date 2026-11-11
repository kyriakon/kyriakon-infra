//! The one-time password link's password half: what a password may be, and the
//! hash the store keeps.
//!
//! The drain hashes the plaintext and installs the hash, so the handler never
//! chooses what is stored. The plaintext travels only in the intent file: the
//! drain overwrites it in memory once hashed, removes the file after a
//! successful apply, and strips it from any intent a refusal leaves in place.
//! bcrypt because the platform's login is BSD auth against the system account,
//! which reads a `$2b$` hash, and the cost is the crate's default for that
//! format.

use crate::Error;
use bcrypt::{hash, verify, DEFAULT_COST};

/// The shortest password accepted. Twelve is what four common words reach
/// without being one: the rule is a length, not a character-class table someone
/// satisfies with `Password1`.
const MIN_LEN: usize = 12;

/// bcrypt reads at most 72 bytes, so a longer password would silently be
/// truncated; refusing it is the honest half of that limit.
const MAX_LEN: usize = 72;

/// Why a password is not acceptable, or nothing.
pub fn validate(plain: &str) -> Result<(), Error> {
    let len = plain.chars().count();
    if len < MIN_LEN {
        return Err(Error::Failed(format!("Use at least {MIN_LEN} characters.")));
    }
    if plain.len() > MAX_LEN {
        return Err(Error::Failed(format!("Use at most {MAX_LEN} characters.")));
    }
    if plain.chars().any(char::is_control) {
        return Err(Error::Failed("Use printable characters only.".to_string()));
    }
    Ok(())
}

/// The hash the store keeps.
pub fn make(plain: &str) -> Result<String, Error> {
    hash(plain, DEFAULT_COST).map_err(|e| Error::context("cannot hash the password", e))
}

/// Whether a stored hash is one this crate made. The drain checks the shape
/// before it writes the hash onto an account, so a malformed intent fails there
/// rather than in `usermod`.
pub fn is_hash(stored: &str) -> bool {
    // A bcrypt hash is `$2b$<cost>$<22-byte salt><31-byte digest>`, 60
    // characters: the salt and the digest are one segment, with no separator
    // between them. The body is exactly 53 characters, checked so a longer line
    // cannot pass as one `usermod -p` would write: BSD auth cannot verify it,
    // which locks the member out while the intent journals `applied`.
    let mut parts = stored.split('$');
    parts.next() == Some("")
        && matches!(parts.next(), Some("2a" | "2b" | "2y"))
        && parts.next().is_some_and(|cost| cost.parse::<u32>().is_ok())
        && parts.next().is_some_and(|body| body.len() == 53)
        && parts.next().is_none()
}

/// Whether a plaintext matches the stored hash. The account page's login uses
/// this when it exists; the tests use it now.
pub fn matches(plain: &str, stored: &str) -> bool {
    verify(plain, stored).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_password_is_refused() {
        assert!(validate("elevenchars").is_err());
        assert!(validate("twelvechars!").is_ok());
    }

    #[test]
    fn a_control_character_is_refused() {
        assert!(validate("twelve chars\n").is_err());
    }

    #[test]
    fn the_hash_is_a_bcrypt_hash_and_matches() {
        let h = make("correct horse").unwrap();
        assert!(is_hash(&h), "{h}");
        assert!(matches("correct horse", &h));
        assert!(!matches("wrong horse", &h));
        // Never the plaintext, and never stable: a fresh salt each time.
        assert!(!h.contains("correct horse"));
        assert_ne!(h, make("correct horse").unwrap());
    }

    #[test]
    fn a_malformed_hash_is_not_a_hash() {
        assert!(!is_hash("not a hash"));
        assert!(!is_hash("$2b$12$"));
        assert!(!is_hash(""));
    }

    /// A body past bcrypt's 53 characters is a line `usermod -p` would write and
    /// BSD auth could not verify, so it must never pass as a hash.
    #[test]
    fn a_body_longer_than_bcrypts_is_not_a_hash() {
        let long = format!("$2b$12${}", "a".repeat(54));
        assert_eq!(long.len(), 61);
        assert!(!is_hash(&long));
    }
}
