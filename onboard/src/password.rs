//! The one-time password link's password half: what a password may be, and the
//! hash the store keeps.
//!
//! The handler hashes and the drain sets the hash, so no plaintext is written
//! anywhere: not to the store, not to the intent file. bcrypt because the
//! platform's login is BSD auth against the system account, which reads a
//! `$2b$` hash, and the cost is the crate's default for that format.

use bcrypt::{hash, verify, DEFAULT_COST};

/// The shortest password accepted. Twelve is what four common words reach
/// without being one: the rule is a length, not a character-class table someone
/// satisfies with `Password1`.
const MIN_LEN: usize = 12;

/// bcrypt reads at most 72 bytes, so a longer password would silently be
/// truncated; refusing it is the honest half of that limit.
const MAX_LEN: usize = 72;

/// Why a password is not acceptable, or nothing.
pub fn validate(plain: &str) -> Result<(), String> {
    let len = plain.chars().count();
    if len < MIN_LEN {
        return Err(format!("Use at least {MIN_LEN} characters."));
    }
    if plain.len() > MAX_LEN {
        return Err(format!("Use at most {MAX_LEN} characters."));
    }
    if plain.chars().any(char::is_control) {
        return Err("Use printable characters only.".to_string());
    }
    Ok(())
}

/// The hash the store keeps.
pub fn make(plain: &str) -> Result<String, String> {
    hash(plain, DEFAULT_COST).map_err(|e| format!("cannot hash the password: {e}"))
}

/// Whether a stored hash is one this crate made. The drain checks the shape
/// before it writes the hash onto an account, so a malformed intent fails there
/// rather than in `usermod`.
pub fn is_hash(stored: &str) -> bool {
    // A bcrypt hash is `$2b$<cost>$<22-byte salt><31-byte digest>`, 60
    // characters: the salt and the digest are one segment, with no separator
    // between them. Its length is checked because `usermod -p` writes any line,
    // and a truncated one locks the account.
    let mut parts = stored.split('$');
    parts.next() == Some("")
        && matches!(parts.next(), Some("2a" | "2b" | "2y"))
        && parts.next().is_some_and(|cost| cost.parse::<u32>().is_ok())
        && parts.next().is_some_and(|body| body.len() >= 53)
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
}
