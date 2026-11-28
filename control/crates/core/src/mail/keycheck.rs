//! The record for a submitted key: its OpenPGP verdict and fingerprint, or the
//! shape of its OpenSSH upload key.
//!
//! The OpenPGP parsing, the three-condition verdict and the fingerprints are
//! [`super::pgp`]'s. This module keeps the two record shapes and the OpenSSH
//! shape check that decides whether sftp and git will accept an upload key.
//!
//! The verdict recorded is the shared crate's, not a value the client sends.
//! This module refuses only something that is not a public key block at all;
//! the form refuses an inspected key whose verdict is not "works", because
//! AEAD, an expiry, a revoked key or no encryption subkey all stop delivery and
//! the applicant can still change the key. The parser-gap advisory proceeds.
//!
//! The fingerprints are hashes rather than checks: a number that names material
//! it was not computed from reads as a number that disagrees with the key on the
//! box. So [`super::pgp::fingerprint`] computes it over the material the
//! record carries, and [`super::pgp::public_key`] refuses a block carrying
//! more than one primary key (#918). The fingerprints decide nothing; the
//! signature check does.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::pgp;
use super::Error;
use crate::store::KeyRecord;

/// The box keyring entry a localpart's mail key is served from: one `<localpart>.asc`
/// per address, which is what the encrypting LMTP reads.
pub fn keyring_file(dir: &str, localpart: &str) -> PathBuf {
    Path::new(dir).join(format!("{localpart}.asc"))
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
pub fn openssh_public_key(value: &str) -> Result<(), Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::UploadKeyMissing);
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
        return Err(Error::NotOpenSshKey);
    }
    let blob = parts.next().ok_or(Error::UploadKeyNoMaterial)?;
    if pgp::base64_decode(blob).is_none_or(|b| b.is_empty()) {
        return Err(Error::UploadKeyNotDecodable);
    }
    Ok(())
}

/// The record for one mail key, with the fingerprint and the verdict computed
/// over the material rather than taken from the client. A block that does not
/// parse is still recorded: the form refuses an inspected finding, and the
/// parser-gap advisory proceeds with the verdict saying what the check found.
pub fn mail_key(mailbox: String, address: &str, material: &str) -> KeyRecord {
    record(mailbox, address, material, Kind::Mail)
}

/// The record for one upload key. The mail check does not apply to it.
pub fn upload_key(material: &str) -> KeyRecord {
    record(String::new(), "", material, Kind::Upload)
}

enum Kind {
    Mail,
    Upload,
}

fn record(mailbox: String, address: &str, material: &str, kind: Kind) -> KeyRecord {
    let mut verdict = pgp::public_key(material)
        .map(|c| c.verdict)
        .unwrap_or_else(|_| "unchecked".to_string());
    if matches!(kind, Kind::Mail) && !address.is_empty() {
        for warning in pgp::uid_warnings(material, address) {
            if verdict == "works" {
                verdict = warning;
            } else {
                verdict.push_str("; ");
                verdict.push_str(&warning);
            }
        }
    }
    let fingerprint = match kind {
        Kind::Mail => pgp::fingerprint(material),
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
    let raw = pgp::base64_decode(blob)?;
    Some(format!(
        "SHA256:{}",
        pgp::base64_encode(&Sha256::digest(&raw))
    ))
}

/// The prototype's four key fixtures, shared by every test that needs a key of
/// a known shape: the keycheck tests below, the pgp tests, and the
/// form-validation tests in `flow`. The expired-subkey fixture is made by gpg
/// 2.5.24 with a faked 2020 clock and a one-day subkey; gpg's export includes it.
#[cfg(test)]
pub(crate) mod fixtures {
    // The core crate's manifest is `control/crates/core`, so three levels up
    // is the repository root. Naming it from there keeps the path readable and
    // independent of where this file sits.
    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../keygen/fixtures/",
                $name
            ))
        };
    }
    pub(crate) const CLEAN: &str = fixture!("generated-clean.asc");
    pub(crate) const AEAD: &str = fixture!("gpg-aead.asc");
    pub(crate) const NO_ENCRYPTION: &str = fixture!("gpg-no-encryption-subkey.asc");
    pub(crate) const EXPIRED_SUBKEY: &str = fixture!("gpg-expired-subkey.asc");
    pub(crate) const PLATFORM_UID: &str = fixture!("platform-uid.asc");
}

#[cfg(test)]
mod tests {
    use super::fixtures::{CLEAN, PLATFORM_UID};
    use super::*;

    #[test]
    fn a_uid_that_is_not_the_platform_address_is_a_warning_not_a_refusal() {
        assert!(pgp::uid_warnings(PLATFORM_UID, "alice@kyriakon.net").is_empty());
        let warnings = pgp::uid_warnings(CLEAN, "spike@kyriakon.net");
        assert!(
            warnings.iter().any(|w| w.contains("User ID")),
            "{warnings:?}"
        );
        let recorded = mail_key("spike".into(), "spike@kyriakon.net", CLEAN);
        assert!(recorded.verdict.contains("User ID"), "{}", recorded.verdict);
        // A person's key record has no mailbox; the username answer supplies
        // the expected address, so the review email still carries the warning.
        let person = mail_key(String::new(), "spike@kyriakon.net", CLEAN);
        assert!(person.verdict.contains("User ID"), "{}", person.verdict);
        assert!(!mail_key(String::new(), "alice@kyriakon.net", PLATFORM_UID)
            .verdict
            .contains("User ID"));
        // The rotation path passes no address and must not append a UID
        // warning to the verdict the rotation check reads.
        assert_eq!(mail_key(String::new(), "", CLEAN).verdict, "works");
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
