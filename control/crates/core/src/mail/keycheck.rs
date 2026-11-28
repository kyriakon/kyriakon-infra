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

/// One submitted key block and what the check made of it. Splitting and
/// inspecting once is what lets a refused block, an advisory and a record share
/// one helper spawn.
#[derive(Debug)]
pub enum Inspected {
    /// An armoured public key block, inspected.
    Checked(pgp::Checked),
    /// Not an armoured public key block at all, which the form refuses.
    NotArmoured(Error),
}

impl Inspected {
    /// The refusal this block has earned, or `None` when it may deliver. The
    /// parser-gap advisory is not a refusal.
    pub fn refusal(&self) -> Option<String> {
        match self {
            Inspected::NotArmoured(source) => Some(source.to_string()),
            Inspected::Checked(checked) => checked.refusal().map(str::to_string),
        }
    }

    /// The inspection, when the block was a public key block at all.
    pub fn checked(&self) -> Option<&pgp::Checked> {
        match self {
            Inspected::Checked(checked) => Some(checked),
            Inspected::NotArmoured(_) => None,
        }
    }
}

/// Split a key answer into its blocks and inspect each once. One helper spawn
/// per block, whatever the caller then does with the result.
pub fn inspect(value: &str) -> Vec<Inspected> {
    pgp::blocks(value)
        .into_iter()
        .map(|block| match pgp::public_key(&block) {
            Ok(checked) => Inspected::Checked(checked),
            Err(source) => Inspected::NotArmoured(source),
        })
        .collect()
}

/// The record for one inspected mail key, with the fingerprint and verdict the
/// inspection carried rather than a second run of the check. The User ID
/// warnings are parsed from the same material in memory, so this spawns
/// nothing.
pub fn mail_key_from_checked(mailbox: String, address: &str, checked: &pgp::Checked) -> KeyRecord {
    let mut verdict = checked.verdict.clone();
    if !address.is_empty() {
        for warning in pgp::uid_warnings(&checked.material, address) {
            if verdict == "works" {
                verdict = warning;
            } else {
                verdict.push_str("; ");
                verdict.push_str(&warning);
            }
        }
    }
    KeyRecord {
        mailbox,
        fingerprint: checked.fingerprint.clone(),
        material: checked.material.trim().to_string(),
        verdict,
    }
}

/// The record for one mail key, inspecting the material once. A caller that
/// already holds a [`pgp::Checked`] uses [`mail_key_from_checked`] instead.
/// A block that does not parse is still recorded: the form refuses an inspected
/// finding, and the parser-gap advisory proceeds with the verdict saying what
/// the check found.
pub fn mail_key(mailbox: String, address: &str, material: &str) -> KeyRecord {
    match pgp::public_key(material) {
        Ok(checked) => mail_key_from_checked(mailbox, address, &checked),
        Err(_) => KeyRecord {
            mailbox,
            fingerprint: pgp::fingerprint(material).unwrap_or_default(),
            material: material.trim().to_string(),
            verdict: "unchecked".to_string(),
        },
    }
}

/// The record for one upload key. The mail check does not apply to it, so this
/// runs no helper: only the OpenSSH fingerprint is computed.
pub fn upload_key(material: &str) -> KeyRecord {
    KeyRecord {
        mailbox: String::new(),
        fingerprint: openssh_fingerprint(material).unwrap_or_default(),
        material: material.trim().to_string(),
        verdict: "unchecked".to_string(),
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
