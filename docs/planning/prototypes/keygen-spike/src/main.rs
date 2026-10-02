// Throwaway spike for kyriakon-infra#185.
//
// Two modes. `gen <variant> <dir>` generates a mail key and writes the armored public and
// passphrase-protected secret halves. `check <public.asc>` reads a public key and reports
// the three conditions that break delivery for this platform, which is the logic the
// public key-check page and the signup path both need.
//
// The conditions, each with the mechanism behind it:
//  - no encryption-capable subkey, so there is nothing to encrypt to and mail is refused
//  - an advertised AEAD preference, because gpg then emits an AEAD packet that some mail
//    clients cannot open, and no flag on the encrypt side overrides it
//  - the key is expired or revoked
//
// Not the deliverable. No error handling worth the name, no CLI worth the name, no tests.

use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::SubpacketData;
use pgp::types::{CompressionAlgorithm, KeyDetails, KeyVersion, Timestamp};
use rand::thread_rng;
use smallvec::smallvec;
use std::fs;

const PASSPHRASE: &str = "spike-passphrase-not-a-secret";

fn generate(variant: &str) -> Result<SignedSecretKey, Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
    let (primary, encryption) = match variant {
        "rsa" | "rsa-nopass" => (KeyType::Rsa(4096), KeyType::Rsa(4096)),
        // algo 18 ECDH with Curve25519, the v4 form. KeyType::X25519 writes algo 25,
        // which gpg 2.5 refuses as "Unusable public key" in a v4 certificate.
        _ => (KeyType::Ed25519Legacy, KeyType::ECDH(ECCCurve::Curve25519Legacy)),
    };
    let passphrase = match variant {
        "rsa-nopass" => None,
        _ => Some(PASSPHRASE.to_string()),
    };

    let key_params = SecretKeyParamsBuilder::default()
        .version(KeyVersion::V4)
        .key_type(primary)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Spike Member <spike@example.invalid>".into())
        // The list scripts/rekey-mail-key.sh applies to keys already in the wild, in the
        // same order, so a generated key needs no re-keying.
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha256,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::BZip2,
            CompressionAlgorithm::ZIP,
            CompressionAlgorithm::Uncompressed,
        ])
        .passphrase(passphrase.clone())
        .subkey(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V4)
                .key_type(encryption)
                .can_encrypt(EncryptionCaps::All)
                .passphrase(passphrase)
                .build()?,
        )
        .build()?;

    Ok(key_params.generate(&mut rng)?)
}


/// The three conditions, as the check page would state them.
fn check(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    let (key, _) = SignedPublicKey::from_armor_single(raw.as_bytes())?;
    let mut findings = Vec::new();

    // Expiry and revocation come from the certificate's own signatures. The preferences
    // can sit on a direct key signature rather than on the user id binding, which is what
    // gpg 2.4 and later write, so both places are read. A checker that reads only the user
    // id passes a key that advertises AEAD, which is the whole condition it exists for.
    let mut all_signatures: Vec<&pgp::packet::Signature> =
        key.details.direct_signatures.iter().collect();
    for user in &key.details.users {
        all_signatures.extend(user.signatures.iter());
    }
    for attribute in &key.details.user_attributes {
        all_signatures.extend(attribute.signatures.iter());
    }

    let mut expires_after: Option<u32> = None;
    let mut aead: Vec<String> = Vec::new();
    for sig in all_signatures {
        if let Some(config) = sig.config() {
            for subpacket in config.hashed_subpackets() {
                match &subpacket.data {
                    SubpacketData::KeyExpirationTime(duration) => {
                        expires_after = Some(duration.as_secs());
                    }
                    SubpacketData::PreferredAeadAlgorithms(list) => {
                        for (cipher, mode) in list.iter() {
                            aead.push(format!("{cipher:?} in {mode:?}"));
                        }
                    }
                    // The subpacket gpg actually writes is type 34, and rpgp 0.20 parses it
                    // as PreferredEncryptionModes rather than as PreferredAeadAlgorithms.
                    // A check that matches only the latter reports a false clean on a real
                    // gpg key, which is the dangerous direction for this warning.
                    SubpacketData::PreferredEncryptionModes(modes) => {
                        for mode in modes.iter() {
                            aead.push(format!("{mode:?} as an AEAD mode"));
                        }
                    }
                    // The AEAD feature bit is the other half of the same advertisement.
                    // rpgp exposes seipd_v2() and keeps the bit gpg actually sets (the one
                    // it inherited from LibrePGP, visible in the debug output as
                    // _libre_ocb) behind a private field, so a check written on rpgp's
                    // public API can read half of the feature byte and not the other half.
                    SubpacketData::Features(features) => {
                        if features.seipd_v2() {
                            aead.push("the SEIPD v2 feature bit in the key's features".into());
                        }
                    }
                    SubpacketData::Other(34, _) => {
                        aead.push("an AEAD ciphersuite subpacket (type 34) this build does not parse".into());
                    }
                    SubpacketData::Other(22, _) => {
                        aead.push("an AEAD algorithms subpacket (type 22) this build does not parse".into());
                    }
                    _ => {}
                }
            }
        }
    }

    if !key.details.revocation_signatures.is_empty() {
        findings.push("The key has been revoked.".into());
    }

    if !aead.is_empty() {
        findings.push(format!(
            "The key asks for AEAD ciphers ({}), so mail encrypted to it may not open in \
             the member's mail program. Remove AEAD from the key's preferences, or make a \
             new key with the generator.",
            aead.join(", ")
        ));
    }

    let created = key.primary_key.created_at().as_secs();
    if let Some(lifetime) = expires_after {
        let expires_at = created.saturating_add(lifetime);
        if expires_at <= Timestamp::now().as_secs() {
            findings.push(format!(
                "The key expired at {expires_at} seconds since the epoch and cannot be used."
            ));
        }
    }

    // A subkey carries its own expiry and its own revocation, in its binding signature.
    // Reading only the primary key's signatures reports a clean key whose encryption
    // subkey died years ago, which is a false clean in the direction that loses mail.
    let now = Timestamp::now().as_secs();
    for sub in &key.public_subkeys {
        let sub_created = sub.key.created_at().as_secs();
        let mut sub_expires: Option<u32> = None;
        let mut sub_revoked = false;
        for sig in &sub.signatures {
            if sig.typ() == Some(pgp::packet::SignatureType::SubkeyRevocation) {
                sub_revoked = true;
            }
            if let Some(config) = sig.config() {
                for subpacket in config.hashed_subpackets() {
                    if let SubpacketData::KeyExpirationTime(duration) = &subpacket.data {
                        sub_expires = Some(duration.as_secs());
                    }
                }
            }
        }
        let encrypts = sub.key.algorithm().can_encrypt();
        if sub_revoked && encrypts {
            findings.push(format!(
                "The encryption subkey {:?} has been revoked, so mail cannot be encrypted to it.",
                sub.key.fingerprint()
            ));
        }
        if let (true, Some(lifetime)) = (encrypts, sub_expires) {
            let expires_at = sub_created.saturating_add(lifetime);
            if expires_at <= now {
                findings.push(format!(
                    "The encryption subkey expired at {expires_at} seconds since the epoch, \
                     so mail encrypted to this key may not open."
                ));
            }
        }
    }

    let encrypting: Vec<String> = key
        .public_subkeys
        .iter()
        .filter(|sub| sub.key.algorithm().can_encrypt())
        .map(|sub| format!("{:?}", sub.key.algorithm()))
        .collect();
    if encrypting.is_empty() {
        findings.push(
            "There is no encryption-capable subkey, so mail to this member would be \
             refused rather than delivered."
                .into(),
        );
    }

    Ok(findings)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("dump") => {
            let raw = fs::read_to_string(args.get(2).cloned().unwrap())?;
            let (key, _) = SignedPublicKey::from_armor_single(raw.as_bytes())?;
            let mut sigs: Vec<(&str, &pgp::packet::Signature)> = Vec::new();
            for sig in &key.details.direct_signatures {
                sigs.push(("direct", sig));
            }
            for user in &key.details.users {
                for sig in &user.signatures {
                    sigs.push(("user", sig));
                }
            }
            for (where_, sig) in sigs {
                println!("{where_} signature, typ {:?}", sig.typ());
                if let Some(config) = sig.config() {
                    for subpacket in config.hashed_subpackets() {
                        println!("    {:?}", subpacket.data);
                    }
                }
            }
        }
        Some("check") => {
            let path = args.get(2).cloned().unwrap_or_else(|| "public.asc".into());
            let findings = check(&path)?;
            if findings.is_empty() {
                println!("OK   {path}");
            } else {
                println!("FAIL {path}");
                for finding in findings {
                    println!("     {finding}");
                }
            }
        }
        _ => {
            let variant = args.get(1).map(String::as_str).unwrap_or("ed25519");
            let out = args.get(2).cloned().unwrap_or_else(|| "/tmp/keygen-out".into());
            fs::create_dir_all(&out)?;
            let key = generate(variant)?;
            let secret_armor = key.to_armored_string(Default::default())?;
            fs::write(format!("{out}/secret.asc"), &secret_armor)?;
            fs::write(
                format!("{out}/public.asc"),
                key.to_public_key().to_armored_string(Default::default())?,
            )?;
            println!("{variant} {}", key.fingerprint());

            // Read back what was just written, so the round trip through the armor is
            // tested rather than assumed.
            let (parsed, _) = SignedSecretKey::from_armor_single(secret_armor.as_bytes())?;
            println!("  parsed, {} secret subkey(s)", parsed.secret_subkeys.len());
        }
    }
    Ok(())
}
