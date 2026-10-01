// Throwaway spike for kyriakon-infra#185.
//
// Question it answers: can a Rust crate generate a mail key that this platform can
// serve, meaning a key with an encryption subkey, no advertised AEAD preference (gpg
// emits an AEAD packet when the recipient advertises one, and no flag on the encrypt
// side overrides it), preferences gpg and Thunderbird both accept, and a
// passphrase-protected private key that gpg can actually unlock.
//
// Not the deliverable. No error handling worth the name, no CLI, no tests.

use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{CompressionAlgorithm, KeyDetails, KeyVersion};
use rand::thread_rng;
use smallvec::smallvec;
use std::fs;

const PASSPHRASE: &str = "spike-passphrase-not-a-secret";

fn build(variant: &str) -> Result<SignedSecretKey, Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
    let (primary, encryption) = match variant {
        "rsa" | "rsa-nopass" => (KeyType::Rsa(4096), KeyType::Rsa(4096)),
        // algo 18 ECDH with Curve25519, the v4 form. KeyType::X25519 writes algo 25,
        // which gpg 2.5 refuses as "Unusable public key" in a v4 certificate.
        _ => (KeyType::Ed25519Legacy, KeyType::ECDH(ECCCurve::Curve25519Legacy)),
    };
    let version = KeyVersion::V4;
    let passphrase = match variant {
        "rsa-nopass" => None,
        _ => Some(PASSPHRASE.to_string()),
    };

    let key_params = SecretKeyParamsBuilder::default()
        .version(version)
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
            CompressionAlgorithm::ZIP,
            CompressionAlgorithm::Uncompressed,
        ])
        .passphrase(passphrase.clone())
        .subkey(
            SubkeyParamsBuilder::default()
                .version(version)
                .key_type(encryption)
                .can_encrypt(EncryptionCaps::All)
                .passphrase(passphrase)
                .build()?,
        )
        .build()?;

    Ok(key_params.generate(&mut rng)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let variant = args.get(1).map(String::as_str).unwrap_or("ed25519");
    let out = args.get(2).cloned().unwrap_or_else(|| "/tmp/keygen-out".into());
    fs::create_dir_all(&out)?;

    let key = build(variant)?;
    let secret_armor = key.to_armored_string(Default::default())?;
    fs::write(format!("{out}/secret.asc"), &secret_armor)?;
    fs::write(
        format!("{out}/public.asc"),
        key.to_public_key().to_armored_string(Default::default())?,
    )?;
    println!("{variant} {}", key.fingerprint());

    // Read back what was just written, so the round trip through the armor is tested
    // rather than assumed, and try to unlock the secret material with the passphrase.
    let (parsed, _) = SignedSecretKey::from_armor_single(secret_armor.as_bytes())?;
    println!("  parsed, {} secret subkey(s)", parsed.secret_subkeys.len());
    match &variant[..] {
        "rsa-nopass" => println!("  unprotected by design"),
        _ => {
            let sub = &parsed.secret_subkeys[0];
            let unlocked = sub
                .key
                .unlock(&PASSPHRASE.into(), |_public, _plain| Ok::<(), pgp::errors::Error>(()));
            match unlocked {
                Ok(Ok(())) => println!("  rpgp unlocks its own protected key: yes"),
                Ok(Err(e)) => println!("  rpgp unlocks its own protected key: NO ({e})"),
                Err(e) => println!("  rpgp unlock error: {e}"),
            }
        }
    }
    Ok(())
}
