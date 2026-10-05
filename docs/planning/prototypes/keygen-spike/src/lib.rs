// Shared core for the key generator spike, kyriakon-infra#185.
//
// The same logic serves two callers: the CLI in src/main.rs, and the browser page that
// loads this as a WebAssembly module. Nothing here touches the filesystem or the network,
// and the clock is passed in rather than read, because SystemTime::now() panics on
// wasm32-unknown-unknown, so a page has to supply the time itself.
//
// The three conditions the check reports, each with the mechanism behind it:
//  - no encryption-capable subkey, so there is nothing to encrypt to and mail is refused
//  - an advertised AEAD preference, because gpg then emits an AEAD packet that some mail
//    clients cannot open, and no flag on the encrypt side overrides it
//  - the key is expired or revoked, on the primary key or on its encryption subkey
//
// Still a spike. No error types worth the name, no tests beyond the self-check below.

use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::SubpacketData;
use pgp::types::{CompressionAlgorithm, KeyDetails, KeyVersion};
use rand::thread_rng;
use smallvec::smallvec;

pub const DEFAULT_USER_ID: &str = "Spike Member <spike@example.invalid>";

pub struct Generated {
    pub fingerprint: String,
    pub public_armor: String,
    pub secret_armor: String,
}

pub fn generate_key(
    variant: &str,
    user_id: &str,
    passphrase: Option<&str>,
) -> Result<Generated, String> {
    let mut rng = thread_rng();
    let (primary, encryption) = match variant {
        "rsa" => (KeyType::Rsa(4096), KeyType::Rsa(4096)),
        // algo 18 ECDH with Curve25519, the v4 form. KeyType::X25519 writes algo 25,
        // which gpg 2.5 refuses as "Unusable public key" in a v4 certificate.
        _ => (
            KeyType::Ed25519Legacy,
            KeyType::ECDH(ECCCurve::Curve25519Legacy),
        ),
    };

    let key_params = SecretKeyParamsBuilder::default()
        .version(KeyVersion::V4)
        .key_type(primary)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(user_id.into())
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
        .passphrase(passphrase.map(str::to_string))
        .subkey(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V4)
                .key_type(encryption)
                .can_encrypt(EncryptionCaps::All)
                .passphrase(passphrase.map(str::to_string))
                .build()
                .map_err(|e| e.to_string())?,
        )
        .build()
        .map_err(|e| e.to_string())?;

    let key: SignedSecretKey = key_params.generate(&mut rng).map_err(|e| e.to_string())?;
    Ok(Generated {
        fingerprint: key.fingerprint().to_string(),
        public_armor: key
            .to_public_key()
            .to_armored_string(Default::default())
            .map_err(|e| e.to_string())?,
        secret_armor: key
            .to_armored_string(Default::default())
            .map_err(|e| e.to_string())?,
    })
}

/// The three conditions, as the check page would state them. `now_secs` is the caller's
/// clock, so the same code runs in a binary and in a browser.
pub fn check_public_key(armor: &str, now_secs: u64) -> Result<Vec<String>, String> {
    let (key, _) = SignedPublicKey::from_armor_single(armor.as_bytes()).map_err(|e| e.to_string())?;
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
                        aead.push(
                            "an AEAD ciphersuite subpacket (type 34) this build does not parse"
                                .into(),
                        );
                    }
                    SubpacketData::Other(22, _) => {
                        aead.push(
                            "an AEAD algorithms subpacket (type 22) this build does not parse"
                                .into(),
                        );
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
        if u64::from(expires_at) <= now_secs {
            findings.push(format!(
                "The key expired at {expires_at} seconds since the epoch and cannot be used."
            ));
        }
    }

    // A subkey carries its own expiry and its own revocation, in its binding signature.
    // Reading only the primary key's signatures reports a clean key whose encryption
    // subkey died years ago, which is a false clean in the direction that loses mail.
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
            if u64::from(expires_at) <= now_secs {
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

/// Minimal JSON string escaping, so the browser exports need no serializer dependency.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn findings_json(findings: &[String]) -> String {
    let items: Vec<String> = findings.iter().map(|f| format!("\"{}\"", esc(f))).collect();
    format!("{{\"ok\":{},\"findings\":[{}]}}", findings.is_empty(), items.join(","))
}

/// Exports for the page. wasm-bindgen returns a string rather than a class so the JavaScript
/// side is one `JSON.parse` and the module stays free of serializer dependencies.
#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn generate(variant: &str, user_id: &str, passphrase: &str) -> String {
        let pass = if passphrase.is_empty() { None } else { Some(passphrase) };
        match generate_key(variant, user_id, pass) {
            Ok(g) => format!(
                "{{\"ok\":true,\"fingerprint\":\"{}\",\"publicArmor\":\"{}\",\"secretArmor\":\"{}\"}}",
                esc(&g.fingerprint),
                esc(&g.public_armor),
                esc(&g.secret_armor)
            ),
            Err(e) => format!("{{\"ok\":false,\"error\":\"{}\"}}", esc(&e)),
        }
    }

    #[wasm_bindgen]
    pub fn check(armor: &str, now_secs: f64) -> String {
        match check_public_key(armor, now_secs as u64) {
            Ok(findings) => findings_json(&findings),
            Err(e) => format!("{{\"ok\":false,\"error\":\"{}\"}}", esc(&e)),
        }
    }
}

/// One runnable check, so a broken preference list or a dropped condition fails loudly
/// rather than shipping a key no client can read. `cargo test` on this crate runs it, and
/// `--self-check` runs it without a test harness.
pub fn self_check() -> Result<(), String> {
    let g = generate_key("ed25519", DEFAULT_USER_ID, Some("not-a-secret"))?;
    if g.fingerprint.len() != 40 {
        return Err(format!("fingerprint looks wrong: {}", g.fingerprint));
    }
    if !g.public_armor.contains("BEGIN PGP PUBLIC KEY BLOCK") {
        return Err("no public armor".into());
    }
    let findings = check_public_key(&g.public_armor, 1_700_000_000)?;
    if !findings.is_empty() {
        return Err(format!("a generated key did not check clean: {findings:?}"));
    }
    let not_a_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot a key\n-----END PGP PUBLIC KEY BLOCK-----\n";
    if check_public_key(not_a_key, 1_700_000_000).is_ok() {
        return Err("a malformed key was accepted".into());
    }
    if findings_json(&["a \"quoted\" \\ line\nsecond".to_string()])
        != "{\"ok\":false,\"findings\":[\"a \\\"quoted\\\" \\\\ line\\nsecond\"]}"
    {
        return Err("json escaping is wrong".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_check_passes() {
        super::self_check().expect("self check");
    }
}
