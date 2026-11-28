// The member key tools: generate a mail key, and check a submitted public key
// against the three conditions that break delivery.
//
// The same logic serves three callers: the CLI in src/main.rs, the browser page
// that loads this as a WebAssembly module, and `keygen-check`, which the control
// plane runs as a process so it does not link the OpenPGP crate. Nothing here
// touches the filesystem or the network, and the clock is passed in rather than
// read, because SystemTime::now() panics on wasm32-unknown-unknown, so a page
// has to supply the time itself.
//
// The three conditions the check reports, each with the mechanism behind it:
//  - no encryption-capable subkey, so there is nothing to encrypt to and mail is refused
//  - an advertised AEAD preference, because gpg then emits an AEAD packet that some mail
//    clients cannot open, and no flag on the encrypt side overrides it
//  - any expiry at all, on the primary key or on its encryption subkey, because
//    scripts/lib.sh::key_problems refuses an expiring key at approval and delivery stops
//    at the date without a word; the clock only decides whether it says "expires" or
//    "expired". Revocation is flagged too.
//
// The check is the half the control plane uses; the generator is the CLI's and
// the page's. `generate` is the feature that separates them.

use pgp::composed::{Deserializable, SignedPublicKey};
#[cfg(feature = "generate")]
use pgp::composed::{
    EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
};
#[cfg(feature = "generate")]
use pgp::crypto::ecc_curve::ECCCurve;
#[cfg(feature = "generate")]
use pgp::crypto::hash::HashAlgorithm;
#[cfg(feature = "generate")]
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Signature, SignatureType, SubpacketData};
#[cfg(feature = "generate")]
use pgp::types::{CompressionAlgorithm, KeyVersion};
use pgp::types::{KeyDetails, Tag};
#[cfg(feature = "generate")]
use rand::thread_rng;
#[cfg(feature = "generate")]
use smallvec::smallvec;

#[cfg(feature = "generate")]
pub const DEFAULT_USER_ID: &str = "Keygen Member <keygen@example.invalid>";

#[cfg(feature = "generate")]
pub struct Generated {
    pub fingerprint: String,
    pub public_armor: String,
    pub secret_armor: String,
}

#[cfg(feature = "generate")]
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

fn binding_allows_encryption(sig: &Signature) -> bool {
    // GnuPG falls back to the algorithm only when the binding omits Key Flags.
    sig.config().is_some_and(|config| {
        config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::KeyFlags(f) => Some(f.encrypt_comms() || f.encrypt_storage()),
                _ => None,
            })
            .unwrap_or(true)
    })
}

fn current_signature(
    signatures: &[Signature],
    now: u64,
    verified: impl Fn(&Signature) -> bool,
) -> Option<&Signature> {
    signatures
        .iter()
        .filter(|sig| {
            let Some(created) = sig.created().map(|t| u64::from(t.as_secs())) else {
                return false;
            };
            let lifetime = sig.signature_expiration_time().map_or(0, |d| d.as_secs());
            created <= now
                && (lifetime == 0 || created + u64::from(lifetime) > now)
                && verified(sig)
        })
        .max_by(|a, b| {
            a.created().cmp(&b.created()).then_with(|| {
                // Simultaneous declarations must not clear a restriction by packet order.
                let restrictions = |s: &Signature| {
                    let expiry = s.key_expiration_time().map_or(0, |d| d.as_secs());
                    (
                        s.typ() == Some(SignatureType::CertRevocation),
                        s.typ() == Some(SignatureType::SubkeyBinding)
                            && !binding_allows_encryption(s),
                        expiry != 0,
                        std::cmp::Reverse(expiry),
                    )
                };
                restrictions(a).cmp(&restrictions(b))
            })
        })
}

/// The three conditions, as the check page would state them. `now_secs` is the caller's
/// clock, so the same code runs in a binary and in a browser.
pub fn check_public_key(armor: &str, now_secs: u64) -> Result<Vec<String>, String> {
    let (key, _) =
        SignedPublicKey::from_armor_single(armor.as_bytes()).map_err(|e| e.to_string())?;
    let mut findings = Vec::new();

    let primary = &key.primary_key;
    let direct = current_signature(&key.details.direct_signatures, now_secs, |sig| {
        sig.typ() == Some(SignatureType::Key) && sig.verify_key(primary).is_ok()
    });
    let users = key.details.users.iter().filter_map(|user| {
        current_signature(&user.signatures, now_secs, |sig| {
            sig.verify_certification(primary, Tag::UserId, &user.id)
                .is_ok()
        })
    });
    let attributes = key.details.user_attributes.iter().filter_map(|attr| {
        current_signature(&attr.signatures, now_secs, |sig| {
            sig.verify_certification(primary, Tag::UserAttribute, &attr.attr)
                .is_ok()
        })
    });

    let mut uid_expiry = None;
    let mut has_self_signature = false;
    let mut aead: Vec<String> = Vec::new();
    for sig in users
        .chain(attributes)
        .filter(|sig| sig.typ() != Some(SignatureType::CertRevocation))
        .chain(direct)
    {
        has_self_signature = true;
        if sig.typ() != Some(SignatureType::Key)
            && let Some(expiry) = sig
                .key_expiration_time()
                .map(|d| d.as_secs())
                .filter(|&d| d != 0)
        {
            uid_expiry = uid_expiry.max(Some((sig.created(), std::cmp::Reverse(expiry))));
        }
        if let Some(config) = sig.config() {
            for subpacket in config.hashed_subpackets() {
                match &subpacket.data {
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
                    // rPGP exposes SEIPDv2, but LibrePGP OCB (0x02) only via the wire flags.
                    SubpacketData::Features(features) => {
                        if Vec::from(features).first().is_some_and(|b| b & 0x02 != 0) {
                            aead.push("the OCB feature bit in the key's features".into());
                        }
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

    if !has_self_signature || (primary.version() == pgp::types::KeyVersion::V6 && direct.is_none())
    {
        findings
            .push("The key has no current, verified self-signature for its primary key.".into());
    }

    if !key.details.revocation_signatures.is_empty() {
        findings.push(
            "The key has been revoked. Make a new key in Thunderbird or with gpg; a revoked key \
             cannot receive mail."
                .into(),
        );
    }

    if !aead.is_empty() {
        findings.push(format!(
            "The key asks for AEAD ciphers ({}), so mail encrypted to it may not open in \
             the member's mail program. Remove AEAD from the key's preferences, or make a \
             new key in Thunderbird or with gpg.",
            aead.join(", ")
        ));
    }

    let created = key.primary_key.created_at().as_secs();
    // Any expiry is a finding, not only one already past: approval's
    // key_problems refuses an expiring key and delivery stops at the date. The
    // clock only chooses the wording. A zero lifetime is OpenPGP's "never".
    // GnuPG uses a direct-key expiry first, then the newest current identity with an expiry.
    let expires_after = direct
        .and_then(Signature::key_expiration_time)
        .map(|d| d.as_secs())
        .filter(|&d| d != 0)
        .or_else(|| uid_expiry.map(|(_, expiry)| expiry.0));
    if let Some(lifetime) = expires_after {
        let expires_at = u64::from(created) + u64::from(lifetime);
        findings.push(if expires_at <= now_secs {
            format!(
                "The key expired at {expires_at} seconds since the epoch and cannot be \
                 used. Make a new key in Thunderbird or with gpg, or extend the expiry in your \
                 mail client before it lapses."
            )
        } else {
            format!(
                "The key expires at {expires_at} seconds since the epoch, and a mail key \
                 must not expire: delivery stops at that date without a word. Choose \
                 \"Key does not expire\" when you make the key, or set its expiry to never \
                 in your mail client."
            )
        });
    }

    // A subkey carries its own expiry and its own revocation, in its binding signature.
    // Reading only the primary key's signatures reports a clean key whose encryption
    // subkey died years ago, which is a false clean in the direction that loses mail.
    let mut has_encryption_subkey = false;
    for sub in &key.public_subkeys {
        if !sub.key.algorithm().can_encrypt() {
            continue;
        }
        let Some(binding) = current_signature(&sub.signatures, now_secs, |sig| {
            sig.typ() == Some(SignatureType::SubkeyBinding)
                && sig.verify_subkey_binding(primary, &sub.key).is_ok()
        }) else {
            continue;
        };
        if !binding_allows_encryption(binding) {
            continue;
        }
        has_encryption_subkey = true;
        if sub.signatures.iter().any(|sig| {
            sig.typ() == Some(SignatureType::SubkeyRevocation)
                && sig.verify_subkey_binding(primary, &sub.key).is_ok()
        }) {
            findings.push(format!(
                "The encryption subkey {:?} has been revoked, so mail cannot be encrypted to \
                 it. Make a new key in Thunderbird or with gpg; a revoked subkey cannot receive mail.",
                sub.key.fingerprint()
            ));
        }
        if let Some(lifetime) = binding.key_expiration_time().map(|d| d.as_secs())
            && lifetime != 0
        {
            let expires_at = u64::from(sub.key.created_at().as_secs()) + u64::from(lifetime);
            findings.push(if expires_at <= now_secs {
                format!(
                    "The encryption subkey expired at {expires_at} seconds since the epoch, \
                     so mail encrypted to this key may not open. Extend the subkey's expiry \
                     in your mail client, or make a new key in Thunderbird or with gpg."
                )
            } else {
                format!(
                    "The encryption subkey expires at {expires_at} seconds since the epoch, \
                     and a mail key must not expire: delivery stops at that date without a \
                     word. Choose \"Key does not expire\" when you make the key, or set the \
                     subkey's expiry to never in your mail client."
                )
            });
        }
    }

    if !has_encryption_subkey {
        findings.push(
            "There is no encryption-capable subkey, so mail to this member would be \
             refused rather than delivered. Make a new key in Thunderbird or with gpg, which makes \
             an encryption subkey beside the signing one."
                .into(),
        );
    }

    Ok(findings)
}

/// Minimal JSON string escaping, so the browser exports need no serializer dependency.
#[cfg(feature = "generate")]
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

#[cfg(feature = "generate")]
fn findings_json(findings: &[String]) -> String {
    let items: Vec<String> = findings.iter().map(|f| format!("\"{}\"", esc(f))).collect();
    format!(
        "{{\"ok\":{},\"findings\":[{}]}}",
        findings.is_empty(),
        items.join(",")
    )
}

/// Exports for the page. wasm-bindgen returns a string rather than a class so the JavaScript
/// side is one `JSON.parse` and the module stays free of serializer dependencies.
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn generate(variant: &str, user_id: &str, passphrase: &str) -> String {
        let pass = if passphrase.is_empty() {
            None
        } else {
            Some(passphrase)
        };
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
#[cfg(feature = "generate")]
pub fn self_check() -> Result<(), String> {
    let g = generate_key("ed25519", DEFAULT_USER_ID, Some("not-a-secret"))?;
    if g.fingerprint.len() != 40 {
        return Err(format!("fingerprint looks wrong: {}", g.fingerprint));
    }
    if !g.public_armor.contains("BEGIN PGP PUBLIC KEY BLOCK") {
        return Err("no public armor".into());
    }
    let findings = check_public_key(&g.public_armor, u64::MAX)?;
    if !findings.is_empty() {
        return Err(format!("a generated key did not check clean: {findings:?}"));
    }
    let not_a_key =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot a key\n-----END PGP PUBLIC KEY BLOCK-----\n";
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

#[cfg(all(test, feature = "generate"))]
mod tests {
    #[test]
    fn self_check_passes() {
        super::self_check().expect("self check");
    }
}
