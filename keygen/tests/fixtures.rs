// The fixtures the check is measured against, through the same function the
// CLI, `keygen-check` and the page's WASM export call. The generator's key is clean, and each gpg
// key isolates one of the conditions: the AEAD advert (subpacket 34), no
// encryption-capable subkey, an expired encryption subkey, and a primary key
// that expires in the future.
//
// Provenance, 2026-10-27, GnuPG 2.5.24:
//   generated-clean.asc          cargo run -- ed25519 <dir>, public half only
//   gpg-aead.asc                 gpg --quick-gen-key 'AEAD Fixture <aead@example.invalid>' default default never
//   gpg-no-encryption-subkey.asc gpg --quick-gen-key 'No Encryption Subkey Fixture <noenc@example.invalid>' ed25519 sign never
//                                then setpref without AEAD, so the fixture isolates one condition
//   gpg-expired-subkey.asc       gpg --faked-system-time 20200101T000000 --quick-gen-key ... ed25519 cert never
//                                gpg --faked-system-time 20200101T000000 --quick-add-key <fpr> cv25519 encr 1d
//                                gpg exported it; the prototype README's note that gpg refuses an expired
//                                subkey did not reproduce with this gpg.
//   gpg-future-expiry.asc        gpg --faked-system-time 20200101T000000 --quick-gen-key 'Future Expiry Fixture
//                                <future@example.invalid>' ed25519 cert 20y, then --quick-add-key <fpr> cv25519
//                                encr never, both with a --default-preference-list without AEAD so the expiry is
//                                the only finding. The primary expires 2040-01-01, after every clock these tests pass.
//   gpg-future-expiry-subkey.asc the same, with cert never and --quick-add-key <fpr> cv25519 encr 20y, so the
//                                primary never expires and only the encryption subkey does (2040-01-01).
// The long-paste fixture is gpg rsa4096 with an encryption subkey, 3216 bytes.

use keygen::check_public_key;

const NOW: u64 = 1_800_000_000;

const CLEAN: &str = include_str!("../fixtures/generated-clean.asc");
const AEAD: &str = include_str!("../fixtures/gpg-aead.asc");
const NO_ENCRYPTION: &str = include_str!("../fixtures/gpg-no-encryption-subkey.asc");
const EXPIRED_SUBKEY: &str = include_str!("../fixtures/gpg-expired-subkey.asc");
const FUTURE_EXPIRY: &str = include_str!("../fixtures/gpg-future-expiry.asc");
const FUTURE_EXPIRY_SUBKEY: &str = include_str!("../fixtures/gpg-future-expiry-subkey.asc");

#[test]
fn the_generators_own_key_is_clean() {
    let findings = check_public_key(CLEAN, NOW).expect("the clean fixture parses");
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn each_gpg_fixture_carries_its_own_verdict() {
    let aead = check_public_key(AEAD, NOW).expect("the AEAD fixture parses");
    assert_eq!(aead.len(), 1, "{aead:?}");
    assert!(aead[0].contains("AEAD"), "{aead:?}");
    assert!(aead[0].contains("Remove AEAD"), "{aead:?}");

    let no_encryption =
        check_public_key(NO_ENCRYPTION, NOW).expect("the no-encryption fixture parses");
    assert_eq!(no_encryption.len(), 1, "{no_encryption:?}");
    assert!(
        no_encryption[0].contains("no encryption-capable subkey"),
        "{no_encryption:?}"
    );
    assert!(
        no_encryption[0].contains("Make a new key"),
        "{no_encryption:?}"
    );

    let expired = check_public_key(EXPIRED_SUBKEY, NOW).expect("the expired fixture parses");
    assert_eq!(expired.len(), 1, "{expired:?}");
    assert!(
        expired[0].contains("encryption subkey expired"),
        "{expired:?}"
    );
    assert!(
        expired[0].contains("Extend the subkey's expiry"),
        "{expired:?}"
    );
}

/// A future expiry is a finding too: `scripts/lib.sh::key_problems` refuses any
/// expiring key at approval, and delivery stops at the date. The same key past
/// its date keeps the distinct already-expired wording.
#[test]
fn an_expiry_in_the_future_is_a_finding_and_a_past_one_says_expired() {
    let future = check_public_key(FUTURE_EXPIRY, NOW).expect("the future-expiry fixture parses");
    assert_eq!(future.len(), 1, "{future:?}");
    assert!(future[0].contains("expires at"), "{future:?}");
    assert!(future[0].contains("Key does not expire"), "{future:?}");
    assert!(!future[0].contains("expired at"), "{future:?}");

    let past = check_public_key(FUTURE_EXPIRY, 2_300_000_000).expect("it still parses");
    assert_eq!(past.len(), 1, "{past:?}");
    assert!(past[0].contains("expired at"), "{past:?}");
    assert!(!past[0].contains("Key does not expire"), "{past:?}");
}

/// The subkey branch is its own reading: a primary that never expires with an
/// encryption subkey that does must be a finding, and the message must name the
/// subkey rather than the key.
#[test]
fn a_future_expiry_on_the_encryption_subkey_alone_is_a_finding() {
    let future =
        check_public_key(FUTURE_EXPIRY_SUBKEY, NOW).expect("the subkey-expiry fixture parses");
    assert_eq!(future.len(), 1, "{future:?}");
    assert!(
        future[0].contains("encryption subkey expires at"),
        "{future:?}"
    );
    assert!(future[0].contains("Key does not expire"), "{future:?}");

    let past = check_public_key(FUTURE_EXPIRY_SUBKEY, 2_300_000_000).expect("it still parses");
    assert_eq!(past.len(), 1, "{past:?}");
    assert!(past[0].contains("encryption subkey expired at"), "{past:?}");
}

// GnuPG: ed25519 cert primary, --quick-add-key <fpr> rsa2048 sign never.
#[test]
fn a_signing_only_rsa_subkey_cannot_receive_mail() {
    let findings = check_public_key(include_str!("../fixtures/gpg-rsa-signing-subkey.asc"), NOW)
        .expect("ordinary signed RSA subkey");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].contains("no encryption-capable subkey"));
}

#[cfg(feature = "generate")]
#[test]
fn the_newest_signed_declaration_wins_in_either_packet_order() {
    use pgp::composed::{Deserializable, SignedSecretKey};
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::packet::{
        Features, KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData,
    };
    use pgp::types::{Duration, KeyDetails, Password, Tag, Timestamp};

    let generated = keygen::generate_key("ed25519", keygen::DEFAULT_USER_ID, None).unwrap();
    let (secret, _) =
        SignedSecretKey::from_armor_single(generated.secret_armor.as_bytes()).unwrap();
    let signer = &secret.primary_key;
    let mut cert = secret.to_public_key();
    let start = Timestamp::now().as_secs() + 1;
    let now = u64::from(start + 3);
    let password = Password::empty();
    for (offset, lifetime, feature) in [(0, 86_400, 0x02), (1, 0, 0x08), (2, 0, 0x01)] {
        let config = |typ| {
            let mut config = SignatureConfig::v4(typ, signer.algorithm(), HashAlgorithm::Sha256);
            for data in [
                SubpacketData::SignatureCreationTime(Timestamp::from_secs(start + offset)),
                SubpacketData::KeyExpirationTime(Duration::from_secs(lifetime)),
            ] {
                config
                    .hashed_subpackets
                    .push(Subpacket::regular(data).unwrap());
            }
            config
        };
        let mut uid = config(SignatureType::CertPositive);
        uid.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::Features(Features::from(&[feature][..]))).unwrap(),
        );
        let user = &mut cert.details.users[0];
        user.signatures.push(
            uid.sign_certification(signer, &cert.primary_key, &password, Tag::UserId, &user.id)
                .unwrap(),
        );

        let mut binding = config(SignatureType::SubkeyBinding);
        // Absent flags retain the legacy algorithm fallback. Explicit zero flags don't.
        if offset == 2 {
            binding
                .hashed_subpackets
                .push(Subpacket::regular(SubpacketData::KeyFlags(KeyFlags::default())).unwrap());
        }
        let sub = &mut cert.public_subkeys[0];
        sub.signatures.push(
            binding
                .sign_subkey_binding(signer, &cert.primary_key, &password, &sub.key)
                .unwrap(),
        );

        for _ in 0..2 {
            let armor = cert.to_armored_string(Default::default()).unwrap();
            let findings = check_public_key(&armor, now).unwrap();
            match offset {
                0 => {
                    assert_eq!(findings.len(), 3, "{findings:?}");
                    assert!(findings.iter().any(|f| f.contains("OCB feature bit")));
                    assert!(findings.iter().any(|f| f.contains("The key expires at")));
                    assert!(findings.iter().any(|f| f.contains("subkey expires at")));
                }
                1 => {
                    assert_eq!(findings.len(), 1, "{findings:?}");
                    assert!(findings[0].contains("SEIPD v2 feature bit"));
                }
                2 => {
                    assert_eq!(findings.len(), 1, "{findings:?}");
                    assert!(findings[0].contains("no encryption-capable subkey"));
                }
                _ => unreachable!(),
            }
            cert.details.users[0].signatures.reverse();
            cert.public_subkeys[0].signatures.reverse();
        }
    }
}

#[cfg(feature = "generate")]
#[test]
fn same_second_aead_and_direct_zero_expiry_and_rotated_subkey_match_gpg() {
    use pgp::composed::{Deserializable, SignedSecretKey};
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::packet::{Features, SignatureConfig, SignatureType, Subpacket, SubpacketData};
    use pgp::types::{Duration, KeyDetails, Password, Tag, Timestamp};

    let generated = keygen::generate_key("ed25519", keygen::DEFAULT_USER_ID, None).unwrap();
    let (secret, _) =
        SignedSecretKey::from_armor_single(generated.secret_armor.as_bytes()).unwrap();
    let signer = &secret.primary_key;
    let password = Password::empty();
    let start = Timestamp::now().as_secs() + 1;
    let now = u64::from(start + 10);

    // 1. Same-second UID signatures (one AEAD, one clean) must flag AEAD in either order.
    let mut cert = secret.to_public_key();
    for feature in [0x02u8, 0x01u8] {
        let mut cfg = SignatureConfig::v4(
            SignatureType::CertPositive,
            signer.algorithm(),
            HashAlgorithm::Sha256,
        );
        cfg.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                start,
            )))
            .unwrap(),
        );
        cfg.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::Features(Features::from(&[feature][..]))).unwrap(),
        );
        let user = &mut cert.details.users[0];
        user.signatures.push(
            cfg.sign_certification(signer, &cert.primary_key, &password, Tag::UserId, &user.id)
                .unwrap(),
        );
    }
    for _ in 0..2 {
        let armor = cert.to_armored_string(Default::default()).unwrap();
        let findings = check_public_key(&armor, now).unwrap();
        assert!(
            findings.iter().any(|f| f.contains("OCB feature bit")),
            "{findings:?}"
        );
        cert.details.users[0].signatures.reverse();
    }

    // 2. A direct-key signature with explicit lifetime 0 ("never") overrides a UID expiry.
    let mut cert = secret.to_public_key();
    let mut uid_cfg = SignatureConfig::v4(
        SignatureType::CertPositive,
        signer.algorithm(),
        HashAlgorithm::Sha256,
    );
    uid_cfg.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            start,
        )))
        .unwrap(),
    );
    uid_cfg.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(
            86_400,
        )))
        .unwrap(),
    );
    let user = &mut cert.details.users[0];
    user.signatures.push(
        uid_cfg
            .sign_certification(signer, &cert.primary_key, &password, Tag::UserId, &user.id)
            .unwrap(),
    );
    let mut direct_cfg = SignatureConfig::v4(
        SignatureType::Key,
        signer.algorithm(),
        HashAlgorithm::Sha256,
    );
    direct_cfg.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            start + 1,
        )))
        .unwrap(),
    );
    direct_cfg.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(0))).unwrap(),
    );
    cert.details.direct_signatures.push(
        direct_cfg
            .sign_key(signer, &password, &cert.primary_key)
            .unwrap(),
    );
    let armor = cert.to_armored_string(Default::default()).unwrap();
    let findings = check_public_key(&armor, now).unwrap();
    assert!(findings.is_empty(), "{findings:?}");

    // 3. A revoked old encryption subkey beside a valid replacement is clean; alone it fails.
    let mut cert = secret.to_public_key();
    let replacement = cert.public_subkeys[0].clone();
    let mut rev_cfg = SignatureConfig::v4(
        SignatureType::SubkeyRevocation,
        signer.algorithm(),
        HashAlgorithm::Sha256,
    );
    rev_cfg.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            start,
        )))
        .unwrap(),
    );
    let rev_sig = rev_cfg
        .sign_subkey_binding(
            signer,
            &cert.primary_key,
            &password,
            &cert.public_subkeys[0].key,
        )
        .unwrap();
    cert.public_subkeys[0].signatures.push(rev_sig);
    let revoked_only = cert.to_armored_string(Default::default()).unwrap();
    let findings = check_public_key(&revoked_only, now).unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].contains("has been revoked"), "{findings:?}");

    cert.public_subkeys.push(replacement);
    let rotated = cert.to_armored_string(Default::default()).unwrap();
    let findings = check_public_key(&rotated, now).unwrap();
    assert!(findings.is_empty(), "{findings:?}");
}
