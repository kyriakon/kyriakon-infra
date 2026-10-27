// The four fixtures the ticket names, checked through the same function the CLI
// and the page's WASM export call. The generator's key is clean, and each gpg
// key isolates one of the three conditions: the AEAD advert (subpacket 34 and
// features 07), no encryption-capable subkey, and an expired encryption subkey.
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
// The long-paste fixture is gpg rsa4096 with an encryption subkey, 3216 bytes.

use keygen_spike::check_public_key;

const NOW: u64 = 1_800_000_000;

const CLEAN: &str = include_str!("../fixtures/generated-clean.asc");
const AEAD: &str = include_str!("../fixtures/gpg-aead.asc");
const NO_ENCRYPTION: &str = include_str!("../fixtures/gpg-no-encryption-subkey.asc");
const EXPIRED_SUBKEY: &str = include_str!("../fixtures/gpg-expired-subkey.asc");

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
