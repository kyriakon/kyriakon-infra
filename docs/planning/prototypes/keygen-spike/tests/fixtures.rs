// The five fixtures the ticket names, checked through the same function the CLI
// and the page's WASM export call. The generator's key is clean, and each gpg
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

use keygen_spike::check_public_key;

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
