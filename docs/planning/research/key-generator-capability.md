# What the key generator can and cannot do, measured

For ticket #185. The crate is `pgp` 0.20.0, which is rpgp. The toolchain is rustc 1.97.1
and gpg 2.5.24 on arm64 macOS. The spike that produced this is committed beside this note
at `docs/planning/prototypes/keygen-spike/`, and every command below is one that was run.

## The five questions the ticket asked

1. Can a Rust crate generate a mail key with an encryption subkey and no `pref-aead-algos`
   subpacket, or does the crate make that impossible?
2. Does the platform's own gpg accept the result and produce a packet the member's client
   can read?
3. Does the passphrase-protected private key import into gpg and unlock?
4. Does Thunderbird import the key, decrypt mail addressed to it, and send mail the box
   encrypts?
5. Does a WASM module built from the crate load from a page with no external requests?

Questions 1 to 3 are answered below with output. Question 4 is not answered, because no
Thunderbird was available here, and question 5 is answered for the compile half only,
because no bindings were written.

## Generation works, and the AEAD requirement needs no patch

`gpg --list-packets public.asc` on a generated key prints, among other lines:

```
:public key packet:
	version 4, algo 22, created 1790859181, expires 0
:public sub key packet:
	version 4, algo 18, created 1790859181, expires 0
	hashed subpkt 30 len 1 (features: 01)
	hashed subpkt 11 len 3 (pref-sym-algos: 9 8 7)
	hashed subpkt 21 len 3 (pref-hash-algos: 10 9 8)
	hashed subpkt 22 len 3 (pref-zip-algos: 2 1 0)
```

Algo 22 is EdDSA with Ed25519, algo 18 is ECDH, and the three preference lists are the
ones the generator set: AES256, AES192 and AES128; SHA512, SHA384 and SHA256; ZLIB, ZIP
and uncompressed. There is **no `pref-aead-algos` line**, which is the whole requirement,
and `features: 01` sets the modification-detection bit without setting the AEAD bit.

This was not certain in advance. The crate's key builder pushes a
`PreferredAeadAlgorithms` subpacket unconditionally in `src/composed/key/shared.rs`, and
the AEAD list defaults to empty rather than absent. An empty list turns out to be
serialised as nothing at all, so the output carries no AEAD advertisement and
`scripts/deploy-mail.sh` will not warn about a key this generator produced.

## The encryption subkey has to be the version 4 form

`KeyType::X25519`, which the crate's own documentation recommends as the modern choice,
writes algorithm 25 in a version 4 certificate. gpg 2.5.24 refuses such a key outright:

```
gpg: /tmp/keygen-ed25519/public.asc: skipped: Unusable public key
gpg: [stdin]: encryption failed: Unusable public key
```

Algorithm 25 is the RFC 9580 identifier, and gpg expects it in a version 6 certificate.
The form gpg accepts is `KeyType::ECDH(ECCCurve::Curve25519Legacy)`, which writes algo 18
with the Curve25519 OID. That is the variant in the committed spike, and it is the one
that produces the output above. The same trap applies to `KeyType::Ed25519` if the
certificate stays at version 4, so the primary key uses `Ed25519Legacy`.

## The daemon's own invocation produces a packet the member can read

Encrypting with the exact argument list from `kyriakon-encrypt/src/lib.rs` (`--batch
--no-tty --no-options --encrypt --armor --no-encrypt-to --recipient-file <key>`), the
ciphertext is:

```
:pubkey enc packet: version 3, algo 18, keyid 713065A87F52A422
:encrypted data packet:
	version: 1
```

Version 1 of the encrypted data packet is SEIPD, the symmetric-encrypted
integrity-protected form, and not the AEAD packet that would appear as version 2. So a
member's client receives the packet shape it can read, with no change to the daemon.

## The protected private key imports and decrypts

Importing the generated `secret.asc` into a fresh GNUPGHOME and decrypting that
ciphertext with `--pinentry-mode loopback --passphrase` succeeds and prints the original
message. The secret key is stored as `iter+salt S2K, algo: 9, SHA1 protection, hash: 8`,
which is AES256 with a salt, and gpg unlocks it. rpgp also unlocks its own protected key
when it reads the file back, so the protection is not one-way in the crate either.

## RSA works, and an unprotected key does not

An RSA 4096 key generates, imports into gpg, signs with the protected primary key, and
decrypts mail addressed to its subkey, which was confirmed by generating and running the
commands twice. The first attempt reported `Bad secret key` and did not reproduce on the
second, and the cause of that first failure is unidentified. It is recorded here rather
than smoothed over, because a flaky result in a key path is the kind of thing worth
looking at again with more care than a throwaway spike gives it.

The variant generated without a passphrase is refused at import:

```
gpg: import from 'secret.asc' failed: Bad secret key
```

So a private key this crate generates must be passphrase-protected before it is handed to
anyone, which is what the design requires anyway: the page hands over a protected file
and an eight-word phrase to keep separately. Whether the same is true of an unprotected
Ed25519 key was not tested.

Both key types are therefore usable, and the choice is about size and client support
rather than capability. Ed25519 with Curve25519 produces a key of a few hundred bytes
rather than a few thousand, which is what a browser should be asked to generate, and it
is the variant the spike tests hardest.

## The browser half compiles

With the crate's `wasm` feature enabled, which pulls in `getrandom/js`, this builds:

```
cargo build --target wasm32-unknown-unknown --release
Finished `release` profile [optimized] target(s) in 42.22s
```

So the dependency graph, including the OpenPGP implementation, compiles for
`wasm32-unknown-unknown`. What is not proved is the page: the spike is a binary with no
`wasm-bindgen` exports, and no browser was involved. The next step for this half is a
library with a generation entry point and a check entry point, loaded by a page whose
Content-Security-Policy forbids external requests, which is the acceptance the ticket
already specifies.

## The check half works, and the crate's API has two traps in it

The same crate reads a submitted key well enough to produce the three verdicts, and the
spike now has a `check` mode that does it. Four keys were run through it:

```
OK   /tmp/kg-ed25519/public.asc     a key this generator produced
FAIL /tmp/kg-aead.asc               a key from gpg 2.5 that advertises AEAD
FAIL /tmp/kg-signonly.asc           a key with no encryption subkey
FAIL /tmp/kg-expired.asc            a key whose subkey expired in 2020
```

Two of those results were wrong before they were right, which is the reason to test this
rather than read it.

**The AEAD preference is not the variant whose name matches it.** gpg writes the AEAD
ciphersuite preference as subpacket type 34, and rpgp 0.20 parses that into
`PreferredEncryptionModes`. The variant called `PreferredAeadAlgorithms` is a different
subpacket entirely. A check that matches the name which looks correct reports a clean key
for one that advertises AEAD, which is the dangerous direction: the member is told they
are fine and their first message will not open.

**Half the feature byte is unreadable.** rpgp exposes `Features::seipd_v1()` and
`Features::seipd_v2()`, and keeps the bit gpg actually sets, the one it inherited from
LibrePGP, behind a private field that only shows up in debug output. The subpacket check
covers the case that matters, so this is a note rather than a blocker, but a checker built
only on the crate's public feature accessors would miss it.

**And the warning will fire often.** Every key gpg generated during this testing
advertised AEAD without being asked to, because present-day GnuPG sets an AEAD mode in
its default preferences. So this is not a warning for unusual keys. It is what a member
gets if they follow the obvious path of making a key in gpg, which is an argument for the
generator and for the walkthrough naming the warning rather than the member meeting it
unexplained.

## What this settles for the design

The generator is buildable in the repository from `pgp` 0.20.0 with no patch to the
crate, using a version 4 certificate, an EdDSA primary key, an ECDH Curve25519
encryption subkey, the three explicit preference lists, and passphrase protection, all of
which the spike produces and gpg accepts end to end. The check half is written and passes
its test matrix, the same crate reading a submitted key and returning the three verdicts,
with the AEAD test written against the subpacket gpg actually writes rather than the
variant whose name matches.

## What is not verified

- Thunderbird on desktop and on Android, both of which the ticket names. No client was
  available here, so the claim that mobile works is still unproven and the walkthrough
  copy that promises it stays unearned until somebody runs it.
- The browser page itself. The module compiles; nothing loads it, and no bindings exist.
- The key inspection against a key larger than the four in the matrix. The verdicts come
  from reading signatures and subpackets, and only the cases above were run.
- Why the RSA secret key failed to unlock on the first attempt and then worked on the
  second, and whether an unprotected Ed25519 key imports where an unprotected RSA key
  does not. Both want retesting before anything ships.
- Whether `features: 01` matters where the deployed keys carry `features: 05`. The extra
  bit in those keys advertises support for version 5 public key packets, which this
  generator does not set, and gpg in both directions handled the difference without
  comment in this test.
