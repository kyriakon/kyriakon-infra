# Zero-access mail pipeline — prototype design (THROWAWAY)

Prototype for wayfinder ticket #9. Resolves the single encryption point for zero-access mail:
a Dovecot lib-storage save-path plugin; SMTP stays plaintext on the local LMTP hop (research
#2, #3). This is a throwaway artifact for reaction, not production — the validated decision is
what survives to `main`.

## Language split (why the plugin is C, and why that's not a problem)

Dovecot's plugin API is a **C ABI**: a plugin is a shared object loaded via `mail_plugins`,
linking `libdovecot-storage`, registering hooks through `mail_storage_hooks_add()`. There is no
Rust plugin interface and no maintained Rust binding to Dovecot's internal plugin API — so the
plugin's entry points **must be C**.

The amount of C is a choice. Split:

- **C shim (~100 lines)**: register the hook, override `save_begin`/`save_finish`, pipe the
  incoming message to the Rust encryptor, write the ciphertext back. No crypto, no keyring, no
  parsing.
- **Rust encryptor (`kyriakon-encrypt`)**: all the logic we author — keyring resolution,
  localpart parsing with `+tag` strip, RFC 3156 PGP/MIME wrapping, driving the OpenPGP engine.
- **GnuPG**: the actual OpenPGP crypto. Battle-tested, ships in OpenBSD ports, and is *not our
  code* — "prefer Rust" governs code we write, not replacing the crypto engine with a younger
  Rust crate (a security downgrade). `sequoia-openpgp` is the pure-Rust alternative to evaluate,
  not the default.

Standing preference (also to be recorded in AGENTS.md): **always prefer Rust over C in this
project.**

## Pipeline

```
SMTP (smtpd) ──LMTP unix socket──▶ Dovecot ──save path──▶ [C shim → kyriakon-encrypt → gpg] ──▶ Maildir (ciphertext)
                                   ▲
                       IMAP APPEND ┘  (same save path, same shim + encryptor)
```

One encryptor, two ingress points. Fail-closed: if no key resolves, the save fails — plaintext is
never written.

## C shim shape (schematic)

```
mail_storage_hooks_add() → mailbox_allocated hook overrides save_begin/save_finish
save_finish: resolve owner user; pipe buffered message → kyriakon-encrypt --user <localpart>;
             replace message body with ciphertext
```

~100 lines, mirroring `mail_crypt`'s hook structure (the reference implementation), zero crypto.

## Rust encryptor (`kyriakon-encrypt`)

- `--user <localpart>`: resolve the base localpart (strip `+tag`), look up the public key.
- Read the raw RFC 5322 message on stdin.
- Wrap as RFC 3156 `multipart/encrypted; protocol="application/pgp-encrypted"` (whole message —
  headers **and** body — encrypted).
- Encrypt to the public key via gpg (`--encrypt --armor --recipient <keyid> --no-encrypt-to`).
- Write ciphertext to stdout. Never touches a private key.

## Keyring

- On-box location: `/etc/kyriakon/keys/<base-localpart>.asc` — public certs only.
- Source of truth: the git-tracked published set in `kyriakon-infra` (proposal §5.6), so key
  substitution is auditable. The on-box keyring is a sync of that set.
- Resolution: strip `+tag` (smtpd already ignores it for local-part; the encryptor does the
  same), map base-localpart → cert.

## Key distribution & recovery-phrase UX

- At signup the user generates a PGP keypair client-side; only the **public** key is submitted,
  never the private key (§5.1).
- The private key stays client-held; the **recovery phrase** (passphrase-protected offline
  export) is the only path back from a lost device. The platform never holds it. Key loss without
  the phrase = permanent mail loss.
- The public key is published to the git-tracked set (auditable) and synced to the box keyring.

## Invariants

1. **No private key on the server — ever.** The encryptor only ever holds public keys and encrypts.
2. **No plaintext at rest**: Maildir holds only ciphertext; the transient smtpd spool window is
   closed by `queue encryption` (platform-held key — defense-in-depth, not zero-access; record the
   residual window in `threat-model.md`).
3. **One encryption point**: SMTP ingress and IMAP APPEND share the same shim + encryptor → byte-
   identical format, no double-encryption.
4. **Fail-closed**: missing key → save fails (never write plaintext); non-local/alias recipient →
   pass through + loud log.

## Open questions to react to

1. **Crypto engine**: gpg (default) vs `sequoia-openpgp` (pure Rust) — I recommend gpg.
2. **Process model**: subprocess per save (default, fine at beta volume) vs a long-lived daemon
   over a unix socket (later optimization — `ponytail:` flag).
3. **Keyring sync**: git checkout of the published set vs a push step from the onboarding service.
