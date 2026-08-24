# Zero-access mail — encrypting IMAP APPEND to the user's public key

Ticket: what mechanism encrypts a message on **IMAP APPEND** (client uploads, and
draft/Sent storage) to that user's own PGP public key, given `mail_crypt` is rejected.

Proposal context: §2/§5.1 require every message to be encrypted to the recipient
user's *public* key "on ingress (delivery and IMAP APPEND)", stored as
whole-message PGP/MIME ciphertext; the server holds only public keys and never a
private key or anything that can derive one.

## Short answer

**Dovecot has no built-in mechanism to encrypt on IMAP APPEND to a user's PGP
public key.** `mail_crypt` is the only encryption plugin Dovecot ships, and it is
rejected for this platform (its key model puts the decryption key in the server's
hands). A Sieve/managesieve hook cannot do it either — Sieve runs at *delivery*
time, and the IMAP variant (IMAPSieve) runs *after* the message is already stored
and cannot rewrite message content. The only workable route is **a small custom C
Dovecot plugin** that hooks Dovecot's lib-storage *save path* — the same hook
`mail_crypt` itself uses — and PGP-encrypts the whole message before it is written.

## Why `mail_crypt` is not zero-access

`mail_crypt` encrypts "before written to storage and decrypted after reading. Both
operations are transparent to the user." — i.e. the server (Dovecot) both encrypts
**and decrypts** on demand, so it can read every stored message.
[mail_crypt plugin — Dovecot docs](https://doc.dovecot.org/2.3/configuration_manual/mail_crypt_plugin/)

Its key model is exactly the "password-wrapped per-user key" §2/§5.1 rejects. Two
modes, and in both the private key material lives on the server:

- **Folder keys**: "the users private key is stored … on the server" — either
  *unencrypted*, or *encrypted* with a password that "must be provided via password
  query" (the user's login password, supplied through `password_query`, e.g.
  `'%w' AS userdb_mail_crypt_private_password`). The server derives the key that
  decrypts the mail.
  [mail_crypt "Modes Of Operation"](https://doc.dovecot.org/2.3/configuration_manual/mail_crypt_plugin/#modes-of-operation)
- **Global keys**: `mail_crypt_global_private_key = <rsaprivkey.pem` — a literal
  private key in the Dovecot config.

Either way, a disclosure order yields the decryption key as well as the ciphertext,
which is the opposite of zero-access. The ciphertext format is also Dovecot-specific
(AES-GCM/IES, symmetric key stored alongside the file), **not** PGP/MIME, so it is
unreadable by a PGP-capable client and unusable for the SMTP-ingress path.
[mail_crypt "Encryption Technologies"](https://doc.dovecot.org/2.3/configuration_manual/mail_crypt_plugin/#encryption-technologies)

## The one correct hook point: the lib-storage *save* path

Dovecot routes **every** write to a mailbox — SMTP/LMTP delivery *and* IMAP APPEND —
through the same lib-storage `save_begin`/`save_finish` vfuncs on `struct
mailbox_vfuncs`. A plugin registers hooks with `mail_storage_hooks_add()` and, in
the `mailbox_allocated` hook, overrides those vfuncs. This is exactly what
`mail_crypt` does, and it is the reference implementation to copy:

```
static void mail_crypt_mailbox_allocated(struct mailbox *box) {
        struct mailbox_vfuncs *v = box->vlast;
        ...
        v->save_begin  = mail_crypt_mail_save_begin;
        v->save_finish = mail_crypt_mail_save_finish;
        ...
}
...
mail_storage_hooks_add_forced(&crypto_post_module, &mail_crypt_mail_storage_hooks_post);
```

Source: [`src/plugins/mail-crypt/mail-crypt-plugin.c`, Dovecot core](https://github.com/dovecot/core/blob/master/src/plugins/mail-crypt/mail-crypt-plugin.c)
(lines: `mailbox_allocated` overrides `save_begin`/`save_finish`; registered via
`mail_storage_hooks_add`). The hook list and the override pattern are documented in
[Mail Plugins — Dovecot developer manual](https://doc.dovecot.org/2.3/developer_manual/design/mail_plugins/).

Because delivery and APPEND share this save path, **one plugin covers both ingress
points** — a useful property for the consistency requirement below.

## Sieve / ManageSieve is not a path

- **Base Sieve is delivery-only.** "As defined in the base specification [RFC 5228],
  the Sieve language is used only during delivery." — quoted in the
  [Dovecot IMAPSieve docs](https://doc.dovecot.org/2.3/configuration_manual/sieve/plugins/imapsieve/).
  Delivery-time Sieve (LDA/LMTP) never runs for an IMAP APPEND.
- **`vnd.dovecot.filter` (the known encrypt-at-rest trick) is delivery-only too.**
  The `sieve_extprograms` plugin's `filter` action pipes the *message under
  delivery* through an external program (e.g. GnuPG) and replaces it with the
  output. This is the mechanism behind the well-known "encrypt incoming mail to
  GPG keys at rest" setups (gpgit + a global `sieve_before` script with
  `filter "encrypt.sh"`).
  [Pigeonhole extprograms plugin](https://doc.dovecot.org/2.3/configuration_manual/sieve/plugins/extprograms/) ·
  [Solène — Emails encryption at rest on OpenBSD (dovecot + gpgit)](https://dataswamp.org/~solene/2024-08-14-automatic-emails-gpg-encryption-at-rest.html)
  It fires only during LMTP delivery, **not** on APPEND, and it leaves headers in
  the clear — so it neither covers the APPEND surface nor the whole-message
  (subject/body/headers) requirement.
- **IMAPSieve (RFC 6785) runs *after* storage and cannot rewrite content.** It
  triggers a Sieve script on APPEND/COPY/FLAG events, but the message is already in
  the mailbox, and "messages in IMAP mailboxes are immutable". Content-changing
  actions (`replace`/`enclose`) are "transient" and "not applicable for the `keep`
  action"; delivery-response actions are "inapplicable". There is no action that
  swaps the stored message body for ciphertext.
  [RFC 6785 §3.1, §3.9, §3.11, §3.12](https://www.rfc-editor.org/rfc/rfc6785)

## `mail-lua` is not a path

Dovecot's Lua plugin exposes only `mail_user_created`; it has no storage/save hook.
The Lua API is authentication (PASSDB/USERDB), HTTP client, logging, events, and
push notification — nothing that intercepts a message write.
[mail-lua plugin settings](https://doc.dovecot.org/2.3/settings/plugin/mail-lua-plugin/) ·
[`src/plugins/mail-lua/mail-lua-plugin.c`, Dovecot core](https://github.com/dovecot/core/blob/master/src/plugins/mail-lua/mail-lua-plugin.c)
(registers `mail_storage_hooks` with only `.mail_user_created`).

## Existing packages / plugins

| Candidate | Verdict |
|---|---|
| `mail_crypt` (Dovecot built-in) | Rejected — server-held/derived private key, transparent decrypt, non-PGP format (§2/§5.1). |
| `vnd.dovecot.filter` + gpgit (Sieve) | Delivery-only; doesn't touch APPEND; headers in clear. |
| `imap_sieve` + `sieve_imapsieve` (IMAPSieve) | Post-storage events; cannot rewrite the message. |
| `mail-lua` | No save hook. |
| Third-party public-key encrypt-on-save Dovecot plugin | **None found** — no maintained plugin does this. |

Everything must be **custom-written**: one C plugin, plus (shared with the SMTP path)
a small OpenPGP encryption helper and a keyring lookup.

## Consistency with SMTP ingress

§5.1 requires the *same* ciphertext format and *same* keyring at both ingress
points. Two things must therefore be a single source of truth shared by both paths:

1. **Ciphertext format** — whole-message PGP/MIME, i.e. RFC 3156
   `multipart/encrypted; protocol="application/pgp-encrypted"` with the message
   (headers **and** body) as the encrypted payload.
   [RFC 3156 §4](https://www.rfc-editor.org/rfc/rfc3156)
2. **Keyring** — the user's public key, from the git-tracked set published in
   `kyriakon-infra` (proposal §5.6), so key substitution stays auditable.

Because the save-path plugin is the single place where *both* LMTP delivery and
IMAP APPEND land, the cleanest shape is to make **the Dovecot plugin the one and
only encryption point** and let SMTP stay plaintext across the local LMTP hop.
This removes the cross-ticket hazard of two independently-written encryption paths
drifting apart. (If SMTP ingress instead encrypts earlier via an OpenSMTPD filter,
that filter and this plugin must call the *same* helper against the *same* keyring,
and the plugin must skip already-encrypted messages to avoid double-encryption —
coordinate with the SMTP-ingress ticket before choosing.)

## Recommended shape

A custom C Dovecot plugin (mirroring `mail_crypt`'s structure), loaded via
`mail_plugins`, that:

1. Registers `mail_storage_hooks_add()` and, in `mailbox_allocated`, overrides
   `save_begin`/`save_finish` (and `copy`) on `struct mailbox_vfuncs`.
2. In `save_begin`: determine the mailbox owner from the storage's `mail_user`,
   look up that user's public key in the shared keyring (no key → fail the save,
   never write plaintext).
3. Encrypt the **whole** RFC 5322 message (headers + body) to that public key as
   RFC 3156 PGP/MIME, using GnuPG (call `gpg` directly, or via the proven
   [`gpgit`](https://github.com/EtiennePerot/gpgit) helper / libgpgme).
4. Hand the ciphertext to the wrapped `save_begin` in place of the plaintext, so
   the Maildir receives only ciphertext.
5. Never load, decrypt, or touch a private key — the plugin only ever holds public
   keys and encrypts, which is what keeps the "server cannot read it" property true.

Ponytail note: this is not a new daemon or a new abstraction — it is a thin C
shim over the same hook `mail_crypt` already proves works, delegating all crypto to
GnuPG. The only genuinely new code is the save-hook glue + keyring lookup; the
encryption and the keying both reuse the SMTP-ingress path's helper.

## Sources

- [mail-crypt plugin — Dovecot 2.3 docs](https://doc.dovecot.org/2.3/configuration_manual/mail_crypt_plugin/)
- [Mail Plugins (hooks) — Dovecot developer manual](https://doc.dovecot.org/2.3/developer_manual/design/mail_plugins/)
- [`mail-crypt-plugin.c` — Dovecot core source](https://github.com/dovecot/core/blob/master/src/plugins/mail-crypt/mail-crypt-plugin.c)
- [Pigeonhole extprograms (`vnd.dovecot.filter`) — Dovecot docs](https://doc.dovecot.org/2.3/configuration_manual/sieve/plugins/extprograms/)
- [Pigeonhole IMAPSieve — Dovecot docs](https://doc.dovecot.org/2.3/configuration_manual/sieve/plugins/imapsieve/)
- [RFC 5228 — Sieve (delivery-only)](https://www.rfc-editor.org/rfc/rfc5228)
- [RFC 6785 — IMAP Events in Sieve](https://www.rfc-editor.org/rfc/rfc6785)
- [RFC 3156 — MIME Security with OpenPGP](https://www.rfc-editor.org/rfc/rfc3156)
- [mail-lua plugin — Dovecot 2.3 docs](https://doc.dovecot.org/2.3/settings/plugin/mail-lua-plugin/)
- [`mail-lua-plugin.c` — Dovecot core source](https://github.com/dovecot/core/blob/master/src/plugins/mail-lua/mail-lua-plugin.c)
- [Solène — Emails encryption at rest on OpenBSD (dovecot + gpgit)](https://dataswamp.org/~solene/2024-08-14-automatic-emails-gpg-encryption-at-rest.html)
- [`gpgit` — Etienne Perot](https://github.com/EtiennePerot/gpgit)
