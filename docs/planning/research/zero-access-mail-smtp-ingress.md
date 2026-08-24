# Zero-access mail: PGP encryption on SMTP ingress (Phase 1, §2/§5.1)

**Question:** how to encrypt a message to the recipient's PGP public key *on SMTP
delivery* in OpenSMTPD on OpenBSD 7.x, so the Maildir stores only ciphertext the platform
holds no key to decrypt — whole-message PGP/MIME (subject **and** body protected), no
plaintext at rest, per-recipient key from a keyring, plus-addressing (`user+tag@`).

**Answer (cross-ticket, resolved with R2):** there is **no OpenSMTPD-side PGP-on-ingress
component to build.** The single encryption point belongs in a **custom Dovecot
lib-storage plugin on the save path** (`mailbox_save_begin`/`save_finish` — the same hooks
`mail_crypt` uses), which covers **both LMTP delivery (SMTP ingress) and IMAP APPEND** with
one piece of code. OpenSMTPD stays plaintext across the local LMTP hop; the only genuinely
custom code is that one plugin. Nothing in OpenBSD ports or upstream does PGP-on-ingress for
smtpd anyway (`gpgit` is body-only and leaves the subject in cleartext), so the "what exists
vs. custom" answer is unchanged: **the encryption logic is custom either way, and the
Dovecot save path is where it belongs.**

If — and only if — plaintext in the smtpd queue spool is deemed unacceptable, an
OpenSMTPD `data-line` filter can encrypt *before* queueing, but it becomes a **second**
encryption point that must stay byte-format- and keyring-identical with the Dovecot plugin
and must skip already-encrypted messages. That is the fallback, not the recommendation.

---

## 1. The single-encryption-point decision

R2 (IMAP APPEND) established that Dovecot has **no built-in encrypt-on-APPEND**: the only
route is a custom C plugin on the lib-storage save path. Dovecot plugins register hooks via
`mail_storage_hooks_add()` and override mailbox vfuncs (`box->v.transaction_begin = …`,
and the save-equivalent `save_begin`/`save_finish`) — exactly the seam `mail_crypt`
plugs into (Dovecot "Mail Plugins" developer doc). Crucially, **every write path** — LMTP
delivery, IMAP APPEND, `dovecot-lda` — funnels through `mailbox_save_*`, so one plugin
encrypts all of them. That makes the Dovecot save path the *natural single point*:

```
SMTP (smtpd) ──LMTP over UNIX socket──▶ Dovecot ──save path (plugin encrypts)──▶ Maildir (ciphertext)
                                          ▲
                              IMAP APPEND ┘  (same save path, same plugin)
```

Because IMAP APPEND already forces a custom Dovecot plugin, encrypting SMTP ingress in
OpenSMTPD too would create **two independent encryptors** to keep in lockstep for no
architectural gain — the exact over-engineering the project's §2 "audit us" posture
punishes. The clean answer is **one encryption point at the Dovecot save path**, and SMTP
plaintext across the local hop.

OpenSMTPD's local delivery to Dovecot is `action … lmtp` (deliver "to an LMTP server at
*destination* … host:port or a UNIX socket", `smtpd.conf(5)`). The hop is a local UNIX
socket/loopback — plaintext never leaves the box in clear over a network link.

## 2. The OpenSMTPD side: what the seam is, and why nothing exists

Even though the recommendation is *not* to use it, the question asks what OpenSMTPD offers.
The extension surface is the **filter API** (`smtpd-filters(7)`): a standalone `proc`
process over stdin/stdout, registered with `filter … proc-exec`. Two requests matter here:

- **`data-line`** — the filter is fed raw dot-escaped SMTP DATA one line at a time,
  terminated by `.`, and replies with a transformed stream; "smtpd(8) assumes that the
  message consists of the output from smtpd-filters." This is the only point where the
  message content can be rewritten *inside* the transaction, before it is committed to the
  spool.
- **`rcpt-to`** (request) / **`tx-rcpt`** (report) — both carry the sanitized recipient
  address, which is how a filter would learn whose key to use.

Wladimir Palant's `opensmtpd.py` writeup demonstrates the pattern (`tx-rcpt` report →
session state → rewrite lines). Filters must "not use blocking I/O" (`smtpd-filters(7)`,
DESIGN), so a whole-message encryptor buffers the message in memory until the terminating
`.`, then encrypts and emits.

**Milter: not an option.** OpenSMTPD does not implement the Sendmail/Postfix milter
protocol; `smtpd(8)`'s only extension path is the filter API. The `milter-*` ports
(`milter-checkrcpt`, `milter-greylist`, `milter-regex`, `milter-spamd`) target
Sendmail/Postfix and cannot attach to smtpd.

**`action … mda` / external proxy: weaker.** `mda` runs a command at delivery time with the
message on stdin (env `LOCAL`, `EXTENSION`, `ORIGINAL_RECIPIENT`), but the message has
already sat in the plaintext spool — same "plaintext on disk" problem as LMTP, only
with a hand-rolled delivery path. A proxy re-implements `data-line` with a second SMTP hop;
no benefit.

### What exists vs. custom (OpenBSD ports, `openbsd/ports` mirror)

- **Exists, useful as building blocks only:** `security/gnupg` (the OpenPGP engine);
  `mail/p5-Mail-GnuPG` (PGP/MIME assembly helpers, body-part oriented);
  `mail/p5-OpenSMTPd-Filter` (Perl filter-protocol plumbing);
  `mail/opensmtpd-filters/libopensmtpd` (C filter library); and the
  `mail/opensmtpd-filters` meta-port whose only packages are `admdscrub`, `dkimsign`,
  `dnsbl`, `mimedefang`, `rspamd`, `senderscore`, `spamassassin`, `spfgreylist` — **none
  encrypt.** `mimedefang` (`filter-mimedefang.pl`) is a general rewrite framework but still
  needs a custom filter to do PGP.
- **Does not exist anywhere:** an OpenPGP-encrypt-on-ingress filter for smtpd. The
  closest off-the-shelf tool is **`gpgit`**, which is not in ports (installed from source by
  the usual writeups) and is **body-only**: its README states "PGP does not encrypt email
  headers … the subject line," and its `--encrypt-mode` values
  (`prefer-inline|pgpmime|inline-or-plain`) all leave headers clear. It fails the
  subject+body requirement on its own. `gpg-mailgate` is Postfix-only. `mail_crypt` is
  rejected (§2).

**Conclusion:** the encryption logic is custom either way; only the *location* of that one
custom piece is a decision. It goes in the Dovecot save path (§1), not in OpenSMTPD.

## 3. Two candidate architectures

| | **A. smtpd `data-line` filter (encrypt before spool)** | **B. Dovecot save-path plugin (encrypt at save)** — *recommended* |
|---|---|---|
| Covers IMAP APPEND? | No (APPEND bypasses smtpd entirely) | Yes (same save path) |
| Covers SMTP delivery? | Yes | Yes (via LMTP) |
| Custom code count | **2 encryptors** (filter + Dovecot plugin) | **1 plugin** |
| Plaintext in smtpd spool? | No | Yes, transiently (seconds), local-disk only |
| Double-encryption risk | Real — must skip already-encrypted | None — single writer |
| Format/keyring drift risk | Real — two codebases must stay identical | None — one codebase |
| Plaintext leaves box over network? | No | No (LMTP is UNIX socket/loopback) |

**Recommendation: B.** The only advantage of A is keeping `/var/spool/smtpd/` free of
plaintext, but that spool is a transient queue (seconds-to-minutes), not the durable store
§2 promises to protect ("Maildirs store only ciphertext"). A's cost — a second encryptor
that must be kept byte-identical with the Dovecot plugin and that must not double-encrypt —
is a standing correctness hazard, exactly what "audit us" cannot afford. B's plaintext
window is closed with the `queue encryption` option below.

## 4. If A is ever chosen (the compatibility contract)

For the record, should plaintext-in-spool become a hard requirement (e.g. a hostile-local-
disk threat model), the smtpd filter **must**:

1. **Share the exact whole-message RFC 3156 format** with the Dovecot plugin — the same
   outer envelope headers, the same `multipart/encrypted; protocol="application/pgp-encrypted"`
   structure, the same placeholder `Subject:`. A filter that produced a *different* on-disk
   shape than APPEND would strand mail for the client.
2. **Share the same git-tracked keyring** and key-resolution logic (§5.6 publishes public
   keys; both encryptors must resolve localpart → the identical key, including the `+tag`
   strip).
3. **Skip already-encrypted messages** (detect the PGP/MIME marker) to avoid
   double-encryption, since the Dovecot plugin would otherwise re-encrypt on save.
4. **Not encrypt non-local/alias recipients** (pass through + loud log) — only keyed local
   users are zero-access; a forwarded-to-remote recipient must never receive undecryptable
   ciphertext.

Plus-addressing needs no special smtpd work either way: smtpd already ignores the
sub-address when resolving the local part (`smtp sub-addr-delim`, default `+`,
`smtpd.conf(5)`); the encryptor (whichever) resolves the base local user for key lookup.

## 5. "No plaintext on disk," reconciled with §2

§2's promise is that **the durable store — Maildir — holds only ciphertext the platform
cannot decrypt.** It explicitly does *not* promise that a message never transits a transient
in-memory or queue state in the clear ("does not stop a compelled admin from intercepting
*future* mail as it relays in plaintext", §5.6). Under architecture B:

- **Maildir:** ciphertext (Dovecot save path encrypts before write).
- **smtpd spool `/var/spool/smtpd/`:** plaintext *transiently* (between queue commit and
  LMTP dispatch). Mitigate with `queue encryption [key]` — spool files encrypted with
  AES-256-GCM (`smtpd.conf(5)`). Note: its key is a startup passphrase (`getpass(3)`),
  **platform-held**, so this is defense-in-depth against a walked-away disk, *not*
  zero-access. Record this in `threat-model.md` as the one residual plaintext window.
- **Never over a network hop in clear:** LMTP is a local UNIX socket/loopback.

## 6. Primary sources

- Dovecot, "Mail Plugins" (developer doc) — `mail_storage_hooks_add()`, vfunc override
  (`transaction_begin`, save path); the seam `mail_crypt` uses; applies to all mailbox
  write paths (LMTP, APPEND, lda). https://doc.dovecot.org/main/developers/design/mail_plugins.html
- `smtpd-filters(7)` — filter API: `data-line` (add/suppress/modify/echo), `rcpt-to`,
  `tx-rcpt`, `commit`, "message consists of the output from smtpd-filters", no blocking I/O.
  https://man.openbsd.org/smtpd-filters.7
- `smtpd.conf(5)` — `filter … proc-exec`, `proc` (`user`/`group`/`chroot`),
  `action … lmtp`, `action … mda` + MDA COMMANDS env vars, `queue encryption`,
  `smtp sub-addr-delim` (default `+`). https://man.openbsd.org/smtpd.conf.5
- `smtpd(8)` — extension surface is the filter API; no milter. https://man.openbsd.org/smtpd.8
- OpenBSD ports tree (official GitHub mirror) — `mail/opensmtpd-filters/Makefile` (full
  filter list), `mail/opensmtpd-filters/{libopensmtpd,mimedefang}/pkg/DESCR`,
  `mail/p5-Mail-GnuPG/pkg/DESCR`, `mail/p5-OpenSMTPd-Filter/pkg/DESCR`,
  `security/gnupg/pkg/DESCR`, `mail/Makefile` (milter-* entries).
  https://github.com/openbsd/ports
- gpgit (Etienne Perot) README + source — "PGP does not encrypt email headers … subject
  line", `--encrypt-mode` = `prefer-inline|pgpmime|inline-or-plain` (body-only).
  https://github.com/EtiennePerot/gpgit
- Wladimir Palant, "Converting incoming emails on the fly with OpenSMTPD filters" (2023) —
  `tx-rcpt` + session context + `data-line` rewrite pattern. https://palant.info/2023/03/08/converting-incoming-emails-on-the-fly-with-opensmtpd-filters/
- Solène Rapenne, "Emails encryption at rest on OpenBSD using dovecot and GPG" (2024) —
  sieve `filter` + gpgit; headers remain clear. https://dataswamp.org/~solene/2024-08-14-automatic-emails-gpg-encryption-at-rest.html
- RFC 3156 ("MIME Security with OpenPGP") §4/§6 — `multipart/encrypted`,
  `application/pgp-encrypted`, whole-message vs. part encryption.
  https://www.rfc-editor.org/rfc/rfc3156.html
