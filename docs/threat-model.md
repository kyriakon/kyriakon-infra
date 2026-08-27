# Threat model

The "audit us" trust claim made concrete: what kyriakon.net protects against, what it
does not, and what the admin can and cannot see. Cross-references to the founding
proposal are `../kyriakon/docs/decisions/kyriakon-net-project-proposal.md`.

## What we protect against

- **Passive surveillance and data mining by the platform itself.** No ads, no
  analytics resale, break-even pricing (proposal §2). There is no business reason to
  look at user data.
- **Disk or backup walkaway.** Full-disk `softraid` encryption and an at-rest-encrypted
  off-box backup (proposal §5.5) mean a stolen or pulled disk — or a walked-away backup
  — yields ciphertext, not mail.
- **Compelled disclosure of stored *content*.** Mail is zero-access (below) and `pass`
  stores are GPG-encrypted client-side (proposal §5.3). Under a disclosure order the
  platform can hand over ciphertext and no decryption key.

## What we do *not* protect against

- **A determined state actor.** A state that can compel the admin to modify the box —
  or seize it outright — can intercept *future* mail as it relays in plaintext, or
  serve modified software. Zero-access is a *storage* property, not an *interception*
  property. This is the same ceiling every encrypted-mail provider has.
- **The transient SMTP spool.** Between smtpd accepting a message and Dovecot writing
  the ciphertext, the message sits in `/var/spool/smtpd/` in plaintext for
  seconds-to-minutes. `queue encryption` encrypts that spool (AES-256-GCM), but its
  key is a platform-held startup passphrase — so this closes the walked-away-disk
  window, not the compelled-admin window. It is the one residual plaintext-at-rest
  point in the mail path.
- **Correspondence metadata.** Envelope addresses, timestamps, and message sizes are
  visible to the server — mail cannot be routed without them — and appear in SMTP logs
  and the outer message wrapper. Logs are retained only as long as operationally
  necessary (~7 days) to minimise exposure.
- **A user's own compromised key or device.** A seized private key or device makes that
  user's mail readable. The only backstop is the user-held recovery phrase.

## What the admin can and cannot see

| | Admin can see | Admin cannot see |
|---|---|---|
| **Mail** | ciphertext; envelope metadata (who/when/size) | content — subject, body, headers |
| **`pass` stores** | git metadata | store plaintext (GPG, client-side) |
| **Web/Gemini** | published files | nothing beyond what is already public |

## Zero-access mail

Mail is encrypted to each user's public key on ingress — at SMTP delivery and on IMAP
APPEND — and stored as whole-message PGP/MIME ciphertext (subject and body both
protected). The server holds only public keys, published in `kyriakon-infra` so key
substitution is auditable; it never holds a private key or anything that can derive
one.

**Key custody.** The private key is client-held, generated locally at signup (only the
public key is ever submitted), and backed up by a user-held **recovery phrase** — a
passphrase-protected offline export. The platform never holds either. Losing both key
and phrase is permanent mail loss; a forgotten login password can be reset without
touching mail, because decryption needs the client key, not the login password.

**Consequences.** No server-side body/header search or threading (search and
`THREAD=REFERENCES` are client-side); abuse monitoring runs on metadata only; spam
classification still runs at the relay, but the learn-from-moves feedback loop is gone
since moved messages are ciphertext. Users must use a PGP-capable client (Thunderbird,
K-9, FairEmail); there is no webmail, because server-served JavaScript would reopen the
active-interception surface.

**Honest ceiling.** This protects stored content against a disclosure order. It does
not stop a compelled admin from modifying the delivery pipeline to capture mail in
plaintext as it relays, nor from swapping a public key to read *future* mail — a swap
is detectable (the user's client can no longer decrypt) but only after the fact.
