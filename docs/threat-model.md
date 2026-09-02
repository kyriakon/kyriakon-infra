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
  and the outer message wrapper. This is a *routing necessity*, not a log-hygiene
  choice: no encrypted-mail provider can hide it, and any "no logs" claim to the
  contrary is marketing. What we *can* minimize is how long the record persists and
  whether the raw IP is retained: `openbsd/etc/newsyslog.conf` enforces a 7-day
  retention bound on `maillog`/`authlog`/`nsd.log`, and abuse monitoring reads
  aggregate *counts* only — never a per-IP identifier (see "Log minimization"
  below).
- **A user's own compromised key or device.** A seized private key or device makes that
  user's mail readable. The only backstop is the user-held recovery phrase.

## Log minimization

Logs carrying user-identifiable data are bounded, not eliminated. `newsyslog.conf`
enforces a 7-day retention window on `maillog` (smtpd envelope + Dovecot auth),
`authlog` (sshd), and `nsd.log`, so the raw per-user record — source IP, timestamps,
message size — expires roughly a week after it is written. 7 days is the shortest
window that still lets abuse monitoring catch a slow-burn compromise (a low-and-slow
relay, a credential-stuffing ramp) without keeping a permanent per-user log.

Abuse monitoring (`scripts/abuse-monitor.sh`) reads **aggregate counts only** — relay
volume, auth-failure count, greylist churn — never a per-IP identifier. Raw IPs are
discarded at rotation. Hashing IPs to retain a longer-lived collision signal was
considered and rejected: a retained hash is a pseudonymous identifier, not data
minimization, and every signal it would serve is already a plain count the monitor
keeps without the raw IP.

Greylisting (`spamd`) is the one store that keeps a literal source IP, and it is not a
user log: entries self-expire in hours as a functional anti-spam mechanism, not a
retention window. The Phase 3 onboarding service will emit its own log; it is to be
born already bounded by a `newsyslog.conf` entry the day it lands, not grandfathered in
after the fact.

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
