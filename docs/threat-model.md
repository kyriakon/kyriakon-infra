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
  property. This is the same ceiling every encrypted-mail provider has. This is
  *interception/compulsion*, distinct from *suppression* below — a hostile state that
  wants you shut down, not read, is a different threat with different defenses.
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

## Hostile-state suppression

Distinct from "a determined state actor" above: that threat *reads* (wiretap, compelled
disclosure). This one *suppresses* — an authority that wants the platform shut down, its
users cut off, or its operators pressured into silence, rather than wanting to read a
specific mailbox. It is the difference between surveillance and persecution, and it
needs different defenses. The named risk is religious persecution of the community the
platform serves (the church in Scotland or Europe), but the shape applies to any
authority-hostile-to-the-platform.

**What suppression attacks, and where hardware/ownership helps:**

| Suppression vector | Owned hardware help? | Why |
|---|---|---|
| Provider terminates service under pressure | **Partial** | Colocation removes the *cloud* provider, but any facility will still answer to its own state's orders. Owning iron in a home concentrates physical-seizure risk on the operator for little gain. |
| Registry/DNS takedown of the domain | **No** | The domain resolves through a registry and registrars that any state can pressure regardless of whose rack the box is in. |
| Payment de-platforming (Stripe) | **No** | Card networks are a separate coercible layer; a chassis is irrelevant. |
| IP/network blackhole (RPKI, state firewall) | **No** | A residential or small-colo IP is *more* exposed to mandated blackholing than a large cloud range, and deliverability (PTR, IP reputation) collapses on a residential address. |
| Physical seizure | **No** | Ownership makes the *operator* the seizure point, with *less* physical deterrence than a datacenter's controls. |

Hardware ownership addresses at most a **small slice** of the *provider-coercion* vector,
and buys it at a 5-20× cost that breaks the £20/yr break-even model. It is the most
expensive, least-leveraged defense against this threat and is therefore a **last**, not
first, step — adopted only if a provider actually *refuses* service under pressure,
never pre-emptively on cost grounds.

**The defenses that actually matter, roughly in order of leverage:**

1. **Zero-access content** (already built): a seized box or compelled keyring yields
   ciphertext and public keys, not mail. Suppression can cut users off but cannot read
   them retroactively — the strongest single property this platform has under
   persecution.
2. **Domain/registry resilience**: the domain is the platform's true fragile point. TLD
   choice, registrant entity, and registry jurisdiction determine whether a hostile
   state can pull `kyriakon.net` out of resolution. (See "Domain resilience" below.)
3. **Jurisdiction-diverse redundancy**: a secondary MX and a backup registrant/operator
   in a *different legal substrate* remove the single coercible point, without any need
   to own hardware.
4. **Payment-path fallback**: a non-Stripe path so a card processor can't unilaterally
   cut the platform off.
5. **Hardware/colo ownership** — last, and only on an observed (not predicted)
   provider-coercion trigger.

**Honest ceiling.** None of this makes the platform immune to a determined state; it
changes the *cost* of suppression and removes single points of leverage. The property
worth defending hardest is the one already held: content that cannot be read even by
someone holding the box.

### Domain resilience

The contested question "which TLD resists a hostile state" has a precise answer, and the
precision matters: **the resilience of a domain is set by the *registry operator's
jurisdiction*, not by the string itself.** A hostile state seizes a domain by compelling
the *operator* — so the question is always "which legal entity controls this TLD, and
what law can reach it," not "is `.foo` a safer ending."

The decisive example: `.com` and `.net` are operated by Verisign, a Virginia (US)
corporation. A single US warrant under 18 U.S.C. § 981 can compel Verisign to redirect,
lock, or transfer *any* `.com`/`.net` domain, regardless of where the registrant sits or
whether they have any US connection. For a platform whose threat is *European*
authority-driven persecution, `.net` exposes it to a *different* coercible jurisdiction
(the US) rather than removing coercibility — a lateral move, not an escape.

ccTLDs change this by making the operator a *national* entity bound to its member
state's law rather than to US forfeiture machinery. But that is a *reduction*, not an
elimination, and it is uneven:

- **`.ch` / `.li` (Switzerland / Liechtenstein)** — operated by SWITCH, an independent
  foundation under Swiss law; no local-presence requirement for the registrant, and
  Swiss legal process is comparatively slow and jurisdictionally conservative. Among
  European ccTLDs these are the closest thing to a *safe-haven* operator: a hostile
  state must proceed through Swiss courts, not a one-stop registry order.
- **`.is` (Iceland)** — ISNIC, with a strong historical free-speech posture, but a
  small registrant base and less legal infrastructure than Switzerland. Real, but
  thinner.
- **`.eu`** — the *worst* choice for this specific threat: the `.eu` registry is
  directly answerable to the European Commission, i.e. to the same layers of EU
  authority the threat model already presumes hostile. `.eu` *concentrates* the very
  pressure you are trying to escape.
- **New gTLDs (e.g. `.email`, `.online`, any 2012-round generic)** — registry operators
  are private companies under ICANN contract, mostly US/UK-incorporated, and thus
  exposed to the same or similar foreign-forfeiture machinery as `.net`, with *less*
  neutrality track record. No advantage.

**The practical consequence for this platform:** the domain is not merely a name; it is
a choice of *which coercible jurisdiction holds the on/off switch.* Re-homing from
`.net` — or, more robustly, holding the primary on a Swiss/Liechtenstein ccTLD with a
registrant entity that is itself jurisdictionally hard to lean on — is materially more
defensible than either staying on `.net` or buying hardware. It is also a *decision*
(touches the published zone, the hidden-primary setup, DKIM/DMARC alignment, and the
proposal's `.net`-canonical naming in §3), not a config flag, and so belongs in the
proposal, not just here.

This section records *why* the TLD question matters and how to rank candidates; it does
not resolve the re-home, which is proposal-level and gated on a concrete suppression
trigger, not on the abstract instinct that it might one day be needed.

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
