# Threat model

The "audit us" claim made concrete: what kyriakon.net protects against, what it does not, and what
the operator can and cannot see. The founding proposal is
`../kyriakon/docs/decisions/kyriakon-net-project-proposal.md`.

Two adversary classes run through the document, defined in the shared glossary
(`../kyriakon/docs/CONTEXT.md`). The **reading adversary** wants the content of mail: the wiretap, the
disclosure order, the compelled operator. The **suppression adversary** wants the platform gone,
unreachable, or its operators silent. Their defences are disjoint, which is why cryptography answers
the first and jurisdiction answers the second.

Companion documents, both referenced from the acceptable use policy: `refusals.md` for the full list
of what the platform will not build and cannot do, and `transparency.md` for what an operator can be
made to produce and what an infrastructure provider holds.

## How to read the claims here

A claim is positive only where cryptography backs it, and then the limit sits next to it. Everything
else is a precise negative: what a compelled operator can produce, and what they cannot. A general
claim of resistance is unverifiable, and a platform whose pitch is "audit us" has no business making
one.

Every refusal is either a choice or a limit. A choice is something the platform could build and does
not, which a reader verifies by finding the component absent from the published configuration. A
limit is something it cannot do, and stating that plainly is the honest form of a ceiling. Stating a
choice as an impossibility invites the reply that it is merely unbuilt, and stating a limit as a
choice invites the reply that it was decided against the user. `refusals.md` splits the two.

None of this makes the platform immune to a determined authority. The defences raise the cost of
reading and of suppression, and they remove single points of leverage. That is the whole claim.

## The reading adversary

### What is protected

Stored content. Mail is encrypted to each user's public key on ingress, at SMTP delivery and on IMAP
APPEND, and stored as whole-message PGP/MIME ciphertext with subject and body both protected. The
server holds public keys only. Under a disclosure order the platform can produce ciphertext and no
key, and that is checkable rather than asserted: the private key is generated client-side and never
submitted, the encryptor resolves a recipient's key as `<localpart>.asc`, and `pass` repositories are
GPG-encrypted client-side (proposal §5.3).

A walked-away disk or backup. Full-disk `softraid` encryption and an at-rest-encrypted off-box backup
(proposal §5.5) mean a pulled disk or a stolen backup yields ciphertext.

The platform's own interest in the data. No advertising, no analytics resale, break-even pricing
(proposal §2). There is no business reason here to look at anybody's mail.

### Where it stops

Envelope metadata. Addresses, timestamps and message sizes are visible to the server, because mail
cannot be routed without them, and they appear in SMTP logs and in the outer message wrapper. This is
a routing necessity rather than a logging choice, and a provider claiming otherwise is describing
something other than SMTP. What can be reduced is how long the record persists and whether the raw
source address is kept, which the log minimization section covers.

The transient spool. Between smtpd accepting a message and Dovecot writing ciphertext, the message
sits in `/var/spool/smtpd/` in plaintext for seconds to minutes. Queue encryption covers that spool
with AES-256-GCM, and its key is persisted at `/etc/mail/queue.key` rather than derived at boot,
because `rc.d` has no terminal for `getpass(3)` to prompt on. The key therefore sits on the disk it
protects against being pulled, so queue encryption closes the walked-away-disk window and not the
compelled-operator one. This is the one residual plaintext-at-rest point in the mail path.

The forward secrecy of the archive. Holding ciphertext and no key is a claim about the present.
Ciphertext archived today plus a key obtained later reads history, and so does a broken KEM. Nothing
in the storage design makes past mail unreadable to a future key compromise, and this document does
not imply otherwise.

A compelled operator. Whoever can compel the operator can modify the delivery pipeline to capture
mail in plaintext as it relays, or swap a public key to read future mail. A key swap is detectable,
in that the user's client stops being able to decrypt, but it is detected after the fact rather than
prevented.

The strength of a client key. The platform never generates it and cannot verify what a client
actually produced beyond its shape. Signup warns when a key looks weak, and the minimum is recorded
in the acceptable use policy §4. Signup is not refused on the shape of a key, because a heuristic
rejection would turn a guarantee into a support ticket without changing what a determined user's
client does.

The correspondent's copy. Mail that has been delivered is held by whoever received it, under their
key and in their jurisdiction. Deleting it here does not touch that.

Physical coercion of the operator. Out of scope for this class and for the suppression class alike.
It is named so that its absence is a decision rather than an oversight.

## Log minimization

Logs carrying user-identifiable data are bounded rather than eliminated. `openbsd/etc/newsyslog.conf`
enforces a seven-day retention window on `maillog` (smtpd envelopes and Dovecot authentication),
`authlog` (sshd) and `nsd.log`, so the raw per-user record, meaning source address, timestamps and
message size, expires about a week after it is written. Seven days is the shortest window that still
lets abuse monitoring catch a slow-burn compromise such as a low-and-slow relay or a
credential-stuffing ramp, without keeping a permanent per-user log.

Abuse monitoring (`scripts/abuse-monitor.sh`) reads aggregate counts only: relay volume,
authentication failures, greylist churn. Never a per-address identifier. Raw addresses are discarded
at rotation. Hashing addresses to keep a longer-lived collision signal was considered and rejected,
because a retained hash is a pseudonymous identifier rather than data minimization, and every signal
it would serve is already a count the monitor keeps without the raw address.

Greylisting (`spamd`) is the one store that holds a literal source address, and it is not a user log.
Greylist tuples are dropped after four hours if the sending host never retries, and a host that does
retry is whitelisted for about 36 days (`greyexp` and `whiteexp` in spamd(8)). Both lifetimes come
from the anti-spam mechanism rather than from a retention policy, and `scripts/abuse-monitor.sh`
still keeps counts only.

The Phase 3 onboarding service will emit its own log, and it is to be born bounded by a
`newsyslog.conf` entry on the day it lands rather than grandfathered in afterwards.

## The suppression adversary

This class attacks choke points rather than content, so cryptography does not answer it. What does is
jurisdiction, diversity, and removing single points of leverage. The named risk is persecution of the
community this platform serves, and the shape applies to any authority that turns hostile to it.

### What it attacks, and what owned hardware would change

| Suppression vector | Owned hardware help? | Why |
|---|---|---|
| Provider terminates service under pressure | Partial | Colocation removes the cloud provider, but any facility still answers to its own state's orders. Owning iron at home concentrates physical-seizure risk on the operator for little gain. |
| Registry or DNS takedown of the domain | No | The domain resolves through a registry and a registrar that any state can pressure, whoever owns the rack. |
| Payment de-platforming | No | Card networks are a separate coercible layer, and a chassis is irrelevant to them. |
| Address or network blackhole (RPKI, state firewall) | No | A residential or small-colo address is more exposed to mandated blackholing than a large cloud range, and deliverability collapses on a residential address. |
| Physical seizure | No | Ownership makes the operator the seizure point, with less deterrence than a datacenter's controls. |

Ownership addresses at most a small slice of the provider-coercion vector, at five to twenty times
the cost, which breaks the £20/yr break-even model. It is the most expensive and least leveraged
defence against this class, so it is last and adopted only on an observed provider refusal, never
pre-emptively on cost grounds (ADR 0007 in the meta repository).

### Defence priorities

Ordered by leverage. Each item carries what it costs, what it buys, and how it is checked. An item
with neither a test nor a trigger does not belong on this list.

| Defence | What it costs | What it buys | How it is checked |
|---|---|---|---|
| Zero-access content | Already built | A seized box or a compelled keyring yields ciphertext, so suppression cannot read users retroactively | Test: read the published configuration, and no private key exists on the box |
| Domain resilience, a non-EU name | About £12/yr, once ten members are paying | A delegation that can be re-pointed without the current host's cooperation | Trigger: ten paying members (ADR 0006) |
| Registry lock on `kyriakon.net` | An answer from the registrar | Update, Delete and Transfer blocked at the registry, not only at the registrar | Test: all three status lines read `server...Prohibited` (ADR 0001) |
| Log minimization | Already built | A seven-day bound on the per-user record | Test: `openbsd/etc/newsyslog.conf` |
| Offline copy of the backup repository | An SSD already owned, plus quarterly attention | The only copy that survives a compromise of the running machine | Test: restore from it during the quarterly rehearsal |
| Prepaid payment rails | The operator's time per payment | A card processor cannot unilaterally cut the platform off | Test: the manual credit path, and the cash and Monero rails written down |
| A second host in a second jurisdiction | A second box | Removes the single provider from the availability story | Trigger: an observed provider action against the account, such as a suspension or a disclosure demand (ADR 0007) |
| Hardware or colo ownership | Five to twenty times the current model | A small slice of the provider-coercion vector only | Trigger: a provider actually refusing service under pressure |

### Access path

The second copy answers on a plain address, with a copy held in a second jurisdiction. An address is
not delegated, so this covers the registry case rather than the network case.

A Tor onion service is deferred to an observed suppression trigger. It answers the address-blackhole
vector, which nothing has exercised yet, and running it early would add an operational surface for a
threat that has not appeared.

I2P was considered and rejected on cost. It defends better against a global passive adversary, but an
adversary that can beat it can also see the operator's link, so it does not answer the class that
matters here, and it asks the backup host to relay for strangers.

### Domain resilience

The resilience of a domain is set by the jurisdiction of the registry operator, not by the string
itself. A state seizes a domain by compelling the operator, so the question is always which legal
entity controls the TLD and what law can reach it.

`.net` and `.com` are operated by Verisign, a Virginia corporation. A single US warrant under
18 U.S.C. § 981 can compel Verisign to redirect, lock or transfer any `.com` or `.net` domain,
wherever the registrant sits and whether or not they have any US connection. For a platform whose
named threat is European, that substitutes one coercible jurisdiction for another rather than
escaping one.

ccTLDs reduce this rather than eliminating it, and the reduction is uneven:

- `.ch` and `.li`, Switzerland and Liechtenstein, are operated by SWITCH, an independent foundation
  under Swiss law, with no local-presence requirement for the registrant. A hostile state has to
  proceed through Swiss courts rather than through a one-stop registry order.
- `.is`, Iceland, is operated by ISNIC with a strong free-expression posture, but it is thinner: a
  smaller registrant base and less legal infrastructure than Switzerland. It also carries three
  registry constraints that work against holding a name in reserve, since every nameserver must be
  registered with ISNIC before a delegation resolves, NS record TTL must be at least 24 hours, and a
  monthly automated compliance test can put the domain on hold with its DNS removed after eight
  weeks of failure.
- `.eu` is the worst choice for this threat, because the registry answers to the European
  Commission, which concentrates the pressure the platform is trying to escape.
- New gTLDs are registry operators under ICANN contract, mostly incorporated in the United States or
  the United Kingdom, so they carry the same exposure as `.net` with less neutrality on record.

ADR 0006 in the meta repository holds the decision: both current names stay where they are, a `.ch`
is acquired at a revenue gate of eight paying members, the registrar must be outside the European
Union, which for `.ch` means a Swiss registrar, and a re-home would be registry, registrar and
hosting jurisdiction together or not at all. Porkbun cannot register `.ch` at all, which was checked
against its own public pricing endpoint: 909 TLDs, `.ch` not among them.

Being non-EU at the name is necessary and not sufficient. The server and the storage box are both in
Germany, so an EU request reaches the mail whatever the domain resolves through. What a non-EU name
buys is a delegation that can be re-pointed without the current host's cooperation, and the removal
of the name from a European legal process.

Registry lock is the other half, and it is not in place today. Verisign's own criterion is that all
three of Update, Delete and Transfer read `server...Prohibited`; `kyriakon.net` currently carries
`client...Prohibited` statuses, which is registrar-level only. ADR 0001 holds the assessment.

## The provider and the hypervisor ceiling

Everything runs on one Hetzner virtual machine in Germany, with the backup repository on a Hetzner
storage box, also in Germany. The firmware, the hypervisor and the management engine are not the
platform's to inspect or control, and a memory snapshot taken from outside the guest sees what the
guest holds at that moment.

That is a named limit rather than a gap. It is why the restic password stays on the machine rather
than being derived at boot: `rc.d` has no terminal, so there is nothing to prompt into, and restic
cannot write an encrypted repository without the key that decrypts it, so a machine that backs
itself up holds the key to its own archive by construction. A running-VM snapshot captures RAM, so
memory-only custody would answer the powered-off disk image and nothing else.

The mitigation is an offline copy whose key the machine never holds, refreshed quarterly and timed
with the quarterly rehearsal. It uses its own repository and passphrase, with the passphrase stored
on the same disk as the copy, because that drive already holds raw `~/.ssh`, `~/.gnupg`,
`~/.password-store` and `~/.wallets` plus the recovery path for the chezmoi age key. One more
passphrase alongside them changes nothing about the exposure, and encrypting the volume is the change
that would. ADR 0007 holds the decision.

## What the operator can and cannot see

| | Operator can see | Operator cannot see |
|---|---|---|
| Mail | ciphertext, and envelope metadata: who, when, size | content, meaning subject, body and protected headers |
| `pass` repositories | git metadata | store plaintext, which is GPG-encrypted client-side |
| Web and Gemini | published files | nothing beyond what is already public |

## Zero-access mail

Mail is encrypted to each user's public key on ingress, at SMTP delivery and on IMAP APPEND, and
stored as whole-message PGP/MIME ciphertext. The server holds public keys, published in this
repository so that key substitution is auditable, and never holds a private key or anything that can
derive one.

The private key is client-held, generated locally at signup with only the public key submitted, and
backed up by a user-held recovery phrase, which is a passphrase-protected offline export. The
platform never holds either. Losing both the key and the phrase is permanent mail loss. A forgotten
login password can be reset without touching mail, because decryption needs the client key rather
than the login password.

What follows from it: no server-side body or header search and no server-side threading, since both
are client-side; abuse monitoring runs on metadata only; spam classification still runs at the relay,
but the learn-from-moves loop is gone because moved messages are ciphertext; and users need a
PGP-capable client, because there is no webmail and server-served JavaScript would reopen the
active-interception surface.

The honest ceiling is the one stated above under the reading adversary: this protects stored content
against a disclosure order, and it does not stop a compelled operator from modifying the delivery
pipeline or swapping a public key.

## Claims this platform does not make

Verifiable boot integrity. On a virtual machine the firmware and the hypervisor are not the
platform's, so there is no attestation chain a user could independently verify. This is refused as a
limit rather than parked as a roadmap item.

Hardware trust below the management engine. No current x86 host provides it, and the platform runs on
commodity virtual hardware, so nothing here can claim to.

Immunity to a determined authority. The defences above raise cost and remove single points of
leverage, and that is all they do.

"We cannot be compelled" in any form. What can be compelled is listed in `transparency.md`, and what
cannot is listed there too, item by item.

## Where the rest lives

- `refusals.md`, what the platform will not build and cannot do.
- `transparency.md`, what an operator can be made to produce, referenced from the acceptable use
  policy.
- ADRs 0005 to 0008 in `../kyriakon/docs/decisions/`, for retention, jurisdiction, provider posture
  and key custody, and the refusal list itself.
- The founding proposal, for the design these claims are made about.
