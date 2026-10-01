# Resistance to a government threat actor

Ticket: #70, "Scope resistance to a government threat actor as a product property".

**Question:** given how this platform is built, what can it honestly state about resisting a
government adversary, what must it refuse to claim, and what check makes each statement verifiable?

**Answer, in five lines.** The phrase "state actor" hides three routes that need different answers: an
order served on the operator, a technical attack on the machine or its host, and observation of the
network. The first is answered by holding no key to mail and by naming every key that is held, and its
checks are readable in the published repository. The second is answered by encryption at rest and by
an offline copy, and its checks are the named limits in `threat-model.md` plus the host's own
published capabilities. The third is answered only in part, because the zone carries no MTA-STS
record, no TLSA record and no DNSSEC, and the sites send no HSTS header today. All three end at the
same ceiling: a compelled operator can change the running pipeline, and no published artifact shows a
change made in memory.

The decisions this note works from are ADRs 0006, 0007 and 0008 in the meta repository, and the
public statements are `docs/threat-model.md`, `docs/refusals.md` and `docs/transparency.md`. Nothing
here re-decides them. The properties table uses the register `transparency.md` sets: a statement of
capability rather than of intent, worded so that a reader checks it against a published file or an
observable record, with the limit written next to the claim.

## The three cases, kept apart

A government adversary reaches this platform by one of three routes, and a claim that does not say
which route it answers is not checkable.

1. An order served on the operator, in the operator's jurisdiction (the United Kingdom) or through
   the host's (Germany). The adversary asks a person to produce something, or to change a system.
2. A technical attack on the machine or on the provider that runs it. The adversary reads the disk, a
   disk image, a running machine's memory, or the mail in flight through the platform.
3. Observation of the network. The adversary reads traffic, the DNS, or the pattern of connections,
   without asking anyone.

Three things are out of scope, and the ticket sets them out to keep the rest honest. The platform
cannot protect a member's own device, and the zero-access design is what makes that separation
defensible rather than a gap. Physical coercion of the operator is out of scope for the reading
adversary and the suppression adversary alike, and both `refusals.md` and ADR 0008 record the
omission as a decision. Nothing here may grant a standard-tier user an interactive shell, which holds
whatever the adversary.

## An order served on the operator

### What the design does

Mail content is ciphertext under a key the platform never has. Dovecot's save path runs the
`kyriakon_encrypt` plugin, which pipes the message to the encryptor and stores RFC 3156 ciphertext
(`openbsd/dovecot/dovecot.conf`, `mail_plugins = $mail_plugins kyriakon_encrypt`), and the plugin is
fail-closed, so a missing key or a missing daemon aborts the save. The encryptor resolves a
recipient's public key as `<localpart>.asc` from `/etc/kyriakon/keys`, and the published set of those
keys is the `keys/` directory in this repository (`scripts/deploy-mail.sh`, the keyring section). An
order that asks for message content produces ciphertext, subjects and bodies included, and an order
that asks for the key produces nothing, because no private key has ever been submitted.

`pass` repositories reach the platform as ciphertext and git metadata, `pass` encrypts on the client,
so the same answer applies.

The per-user record is bounded rather than absent. `openbsd/etc/newsyslog.conf` keeps seven copies of
`maillog`, `authlog` and `nsd.log`, so the raw record of who wrote to whom expires about a week after
it is written. What survives an order is the account list, quota usage, published site files, and the
mail that is still in its retention window or still on disk as ciphertext.

### What it cannot do

The operator can be made to change the running system, and nothing in the design prevents it. The
encryptor holds plaintext in memory between the LMTP connection and the ciphertext write, so a
modified encryptor or a modified delivery path can copy it. The keyring can be rewritten, so mail can
be encrypted to a key the operator holds instead of the member's. That second change is detectable
after the fact, because the member's client stops being able to decrypt, but it is not prevented, and
an operator who copies the plaintext and then re-encrypts to the member's real key leaves no signal at
all. `threat-model.md` states this as the honest ceiling of zero-access, and it is the sentence every
claim below has to respect.

The operator also has no way to refuse and keep serving. There is no mechanism by which the platform
becomes technically unable to comply, and a claim that it is would be false.

What the platform holds is short and can be listed exactly: the DKIM signing key at
`/etc/mail/dkim/private.rsa.key`, the smtpd queue key at `/etc/mail/queue.key`, and the restic
repository password. The queue key covers the spool, which holds a message in plaintext for seconds to
minutes before the encryptor runs, and it sits on the same disk it protects, because `rc.d` has no
terminal for `getpass(3)` to prompt on (`openbsd/etc/smtpd.conf`, the queue section). It closes the
walked-away-disk window and not the compelled-operator one. The restic password is the key to the
backup archive, and it stays on the machine because a machine that backs itself up cannot avoid
holding the key that writes its own repository (ADR 0007).

### What a member can check

These checks need no cooperation from the operator, which is the reason a refusal is a stronger
statement than a promise.

- No private key is in the published tree or on the box. `grep -rIl "BEGIN PGP PRIVATE KEY" .` returns
  nothing,
  `keys/` holds public keys only (`ls keys/*.asc` returns one file today), and `/etc/kyriakon/keys/`
  on the box holds the same set.
- The keyring that the encryptor reads is the published one. `git log -- keys/` shows every change to
  a published key, so a durable substitution is a visible commit, and a member who recorded their own
  fingerprint at signup can tell whether the key the server encrypted to was theirs.
- The encryptor is on the only path into a mailbox. `openbsd/dovecot/dovecot.conf` sets the plugin,
  `openbsd/etc/smtpd.conf` delivers local mail over LMTP to `/var/dovecot/lmtp`, and no other path
  writes to a Maildir.
- The retention window exists as configuration. `openbsd/etc/newsyslog.conf` sets seven copies on the
  three logs that carry per-user data, and a member can read the file in the repository and, with the
  operator's help or on a restored copy, on the box.

What a member cannot check is whether an order was received, whether the running pipeline was
modified, or whether the operator complied. Nothing observable to a member answers those questions,
and the platform should not pretend otherwise.

### The legal routes, briefly

The operator is a United Kingdom sole trader, so a UK instrument reaches the operator directly
whatever the machine's location. The Investigatory Powers Act 2016 defines a "relevant operator" as a
postal operator or a telecommunications operator (s. 253(3)), and s. 261(12) puts a service inside
"telecommunications service" when it "consists in or includes facilitating the creation, management or
storage of communications" (legislation.gov.uk, read 2026-10-01). On that wording a hosted mail
service is in scope, so a technical capability notice under s. 253 is the instrument to name. Such a
notice may require "facilities or services of a specified description" (s. 253(5)(a)) and the "removal
by a relevant operator of electronic protection applied by or on behalf of that operator"
(s. 253(5)(c)), and it may be given to a person outside the United Kingdom (s. 253(8)). Paragraph (c)
has nothing to bite on, because the platform applies no protection it could remove: the keys that
protect mail content are the members'. Paragraph (a) is the route by which a change to the pipeline
could be required, and that is the same ceiling stated above. RIPA 2000 s. 49 lets a notice require
the disclosure of a key from a person believed to hold one; the keys the platform holds open a signing
operation and the spool, not stored mail.

The machine is in Germany, so German process reaches it and its provider. § 94 StPO allows the seizure
of objects that may serve as evidence, and § 99 StPO allows the seizure of mail in the custody of a
provider of postal or telecommunications services. The second sentence matters here: § 99(2) permits a
demand for the content of a mail item only where the provider has lawfully obtained knowledge of it,
which is the statutory shape of the zero-access claim, since the platform never holds the plaintext.
§ 100a StPO governs interception, and § 100a(4) obliges anyone providing telecommunications services
to enable an interception and give the required information. Whether an email hosting platform is a
"Telekommunikationsdienst" under the Telecommunications Act rather than a digital service is a
question about that Act, and this note does not settle it.

One German development is worth recording, because it dates the picture. On 24 June 2025 the
Bundesverfassungsgericht declared § 100a(1) sentences 2 and 3 StPO void and held § 100b StPO
incompatible with Article 10(1) of the Basic Law while leaving it in force until a replacement
(1 BvR 180/23, read 2026-10-01). Those provisions authorise interference with an end device, which is
the endpoint case this note leaves out of scope, so the decision does not change the platform's
position. It does remove, for now, one German route against member devices.

At the European level, the e-evidence Regulation gives a member state's judicial authority a European
Production Order that it serves directly on a service provider established or represented in another
member state, with ten days to respond and six hours in an emergency, and a preservation order that
stops deletion while the production order is processed. It covers stored data and not real-time
interception (Council of the European Union, read 2026-10-01). Hetzner is established in Germany, so
an order of that kind reaches the provider's copy of the disk or a snapshot without the operator
being involved. The companion directive obliges providers that are not established in the Union but
offer services in it to appoint a legal representative. Whether this platform is such a provider, and
what the transposition requires of a sole trader, is a legal question this note leaves open.

The domains are American in substance. `.net` is a Verisign registry and Porkbun is a United States
registrar (ADR 0006), and the DNS secondaries are Hurricane Electric, a company in Fremont, California
(ARIN RDAP record for AS6939, read 2026-10-01). Those facts concern the name and the queries, and they
appear in the case below.

## A technical attack on the box or its provider

### What the design does

A disk that has been pulled, imaged, or handed over while the machine is off is ciphertext, because
the root volume is a `softraid` CRYPTO volume and `softraid(4)` states that CRYPTO and 1C volumes
"require a decryption passphrase or keydisk at boot time" (man.openbsd.org, read 2026-10-01). The
passphrase is typed at the console, so a restart is not something a remote adversary can steer, and an
unattended reboot leaves the service down until someone is at a keyboard. That is the price already
paid for the property.

Mail content is ciphertext on the running machine as well, so a copy of the live disk yields mail
ciphertext for content, and envelope metadata in the clear. The published configuration shows the
encryptor on the save path, and `threat-model.md` names the hypervisor as the limit rather than
leaving it implied.

### What it cannot do

The provider can copy the machine, and the platform can neither prevent nor detect it.
`transparency.md` states that the provider holds the disk image, the hypervisor and the ability to
take a memory snapshot, and that those are the provider's to produce on the provider's own legal
process. A running machine holds plaintext in the spool and holds the queue key, the DKIM key and the
restic password, so a copy taken from outside sees the machine's secrets and whatever is in flight.

Verifiable boot integrity is not available, and that is a property of the host rather than a decision.
Hetzner's own FAQ answers "Is secure boot supported?" with "No, we do not support 'secure boot' on our
cloud servers", and "Do the cloud servers support vTPM or TPM?" with "No, our cloud servers do not
support vTPM (Virtual Trusted Platform Module) or TPM (Trusted Platform Module)" (read 2026-10-01).
With no measured boot and nothing to attest to, no attestation chain exists for a member to check, and
ADR 0008 records the refusal.

Two items are dropped from the roadmap with a reason rather than parked. Verifiable boot integrity and
hardware trust below the management engine cannot be built on this host, so they stay on the limits
list in ADR 0008 and `refusals.md` and appear in no plan.

The mitigation for the running-machine case is the offline copy decided in ADR 0007: its own
repository and passphrase, on a disk the machine's credentials do not open, refreshed quarterly and
timed so the quarterly rehearsal runs against the freshest copy. That copy does not exist yet, which
the section below on the published documents and the box records.

### What a member can check

This route is the weakest for member-side evidence, and saying so is the honest form of the finding.
The checks are the published limits plus the host's own statements:

- `docs/threat-model.md` names the hypervisor ceiling, the spool plaintext, the queue key at rest and
  the forward-secrecy limit of the archive.
- Hetzner's FAQ states the absence of secure boot and of a vTPM, which is third-party evidence that
  the boot-integrity refusal is not a choice made against members.
- The quarterly rehearsal is the only test of the offline copy, and it does not test that copy today.

No member-side technical check answers whether the provider read the machine. The platform should
claim no detection capability, because it has none.

## A network adversary watching traffic

### What the design does

Retrieval is TLS-only: `openbsd/dovecot/dovecot.conf` sets `ssl = required`, so IMAP cannot run in the
clear. Submission uses the `smtps` listener with authentication in `openbsd/etc/smtpd.conf`. The sites
serve TLS on 443 and redirect plain HTTP to it, and certificates come from Let's Encrypt over HTTP-01,
so any issuance is visible in Certificate Transparency logs.

### What it cannot do

Transport to other mail servers cannot be authenticated, inbound delivery can be downgraded, and the
platform's own name is unauthenticated in the DNS.

The zone carries no `_mta-sts` TXT record and no TLSA record. `dig +short TXT _mta-sts.kyriakon.net
@ns1.he.net` and `dig +short TLSA _25._tcp.mail.kyriakon.net @ns1.he.net` both return nothing (read
2026-10-01). Inbound mail therefore relies on opportunistic STARTTLS, which an adversary between the
sender and the box can strip, and outbound delivery cannot authenticate the peer it talks to. The
sending side cannot be fixed the way the receiving side can: `smtpd.conf(5)` as served on 2026-10-01
documents `tls` and `tls-require` for relays and listeners but no DANE or MTA-STS keyword, so this
OpenBSD mail server cannot validate a TLSA record or follow a peer's MTA-STS policy. Publishing an
MTA-STS policy for inbound mail is a property remote senders apply, and it works without smtpd
learning anything.

The delegation is unsigned. The registry's own record reports `"secureDNS": {"delegationSigned":
false}` (Verisign RDAP for `kyriakon.net`, read 2026-10-01), and a `+dnssec` query returns no RRSIG.
Without DNSSEC a resolver cannot tell a genuine answer from a forged one, and DANE would rest on a
record that proves nothing, so signing the zone is the prerequisite for authenticating mail transport
by TLSA rather than an alternative to it.

The sites send no HSTS header, because `openbsd/etc/httpd.conf` has no `hsts` block and the live file
has none either (`grep -c hsts /etc/httpd.conf` returns 0 on the box, read 2026-10-01). `httpd.conf(5)`
documents the `hsts` option with `max-age`, `preload` and `includeSubDomains`, so the gap is one
directive rather than a missing feature.

Metadata is visible and stays visible. The provider sees connections, timings and volumes, the mail
server sees the envelope, and the DNS secondaries see every query for the zone. The zone uses a single
wildcard A record, so it does not enumerate members, but a query for `member.kyriakon.net` is answered
by Hurricane Electric's fleet and is visible there. That is a third party in the United States
observing which member names get looked up.

A global passive adversary is not defended against, and ADR 0008 refuses the claim. RFC 7258 records
the IETF position that pervasive monitoring is a technical attack to be mitigated where possible, and
that mitigation "does not imply an ability to completely prevent or thwart an attack" (BCP 188,
May 2014, read 2026-10-01). Correlation of the platform's link with a correspondent's link is outside
what any change here reaches. Tor is deferred and I2P was rejected in `threat-model.md`, both on the
grounds that the adversary these would answer is not the one the platform can affect.

### What a member can check

- The certificate: `openssl s_client -connect mail.kyriakon.net:993` shows the chain,
  and the issuance appears in Certificate Transparency logs.
- The absence of transport authentication: the two `dig` commands above return nothing, which is a
  check that succeeds by finding nothing.
- The absence of DNSSEC: the registry RDAP URL above reports `delegationSigned` false.
- The absence of HSTS: `curl -sI https://kyriakon.net | grep -i strict-transport-security` returns
  nothing.
- The secondaries: `dig +short NS kyriakon.net` lists the five nameservers, all of which are Hurricane
  Electric.

## Properties worth stating

Each row is a sentence the platform could publish, the check that makes it verifiable, the cost of
holding to it, and the decision behind it. Rows marked built are true today and checkable now. Rows
marked proposed are recommendations from this note, and the last row is decided but not yet built.

| Property as stated | Check | Cost of holding to it | Status |
|---|---|---|---|
| The server holds no key that opens mail, and nothing that derives one. | `grep -rIl "BEGIN PGP PRIVATE KEY" .` is empty; `keys/` holds public keys; the encryptor resolves `<localpart>.asc` | No server-side search or threading, a PGP client on every device, and permanent loss when a member loses both key and recovery phrase | Built, ADRs 0002, 0003 and 0008 |
| The keys the platform does hold are the DKIM signing key, the queue key at `/etc/mail/queue.key`, and the restic password, and each is named with what it opens. | `docs/transparency.md`; `openbsd/etc/smtpd.conf`; `scripts/backup.sh` states that the password is the key | None. This is a statement, and it is what makes the negative claims precise | Built, ADR 0007 |
| A powered-off disk or a stored image is ciphertext. | The root volume is `softraid` CRYPTO and needs a passphrase at boot; `sysctl hw.sensors.softraid0.drive0` reports the volume on the box, and `bioctl` on the volume shows the discipline, which needs root | A passphrase typed at the console on every boot, so an unattended reboot is an outage until someone is present | Built, `softraid(4)`, ADR 0007 |
| The raw per-user log record expires about a week after it is written. | `openbsd/etc/newsyslog.conf` sets seven copies on `maillog`, `authlog` and `nsd.log` | A slow-burn relay or a credential-stuffing ramp is caught inside the window or not at all | Built, but the box runs a different file, see below |
| A durable substitution of a member's public key is a commit in this repository. | `git log -- keys/`, and the member compares the fingerprint recorded at signup | The check only works for a member who recorded the fingerprint, and it does not see a change made in memory and reverted | Built, `threat-model.md` |
| Inbound mail declares a policy that senders must use TLS, and delivery to a host without a valid certificate should fail. | `dig +short TXT _mta-sts.kyriakon.net` returns a policy, and `https://mta-sts.kyriakon.net/.well-known/mta-sts.txt` matches it | A TXT record, a file served by httpd, and the discipline to keep both current, since a stale or wrong policy makes well-behaved senders bounce mail. It does not cover the sending direction | Proposed, RFC 8461 |
| The sites are HTTPS-only after the first visit. | `curl -sI https://kyriakon.net` carries a `Strict-Transport-Security` header | One `hsts` block in `httpd.conf`, and a commitment that every host under the name keeps a valid certificate. Preload is refused for now because the list is public and slow to leave | Proposed, `httpd.conf(5)` |
| Update, delete and transfer of `kyriakon.net` are blocked at the registry, not only at the registrar. | All three statuses read `server...Prohibited` in the registry RDAP record. Today the record reads `client delete prohibited` and `client transfer prohibited`, which is registrar level only | Unlocking is registrar-mediated with out-of-band verification, which works against moving the name in a hurry | Proposed, ADR 0001 |
| A copy of the backup repository exists that the machine's credentials do not open, refreshed quarterly. | Restore from that copy during the quarterly rehearsal instead of from the storage box | The SSD the operator already owns, quarterly attention, and custody of a passphrase that does not travel with the copy | Decided, ADR 0007, not built |
| A second name outside the European Union, so the delegation can be re-pointed without the current host's cooperation. | Ten paying members, counted from the payment state the portal holds, then the delegation at the Swiss registry | About £12 a year, a registrar relationship, and the rule that a re-home takes registry, registrar and hosting together or not at all | Decided, ADR 0006, gated |

Two items that a roadmap would normally carry are absent on purpose. Verifiable boot integrity and
hardware trust below the management engine have no test and no trigger, and the rule the ticket sets
is that an item with neither gets dropped rather than left implied. Both stay on the limits list in
ADR 0008.

## Claims to refuse

These are the claims this note recommends the platform never make. Each is either unverifiable, false
as worded, or made true only by a limit that the same sentence would hide.

- Resistance to a state actor, in any general form. The threat model's own ceiling forbids it, and a
  claim a reader cannot check is worse than no claim.
- "We cannot be compelled." `transparency.md` lists what an operator can be made to produce, and a
  compelled operator can change the pipeline.
- "We will tell you if we are asked." A gag order is the ordinary instrument, and the operator is one
  person who can be silenced. The capability statement belongs in `transparency.md`; the promise does
  not belong anywhere.
- A warrant canary. ADR 0008 refuses it because it can be coerced into silence and needs standing
  signing infrastructure, where a static statement of capability is checkable against configuration.
- "No logs" or "we keep nothing". Seven days of `maillog`, `authlog` and `nsd.log` carry the raw
  per-user record, and envelope metadata appears in the outer message wrapper.
- "Anonymous". A card payment and a cash payment handed over in person both establish who paid.
  ADR 0009 makes the financial ledger unlinkable after an account is deleted, which is a narrower
  statement than anonymity.
- "End to end encrypted". Accurate against the operator for stored mail, wrong for a message crossing
  the encryptor, which holds plaintext in memory, and wrong for the spool, which holds plaintext for
  seconds to minutes.
- "Forward secret". Ciphertext archived today plus a key obtained later reads history, and
  `refusals.md` states the limit.
- "Metadata protected". Routing needs the envelope, and the provider sees connections and timings.
- "You can verify what the box is running". The repository publishes intended state, and Hetzner
  supports no secure boot and no vTPM.
- "Uncensored" or "cannot be taken down". Availability under provider coercion is not guaranteed
  (ADR 0007), and the defences raise the cost rather than removing the risk.
- "A re-home would put the platform beyond reach". The operator is a UK sole trader, so moving the
  machine leaves the operator route intact. ADR 0006 says a re-home is all three parts or none.

## Where the published documents and the box disagree

The check in every row above that reads a published file tests the intended state. On this box, two
places already differ, and both are worth recording because they weaken claims the threat model makes.

`scripts/deploy-mail.sh` installs the mail stack, the keyring and the queue key, and no script in
`scripts/` installs `openbsd/etc/newsyslog.conf` (`grep -rn newsyslog scripts/` returns one comment in
`scripts/abuse-monitor.sh` and no install step). The box therefore runs the stock OpenBSD file: it is
838 bytes, dated 2026-05-06, and contains no `nsd` entry, so `/var/log/nsd.log` is not rotated by
newsyslog, and `maillog` and `authlog` are mode 640 rather than the published 600. The retention claim
holds in effect for the two logs that carry per-user data, because the stock file also keeps seven
copies, and does not hold for `nsd.log`. HostConfig recorded the human step as
`install -m 0644 openbsd/etc/newsyslog.conf /etc/newsyslog.conf` followed by `rcctl restart syslogd`,
and put the fix in its own ticket rather than folding it into an unrelated change.

`docs/transparency.md` says the offline copy of the backup repository "exists with a key the machine
never holds". It does not exist at this commit. `scripts/rehearsal.sh` and `scripts/restore-test.sh`
both read `RESTIC_REPOSITORY`, which is the storage box, and `scripts/` contains no offline-copy path
(`grep -rn -i "offline" scripts/` returns two comments about keeping a copy of the restic password).
ADR 0007 decides the copy, the ticket lists building it as an open action, and one sentence in
`transparency.md` states it in the present tense. The sentence should change, or the copy should be
built.

The wider version of this point is the one to state plainly in the product: a check that reads the
published repository verifies what the platform intends to run, and the running machine is a separate
observation. The finger page is generated from the same repository files
(`scripts/gen-finger-page.sh`), so it does not close that distance either. The member-side checks that
do test the running system are the ones that touch it: the certificate, the Transport Layer Security
handshake, the DNS answers, and whether their own client can decrypt what arrives.

## Sources

All read on 2026-10-01 unless stated.

- Investigatory Powers Act 2016, ss. 253 and 261: https://www.legislation.gov.uk/ukpga/2016/25/section/253
  and https://www.legislation.gov.uk/ukpga/2016/25/section/261
- Regulation of Investigatory Powers Act 2000, s. 49:
  https://www.legislation.gov.uk/ukpga/2000/23/section/49
- German Code of Criminal Procedure, §§ 94, 99 and 100a: https://www.gesetze-im-internet.de/stpo/__94.html,
  https://www.gesetze-im-internet.de/stpo/__99.html, https://www.gesetze-im-internet.de/stpo/__100a.html
- Bundesverfassungsgericht, judgment of 24 June 2025, 1 BvR 180/23:
  https://www.bundesverfassungsgericht.de/SharedDocs/Entscheidungen/DE/2025/06/rs20250624_1bvr018023.html
- Council of the European Union, e-evidence: https://www.consilium.europa.eu/en/policies/e-evidence/
- Hetzner Online GmbH legal notice (the operator of the host, Gunzenhausen):
  https://www.hetzner.com/legal/legal-notice/
- Hetzner Cloud FAQ (secure boot and vTPM):
  https://docs.hetzner.com/cloud/servers/faq/
- Hurricane Electric, registrant of AS6939, Fremont, California:
  https://rdap.arin.net/registry/autnum/6939
- Verisign RDAP record for `kyriakon.net` (statuses and `delegationSigned`):
  https://rdap.verisign.com/net/v1/domain/kyriakon.net
- OpenBSD manual pages, `softraid(4)`, `smtpd.conf(5)`, `httpd.conf(5)`:
  https://man.openbsd.org/softraid.4, https://man.openbsd.org/smtpd.conf, https://man.openbsd.org/httpd.conf
- RFC 7258, Pervasive Monitoring Is an Attack: https://www.rfc-editor.org/rfc/rfc7258
- RFC 8461, SMTP MTA Strict Transport Security: https://www.rfc-editor.org/rfc/rfc8461
- RFC 7672, SMTP Security via Opportunistic DANE TLS: https://www.rfc-editor.org/rfc/rfc7672
- Repository files: `openbsd/etc/smtpd.conf`, `openbsd/etc/newsyslog.conf`, `openbsd/etc/httpd.conf`,
  `openbsd/etc/nsd/nsd.conf`, `openbsd/dovecot/dovecot.conf`, `scripts/deploy-mail.sh`,
  `scripts/backup.sh`, `scripts/rehearsal.sh`, `scripts/restore-test.sh`, `scripts/gen-finger-page.sh`,
  `docs/threat-model.md`, `docs/transparency.md`, `docs/refusals.md`
- Meta repository: ADRs 0006, 0007, 0008 and 0009 in `../kyriakon/docs/decisions/`

## Not verified

- The reading of IPA 2016 s. 261(10) to (12) that puts a mail hosting service inside
  "telecommunications operator" is mine, not a decided case, and no lawyer has reviewed it.
- Whether an email hosting platform is a "Telekommunikationsdienst" under the German
  Telecommunications Act, which decides how far § 100a(4) StPO reaches it.
- The text of the e-evidence Regulation and the directive on legal representatives. EUR-Lex refused
  automated fetches, so the account above comes from the Council's own explanation of the two
  instruments. Whether the directive obliges this platform to appoint a representative was not
  settled.
- Whether Hurricane Electric's secondary service can serve a signed `kyriakon.net` zone. Its
  secondary configuration panel was not read, and DNSSEC at the secondaries is the prerequisite for
  TLSA records to mean anything.
- Whether a Hetzner snapshot of a running server captures memory. The FAQ describes snapshots as a
  copy of the disk, and the hypervisor is not the platform's to inspect, so the memory question is
  recorded as unknown rather than asserted either way.
- The live box was read only, over `ssh`, without `doas`: `sysctl hw.sensors.softraid0.drive0`,
  `ls -l /etc/mail/queue.key`, `ls -l /etc/kyriakon/keys/`, `grep -c hsts /etc/httpd.conf` and
  `grep -n nsd /etc/newsyslog.conf`. The `softraid` volume reports `online (sd1), OK`, which shows the
  volume exists and does not on its own show the discipline, since `bioctl -q` needs root and was not
  run.
- No mail was sent and no mailbox was read, so the end-to-end behaviour of the encryptor was not
  exercised in this session.
