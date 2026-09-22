# Refusals

What kyriakon.net will not build, and what it cannot do. This is the strongest form of assurance the
platform can offer, because a refusal is checkable without trusting the operator: the component is
absent from the published configuration, and anyone can look.

The two kinds are kept apart deliberately. A choice is something the platform could build and does
not, which a reader verifies by finding it missing. A limit is something it cannot do, and saying so
is the honest form of a ceiling. Reading a choice as a limit would make a decision look impossible to
reverse, and reading a limit as a choice would make a physical ceiling look like a policy taken
against the user.

Every item below is either something a reader can search for or something physics decides. Anything
that is neither is not claimed at all.

## What the platform will not build

Content classification or scanning on the mail box. Classification belongs on the operator host, and
the mail box never sees plaintext. Check: no scanner appears in `openbsd/etc/smtpd.conf` or
`openbsd/dovecot/dovecot.conf`, and the encryptor runs at delivery.

Third-party inference for message content. No message text is sent to a hosted model. Check: no
inference endpoint in the mail path.

Any key that opens mail. No escrow, no account recovery that restores content, no server-side
decryption of message bodies. Check: the keyring holds public keys only, a recipient's key resolving
as `<localpart>.asc`, and the private key is generated client-side and never submitted.

Retention of message or application text past the 90-day window. Check: the window in proposal
§5.9.1 and the retention section of `threat-model.md`.

An interactive shell for a standard-tier user. Check: `scripts/add-user.sh` creates the account with
`-s /sbin/nologin`.

A signup refused on the shape of a key. Signup warns about weak keys, and the minimum is recorded in
the acceptable use policy §4. Check: the signup path warns and proceeds, because the platform cannot
verify what a client generated and a heuristic rejection would turn a guarantee into a support
ticket.

A warrant canary. It can be coerced into silence and it needs standing signing infrastructure, where
a static statement of capability in `transparency.md` is checkable against configuration. Check:
there is no canary to coerce.

Third-party analytics or scripts on the published sites. Check: the served files are static, with no
third-party script, font or beacon.

Read receipts, open tracking, or delivery telemetry beyond what SMTP requires. Check: nothing is
added to a message on egress.

A customer list held by a payment processor. Lifecycle state lives on the platform's own machine,
which makes a processor one of several ways to extend a date rather than the system of record.
Check: the payment state in the onboarding service, once it lands, with the processor holding no
member list.

## What the platform cannot do

A global passive adversary is not defended against. The platform's link and the correspondent's link
are both observable, and no amount of care at either end changes that.

A correspondent's stored copy is not protected. What has arrived is held under their key and in their
jurisdiction.

Ciphertext archived today is not guaranteed to stay unreadable. Holding ciphertext and no key is a
claim about the present, and a key obtained later, or a broken KEM, reads history.

The strength of a client key cannot be verified. The platform sees the shape of a key and not what
produced it.

Verifiable boot integrity cannot be provided. On a virtual machine the firmware and the hypervisor
belong to somebody else, so there is no attestation chain a user could check.

Hardware trust below the management engine cannot be provided. No current x86 host provides it, and
this platform runs on commodity virtual hardware.

Mail already delivered cannot be erased. Deletion here does not reach a recipient's copy.

Availability under provider coercion cannot be guaranteed. The platform runs on a provider that can
be compelled, and the ceiling is stated in `threat-model.md`.

Suppression cannot be answered with cryptography. It is a jurisdiction and diversity problem, and the
defences are limited to raising its cost.

Physical coercion of the operator is out of scope, for the reading adversary and the suppression
adversary alike. It is listed here so that the omission is a decision.

## References

- The decisions behind these refusals are ADRs 0002, 0003, 0005, 0006, 0007 and 0008 in
  `../kyriakon/docs/decisions/`.
- `threat-model.md` states the limits these items are drawn from.
- `transparency.md` states what an operator can be made to produce.

## Why this list is the spine

Every claim elsewhere in these documents either rests on cryptography, and states its limit next to
it, or appears on one of these two lists. That is the standard the threat model sets for itself, and
it is the reason a reader can audit the platform without taking the operator's word for anything.
