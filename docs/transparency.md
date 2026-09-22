# Transparency statement

What an operator of kyriakon.net can be made to produce, what they cannot, and what sits with an
infrastructure provider instead. Referenced from the acceptable use policy (`aup.md`).

This is a statement of capability rather than of intent. It describes what the system is built to
hold, so that a reader can check the claim against the published configuration rather than deciding
whether to believe it.

## Mail content

Message bodies, subjects and the protected headers are PGP ciphertext on the server, encrypted to
each user's public key on ingress, and the platform holds no private key and nothing that could
derive one. An order compelling the operator to disclose mail content produces ciphertext.

That is a claim about stored content. It does not extend to a message in transit through the spool,
to a modified delivery pipeline, or to mail already archived and later read with a key obtained by
some other route. Those limits are named in `threat-model.md` and in `refusals.md`.

## What an operator can produce

Envelope metadata for mail the platform handled: sender, recipient, timestamp and size. Mail cannot
be routed without it, and it appears in SMTP logs and in the outer message wrapper.

Log records inside their retention window. `openbsd/etc/newsyslog.conf` bounds `maillog`, `authlog`
and `nsd.log` at seven days, so the raw per-user record expires about a week after it is written.
Records older than that do not exist to be produced. Abuse monitoring keeps aggregate counts rather
than per-address identifiers.

The account list: which accounts exist, their quota usage, and their published web and Gemini files,
which are public by design.

The DKIM signing key, which signs mail on egress, and the mail queue encryption key at
`/etc/mail/queue.key`.

## What an operator cannot produce

The content of any message stored on the platform, including an old one, because no key exists here.

The plaintext of a `pass` repository, which is GPG-encrypted client-side and reaches the platform as
ciphertext and git metadata.

Anything already deleted under the retention rules, or anything that was never written because the
platform does not keep it: the log records past seven days, message text past the 90-day application
window, and per-address abuse data at all.

A user's private key or recovery phrase, neither of which has ever been submitted.

## What the infrastructure provider holds

The platform runs on a Hetzner virtual machine in Germany, with its backup repository on a Hetzner
storage box, also in Germany. The provider holds the disk image, the hypervisor, and the ability to
take a memory snapshot of the running machine. Those are the provider's to produce, on their own
legal process, and the platform cannot prevent it or detect it.

This is the reason for the named hypervisor ceiling in `threat-model.md`, and the reason the offline
copy of the backup repository exists with a key the machine never holds.

## Payments

Where a member pays by card, the processor holds the transaction and knows that a payment was made.
What it does not hold is a list of members: the payment lifecycle state lives on the platform's own
machine, so the processor is one of several ways to extend a date rather than the system of record.

Members paying by cash or by Monero are not in a processor's records at all. A posted payment is
matched by a token issued at approval, which carries no name or address, and a Monero payment is
matched by a per-member subaddress.

## What this statement does not cover

A compelled operator who modifies the delivery pipeline can capture mail in plaintext as it relays,
and can swap a public key to read future mail. A swap is detectable after the fact, in that the
user's client stops being able to decrypt, but it is not prevented.

Ciphertext archived before such an intervention is not made unreadable by it, and ciphertext archived
now is not protected against a key obtained later.

Mail already delivered to a correspondent is held by them, under their key and in their jurisdiction,
and nothing said here reaches it.

Anything outside the platform's infrastructure, including the network path, the correspondent's
provider and the devices at either end, is outside this statement.

## Status

The mail stack, the backup and restore path, and the published-configuration claims in these
documents are built and checkable now. The paid tier and the onboarding service that holds payment
state are specified and not yet live; when they land, this statement and `aup.md` are updated with
them rather than before them.
