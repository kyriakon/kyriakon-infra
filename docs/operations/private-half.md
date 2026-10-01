# The private half of the runbook

The runbook is split, decided in #157. The procedures an operator follows are public in `docs/runbook.md`, beside the configuration they describe. The other half stays off this repository, because it lists who holds what and where things physically are, and publishing that would read as a target list.

The live copy lives in the operator's own store, reachable without the box and without this repository. This file is the structure of that half and carries no values. Nothing on this page is a placeholder for a secret: if a value were needed here to make the page readable, it would belong in the private copy instead.

Both the operator and the second root holder keep a copy, so that a single loss, a single office, or a single provider does not take the only one.

## Who holds the second root credential

Who the second holder is, how to reach them, and which key is theirs.

- The name and the usual contact channels.
- The public half of their key, or the fingerprint of it, so the credential can be checked rather than assumed.
- Where their copy of this document is kept.
- The date the credential was handed over, and the date it was last checked.
- What they can do with it: root over SSH is disabled, they log in as an unprivileged user, and `doas` carries every root action. The power they hold is the same as the operator's, including replacing a published key, and the threat model records that a compelled operator is outside what cryptography answers.

## The offline copy of the backup repository

Where the offline copy physically is, what unlocks it, and how it is refreshed.

- The location, described as a place a person can go to, not as a path.
- The names of the operators who can reach it and what each of them needs.
- The restic repository password, held separately from the medium it is written on, and separately from the copy on the box at `/root/.restic-pass`.
- The date the copy was last made and the date it was last test-restored.
- The schedule for refreshing it, and who is expected to do that.
- Which snapshots it holds, by id or date, so a restore can tell whether the copy is ahead of or behind the storage box.

## Reaching the operator when the operator is unreachable

The continuity path, for the case where the operator is ill, away, or dead and the platform keeps running.

- The order in which people are approached, with the contact details of each.
- What each person is expected to do first: which procedures in `docs/runbook.md` to read, and which of them to leave alone.
- The decisions that wait for a named person rather than for whoever gets there first, including refunds, account deletions and suspensions of member accounts.
- The address the platform's providers hold for billing and abuse, and who can change it.
- What the second root holder should not do on their own initiative, so that the review a change normally gets is not lost.

## Support addresses and what is promised

Which address is published for what, and the promise attached to each.

- The addresses, and which kinds of request each one takes.
- The stated expectation: best effort, with no uptime and no response time guarantee.
- What is not offered, so that a member asking for it gets the published answer rather than a new commitment.
- Where the promises are published, so the private copy and the public text do not drift apart.

## Rotation and change log

The dates, which are the part of #175 that stays off the repository.

- The date each rotation was done, and what was rotated: the repository publish token, the Stripe webhook signing secret, the DKIM signing key, the restic repository password.
- The reason when a rotation follows a change of operator rather than the yearly schedule.
- Who performed each rotation, and where the previous value was retired.
- The scopes, so a later reader can tell a narrow credential from a wide one without opening the provider's dashboard.
- The ICO registration reference and the date the fee was paid, since the operator actions in #175 need a record of when each one was done. The published part of the registration goes in the privacy policy, not here.

## Provider and account inventory

What the platform depends on, and how each dependency is reached when the usual route is broken.

- The hosting provider account, the storage box account, the storage box sub-accounts and their scopes, the registrar, the DNS secondary provider, and the Healthchecks account.
- The break-glass route for each: how the box is reached when ssh or DNS or the provider's console is the problem, and which of those routes needs a person rather than a key.
- Which credentials the box itself holds, so that an incident can tell what a compromise of the box reaches. The box holds the repository publish token, the Stripe signing secret, the DKIM signing key, the queue key, and the restic repository password.
- The domain names and the nameserver delegation, so that a DNS failure can be reasoned about away from the box.

## Incident communication

The channel that still works when the platform's own mail is the thing that is down.

- The address members are mailed from when the box is down, which is not an address on this platform, and who can send from it.
- The address list used for those messages, and where it comes from. It is the outside address signup collected, which is optional, so some members have none and the account page is the only channel for them.
- What is said, and what is not, when the platform is down: no status page exists, and #157 records why.
- Where the message template and the list live, and who is allowed to widen the list.
