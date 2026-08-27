# Acceptable Use Policy

Draft for Oliver to finalize. Governs the individual tier (£20/yr,
`user@kyriakon.net`) and the standard shell-less account. The privacy policy is a
separate document.

**Our position on speech law.** We hold that the current British and Scottish
restrictions on speech infringe freedom of speech and the law of God. We comply
with them only because the law currently requires it, and we read every such law
as narrowly as it can honestly be read. Scottish law is the more restrictive of
the two and is the one most likely to bear on religious speech (see §2).

## 1. Mail abuse

- No sending spam, bulk unsolicited mail, or mail to harvested addresses.
- No phishing, spoofing, or relaying through third-party servers.
- Outbound volume is monitored. A sudden spike from one mailbox is treated as
  compromise or abuse and may trigger enforcement (§5).

## 2. Published content

What you host on `username.kyriakon.net` (HTTP/Gemini) is public.

**Content floor.** The following are not permitted as published content:

- content that is illegal under UK law;
- pornographic content;
- gambling content.

The first is a legal floor; the latter two are policy floors, not legal ones.

**Illegal content and the Online Safety Act.** We will remove content we know, or are
told, is illegal under UK law, and we comply with UK law to the extent it applies —
including the Online Safety Act 2023. Most kyriakon.net services (private mail,
static hosting) fall outside that Act's "user-to-user service" definition, but we do
not rely on that to avoid removing illegal content when we become aware of it.

**What the law actually prohibits, and what it does not.** This is our honest
reading, not legal advice. The offences that most often bear on published speech
are:

- *Stirring up hatred* — the Hate Crime and Public Order (Scotland) Act 2021
  criminalises threatening or abusive conduct that is intended to stir up hatred
  against a group defined by age, disability, race, religion, sexual orientation,
  or transgender identity. Note the two limits the statute itself draws: the
  conduct must be *threatening or abusive*, and it must be *intended* to stir up
  hatred. It expressly protects discussion and criticism of these matters, and
  expression of religious views — including views that others find offensive.
- *Threats* — a threat of death or serious harm is illegal (Online Safety Act 2023
  s181 and equivalent older offences).
- *Knowingly false communications* — sending information you know to be false, with
  intent to cause non-trivial harm, is illegal (Online Safety Act 2023 s179).
- *Grossly offensive or indecent communications* — the residual "grossly
  offensive" offence (Communications Act 2003 s127, Malicious Communications Act
  1988) is the vaguest of these and the one most abused in practice.

**What you may say.** Sincere religious teaching, quotation of scripture,
criticism of belief systems, and disagreement with prevailing views on sexuality,
gender, or anything else are not, on their own, any of the offences above —
regardless of how strongly they offend someone. Offence is not a crime. The line
the law actually draws is *threatening or abusive conduct intended to stir up
hatred*; expressing a position someone dislikes does not cross it.

**Police abuse of the gray area.** The "grossly offensive" and "stirring up
hatred" offences are deliberately vague, and we have no confidence they are
applied consistently. Police forces record "hate incidents" that are not crimes,
and officers have latitude to interpret vagueness against the speaker. We will not
amplify that: we remove content only when it is actually illegal, not merely
because it is offensive, unpopular, or the subject of a complaint or a recorded
non-crime hate incident. Where the law is genuinely uncertain, we state so rather
than guessing against you.

**Future concern: conversion practices.** As of writing there is no "conversion
practices" Act in Scotland: it is a consultation proposal, and no Bill has yet been
introduced. It is a *future* concern, not current law — but it is the future concern
most likely to bear on the Church, so we address it now rather than after the fact.

The proposal would criminalise "conversion practices" — acts intended to change or
suppress a person's sexual orientation or gender identity. The Government's own
consultation names "requiring a person not to act on their same-sex attraction,
including through celibacy" as an example of such a practice. We say plainly what
this means for us: teaching Orthodox sexual ethics — chastity included — is the
faith of the Church, not abuse, and a law which criminalises teaching it infringes
the freedom of religion and the law of God.

**The gray area is the point.** The proposal's carve-out for "non-directive"
guidance sounds reassuring and protects nothing. The operative line it draws —
between protected "discussion" and criminalised "directive" counsel — runs through
the very conversations a priest has with a penitent, and there is no stable way to
tell the two apart on paper. That vagueness is not a drafting accident to be fixed
in committee; it is the mechanism by which the law would work in practice.

**How this would actually be used.** We do not expect these laws to be applied to
the hypothetical "coercive therapy" they claim to target — that already sits under
existing assault and abuse offences. We expect them to be applied the way the
"grossly offensive" and "stirring up hatred" offences already are: a complaint or a
recorded non-crime incident names a sermon, a blog post, or a pastoral conversation,
and the vagueness of "change or suppress" and of "directive" does the rest. The
preaching itself never has to say anything coercive; it only has to be *described*
as an attempt to change or suppress someone, by anyone who wishes it suppressed.
The priest then has the burden of proving his preaching was "non-directive" — a
burden no preacher can carry, because preaching is directive by its nature.

If such a law is enacted, we will read it as narrowly as it can honestly be read,
and we will not pre-emptively police preaching as though the proposal were already
law. But we state now, before a specific person is involved, that we will not be a
channel for using this law — or any law — to suppress Orthodox teaching that is not
itself illegal.

**Zero-access boundary.** This floor governs what you *publish*. Your private mail is
encrypted to your key; the platform cannot read it. Mail content is therefore not and
cannot be policed, and this policy makes no claim to the contrary.

## 3. Resource use

- 5 GB per account, across mail, web, and git combined, enforced via `edquota`.
- Approaching the quota alerts the operator, so disk exhaustion is caught before it
  takes the box down.

## 4. Account security

- Keep your recovery phrase safe. Losing both the phrase and your key means permanent
  mail loss.
- Share accounts only via a `pass` repository — never share raw credentials.
- Use a PGP-capable mail client. There is no webmail.
- Your account has no interactive shell.

## 5. Enforcement

Abuse is handled the same way for every account, with no exception for known
contacts.

1. **Detect** — automated monitoring or a report to `abuse@kyriakon.net`.
2. **Warn** — we notify you; you have 72 hours to respond.
3. **Suspend** — the affected service is suspended pending resolution.
4. **Delete** — after a 40-day grace period, the account is deleted by the admin.

The ladder applies uniformly, including to people the operator knows personally.
