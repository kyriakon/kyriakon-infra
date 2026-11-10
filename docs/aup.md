# Acceptable use policy

This policy governs every account on kyriakon.net, including individual accounts and own-domain groups, whether paid or free. You accept it when you apply, on the same checkbox as the terms of service and the privacy notice.

Sections 1 to 5 state the rules that bind your use of the service and how we enforce them. Section 6 is separate from those rules: it states our own opinion on British and Scottish speech legislation and how we read the law when we assess a complaint against published content.

The technical security claims and their limits sit in the companion documents in our public repository (`threat-model.md`, `transparency.md`, and `refusals.md`), which describe what the platform protects against, what an operator can be compelled to produce, and what the platform refuses to build.

## 1. Mail use

- You must not send spam, bulk unsolicited mail, or mail to harvested addresses.
- You must not use the service for phishing, spoofing, deceptive sender addresses, or relaying mail for third parties.
- You may send mail only from addresses assigned to your account or to your group's domain.
- We monitor aggregate outbound mail volume to protect the server's delivery reputation. A sudden spike from one mailbox is treated as a sign of compromise or abuse and may trigger enforcement under section 5.

## 2. Published content and the zero-access boundary

What you publish on `username.kyriakon.net` or on your own domain over HTTP or Gemini is public. The following are not permitted as published content:

- content that is illegal under the law of the United Kingdom;
- pornographic content;
- gambling content.

The first is a legal requirement; the second and third are conditions of the service.

We remove published content when we know, or are shown, that it is illegal under UK law or breaches the rules above, and we comply with UK law to the extent it applies, including the Online Safety Act 2023. Most kyriakon.net services, including private mail and static hosting, fall outside that Act's definition of a "user-to-user service", but we do not rely on that distinction to leave unlawful published material up once we become aware of it.

We do not remove published content merely because it is offensive, unpopular, or the subject of a third-party complaint or a recorded non-crime hate incident.

These content rules govern what you publish. Your private mail is PGP ciphertext on our server, encrypted to your public key when it arrives, and the platform holds no private key that can open it. Zero-access covers stored message content and not the addressing information mail needs to move: sender, recipient, timestamp and size appear in the server's logs and in the outer message wrapper. Mail content is therefore not and cannot be policed, and this policy makes no claim to the contrary.

## 3. Resource use

- Each account has a 5 GB soft allowance and a 5.5 GB hard limit across mail, web, Gemini, and git repositories combined, enforced by a per-account filesystem quota.
- Approaching the quota alerts the operator so that disk exhaustion is caught before it degrades the server for other members.
- You must not use the service to attack, scan, or disrupt other hosts or networks, or to place an unreasonable load on the shared machine.

## 4. Account security

- Keep your private keys and your recovery phrase safe. Because the platform holds neither, losing both your mail private key and your recovery phrase means permanent mail loss.
- Do not share your mail password or raw private keys with another person. Where a group shares access, share credentials through an encrypted `pass` repository.
- Use a PGP-capable mail client; there is no webmail.
- Your account has no interactive shell. Access is confined to IMAP and SMTP for mail, SFTP for web and Gemini uploads, and `git-shell` for your repositories.

## 5. Enforcement

The enforcement ladder applies uniformly to every account, with no exception for people the operator knows personally.

1. **Detect.** We use automated volume and health monitoring, and we take abuse reports at `abuse@kyriakon.net`.
2. **Warn.** We notify you and give you 72 hours to respond, except where outbound mail or hosting must be paused immediately to stop active spam, a compromised credential, or ongoing unlawful conduct.
3. **Suspend.** Outbound mail, SFTP uploads, and git pushes stop, and the published site and Gemini capsule are taken down. Inbound mail keeps arriving and stays readable, and the account page stays open so you can see the reason and reply at `admin@kyriakon.net`.
4. **Delete.** A suspension that is not resolved starts a 40-day grace period, so answering a warning and resolving the breach ends the suspension before this step is reached. We send a final notice 7 days before the end of the grace period, and the account is then deleted automatically. Copies in the encrypted backup repository expire within about seven months.

## 6. Statement of position: UK and Scottish speech law

This section states the operator's own views on current and proposed British and Scottish speech laws, and explains how we read those statutes when we evaluate a complaint under section 2. It is a statement of position rather than legal advice, and it adds no contractual restriction beyond sections 1 to 5.

### Our view of current speech restrictions

We hold that current British and Scottish restrictions on speech infringe freedom of speech and the law of God. We comply with them only because the law requires it, and we read every such restriction as narrowly as it can honestly be read. Of the two jurisdictions, Scottish law reaches furthest into religious expression, and it is where the next expansion has been proposed: the Scottish stirring-up offence covers more characteristics than the English one, and the conversion-practices consultation discussed below is a Scottish proposal.

### How we read the offences that bear on published speech

Checked against legislation.gov.uk on 9 October 2026, the offences most often cited against published speech are these:

- Stirring up hatred in Scotland: under the Hate Crime and Public Order (Scotland) Act 2021, section 4(1) covers behaviour that is threatening, abusive, or insulting and intended or likely to stir up hatred against a group defined by race, colour, nationality, or ethnic or national origins. Section 4(2) covers behaviour that is threatening or abusive and intended to stir up hatred against a group defined by age, disability, religion, sexual orientation, transgender identity, or variations in sex characteristics. S.S.I. 2026/150, made but not yet in force, adds sex to that list on 5 April 2027. Section 4(2) requires both that the conduct be threatening or abusive and that it be intended to stir up hatred, and the Act expressly protects discussion, criticism, and expressions of antipathy, dislike, ridicule, or insult concerning religious beliefs and practices and these other matters.
- Stirring up hatred in England and Wales: under the Public Order Act 1986, sections 18 to 21 cover racial hatred (where likelihood suffices without intent), and Part 3A covers religious hatred and hatred on the grounds of sexual orientation (which require threatening words or behaviour and intent to stir up hatred, with explicit statutory savings for discussion, criticism, and expressions of antipathy or dislike). Those provisions do not extend to Scotland, where sections 18 to 21 were repealed on 1 April 2024.
- Threats of death or serious harm: illegal in England, Wales, and Northern Ireland under the Online Safety Act 2023, section 181, and covered in Scotland by the general offence of threatening or abusive behaviour under the Criminal Justice and Licensing (Scotland) Act 2010, section 38.
- Knowingly false communications: sending a message known to be false with intent to cause non-trivial psychological or physical harm without reasonable excuse is an offence in England, Wales, and Northern Ireland under the Online Safety Act 2023, section 179. Scotland retains the older offence under the Communications Act 2003, section 127(2)(a), covering a message known to be false sent for the purpose of causing annoyance, inconvenience, or needless anxiety.
- Grossly offensive or indecent communications: section 127(1) of the Communications Act 2003 applies across the United Kingdom to sending a message that is grossly offensive or of an indecent, obscene, or menacing character over a public electronic communications network, and the Malicious Communications Act 1988, section 1, applies in England and Wales to sending an indecent or grossly offensive communication with intent to cause distress or anxiety.

Sincere religious teaching, quotation of scripture, criticism of belief systems, and disagreement with prevailing views on sexuality, gender, or morals are not, on their own, any of the offences above, however strongly they offend a reader. Giving offence is not a crime. For religious and moral speech, the statutory threshold is threatening or abusive conduct intended to stir up hatred, and stating a Christian doctrine or moral teaching does not cross it.

The "grossly offensive" and "stirring up hatred" provisions are broad, and police forces also record "non-crime hate incidents" where no offence has been committed. We do not treat a police non-crime record or a complainant's offence as evidence of illegality. Where a complaint is made against published material and the legal position is genuinely uncertain, we tell the member plainly rather than resolving doubt against the speaker.

### Future concern: Scottish conversion-practices proposals

At the time of writing there is no "conversion practices" statute in Scotland; the Scottish Government has run a consultation and no Bill has been enacted. Because it is the legislative proposal most likely to bear on the Church, we state our position on it now.

The consultation proposed criminalising acts intended to change or suppress a person's sexual orientation or gender identity, and gave "requiring a person not to act on their same-sex attraction, including through celibacy" as an example. Teaching Orthodox Christian sexual ethics, including chastity and celibacy outside marriage, is the faith of the Church and not abuse.

A statutory carve-out for "non-directive" guidance does not cure that defect. Preaching, catechesis, and pastoral counsel are directive by their nature: they call the hearer to repentance and to a specific way of life. Drawing the criminal line between permitted "discussion" and forbidden "directive" counsel places the burden on a priest or writer to prove that ordinary pastoral teaching was non-directive whenever a complainant describes it as an attempt to change or suppress someone.

If such a law is enacted, we will read it as narrowly as the text and the European Convention on Human Rights allow, and we will not pre-emptively police sermons, catechesis, or theological writing as though a consultation paper were statute. We will not act as an instrument for suppressing Orthodox Christian teaching that is not itself unlawful.
