# Privacy notice

This notice says what personal data kyriakon.net holds, why it holds it, how long it keeps it, and what you can ask it to do. It covers both a free account and a paid one.

## Who is responsible for your data

kyriakon.net is run by Oliver Brotchie, a sole trader in the United Kingdom. He is the data controller for the data described here, which means he decides why it is held and what happens to it. The address at which the business is established is REPLACE_ME_TRADING_ADDRESS, and the contact address for any privacy question or request is admin@kyriakon.net. Our registration with the Information Commissioner's Office is REPLACE_ME_ICO_REFERENCE.

If you are in the European Union, our representative there is REPLACE_ME_REPRESENTATIVE, reached through REPLACE_ME_REPRESENTATIVE_CONTACT. The representative exists so that a Union member has somewhere in the Union to write about this notice.

This notice is one of the three documents you accept when you apply, alongside the terms of service and the acceptable use policy.

## What we hold, and why

Article 6 of the UK GDPR requires a lawful basis for each purpose, and the same article of the EU GDPR applies to a member in the Union. We rely on two bases, and on your contract rather than your consent.

| Purpose | What we hold | Lawful basis |
| --- | --- | --- |
| Reviewing your application and deciding it | The username you ask for, the contact address you give if you give one, your mail public key, any SSH key, your payment preference, and a free-text reason if you give one | Performance of a contract, or steps at your request before one, Article 6(1)(b) |
| Running your account: provisioning, mail delivery, web and gemini hosting, git hosting, quota | Account data, keys, and quota usage | Contract, Article 6(1)(b) |
| Billing, renewal and receipts | The paid-until date, the rail, and the payment ledger keyed by your token | Contract, Article 6(1)(b) |
| Abuse detection, outbound-mail spike watching, authentication-failure counting, rate limiting and blocklist checks | Log lines and aggregate counts | Legitimate interests, Article 6(1)(f), including the recognised interest in the security of network and information systems |
| Security logging that identifies you by address or timestamp | The raw per-user record | Legitimate interests, Article 6(1)(f). The seven-day window is what makes the balance defensible |
| The triage model | The message text and application text it reads on the operator host, and the decisions and scores it makes | Contract, Article 6(1)(b). Classification belongs on the operator host and never on the mail box, and no text it reads is sent to a third-party inference service |

We rely on consent for nothing. Membership and delivery rest on the contract, and security logging rests on legitimate interests, so there is no consent to withdraw.

The classifier files messages. It does not make a decision with a legal or similarly significant effect, so Article 22 does not apply.

Two other things are worth saying plainly. If you ask not to be charged, we hold only that your account is free, never why, so the free-text reason you gave does not survive the application window. And where we keep a record because tax law requires it, we keep it for that reason, which the retention table below states.

## What we do not hold

We collect no legal name and no postal address, at signup or at approval. We hold no card details: card payment happens on Stripe's site and the card data never reaches us. We hold no country on your account; where VAT needs to know which country a Union consumer is in, the evidence comes from the payment record and not from you. We serve no third-party scripts, fonts or beacons on the pages we publish, and we use no analytics.

## Zero-access mail, and its limit

Your message bodies, subjects and protected headers are PGP ciphertext on our server, encrypted to your public key when they arrive. We hold no private key and nothing that could derive one, so no key exists here that opens your mail, and an order to disclose its content produces ciphertext.

That covers stored content, not the addressing information mail needs to move. Sender, recipient, timestamp and size appear in the SMTP logs and in the outer message wrapper, and the seven-day window is what bounds how long the raw record exists. It is also a claim about mail at rest: it does not cover a message in transit through the spool, it does not hold against a delivery pipeline modified to capture mail in plaintext as it relays, and it does not reach a copy that was already delivered to someone else.

## How long we keep things

| What | How long |
| --- | --- |
| Log records that identify you: smtpd envelope, Dovecot authentication, sshd, dns | 7 days |
| Spam greylist and whitelist entries | about 36 days on the whitelist |
| Application data for an application that is rejected or abandoned, and the text the triage model saw | 90 days |
| Your account, mailbox, website, gemini capsule and git repositories | while the account exists, then deleted |
| A suspended account | a 40-day grace, then deletion |
| An account after a failed renewal | a 40-day grace, then deletion |
| Copies of deleted data in the encrypted backup repository | up to about 7 months after the data leaves the live tree |
| Billing and accounting records | 5 years after the 31 January filing deadline for the tax year, and 6 years once we are registered for VAT |
| Card data | never held by us; held by Stripe |

Deleting an account removes the account and the live data: the mailbox, the git repositories, and the web and gemini roots. It does not remove the copies instantly. The backup repository is content-addressed, so its only deletion mechanism is snapshot expiry, and a copy of a deleted account can survive in it as ciphertext for up to about seven months. This is why we do not say that deletion is immediate, and why the window is stated here rather than shortened in the wording.

The billing record outlives the backup repository, because tax law requires it. Its amounts, dates and rails are keyed by your payment token, not by your username. When an account is deleted, the token that joined its payments to it is deleted too, so the surviving record is a dated amount that no longer resolves to a person.

## Who else sees your data

Stripe processes card payments and holds the card data. Hetzner hosts the server and the backup repository, in Germany. Those are the only third parties in the path of your data, and neither is given your mail content. We do not sell data.

Mail you send is delivered to the recipient's mail server, which is outside our control, as is any copy the recipient keeps.

## Your rights

You have the right to see the data we hold about you, to have it corrected, to have it erased, to restrict or object to some processing, and to receive it in a portable form. The full set comes from Articles 15 to 21 of the UK GDPR.

To make a request, use the account page to export your data or to delete your account, or write to admin@kyriakon.net for anything else. We answer within one month of receiving the request, which is the deadline Article 12(3) sets. If a request is complex we may extend that by up to two further months, and we will tell you if we do. There is normally no charge. We may ask you to confirm control of the account before we act, and for an account that is not usually a document check.

You also have the right to complain to us about how we handle your data, under section 164A of the Data Protection Act 2018, and the route to do that is below.

## If something goes wrong

If a breach of security puts your data at risk, we tell the Information Commissioner's Office within 72 hours of becoming aware of it, where the law requires it, and we tell you without undue delay if the risk to you is high. Those duties come from Articles 33 and 34 of the UK GDPR. A suspected breach can be reported to admin@kyriakon.net.

## Complaints

If you are unhappy with how we handle your data, tell us first at admin@kyriakon.net and we will try to put it right. You also have the right to complain to the Information Commissioner's Office at any time, and you do not have to come to us first. The ICO takes complaints at ico.org.uk/make-a-complaint and on 0303 123 1113.

## Changes to this notice

A material change, such as a change to what we hold or how long we keep it, gets at least thirty days' notice by email before it takes effect, with the difference published and the date it starts. If you object, you can cancel and we refund the unused part of your year. Changes that only fix wording take effect when published, with a changelog entry. The version you accepted when you applied is recorded by date and short commit.
