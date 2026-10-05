# Terms of service

These terms are the contract between you and us for a kyriakon.net account. When you apply, you accept three documents on one checkbox: these terms, the acceptable use policy, and the privacy notice. The refusal list sits next to them as a link and is not part of what you accept. It states what the platform cannot do and will not build, and a reader checks it against the published configuration rather than agreeing to it.

If anything here is unclear, write to admin@kyriakon.net before you pay and we will answer.

## Who you are dealing with

kyriakon.net is run by Oliver Brotchie, a sole trader in the United Kingdom. The address at which the business is established is REPLACE_ME_TRADING_ADDRESS. The contact address for everything in these terms is admin@kyriakon.net.

We are not registered for VAT, so there is no VAT number to show. The price does not include VAT because there is no VAT to include, and we do not describe a charge as including VAT while that is true.

## What you are buying

| Tier | Price | What it is |
| --- | --- | --- |
| Individual | £20 a year | One `name@kyriakon.net` account: mail, a static website, a gemini capsule, git repositories, and 5 GB of storage in total |
| Own domain | £40 a year | A domain you own, served on the same infrastructure: up to ten addresses, each mailbox with the standard 5 GB, mail, website and capsule for that domain, and git repositories for each account |
| Managed instance | £150 a year, by enquiry | A separate server, listed with its price and ordered by hand rather than on the site |
| Clergy, monastics and anyone who cannot pay | no charge | The same service, through the approve-without-charge path described under the free tier |

The 5 GB is shared across mail, web and git. Every account needs an SSH key for uploads; a member who does not set one up gets mail and nothing else.

## Price and payment

The price is stated in pounds, and the number on this page is the number you pay. If you are a consumer in the European Union, the rate of VAT that applies where you live is taken out of the price rather than added to it, so we do not add a surcharge at checkout and no page needs an asterisk. We absorb the difference.

You pay by card through Stripe, by cash by post, by cash in hand, or in Monero. Card payment happens on Stripe's own site and your card details never reach us. For the other rails we give you a payment token, and a postal address or a Monero subaddress. The amount owed is in pounds even when it is quoted in Monero.

When we approve your application we open a fourteen-day payment window. Pay inside it and your year starts on the day we record the payment, not the day the window opened, so paying early costs you nothing. If the window closes with nothing recorded, the account lapses. A member who says the money is in the post can ask for one extension of the window, of another fourteen days.

Stripe sends a receipt for every successful card payment. It is a receipt, not a VAT invoice, and there is no VAT number on it because there is none.

## Your right to cancel

By law you have fourteen days to cancel, starting the day the contract is made. The right is unconditional: you can cancel for any reason, or none. An email to admin@kyriakon.net saying that you want to cancel is enough, and you can use the form below if you would rather.

Provisioning does not take the right away, and we refund in full if you cancel inside the window. To supply you inside the fourteen days we need two things from you, both recorded before you pay:

- your express request that we start now, before the cancellation period ends;
- your acknowledgement, for digital content, that supply begins immediately and the right to cancel can be lost once it does.

Those are the two checkboxes that appear before payment. We record both, and the confirmation email we send before we provision the account repeats them in writing. If you tick neither, we hold the account until the fourteen days have passed.

Cancelling inside the window costs you nothing. We refund what you paid in full, within fourteen days, in the rail you paid with, or as a credit against the next year if you would rather. Even though the law allows us to charge for the part of the year already supplied, we do not: if you cancel on day three you get the whole amount back and we deduct nothing.

A refund under this right closes the account. Before it closes we offer you an export of your mailbox ciphertext and your git repositories, and your address stops accepting mail when the account closes.

### How to cancel

Write to us, or send this form. You do not have to use it, and any clear statement that you want to cancel works:

> To Oliver Brotchie, REPLACE_ME_TRADING_ADDRESS, admin@kyriakon.net:
>
> I give notice that I cancel my contract for the supply of a kyriakon.net account.
>
> Ordered on: [date]
>
> Name:
>
> Address:
>
> Signature (only if you send this on paper):
>
> Date:

## Renewal and lapse

Your year runs from the day we record your payment. We email a reminder before it ends. If the year ends with nothing paid, the account lapses.

A lapsed account still receives mail and you can still read it, and everything you published stays up. What stops is sending from your address, uploading to your site, and pushing to your git repositories. Nothing you already have is withheld over a missed payment; the pressure to pay is the notices, not the holding of your correspondence.

Lapsing starts a grace period of forty days. We send a final notice before the end of it, and if nothing changes the account is deleted automatically on the last day. Deletion removes the account and the live data. Copies remain in our encrypted backups for up to about seven months and then expire, which the privacy notice states in full.

## Suspension, closing and deletion

These are three different things, and it helps to keep them apart.

Suspension is an enforcement step under the acceptable use policy. When an account is suspended, outbound mail stops at once and the website and capsule come down. Inbound mail keeps arriving and stays readable, and the account page stays open so you can see the reason and reply. A suspension that is not resolved starts the same forty-day grace and ends in deletion.

Closing is what happens when you ask us to close the account, or when a refund is given. Closing runs for seven days. The account works normally throughout, so you can take everything with you, and you can cancel the closure from the account page. Delivery continues during the seven days. At the end of day seven the account is deleted and the address stops accepting mail.

Deletion removes the account, the mailbox, the git repositories, and the web and gemini roots. Your username is held for ninety days and then released, so an old correspondent's mail does not land in a stranger's mailbox. A deleted account is not restored: if you come back you apply again as a new applicant, and the old mailbox, keys and settings are gone.

## The free tier

Clergy, monastics and anyone who cannot pay are not charged. You say so in the application, a person reads it, and the same person decides, with no means test and no proof asked for. We record only that the account is free. We do not record why, and we do not ask again.

A free account is permanent. It has the same 5 GB, and the same acceptable use policy, suspension and deletion apply. It never lapses for payment, because there is no payment. Once a year we send a notice saying that nothing is due and that the paid path is there if your circumstances change.

Free places have no fixed number. We say yes as far as capacity allows, and the operator reviews the share of free accounts once it passes about a fifth. A free account ends when you ask us to close it, on a breach of the acceptable use policy, or when the operator closes one that has been unreachable and unused for a year.

Because nothing was paid, the liability cap below is nil for a free account, and there is nothing to refund if you cancel. The fourteen-day right to cancel still exists, and its remedy is nothing, because you paid nothing.

## Who may apply

There is one restriction on who may apply. Applications from residents of countries under UK sanctions are declined. The reviewer checks the consolidated list at approval. That is the only limit: no other country, and no other ground, is a reason to refuse an application.

## Keys and your account

The platform holds no key that opens your mail. Your mail key is made on your own machine, and the private half never reaches us. The recovery phrase you write down, together with the key file, is the only way back into the mailbox. If you lose your device and the recovery phrase, the mail is gone permanently: we cannot restore it, because we cannot read it either. Keep the file and the phrase in separate places.

You submit your mail public key and, if you want a website, an SSH key for uploads. The private keys and the recovery phrase stay with you. Zero-access covers message content and not the addressing information mail needs to move, and the hosting page states that limit wherever the property is claimed.

There is no webmail. You need a PGP-capable mail client, and the walkthrough shows you how to set one up.

## Our liability

Nothing in these terms excludes our liability for death or personal injury caused by our negligence, for fraud, or for anything else the law does not let us exclude. Your statutory rights as a consumer are not affected, and the Consumer Rights Act 2015 requires us to perform the service with reasonable care and skill.

Except for those, our liability for any claim is capped at the fees you paid us in the twelve months before the claim. For a free account that is nothing, which is the honest figure rather than a rebate. We are not liable for indirect or consequential loss.

We do not promise any particular uptime and we do not promise a response time. One operator runs one server. If it fails, we tell you by mail from a different machine, because if the box is down your mailbox is one of the things that is down. We do not promise that a message will be delivered, that a certificate will be issued on a particular day, or that ciphertext archived today stays unreadable. The hosting page and the refusal list state those limits beside the claims they qualify.

## Changes to these terms

We publish these terms as a page on kyriakon.net, generated from a file kept in our public repository, and they change only by a reviewed commit.

A material change gets at least thirty days' notice by email before it takes effect, with the difference published and the date it starts. Material means price, cancellation, enforcement, or retention. If you object, you can cancel and we refund the unused part of your year.

Changes that only fix wording, spelling or a broken link take effect when published, with a changelog entry. When you apply, the record of what you accepted names the version by date and short commit.

## Governing law

These terms are governed by the law of Scotland, and the Scottish courts have jurisdiction.

That choice does not remove any protection you have that cannot be removed by agreement. If you are a consumer in the European Union, you keep the mandatory rights of the law of the country where you live, and the choice of Scottish law and the liability cap above are read subject to them. Nothing here cuts off a right the law gives you and does not let us sign away.

## How to contact us

Everything, including anything in these terms: admin@kyriakon.net. Abuse reports: abuse@kyriakon.net. Support is a stated best effort, with no uptime figure and no response-time guarantee.
