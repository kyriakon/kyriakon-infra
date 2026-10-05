# The community block

Prototype for [Decide the organisation's application questions](https://github.com/kyriakon/kyriakon-infra/issues/233). Not production, not a spec. React to it: what to cut, what to reword, and whether it is one form or two.

The existing application is one page in four sections, `You`, `Your mail key`, `How you will pay`, and `What to tell us about you`, drawn in `signup-and-account-page.html`. Everything below is additive to that page, and nothing in it repeats a question the page already asks.

## Who a body is

Not only a parish. The two cases that matter are a parish or a monastery with its own domain, and a small Orthodox business that wants `orders@` on a domain it already owns: a bookshop, an icon workshop, a publisher, a sole trader. The wording throughout this tier says a body rather than a parish, and the hosting page says who it serves.

## The shape

**One form, and the community block is conditional.** The second question of the page asks whether the application is for the applicant alone or for a body, and the block appears when the answer is a body. One form means one intent stream, one reviewer queue, one set of keys, one payment step and one set of acceptances, which is all the same code either way. A second form at its own link would duplicate every one of those, and the destination this map is walking toward says all three front-ends write into one intent API.

The applicant stays one person throughout. A body is not the applicant; the person applying for it is, and they are the one we can reach, the one who accepts the terms, and the one who pays.

## What the page asks first

> ### Is this for you, or for a body?
>
> - `( )` Just me, one address at kyriakon.net
> - `( )` A body, with its own domain, like `secretary@theirparish.example` or `orders@theiconshop.example`

Choosing the body path opens the block below and changes three things on the rest of the page: the price reads £40 a year rather than £20, the mail key section becomes one key per mailbox, and the account section asks about the domain.

## The block

> ### The body
>
> **Name** *(required)*
> `________________`
> The name you use, as you would say it out loud. A parish, a monastery, a mission, a school, a shop, a workshop. There is no list to choose from.
>
> **Kind** *(required)*
> `[ ] parish  [ ] monastery  [ ] school  [ ] business  [ ] other: ________`
> This tells us what sort of application it is when we read the queue. Nothing is decided on it.
>
> **Domain** *(required)*
> `________________`
> The domain the mail will live on. You keep control of it: you point its mail at us and we tell you exactly which records to create. Nothing here changes your domain's registration.
>
> **Addresses** *(required, one row per address)*
>
> | The part before the @ | Whose address it is | Its own mailbox, or an alias into one |
> |---|---|---|
> | `secretary` | the office | its own mailbox |
> | `hall` | the hall bookings | alias into `secretary` |
> | `father` | the priest | its own mailbox |
> | `orders` | the shop | its own mailbox |
>
> Up to ten. An address that is an alias shares the mailbox, and therefore the key, of the one it points at; an address with its own mailbox gets its own key and its own 5 GB.
>
> **Mail keys** *(one per mailbox, required)*
> One public key for each mailbox above, made in this page the same way the single-address path makes yours: nothing is uploaded, the private key never leaves your browser, and you write down the words that go with it. Two people who will both read `secretary` both need that mailbox's key, so make it somewhere you can both keep it.
>
> **The account name** *(required, one per mailbox)*
> `________________`
> The name the account is known by on our machine, which is not the same as its address. We suggest one from the domain and the address, and you can change it. Two parishes may both have a `secretary@`, because the address carries the domain and the account name does not.
>
> **Upload key for the website** *(optional; only needed if the domain gets a site or repositories)*
> `ssh-ed25519 AAAA...`
>
> **Who should we talk to about DNS?** *(optional)*
> `________________`
> A name or an address of your choosing, or leave it empty and we will write to the address above. This is used while the records are being set up and is not kept afterwards.
>
> **How you will pay** *(required)*
> The same three rails as the single-address path. The amount is £40 for the year, which covers the domain and up to ten addresses, and it does not change with the kind.
>
> **Before you send** *(required)*
> `[ ]` I accept the terms, the acceptable use policy and the refusal list. The same three links as the single-address path.
>
> **Anything to tell us** *(optional)*
> The same free-text field the page already has. This is where a monastery says it is a monastery, where a business says what it does, where an applicant asks to be considered without charge, and where anything we have not thought to ask about goes.

## What the block does not ask, and why

- **No legal name, for the person or the body.** ADR 0009 says the platform collects no legal name and no postal address, from a member or an applicant. The accountable person is whoever is signed in and can be reached at the address on the form.
- **No second copy of the contact details.** The address outside the platform, the mail password and the acceptances are asked once, on the same page.
- **No `A`, `MX` or `TXT` values in the form.** They come back to the applicant in the approval email, generated from the domain, because they cannot be written until the domain is known to us and because a form field is not where a DNS mistake should be made by hand.
- **Nothing that turns the kind into a gate.** The kind filters the queue; the three outcomes are the same for a shop as for a parish.
- **No personal questions about the applicant's own clergy status beyond what the page already asks**, which is optional there and stays optional here.

## What the reviewer sees

The same queue, with a tag that says body, its kind and the domain on the row, filterable. The three outcomes do not change: approve paid, approve without charge, or decline. A body application carries two extra things for the reviewer to check, that the domain resolves and that the applicant can add its records, and one extra step after approval, that the domain's records and the mailboxes are issued rather than one address.

One thing the reviewer needs to know and the form cannot ask: a body applying in the course of business is not a consumer, so the fourteen-day cancellation right does not reach it the way it does a person. That is the terms' business, tracked in [Draft the terms and privacy notice](https://github.com/kyriakon/kyriakon-infra/issues/235), not a question for this form.

## Open questions this draft takes a position on

1. One form with a block, not two forms. Rationale above.
2. The kind is asked, as a filter for the reviewer and not a gate. Rationale above.
3. Keys per mailbox made in the browser at application time, not added after approval, because delivery fails closed without a key and a mailbox that cannot receive mail is not an account. The alternative is lighter to apply for and leaves the account unable to receive anything until someone comes back with a key.
