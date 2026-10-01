# What comparable providers charge for a domain-attached, multi-address mail account

**Question.** The individual tier is £20/yr and the own-domain tier was guessed at around
£50/yr (proposal §2, ticket #188). What do other providers actually charge for one personal
mailbox, for one domain carrying several addresses for a household or parish, and for the
small-business tier each one markets, and what does that imply for the parish price?

**Answer in one paragraph.** For five addresses on one domain the mainstream providers charge
between about £48/yr (Zoho Mail Lite) and about £354/yr (Google Workspace Starter), with
Fastmail's six-user Family plan at £118.80/yr and Microsoft 365 Business Basic at £324/yr for
five users. The shapes that undercut a per-seat price are the flat-rate hosts: Purelymail at
£7.53/yr, MXroute Small at £44.41/yr and Migadu Mini at £67.74/yr, all with unlimited domains
and addresses, plus Zoho's free tier for up to five users on one domain. Registrars sell mail
per mailbox, from £11.20/yr (Namecheap Launch) to £51.18/yr (Gandi Standard). The
recommendation is a flat **£50 per domain per year** with a cap on addresses (ten) and pooled
storage, inside a defensible band of £40 to £60. Above £60 starts to look like extracting money
from a congregation when Fastmail Family sells six mailboxes for £118.80, and below £30 does not
pay for the DNS, certificate and DKIM attention every parish domain costs. Charging per address
would be wrong on this platform, because an extra address costs storage and operator attention,
not a licence fee.

---

## 1. How to read these figures

Everything below was read from the provider's own pricing page on **1 October 2026** unless the
row says otherwise. Where a figure came from a secondary source, that is said in the text.

Currency conversions use the European Central Bank's daily reference rates for **30 September
2026** (read 1 October 2026, <https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml>):

| Rate | Value |
| --- | --- |
| 1 euro | £0.85463 |
| 1 US dollar | £0.75264 (derived: 0.85463 / 1.1355) |

Prices are quoted as the provider shows them. Some include tax and some do not, which matters
for the comparison: Fastmail's UK prices are tax-inclusive; Zoho, Gandi, Hetzner, Tuta and
Proton quote before tax; Microsoft 365 and Google Workspace quote before VAT; mailbox.org does
not state the tax treatment on the page read, so that figure is not verified as inclusive.

Per-year figures are the price of a twelve-month commitment where the provider offers one, since
a parish buys annually. Where a provider only quotes monthly, twelve times the monthly price is
shown and marked as such.

---

## 2. Mainstream personal and business mail

### 2.1 Fastmail

Source: <https://www.fastmail.com/pricing/> (read 1 October 2026), business tab.

| Plan | Price | Addresses | Storage | Own domain |
| --- | --- | --- | --- | --- |
| Individual | £4.50/month, £54 for 12 months | 1 mailbox | 50 GB mail plus 10 GB files | Yes |
| Duo | £7.20/month, £86.40 for 12 months | 2 mailboxes | 50 GB mail each | Yes |
| Family | £9.90/month, £118.80 for 12 months | Up to 6 mailboxes | 50 GB mail each | Yes |
| Business Basic | £2.70 per user/month, £32.40 per user for 12 months | 1 mailbox per user, shared addresses included | 5 GB mail plus 1 GB files | Yes |
| Business Standard | £4.50 per user/month, £54 per user for 12 months | 1 mailbox per user, shared addresses included | 50 GB mail plus 10 GB files | Yes |
| Business Professional | £8.10 per user/month, £97.20 per user for 12 months | 1 mailbox per user, shared addresses included | 100 GB mail plus 50 GB files | Yes |

The smallest bill for a household is the Family plan at £118.80/yr for six people (or £9.90 for
one month). A parish of five on Business Basic pays £162/yr; on Family it pays £118.80/yr and is
buying six inboxes, which is cheaper per address than any per-user tier.

### 2.2 Proton

Sources: <https://proton.me/pricing> and <https://proton.me/business> (read 1 October 2026).
Proton quotes business prices in euros, before tax, on an annual commitment.

| Plan | Price | Addresses | Storage | Own domain |
| --- | --- | --- | --- | --- |
| Mail Plus (personal) | £3.19/month, £38.28 for 12 months | 1 user | 15 GB | 1 custom domain |
| Unlimited (personal) | £7.99/month, £95.88 for 12 months | 1 user | 500 GB | 3 custom domains |
| Workspace Standard | €12.99 per user/month, €155.88 per user/yr (£133.22) | 1 user per seat | 1 TB per user | 15 custom domains |
| Workspace Premium | €19.99 per user/month, €239.88 per user/yr (£205.00) | 1 user per seat | 3 TB per user | 20 custom domains |

The smallest parish bill on Proton Business is one seat at €155.88/yr (£133.22); every extra
person on the domain is another seat at the same price. This is the most expensive per-seat
shape in the survey for a small parish.

### 2.3 Tuta

Sources: <https://tuta.com/pricing> and <https://tuta.com/business> (read 1 October 2026).
Prices are in euros, excluding tax, on the yearly billing option.

| Plan | Price | Addresses | Storage | Own domain |
| --- | --- | --- | --- | --- |
| Revolutionary (personal) | €3/month billed yearly, €36/yr (£30.77) | 1 user, 15 aliases | 20 GB | 3 domains |
| Legend (personal) | €8/month billed yearly, €96/yr (£82.05) | 1 user, 30 aliases | 500 GB | 10 domains |
| Business Essential | €6 per user/month billed yearly, €72 per user/yr (£61.53) | 1 user, 15 aliases | 50 GB | 3 domains |
| Business Advanced | €8 per user/month billed yearly, €96 per user/yr (£82.05) | 1 user, 30 aliases | 500 GB | 10 domains |
| Business Unlimited | €12 per user/month billed yearly, €144 per user/yr (£123.07) | 1 user, 30 aliases | 1 TB | Unlimited domains |

Tuta sells unlimited custom-domain addresses on every paid plan, so aliases are not the
constraint; seats are. Five people on Essential costs €360/yr (£307.67).

### 2.4 Mailbox.org

Source: <https://mailbox.org/en/prices/> (read 1 October 2026). Prices are per mailbox, in euros,
and the page does not state whether they include German VAT. Paying annually gives twelve months
for the price of ten.

| Plan | Price | Addresses | Storage | Own domain |
| --- | --- | --- | --- | --- |
| Light | €1/month (€12 minimum deposit) | 1 mailbox, 3 aliases at mailbox.org | 2 GB | Only through a family account |
| Standard | €4/month, €40/yr (£34.19) | 1 mailbox, 50 aliases at your domain | 20 GB mail plus 10 GB Drive | Yes |
| Premium | €12/month, €120/yr (£102.56) | 1 mailbox, 250 aliases at your domain | 50 GB mail plus 100 GB Drive | Yes |

Mailbox.org has a family account with up to ten users, which is the honest comparison for a
household rather than a parish; the price is still per mailbox. Five Standard mailboxes cost
€200/yr (£170.93).

### 2.5 Migadu

Source: <https://www.migadu.com/pricing/> (read 1 October 2026). Prices are flat per account, in
US dollars, with unlimited addresses and unlimited domains; the plan limits are account-wide
soft quotas on storage and mail volume.

| Plan | Price | Addresses | Storage | Own domain |
| --- | --- | --- | --- | --- |
| Micro | $19/yr (£14.30) | Unlimited addresses, unlimited domains | 5 GB | Yes |
| Mini | $9/month or $90/yr (£67.74) | Unlimited | 30 GB | Yes |
| Standard | $29/month or $290/yr (£218.30) | Unlimited | 100 GB | Yes |
| Maxi | $99/month or $990/yr (£745.15) | Unlimited | 500 GB | Yes |

Migadu is explicit on the page that "additional email addresses do not incur additional costs"
and that the limits are per account, not per mailbox. Its FAQ also says non-profits get "a
significant discount", with no figure published. Micro at £14.30/yr is the cheapest flat-rate
plan in this survey that still uses paid infrastructure, and it is below the £20 individual
tier.

### 2.6 Zoho Mail

Source: <https://www.zoho.com/mail/zohomail-pricing.html> (read 1 October 2026). Prices are in
pounds, before local taxes, on annual billing. Mail Lite and Mail Premium are yearly only.

| Plan | Price | Addresses | Storage | Own domain |
| --- | --- | --- | --- | --- |
| Free | £0 | Up to 5 users | 5 GB each | One domain, in selected data centres |
| Mail Lite | £0.80 per user/month billed annually, £9.60 per user/yr | 1 user | 5 GB | Yes |
| Mail Premium | £3.20 per user/month billed annually, £38.40 per user/yr | 1 user | 50 GB mail plus 50 GB retention | Yes |
| Workplace Standard | £2.40 per user/month billed annually, £28.80 per user/yr (or £3.20 monthly) | 1 user | 30 GB mail, 50 GB retention, 10 GB WorkDrive | Yes |
| Workplace Professional | £4.80 per user/month billed annually, £57.60 per user/yr (or £5.60 monthly) | 1 user | 100 GB mail, 100 GB retention, 100 GB WorkDrive | Yes |

This is the price a parish administrator will find first, and it is the hardest to argue with:
five users on one domain is free, and five on Mail Lite is £48/yr. A paid plan is per user, so
the parish grows more expensive as it adds people, but the free tier covers a small parish
outright.

### 2.7 Google Workspace

Source: <https://workspace.google.com/pricing.html> (read 1 October 2026). Prices are in pounds,
per user per month, before VAT, on an annual commitment.

| Plan | Price | Addresses | Storage | Own domain |
| --- | --- | --- | --- | --- |
| Business Starter | £5.90 per user/month, £70.80 per user/yr | 1 seat | 30 GB pooled per user | Yes |
| Business Standard | £11.80 per user/month, £141.60 per user/yr | 1 seat | 2 TB per user | Yes |
| Business Plus | £18.40 per user/month, £220.80 per user/yr | 1 seat | 5 TB per user | Yes |

Google was running introductory discounts on 1 October 2026 (20 per cent off Starter and Plus,
50 per cent off Standard, for three months, ending 15 January 2027); the standard prices above
are what a parish pays after those end. Five seats on Starter is £354/yr.

### 2.8 Microsoft 365

Source: <https://www.microsoft.com/en-gb/microsoft-365/business> (read 1 October 2026). Prices
are in pounds, per user per month, before VAT, paid yearly.

| Plan | Price | Addresses | Storage | Own domain |
| --- | --- | --- | --- | --- |
| Business Basic | £5.40 per user/month, £64.80 per user/yr | 1 seat | 1 TB OneDrive per user | Yes |
| Business Standard with Copilot | £18.10 per user/month, £217.20 per user/yr | 1 seat | 1 TB OneDrive per user | Yes |
| Business Premium with Copilot | £24.60 per user/month, £295.20 per user/yr | 1 seat | 1 TB OneDrive per user | Yes |

The mailbox quota is not stated on the page read; the 1 TB figure is OneDrive storage, and
Exchange Online mailboxes are the part a parish actually cares about. Five seats on Business
Basic is £324/yr. Note that Microsoft's current UK business line-up pairs Standard and Premium
with Copilot, so the cheap end of the range is basically Business Basic.

---

## 3. The cheap shapes that undercut a per-seat price

| Provider | Price | Addresses | Storage | Own domain | Smallest bill |
| --- | --- | --- | --- | --- | --- |
| Purelymail | $10/yr (£7.53) | No hard limit on users or domains | No hard limit | Yes | £7.53/yr |
| MXroute Small | $59/yr (£44.41) | Unlimited accounts, unlimited domains | 10 GB account-wide | Yes | £44.41/yr |
| MXroute Medium | $69/yr (£51.93) | Unlimited | 25 GB | Yes | £51.93/yr |
| MXroute Large | $79/yr (£59.46) | Unlimited | 50 GB | Yes | £59.46/yr |
| Hetzner Webhosting S | €1.60/month, €19.20/yr (£16.41) plus domain from €4.90/yr (£4.19) | Unlimited mailboxes | 10 GB, shared with the website | Yes, domain bought separately | £20.60/yr |
| Gandi Mail Standard | €4.99 per mailbox/month, €59.88/yr (£51.18), tax excluded | 1 mailbox, unlimited aliases | 10 GB | Yes, domain separate | £51.18/yr |
| Hover Small Mailbox | $30/yr (£22.58) | 1 mailbox | 10 GB | Yes | £22.58/yr |
| Hover Big Mailbox | $40/yr (£30.11) | 1 mailbox | 1 TB | Yes | £30.11/yr |
| Namecheap Private Email Launch | $14.88/yr (£11.20) | 1 mailbox, 10 aliases | 5 GB | Yes | £11.20/yr |
| Namecheap Private Email Expand | $41.88/yr (£31.52) | 3 mailboxes, 50 aliases each | 10 GB each | Yes | £31.52/yr |
| Namecheap Private Email Scale | $71.88/yr (£54.10) | 5 mailboxes, unlimited aliases | 15 GB each | Yes | £54.10/yr |

Sources, all read 1 October 2026: <https://purelymail.com/pricing>,
<https://mxroute.com/>, <https://www.hetzner.com/webhosting/>,
<https://www.gandi.net/en/domain/email>, <https://www.hover.com/email>, and
<https://www.namecheap.com/hosting/email/>.

Four things stand out.

1. The flat-rate hosts (Purelymail, MXroute, Migadu) sell a whole domain of addresses for less
   than one Fastmail Business seat. MXroute's Small plan at £44.41/yr is the direct competitor
   to a £50 parish price, and it advertises "unlimited domains, unlimited email accounts, no
   per-seat charges".
2. Hetzner Webhosting S at £16.41/yr plus a domain is the cheapest way to get a domain with
   unlimited mailboxes from a provider with real support, though it is shared Linux hosting
   with a control panel, not the same trust model as this platform.
3. The registrars that sell mail per mailbox land between £11.20 and £51.18 for one address, and
   then charge per extra mailbox ($8.88 to $39.88 per year at Namecheap, one flat price each at
   Hover and Gandi).
4. Namecheap publishes a competitor table dated April 2026 listing starting prices of $84/yr for
   Google Workspace, $72/yr for Microsoft 365, $95.88/yr for ProtonMail, $70/yr for StartMail
   and $29.88/yr for Neo Mail. That table is a secondary source and is quoted only to show what
   a parish sees when shopping.

Hetzner's own page states domain registration "from €4.90/year" without saying for which
extension, and Hover's states that most domains cost between $15 and $30 per year.

---

## 4. Nonprofit and charity terms

### 4.1 Google for Nonprofits

Source: <https://www.google.com/nonprofits/offerings/workspace/> (read 1 October 2026). Prices
are in US dollars and the page does not say whether they are before tax.

| Offer | Price | Addresses | Storage | Own domain |
| --- | --- | --- | --- | --- |
| Google Workspace for Nonprofits | $0 per user/month | Not stated on the page | 100 TB shared across all users | Yes |
| Business Standard nonprofit | $3.50 per user/month on a one-year commitment (£2.63), marked as 75 per cent or more off standard | Not stated | 2 TB per user | Yes |
| Business Plus nonprofit | $6.16 per user/month on a one-year commitment (£4.64), marked as 72 per cent or more off standard | Not stated | 5 TB per user | Yes |

Eligibility requires registration as a charity in one of the listed countries (the United
Kingdom is listed), verification through Goodstack, and acceptance of the nonprofit terms.
Hospitals, healthcare organisations, schools and universities are excluded
(<https://www.google.com/nonprofits/eligibility/>, read 1 October 2026). A parish that is a
registered charity therefore gets a free Workspace account, which is the single biggest
commercial fact in this note: it makes the £50 parish tier a hard sell to any parish that knows
about it.

### 4.2 Microsoft 365 nonprofit

Sources: <https://www.microsoft.com/en-us/nonprofits/microsoft-365> and
<https://www.microsoft.com/en-us/nonprofits/eligibility> (both read 1 October 2026; the en-gb
URL redirects to the en-us page).

Microsoft states that "Microsoft 365 Business Premium is available at a 75% discount for
eligible nonprofits", that Copilot is discounted 15 per cent for nonprofits, that the annual
Azure grant is $2,000 of credits, and that Dynamics 365 Business Central is discounted 60 per
cent. The eligibility page distinguishes grants from discounts and restricts them:

- Granted licences are limited to paid employees and unpaid executive staff, and organisations
  are expected to remove unused granted licences.
- Discounted licences are available to paid staff, unpaid executive staff, volunteers and
  temporary staff.
- "Nonprofit beneficiaries, donors, and members (such as members of a church, club, or sports
  team) are not eligible for nonprofit offers."

That last sentence matters directly: a parish can license its staff, churchwardens and
volunteers, but it cannot license its congregation through the nonprofit programme. This page
does not state a free Business Basic grant, so the often-quoted free tier is not verified here.

### 4.3 TechSoup

Source: <https://www.techsoup.uk/> (read 1 October 2026), the UK affiliate listed on TechSoup's
global affiliates page (<https://www.techsoup.org/global/affiliates/>). TechSoup UK lists
"Microsoft 365 Nonprofit Cloud Subscription" and "Microsoft Donated Software" and "Microsoft
Discounted Software", plus paid migration and tenant setup services. Prices and admin fees are
shown to registered members rather than on the public pages, so no figure could be verified.

Its practical role for a UK parish is as an intermediary for Microsoft donations rather than as
a cheaper alternative to Microsoft's own nonprofit programme.

---

## 5. This platform's own numbers

From proposal §2: fixed cost is about £113/yr, made up of the VPS (about £71), the storage box
(about £30) and the domain (about £12), plus about £0.50 per user per year in Stripe fees.
Break-even is about six paying users. The individual tier is £20/yr; the own-domain tier was
guessed at around £50/yr. The storage quota is 5 GB per member across mail, web and git.

Two facts about the cost structure are what make the parish tier different from a per-seat
product:

- An extra address on the same domain is another Dovecot user, another 5 GB of quota on the same
  disk, and a share of the operator's attention. It is not another licence, another control
  panel seat, or another vendor invoice.
- An extra domain is a one-off provisioning cost (DKIM key, certificate, vhost and capsule
  block, documented DNS records the parish creates itself), plus the ongoing cost of somebody
  else's DNS being on the critical path for renewal.

So the marginal cost of a parish is storage and attention, and it grows with the number of
addresses only through the storage they use, not through a per-seat fee.

---

## 6. What this implies for the parish price

### 6.1 The band

For five addresses on one domain, the comparable annual bills are:

| Provider, five addresses | Annual bill |
| --- | --- |
| Zoho Mail free tier | £0 |
| Purelymail | £7.53 |
| MXroute Small | £44.41 |
| Zoho Mail Lite (five users) | £48 |
| Namecheap Private Email Scale (five mailboxes) | £54.10 |
| Migadu Mini | £67.74 |
| Fastmail Family (six mailboxes, one domain) | £118.80 |
| Fastmail Business Basic (five users) | £162 |
| Mailbox.org Standard (five mailboxes) | £170.93 |
| Gandi Mail Standard (five mailboxes) | £255.89 |
| Tuta Business Essential (five users) | £307.67 |
| Microsoft 365 Business Basic (five users) | £324 |
| Google Workspace Starter (five users) | £354 |
| Proton Workspace Standard (five users) | £666 |

The honest band is **£40 to £60 per domain per year**, and I would publish £50. That figure sits
just above MXroute's Small plan and just below Namecheap's five-mailbox plan, which is the right
neighbourhood: it is not the cheapest way to get mail for a domain, because it is not selling
the same thing, but it is nowhere near the per-seat providers.

What would look exploitative: anything above about £60. Fastmail gives six people a full
mail, calendar and file suite for £118.80, so a parish paying £100 for mail alone is being
overcharged by a provider that claims not to extract. Charging a price per address, say £10
per address per year, would put a five-address parish at £50 but a twenty-address parish at
£200, which is more than Fastmail Family and closer to Google Workspace, for a service that
costs the platform a few gigabytes of disk.

What would be unsustainable: anything under about £30, unless the free tier carries the small
cases. At £30 a parish contributes about £29.50 after Stripe fees; the fixed cost is £113, so
four parishes cover the box and nothing else. The operator attention a parish consumes is
front-loaded (DKIM, certificate, DNS guidance, a vhost, the first deliverability problem) and
does not scale down with a low price.

### 6.2 The shape

The honest shape is **one flat price per domain**, not per address and not per organisation
regardless of size.

Per address is wrong for this platform's cost structure. The ticket already records the reason:
an additional address on a shared box costs storage and operator attention, not a per-seat
licence. A per-address price imports the per-seat logic that the platform exists to avoid, and
it penalises exactly the shape a parish has, which is one office address, a treasurer, a
warden, a hall booking address and a clergy address on one domain.

Per organisation regardless of size is wrong in the other direction. A parish with a second
domain (a church hall, a cemetery, a school) is a second DKIM key, a second certificate and a
second set of DNS instructions, so it should be a second domain charge, not free. A flat price
per organisation also lets one large organisation consume as much as it likes at the same price
as a small parish.

A flat price per domain with a stated cap (ten addresses and a pooled storage allowance, with
the 5 GB-per-member fairness rule applying across them) matches the cost, matches the
provisioning work, and is easy to explain on a page.

### 6.3 Consequences for the other tiers

The £20 individual tier sits between Migadu Micro (£14.30) and Tuta Revolutionary (£30.77), and
below Fastmail Individual (£54) and Proton Mail Plus (£38.28). It is already generous, which is
consistent with the proposal's stated posture of break-even plus a small buffer rather than a
revenue target.

Break-even at £20 per member is about six members. A £50 domain tier contributes about £49.50
after Stripe fees, so it reaches break-even at roughly three domains, or one domain plus six
individuals. That is the argument for the £50 figure being defensible rather than greedy: it is
the smallest number that lets three parishes carry the box.

The uncomfortable finding is Zoho's free tier for five users and Google's free Workspace for
Nonprofits. Both are real and both are one search away for a parish administrator. The case for
£50 has to be the things those providers do not sell: mail the platform cannot read, no shell,
no advertising or AI training on the data, published configuration, and a community rather than
an account. The price cannot be defended on features or storage, because it loses both.

---

## 7. What could not be verified

- The mailbox quota for Microsoft 365 Business Basic, Standard and Premium. The UK business page
  states 1 TB of OneDrive storage per user and does not state the Exchange Online mailbox size.
- Whether mailbox.org's private-plan prices include German VAT. The page read does not say; it
  only mentions VAT bulk invoices for business customers.
- TechSoup UK's prices and admin fees. The donation and cloud subscription pages require a
  member login, so no figure was read from a primary page.
- Microsoft's free nonprofit grants at the Business Basic level. The current pages state a 75
  per cent discount on Business Premium and the eligibility rules for grants and discounts, but
  do not name a free tier, so any claim of a free Business Basic account is unverified here.
- Google for Nonprofits storage and user limits for the $0 edition beyond the 100 TB shared
  figure, and whether the dollar prices carry tax.
- Migadu's non-profit discount. The FAQ confirms it exists and gives no percentage.
- Purelymail's advanced usage pricing. The linked advanced pricing page returned a 404 on
  1 October 2026; only the $10/yr simple price was read.
- Domain-only prices at Gandi, Hover and Namecheap, beyond Hetzner's "from €4.90/year" and
  Hover's statement that most domains cost $15 to $30 per year.
- Fastmail's Business plan names in the comparison table (Basic, Standard, Professional) are
  read from the tab labels; the exact per-plan alias counts beyond "shared email addresses" are
  not stated as numbers.
- Proton's personal plan storage and domain counts are from its pricing page; the business
  prices were read from <https://proton.me/business>, because
  <https://proton.me/business/pricing> returns a 404.
- The Namecheap competitor comparison table (Google Workspace $84/yr, Microsoft 365 $72/yr,
  ProtonMail $95.88/yr, StartMail $70/yr, Neo Mail $29.88/yr) is a secondary source dated April
  2026 and is not a primary quote for any of those providers.
