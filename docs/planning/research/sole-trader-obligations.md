# Sole trader obligations: cancellation, privacy, VAT and identity (public release)

**Question:** what must one UK sole trader publish and promise to sell a £20/yr
hosted service (mail, static web, gemini, `pass` git repos) to consumers online by card or by
a prepaid rail, given that members may be anywhere in the world, the EU included?

**Answer:** four things have to be true before the public site goes up.

1. **The 14-day cancellation right applies, and immediate provisioning does not remove it.**
   A hosted subscription is a service contract or a digital content contract, either way
   [reg 30(2)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/30) gives 14 days from
   the day the contract is entered into. Supply may begin inside that period only on the
   consumer's
   [express request](https://www.legislation.gov.uk/uksi/2013/3134/regulation/36), and for
   digital content only with a separate acknowledgement that the right will be lost
   ([reg 37(1)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/37)). Because the
   service is not fully performed for a year, a member who cancels inside the 14 days is owed
   money back. **Proposal §5.9.1's "no refund path exists at all" cannot be published to
   consumers** *(interpretation)*.
2. **Three pages, and a retention schedule that matches what the box actually does.** The
   privacy policy must name the trader, give the
   [Article 6](https://www.legislation.gov.uk/eur/2016/679/article/6) basis per purpose, and
   state retention periods ([Article 13(2)(a)](https://www.legislation.gov.uk/eur/2016/679/article/13)).
   The seven-day, 90-day and restic windows are reconciled in section 5 below. The ICO's data
   protection fee is due and is £52 at this scale, and selling into the Union also requires a
   representative established there (2.7).
3. **No UK VAT registration at this revenue, and EU VAT handled through the non-Union OSS.**
   The threshold is
   [£90,000](https://www.gov.uk/register-for-vat), so £20/yr per member is three orders of
   magnitude short. Sales to consumers in the EU are the exception, where VAT is due from the
   first euro: HMRC's route is the non-Union OSS in a member state of the trader's choosing, and
   section 3.5 records what registering, filing and pricing involve. Stripe already issues a
   receipt per successful payment; it does not issue anyone a VAT invoice.
4. **Publish the trader, not a company.** Name, geographic address and a contact email, with
   no registered office and no company number to show
   ([E-Commerce Regs 2002 reg 6](https://www.legislation.gov.uk/uksi/2002/2013/regulation/6)).

**How to read the sourcing.** Every section carries a link to the primary source: legislation.gov.uk,
the ICO, GOV.UK, or Stripe's own documentation. Sentences marked *(interpretation)* apply that
law to this platform and are a reading, not a quotation. Nothing here is legal advice; section
6 lists the questions that need a lawyer or an accountant rather than a document.

---

## 1. Cancellation

### 1.1 The right exists and the period is 14 days

The right is unconditional. [Reg 29(1)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/29):
"The consumer may cancel a distance or off-premises contract at any time in the cancellation
period without giving any reason." [Reg 30(2)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/30)
sets the period:

> If the contract is (a) a service contract, or (b) a contract for the supply of digital
> content which is not supplied on a tangible medium, the cancellation period ends at the end
> of 14 days after the day on which the contract is entered into.

Three details that matter here.

- **A member is a consumer only if they buy outside their work.** [Reg 4](https://www.legislation.gov.uk/uksi/2013/3134/regulation/4)
  defines a consumer as "an individual acting for purposes which are wholly or mainly outside
  that individual's trade, business, craft or profession". A member who buys the account for
  parish business is arguably not a consumer and the 14-day right then does not apply to them
  *(interpretation)*. The site should not try to sort members into two regimes; it should give
  every individual the right.
- **The £42 exemption does not cover this product.** [Reg 27(3)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/27)
  reads "This Part does not apply to off-premises contracts under which the payment to be made
  by the consumer is not more than £42", and off-premises means a contract concluded in the
  consumer's presence. GOV.UK's summary, "These rules do not apply to: goods and services worth
  £42 or less" ([GOV.UK online and distance selling](https://www.gov.uk/online-and-distance-selling-for-businesses)),
  is wider than the regulation. An online £20 subscription is a distance contract and gets no
  £42 exemption *(interpretation)*.
- **Getting the paperwork wrong extends the period to a year.** [Reg 31](https://www.legislation.gov.uk/uksi/2013/3134/regulation/31)
  applies "if the trader does not provide the consumer with the information on the right to
  cancel required by paragraph (l) of Schedule 2", and then: "Otherwise the cancellation period
  ends at the end of 12 months after the day on which it would have ended under regulation 30."
  Failing to give that notice is a criminal offence only for off-premises contracts
  ([reg 19(1)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/19) names regulation 10),
  so an online trader's sanction is the 12-month window, not a fine *(interpretation)*. Every
  contract also carries an implied term that the trader complied with the information duties
  ([reg 18](https://www.legislation.gov.uk/uksi/2013/3134/regulation/18)).

Cancelling costs the member nothing to attempt: [reg 32(3)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/32)
lets them use the Schedule 3 Part B form "or make any other clear statement setting out the
decision to cancel the contract", and an email is a clear statement.

### 1.2 Immediate provisioning: two provisions, and both want a recorded request

Which provision governs depends on how the supply is characterised, so the signup flow has to
satisfy both readings.

**Digital content, not on a tangible medium** ([reg 37(1)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/37)):

> the trader must not begin supply of the digital content before the end of the cancellation
> period provided for in regulation 30(1), unless (a) the consumer has given express consent,
> and (b) the consumer has acknowledged that the right to cancel the contract under regulation
> 29(1) will be lost.

Once supply begins after that consent and acknowledgement, the right is gone
([reg 37(2)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/37)). The confirmation of
the contract must repeat both, because
[reg 16(3)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/16) requires the
confirmation to "include confirmation of the consent and acknowledgement". If any of the three
is missing then "the consumer bears no cost for supply of the digital content, in full or in
part, in the cancellation period" ([reg 37(4)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/37)).

**A service** ([reg 36](https://www.legislation.gov.uk/uksi/2013/3134/regulation/36)) works
differently, and this is the reading that bites hardest:

> The trader must not begin the supply of a service before the end of the cancellation period
> provided for in regulation 30(1) unless the consumer (a) has made an express request, and
> (b) in the case of an off-premises contract, has made the request on a durable medium.

> the consumer ceases to have the right to cancel a service contract under regulation 29(1) if
> the service has been fully performed, and performance of the service began (a) after a
> request by the consumer in accordance with paragraph (1), and (b) with the acknowledgement
> that the consumer would lose that right once the contract had been fully performed by the
> trader.

Mail transport, web serving and git hosting are performed continuously, so a 12-month
subscription is not "fully performed" until the last day of the year *(interpretation)*. Reg
36(2) therefore never makes the right disappear during the 14 days. What reg 36(4) does instead:

> the consumer must (subject to paragraph (6)) pay to the trader an amount (a) for the supply
> of the service for the period for which it is supplied, ending with the time when the trader
> is informed of the consumer's decision to cancel the contract ... and (b) which is in
> proportion to what has been supplied, in comparison with the full coverage of the contract.

Reg 36(6) removes that charge entirely, so the member pays nothing at all, "if (a) the trader
has failed to provide the consumer with the information on the right to cancel required by
paragraph (l) of Schedule 2, or the information on payment of that cost required by paragraph
(n) of that Schedule ... or (b) the service is not supplied in response to a request in
accordance with paragraph (1)."

Two consequences for the onboarding service *(interpretation)*:

- Record the express request before provisioning. An unchecked signup box means the member can
  cancel and owe nothing for the days they used, since reg 36(6)(b) applies.
- Give the cancellation information and the cost-of-early-supply information at checkout, or
  the same result follows under reg 36(6)(a) and the period is extended by reg 31.

### 1.3 The waiver, in the wording the regulations ask for

The regulations do not prescribe a sentence; they require two distinct acts before supply
begins, plus a confirmation afterwards. A drafting that satisfies all three *(interpretation;
not legal advice)*:

> **Before you pay.** Tick both boxes.
> [ ] Activate my account now, before the 14-day cancellation period ends. (express consent,
> reg 37(1)(a) or the reg 36(1) request)
> [ ] I understand that once you begin supplying the service I lose my right to cancel.
> (acknowledgement, reg 37(1)(b) and reg 36(2)(b))

The emailed confirmation required by [reg 16(1)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/16)
("the trader must give the consumer confirmation of the contract on a durable medium") then has
to restate both, and under reg 16(4)(b) it must arrive "before performance begins of any
service supplied under the contract". The onboarding service should send it before it runs
`useradd`.

Where all of this is stated, with the regulation that requires it:

| Statement | Requirement |
|---|---|
| Identity of the trader, geographic address, contact details | [reg 13(1)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/13) with [Schedule 2](https://www.legislation.gov.uk/uksi/2013/3134/schedule/2) paras (b), (c) |
| Price inclusive of taxes, and total cost per billing period for a subscription | Schedule 2 paras (f), (h) |
| Conditions, time limit and procedures for cancelling | Schedule 2 para (l), enforced by [reg 31](https://www.legislation.gov.uk/uksi/2013/3134/regulation/31) |
| Notice that a member who asked for early supply pays for what they used | Schedule 2 para (n) |
| Notice that the right is lost, or the circumstances in which it is lost | Schedule 2 para (o) |
| Duration of the contract and the conditions for termination | Schedule 2 para (s) |
| Model cancellation form | [reg 13(1)(b)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/13), form in [Schedule 3 Part B](https://www.legislation.gov.uk/uksi/2013/3134/schedule/3) |

### 1.4 A member who cancels after provisioning

Refunds are the trader's duty, not a favour: [reg 34(1)](https://www.legislation.gov.uk/uksi/2013/3134/regulation/34)
requires the trader to "reimburse all payments, other than payments for delivery", reg 34(4)-(6)
sets the deadline at 14 days, and reg 34(7) and (8) require the same means of payment and no
fee. The one deduction available is the reg 36(4) pro-rata charge for a service, and 14 days of
a £20 year is well under a pound *(interpretation)*. For digital content supplied under a
proper reg 37 waiver the right is lost at first supply, so the member gets nothing back.

The practical shape: build a refund path before launch, honour it without argument inside 14
days, and treat the reg 36(4) deduction as optional since the amount is trivial and the
conditions for it are easy to fail.

### 1.5 Cancelling is not the same as the account closing

Deletion itself stays admin-mediated, which is separate from the refund question. The
[Digital Markets, Competition and Consumers Act 2024, Part 4 Chapter 2](https://www.legislation.gov.uk/ukpga/2024/13/part/4/chapter/2)
adds pre-contract information, renewal reminder notices, cooling-off rights and an easy exit
for subscription contracts, and it is **not in force**: legislation.gov.uk marks the chapter
"This version of this chapter contains provisions that are prospective", section 253 carries
"S. 253 not in force at Royal Assent, see s. 339(1)", and [s. 339(1)](https://www.legislation.gov.uk/ukpga/2024/13/section/339)
provides for commencement by regulations. The commencement orders checked do not include the
chapter ([SI 2025/272](https://www.legislation.gov.uk/uksi/2025/272/regulation/2/made),
[SI 2026/284](https://www.legislation.gov.uk/uksi/2026/284/regulation/2)), and the government's
consultation response says "we anticipate that the regime will commence in spring 2027"
([DBT response, updated 2 April 2026](https://www.gov.uk/government/consultations/consultation-on-the-implementation-of-the-new-subscription-contracts-regime/outcome/government-response-to-consultation-on-the-implementation-of-the-new-subscription-contracts-regime-web-accessible-version)).
So today the regulations above are the whole of it, and a renewal-cooling-off design should not
be built against a date that has not been set *(interpretation)*.

### 1.6 The consumer's remedies under the Consumer Rights Act 2015

Short version, because it constrains what the AUP and terms can say. Digital content has
"the right to repair or replacement" and "the right to a price reduction"
([s. 42](https://www.legislation.gov.uk/ukpga/2015/15/section/42)), a supply of a service
carries "a term that the trader must perform the service with reasonable care and skill"
([s. 49(1)](https://www.legislation.gov.uk/ukpga/2015/15/part/1/chapter/4)), and the price
reduction right includes "the right to receive a refund for anything already paid above the
reduced amount" ([s. 56(1)](https://www.legislation.gov.uk/ukpga/2015/15/section/56)). A terms
page that excludes all refunds sits badly against both these and reg 34.

---

## 2. Privacy

### 2.1 What the policy must state

[Article 13(1)](https://www.legislation.gov.uk/eur/2016/679/article/13) requires the controller
to provide at the time data is collected, among other things:

> (a) the identity and the contact details of the controller and, where applicable, of the
> controller's representative

plus the purposes and the legal basis, the legitimate interests where Article 6(1)(f) is
relied on, the recipients, and, under Article 13(2)(a), "the period for which the personal data
will be stored, or if that is not possible, the criteria used to determine that period". The
ICO's table of required privacy information marks as "Always" the name and contact details, the
retention periods, the lawful basis, the rights available, and the right to complain to a
supervisory authority
([ICO, what privacy information should we provide](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/what-privacy-information-should-we-provide/)).
The revised Article 13 as it stands on 30 September 2026 also requires telling people of "the
right to make a complaint to the controller under section 164A of the 2018 Act" *(the revised
text carries Data (Use and Access) Act 2025 amendments dated 19 June 2026)*.

### 2.2 Controller identity for a sole trader

A sole trader is the controller personally, so the policy names the individual, not only a
trading name *(interpretation of Article 13(1)(a), which asks for "the identity and the contact
details of the controller")*. The ICO's register of fee payers publishes "the name and address
of the controller" and a registration reference
([ICO register of fee payers](https://ico.org.uk/about-the-ico/what-we-do/register-of-fee-payers/)),
and the policy should use the same name and address, so that a member or the ICO can match the
two. Including the registration reference in the policy is practice, not law: Article 13 does
not ask for it and the ICO's required list does not mention it *(interpretation)*.

### 2.3 Lawful basis per purpose

Article 6(1) allows processing only where one of the listed grounds applies. The two that fit
this platform, quoted from [Article 6](https://www.legislation.gov.uk/eur/2016/679/article/6):

> (b) processing is necessary for the performance of a contract to which the data subject is
> party or in order to take steps at the request of the data subject prior to entering into a
> contract

> (f) processing is necessary for the purposes of the legitimate interests pursued by the
> controller or by a third party, except where such interests are overridden by the interests
> or fundamental rights and freedoms of the data subject which require protection of personal
> data, in particular where the data subject is a child.

| Purpose | Basis | Note |
|---|---|---|
| Application review, account provisioning, mail and hosting delivery, billing, renewal | Art 6(1)(b) contract | The ICO warns the contract basis "does not apply if you collect and reuse your customer's data for your own business purposes" ([ICO contract basis](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/lawful-basis/a-guide-to-lawful-basis/contract/)) |
| Abuse detection, outbound-mail spike watching, auth-failure counting, rate limiting, blocklist checks | Art 6(1)(f) legitimate interests, with the recognised interest for network and information security available under the revised Article 6 | The revised Article 6 adds "(ea) processing is necessary for the purposes of a recognised legitimate interest", and its Annex lists "processing that is necessary for the purposes of ensuring the security of network and information systems" ([Article 6](https://www.legislation.gov.uk/eur/2016/679/article/6)). The ICO's three-part test still applies: identify the interest, show necessity, balance it ([ICO legitimate interests](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/lawful-basis/a-guide-to-lawful-basis/legitimate-interests/)) |
| Security logging that identifies a member by address or timestamp | Art 6(1)(f) | The seven-day window is what makes the balance defensible: the raw per-user record expires inside a week (`openbsd/etc/newsyslog.conf`, described in `docs/threat-model.md`) |
| Triage classifier decisions and scores | Art 6(1)(b) contract, as part of delivering the mail service | The policy should still describe the classifier. It files messages and does not decide anything with legal effect, so Article 22 should not apply, but that is a judgement, not a quotation *(interpretation)* |

Consent appears nowhere. Nothing in the service needs it *(interpretation)*: membership and
delivery rest on the contract, and logging rests on legitimate interests. Reaching for consent
would add a withdrawal path, a records burden and a second legal basis for the same operations,
for no gain.

### 2.4 Retention

[Article 5(1)(e)](https://www.legislation.gov.uk/eur/2016/679/article/5) requires data be "kept
in a form which permits identification of data subjects for no longer than is necessary for the
purposes for which the personal data are processed". The law sets no fixed periods: "The UK
GDPR does not set specific time limits for different types of data. This is up to you, and will
depend on how long you need the data for your specified purposes"
([ICO storage limitation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-protection-principles/a-guide-to-the-data-protection-principles/storage-limitation/)).
What Article 13 requires is that the published policy states the periods, so the schedule in
section 5 is the source for the privacy page rather than an internal note.

### 2.5 Records of processing

[Article 30(1)](https://www.legislation.gov.uk/eur/2016/679/article/30) requires a written
record of processing activities, and Article 30(5) exempts enterprises "employing fewer than
250 persons unless ... the processing is not occasional". Continuous self-serve signup,
provisioning, billing and log processing are not occasional, so the exemption does not apply and
the record is required even for a one-person business *(interpretation)*. The ICO says the same
and adds that documenting is good practice regardless
([ICO who needs to document their processing activities](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/documentation/who-needs-to-document-their-processing-activities/)).

### 2.6 The data protection fee is due, and is £52

The ICO states the duty plainly: "Under the Data Protection (Charges and Information)
Regulations 2018, organisations (including sole traders) that use personal information need to
pay a data protection fee, unless they are exempt"
([ICO data protection fee](https://ico.org.uk/for-organisations/data-protection-fee/)).

The amounts are set in the regulations themselves:
[reg 3(1)](https://www.legislation.gov.uk/uksi/2018/480/regulation/3) sets tier 1 at £52, tier 2
at £78 and tier 3 at £3,763, and reg 3(5) reduces the charge by £5 for direct debit. Tier 1
covers a controller with turnover of no more than £632,000 or no more than 10 members of staff
(reg 3(2)(a)). The ICO's guide repeats the same figures and the £5 direct debit discount
([ICO guide to the data protection fee](https://ico.org.uk/for-organisations/data-protection-fee/data-protection-fee/)),
and records that the fees rose on 17 February 2025
([ICO fee changes](https://ico.org.uk/for-organisations/data-protection-fee/changes-to-the-data-protection-fee/)).

The exemption is narrow and does not reach this service. Reg 2(1) exempts a controller only
where **all** its processing is exempt, and the exempt purposes in the
[schedule](https://www.legislation.gov.uk/uksi/2018/480/schedule/paragraph/2) are processing for
staff administration, for the controller's own "advertising, marketing and public relations",
for keeping accounts and records of transactions, and for deciding whether to accept a person as
a customer. Mailbox content, member account data, server logs and abuse monitoring fall outside
every one of those descriptions, so the fee is due and the tier is 1: £52, or £47 by direct
debit *(interpretation)*. Non-payment carries fines described by the ICO as ranging from £400 to
£4,000 ([ICO fee FAQs](https://ico.org.uk/for-organisations/data-protection-fee/faqs-data-protection-fee-payment-and-online-registration/)).

### 2.7 EU members: the representative question, answered

Selling to a consumer in the Union brings the EU GDPR in. Article 3(2)(a) applies where the
controller "offers goods or services" to data subjects in the Union, and recital 23 says that
holds "irrespective of whether connected to a payment", so a free account is as much in scope as
a paid one. The [copy on legislation.gov.uk](https://www.legislation.gov.uk/eur/2016/679/article/27)
is the retained UK version, which asks for a representative in the United Kingdom; the text that
binds a UK trader selling into the Union asks for
[a representative in the Union](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32016R0679)
(OJ L 119, 4.5.2016, Article 27(1)).

Article 27(2)(a) removes the duty only where the processing "is occasional", does not include or
is not likely to result in processing of "special categories of data" under Article 9(1) or of
"personal data relating to criminal convictions and offences" under Article 10, and is unlikely
to risk anyone's rights. Hosting a platform's own member accounts is continuous and is the
business itself, so the exemption does not apply and a representative is required
*(interpretation)*. Article 27(3) then fixes where: "The
representative shall be established in one of the Member States where the data subjects, whose
personal data are processed in relation to the offering of goods or services to them, or whose
behaviour is monitored, are." A firm sitting in a member state where the platform has no members
does not satisfy Article 27(3), whose words tie the representative to a state where the data
subjects are, so the person or firm has to be in a country a member actually lives in
*(interpretation)*. The privacy notice already has a slot for
this, because Article 13(1)(a) requires "the identity and the contact details of the controller
and, where applicable, of the controller's representative" (2.1).

None of this changes what the member experiences, and none of it applies to a release that
refuses Union applications outright. The release serves them, so the representative is an
operator action on the checklist before the first payment (#175), alongside setting up the
Monero wallet (#178).

### 2.8 The terms' one limit, and a data-subject request

Two further mechanics from #163 sit beside the representative. The terms state one limit on who
may apply: applications from residents of countries under UK sanctions are declined, checked at
approval against the consolidated list, and no other restriction is placed on where a member may
be. That wording belongs to the terms, drafted under #235 *(decision in #163)*. A data-subject
request is answered on the account page for export and delete, and by an operator-run script
with a written record for everything else, with the one-month deadline the Union sets stated in
the privacy notice. That path is specified in #241 *(decision in #163)*.

---

## 3. VAT

### 3.1 The threshold, and this revenue

[GOV.UK](https://www.gov.uk/register-for-vat): "You must register if either: your total taxable
turnover for the last 12 months goes over £90,000 ... or you expect your taxable turnover to go
over £90,000 in the next 30 days". The figures sit in
[VATA 1994 Schedule 1](https://www.legislation.gov.uk/ukpga/1994/23/schedule/1) para 1(1), which
applies liability "at the end of any month, if ... the value of his taxable supplies in the
period of one year then ending has exceeded £90,000" and "at any time, if ... there are
reasonable grounds for believing that the value of his taxable supplies in the period of 30 days
then beginning will exceed £90,000". The deregistration figure is £88,000 (paras 1(3), 4(1)), and
a taxable supply is "a supply of goods or services made in the United Kingdom other than an
exempt supply" ([s. 4(2)](https://www.legislation.gov.uk/ukpga/1994/23/section/4)).

At £20/yr, reaching £90,000 needs 4,500 members *(interpretation)*. Two qualifications: sales to
EU consumers have their place of supply in the member state, so their value does not count
towards the UK threshold *(interpretation of the place of supply rule in 3.4)*, and the
forward-look test means a price rise or a large prepaid block could trigger registration ahead
of the rolling year.

### 3.2 What Stripe issues per payment

Stripe's documentation: "Stripe creates receipts for all successful payments and refunds,
including invoice payments and recurring payments as part of a subscription", and receipts carry
the legal business name, support address, support email and the privacy policy URL
([Stripe receipts](https://docs.stripe.com/receipts)). Receipts are switched on in the Dashboard
settings and are sent only on success.

A receipt is not a VAT invoice, and this is not a gap while the trader is unregistered: a VAT
invoice is only obligatory for a taxable supply to another taxable person
([VAT Regulations 1995 reg 13(1)(a)](https://www.legislation.gov.uk/uksi/1995/2518/regulation/13)).
Stripe puts the compliance duty on the merchant: "You're responsible for verifying that the
invoices you issue meet local tax requirements"
([Stripe invoicing](https://docs.stripe.com/invoicing/customize)), and Stripe Tax likewise tells
merchants to "Register for tax in those locations" before it can help
([Stripe Tax](https://docs.stripe.com/tax/how-tax-works)). So: nothing to change per payment
today, and no VAT number on the receipts because there is none *(interpretation)*. An
unregistered trader must not show VAT, and must not describe a charge as including VAT.

### 3.3 Crossing the threshold

Registration is triggered by the tests in 3.1, and the mechanics are in Schedule 1: notify HMRC
within 30 days of the end of the relevant month, with registration effective from the end of the
following month (paras 5(1), 5(2)); the forward-look limb registers the trader from the start of
the 30-day period (paras 6(1), 6(2)). Once registered, VAT is charged at 20 per cent
([VATA 1994 s. 2(1)](https://www.legislation.gov.uk/ukpga/1994/23/section/2)), business customers
must be given a VAT invoice ([reg 13](https://www.legislation.gov.uk/uksi/1995/2518/regulation/13))
containing the particulars in [reg 14(1)](https://www.legislation.gov.uk/uksi/1995/2518/regulation/14)
(supplier name, address and registration number, the time of supply, the rate and amount of VAT,
and the total VAT "expressed in sterling"), and VAT records must be kept "for at least 6 years"
([GOV.UK keeping VAT records](https://www.gov.uk/charge-reclaim-record-vat/keeping-vat-records)).
Cancelling a registration is a request under Schedule 1 para 13, not an automatic step.
*(interpretation)* The £20 price is the whole of the work here: it either includes VAT, or it
rises to £24, and the prepaid rails in the map's scope have to quote the same number.

### 3.4 EU consumers: VAT from the first euro

This is the finding with product consequences. B2C electronically supplied services are taxed
where the consumer belongs, not where the supplier is:
[VATA 1994 Schedule 4A para 15](https://www.legislation.gov.uk/ukpga/1994/23/schedule/4A) states
that "a supply to a person who is not a relevant business person of services to which this
paragraph applies is to be treated as made in the country in which the recipient belongs", and
HMRC lists "website supply or web hosting services" among the digital services that fall under
these rules
([HMRC, VAT rules for supplies of digital services to consumers](https://www.gov.uk/guidance/the-vat-rules-if-you-supply-digital-services-to-private-consumers)).

HMRC's own instruction to a UK business in that position: "You must either: register for the
Non-Union VAT MOSS scheme in an EU member state; register for VAT in each EU member state where
you supply digital services to consumers." The old UK de minimis is gone: Schedule 4A para 15(3)
once disapplied the rule below £8,818 for supplies to relevant EU persons, and those paragraphs
were omitted with effect from 31 December 2020. The EU's €10,000 threshold in Article 59c of
Directive 2006/112/EC, inserted by
[Directive (EU) 2017/2455](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32017L2455),
only disapplies the destination rule where the supplier "is established or ... usually resides
only in one Member State", which a UK-established trader is not *(interpretation)*.

### 3.5 Registering, filing and pricing under the non-Union OSS

The scheme fits this trader exactly: "Any taxable person, not established in the EU, who supplies
services to non-taxable persons taking place in the EU, can register in the non-Union scheme"
([European Commission, The One Stop Shop](https://vat-one-stop-shop.ec.europa.eu/one-stop-shop_en)).
It is for services, so no intermediary is involved (that is the import scheme for goods), and the
member state of identification is a free choice: "a taxable person ... can choose any Member
State to be the Member State of identification", changeable at the end of any calendar quarter
([Register to OSS](https://vat-one-stop-shop.ec.europa.eu/one-stop-shop/register-oss_en)). The
scheme issues its own EU-format VAT number, and returns are quarterly. The OSS return is
additional to any domestic return, and there is none here, because UK registration is not
required at this revenue (3.1) *(interpretation)*.

The threshold in 3.4 does not rescue anyone: the €10,000 one applies only where the supplier is
established in a single member state, and a UK trader is not. The timing, however, is
forgiving, and it is what makes opening applications before registering safe: registration
normally begins with the next quarter, but "there may be situations in which a taxable person
starts making supplies under the scheme before this date. If this is the case, then the taxable
person can start using the scheme from the date of that first supply, provided he has informed
the Member State of identification that he has started activities under the scheme by the tenth
day of the month following that first supply." Miss that deadline and the trader "is required to
register and account for the VAT in the Member State(s) of consumption directly"
*(interpretation: notify the day the first Union payment lands, not later)*.

Two pieces of evidence fix the consumer's country, and HMRC names them: "at the point of sale,
ask the consumer for details of either their billing address, including the country, or their
telephone number", and from the payment provider "a notification advice containing the 2-digit
country code of the consumer's country of residence"
([HMRC](https://www.gov.uk/guidance/the-vat-rules-if-you-supply-digital-services-to-private-consumers)).
A card payment through Stripe supplies both without the platform asking anything of its own, and
the signup form carries no country field, so the member record holds no location
*(interpretation)*. A prepaid member supplies neither, so the platform has to keep the evidence
itself, which is on the accountant list in section 6.

Which of the services are electronically supplied is only half settled. HMRC names "website
supply or web hosting services" in the list, so the bundle the platform sells is a digital
service and VAT is due from the first euro for a Union consumer *(interpretation)*. Whether mail
hosting alone would be, and whether a £20 bundle of three services is one supply or three, stay
with the accountant *(interpretation)*.

The price keeps its shape: the member pays the number on the site, and the destination rate is
taken out of the £20 rather than added on top, so no page needs an asterisk and no prepaid quote
changes *(decision in #163, and the terms carry the wording under #235)*. On the card rail
Stripe Tax computes the destination rate, having already been pointed
at the fact that the merchant must be registered for it to help (3.2). If Union membership grows
to where the absorbed rate matters, the pricing decision is revisited rather than the promise.

Regimes beyond the Union and the UK are not examined here. The release serves any country, so the
map carries them as its own ticket.

---

## 4. Sole trader specifics

### 4.1 What has to be published

[E-Commerce (EC Directive) Regulations 2002 reg 6(1)](https://www.legislation.gov.uk/uksi/2002/2013/regulation/6)
requires a person providing an information society service to make available, "in a form and
manner which is easily, directly and permanently accessible", the name of the service provider,
the geographic address at which it is established, and details including an email address "which
make it possible to contact him rapidly and communicate with him in a direct and effective
manner". Reg 6(1)(g) requires the VAT identification number where the activity is subject to VAT.
Hosted mail, web hosting and git hosting are information society services, so this applies to a
sole trader with no intermediary *(interpretation)*.

[Provision of Services Regulations 2009 reg 8(1)](https://www.legislation.gov.uk/uksi/2009/2999/regulation/8)
adds the provider's name, "the provider's legal status and form", the geographic address and
contact details, and the VAT number where the activity is subject to VAT. For a sole trader,
"legal status and form" means stating that the provider is a sole trader rather than a company
*(interpretation)*. The same identity and address must appear in the pre-contract information for
the distance contract, through
[Schedule 2 paras (b) and (c)](https://www.legislation.gov.uk/uksi/2013/3134/schedule/2).

Invoices have their own requirement, which HMRC states for sole traders: the invoice must
include "your name and any business name being used" and "an address where any legal documents
can be delivered to you if you are using a business name"
([GOV.UK invoices: what they must include](https://www.gov.uk/invoicing-and-taking-payment-from-customers/invoices-what-they-must-include)).

### 4.2 What does not apply

A sole trader is not a company, so the company trading-disclosure rules do not attach:
[Companies Act 2006 s. 82](https://www.legislation.gov.uk/ukpga/2006/46/section/82) is the power
to require "companies" to state specified information, and
[s. 83](https://www.legislation.gov.uk/ukpga/2006/46/section/83) applies to legal proceedings by
a company to which s. 82 applies. There is no registered office to publish, no company number,
and no "registered in England and Wales" line *(interpretation)*. What remains is the geographic
address duty in 4.1, which a trading name does not discharge on its own.

### 4.3 The controller line, and the one registration duty

The privacy policy's controller line names the individual trader, at the address published under
4.1, with the contact email. That is Article 13(1)(a) applied to a sole trader, and it should be
the same identity the ICO register carries (2.2). The registration duty is the data protection
fee in 2.6: £52 at tier 1, paid annually, with the registration reference usable in the policy
but not required there.

---

## 5. Draft retention schedule

The numbers below are the ones the platform already implements, or has written down. "Repo"
means a file in this repository at this commit; the ADRs and the proposal live in the sibling
docs repository `../kyriakon/docs/decisions/`.

| Data | How long | Where the number comes from |
|---|---|---|
| Per-user log records: smtpd envelope, Dovecot authentication, sshd, nsd | 7 days | [newsyslog.conf](../../../openbsd/etc/newsyslog.conf) rotates `maillog`, `authlog` and `nsd.log` weekly with 7 generations; `docs/threat-model.md` calls this "the single place that enforces the retention window the threat model claims" |
| spamd greylist and whitelist entries | about 36 days on the whitelist | `docs/planning/research/spamd-greylisting.md`; `whiteexp` "defaults to ... 864 (hours, approximately 36 days)" ([spamd(8)](https://man.openbsd.org/spamd.8)). An anti-spam lifetime rather than a retention policy, as `docs/threat-model.md` says |
| Application data, rejected or abandoned | 90 days | proposal §5.9.1, "Rejected/abandoned application data is purged after 90 days"; ADR 0005 |
| Message text and application text seen by the triage classifier | 90 days | ADR 0005. Decisions, scores and outcome labels are kept, and fitted calibration scalars persist beyond the window |
| Account data after deletion: mailbox, git repos, web and gemini roots, OS account | deleted, admin-mediated, no scheduled window | proposal §5.9.1 account lifecycle, which names a `scripts/del-user.sh` that does not exist in either repository yet |
| Suspended account (AUP enforcement ladder) | 40-day grace, then deletion | `docs/aup.md`, "after a 40-day grace period, the account is deleted by the admin" |
| Account after failed renewal | read-only drop, email, 40 days, then human contact before deletion | proposal §5.9.1 account lifecycle |
| Encrypted backup repository, `/home` plus `/etc/mail` | up to about 7 months after the data leaves the live tree | [backup.sh](../../../scripts/backup.sh), `restic forget --keep-daily 30 --keep-weekly 8 --keep-monthly 6`. The oldest kept snapshot is the last one of the month six months back, so a file deleted today can survive in the repository for about seven months *(interpretation)* |
| Billing and accounting records | 5 years after the 31 January submission deadline for that tax year, and 6 years once VAT-registered | [GOV.UK business records if you're self-employed](https://www.gov.uk/self-employed-records/how-long-to-keep-your-records); [GOV.UK keeping VAT records](https://www.gov.uk/charge-reclaim-record-vat/keeping-vat-records) |
| Card data and payment records | never on the platform; held by Stripe | proposal §5.9.1 step 3, payment happens on Stripe's domain, so "the platform never touches card data, no PCI scope" |
| Country evidence for a prepaid Union member (3.5) | not yet settled; with the accountant | section 3.5 creates the class, because a prepaid payment carries neither of the two pieces of country evidence HMRC asks for, and section 6 carries the question |

Three things the schedule has to reconcile, and they are the reason it is a table rather than a
paragraph *(interpretation)*.

- **The backup window is the outlier.** Seven days, 90 days and 40 days are all shorter than
  about seven months. A privacy policy cannot say that deleting an account means the data is
  gone, because a deleted Maildir survives as ciphertext in the repository for months. The
  policy should name the backup window as the retention period for deleted account data, and
  `docs/transparency.md` should be worded to match.
- **A content-addressed repository cannot delete one member's files.** `backup.sh` states the
  consequence: "Retention is the purge mechanism". So the erasure answer for a member is the
  snapshot expiry, not an instant delete, and the account lifecycle's "GDPR erasure is a hard
  obligation" is discharged by the admin-mediated deletion the proposal describes plus the
  window.
- **HMRC outlives the backup.** Five years of self-employed records, or six years once VAT is
  registered, is longer than the repository keeps anything. If billing records live only inside
  the backed-up tree, the purge in `backup.sh` deletes records HMRC can ask for. Either keep the
  accounting records outside the purge path, or accept that they have to be exported before the
  window closes.

---

## 6. What needs a lawyer or an accountant

- Whether the hosted service is a service, digital content, or both, for the purpose of
  [reg 36](https://www.legislation.gov.uk/uksi/2013/3134/regulation/36) and
  [reg 37](https://www.legislation.gov.uk/uksi/2013/3134/regulation/37), and whether the waiver
  wording in 1.3 is enough. The two provisions give different answers about a member who cancels
  on day three.
- Which of the three services is electronically supplied on its own, and whether the £20 bundle
  is a single supply or several, now that the registration route is settled as the non-Union OSS
  (3.5).
- Who acts as the Union representative, established in a member state where members actually
  live, as Article 27(3) requires (2.7).
- Whether the triage classifier needs anything beyond a description in the policy (2.3).
- The DMCCA subscription regime's commencement, if the release date moves near spring 2027 (1.5).
- Whether the prepaid rails, as distinct from card payments, bring any regime of their own. The
  map puts them in scope; nothing in this note examines them. They also cannot produce the two
  pieces of country evidence HMRC asks for, so what a prepaid Union member's record has to carry
  is an accountant question (3.5).
- The domestic consumer law of each member state, which this note does not examine. It reads the
  UK regime and the Union instruments, so the choice of Scottish law and the mandatory rights a
  Union consumer keeps need a lawyer's read (#235).

---

## 7. Primary sources

Legislation, in the order it is used:

- [Consumer Contracts (Information, Cancellation and Additional Charges) Regulations 2013, SI 2013/3134](https://www.legislation.gov.uk/uksi/2013/3134/contents): regs 4, 13, 16, 18, 19, 27, 29, 30, 31, 32, 34, 36, 37, Schedules 2 and 3.
- [Consumer Rights Act 2015](https://www.legislation.gov.uk/ukpga/2015/15/contents): ss. 42, 49, 54, 56.
- [Digital Markets, Competition and Consumers Act 2024](https://www.legislation.gov.uk/ukpga/2024/13/contents): Part 4 Chapter 2, s. 339; [SI 2025/272](https://www.legislation.gov.uk/uksi/2025/272/regulation/2/made); [SI 2026/284](https://www.legislation.gov.uk/uksi/2026/284/regulation/2).
- [UK GDPR, Regulation (EU) 2016/679 as retained](https://www.legislation.gov.uk/eur/2016/679/contents): Articles 5, 6, 13, 30.
- [Data Protection (Charges and Information) Regulations 2018, SI 2018/480](https://www.legislation.gov.uk/uksi/2018/480/contents): regs 2, 3 and the schedule.
- [Electronic Commerce (EC Directive) Regulations 2002, SI 2002/2013](https://www.legislation.gov.uk/uksi/2002/2013/regulation/6): reg 6.
- [Provision of Services Regulations 2009, SI 2009/2999](https://www.legislation.gov.uk/uksi/2009/2999/regulation/8): reg 8.
- [Value Added Tax Act 1994](https://www.legislation.gov.uk/ukpga/1994/23/contents): ss. 2, 3, 4, 7A, Schedules 1 and 4A.
- [Value Added Tax Regulations 1995, SI 1995/2518](https://www.legislation.gov.uk/uksi/1995/2518/contents): regs 13, 14.
- [Companies Act 2006](https://www.legislation.gov.uk/ukpga/2006/46/contents): ss. 82, 83.
- [Directive (EU) 2017/2455](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32017L2455), inserting Article 59c into Directive 2006/112/EC.
- [Regulation (EU) 2016/679, as it stands in the Union](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32016R0679), OJ L 119, 4.5.2016: Articles 3(2) and 27, recitals 23 and 24, read against the [retained UK version](https://www.legislation.gov.uk/eur/2016/679/article/27).

Regulators and processors:

- ICO: [data protection fee](https://ico.org.uk/for-organisations/data-protection-fee/), [guide to the fee](https://ico.org.uk/for-organisations/data-protection-fee/data-protection-fee/), [fee changes](https://ico.org.uk/for-organisations/data-protection-fee/changes-to-the-data-protection-fee/), [fee FAQs](https://ico.org.uk/for-organisations/data-protection-fee/faqs-data-protection-fee-payment-and-online-registration/), [right to be informed](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/what-privacy-information-should-we-provide/), [storage limitation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-protection-principles/a-guide-to-the-data-protection-principles/storage-limitation/), [lawful basis](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/lawful-basis/a-guide-to-lawful-basis/), [records of processing](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/documentation/who-needs-to-document-their-processing-activities/), [register of fee payers](https://ico.org.uk/about-the-ico/what-we-do/register-of-fee-payers/).
- European Commission: [The One Stop Shop](https://vat-one-stop-shop.ec.europa.eu/one-stop-shop_en) and [Register to OSS](https://vat-one-stop-shop.ec.europa.eu/one-stop-shop/register-oss_en), for the non-Union scheme, the free choice of identification state, the quarterly return and the first-supply window.
- HMRC and GOV.UK: [register for VAT](https://www.gov.uk/register-for-vat), [digital services to consumers](https://www.gov.uk/guidance/the-vat-rules-if-you-supply-digital-services-to-private-consumers), [keeping VAT records](https://www.gov.uk/charge-reclaim-record-vat/keeping-vat-records), [self-employed records](https://www.gov.uk/self-employed-records/how-long-to-keep-your-records), [invoices](https://www.gov.uk/invoicing-and-taking-payment-from-customers/invoices-what-they-must-include), [online and distance selling](https://www.gov.uk/online-and-distance-selling-for-businesses), [subscription contracts consultation response](https://www.gov.uk/government/consultations/consultation-on-the-implementation-of-the-new-subscription-contracts-regime/outcome/government-response-to-consultation-on-the-implementation-of-the-new-subscription-contracts-regime-web-accessible-version).
- Stripe: [receipts](https://docs.stripe.com/receipts), [invoicing](https://docs.stripe.com/invoicing/customize), [how tax works](https://docs.stripe.com/tax/how-tax-works).
- OpenBSD: [spamd(8)](https://man.openbsd.org/spamd.8).

Repo files reconciled in section 5: `openbsd/etc/newsyslog.conf`, `scripts/backup.sh`,
`scripts/del-user.sh`, `docs/aup.md`, `docs/threat-model.md`, `docs/transparency.md`,
`docs/planning/research/spamd-greylisting.md`, and in the sibling docs repo ADR 0005 and
`kyriakon-net-project-proposal.md` §5.9.1.
