# Worldwide obligations: the data protection and indirect tax regimes outside the UK and the EU

**Question:** one UK sole trader sells hosted mail, static web hosting, gemini hosting and
`pass` git repos to consumers anywhere, at £20 a year for an individual, £40 for an
organisation's own domain and £150 or more for a managed instance, with a free tier for
clergy, monastics and those without means. Payment is by card or by a prepaid rail. The
first year is expected to bring tens of members. Which data protection and indirect tax
regimes outside the UK and the EU reach that business?

**Answer:** the UK position and the EU position are settled in the companion note
`sole-trader-obligations.md`, as amended by PR #242 for ticket #163, and are not restated
here. Outside those two, the answer has three parts.

1. **Data protection is not exhausted by the UK GDPR and the EU GDPR.** Five regimes apply
   at any scale, with no revenue or volume threshold. Canada's PIPEDA applies where the
   processing has a real and substantial connection to Canada. Switzerland's revised FADP
   applies where the processing has an effect in Switzerland. Brazil's LGPD applies where
   the processing is aimed at offering goods or services to people in Brazil. Japan's APPI
   applies where the business supplies a person in Japan. India's DPDP Act will apply to
   the same kind of offer when section 3 commences, on or about 13 May 2027. Two size-based
   regimes do not reach a business of this size: California's CCPA as amended by the CPRA
   starts at [USD 26,625,000](https://cppa.ca.gov/regulations/cpi_adjustment.html) of revenue
   or [100,000 consumers or households](https://cppa.ca.gov/pdf/20260101_ccpa_statute.pdf),
   and the Australian Privacy Act leaves a small business operator
   turning over [AUD 3,000,000](https://www.legislation.gov.au/C2004A03712/latest) or less
   outside the Australian Privacy Principles.
2. **On indirect tax, one jurisdiction among those examined charges from the first sale.**
   The regimes are the ones the ticket named, so the list is a floor rather than a ceiling
   and a jurisdiction outside it is not examined; another country may charge from the first
   sale without appearing here. India taxes online information and database access or
   retrieval services supplied from outside the country to an unregistered recipient, with
   no turnover floor, so a UK supplier of hosted services to an Indian consumer must take
   an Indian registration. Norway's
   [NOK 50,000](https://lovdata.no/dokument/NL/lov/2009-06-19-58) over twelve months is the
   only other threshold a first year of tens of members could approach. Canada, New
   Zealand, Australia, Switzerland, Japan and Singapore each set a figure, from Canada's
   [CAD 30,000](https://laws-lois.justice.gc.ca/eng/acts/E-15/section-211.12.html) to
   Singapore's [SGD 1,000,000](https://www.iras.gov.sg/taxes/goods-services-tax-(gst)/gst-and-digital-economy/overseas-businesses),
   all far above the scale this release expects. The figures are in the table.
3. **What the release does with each regime is in the table in section 3.** It registers
   for Indian GST, it publishes the notice lines the in-scope privacy regimes need, and it
   writes down the ceiling for every threshold regime so that crossing one is a decision
   rather than an accident.

**How to read the sourcing.** Every threshold below carries a link to the primary source,
and section 5 records the date each source was checked. Legislation is read from the
official gazette or the official consolidated text. Regulator guidance is used where it
states the figure the regulator administers, and the note says so where the underlying
statute could not be reached. Sentences marked *(interpretation)* apply that law to this
platform and are a reading, not a quotation. Nothing here is legal advice, and section 4
lists the questions that need a lawyer or an accountant.

---

## 1. Data protection

### 1.1 The shape of the question

A foreign data protection law can reach a UK business in one of two ways. The first is by
connection: if the business offers a service to people in the country, the law applies, and
the statute contains no revenue or volume test at all. The second is by size: the statute
names a revenue, turnover or volume figure, and a business below every figure in the test
is outside the law. The regimes this ticket asks about split cleanly into those two groups,
and the split decides the work. A connection-based regime has to be complied with from the
first member in that country. A size-based regime only has to be watched.

The ticket also asks which regimes are about consumers and which are about customers of any
kind. The CCPA is the only one here whose unit is the consumer: it counts consumers or
households. Every other regime attaches to personal information about an individual, so a
customer of any kind is inside it. PIPEDA's personal information, the FADP's and the LGPD's
natural persons, the DPDP Act's Data Principal and the APPI's person in Japan all cover a
sole trader, an employee or a business contact, and the Australian Privacy Act does the
same, although its size threshold keeps it out of reach here.

### 1.2 Regimes that apply at any scale

#### Canada: PIPEDA and the real and substantial connection test

[Section 4(1)](https://laws-lois.justice.gc.ca/eng/acts/P-8.6/section-4.html) applies
PIPEDA to "every organization in respect of personal information that the organization
collects, uses or discloses in the course of commercial activities", and there is no
revenue or volume threshold anywhere in it. What decides whether it reaches a UK business
is the real and substantial connection test the Office of the Privacy Commissioner applied
to SWIFT, a Belgian cooperative. The OPC listed the links it counted: SWIFT collected
personal information from and disclosed it to Canadian banks, charged them a fee, had
fourteen Canadian shareholders, and was an integral part of the Canadian financial system,
and on those links the Commissioner found SWIFT "was engaged in a commercial activity
within Canada" and subject to PIPEDA
([OPC, Leading by Example](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/r_o_p/lbe_080523/),
section 2.2). The same report records that in *Lawson v. Accusearch* the Federal Court held
PIPEDA can cover a foreign entity that collects and discloses personal information about
individuals in Canada, while leaving open which connecting factors are enough. On that
approach a UK host with a handful of Canadian members is at the thin end of the test, and
the OPC has asserted jurisdiction on less *(interpretation)*.

The duties themselves are the ones the UK GDPR already imposes: identify the purpose,
obtain consent, limit collection, safeguard the data, answer access and correction
requests, and provide a route to challenge compliance. The marginal work is the report to
the OPC where a breach of security safeguards creates a real risk of significant harm
([section 10.1](https://laws-lois.justice.gc.ca/eng/acts/P-8.6/section-10.1.html)). The
OPC's [summary of privacy laws in Canada](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/02_05_d_15/)
records that Alberta, British Columbia and Quebec have private-sector laws declared
substantially similar, which apply instead of PIPEDA where an organisation operates
entirely inside the province; a UK business serving members across borders stays on
PIPEDA *(interpretation)*.

#### Switzerland: the revised FADP follows the effect

[Article 3(1)](https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2022/491/20230901/en/pdf-a/fedlex-data-admin-ch-eli-cc-2022-491-20230901-en-pdf-a.pdf)
of the Federal Act on Data Protection provides that it "applies to circumstances that have
an effect in Switzerland, even if they were initiated abroad", and neither Article 2 nor
Article 3 contains a revenue or volume threshold. Two provisions matter for this platform.
Article 14 requires a controller with its registered office or domicile abroad to appoint a
Swiss representative only where the processing is connected with an offer to people in
Switzerland, is on a large scale, is regular and poses a high risk. A service with tens of
members fails the large-scale limb, so the representative duty does not apply
*(interpretation)*. Article 12(5) lets the Federal Council exempt legal entities with fewer
than 250 employees from the record of processing activities; that is a power about legal
entities, and a sole trader is not one, so the record duty is not displaced by that
provision *(interpretation)*. The rest of the Act (information duties, breach notification,
access and erasure) has the same shape as the UK GDPR duties the release already meets.
The English text on Fedlex is a translation with no legal force.

#### Brazil: LGPD follows the offer

[Article 3](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/L13709.htm) of
the Lei Geral de Proteção de Dados applies to any processing, "independentemente do meio,
do país de sua sede ou do país onde estejam localizados os dados", where the processing
aims at offering or supplying goods or services to individuals located in Brazil. There is
no threshold. The ANPD's small-processing-agent regime in
[Resolução CD/ANPD nº 2/2022](https://www.in.gov.br/web/dou/-/resolucao-cd/anpd-n-2-de-27-de-janeiro-de-2022-376562019)
lightens some duties, but it is defined by Brazilian legal forms: microempresas, empresas
de pequeno porte and startups registered in Brazil. A UK sole trader does not fit that
definition, so the lighter regime is not available to it *(interpretation)*. The
consequence that lands on the site is
[Article 41](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/L13709.htm):
the controller must appoint an encarregado and publish the identity and contact details,
"preferencialmente no sítio eletrônico do controlador".

#### India: the DPDP Act and its staged commencement

[Section 3(b)](https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf)
applies the Digital Personal Data Protection Act, 2023, to processing outside India "if
such processing is in connection with any activity related to offering of goods or services
to Data Principals within the territory of India". There is no threshold. The Act is
staged into force by [notification G.S.R. 843(E) of 13 November 2025](https://www.meity.gov.in/static/uploads/2025/11/c56ceae6c383460ca69577428d36828b.pdf):
sections 2 and 18 to 26 commenced that day, and sections 3 to 5, 6 except sub-section (9),
and 7 to 17 commence eighteen months later, on or about 13 May 2027. The copy of the Act
reached is the 2024 upload, which predates the notification and cannot carry it, so the
dates rest on the notification rather than on a footnote to the Act. As of 5 October 2026
the extraterritorial limb is therefore not yet operative. When it commences, section 5
requires a notice describing the personal data, the purpose, the manner of exercising
rights and the manner of complaining to the Data Protection Board, and section 5(3)
requires the Data Principal to be able to access that notice "in English or any language
specified in the Eighth Schedule to the Constitution". Section 6 requires consent that is
"free, specific, informed, unconditional and unambiguous with a clear affirmative action". A
signup flow built for the UK GDPR covers most of this, but the notice wording and the
language option are additions
*(interpretation)*.

#### Japan: the APPI follows the supply to a person in Japan

[Article 171](https://www.japaneselawtranslation.go.jp/en/laws/view/4241/en) applies the Act
on the Protection of Personal Information where, "in relation to supplying a good or service
to a person in Japan", a business handles that person's identifiable personal information
in a foreign country. There is no threshold: Article 16(2) defines a business handling
personal information as a person that uses a personal information database for business,
and the only exclusions are government bodies. The duties that add to a UK GDPR policy
are the notification of the purpose of use when personal information is acquired
(Article 21), the restrictions on providing personal data to third parties (Article 27) and
to third parties in a foreign country (Article 28), and the disclosure, correction and
cessation routes (Articles 32 to 35). The breach report to the Personal Information
Protection Commission is triggered by a leak affecting more than 1,000 data subjects
([PPC leak reporting page](https://www.ppc.go.jp/personalinfo/legal/leakAction/)), a figure
this release will not approach *(interpretation)*.

### 1.3 Regimes with a size threshold this release is nowhere near

#### California: CCPA as amended by CPRA

[Section 1798.140(d)(1)](https://cppa.ca.gov/pdf/20260101_ccpa_statute.pdf) defines a
business as an entity that does business in California and satisfies "one or more" of three
thresholds: annual gross revenues in excess of USD 25,000,000 in the preceding calendar year,
as adjusted; alone or in combination annually buying, selling or sharing the personal
information of 100,000 or more consumers or households; or deriving 50 percent or more of
annual revenues from selling or sharing consumers' personal information. The CPPA's
[current published adjustment](https://cppa.ca.gov/regulations/cpi_adjustment.html) sets
the revenue figure at USD 26,625,000 from 1 January 2025. The platform meets none of the three
at tens of members, and it does not sell or share personal information at all
*(interpretation)*, so the CCPA places no duty on this release. Reaching the revenue limb
would need more than a million members at £20 a year *(interpretation)*.

#### Australia: the small business exemption in section 6D

[Section 6D(1)](https://www.legislation.gov.au/C2004A03712/latest) provides that "a business
is a small business at a time ... in a financial year ... if its annual turnover for the
previous financial year is AUD 3,000,000 or less", and section 6C leaves a small business
operator out of the definition of "organisation", so the Australian Privacy Principles do
not bind it. Section 6D(4) removes the exemption for a business that provides a health
service, discloses personal information to anyone else for a benefit, service or advantage,
provides a benefit to collect personal information, is a contracted service provider for a
Commonwealth contract, or is a credit reporting body. A paid hosting service does none of
those things, and its turnover is orders of magnitude below AUD 3,000,000, so the exemption
covers the release *(interpretation)*. Section 5B gives the Act an extraterritorial
operation, but that question does not arise while section 6D applies.

---

## 2. Indirect tax

### 2.1 Two shapes, and what each means here

A country taxes a foreign supplier of hosted services in one of two ways. It either charges
from the first sale to a consumer, or it sets a turnover figure below which the foreign
supplier is left alone. Only India uses the first shape among the regimes this ticket
lists, and the list is a floor rather than a ceiling: the ticket named these eight
jurisdictions, and one outside them is not examined. Every other regime has a figure, and
the figures range from NOK 50,000 to SGD 1,000,000, so the practical question is not whether
the release is liable but how far away each ceiling is. The regimes are also not drawn the
same way around the consumer. India and Australia turn on whether the recipient is
registered, so an unregistered business is caught as much as an individual, while Japan,
Singapore, Norway and Switzerland reach only the consumer or the non-business recipient.
Canada and New Zealand are described in terms of the customer to whom the supply is made,
which does not settle where their line falls. Sales to local registered businesses fall to
the reverse charge or outside the scheme, which matters little here because the platform
sells to individuals *(interpretation)*.

Switzerland alone measures its figure differently: the CHF 100,000 is worldwide turnover, so
business sales and sales outside Switzerland count toward it, and the ceiling is not
confined to Swiss consumers. The distance, at £20 a member and a rough rate to sterling, is
about 190 members for Norway, about 800 for Canada, about 1,350 for New Zealand, about 1,900
for Australia, about 2,600 for Japan and about 4,600 for Switzerland *(interpretation,
rounded, and the figures count members in the country concerned, except Switzerland's,
which is worldwide)*. California's revenue limb is further away again.

### 2.2 India: no threshold, so the first sale is the trigger

[Section 14(1)](https://indiacode.gov.in/server/api/core/bitstreams/c34dadd9-0609-4cd5-89c5-2f6750daa70b/content)
of the Integrated Goods and Services Tax Act, 2017 makes the foreign supplier itself "the
person liable for paying integrated tax" on a supply of online information and database
access or retrieval services to a non-taxable online recipient, and section 14(2) requires
that supplier to "take a single registration under the Simplified Registration Scheme".
There is no turnover figure in section 14. The taxed service is defined in section 2(17) to
include "providing cloud services", "providing data or information, retrievable or
otherwise, to any person in electronic form through a computer network" and "digital data
storage", so hosted mail, web and git hosting are of that character *(interpretation)*. A
recipient registered under the ordinary GST regime is not a non-taxable online recipient,
so sales to Indian businesses are outside this charge.

In practice, [rule 14(1)](https://indiacode.gov.in/server/api/core/bitstreams/a500c9f2-d982-4cdd-a1e5-9a5f7cd449e7/content)
of the Central Goods and Services Tax Rules, 2017 requires the supplier to submit an
application in FORM GST REG-10 at the common portal, verified by electronic verification
code, and [rule 64](https://indiacode.gov.in/server/api/core/bitstreams/a500c9f2-d982-4cdd-a1e5-9a5f7cd449e7/content)
requires a return in FORM GSTR-5A "on or before the twentieth day of the month succeeding
the calendar month or part thereof". Section 14(2) also provides that where the supplier has
no physical presence and no representative in India, it may appoint a person in India to
pay the tax. The rules as read state no lead time before the first supply, and the CBIC's
own guidance could not be reached to confirm whether a later amendment added one.

### 2.3 Norway: NOK 50,000, and a UK exemption from the representative rule

[Section 2-1(1)](https://lovdata.no/dokument/NL/lov/2009-06-19-58) of the Norwegian VAT Act
requires registration once turnover and withdrawals "til sammen har oversteget 50.000
kroner i en periode på tolv måneder", and section 2-1(3) brings supplies of the services
covered by section 3-30 to non-business recipients inside that rule, so the same threshold
applies. The Tax Administration states the figure in the same terms and adds that a
business may register from its first sale
([VOEC registration](https://www.skatteetaten.no/en/business-and-organisation/vat-and-duties/vat/foreign/e-commerce-voec/register/)).
Remotely deliverable services, including electronic ones, are the subject, and hosting is
delivered that way *(interpretation)*.

Two provisions save work. Section 14-4 provides a simplified registration scheme for a
supplier with no place of business in Norway, with all communication electronic, and no
deduction for input VAT but a refund route. Section 2-1(6) requires a foreign taxable
person to register through a representative, then disapplies that duty for a business
resident in an EEA state "eller Storbritannia", so a UK sole trader does not need a
Norwegian representative. Filing is quarterly, by the 20th of the month after the quarter,
through the VOEC portal.

### 2.4 Canada: CAD 30,000 over twelve months

[Section 211.12(2)](https://laws-lois.justice.gc.ca/eng/acts/E-15/section-211.12.html) of
the Excise Tax Act requires a specified non-resident supplier to register where its
"threshold amount ... for any period of 12 months ... exceeds \$30,000", and section
211.12(1) defines that threshold amount as the value of specified supplies made to
specified Canadian recipients. The CRA's
[threshold page](https://www.canada.ca/en/revenue-agency/services/tax/businesses/topics/gst-hst-businesses/digital-economy-gsthst/find-out-need-register.html)
states the same figure and confirms that only Canadian-facing supplies count, so a UK
business does not add up worldwide revenue to reach it. A "specified supply" is a taxable
supply of intangible personal property or a service, which covers the hosted services
*(interpretation)*. Registration is the simplified GST/HST registration, reporting runs on
the calendar quarter, the return is due one month after the period, filing is by NETFILE,
and the registrant claims no input tax credits
([CRA, filing a simplified return](https://www.canada.ca/en/revenue-agency/services/tax/businesses/topics/gst-hst-businesses/digital-economy-gsthst/file-return.html)).

### 2.5 Australia: AUD 75,000 of Australian-connected turnover

[Section 23-15](https://www.legislation.gov.au/C2004A00446/latest) of the Goods and Services
Tax Act 1999 sets the registration turnover threshold at AUD 50,000 or "such higher amount as
the regulations specify", and the ATO states the operative figure for a non-resident as
AUD 75,000 of GST turnover from sales connected with Australia, measured on current or
projected turnover and after excluding sales to GST-registered businesses buying for
business use
([ATO, how Australian GST works](https://www.ato.gov.au/businesses-and-organisations/international-tax-for-business/gst-for-non-resident-businesses/how-australian-gst-works)).
GST has applied to imported services and digital products sold to Australian consumers
since 1 July 2017, which the ATO calls inbound intangible consumer supplies
([ATO, GST on imported services and digital products](https://www.ato.gov.au/businesses-and-organisations/international-tax-for-business/gst-for-non-resident-businesses/gst-on-imported-services-and-digital-products)).
A non-resident may take simplified GST registration, which makes it a limited registration
entity with quarterly tax periods and no input tax credits, and register, lodge and pay
online ([ATO, simplified GST registration](https://www.ato.gov.au/businesses-and-organisations/international-tax-for-business/gst-for-non-resident-businesses/gst-registration-for-non-resident-businesses/simplified-gst-registration)).

### 2.6 New Zealand: NZD 60,000

The Inland Revenue Department states the rule as "you must register for and charge GST when
your total supplies of goods and services to New Zealand customers either were more that
\$60,000 in the last 12 months, or are expected to be more than \$60,000 in the next 12
months", for a non-resident supplying remote services from outside New Zealand to New
Zealand tax resident customers
([IRD, supplying remote services](https://www.ird.govt.nz/gst/gst-for-overseas-businesses/supplying-remote-services-into-new-zealand)).
The IRD names website design and web publishing among its examples and cites section 8(2)
to (4) of the Goods and Services Tax Act 1985 for the place of supply; hosting is consumed
remotely, which brings it inside the description *(interpretation)*. Registration is in
myIR or on form IR994, and returns are quarterly. The statutory text on legislation.govt.nz
sits behind a JavaScript challenge and could not be fetched, so the figure is cited to the
IRD rather than to the Act.

### 2.7 Japan: JPY 10,000,000 of Japanese taxable sales

The National Tax Agency states that "a business with taxable sales not exceeding 10 million
yen in the base period for the taxable period is exempt from consumption tax obligation",
and that for a foreign business providing only electronic services the taxable sales are
those from B2C electronic services provided within Japan, with B2B sales excluded
([NTA, consumption tax implication for cross-border supplies of services](https://www.nta.go.jp/english/taxes/consumption_tax/0024006-219.pdf)).
The NTA names "providing cloud services" and "storage space to save their electronic data
in the cloud" as covered, and excludes services that merely mediate transmission, so the
hosted services are in scope and a bare mail-relay reading is not *(interpretation)*. A
sole proprietor without domicile or residence in Japan must designate a Tax Agent, and the
foreign business files and pays in Japan. Platform taxation, effective 1 April 2025, shifts
that duty only where a designated platform collects the price, which is not this case. The
FY2025 and FY2026 reform outlines contain no change to the 10 million yen threshold
([MOF FY2025 key points](https://www.mof.go.jp/english/policy/tax_policy/tax_reform/fy2025/07keyhighlight.pdf),
[MOF FY2026 outline](https://www.mof.go.jp/tax_policy/tax_reform/outline/fy2026/08taikou_04.htm)).

### 2.8 Switzerland: CHF 100,000 of worldwide turnover

[Article 10(2)(a)](https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2009/615/20240101/en/html/fedlex-data-admin-ch-eli-cc-2009-615-20240101-en-html-4.html)
of the Value Added Tax Act exempts a person whose turnover on Swiss territory and abroad
from non-exempt supplies is less than 100,000 francs within a year, and Article 10(2)(b)(2)
removes the foreign-supplier exemption for a business supplying telecommunication or
electronic services to recipients who are not liable to the tax. Above the threshold,
therefore, the platform is liable on sales to Swiss consumers. Article 67(1) requires a
taxable person without a Swiss domicile, registered office or permanent establishment to
appoint a representative, and Articles 34(2) and 35(1) make the tax period the calendar
year with quarterly reporting. Unlike Norway, the Act carries no United Kingdom exemption
from that representative duty *(interpretation)*.

### 2.9 Singapore: SGD 1,000,000 and SGD 100,000

The Inland Revenue Authority of Singapore states that "overseas businesses with an annual
global turnover exceeding S\$1 million and that make B2C supplies of remote services and/or
low-value goods to customers in Singapore exceeding SGD 100,000 annually, will be required to
register for GST"
([IRAS, overseas businesses](https://www.iras.gov.sg/taxes/goods-services-tax-(gst)/gst-and-digital-economy/overseas-businesses)).
Web hosting is named in the IRAS list of electronic data management services, and email
hosting is not named, but both are remote services on the IRAS definition
*(interpretation)*. Registration is the overseas vendor registration, the regime is
pay-only with no input tax claims, and filing is electronic.

---

## 3. What the release does

Three values are used in the action column. "Register" means the release must hold a local
registration before or at the first sale. "State a limit" means the release publishes the
ceiling it works under, or the position it takes, so that crossing the ceiling is a
decision. "Nothing" means neither a registration nor a publication is needed, because the
regime does not reach this release or the release already does the work.

| Regime | Threshold | Reaches this product | Action | Why |
|---|---|---|---|---|
| California, CCPA as amended by CPRA | [USD 26,625,000](https://cppa.ca.gov/regulations/cpi_adjustment.html) of revenue, or [100,000 consumers or households](https://cppa.ca.gov/pdf/20260101_ccpa_statute.pdf), or 50 percent of revenue from selling or sharing | No | Nothing | every limb is out of reach, and the platform sells no personal information |
| Canada, PIPEDA | [None](https://laws-lois.justice.gc.ca/eng/acts/P-8.6/section-4.html) | Yes, where the connection is real and substantial | State a limit | the policy states the OPC route, and the release reports a harmful breach to the OPC |
| Australia, Privacy Act 1988 | [AUD 3,000,000 annual turnover](https://www.legislation.gov.au/C2004A03712/latest) for the small business exemption | No | Nothing | turnover is far below the exemption, and none of the section 6D(4) carve-outs is known to apply, with the processor-disclosure reading left open in section 4 |
| Switzerland, revised FADP | [None](https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2022/491/20230901/en/pdf-a/fedlex-data-admin-ch-eli-cc-2022-491-20230901-en-pdf-a.pdf) | Yes | Nothing | the duties match the UK GDPR ones already in place, and the representative duty needs large-scale processing |
| Brazil, LGPD | [None](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/L13709.htm) | Yes | State a limit | Article 41 requires a published encarregado, and the small-agent relief is keyed to Brazilian legal forms |
| India, DPDP Act 2023 | [None](https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf) | Yes, when section 3 commences | State a limit | the notice and consent wording, with the scheduled-language option, has to be ready before 13 May 2027 |
| Japan, APPI | [None](https://www.japaneselawtranslation.go.jp/en/laws/view/4241/en) | Yes | State a limit | the purpose-of-use notice and the disclosure and cessation routes need a Japanese-facing answer |
| India, OIDAR services | [None](https://indiacode.gov.in/server/api/core/bitstreams/c34dadd9-0609-4cd5-89c5-2f6750daa70b/content) | Yes | Register | liability runs from the first sale to an unregistered recipient, with no turnover floor |
| Norway, VAT | [NOK 50,000 over twelve months](https://lovdata.no/dokument/NL/lov/2009-06-19-58) | Yes, above the threshold | State a limit | closest ceiling to this release; the UK is exempt from the representative duty |
| Canada, GST/HST | [CAD 30,000 over twelve months](https://laws-lois.justice.gc.ca/eng/acts/E-15/section-211.12.html) | Yes, above the threshold | State a limit | only Canadian-facing supplies count toward the figure |
| Australia, GST | [AUD 75,000](https://www.ato.gov.au/businesses-and-organisations/international-tax-for-business/gst-for-non-resident-businesses/how-australian-gst-works) | Yes, above the threshold | State a limit | the test counts Australian-connected turnover only |
| New Zealand, GST | [NZD 60,000 over twelve months](https://www.ird.govt.nz/gst/gst-for-overseas-businesses/supplying-remote-services-into-new-zealand) | Yes, above the threshold | State a limit | the figure counts supplies to New Zealand tax residents |
| Japan, consumption tax | [JPY 10,000,000 in the base period](https://www.nta.go.jp/english/taxes/consumption_tax/0024006-219.pdf) | Yes, above the threshold | State a limit | the figure counts Japanese B2C taxable sales only |
| Switzerland, VAT | [CHF 100,000 of worldwide turnover](https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2009/615/20240101/en/html/fedlex-data-admin-ch-eli-cc-2009-615-20240101-en-html-4.html) | Yes, above the threshold | State a limit | the only threshold measured on worldwide turnover |
| Singapore, GST | [SGD 1,000,000 global turnover and SGD 100,000 of Singapore sales](https://www.iras.gov.sg/taxes/goods-services-tax-(gst)/gst-and-digital-economy/overseas-businesses) | Yes, above both | State a limit | both limbs have to be exceeded |

The one registration is the India OIDAR registration, and per
[Decide the indirect-tax registrations a worldwide release needs](https://github.com/kyriakon/kyriakon-infra/issues/249)
it is taken after the first Indian sale rather than before it: rule 10(2) of the CGST Rules
gives thirty days from the date online services begin in India to apply, and the registration
is backdated to that date when the reference number issues inside the window
([Research what taking an Indian OIDAR registration involves](https://github.com/kyriakon/kyriakon-infra/issues/264)).
So it is the one item in the table that has to be undertaken, and no item has to precede a sale. The notice additions are small: an encarregado line for Brazil, a
purpose-of-use and complaint line for Japan, and the DPDP notice in a scheduled language
for India once the provision commences. Everything else is a number written down so that
the release notices when it approaches one.

---

## 4. What needs a lawyer or an accountant

- Whether routine disclosures to processors, such as the payment rail and the backup
  target, count as disclosing personal information "for a benefit, service or advantage"
  under section 6D(4)(c) of the Australian Privacy Act. If they do, the small business
  exemption falls away and the Australian Privacy Principles bind the release.
- Whether the platform acts as controller or processor for each data set it holds. This
  note treats it as controller of account, billing and log data, and of the message text
  the triage model sees, which the companion note's retention schedule holds for 90
  days; the zero-access design keeps the rest of the message content out of its hands. The
  DPDP Act, the LGPD and the APPI draw the controller line differently from the UK GDPR
  *(interpretation)*.
- What "encarregado" means in practice for a one-person business in Brazil, and whether the
  ANPD would accept a named individual who is not resident in Brazil.
- Whether the DPDP notice in a scheduled language is a duty to translate or a duty to offer
  translation on request.
- Whether the Indian registration needs an Indian address or a person in India, and which
  of the two arrangements in section 14(2) the portal expects.
- Whether the three hosted services are one supply or several, which changes the threshold
  arithmetic in every regime above and is already an open question for the EU OSS in the
  companion note.
- How a prepaid member evidences the country of the customer for the thresholds that turn
  on the recipient's residence. The companion note records the same gap for the EU OSS, and
  the card rail solves it by itself.
- What a Japanese Tax Agent and a Swiss fiscal representative cost, since both become
  necessary only if their thresholds are crossed.

---

## 5. Primary sources

Each entry carries the date it was checked.

Data protection legislation:

- [PIPEDA, S.C. 2000, c. 5, section 4](https://laws-lois.justice.gc.ca/eng/acts/P-8.6/section-4.html) and [section 10.1](https://laws-lois.justice.gc.ca/eng/acts/P-8.6/section-10.1.html), checked 5 October 2026.
- [OPC, Leading by Example, section 2.2](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/r_o_p/lbe_080523/), checked 5 October 2026. The page is archived, and the real and substantial connection factors are stated there.
- [OPC, Summary of privacy laws in Canada](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/02_05_d_15/), checked 5 October 2026.
- [Swiss FADP, SR 235.1](https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2022/491/20230901/en/pdf-a/fedlex-data-admin-ch-eli-cc-2022-491-20230901-en-pdf-a.pdf), Articles 2, 3, 12 and 14, checked 5 October 2026. English text is a translation with no legal force.
- [Brazil LGPD, Lei 13.709/2018](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/L13709.htm), Articles 3 and 41, checked 5 October 2026.
- [ANPD, Resolução CD/ANPD nº 2/2022](https://www.in.gov.br/web/dou/-/resolucao-cd/anpd-n-2-de-27-de-janeiro-de-2022-376562019), checked 5 October 2026.
- [Digital Personal Data Protection Act, 2023](https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf), sections 1, 3, 5 and 6, checked 5 October 2026. The copy reached is the 2024 upload, which predates the commencement notification.
- [Notification G.S.R. 843(E), 13 November 2025](https://www.meity.gov.in/static/uploads/2025/11/c56ceae6c383460ca69577428d36828b.pdf), checked 5 October 2026. The commencement dates in section 1.2 come from this notification, not from a footnote to the Act.
- [APPI, Act No. 57 of 2003](https://www.japaneselawtranslation.go.jp/en/laws/view/4241/en), Articles 16, 21, 26, 27, 28 and 171, checked 5 October 2026.
- [PPC, leak reporting](https://www.ppc.go.jp/personalinfo/legal/leakAction/), checked 5 October 2026. The 1,000-person trigger sits in the Commission's order rather than in the Act.
- [California CCPA of 2018 as amended, text effective 1 January 2026](https://cppa.ca.gov/pdf/20260101_ccpa_statute.pdf), section 1798.140(d), checked 5 October 2026.
- [CPPA, updated monetary thresholds](https://cppa.ca.gov/regulations/cpi_adjustment.html), checked 5 October 2026.
- [Privacy Act 1988, compilation 104](https://www.legislation.gov.au/C2004A03712/latest), sections 5B, 6C, 6D and 6DA, checked 5 October 2026.

Indirect tax legislation and guidance:

- [IGST Act 2017](https://indiacode.gov.in/server/api/core/bitstreams/c34dadd9-0609-4cd5-89c5-2f6750daa70b/content), sections 2, 13 and 14, checked 5 October 2026.
- [CGST Rules 2017](https://indiacode.gov.in/server/api/core/bitstreams/a500c9f2-d982-4cdd-a1e5-9a5f7cd449e7/content), rules 14 and 64, checked 5 October 2026. The text reached is the consolidated version dated 9 October 2019, and the CBIC guidance could not be reached to confirm later amendments.
- [Norwegian VAT Act, LOV-2009-06-19-58](https://lovdata.no/dokument/NL/lov/2009-06-19-58), sections 2-1, 3-30, 14-4 and 14-6, checked 5 October 2026.
- [Skatteetaten, registration in the VOEC register](https://www.skatteetaten.no/en/business-and-organisation/vat-and-duties/vat/foreign/e-commerce-voec/register/), checked 5 October 2026.
- [Excise Tax Act, section 211.12](https://laws-lois.justice.gc.ca/eng/acts/E-15/section-211.12.html), checked 5 October 2026.
- [CRA, find out if you need to register](https://www.canada.ca/en/revenue-agency/services/tax/businesses/topics/gst-hst-businesses/digital-economy-gsthst/find-out-need-register.html) and [CRA, filing a return](https://www.canada.ca/en/revenue-agency/services/tax/businesses/topics/gst-hst-businesses/digital-economy-gsthst/file-return.html), checked 5 October 2026.
- [GST Act 1999](https://www.legislation.gov.au/C2004A00446/latest), sections 23-15 and 146-5, checked 5 October 2026. The Act states a AUD 50,000 base threshold with power for the regulations to raise it.
- [ATO, how Australian GST works](https://www.ato.gov.au/businesses-and-organisations/international-tax-for-business/gst-for-non-resident-businesses/how-australian-gst-works), [ATO, GST on imported services and digital products](https://www.ato.gov.au/businesses-and-organisations/international-tax-for-business/gst-for-non-resident-businesses/gst-on-imported-services-and-digital-products) and [ATO, simplified GST registration](https://www.ato.gov.au/businesses-and-organisations/international-tax-for-business/gst-for-non-resident-businesses/gst-registration-for-non-resident-businesses/simplified-gst-registration), checked 5 October 2026.
- [IRD, supplying remote services into New Zealand](https://www.ird.govt.nz/gst/gst-for-overseas-businesses/supplying-remote-services-into-new-zealand), checked 5 October 2026. The GST Act 1985 on legislation.govt.nz is behind a JavaScript challenge and could not be fetched, so the figure rests on the IRD page.
- [NTA, consumption tax implication for cross-border supplies of services](https://www.nta.go.jp/english/taxes/consumption_tax/0024006-219.pdf), July 2024, and [NTA, notifications and applications](https://www.nta.go.jp/english/taxes/consumption_tax/03.htm), checked 5 October 2026. The NTA brochure states the threshold without an article number.
- [MOF, FY2025 key points](https://www.mof.go.jp/english/policy/tax_policy/tax_reform/fy2025/07keyhighlight.pdf) and [MOF, FY2026 outline](https://www.mof.go.jp/tax_policy/tax_reform/outline/fy2026/08taikou_04.htm), checked 5 October 2026. Neither removes the consumption tax threshold for foreign digital suppliers.
- [Swiss VAT Act, SR 641.20](https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2009/615/20240101/en/html/fedlex-data-admin-ch-eli-cc-2009-615-20240101-en-html-4.html), Articles 8, 10, 34, 35 and 67, checked 5 October 2026.
- [IRAS, overseas businesses](https://www.iras.gov.sg/taxes/goods-services-tax-(gst)/gst-and-digital-economy/overseas-businesses), checked 5 October 2026.

Repo files reconciled here: none. This note answers a question about foreign law and does
not depend on the state of the checkout. The companion note
`docs/planning/research/sole-trader-obligations.md` holds the UK and EU positions, and the
figures in this note were read on the branch that this file is committed to.
