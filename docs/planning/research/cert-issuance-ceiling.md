# The certificate-issuance ceiling and its automatic handling (public release)

**Question:** with one Let's Encrypt certificate per member subdomain over HTTP-01, what happens
past the 50-new-certificates-per-registered-domain-per-7-days ceiling, can an override or a second
CA lift it, is one `*.kyriakon.net` certificate workable on this DNS setup, and what does the
automatic handling have to get right so issuance degrades into a queue instead of failing a signup
or a renewal?

**Answer, in five lines.** The 50-per-registered-domain figure is a continuous refill rate, not a
weekly bucket that resets. The refill is one certificate every 202 minutes, so onboarding 200
members costs about 21 days whether or not anyone watches which day of the week it is. Let's
Encrypt's published override is discretionary, reviewed weekly and deployed twice monthly with no
guaranteed timeline, and its own application form starts its volume question at 100 new
certificates per week for a single registered domain, so a platform whose entire ceiling is about
50 is below the form's smallest band. ZeroSSL, Google Trust Services and Actalis all require
external account binding, which the deployed `acme-client` on OpenBSD 7.9 does not implement, and
Buypass stopped selling TLS certificates on 16 October 2025. A single `*.kyriakon.net` certificate
is achievable with DNS-01, but not with `acme-client`, not by RFC 2136 against `nsd`, and not by
writing the `_acme-challenge` record into HE's panel: the record has to land in the zone file on the
hidden primary and be transferred, which is a script hook, not a provider plugin.

**Tested against versus read from sources.** `mail.kyriakon.net` (OpenBSD 7.9 GENERIC.MP#11 amd64,
NSD 4.14.2) is reachable over SSH and was read, not modified. Verified on the box: `man acme-client`
shows the synopsis `acme-client [-Fnrv] [-f configfile] handle` with no `-e` flag and no
external-account-binding text, and its description names one challenge type only, HTTP-01, where "a
file is created within a directory accessible by a locally run web server"; `man acme-client.conf`
has `challengedir` and no DNS-01 option; `man httpd.conf`
documents `certificate file` with "The default is /etc/ssl/server.crt"; `nsd -v` reports version
4.14.2 and `man nsd.conf` documents `drop-updates`. Read-only DNS queries were run from this
workstation against all five Hurricane Electric nameservers. Everything else is documentary: Let's
Encrypt policy pages, the override application form itself (fetched in a headless browser, since it
is rendered by JavaScript), each CA's own documentation, RFC 8555 and RFC 6125, NSD's source, and
the client tools' own provider sources. No zone edit, configuration deploy, or certificate issuance
was performed, because that would mean writing to the live box.

---

## 1. The override process: what it is and what it is not

The Rate Limits page is explicit that an override is a discretionary exception with lead time, not
a capacity increase you schedule around. Verbatim, from "Requesting an Override":

> If you are a large hosting provider or organization working on a Let's Encrypt integration, we
> have a [rate limiting form](https://isrg.formstack.com/forms/rate_limit_adjustment_request) that
> can be used to request higher rate limits. It takes a few weeks to process requests, so this form
> is not suitable if you just need to reset a rate limit faster than it resets on its own.

The same page states that the per-registered-domain limit's override route is that form ("To exceed
this limit, you must request an override for the specific registered domain or an account"), and
that for five other limits, including the 5-per-exact-identifier-set and both authorization-failure
limits, "We do **not** offer overrides for this limit."

The form itself is at `https://isrg.formstack.com/forms/rate_limit_adjustment_request`. It renders
entirely in JavaScript, so it was read in a headless browser rather than fetched as text. Its
landing page states the turnaround and the discretion directly:

> Depending on the availability of our team, we look at form responses weekly and move the
> adjustments to production twice monthly. We will do our best to consider your application in a
> timely manner but we cannot guarantee any timeline. We'll notify you via email when your
> application is processed. We reserve the right to reject applications at our discretion.

> If you need multiple rate limit adjustments, you may need to fill this form out multiple times.

The application is eleven pages. Its earlier steps require the applicant to confirm it has read the
Integration Guide and the Rate Limits documentation, ask whether the applicant is already receiving
a rate limit error or is "proactively reaching out", ask which limit needs adjusting ("Certificates
per Registered Domain" or "New Orders"), and offer a fixed list of error strings to choose from,
including "too many certificates already issued", "too many new orders recently" and "none of the
above". For the registered-domain limit, the form says:

> The default limit is 50 per week.

> You may request an adjustment by domain name or by ACME account ID. We recommend adjusting by
> ACME account ID if possible. Using a single account will require you to request all your
> certificates through one ACME account, but the advantage is that the rate limit adjustment
> applies to all domains that the account attempts certificate issuance.

> You can also adjust by domain, but you may only request an adjustment for up to three domains.
> Subsequent requests for more per-domain adjustments are not likely to be granted. This is why we
> recommend adjusting by account ID - then the adjustment applies to all domains used by your
> account. Please provide the base domain name(eTLD+1) only; adjustments will apply to subdomains
> too, but cannot be limited to them.

The volume question is the part that decides whether this platform is a candidate. Verbatim:

> What is the largest number of new certificates under a single registered domain or account you
> will need in a single week, ignoring renewals?
>
> 100 - 300
> 300 - 1,000
> 1,000 - 3,000
> 3,000 - 5,000
> 5,000 - 10,000
> 10,000+

The New Orders variant asks the same question "including renewals" and starts at 300. The form also
asks for an organization or company name and website, the ACME client used, and the applicant's
email address, and it ends with a sponsorship prompt addressed to "your organization".

The arithmetic puts the platform below that form's floor. At 200 members and one certificate per
member, onboarding consumes the full 50 in the first week and then refills at one per 202 minutes,
which is 150 further certificates in about 21 days: a sustained rate of roughly 50 new certificates
per week against a single registered domain, `kyriakon.net`. Fifty per week is half of the form's
smallest answer band of 100 to 300, and there is no band below it. The volume the form asks about,
ignoring renewals, is the volume this platform needs at its ceiling, so there is no truthful answer
in the form's range short of the 200-member case being treated as a short burst rather than a rate.

Three further facts bound how much an override could be relied on even if it were granted. The
adjustment is per account or per domain, not per platform, so it applies to all of `kyriakon.net` at
once rather than carving out member names, which is what the platform wants but also means the
platform cannot use the exemption to protect one customer from another's burn. The Integration
Guide warns against spreading issuance across accounts for exactly this reason ("We will be unable
to effectively adjust rate limits if many different accounts are used"), which suits the current
shape, where `openbsd/etc/acme-client.conf` declares one authority with one account key. And the
form's own text says the adjustment is a change to a limit, not a removal of the queue: the refill
is still continuous and a client still has to respect `Retry-After`.

Plainly: an override is worth filing before launch if the platform expects more than 100 new names
per week, because the form is the only route and it needs weeks of lead time. It is not worth
planning around, because nothing published states what fraction of applications are granted, and
the only published timeline is "weekly" review and "twice monthly" deployment with an explicit
refusal to guarantee anything. The plan has to work at 50.

## 2. What the 50 counts, and how the window behaves

The current text of the limit, verbatim from "New Certificates per Registered Domain":

> A registered domain is, generally speaking, the part of the domain you purchased from your domain
> name registrar. For instance, in `www.example.com`, the registered domain is `example.com`.

> Up to 50 certificates can be issued per registered domain (or IPv4 address, or IPv6 /64 range)
> every 7 days. This is a global limit, and all new order requests, regardless of which account
> submits them, count towards this limit. The ability to issue new certificates for the same
> registered domain refills at a rate of 1 certificate every 202 minutes.

Registered domains come from the Public Suffix List, which the page also cites. For `kyriakon.net`
the registered domain is `kyriakon.net`, so every member name, the apex, the mail host and the
defensive domain all draw on one budget. The limit is global in the sense that it is not per
account: an override on one account does not protect the domain from another account's ordering,
and a second Let's Encrypt account on a second host does not get a second allowance.

What counts as new is defined by the exemption section. Verbatim, from "Limit Exemptions for
Renewals":

> Let's Encrypt recognizes a new certificate order as a "renewal" in two ways: the preferred method
> is through ACME Renewal Info (ARI), which is exempt from all rate limits, and the other relies on
> older renewal detection logic that considers orders with the exact same set of identifiers as
> renewals but may still be subject to certain rate limits.

> If your client or hosting provider has yet to add support for ARI, your order can still be
> considered a renewal of an earlier certificate if it contains the exact same set of identifiers,
> ignoring capitalization and the order of identifiers. [...] Each of these new orders would be
> considered renewals and would be exempt from the New Orders per Account and New Certificates per
> Registered Domain rate limits. However, unlike ARI renewals, these orders would still be subject
> to Authorization Failures per Identifier per Account and New Certificates per Exact Set of
> Identifiers.

So renewals are exempt, and the exemption does not depend on ARI. `acme-client` 7.9 has no ARI (the
sibling ticket established this and it is unchanged), but it does request a certificate for the
same one-identifier set on every renewal, so its renewals fall under the older rule and do not
consume the 50. Both checkboxes are therefore satisfied: renewals do not count, and ARI's absence
costs nothing at 90-day lifetimes, though it removes the margin if lifetimes shorten.

Duplicate certificates are a separate named limit, not a free retry. The old
`https://letsencrypt.org/docs/duplicate-certificate-limit/` URL that the override form still links
to returns 404 today; the live text is "New Certificates per Exact Set of Identifiers":

> Up to 5 certificates can be issued per exact same set of identifiers every 7 days. This is a
> global limit, and all new order requests, regardless of which account submits them, count towards
> this limit. The ability to request new certificates for the same exact set of identifiers refills
> at a rate of 1 certificate every 34 hours.

> Reinstalling your client multiple times to troubleshoot an unknown error, or deleting your ACME
> client's configuration data each time you deploy your application, are common ways to hit this
> limit.

A reissue for a name that already has a certificate is therefore a renewal for the purposes of the
50 and a counted event for the purposes of the 5. A first issue for a new member name is neither:
it is a new identifier set, so it counts against the 50. Two different member names are two
different identifier sets, so both count against the 50 and each has its own 5. Reissuing the same
member name five times inside a week is what the 5 catches, and the documented workaround is to
change the identifier set, which the page notes would then "not be considered renewals" and would
be subject to the 50.

The window is not a window. Verbatim from "How Our Rate Limits Work":

> Limits are calculated, per request, using a token bucket algorithm. This approach provides
> flexibility in how you use your allotted requests. You can either make requests in bursts, up to
> the full limit, or space out your requests to avoid the risk of being limited.

> If you've hit a rate limit, we don't have a way to temporarily reset it. Don't worry, your
> capacity for that limit will gradually refill over time, allowing you to make more requests
> without any additional action on your part. Revoking certificates does **not** reset rate limits,
> because the resources used to issue those certificates have already been consumed.

An earlier, longer account of the same change is in the January 2025 post "Scaling Our Rate Limits
to Prepare for a Billion Active Certificates", which describes the old system and the reason it was
replaced:

> Subscribers were frequently hitting rate limits unexpectedly, leaving them unable to request
> certificates for days. This issue stemmed from our use of relatively large rate limiting windows,
> most spanning a week. Subscribers could deplete their entire limit in just a few moments by
> repeating the same request, and find themselves locked out for the remainder of the week.

> Unlike sliding windows, where users must wait for an entire time block to reset, GCRA allows users
> to retry as soon as enough time has passed to maintain the steady rate. This dynamic pacing
> reduces frustration and provides a smoother, more predictable experience for subscribers.

The consequence for the question as posed is that there is no "last day of a window" for a member
to land on. The 50 is burst capacity and the 202-minute refill is the rate. A member who signs up
first gets a certificate immediately; the fifty-first member of an afternoon waits about 3 hours
22 minutes; a member who signs up on the seventh day after a burst waits exactly as long as they
would have on the first day. What the platform can read instead of guessing is the `Retry-After`
header, documented verbatim:

> We include a `Retry-After` header in all rate limit error responses, indicating the duration your
> client should wait before retrying.

Rate-limited responses use a fixed message shape, also quoted from the same page:

> too many new registrations (10) from this IP address in the last 3h0m0s, retry after 1970-01-01
> 00:18:15 UTC.

> If your request exceeds the capacity of more than one of our limits, we will always return the
> error message for the limit that resets furthest in the future.

Two limits matter to a queue that retries badly. The order limit is 300 new orders per account every
3 hours, refilling at one order every 36 seconds, and the overall per-endpoint limits cap
`/acme/new-order` at 300 requests per second with a burst of 200. Neither binds at this scale. The
authorization-failure limits do: 5 failures per identifier per hour, refilling at one per identifier
every 12 minutes, and once exceeded "this limit is enforced by preventing any new orders for the same
identifier, by the same account until the limit resets". Beyond that, 1,152 consecutive authorization
failures per identifier pause issuance permanently until a human acts, and the error carries a link
to a Self-Service Portal that unpauses "the paused identifier and up to 49,999 additional paused
identifiers associated with their account". A retry loop that ignores its own failures can turn one
member's broken name into a paused name, and the pause is per identifier, so it does not spread.

One discrepancy is worth recording because the queue design touches it. The override application
form states "You can have a maximum of 300 Pending Authorizations on your account" and links to a
"Clearing Pending Authorizations" anchor on the Rate Limits page. The Rate Limits page as served
today has no pending-authorizations section; the anchor does not exist. Treat the form as the more
specific source and the figure as unverified against the policy page.

## 3. Other CAs

Limits are published, or not, by each CA. The table below is what each CA's own pages say, and the
last two columns are the parts that decide whether the platform could actually use them.

| CA | Published new-issue limit for this shape | ACME endpoint and client requirements | Usable by `acme-client` 7.9 |
|---|---|---|---|
| Let's Encrypt | 50 per registered domain per 7 days, refill 1 per 202 minutes | ACME v2, no EAB, HTTP-01 supported | Yes, this is the current deployment |
| Buypass Go | Service withdrawn | Not applicable | Not applicable |
| ZeroSSL | "No Rate Limits" claimed on the ACME feature page; no number published. EAB credentials are "limited to a maximum per user/per day" | ACME v2 at `https://acme.zerossl.com/v2/DV90`, EAB required | No, EAB required |
| Google Trust Services (Public CA) | API quotas per project: `newOrder` 100 per hour, `newAuthz` 300 per hour. No per-registered-domain cap published | ACME v2 at `https://dv.acme-v02.api.pki.goog/directory`, EAB required, Google Cloud project required | No, EAB required |
| Actalis | Free plan advertises "Domain Validation Single Domain - 90 days ... Unlimited via ACME"; no numeric rate limit found | ACME, EAB required for identified customers | No, EAB required |
| SSL.com | "No rate limits" claimed; certificates are paid | ACME v2 DV at `https://acme.ssl.com/sslcom-dv/directory` | Would work as a client, but it is not free |

Buypass Go is gone. Its own product page states, in the same paragraph that carries the date:

> **October 16, 2025:** TLS/SSL certificates can no longer be ordered, renewed, or replaced. The
> decision is based on a comprehensive assessment of the market situation and the regulatory
> framework surrounding TLS/SSL certificates.

> Existing TLS/SSL certificates will remain valid and functional until they expire or are revoked.

The announcement it links to, `https://community.buypass.com/t/y4y130p`, is unreachable from this
session (`getaddrinfo ENOTFOUND community.buypass.com`), so the reasoning behind the withdrawal is
not readable here. The operational fact is that Buypass Go cannot be a second issuer, and its ACME
requirements went with it: the resource page that would have described them now redirects to the
withdrawal notice, so whether it required external account binding is unverified here.

ZeroSSL requires external account binding, from its ACME documentation:

> Unlike for the ZeroSSL API for which you are using a ZeroSSL access key, for using our ACME
> service you have to create and use EAB (External Account Binding) credentials within your ZeroSSL
> dashboard.

Its ACME feature page claims "No Rate Limits" and "Unlimited Certificates, Free of Charge", while
the same documentation page qualifies both:

> Configure your scripts and clients to use our free of charge ACME API in a meaningful way. We want
> to provide a reliable and stable service to all our customers, malicious users can be limited or
> even blocked. Also, the **maximum number of labels in subdomains is six**, excluding the public
> suffix.

Its Terms of Service contains no number at all and reserves the right to withdraw the offer:
"ZeroSSL offers a free account option. ZeroSSL reserves the right to change the free account
structure or terminate free accounts at any time." A "no rate limits" sentence on a marketing page,
with no published figure and a fair-use clause in the documentation, is not a limit the platform can
plan against; it is the absence of a promise.

Google Trust Services issues free certificates through Public CA, with the same EAB requirement
stated twice in its documentation: "Your ACME client must support external account binding (EAB) to
work with Public CA", and the tutorial's step is `certbot register --eab-kid ... --eab-hmac-key`.
Public CA is tied to a Google Cloud project: an EAB secret is created per project with
`gcloud publicca external-account-keys create`, "You must use an EAB secret within 7 days of
obtaining it", and "You can only register one ACME account with an EAB secret." Its published
quotas are per project rather than per registered domain, so `newOrder` at 100 per hour is a
looser ceiling for a single domain than Let's Encrypt's 50 per week, but it is a Google Cloud
quota that can be requested upward and it comes with a GCP project, a service account or IAM role,
and a second account lifecycle to run. Public CA also supports HTTP-01, TLS-ALPN-01 and DNS-01, and
it states the wildcard rule that Let's Encrypt states: "If you use the DNS challenge, the client
can also request subdomains of that domain name to be included in a certificate." Its documentation
also warns that the API returns HTTP 429 and that "Your ACME clients must support this response code
and respect the `Retry-After` header".

Actalis supports ACME and its subscription page lists a free tier whose ACME column reads
"Unlimited via ACME", with the footnote "Automatic ACME activation gives you unlimited 90-day DV
certificates." Its ACME page says "For identified customers, EAB credentials (Key ID + HMAC Key) are
required", and its list of compatible clients names Certbot, acme.sh, win-acme, Posh-ACME and
Acme4J. Its pages do not state a numeric issuance limit that I could find, so the claim "unlimited"
here is unverified, and the free tier's shape (which certificate types, how many names) is not
readable from the published page.

SSL.com is the one other CA whose page states the client requirements plainly and whose ACME
directory is public for DV. It is not free: "ACME is a protocol. There is no charge for using it.
You pay for SSL.com certificates as normal; ACME is simply the mechanism by which they are
requested and renewed automatically." Its "No rate limits" sentence is the same kind of claim as
ZeroSSL's.

HARICA was checked and could not be reached: `https://www.harica.gr/en/Products/ServerCertificates`
and several neighbouring paths return 404, `https://acme.harica.gr/v2/` returns 404, and the site
root answers with an RSS feed, so nothing about its limits or client requirements is verified here.

The client requirement is the part that turns "use a second CA" from a configuration change into a
second deployment. `acme-client` on OpenBSD 7.9 implements RFC 8555 (the man page's STANDARDS
section cites it) and nothing else; on the box, `man acme-client` shows the synopsis
`acme-client [-Fnrv] [-f configfile] handle`, the man page describes only `http-01`, and
`acme-client.conf(5)` has `challengedir` and no DNS or EAB option. External account binding was
added to OpenBSD's `acme-client` in a commit dated 2026-05-22, which is after 7.9, so the feature
exists in `-current` as `-e key-id:key` and does not exist on the deployed box. Every free
alternative except Let's Encrypt therefore needs a different client: `acme.sh`, `lego`, `certbot`
or `dehydrated`, each with its own account, credentials, storage, cron entry, and failure modes,
running beside `acme-client` rather than replacing it, since `acme-client` still owns the HTTP-01
certificates the platform already has.

That is the honest engineering answer to whether a second issuer is overflow capacity. A spillover
CA only helps if it is genuinely not rate-limited for this shape, and the three free candidates
that publish anything either claim no limit without committing to one, or set quotas at a level
where Google's 100 orders per hour would be reached only in a burst that Let's Encrypt's
202-minute refill would never allow anyway. What a second CA does add is a second account key
holding authorizations for the same names, a second client binary on the box, a second code path
for the queue to reason about when deciding whether a given member's certificate has been issued,
and a second place for a stuck authorization to hide. The 429, `Retry-After` and
authorization-failure behaviours differ per CA, so the queue would need per-CA logic rather than one
retry rule.

## 4. DNS-01 and one wildcard

A wildcard certificate requires DNS-01, from two directions. Let's Encrypt's "Challenge Types" page
lists HTTP-01's cons as including "This challenge cannot be used to issue wildcard certificates",
and describes DNS-01 with "It also allows you to issue wildcard certificates." RFC 8555 defines what
a wildcard identifier is and what the CA must do with it:

> Any identifier of type "dns" in a newOrder request MAY have a wildcard domain name as its value.
> A wildcard domain name consists of a single asterisk character followed by a single full stop
> character ("*.") followed by a domain name as defined for use in the Subject Alternate Name
> Extension by [RFC5280]. An authorization returned by the server for a wildcard domain name
> identifier MUST NOT include the asterisk and full stop ("*.") prefix in the authorization
> identifier value. The returned authorization MUST include the optional "wildcard" field, with a
> value of true.

So a certificate for `*.kyriakon.net` produces an authorization for `kyriakon.net` with
`wildcard: true`, and the record to publish follows from RFC 8555's DNS challenge section:

> The client constructs the validation domain name by prepending the label "_acme-challenge" to the
> domain name being validated, then provisions a TXT record with the digest value under that name.
> For example, if the domain name being validated is "www.example.org", then the client would
> provision the following DNS record:
>
>     _acme-challenge.www.example.org. 300 IN TXT "gfj9Xq...Rg85nM"

The digest is the SHA-256 of the key authorization, base64url encoded. Let's Encrypt's page states
the same location in prose ("put that record at `_acme-challenge.<YOUR_DOMAIN>`") and adds the case
that matters when the certificate covers both the wildcard and the apex:

> You can have multiple TXT records in place for the same name. For instance, this might happen if
> you are validating a challenge for a wildcard and a non-wildcard certificate at the same time.
> However, you should make sure to clean up old TXT records, because if the response size gets too
> big Let's Encrypt will start rejecting it.

For `kyriakon.net` both authorizations use the same name, `_acme-challenge.kyriakon.net`, so an
apex-plus-wildcard certificate needs two TXT records at one name, and a certificate that covers only
`*.kyriakon.net` needs one.

Where that record has to be written is decided by the DNS layout, which the repo records: the zone's
NS records are `ns1.he.net` through `ns5.he.net` only, `ns0.kyriakon.net` is the hidden primary and
is absent from NS, and `openbsd/etc/nsd/nsd.conf` gives HE `provide-xfr` over AXFR with the
`kyriakon-he` TSIG key and one working `notify` target plus the SOA refresh timer as the backstop.
The public secondaries only ever serve what they transfer from the hidden primary, so the TXT record
must land in `/var/nsd/etc/kyriakon.net.zone` on the box and be transferred from there. There is no
route that writes it at HE directly: HE's free DNS offers a slave/secondary panel, not an API for
publishing zone data into a zone the primary owns.

The next question is how to write it, and the answer rules out the obvious tool. NSD does not
implement RFC 2136 dynamic update. The mechanism is in NSD's `query.c`, which handles only two
opcodes and answers everything else with NOTIMP:

```
	q->opcode = OPCODE(q->packet);
	if(q->opcode != OPCODE_QUERY && q->opcode != OPCODE_NOTIFY) {
		if(query_ratelimit_err(nsd))
			return QUERY_DISCARDED;
		if(nsd->options->drop_updates && q->opcode == OPCODE_UPDATE)
			return QUERY_DISCARDED;
		return query_error(q, NSD_RC_IMPL);
	}
```

and the `drop-updates` option exists only to discard UPDATE packets outright, as the man page says:

> **drop-updates: <yes or no>**
> If set to yes, drop received packets with the UPDATE opcode. Default is no.

So `nsupdate` cannot add the record. The clients whose DNS-01 providers assume RFC 2136 all fail
for the same reason: `acme.sh`'s provider is literally described in its own source as "nsupdate RFC
2136 DynDNS client"; `lego` ships a provider named "DNS Update (RFC2136)" whose documented
configuration is `DNSUPDATE_NAMESERVER`, `DNSUPDATE_TSIG_KEY`, `DNSUPDATE_TSIG_ALGORITHM` and
`DNSUPDATE_TSIG_SECRET`; and `certbot` ships `certbot-dns-rfc2136`. None of them has an NSD
provider, because there is no protocol to speak.

What does work is running a script. `lego`'s `exec` provider calls a program with three arguments,
documented as "the action (\"present\" or \"cleanup\"), the fully-qualified domain name and the value
for the record", so the script can write the TXT into the zone file, bump the SOA serial, and reload
NSD with `rcctl reload nsd`, which OpenBSD's rc script implements as `nsd-control reconfig` followed
by `nsd-control reload`. `certbot` has the same shape in `--manual-auth-hook`, and `dehydrated` has
`deploy_challenge` and `clean_challenge` hooks whose argument layout is documented in its
`hook_chain.md`. `acme.sh` supports a user-supplied dnsapi script the same way. The cost of all of
these is that the hook is now part of the issuance path, the zone file becomes a file that two
processes write, and the serial-bump discipline the zone file already warns about is enforced by
that script rather than by a human.

The alternative that avoids touching the hidden primary is delegation. Let's Encrypt follows
CNAMEs and NS records when it looks up the TXT record, and its own guidance for providers is to
delegate the challenge name:

> Since Let's Encrypt follows the DNS standards when looking up TXT records for DNS-01 validation,
> you can use CNAME records or NS records to delegate answering the challenge to other DNS zones.
> This can be used to delegate the `_acme-challenge` subdomain to a validation-specific server or
> zone.

The same idea is the subject of the 2019 post "Onboarding Your Customers with Let's Encrypt and
ACME", which is the closest thing Let's Encrypt publishes to a queue design. It recommends a CNAME
from `_acme-challenge.<name>` to a name the provider controls, so the challenge value never changes
when the account key rotates, and describes the failure the queue exists to prevent: "Before your
new customer points their domain name at your servers, you need to have a certificate already
installed for them. Otherwise visitors to the customer's site will see an outage for a few minutes
while you issue and install a certificate."

Propagation from the hidden primary to the public secondaries was measured today, read-only. All
five HE nameservers answer the same SOA for `kyriakon.net`, serial 2026092401, with a refresh of
3600 seconds, a retry of 900 and a negative-cache TTL (the SOA minimum) of 3600. The wildcard A
record answers with a TTL of 3600. `_acme-challenge.kyriakon.net` currently has no TXT record on
any queried nameserver. The sibling ticket measured, from the box, that only `216.218.130.2`
(ns1.he.net) answers a NOTIFY and the other four refuse it, yet all five serve the same serial, so
HE distributes the zone internally once ns1 has pulled it. What that implies for a TXT edit is a
push path of seconds to a minute after the reload and notify, with a worst case bounded by the SOA
refresh timer of one hour if a notify is lost, and with one further hour of possible negative
caching of the not-yet-existing `_acme-challenge` name, since the SOA minimum is also 3600. Let's
Encrypt's own page is clear that this cannot be measured from the outside with confidence, because
of anycast and because the vantage point differs from the validator's: "The best DNS APIs provide a
way for you to automatically check whether an update is fully propagated. If your DNS provider
doesn't have this, you just have to configure your client to wait long enough (often as much as an
hour)." No end-to-end timed edit was made, because that means writing to the live zone.

One wildcard changes what the ceiling costs, and the blast radius of the key. The cost side is
simple: issuance and renewal of one certificate for `*.kyriakon.net` is one order and one
certificate, so onboarding stops touching the 50 entirely, and the 5-per-exact-set limit is satisfied
by one renewal per 90-day (or, later, 45-day) lifetime. The limit that would remain is the same
refill, costing one certificate per renewal rather than one per member. The risks are also concrete.
A wildcard matches one label and no more: RFC 6125's client rule is that "*.example.com would match
foo.example.com but not bar.foo.example.com or example.com", so the certificate needs
`kyriakon.net` as a second name if the apex has to be served by the same file, and it does not
cover any nested name the platform might introduce later. The private key has to be readable by the
daemons that present it: `openbsd/etc/gmid.conf` points at `/etc/ssl/kyriakon.net.key` and
`/etc/ssl/private/oliver.kyriakon.net.key`, and each httpd vhost names the matching `certificate
file`, so one wildcard key would sit in the same place for every member name. Any compromise that
reaches that file impersonates every member at once, and the account key that can reissue it is a
single credential whose theft yields a wildcard. Revocation
is one event for all members rather than one per member, and the Rate Limits page states that
revoking does not restore the issuance budget. Against that, per-member keys mean a leaked key costs
one member's impersonation and one reissue, and a member whose name is compromised is revoked
alone. The platform already chose per-member isolation in the repo's own comment on the defensive
domain, where it split `kyriakon.com` off rather than putting it on `kyriakon.net`'s certificate so
that "a validation failure on one name cannot take the other's renewal down with it".

## 5. The queue's obligations

Nothing on the CA side queues anything. There is no server-side waiting list, and a rate-limited
request is simply refused with a `Retry-After` value. The queue is the platform's own, and the
following are the parts it has to get right, each grounded in a source.

### What serves while the certificate is pending

HTTP-01 validation requires the name to answer on
port 80. RFC 8555's HTTP challenge says the request "MUST be sent to TCP port 80 on the HTTP
server", Let's Encrypt states "The HTTP-01 challenge can only be done on port 80" and that it
follows redirects up to ten deep, and it recommends serving port 80 always: "all servers meant for
general web use should offer both HTTP on port 80 and HTTPS on port 443. They should also send
redirects for all port 80 requests". Nothing about HTTP-01 needs a working certificate, so the
challenge path and the queue are independent of TLS. HTTPS before issuance is the harder case.
`httpd.conf(5)` documents `certificate file` with a default, "The default is /etc/ssl/server.crt",
so a vhost that names no certificate of its own presents that file rather than refusing the
connection. A member whose certificate is still queued therefore reaches their site over HTTPS and
gets a name mismatch, unless the platform serves them from a certificate that already covers their
name or over HTTP alone. That is the design decision the queue's serving behaviour depends on: with
the wildcard described in section 4, the member is served correctly from the first second and the
per-member certificate becomes an upgrade path; with per-member issuance, the member has a valid
site only after their certificate lands.

### How retries should be timed

The rate limit is the clock, and it is published. A client that has
drained the bucket gets exactly one new certificate per 202 minutes, so a retry loop that fires
every few minutes spends authorization failures for nothing. The Integration Guide prescribes a
backoff pattern and the reasoning for it:

> Renewal failure should not be treated as a fatal error. You should implement graceful retry logic
> in your issuing services using an exponential backoff pattern, maxing out at once per day per
> certificate. For instance, a reasonable backoff schedule would be: 1st retry after one minute,
> 2nd retry after ten minutes, 3rd retry after 100 minutes, 4th and subsequent retries after one
> day.

> Backoffs on retry mean that your issuance software should keep track of failures as well as
> successes, and check if there was a recent failure before attempting a fresh issuance. There's no
> point in attempting issuance hundreds of times per hour, since repeated failures are likely to be
> persistent.

> All errors should be sent to the administrator in charge, in order to see if specific problems
> need fixing.

Two constraints sit on top of that schedule. A retry against a drained bucket must take its wait
from the `Retry-After` header rather than from the backoff schedule, because the header is the
exact time the limit resets and the schedule is only a default. And a retry must not be issued for a
name whose authorization already failed, because the 5-failures-per-identifier-per-hour limit turns
a retry storm into a longer refusal, and 1,152 consecutive failures pauses the identifier until
somebody visits the Self-Service Portal. Onboarding requests are not renewals, so they cannot
inherit a renewal's exemption, and the identifier set is new, so the queue's ordering only has to
decide which member gets the one slot that becomes available every 202 minutes.

The Integration Guide's advice for large estates is the reason to make renewals a separate,
low-priority lane. For installations issuing for more than 10,000 hostnames it recommends
"automated renewal in small runs, rather than batching up renewals into large chunks", and it
recommends randomising the scheduled minute, with the FAQ giving the reason: "When the service is
too busy, clients will be asked to try again later, so randomizing renewal times can help avoid
unnecessary retries." At this platform's size there is no need for a batch runner, but the existing
`scripts/renew-acme.sh`, which runs daily at 03:00 and exits 2 when a certificate is still current,
already behaves this way, and it must keep running even when the onboarding queue is backed up,
because a lapsed member certificate is worse than a slow signup.

Two mechanics make the queue cheaper to build. First, a completed authorization is cached, so the
platform can validate a member's name when they sign up and issue later without running the
challenge again: "Once you successfully complete the challenges for a domain, the resulting
authorization is cached for your account to use again later. Cached authorizations last for up to 30
days from the time of validation, depending on the associated profile." A member validated today can
wait three weeks for a slot and still be issued without touching their name. Second, the opposite
is true of an authorization that is merely pending: the 2019 post says that if a customer is given a
digest value to deploy themselves, "it has a fixed lifetime before it expires (for Let's Encrypt
this lifetime is 7 days)", so an unfulfilled pending authorization is the thing to avoid, not
something to leave lying around. The same post warns about the failure mode after onboarding,
because a delegated `_acme-challenge` name that is never cleaned up is "a delegated authorization to
issue certificates".

### What the operator needs to watch

The queue is invisible unless the platform counts its own
issuances, and the sources name three places to look. Let's Encrypt's own suggestions for counting
what has been issued for a domain are the transparency logs: "You can get a list of certificates
issued for your registered domain by searching crt.sh or Censys". The rate-limit errors themselves
carry the reset time in `Retry-After`, and the client's log is where a rising refusal rate shows up
first; the Rate Limits page's own example is the error text a human reads. A paused identifier is
only announced in the error that carries the Self-Service Portal link, so a queue that swallows
errors also swallows the one signal that a member's name is paused. For service-level changes, the
Integration Guide points at two channels: "To receive low-volume updates about important changes
like the ones described above, subscribe to our API Announcements group" and "For higher-volume
updates about maintenances and outages, visit our status page and hit Subscribe in the upper right."
For certificate expiry as distinct from issuance, Let's Encrypt's monitoring page lists external
services, and recommends Red Sift Certificates Lite with a free tier of 250 certificates, which is
above the member count in question. On the box, the signal that already exists is the exit code:
`acme-client(1)` "returns 0 if certificates were changed (revoked or updated), 1 on failure, or 2 if
the certificates didn't change", and `scripts/renew-acme.sh` already distinguishes 2 from failure
and lets the failure reach cron's mail. A queue built the same way needs its refusals to reach a
human too, rather than being retried quietly until a member complains.

### What the member is told

No source states this, so it is a product decision, but the facts bound
it. The wait is computable rather than unknown, since a drained bucket refills one certificate per
202 minutes and the position in the queue is known to the platform. The name can be validated at
signup and the certificate issued later inside the 30-day cached-authorization window. Nothing in
Let's Encrypt's documentation makes issuance a precondition for serving the member's site over
HTTP, and if the platform holds a wildcard certificate then it is not a precondition for HTTPS
either. Against the ticket's requirement that issuance never fails a signup or a renewal, those are
the levers: a queue with a computed position, an authorization validated up front, and serving that
does not depend on per-member issuance.

## 6. Options, and where the recommendation stops

The facts above leave four options, and the choice between them is engineering judgement rather than
something a source decides.

Pacing signups at the refill rate is the only option that needs no new machinery. It holds
onboarding to about 7 members a day after the first 50, which is 21 days for 200 members, and it
requires the signup path to accept members it cannot immediately issue for, which is the queue in
section 5.

Filing the override before launch is worth doing only if the platform expects to exceed 100 new
names per week, because that is the form's smallest band and there is no smaller one. It changes a
limit and does not remove the queue, and the published timeline is weekly review with a twice
monthly deployment.

Adding a second free CA buys a second account and a second client, not a second half of the
platform's name space. All three free candidates that publish anything require EAB, which the
deployed `acme-client` does not implement, so this option means running `acme.sh`, `lego`, `certbot`
or `dehydrated` beside `acme-client` for the same names. The claim that made this option attractive,
unlimited issuance, is asserted by ZeroSSL and SSL.com without a number, and Google's is a per
project quota of 100 orders per hour that no honest queue at this scale would reach.

One wildcard certificate removes onboarding from the ceiling altogether. It requires DNS-01, so it
requires a second client anyway, plus a script that writes the `_acme-challenge` record into the
zone on the hidden primary and reloads NSD, plus an explicit decision to accept that one key and one
account key cover every member name. Given that the alternatives are a queue and a second client,
the wildcard and the queue are not mutually exclusive: the wildcard removes the onboarding backlog,
and the queue remains necessary for platform certificates, renewals under a shortened lifetime, and
any future limit.

What this file does not recommend is an override as the mechanism, or a second CA as overflow. Both
are plausible on their own terms, and both are weaker than they look against their own published
documentation. The one thing the sources settle is that 50 new certificates per registered domain
per week, refilling one per 202 minutes, is a rate the platform has to live inside, and that the
only published escape from it, for a single registered domain at this volume, is an override whose
application form begins above the platform's ceiling.

## 7. Not verified, and unreachable

The following could not be checked and are not claimed.

The override form's internal steps were read in full, but nothing published states how many
applications are granted, what volume actually clears the bar, or what an adjustment's new number
is, so any statement about the platform's chances of being granted one would be a guess. The form
links to `https://letsencrypt.org/docs/duplicate-certificate-limit/`, which returns 404; its content
now lives under "New Certificates per Exact Set of Identifiers" on the Rate Limits page, which is
what section 2 quotes. The form also cites a "Clearing Pending Authorizations" limit of 300, an
anchor and a figure that no longer appear on the Rate Limits page.

Buypass's withdrawal announcement at `https://community.buypass.com/t/y4y130p` is unreachable from
this session (`getaddrinfo ENOTFOUND`), so the withdrawal is cited from Buypass's own product page,
which states it and dates it.

HARICA's product and ACME pages return 404 and its site root answers as an RSS feed, so its limits,
ACME version and client requirements are unverified.

Actalis's numeric limits are unverified: its free tier advertises unlimited 90-day DV certificates
via ACME, and no rate-limit figure was found on its pages.

ZeroSSL's "No Rate Limits" and SSL.com's "No rate limits" are quoted as published claims, not as
verified capacities. Neither page publishes a number.

No end-to-end timing of a `_acme-challenge` TXT write was measured, because that means editing the
live zone and reloading NSD on the box. What was measured is the current state: five HE secondaries
in sync on SOA serial 2026092401 with a 3600-second refresh and a 3600-second negative-cache TTL,
and no existing TXT record at `_acme-challenge.kyriakon.net`. The propagation figures in section 4
are derived from the SOA timers and the notify behaviour measured in the sibling ticket, not from a
timed edit.

The obligation to keep the deployment off the live box means every config-side claim here comes
from the man pages, the source, and read-only commands on the box. Nothing was written.

## 8. Primary sources

- Let's Encrypt, "Rate Limits", last updated 5 August 2026. New Certificates per Registered Domain,
  New Certificates per Exact Set of Identifiers, Authorization Failures per Identifier per Account,
  Consecutive Authorization Failures per Identifier per Account, New Orders per Account, Limit
  Exemptions for Renewals, Retry-After Header, Requesting an Override.
  https://letsencrypt.org/docs/rate-limits/
- ISRG, "Rate Limit Adjustment Request" application form, read in a headless browser because it is
  JavaScript-rendered. Landing-page criteria and turnaround, the 50-per-week statement, the
  account-versus-domain rule, the three-domain cap, the volume bands, the organization and ACME
  client questions, and the 300 pending authorizations text.
  https://isrg.formstack.com/forms/rate_limit_adjustment_request
- Let's Encrypt, "Challenge Types", last updated 12 February 2026. HTTP-01 port 80 and the wildcard
  exclusion, DNS-01 wildcard support, `_acme-challenge` location, multiple TXT records at one name,
  propagation and the hour-long wait, CNAME and NS delegation.
  https://letsencrypt.org/docs/challenge-types/
- Let's Encrypt, "Client and Large Provider Integration Guide", last updated 23 June 2025. One
  account versus many and the rate-limit-adjustment reason, separate certificates per hostname,
  retry and backoff schedule, renewal in small runs, randomised scheduling, API Announcements and
  status page. https://letsencrypt.org/docs/integration-guide/
- Let's Encrypt, "Best Practice - Keep Port 80 Open", last updated 24 January 2019.
  https://letsencrypt.org/docs/allow-port-80/
- Let's Encrypt, "Frequently Asked Questions". Cached authorizations lasting up to 30 days, random
  renewal times, "When the service is too busy, clients will be asked to try again later".
  https://letsencrypt.org/docs/faq/
- Let's Encrypt, "Monitoring Service Options", last updated 13 July 2026. Red Sift Certificates Lite
  with a free tier of 250 certificates. https://letsencrypt.org/docs/monitoring-options/
- Let's Encrypt, "Scaling Our Rate Limits to Prepare for a Billion Active Certificates", 30 January
  2025. MariaDB weekly windows, Redis and GCRA, continuous refill, Retry-After from the theoretical
  arrival time. https://letsencrypt.org/2025/01/30/scaling-rate-limits
- Let's Encrypt, "Onboarding Your Customers with Let's Encrypt and ACME", 9 October 2019. The cutover
  outage, the CNAME delegation pattern, the 7-day pending authorization lifetime, cleaning up unused
  CNAMEs. https://letsencrypt.org/2019/10/09/onboarding-your-customers-with-lets-encrypt-and-acme
- RFC 8555, "Automatic Certificate Management Environment (ACME)", March 2019. Wildcard identifiers
  and the `wildcard` authorization field in section 7.1.3, the DNS challenge in section 8.4, the
  HTTP challenge on port 80 in section 8.3, the standard ACME problem document and rate-limit
  considerations in section 6.6. https://www.rfc-editor.org/rfc/rfc8555
- RFC 6125, "Representation and Verification of Domain-Based Application Service Identity", March
  2011. Section 6.4.3, the one-label wildcard matching rule.
  https://www.rfc-editor.org/rfc/rfc6125
- OpenBSD 7.9, `acme-client(1)`, read on the box with `man acme-client`. Synopsis without `-e`,
  HTTP-01 only, renewal at one third of lifetime, exit codes 0, 1 and 2, RFC 8555 in STANDARDS.
  https://man.openbsd.org/acme-client.1
- OpenBSD 7.9, `acme-client.conf(5)`, read on the box. Authorities, `domain` blocks, `challengedir`,
  `profile`, and the absence of any DNS or EAB option. https://man.openbsd.org/acme-client.conf.5
- OpenBSD 7.9, `httpd.conf(5)`, read on the box. `certificate file` and its default
  `/etc/ssl/server.crt`. https://man.openbsd.org/httpd.conf.5
- OpenBSD `src`, `usr.sbin/acme-client/acme-client.1` and the EAB commit dated 2026-05-22, "Add
  support for external account binding", which is after 7.9 and shows the flag as `-e
  key-id:key`. https://github.com/openbsd/src/commits/master/usr.sbin/acme-client/acme-client.1
- OpenBSD 7.9, `nsd.conf(5)` (`drop-updates`), read on the box, and NSD 4.14.2 as installed
  (`nsd -v`). https://man.openbsd.org/nsd.conf.5
- NSD `query.c`, the opcode check that answers anything other than QUERY or NOTIFY with NOTIMP.
  https://raw.githubusercontent.com/NLnetLabs/nsd/master/query.c
- NSD `nsd.conf(5)` and `nsd.conf.sample.in`, the `drop-updates` description.
  https://www.nlnetlabs.nl/documentation/nsd/nsd.conf/
- Hurricane Electric free DNS, `https://dns.he.net/`, for the slave/secondary panel and its AXFR
  validation, as recorded in the sibling DNS ticket.
- `acme.sh`, `dnsapi/dns_nsupdate.sh`, described in its own header as "nsupdate RFC 2136 DynDNS
  client". https://raw.githubusercontent.com/acmesh-official/acme.sh/master/dnsapi/dns_nsupdate.sh
- `lego`, DNS provider documentation: "DNS Update (RFC2136)" and its `DNSUPDATE_*` variables, and
  "External program" (`exec`), which calls the program with the action, the FQDN and the value.
  https://go-acme.github.io/lego/dns/rfc2136/ and https://go-acme.github.io/lego/dns/exec/
- Certbot, "User Guide", DNS plugins including `certbot-dns-rfc2136` and the `--manual-auth-hook`
  path for hooks. https://eff-certbot.readthedocs.io/en/stable/using.html
- `dehydrated`, `docs/hook_chain.md`, for `deploy_challenge` and `clean_challenge`.
  https://github.com/dehydrated-io/dehydrated/blob/master/docs/hook_chain.md
- Buypass, "Buypass Go SSL (Discontinued)". The 16 October 2025 withdrawal and the treatment of
  existing certificates. https://www.buypass.com/products/tls-ssl-certificates/go-ssl
- ZeroSSL, "ACME", endpoint URL and EAB requirement, the label limit and the fair-use wording.
  https://zerossl.com/documentation/acme
- ZeroSSL, "Generate EAB Credentials", the per-day EAB limit.
  https://zerossl.com/documentation/acme/generate-eab-credentials
- ZeroSSL, "ACME Automation" feature page, "No Rate Limits" and "Unlimited Certificates, Free of
  Charge". https://zerossl.com/features/acme
- ZeroSSL, "Terms & Conditions", last modified 23 March 2021, the free-account clause.
  https://zerossl.com/legal/terms
- Google Cloud, "Request a certificate using Public CA and an ACME client", the EAB steps, the
  7-day EAB validity and the one-account-per-secret rule, the production directory URL, and "There
  is no charge for requesting certificates from Public CA".
  https://docs.cloud.google.com/certificate-manager/docs/public-ca-tutorial
- Google Cloud, "Public CA", EAB as a client requirement, the three challenge types, the DNS-01
  subdomain rule. https://docs.cloud.google.com/certificate-manager/docs/public-ca
- Google Cloud, "Quotas and limits" for Certificate Manager, the Public CA request quotas
  (`newOrder` 100 per hour, `newAuthz` 300 per hour) and the HTTP 429 with `Retry-After`.
  https://docs.cloud.google.com/certificate-manager/docs/quotas
- Actalis, "ACME Protocol: SSL Certificate Automation", EAB for identified customers, the client
  list and the wildcard support. https://www.actalis.com/acme-protocol-ssl-certificate-automation
- Actalis, "Subscription plans", the free tier and the "Unlimited via ACME" footnote.
  https://www.actalis.com/subscription
- SSL.com, "ACME", the DV-only directory URL, "No rate limits", and the statement that ACME itself
  is free while certificates are paid. https://www.ssl.com/acme/
- Repo files read for the current shape: `openbsd/etc/acme-client.conf` (one authority, one account
  key, per-hostname HTTP-01 domains), `openbsd/etc/nsd/nsd.conf` (hidden primary, TSIG, one working
  notify target, SOA refresh as backstop), `openbsd/etc/nsd/kyriakon.net.zone` (NS set, SOA timers,
  wildcard A/AAAA, TXT records for SPF, DKIM and DMARC, no CAA record), `scripts/renew-acme.sh`
  (daily run, exit-code handling, cron mail on failure).
