# DNS — `nsd` hidden primary + Hurricane Electric secondary, and the mail go-live record set

Ticket: configure `nsd` (OpenBSD base) as the hidden primary for `kyriakon.net`, with Hurricane Electric's free DNS as the public secondary via AXFR/NOTIFY (proposal §5.7, §6.13), and define the exact record set so mail can go live — MX, SPF, DKIM (selector + key placement), DMARC (`p=none` start, §6.2), PTR (via Hetzner, not the zone), and the `*.kyriakon.net` wildcard A/AAAA for per-user subdomains (§5.2).

## Recommended shape (short answer)

1. `nsd` on the box is the **hidden primary**: it serves the zone file as source of truth and answers AXFR/NOTIFY to HE, but is **not listed in the public NS records** (those point only at HE's anycast secondaries).
2. `nsd.conf` declares one `server:` clause and one `zone:` clause per zone; the hidden-primary role is three lines — `notify:` + `provide-xfr:` (plus `outgoing-interface:` if the box has multiple IPs) pointing at HE's transfer servers.
3. The zone file holds the full record set (§4); the public NS set is `ns1.he.net` … `ns5.he.net`, and the box's own name is absent from NS.
4. At HE, the domain is added as a **slave/secondary** domain pointing at the box's IP; HE pulls AXFR, validates it, then listens for NOTIFY and refreshes on the SOA/`refresh` timer.
5. **Ordering:** zone published (AXFR to HE, verified) **before** mail goes live — MX/SPF/DKIM/DMARC must resolve publicly first, and PTR set at Hetzner, before the first send.

---

## 1. `nsd.conf` shape (hidden primary)

OpenBSD's `nsd` chroots to `/var/nsd` and runs as the `_nsd` user; the man page's own EXAMPLE uses `zonelistfile: /var/nsd/db/zone.list`, `xfrdfile: /var/nsd/run/xfrd.state`, and zone files under `/var/nsd/etc/` ([nsd.conf(5)](https://man.openbsd.org/nsd.conf.5)). The config file itself therefore lives at `/var/nsd/etc/nsd.conf`. The format is `attribute: value`, `#` comments, and the top level allows only `server:`, `verify:`, `key:`, `pattern:`, `zone:`, `tls-auth:`, `remote-control:` ([nsd.conf(5), FILE FORMAT](https://man.openbsd.org/nsd.conf.5)).

The hidden-primary role is exactly the "this server is the primary and 192.0.2.1 is the secondary" example from the man page:

```nsd
server:
	server-count: 1
	username: _nsd
	zonelistfile: /var/nsd/db/zone.list
	logfile: /var/log/nsd.log
	xfrdfile: /var/nsd/run/xfrd.state

zone:
	name: kyriakon.net
	zonefile: /var/nsd/etc/kyriakon.net.zone
	# HE secondary: send it NOTIFY and allow it to AXFR. NOKEY = no TSIG.
	notify: <he-transfer-ip-1> NOKEY
	notify: <he-transfer-ip-2> NOKEY
	provide-xfr: <he-transfer-ip-1> NOKEY
	provide-xfr: <he-transfer-ip-2> NOKEY
```

The three directives, from the man page:

- `notify: <ip-address> <key-name | NOKEY>` — "The listed address (a secondary) is notified of updates to this zone via UDP" ([nsd.conf(5), notify](https://man.openbsd.org/nsd.conf.5)).
- `provide-xfr: <ip-spec> <key-name | NOKEY | BLOCKED> [tls-auth-name]` — "The listed address (a secondary) is allowed to request XFR from this server. Zone data will be provided to the address" ([nsd.conf(5), provide-xfr](https://man.openbsd.org/nsd.conf.5)).
- `outgoing-interface: <ip-address>` — "used to request AXFR|IXFR (in case of a secondary) or used to send notifies (in case of a primary)"; needed only if the box has multiple routable IPs and the notify/XFR source address matters ([nsd.conf(5), outgoing-interface](https://man.openbsd.org/nsd.conf.5)).

Reload after a zone-file edit with `kill -HUP` to the `nsd` pid ("Then, use kill -HUP to reload changes from primary zone files", [nsd.conf(5), EXAMPLE](https://man.openbsd.org/nsd.conf.5)).

Two operational points the man page implies but doesn't decide:

- **HE's AXFR source IPs are not published** in the public dns.he.net docs. `provide-xfr`/`notify` are IP-based ACLs, so the exact HE transfer source IPs must be pinned down at signup (the dns.he.net portal's slave-validation flow confirms the transfer; see §3). Do **not** leave `provide-xfr: 0.0.0.0/0` — that would let anyone AXFR the whole zone (which also leaks the DKIM/TXT set and every per-user hostname pattern). Grab HE's real transfer IPs and list them.
- **TSIG is available but not required by HE's free service.** The man page supports `key:` + named keys instead of `NOKEY` ([nsd.conf(5), FILE FORMAT](https://man.openbsd.org/nsd.conf.5)). HE's free secondary docs don't require TSIG, so `NOKEY` + IP ACL is the MVP floor; TSIG is a later hardening step, not a go-live blocker.

---

## 2. Zone-file template

`/var/nsd/etc/kyriakon.net.zone`. IPs are placeholders (`203.0.113.0/24` is TEST-NET-3, RFC 5737; `2001:db8::/32` is documentation space, RFC 3849) — substitute the box's real Hetzner IPv4/IPv6.

```
$ORIGIN kyriakon.net.
$TTL 3600

@	IN	SOA	ns0.kyriakon.net. hostmaster.kyriakon.net. (
			2024082401	; serial  (YYYYMMDDNN — bump on every edit)
			3600		; refresh — HE re-checks at least this often
			900		; retry
			1209600		; expire  (14 days — how long HE keeps serving if primary dies)
			3600		; negative-cache TTL
			)

; Public delegation: HE's anycast secondaries ONLY. The hidden primary
; (ns0 / this box) is deliberately ABSENT from NS.
@	IN	NS	ns1.he.net.
@	IN	NS	ns2.he.net.
@	IN	NS	ns3.he.net.
@	IN	NS	ns4.he.net.
@	IN	NS	ns5.he.net.

; SOA MNAME resolves to the hidden primary (so `dig SOA` / tooling can reach
; it), but it is NOT in NS — hidden, not public.
ns0	IN	A	203.0.113.10
ns0	IN	AAAA	2001:db8::10

; Apex — the box's real IPs. Mail, SSH/git, Gemini, and the landing site all
; resolve here (proposal §5.7: the box's IP is public by design).
@	IN	A	203.0.113.10
@	IN	AAAA	2001:db8::10

; MX — mail delivered to the box. No secondary MX in MVP (§6.11 layer 3 deferred).
@	IN	MX	10 mail.kyriakon.net.
mail	IN	A	203.0.113.10
mail	IN	AAAA	2001:db8::10

; SPF — box is the only sender. "mx" covers the MX host; "-all" hard-fails rest.
@	IN	TXT	"v=spf1 mx -all"

; DKIM — public key for selector "mail" (rename to a dated selector like "2024"
; to make yearly rotation trivial, §6.2). Base64 body is the public half only.
mail._domainkey	IN	TXT	"v=DKIM1; k=rsa; p=<base64-public-key>"

; DMARC — start p=none with aggregate reporting, tighten later (§6.2).
_dmarc	IN	TXT	"v=DMARC1; p=none; rua=mailto:dmarc@kyriakon.net"

; Wildcard — one record serves every per-user subdomain (username.kyriakon.net,
; §5.2). This is a wildcard A/AAAA RECORD, not a wildcard cert: acme-client is
; HTTP-01 only, so per-user certs are issued individually per signup (§5.2).
*	IN	A	203.0.113.10
*	IN	AAAA	2001:db8::10
```

Zone-file mechanics worth stating explicitly:

- **Serial must increment on every edit** or HE's secondaries won't pick up the change. The SOA `serial` is the single source of "has the zone changed" for both NOTIFY-triggered and refresh-timer-triggered transfers (SOA semantics, [RFC 1035 §3.3.13](https://www.rfc-editor.org/rfc/rfc1035)).
- **The `refresh` value is HE's re-check floor.** HE "mak[es] periodic checks (depending on your TTL)" ([dns.he.net](https://dns.he.net/)); with NOTIFY working, transfers are prompt, but `refresh` bounds worst-case staleness if a NOTIFY is lost.
- `nsd` answers AXFR on TCP port 53 — the box's `pf.conf` must allow **TCP/53 from HE's transfer IPs** (and only them) inbound, separate from the UDP/53 public-query rule. This is the one firewall change the hidden-primary pattern adds over a plain authoritative server.
- `@` is shorthand for `$ORIGIN`; the trailing dots matter (FQDN vs. relative-to-origin). The template above keeps them explicit.

---

## 3. Hurricane Electric secondary — signup & transfer requirements

HE's free DNS is the `dns.he.net` portal. Primary-source facts:

- **Records supported** include `A, AAAA, ALIAS, CNAME, CAA, MX, NS, TXT, SRV, SSHFP, SPF, RP, NAPTR, HINFO, LOC, PTR` — everything the §4 record set needs — plus explicit "Slave support" and "Geographically diverse servers" ([dns.he.net](https://dns.he.net/)).
- **Account:** free — sign up via the IPv6-certification/tunnelbroker registration link, or, for existing `admin.he.net` accounts, email `support@he.net` for a DNS password ([dns.he.net](https://dns.he.net/)).
- **Add the domain as a slave/secondary** pointing at the hidden primary's IP. The portal then validates the transfer: *"Secondary domains that disallow AXFR's will be deactivated until they have been validated. You can validate the domain by selecting it from the 'Slave domains for this account' … This will attempt to pull the zone from the specified nameserver(s). If it is successful, it will validate the domain and will start listening to your nameservers NOTIFY packets as well as making periodic checks (depending on your TTL)."* ([dns.he.net](https://dns.he.net/)).
- **Delegation** is to HE's anycast nameservers `ns1.he.net` … `ns5.he.net` (verified via `dig NS he.net`; the five addresses are `216.218.130.2`, `216.218.131.2`, `216.218.132.2`, `216.66.1.2`, `216.66.80.18`). These five go in the registrar's NS field and in the zone's NS records (§2).

Consequences for the primary:

1. The box's IP **must be reachable on TCP/53 by HE** for the initial AXFR and any refresh transfer (AXFR runs over TCP; `nsd` serves it per [nsd.conf(5)](https://man.openbsd.org/nsd.conf.5)). This is the "box IP is public by design" reality from §5.7 made concrete — the hidden-primary pattern hides the DNS *answering* service from public NS records, not the box from the network.
2. `provide-xfr` must allow **HE's transfer source IPs** (not the anycast query IPs necessarily — capture them at validation time, §1).
3. `notify` must reach HE so changes propagate immediately rather than waiting out `refresh`.

HE free secondary is DNS-only redundancy: it keeps answering from the last transferred zone if the box goes down (§5.7, §6.11), but it does not queue or deliver mail (that's the deferred secondary-MX layer, §6.11 layer 3).

---

## 4. Record set for mail go-live

| Record | Name | Type | Value | Authority / note |
|---|---|---|---|---|
| NS (×5) | `@` | NS | `ns1.he.net.` … `ns5.he.net.` | Public delegation = HE only; hidden primary absent ([dns.he.net](https://dns.he.net/)). |
| A / AAAA | `@` | A/AAAA | box IPv4 / IPv6 | Mail, SSH, Gemini, landing site all resolve to the box (§5.7). |
| MX | `@` | MX | `10 mail.kyriakon.net.` | Mail routing; `10` = preference (lower wins). Single MX — no secondary in MVP ([RFC 5321 §5.1](https://www.rfc-editor.org/rfc/rfc5321)). |
| A / AAAA | `mail` | A/AAAA | box IPv4 / IPv6 | The MX target must resolve. |
| SPF | `@` | TXT | `v=spf1 mx -all` | Authorizes the MX host as the only sender; `-all` hard-fails all else ([RFC 7208 §4](https://www.rfc-editor.org/rfc/rfc7208)). |
| DKIM | `mail._domainkey` | TXT | `v=DKIM1; k=rsa; p=<base64>` | Public key at `<selector>._domainkey.<domain>` ([RFC 6376 §3.6.1](https://www.rfc-editor.org/rfc/rfc6376)). |
| DMARC | `_dmarc` | TXT | `v=DMARC1; p=none; rua=mailto:dmarc@kyriakon.net` | `p=none` (monitor only) + aggregate reporting, per §6.2 ([RFC 7489 §6.3](https://www.rfc-editor.org/rfc/rfc7489)). |
| Wildcard | `*` | A/AAAA | box IPv4 / IPv6 | Per-user subdomains (§5.2). |
| PTR | — (not in zone) | PTR | `203.0.113.10` → `mail.kyriakon.net.` | Set at **Hetzner**, see below. |

### 4.1 DKIM — selector and key placement

- **Selector** is chosen by the operator and forms the record *name*: the public key lives at `<selector>._domainkey.kyriakon.net`, e.g. `mail._domainkey` for selector `mail` ([RFC 6376 §3.6.2.1](https://www.rfc-editor.org/rfc/rfc6376)). Use a selector that makes rotation cheap — `mail` for MVP, or a dated selector (`2024`) so yearly rotation (§6.2) is just "add a new record + switch the signer."
- **Key placement — public in DNS, private on the box, never in git.** OpenSMTPD signs via the `opensmtpd-filter-dkimsign` package filter, which takes the private key path on the box: `filter "dkimsign" proc-exec "filter-dkimsign -d <domain> -s <selector> -k /etc/mail/dkim/private.key" user _dkimsign group _dkimsign` ([smtpd.conf(5)](https://man.openbsd.org/smtpd.conf.5)). So:
  - **Private key** → `/etc/mail/dkim/private.key` on the box, run as the `_dkimsign` user, **excluded from the public `kyriakon-infra` repo** (§5.6: "Everything here is public except secrets themselves (DKIM private keys…)").
  - **Public key** → the `p=` tag of the `mail._domainkey` TXT record (§2). Only the public half is ever published.

### 4.2 PTR is set at Hetzner, not in the zone

Forward zone files can't set reverse records — PTR lives in the `in-addr.arpa` / `ip6.arpa` zones owned by whoever owns the IP block, which for a Hetzner Cloud VPS is Hetzner ([RFC 1035 §3.3.12](https://www.rfc-editor.org/rfc/rfc1035) defines PTR; reverse zones delegated from the address space holder). Set the reverse DNS (rDNS) for the mail IP via Hetzner, matching it to the forward hostname (`mail.kyriakon.net`) — the "make sure your PTR and A records match" rule ([RFC 1912 §2.1](https://www.rfc-editor.org/rfc/rfc1912)) is the deliverability point §6.2 flags.

Via hcloud CLI:

```sh
hcloud server set-rdns --ip <box-ipv4> --hostname mail.kyriakon.net <server>
hcloud server set-rdns --ip <box-ipv6> --hostname mail.kyriakon.net <server>
```

Command and flags from the hcloud source: `set-rdns [--ip <ip>] (--hostname <hostname> | --reset) <server>`, with `--hostname` ("Hostname to set as a reverse DNS PTR entry") and `--reset` ("Reset the reverse DNS entry to the default value") ([hcloud CLI `set_rdns.go`](https://github.com/hetznercloud/cli/blob/main/internal/cmd/server/set_rdns.go), wrapping `RDNS().ChangeDNSPtr`). The same field is editable in the Hetzner Cloud Console under the server's IP settings.

Hetzner requires the rDNS *hostname* to already resolve forward to the IP before it will serve the PTR — so the forward A/AAAA for `mail.kyriakon.net` (§2) must be live first. This makes PTR a **Hetzner-side step sequenced after the zone is published**, not a record in `kyriakon.net`.

### 4.3 Wildcard is a record, not a cert

`*.kyriakon.net` is a **wildcard A/AAAA record** so any `username.kyriakon.net` resolves to the box without a DNS write per signup (§5.2). It is *not* a wildcard TLS cert: `acme-client` implements HTTP-01 only, not DNS-01, so there is no `*.kyriakon.net` certificate — each signup issues its own per-user cert for `username.kyriakon.net` over HTTP-01 (§5.2, "confirmed against the current man page, a permanent scope decision"). The wildcard record and the per-user cert issuance are independent; the record just means every subdomain resolves to the same IP, while each hostname still gets its own cert.

---

## 5. Ordering — zone published before mail goes live

The dependency is one-directional: deliverability depends on DNS, not the reverse. Sequence:

1. **Zone + `nsd.conf` committed to the repo** (§2), `nsd` configured and serving locally.
2. **HE secondary added and validated** (§3): add slave domain → HE pulls AXFR → validated → NOTIFY live. Verify publicly with `dig @ns1.he.net kyriakon.net AXFR`/`SOA` and confirm the zone propagates.
3. **Registrar NS changed** to `ns1.he.net` … `ns5.he.net` (if not already), so public queries hit HE.
4. **Forward records verified** publicly — MX, SPF (`v=spf1 mx -all`), DKIM (`mail._domainkey`), DMARC (`_dmarc`), wildcard.
5. **PTR set at Hetzner** (§4.2) — needs the forward `mail` A/AAAA live first.
6. **Mail go-live** — SMTP/IMAP/`smtpd` with the DKIM filter (§4.1), then §6.2's pre-send reputation checks (MXToolbox / mail-tester / Spamhaus check on the assigned IP) and dogfood first.

This ordering is what §5.7/§6.13 mean by "DNS redundancy from day one": HE is serving the zone before the first message is sent, so mail-related records are already anycast-resilient at go-live.

---

## Sources

- [OpenBSD `nsd.conf(5)`](https://man.openbsd.org/nsd.conf.5) — file format, hidden-primary EXAMPLE, `notify`/`provide-xfr`/`allow-notify`/`request-xfr`/`outgoing-interface`/`notify-retry` semantics, `_nsd` user + `/var/nsd` chroot paths, `kill -HUP` reload.
- [OpenBSD `smtpd.conf(5)`](https://man.openbsd.org/smtpd.conf.5) — DKIM signing via `opensmtpd-filter-dkimsign` (`-d <domain> -s <selector> -k /etc/mail/dkim/private.key`, `_dkimsign` user).
- [Hurricane Electric free DNS — `dns.he.net`](https://dns.he.net/) — free account signup, supported record types, "Slave support," secondary AXFR validation + NOTIFY/periodic-check behaviour.
- `dig NS he.net` (run during this research) — HE's public nameservers `ns1`–`ns5.he.net` and their IPv4 addresses.
- [RFC 1035 — Domain Names — Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035) — SOA (§3.3.13), PTR (§3.3.12).
- [RFC 1912 — Common DNS Operational and Configuration Errors](https://www.rfc-editor.org/rfc/rfc1912) — §2.1 PTR/A matching.
- [RFC 5321 — Simple Mail Transfer Protocol](https://www.rfc-editor.org/rfc/rfc5321) — §5.1 MX record / target-host location.
- [RFC 7208 — Sender Policy Framework](https://www.rfc-editor.org/rfc/rfc7208) — SPF TXT record format and mechanisms.
- [RFC 6376 — DomainKeys Identified Mail (DKIM) Signatures](https://www.rfc-editor.org/rfc/rfc6376) — §3.6.1 textual record, §3.6.2.1 selector/key tag placement.
- [RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489) — §6.3 record location/format, `p=` policy.
- [hcloud CLI — `server set_rdns.go`](https://github.com/hetznercloud/cli/blob/main/internal/cmd/server/set_rdns.go) and [base `set_rdns.go`](https://github.com/hetznercloud/cli/blob/main/internal/cmd/base/set_rdns.go) — `hcloud server set-rdns --ip … --hostname …`, wrapping `ChangeDNSPtr`.
- Kyriakon project proposal `../kyriakon/docs/decisions/kyriakon-net-project-proposal.md` — §5.7/§6.13 (hidden primary + HE), §5.2 (wildcard record, per-user certs, HTTP-01 only), §6.2 (DMARC `p=none` start, DKIM rotation), §6.11 (secondary MX deferred), §5.6 (DKIM private keys excluded from the repo).
