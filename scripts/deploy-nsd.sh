#!/bin/ksh
# deploy-nsd.sh — install the kyriakon.net zone + nsd.conf on the box, start nsd,
# and verify it answers locally.
#
# Runs ON the box as root (invoke under doas). It does NOT touch pf.conf and does
# NOT fill in Hurricane Electric's transfer IPs — those are the propose-only / #24
# steps. The zone's real IPs are substituted here from the two required arguments;
# any HE notify/provide-xfr lines still carrying <he-transfer-ip> placeholders are
# commented out in the deployed copy until #24 captures the real IPs.
#
# Usage (after scp'ing this file + kyriakon.net.zone + nsd.conf into one dir):
#   doas ksh deploy-nsd.sh <ipv4> <ipv6> [src_dir]
#
#   <ipv4> <ipv6>   the box's real Hetzner IPs
#                   (terraform output ipv4_address ipv6_address, on the box that
#                    holds state)
#   src_dir         dir containing kyriakon.net.zone and nsd.conf; defaults to
#                   this script's directory.

set -euo pipefail

usage() {
	printf 'usage: doas ksh %s <ipv4> <ipv6> [src_dir]\n' "$0" >&2
	exit 2
}

[ "$#" -ge 2 ] || usage
ipv4="$1"
ipv6="$2"
src_dir="${3:-$(dirname "$0")}"

zone_src="$src_dir/kyriakon.net.zone"
conf_src="$src_dir/nsd.conf"
zone_dst=/var/nsd/etc/kyriakon.net.zone
conf_dst=/var/nsd/etc/nsd.conf

[ -r "$zone_src" ] || { printf 'zone not found: %s\n' "$zone_src" >&2; exit 1; }
[ -r "$conf_src" ] || { printf 'nsd.conf not found: %s\n' "$conf_src" >&2; exit 1; }

# Trust-boundary guard: refuse obviously-wrong inputs rather than serve a bogus
# zone. Loose on purpose — a dotted-quad IPv4 and a colon-containing IPv6.
printf '%s' "$ipv4" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
	|| { printf 'invalid ipv4: %s\n' "$ipv4" >&2; exit 1; }
printf '%s' "$ipv6" | grep -Eq ':' \
	|| { printf 'invalid ipv6: %s\n' "$ipv6" >&2; exit 1; }

install -d -m 0755 /var/nsd/etc

# Zone: substitute the RFC 5737/3849 documentation placeholders with the real
# IPs. The placeholders appear in five records each (ns0, apex, mail, wildcard).
sed -e "s/203\.0\.113\.10/$ipv4/g" -e "s/2001:db8::10/$ipv6/g" "$zone_src" > "$zone_dst"

# nsd.conf: comment out any HE notify/provide-xfr line still carrying a
# <he-transfer-ip> placeholder — nsd-checkconf rejects them, and the real IPs
# aren't known until #24. If the repo file already has real IPs filled in, no
# line matches and they stay active, so this is safe either way.
sed '/he-transfer-ip/s/^/# /' "$conf_src" > "$conf_dst"

chmod 0644 "$zone_dst" "$conf_dst"

# Guard: no placeholder may survive into the deployed RECORDS. Skip `;` comment
# lines — the header legitimately names the RFC 5737 (203.0.113.0/24) and
# RFC 3849 (2001:db8::/32) ranges as documentation, which are prose, not
# placeholders to substitute, so a whole-file grep false-positives on them.
if grep -v '^;' "$zone_dst" | grep -Eq '203\.0\.113|2001:db8'; then
	printf 'zone still contains documentation placeholders - check your ipv4/ipv6 args\n' >&2
	exit 1
fi

# Syntax-check (must print nothing), then enable + start (restart if already up).
nsd-checkconf "$conf_dst"
rcctl enable nsd
if rcctl check nsd >/dev/null 2>&1; then
	rcctl restart nsd
else
	rcctl start nsd
fi

# Verify the box answers with exactly the IPs we just wrote.
serial=$(dig @127.0.0.1 kyriakon.net SOA +short | awk '{print $3}')
got4=$(dig @127.0.0.1 kyriakon.net A +short)
got6=$(dig @127.0.0.1 kyriakon.net AAAA +short)
printf 'SOA serial: %s\n' "$serial"
printf 'MX:         %s\n' "$(dig @127.0.0.1 kyriakon.net MX +short)"
printf 'A:          %s\n' "$got4"
printf 'AAAA:       %s\n' "$got6"
[ "$got4" = "$ipv4" ] || { printf 'A record mismatch: wanted %s got %s\n' "$ipv4" "$got4" >&2; exit 1; }
[ "$got6" = "$ipv6" ] || { printf 'AAAA record mismatch: wanted %s got %s\n' "$ipv6" "$got6" >&2; exit 1; }

printf 'nsd is serving kyriakon.net locally.\n'
printf 'next: after #24 captures the HE transfer IPs, un-comment notify/provide-xfr in\n'
printf '%s and add the pf TCP/53 rule.\n' "$conf_dst"
