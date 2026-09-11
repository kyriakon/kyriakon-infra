#!/bin/ksh
# deploy-nsd.sh — install the kyriakon.net zone + nsd.conf on the box, start
# nsd, and verify it answers locally.
#
# Runs ON the box as root (invoke under doas). It does NOT touch pf.conf — the
# inbound TCP/53 rule is the propose-only half of #24 and stays a manual, human
# step. This script substitutes the box's real IPs and the HMAC-SHA256 TSIG
# secret HE signs its AXFR requests with into the deployed nsd.conf.
#
# Usage:
#   doas ksh deploy-nsd.sh <ipv4> <ipv6> <tsig-secret> [src_dir]
#
#   <ipv4> <ipv6>   the box's real Hetzner IPs
#                   (terraform output ipv4_address ipv6_address)
#   <tsig-secret>   the base64 HMAC-SHA256 secret shared with HE. Key name is
#                   kyriakon-he and the algorithm is hmac-sha256, both fixed in
#                   nsd.conf; the same name/algorithm must be set on the HE
#                   portal's slave entry for kyriakon.net. Generate your own
#                   with `openssl rand -base64 32`, or paste what HE generated.
#                   NOTE: argv is visible to other users on the box via ps(1)
#                   for the run's lifetime, and a literal in the command would
#                   be recorded in the shell's history file. Assign it with
#                   `read -rs` or export it instead of typing it inline. The
#                   value is never echoed and lands only in
#                   /var/nsd/etc/nsd.conf (chmod 0640, root).
#   src_dir         dir containing kyriakon.net.zone and nsd.conf; defaults to
#                   this script's directory.

set -euo pipefail

usage() {
	printf 'usage: doas ksh %s <ipv4> <ipv6> <tsig-secret> [src_dir]\n' "$0" >&2
	exit 2
}

[ "$#" -ge 3 ] || usage
ipv4="$1"
ipv6="$2"
secret="$3"
src_dir="${4:-$(dirname "$0")}"

zone_src="$src_dir/kyriakon.net.zone"
conf_src="$src_dir/nsd.conf"
zone_dst=/var/nsd/etc/kyriakon.net.zone
conf_dst=/var/nsd/etc/nsd.conf

[ -r "$zone_src" ] || { printf 'zone not found: %s\n' "$zone_src" >&2; exit 1; }
[ -r "$conf_src" ] || { printf 'nsd.conf not found: %s\n' "$conf_src" >&2; exit 1; }

# Trust-boundary guards — refuse obviously-wrong inputs, never serve a bogus
# zone or leak a malformed secret into a live config. Loose on purpose.
printf '%s' "$ipv4" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
	|| { printf 'invalid ipv4: %s\n' "$ipv4" >&2; exit 1; }
printf '%s' "$ipv6" | grep -Eq ':' \
	|| { printf 'invalid ipv6: %s\n' "$ipv6" >&2; exit 1; }
# Reject the repo placeholder so a stale value never ships, and anything nsd
# cannot parse as a base64 secret.
case "$secret" in
	REPLACE_ME|'') printf 'refusing placeholder/empty tsig-secret\n' >&2; exit 1;;
esac
printf '%s' "$secret" | grep -Eq '^[A-Za-z0-9+/=]+$' \
	|| { printf 'tsig-secret is not clean base64\n' >&2; exit 1; }

install -d -m 0755 /var/nsd/etc

# Zone: substitute the RFC 5737/3849 documentation placeholders with the real
# IPs (appear in five records each: ns0, apex, mail, wildcard).
sed -e "s/203\.0\.113\.10/$ipv4/g" -e "s/2001:db8::10/$ipv6/g" "$zone_src" > "$zone_dst"

# nsd.conf: substitute the TSIG secret. '|' delimits the s/// because base64
# secrets routinely contain '/', which would end a '/'-delimited expression
# mid-secret. The secret is written only into the deployed file, never stdout.
sed -e "s|REPLACE_ME|$secret|" "$conf_src" > "$conf_dst"

# On-box perms: nsd chroots to /var/nsd and reads this before dropping to
# _nsd, so root-only is right and the secret stays out of the chroot's reach.
chmod 0640 "$conf_dst"
chmod 0644 "$zone_dst"

# Guard: no placeholder may survive into the deployed files. Skip `;` comment
# lines in the zone — the header legitimately names the RFC ranges as prose.
if grep -v '^;' "$zone_dst" | grep -Eq '203\.0\.113|2001:db8'; then
	printf 'zone still contains documentation placeholders - check your ipv4/ipv6 args\n' >&2
	exit 1
fi
if grep -Eq 'REPLACE_ME|NOKEY' "$conf_dst"; then
	printf 'nsd.conf still contains a placeholder (REPLACE_ME / NOKEY)\n' >&2
	exit 1
fi

# Syntax-check (must print nothing). nsd-checkconf validates the key block:
# algorithm, secret base64, and that every provide-xfr references a defined key.
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

printf 'nsd is serving kyriakon.net locally, TSIG key kyriakon-he.\n' >&2
printf 'next (manual): confirm the pf TCP/53 inbound rule, then run the HE portal\n' >&2
printf 'validation. TSIG is only proven live by a signed AXFR from HE.\n' >&2
