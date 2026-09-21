#!/bin/ksh
# deploy-nsd.sh — install the kyriakon.net zone + nsd.conf on the box, start
# nsd, and verify it answers locally. Also installs /etc/hostname.vio0, since
# this script is what publishes the box's IPv6 address in DNS and Hetzner does
# not send router advertisements, so an unconfigured interface would answer no
# AAAA at all.
#
# Runs ON the box as root (invoke under doas). It does NOT touch pf.conf — the
# inbound TCP/53 rule is the propose-only half of #24 and stays a manual, human
# step. This script substitutes the box's real IPs and the HMAC-SHA256 TSIG
# secret HE signs its AXFR requests with into the deployed nsd.conf.
#
# Usage:
#   doas ksh deploy-nsd.sh [ipv4] [ipv6] [tsig-secret] [src_dir]
#
#   <ipv4> <ipv6>   the box's real Hetzner IPs. Omit them to take
#                   KYRIAKON_IPV4 / KYRIAKON_IPV6 from /root/.kyriakon-env
#                   (terraform output ipv4_address ipv6_address).
#   <tsig-secret>   the base64 HMAC-SHA256 secret shared with HE. Key name is
#                   kyriakon-he and the algorithm is hmac-sha256, both fixed in
#                   nsd.conf; the same name/algorithm must be set on the HE
#                   portal's slave entry for kyriakon.net. Generate your own
#                   with `openssl rand -base64 32`, or paste what HE generated.
#                   Omit it to take KYRIAKON_TSIG_SECRET from /root/.kyriakon-env,
#                   which is mode 0600, and never type it inline: argv is visible
#                   to other users through ps(1) for the run's lifetime, and a
#                   literal is recorded in the shell's history. The value is never
#                   echoed and lands only in /var/nsd/etc/nsd.conf (0640, root).
#   src_dir         dir containing kyriakon.net.zone and nsd.conf; defaults to
#                   this script's directory. hostname.vio0 is read from
#                   src_dir/.. , which is openbsd/etc/ in the repo layout.

set -euo pipefail

env_file="${KYRIAKON_ENV:-/root/.kyriakon-env}"
if [ -r "$env_file" ]; then
	# shellcheck disable=SC1090 # the path is the operator's, not a fixed literal
	. "$env_file"
fi

usage() {
	printf 'usage: doas ksh %s [ipv4] [ipv6] [tsig-secret] [src_dir]\n' "$0" >&2
	printf '       anything omitted is read from %s, whose template is\n' "$env_file" >&2
	printf '       openbsd/etc/kyriakon.env in this repo\n' >&2
	exit 2
}

# Arguments first, so a box that is not this one can be served from elsewhere, and
# the env file otherwise, so a rebuild is one command with nothing retyped.
ipv4="${1:-${KYRIAKON_IPV4:-}}"
ipv6="${2:-${KYRIAKON_IPV6:-}}"
secret="${3:-${KYRIAKON_TSIG_SECRET:-}}"
src_dir="${4:-$(dirname "$0")}"
if [ -z "$ipv4" ] || [ -z "$ipv6" ] || [ -z "$secret" ]; then
	usage
fi

# Every *.zone beside nsd.conf is served: kyriakon.net is the mail domain and
# kyriakon.com is a defensive registration, and both live here so the second one
# cannot drift from the first. Adding a third zone is adding a file.
conf_src="$src_dir/nsd.conf"
conf_dst=/var/nsd/etc/nsd.conf
# hostname.vio0 lives in openbsd/etc/, one level up from openbsd/etc/nsd/.
iface_src="$src_dir/../hostname.vio0"
iface_dst=/etc/hostname.vio0

zone_count=0
for z in "$src_dir"/*.zone; do
	[ -r "$z" ] && zone_count=$((zone_count + 1))
done
[ "$zone_count" -gt 0 ] || { printf 'no *.zone files found in %s\n' "$src_dir" >&2; exit 1; }
[ -r "$conf_src" ] || { printf 'nsd.conf not found: %s\n' "$conf_src" >&2; exit 1; }
[ -r "$iface_src" ] || { printf 'hostname.vio0 not found: %s\n' "$iface_src" >&2; exit 1; }

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

# 0750 root:_nsd, as /etc/mtree/special declares for this path. A bare
# `install -d` gives 0755 root:wheel, and the daily security(8) mail reports the
# difference. The group is part of the fix: nsd runs as _nsd inside the /var/nsd
# chroot, so it has to be able to read its own etc directory.
install -d -m 0750 -o root -g _nsd /var/nsd/etc

# Zones: substitute the RFC 5737/3849 documentation placeholders with the real
# IPs. kyriakon.net carries them in four record sets (ns0, apex, mail and a
# wildcard), kyriakon.com in one (the apex, which only redirects).
zone_names=
for zone_src in "$src_dir"/*.zone; do
	[ -r "$zone_src" ] || continue
	zone_name=$(basename "$zone_src" .zone)
	zone_dst="/var/nsd/etc/$zone_name.zone"
	sed -e "s/203\.0\.113\.10/$ipv4/g" -e "s/2001:db8::10/$ipv6/g" "$zone_src" > "$zone_dst"
	chmod 0644 "$zone_dst"
	zone_names="$zone_names $zone_name"
done

# Interface config: the same documentation IPv6 placeholder, so the address the
# zone advertises is the address the box holds. Nothing else sets this up, and
# Hetzner sends no router advertisement, so without this file the box serves an
# AAAA it cannot answer.
sed -e "s/2001:db8::10/$ipv6/g" "$iface_src" > "$iface_dst"
chmod 0644 "$iface_dst"

# nsd.conf: substitute the TSIG secret. '|' delimits the s/// because base64
# secrets routinely contain '/', which would end a '/'-delimited expression
# mid-secret. The secret is written only into the deployed file, never stdout.
sed -e "s|REPLACE_ME|$secret|" "$conf_src" > "$conf_dst"

# On-box perms: nsd chroots to /var/nsd and reads this before dropping to
# _nsd, so root-only is right and the secret stays out of the chroot's reach.
chmod 0640 "$conf_dst"

# Per-zone guards, run over what the loop above actually wrote. A surviving
# placeholder means the IP arguments were wrong, and a parse error leaves nsd
# running and serving nothing for that domain, which looks like a silent outage.
# `;` comment lines are skipped because the zone headers legitimately name the
# RFC ranges as prose.
for zone_name in $zone_names; do
	zone_dst="/var/nsd/etc/$zone_name.zone"
	if grep -v '^;' "$zone_dst" | grep -Eq '203\.0\.113|2001:db8'; then
		printf '%s still contains documentation placeholders - check your ipv4/ipv6 args\n' "$zone_name" >&2
		exit 1
	fi
	nsd-checkzone "$zone_name" "$zone_dst"
done
if grep -Eq 'REPLACE_ME|NOKEY' "$conf_dst"; then
	printf 'nsd.conf still contains a placeholder (REPLACE_ME / NOKEY)\n' >&2
	exit 1
fi
if grep -Eq '2001:db8' "$iface_dst"; then
	printf 'hostname.vio0 still contains the documentation placeholder\n' >&2
	exit 1
fi

# Put the address on the interface now, if it is not already there. Services
# bind interface addresses at startup, so anything started before this would
# come up without it and the box would publish an AAAA nothing answers. Adding
# an address does not disturb the interface or drop the session running this.
if ifconfig vio0 | grep -q "$ipv6"; then
	printf 'vio0 already holds %s\n' "$ipv6"
else
	printf 'adding %s to vio0\n' "$ipv6"
	ifconfig vio0 inet6 "$ipv6" prefixlen 64
	route add -inet6 default fe80::1%vio0 2>/dev/null \
		|| printf 'default v6 route already present, or the add failed; check route -n show -inet6\n'
fi

# Syntax-check both, and check the *zone* rather than only the config:
# nsd-checkconf validates nsd.conf, while a zone parse error leaves nsd running
# and serving nothing for that domain, which looks like a silent outage.
nsd-checkconf "$conf_dst"

# Any nsd left over from a config without remote-control cannot be signalled
# through nsd-control, and a second nsd would fail to bind port 53. Clear it by
# name so this script is idempotent from any prior state.
pkill -x nsd >/dev/null 2>&1 || true
sleep 1

rcctl enable nsd
rcctl start nsd
rcctl check nsd >/dev/null 2>&1 \
	|| { printf 'nsd did not start; see /var/log/nsd.log and /var/log/messages\n' >&2; exit 1; }

# Verify the box answers with exactly the IPs we just wrote, and that it serves
# every zone at all: a zone nsd refuses to load would otherwise pass unnoticed.
for zone_name in $zone_names; do
	printf 'SOA %-13s %s\n' "$zone_name" "$(dig @127.0.0.1 "$zone_name" SOA +short | awk '{print $3}')"
done
serial=$(dig @127.0.0.1 kyriakon.net SOA +short | awk '{print $3}')
got4=$(dig @127.0.0.1 kyriakon.net A +short)
got6=$(dig @127.0.0.1 kyriakon.net AAAA +short)
printf 'SOA serial: %s\n' "$serial"
printf 'MX:         %s\n' "$(dig @127.0.0.1 kyriakon.net MX +short)"
printf 'A:          %s\n' "$got4"
printf 'AAAA:       %s\n' "$got6"
printf 'IPv6 addr:  %s\n' "$(ifconfig vio0 | awk '/inet6 .*prefixlen 64/ && !/fe80/ {print $2}')"
[ "$got4" = "$ipv4" ] || { printf 'A record mismatch: wanted %s got %s\n' "$ipv4" "$got4" >&2; exit 1; }
[ "$got6" = "$ipv6" ] || { printf 'AAAA record mismatch: wanted %s got %s\n' "$ipv6" "$got6" >&2; exit 1; }
ifconfig vio0 | grep -q "$ipv6" \
	|| { printf 'vio0 does not hold %s, so the AAAA just published is unanswered\n' "$ipv6" >&2; exit 1; }

printf 'nsd is serving kyriakon.net locally, TSIG key kyriakon-he.\n' >&2
printf 'next (manual): confirm the pf TCP/53 inbound rule, then run the HE portal\n' >&2
printf 'validation. TSIG is only proven live by a signed AXFR from HE.\n' >&2
