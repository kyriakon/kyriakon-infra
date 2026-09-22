#!/bin/ksh
# gen-finger-page.sh — print the page fingerd serves, to stdout.
#
# Reads, from this repo:
#   openbsd/etc/finger.txt   the fixed prose
#   openbsd/etc/httpd.conf   which vhosts serve content over TLS
#   openbsd/etc/gmid.conf    which capsules serve Gemini
#
# The endpoint list is derived rather than maintained, so adding a vhost is the
# only edit needed for it to appear, and the page cannot advertise something the
# box does not serve. An httpd block counts as public when it terminates TLS on
# 443 and is not a pure redirect: that excludes the www and kyriakon.com
# redirectors, and it excludes every port 80 block, which exists only to answer
# the ACME challenge. A gmid block is public by definition, since gmid has no
# other reason to name a host.
#
# Output is plain LF, not CRLF. fingerd converts every newline to CRLF itself while
# copying the provider's stdout out to the client, so writing CRLF here doubles the
# carriage return on every line and inserts a stray blank line between them.
#
# Prints for a finger client, so reading it with cat on the box is the way to see
# what is actually served.

set -euo pipefail

repo_dir=$(cd "$(dirname "$0")/.." && pwd)

prose="$repo_dir/openbsd/etc/finger.txt"
httpd_conf="$repo_dir/openbsd/etc/httpd.conf"
gmid_conf="$repo_dir/openbsd/etc/gmid.conf"

for f in "$prose" "$httpd_conf" "$gmid_conf"; do
	if [ ! -r "$f" ]; then
		printf 'gen-finger-page: cannot read %s\n' "$f" >&2
		exit 1
	fi
done

cat "$prose"
printf '\n'

{
	awk '
		/^#/ { next }
		/^server "/ {
			name = $2
			gsub(/"/, "", name)
			inblock = 1
			tls = 0
			redirect = 0
			next
		}
		inblock && /listen on .*tls port 443/ { tls = 1 }
		inblock && /block return/ { redirect = 1 }
		inblock && /^}/ {
			if (tls && !redirect) { print "https://" name }
			inblock = 0
		}
	' "$httpd_conf"

	awk '
		/^#/ { next }
		/^server "/ {
			name = $2
			gsub(/"/, "", name)
			print "gemini://" name
		}
	' "$gmid_conf"
} | sort -u | awk '{ print "  " $0 }'
