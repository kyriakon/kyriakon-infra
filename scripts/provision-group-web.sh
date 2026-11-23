#!/bin/ksh
# provision-group-web.sh: an own-domain body's httpd vhosts, as one file.
#
# Usage:
#   doas ksh scripts/provision-group-web.sh <domain> <site-account>
#        ksh scripts/provision-group-web.sh --self-test
#
# Runs ON the box as root, from the drain's group intent, and again later: the
# loopback blocks appear the moment the domain's certificate file does, so a
# certificate that lands after approval is applied by running this again rather
# than by editing anything by hand. scripts/acme-queue.sh runs it when it issues.
#
# What it writes, and why each shape:
#
#   /etc/httpd.d/<domain>.conf    root:wheel 0644
#
# The site tree is the site owner's member tree, never a directory named after
# the domain. The upload session is chrooted to /home/www/<site-account>.kyriakon.net
# by the hand-applied sshd_config, so the document root is that account's www and
# a body's upload path stays identical to a member's. Writing a root named after
# the domain would need that file changed by hand, which is exactly what the tier
# avoids.
#
# The port 80 blocks come first. Every name the certificate covers needs its own
# HTTP-01 vhost, because acme-client validates each identifier over port 80, so
# the apex and www each get a challenge location and then the 301 to the apex.
# httpd uses the first matching location and ignores the rest, so the challenge
# has to come before the redirect or every renewal is answered with the redirect
# and fails.
#
# The two loopback blocks are the site behind relayd, plain HTTP on 127.0.0.1
# port 8080: relayd terminates TLS for every name and passes the Host header
# through, so the vhost is the shape every other site on the box has. They are
# written only when the certificate file exists, because relayd presents a
# certificate it was told about and a name it has none for is answered with the
# default certificate. Until then the body has a resolving name, a working
# challenge and no site, which is the member's pending state.
#
# The relayd keypair line is not written here. relayd.conf cannot include a file
# where a keypair belongs, so scripts/relayd-members.sh fills the marked region
# from the generated files under /etc/httpd.d, including this one, and
# scripts/cron-apply.sh --web rewrites it. Both appear only once the certificate
# pair is complete, so the loopback blocks, the relayd entry and the reload land
# together.
#
# The paths inside the blocks are httpd's. httpd chroots to /home/www, so
# The site's content is not a root: every path goes to the member content
# responder, which serves the site account's own tree and refuses links, because
# that tree is writable by the account (#815). The vhost is named for the body's
# domain and the files live in the site owner's tree, so this script also writes
# /etc/onboard/static-hosts/<domain> with that tree's name: the responder has no
# other way to know the two differ. root "/acme" is the challenge directory the
# mail deploy created.
#
# Nothing is written when the file already holds the bytes this script would
# write, so a run after a certificate has not landed yet is free.
#
# Env: MAIL_DOMAINS names the mail table the platform's own domain is read from.
# The self-test rebinds it and this script's own paths to a throwaway tree under
# TMPDIR, so it needs no root and touches nothing outside it.
#
# Not this script's job: the site owner's tree (scripts/provision-member.sh), the
# capsule (scripts/provision-group-capsule.sh), the acme-client block and the
# queued order (scripts/provision-group-acme.sh), the index, the relayd region,
# or the reloads (scripts/cron-apply.sh --web).

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

# The key this file writes is not secret, but the temporary file is created here,
# and a 0600 temporary chmodded 0644 before the rename cannot leave a readable
# half-written vhost behind.
umask 077

# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$(dirname "$0")/lib.sh"

httpd_d=/etc/httpd.d
ssl_dir=${SSL_DIR:-/etc/ssl}
ssl_private=${SSL_PRIVATE_DIR:-/etc/ssl/private}
public_root=/home/www
# The responder's host-to-tree map: one file per domain whose files live in the
# site owner's member tree rather than in a directory named after the domain.
static_hosts=/etc/onboard/static-hosts
# The mail table whose first line is the platform's own domain, read the way
# remove-group.sh and the drain read it.
mail_domains=${MAIL_DOMAINS:-/etc/mail/mail_domains}
conf_owner="root:wheel"

usage() {
	cat >&2 <<'USAGE'
usage: doas ksh provision-group-web.sh <domain> <site-account>
       ksh provision-group-web.sh --self-test
USAGE
	exit 2
}

die() {
	printf 'provision-group-web: %s\n' "$*" >&2
	exit 1
}

# A validated FQDN: labels of lowercase letters, digits and hyphens, at least two
# of them, and no label starting or ending with a hyphen. It is the stem of the
# generated file, the server name and a path component under /etc/ssl, so a name
# outside this set could not be a body's domain.
#
# The platform's own domain and everything under it are refused here too, the
# rule the drain applies before it runs this lane: a hand-run
# `provision-group-web.sh kyriakon.net alice` would otherwise write a vhost and a
# host map that collide with the platform's own. The name is the first line of
# mail_domains, and kyriakon.com is refused for the reason remove-group.sh gives.
domain_ok() {
	valid_domain "$1" || return 1
	# The platform's own names are the operator's, the rule the drain applies
	# before it runs this lane; lib.sh holds the rule and its `kyriakon.com`
	# clause so a hand-run does not need a second copy.
	domain_is_platform "$1" "$mail_domains" && return 1
	return 0
}

# The paths, as functions so the self-test rebinds them once.
cert_file() { printf '%s/%s.fullchain.pem' "$ssl_dir" "$domain"; }
key_file() { printf '%s/%s.key' "$ssl_private" "$domain"; }
group_conf() { printf '%s/%s.conf' "$httpd_d" "$domain"; }
site_public() { printf '%s/%s.kyriakon.net' "$public_root" "$account"; }
host_map() { printf '%s/%s' "$static_hosts" "$domain"; }

# The tree this domain is served from, as the responder reads it: the site
# owner's member tree, named rather than derived, because the vhost is named for
# the domain and the files are not under it.
host_map_body() { printf '%s.kyriakon.net\n' "$account"; }

# The file body, printed rather than written so the caller can hold it in a work
# file and compare it with what is already there.
group_conf_body() {
	printf 'server "%s" {\n' "$domain"
	printf '\tlisten on * port 80\n'
	printf '\tlocation "/.well-known/acme-challenge/*" {\n'
	printf '\t\troot "/acme"\n'
	printf '\t\trequest strip 2\n'
	printf '\t}\n'
	printf '\tlocation "/*" {\n'
	# shellcheck disable=SC2016 # httpd substitutes $REQUEST_URI per request, so
	# the generated line carries the token literally and ksh must not expand it
	printf '\t\tblock return 301 "https://%s$REQUEST_URI"\n' "$domain"
	printf '\t}\n'
	printf '}\n'

	# www has to answer the challenge too: it is an alternative name on the
	# same order, so acme-client validates it over port 80 before TLS exists.
	printf '\n'
	printf 'server "www.%s" {\n' "$domain"
	printf '\tlisten on * port 80\n'
	printf '\tlocation "/.well-known/acme-challenge/*" {\n'
	printf '\t\troot "/acme"\n'
	printf '\t\trequest strip 2\n'
	printf '\t}\n'
	printf '\tlocation "/*" {\n'
	# shellcheck disable=SC2016 # as above
	printf '\t\tblock return 301 "https://%s$REQUEST_URI"\n' "$domain"
	printf '\t}\n'
	printf '}\n'

	# The site and its www redirect, only once the certificate is there: the relay
	# presents what /etc/relayd.conf names, and a name it has no keypair for is
	# answered with the default certificate.
	# -s, not -f: an empty chain is an interrupted acme-client write, and the
	# relay cannot present it, so it is no certificate at all.
	[ -s "$(cert_file)" ] || return 0
	printf '\n'
	printf 'server "%s" {\n' "$domain"
	printf '\tlisten on 127.0.0.1 port 8080\n'
	printf '\tlog { style forwarded }\n'
	# No `.git` block and no root: the site owner uploads into their own tree
	# over sftp, so a link planted in it would reach a neighbour's tree or the
	# landing checkout (#815). Every path goes to the responder, which resolves
	# it from the owner's own tree and refuses links and dot components.
	printf '\tlocation "/*" {\n'
	printf '\t\tfastcgi socket "/run/onboard-static-httpd/static.sock"\n'
	printf '\t}\n'
	printf '}\n'

	printf '\n'
	printf 'server "www.%s" {\n' "$domain"
	printf '\tlisten on 127.0.0.1 port 8080\n'
	printf '\tlog { style forwarded }\n'
	printf '\tlocation "/*" {\n'
	# shellcheck disable=SC2016 # as above
	printf '\t\tblock return 301 "https://%s$REQUEST_URI"\n' "$domain"
	printf '\t}\n'
	printf '}\n'
}

# write_group_conf: the file in the shape the domain's certificate calls for.
# Sets conf_changed so the caller can say whether the index and daemon need the
# --web pass.
write_group_conf() {
	typeset target

	# The map first, so a vhost that names the socket is never live before the
	# responder knows which tree the name belongs to. Its write also leaves
	# conf_changed set, which the vhost's write below replaces.
	if ! write_generated "$(host_map)" host_map_body; then
		return 1
	fi

	target=$(group_conf)

	# A certificate without its key is refused by write_generated, which returns 1
	# with the message and leaves the previous file exactly as it was.
	if ! write_generated "$target" group_conf_body "$(cert_file)" "$(key_file)"; then
		return 1
	fi

	if [ "$conf_changed" = no ]; then
		if [ -s "$(cert_file)" ]; then
			printf '%s: unchanged, the site and the www redirect are in place\n' "$target"
		else
			printf '%s: unchanged, port 80 only until %s exists\n' "$target" "$(cert_file)"
		fi
		return 0
	fi

	if [ -s "$(cert_file)" ]; then
		printf 'wrote %s: port 80, the site and the www redirect for %s\n' "$target" "$domain"
		printf '  next: doas ksh scripts/cron-apply.sh --web   # adds the relayd keypair, checks, reloads\n'
	else
		printf 'wrote %s: port 80 for %s and www.%s; the site lands when\n' \
			"$target" "$domain" "$domain"
		printf '  %s exists, which is the certificate queue issuing it\n' "$(cert_file)"
	fi
}

# The last line of defence: the file is there, readable by the daemon that parses
# it, and root's. The expected owner is a variable because the self-test's tree
# belongs to whoever runs the test.
assert_group_conf() {
	typeset conf shape map
	conf=$(group_conf)
	[ -f "$conf" ] || die "$conf is not there after writing it"
	shape=$(stat -f '%Su:%Sg %Lp' "$conf")
	[ "$shape" = "$conf_owner 644" ] || die "$conf is $shape, wanted $conf_owner 644"
	# Without this file the responder looks for a directory named after the
	# domain, finds none and answers 404 for the whole site.
	map=$(host_map)
	[ -f "$map" ] || die "$map is not there after writing it"
	[ "$(cat "$map")" = "$account.kyriakon.net" ] \
		|| die "$map names $(cat "$map"), wanted $account.kyriakon.net"
	shape=$(stat -f '%Su:%Sg %Lp' "$map")
	[ "$shape" = "$conf_owner 644" ] || die "$map is $shape, wanted $conf_owner 644"
}

# The site owner's tree, built by scripts/provision-member.sh. A vhost for a
# name with no tree is a site with nowhere to put it, so this is a refusal.
assert_site_tree() {
	typeset public
	public=$(site_public)
	[ -d "$public" ] || die "no $public: run scripts/provision-member.sh $account first"
	[ -d "$public/www" ] || die "no $public/www: run scripts/provision-member.sh $account first"
}

# --- self-test ---------------------------------------------------------------
#
# The generation is the whole risk, so it is exercised against a throwaway tree:
# the file with no certificate, the file once a certificate exists, a second run
# in each state, and the refusals. Runs as anyone, writes only under TMPDIR.

self_test() {
	typeset tree conf before code map_before
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	httpd_d="$tree/etc/httpd.d"
	ssl_dir="$tree/etc/ssl"
	ssl_private="$ssl_dir/private"
	public_root="$tree/home/www"
	static_hosts="$tree/etc/onboard/static-hosts"
	mail_domains="$tree/etc/mail/mail_domains"
	domain=parish.example
	account=parish-secretary
	install -d -m 0755 "$httpd_d" "$ssl_private" "$public_root/parish-secretary.kyriakon.net/www" \
		"$static_hosts" "$tree/etc/mail"
	# The platform's own domain is the table's first line, as on the box.
	printf 'kyriakon.net\n' > "$mail_domains"
	conf_owner="$(id -un):$(stat -f '%Sg' "$httpd_d")"
	conf=$(group_conf)

	# 1. no certificate: both port 80 names, challenge first, no site
	write_group_conf >/dev/null
	check "the apex block is first" "$(awk 'NR == 1' "$conf")" 'server "parish.example" {'
	check "both names listen on port 80" "$(grep -c 'listen on \* port 80' "$conf")" 2
	check "both names serve the challenge" "$(grep -c 'root "/acme"' "$conf")" 2
	check "the challenge is stripped" "$(grep -c 'request strip 2' "$conf")" 2
	# shellcheck disable=SC2016 # the generated line carries $REQUEST_URI literally
	check "and every other request goes to the apex over https" \
		"$(grep -cF 'block return 301 "https://parish.example$REQUEST_URI"' "$conf")" 2
	check "there is no site behind the relay yet" "$(grep -c '127.0.0.1 port 8080' "$conf")" 0
	check "the file is mode 644 and the writer's" "$(stat -f '%Su:%Sg %Lp' "$conf")" "$conf_owner 644"
	check "the responder's map names the site owner's tree" \
		"$(cat "$(host_map)")" "parish-secretary.kyriakon.net"
	assert_group_conf
	printf '\n%s:\n' "$conf"
	cat "$conf"
	printf '\n'

	# 2. the same again: nothing rewritten
	before=$(stat -f '%i %m' "$conf")
	map_before=$(stat -f '%i %m' "$(host_map)")
	write_group_conf > "$tree/again.out"
	check "a second run leaves the file alone" "$(stat -f '%i %m' "$conf")" "$before"
	check "and leaves the map alone" "$(stat -f '%i %m' "$(host_map)")" "$map_before"
	check "and says the port 80 shape is unchanged" \
		"$(grep -c 'unchanged, port 80 only until' "$tree/again.out")" 1

	# 3. the certificate lands: the site and the www redirect appear, port 80 stays
	printf 'key\n' > "$(key_file)"
	printf 'certificate\n' > "$(cert_file)"
	write_group_conf > "$tree/certrun.out"
	check "the apex block is still first" "$(awk 'NR == 1' "$conf")" 'server "parish.example" {'
	check "both names now have a loopback block" "$(grep -c 'listen on 127.0.0.1 port 8080' "$conf")" 2
	check "the apex site hands every path to the responder" \
		"$(grep -c 'fastcgi socket "/run/onboard-static-httpd/static.sock"' "$conf")" 1
	check "and names no root" "$(grep -c '^[[:space:]]*root "/parish' "$conf")" 0
	check "and no .git block to match a path the responder refuses" \
		"$(grep -c 'location "/.git/' "$conf")" 0
	# shellcheck disable=SC2016 # as above
	check "the www loopback name redirects to the apex" \
		"$(awk '/server "www.parish.example" \{/{n++} n == 2' "$conf" | grep -cF 'block return 301 "https://parish.example$REQUEST_URI"')" 1
	check "and points at the pass that adds the relayd keypair" \
		"$(grep -c 'cron-apply.sh --web' "$tree/certrun.out")" 1

	# 4. a second run in that shape
	before=$(stat -f '%i %m' "$conf")
	write_group_conf > "$tree/cert.out"
	check "a second run with a certificate leaves the file alone" "$(stat -f '%i %m' "$conf")" "$before"
	check "and says the site is in place" \
		"$(grep -c 'unchanged, the site and the www redirect are in place' "$tree/cert.out")" 1

	# 5. a certificate whose key is missing is refused, and the file is untouched
	before=$(stat -f '%i %m %z' "$conf")
	rm -f "$(key_file)"
	code=0
	( write_group_conf ) > "$tree/nokey.out" 2>&1 || code=$?
	check "a certificate with no key is refused" "$code" 1
	check "and the refusal names the file it left alone" \
		"$(grep -c 'was left alone' "$tree/nokey.out")" 1
	check "and the file is untouched, inode and all" "$(stat -f '%i %m %z' "$conf")" "$before"

	# 6. a site owner whose tree is not built is refused
	account=nobody
	rm -rf "$public_root/nobody.kyriakon.net"
	code=0
	( assert_site_tree ) > "$tree/notree.out" 2>&1 || code=$?
	check "a site owner with no tree is refused" "$code" 1
	check "and the refusal names provision-member.sh" \
		"$(grep -c 'scripts/provision-member.sh nobody' "$tree/notree.out")" 1

	# 7. a name that is not a validated FQDN is refused at the door
	check "a domain is accepted" "$(domain_ok parish.example && printf yes || printf no)" yes
	check "a single label is refused" "$(domain_ok parish && printf yes || printf no)" no
	check "a leading hyphen is refused" "$(domain_ok -parish.example && printf yes || printf no)" no
	check "a name with a slash is refused" "$(domain_ok parish.example/x && printf yes || printf no)" no

	# 8. the platform's own names are refused, the rule the drain applies before
	# this lane runs: a hand-run write here would collide with the platform's own
	# vhost, map and certificate.
	check "the platform's own domain is refused" \
		"$(domain_ok kyriakon.net && printf yes || printf no)" no
	check "and a name under it" "$(domain_ok parish.kyriakon.net && printf yes || printf no)" no
	check "and the defensive registration" "$(domain_ok kyriakon.com && printf yes || printf no)" no
	check "and a name under that" "$(domain_ok www.kyriakon.com && printf yes || printf no)" no
	check "a name that only ends in the same letters is a body's" \
		"$(domain_ok notkyriakon.net && printf yes || printf no)" yes
	# No table means no way to tell the operator's domain from a body's, so every
	# name is refused rather than guessed at.
	mail_domains="$tree/etc/mail/absent"
	check "a missing mail table refuses the name" \
		"$(domain_ok parish.example && printf yes || printf no)" no
	mail_domains="$tree/etc/mail/mail_domains"

	self_test_end
}

conf_changed=no

case "${1:-}" in
--self-test)
	[ "$#" -eq 1 ] || usage
	self_test
	;;
"")
	usage
	;;
-*)
	usage
	;;
*)
	[ "$#" -eq 2 ] || usage
	domain="$1"
	account="$2"
	domain_ok "$domain" || die "not a domain: $domain (lowercase FQDN, at least two labels, and not the platform's own)"
	valid_localpart "$account" || die "not an account name: $account"
	[ "$(id -u)" -eq 0 ] || die "run this with doas: it writes $httpd_d"
	[ -d "$httpd_d" ] || die "no $httpd_d: doas ksh scripts/deploy-mail.sh creates it, with the index httpd.conf includes"
	assert_site_tree
	write_group_conf
	assert_group_conf
	if [ "$conf_changed" = yes ]; then
		printf 'next: doas ksh scripts/cron-apply.sh --web   # regenerate the index, check httpd, reload\n'
	fi
	;;
esac
