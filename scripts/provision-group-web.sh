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
# root "/<site-account>.kyriakon.net/www" is that account's public tree, and
# root "/acme" is the challenge directory the mail deploy created.
#
# Nothing is written when the file already holds the bytes this script would
# write, so a run after a certificate has not landed yet is free.
#
# Env: none. The self-test rebinds this script's own paths to a throwaway tree
# under TMPDIR, so it needs no root and touches nothing outside it.
#
# Not this script's job: the site owner's tree (scripts/provision-member.sh), the
# capsule (scripts/provision-group-capsule.sh), the acme-client block and the
# queued order (scripts/provision-group-acme.sh), the index, the relayd region,
# or the reloads (scripts/cron-apply.sh --web).

set -euo pipefail

# The key this file writes is not secret, but the temporary file is created here,
# and a 0600 temporary chmodded 0644 before the rename cannot leave a readable
# half-written vhost behind.
umask 077

httpd_d=/etc/httpd.d
ssl_dir=/etc/ssl
ssl_private=/etc/ssl/private
public_root=/home/www
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
domain_ok() {
	typeset name="$1"
	[ "${#name}" -le 253 ] || return 1
	case "$name" in
	*.*) ;;
	*) return 1 ;;
	esac
	printf '%s' "$name" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
}

# The site owner is a member account: the same charset add-user.sh and
# provision-member.sh apply, because it is a path component under /home/www.
account_ok() {
	printf '%s' "$1" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'
}

# The paths, as functions so the self-test rebinds the directories once.
cert_file() { printf '%s/%s.fullchain.pem' "$ssl_dir" "$domain"; }
key_file() { printf '%s/%s.key' "$ssl_private" "$domain"; }
group_conf() { printf '%s/%s.conf' "$httpd_d" "$domain"; }
site_public() { printf '%s/%s.kyriakon.net' "$public_root" "$account"; }

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
	[ -f "$(cert_file)" ] || return 0
	printf '\n'
	printf 'server "%s" {\n' "$domain"
	printf '\tlisten on 127.0.0.1 port 8080\n'
	printf '\tlog { style forwarded }\n'
	printf '\tlocation "/.git/*" {\n'
	printf '\t\tblock\n'
	printf '\t}\n'
	printf '\tlocation "/*" {\n'
	printf '\t\troot "/%s.kyriakon.net/www"\n' "$account"
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
	typeset target candidate

	target=$(group_conf)

	# A certificate without its key is a broken pair rather than a state to serve
	# from: relayd would name a key that is not there and its config check would
	# fail. Refusing leaves the previous file exactly as it was.
	if [ -f "$(cert_file)" ] && [ ! -f "$(key_file)" ]; then
		die "$(cert_file) is there and $(key_file) is not, so $target was left alone: the relay needs both halves of the pair"
	fi

	candidate="$target.new.$$"
	if ! group_conf_body > "$candidate"; then
		rm -f "$candidate"
		exit 1
	fi

	if [ -f "$target" ] && cmp -s "$candidate" "$target"; then
		rm -f "$candidate"
		conf_changed=no
		if [ -f "$(cert_file)" ]; then
			printf '%s: unchanged, the site and the www redirect are in place\n' "$target"
		else
			printf '%s: unchanged, port 80 only until %s exists\n' "$target" "$(cert_file)"
		fi
		return 0
	fi

	chmod 0644 "$candidate"
	mv "$candidate" "$target"
	conf_changed=yes

	if [ -f "$(cert_file)" ]; then
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
	typeset conf shape
	conf=$(group_conf)
	[ -f "$conf" ] || die "$conf is not there after writing it"
	shape=$(stat -f '%Su:%Sg %Lp' "$conf")
	[ "$shape" = "$conf_owner 644" ] || die "$conf is $shape, wanted $conf_owner 644"
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
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$(dirname "$0")/lib.sh"
	typeset tree conf before code
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	httpd_d="$tree/etc/httpd.d"
	ssl_dir="$tree/etc/ssl"
	ssl_private="$ssl_dir/private"
	public_root="$tree/home/www"
	domain=parish.example
	account=parish-secretary
	install -d -m 0755 "$httpd_d" "$ssl_private" "$public_root/parish-secretary.kyriakon.net/www"
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
	assert_group_conf
	printf '\n%s:\n' "$conf"
	cat "$conf"
	printf '\n'

	# 2. the same again: nothing rewritten
	before=$(stat -f '%i %m' "$conf")
	write_group_conf > "$tree/again.out"
	check "a second run leaves the file alone" "$(stat -f '%i %m' "$conf")" "$before"
	check "and says the port 80 shape is unchanged" \
		"$(grep -c 'unchanged, port 80 only until' "$tree/again.out")" 1

	# 3. the certificate lands: the site and the www redirect appear, port 80 stays
	: > "$(key_file)"
	: > "$(cert_file)"
	write_group_conf > "$tree/certrun.out"
	check "the apex block is still first" "$(awk 'NR == 1' "$conf")" 'server "parish.example" {'
	check "both names now have a loopback block" "$(grep -c 'listen on 127.0.0.1 port 8080' "$conf")" 2
	check "the apex site roots the site owner's www tree" \
		"$(grep -c 'root "/parish-secretary.kyriakon.net/www"' "$conf")" 1
	check "and not a directory named after the domain" "$(grep -c 'root "/parish.example' "$conf")" 0
	check "the loopback apex blocks .git" "$(grep -c 'location "/.git/\*"' "$conf")" 1
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
	domain_ok "$domain" || die "not a domain: $domain (lowercase FQDN, at least two labels)"
	account_ok "$account" || die "not an account name: $account"
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
