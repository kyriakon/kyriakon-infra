#!/bin/ksh
# provision-member-web.sh: the member's httpd vhost, as one generated file.
#
# Usage:
#   doas ksh scripts/provision-member-web.sh <username>
#        ksh scripts/provision-member-web.sh --self-test
#
# Runs ON the box as root, after scripts/provision-member.sh has built the
# member's tree, and again later: the block behind the relay appears the moment
# the member's certificate file does, so a certificate that lands after signup is
# applied by running this again rather than by editing anything by hand.
#
# What it writes, and why each shape:
#
#   /etc/httpd.d/<username>.kyriakon.net.conf    root:wheel 0644
#
# The port 80 block comes first and holds the ACME challenge location before the
# 301 to the same name over HTTPS. httpd uses the first location that matches and
# ignores the rest, so the challenge has to come before any catch-all or a
# renewal is answered with the redirect and fails. The second block is the
# member's site behind the relay, on 127.0.0.1 port 8080, plain HTTP: relayd
# terminates TLS for every name on 443 and passes the Host header through, so the
# vhost here is the same shape every other site on the box has. It is written only
# when the member's certificate file exists, because the relay presents a
# certificate it was told about, and a name answered with the relay's default
# certificate is served under the wrong name, which is worse than not serving it.
# A member whose certificate is still in the queue has a resolving name, a
# working challenge and no site yet, in the meantime.
#
# The keypair line that makes the relay present this member's certificate is not
# written here. relayd.conf cannot include a file where a keypair belongs
# (include is a top-level statement and a keypair is a statement inside
# `http protocol`), so the tracked file carries a marked region that
# scripts/relayd-members.sh fills from the member files under /etc/httpd.d, and
# scripts/cron-apply.sh --web rewrites it and reloads relayd once a certificate
# is on disk. The queue runs both after it issues: scripts/acme-queue.sh attempt
# runs this script and then the web apply, so the block below, the keypair line
# and the reload land together without a human.
#
# The paths inside the blocks are httpd's. httpd's chroot is /home/www, so
# root "/<name>.kyriakon.net/www" is /home/www/<name>.kyriakon.net/www, which is
# the member's own public tree, and root "/acme" is the challenge directory
# deploy-mail.sh created. The certificate paths are not, which is why the
# certificate check below names the one under /etc/ssl in full: relayd reads the
# pair from there, out of the chroot, before it drops privileges.
#
# The index and the reload are not this script's job. /etc/httpd.d/index.conf is
# regenerated and httpd is checked with httpd -n and then reloaded by
# scripts/cron-apply.sh --web, which does it once for every member file at once:
# one reload for a batch rather than one per member, and the check runs first, so
# a file that does not parse leaves the running configuration alone.
#
# Nothing is written when the file already holds the bytes this script would
# write, so a run after a certificate has not landed yet is free, and the one
# line it prints says which of the two shapes the file is in.
#
# Env: none. The self-test rebinds this script's own paths to a throwaway tree
# under TMPDIR, so it needs no root and touches nothing outside it.
#
# Not this script's job: the member's tree (scripts/provision-member.sh), the
# acme-client block and the queued request (scripts/provision-member-acme.sh),
# the index, the relayd keypair region, the reloads, or the capsule block for the
# same name (scripts/provision-member-capsule.sh).

set -euo pipefail

# The key this file writes is not secret, but the temporary file it is written
# through is created here, and a 0600 temporary that is chmodded 0644 before the
# rename is the one shape that cannot leave a readable half-written vhost behind.
umask 077

# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$(dirname "$0")/lib.sh"

httpd_d=/etc/httpd.d
ssl_dir=/etc/ssl
ssl_private=/etc/ssl/private
public_root=/home/www
conf_owner="root:wheel"

usage() {
	cat >&2 <<'USAGE'
usage: doas ksh provision-member-web.sh <username>
       doas ksh provision-member-web.sh --remove <username>
       ksh provision-member-web.sh --self-test
USAGE
	exit 2
}

die() {
	printf 'provision-member-web: %s\n' "$*" >&2
	exit 1
}

# The name, and the same charset rule add-user.sh and provision-member.sh apply.
# It is a subdomain label here, a path component under /home/www and the stem of
# the generated file, so a name outside that set could not be a member's.
name_ok() {
	printf '%s' "$1" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'
}

# The three paths, as functions rather than variables so the self-test rebinds
# the directories once and every caller follows.
cert_file() { printf '%s/%s.kyriakon.net.fullchain.pem' "$ssl_dir" "$user"; }
key_file() { printf '%s/%s.kyriakon.net.key' "$ssl_private" "$user"; }
member_conf() { printf '%s/%s.kyriakon.net.conf' "$httpd_d" "$user"; }

# The port 80 block every shape starts with: the ACME challenge comes before any
# catch-all, because httpd uses the first location that matches. Kept on its own
# so the removal can leave it in place for a renewal while serving is off.
port_80_challenge() {
	printf 'server "%s.kyriakon.net" {\n' "$user"
	printf '\tlisten on * port 80\n'
	printf '\tlocation "/.well-known/acme-challenge/*" {\n'
	printf '\t\troot "/acme"\n'
	printf '\t\trequest strip 2\n'
	printf '\t}\n'
}

# The file body, printed rather than written so the caller can hold it in a work
# file and compare it with what is already there.
member_conf_body() {
	port_80_challenge
	printf '\tlocation "/*" {\n'
	# shellcheck disable=SC2016 # httpd substitutes $REQUEST_URI per request, so the
	# generated line carries the token literally and ksh must not expand it here
	printf '\t\tblock return 301 "https://%s.kyriakon.net$REQUEST_URI"\n' "$user"
	printf '\t}\n'
	printf '}\n'

	# The block behind the relay, only once the member's certificate is there: the
	# relay presents what /etc/relayd.conf names, and a name it has no keypair for
	# is answered with the default certificate.
	# -s, not -f: an empty chain is an interrupted acme-client write, and the
	# relay cannot present it, so it is no certificate at all.
	[ -s "$(cert_file)" ] || return 0
	printf '\n'
	printf 'server "%s.kyriakon.net" {\n' "$user"
	printf '\tlisten on 127.0.0.1 port 8080\n'
	printf '\tlog { style forwarded }\n'
	printf '\tlocation "/.git/*" {\n'
	printf '\t\tblock\n'
	printf '\t}\n'
	printf '\tlocation "/*" {\n'
	printf '\t\troot "/%s.kyriakon.net/www"\n' "$user"
	printf '\t}\n'
	printf '}\n'
}

# write_member_conf: the file in the shape the member's certificate calls for.
# Sets conf_changed, so the caller can say whether the index and the daemon need
# the --web pass.
write_member_conf() {
	typeset target

	target=$(member_conf)

	# A certificate without its key is refused by write_generated, which returns 1
	# with the message and leaves the previous file exactly as it was.
	if ! write_generated "$target" member_conf_body "$(cert_file)" "$(key_file)"; then
		return 1
	fi

	if [ "$conf_changed" = no ]; then
		if [ -s "$(cert_file)" ]; then
			printf '%s: unchanged, the block behind the relay is in place\n' "$target"
		else
			printf '%s: unchanged, port 80 only until %s exists\n' "$target" "$(cert_file)"
		fi
		return 0
	fi

	if [ -s "$(cert_file)" ]; then
		printf 'wrote %s: port 80 and the loopback block for %s.kyriakon.net\n' "$target" "$user"
		printf '  next: doas ksh scripts/cron-apply.sh --web   # adds the relayd keypair, checks, reloads\n'
	else
		printf 'wrote %s: port 80 for %s.kyriakon.net; the loopback block lands when\n' \
			"$target" "$user"
		printf '  %s exists, which is the certificate queue issuing it; that run\n' "$(cert_file)"
		printf '  applies this script and cron-apply.sh --web again\n'
	fi
}

# The last line of defence: the file is there, readable by the daemon that parses
# it, and root's, so nothing a member can write is a vhost. The expected owner is
# a variable rather than a literal because the self-test's throwaway tree belongs
# to whoever runs the test.
assert_member_conf() {
	typeset conf shape
	conf=$(member_conf)
	[ -f "$conf" ] || die "$conf is not there after writing it"
	shape=$(stat -f '%Su:%Sg %Lp' "$conf")
	[ "$shape" = "$conf_owner 644" ] || die "$conf is $shape, wanted $conf_owner 644"
}

# The shape a removal leaves: the port 80 challenge alone, so a renewal still
# answers while the site is off.
member_conf_removed_body() {
	port_80_challenge
	printf '}\n'
}

# remove_member_conf: take the member's site out of the generated vhost, for the
# account page's "serve your website over HTTP: off". The site block is replaced by
# the port 80 challenge alone, because a renewal has to answer on port 80 whatever
# the site is doing; an unmatched path is a 404, so nothing else is served. The
# tracked httpd.conf includes an index that cron-apply.sh --web regenerates from the
# files present, and nothing of the member's is deleted.
remove_member_conf() {
	typeset target
	target=$(member_conf)
	# A member with no file was never served, and there is no challenge to keep.
	[ -f "$target" ] || return 0
	if ! write_generated "$target" member_conf_removed_body; then
		return 1
	fi
	# A second removal writes the same challenge-only file, so write_generated
	# leaves the file and its mtime alone and this says nothing about it.
	[ "$conf_changed" = yes ] || return 0
	printf '%s: %s.kyriakon.net is no longer served over HTTP; the ACME challenge stays for renewal\n' "$target" "$user"
	printf '  next: doas ksh scripts/cron-apply.sh --web   # regenerate the index, check httpd, reload\n'
}

# The tree this file names, which provision-member.sh builds and which no vhost
# can serve from if it is gone.
assert_member_tree() {
	typeset public
	public="$public_root/$user.kyriakon.net"
	[ -d "$public" ] || die "no $public: run scripts/provision-member.sh $user first"
	[ -d "$public/www" ] || die "no $public/www: run scripts/provision-member.sh $user first"
}

# --- self-test ---------------------------------------------------------------
#
# The generation is the whole of this script's risk, so it is exercised here
# against a throwaway tree: the file with no certificate, the file once a
# certificate exists, a second run in each state, and the two refusals. Runs as
# anyone, writes only under TMPDIR.

self_test() {
	typeset tree conf before
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	httpd_d="$tree/etc/httpd.d"
	ssl_dir="$tree/etc/ssl"
	ssl_private="$ssl_dir/private"
	public_root="$tree/home/www"
	user=alice
	install -d -m 0755 "$httpd_d" "$ssl_private" "$public_root/alice.kyriakon.net/www"
	# A new file takes its directory's group on this box, and in a throwaway tree
	# that is the tree's owner rather than wheel, so the group comes from the
	# directory the file lands in. On the box it is root:wheel, which is what
	# assert_member_conf checks in the production path.
	conf_owner="$(id -un):$(stat -f '%Sg' "$httpd_d")"

	conf=$(member_conf)

	# 1. no certificate: port 80 only, challenge first
	write_member_conf >/dev/null
	check "the port 80 block is first" "$(awk 'NR == 1' "$conf")" 'server "alice.kyriakon.net" {'
	check "the listener is port 80" "$(grep -c 'listen on \* port 80' "$conf")" 1
	check "the challenge location comes before the catch-all" \
		"$(awk '/location/ { print $2; exit }' "$conf")" '"/.well-known/acme-challenge/*"'
	check "the challenge root is /acme" "$(grep -c 'root "/acme"' "$conf")" 1
	check "the challenge is stripped" "$(grep -c 'request strip 2' "$conf")" 1
	check "everything else is a 301 to https" \
		"$(grep -cF "block return 301 \"https://alice.kyriakon.net\$REQUEST_URI\"" "$conf")" 1
	check "and there is no block behind the relay yet" "$(grep -c '127.0.0.1 port 8080' "$conf")" 0
	check "the file is mode 644 and the writer's" "$(stat -f '%Su:%Sg %Lp' "$conf")" "$conf_owner 644"
	assert_member_conf
	# Printed once, so this check's output carries the file it asserts about: the
	# lines above are what was written, not a description of it.
	printf '\n%s:\n' "$conf"
	cat "$conf"
	printf '\n'

	# 2. the same again: nothing rewritten, and the run says which shape it is in
	before=$(stat -f '%i %m' "$conf")
	write_member_conf > "$tree/again.out"
	check "a second run leaves the file alone" "$(stat -f '%i %m' "$conf")" "$before"
	check "and says the file is unchanged" "$(grep -c 'unchanged, port 80 only until' "$tree/again.out")" 1

	# 3. the certificate lands: the block behind the relay appears, port 80 stays
	# first, and the block names no certificate, because the relay presents it
	printf 'key\n' > "$(key_file)"
	printf 'certificate\n' > "$(cert_file)"
	write_member_conf > "$tree/certrun.out"
	check "the port 80 block is still first" "$(awk 'NR == 1' "$conf")" 'server "alice.kyriakon.net" {'
	check "and it points at the pass that adds the relayd keypair" \
		"$(grep -c 'cron-apply.sh --web' "$tree/certrun.out")" 1
	check "the second block listens on the relay's loopback port" \
		"$(grep -c 'listen on 127.0.0.1 port 8080' "$conf")" 1
	check "it names no certificate or key of its own" \
		"$(grep -cE 'certificate|key "|tls' "$conf")" 0
	check "it logs the forwarded address the relay sets" \
		"$(grep -c 'log { style forwarded }' "$conf")" 1
	check "it blocks .git" "$(grep -c 'location "/.git/\*"' "$conf")" 1
	check "and roots the member's www directory" \
		"$(grep -c 'root "/alice.kyriakon.net/www"' "$conf")" 1

	# 4. a second run in that shape, and the file it compares is the one just written
	before=$(stat -f '%i %m' "$conf")
	write_member_conf > "$tree/cert.out"
	check "a second run with a certificate leaves the file alone" "$(stat -f '%i %m' "$conf")" "$before"
	check "and says the block behind the relay is in place" \
		"$(grep -c 'unchanged, the block behind the relay is in place' "$tree/cert.out")" 1

	# 5. a certificate whose key is missing is refused, and the file is untouched
	before=$(stat -f '%i %m %z' "$conf")
	rm -f "$(key_file)"
	set +e
	( write_member_conf ) > "$tree/nokey.out" 2>&1
	rc=$?
	set -e
	check "a certificate with no key is refused" "$rc" 1
	check "and the refusal names the file it left alone" \
		"$(grep -c 'was left alone' "$tree/nokey.out")" 1
	check "and the member file is untouched, inode and all" \
		"$(stat -f '%i %m %z' "$conf")" "$before"

	# An empty key is an interrupted write, not a key: it is refused as no key
	# at all, because the file the relay would name is unreadable either way.
	: > "$(key_file)"
	set +e
	( write_member_conf ) > "$tree/emptykey.out" 2>&1
	rc=$?
	set -e
	check "a certificate with an empty key is refused" "$rc" 1
	check "and leaves the member file as it was" \
		"$(stat -f '%i %m %z' "$conf")" "$before"

	# The other way round is not a refusal: a key with no certificate is a pair
	# the queue has not issued yet, so the file is the port 80 block alone.
	printf 'key\n' > "$(key_file)"
	rm -f "$(cert_file)"
	write_member_conf > "$tree/keyonly.out"
	check "a key with no certificate is not refused" \
		"$(grep -c 'unchanged\|wrote' "$tree/keyonly.out")" 1
	check "and the file is port 80 only" \
		"$(grep -c '127.0.0.1 port 8080' "$conf")" 0
	# An empty certificate is an interrupted write, not a certificate: the
	# loopback block stays absent and the port 80 challenge keeps answering.
	: > "$(cert_file)"
	write_member_conf > "$tree/emptycert.out"
	check "an empty certificate serves no loopback block" \
		"$(grep -c '127.0.0.1 port 8080' "$conf")" 0

	# The helper's own contract: the body runs under umask 077 whatever the
	# caller's is, so the candidate is never member-readable.
	umask_body() { : >"$tree/umask-probe"; stat -f '%Lp' "$tree/umask-probe"; }
	( umask 022; write_generated "$tree/umask.out" umask_body )
	check "the body runs under umask 077" "$(cat "$tree/umask.out")" 600
	rm -f "$tree/umask-probe"

	# 6. a member whose tree is not built is refused rather than vhosted
	user=nobody
	rm -rf "$public_root/nobody.kyriakon.net"
	set +e
	( assert_member_tree ) > "$tree/notree.out" 2>&1
	rc=$?
	set -e
	check "a member with no tree is refused" "$rc" 1
	check "and the refusal names provision-member.sh" \
		"$(grep -c 'scripts/provision-member.sh nobody' "$tree/notree.out")" 1

	# 7. the account page's "serve over HTTP: off" leaves the port 80 challenge
	# alone: a renewal has to answer while the site is off. The member's tree is
	# untouched, and a second removal has nothing to say.
	user=alice
	rm -f "$(cert_file)"
	write_member_conf >/dev/null
	remove_member_conf >"$tree/remove.out"
	check "the vhost is kept for the challenge" "$([ -f "$conf" ] && printf yes || printf no)" yes
	check "it holds one location, the challenge" \
		"$(grep -c 'location ' "$conf")" 1
	check "the challenge is still rooted at /acme" "$(grep -c 'root "/acme"' "$conf")" 1
	check "the site's catch-all is gone" "$(grep -c 'block return 301' "$conf")" 0
	check "no block behind the relay is left" "$(grep -c '127.0.0.1 port 8080' "$conf")" 0
	check "and the member's tree is still there" \
		"$([ -d "$public_root/alice.kyriakon.net/www" ] && printf yes || printf no)" yes
	check "and it points at the reload pass" "$(grep -c 'cron-apply.sh --web' "$tree/remove.out")" 1
	before=$(stat -f '%i %m' "$conf")
	remove_member_conf >"$tree/remove-again.out"
	check "a second removal prints nothing" "$(wc -c <"$tree/remove-again.out" | tr -d ' ')" 0
	check "and leaves the file alone" "$(stat -f '%i %m' "$conf")" "$before"
	# Turning it back on writes the site again rather than leaving the challenge
	# shape in place.
	write_member_conf >/dev/null
	check "turning serving back on restores the site" "$(grep -c 'block return 301' "$conf")" 1

	self_test_end
}

conf_changed=no

case "${1:-}" in
--self-test)
	[ "$#" -eq 1 ] || usage
	self_test
	;;
--remove)
	[ "$#" -eq 2 ] || usage
	user="$2"
	name_ok "$user" || die "not a member name: $user (lowercase [a-z0-9._-], first character alphanumeric, at most 32 characters)"
	[ "$(id -u)" -eq 0 ] || die "run this with doas: it rewrites $httpd_d/$user.kyriakon.net.conf to the challenge alone"
	[ -d "$httpd_d" ] || die "no $httpd_d: doas ksh scripts/deploy-mail.sh creates it"
	remove_member_conf
	;;
"")
	usage
	;;
-*)
	usage
	;;
*)
	[ "$#" -eq 1 ] || usage
	user="$1"
	name_ok "$user" || die "not a member name: $user (lowercase [a-z0-9._-], first character alphanumeric, at most 32 characters)"
	[ "$(id -u)" -eq 0 ] || die "run this with doas: it writes $httpd_d"
	# deploy-mail.sh creates the directory with the empty index httpd.conf includes,
	# and a member file with no index to list it is a config nobody reads: a box
	# that has not run the mail deploy has no member hosting to write into.
	[ -d "$httpd_d" ] || die "no $httpd_d: doas ksh scripts/deploy-mail.sh creates it, with the index httpd.conf includes"
	assert_member_tree
	write_member_conf
	assert_member_conf
	if [ "$conf_changed" = yes ]; then
		printf 'next: doas ksh scripts/cron-apply.sh --web   # regenerate the index, check httpd, reload\n'
	fi
	;;
esac
