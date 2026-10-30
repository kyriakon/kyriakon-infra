#!/bin/ksh
# relayd-members.sh: rewrite the generated member keypair region of a relayd
# configuration, from the member files the web lane has written.
#
# Usage:
#   ksh scripts/relayd-members.sh [--check] <relayd.conf>
#        ksh scripts/relayd-members.sh --self-test
#
# Runs ON the box as root. Two callers, one owner: scripts/deploy-relayd.sh
# renders the region into the candidate it checks and installs, so a deploy does
# not erase the member keypairs, and scripts/cron-apply.sh --web renders it into
# the installed file after the web lane has written a member's vhost. Neither
# writes the region itself, which is what keeps the two from disagreeing.
#
# Why a marked region rather than a file per member. relayd.conf(5) gives
# `include` only as a top-level statement, and a keypair is a statement inside
# `http protocol`, so a member's line cannot live in a generated file the way
# /etc/httpd.d, /etc/gmid.d and /etc/acme-client.d do. The tracked relayd.conf
# therefore carries the two markers, and this script owns the bytes between
# them and nothing else: every line outside them is passed through untouched, so
# the tracked keypairs, the commented Titan block and the relay below are exactly
# what is committed.
#
# Who gets a line. Every generated vhost under /etc/httpd.d whose stem is a
# hostname: a member's <name>.kyriakon.net written by
# scripts/provision-member-web.sh, and an own-domain body's <domain> written by
# scripts/provision-group-web.sh. The same directory is what the httpd index is
# built from, so the two lists cannot disagree. index.conf and any other file
# whose stem is not a hostname are skipped. A keypair line is emitted only when
# the name's pair is complete, /etc/ssl/<name>.fullchain.pem and
# /etc/ssl/private/<name>.key: a line for a name with no certificate is a relayd
# -n failure, and relayd's config check runs before every reload, so that failure
# is a reload that never happens rather than a name that is merely wrong. Names
# are sorted, so a second run over the same directory is the same bytes.
#
# The certificate link is made here for the same reason. relayd looks a keypair
# named <name> up under /etc/ssl/<name>.crt, and acme-client writes
# <name>.fullchain.pem; scripts/deploy-relayd.sh links the tracked names when it
# installs the config, but a member's certificate lands after that deploy, so a
# line without a link is a config that passes until the next relayd -n. A real
# file at the link path is refused rather than replaced: it may be somebody
# else's certificate.
#
# Writing is temp-then-rename in the config's own directory, at 0600, which is
# the mode /etc/mtree/special carries for /etc/relayd.conf. --check prints
# changed or unchanged and writes nothing, not even a link.
#
# Env: RELAYD_MEMBERS_HTTPD_D, RELAYD_MEMBERS_SSL_DIR and
# RELAYD_MEMBERS_SSL_PRIVATE rebind the three directories, so the self-test needs
# no root and touches nothing outside its own temporary tree.

set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "$0")" && pwd)

httpd_d=${RELAYD_MEMBERS_HTTPD_D:-/etc/httpd.d}
ssl_dir=${RELAYD_MEMBERS_SSL_DIR:-/etc/ssl}
ssl_private=${RELAYD_MEMBERS_SSL_PRIVATE:-/etc/ssl/private}

# Matched anywhere in a line, because the markers are comments inside a block and
# may be indented. Nothing else in relayd.conf carries either phrase.
begin_marker='BEGIN member keypairs'
end_marker='END member keypairs'

usage() {
	printf 'usage: doas ksh relayd-members.sh [--check] <relayd.conf>\n' >&2
	printf '       ksh scripts/relayd-members.sh --self-test\n' >&2
	exit 2
}

die() {
	printf 'relayd-members: %s\n' "$*" >&2
	exit 1
}

# member_names: every generated vhost's hostname, sorted. A glob with no match is
# the literal pattern, which the existence test skips. index.conf is the include
# file rather than a vhost, and a stem without a dot is not a hostname, so both
# are skipped here rather than being left to the certificate check.
member_names() {
	typeset f name
	for f in "$httpd_d"/*.conf; do
		[ -e "$f" ] || continue
		name=${f##*/}
		name=${name%.conf}
		case "$name" in
		*.*) printf '%s\n' "$name" ;;
		esac
	done | LC_ALL=C sort
}

# member_ready <name>: the complete pair is on disk, which is the condition for a
# line and for the link.
member_ready() {
	# -s and not -f: an interrupted acme-client write leaves an empty file, and a
	# keypair line for it is a `relayd -n` failure that rolls back every other
	# member's pending change in the same pass.
	[ -s "$ssl_dir/$1.fullchain.pem" ] && [ -s "$ssl_private/$1.key" ]
}

# ensure_member_link <name>: /etc/ssl/<name>.crt is the symlink relayd looks the
# keypair up through. Same rule as deploy-relayd.sh's ensure_cert_link.
ensure_member_link() {
	typeset cert_name="$1" cert_link cert_target now
	cert_link="$ssl_dir/$cert_name.crt"
	cert_target="$cert_name.fullchain.pem"
	if [ -L "$cert_link" ]; then
		now=$(readlink "$cert_link")
		[ "$now" = "$cert_target" ] && return 0
		ln -sfn "$cert_target" "$cert_link"
		return 0
	fi
	if [ -e "$cert_link" ]; then
		die "$cert_link is not a symlink; refusing to replace a file that may be a certificate"
	fi
	ln -s "$cert_target" "$cert_link"
}

# keypair_lines: the region's body, one statement per ready member. The loop's
# `|| continue` is what keeps set -e from ending the run on a member without a
# certificate, which is an ordinary state rather than a failure.
keypair_lines() {
	typeset name
	member_names | while read -r name; do
		member_ready "$name" || continue
		printf '\ttls keypair "%s"\n' "$name"
	done
}

# render <target> <lines>: the target with the region replaced, on stdout.
render() {
	awk -v kp="$2" -v b="$begin_marker" -v e="$end_marker" '
		index($0, b) {
			print
			while ((getline line < kp) > 0) print line
			close(kp)
			skip = 1
			next
		}
		index($0, e) { skip = 0 }
		skip { next }
		{ print }
	' "$1"
}

# apply <target> <check|write>
apply() {
	typeset target="$1" mode="$2" begin_line end_line lines candidate name

	[ -f "$target" ] || die "no $target"
	# awk rather than grep, because grep's exit status for no match would end the
	# run under `set -o pipefail` before the refusal below could name the file.
	begin_line=$(awk -v m="$begin_marker" 'index($0, m) { print NR; exit }' "$target")
	end_line=$(awk -v m="$end_marker" 'index($0, m) { print NR; exit }' "$target")
	if [ -z "$begin_line" ] || [ -z "$end_line" ] || [ "$begin_line" -ge "$end_line" ]; then
		die "$target does not carry the member keypair markers, so this script has no region it owns there (the tracked relayd.conf does)"
	fi

	# The links first, in write mode, so a link removed by hand is repaired even
	# when the region already matches: a region that names a certificate relayd
	# cannot open is a config its own check rejects. Before the temporary files
	# below, so a refusal leaves nothing behind in /etc.
	if [ "$mode" = write ]; then
		member_names | while read -r name; do
			if member_ready "$name"; then
				ensure_member_link "$name"
			fi
		done
	fi

	lines="$target.lines.$$"
	candidate="$target.new.$$"
	keypair_lines > "$lines"
	if ! render "$target" "$lines" > "$candidate"; then
		rm -f "$lines" "$candidate"
		die "could not render $target"
	fi

	# Compared before anything moves, so a run that would produce the same file
	# says so and leaves the mtime and inode alone.
	if cmp -s "$candidate" "$target"; then
		rm -f "$lines" "$candidate"
		printf 'unchanged\n'
		return 0
	fi
	if [ "$mode" = check ]; then
		rm -f "$lines" "$candidate"
		printf 'changed\n'
		return 0
	fi

	chmod 0600 "$candidate"
	mv "$candidate" "$target"
	rm -f "$lines"
	printf 'changed\n'
}

# --- self-test ---------------------------------------------------------------
#
# The region is the whole risk, so it is exercised against a throwaway tree: a
# member with a pair gains a line and one without gains none, the order is by
# name, a second run is free, a file without the markers is refused, and every
# line outside the region comes through byte for byte.

self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$script_dir/lib.sh"
	typeset tree conf before out code
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	httpd_d="$tree/httpd.d"
	ssl_dir="$tree/ssl"
	ssl_private="$ssl_dir/private"
	conf="$tree/relayd.conf"
	install -d -m 0755 "$httpd_d" "$ssl_private"

	cat > "$conf" <<'EOF'
http protocol "kyriakon-https" {
	tls keypair "kyriakon.net"
	# BEGIN member keypairs: generated by scripts/relayd-members.sh, do not edit
	# END member keypairs
	match header set "X-Forwarded-For" value "$REMOTE_ADDR"
}

relay "https" {
	listen on egress port 443 tls
}
EOF

	# alice and zed have a complete pair, bob has a vhost and no certificate, and
	# carol has a pair and no vhost. parish.example is an own-domain body with a
	# complete pair; another.example is one whose certificate has not landed.
	: > "$httpd_d/alice.kyriakon.net.conf"
	: > "$httpd_d/bob.kyriakon.net.conf"
	: > "$httpd_d/zed.kyriakon.net.conf"
	: > "$httpd_d/parish.example.conf"
	: > "$httpd_d/another.example.conf"
	for name in alice.kyriakon.net zed.kyriakon.net carol.kyriakon.net parish.example; do
		printf 'certificate\n' > "$ssl_dir/$name.fullchain.pem"
		printf 'key\n' > "$ssl_private/$name.key"
	done
	# A vhost whose stem is not a hostname is not a vhost relayd can key.
	: > "$httpd_d/parish.conf"

	apply "$conf" write > "$tree/first.out"
	check "the first run reports a change" "$(cat "$tree/first.out")" "changed"
	check "a member with a complete pair gains a keypair line" \
		"$(grep -c 'tls keypair "alice.kyriakon.net"' "$conf")" 1
	check "one without a certificate gains none" \
		"$(grep -c 'bob.kyriakon.net' "$conf")" 0
	check "one without a vhost gains none" \
		"$(grep -c 'carol.kyriakon.net' "$conf")" 0
	check "a file whose stem is not a hostname gains none" \
		"$(grep -c 'tls keypair "parish"' "$conf")" 0
	check "an own-domain body with a complete pair gains a keypair line" \
		"$(grep -c 'tls keypair "parish.example"' "$conf")" 1
	check "one whose certificate has not landed gains none" \
		"$(grep -c 'another.example' "$conf")" 0
	check "the names are sorted" \
		"$(grep 'tls keypair "' "$conf" | sed 's/.*"\(.*\)"/\1/' | paste -s -d ' ' -)" \
		"kyriakon.net alice.kyriakon.net parish.example zed.kyriakon.net"
	check "the tracked keypair is untouched" \
		"$(grep -c 'tls keypair "kyriakon.net"' "$conf")" 1
	check "and so is the line below the region" \
		"$(grep -c 'match header set "X-Forwarded-For"' "$conf")" 1
	check "and the relay after it" "$(grep -c 'listen on egress port 443 tls' "$conf")" 1
	check "the file is mode 0600" "$(stat -f %Lp "$conf")" 600
	check "the certificate link relayd looks up is made" \
		"$(readlink "$ssl_dir/alice.kyriakon.net.crt")" "alice.kyriakon.net.fullchain.pem"
	check "and the own-domain link is made too" \
		"$(readlink "$ssl_dir/parish.example.crt")" "parish.example.fullchain.pem"

	# A second run over the same members: same bytes, nothing written.
	before=$(stat -f '%i %m %z' "$conf")
	apply "$conf" write > "$tree/second.out"
	check "a second run reports no change" "$(cat "$tree/second.out")" "unchanged"
	check "and leaves the file alone, inode and all" "$(stat -f '%i %m %z' "$conf")" "$before"

	# A link removed by hand is repaired even when the region matches, because the
	# next relayd -n loads it.
	rm -f "$ssl_dir/alice.kyriakon.net.crt"
	apply "$conf" write > "$tree/relink.out"
	check "a missing link is repaired on an unchanged run" \
		"$(readlink "$ssl_dir/alice.kyriakon.net.crt")" "alice.kyriakon.net.fullchain.pem"
	check "and the region still reports no change" "$(cat "$tree/relink.out")" "unchanged"

	# --check sees a change and writes nothing.
	: > "$httpd_d/third.kyriakon.net.conf"
	printf 'certificate\n' > "$ssl_dir/third.kyriakon.net.fullchain.pem"
	printf 'key\n' > "$ssl_private/third.kyriakon.net.key"
	before=$(stat -f '%i %m %z' "$conf")
	apply "$conf" check > "$tree/check.out"
	check "--check reports the change" "$(cat "$tree/check.out")" "changed"
	check "and writes nothing" "$(stat -f '%i %m %z' "$conf")" "$before"
	check "and makes no link" "$([ -e "$ssl_dir/third.kyriakon.net.crt" ] && printf yes || printf no)" no

	# A config without the markers is refused rather than guessed at.
	printf 'http protocol "https" {\n\ttls keypair "kyriakon.net"\n}\n' > "$tree/nomarkers.conf"
	code=0
	( apply "$tree/nomarkers.conf" write ) > "$tree/nomarkers.out" 2>&1 || code=$?
	check "a config without the markers is refused" "$code" 1
	check "and the refusal says which file" \
		"$(grep -c 'does not carry the member keypair markers' "$tree/nomarkers.out")" 1
	check "and the file is untouched" \
		"$(grep -c 'kyriakon.net' "$tree/nomarkers.conf")" 1
	# The real entry point, not `apply` inside a subshell whose status is being
	# tested: the refusal has to print the message there too, or a caller dies with
	# an empty terminal.
	code=0
	ksh "$script_dir/relayd-members.sh" "$tree/nomarkers.conf" > "$tree/direct.out" 2>&1 || code=$?
	check "the script itself refuses a config with no markers" "$code" 1
	check "and prints the refusal rather than dying silently" \
		"$(grep -c 'does not carry the member keypair markers' "$tree/direct.out")" 1

	# An empty full chain is an interrupted write, not a certificate: a keypair
	# line for it is a config relayd refuses, which would roll back every other
	# member's change in the same pass.
	: > "$ssl_dir/zed.kyriakon.net.fullchain.pem"
	apply "$conf" write > "$tree/empty.out"
	check "an empty certificate is not treated as ready" \
		"$(grep -c 'zed.kyriakon.net' "$conf")" 0

	# A real file where the link goes is refused, and left alone.
	rm -f "$ssl_dir/zed.kyriakon.net.crt"
	printf 'not a link\n' > "$ssl_dir/zed.kyriakon.net.crt"
	code=0
	( ensure_member_link zed.kyriakon.net ) > "$tree/linkfile.out" 2>&1 || code=$?
	check "a real file at the link path is refused" "$code" 1
	check "and left as it was" "$(cat "$ssl_dir/zed.kyriakon.net.crt")" "not a link"

	# The tracked file this deploy renders carries the markers, so the two
	# callers can rely on it rather than on the fixture above.
	shipped="$script_dir/../openbsd/etc/relayd.conf"
	check "the shipped relayd.conf carries the begin marker" \
		"$(grep -c "$begin_marker" "$shipped")" 1
	check "and the end marker" "$(grep -c "$end_marker" "$shipped")" 1
	out=$(awk -v b="$begin_marker" -v e="$end_marker" '
		index($0, b) { inside = 1; next }
		index($0, e) { inside = 0; next }
		inside { n++ }
		END { print n + 0 }
	' "$shipped")
	check "with nothing generated between them" "$out" 0

	self_test_end
}

case "${1:-}" in
--self-test)
	[ "$#" -eq 1 ] || usage
	self_test
	;;
--check)
	[ "$#" -eq 2 ] || usage
	apply "$2" check
	;;
-*)
	usage
	;;
*)
	[ "$#" -eq 1 ] || usage
	apply "$1" write
	;;
esac
