#!/bin/ksh
# deploy-relayd.sh - install /etc/relayd.conf, link the certificates under the
# names relayd looks them up by, check the file, and start (or restart) the
# relay that terminates TLS for every name this box serves on 443.
#
# Runs ON the box as root (invoke under doas). It does NOT touch pf.conf: 443
# needs no rule, the box runs the stock OpenBSD ruleset, and the loopback port
# the relay forwards to is unreachable from off the box. It does not install
# httpd.conf either, though this script depends on the version of it that has
# httpd behind the relay: scripts/deploy-mail.sh installs that file and issues
# the certificates, and this script refuses to start anything until both are
# true, because a relay and httpd cannot both listen on 443 (see relayd.conf).
#
# The candidate it checks and installs is the tracked file with the marked
# member keypair region rendered by scripts/relayd-members.sh from the member
# files under /etc/httpd.d. That is what makes a deploy safe after member
# certificates have landed: installing the tracked file unchanged would drop
# every member's keypair and answer those names with the default certificate.
# The render also creates each member's /etc/ssl/<name>.crt link, which is the
# name relayd looks a keypair up under.
#
# So the order on a box that has not run this before is:
#
#   doas ksh scripts/deploy-mail.sh     # installs httpd.conf, issues the certs
#   doas ksh scripts/deploy-relayd.sh   # installs the relay, brings 443 back
#
# After that, a rebuild is this script alone whenever the relay changes.
#
# Usage:
#   doas ksh deploy-relayd.sh [src_dir]
#   ksh scripts/deploy-relayd.sh --self-test [src_dir]
#
#   src_dir   directory holding relayd.conf; defaults to this script's
#             directory with ../openbsd/etc, which is the repo layout. The
#             self-test reads that file too, because the extraction that links
#             the certificates has to work on the config being deployed and not
#             only on its own fixture, and that is the check that would have
#             caught the keypair shape that once stopped this deploy.
#   --self-test  run the checks below against a temporary tree and exit. No
#             daemon is touched and no file outside the temporary tree is
#             written, so it runs as an ordinary user.

set -euo pipefail

script_dir=$(cd "$(dirname -- "$0")" && pwd)

# src_dir: the argument when one is given, and this script's ../openbsd/etc
# otherwise, which is the repo layout. --self-test takes its directory as a
# second argument, because that check reads the config the deploy installs and
# has to be able to find it wherever it is run from.
case "${1:-}" in
--self-test) src_dir="${2:-$script_dir/../openbsd/etc}" ;;
*) src_dir="${1:-$script_dir/../openbsd/etc}" ;;
esac

conf_src="$src_dir/relayd.conf"
conf_dst=/etc/relayd.conf
httpd_conf=/etc/httpd.conf
httpd_port=8080

# The certificate half. relayd looks a keypair named after a certificate up
# under /etc/ssl/<name>.crt and /etc/ssl/private/<name>.key; acme-client writes
# /etc/ssl/<name>.fullchain.pem and /etc/ssl/private/<name>.key. The key is
# already in the place relayd looks, so only the public half needs a link, and a
# link rather than a copy is what keeps a renewal on the acme-client name.
ssl_dir=/etc/ssl
ssl_private=/etc/ssl/private

usage() {
	printf 'usage: doas ksh deploy-relayd.sh [src_dir]\n' >&2
	printf '       ksh scripts/deploy-relayd.sh --self-test [src_dir]\n' >&2
	exit 2
}

die() {
	printf 'deploy-relayd: %s\n' "$*" >&2
	exit 1
}

# The names the relay will present a certificate for, read out of the config
# rather than listed again here, so a line added there is a certificate this
# script also links. Both shapes the option is written in are read: one
# `keypair "name"` per statement, which is what the file uses, and the
# comma-separated list inside a `tls { }` block, which is the other form the same
# man page shows. A commented line is not a name, and a shape this cannot read is
# a deploy that stops on the box, so the self-test below runs it against the
# shipped file rather than only against a fixture.
keypair_names() {
	awk '
		/^[[:space:]]*#/ { next }
		{
			while (match($0, /keypair[[:space:]]+"[^"]+"/)) {
				name = substr($0, RSTART, RLENGTH)
				sub(/^keypair[[:space:]]+"/, "", name)
				sub(/"$/, "", name)
				print name
				$0 = substr($0, RSTART + RLENGTH)
			}
		}' "${1:--}"
}

# How many sockets are listening on 443, from a netstat capture. Read from stdin
# so the self-test can hand it a fixed one; a live run pipes netstat into it. The
# number matters after relayd has been stopped: anything still there is another
# daemon, and starting relayd next to it would either fail or put both on the
# port and split the traffic.
listeners_on_443() {
	awk '$4 ~ /\.443$/ && $NF == "LISTEN" { n++ } END { print n + 0 }' "${1:--}"
}

# Put the certificate relayd looks for in place, for one name. A link, and never
# over a file that is not a link: a real file at that path is somebody else's
# certificate and deleting it would take a name down.
ensure_cert_link() {
	typeset name link target now
	name="$1"
	link="$ssl_dir/$name.crt"
	target="$name.fullchain.pem"

	[ -s "$ssl_private/$name.key" ] \
		|| die "no $ssl_private/$name.key, so relayd cannot present $name: scripts/deploy-mail.sh issues the pair"
	[ -s "$ssl_dir/$target" ] \
		|| die "no $ssl_dir/$target, so relayd cannot present $name: scripts/deploy-mail.sh issues the pair"

	if [ -L "$link" ]; then
		now=$(readlink "$link")
		if [ "$now" = "$target" ]; then
			return 0
		fi
		ln -sfn "$target" "$link"
		printf '%s: relinked to %s (was %s)\n' "$link" "$target" "$now"
	elif [ -e "$link" ]; then
		die "$link is not a symlink; refusing to replace a file that may be a certificate"
	else
		ln -s "$target" "$link"
		printf 'linked %s -> %s\n' "$link" "$target"
	fi
}

# Install the config only when it differs, and say which happened: a run that
# changes nothing should read as a run that changed nothing.
install_conf() {
	if [ -r "$2" ] && cmp -s "$1" "$2"; then
		printf '%s: unchanged, the relay configuration is in place\n' "$2"
		return 0
	fi
	# /etc/mtree/special carries relayd.conf at 0600, and security(8) reports the
	# difference daily until it matches.
	install -m 0600 "$1" "$2"
	printf 'installed %s\n' "$2"
}

# install_checked_conf — the shipped configuration with the member region
# rendered, checked as a candidate and installed only if the check passes.
#
# The candidate is a file in $conf_dst's own directory, removed on both paths:
# leaving one in /etc is a file the next run has to explain. Not by an EXIT trap,
# which would replace whatever trap the caller already had, and --self-test has
# one.
#
# The check used to run on $conf_dst after the install, which is the other way
# round, so a typo left the live file failing its own configtest: "nothing was
# restarted" was true of that run and only that run, and the next
# `rcctl start relayd` or a reboot then came up with no listener on 443. The shape
# is pf-apply.sh's: prepare, check the candidate, install it.
#
# Root is required for the check, which is one reason this script runs under doas.
install_checked_conf() {
	conf_candidate=$(mktemp "$conf_dst.XXXXXX")
	install -m 0600 "$conf_src" "$conf_candidate"
	# The member keypairs, from the member files present now: the tracked file's
	# region is the empty one, and installing it as it stands would drop every
	# member's certificate and answer those names with the default pair. The
	# render also makes each member's /etc/ssl/<name>.crt link, which relayd
	# loads during the check below.
	if ! ksh "$script_dir/relayd-members.sh" "$conf_candidate" >/dev/null; then
		rm -f "$conf_candidate"
		die "$conf_src could not have its member keypair region rendered, so $conf_dst was left as it was and nothing was restarted"
	fi
	if ! relayd -n -f "$conf_candidate"; then
		rm -f "$conf_candidate"
		die "$conf_src does not check, so $conf_dst was left as it was and nothing was restarted"
	fi
	install_conf "$conf_candidate" "$conf_dst"
	rm -f "$conf_candidate"
}

self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$(dirname "$0")/lib.sh"
	typeset tree names link code stub
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	# --- the shipped config, read the way the deploy reads it ---
	# This is the check that matters: the extraction is what the deploy links
	# certificates from, so a config shape it cannot read is a deploy that stops on
	# the box, which is exactly what happened when the keypairs moved from a block
	# to one statement each. It runs against the file that gets installed, not only
	# against the fixture above, and the expected names come from grep rather than
	# from the function itself, so a name it misses is a difference here instead of
	# agreement with itself.
	[ -r "$conf_src" ] \
		|| die "no $conf_src to check: run this from the checkout, or pass its directory as the second argument"
	shipped=$(keypair_names "$conf_src")
	reference=$(grep -v '^[[:space:]]*#' "$conf_src" \
		| grep -o 'keypair[[:space:]]*"[^"]*"' | sed 's/.*"\(.*\)"/\1/')
	check "the shipped config names a certificate" "$([ -n "$shipped" ] && printf yes || printf no)" "yes"
	check "every keypair in the shipped config is read" "$shipped" "$reference"

	# --- which keypair is the default ---
	# The first keypair in the file is what a client that sends no SNI is served,
	# and it has to be the one carrying the name the box is best known by: the
	# apex certificate is the only one that names kyriakon.net and the hosts
	# beside it. A pair placed above the apex takes that fallback away, and the
	# fault is invisible from outside, because the handshake still succeeds with
	# the wrong name in it. Nothing else in this file reads the order.
	check "the first keypair is the one carrying the apex name" \
		"$(printf '%s\n' "$shipped" | sed -n 1p)" "kyriakon.net"

	# --- the keypair names the config asks for ---
	printf '%s\n' \
		'http protocol "https" {' \
		'	tls {' \
		'		keypair "kyriakon.net"' \
		'		# keypair "capsule-kyriakon.net"' \
		'	}' \
		'}' \
		'# keypair "not.this.one"' > "$tree/relayd.conf"
	names=$(keypair_names "$tree/relayd.conf")
	check "a configured keypair is a name to link" "$names" "kyriakon.net"

	# Both shapes the option is written in, since a change to which one the file
	# uses is what stopped a deploy: a comma-separated list on one line, and one
	# statement per keypair.
	printf '%s\n' \
		'tls { keypair "one.example", keypair "two.example" }' \
		'tls keypair "three.example"' > "$tree/both.conf"
	check "a comma-separated list on one line is read" \
		"$(keypair_names "$tree/both.conf" | paste -s -d ' ' -)" "one.example two.example three.example"

	# --- what still holds 443 ---
	printf '%s\n' \
		'tcp          0      0  *.443                  *.*                    LISTEN' \
		'tcp6         0      0  *.443                  *.*                    LISTEN' \
		'tcp          0      0  127.0.0.1.7080         *.*                    LISTEN' \
		'tcp          0      0  127.0.0.1.8080         *.*                    LISTEN' \
		'tcp          0      0  95.216.152.17.443      198.51.100.7.51234     ESTABLISHED' \
		> "$tree/netstat"
	check "two listeners on 443 are two" "$(listeners_on_443 "$tree/netstat")" 2
	printf 'tcp 0 0 127.0.0.1.8080 *.* LISTEN\n' > "$tree/quiet"
	check "the loopback port is not 443" "$(listeners_on_443 "$tree/quiet")" 0

	# --- the certificate link, in a tree of its own ---
	ssl_dir="$tree/etc/ssl"
	ssl_private="$ssl_dir/private"
	mkdir -p "$ssl_private"
	# Non-empty, because the guard below is `-s`: a zero-length certificate is a
	# broken certificate, and the refusal it triggers is what the case below
	# exercises.
	printf 'certificate\n' > "$ssl_dir/kyriakon.net.fullchain.pem"
	printf 'key\n' > "$ssl_private/kyriakon.net.key"

	# Each call in a subshell: the refusals below exit, and an exit inside a
	# function is not something `|| code=$?` can catch.
	code=0
	( ensure_cert_link kyriakon.net ) > "$tree/link.out" 2>&1 || code=$?
	link="$ssl_dir/kyriakon.net.crt"
	check "a missing link is created" "$code" 0
	check "and it points at the acme-client name" "$(readlink "$link")" "kyriakon.net.fullchain.pem"
	check "and the run says so" "$(grep -c 'linked ' "$tree/link.out")" 1

	code=0
	( ensure_cert_link kyriakon.net ) > "$tree/again.out" 2>&1 || code=$?
	check "a correct link is left alone" "$code" 0
	check "and the run says nothing about it" "$(wc -l < "$tree/again.out" | tr -d ' ')" 0

	rm -f "$link"
	printf 'not a link\n' > "$link"
	code=0
	( ensure_cert_link kyriakon.net ) > "$tree/file.out" 2>&1 || code=$?
	check "a real file where the link goes is refused" "$code" 1
	check "and the refusal says why" "$(grep -c 'refusing to replace' "$tree/file.out")" 1
	check "and the file is left alone" "$(cat "$link")" "not a link"
	rm -f "$link"

	rm -f "$ssl_dir/kyriakon.net.fullchain.pem"
	code=0
	( ensure_cert_link kyriakon.net ) > "$tree/nocert.out" 2>&1 || code=$?
	check "a name with no certificate is refused" "$code" 1
	check "and the refusal names the deploy that issues it" \
		"$(grep -c 'scripts/deploy-mail.sh' "$tree/nocert.out")" 1
	printf 'certificate\n' > "$ssl_dir/kyriakon.net.fullchain.pem"

	# --- installing the config, once ---
	install_conf "$tree/relayd.conf" "$tree/etc/relayd.conf" > "$tree/first.out" 2>&1
	install_conf "$tree/relayd.conf" "$tree/etc/relayd.conf" > "$tree/second.out" 2>&1
	check "the first install is reported" "$(grep -c '^installed ' "$tree/first.out")" 1
	check "and installed at the mode mtree special expects" \
		"$(stat -f %Lp "$tree/etc/relayd.conf")" 600
	check "and the second run says unchanged" "$(grep -c 'unchanged' "$tree/second.out")" 1

	# --- checking the configuration before installing it ---
	# `relayd -n` needs root and a configuration it can parse, so it is stubbed
	# here: what is being checked is the order the deploy does things in, not
	# relayd's parser.
	stub="$tree/bin"
	mkdir "$stub"
	# shellcheck disable=SC2016 # the stub expands this at its own run time
	printf '#!/bin/sh\n[ "${STUB_RELAYD_CHECK:-ok}" = fail ] && exit 1\nexit 0\n' > "$stub/relayd"
	chmod 0755 "$stub/relayd"
	PATH="$stub:$PATH"
	export PATH
	conf_src="$tree/shipped.conf"
	conf_dst="$tree/etc/relayd-checked.conf"
	cat > "$conf_src" <<'EOF'
http protocol "kyriakon-https" {
	tls keypair "kyriakon.net"
	# --- BEGIN member keypairs ---
	# --- END member keypairs ---
}

relay "https" {
	listen on egress port 443 tls
}
EOF
	printf 'the configuration the relay is running\n' > "$conf_dst"

	# Two members: one whose certificate pair is complete, and one whose
	# certificate has not landed yet. The first gains a keypair line and the
	# second must not, because a line for a name with no certificate is a config
	# relayd refuses.
	RELAYD_MEMBERS_HTTPD_D="$tree/httpd.d"
	RELAYD_MEMBERS_SSL_DIR="$ssl_dir"
	RELAYD_MEMBERS_SSL_PRIVATE="$ssl_private"
	export RELAYD_MEMBERS_HTTPD_D RELAYD_MEMBERS_SSL_DIR RELAYD_MEMBERS_SSL_PRIVATE
	mkdir -p "$RELAYD_MEMBERS_HTTPD_D"
	: > "$RELAYD_MEMBERS_HTTPD_D/alice.kyriakon.net.conf"
	: > "$RELAYD_MEMBERS_HTTPD_D/bob.kyriakon.net.conf"
	printf 'certificate\n' > "$ssl_dir/alice.kyriakon.net.fullchain.pem"
	printf 'key\n' > "$ssl_private/alice.kyriakon.net.key"

	STUB_RELAYD_CHECK=fail
	export STUB_RELAYD_CHECK
	code=0
	( install_checked_conf ) > "$tree/refused.out" 2>&1 || code=$?
	check "a configuration that does not check is a failure" \
		"$([ "$code" -ne 0 ] && printf yes || printf no)" yes
	check "and it is not installed" "$(cat "$conf_dst")" \
		"the configuration the relay is running"
	check "and the refusal says the installed file was left alone" \
		"$(grep -c 'was left as it was' "$tree/refused.out")" 1

	STUB_RELAYD_CHECK=ok
	export STUB_RELAYD_CHECK
	( install_checked_conf ) > "$tree/checked.out" 2>&1
	check "and reported as installed" "$(grep -c '^installed ' "$tree/checked.out")" 1
	check "a member with a certificate and key gains a keypair line" \
		"$(grep -c 'tls keypair "alice.kyriakon.net"' "$conf_dst")" 1
	check "and one whose certificate has not landed gains none" \
		"$(grep -c 'bob.kyriakon.net' "$conf_dst")" 0
	check "the tracked keypair comes through the render unchanged" \
		"$(grep -c 'tls keypair "kyriakon.net"' "$conf_dst")" 1
	check "and so does the relay below the region" \
		"$(grep -c 'listen on egress port 443 tls' "$conf_dst")" 1
	check "the member's certificate link is made for relayd" \
		"$(readlink "$ssl_dir/alice.kyriakon.net.crt")" "alice.kyriakon.net.fullchain.pem"

	# Neither path leaves its candidate in /etc.
	set -- "$tree/etc"/relayd-checked.conf.*
	check "and no candidate is left behind" "$([ -e "$1" ] && printf yes || printf no)" no

	self_test_end
}

case "${1:-}" in
--self-test)
	[ "$#" -le 2 ] || usage
	self_test
	;;
-*)
	usage
	;;
*)
	[ "$#" -le 1 ] || usage
	[ -r "$conf_src" ] || die "no $conf_src"
	[ "$(id -u)" -eq 0 ] || die "run this with doas: it writes $conf_dst, links the certificates, and starts relayd"

	names=$(keypair_names "$conf_src")
	[ -n "$names" ] || die "no keypair lines in $conf_src, so the relay would present no certificate"

	# Before anything is stopped or written: the relay forwards to httpd on
	# loopback, and a box whose httpd.conf still has the old 443 vhosts has httpd
	# holding the port the relay is about to want.
	grep -q "listen on 127.0.0.1 port $httpd_port" "$httpd_conf" \
		|| die "$httpd_conf has no 'listen on 127.0.0.1 port $httpd_port': scripts/deploy-mail.sh installs the httpd.conf that puts httpd behind this relay, and it must run first"

	# Certificates first: relayd's check loads the keypairs the configuration
	# names, so a candidate checked before the links exist would fail a first
	# deploy. Linking writes only under /etc/ssl, which the running relay reads
	# when it starts and not before.
	# shellcheck disable=SC2086 # names is a deliberate word list
	for name in $names; do
		ensure_cert_link "$name"
	done

	# The candidate is checked before it is installed: see install_checked_conf.
	install_checked_conf

	# Any relayd from an earlier run goes first, and we wait for the process to
	# actually exit: the guard below is only meaningful once the port is free of
	# our own listener, and starting against a still-running relay fails with
	# EADDRINUSE and looks like a config fault. A fixed sleep is a guess at how
	# long a shutdown takes.
	pkill -x relayd >/dev/null 2>&1 || true
	waited=0
	while pgrep -x relayd >/dev/null 2>&1 && [ "$waited" -lt 10 ]; do
		sleep 1
		waited=$((waited + 1))
	done

	holders=$(netstat -an | listeners_on_443)
	if [ "$holders" -gt 0 ]; then
		printf 'deploy-relayd: %s socket(s) still listening on 443, and relayd is not one of them\n' "$holders" >&2
		if grep -rqs 'tls port 443' "$httpd_conf" /etc/httpd.d 2>/dev/null; then
			printf '  httpd still terminates TLS on 443: run doas ksh scripts/deploy-mail.sh, then this script,\n' >&2
			printf '  since only one daemon can hold that port (see /etc/relayd.conf).\n' >&2
		else
			printf '  find the holder with: netstat -an | grep LISTEN, and fstat -n for its pid.\n' >&2
		fi
		exit 1
	fi

	rcctl enable relayd
	# rcctl start reports a failure as relayd(failed) and exits non-zero, which
	# set -e would turn into a silent stop before the diagnostic below.
	rcctl start relayd || true
	rcctl check relayd >/dev/null 2>&1 \
		|| die "relayd did not start; see /var/log/messages and /var/log/daemon"

	# Verify the service that is actually running, not that it started. A request
	# through the relay to the name this relay fronts: 200 is the handler's form,
	# and curl validating the certificate is the check that the right pair is on
	# the port. And a request to httpd's loopback port, which is the half that
	# serves everything else for every name.
	ip4=$(ifconfig egress inet 2>/dev/null | awk '$1 == "inet" && $2 != "127.0.0.1" { print $2; exit }')
	[ -n "$ip4" ] || die "no IPv4 address on egress, so there is no address to test the relay on"

	code=$(curl -s -o /dev/null -w '%{http_code}' \
		--resolve "signup.kyriakon.net:443:$ip4" https://signup.kyriakon.net/) || true
	[ "$code" = 200 ] \
		|| die "signup.kyriakon.net answered '$code' through the relay, wanted 200 from the handler (see /var/log/daemon)"
	printf 'signup.kyriakon.net: 200 from the handler through the relay, certificate valid\n'

	# The other half of the same name, a path the rules do not claim, so it goes
	# to whatever the main table holds. Any answer httpd gives will do, including
	# its 404 while the signup root is empty; a relay error or no answer at all
	# means the default forward is wrong.
	code=$(curl -s -o /dev/null -w '%{http_code}' \
		--resolve "signup.kyriakon.net:443:$ip4" https://signup.kyriakon.net/relay-deploy-check) || true
	case "$code" in
	"" | 000 | 502 | 503 | 504) die "the relay answered '$code' for a path httpd should serve, so the default forward is broken (see /var/log/daemon)" ;;
	esac
	printf 'signup.kyriakon.net: %s for a path the static half owns\n' "$code"

	code=$(curl -s -o /dev/null -w '%{http_code}' \
		-H 'Host: kyriakon.net' "http://127.0.0.1:$httpd_port/") || true
	case "$code" in
	"" | 000) die "nothing answered on 127.0.0.1:$httpd_port, so the relay has no backend for the static half" ;;
	esac
	printf 'httpd on 127.0.0.1:%s: %s for a name behind the relay\n' "$httpd_port" "$code"

	printf 'relayd is terminating TLS on 443; relayd.conf names the certificates it presents.\n' >&2
	printf 'next (manual): from a second machine, curl -sI https://signup.kyriakon.net/ | head -1\n' >&2
	printf 'should be 200. The Titan listener stays commented in /etc/relayd.conf until\n' >&2
	printf 'an operator enables it. Its handler listener exists now, and its public port\n' >&2
	printf 'is the TITAN_PORT rule scripts/pf-apply.sh proposes; neither step is automatic.\n' >&2
	;;
esac
