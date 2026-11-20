#!/bin/ksh
# verify-hosting.sh — the web and gemini daemons, and the responder behind them,
# against a two-member fixture.
#
# Usage:
#   doas ksh scripts/verify-hosting.sh              # OpenBSD, as root
#        ksh scripts/verify-hosting.sh --self-test  # fixture only, no daemon
#
# Why this exists: no other check opens a file through a chroot. The scripts'
# self-tests exercise the scripts, shellcheck reads the shell, and the Rust
# tests never start httpd or gmid, so the behaviour #815 recorded — a member's
# symlink resolved from the shared chroot into another member's tree, and a
# `.git` block matched on the request path while the link is served — had no
# guardrail. This starts both daemons, and the responder they hand requests to,
# and reads the paths back.
#
# The fixture is one member's two trees and another member's, plus the landing
# checkout, in one chroot:
#
#   alice.kyriakon.net/www/index.html            a plain file, the 200 control
#   alice.kyriakon.net/www/sub/index.html        a directory, for the redirect
#   alice.kyriakon.net/www/leak -> ../../bob.kyriakon.net/www/secret.html
#   alice.kyriakon.net/www/gitleak -> <fixture>/landing/www/.git/config
#   alice.kyriakon.net/gemini/index.gmi          the capsule's control
#   alice.kyriakon.net/gemini/leak ->            the same two links, from the
#   alice.kyriakon.net/gemini/gitleak ->         capsule's own tree
#   bob.kyriakon.net/www/secret.html             bob's bytes, no link to them
#   landing/www/.git/config                      [core], the link's target
#   logs/                                        httpd fatals without it
#
# The contract asserted: the plain file is served, a directory without its
# trailing separator is redirected to it, the two links serve nothing outside
# alice's tree on either front-end, and a direct `/.git/config` request is
# refused. The daemons are configured the way scripts/provision-member-*.sh
# writes a member's block — a fastcgi socket and no root — so a change to either
# shape without the other fails here.
#
# The full run is OpenBSD-only: it needs root for chroot(2), the www and _gmid
# accounts, the two daemons, and a built responder. KYRIAKON_STATIC_BIN names the
# binary; the default is the release build under control/target. --self-test
# builds the same fixture and checks its layout, its bytes and the generated
# configs without starting anything, so a wrong fixture fails loudly instead of a
# daemon quietly answering 404s on the box.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

openssl=/usr/bin/openssl
static_bin=${KYRIAKON_STATIC_BIN:-$script_dir/../control/target/release/kyriakon-control-static}
chroot_dir=''
static_pid=''
httpd_pid=''
gmid_pid=''

# The one name both daemons serve. It is the member's hostname, not localhost:
# the responder chooses the tree by it, so a request under another name would be
# a request for another member.
HOST='alice.kyriakon.net'

# The bytes the fixture serves. Written with a newline, compared without one:
# command substitution strips trailing newlines, so these are what `$(cat)`
# returns from the files below.
BOB_SECRET='bob wrote this and linked it from nowhere'
GIT_CONFIG='[core]
	repositoryformatversion = 0
	bare = false'

usage() {
	cat >&2 <<'USAGE'
usage: doas ksh verify-hosting.sh
       ksh verify-hosting.sh --self-test
USAGE
	exit 2
}

die() {
	printf 'verify-hosting: %s\n' "$*" >&2
	exit 1
}

# make_fixture <dir>: the tree the daemon configs point at and both halves of
# the test read. One function, so the configs and --self-test cannot describe
# two different fixtures.
make_fixture() {
	typeset tree="$1"
	mkdir -p "$tree/alice.kyriakon.net/www/sub" "$tree/alice.kyriakon.net/gemini/sub" \
		"$tree/bob.kyriakon.net/www" "$tree/landing/www/.git" "$tree/run" \
		"$tree/logs" || return 1
	printf 'alice\n' > "$tree/alice.kyriakon.net/www/index.html"
	printf 'sub page\n' > "$tree/alice.kyriakon.net/www/sub/index.html"
	printf '# alice capsule\n' > "$tree/alice.kyriakon.net/gemini/index.gmi"
	printf '# sub capsule\n' > "$tree/alice.kyriakon.net/gemini/sub/index.gmi"
	printf '%s\n' "$BOB_SECRET" > "$tree/bob.kyriakon.net/www/secret.html"
	printf '%s\n' "$GIT_CONFIG" > "$tree/landing/www/.git/config"
	# Relative: from alice's own tree, up to the chroot root and into bob's.
	# #815's first case, from each of her two trees.
	ln -s ../../bob.kyriakon.net/www/secret.html "$tree/alice.kyriakon.net/www/leak"
	ln -s ../../bob.kyriakon.net/www/secret.html "$tree/alice.kyriakon.net/gemini/leak"
	# Absolute: the responder is not chrooted, so this names the landing checkout
	# on the real filesystem. It resolves, and only `O_NOFOLLOW` refuses it.
	ln -s "$tree/landing/www/.git/config" "$tree/alice.kyriakon.net/www/gitleak"
	ln -s "$tree/landing/www/.git/config" "$tree/alice.kyriakon.net/gemini/gitleak"
}

# assert_fixture <dir>: the layout and the bytes, before any daemon starts. A
# fixture that is wrong here would make the daemon assertions pass or fail for
# the wrong reason, so it is a hard stop.
assert_fixture() {
	typeset tree="$1" ok=yes want kind

	if [ ! -d "$tree/logs" ] || [ ! -d "$tree/run" ]; then
		printf 'verify-hosting: fixture: no %s/logs or %s/run\n' "$tree" "$tree" >&2
		ok=no
	fi
	for kind in www gemini; do
		if [ ! -d "$tree/alice.kyriakon.net/$kind" ]; then
			printf 'verify-hosting: fixture: no alice %s tree\n' "$kind" >&2
			ok=no
		fi
	done
	if [ ! -f "$tree/alice.kyriakon.net/www/index.html" ]; then
		printf 'verify-hosting: fixture: no alice index.html\n' >&2
		ok=no
	fi
	if [ ! -f "$tree/alice.kyriakon.net/gemini/index.gmi" ]; then
		printf 'verify-hosting: fixture: no alice index.gmi\n' >&2
		ok=no
	fi

	want='../../bob.kyriakon.net/www/secret.html'
	for kind in www gemini; do
		if [ "$(readlink "$tree/alice.kyriakon.net/$kind/leak" 2>/dev/null)" != "$want" ]; then
			printf 'verify-hosting: fixture: %s/leak is not a link to %s\n' "$kind" "$want" >&2
			ok=no
		elif [ "$(cat "$tree/alice.kyriakon.net/$kind/leak" 2>/dev/null)" != "$BOB_SECRET" ]; then
			printf 'verify-hosting: fixture: %s/leak does not resolve to bob bytes\n' "$kind" >&2
			ok=no
		fi
	done

	# The link's target is a real path here, so it can be read: the refusal must
	# not be passing for a missing file.
	want="$tree/landing/www/.git/config"
	for kind in www gemini; do
		if [ "$(readlink "$tree/alice.kyriakon.net/$kind/gitleak" 2>/dev/null)" != "$want" ]; then
			printf 'verify-hosting: fixture: %s/gitleak is not a link to %s\n' "$kind" "$want" >&2
			ok=no
		fi
	done
	if ! grep -q '^\[core\]$' "$tree/landing/www/.git/config" 2>/dev/null; then
		printf 'verify-hosting: fixture: the gitleak target has no [core]\n' >&2
		ok=no
	fi

	[ "$ok" = yes ]
}

# static_conf <chroot>: the responder's config for this fixture. Its root is the
# chroot and its sockets are inside it, which is the deployed relation.
static_conf() {
	cat <<EOF
root = "$1"
httpd_socket = "$1/run/static-httpd.sock"
gemini_socket = "$1/run/static-gemini.sock"
EOF
}

# httpd_conf <chroot> <port>: the shape scripts/provision-member-web.sh writes
# for a member's loopback block — a fastcgi socket and no root.
httpd_conf() {
	cat <<EOF
chroot "$1"
server "$HOST" {
	listen on 127.0.0.1 port $2
	location "/*" {
		fastcgi socket "/run/static-httpd.sock"
	}
}
EOF
}

# gmid_conf <chroot> <port>: the capsule counterpart, the shape
# scripts/provision-member-capsule.sh writes.
gmid_conf() {
	cat <<EOF
chroot "$1"
user "_gmid"
server "$HOST" {
	listen on 127.0.0.1 port $2
	cert "$1/tls.crt"
	key "$1/tls.key"
	fastcgi socket "/run/static-gemini.sock"
}
EOF
}

# free_port: a loopback port nothing is listening on. The daemons fail at bind
# if the answer raced; the readiness check below reports that rather than the
# script passing on a daemon that never started.
free_port() {
	typeset port tries=0
	while [ "$tries" -lt 50 ]; do
		port=$((20000 + ($$ * 37 + tries * 17) % 20000))
		if ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
			printf '%s\n' "$port"
			return 0
		fi
		tries=$((tries + 1))
	done
	return 1
}

# wait_sockets: both responder sockets exist and accept, which is what the
# daemons need before their first request. A responder that failed at bind exits
# with the path in its message, and the log is printed above the failure.
wait_sockets() {
	typeset tries=0
	while [ "$tries" -lt 50 ]; do
		[ -S "$chroot_dir/run/static-httpd.sock" ] &&
			[ -S "$chroot_dir/run/static-gemini.sock" ] && return 0
		kill -0 "$static_pid" 2>/dev/null || return 1
		sleep 0.2
		tries=$((tries + 1))
	done
	return 1
}

wait_http() {
	typeset port="$1" tries=0
	while [ "$tries" -lt 50 ]; do
		curl -s -o /dev/null --max-time 1 -H "Host: $HOST" \
			"http://127.0.0.1:$port/index.html" >/dev/null 2>&1 && return 0
		sleep 0.2
		tries=$((tries + 1))
	done
	return 1
}

# gemini_get <port> <path>: the whole response, CRs stripped. curl has no
# gemini support, so the request line goes through openssl s_client. The name in
# the request and the SNI is the member's, because that is what gmid routes and
# the responder keys the tree on.
gemini_get() {
	printf 'gemini://%s:%s%s\r\n' "$HOST" "$1" "$2" |
		"$openssl" s_client -connect "127.0.0.1:$1" -servername "$HOST" -quiet \
			2>/dev/null | tr -d '\r'
}

wait_gemini() {
	typeset port="$1" tries=0
	while [ "$tries" -lt 50 ]; do
		[ -n "$(gemini_get "$port" /index.gmi | sed -n 1p)" ] && return 0
		sleep 0.2
		tries=$((tries + 1))
	done
	return 1
}

# expect_http <port> <path> <status> <pattern> <what>: the status and, when a
# pattern is given, that the body carries it.
expect_http() {
	typeset port="$1" path="$2" want="$3" pattern="$4" what="$5" body status
	body=$(mktemp "$chroot_dir/http-body.XXXXXX") || return 1
	status=$(curl -sS --max-time 5 -o "$body" -w '%{http_code}' -H "Host: $HOST" \
		"http://127.0.0.1:$port$path" 2>/dev/null) || status='no answer'
	if [ "$status" != "$want" ]; then
		rm -f "$body"
		die "http $what: GET $path answered [$status], wanted $want"
	fi
	if [ -n "$pattern" ] && ! grep -q "$pattern" "$body"; then
		printf 'body: %s\n' "$(sed -n 1,5p "$body")" >&2
		rm -f "$body"
		die "http $what: GET $path has no [$pattern]"
	fi
	rm -f "$body"
	printf 'ok: http %s: GET %s -> %s\n' "$what" "$path" "$status"
}

# expect_http_redirect <port> <path> <location> <what>: a 301 whose Location is
# the same path with its trailing separator.
expect_http_redirect() {
	typeset port="$1" path="$2" want="$3" what="$4" seen
	seen=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code} %{redirect_url}' \
		-H "Host: $HOST" "http://127.0.0.1:$port$path" 2>/dev/null) || seen='no answer'
	[ "$seen" = "301 http://$HOST:$port$want" ] ||
		die "http $what: GET $path answered [$seen], wanted 301 to $want"
	printf 'ok: http %s: GET %s -> 301 %s\n' "$what" "$path" "$want"
}

# expect_gemini <port> <path> <status> <pattern> <what>
expect_gemini() {
	typeset port="$1" path="$2" want="$3" pattern="$4" what="$5" response status line
	response=$(gemini_get "$port" "$path")
	line=$(printf '%s\n' "$response" | sed -n 1p)
	status=$(printf '%s\n' "$line" | cut -d' ' -f1)
	if [ "$status" != "$want" ]; then
		die "gemini $what: GET $path answered [$line], wanted $want"
	fi
	if [ -n "$pattern" ] && [ "$(printf '%s\n' "$response" | grep -c "$pattern")" -eq 0 ]; then
		die "gemini $what: GET $path has no [$pattern]"
	fi
	printf 'ok: gemini %s: GET %s -> %s\n' "$what" "$path" "$status"
}

# expect_http_denied <port> <path> <secret> <what>: the link is refused (403 or
# 404) and its body does not carry the bytes outside the member's tree.
expect_http_denied() {
	typeset port="$1" path="$2" secret="$3" what="$4" body status
	body=$(mktemp "$chroot_dir/http-body.XXXXXX") || return 1
	status=$(curl -sS --max-time 5 -o "$body" -w '%{http_code}' -H "Host: $HOST" \
		"http://127.0.0.1:$port$path" 2>/dev/null) || status='no answer'
	case "$status" in
	403 | 404) ;;
	*)
		rm -f "$body"
		die "http $what: GET $path answered [$status], wanted 403 or 404"
		;;
	esac
	if grep -q "$secret" "$body"; then
		rm -f "$body"
		die "http $what: GET $path served bytes outside the member tree"
	fi
	rm -f "$body"
	printf 'ok: http %s: GET %s refused as %s\n' "$what" "$path" "$status"
}

# expect_gemini_denied <port> <path> <secret> <what>: the capsule answers 51
# (not found) and carries none of the bytes outside the member's tree.
expect_gemini_denied() {
	typeset port="$1" path="$2" secret="$3" what="$4" response status line
	response=$(gemini_get "$port" "$path")
	line=$(printf '%s\n' "$response" | sed -n 1p)
	status=$(printf '%s\n' "$line" | cut -d' ' -f1)
	if [ "$status" != "51" ]; then
		die "gemini $what: GET $path answered [$line], wanted 51"
	fi
	if printf '%s\n' "$response" | grep -q "$secret"; then
		die "gemini $what: GET $path served bytes outside the member tree"
	fi
	printf 'ok: gemini %s: GET %s refused as %s\n' "$what" "$path" "$status"
}

cleanup() {
	typeset pid
	for pid in "$httpd_pid" "$gmid_pid" "$static_pid"; do
		[ -n "$pid" ] || continue
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	if [ -n "$chroot_dir" ]; then
		rm -rf "$chroot_dir"
	fi
	return 0
}

full_run() {
	typeset http_port gemini_port static_conf_file httpd_conf_file gmid_conf_file

	[ "$(uname -s)" = OpenBSD ] ||
		die "the daemon half is OpenBSD-only; run --self-test on this host"
	[ "$(id -u)" -eq 0 ] ||
		die "run this with doas: httpd and gmid chroot(2) and drop to their own users"
	[ -x "$openssl" ] || die "no $openssl"
	[ -x "$static_bin" ] ||
		die "no $static_bin: build it with cargo build --release --manifest-path control/Cargo.toml"
	for prog in httpd gmid curl nc; do
		command -v "$prog" >/dev/null 2>&1 ||
			die "no $prog: ksh scripts/install-packages.sh --ci"
	done

	chroot_dir=$(mktemp -d "${TMPDIR:-/tmp}/verify-hosting.XXXXXX") || exit 1
	# The daemons drop to www and _gmid inside this directory, so "/" in the jail
	# has to be traversable by them; mktemp makes it 0700.
	chmod 0755 "$chroot_dir"
	trap 'cleanup' EXIT
	trap 'exit 1' HUP INT TERM

	make_fixture "$chroot_dir" || die "could not build the fixture under $chroot_dir"
	assert_fixture "$chroot_dir" || die "the fixture's layout or bytes are wrong"

	# --- the responder ---------------------------------------------------
	# It starts first: both daemons connect lazily, and a socket that is not
	# there yet is a 502 on the first request rather than a startup failure.
	static_conf_file="$chroot_dir/static.toml"
	static_conf "$chroot_dir" > "$static_conf_file"
	"$static_bin" --config "$static_conf_file" > "$chroot_dir/static.log" 2>&1 &
	static_pid=$!
	wait_sockets || {
		sed -n 1,20p "$chroot_dir/static.log" >&2
		die "the responder did not bind its sockets under $chroot_dir/run"
	}
	# The live deploy gives each socket a set-group-id directory and 0660, so the
	# daemon's group is what may connect. The fixture has no such directory, so
	# the sockets are opened to the daemons' users here; the mode itself is
	# asserted by scripts/deploy-control.sh's self-test.
	chmod 0666 "$chroot_dir/run/static-httpd.sock" "$chroot_dir/run/static-gemini.sock"

	# --- httpd -----------------------------------------------------------
	http_port=$(free_port) || die "no free port for httpd"
	httpd_conf_file="$chroot_dir/httpd.conf"
	httpd_conf "$chroot_dir" "$http_port" > "$httpd_conf_file"
	httpd -n -f "$httpd_conf_file" || die "httpd refused the fixture config"
	# -d keeps the parent in this script's process group so the pid below is a
	# handle: killing it terminates the workers it started.
	httpd -d -f "$httpd_conf_file" > "$chroot_dir/httpd.log" 2>&1 &
	httpd_pid=$!
	printf '%s\n' "$httpd_pid" > "$chroot_dir/httpd.pid"
	wait_http "$http_port" || {
		sed -n 1,20p "$chroot_dir/httpd.log" >&2
		sed -n 1,20p "$chroot_dir/static.log" >&2
		die "httpd did not answer on 127.0.0.1:$http_port"
	}
	expect_http "$http_port" '/index.html' 200 'alice' 'plain file'
	expect_http "$http_port" '/' 200 'alice' 'the index a directory serves'
	expect_http_redirect "$http_port" '/sub' '/sub/' 'directory without its separator'
	expect_http_denied "$http_port" '/leak' "$BOB_SECRET" 'relative link'
	expect_http_denied "$http_port" '/gitleak' '[core]' 'absolute .git link'
	expect_http_denied "$http_port" '/.git/config' '[core]' 'direct .git'
	expect_http_denied "$http_port" '/sub/../leak' "$BOB_SECRET" 'traversal spelling'

	# --- gmid ------------------------------------------------------------
	gemini_port=$(free_port) || die "no free port for gmid"
	gmid_conf_file="$chroot_dir/gmid.conf"
	gmid_conf "$chroot_dir" "$gemini_port" > "$gmid_conf_file"
	"$openssl" req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$HOST" \
		-keyout "$chroot_dir/tls.key" -out "$chroot_dir/tls.crt" >/dev/null 2>&1 ||
		die "could not make the self-signed certificate"
	gmid -n -c "$gmid_conf_file" || die "gmid refused the fixture config"
	gmid -f -P "$chroot_dir/gmid.pid" -c "$gmid_conf_file" > "$chroot_dir/gmid.log" 2>&1 &
	gmid_pid=$!
	wait_gemini "$gemini_port" || {
		sed -n 1,20p "$chroot_dir/gmid.log" >&2
		sed -n 1,20p "$chroot_dir/static.log" >&2
		die "gmid did not answer on 127.0.0.1:$gemini_port"
	}
	expect_gemini "$gemini_port" '/index.gmi' 20 'alice capsule' 'plain file'
	expect_gemini "$gemini_port" '/sub' 31 "gemini://$HOST/sub/" 'directory without its separator'
	expect_gemini_denied "$gemini_port" '/leak' "$BOB_SECRET" 'relative link'
	expect_gemini_denied "$gemini_port" '/gitleak' '[core]' 'absolute .git link'
	expect_gemini_denied "$gemini_port" '/.git/config' '[core]' 'direct .git'

	printf '\nverify-hosting: httpd, gmid and the responder served the fixture as the contract says\n'
}

# --- self-test ---------------------------------------------------------------
#
# The fixture and the config shapes are what the daemon run rests on, and both
# are built with no root and no daemon here. The daemons themselves are
# exercised by the full run in CI's OpenBSD VM.

self_test() {
	typeset tree bad conf
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work/fixture
	bad=$self_test_work/broken

	mkdir "$tree" "$bad"
	make_fixture "$tree"
	make_fixture "$bad"

	check "the fixture has httpd's log directory" \
		"$([ -d "$tree/logs" ] && printf yes || printf no)" yes
	check "alice's plain files are there" \
		"$([ -f "$tree/alice.kyriakon.net/www/index.html" ] &&
			[ -f "$tree/alice.kyriakon.net/gemini/index.gmi" ] && printf yes || printf no)" yes
	check "leak is a relative link out of alice's web tree" \
		"$(readlink "$tree/alice.kyriakon.net/www/leak")" \
		'../../bob.kyriakon.net/www/secret.html'
	check "and out of her capsule tree" \
		"$(readlink "$tree/alice.kyriakon.net/gemini/leak")" \
		'../../bob.kyriakon.net/www/secret.html'
	check "leak resolves to bob's bytes" \
		"$(cat "$tree/alice.kyriakon.net/www/leak")" "$BOB_SECRET"
	check "gitleak is an absolute link to the landing checkout" \
		"$(readlink "$tree/alice.kyriakon.net/www/gitleak")" "$tree/landing/www/.git/config"
	check "the gitleak target holds a git config" \
		"$(grep -c '^\[core\]$' "$tree/landing/www/.git/config")" 1
	check "a complete fixture passes its own check" \
		"$(assert_fixture "$tree" >/dev/null 2>&1 && printf yes || printf no)" yes

	# The check has to fail on the mistake, not restate the tree: a missing link
	# and a link whose target bytes are wrong are the two a careless edit makes.
	rm "$bad/alice.kyriakon.net/www/leak"
	check "a fixture with no leak link is refused" \
		"$(assert_fixture "$bad" >/dev/null 2>&1 && printf yes || printf no)" no
	rm -rf "$bad"
	mkdir "$bad"
	make_fixture "$bad"
	printf 'someone else wrote this\n' > "$bad/bob.kyriakon.net/www/secret.html"
	check "a leak serving the wrong bytes is refused" \
		"$(assert_fixture "$bad" >/dev/null 2>&1 && printf yes || printf no)" no

	# The configs the daemons will read, and the responder's: the socket, not a
	# root, and no `.git` block to rely on.
	conf=$(static_conf "$tree")
	check "static.toml roots at the fixture" \
		"$(printf '%s\n' "$conf" | grep -cF "root = \"$tree\"")" 1
	check "static.toml puts both sockets inside it" \
		"$(printf '%s\n' "$conf" | grep -cF "socket = \"$tree/run/")" 2

	conf=$(httpd_conf "$tree" 19650)
	check "httpd.conf chroots to the fixture" \
		"$(printf '%s\n' "$conf" | grep -cF "chroot \"$tree\"")" 1
	check "httpd.conf serves the member's name" \
		"$(printf '%s\n' "$conf" | grep -cF "server \"$HOST\"")" 1
	check "httpd.conf hands every path to the responder" \
		"$(printf '%s\n' "$conf" | grep -cF 'fastcgi socket "/run/static-httpd.sock"')" 1
	check "httpd.conf names no root" \
		"$(printf '%s\n' "$conf" | grep -c '^[[:space:]]*root ')" 0

	conf=$(gmid_conf "$tree" 19650)
	check "gmid.conf chroots to the fixture" \
		"$(printf '%s\n' "$conf" | grep -cF "chroot \"$tree\"")" 1
	check "gmid.conf serves the member's name" \
		"$(printf '%s\n' "$conf" | grep -cF "server \"$HOST\"")" 1
	check "gmid.conf hands every path to the responder" \
		"$(printf '%s\n' "$conf" | grep -cF 'fastcgi socket "/run/static-gemini.sock"')" 1
	check "gmid.conf names no root" \
		"$(printf '%s\n' "$conf" | grep -c '^[[:space:]]*root ')" 0
	check "and no .git block" \
		"$(printf '%s\n' "$conf" | grep -c 'location')" 0

	self_test_end
}

case "${1:-}" in
--self-test)
	[ "$#" -eq 1 ] || usage
	self_test
	;;
"")
	full_run
	;;
*)
	usage
	;;
esac
