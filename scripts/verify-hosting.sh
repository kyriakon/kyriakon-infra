#!/bin/ksh
# verify-hosting.sh — the web and gemini daemons against a two-member fixture.
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
# guardrail. This starts both daemons and reads the paths back.
#
# The fixture is two member trees and the landing checkout in one chroot:
#
#   alice.kyriakon.net/www/index.html        a plain file, the 200 control
#   alice.kyriakon.net/www/leak -> ../../bob.kyriakon.net/www/secret.html
#   alice.kyriakon.net/www/gitleak -> /landing/www/.git/config
#   bob.kyriakon.net/www/secret.html         bob's bytes, no link to them
#   landing/www/.git/config                  [core], the blocked-path target
#   logs/                                    httpd fatals without it
#
# The assertions are the behaviour #815 found: the plain file is served, the
# relative link serves bob's bytes, the absolute link serves the landing
# checkout's `.git/config`, and a direct `/.git/config` request is blocked. A
# change in any of the four fails the run, so the residual is not silently
# forgotten and a fix to the chroot shape arrives as a deliberate edit here.
#
# The full run is OpenBSD-only: it needs root for chroot(2), the www and _gmid
# accounts, and the two daemons. --self-test builds the same fixture and checks
# its layout and bytes without starting anything, so a wrong fixture fails
# loudly instead of a daemon quietly answering 404s on the box.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

openssl=/usr/bin/openssl
chroot_dir=''
httpd_pid=''
gmid_pid=''

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

# make_fixture <dir>: the tree both daemon configs point at and both halves of
# the test read. One function, so the configs and --self-test cannot describe
# two different fixtures.
make_fixture() {
	typeset tree="$1"
	mkdir -p "$tree/alice.kyriakon.net/www" "$tree/bob.kyriakon.net/www" \
		"$tree/landing/www/.git" "$tree/logs" || return 1
	printf 'alice\n' > "$tree/alice.kyriakon.net/www/index.html"
	printf '%s\n' "$BOB_SECRET" > "$tree/bob.kyriakon.net/www/secret.html"
	printf '%s\n' "$GIT_CONFIG" > "$tree/landing/www/.git/config"
	# Relative: resolved from the daemon's root after chroot, so it leaves
	# alice's own tree and lands in bob's. #815's first case.
	ln -s ../../bob.kyriakon.net/www/secret.html "$tree/alice.kyriakon.net/www/leak"
	# Absolute: after chroot "/landing" is the fixture's landing tree, so this
	# serves a .git config that the request-path block never sees.
	ln -s /landing/www/.git/config "$tree/alice.kyriakon.net/www/gitleak"
}

# assert_fixture <dir>: the layout and the bytes, before any daemon starts. A
# fixture that is wrong here would make the daemon assertions pass or fail for
# the wrong reason, so it is a hard stop.
assert_fixture() {
	typeset tree="$1" ok=yes want

	if [ ! -d "$tree/logs" ]; then
		printf 'verify-hosting: fixture: no %s/logs\n' "$tree" >&2
		ok=no
	fi
	if [ ! -f "$tree/alice.kyriakon.net/www/index.html" ]; then
		printf 'verify-hosting: fixture: no alice index.html\n' >&2
		ok=no
	fi

	want='../../bob.kyriakon.net/www/secret.html'
	if [ "$(readlink "$tree/alice.kyriakon.net/www/leak" 2>/dev/null)" != "$want" ]; then
		printf 'verify-hosting: fixture: leak is not a link to %s\n' "$want" >&2
		ok=no
	elif [ "$(cat "$tree/alice.kyriakon.net/www/leak" 2>/dev/null)" != "$BOB_SECRET" ]; then
		printf 'verify-hosting: fixture: leak does not resolve to bob bytes\n' >&2
		ok=no
	fi

	# The link's target cannot be read through the link off OpenBSD: "/landing"
	# there is the host's root, not the fixture. Check the target the daemon will
	# resolve and the file it resolves to.
	want='/landing/www/.git/config'
	if [ "$(readlink "$tree/alice.kyriakon.net/www/gitleak" 2>/dev/null)" != "$want" ]; then
		printf 'verify-hosting: fixture: gitleak is not a link to %s\n' "$want" >&2
		ok=no
	elif ! grep -q '^\[core\]$' "$tree/landing/www/.git/config" 2>/dev/null; then
		printf 'verify-hosting: fixture: the gitleak target has no [core]\n' >&2
		ok=no
	fi

	[ "$ok" = yes ]
}

# httpd_conf <chroot> <port>: the smallest config that has the deployed shape.
httpd_conf() {
	cat <<EOF
chroot "$1"
server "*" {
	listen on 127.0.0.1 port $2
	location "/.git/*" {
		block
	}
	location "/*" {
		root "/alice.kyriakon.net/www"
	}
}
EOF
}

# gmid_conf <chroot> <port>: the capsule counterpart, same chroot and root.
gmid_conf() {
	cat <<EOF
chroot "$1"
user "_gmid"
server "localhost" {
	listen on 127.0.0.1 port $2
	cert "$1/tls.crt"
	key "$1/tls.key"
	root "/alice.kyriakon.net/www"
	location "/.git/*" {
		block return 51
	}
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

wait_http() {
	typeset port="$1" tries=0
	while [ "$tries" -lt 50 ]; do
		curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/index.html" \
			>/dev/null 2>&1 && return 0
		sleep 0.2
		tries=$((tries + 1))
	done
	return 1
}

# gemini_get <port> <path>: the whole response, CRs stripped. curl has no
# gemini support, so the request line goes through openssl s_client.
gemini_get() {
	printf 'gemini://localhost:%s%s\r\n' "$1" "$2" |
		"$openssl" s_client -connect "127.0.0.1:$1" -servername localhost -quiet \
			2>/dev/null | tr -d '\r'
}

wait_gemini() {
	typeset port="$1" tries=0
	while [ "$tries" -lt 50 ]; do
		[ -n "$(gemini_get "$port" /index.html | sed -n 1p)" ] && return 0
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
	status=$(curl -sS --max-time 5 -o "$body" -w '%{http_code}' \
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

cleanup() {
	typeset pid
	for pid in "$httpd_pid" "$gmid_pid"; do
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
	typeset http_port gemini_port httpd_conf_file gmid_conf_file

	[ "$(uname -s)" = OpenBSD ] ||
		die "the daemon half is OpenBSD-only; run --self-test on this host"
	[ "$(id -u)" -eq 0 ] ||
		die "run this with doas: httpd and gmid chroot(2) and drop to their own users"
	[ -x "$openssl" ] || die "no $openssl"
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
		die "httpd did not answer on 127.0.0.1:$http_port"
	}
	expect_http "$http_port" '/index.html' 200 'alice' 'plain file'
	expect_http "$http_port" '/leak' 200 "$BOB_SECRET" 'relative link'
	expect_http "$http_port" '/gitleak' 200 '\[core\]' 'absolute .git link'
	expect_http "$http_port" '/.git/config' 403 '' 'direct .git'

	# --- gmid ------------------------------------------------------------
	gemini_port=$(free_port) || die "no free port for gmid"
	gmid_conf_file="$chroot_dir/gmid.conf"
	gmid_conf "$chroot_dir" "$gemini_port" > "$gmid_conf_file"
	"$openssl" req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
		-keyout "$chroot_dir/tls.key" -out "$chroot_dir/tls.crt" >/dev/null 2>&1 ||
		die "could not make the self-signed certificate"
	gmid -n -c "$gmid_conf_file" || die "gmid refused the fixture config"
	gmid -f -P "$chroot_dir/gmid.pid" -c "$gmid_conf_file" > "$chroot_dir/gmid.log" 2>&1 &
	gmid_pid=$!
	wait_gemini "$gemini_port" || {
		sed -n 1,20p "$chroot_dir/gmid.log" >&2
		die "gmid did not answer on 127.0.0.1:$gemini_port"
	}
	expect_gemini "$gemini_port" '/index.html' 20 'alice' 'plain file'
	expect_gemini "$gemini_port" '/leak' 20 "$BOB_SECRET" 'relative link'
	expect_gemini "$gemini_port" '/gitleak' 20 '\[core\]' 'absolute .git link'
	expect_gemini "$gemini_port" '/.git/config' 51 '' 'direct .git'

	printf '\nverify-hosting: httpd and gmid served the fixture\n'
}

# --- self-test ---------------------------------------------------------------
#
# The fixture and the two config shapes are what the daemon run rests on, and
# both are built with no root and no daemon here. The daemons themselves are
# exercised by the full run in CI's OpenBSD VM.

self_test() {
	typeset tree bad conf first_location
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work/fixture
	bad=$self_test_work/broken

	mkdir "$tree" "$bad"
	make_fixture "$tree"
	make_fixture "$bad"

	check "the fixture has httpd's log directory" \
		"$([ -d "$tree/logs" ] && printf yes || printf no)" yes
	check "alice's plain file is there" \
		"$([ -f "$tree/alice.kyriakon.net/www/index.html" ] && printf yes || printf no)" yes
	check "leak is a relative link out of alice's tree" \
		"$(readlink "$tree/alice.kyriakon.net/www/leak")" \
		'../../bob.kyriakon.net/www/secret.html'
	check "leak resolves to bob's bytes" \
		"$(cat "$tree/alice.kyriakon.net/www/leak")" "$BOB_SECRET"
	check "gitleak is an absolute link to the landing checkout" \
		"$(readlink "$tree/alice.kyriakon.net/www/gitleak")" '/landing/www/.git/config'
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

	# The configs the daemons will read: chroot, root and first match.
	conf=$(httpd_conf "$tree" 19650)
	check "httpd.conf chroots to the fixture" \
		"$(printf '%s\n' "$conf" | grep -cF "chroot \"$tree\"")" 1
	check "httpd.conf roots at alice's tree" \
		"$(printf '%s\n' "$conf" | grep -cF 'root "/alice.kyriakon.net/www"')" 1
	first_location=$(printf '%s\n' "$conf" | sed -n 's/.*location "\([^"]*\)".*/\1/p' | sed -n 1p)
	check "httpd.conf matches .git before the catch-all" "$first_location" '/.git/*'
	check "httpd.conf blocks rather than redirects .git" \
		"$(printf '%s\n' "$conf" | grep -c 'block$')" 1

	conf=$(gmid_conf "$tree" 19650)
	check "gmid.conf chroots to the fixture" \
		"$(printf '%s\n' "$conf" | grep -cF "chroot \"$tree\"")" 1
	check "gmid.conf roots at alice's tree" \
		"$(printf '%s\n' "$conf" | grep -cF 'root "/alice.kyriakon.net/www"')" 1
	first_location=$(printf '%s\n' "$conf" | sed -n 's/.*location "\([^"]*\)".*/\1/p' | sed -n 1p)
	check "gmid.conf matches .git before serving a root" "$first_location" '/.git/*'
	check "gmid.conf answers a blocked path with 51" \
		"$(printf '%s\n' "$conf" | grep -c 'block return 51')" 1

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
