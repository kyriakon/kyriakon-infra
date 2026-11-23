#!/bin/ksh
# verify-binary-sandbox.sh — start every sandboxed binary under real OpenBSD
# unveil(2) and pledge(2), and prove the kernel still refuses what the policy
# forbids.
#
# Usage:
#   ksh scripts/verify-binary-sandbox.sh              # OpenBSD, real binaries
#        ksh scripts/verify-binary-sandbox.sh --self-test  # fixture only
#
# Why this exists: unveil and pledge are OpenBSD-only, and a wrong promise kills
# the process with SIGABRT on the first forbidden operation rather than failing a
# test. The drain has its own verifier (#849); this one covers the four
# network-facing programs #952 names — the static responder, the handler, the
# terminal and the encryptor — plus the compiled fromcheck filter.
#
# The fixture is one tree under /var/db (not ${TMPDIR:-/tmp}, because the
# encryptor's scratch homedir lives under /tmp and a fixture there would make an
# omitted rule look reachable). Every path a policy names is real, so a missing
# entry fails the binary at startup or at its first read, and the smoke run says
# so.
#
# What is asserted:
#   * sandbox-probe path: a locked unveil list refuses a path it did not name.
#   * sandbox-probe syscall: `pledge "stdio"` kills a `chmod(2)` with SIGABRT.
#   * static: binds both sockets, starts, and survives (verify-hosting.sh makes
#     it serve requests).
#   * handler: starts, answers one portal status read, and exits no cleaner than
#     a signal.
#   * tui: a plain-mode session reads its catalogue, takes its session lock, and
#     exits on "q".
#   * encrypt: encrypts a message through the real gpg, under the veil.
#   * fromcheck: answers the protocol's `config|ready` registration.
#
# --self-test builds the same fixture and checks its shape and the generated
# configs with no binary and no unveil, so a wrong fixture fails on the day CI
# runs it rather than as a confusing SIGABRT.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

repo=$(cd "$script_dir/.." && pwd)
control_target=${CARGO_TARGET_DIR:-$repo/control/target}
static_bin=${KYRIAKON_STATIC_BIN:-$control_target/release/kyriakon-control-static}
handler_bin=${KYRIAKON_HANDLER_BIN:-$control_target/release/kyriakon-control}
tui_bin=${KYRIAKON_TUI_BIN:-$control_target/release/kyriakon-control-tui}
fromcheck_bin=${KYRIAKON_FROMCHECK_BIN:-$control_target/release/kyriakon-fromcheck}
encrypt_bin=${KYRIAKON_ENCRYPT_BIN:-$repo/kyriakon-encrypt/target/release/kyriakon-encrypt}
probe_bin=${KYRIAKON_SANDBOX_PROBE:-$control_target/release/examples/sandbox-probe}

# The nested test key: a public key with an encryption subkey, from the
# keygen-spike fixtures the other Rust tests share. Its private half is nowhere.
fixture_key=$repo/docs/planning/prototypes/keygen-spike/fixtures/generated-clean.asc
catalogue_src=$repo/openbsd/etc/onboard/catalogue.toml
reserved_src=$repo/reserved-usernames.txt
config_src=$repo/openbsd/etc/onboard/onboard.toml
status_token=abcdefghjkmnpqrstvwxyz0123

usage() {
	cat >&2 <<'USAGE'
usage: ksh verify-binary-sandbox.sh
       ksh verify-binary-sandbox.sh --self-test
USAGE
	exit 2
}

die() {
	printf 'verify-binary-sandbox: %s\n' "$*" >&2
	exit 1
}

# fail <why>: the binary's own output, then exit. A failed assertion in CI is
# otherwise one line with no state to read.
fail() {
	typeset log
	if [ -n "${tree:-}" ]; then
		for log in "$tree"/logs/*; do
			[ -f "$log" ] || continue
			printf -- '--- %s\n' "$log" >&2
			sed -n 1,40p "$log" >&2
		done
	fi
	die "$*"
}

wait_for() {
	typeset path=$1 tries=0
	while [ "$tries" -lt 100 ]; do
		[ -e "$path" ] && return 0
		sleep 0.1
		tries=$((tries + 1))
	done
	return 1
}

# make_fixture <tree>: every path the five policies name, and the store records
# the handler's startup reads. One function, so the run and --self-test cannot
# describe two different trees.
make_fixture() {
	typeset tree=$1
	mkdir -p "$tree/store/accounts/alice" "$tree/store/applications" \
		"$tree/store/intents" "$tree/store/sessions" "$tree/store/groups" \
		"$tree/store/pages" "$tree/proofs" "$tree/run" "$tree/www/example.test/www" \
		"$tree/static-hosts" "$tree/keyring" "$tree/gpg" "$tree/mail" \
		"$tree/logs" "$tree/state" || return 1

	cp "$reserved_src" "$tree/store/reserved-usernames.txt"
	cp "$catalogue_src" "$tree/store/catalogue.toml"
	for page in terms.gmi aup.gmi privacy.gmi key-walkthrough.gmi; do
		printf '# %s\n\nA mirrored page.\n' "$page" > "$tree/store/pages/$page"
	done
	printf 'alice\n' > "$tree/store/accounts/alice/account.json"
	printf 'kyriakon.net\n' > "$tree/mail/mail_from"
	cp "$fixture_key" "$tree/keyring/alice.asc"
	chmod 700 "$tree/gpg"
}

# handler_config <tree>: the tracked handler config with every path pointed at
# the fixture and every listener inside it.
handler_config() {
	typeset tree=$1
	sed \
		-e "s|^store_root = .*|store_root = \"$tree/store\"|" \
		-e "s|^reserved = .*|reserved = \"$tree/store/reserved-usernames.txt\"|" \
		-e "s|^catalogue = .*|catalogue = \"$tree/store/catalogue.toml\"|" \
		-e "s|^pages = .*|pages = \"$tree/store/pages\"|" \
		-e "s|^proof_dir = .*|proof_dir = \"$tree/proofs\"|" \
		-e "s|^httpd_socket = .*|httpd_socket = \"$tree/run/httpd.sock\"|" \
		-e "s|^gemini_socket = .*|gemini_socket = \"$tree/run/gemini.sock\"|" \
		-e "s|^portal_socket = .*|portal_socket = \"$tree/run/portal.sock\"|" \
		-e "s|^titan_listener = .*|titan_listener = \"127.0.0.1:0\"|" \
		"$config_src"
}

# static_config <tree>: the two readable trees and the two sockets.
static_config() {
	typeset tree=$1
	cat <<EOF
root = "$tree/www"
httpd_socket = "$tree/run/static-httpd.sock"
gemini_socket = "$tree/run/static-gemini.sock"
hosts = "$tree/static-hosts"
EOF
}

# assert_fixture <tree>: the shape the smoke runs depend on.
assert_fixture() {
	typeset tree=$1 ok=yes
	[ -f "$tree/store/reserved-usernames.txt" ] || ok=no
	[ -f "$tree/store/catalogue.toml" ] || ok=no
	[ -f "$tree/store/pages/aup.gmi" ] || ok=no
	[ -f "$tree/keyring/alice.asc" ] || ok=no
	[ -f "$tree/mail/mail_from" ] || ok=no
	[ -d "$tree/www/example.test/www" ] || ok=no
	[ -d "$tree/gpg" ] || ok=no
	[ "$ok" = yes ]
}

# assert_signal_only <status> <what>: a signal after SIGTERM is expected; 134 is
# a pledge violation and any other status is a startup failure.
assert_signal_only() {
	typeset status=$1 what=$2
	case "$status" in
	0 | 143 | 129 | 130) ;;
	134) fail "$what was killed by SIGABRT" ;;
	*) fail "$what exited with an unexpected status $status" ;;
	esac
}

full_run() {
	[ "$(uname -s)" = OpenBSD ] ||
		die "the full run needs OpenBSD's unveil(2) and pledge(2); use --self-test"
	typeset bin
	for bin in "$static_bin" "$handler_bin" "$tui_bin" "$fromcheck_bin" \
		"$encrypt_bin" "$probe_bin"; do
		[ -x "$bin" ] || die "no binary at $bin; set its KYRIAKON_*_BIN"
	done
	for file in "$fixture_key" "$catalogue_src" "$reserved_src" "$config_src"; do
		[ -f "$file" ] || die "no $file"
	done
	command -v gpg >/dev/null 2>&1 || die "gpg is needed for the encryptor smoke run"
	command -v perl >/dev/null 2>&1 || die "perl is needed to write one FastCGI request"
	# The pledge probe is *meant* to abort; a core file in the checkout would be
	# an artifact, not evidence.
	ulimit -c 0

	work=$(mktemp -d /var/db/kyriakon-binsandbox.XXXXXX) || exit 1
	trap 'rm -rf "$work"' EXIT
	# The handler's policy names the installed checker path, which a bare CI VM
	# has never run deploy-control.sh to install. A stand-in is enough for the
	# startup unveil; an existing one (a real box) is left untouched.
	authcheck=/usr/local/libexec/kyriakon-authcheck
	made_authcheck=no
	if [ ! -e "$authcheck" ]; then
		mkdir -p /usr/local/libexec
		printf '#!/bin/ksh\nexit 1\n' > "$authcheck"
		chmod 755 "$authcheck"
		made_authcheck=yes
		trap 'rm -rf "$work"; [ "$made_authcheck" = yes ] && rm -f "$authcheck"' EXIT
	fi
	tree=$work/fixture
	mkdir "$tree"
	make_fixture "$tree" || die "could not make the fixture"
	assert_fixture "$tree" || die "the fixture is incomplete"

	handler_config "$tree" > "$tree/handler.toml"
	static_config "$tree" > "$tree/static.toml"

	# 1. The shared wrapper is enforced, not merely called.
	if ! "$probe_bin" path > "$tree/logs/probe-path" 2>&1; then
		fail "a locked unveil list did not block a forbidden path"
	fi
	grep -q '^blocked:' "$tree/logs/probe-path" ||
		fail "the path probe did not report a blocked read"

	# A pledge violation must abort the child. ksh reports 134 for SIGABRT.
	if "$probe_bin" syscall > "$tree/logs/probe-syscall" 2>&1; then
		fail "a forbidden syscall returned under pledge"
	else
		code=$?
	fi
	[ "$code" -eq 134 ] ||
		fail "the forbidden syscall did not abort (status $code)"

	# 2. static: bind, veil, stay up.
	"$static_bin" --config "$tree/static.toml" > "$tree/logs/static" 2>&1 &
	spid=$!
	wait_for "$tree/run/static-httpd.sock" || fail "static bound no httpd socket"
	wait_for "$tree/run/static-gemini.sock" || fail "static bound no gemini socket"
	kill -0 "$spid" 2>/dev/null || fail "static exited after binding"
	kill "$spid" 2>/dev/null || true
	status=0
	wait "$spid" 2>/dev/null || status=$?
	assert_signal_only "$status" "static"

	# 3. handler: bind four listeners, keep its view, answer one portal read,
	# then run one login through doas. The VM has no doas rule for the checker,
	# so doas refuses and the login answers its ordinary failure page. What the
	# step proves is that the handler could exec the fixed program at all: a
	# missing `unveil(DOAS, "x")` or `exec` promise shows as "cannot run the
	# login check", while a killed process fails the wait below.
	"$handler_bin" serve --config "$tree/handler.toml" > "$tree/logs/handler" 2>&1 &
	hpid=$!
	wait_for "$tree/run/portal.sock" || fail "the handler bound no portal socket"
	wait_for "$tree/run/httpd.sock" || fail "the handler bound no httpd socket"
	wait_for "$tree/run/gemini.sock" || fail "the handler bound no gemini socket"
	kill -0 "$hpid" 2>/dev/null || fail "the handler exited after binding"
	printf 'STATUS - %s\n' "$status_token" |
		nc -U -w 2 "$tree/run/portal.sock" > "$tree/logs/portal-reply" 2>&1 ||
		fail "the portal status read failed"
	grep -q '^notice ' "$tree/logs/portal-reply" ||
		fail "the portal answered no notice for an unknown token"

	# One FastCGI POST to /login. The fields are the minimum the route reads,
	# and the origin names the one the handler accepts. The request is built in
	# Perl because the OpenBSD base has it and the wire has two length forms to
	# encode.
	cat > "$work/fcgi-login.pl" <<'PERL'
use strict;
use warnings;
use IO::Socket::UNIX;

my ($path, $body, @env) = @ARGV;
sub record {
	my ($type, $content) = @_;
	return pack('CCnnCC', 1, $type, 1, length($content), 0, 0) . $content;
}
sub param {
	my ($name, $value) = @_;
	return pack('CC', length($name), length($value)) . $name . $value;
}
my $params = join '', map {
	my ($name, $value) = split /=/, $_, 2;
	param($name, defined $value ? $value : '');
} @env;
my $request = record(1, pack('CCCCCCCC', 0, 1, 0, 0, 0, 0, 0, 0))
	. record(4, $params) . record(4, '')
	. record(5, $body) . record(5, '');
my $socket = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $path)
	or die "connect: $!";
print {$socket} $request or die "write: $!";
my $reply = '';
while (1) {
	my $read = sysread($socket, my $chunk, 65536);
	die "read: $!" unless defined $read;
	last if $read == 0;
	$reply .= $chunk;
}
print $reply;
PERL
	perl "$work/fcgi-login.pl" "$tree/run/httpd.sock" \
		'username=alice&password=wrong' \
		REQUEST_METHOD=POST REQUEST_URI=/login REMOTE_ADDR=127.0.0.1 \
		SERVER_NAME=signup.kyriakon.net \
		CONTENT_TYPE=application/x-www-form-urlencoded \
		HTTP_ORIGIN=https://signup.kyriakon.net \
		> "$tree/logs/login-reply" 2>&1 ||
		fail "the login request could not be sent"
	grep -q 'httpd /login 200' "$tree/logs/handler" ||
		fail "the handler did not answer the login route"
	if grep -q 'cannot run the login check' "$tree/logs/handler"; then
		fail "the handler could not exec doas under its pledge"
	fi

	# 4. tui: a plain session reads its catalogue, takes its session lock, asks
	# the handler for a status so the unix connect is exercised, and leaves. The
	# start screen's word is "quit"; the menu's is "q", which this session never
	# reaches. The handler is still up for the status read.
	printf 'status\n%s\n\nquit\n' "$status_token" |
		"$tui_bin" --plain --config "$tree/handler.toml" --state "$tree/state" \
		> "$tree/logs/tui" 2>&1 ||
		fail "the plain terminal session failed"
	grep -q 'This link is not in use' "$tree/logs/tui" ||
		fail "the terminal did not read the handler's status"
	if grep -q 'status service is not answering' "$tree/logs/tui"; then
		fail "the terminal could not connect to the portal socket"
	fi

	kill "$hpid" 2>/dev/null || true
	status=0
	wait "$hpid" 2>/dev/null || status=$?
	assert_signal_only "$status" "the handler"

	# 5. encrypt: a real gpg encrypted the message under the veil.
	printf 'From: alice@kyriakon.net\nTo: alice@kyriakon.net\nSubject: probe\n\nbody\n' |
		"$encrypt_bin" encrypt --user alice --keyring "$tree/keyring" \
		--gpg-home "$tree/gpg" > "$tree/logs/encrypt" 2>&1 ||
		fail "the encryptor failed under the veil"
	grep -q -- '-----BEGIN PGP MESSAGE-----' "$tree/logs/encrypt" ||
		fail "the encryptor wrote no ciphertext"

	# 6. fromcheck: the filter registers its protocol hooks under its veil.
	printf 'config|ready\n' |
		"$fromcheck_bin" -t "$tree/mail/mail_from" -a kyriakon.net \
		> "$tree/logs/fromcheck" 2>&1 ||
		fail "the fromcheck filter failed"
	grep -q 'register|ready' "$tree/logs/fromcheck" ||
		fail "fromcheck did not register"

	printf '\nverify-binary-sandbox: every binary started, served and stayed within its veil\n'
}

# --- self-test ---------------------------------------------------------------
#
# The fixture and the generated configs are what the runs rest on; both are
# built with no binary and no unveil here.

self_test() {
	typeset tree conf
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work/fixture
	mkdir "$tree"
	make_fixture "$tree"

	check "the fixture has the tracked catalogue" \
		"$(grep -c '^\[\[service\]\]' "$tree/store/catalogue.toml" | head -1)" \
		"$(grep -c '^\[\[service\]\]' "$catalogue_src" | head -1)"
	check "the fixture has the four mirrored pages" \
		"$(find "$tree/store/pages" -type f | wc -l | tr -d ' ')" 4
	check "the fixture has the encryption key" \
		"$(grep -c 'BEGIN PGP PUBLIC KEY BLOCK' "$tree/keyring/alice.asc")" 1
	check "a complete fixture passes its own check" \
		"$(assert_fixture "$tree" >/dev/null 2>&1 && printf yes || printf no)" yes

	conf=$(handler_config "$tree")
	check "the handler config names the fixture store" \
		"$(printf '%s\n' "$conf" | grep -cF "store_root = \"$tree/store\"")" 1
	check "the handler config names the fixture portal socket" \
		"$(printf '%s\n' "$conf" | grep -cF "portal_socket = \"$tree/run/portal.sock\"")" 1
	check "the handler config binds Titan on a loopback port" \
		"$(printf '%s\n' "$conf" | grep -cF 'titan_listener = "127.0.0.1:0"')" 1
	check "the static config names the fixture root" \
		"$(static_config "$tree" | grep -cF "root = \"$tree/www\"")" 1

	# A broken fixture must fail the check rather than the run.
	rm "$tree/keyring/alice.asc"
	check "a fixture without the key is refused" \
		"$(assert_fixture "$tree" >/dev/null 2>&1 && printf yes || printf no)" no

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
