#!/bin/ksh
# verify-binary-sandbox.sh — start every sandboxed binary under real OpenBSD
# unveil(2) and pledge(2), and prove the kernel still refuses what the policy
# forbids.
#
# Usage:
#   doas ksh scripts/verify-binary-sandbox.sh              # OpenBSD VM, root
#        ksh scripts/verify-binary-sandbox.sh --self-test  # fixture only
#
# On a box that already has the installed login checker, set
# KYRIAKON_SANDBOX_SWAP_CHECKER=yes: the run saves it, replaces it with a
# one-password stand-in for the duration, and restores it on exit or signal.
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
#   * handler: starts, answers one portal status read, one capsule `/apply`
#     request and one successful login, and exits no cleaner than a signal. The
#     capsule and login are the two requests that take a store lock
#     (`drafts/.lock` and `sessions/.<id>.lock`), so the handler still being
#     alive after each is what proves its pledge carries `flock`.
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
# keygen fixtures the other Rust tests share. Its private half is nowhere.
fixture_key=$repo/keygen/fixtures/generated-clean.asc
refused_key=$repo/keygen/fixtures/gpg-no-encryption-subkey.asc
catalogue_src=$repo/openbsd/etc/onboard/catalogue.toml
reserved_src=$repo/reserved-usernames.txt
config_src=$repo/openbsd/etc/onboard/onboard.toml
status_token=abcdefghjkmnpqrstvwxyz0123
# The stand-in login checker's one password, and the proof token it prints. The
# real checker verifies a mail password through doas and writes a proof; this run
# only needs one request to succeed so it reaches `session::open`, which takes
# the session lock under the handler's pledge.
fixture_password=righthorsebattery
proof_token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

usage() {
	cat >&2 <<'USAGE'
usage: doas ksh verify-binary-sandbox.sh
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

# restore_system: put back the login checker and `/etc/doas.conf` this run
# borrowed, then remove the fixture. It runs from an EXIT trap, so every branch
# is best-effort and the status is zero.
restore_system() {
	if [ "${borrowed_authcheck:-no}" = yes ]; then
		if [ -f "${authcheck_saved:-}" ]; then
			cp -p "$authcheck_saved" "$authcheck" || true
		else
			rm -f "$authcheck" || true
		fi
	fi
	if [ "${borrowed_doas:-no}" = yes ]; then
		if [ -f "${doas_conf_saved:-}" ]; then
			cp -p "$doas_conf_saved" "$doas_conf" || true
		else
			rm -f "$doas_conf" || true
		fi
	fi
	[ -n "${work:-}" ] && rm -rf "$work"
	return 0
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

# alive <pid>: whether the process is still running. A child that took SIGABRT
# stays visible to kill(0) as a zombie until it is waited for, so this reads the
# state instead: a pledge violation cannot pass as a live handler.
alive() {
	typeset state
	state=$(ps -o state= -p "$1" 2>/dev/null) || return 1
	case "$state" in
	'' | Z*) return 1 ;;
	esac
	return 0
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
	cat > "$tree/store/accounts/alice/account.json" <<'ACCOUNT'
{"version":1,"username":"alice","state":"active","decision":"approve","decided_at":"2026-09-30T09:00:00Z",
"rail":"no_charge","no_charge":true,"created_at":"2026-09-30T09:00:00Z","certificates":[],"mail_key":"AAAA"}
ACCOUNT
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
		"$encrypt_bin" "$probe_bin" "${KYRIAKON_KEYGEN_CHECK:-/usr/local/libexec/keygen-check}"; do
		[ -x "$bin" ] || die "no binary at $bin; set its KYRIAKON_*_BIN"
	done
	for file in "$fixture_key" "$refused_key" "$catalogue_src" "$reserved_src" "$config_src"; do
		[ -f "$file" ] || die "no $file"
	done
	command -v gpg >/dev/null 2>&1 || die "gpg is needed for the encryptor smoke run"
	command -v perl >/dev/null 2>&1 || die "perl is needed to write one FastCGI request"
	# The pledge probe is *meant* to abort; a core file in the checkout would be
	# an artifact, not evidence.
	ulimit -c 0

	work=$(mktemp -d /var/db/kyriakon-binsandbox.XXXXXX) || exit 1
	trap restore_system EXIT
	trap 'exit 1' HUP INT TERM
	[ "$(id -u)" -eq 0 ] ||
		die "the full run installs a stand-in checker and a doas rule; run it as root"
	# The login check is `doas` plus the fixed checker. A successful login is
	# the one request that reaches `session::open` and its store lock, so the run
	# needs a checker that admits one fixture password and a doas rule that lets
	# the handler's process run it. A bare CI VM has neither, so both are
	# supplied here and put back on exit; a real box's copies are saved first.
	authcheck=/usr/local/libexec/kyriakon-authcheck
	doas_conf=/etc/doas.conf
	authcheck_saved=$work/kyriakon-authcheck.saved
	doas_conf_saved=$work/doas.conf.saved
	borrowed_authcheck=no
	borrowed_doas=no
	mkdir -p /usr/local/libexec
	if [ -e "$authcheck" ]; then
		# Replacing an installed checker would hand a login bypass to anyone
		# who can reach the live portal until this run restores it.
		[ "${KYRIAKON_SANDBOX_SWAP_CHECKER:-no}" = yes ] ||
			die "$authcheck is installed; set KYRIAKON_SANDBOX_SWAP_CHECKER=yes to replace it for this run"
		cp -p "$authcheck" "$authcheck_saved" || die "could not save $authcheck"
	fi
	# From here the path may be truncated or rewritten, so the trap must put the
	# saved copy back even if the write fails.
	borrowed_authcheck=yes
	cat > "$authcheck" <<EOF
#!/bin/ksh
# Only the fixture handler gets a proof: a stand-in left behind by a killed
# run must not admit a live login, whose proof directory is elsewhere.
[ "\$2" = '$work/fixture/proofs' ] || exit 1
read -r given
[ "\$given" = '$fixture_password' ] || exit 1
printf '%s\n' '$proof_token'
EOF
	chmod 755 "$authcheck"
	if [ -e "$doas_conf" ]; then
		cp -p "$doas_conf" "$doas_conf_saved" || die "could not save $doas_conf"
	fi
	borrowed_doas=yes
	# A leading newline keeps the rule on its own line even when an existing
	# file does not end with one; doas ignores the blank line.
	printf '\npermit nopass %s as root cmd %s\n' "$(id -un)" "$authcheck" \
		>> "$doas_conf"
	# doas refuses a group- or world-writable config; narrow rather than widen,
	# and the saved copy restores the original mode on exit.
	chmod go-w "$doas_conf"
	doas -C "$doas_conf" "$authcheck" >/dev/null 2>&1 ||
		die "the temporary doas rule does not permit the checker"
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
	alive "$spid" || fail "static exited after binding"
	kill "$spid" 2>/dev/null || true
	status=0
	wait "$spid" 2>/dev/null || status=$?
	assert_signal_only "$status" "static"

	# 3. handler: bind four listeners, keep its view, and answer a portal read
	# and three FastCGI requests. The capsule's `/apply` is unauthenticated and
	# reaches `draft::save`; the successful login reaches `session::open`. Both
	# take a store lock, so a pledge without `flock` aborts the handler inside
	# them. A wrong password still proves the handler could exec doas and the
	# checker: a missing `unveil(DOAS, "x")` or `exec` promise shows as "cannot
	# run the login check". Each request is followed by a liveness check, not
	# just the final wait, so a killed handler cannot pass as a clean answer.
	"$handler_bin" serve --config "$tree/handler.toml" > "$tree/logs/handler" 2>&1 &
	hpid=$!
	wait_for "$tree/run/portal.sock" || fail "the handler bound no portal socket"
	wait_for "$tree/run/httpd.sock" || fail "the handler bound no httpd socket"
	wait_for "$tree/run/gemini.sock" || fail "the handler bound no gemini socket"
	alive "$hpid" || fail "the handler exited after binding"
	printf 'STATUS - %s\n' "$status_token" |
		nc -U -w 2 "$tree/run/portal.sock" > "$tree/logs/portal-reply" 2>&1 ||
		fail "the portal status read failed"
	grep -q '^notice ' "$tree/logs/portal-reply" ||
		fail "the portal answered no notice for an unknown token"

	# The FastCGI requests below are built in Perl because the OpenBSD base has
	# it and the wire has two length forms to encode. `$1` is the socket, `$2` the
	# body, and the rest is the request's environment.
	cat > "$work/fcgi-request.pl" <<'PERL'
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
	# The capsule's first page: unauthenticated, GET as gmid sends it, and it
	# calls `draft::save`, which takes `drafts/.lock`. A handler killed there
	# writes no draft, so both the live process and the record are checked.
	perl "$work/fcgi-request.pl" "$tree/run/gemini.sock" '' \
		REQUEST_METHOD=GET GATEWAY_INTERFACE=CGI/1.1 \
		GEMINI_URL_PATH=apply QUERY_STRING= \
		REMOTE_ADDR=203.0.113.10 SERVER_NAME=signup.kyriakon.net \
		> "$tree/logs/capsule-reply" 2>&1 ||
		fail "the capsule /apply request could not be sent"
	alive "$hpid" ||
		fail "the handler died on the unauthenticated capsule /apply request"
	grep -q 'gemini /apply 30' "$tree/logs/handler" ||
		fail "the handler did not answer the capsule /apply route"
	ls "$tree/store/drafts"/*.json >/dev/null 2>&1 ||
		fail "the capsule /apply request wrote no draft"

	# A wrong password first: it must still be refused by the checker, and it
	# must show the handler could exec doas at all.
	perl "$work/fcgi-request.pl" "$tree/run/httpd.sock" \
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

	# The same route with the checker's password. This is the only request that
	# reaches `session::open`, which takes `sessions/.<id>.lock`, so a pledge
	# without `flock` aborts the handler here rather than answering with a
	# redirect. Check the live process and the session record it must leave.
	perl "$work/fcgi-request.pl" "$tree/run/httpd.sock" \
		"username=alice&password=$fixture_password" \
		REQUEST_METHOD=POST REQUEST_URI=/login REMOTE_ADDR=127.0.0.1 \
		SERVER_NAME=signup.kyriakon.net \
		CONTENT_TYPE=application/x-www-form-urlencoded \
		HTTP_ORIGIN=https://signup.kyriakon.net \
		> "$tree/logs/login-ok-reply" 2>&1 ||
		fail "the successful login request could not be sent"
	alive "$hpid" ||
		fail "the handler died on the successful login"
	grep -q 'httpd /login 303' "$tree/logs/handler" ||
		fail "the handler did not open a session for the correct password"
	ls "$tree/store/sessions"/*.json >/dev/null 2>&1 ||
		fail "the successful login wrote no session record"

	# An unavailable checker only warns. Its specific refusal proves the handler
	# executed the real checker after locking the veil.
	cookie=$(perl -ne 'print $1 if /Set-Cookie:\s*(__Host-kyriakon_session=[^;]+)/i' \
		"$tree/logs/login-ok-reply")
	[ -n "$cookie" ] || fail "the login returned no session cookie"
	key_body=$(perl -0777 -pe 's/([^A-Za-z0-9])/sprintf("%%%02X",ord($1))/ge' "$refused_key")
	perl "$work/fcgi-request.pl" "$tree/run/httpd.sock" "action=replace&key=$key_body" \
		REQUEST_METHOD=POST REQUEST_URI=/account/mail-key REMOTE_ADDR=127.0.0.1 \
		SERVER_NAME=signup.kyriakon.net CONTENT_TYPE=application/x-www-form-urlencoded \
		HTTP_ORIGIN=https://signup.kyriakon.net "HTTP_COOKIE=$cookie" \
		> "$tree/logs/key-reply" || fail "the key replacement request failed"
	grep -aq 'no encryption-capable subkey' "$tree/logs/key-reply" ||
		fail "the handler did not inspect the signing-only key"

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

	apply_row=$(awk '/^\[\[service\]\]/ { ++row } /^action = "apply"/ { print row; exit }' "$catalogue_src")
	{
		printf '\n%s\ntheophilus\nperson\n\n\n' "$apply_row"
		cat "$refused_key"
		printf '\nquit\n'
	} | "$tui_bin" --plain --config "$tree/handler.toml" --state "$tree/state" \
		> "$tree/logs/tui-key" 2>&1 || fail "the terminal key session failed"
	grep -q 'no encryption-capable subkey' "$tree/logs/tui-key" ||
		fail "the terminal did not inspect the signing-only key"

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
