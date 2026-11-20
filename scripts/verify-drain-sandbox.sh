#!/bin/ksh
# verify-drain-sandbox.sh — a full drain pass under unveil and pledge.
#
# Usage:
#   doas ksh scripts/verify-drain-sandbox.sh              # OpenBSD, a real pass
#        ksh scripts/verify-drain-sandbox.sh --self-test  # fixture only
#
# Why this exists: the drain is the one program that runs as root from cron,
# and #849 requires it to start with its filesystem view and syscall set cut to
# what a pass uses. No Rust test can prove that: unveil(2) and pledge(2) are
# OpenBSD-only, and a wrong promise kills the process with SIGABRT after the
# first minute of production instead of failing a test. This runs the release
# binary over a fixture store and reads what the pass did.
#
# The fixture is a store with one malformed intent (a failure the drain mails
# about) and one intent of a kind this build does not implement (a refusal it
# journals and leaves in place), plus every path drain.toml names:
#
#   store/intents/01AAAA...json      {"kind":"close"}, a parse failure
#   store/intents/01BBBB...json      {"kind":"future-verb"}, a refusal
#   bin/{sendmail,curl,dig,repquota,gpg}  stubs that record or answer
#   key, stripe-secret, passwd, reserved, the five mail tables
#   logins/, keyring/, mail/new/, bounce/new/, home/www/, store/rates/
#
# What the pass proves when it exits 0 and the assertions hold: the approval key
# and the config were read, the store lock was taken, an intent was parsed, one
# failure was mailed through `sendmail` (fork and exec under the pledge), the
# rate cache was fetched through `curl` and written, an intent was refused and
# journalled, and every sweep ran over the empty store. A missing promise or
# unveil entry aborts the process, so the exit status is the test.
#
# The second half runs the same config with a store root whose parent does not
# exist: unveil fails at startup and the message must name the path and the
# reason, which is what an operator reading cron mail needs.
#
# The full run needs the built binary. KYRIAKON_DRAIN_BIN names it; the default
# is the release build under control/target. --self-test builds the same fixture
# and checks its shape and the generated config with no binary and no unveil, so
# the fixture cannot be wrong on the day the CI VM runs it.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

repo=$(cd "$script_dir/.." && pwd)
drain_bin=${KYRIAKON_DRAIN_BIN:-$repo/control/target/release/kyriakon-control-drain}
config_src=$repo/openbsd/etc/onboard/drain.toml

usage() {
	cat >&2 <<'USAGE'
usage: doas ksh verify-drain-sandbox.sh
       ksh verify-drain-sandbox.sh --self-test
USAGE
	exit 2
}

die() {
	printf 'verify-drain-sandbox: %s\n' "$*" >&2
	exit 1
}

# stub <path> <body...>: a script the drain runs instead of a system binary.
# The body is written as given, so a stub that answers on stdout and one that
# records its arguments are the same line here.
stub() {
	typeset path=$1
	shift
	{
		printf '#!/bin/ksh\n'
		printf '%s\n' "$@"
	} > "$path"
	chmod 755 "$path"
}

# make_fixture <dir>: the store, the config's paths and the stubs. One function,
# so the full run and --self-test can never describe two different fixtures.
make_fixture() {
	typeset tree=$1
	mkdir -p "$tree/store/intents" "$tree/store/accounts" "$tree/store/groups" \
		"$tree/store/holds" "$tree/store/webhooks" "$tree/store/ledger" \
		"$tree/store/rates" "$tree/store/drafts" "$tree/store/applications" \
		"$tree/logins" "$tree/keyring" "$tree/mail/new" "$tree/mail/cur" \
		"$tree/bounce/new" "$tree/home/www" "$tree/bin" "$tree/log" || return 1

	# The two keys: root-only 0600, which sign::read_key insists on.
	printf 'unveil-fixture-approval-key\n' > "$tree/key"
	printf 'unveil-fixture-stripe-secret\n' > "$tree/stripe-secret"
	chmod 600 "$tree/key" "$tree/stripe-secret"

	# The account list and the reserved names the approval checks.
	printf 'root:*:0:0::0:0:Charlie &:/root:/bin/ksh\n' > "$tree/passwd"
	printf 'admin\nroot\n' > "$tree/reserved"

	# The five mail tables, in their shipped shape: one domain, one alias.
	printf 'kyriakon.net\n' > "$tree/mail_domains"
	printf 'postmaster: root\n' > "$tree/virtuals"
	printf 'root: root@kyriakon.net\n' > "$tree/mail_from"
	printf 'kyriakon.net\n' > "$tree/dkim_domains"
	printf '@kyriakon.net\n' > "$tree/spamd.alloweddomains"

	# A malformed intent: the drain mails the operator once and leaves it.
	printf '{"kind":"close"}\n' > "$tree/store/intents/01AAAAAAAAAAAAAAAAAAAAAAAA.json"
	# A kind this build does not implement: refused, journalled, left in place.
	printf '{"kind":"future-verb","note":"left for the release that knows it"}\n' \
		> "$tree/store/intents/01BBBBBBBBBBBBBBBBBBBBBBBB.json"

	# The enqueuer: append what the drain would have sent to one file.
	stub "$tree/bin/sendmail" \
		"printf 'args: %s\\n' \"\$*\" >> '$tree/log/sendmail'" \
		"cat >> '$tree/log/sendmail'"
	# The rate source: the one answer the parser accepts.
	stub "$tree/bin/curl" \
		"printf '%s\\n' '{\"monero\":{\"gbp\":409.44,\"last_updated_at\":1790857880}}'"
	# The remaining tools are installed on the box; the fixture only has to
	# exist so its path can be unveiled and exec'd.
	stub "$tree/bin/dig" 'exit 0'
	stub "$tree/bin/repquota" 'exit 0'
	stub "$tree/bin/gpg" 'exit 0'
}

# config_for <tree>: the tracked drain.toml with every path pointed at <tree>.
# Reading the shipped file rather than restating it means a key added there is
# exercised here without this script being edited.
config_for() {
	typeset tree=$1
	sed \
		-e "s|^store_root = .*|store_root = \"$tree/store\"|" \
		-e "s|^reserved = .*|reserved = \"$tree/reserved\"|" \
		-e "s|^scripts = .*|scripts = \"$tree/bin\"|" \
		-e "s|^sendmail = .*|sendmail = \"$tree/bin/sendmail\"|" \
		-e "s|^passwd = .*|passwd = \"$tree/passwd\"|" \
		-e "s|^mail_domains = .*|mail_domains = \"$tree/mail_domains\"|" \
		-e "s|^virtuals = .*|virtuals = \"$tree/virtuals\"|" \
		-e "s|^mail_from = .*|mail_from = \"$tree/mail_from\"|" \
		-e "s|^dkim_domains = .*|dkim_domains = \"$tree/dkim_domains\"|" \
		-e "s|^spamd_alloweddomains = .*|spamd_alloweddomains = \"$tree/spamd.alloweddomains\"|" \
		-e "s|^approval_key = .*|approval_key = \"$tree/key\"|" \
		-e "s|^keyring_dir = .*|keyring_dir = \"$tree/keyring\"|" \
		-e "s|^stripe_webhook_secret = .*|stripe_webhook_secret = \"$tree/stripe-secret\"|" \
		-e "s|^stripe_api_key = .*|stripe_api_key = \"$tree/stripe-secret\"|" \
		-e "s|^keyring_publish_token = .*|keyring_publish_token = \"$tree/stripe-secret\"|" \
		-e "s|^mail_dir = .*|mail_dir = \"$tree/mail/new\"|" \
		-e "s|^bounce_dir = .*|bounce_dir = \"$tree/bounce/new\"|" \
		-e "s|^resolver = .*|resolver = \"$tree/bin/dig\"|" \
		-e "s|^repquota = .*|repquota = \"$tree/bin/repquota\"|" \
		-e "s|^rates = .*|rates = \"$tree/store/rates/xmr-gbp.json\"|" \
		-e "s|^rates_fetch = .*|rates_fetch = \"$tree/bin/curl\"|" \
		-e "s|^gpg = .*|gpg = \"$tree/bin/gpg\"|" \
		-e "s|^proof_dir = .*|proof_dir = \"$tree/logins\"|" \
		-e "s|^public_root = .*|public_root = \"$tree/home/www\"|" \
		"$config_src"
}

# assert_fixture <dir>: the shape the pass depends on, before anything runs.
assert_fixture() {
	typeset tree=$1 ok=yes
	[ -f "$tree/store/intents/01AAAAAAAAAAAAAAAAAAAAAAAA.json" ] || ok=no
	[ -f "$tree/store/intents/01BBBBBBBBBBBBBBBBBBBBBBBB.json" ] || ok=no
	[ -x "$tree/bin/sendmail" ] || ok=no
	[ -x "$tree/bin/curl" ] || ok=no
	[ -f "$tree/key" ] || ok=no
	[ -d "$tree/store/rates" ] || ok=no
	[ "$(cat "$tree/mail_domains")" = kyriakon.net ] || ok=no
	[ "$ok" = yes ]
}

full_run() {
	[ "$(uname -s)" = OpenBSD ] || missing "the full run needs OpenBSD's unveil(2) and pledge(2); use --self-test"
	[ -x "$drain_bin" ] || missing "no drain binary at $drain_bin; set KYRIAKON_DRAIN_BIN"
	[ -f "$config_src" ] || missing "no drain.toml at $config_src"

	work=$(mktemp -d "${TMPDIR:-/tmp}/verify-drain.XXXXXX") || exit 1
	trap 'rm -rf "$work"' EXIT
	tree=$work/fixture
	mkdir "$tree"
	make_fixture "$tree" || die "could not make the fixture"
	assert_fixture "$tree" || die "the fixture is incomplete"
	config_for "$tree" > "$work/drain.toml"

	# The pass must finish. Its stderr carries the malformed intent's report,
	# which is expected; the exit status is what says unveil and pledge held.
	if ! "$drain_bin" --config "$work/drain.toml" > "$work/out" 2>&1; then
		sed -n 1,40p "$work/out" >&2
		die "the drain failed under unveil and pledge"
	fi

	# The malformed intent is a pass failure the drain mails about: the stub's
	# marker is proof that fork and exec of sendmail survived the pledge.
	grep -q 'the drain failed' "$tree/log/sendmail" ||
		die "no failure notice was enqueued; sendmail was not run"
	# The unknown kind is refused and left where the release that knows it finds it.
	grep -q 'refused' "$tree/store/journal.jsonl" ||
		die "the unknown intent was not journalled as refused"
	[ -f "$tree/store/intents/01BBBBBBBBBBBBBBBBBBBBBBBB.json" ] ||
		die "the refused intent was removed instead of kept"
	# The rate cache was fetched by curl and written by the pass.
	grep -q '409.44' "$tree/store/rates/xmr-gbp.json" ||
		die "the rate cache was not written"

	# A path whose parent does not exist fails at unveil, and the message names
	# the path and the errno text: the operator can fix the config from cron mail.
	sed -e "s|^store_root = .*|store_root = \"$work/no-such-parent/store\"|" \
		"$work/drain.toml" > "$work/bad.toml"
	if "$drain_bin" --config "$work/bad.toml" > "$work/bad-out" 2>&1; then
		die "a missing store root was accepted"
	fi
	grep -q 'unveil' "$work/bad-out" || {
		sed -n 1,10p "$work/bad-out" >&2
		die "the failure does not name unveil"
	}
	grep -q "$work/no-such-parent/store" "$work/bad-out" ||
		die "the failure does not name the path"
	grep -q 'No such file or directory' "$work/bad-out" ||
		die "the failure does not carry the errno text"

	printf '\nverify-drain-sandbox: the drain unveiled, pledged and finished a pass\n'
}

# missing <why> only exists so the full-run guards read as one shape.
missing() {
	die "$*"
}

# --- self-test ---------------------------------------------------------------
#
# The fixture, its stubs and the generated config are what the pass rests on;
# all of them are built with no binary and no unveil here.

self_test() {
	typeset tree conf
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work/fixture
	mkdir "$tree"
	make_fixture "$tree"

	check "the fixture has both intents" \
		"$(find "$tree/store/intents" -name '*.json' | wc -l | tr -d ' ')" 2
	check "the fixture has the box's account list" \
		"$(grep -c '^root:' "$tree/passwd")" 1
	check "the fixture's key is root-only" \
		"$(stat -f '%Lp' "$tree/key")" 600
	check "the fixture's sendmail is executable" \
		"$([ -x "$tree/bin/sendmail" ] && printf yes || printf no)" yes
	check "a complete fixture passes its own check" \
		"$(assert_fixture "$tree" >/dev/null 2>&1 && printf yes || printf no)" yes

	conf=$(config_for "$tree")
	check "the config points the store at the fixture" \
		"$(printf '%s\n' "$conf" | grep -cF "store_root = \"$tree/store\"")" 1
	check "the config points the approval key at the fixture" \
		"$(printf '%s\n' "$conf" | grep -cF "approval_key = \"$tree/key\"")" 1
	check "the config names the fixture's rate client" \
		"$(printf '%s\n' "$conf" | grep -cF "rates_fetch = \"$tree/bin/curl\"")" 1

	# A broken fixture must fail the check rather than the run.
	rm "$tree/bin/sendmail"
	check "a fixture without the enqueuer is refused" \
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
