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
#   key, stripe-secret, passwd, reserved
#   etc/mail/{mail_domains,virtuals,mail_from,dkim_domains,spamd.alloweddomains}
#   etc/mail/mail_domains.lock      the empty flock file the writer creates
#   logins/, keyring/, mail/new/, bounce/new/, home/www/, store/rates/
#
# The tree is made outside the process's temp directory: restrict unveils /tmp
# with rwc, so a fixture under it would resolve every path and a missing unveil
# entry would pass. The tables have a directory of their own for the same
# reason, because restrict unveils the tables' parent.
#
# Two applications are approved through the console, with the same key the
# drain verifies: one person's, and one body's. The body's approval takes the
# group path, so the pass writes mail_domains, and that write is what opens the
# kernel lock beside the table.
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
admin_bin=${KYRIAKON_ADMIN_BIN:-$repo/control/target/release/kyriakon-admin}
config_src=$repo/openbsd/etc/onboard/drain.toml
# The member key the fixture's application carries: the throwaway public key
# the export tests use. It carries an encryption subkey, which is what the
# approval insists on, and it has no private half anywhere. It is extracted from
# the Rust source so the suite holds one copy of it.
key_src=$repo/control/crates/tests/tests/areas/export.rs
# The application's status token: 26 Crockford characters, the shape
# Store::is_status_token accepts.
status_token=01arz3ndektsv4rrffq69g5fav
# The body's application token, the same shape and a different value.
body_token=01arz3ndektsv4rrffq69g5fax

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

# fail <why>: the pass's own output and the journal, then exit. A failed
# assertion in CI is otherwise one line with no state to read.
fail() {
	if [ -n "${work:-}" ] && [ -f "$work/out" ]; then
		printf -- '--- drain output\n' >&2
		sed -n 1,40p "$work/out" >&2
	fi
	if [ -n "${tree:-}" ] && [ -f "$tree/store/journal.jsonl" ]; then
		printf -- '--- journal\n' >&2
		tail -n 10 "$tree/store/journal.jsonl" >&2
	fi
	die "$*"
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
		"$tree/store/sessions" \
		"$tree/store/rates" "$tree/store/drafts" "$tree/store/applications" \
		"$tree/logins" "$tree/keyring" "$tree/mail/new" "$tree/mail/cur" \
		"$tree/bounce/new" "$tree/home/www" "$tree/bin" "$tree/log" \
		"$tree/etc/mail" || return 1

	# The two keys: root-only 0600, which sign::read_key insists on.
	printf 'unveil-fixture-approval-key\n' > "$tree/key"
	printf 'unveil-fixture-stripe-secret\n' > "$tree/stripe-secret"
	chmod 600 "$tree/key" "$tree/stripe-secret"

	# The account list and the reserved names the approval checks.
	printf 'root:*:0:0::0:0:Charlie &:/root:/bin/ksh\n' > "$tree/passwd"
	printf 'admin\nroot\n' > "$tree/reserved"

	# The five mail tables, in their shipped shape: one domain, one alias. They
	# live in a directory of their own because restrict unveils the tables'
	# parent, and a fixture that put them at the tree root would lay the whole
	# fixture under that rule and hide a missing unveil entry.
	printf 'kyriakon.net\n' > "$tree/etc/mail/mail_domains"
	printf 'postmaster: root\n' > "$tree/etc/mail/virtuals"
	printf 'root: root@kyriakon.net\n' > "$tree/etc/mail/mail_from"
	printf 'kyriakon.net\n' > "$tree/etc/mail/dkim_domains"
	printf '@kyriakon.net\n' > "$tree/etc/mail/spamd.alloweddomains"

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
	# Every privileged script the approval runs, the group's reload lanes
	# included. Each records its own name, which is what proves the drain exec'd
	# it under the pledge.
	typeset name
	for name in add-user.sh provision-member.sh publish-mail-key.sh cron-apply.sh \
		reload-smtpd.sh reload-spamd.sh; do
		stub "$tree/bin/$name" \
			"printf '%s %s\\n' \"\$0\" \"\$*\" >> '$tree/log/scripts'"
	done
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
		-e "s|^mail_domains = .*|mail_domains = \"$tree/etc/mail/mail_domains\"|" \
		-e "s|^virtuals = .*|virtuals = \"$tree/etc/mail/virtuals\"|" \
		-e "s|^mail_from = .*|mail_from = \"$tree/etc/mail/mail_from\"|" \
		-e "s|^dkim_domains = .*|dkim_domains = \"$tree/etc/mail/dkim_domains\"|" \
		-e "s|^spamd_alloweddomains = .*|spamd_alloweddomains = \"$tree/etc/mail/spamd.alloweddomains\"|" \
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
		-e "s|^ipv4 = .*|ipv4 = \"192.0.2.10\"|" \
		-e "s|^ipv6 = .*|ipv6 = \"2001:db8::10\"|" \
		-e "s|^dkim_selector = .*|dkim_selector = \"mail\"|" \
		-e "s|^dkim_public_key = .*|dkim_public_key = \"v=DKIM1; k=rsa; p=example\"|" \
		-e "s|^postal_address = .*|postal_address = \"1 Example Street, Example\"|" \
		"$config_src"
}

# extract_member_key <out>: the public key block the export tests carry, with
# the Rust string quoting and continuations removed. The approval re-inspects
# the material, so a real frame with a subkey is what lets that check run.
extract_member_key() {
	awk '
		/BEGIN PGP PUBLIC KEY BLOCK/ { started = 1 }
		started {
			line = $0
			sub(/^.*BEGIN PGP PUBLIC KEY BLOCK-----/, "-----BEGIN PGP PUBLIC KEY BLOCK-----", line)
			gsub(/\\n/, "\n", line)
			gsub(/\\/, "", line)
			print line
			if (line ~ /END PGP PUBLIC KEY BLOCK-----/) exit
		}
	' "$key_src" | sed '/^[[:space:]]*$/d' > "$1"
}

# file_approval <tree> <key>: the handler-shaped application the console's
# decision needs, filed in applications/ under its own token. Every field the
# approval reads is here, and there is no outside address, so the confirmation
# letter has nowhere to go and the pass does not depend on it.
file_approval() {
	typeset tree=$1 key=$2
	mkdir -p "$tree/store/applications"
	jq -n --arg token "$status_token" --arg key "$(cat "$key")" '{
		username: "alice",
		status_token: $token,
		filed_at: "2026-11-01T09:00:00Z",
		front_end: "web",
		stage: "received",
		answers: {},
		mail_keys: [{mailbox: "", fingerprint: "", material: $key, verdict: "works"}],
		upload_key: {mailbox: "", fingerprint: "SHA256:fixture", material: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample alice@example", verdict: "unchecked"},
		rail: "",
		no_charge: true,
		# The applicant asked us to start now, so the approval supplies the
		# account at once. Without this the fourteen-day hold leaves the
		# keyring empty until its sweep, which is not what this pass checks.
		acceptances: [{"document": "immediate supply and the digital-content acknowledgement", "version": "fixture"}],
		question_list: "fixture"
	}' > "$tree/store/applications/$status_token.json"
}

# file_body_approval <tree> <key>: a community body's application, so the
# console's free approval takes the group path and the drain writes the mail
# tables on its way. One mailbox, which owns the site; no outside address and an
# empty upload key, so the pass makes no hosting lanes and depends on no
# external mail address.
file_body_approval() {
	typeset tree=$1 key=$2
	mkdir -p "$tree/store/applications"
	jq -n --arg token "$body_token" --arg key "$(cat "$key")" '{
		username: "warden",
		status_token: $token,
		filed_at: "2026-11-01T09:00:00Z",
		front_end: "web",
		stage: "received",
		domain: "parish.example",
		outside_address: null,
		answers: {
			whose: "body",
			body_name: "Parish of Example",
			body_kind: "parish",
			body_domain: "parish.example",
			body_records: "yes",
			body_addresses: "secretary: own",
			body_account_names: "parish-secretary"
		},
		mail_keys: [{mailbox: "parish-secretary", fingerprint: "1111 2222 3333 4444", material: $key, verdict: "works"}],
		upload_key: {mailbox: "", fingerprint: "", material: "", verdict: "unchecked"},
		rail: "cash",
		no_charge: true,
		acceptances: [{"document": "terms", "version": "fixture"}],
		question_list: "fixture"
	}' > "$tree/store/applications/$body_token.json"
}

# file_export <tree>: a proved session and the intent the account page files.
# The proof is the root-written file the drain checks, with a real 64 hex name
# and a live expiry, and the intent's id sorts after the console's ULID so the
# second pass reads it after the account exists.
file_export() {
	typeset tree=$1 session proof
	session=01arz3ndektsv4rrffq69g5faw
	proof=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	printf '{"username":"alice","expires":%s}\n' "$(( $(date +%s) + 3600 ))" \
		> "$tree/logins/$proof"
	printf '{"created_at":"2026-11-01T09:00:00Z","proof":"%s"}\n' "$proof" > "$tree/store/sessions/$session.json"
	printf '{"id":"09ZZZZZZZZZZZZZZZZZZZZZZZZ","kind":"export","filed_at":"2026-11-01T09:05:00Z","username":"alice","session":"%s"}\n' \
		"$session" > "$tree/store/intents/09ZZZZZZZZZZZZZZZZZZZZZZZZ.json"
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
	[ "$(cat "$tree/etc/mail/mail_domains")" = kyriakon.net ] || ok=no
	[ "$ok" = yes ]
}

full_run() {
	[ "$(uname -s)" = OpenBSD ] || missing "the full run needs OpenBSD's unveil(2) and pledge(2); use --self-test"
	[ -x "$drain_bin" ] || missing "no drain binary at $drain_bin; set KYRIAKON_DRAIN_BIN"
	[ -f "$config_src" ] || missing "no drain.toml at $config_src"

	# Outside the process's temp directory on purpose: restrict unveils /tmp
	# with rwc, so a fixture under it would resolve every path whatever the
	# unveil list named and a missing entry would still exit 0.
	work=$(mktemp -d /var/db/kyriakon-verify.XXXXXX) || exit 1
	trap 'rm -rf "$work"' EXIT
	tree=$work/fixture
	mkdir "$tree"
	make_fixture "$tree" || die "could not make the fixture"
	assert_fixture "$tree" || die "the fixture is incomplete"
	config_for "$tree" > "$work/drain.toml"

	[ -x "$admin_bin" ] ||
		missing "no console at $admin_bin; set KYRIAKON_ADMIN_BIN"
	[ -f "$key_src" ] || missing "no test key source at $key_src"
	command -v jq >/dev/null 2>&1 || missing "jq is needed to write the fixture's application"
	extract_member_key "$work/member-key.asc"
	grep -q '^-----BEGIN PGP PUBLIC KEY BLOCK-----$' "$work/member-key.asc" ||
		die "could not extract the test key"

	# The console signs an approval of the fixture's application with the same
	# key the drain verifies, so the pass below carries a real root verb.
	file_approval "$tree" "$work/member-key.asc"
	if ! "$admin_bin" --config "$work/drain.toml" approve-free alice "$status_token" \
		> "$work/admin-out" 2>&1; then
		sed -n 1,20p "$work/admin-out" >&2
		die "the console could not sign the fixture's decision"
	fi
	# The body's free approval takes the group path, and the drain's own
	# provision-group transition writes mail_domains. That is the table write
	# the stale lock below is reaped by.
	file_body_approval "$tree" "$work/member-key.asc"
	if ! "$admin_bin" --config "$work/drain.toml" approve-free warden "$body_token" \
		> "$work/admin-body-out" 2>&1; then
		sed -n 1,20p "$work/admin-body-out" >&2
		die "the console could not sign the fixture's body decision"
	fi

	# The pass must finish. Its stderr carries the malformed intent's report,
	# which is expected; the exit status is what says unveil and pledge held.
	if ! "$drain_bin" --config "$work/drain.toml" > "$work/out" 2>&1; then
		sed -n 1,40p "$work/out" >&2
		fail "the drain failed under unveil and pledge"
	fi

	# The approval reached the store, the keyring and the privileged scripts:
	# account_on_box read /etc/passwd, name_allowed read the reserved names, and
	# the four scripts ran by execve under the pledge.
	[ -f "$tree/store/accounts/alice/account.json" ] ||
		fail "the approval wrote no account record"
	grep -q '"no_charge": true' "$tree/store/accounts/alice/account.json" ||
		fail "the approval did not record the free decision"
	[ -f "$tree/keyring/alice.asc" ] ||
		fail "the approval did not write the member's key into the keyring"
	# The body's approval took the group path and wrote the mail tables on the
	# way. That write also proves the kernel lock beside the table opens under
	# the veil: a refused open aborts the approval.
	[ -f "$tree/store/groups/parish.example/group.json" ] ||
		fail "the body approval wrote no group record"
	[ -f "$tree/store/accounts/parish-secretary/account.json" ] ||
		fail "the body approval wrote no mailbox account"
	[ -f "$tree/keyring/parish-secretary.asc" ] ||
		fail "the body approval did not write the mailbox key into the keyring"
	grep -qx 'parish.example' "$tree/etc/mail/mail_domains" ||
		fail "the body approval did not add its domain to mail_domains"
	[ -f "$tree/etc/mail/mail_domains.lock" ] ||
		fail "the table writer left no kernel lock file"
	for script in add-user.sh provision-member.sh publish-mail-key.sh; do
		grep -q "$script" "$tree/log/scripts" ||
			fail "the approval did not run $script"
	done
	grep -q '"outcome":"applied"' "$tree/store/journal.jsonl" ||
		fail "the approval was not journalled as applied"
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

	# A second pass, with the member now on the box and a proved session, carries
	# the export: public_root is written and every file is chowned.
	printf 'alice:*:1001:1001::0:0:Alice:/nonexistent:/sbin/nologin\n' >> "$tree/passwd"
	mkdir -p "$tree/home/www/alice.kyriakon.net"
	file_export "$tree"
	if ! "$drain_bin" --config "$work/drain.toml" > "$work/export-out" 2>&1; then
		sed -n 1,40p "$work/export-out" >&2
		fail "the drain failed on the export pass"
	fi
	# A file list rather than `find -quit`: OpenBSD's find has no `-quit`, and
	# grep exiting early would make the pipeline a SIGPIPE under pipefail.
	find "$tree/home/www/alice.kyriakon.net/export" -type f > "$work/export-files" 2>/dev/null
	[ -s "$work/export-files" ] || fail "the export wrote no bundle under public_root"

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
