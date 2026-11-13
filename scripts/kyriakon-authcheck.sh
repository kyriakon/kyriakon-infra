#!/bin/ksh
# kyriakon-authcheck: verify one member's mail password, and write the proof a
# page session is trusted by.
#
# This is the whole of the one `doas` rule the control plane needs:
#
#   permit nopass _onboard as root cmd /usr/local/libexec/kyriakon-authcheck
#
# `doas.conf(5)` matches the argument list literally, so a rule naming
# `cmd doveadm args auth test` would refuse the username the check has to pass
# and every login would be denied. The rule therefore authorises this program,
# which takes the username and the proof directory, reads the password from
# stdin so it never appears in `ps`, refuses a name that is not a member
# account, and runs the one doveadm subcommand. There is no way from here to run
# another.
#
# The handler runs unprivileged and writes `sessions/<id>.json` itself, so that
# record cannot prove a login. On success this script, as root, writes one file
# in the proof directory naming the account and an expiry, and prints the
# file's random token on stdout. The handler stores the token in the session
# record and cannot mint one; the drain reads the file back and trusts only it.
# The directory is root-owned 0700 (scripts/deploy-control.sh makes it), so the
# handler can neither write a proof nor replace one.
#
# Installed by scripts/deploy-control.sh at /usr/local/libexec/kyriakon-authcheck,
# mode 0755, root-owned.
#
# Usage:
#   kyriakon-authcheck <username> [proof-dir]   # password on stdin
#   ksh kyriakon-authcheck --self-test
#
# Exit: 0 the password is correct and a proof was written; 1 it is not,
# including a name with no member account record, or the proof could not be
# written; 64 usage or a username shape this platform could not have made. The
# handler treats every non-zero code as a refusal.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

# The production proof directory, matching `session::PROOF_DIR` and the
# `proof_dir` value in both onboarding configs. The handler may pass another
# only in a test; the drain reads its own configured directory either way.
proof_dir_default=/var/db/kyriakon/logins

# The page session's lifetime, in seconds: `session::TTL_HOURS` is twelve. A
# proof that outlived the session it was minted for would be evidence for
# nothing.
proof_ttl=43200

# The control store, matching the handler's `store_root`. `accounts/` under it
# is root-owned 0750 (scripts/control-store.sh), and the drain writes one
# `account.json` per member account, so the record is the roster of the accounts
# this platform made.
store_root=/var/db/onboard

die() {
	printf 'kyriakon-authcheck: %s\n' "$*" >&2
	exit 64
}

fail() {
	printf 'kyriakon-authcheck: %s\n' "$*" >&2
	exit 1
}

# Whether `dir` is the root-owned 0700 directory the deploy makes. A directory
# the handler could write would let it plant or replace a proof, so the check
# refuses rather than trusting where it was pointed.
root_proof_dir() {
	[ -d "$1" ] || return 1
	[ "$(stat -f '%u' "$1")" -eq 0 ] || return 1
	[ "$(stat -f '%Lp' "$1" | sed 's/^0*//')" = "700" ]
}

# Whether `name` is an account this platform made. Only those have a record at
# `accounts/<name>/account.json` in the control store; root, `_onboard` and the
# other system accounts have none, and neither does a guessed name. This runs
# before doveadm because bsdauth answers for every system account that has a
# password, the operator's own included: without the gate the form verifies the
# operator's system password and sets a session for it.
member_account() {
	[ -f "$store_root/accounts/$1/account.json" ]
}

# authenticate <username>: the one doveadm subcommand. A function so the
# self-test can stand in for it and count the calls, which is what proves a
# refused name never reaches it. The path is a literal, because an environment
# override would let the unprivileged caller run any binary as root.
authenticate() {
	/usr/local/bin/doveadm auth test "$1" >/dev/null
}

# mint_proof <dir> <username> — write one proof and print its token. The token
# is 32 random bytes as hex, so it is a filename this code chooses and not one a
# caller supplies; the file is 0600 under the directory's 0700.
mint_proof() {
	[ -d "$1" ] || return 1
	token=$(openssl rand -hex 32) || return 1
	[ "${#token}" -eq 64 ] || return 1
	expires=$(( $(date +%s) + proof_ttl ))
	(
		umask 077
		printf '{"username":"%s","expires":%s}\n' "$2" "$expires" > "$1/$token"
	) || return 1
	printf '%s\n' "$token"
}

# login_check <username> <proof-dir>: the whole decision, in the order that
# matters. A name the platform could not have made is the usage answer, a name
# with no member account record is the wrong-password answer and never reaches
# doveadm, and only then is the password checked. The password is read from stdin by
# doveadm itself, so it is never an argument and never written anywhere. A
# dovecot that cannot answer exits non-zero, which the handler reads as a
# refusal rather than as an admission. Its own output is discarded: stdout
# carries the proof token and nothing else.
login_check() {
	typeset login_user=$1 login_dir=$2
	valid_localpart "$login_user" || die "not a member username: $login_user"
	member_account "$login_user" || exit 1
	root_proof_dir "$login_dir" \
		|| fail "$login_dir is not the root-owned 0700 login proof directory; run scripts/deploy-control.sh"
	authenticate "$login_user" || exit 1
	token=$(mint_proof "$login_dir" "$login_user") \
		|| fail "cannot write the login proof in $login_dir"
	printf '%s\n' "$token"
}

self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	work=$self_test_work
	check "a member shape passes" \
		"$(valid_localpart 'theophilus-1' && printf yes || printf no)" yes
	check "an uppercase letter is refused" \
		"$(valid_localpart 'Theophilus' && printf yes || printf no)" no
	check "a leading dot is refused" \
		"$(valid_localpart '.theophilus' && printf yes || printf no)" no
	check "a slash is refused" \
		"$(valid_localpart 'theo/philus' && printf yes || printf no)" no
	check "31 characters are accepted" \
		"$(valid_localpart 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' && printf yes || printf no)" yes
	check "32 characters are refused" \
		"$(valid_localpart 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' && printf yes || printf no)" no

	token=$(mint_proof "$work" 'theophilus-1')
	check "a proof token is 64 lowercase hex characters" \
		"$(printf '%s' "$token" | grep -cE '^[0-9a-f]{64}$')" "1"
	check "the proof names the account" \
		"$(grep -c '"username":"theophilus-1"' "$work/$token")" "1"
	check "the proof carries an expiry" \
		"$(grep -cE '"expires":[0-9]+' "$work/$token")" "1"
	check "the proof is readable only by its owner" \
		"$(stat -f '%Lp' "$work/$token" | sed 's/^0*//')" "600"
	check "a second login mints a different token" \
		"$([ "$(mint_proof "$work" 'theophilus-1')" = "$token" ] && printf same || printf different)" \
		different
	check "a missing directory mints nothing" \
		"$(mint_proof "$work/absent" theophilus-1 >/dev/null 2>&1 && printf yes || printf no)" no
	# The runner's own temp directory is 0700 and not root's, which is the
	# misconfiguration this check exists to refuse on the box. A root run's mktemp
	# is root's own, so make one owned by somebody else for that case; `nobody` is
	# uid 32767 on both OpenBSD and macOS.
	foreign=$work
	if [ "$(id -u)" -eq 0 ]; then
		foreign=$work/foreign
		mkdir "$foreign"
		chown 32767 "$foreign"
		chmod 0700 "$foreign"
	fi
	check "a directory not owned by root is refused" \
		"$(root_proof_dir "$foreign" && printf yes || printf no)" no

	# The member gate. The store is the handler's own, so the test builds a
	# fixture with one member record, then runs the whole login path with the
	# proof-directory check and doveadm stood in for. The call count is the
	# assertion that a refused name never reached the password check.
	store_root="$work/store"
	mkdir -p "$store_root/accounts/theophilus-1"
	printf '{"version":1}\n' >"$store_root/accounts/theophilus-1/account.json"
	check "a member account is in the roster" \
		"$(member_account theophilus-1 && printf yes || printf no)" yes

	doveadm_log="$work/doveadm-calls"
	: >"$doveadm_log"
	authenticate() { printf '%s\n' "$1" >>"$doveadm_log"; }
	# The ownership case above ran the real check; the runner's temp dir is not
	# root's, so the test path stands this in.
	root_proof_dir() { return 0; }

	# A system account that passes the shape check gets the wrong-password code,
	# so nothing distinguishes it from a member's wrong password.
	for name in root oliver theophilus-2; do
		status=0
		( login_check "$name" "$work" ) >/dev/null 2>&1 || status=$?
		check "$name is refused as a wrong password" "$status" "1"
	done
	# `_onboard` never passes the shape check, so it stops one step earlier with
	# the usage code; the handler renders the same refusal either way, and the
	# assertion that matters is the doveadm count below.
	status=0
	( login_check _onboard "$work" ) >/dev/null 2>&1 || status=$?
	check "_onboard is refused" "$status" "64"
	check "no refused name reached doveadm" "$(grep -c . "$doveadm_log")" "0"

	token=$(login_check theophilus-1 "$work")
	check "a member account reaches doveadm" \
		"$(grep -c '^theophilus-1$' "$doveadm_log")" "1"
	check "a member account still gets the proof token" \
		"$(printf '%s' "$token" | grep -cE '^[0-9a-f]{64}$')" "1"

	# The other half of "indistinguishable": a member's wrong password is the
	# same exit code as a non-member name.
	authenticate() { printf '%s\n' "$1" >>"$doveadm_log"; return 1; }
	status=0
	( login_check theophilus-1 "$work" ) >/dev/null 2>&1 || status=$?
	check "a member's wrong password gets the same answer" "$status" "1"
	self_test_end
}

case "${1:-}" in
--self-test)
	# The self-test mints in its own temp directory as whoever runs it; only the
	# production path checks the ownership the deploy sets.
	self_test
	exit 0
	;;
esac

[ "$#" -ge 1 ] && [ "$#" -le 2 ] \
	|| die "usage: kyriakon-authcheck <username> [proof-dir] (password on stdin)"
login_check "$1" "${2:-$proof_dir_default}"
