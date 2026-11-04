#!/bin/ksh
# kyriakon-authcheck: verify one member's mail password, and write the proof a
# page session is trusted by.
#
# This is the whole of the one `doas` rule the onboarding service needs:
#
#   permit nopass _onboard as root cmd /usr/local/libexec/kyriakon-authcheck
#
# `doas.conf(5)` matches the argument list literally, so a rule naming
# `cmd doveadm args auth test` would refuse the username the check has to pass
# and every login would be denied. The rule therefore authorises this program,
# which takes the username and the proof directory, reads the password from
# stdin so it never appears in `ps`, validates the shape, and runs the one
# doveadm subcommand. There is no way from here to run another.
#
# The handler runs unprivileged and writes `sessions/<id>.json` itself, so that
# record cannot prove a login. On success this script, as root, writes one file
# in the proof directory naming the account and an expiry, and prints the
# file's random token on stdout. The handler stores the token in the session
# record and cannot mint one; the drain reads the file back and trusts only it.
# The directory is root-owned 0700 (scripts/deploy-onboard.sh makes it), so the
# handler can neither write a proof nor replace one.
#
# Installed by scripts/deploy-onboard.sh at /usr/local/libexec/kyriakon-authcheck,
# mode 0755, root-owned.
#
# Usage:
#   kyriakon-authcheck <username> [proof-dir]   # password on stdin
#   ksh kyriakon-authcheck --self-test
#
# Exit: 0 the password is correct and a proof was written; 1 it is not, or the
# proof could not be written; 64 usage or a username shape this platform could
# not have made. The handler treats every non-zero code as a refusal.

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

self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	work=$self_test_work
	check "a member shape passes" \
		"$(valid_localpart 'theophilus.1' && printf yes || printf no)" yes
	check "an uppercase letter is refused" \
		"$(valid_localpart 'Theophilus' && printf yes || printf no)" no
	check "a leading dot is refused" \
		"$(valid_localpart '.theophilus' && printf yes || printf no)" no
	check "a slash is refused" \
		"$(valid_localpart 'theo/philus' && printf yes || printf no)" no
	check "33 characters are refused" \
		"$(valid_localpart 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' && printf yes || printf no)" no

	token=$(mint_proof "$work" 'theophilus.1')
	check "a proof token is 64 lowercase hex characters" \
		"$(printf '%s' "$token" | grep -cE '^[0-9a-f]{64}$')" "1"
	check "the proof names the account" \
		"$(grep -c '"username":"theophilus.1"' "$work/$token")" "1"
	check "the proof carries an expiry" \
		"$(grep -cE '"expires":[0-9]+' "$work/$token")" "1"
	check "the proof is readable only by its owner" \
		"$(stat -f '%Lp' "$work/$token" | sed 's/^0*//')" "600"
	check "a second login mints a different token" \
		"$([ "$(mint_proof "$work" 'theophilus.1')" = "$token" ] && printf same || printf different)" \
		different
	check "a missing directory mints nothing" \
		"$(mint_proof "$work/absent" theophilus.1 >/dev/null 2>&1 && printf yes || printf no)" no
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
user=$1
proof_dir=${2:-$proof_dir_default}
valid_localpart "$user" || die "not a member username: $user"
root_proof_dir "$proof_dir" \
	|| fail "$proof_dir is not the root-owned 0700 login proof directory; run scripts/deploy-onboard.sh"

# The password is read from stdin by doveadm itself, so it is never an argument
# and never written anywhere. A dovecot that cannot answer exits non-zero, which
# the handler reads as a refusal rather than as an admission. Its own output is
# discarded: stdout carries the proof token and nothing else.
/usr/local/bin/doveadm auth test "$user" >/dev/null || exit 1

token=$(mint_proof "$proof_dir" "$user") \
	|| fail "cannot write the login proof in $proof_dir"
printf '%s\n' "$token"
