#!/bin/ksh
# kyriakon-authcheck: verify one member's mail password, and nothing else.
#
# This is the whole of the one `doas` rule the onboarding service needs:
#
#   permit nopass _onboard as root cmd /usr/local/libexec/kyriakon-authcheck
#
# `doas.conf(5)` matches the argument list literally, so a rule naming
# `cmd doveadm args auth test` would refuse the username the check has to pass
# and every login would be denied. The rule therefore authorises this program,
# which takes exactly one argument (the username), reads the password from stdin
# so it never appears in `ps`, validates the shape, and runs the one doveadm
# subcommand. There is no way from here to run another.
#
# Installed by scripts/deploy-onboard.sh at /usr/local/libexec/kyriakon-authcheck,
# mode 0755, root-owned.
#
# Usage:
#   kyriakon-authcheck <username>      # password on stdin
#   ksh kyriakon-authcheck --self-test
#
# Exit: 0 the password is correct; 1 it is not; 64 usage or a username shape
# this platform could not have made. The handler treats every non-zero code as a
# refusal.

set -euo pipefail

die() {
	printf 'kyriakon-authcheck: %s\n' "$*" >&2
	exit 64
}

# The username charset scripts/add-user.sh enforces: lowercase letters, digits,
# dot, underscore and hyphen, starting with a letter or a digit, at most 32.
# Anything else is not a member and is refused before doveadm sees it.
valid_username() {
	case "$1" in
	'' | [!a-z0-9]* | *[!a-z0-9._-]*) return 1 ;;
	esac
	[ "${#1}" -le 32 ]
}

self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$(dirname "$0")/lib.sh"
	self_test_begin
	check "a member shape passes" \
		"$(valid_username 'theophilus.1' && printf yes || printf no)" yes
	check "an uppercase letter is refused" \
		"$(valid_username 'Theophilus' && printf yes || printf no)" no
	check "a leading dot is refused" \
		"$(valid_username '.theophilus' && printf yes || printf no)" no
	check "a slash is refused" \
		"$(valid_username 'theo/philus' && printf yes || printf no)" no
	check "33 characters are refused" \
		"$(valid_username 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' && printf yes || printf no)" no
	self_test_end
}

case "${1:-}" in
--self-test)
	self_test
	exit 0
	;;
esac

[ "$#" -eq 1 ] || die "usage: kyriakon-authcheck <username> (password on stdin)"
user=$1
valid_username "$user" || die "not a member username: $user"

# The password is read from stdin by doveadm itself, so it is never an argument
# and never written anywhere. A dovecot that cannot answer exits non-zero, which
# the handler reads as a refusal rather than as an admission.
exec /usr/local/bin/doveadm auth test "$user"
