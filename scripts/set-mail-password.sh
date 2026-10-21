#!/bin/ksh
# set-mail-password.sh — set a member's mail password from a hash the handler made.
#
# Runs as root, from the drain, after the drain has verified the one-time link's
# signature. The password itself is never seen here: the handler hashed it, the
# intent carried the hash, and this writes it onto the system account BSD auth
# checks it against. Dovecot reads the same account, so one write covers IMAP and
# whatever the account page adds later.
#
# Usage:
#   ksh set-mail-password.sh <username> <bcrypt-hash>
#   ksh set-mail-password.sh --self-test
#
# The hash is checked before usermod sees it. `usermod -p` takes any line, and a
# malformed one locks the account instead of failing loudly. The account must
# already exist: this never creates one, and never touches an account without a
# dot in its name (root, _onboard and every daemon account are not members).

# The bcrypt fixtures in the self-test are literals, not expansions: shellcheck
# reads `$2b` as a positional parameter and warns that it will not expand.
# shellcheck disable=SC2016
set -euo pipefail

die() {
	printf 'set-mail-password: %s\n' "$*" >&2
	exit 1
}

# is_member <home>: whether this home is a member's. A Maildir is what
# add-user.sh creates and what Dovecot reads; root, _onboard and every daemon
# account have none, and the name is not the test because a localpart need not
# contain a dot.
is_member() {
	[ -d "$1/Maildir" ]
}

# is_bcrypt <hash>: the shape bcrypt writes, and the one BSD auth reads.
is_bcrypt() {
	case "$1" in
	\$2a\$[0-9][0-9]\$*) return 0 ;;
	\$2b\$[0-9][0-9]\$*) return 0 ;;
	\$2y\$[0-9][0-9]\$*) return 0 ;;
	*) return 1 ;;
	esac
}

self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$(dirname "$0")/lib.sh"
	self_test_begin
	check "a bcrypt hash is accepted" \
		"$(is_bcrypt '$2b$12$abcdefghijklmnopqrstuv' && printf yes || printf no)" yes
	check "the 2a and 2y variants are too" \
		"$(is_bcrypt '$2a$10$abcdefghijklmnopqrstuv' && is_bcrypt '$2y$11$abcdefghijklmnopqrstuv' && printf yes || printf no)" yes
	check "a plaintext is not a hash" "$(is_bcrypt 'correct horse battery' && printf yes || printf no)" no
	check "an empty value is not a hash" "$(is_bcrypt '' && printf yes || printf no)" no
	check "a crypt hash is not bcrypt" "$(is_bcrypt '$6$salt$hash' && printf yes || printf no)" no
	check "a two-digit cost is required" "$(is_bcrypt '$2b$1$abc' && printf yes || printf no)" no
	self_test_end
}

case "${1:-}" in
--self-test) self_test ;;
esac

[ "$#" -eq 2 ] || die "usage: ksh $0 <username> <bcrypt-hash>"
user="$1"
hash="$2"

is_bcrypt "$hash" || die "the second argument is not a bcrypt hash, so it is not written to $user"
id -u "$user" >/dev/null 2>&1 || die "there is no account named $user"
home=$(getent passwd "$user" | cut -d: -f6)
if [ -z "$home" ] || ! is_member "$home"; then
	die "$user has no Maildir, so it is not a member account name; nothing was written"
fi
usermod -p "$hash" "$user"
printf 'set-mail-password: wrote the stored hash for %s\n' "$user"
