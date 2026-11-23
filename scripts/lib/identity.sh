#!/bin/ksh
# identity.sh: the name and account predicates every script shares. Sourced by
# scripts/lib.sh.

# valid_localpart <name> — the username and mailbox charset: 1-31 lowercase
# letters, digits and interior hyphens, starting and ending alphanumeric: a
# single DNS label. It is a filesystem path component, a subdomain label and a
# keyring filename, so every script that takes a member name checks it here.
# The case guard runs first: grep matches any line of its input, so without it a
# valid first line would carry an arbitrary second one through.
valid_localpart() {
	case "$1" in '' | *[!a-z0-9-]*) return 1 ;; esac
	printf '%s' "$1" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,29}[a-z0-9])?$'
}

# valid_domain <name> — a lowercase FQDN: labels of letters, digits and hyphens,
# at least two labels, no label starting or ending with a hyphen, at most 253
# characters. It is the stem of generated file names, a server name and a path
# component, so a newline anywhere in it is refused outright rather than left to
# a line-oriented grep.
valid_domain() {
	case "$1" in '' | *[!a-z0-9.-]*) return 1 ;; esac
	[ "${#1}" -le 253 ] || return 1
	printf '%s' "$1" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
}

# require_member <user> — true only for a provisioned member account: an OS
# account with uid > 0, a Maildir under its home, an account.json in the store,
# and a $home/.ssh that is not a symlink. Sets member_phase to the first phase
# that failed, so the caller can say why rather than guessing. HOME_ROOT and
# ONBOARD_STORE rebind the tree for a self-test.
#
# The charset check is the caller's first guard; this is the one that tells a
# member from the operator's account or root, which also passes the charset.
require_member() {
	typeset member_user="$1" member_home member_uid
	member_home="${HOME_ROOT:-/home}/$member_user"
	member_phase=account
	# shellcheck disable=SC2034 # the caller reads it
	export member_phase
	member_uid=$(id -u "$member_user" 2>/dev/null) || return 1
	case "$member_uid" in '' | *[!0-9]*) return 1 ;; esac
	[ "$member_uid" -gt 0 ] || return 1
	member_phase=maildir
	[ -d "$member_home/Maildir" ] || return 1
	member_phase=record
	[ -r "${ONBOARD_STORE:-/var/db/onboard}/accounts/$member_user/account.json" ] || return 1
	member_phase=ssh
	[ ! -L "$member_home/.ssh" ] || return 1
	member_phase=ok
	return 0
}
