#!/bin/ksh
# add-user.sh — create a shell-less mail account with a Maildir home.
#
# Usage: doas ./add-user.sh <username>
#
# Creates the OS account (shell forced to /sbin/nologin — no interactive
# session, the platform's core safety property) and an empty Maildir under its
# home. PAM auth against this account works regardless of the nologin shell.
#
# The account starts disabled (useradd default with no -p): the operator sets
# the password separately (doas passwd <username>) or passes -p with an
# encrypt(1) hash — never a plaintext password.
#
# The user's PGP public key is NOT touched here; it is synced into the keyring
# (/etc/kyriakon/keys/<localpart>.asc) from the git-tracked published set.
# Until that key exists, delivery to the account fails closed (see
# kyriakon-encrypt).

set -euo pipefail

if [ "$#" -ne 1 ]; then
	printf 'usage: %s <username>\n' "$0" >&2
	exit 2
fi
user="$1"

# Localpart-safe charset: lowercase alnum and a short safe set. Keeps the
# username valid as a filesystem path and keyring filename, and as the
# username.kyriakon.net subdomain label.
if ! printf '%s' "$user" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'; then
	printf 'invalid username: %s (lowercase [a-z0-9._-], <=32 chars)\n' "$user" >&2
	exit 1
fi

if id "$user" >/dev/null 2>&1; then
	printf 'user %s already exists\n' "$user" >&2
	exit 1
fi

# -m creates the home; -d sets it explicitly (OpenBSD userinfo has no home-dir
# flag, and base has no getent — so pin the path rather than look it up).
# -s forces nologin; -g =uid gives a fresh matching uid/gid (one OS user per
# person — clean per-user isolation for Maildir and git).
home="/home/$user"
useradd -m -d "$home" -s /sbin/nologin -g =uid "$user"

install -d -m 0700 -o "$user" -g "$user" \
	"$home/Maildir/cur" "$home/Maildir/new" "$home/Maildir/tmp"

printf 'created %s (shell /sbin/nologin, Maildir %s/Maildir)\n' "$user" "$home"
printf 'next: set password (doas passwd %s) and sync %s.asc into the keyring\n' \
	"$user" "$user"
