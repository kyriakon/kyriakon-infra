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

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

# ensure_maildir_dir <path> <owner> <group>: one Maildir directory in the
# account's shape. install -d follows a final symlink, and the home it descends
# is the account's own: a link planted there would make root chown and chmod the
# target, so refuse one before the install runs.
ensure_maildir_dir() {
	[ -L "$1" ] && {
		printf '%s is a symlink; refusing to install through it\n' "$1" >&2
		exit 1
	}
	install -d -m 0700 -o "$2" -g "$3" "$1"
	chown "$2:$3" "$1"
}

# The guard's own check: a symlink planted at a Maildir entry is refused and its
# target keeps its mode; a plain path is created 0700. Runs as the invoking
# user, so it needs no root.
self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin
	tree=$self_test_work
	mkdir -p "$tree/target" "$tree/Maildir"
	chmod 0755 "$tree/target"
	ln -s "$tree/target" "$tree/Maildir/cur"
	code=0
	( ensure_maildir_dir "$tree/Maildir/cur" "$(id -un)" "$(id -gn)" ) >/dev/null 2>"$tree/err" || code=$?
	check "a symlinked Maildir entry is refused" "$code" 1
	check "and the target keeps its mode" "$(stat -f '%Lp' "$tree/target")" 755
	check "the refusal names the link" \
		"$(grep -c 'is a symlink' "$tree/err")" 1
	code=0
	( ensure_maildir_dir "$tree/Maildir/new" "$(id -un)" "$(id -gn)" ) >/dev/null 2>&1 || code=$?
	check "a plain Maildir entry is created" "$code" 0
	check "at 0700" "$(stat -f '%Lp' "$tree/Maildir/new")" 700
	self_test_end
}

case "${1:-}" in
--self-test) self_test ;;
esac

if [ "$#" -ne 1 ]; then
	printf 'usage: %s <username>\n' "$0" >&2
	exit 2
fi
user="$1"

# Localpart-safe charset: lowercase alnum and a short safe set. Keeps the
# username valid as a filesystem path and keyring filename, and as the
# username.kyriakon.net subdomain label. One rule for every script.
if ! valid_localpart "$user"; then
	printf 'invalid username: %s (lowercase [a-z0-9-], starts and ends alphanumeric, 1-31 chars)\n' "$user" >&2
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
#
# Membership of the members group is what sshd matches to give a member the
# chrooted sftp server and git-shell and nothing more (openbsd/etc/sshd_config).
# deploy-mail.sh creates that group, so a box that has not run it since this was
# written has none, and an account without the membership is still a working mail
# account. Say so rather than failing: mail is the account's first job.
home="/home/$user"
if getent group members >/dev/null 2>&1; then
	useradd -m -d "$home" -s /sbin/nologin -g =uid -G members "$user"
else
	useradd -m -d "$home" -s /sbin/nologin -g =uid "$user"
	printf 'note: no members group, so %s has no sftp or git access yet.\n' "$user" >&2
	printf '  doas ksh scripts/deploy-mail.sh   # creates the group\n' >&2
	printf '  doas usermod -G members %s\n' "$user" >&2
fi

# The Maildir root as well as its subdirectories. Dovecot creates
# dovecot-uidlist and its index files in the root, and install -d creates
# missing parents itself, which would leave a root-owned root behind: the
# account then authenticates, every service reports healthy, and each IMAP
# session fails with "file_dotlock_create ... Permission denied".
for d in "$home/Maildir" "$home/Maildir/cur" "$home/Maildir/new" "$home/Maildir/tmp"; do
	ensure_maildir_dir "$d" "$user" "$user"
done

owner=$(stat -f '%Su' "$home/Maildir")
[ "$owner" = "$user" ] || { printf 'Maildir root owned by %s, not %s\n' "$owner" "$user" >&2; exit 1; }

# The 5 GB allowance the site promises for this account, across mail, web and git.
# Exit 3 means quotas are not on for the mount yet, which is a state rather than a
# failure of provisioning: the account is usable, and its allowance follows when
# scripts/quota-apply.sh --enable has been run. Any other failure is reported and
# the account is still left usable, because delivery does not depend on the quota.
# The status is read from the assignment, not from inside a negated command:
# `if ! out=$(...); then rc=$?; fi` reads the status of the `!`, which is always
# 0, so the 3) arm never ran and the state the comment above calls "not a
# failure" was reported as one, in words identical to a real failed write.
# provision-member.sh reads it the same way.
rc=0
quota_out=$(ksh "$script_dir/quota-apply.sh" "$user" 2>&1) || rc=$?
case $rc in
0) ;;
3) printf 'note: %s\n' "$quota_out" >&2 ;;
*) printf 'warning: the allowance was not set: %s\n' "$quota_out" >&2 ;;
esac

printf 'created %s (shell /sbin/nologin, Maildir %s/Maildir)\n' "$user" "$home"
printf 'next: set password (doas passwd %s) and sync %s.asc into the keyring\n' \
	"$user" "$user"
