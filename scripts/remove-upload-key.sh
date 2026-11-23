#!/bin/ksh
# remove-upload-key.sh: take a member's upload key out of their upload session.
#
# Usage:
#   doas ksh remove-upload-key.sh <username>
#        ksh remove-upload-key.sh --self-test
#
# Runs ON the box as root, from the drain, after the member removed their upload
# key on the account page.
#
# One key serves both sessions: the chrooted sftp upload on port 22 and the
# confined git shell on 2222, and sshd reads
# /etc/ssh/authorized_keys/<username> for the members group once the hand
# sshd_config step has landed. The older copy at
# /home/<username>/.ssh/authorized_keys is still removed for a box that has not
# applied that step, and for the transition. Removing both is the whole change.
# Nothing is restarted, because there is nothing holding the old file open, and
# the next session is refused rather than a running one being cut off.
#
# The tree, the published site, the repositories and the mail are left exactly
# where they are. The account page's own words say the same: removing an upload
# key stops sftp and git and nothing else, and adding one back serves what is
# already in the directories.
#
# Not this script's job: removing the key from the store (`keys/<username>.pub`,
# which provision-member.sh reads) or from the account record. Those are the
# drain's, in the same transition that runs this.
#
# Idempotent, and silent when there is nothing to remove: a scheduled job's
# output is mail. The name is checked with the charset add-user.sh uses, and the
# account must exist with a Maildir, so a name that is not a member never turns
# into a path.
#
# Env: HOME_ROOT (default /home) and AUTHORIZED_KEYS_DIR (default
# /etc/ssh/authorized_keys). They exist for the self-test's throwaway tree; the
# drain sets nothing.
#
# Exit: 0 the key is gone or was not there; 1 the file could not be removed;
#       2 the arguments or the account are wrong.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

home_root=${HOME_ROOT:-/home}
keys_root=${AUTHORIZED_KEYS_DIR:-/etc/ssh/authorized_keys}

usage() {
	printf 'usage: doas ksh %s <username>\n' "$0" >&2
	printf '       ksh %s --self-test\n' "$0" >&2
	exit 2
}

die() {
	printf 'remove-upload-key: %s\n' "$*" >&2
	exit 2
}

# The two predicates the self-test replaces: whether the box has the account,
# and whether its home is a member's. Both are checks rather than assumptions
# because the only thing standing between a name and a path here is the name.
account_exists() { id "$1" >/dev/null 2>&1; }
has_maildir() { [ -d "$1/Maildir" ]; }
is_root() { [ "$(id -u)" -eq 0 ]; }

# remove <username>: the whole job, so the self-test drives the same body the
# drain runs.
remove() {
	typeset user home key_file removed=no
	user=$1
	valid_localpart "$user" ||
		die "not a member name: $user (lowercase [a-z0-9-], starts and ends alphanumeric, at most 31 characters)"
	is_root || die "run this with doas: the member's home is not yours to change"
	if ! require_member "$user"; then
		# shellcheck disable=SC2154 # require_member sets member_phase
		die "$user is not a member account (missing $member_phase); nothing was removed"
	fi
	home="${HOME_ROOT:-$home_root}/$user"

	# Both copies, because a box that has not applied the sshd_config hand step
	# reads the home one and a box that has reads the managed one. A symlinked
	# .ssh or key is refused: as root, following one would delete somebody
	# else's authorized_keys (#934).
	[ ! -L "$home/.ssh" ] || die "$home/.ssh is a symlink; nothing was removed"
	for key_file in "$keys_root/$user" "$home/.ssh/authorized_keys"; do
		[ -e "$key_file" ] || continue
		[ ! -L "$key_file" ] || die "$key_file is a symlink; nothing was removed"
		rm -f "$key_file" || {
			printf 'remove-upload-key: could not remove %s\n' "$key_file" >&2
			exit 1
		}
		removed=yes
	done
	[ "$removed" = yes ] || return 0
	printf 'removed the upload key for %s; sftp and git are refused from the next session\n' "$user"
}

self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work
	home_root="$tree/home"
	keys_root="$tree/etc/ssh/authorized_keys"

	# The fixture is a member with one key, and the predicates answer for it so no
	# real account is touched.
	HOME_ROOT="$home_root"
	ONBOARD_STORE="$tree/store"
	mkdir -p "$home_root/alice/Maildir" "$home_root/alice/.ssh" "$keys_root" \
		"$ONBOARD_STORE/accounts/alice"
	: > "$ONBOARD_STORE/accounts/alice/account.json"
	id() {
		case "$1:$2" in
		-u:alice) printf '1001\n' ;;
		*) return 1 ;;
		esac
	}
	account_exists() { [ "$1" = "alice" ]; }
	has_maildir() { [ -d "$1/Maildir" ]; }
	is_root() { return 0; }
	key_file="$home_root/alice/.ssh/authorized_keys"
	managed_key="$keys_root/alice"
	printf 'ssh-ed25519 AAAAexample alice@example\n' >"$key_file"
	printf 'ssh-ed25519 AAAAexample alice@example\n' >"$managed_key"

	set +e
	( remove alice ) >"$tree/first.out" 2>&1
	rc=$?
	set -e
	check "the key is removed" "$rc" 0
	check "and the home copy is gone" "$([ -f "$key_file" ] && printf yes || printf no)" no
	check "and the managed copy is gone" "$([ -f "$managed_key" ] && printf yes || printf no)" no
	check "and the member's Maildir is untouched" \
		"$([ -d "$home_root/alice/Maildir" ] && printf yes || printf no)" yes

	# A second run has nothing to do and says nothing: a drain and a cron job
	# both keep their output.
	set +e
	( remove alice ) >"$tree/second.out" 2>&1
	rc=$?
	set -e
	check "a second run succeeds" "$rc" 0
	check "and prints nothing" "$(wc -c <"$tree/second.out" | tr -d ' ')" 0

	# #934: a member-owned ~/.ssh replaced by a symlink must not lead root to
	# remove a key outside the fixture tree.
	mkdir -p "$tree/elsewhere"
	printf 'ssh-ed25519 AAAAexample victim@example\n' >"$tree/elsewhere/authorized_keys"
	rm -rf "$home_root/alice/.ssh"
	ln -s "$tree/elsewhere" "$home_root/alice/.ssh"
	set +e
	( remove alice ) >"$tree/symlink.out" 2>&1
	rc=$?
	set -e
	check "a symlinked .ssh is refused" "$rc" 2
	check "and the target's key is untouched" \
		"$([ -f "$tree/elsewhere/authorized_keys" ] && printf yes || printf no)" yes
	rm -f "$home_root/alice/.ssh"
	mkdir -p "$home_root/alice/.ssh"

	# A name that is not an account, and a name that is not a member name, both
	# stop before any path is built.
	set +e
	( remove bob ) >"$tree/noaccount.out" 2>&1
	rc=$?
	set -e
	check "an unknown account is refused" "$rc" 2
	set +e
	( remove ../alice ) >"$tree/badname.out" 2>&1
	rc=$?
	set -e
	check "a name outside the charset is refused" "$rc" 2
	check "and the refusal names the shape it wanted" \
		"$(grep -c 'not a member name' "$tree/badname.out")" 1

	self_test_end
}

case "${1:-}" in
--self-test)
	[ "$#" -eq 1 ] || usage
	self_test
	;;
"")
	usage
	;;
-*)
	usage
	;;
*)
	[ "$#" -eq 1 ] || usage
	remove "$1"
	;;
esac
