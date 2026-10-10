#!/bin/ksh
# onboard-store.sh: create the onboarding service's store and install the two
# files the three front-ends share.
#
# Usage: doas ksh scripts/onboard-store.sh
#
# Run from the repository, in place, like the other scripts here. Every step is
# install(1), so a second run changes nothing and a store left half-built by an
# interrupted first run is completed rather than refused. Because install(1)
# also leaves an existing path alone, each step is followed by an assertion of
# owner, group and mode: a store from an earlier run with the wrong mode would
# pass the installs silently, and this script exists so that a half-built state
# cannot report success.
#
# The split is the spec's. The unprivileged `_onboard` user writes exactly four
# directories, intents/ (one JSON per submission, written by rename), drafts/
# (the capsule and TUI's server-side state), applications/ (the record the status
# page renders) and webhooks/ (a webhook's raw body and signature header). It
# also owns mail/, the Maildir the smtpd action for apply@ delivers into as that
# user. The rest belongs to the root drain: accounts, groups, tokens, ledger,
# rates and journal.jsonl. `/etc/kyriakon/onboard/` is the drain's own root-only
# home for Stripe's signing secret and the keyring publish token; it is not under
# the store root, which is why it is created here too.
#
# The `_onboard` user is created by hand, never by this script: it is a
# reserved-uid account in the shape `_gmid` has, and useradd is an operator step.
# This script only checks for it, and names the exact line when it is missing.
#
# The four writable directories are 0700, owner `_onboard`: tighter than the
# capsule spec's own rc_pre and much tighter than a bare `install -d` would leave
# them (0755). They hold a stranger's own words, their public keys, their outside
# address and the privilege boundary's payloads, and no other local user, member
# or not, has any reason to read any of them.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_dir=$(cd "$script_dir/.." && pwd)

if [ "$#" -ne 0 ]; then
	printf 'usage: doas ksh %s\n' "$0" >&2
	exit 2
fi

store='/var/db/onboard'
drain_conf='/etc/kyriakon/onboard'
onboard_user='_onboard'

# The reserved set is a repository file, read at the store's top so the handler
# and the TUI can both read it. The question list is the service workstream's and
# is installed beside it, 0644, for the same reason.
reserved_src="$repo_dir/reserved-usernames.txt"
questions_src="$repo_dir/openbsd/etc/onboard/questions.tsv"

# fail <message>: one place for the error shape, so every refusal reads the same.
fail() {
	printf 'onboard-store: %s\n' "$1" >&2
	exit 1
}

# assert_mode <path> <owner> <group> <octal-mode>: the post-condition check.
# %Lp prints the permission bits in octal without a leading zero, the same form
# the mode arguments above are written in.
assert_mode() {
	got=$(stat -f '%Su %Sg %Lp' "$1")
	[ "$got" = "$2 $3 $4" ] ||
		fail "$1 is \"$got\", expected \"$2 $3 $4\""
}

# store_dir <name> <owner> <group> <mode>: create one directory under the store
# and assert it at once, so the assertion cannot be forgotten for a later entry.
store_dir() {
	install -d -m "$4" -o "$2" -g "$3" "$store/$1"
	assert_mode "$store/$1" "$2" "$3" "$4"
}

# The account is the one thing here this script will not create. Print the line
# rather than a description of it: the account is a reserved-uid one in the same
# shape `_gmid` has, with a number reserved at build time beside `_gmid`'s own.
# 900 sits above the highest reserved account on the box, which is gmid's 878, and
# below the range a person's account starts at, so the two families stay apart. It
# is written down rather than chosen per box, because the same account has to come
# back from a restored snapshot with the same number.
if ! id "$onboard_user" >/dev/null 2>&1; then
	cat >&2 <<EOF
onboard-store: the $onboard_user user does not exist.

Create it by hand, once, as a reserved-uid account in the shape _gmid has
(numeric uid and gid reserved for it, home /var/empty, shell /sbin/nologin, no
group memberships beyond its own, no doas rule), then run this script again:

useradd -d /var/empty -c "Kyriakon onboarding handler" -s /sbin/nologin -u 900 -g =uid $onboard_user
EOF
	exit 1
fi

# The store root, then the four the handler writes, the mail spool, and the
# root-owned rest.
install -d -m 0755 -o root -g wheel "$store"
assert_mode "$store" root wheel 755
store_dir intents      "$onboard_user" "$onboard_user" 700
store_dir webhooks     "$onboard_user" "$onboard_user" 700
store_dir drafts       "$onboard_user" "$onboard_user" 700
store_dir applications "$onboard_user" "$onboard_user" 700
store_dir accounts     root wheel 750
store_dir groups       root wheel 750
store_dir tokens       root wheel 750
store_dir ledger       root wheel 750
store_dir rates        root wheel 750

# mail/ is _onboard's, not the root drain's, and with the Maildir's three
# subdirectories. The smtpd action for apply@ runs the delivery as _onboard
# (`user _onboard`), so the account has to be able to write here, and the drain
# reads it as root, which can read anything. The capsule spec's own rc_pre gives
# the same ownership, which is what makes the mail route work.
store_dir mail         "$onboard_user" "$onboard_user" 700
store_dir mail/cur     "$onboard_user" "$onboard_user" 700
store_dir mail/new     "$onboard_user" "$onboard_user" 700
store_dir mail/tmp     "$onboard_user" "$onboard_user" 700

# The drain's own configuration, outside the store and root-only.
install -d -m 0700 -o root -g wheel "$drain_conf"
assert_mode "$drain_conf" root wheel 700

# The two shared files, at the top of the store, 0644, readable by the handler
# and the TUI both. The question list is checked for readability before it is
# installed, so a missing sibling file fails here rather than at first request.
for src in "$reserved_src" "$questions_src"; do
	[ -r "$src" ] || fail "cannot read $src"
done
install -m 0644 -o root -g wheel "$reserved_src" "$store/reserved-usernames.txt"
install -m 0644 -o root -g wheel "$questions_src" "$store/questions.tsv"
assert_mode "$store/reserved-usernames.txt" root wheel 644
assert_mode "$store/questions.tsv" root wheel 644
[ -s "$store/questions.tsv" ] || fail "$store/questions.tsv is empty"

printf 'store ready: %s (four dirs and mail/ writable by %s, the rest root), %s 0700 root\n' \
	"$store" "$onboard_user" "$drain_conf"
