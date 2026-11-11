#!/bin/ksh
# control-store.sh: create the control plane's store and install the two
# files the front-ends share.
#
# Usage: doas ksh scripts/control-store.sh
#
# Run from the repository, in place, like the other scripts here. Every step is
# install(1), so a second run changes nothing and a store left half-built by an
# interrupted first run is completed rather than refused. Because install(1)
# also leaves an existing path alone, each step is followed by an assertion of
# owner, group and mode: a store from an earlier run with the wrong mode would
# pass the installs silently, and this script exists so that a half-built state
# cannot report success.
#
# A run that changes nothing prints nothing: every step records whether it had
# to do anything, and only a run that did prints the summary. The deploy calls
# this on every run, and a store already in place should not report work it did
# not do.
#
# The split is the spec's. The unprivileged `_onboard` user writes exactly five
# directories, intents/ (one JSON per submission, written by rename), drafts/
# (the capsule and TUI's server-side state), applications/ (the record the status
# page renders), sessions/ (one file per live account-page login) and webhooks/
# (a webhook's raw body and signature header). It also owns mail/, the Maildir
# the smtpd action for apply@ delivers into as that user. The rest belongs to the
# root drain: accounts, groups, tokens, keys (the members' public upload keys,
# which the builder reads), holds (a closed member's name, kept ninety days),
# ledger, rates and journal.jsonl.
#
# accounts/ and groups/ are root:_onboard 0750, and the records the drain writes
# in them are 0640. The handler renders the account page from those records and
# runs as _onboard, so a root:wheel 0750 directory would make every page read as
# missing; the group lets it read without letting it write.
# `/etc/kyriakon/onboard/` is the drain's own root-only home for Stripe's
# signing secret and the keyring publish token; it is not under the store root,
# which is why it is created here too.
#
# The `_onboard` user is created by hand, never by this script: it is a
# reserved-uid account in the shape `_gmid` has, and useradd is an operator step.
# This script only checks for it, and names the exact line when it is missing.
#
# The writable directories are 0700, owner `_onboard`: tighter than the capsule
# spec's own rc_pre and much tighter than a bare `install -d` would leave them
# (0755). They hold a stranger's own words, their public keys, their outside
# address, live sessions and the privilege boundary's payloads, and no other
# local user, member or not, has any reason to read any of them.

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
# and the TUI can both read it. The service catalogue is the service workstream's
# and is installed beside it, 0644, for the same reason: one file read by every
# front-end, and no copy of it anywhere else. The question list is not here: the
# crate carries it, so there is nothing to install and nothing to keep in step
# with a rebuild.
reserved_src="$repo_dir/reserved-usernames.txt"
catalogue_src="$repo_dir/openbsd/etc/onboard/catalogue.toml"

# fail <message>: one place for the error shape, so every refusal reads the same.
fail() {
	printf 'control-store: %s\n' "$1" >&2
	exit 1
}

# Whether this run has changed anything on the box. Every step that installs,
# creates or removes records it, and the summary is printed only when one did:
# the deploy runs this every time, and a run with nothing to do says nothing.
changed=0

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
	# A missing directory, or one with the wrong owner, group or mode, is what
	# this run is for; one already right changes nothing.
	[ "$(stat -f '%Su %Sg %Lp' "$store/$1" 2>/dev/null)" = "$2 $3 $4" ] || changed=1
	install -d -m "$4" -o "$2" -g "$3" "$store/$1"
	assert_mode "$store/$1" "$2" "$3" "$4"
}

# install_file <source> <installed> <owner> <group> <mode>: install one shared
# file and assert it, recording whether its contents, its owner or its mode
# changed. The comparison is the file's bytes, because these are data files read
# by every front-end and a byte that differs is a rendering that differs, and the
# mode beside it for the same reason the directories are compared: a run that
# repaired one has changed something and should say so.
install_file() {
	[ "$(stat -f '%Su %Sg %Lp' "$2" 2>/dev/null)" = "$3 $4 $5" ] || changed=1
	cmp -s "$1" "$2" 2>/dev/null || changed=1
	install -m "$5" -o "$3" -g "$4" "$1" "$2"
	assert_mode "$2" "$3" "$4" "$5"
}

# remove_legacy <path>: a copy an older layout leaves behind is removed rather
# than left. An unused copy of a shared file is one a person edits by mistake,
# and nothing reads it.
remove_legacy() {
	[ -e "$1" ] || return 0
	rm -f "$1"
	changed=1
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
control-store: the $onboard_user user does not exist.

Create it by hand, once, as a reserved-uid account in the shape _gmid has
(numeric uid and gid reserved for it, home /var/empty, shell /sbin/nologin, no
group memberships beyond its own, no doas rule), then run this script again:

useradd -d /var/empty -c "Kyriakon handler" -s /sbin/nologin -u 900 -g =uid $onboard_user
EOF
	exit 1
fi

# The store root, then the four the handler writes, the mail spool, and the
# root-owned rest.
[ "$(stat -f '%Su %Sg %Lp' "$store" 2>/dev/null)" = "root wheel 755" ] || changed=1
install -d -m 0755 -o root -g wheel "$store"
assert_mode "$store" root wheel 755
store_dir intents      "$onboard_user" "$onboard_user" 700
store_dir webhooks     "$onboard_user" "$onboard_user" 700
store_dir drafts       "$onboard_user" "$onboard_user" 700
store_dir applications "$onboard_user" "$onboard_user" 700
store_dir sessions     "$onboard_user" "$onboard_user" 700
store_dir accounts     root "$onboard_user" 750
store_dir groups       root "$onboard_user" 750
store_dir tokens       root wheel 750
store_dir keys         root wheel 750
store_dir holds        root wheel 750
store_dir ledger       root wheel 750
store_dir rates        root wheel 750

# The records the handler renders are readable by its group, and an upgrade
# must repair the ones an earlier release wrote 0600 root. Only these three are
# shared: account.json and group.json are what the account page reads, and
# notices.jsonl is the notice list on it. journal.jsonl and requests.jsonl stay
# root-only, because nothing outside the drain reads them.
share_record() {
	[ -e "$1" ] || return 0
	if [ "$(stat -f '%Su %Sg %Lp' "$1")" != "root $onboard_user 640" ]; then
		changed=1
		chown root:"$onboard_user" "$1"
		chmod 0640 "$1"
	fi
}
for account in "$store"/accounts/*; do
	[ -d "$account" ] || continue
	share_record "$account/account.json"
	share_record "$account/notices.jsonl"
done
for group in "$store"/groups/*; do
	[ -d "$group" ] || continue
	share_record "$group/group.json"
done

# settle_lock <path> <owner> <group>: a lock file the service takes, left by an
# earlier run or by the other half. Every append and every rewrite takes the
# record's own lock, `<record>.lock`, and the ones below live in a directory the
# handler owns: a root-owned one there locks the handler out of that record until
# root happens to take the same lock again, which is a deploy rather than a
# request. So the layout settles them here. A regular file is handed to the
# directory's owner; anything else, which is a name the handler could have
# planted, is removed, because the deploy has the service stopped.
settle_lock() {
	[ -e "$1" ] || [ -L "$1" ] || return 0
	if [ -L "$1" ] || [ ! -f "$1" ]; then
		changed=1
		rm -f "$1"
		return 0
	fi
	if [ "$(stat -f '%Su %Sg %Lp' "$1")" != "$2 $3 600" ]; then
		changed=1
		chown "$2:$3" "$1"
		chmod 0600 "$1"
	fi
	assert_mode "$1" "$2" "$3" 600
}

settle_lock "$store/drafts/.lock" "$onboard_user" "$onboard_user"
settle_lock "$store/applications/.confirmation.lock" "$onboard_user" "$onboard_user"
settle_lock "$store/ledger/payments.jsonl.lock" root wheel
settle_lock "$store/ledger/unattributed.jsonl.lock" root wheel

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
[ "$(stat -f '%Su %Sg %Lp' "$drain_conf" 2>/dev/null)" = "root wheel 700" ] || changed=1
install -d -m 0700 -o root -g wheel "$drain_conf"
assert_mode "$drain_conf" root wheel 700

# The two shared files, at the top of the store, 0644, readable by the handler and
# the TUI both. Each is checked for readability before any of them is installed,
# so a missing sibling file fails here rather than at first request: the handler
# refuses to start on a file it cannot read, and the deploy would otherwise write
# the store before discovering it.
for src in "$reserved_src" "$catalogue_src"; do
	[ -r "$src" ] || fail "cannot read $src"
done

# The question list used to be seeded here, under two names as its format
# changed. It is the crate's now, compiled into the handler, so neither name is
# read by anything: an unused copy of the list is one a person edits by mistake
# and expects to take effect. Removed, not left.
remove_legacy "$store/questions.tsv"
[ ! -e "$store/questions.tsv" ] || fail "$store/questions.tsv is still there"
remove_legacy "$store/questions.toml"
[ ! -e "$store/questions.toml" ] || fail "$store/questions.toml is still there"

# The catalogue has no older name of its own: #370 settled TOML before the file
# existed. The pre-TOML name goes the same way and for the same reason, so a
# copy of the list sitting beside the real one, unread, is not something a
# person edits by mistake on a box that has one.
remove_legacy "$store/catalogue.tsv"
[ ! -e "$store/catalogue.tsv" ] || fail "$store/catalogue.tsv is still there"

install_file "$reserved_src" "$store/reserved-usernames.txt" root wheel 644
install_file "$catalogue_src" "$store/catalogue.toml" root wheel 644
[ -s "$store/catalogue.toml" ] || fail "$store/catalogue.toml is empty"

if [ "$changed" -ne 0 ]; then
	printf 'store ready: %s (five dirs and mail/ writable by %s, the rest root), %s 0700 root\n' \
		"$store" "$onboard_user" "$drain_conf"
fi
