#!/bin/ksh
# provision-member.sh: build a member's address, allowance and public tree.
#
# Usage:
#   doas ksh scripts/provision-member.sh <username> [public-key-file]
#
# Runs ON the box as root, and only after the account exists. On the signup path
# that order is add-user.sh first, then this:
#
#   doas ksh scripts/add-user.sh <username>
#   doas passwd <username>
#   doas ksh scripts/provision-member.sh <username>
#
# The key is optional. A member who only wants mail leaves it empty, and the run
# then does the mail work and stops: the address, the allowance and the login
# class are the whole account. A member with a key also gets the public tree, the
# upload session and the two daemon lanes, which is everything the key is needed
# for. Mail is never behind the key.
#
# add-user.sh creates the account, its Maildir and its quota record. This script
# asserts the account is there rather than making one: a second creation path
# would drift from that script's work, and the signup drain runs the two in this
# order by design.
#
# What it builds, and why each shape:
#
#   /home/www/<username>.kyriakon.net           root:wheel 0755
#   /home/www/<username>.kyriakon.net/www       <username>:members 0755
#   /home/www/<username>.kyriakon.net/gemini    <username>:members 0755
#   /home/<username>/repos                      the member, 0700
#   /home/<username>/.ssh                       root:<group>, 0750
#   /home/<username>/.ssh/authorized_keys       root:<group>, 0640
#   /etc/ssh/authorized_keys/<username>         root:wheel 0644
#   /usr/local/libexec/member-git-shell.sh      root:wheel 0755
#   /etc/login.conf.d/member                    root:wheel 0644
#
# and then hands the last three lanes to scripts of their own, so that one command
# still provisions a member and each lane can be read on its own:
#
#   /etc/httpd.d/<username>.kyriakon.net.conf           provision-member-web.sh
#   /etc/gmid.d/<username>.kyriakon.net.conf            provision-member-capsule.sh
#   /etc/acme-client.d/<username>.kyriakon.net.conf     provision-member-acme.sh
#
# and the third one files the member's certificate request with the queue after
# writing its block, which is how the 443 path is built later without a human.
#
# The public root is the chroot sshd's port 22 block names, and the two
# directories under it are the only things the member's sftp session can reach.
# sshd's safely_chroot checks that root and every component above it for root
# ownership and no group or other write bit, so the root is root:wheel and the
# two content directories are the member's; a component the member could write
# would let them replace the root of their own jail. repos is beside Maildir,
# outside that chroot, so the upload session never sees it and the repositories
# are reached only through the confined git shell on 2222, which is not chrooted.
#
# The member's key is written twice. /etc/ssh/authorized_keys/<username> is the
# one that matters: /etc and /etc/ssh are root-owned, so nothing the member can
# write is on the path to it, which is what makes a root-authored key file
# stick. sshd is proposed to read it for the members group
# (AuthorizedKeysFile /etc/ssh/authorized_keys/%u); see the PR and the runbook
# for the hand step, because openbsd/etc/sshd_config is propose-only.
#
# ~/.ssh/authorized_keys is the second copy, and it is defence in depth rather
# than the fix: the home stays member-owned, so the member can rename ~/.ssh
# away and put a directory of their own in its place. A user-owned file passes
# StrictModes. The copy keeps the login working on a box whose sshd_config has
# not been changed yet, and it is root:<group> 0750/0640 while it is used. The
# account still owns ~/repos and the Maildir.
#
# Every path is checked after it is made, and a run that finds anything else
# stops: a half-built tree that reports success is worse than a refusal.
#
# Idempotent. A second run finds every path in the shape it wants, writes
# nothing, and says so rather than printing the provisioning lines again. The one
# thing it always does is run scripts/quota-apply.sh, which rewrites the
# account's record in place with the same limits.
#
# The three lane scripts are idempotent the same way. They are separate scripts
# because one of them has to be run again later: the httpd vhost gains its block
# behind the relay when the member's certificate lands, which is a second run of
# provision-member-web.sh rather than an edit by hand, and the queue runs it. A
# lane that fails stops this run, because an account with a tree and no vhost is
# not a provisioned member, and the drain that calls this applies the whole thing
# or reports it.
#
# Not this script's job: creating the account or its Maildir, issuing the
# certificate the acme lane queues (scripts/acme-queue.sh --run), the generated
# indexes and the relayd keypair region and the reloads that follow them
# (scripts/cron-apply.sh --web), or adding and removing keys.

set -euo pipefail

# doas and cron both hand over a minimal PATH, and this script now calls
# cap_mkdb and usermod, which live in /usr/sbin. Set it rather than trusting the
# caller, the same line the other box scripts carry.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

usage() {
	printf 'usage: %s <username> [public-key-file]\n' "$0" >&2
	printf '       ksh %s --self-test\n' "$0" >&2
	exit 2
}

# stat's %Lp prints a mode in octal with no leading zero, so a call site reads
# 0755 while the comparison is against 755. Strip the zero the same way in the
# checks and the assertions, or every comparison would report a change.
strip_mode() {
	printf '%s\n' "${1#0}"
}

# assert_shape <path> <owner:group> <mode>: fail loudly if the path is not what
# was just built. This is the last line of defence for the whole script, and it
# sits above the self-test so the test drives this body rather than a copy.
assert_shape() {
	typeset got want
	got=$(stat -f '%Su:%Sg %Lp' "$1" 2>/dev/null) || got=missing
	want="$2 $(strip_mode "$3")"
	if [ "$got" != "$want" ]; then
		printf '%s is %s, wanted %s\n' "$1" "$got" "$want" >&2
		printf 'refusing to report a tree that is not built\n' >&2
		exit 1
	fi
}

# ensure_dir <path> <mode> <owner> <group>: the directory, in that shape.
# Returns 0 when it created or corrected it and 1 when it was already right, so
# a run can report what it did rather than claiming work it did not do. install
# -d on an existing directory sets the mode and owner, so a drifted permission
# is corrected here rather than left for sshd to refuse at a session start.
ensure_dir() {
	typeset path mode want
	path="$1"
	# install -d follows a final symlink, and the tree it descends is the
	# member's own: a planted link would make root chown and chmod the target
	# before the shape check below ran. Refuse it first, and never touch it.
	[ -L "$path" ] && {
		printf '%s is a symlink; refusing to install through it\n' "$path" >&2
		exit 1
	}
	mode="$2"
	# The names, not the ids: every call site names an owner and a group, and
	# %Su/%Sg are what print those. %u/%g would print 0:0 beside "root:wheel".
	want="$3:$4 $(strip_mode "$2")"
	if [ -d "$path" ] && [ "$(stat -f '%Su:%Sg %Lp' "$path")" = "$want" ]; then
		return 1
	fi
	install -d -m "$mode" -o "$3" -g "$4" "$path"
	return 0
}

# put_key <src> <dst> <owner> <group> <mode>: install one key file when its
# bytes, owner or mode differ, so a second run leaves its inode and mtime alone.
# Returns 0 when it wrote and 1 when the file was already right, the same
# contract ensure_dir has. Both key copies go through this one body.
put_key() {
	typeset src dst owner group mode
	src=$1
	dst=$2
	owner=$3
	group=$4
	mode=$5
	if [ -f "$dst" ] &&
		[ "$(stat -f '%Su:%Sg %Lp' "$dst")" = "$owner:$group $(strip_mode "$mode")" ] &&
		cmp -s "$src" "$dst"; then
		return 1
	fi
	install_staged "$src" "$dst" -m "$mode" -o "$owner" -g "$group"
	return 0
}

# --- the member's own address -----------------------------------------------
#
# The virtual table is the whole answer for the local dispatcher: a lookup that
# finds neither <user>@<domain> nor <user> has nothing to expand to, so a member
# whose address is missing from it is a member mail cannot reach, and the
# rejection happens at RCPT time where only the sender sees it. deploy-mail.sh
# seeds one entry per account that exists when it runs, which is every account
# except the one being provisioned now, so the entry is written here too.
#
# The platform's own domain is the first line the deploy writes into
# mail_domains, and the deploy refuses a table whose first line is anything else.
# A box that has not run the mail deploy yet has no table to write to, and that is
# a note rather than a failure: the account is usable for everything but mail
# until then.
#
# mail_from is the sender mapping the listeners' `senders` option reads: an
# authenticated account may only name an envelope sender in its own list. The
# deploy generates it from /etc/passwd and this table, and it is written here
# too, because the member is made after the last deploy and is refused at MAIL
# FROM until the next one. The same table lock the table helpers take keeps a
# deploy's regeneration and this append from losing each other's lines.
virtuals=${VIRTUALS:-/etc/mail/virtuals}
mail_domains_table=${MAIL_DOMAINS:-/etc/mail/mail_domains}
mail_from_table=${MAIL_FROM:-/etc/mail/mail_from}
smtpd_conf=${SMTPD_CONF:-/etc/mail/smtpd.conf}
smtpd_template=${SMTPD_TEMPLATE:-/etc/mail/smtpd.conf.template}
dkim_domains_table=${DKIM_DOMAINS:-/etc/mail/dkim_domains}
queue_key_file=${QUEUE_KEY:-/etc/mail/queue.key}

# mail_from_ensure <address> <account>: add the address to the account's sender
# list, saying so when it was not there. A box that has not run the mail deploy
# has no table yet, which is the same note the virtual table gives rather than a
# failure.
mail_from_ensure() {
	typeset address="$1" account="$2" rc=0
	if [ ! -f "$mail_from_table" ]; then
		printf 'note: no %s yet, so %s cannot submit until the mail deploy runs\n' \
			"$mail_from_table" "$address" >&2
		return 0
	fi
	table_map_add "$mail_from_table" "$account" "$address" || rc=$?
	case $rc in
	0)
		printf 'mail-from %s added for %s\n' "$address" "$account"
		changed=yes
		mail_changed=yes
		;;
	1) ;;
	*)
		printf 'could not add %s to %s\n' "$address" "$mail_from_table" >&2
		exit 1
		;;
	esac
}

# ensure_mail_address: the address line, and the smtpd restart that makes it
# live. A function so the self-test drives the same body against a fixture tree.
ensure_mail_address() {
	typeset domain key current mail_changed=no
	if [ ! -f "$virtuals" ]; then
		printf 'note: no %s yet, so %s has no address until the mail deploy runs\n' \
			"$virtuals" "$user" >&2
		return 0
	fi
	if [ ! -s "$mail_domains_table" ]; then
		printf 'note: %s has no domain line, so %s@ was not added anywhere\n' \
			"$mail_domains_table" "$user" >&2
		return 0
	fi
	domain=$(mail_domains_first "$mail_domains_table")
	key="$user@$domain"
	if awk -F: -v k="$key" '$1 == k { found = 1 } END { exit !found }' "$virtuals"; then
		# An address aimed somewhere else on purpose is left where it is: this
		# script provisions an account, it does not overrule a forward.
		current=$(awk -F: -v k="$key" '$1 == k { sub(/^[^:]*:[ \t]*/, ""); print; exit }' "$virtuals")
		if [ "$current" != "$user" ]; then
			printf 'note: %s maps to %s, so mail for this member goes there\n' "$key" "$current" >&2
		fi
	else
		table_set "$virtuals" "$key" "$key: $user"
		awk -F: -v k="$key" '$1 == k { found = 1 } END { exit !found }' "$virtuals" \
			|| { printf 'could not add %s to %s\n' "$key" "$virtuals" >&2; exit 1; }
		printf 'virtual %s added\n' "$key"
		changed=yes
		mail_changed=yes
	fi
	mail_from_ensure "$key" "$user"
	# smtpd reads the table when it starts, so a line is not live until it is
	# restarted: /etc/rc.d/smtpd defines no reload verb, and delete-user.sh restarts
	# it for the same reason. The configuration is checked first, so a table smtpd
	# would refuse leaves the running daemon alone, and the restart happens only
	# when a line was actually added, so a run that finds the line already present
	# restarts nothing.
	#
	# The render runs only on the path that checks and restarts, so a config this
	# script installs is always checked with smtpd -n. The filter's -d list is
	# spliced at deploy time, so a body's domain appended to the table is only
	# signed after a re-render. A render that fails is a note, not a refusal: the
	# member's address is on the platform's own domain, which the deployed list
	# already carries.
	if [ "$mail_changed" = yes ]; then
		if [ -f "$smtpd_template" ] && [ -f "$dkim_domains_table" ] && [ -f "$queue_key_file" ]; then
			install_smtpd_conf "$smtpd_template" "$dkim_domains_table" \
				"$queue_key_file" "$smtpd_conf" smtpd \
				|| printf 'note: %s could not be re-expanded from %s; restart smtpd after fixing it\n' \
					"$smtpd_conf" "$dkim_domains_table" >&2
		fi
		if [ -f "$smtpd_conf" ] && smtpd -n -f "$smtpd_conf"; then
			rcctl restart smtpd >/dev/null
			printf 'restarted smtpd, which reads the table at start\n'
		else
			printf 'note: %s added but smtpd was not restarted; restart it before mail is delivered\n' \
				"$key" >&2
		fi
	fi
}

# The mail writes against a fixture tree, on a table whose last line has no
# newline: that is the state an interrupted append leaves behind and the one the
# helper has to survive. The render runs against the tracked template, so the
# self-test proves the -d list follows the table.
self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin
	tree=$self_test_work
	# smtpd -n validates the live tree, maildir and filter, which this fixture
	# does not have. The deploy self-test proves the parser check with a stub.
	export SMTPD_CONF_CHECK=no
	user=alice
	changed=no
	virtuals="$tree/virtuals"
	mail_domains_table="$tree/mail_domains"
	mail_from_table="$tree/mail_from"
	smtpd_conf="$tree/smtpd.conf"
	smtpd_template="$tree/smtpd.conf.template"
	dkim_domains_table="$tree/dkim_domains"
	queue_key_file="$tree/queue.key"
	printf 'kyriakon.net\nparish.example\n' > "$mail_domains_table"
	printf 'hello: oliver' > "$virtuals"
	printf 'oliver: oliver@kyriakon.net' > "$mail_from_table"
	printf 'kyriakon.net\nparish.example\n' > "$dkim_domains_table"
	printf '0123456789abcdef0123456789abcdef\n' > "$queue_key_file"
	# The tracked template, placeholders and all, as deploy-mail.sh installs it.
	repo_dir=$(cd "$script_dir/.." && pwd)
	cp "$repo_dir/openbsd/etc/smtpd.conf" "$smtpd_template"

	ensure_mail_address > "$tree/first.out" 2>&1
	check "the member's address is added" \
		"$(grep -c '^alice@kyriakon.net: alice$' "$virtuals")" 1
	check "the last line it appends to stays whole" \
		"$(grep -c '^hello: oliver$' "$virtuals")" 1
	check "and the two are not joined" "$(grep -c 'oliveralice' "$virtuals" || true)" 0
	check "the table is left 0644" "$(stat -f '%Lp' "$virtuals")" 644
	check "and the run says what it added" \
		"$(grep -c '^virtual alice@kyriakon.net added$' "$tree/first.out")" 1
	check "the address is also on the account's sender line" \
		"$(grep -c '^alice: alice@kyriakon.net$' "$mail_from_table")" 1
	check "and the earlier account's line survives" \
		"$(grep -c '^oliver: oliver@kyriakon.net$' "$mail_from_table")" 1
	check "and one account's line never carries another's address" \
		"$(awk -F': ' '$1 == "alice" && $2 ~ /oliver@/ { found = 1 } END { exit !found }' "$mail_from_table" \
			&& printf yes || printf no)" no
	check "the body's domain is in the filter's -d list" \
		"$(grep -c '^filter \"dkimsign\" proc-exec \"filter-dkimsign -d kyriakon.net -d parish.example' "$smtpd_conf")" 1
	check "with no placeholder left" "$(grep -c REPLACE_ME "$smtpd_conf")" 0

	changed=no
	ensure_mail_address > "$tree/second.out" 2>&1
	check "a second run writes nothing" "$(wc -c < "$tree/second.out" | tr -d ' ')" 0

	# The renderer refuses a table whose first line is malformed, because the
	# filter falls back to its first -d and skipping that line moves the fallback
	# onto a body's domain. A failed render is a note here, as it was before, but
	# the live configuration stays as it was rather than being restarted onto a
	# moved fallback.
	user=carol
	printf ' parish.example\nkyriakon.net\nparish.example\n' > "$dkim_domains_table"
	cp "$smtpd_conf" "$tree/anchor.expected"
	ensure_mail_address > "$tree/moved.out" 2>&1
	check "a malformed first line refuses the render here too" \
		"$(grep -c 'could not be re-expanded' "$tree/moved.out")" 1
	check "and the live configuration is unchanged" \
		"$(cmp -s "$smtpd_conf" "$tree/anchor.expected" && printf same || printf changed)" same
	user=alice
	printf 'kyriakon.net\nparish.example\n' > "$dkim_domains_table"

	# The post-condition the run ends with: a path in the shape it wants passes,
	# and one whose mode has drifted fails. Both run in a subshell because
	# assert_shape exits on a mismatch rather than returning.
	mkdir -p "$tree/shape"
	chmod 0750 "$tree/shape"
	shape_owner=$(stat -f '%Su:%Sg' "$tree/shape")
	rc=0
	( assert_shape "$tree/shape" "$shape_owner" 0750 ) >/dev/null 2>&1 || rc=$?
	check "a path in the wanted shape passes the post-condition" "$rc" 0
	chmod 0700 "$tree/shape"
	rc=0
	( assert_shape "$tree/shape" "$shape_owner" 0750 ) >/dev/null 2>&1 || rc=$?
	check "a drifted mode fails the post-condition" "$rc" 1
	check "strip_mode reads a stat mode the way a call site writes it" \
		"$(strip_mode 0750)" 750
	check "and the key file's mode, too" "$(strip_mode 0640)" 640

	# The managed key file, through the same body the live run uses. The
	# owner and group here are this run's, because the test has no root to
	# chown to: the live call passes root and wheel.
	printf 'ssh-ed25519 AAAAexample alice@example\n' >"$tree/key.pub"
	mkdir -p "$tree/etc/ssh/authorized_keys"
	key_fixture="$tree/etc/ssh/authorized_keys/alice"
	rc=0
	( put_key "$tree/key.pub" "$key_fixture" "$(id -un)" "$(id -gn)" 0644 ) >/dev/null 2>&1 || rc=$?
	check "the managed key file is written" "$rc" 0
	check "with the source bytes" \
		"$(cmp -s "$tree/key.pub" "$key_fixture" && printf same || printf differs)" same
	check "at the wanted mode" "$(stat -f '%Lp' "$key_fixture")" 644
	rc=0
	( put_key "$tree/key.pub" "$key_fixture" "$(id -un)" "$(id -gn)" 0644 ) >/dev/null 2>&1 || rc=$?
	check "a second write finds it unchanged" "$rc" 1

	# ensure_dir's contract, which the changed flag is read from: 1 when the
	# directory is already right and 0 when it corrected it. The owner and group
	# are this run's for the same reason put_key's are.
	mkdir "$tree/dir"
	chmod 0755 "$tree/dir"
	rc=0
	( ensure_dir "$tree/dir" 0755 "$(id -un)" "$(id -gn)" ) >/dev/null 2>&1 || rc=$?
	check "an already-right directory reports no change" "$rc" 1
	rc=0
	( ensure_dir "$tree/dir" 0700 "$(id -un)" "$(id -gn)" ) >/dev/null 2>&1 || rc=$?
	check "a drifted directory reports a change" "$rc" 0
	check "and the mode is corrected" "$(stat -f '%Lp' "$tree/dir")" 700

	# A planted symlink is refused before install runs. The rc alone cannot
	# tell a refusal from "already right", so the message is what is asserted,
	# beside the target's untouched mode.
	mkdir "$tree/planted-target"
	chmod 0755 "$tree/planted-target"
	ln -s "$tree/planted-target" "$tree/planted"
	rc=0
	( ensure_dir "$tree/planted" 0700 "$(id -un)" "$(id -gn)" ) >/dev/null 2>"$tree/planted.err" || rc=$?
	check "a symlinked directory is refused" "$rc" 1
	check "and its target keeps its mode" "$(stat -f '%Lp' "$tree/planted-target")" 755
	check "the refusal names the link" \
		"$(grep -c 'is a symlink' "$tree/planted.err")" 1

	self_test_end
}

case "${1:-}" in
--self-test)
	[ "$#" -eq 1 ] || usage
	self_test
	;;
esac

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	usage
fi
user="$1"
key_arg="${2:-}"

# Whether this run wrote anything, read by the report at the end. Set here rather
# than beside the tree because the login class below is as much a part of a run as
# the tree is.
changed=no

# The name is a filesystem path component, a subdomain label
# (<username>.kyriakon.net) and here also a chroot path component under
# /home/www, so the shared charset rule is the guard.
if ! valid_localpart "$user"; then
	printf 'invalid username: %s (lowercase [a-z0-9-], starts and ends alphanumeric, 1-31 chars)\n' "$user" >&2
	exit 1
fi

# Ownership is the point of most of what follows, and a run as an ordinary user
# would fail partway through with the tree already half made.
if [ "$(id -u)" -ne 0 ]; then
	printf 'provision-member: run this with doas: it makes root-owned paths under /home/www\n' >&2
	exit 1
fi

# --- the account, which this script must never create -----------------------

if ! id "$user" >/dev/null 2>&1; then
	printf 'no such account: %s\n' "$user" >&2
	printf 'the account comes first, and nothing here makes one:\n' >&2
	printf '  doas ksh scripts/add-user.sh %s\n' "$user" >&2
	printf '  doas passwd %s\n' "$user" >&2
	exit 1
fi

# --- whether this member has hosting at all ---------------------------------
#
# A member with an upload key gets the public tree, the upload session and the
# daemon lanes. A member without one gets mail and nothing else: the key is
# optional in the spec and in the question list, and someone who only wants mail
# leaves it empty. So the key decides hosting and nothing else, the address and
# the allowance below are provisioned either way, and a missing default key is a
# mail-only member rather than an error. A key named on the command line is
# different: it was asked for explicitly, so a path that is not there is
# refused, and the check is below.
key_src="$key_arg"
have_key=yes
if [ -z "$key_src" ]; then
	key_src="/var/db/onboard/keys/$user.pub"
	if [ ! -f "$key_src" ]; then
		have_key=no
	fi
fi

# --- the quota --------------------------------------------------------------
#
# The 5 GB allowance the site promises for this account, across mail, web and
# git. quota-apply.sh writes the record and reads it back from the file, so a
# zero here means the allowance is in place rather than that a write was
# attempted. Exit 3 means quotas are not on for the mount yet, which is a state
# rather than a failure of provisioning: the account and its tree are usable, and
# the allowance follows when quota-apply.sh --enable has been run. Any other
# failure is reported and the member is still provisioned, because hosting does
# not depend on the quota.
#
# The status is taken from $? directly rather than from an `if ! cmd` test: in
# ksh a negated command leaves 0 behind in $?, so a case on $? inside that branch
# could never tell exit 3 from any other failure.
set +e
quota_out=$(ksh "$script_dir/quota-apply.sh" "$user" 2>&1)
rc=$?
set -e
case $rc in
0)
	printf 'quota: %s\n' "$quota_out"
	;;
3)
	printf 'note: %s\n' "$quota_out" >&2
	;;
*)
	printf 'warning: the allowance was not set: %s\n' "$quota_out" >&2
	;;
esac

# --- the member's own address -----------------------------------------------
ensure_mail_address

# --- the session shell, from the login class --------------------------------
#
# One account carries both sessions and the port decides which. Port 22's block
# forces internal-sftp, which sshd runs in process before it reads any shell.
# Every other session runs through the login shell with -c, an external subsystem
# request included: session_subsystem_req() hands the Subsystem command to
# do_exec(), and do_child() execs the shell with it. Port 2222 also carries a
# ForceCommand of the wrapper, so a push arrives there as
# `member-git-shell.sh -c '<wrapper> --force'` with the client's command in
# SSH_ORIGINAL_COMMAND, and an sftp request is refused either way. That shell
# comes from the account's login class rather than from the password entry: auth.c
# sets lc = login_getclass(pw->pw_class), and session.c's do_child() takes
# login_getcapstr(lc, "shell", pw_shell, pw_shell) before it execs anything. So
# the entry keeps /sbin/nologin, which is the platform's core safety property,
# and 2222 runs the confined shell all the same.
#
# Why not git-shell(1): git-shell re-execs git-receive-pack or git-upload-pack
# with whatever path the client sent. Port 2222 is not chrooted, and the upload
# tree the chrooted sftp session on 22 reaches is the same directory the member
# owns outside it, so a repository uploaded there with an executable
# hooks/pre-receive (or a config naming core.fsmonitor) would run as the member
# on a push. git-shell also runs executables from ~/git-shell-commands. The
# wrapper in scripts/member-git-shell.sh accepts only the three git commands,
# only /home/<user>/repos/<name>.git, and passes core.hooksPath=/dev/null and
# core.fsmonitor=false to git. login.conf.d/member names it, and it is installed
# here beside the class so a class that names a missing file cannot land.
#
# The class is the drop-in at /etc/login.conf.d/member, the directory this box
# already runs its dovecot and rspamd classes from, and a class there takes
# precedence over the same name in /etc/login.conf, so the base file is never
# edited and a base update cannot conflict with it. The file is tracked in this
# repository and installed here rather than left to a hand step, because
# usermod -L names a class that has to exist first: that step has failed on this
# box once already, with "No such login class 'onboard'", after the account was
# made.
#
# cap_mkdb is what makes the class visible to sshd while /etc/login.conf.db
# exists, because that database is what login_getclass reads when it is there
# (login.conf(5), and cap_mkdb(1) says the same). The spec expected no database on
# this box and no cap_mkdb run; the box has one now, built when the onboard class
# was added, so this runs cap_mkdb whenever the database is the older of the two
# files and says which of the two states it found rather than assuming either.
class_src="$script_dir/../openbsd/etc/login.conf.d/member"
shell_src="$script_dir/member-git-shell.sh"
shell_dst=/usr/local/libexec/member-git-shell.sh
login_conf_d=/etc/login.conf.d
if [ ! -f "$class_src" ]; then
	printf 'no %s, which is the member class this script installs\n' "$class_src" >&2
	printf 'this script is run from the repository checkout:\n' >&2
	printf '  doas ksh scripts/provision-member.sh %s\n' "$user" >&2
	exit 1
fi
if [ ! -f "$shell_src" ]; then
	printf 'no %s, which is the session shell the member class names\n' "$shell_src" >&2
	printf 'this script is run from the repository checkout:\n' >&2
	printf '  doas ksh scripts/provision-member.sh %s\n' "$user" >&2
	exit 1
fi

# The session shell before the class that names it. root:wheel 0755, in a
# directory the member can read and execute and cannot write, and which the
# member's PATH does not include.
install -d -m 0755 /usr/local/libexec
if [ -f "$shell_dst" ] && cmp -s "$shell_src" "$shell_dst" &&
	[ "$(stat -f '%Su:%Sg %Lp' "$shell_dst")" = "root:wheel $(strip_mode 0755)" ]; then
	:
else
	install_staged "$shell_src" "$shell_dst" -m 0755 -o root -g wheel
	printf 'session shell installed: %s\n' "$shell_dst"
	changed=yes
fi
install -d -m 0755 "$login_conf_d"
if [ -f "$login_conf_d/member" ] && cmp -s "$class_src" "$login_conf_d/member"; then
	:
else
	install -m 0644 "$class_src" "$login_conf_d/member"
	printf 'login class installed: %s\n' "$login_conf_d/member"
	changed=yes
fi

# The mtimes are compared as numbers rather than with test's -nt, so the check
# reads the same in every shell this runs under.
if [ -f /etc/login.conf.db ]; then
	if [ "$(stat -f '%m' /etc/login.conf.db)" -lt "$(stat -f '%m' "$login_conf_d/member")" ]; then
		cap_mkdb /etc/login.conf
		printf 'cap_mkdb: /etc/login.conf.db rebuilt, because that database is what\n'
		printf '  sshd reads while it exists\n'
		changed=yes
	fi
	[ "$(stat -f '%m' /etc/login.conf.db)" -ge "$(stat -f '%m' "$login_conf_d/member")" ] || {
		printf '/etc/login.conf.db is older than %s, so the class is not in the\n' "$login_conf_d/member" >&2
		printf 'database sshd reads and port 2222 would run /sbin/nologin\n' >&2
		exit 1
	}
else
	printf 'note: no /etc/login.conf.db, so the drop-in is read directly and no cap_mkdb run is needed\n'
fi

# The class on the account. Field 5 of /etc/master.passwd is the class and getent
# passwd does not carry it (passwd(5), master.passwd(5)), so the class is read from
# there; nothing else in that file is looked at. usermod -L is the only step that
# puts an account in a class, so an account left in the default class is one whose
# 2222 session is /sbin/nologin, which ignores -c and exits.
#
# A lapsed account keeps its class. Assigning member here would undo the lapse
# before the group check below notices: submission would work again while the
# store and the page still said lapsed. The check that follows refuses either
# way; the difference is whether the refusal leaves the account as it was.
class_now=$(awk -F: -v u="$user" '$1 == u { print $5 }' /etc/master.passwd)
if [ "$class_now" != member ] && [ "$class_now" != lapsed ]; then
	usermod -L member "$user" || {
		printf 'usermod -L member %s failed\n' "$user" >&2
		exit 1
	}
	printf 'login class: %s assigned to the member class\n' "$user"
	changed=yes
fi

class_now=$(awk -F: -v u="$user" '$1 == u { print $5 }' /etc/master.passwd)
if [ "$class_now" != member ]; then
	printf '%s is in the %s login class, not member, so 2222 would run a shell that is not the confined git shell\n' \
		"$user" "${class_now:-default}" >&2
	exit 1
fi
shell_now=$(getent passwd "$user" | awk -F: 'NR == 1 { print $7 }')
if [ "$shell_now" != /sbin/nologin ]; then
	printf 'the password entry for %s runs %s, and it has to stay /sbin/nologin:\n' \
		"$user" "$shell_now" >&2
	printf 'the session shell comes from the login class, so the account keeps no shell of its own\n' >&2
	exit 1
fi

# The members group is what sshd's Match blocks key on, and both the sftp upload
# on 22 and the confined git shell on 2222 sit behind it. An account outside the group has
# neither, so the tree built below would be unreachable, and that is a refusal
# rather than a note. deploy-mail.sh creates the group, so a box that has not run
# it has none. The check runs for a mail-only account too: the own-domain tier
# gives every mailbox the class whose shell is confined git, and the group is what
# the member sessions match.
if ! getent group members >/dev/null 2>&1; then
	printf 'no members group, which is what sshd matches for the member sessions\n' >&2
	printf '  doas ksh scripts/deploy-mail.sh\n' >&2
	exit 1
fi
if ! id -Gn "$user" | tr ' ' '\n' | grep -qx members; then
	printf '%s is not in the members group, so it has no sftp or git session\n' "$user" >&2
	printf 'and this tree would be unreachable:\n' >&2
	printf '  doas usermod -G members %s\n' "$user" >&2
	exit 1
fi


# Mail is the account's whole job when there is no key, so a mail-only member
# stops here: the class, the address and the allowance are in place, and the
# tree, the upload session and the daemon lanes are not built because there is
# no key to reach them with. The class is set for a mail-only account too, the
# same as for one with a key: an own-domain mailbox carries no key of its own,
# and the spec gives every mailbox the class whose shell is confined git. An
# account with no `authorized_keys` cannot use that session either way.
if [ "$have_key" = no ]; then
	printf 'provisioned %s: mail only, no upload key\n' "$user"
	printf '  the class, the address and the allowance are in place; the public tree, the upload\n'
	printf '  session and the daemon lanes are not built, because the member holds no key\n'
	printf 'next: add a key from the member page, then run this script again\n'
	exit 0
fi

# --- the upload key's source -------------------------------------------------
#
# The key source, and why it is a file rather than an argument this script is
# handed. The signup path collects the applicant's public key with the
# application, and the root drain that applies the intent has already written it
# out as a file, so a path is the shape that works for both the drain and an
# operator running this by hand. An operator then never retypes key material,
# which matters because a mistyped key locks the member out of their own upload
# path with an error only sshd sees, and nothing on the box reports it.
# The default sits under /var/db/onboard, the control plane's own state tree,
# which the service writes and root reads; this script only ever reads it. That
# path is this script's convention rather than one any document fixes: the store
# listing in the signup spec has no keys directory yet, so the drain that applies
# an application intent has to write the upload key there, and the default here is
# the contract it has to meet. Until it does, name the file with the second
# argument.
#
# The second argument names the file explicitly, for a key collected by some
# other route and for exercising this script before the service writes that tree.
# Whether there is a key at all was settled at the top, and a member with none
# stopped there on the mail-only path; this run has one, so what is left is to
# check that the file it names can become an authorized_keys line. An explicitly
# named file that is not there is a refusal, not a mail-only member: the caller
# asked for it, and building the member without the tree they asked about would
# silently ignore them.
if [ ! -f "$key_src" ]; then
	printf 'no such public key file: %s\n' "$key_src" >&2
	exit 1
fi
if [ ! -s "$key_src" ]; then
	printf 'public key file is empty: %s\n' "$key_src" >&2
	exit 1
fi

# Only bare key lines, checked before anything is built. An authorized_keys line
# may carry options before its key type, and the spec writes none of them: the
# port decides whether a session is the sftp upload or the git session, not a forced
# command, so a line that begins with anything but a key type is refused here
# rather than installed into an account root later authenticates against.
if ! awk 'NF && $1 !~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+|sk-[a-z0-9-]+@openssh\.com)$/ { exit 1 }' "$key_src"; then
	printf '%s is not a bare SSH public key file: a line begins with something\n' "$key_src" >&2
	printf 'other than a key type, and no authorized_keys options are written here\n' >&2
	exit 1
fi

# --- paths ------------------------------------------------------------------

home="/home/$user"
public="/home/www/$user.kyriakon.net"
authorized_keys="$home/.ssh/authorized_keys"
managed_keys_dir="/etc/ssh/authorized_keys"
managed_key="$managed_keys_dir/$user"

if [ ! -d "$home" ]; then
	printf 'no home directory at %s, so the account is not one add-user.sh finished\n' "$home" >&2
	exit 1
fi
group=$(id -gn "$user")

# assert_shape <path> <owner:group> <mode>: fail loudly if the path is not what
# was just built. This is the last line of defence for the whole script.
# (Definition above the self-test, which drives it.)

# The chroot root is root:wheel so sshd will chroot into it, and the two
# directories that carry content belong to the member.
if ensure_dir "$public" 0755 root wheel; then changed=yes; fi
if ensure_dir "$public/www" 0755 "$user" members; then changed=yes; fi
if ensure_dir "$public/gemini" 0755 "$user" members; then changed=yes; fi

# Beside Maildir, which add-user.sh made, and outside the chroot above. The
# managed key under /etc is the one on a root-owned path. The .ssh copy below is
# for a box that has not applied the sshd hand step, and after it is defence in
# depth only: the home stays member-owned, so the member can replace the
# directory, and sshd accepts a user-owned file under StrictModes.
if ensure_dir "$home/repos" 0700 "$user" "$group"; then changed=yes; fi
if ensure_dir "$home/.ssh" 0750 root "$group"; then changed=yes; fi
if ensure_dir "$managed_keys_dir" 0755 root wheel; then changed=yes; fi

# The key is installed whole rather than appended: the source file is the record
# of which keys the account holds, one line each, so a line removed there is gone
# from the account on the next run. The managed copy under /etc is the one sshd
# will read for members; the ~/.ssh copy keeps the session working until the
# sshd_config hand step lands.
if put_key "$key_src" "$authorized_keys" root "$group" 0640; then changed=yes; fi
if put_key "$key_src" "$managed_key" root wheel 0644; then changed=yes; fi

# --- the post-conditions ----------------------------------------------------

assert_shape "$public" root:wheel 0755
assert_shape "$public/www" "$user:members" 0755
assert_shape "$public/gemini" "$user:members" 0755
assert_shape "$home/repos" "$user:$group" 0700
assert_shape "$home/.ssh" "root:$group" 0750
assert_shape "$authorized_keys" "root:$group" 0640
assert_shape "$managed_keys_dir" root:wheel 0755
assert_shape "$managed_key" root:wheel 0644
assert_shape "$shell_dst" root:wheel 0755

# cmp, not a size: install could copy a truncated file and the mode would still
# be right. The source is checked above, so this proves each copy is the file
# that was checked.
for key_copy in "$authorized_keys" "$managed_key"; do
	if ! cmp -s "$key_src" "$key_copy"; then
		printf '%s and %s differ after the install\n' "$key_src" "$key_copy" >&2
		exit 1
	fi
done

# The home belongs to the member, or the git session's ~ and everything the member
# writes inside it land somewhere they cannot use.
home_owner=$(stat -f '%Su' "$home")
if [ "$home_owner" != "$user" ]; then
	printf '%s is owned by %s, not %s\n' "$home" "$home_owner" "$user" >&2
	exit 1
fi

# The whole chroot chain, not just the directory this script made. sshd's
# safely_chroot refuses a chroot path with any component that is not root-owned
# or that is group- or other-writable, and a refused chroot fails silently from
# the member's side. /home and /home/www belong to the base install and to
# deploy-mail.sh, so they are checked and never modified here.
for d in /home /home/www "$public"; do
	owner=$(stat -f '%Su' "$d")
	if [ "$owner" != root ]; then
		printf '%s is owned by %s, not root, so sshd cannot chroot to %s\n' "$d" "$owner" "$public" >&2
		exit 1
	fi
	# In the symbolic mode (%Sp, for example drwxr-xr-x) the group write bit is
	# the sixth character and the other write bit is the ninth, so a w at either
	# position is a chroot sshd will refuse.
	case "$(stat -f '%Sp' "$d")" in
	?????w*|????????w*)
		printf '%s is writable by group or other, so sshd cannot chroot to %s\n' "$d" "$public" >&2
		exit 1
		;;
	esac
done

# --- the daemon lanes -------------------------------------------------------
#
# Each lane is its own script, run from here so that one command still provisions
# a member, and each is idempotent: a second run rewrites nothing and says so.
# They are separate scripts because the web one has to be run again later, when
# the member's certificate lands and the block behind the relay becomes due, and
# because a lane read on its own is a lane reviewed on its own. The acme lane is
# the one that makes that later run happen: it writes the member's acme-client
# block and files the request with the queue, and the queue runs the web lane and
# cron-apply.sh --web when the certificate lands. A lane that fails stops this
# run: an account with a tree and no vhost is not a provisioned member.
for lane in provision-member-web.sh provision-member-capsule.sh provision-member-acme.sh; do
	if [ ! -f "$script_dir/$lane" ]; then
		printf 'no %s beside this script, so %s has no generated daemon file\n' "$lane" "$user" >&2
		printf 'run this from the repository checkout:\n' >&2
		printf '  doas ksh scripts/provision-member.sh %s\n' "$user" >&2
		exit 1
	fi
	ksh "$script_dir/$lane" "$user"
done

# --- report -----------------------------------------------------------------

if [ "$changed" = no ]; then
	printf '%s is already provisioned; the tree and the key are unchanged\n' "$user"
	printf 'and the lanes above report any change to the generated daemon files\n'
	exit 0
fi

printf 'provisioned %s\n' "$user"
printf '  public:  %s (root:wheel 0755; www and gemini %s:members)\n' "$public" "$user"
printf '  private: %s/repos 0700, %s/.ssh/authorized_keys root:%s 0640\n' "$home" "$home" "$group"
printf '  session: sftp on 22 and confined git on 2222 from the member login class, one key\n'
printf '  key:     %s (root:wheel 0644; sshd reads it for members once the hand step lands)\n' "$managed_key"
printf '  files:   /etc/httpd.d/%s.kyriakon.net.conf, /etc/gmid.d/%s.kyriakon.net.conf\n' "$user" "$user"
printf '           /etc/acme-client.d/%s.kyriakon.net.conf, request queued\n' "$user"
printf '  key from: %s\n' "$key_src"
printf 'next: doas ksh scripts/cron-apply.sh --web   # index the member files, check, reload\n'
printf 'then: an sftp session on port 22 as %s uploads into %s/www\n' "$user" "$public"
