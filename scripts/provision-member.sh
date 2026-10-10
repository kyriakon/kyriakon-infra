#!/bin/ksh
# provision-member.sh: build a member's public tree, upload key and quota record.
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
#   /home/<username>/.ssh                       the member, 0700
#   /home/<username>/.ssh/authorized_keys       the member, 0600
#
# The public root is the chroot sshd's port 22 block names, and the two
# directories under it are the only things the member's sftp session can reach.
# sshd's safely_chroot checks that root and every component above it for root
# ownership and no group or other write bit, so the root is root:wheel and the
# two content directories are the member's; a component the member could write
# would let them replace the root of their own jail. repos is beside Maildir,
# outside that chroot, so the upload session never sees it and the repositories
# are reached only through git-shell on 2222, which is not chrooted.
#
# Every path is checked after it is made, and a run that finds anything else
# stops: a half-built tree that reports success is worse than a refusal.
#
# Idempotent. A second run finds every path in the shape it wants, writes
# nothing, and says so rather than printing the provisioning lines again. The one
# thing it always does is run scripts/quota-apply.sh, which rewrites the
# account's record in place with the same limits.
#
# Not this script's job: creating the account or its Maildir, the member's shell
# or login class, the vhost, capsule and acme-client files, certificate
# generation, or adding and removing keys.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)

usage() {
	printf 'usage: %s <username> [public-key-file]\n' "$0" >&2
	exit 2
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	usage
fi
user="$1"
key_arg="${2:-}"

# Same charset rule as add-user.sh, and for the same reasons: the name is a
# filesystem path component, a subdomain label (<username>.kyriakon.net) and here
# also a chroot path component under /home/www.
if ! printf '%s' "$user" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'; then
	printf 'invalid username: %s (lowercase [a-z0-9._-], <=32 chars)\n' "$user" >&2
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

# The members group is what sshd's Match blocks key on, and both the sftp upload
# on 22 and git-shell on 2222 sit behind it. An account outside the group has
# neither, so the tree built below would be unreachable, and that is a refusal
# rather than a note. deploy-mail.sh creates the group, so a box that has not run
# it has none.
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

# --- the upload key's source -------------------------------------------------
#
# The key source, and why it is a file rather than an argument this script is
# handed. The signup path collects the applicant's public key with the
# application, and the root drain that applies the intent has already written it
# out as a file, so a path is the shape that works for both the drain and an
# operator running this by hand. An operator then never retypes key material,
# which matters because a mistyped key locks the member out of their own upload
# path with an error only sshd sees, and nothing on the box reports it.
# The default sits under /var/db/onboard, the onboarding service's own state tree,
# which the service writes and root reads; this script only ever reads it. That
# path is this script's convention rather than one any document fixes: the store
# listing in the signup spec has no keys directory yet, so the drain that applies
# an application intent has to write the upload key there, and the default here is
# the contract it has to meet. Until it does, name the file with the second
# argument.
#
# The second argument names the file explicitly, for a key collected by some
# other route and for exercising this script before the service writes that tree.
# With no argument and nothing at the default path the run stops before it builds
# anything, naming the path it looked for.
key_src="$key_arg"
if [ -z "$key_src" ]; then
	key_src="/var/db/onboard/keys/$user.pub"
	if [ ! -f "$key_src" ]; then
		printf 'no public key at %s\n' "$key_src" >&2
		printf 'if the key was collected elsewhere, name the file:\n' >&2
		printf '  doas ksh scripts/provision-member.sh %s <public-key-file>\n' "$user" >&2
		exit 1
	fi
fi
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
# port decides whether a session is the sftp upload or git-shell, not a forced
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

if [ ! -d "$home" ]; then
	printf 'no home directory at %s, so the account is not one add-user.sh finished\n' "$home" >&2
	exit 1
fi
group=$(id -gn "$user")

# stat's %Lp prints a mode in octal with no leading zero, so a call site reads
# 0755 while the comparison is against 755. Strip the zero the same way in the
# check and in the assertion below, or every comparison would report a change.
strip_mode() {
	printf '%s\n' "${1#0}"
}

# ensure_dir <path> <mode> <owner> <group>: the directory, in that shape.
# Returns 0 when it created or corrected it and 1 when it was already right, so
# a run can report what it did rather than claiming work it did not do. install
# -d on an existing directory sets the mode and owner, so a drifted permission
# is corrected here rather than left for sshd to refuse at a session start.
ensure_dir() {
	typeset path mode want
	path="$1"
	mode="$2"
	want="$3:$4 $(strip_mode "$2")"
	if [ -d "$path" ] && [ "$(stat -f '%Su:%Sg %Lp' "$path")" = "$want" ]; then
		return 1
	fi
	install -d -m "$mode" -o "$3" -g "$4" "$path"
	return 0
}

# assert_shape <path> <owner:group> <mode>: fail loudly if the path is not what
# was just built. This is the last line of defence for the whole script.
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

changed=no

# The chroot root is root:wheel so sshd will chroot into it, and the two
# directories that carry content belong to the member.
ensure_dir "$public" 0755 root wheel || changed=yes
ensure_dir "$public/www" 0755 "$user" members || changed=yes
ensure_dir "$public/gemini" 0755 "$user" members || changed=yes

# Beside Maildir, which add-user.sh made, and outside the chroot above.
ensure_dir "$home/repos" 0700 "$user" "$group" || changed=yes
ensure_dir "$home/.ssh" 0700 "$user" "$group" || changed=yes

# The key is installed whole rather than appended: the source file is the record
# of which keys the account holds, one line each, so a line removed there is gone
# from the account on the next run. Writing only when the bytes, the owner or the
# mode differ is what lets a second run leave the file's mtime and inode alone.
if [ -f "$authorized_keys" ] &&
	[ "$(stat -f '%Su:%Sg %Lp' "$authorized_keys")" = "$user:$group $(strip_mode 0600)" ] &&
	cmp -s "$key_src" "$authorized_keys"; then
	:
else
	install -m 0600 -o "$user" -g "$group" "$key_src" "$authorized_keys"
	changed=yes
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

# --- the post-conditions ----------------------------------------------------

assert_shape "$public" root:wheel 0755
assert_shape "$public/www" "$user:members" 0755
assert_shape "$public/gemini" "$user:members" 0755
assert_shape "$home/repos" "$user:$group" 0700
assert_shape "$home/.ssh" "$user:$group" 0700
assert_shape "$authorized_keys" "$user:$group" 0600

# cmp, not a size: install could copy a truncated file and the mode would still
# be right. The source is checked above, so this proves the copy is the file that
# was checked.
if ! cmp -s "$key_src" "$authorized_keys"; then
	printf '%s and %s differ after the install\n' "$key_src" "$authorized_keys" >&2
	exit 1
fi

# The home belongs to the member, or git-shell's ~ and everything the member
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

# --- report -----------------------------------------------------------------

if [ "$changed" = no ]; then
	printf '%s is already provisioned; nothing changed\n' "$user"
	exit 0
fi

printf 'provisioned %s\n' "$user"
printf '  public:  %s (root:wheel 0755; www and gemini %s:members)\n' "$public" "$user"
printf '  private: %s/repos 0700, %s/.ssh/authorized_keys 0600\n' "$home" "$home"
printf '  key from: %s\n' "$key_src"
printf 'next: an sftp session on port 22 as %s uploads into %s/www\n' "$user" "$public"
