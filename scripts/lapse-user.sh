#!/bin/ksh
# lapse-user.sh: stop a lapsed member's sending, uploading and pushing, and
# put them back when the account is paid.
#
# Usage:
#   doas ksh lapse-user.sh <username>
#   doas ksh lapse-user.sh --restore <username>
#   ksh lapse-user.sh --self-test
#
# Lapsed is the lifecycle state where mail keeps arriving and stays readable and
# everything already published stays up, while sending from the address,
# uploading to the site and pushing to git stop. The mechanisms are the ones the
# runbook and the enforcement research name, not a second kind of lock:
#
#   sending        usermod -L lapsed. The login class sets auth-smtp=reject, so
#                  smtpd authentication refuses while IMAP still authenticates.
#   upload, push   usermod -S ''. Both the sftp upload and git-shell sit behind
#                  the sshd `Match Group members` blocks, so emptying the
#                  secondary groups removes both sessions without touching the
#                  member's key or their published vhosts.
#
# Nothing here touches the Maildir, the public roots, the vhost files or the
# member's authorized_keys: the site stays up and the mail stays readable. The
# reverse run restores the member class and the members group.
#
# Root runs it, from the drain's window sweep and its credit path. The login
# class files are tracked beside the scripts and installed here, the same way
# provision-member.sh installs the member class before naming it in usermod.

set -euo pipefail

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

die() {
	printf 'lapse-user: %s\n' "$*" >&2
	exit 1
}

script_dir=$(cd "$(dirname "$0")" && pwd)
class_src_dir=${CLASS_SRC_DIR:-$script_dir/../openbsd/etc/login.conf.d}
login_conf_d=${LOGIN_CONF_D:-/etc/login.conf.d}
usermod_cmd=${USERMOD:-usermod}
cap_mkdb_cmd=${CAP_MKDB:-cap_mkdb}

user_exists() {
	id -u "$1" >/dev/null 2>&1
}

# install_class <member|lapsed>: install the tracked drop-in and rebuild the
# login database when this box has one, because login_getclass reads the database
# in preference to the plain file.
install_class() {
	class=$1
	[ -f "$class_src_dir/$class" ] || die "no $class class at $class_src_dir/$class"
	install -d -m 0755 "$login_conf_d"
	install -m 0644 "$class_src_dir/$class" "$login_conf_d/$class"
	if [ -f /etc/login.conf.db ]; then
		"$cap_mkdb_cmd" /etc/login.conf
	fi
}

set_class() {
	"$usermod_cmd" -L "$1" "$2"
}

# An empty secondary-group list is what usermod(8) documents as removing the
# user from every secondary group, which is the members group sshd matches on.
set_groups() {
	"$usermod_cmd" -S "$1" "$2"
}

lapse() {
	user=$1
	install_class lapsed
	set_class lapsed "$user"
	set_groups "" "$user"
	printf 'lapse-user: %s lapses: submission refused, sftp and git stop, mail and the site stay\n' "$user"
}

restore() {
	user=$1
	install_class member
	set_class member "$user"
	set_groups members "$user"
	printf 'lapse-user: %s is active again: submission, sftp and git restored\n' "$user"
}

self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$script_dir/lib.sh"
	self_test_begin
	class_src_dir="$script_dir/../openbsd/etc/login.conf.d"
	check "the lapsed class ships" \
		"$([ -f "$class_src_dir/lapsed" ] && printf yes || printf no)" yes
	check "the lapsed class refuses SMTP authentication" \
		"$(grep -c '^lapsed:.*auth-smtp=reject' "$class_src_dir/lapsed")" 1

	# shellcheck disable=SC2154 # self_test_work is set by lib.sh's self_test_begin
	login_conf_d="$self_test_work/login.conf.d"
	usermod_log="$self_test_work/usermod.log"
	cat >"$self_test_work/usermod" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >>"$USERMOD_LOG"
SH
	chmod 0755 "$self_test_work/usermod"
	export USERMOD_LOG="$usermod_log"
	usermod_cmd="$self_test_work/usermod"
	# shellcheck disable=SC2329 # called indirectly through lapse/restore
	user_exists() { return 0; }

	lapse alice >/dev/null
	check "lapse installs the lapsed class" \
		"$([ -f "$login_conf_d/lapsed" ] && printf yes || printf no)" yes
	check "lapse switches the login class" \
		"$(grep -c '^-L lapsed alice$' "$usermod_log")" 1
	check "lapse empties the secondary groups" \
		"$(grep -c '^-S  alice$' "$usermod_log")" 1

	: >"$usermod_log"
	restore alice >/dev/null
	check "restore installs the member class" \
		"$([ -f "$login_conf_d/member" ] && printf yes || printf no)" yes
	check "restore switches the member class" \
		"$(grep -c '^-L member alice$' "$usermod_log")" 1
	check "restore puts the members group back" \
		"$(grep -c '^-S members alice$' "$usermod_log")" 1

	self_test_end
}

if [ "${1:-}" = --self-test ]; then
	self_test
fi

case "${1:-}" in
--restore)
	[ "$#" -eq 2 ] || die "usage: ksh $0 --restore <username>"
	user=$2
	restore "$user" || exit 1
	;;
*)
	[ "$#" -eq 1 ] || die "usage: ksh $0 <username>"
	user=$1
	user_exists "$user" || die "there is no account named $user"
	lapse "$user" || exit 1
	;;
esac
