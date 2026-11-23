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
#   printf '%s\n' <bcrypt-hash> | ksh set-mail-password.sh <username>
#   ksh set-mail-password.sh --self-test
#
# The hash arrives on stdin and never in argv. OpenBSD exposes KERN_PROC_ARGV to
# every local user, so `usermod -p <hash>` is a password hash readable with ps(1).
# This script instead edits a private copy of master.passwd and rebuilds the
# password databases from it, which is the one update path with no secret in any
# process's arguments.
#
# The hash is checked before it reaches master.passwd. The full 60-character
# bcrypt shape is required, so a newline or a colon cannot smuggle a second
# field into the password file even if the script is run by hand.

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
# account have none, and the name is not the test because `root` fits the
# single-label username rule.
is_member() {
	[ -d "$1/Maildir" ]
}

# is_bcrypt <hash>: exactly the 60 characters bcrypt writes and BSD auth reads.
# The length and the full character set are checked, not only the prefix: a
# trailing `:0:0` would otherwise become the next field of master.passwd.
is_bcrypt() {
	[ "${#1}" -eq 60 ] || return 1
	case "$1" in
	\$2[aby]\$[0-9][0-9]\$*) ;;
	*) return 1 ;;
	esac
	case "${1#\$2?}" in
	*[!A-Za-z0-9\$./]*) return 1 ;;
	esac
	return 0
}

# set_hash <username>: replace that account's password field in master.passwd and
# rebuild the databases. `hash` is read from the caller's environment, never from
# argv; the private copy is written under the same directory so the final rename
# cannot cross a filesystem.
set_hash() {
	user="$1"
	master="${MASTER_PASSWD:-/etc/master.passwd}"
	mkdb="${PWD_MKDB:-pwd_mkdb}"
	dir=${master%/*}
	[ "$dir" = "$master" ] && dir=.
	hashfile=$(mktemp "$dir/.mail-password-hash.XXXXXX") || die "cannot make a private hash file"
	tmp=$(mktemp "$dir/.master.passwd.XXXXXX") || {
		rm -f "$hashfile"
		die "cannot make a private master.passwd copy"
	}
	trap 'rm -f "$hashfile" "$tmp"' EXIT HUP INT TERM
	chmod 0600 "$hashfile" "$tmp"
	printf '%s\n' "$hash" > "$hashfile" || die "cannot write the private hash file"
	count=$(awk -F: -v u="$user" '$1 == u { n++ } END { print n + 0 }' "$master")
	[ "$count" -eq 1 ] || die "there is no single master.passwd entry for $user"
	awk -F: -v u="$user" '
		BEGIN { OFS = ":" }
		NR == FNR { password = $0; next }
		$1 == u { $2 = password }
		{ print }
	' "$hashfile" "$master" > "$tmp" || die "cannot build the new master.passwd"
	"$mkdb" -p -u "$user" "$tmp" || die "pwd_mkdb refused the new password database"
	mv "$tmp" "$master" || die "cannot install the new master.passwd"
	rm -f "$hashfile"
	trap - EXIT HUP INT TERM
}

self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$(dirname "$0")/lib.sh"
	self_test_begin
	old='$2b$12$abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstu'
	new='$2b$13$abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstu'
	check "a bcrypt hash is accepted" \
		"$(is_bcrypt "$old" && printf yes || printf no)" yes
	check "the 2a and 2y variants are too" \
		"$(is_bcrypt '$2a$10$abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstu' && is_bcrypt '$2y$11$abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstu' && printf yes || printf no)" yes
	check "a plaintext is not a hash" "$(is_bcrypt 'correct horse battery' && printf yes || printf no)" no
	check "an empty value is not a hash" "$(is_bcrypt '' && printf yes || printf no)" no
	check "a crypt hash is not bcrypt" "$(is_bcrypt '$6$salt$hash' && printf yes || printf no)" no
	check "a two-digit cost is required" "$(is_bcrypt '$2b$1$abc' && printf yes || printf no)" no
	check "a hash with a trailing field is refused" \
		"$(is_bcrypt "$old:0:0" && printf yes || printf no)" no
	check "a hash with a newline is refused" \
		"$(is_bcrypt "$old
extra" && printf yes || printf no)" no

	# The stdin and no-argv contract, against a private master.passwd and a
	# pwd_mkdb that records its own argv. The hash must reach the file and never
	# the command line.
	# shellcheck disable=SC2154 # set by self_test_begin
	tree=$self_test_work
	master=$tree/master.passwd
	printf 'root:%s:0:0::0:0:root:/root:/bin/ksh\nalice:%s:1000:1000::0:0:Alice:/home/alice:/bin/ksh\n' \
		"$old" "$old" > "$master"
	mkdb_log=$tree/mkdb.argv
	cat > "$tree/pwd_mkdb" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$MKDB_LOG"
STUB
	chmod 0700 "$tree/pwd_mkdb"
	export MKDB_LOG=$mkdb_log
	MASTER_PASSWD=$master PWD_MKDB=$tree/pwd_mkdb
	hash=$new
	printf '%s\n' "$hash" | set_hash alice
	check "the stdin hash reached master.passwd" \
		"$(awk -F: '$1 == "alice" { print $2 }' "$master")" "$new"
	check "the root entry was left alone" \
		"$(awk -F: '$1 == "root" { print $2 }' "$master")" "$old"
	check "pwd_mkdb was asked for that user" \
		"$(grep -c -- '-u alice' "$mkdb_log")" 1
	check "the hash never reached a process argument" \
		"$(grep -F -c -- "$hash" "$mkdb_log")" 0
	unset MASTER_PASSWD PWD_MKDB MKDB_LOG
	self_test_end
}

case "${1:-}" in
--self-test) self_test ;;
esac

[ "$#" -eq 1 ] || die "usage: printf '%s\\n' <bcrypt-hash> | ksh $0 <username>"
user="$1"
IFS= read -r hash || die "no bcrypt hash on stdin"
[ -n "$hash" ] || die "the bcrypt hash on stdin is empty"
if IFS= read -r extra; then
	: "$extra"
	die "stdin carries more than one line"
fi
is_bcrypt "$hash" || die "stdin is not one bcrypt hash, so nothing was written to $user"
id -u "$user" >/dev/null 2>&1 || die "there is no account named $user"
home=$(getent passwd "$user" | cut -d: -f6)
if [ -z "$home" ] || ! is_member "$home"; then
	die "$user has no Maildir, so it is not a member account name; nothing was written"
fi
set_hash "$user"
printf 'set-mail-password: wrote the stored hash for %s\n' "$user"
