#!/bin/ksh
# atomic-fs.sh: the one staged-write shape and the one mkdir lock, sourced by
# scripts/lib.sh. Every writer in scripts/ uses these rather than a redirect or
# a truncating install over a live file: a reader must see the old file or the
# whole new one, and a killed run must leave the installed file as it was.
#
# OpenBSD has no flock(1) or lockf(1); the shell-side lock is the mkdir below.

# write_atomic <dst> <owner:group|""> <mode> <src|body-fn> [validator...]
#
# Write <dst> atomically from a source file or from a function/command that
# prints the whole file on stdout. The candidate is a sibling created under
# umask 077, so a private key is never briefly world-readable even before the
# chmod; it is compared with <dst> and left alone when the bytes match; then it
# is chowned, chmodded and renamed into place.
#
# <owner:group> may be empty to leave the candidate's ownership to the caller's
# euid (root in every deploy). A symlink or a hard-linked <dst> is refused:
# replacing either is somebody else's file. A validator is a command and its
# flags, with the candidate appended (pfctl -nf, httpd -n -f, smtpd -n -f), and
# its refusal leaves <dst> untouched.
#
# Sets atomic_changed to yes or no. Returns 0 when <dst> is now the candidate or
# already held those bytes, non-zero after printing why <dst> was left alone.
write_atomic() {
	typeset dst="$1" owner="$2" mode="$3" src="$4"
	shift 4
	typeset dir base candidate links
	case "$dst" in
	*/*) dir=${dst%/*}; base=${dst##*/} ;;
	*) dir=.; base=$dst ;;
	esac
	if [ -L "$dst" ]; then
		printf 'refusing to write %s: it is a symlink\n' "$dst" >&2
		return 1
	fi
	if [ -e "$dst" ]; then
		links=$(stat -f %l "$dst" 2>/dev/null || stat -c %h "$dst" 2>/dev/null || printf '')
		if [ "$links" != 1 ]; then
			printf 'refusing to write %s: it has %s hard links\n' "$dst" "$links" >&2
			return 1
		fi
	fi
	candidate=$(umask 077; mktemp "$dir/.$base.XXXXXX") || {
		printf 'could not create a candidate beside %s\n' "$dst" >&2
		return 1
	}
	if [ -f "$src" ]; then
		if ! cat "$src" >"$candidate"; then
			rm -f "$candidate"
			printf 'could not read %s; %s left as it was\n' "$src" "$dst" >&2
			return 1
		fi
	else
		if ! ( umask 077; "$src" >"$candidate" ); then
			rm -f "$candidate"
			printf 'could not write %s for %s; %s left as it was\n' \
				"$src" "$dst" "$dst" >&2
			return 1
		fi
	fi
	if [ "${ATOMIC_REPLACE:-no}" != yes ] &&
		[ -f "$dst" ] && cmp -s "$candidate" "$dst"; then
		rm -f "$candidate"
		atomic_changed=no
		return 0
	fi
	if [ "$#" -gt 0 ] && ! "$@" "$candidate" >/dev/null; then
		rm -f "$candidate"
		printf '%s fails its own check (%s); %s is unchanged\n' \
			"$candidate" "$1" "$dst" >&2
		return 1
	fi
	if [ -n "$owner" ] && ! chown "$owner" "$candidate"; then
		rm -f "$candidate"
		printf 'could not set the owner of %s; %s left as it was\n' "$candidate" "$dst" >&2
		return 1
	fi
	if ! chmod "$mode" "$candidate"; then
		rm -f "$candidate"
		printf 'could not set the mode of %s; %s left as it was\n' "$candidate" "$dst" >&2
		return 1
	fi
	if ! mv "$candidate" "$dst"; then
		rm -f "$candidate"
		printf 'could not rename %s into place; %s left as it was\n' "$candidate" "$dst" >&2
		return 1
	fi
	atomic_changed=yes
	return 0
}

# install_staged <src> <dst> [install flags...]: install one file without ever
# leaving a partial one at <dst>. Kept as the name the deploys already use; the
# write itself is write_atomic. Only -m, -o and -g are honoured, which is every
# flag the call sites pass.
install_staged() {
	typeset staging_src="$1" staging_dst="$2" staging_mode=0644 staging_owner=""
	typeset staging_replace=${ATOMIC_REPLACE:-no} staging_rc=0
	shift 2
	while [ "$#" -gt 0 ]; do
		case "$1" in
		-m) staging_mode="$2"; shift 2 ;;
		-o) staging_owner="$2"; shift 2 ;;
		-g) staging_owner="${staging_owner%%:*}:$2"; shift 2 ;;
		*) shift ;;
		esac
	done
	ATOMIC_REPLACE=yes
	write_atomic "$staging_dst" "$staging_owner" "$staging_mode" "$staging_src" || staging_rc=$?
	ATOMIC_REPLACE=$staging_replace
	return "$staging_rc"
}


# write_generated <target> <body-fn> [<cert> <key>]: write <target> from the
# body function, atomically, and only when the bytes differ. Sets conf_changed
# to yes or no, the answer the callers print and the --web pass keys off.
#
# <cert> and <key> guard a relayd pair: the guard trips when the certificate is
# present and not empty and the key is not, the half pair that passes `httpd -n`
# and fails `relayd -n`.
write_generated() {
	typeset gen_target="$1" gen_body="$2" gen_cert="${3:-}" gen_key="${4:-}"
	if [ -n "$gen_cert" ] && [ -s "$gen_cert" ] && [ ! -s "$gen_key" ]; then
		printf '%s is there and %s is not, so %s was left alone: the relay needs both halves of the pair\n' \
			"$gen_cert" "$gen_key" "$gen_target" >&2
		return 1
	fi
	write_atomic "$gen_target" "" 0644 "$gen_body" || return 1
	# shellcheck disable=SC2034 # the caller reads it
	conf_changed=$atomic_changed
	return 0
}


# install_validated <source> <destination> <checker> [<args>...]: install a
# config to <destination>, run the daemon's own parser over the candidate, then
# rename it onto the live path. A parser that refuses leaves the live file
# exactly as it was and removes the candidate.
install_validated() {
	typeset iv_src="$1" iv_dst="$2"
	shift 2
	write_atomic "$iv_dst" "" 0644 "$iv_src" "$@"
}

# install_smtpd_conf <template> <dkim-domains> <queue-key-file> <destination> [<parser>]
#
# The shipped config with the queue key and the filter's domain list substituted,
# staged beside <destination> and renamed onto it, 0600 because it carries the
# key. Both placeholders are substituted in the one pass. With a fifth argument
# the candidate is parsed before the rename as `"$parser" -n -f <candidate>`.
install_smtpd_conf() {
	typeset conf_template="$1" conf_domains="$2" conf_keyfile="$3" conf_dst="$4" \
		conf_key conf_args conf_candidate conf_replace=${ATOMIC_REPLACE:-no} conf_rc=0
	conf_args=$(dkim_domains_args "$conf_domains") || return 1
	conf_key=$(cat "$conf_keyfile" 2>/dev/null) \
		|| { printf 'could not read the queue key from %s\n' "$conf_keyfile" >&2; return 1; }
	[ -n "$conf_key" ] || { printf '%s holds no queue key\n' "$conf_keyfile" >&2; return 1; }
	if [ "${#conf_key}" -ne 32 ]; then
		printf '%s holds a %s-character queue key, not 32; it is replaced only deliberately: remove it and run scripts/deploy-mail.sh, which discards anything still queued under it\n' \
			"$conf_keyfile" "${#conf_key}" >&2
		return 1
	fi
	conf_candidate=$(mktemp "$conf_dst.XXXXXX") || {
		printf 'could not create a candidate beside %s\n' "$conf_dst" >&2
		return 1
	}
	if ! sed -e "s|REPLACE_ME_QUEUE_KEY|$conf_key|" \
		-e "s|REPLACE_ME_DKIM_DOMAINS|$conf_args|" \
		"$conf_template" > "$conf_candidate"; then
		printf 'could not render %s from %s\n' "$conf_dst" "$conf_template" >&2
		rm -f "$conf_candidate"
		return 1
	fi
	if [ -n "${5:-}" ] && [ "${SMTPD_CONF_CHECK:-yes}" = yes ] \
		&& command -v "$5" >/dev/null 2>&1; then
		if ! "$5" -n -f "$conf_candidate"; then
			printf '%s fails its own syntax check; %s is unchanged\n' \
				"$conf_candidate" "$conf_dst" >&2
			rm -f "$conf_candidate"
			return 1
		fi
	fi
	ATOMIC_REPLACE=yes
	write_atomic "$conf_dst" "" 0600 "$conf_candidate" || conf_rc=$?
	ATOMIC_REPLACE=$conf_replace
	rm -f "$conf_candidate"
	return "$conf_rc"
}


# --- locking ----------------------------------------------------------------
#
# mkdir(2) is the lock: it fails when the directory exists, and nothing else
# needs a base tool. The owner writes its pid inside.
#
# lock_dir <path> [tries] [interval] [max-age]
#
# Returns 0 when acquired, 1 when a live writer holds it, 2 when the path cannot
# be created or the pid cannot be written. A stale lock is reaped by renaming it
# to a unique sibling and only then removing it: two reapers that both saw the
# same dead pid cannot delete each other's fresh lock, because only one rename
# succeeds and the renamed pid is compared with the dead one it observed. A lock
# whose pid is gone, is 0 or 1, is not numeric, or has been held longer than
# max-age (default 30 seconds) is stale.
lock_dir() {
	typeset lock_path="$1" tries=0 limit="${2:-5}" interval="${3:-1}" max_age="${4:-30}"
	typeset reason observed tomb taken
	while [ "$tries" -lt "$limit" ]; do
		if mkdir -m 0700 "$lock_path" 2>/dev/null; then
			if ! printf '%s\n' "$$" >"$lock_path/pid"; then
				rm -rf "$lock_path"
				printf 'could not write the owner pid into %s\n' "$lock_path" >&2
				return 2
			fi
			return 0
		fi
		if [ ! -d "$lock_path" ]; then
			printf 'could not lock %s: cannot create it\n' "$lock_path" >&2
			return 2
		fi
		lock_dir_stale "$lock_path" "$max_age"
		reason=$lock_stale_reason
		observed=$lock_stale_pid
		if [ -n "$reason" ]; then
			# A unique tomb: two reapers race to rename, and only one wins.
			tomb="$lock_path.reap.$$"
			taken=no
			if mv "$lock_path" "$tomb" 2>/dev/null; then
				if [ "$(cat "$tomb/pid" 2>/dev/null || true)" = "$observed" ]; then
					taken=yes
				else
					mv "$tomb" "$lock_path" 2>/dev/null || rm -rf "$tomb"
				fi
			fi
			if [ "$taken" = yes ]; then
				printf 'reaping stale lock %s: %s\n' "$lock_path" "$reason" >&2
				rm -rf "$tomb"
				continue
			fi
		fi
		tries=$((tries + 1))
		[ "$tries" -ge "$limit" ] || sleep "$interval"
	done
	printf 'could not lock %s: it exists and did not clear; remove it if no writer is running\n' \
		"$lock_path" >&2
	return 1
}

# lock_dir_stale <path> [max-age]: set lock_stale_reason to why the lock is not
# held by a live writer, or the empty string when it looks live, and
# lock_stale_pid to the pid it read. The reaper compares that pid after the
# atomic rename. Callers must read the globals in the same shell, not through a
# command substitution.
lock_dir_stale() {
	typeset lock_path="$1" max_age="${2:-30}" pid mtime now age
	lock_stale_pid=''
	lock_stale_reason=''
	[ -d "$lock_path" ] || return 0
	pid=$(cat "$lock_path/pid" 2>/dev/null || true)
	lock_stale_pid=$pid
	case "$pid" in
	'')
		# A lock between mkdir and its pid write: give a fresh one a moment.
		age=$(lock_dir_age "$lock_path")
		if [ -n "$age" ] && [ "$age" -lt 2 ]; then
			return 0
		fi
		lock_stale_reason='the owner pid is not written'
		return 0
		;;
	*[!0-9]*)
		lock_stale_reason="the owner pid \"$pid\" is not a number"
		return 0
		;;
	0 | 1)
		lock_stale_reason="the owner pid $pid is not a writer"
		return 0
		;;
	esac
	if kill -0 "$pid" 2>/dev/null; then
		age=$(lock_dir_age "$lock_path")
		if [ -n "$age" ] && [ "$age" -gt "$max_age" ]; then
			lock_stale_reason="it has been held for $age seconds"
		fi
		# A live owner is holding it, however long the write is taking.
		return 0
	fi
	lock_stale_reason="the owner pid $pid is gone"
	return 0
}

# lock_dir_age <path>: the lock directory's age in seconds, or nothing when stat
# cannot say. OpenBSD and macOS stat use -f, GNU stat uses -c.
lock_dir_age() {
	typeset mtime now
	mtime=$(stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null || printf '')
	[ -n "$mtime" ] || return 0
	now=$(date +%s)
	printf '%s' "$((now - mtime))"
}

# unlock_dir <path>: remove the lock only when this process wrote its pid.
unlock_dir() {
	typeset lock_path="$1"
	[ -d "$lock_path" ] || return 0
	[ "$(cat "$lock_path/pid" 2>/dev/null || true)" = "$$" ] || return 0
	rm -rf "$lock_path"
}


# table_lock <table> [tries] [interval]: the mail tables' lock, with the pid
# file the drain's Rust writer also uses. Returns 0, 1 (live holder) or 2.
table_lock() {
	lock_dir "$1.lock" "${2:-5}" "${3:-1}" 30
}

# table_lock_stale <table>: why <table>.lock is not being held by a live writer,
# one line, or nothing when it is absent or looks live. check-hygiene.sh reads it.
table_lock_stale() {
	lock_dir_stale "$1.lock" 30
	[ -z "$lock_stale_reason" ] || printf '%s\n' "$lock_stale_reason"
}

table_unlock() {
	unlock_dir "$1.lock"
}
