#!/bin/ksh
# kyriakon-authcheck: verify one member's mail password, and write the proof a
# page session is trusted by.
#
# This is the whole of the one `doas` rule the control plane needs:
#
#   permit nopass _onboard as root cmd /usr/local/libexec/kyriakon-authcheck
#
# `doas.conf(5)` matches the argument list literally, so a rule naming
# `cmd doveadm args auth test` would refuse the username the check has to pass
# and every login would be denied. The rule therefore authorises this program,
# which takes the username and the proof directory, reads the password from
# stdin so it never appears in `ps`, refuses a name that is not a member
# account, and runs the one doveadm subcommand. There is no way from here to run
# another.
#
# The handler runs unprivileged and writes `sessions/<id>.json` itself, so that
# record cannot prove a login. On success this script, as root, writes one file
# in the proof directory naming the account and an expiry, and prints the
# file's random token on stdout. The handler stores the token in the session
# record and cannot mint one; the drain reads the file back and trusts only it.
# The directory is root-owned 0700 (scripts/deploy-control.sh makes it), so the
# handler can neither write a proof nor replace one.
#
# Installed by scripts/deploy-control.sh at /usr/local/libexec/kyriakon-authcheck,
# mode 0755, root-owned.
#
# Usage:
#   kyriakon-authcheck <username> [proof-dir]   # password on stdin
#   ksh kyriakon-authcheck --self-test
#
# Exit: 0 the password is correct and a proof was written; 1 it is not,
# including a name with no member account record, or the proof could not be
# written; 64 usage or a username shape this platform could not have made. The
# handler treats every non-zero code as a refusal.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

# The production proof directory, matching `session::PROOF_DIR` and the
# `proof_dir` value in both onboarding configs. The handler may pass another
# only in a test; the drain reads its own configured directory either way.
proof_dir_default=/var/db/kyriakon/logins

# The page session's lifetime, in seconds: `session::TTL_HOURS` is twelve. A
# proof that outlived the session it was minted for would be evidence for
# nothing.
proof_ttl=43200

# The control store, matching the handler's `store_root`. `accounts/` under it
# is root-owned 0750 (scripts/control-store.sh), and the drain writes one
# `account.json` per member account, so the record is the roster of the accounts
# this platform made.
store_root=/var/db/onboard

# The failed-login records: one file per member name, each line an epoch
# timestamp. Root-owned 0700, made by scripts/deploy-control.sh next to the
# proofs. Ten failures in fifteen minutes bound the guesses per name, which the
# handler's per-address bucket cannot do for a distributed run. Older lines are
# dropped on every check, so the file stays small and a member who mistyped is
# clear again when the window passes.
attempts_dir=/var/db/kyriakon/login-attempts
attempt_window=900
attempt_limit=10

die() {
	printf 'kyriakon-authcheck: %s\n' "$*" >&2
	exit 64
}

fail() {
	printf 'kyriakon-authcheck: %s\n' "$*" >&2
	exit 1
}

# Whether `dir` is the root-owned 0700 directory the deploy makes. A directory
# the handler could write would let it plant or replace a proof, so the check
# refuses rather than trusting where it was pointed.
root_proof_dir() {
	[ -d "$1" ] || return 1
	[ "$(stat -f '%u' "$1")" -eq 0 ] || return 1
	[ "$(stat -f '%Lp' "$1" | sed 's/^0*//')" = "700" ]
}

# Whether `name` is an account this platform made. Only those have a record at
# `accounts/<name>/account.json` in the control store; root, `_onboard` and the
# other system accounts have none, and neither does a guessed name. This runs
# before doveadm because bsdauth answers for every system account that has a
# password, the operator's own included: without the gate the form verifies the
# operator's system password and sets a session for it.
member_account() {
	[ -f "$store_root/accounts/$1/account.json" ]
}

# Whether `dir` is the root-owned 0700 directory the deploy makes for the
# failed-login records. A directory the handler could write would let it erase
# its own failures, so the throttle only counts where it cannot.
attempts_dir_ready() {
	[ -d "$1" ] || return 1
	[ "$(stat -f '%u' "$1")" -eq 0 ] || return 1
	[ "$(stat -f '%Lp' "$1" | sed 's/^0*//')" = "700" ]
}

# attempts_file <username>: the record for one member. The directory is root's
# and the name passed the charset check, so this is a path this code made.
attempts_file() {
	printf '%s/%s' "$attempts_dir" "$1"
}

# prune_attempts <file>: drop the lines older than the window and print how many
# are left. Rewriting on every check keeps the file bounded by the window's
# failures.
prune_attempts() {
	typeset prune_file=$1 prune_cutoff prune_kept
	[ -f "$prune_file" ] || { printf '0'; return 0; }
	prune_cutoff=$(( $(date +%s) - attempt_window ))
	prune_kept=$(awk -v cutoff="$prune_cutoff" '$1 ~ /^[0-9]+$/ && $1 > cutoff' "$prune_file") || {
		printf '0'
		return 0
	}
	if [ -z "$prune_kept" ]; then
		rm -f "$prune_file"
		printf '0'
		return 0
	fi
	printf '%s\n' "$prune_kept" > "$prune_file" || {
		printf '0'
		return 0
	}
	printf '%s\n' "$prune_kept" | wc -l | tr -d ' '
}

# throttled <username>: zero when this member has used up the window's failures.
# The caller answers it as a wrong password and does not run doveadm.
throttled() {
	[ "$(prune_attempts "$(attempts_file "$1")")" -ge "$attempt_limit" ]
}

record_failure() {
	printf '%s\n' "$(date +%s)" >>"$(attempts_file "$1")" 2>/dev/null || true
}

clear_failures() {
	rm -f "$(attempts_file "$1")" 2>/dev/null || true
}

# authenticate <username>: the one doveadm subcommand. A function so the
# self-test can stand in for it and count the calls, which is what proves a
# refused name never reaches it. The path is a literal, because an environment
# override would let the unprivileged caller run any binary as root.
authenticate() {
	/usr/local/bin/doveadm auth test "$1" >/dev/null
}

# mint_proof <dir> <username> — write one proof and print its token. The token
# is 32 random bytes as hex, so it is a filename this code chooses and not one a
# caller supplies; the file is 0600 under the directory's 0700.
mint_proof() {
	[ -d "$1" ] || return 1
	token=$(openssl rand -hex 32) || return 1
	[ "${#token}" -eq 64 ] || return 1
	expires=$(( $(date +%s) + proof_ttl ))
	(
		umask 077
		printf '{"username":"%s","expires":%s}\n' "$2" "$expires" > "$1/$token"
	) || return 1
	printf '%s\n' "$token"
}

# login_check <username> <proof-dir>: the whole decision, in the order that
# matters. A name the platform could not have made is the usage answer, a name
# with no member account record is the wrong-password answer and never reaches
# doveadm, a member past the window's failures is the same wrong-password answer
# and also never reaches doveadm, and only then is the password checked. The
# password is read from stdin by doveadm itself, so it is never an argument and
# never written anywhere. A dovecot that cannot answer exits non-zero, which the
# handler reads as a refusal rather than as an admission. Its own output is
# discarded: stdout carries the proof token and nothing else.
login_check() {
	typeset login_user=$1 login_dir=$2 login_counting=off
	valid_localpart "$login_user" || die "not a member username: $login_user"
	member_account "$login_user" || exit 1
	root_proof_dir "$login_dir" \
		|| fail "$login_dir is not the root-owned 0700 login proof directory; run scripts/deploy-control.sh"
	# The rate bound. Only a member's failures are recorded: a name outside the
	# roster is already answered for free, so a guess cannot fill the directory.
	# Without the deployed directory the throttle is skipped, because a rate
	# bound must not refuse every member on a box that has not run the deploy.
	if attempts_dir_ready "$attempts_dir"; then
		if throttled "$login_user"; then
			exit 1
		fi
		login_counting=on
	fi
	if authenticate "$login_user"; then
		if [ "$login_counting" = on ]; then
			clear_failures "$login_user"
		fi
	else
		if [ "$login_counting" = on ]; then
			record_failure "$login_user"
		fi
		exit 1
	fi
	token=$(mint_proof "$login_dir" "$login_user") \
		|| fail "cannot write the login proof in $login_dir"
	printf '%s\n' "$token"
}

self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	work=$self_test_work
	check "a member shape passes" \
		"$(valid_localpart 'theophilus-1' && printf yes || printf no)" yes
	check "an uppercase letter is refused" \
		"$(valid_localpart 'Theophilus' && printf yes || printf no)" no
	check "a leading dot is refused" \
		"$(valid_localpart '.theophilus' && printf yes || printf no)" no
	check "a slash is refused" \
		"$(valid_localpart 'theo/philus' && printf yes || printf no)" no
	check "31 characters are accepted" \
		"$(valid_localpart 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' && printf yes || printf no)" yes
	check "32 characters are refused" \
		"$(valid_localpart 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' && printf yes || printf no)" no

	token=$(mint_proof "$work" 'theophilus-1')
	check "a proof token is 64 lowercase hex characters" \
		"$(printf '%s' "$token" | grep -cE '^[0-9a-f]{64}$')" "1"
	check "the proof names the account" \
		"$(grep -c '"username":"theophilus-1"' "$work/$token")" "1"
	check "the proof carries an expiry" \
		"$(grep -cE '"expires":[0-9]+' "$work/$token")" "1"
	check "the proof is readable only by its owner" \
		"$(stat -f '%Lp' "$work/$token" | sed 's/^0*//')" "600"
	check "a second login mints a different token" \
		"$([ "$(mint_proof "$work" 'theophilus-1')" = "$token" ] && printf same || printf different)" \
		different
	check "a missing directory mints nothing" \
		"$(mint_proof "$work/absent" theophilus-1 >/dev/null 2>&1 && printf yes || printf no)" no
	# The runner's own temp directory is 0700 and not root's, which is the
	# misconfiguration this check exists to refuse on the box. A root run's mktemp
	# is root's own, so make one owned by somebody else for that case; `nobody` is
	# uid 32767 on both OpenBSD and macOS.
	foreign=$work
	if [ "$(id -u)" -eq 0 ]; then
		foreign=$work/foreign
		mkdir "$foreign"
		chown 32767 "$foreign"
		chmod 0700 "$foreign"
	fi
	check "a directory not owned by root is refused" \
		"$(root_proof_dir "$foreign" && printf yes || printf no)" no

	# The throttle directory has the same ownership rule as the proof
	# directory, because a handler-writable one would let the caller erase its
	# own failures. The runner's temp dir is not root's, and a root run's mktemp
	# is, so make one owned by somebody else for that case.
	foreign_attempts=$work
	if [ "$(id -u)" -eq 0 ]; then
		foreign_attempts=$work/attempts-foreign
		mkdir "$foreign_attempts"
		chown 32767 "$foreign_attempts"
		chmod 0700 "$foreign_attempts"
	fi
	check "a throttle directory not owned by root is refused" \
		"$(attempts_dir_ready "$foreign_attempts" && printf yes || printf no)" no

	# The member gate. The store is the handler's own, so the test builds a
	# fixture with one member record, then runs the whole login path with the
	# proof-directory check and doveadm stood in for. The call count is the
	# assertion that a refused name never reached the password check.
	store_root="$work/store"
	mkdir -p "$store_root/accounts/theophilus-1"
	printf '{"version":1}\n' >"$store_root/accounts/theophilus-1/account.json"
	check "a member account is in the roster" \
		"$(member_account theophilus-1 && printf yes || printf no)" yes

	attempts_dir="$work/attempts"
	mkdir "$attempts_dir"
	# The ownership case above ran the real check; the runner's temp dir is not
	# root's, so the test path stands this in.
	attempts_dir_ready() { return 0; }

	doveadm_log="$work/doveadm-calls"
	: >"$doveadm_log"
	auth_rc=0
	authenticate() {
		printf '%s\n' "$1" >>"$doveadm_log"
		return "$auth_rc"
	}
	# shellcheck disable=SC2329 # called through login_check
	root_proof_dir() { return 0; }

	# A system account that passes the shape check gets the wrong-password code,
	# so nothing distinguishes it from a member's wrong password.
	for name in root oliver theophilus-2; do
		status=0
		( login_check "$name" "$work" ) >/dev/null 2>&1 || status=$?
		check "$name is refused as a wrong password" "$status" "1"
	done
	check "a refused name writes no failure record" \
		"$([ -e "$(attempts_file root)" ] && printf present || printf none)" none
	# `_onboard` never passes the shape check, so it stops one step earlier with
	# the usage code; the handler renders the same refusal either way, and the
	# assertion that matters is the doveadm count below.
	status=0
	( login_check _onboard "$work" ) >/dev/null 2>&1 || status=$?
	check "_onboard is refused" "$status" "64"
	check "no refused name reached doveadm" "$(grep -c . "$doveadm_log")" "0"

	token=$(login_check theophilus-1 "$work")
	check "a member account reaches doveadm" \
		"$(grep -c '^theophilus-1$' "$doveadm_log")" "1"
	check "a member account still gets the proof token" \
		"$(printf '%s' "$token" | grep -cE '^[0-9a-f]{64}$')" "1"

	# The other half of "indistinguishable": a member's wrong password is the
	# same exit code as a non-member name, and it is the one thing the throttle
	# counts.
	auth_rc=1
	status=0
	( login_check theophilus-1 "$work" ) >/dev/null 2>&1 || status=$?
	check "a member's wrong password gets the same answer" "$status" "1"
	check "a wrong password records one failure" \
		"$(prune_attempts "$(attempts_file theophilus-1)")" "1"

	# Nine failures, one short of the limit of ten, then the right password: the
	# member is admitted and the success clears the record.
	clear_failures theophilus-1
	i=0
	while [ "$i" -lt 9 ]; do
		( login_check theophilus-1 "$work" ) >/dev/null 2>&1 || true
		i=$(( i + 1 ))
	done
	check "nine failures are recorded" \
		"$(prune_attempts "$(attempts_file theophilus-1)")" "9"
	before=$(grep -c '^theophilus-1$' "$doveadm_log")
	auth_rc=0
	token=$(login_check theophilus-1 "$work")
	check "one short of the limit, the right password is admitted" \
		"$(printf '%s' "$token" | grep -cE '^[0-9a-f]{64}$')" "1"
	check "a success clears the failures" \
		"$([ -e "$(attempts_file theophilus-1)" ] && printf present || printf cleared)" cleared
	check "the admitted attempt reached doveadm" \
		"$(( $(grep -c '^theophilus-1$' "$doveadm_log") - before ))" "1"

	# At the limit, even the right password is refused before doveadm.
	auth_rc=1
	i=0
	while [ "$i" -lt "$attempt_limit" ]; do
		( login_check theophilus-1 "$work" ) >/dev/null 2>&1 || true
		i=$(( i + 1 ))
	done
	before=$(grep -c '^theophilus-1$' "$doveadm_log")
	auth_rc=0
	status=0
	( login_check theophilus-1 "$work" ) >/dev/null 2>&1 || status=$?
	check "a throttled name gets the wrong-password code" "$status" "1"
	check "a throttled name does not reach doveadm" \
		"$(( $(grep -c '^theophilus-1$' "$doveadm_log") - before ))" "0"

	# The window bounds the lockout. A stale line is dropped, so the member is
	# admitted again, and a record wholly outside the window is removed rather
	# than left to grow.
	record=$(attempts_file theophilus-1)
	{
		printf '%s\n' "$(( $(date +%s) - attempt_window - 1 ))"
		printf '%s\n' "$(date +%s)"
	} >"$record"
	check "pruning keeps only the attempt inside the window" \
		"$(prune_attempts "$record")" "1"
	printf '%s\n' "$(( $(date +%s) - attempt_window - 1 ))" >"$record"
	auth_rc=0
	token=$(login_check theophilus-1 "$work")
	check "a member is admitted again once the window has passed" \
		"$(printf '%s' "$token" | grep -cE '^[0-9a-f]{64}$')" "1"
	printf '%s\n' "$(( $(date +%s) - attempt_window - 1 ))" >"$record"
	check "a record outside the window is pruned away" \
		"$(prune_attempts "$record")" "0"
	check "the pruned record is removed" \
		"$([ -e "$record" ] && printf present || printf gone)" gone
	self_test_end
}

case "${1:-}" in
--self-test)
	# The self-test mints in its own temp directory as whoever runs it; only the
	# production path checks the ownership the deploy sets.
	self_test
	exit 0
	;;
esac

[ "$#" -ge 1 ] && [ "$#" -le 2 ] \
	|| die "usage: kyriakon-authcheck <username> [proof-dir] (password on stdin)"
login_check "$1" "${2:-$proof_dir_default}"
