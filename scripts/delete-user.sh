#!/bin/ksh
# delete-user.sh — remove a member, and everything provisioning wrote for them.
#
# Usage:
#   doas ksh scripts/delete-user.sh <username>
#   doas ksh scripts/delete-user.sh --show <username>    report, change nothing
#   ksh scripts/delete-user.sh --self-test               logic only, needs no root
#
# Runs ON the box as root. It is the reverse of the two scripts that make a
# member: add-user.sh, which creates the account, its Maildir and its quota
# record, and provision-member.sh, which builds the tree, installs the upload key
# and the login class, writes the member's line in the mail virtual table, and
# hands the two daemon lanes to scripts of their own.
#
# The order is the spec's (docs/planning/specs/per-member-hosting.md, "Removing a
# member's hosting") and it is not a preference. The daemon configuration goes
# first, the indexes are regenerated and the daemons reloaded, and only then do
# the tree, the certificate material and the account go. A daemon reloaded while
# its index names a file that has already gone keeps its old configuration, and a
# daemon restarted with such an index fails outright, because no daemon in this
# stack can include a directory and an include of a missing file is fatal.
#
# Called by the deletion transition that #241 owns, from the drain, rather than
# by a person. A run with nothing left to remove prints nothing at all: a drain
# and a cron job both keep their output, and a no-op that talks is noise on a
# quiet night.
#
# Not this script's job, and named at the end of a run that did something: the
# store record, the ledger line, the keyring's published set, the backup window
# and the 90-day username hold. Those are the drain's, inside the transition.
#
# The keyring entry on this box is deliberately left where it is.
# check-keyring-drift.sh compares the box's set against the published one and
# raises a signal for a key that is published and missing here, so removing this
# side before the publish pull request lands would raise that signal at the very
# moment the key is meant to be going away. The drain pulls the published set
# through its own token and the check follows it.
#
# The capsule certificate is not touched either: one pair serves every capsule on
# the box (/etc/ssl/capsule-kyriakon.net.crt and its key), so a member's departure
# removes the vhost that named it, not the pair itself. The member's own ACME
# pair, the one issued for their name, does go.
#
# Idempotent: a second run, or a run after one that stopped partway, removes what
# is left and says so. Nothing here is undone by running it twice.

set -euo pipefail

# doas and cron both hand over a minimal PATH, and this script calls install and
# userdel, which live in /usr/sbin. Set it rather than trusting the caller, the
# same line the other box scripts carry.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

script_dir=$(cd "$(dirname "$0")" && pwd)

usage() {
	printf 'usage: doas ksh %s <username>\n' "$0" >&2
	printf '       doas ksh %s --show <username>\n' "$0" >&2
	printf '       ksh %s --self-test\n' "$0" >&2
	exit 2
}

# --- the paths, as variables so the self-test can rebind them ---------------
#
# Every path this script removes is built from the username rather than searched
# for, which is what makes the removal complete and also what makes the two
# guards below necessary. The member's home is not among them: userdel -r takes
# it, Maildir and all.
www_root=${WWW_ROOT:-/home/www}
httpd_d=${HTTPD_D:-/etc/httpd.d}
gmid_d=${GMID_D:-/etc/gmid.d}
acme_d=${ACME_D:-/etc/acme-client.d}
ssl_dir=${SSL_DIR:-/etc/ssl}
ssl_private=${SSL_PRIVATE:-/etc/ssl/private}
virtuals=${VIRTUALS:-/etc/mail/virtuals}

# --- the steps, as functions, so the self-test can replace them -------------
#
# The self-test redefines these four to record what would have been called. Each
# wraps exactly one external command, so what the tests exercise is this script's
# decisions rather than the tools'.
# Whether there is still an account to remove. The whole script is a no-op when
# there is not, which is what makes a second run silent, and a predicate rather
# than a bare id(1) call because the self-test has to answer it too.
account_exists() { id "$user" >/dev/null 2>&1; }

remove_account() { userdel -r "$user"; }
clear_quota() { ksh "$script_dir/quota-apply.sh" --clear "$user"; }
regen_indexes() { ksh "$script_dir/cron-apply.sh" --web; }
restart_smtpd() { rcctl restart smtpd >/dev/null; }

# would <description> <path>: in --show mode, report rather than remove. Returns
# 0 when the caller should keep going (the path is there), 1 when there is
# nothing to do, so the two modes share one body.
would() {
	if [ ! -e "$2" ] && [ ! -L "$2" ]; then
		return 1
	fi
	if [ "$show" = yes ]; then
		printf 'would remove %s (%s)\n' "$2" "$1"
	fi
	return 0
}

# remove_member: the whole job, in the spec's order.
remove_member() {
	did=no
	reindex=no

	# 1. The daemon configuration. Three lanes, each written by a script of its
	# own: the site's vhost, the capsule's server block, and the ACME block that
	# the certificate queue adds for the member's name. Any of them may be
	# absent, since a member with no certificate yet has no ACME block and a
	# member with no site has no vhost.
	for pair in \
		"$httpd_d/$user.kyriakon.net.conf" \
		"$gmid_d/$user.kyriakon.net.conf" \
		"$acme_d/$user.kyriakon.net.conf"
	do
		if would "daemon configuration" "$pair"; then
			if [ "$show" = no ]; then
				rm -f "$pair"
				printf 'removed %s\n' "$pair"
			fi
			did=yes
			reindex=yes
		fi
	done

	# 2. The indexes, before anything they name disappears. One reload for the
	# batch, the same pass provisioning asks for at its end. Skipped when no
	# lane file went, because the pass reloads the daemons and a reload that
	# changes nothing is a service blip for no reason.
	if [ "$reindex" = yes ]; then
		if [ "$show" = yes ]; then
			printf 'would regenerate the indexes and reload httpd and gmid\n'
		else
			regen_indexes
			printf 'regenerated the indexes and reloaded httpd and gmid\n'
		fi
	fi

	# 3. The public tree: the chroot root sshd uses for sftp, and the two
	# directories under it. Root-owned at the top so sshd will chroot into it,
	# and never anything but the member's own name, which the two guards below
	# hold to.
	if would "the public tree" "$public"; then
		if [ "$show" = no ]; then
			rm -rf "$public"
			printf 'removed %s\n' "$public"
		fi
		did=yes
	fi

	# 4. The member's own certificate pair, the one issued for their name. The
	# shared capsule pair stays, and so does the certificate itself, which is
	# left to expire rather than revoked: revocation is an act with a rate limit
	# and nothing promises it.
	for f in "$ssl_dir/$user.kyriakon.net.fullchain.pem" "$ssl_private/$user.kyriakon.net.key"; do
		if would "the member's certificate material" "$f"; then
			if [ "$show" = no ]; then
				rm -f "$f"
				printf 'removed %s\n' "$f"
			fi
			did=yes
		fi
	done

	# 5 and 6. The account, its home and the Maildir inside it, and the allowance
	# record that belongs to it. Both are guarded on the account still being
	# there, which is what makes a second run print nothing and call nothing:
	# userdel(8) fails on a name that is not in the password file, and a drain
	# that runs this every pass must not report a failure it caused itself.
	#
	# -r is the flag that removes the home; -p is the one that preserves the
	# account instead, which is the opposite of what this script is for. userdel
	# rewrites the password database through pwd_mkdb in the background, so for a
	# moment afterwards the account can still be resolved and the file is
	# unavailable for other updates: nothing after this step touches either.
	if account_exists; then
		did=yes
		if [ "$show" = yes ]; then
			printf 'would clear the quota record\n'
		else
			if clear_quota; then
				printf 'cleared the quota record\n'
			else
				printf 'warning: the quota record was not cleared (quota-apply.sh --clear failed)\n' >&2
			fi
		fi
		if [ "$show" = yes ]; then
			printf 'would remove the account %s, its home and its Maildir\n' "$user"
		else
			remove_account
			printf 'removed the account %s, its home and its Maildir\n' "$user"
		fi
	fi

	# 7. The member's own line in the mail virtual table, which provisioning
	# wrote and nothing else removes. A lookup that finds nothing there has
	# nothing to expand to, so the address starts bouncing at RCPT time, which is
	# the point: a deleted member is not a catch-all.
	if [ -f "$virtuals" ]; then
		if [ "$show" = yes ]; then
			if awk -v u="$user" -F: '$1 ~ ("^" u "@")' "$virtuals" | grep -q .; then
				printf 'would remove the address lines for %s@\n' "$user"
			fi
		else
			if remove_own_addresses; then
				printf 'removed the address lines for %s@ from %s\n' "$user" "$virtuals"
				restart_smtpd
				printf 'restarted smtpd, which reads the table at start\n'
			fi
		fi
		# An address that points at this member without being theirs is a body's
		# alias or the platform's own. Removing it silently would break someone
		# else's mail, and leaving it silently would leave a virtual entry with
		# nothing to deliver to, so it is printed and left alone.
		aliases=$(awk -v u="$user" -F: '{ t = $2; gsub(/^[ \t]+|[ \t]+$/, "", t); if (t == u && $1 !~ ("^" u "@")) print $1 }' "$virtuals" | tr '\n' ' ')
		if [ -n "$aliases" ]; then
			printf 'note: %s point at %s and were left alone; they now deliver nowhere\n' "$aliases" "$user" >&2
			printf '  Re-point or remove them in %s and restart smtpd.\n' "$virtuals" >&2
		fi
	fi

	# The last line, and the reason a run that did something is not silent.
	if [ "$did" = yes ] && [ "$show" = no ]; then
		printf 'not this script'"'"'s: the store record, the ledger line, the keyring'"'"'s published\n'
		printf '  set, the backup window and the 90-day username hold. All the drain'"'"'s.\n'
	fi
	return 0
}

# remove_own_addresses: drop this member's own lines from the virtual table.
# Returns 0 when the file changed and 1 when it did not, which is what decides
# whether smtpd needs restarting. The table is rewritten rather than edited in
# place so a crash cannot leave it half written, a copy of the one it replaces is
# kept, and the mode and ownership are set explicitly because a file smtpd reads
# with the wrong owner is a table that does not load.
remove_own_addresses() {
	stamp=$(date +%Y%m%d%H%M%S)
	# Root sets the owner explicitly, because a table smtpd reads with the wrong
	# owner is a table that does not load. The self-test runs unprivileged in a
	# throwaway tree, where chown cannot and need not happen.
	# shellcheck disable=SC2086  # intentional splitting: two flags, or none
	owner_flags=$([ "$(id -u)" -eq 0 ] && printf '%s' "-o root -g wheel")
	candidate="$virtuals.kyriakon.$$"
	awk -v u="$user" -F: '$1 !~ ("^" u "@")' "$virtuals" >"$candidate"
	if cmp -s "$virtuals" "$candidate"; then
		rm -f "$candidate"
		return 1
	fi
	cp -p "$virtuals" "$virtuals.$stamp.bak"
	# shellcheck disable=SC2086
	install -m 0644 $owner_flags "$candidate" "$virtuals"
	rm -f "$candidate"
	printf 'kept %s.%s.bak\n' "$virtuals" "$stamp"
	return 0
}

# --- the self-test ----------------------------------------------------------
#
# Rebind the paths to a throwaway tree and replace the four steps that need root,
# so the logic runs anywhere: no root, no account, no daemon, nothing outside
# TMPDIR. What it checks is this script's own decisions, not the tools'.
self_test() {
	tree=$(mktemp -d "${TMPDIR:-/tmp}/delete-user.XXXXXX") || exit 1
	trap 'rm -rf "$tree"' EXIT

	case_dir="$tree/calls"
	mkdir -p "$case_dir"
	WWW_ROOT="$tree/home/www"
	HTTPD_D="$tree/etc/httpd.d"; GMID_D="$tree/etc/gmid.d"; ACME_D="$tree/etc/acme-client.d"
	SSL_DIR="$tree/etc/ssl"; SSL_PRIVATE="$tree/etc/ssl/private"
	VIRTUALS="$tree/etc/mail/virtuals"
	www_root="$WWW_ROOT"; httpd_d="$HTTPD_D"
	gmid_d="$GMID_D"; acme_d="$ACME_D"; ssl_dir="$SSL_DIR"
	ssl_private="$SSL_PRIVATE"; virtuals="$VIRTUALS"

	mkdir -p "$httpd_d" "$gmid_d" "$acme_d" "$ssl_private" "$www_root" "$(dirname "$virtuals")"

	failures=0
	check() {
		if [ "$2" = "$3" ]; then
			printf 'ok   %s\n' "$1"
		else
			printf 'FAIL %s (got %s, wanted %s)\n' "$1" "$2" "$3" >&2
			failures=$((failures + 1))
		fi
	}
	# The predicate and the steps, recorded rather than run.
	account_exists() { return 0; }
	remove_account() { printf 'userdel -r %s\n' "$user" >>"$case_dir/calls"; }
	clear_quota() { printf 'quota-apply --clear %s\n' "$user" >>"$case_dir/calls"; }
	regen_indexes() { printf 'cron-apply --web\n' >>"$case_dir/calls"; }
	restart_smtpd() { printf 'rcctl restart smtpd\n' >>"$case_dir/calls"; }

	# remove_member is called directly, so the root check, the charset check and
	# the two guards on the public tree are not in the way: they are the caller's
	# business and the real entry point still runs them.
	: >"$case_dir/calls"
	user=alice
	show=no
	public="$www_root/$user.kyriakon.net"
	mkdir -p "$public/www"
	: >"$httpd_d/$user.kyriakon.net.conf"
	: >"$gmid_d/$user.kyriakon.net.conf"
	: >"$acme_d/$user.kyriakon.net.conf"
	: >"$ssl_dir/$user.kyriakon.net.fullchain.pem"
	: >"$ssl_private/$user.kyriakon.net.key"
	{
		printf 'alice@kyriakon.net: alice\n'
		printf 'secretary@parish.example: alice\n'
		printf 'oliver@kyriakon.net: oliver\n'
	} >"$virtuals"

	remove_member >"$tree/first.out" 2>"$tree/first.err"
	check "the vhost went" "$([ -e "$httpd_d/$user.kyriakon.net.conf" ] && echo present || echo gone)" gone
	check "the capsule block went" "$([ -e "$gmid_d/$user.kyriakon.net.conf" ] && echo present || echo gone)" gone
	check "the acme block went" "$([ -e "$acme_d/$user.kyriakon.net.conf" ] && echo present || echo gone)" gone
	check "the tree went" "$([ -d "$public" ] && echo present || echo gone)" gone
	check "the member's certificate went" "$([ -e "$ssl_dir/$user.kyriakon.net.fullchain.pem" ] && echo present || echo gone)" gone
	check "the member's key went" "$([ -e "$ssl_private/$user.kyriakon.net.key" ] && echo present || echo gone)" gone
	check "the member's own address went" "$(awk '/^alice@/' "$virtuals" | wc -l | tr -d ' ')" 0
	check "someone else's address stayed" "$(awk '/^oliver@/' "$virtuals" | wc -l | tr -d ' ')" 1
	check "the alias into them stayed" "$(awk '/^secretary@/' "$virtuals" | wc -l | tr -d ' ')" 1
	check "and the note names it" "$(grep -c 'secretary@parish.example' "$tree/first.err")" 1
	check "the order starts with the indexes" "$(awk 'NR == 1' "$case_dir/calls")" 'cron-apply --web'
	check "and the account goes last of the tools" "$(awk 'NR == 3' "$case_dir/calls")" 'userdel -r alice'
	check "smtpd restarted once" "$(grep -c 'rcctl restart smtpd' "$case_dir/calls")" 1

	# A second run against the same tree must do nothing and say nothing.
	account_exists() { return 1; }
	: >"$case_dir/calls"
	remove_member >"$tree/second.out" 2>"$tree/second.err"
	check "a second run is silent on stdout" "$(wc -c <"$tree/second.out" | tr -d ' ')" 0
	check "a second run calls no tools" "$(wc -c <"$case_dir/calls" | tr -d ' ')" 0

	# --show removes nothing and reports what it would.
	account_exists() { return 0; }
	: >"$case_dir/calls"
	mkdir -p "$public"
	: >"$httpd_d/$user.kyriakon.net.conf"
	show=yes
	remove_member >"$tree/third.out" 2>&1
	check "--show leaves the vhost" "$([ -e "$httpd_d/$user.kyriakon.net.conf" ] && echo present || echo gone)" present
	check "--show leaves the tree" "$([ -d "$public" ] && echo present || echo gone)" present
	check "--show names each path it would remove" "$(grep -c '^would remove /' "$tree/third.out")" 2
	check "and names the account" "$(grep -c 'would remove the account alice' "$tree/third.out")" 1
	check "--show calls no tools" "$(wc -c <"$case_dir/calls" | tr -d ' ')" 0

	printf '\n%s\n' "$([ "$failures" -eq 0 ] && echo 'self-test passed' || echo "self-test FAILED: $failures")"
	rm -rf "$tree"
	trap - EXIT
	[ "$failures" -eq 0 ]
}

# --- the entry --------------------------------------------------------------

self_test_mode=no
case "${1:-}" in
--self-test) self_test_mode=yes ;;
--show) show=yes; shift ;;
-h | --help) usage ;;
*) show=no ;;
esac

if [ "$self_test_mode" = yes ]; then
	self_test
	exit $?
fi

if [ "$#" -ne 1 ]; then
	usage
fi
user="$1"

# The same charset rule add-user.sh and provision-member.sh enforce, and for the
# same reasons: the name is a filesystem path component, a subdomain label and
# part of three configuration file names. Here it is also the thing standing
# between this script and an rm -rf somewhere else, which is why the two guards
# below repeat the work rather than trusting it.
if ! printf '%s' "$user" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'; then
	printf 'invalid username: %s (lowercase [a-z0-9._-], <=32 chars)\n' "$user" >&2
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	printf 'must run as root: doas ksh %s %s\n' "$0" "$user" >&2
	exit 1
fi

# The guards. The public tree is the only recursive removal here, so it is
# checked twice: it must be exactly this shape, and it must not be a symlink,
# because rm -rf on a symlink to a directory removes what it points at on some
# systems and the platform's own trees are never symlinks.
public="$www_root/$user.kyriakon.net"
case "$public" in
"$www_root"/*.kyriakon.net) ;;
*)
	printf 'refusing: %s is not the shape this script removes\n' "$public" >&2
	exit 1
	;;
esac
if [ -L "$public" ]; then
	printf 'refusing: %s is a symlink, not the member tree\n' "$public" >&2
	exit 1
fi

remove_member
