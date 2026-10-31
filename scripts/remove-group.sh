#!/bin/ksh
# remove-group.sh: take one own-domain body's name off the box.
#
# Usage:
#   doas ksh scripts/remove-group.sh <domain>
#        ksh scripts/remove-group.sh --self-test
#
# Runs ON the box as root, from the drain's `remove-group` intent. It is the
# host-file half of the transition: the group record, the accounts, the holds and
# the token index are the drain's, inside the intent, the way delete-user.sh
# leaves the store's records and the name hold to it.
#
# scripts/cron-apply.sh --web runs after this script, not inside it, for the
# reason group provisioning runs it at its end: the httpd file this script
# removes is what scripts/relayd-members.sh generates the domain's keypair line
# from, and the index rewrite and the reload are the drain's one pass.
#
# What goes:
#
#   /etc/mail/mail_domains       the domain's whole line
#   /etc/mail/dkim_domains       the domain's whole line, so the filter stops
#                                signing it
#   /etc/mail/virtuals           every <address>@<domain> entry, mailboxes and
#                                aliases alike
#   /etc/httpd.d/<domain>.conf   the generated vhosts
#   /etc/gmid.d/<domain>.conf    the generated capsule block
#   /etc/acme-client.d/<domain>.conf
#                                the block renew-acme.sh reads, so the
#                                certificate stops being renewed
#   /etc/ssl/<domain>.fullchain.pem, /etc/ssl/private/<domain>.key
#                                the certificate pair
#   /etc/ssl/<domain>.crt        the symlink relayd looks the keypair up through
#   /etc/ssl/capsule-<domain>.cnf, .crt and /etc/ssl/private/capsule-<domain>.key
#                                the self-signed capsule pair and its config
#   <queue>/pending/<domain>     the queued order, so the queue never issues it
#
# The certificate itself is left to expire rather than revoked, the same choice
# delete-user.sh makes: revocation spends a CA rate limit and buys nothing for a
# name that no longer points here.
#
# smtpd reads both mail tables at start and has no reload verb, so it is
# restarted when either changed. The restart is reload-smtpd.sh's, which checks
# the configuration first, and it is skipped when no table changed, because a
# restart that changes nothing is a service blip for no reason.
#
# Idempotent: a second run, or a run after one that stopped partway, removes what
# is left and prints nothing when there is nothing. A table is rewritten through
# a temporary beside it and moved into place, with a timestamped copy of the old
# one kept, so a crash cannot leave smtpd reading half a table.
#
# Not this script's job: the group record, the accounts, their keys and holds,
# the token index and the journal. Those are the drain's, in the transition.
#
# Env: MAIL_DOMAINS, VIRTUALS, DKIM_DOMAINS, HTTPD_D, GMID_D, ACME_D, SSL_DIR,
# SSL_PRIVATE and ACME_QUEUE_DIR rebind the paths, and SMTPD_CONF is passed
# through to reload-smtpd.sh. The self-test uses the first set, so it needs no
# root and touches nothing outside TMPDIR.

set -euo pipefail

# doas and cron both hand over a minimal PATH, and install lives in /usr/sbin.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

script_dir=$(cd "$(dirname "$0")" && pwd)

mail_domains=${MAIL_DOMAINS:-/etc/mail/mail_domains}
virtuals=${VIRTUALS:-/etc/mail/virtuals}
dkim_domains=${DKIM_DOMAINS:-/etc/mail/dkim_domains}
httpd_d=${HTTPD_D:-/etc/httpd.d}
gmid_d=${GMID_D:-/etc/gmid.d}
acme_d=${ACME_D:-/etc/acme-client.d}
ssl_dir=${SSL_DIR:-/etc/ssl}
ssl_private=${SSL_PRIVATE:-/etc/ssl/private}
acme_queue_dir=${ACME_QUEUE_DIR:-/var/db/kyriakon-acme-queue}

usage() {
	printf 'usage: doas ksh %s <domain>\n' "$0" >&2
	printf '       ksh %s --self-test\n' "$0" >&2
	exit 2
}

# A validated FQDN: labels of lowercase letters, digits and hyphens, at least two
# of them, and no label starting or ending with a hyphen. It is the stem of every
# generated file name and a path component under /etc/ssl, so a name outside this
# set could not be a body's domain.
domain_ok() {
	typeset name="$1"
	[ "${#name}" -le 253 ] || return 1
	case "$name" in
	*.*) ;;
	*) return 1 ;;
	esac
	printf '%s' "$name" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
}

# The restart, as a function so the self-test can record it instead of running it.
reload_smtpd() { ksh "$script_dir/reload-smtpd.sh"; }

# install_table <file> <candidate>: keep a timestamped copy of the table and move
# the candidate into its place. Root sets the owner explicitly, because a table
# smtpd reads with the wrong owner is a table that does not load; the self-test
# runs unprivileged in a throwaway tree, where chown cannot and need not happen.
install_table() {
	typeset file="$1" candidate="$2" stamp owner_flags
	stamp=$(date +%Y%m%d%H%M%S)
	cp -p "$file" "$file.$stamp.bak"
	owner_flags=""
	if [ "$(id -u)" -eq 0 ]; then
		owner_flags="-o root -g wheel"
	fi
	# shellcheck disable=SC2086  # intentional splitting: two flags, or none
	install -m 0644 $owner_flags "$candidate" "$file"
	rm -f "$candidate"
	printf 'kept %s.%s.bak\n' "$file" "$stamp"
}

# drop_line <file> <line>: remove the whole lines equal to <line>. Returns 0 and
# says whether it changed the file, which is what decides the smtpd restart.
drop_line() {
	typeset file="$1" line="$2" candidate
	table_changed=no
	[ -f "$file" ] || return 0
	candidate="$file.kyriakon.$$"
	awk -v line="$line" '$0 != line' "$file" >"$candidate"
	if cmp -s "$file" "$candidate"; then
		rm -f "$candidate"
		return 0
	fi
	install_table "$file" "$candidate"
	printf 'removed %s from %s\n' "$line" "$file"
	table_changed=yes
}

# drop_domain_addresses <file> <domain>: remove every entry whose address is on
# the body's domain, both mailboxes and aliases. The key is compared after the
# colon, trimmed, and only by its suffix, so an address on another domain that
# merely contains this one is left alone.
drop_domain_addresses() {
	typeset file="$1" domain="$2" candidate
	table_changed=no
	[ -f "$file" ] || return 0
	candidate="$file.kyriakon.$$"
	awk -v suffix="@$domain" -F: '{
		key = $1
		gsub(/^[ \t]+|[ \t]+$/, "", key)
		if (length(key) >= length(suffix) \
			&& substr(key, length(key) - length(suffix) + 1) == suffix) next
		print
	}' "$file" >"$candidate"
	if cmp -s "$file" "$candidate"; then
		rm -f "$candidate"
		return 0
	fi
	install_table "$file" "$candidate"
	printf 'removed the %s entries from %s\n' "$domain" "$file"
	table_changed=yes
}

# remove_path <description> <path>: remove one file or symlink, saying so only
# when it was there.
remove_path() {
	typeset description="$1" path="$2"
	if [ ! -e "$path" ] && [ ! -L "$path" ]; then
		return 0
	fi
	rm -f "$path"
	printf 'removed the %s %s\n' "$description" "$path"
}

# remove_group: the whole job, in the order the transition's notes give.
remove_group() {
	tables_changed=no

	# 1. The mail tables. mail_domains and dkim_domains carry the domain as a
	# whole line; virtuals carries one line per address on it.
	drop_line "$mail_domains" "$domain"
	if [ "$table_changed" = yes ]; then
		tables_changed=yes
	fi
	drop_line "$dkim_domains" "$domain"
	if [ "$table_changed" = yes ]; then
		tables_changed=yes
	fi
	drop_domain_addresses "$virtuals" "$domain"
	if [ "$table_changed" = yes ]; then
		tables_changed=yes
	fi

	# 2. The generated daemon blocks and the certificate material. The order
	# inside this step does not matter: cron-apply.sh --web runs after this
	# script and reads the directory as it finds it.
	remove_path "daemon block" "$httpd_d/$domain.conf"
	remove_path "daemon block" "$gmid_d/$domain.conf"
	remove_path "daemon block" "$acme_d/$domain.conf"
	remove_path "certificate chain" "$ssl_dir/$domain.fullchain.pem"
	remove_path "certificate key" "$ssl_private/$domain.key"
	remove_path "relayd certificate link" "$ssl_dir/$domain.crt"
	remove_path "capsule configuration" "$ssl_dir/capsule-$domain.cnf"
	remove_path "capsule certificate" "$ssl_dir/capsule-$domain.crt"
	remove_path "capsule key" "$ssl_private/capsule-$domain.key"
	remove_path "queued certificate request" "$acme_queue_dir/pending/$domain"

	# 3. smtpd, once, and only if a table changed. The tables were already
	# rewritten, so this makes both live together.
	if [ "$tables_changed" = yes ]; then
		reload_smtpd
		printf 'restarted smtpd, which reads the tables at start\n'
	fi
	return 0
}

# --- the self-test ----------------------------------------------------------
#
# Rebind the paths to a throwaway tree and record the restart, so the logic runs
# anywhere: no root, no daemon, nothing outside TMPDIR. What it checks is this
# script's own decisions, not the tools'.

self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$script_dir/lib.sh"
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	mail_domains="$tree/etc/mail/mail_domains"
	virtuals="$tree/etc/mail/virtuals"
	dkim_domains="$tree/etc/mail/dkim_domains"
	httpd_d="$tree/etc/httpd.d"
	gmid_d="$tree/etc/gmid.d"
	acme_d="$tree/etc/acme-client.d"
	ssl_dir="$tree/etc/ssl"
	ssl_private="$ssl_dir/private"
	acme_queue_dir="$tree/queue"
	calls="$tree/calls"

	install -d -m 0755 "$(dirname "$mail_domains")" "$httpd_d" "$gmid_d" \
		"$acme_d" "$ssl_private" "$acme_queue_dir/pending"

	reload_smtpd() { printf 'reload-smtpd\n' >>"$calls"; }

	domain=parish.example
	other=other.example
	{
		printf 'kyriakon.net\n'
		printf '%s\n' "$domain"
		printf '%s\n' "$other"
	} >"$mail_domains"
	cp "$mail_domains" "$dkim_domains"
	{
		printf 'secretary@%s: parish-secretary\n' "$domain"
		printf 'office@%s: parish-secretary\n' "$domain"
		printf 'alice@kyriakon.net: alice\n'
		printf 'secretary@%s: somebody\n' "$other"
	} >"$virtuals"
	for d in "$domain" "$other"; do
		: >"$httpd_d/$d.conf"
		: >"$gmid_d/$d.conf"
		: >"$acme_d/$d.conf"
		: >"$ssl_dir/$d.fullchain.pem"
		: >"$ssl_private/$d.key"
		ln -s "$d.fullchain.pem" "$ssl_dir/$d.crt"
		: >"$ssl_dir/capsule-$d.cnf"
		: >"$ssl_dir/capsule-$d.crt"
		: >"$ssl_private/capsule-$d.key"
		: >"$acme_queue_dir/pending/$d"
	done

	: >"$calls"
	remove_group >"$tree/first.out" 2>"$tree/first.err"

	check "the mail domain table lost the domain" \
		"$(grep -cxF "$domain" "$mail_domains" || true)" 0
	check "and kept the platform and the other body" \
		"$(grep -cE '^(kyriakon\.net|other\.example)$' "$mail_domains")" 2
	check "the DKIM list lost the domain" \
		"$(grep -cxF "$domain" "$dkim_domains" || true)" 0
	check "and kept the other body" "$(grep -cxF "$other" "$dkim_domains")" 1
	check "the virtual table lost every address on the domain" \
		"$(grep -c "@$domain" "$virtuals" || true)" 0
	check "and kept the platform's and the other body's" \
		"$(grep -cE '^(alice@kyriakon\.net|secretary@other\.example)' "$virtuals")" 2
	check "the vhost went" "$([ -e "$httpd_d/$domain.conf" ] && echo present || echo gone)" gone
	check "the capsule block went" "$([ -e "$gmid_d/$domain.conf" ] && echo present || echo gone)" gone
	check "the ACME block went" "$([ -e "$acme_d/$domain.conf" ] && echo present || echo gone)" gone
	check "the certificate went" \
		"$([ -e "$ssl_dir/$domain.fullchain.pem" ] && echo present || echo gone)" gone
	check "the certificate key went" \
		"$([ -e "$ssl_private/$domain.key" ] && echo present || echo gone)" gone
	check "the relayd link went" "$([ -L "$ssl_dir/$domain.crt" ] && echo present || echo gone)" gone
	check "the capsule configuration went" \
		"$([ -e "$ssl_dir/capsule-$domain.cnf" ] && echo present || echo gone)" gone
	check "the capsule pair went" \
		"$([ -e "$ssl_dir/capsule-$domain.crt" ] && echo present || echo gone)" gone
	check "the capsule key went" \
		"$([ -e "$ssl_private/capsule-$domain.key" ] && echo present || echo gone)" gone
	check "the queued order went" \
		"$([ -e "$acme_queue_dir/pending/$domain" ] && echo present || echo gone)" gone
	check "the other body's files stayed" \
		"$([ -e "$httpd_d/$other.conf" ] && [ -e "$ssl_private/$other.key" ] \
			&& [ -e "$acme_queue_dir/pending/$other" ] && echo present || echo gone)" present
	check "a copy of the old table was kept" \
		"$(find "$(dirname "$mail_domains")" -name 'mail_domains.*.bak' | wc -l | tr -d ' ')" 1
	check "smtpd was restarted once" "$(grep -c '^reload-smtpd$' "$calls")" 1
	check "and the first run said what it did" \
		"$(grep -c '^removed ' "$tree/first.out")" 13

	# A second run against the same tree must do nothing and say nothing.
	: >"$calls"
	before=$(stat -f '%i %m' "$mail_domains")
	remove_group >"$tree/second.out" 2>"$tree/second.err"
	check "a second run is silent on stdout" "$(wc -c <"$tree/second.out" | tr -d ' ')" 0
	check "a second run restarts nothing" "$(wc -c <"$calls" | tr -d ' ')" 0
	check "and leaves the table alone" "$(stat -f '%i %m' "$mail_domains")" "$before"

	# A domain that is not there is the same no-op.
	domain=absent.example
	: >"$calls"
	remove_group >"$tree/absent.out" 2>&1
	check "a name with nothing to remove says nothing" \
		"$(wc -c <"$tree/absent.out" | tr -d ' ')" 0
	check "and restarts nothing" "$(wc -c <"$calls" | tr -d ' ')" 0

	# The shape check is the guard between the argument and every rm above.
	check "a domain is accepted" "$(domain_ok parish.example && printf yes || printf no)" yes
	check "a single label is refused" "$(domain_ok parish && printf yes || printf no)" no
	check "a path is refused" "$(domain_ok ../parish.example && printf yes || printf no)" no
	check "a leading hyphen is refused" "$(domain_ok -parish.example && printf yes || printf no)" no
	check "an uppercase label is refused" "$(domain_ok Parish.example && printf yes || printf no)" no

	self_test_end
}

# --- the entry --------------------------------------------------------------

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
	domain="$1"
	domain_ok "$domain" || {
		printf 'invalid domain: %s (lowercase FQDN, at least two labels)\n' "$domain" >&2
		exit 1
	}
	[ "$(id -u)" -eq 0 ] || {
		printf 'must run as root: doas ksh %s %s\n' "$0" "$domain" >&2
		exit 1
	}
	remove_group
	;;
esac
