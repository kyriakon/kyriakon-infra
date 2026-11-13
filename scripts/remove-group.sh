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
#   /etc/mail/spamd.alloweddomains
#                                the domain's `@<domain>` line, so spamd stops
#                                treating mail to it as a spamtrap hit
#   /etc/mail/virtuals           every <address>@<domain> entry, mailboxes and
#                                aliases alike
#   /etc/mail/mail_from          every address on the domain from every
#                                account's sender list, so a mailbox that has
#                                left cannot submit as one
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
# spamd reads its allow list at start and has no reload verb either, so it is
# restarted by reload-spamd.sh when the domain's `@<domain>` line was there to
# remove. A line that was already gone restarts nothing.
#
# Idempotent: a second run, or a run after one that stopped partway, removes what
# is left and prints nothing when there is nothing. A table is rewritten through
# a temporary beside it and moved into place, with a timestamped copy of the old
# one kept, so a crash cannot leave smtpd reading half a table.
#
# Not this script's job: the group record, the accounts, their keys and holds,
# the token index and the journal. Those are the drain's, in the transition.
#
# Env: MAIL_DOMAINS, VIRTUALS, MAIL_FROM, DKIM_DOMAINS, SPAMD_ALLOWEDDOMAINS, HTTPD_D,
# GMID_D, ACME_D, SSL_DIR, SSL_PRIVATE and ACME_QUEUE_DIR rebind the paths, and
# SMTPD_CONF is passed through to reload-smtpd.sh. The self-test uses the first
# set, so it needs no root and touches nothing outside TMPDIR.

set -euo pipefail

# doas and cron both hand over a minimal PATH, and install lives in /usr/sbin.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

# cert_paths: the link, chain and key are the same three files the relay deploy
# and the member pass make, so removing one under a different name is how a
# dotted file is left behind.
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

mail_domains=${MAIL_DOMAINS:-/etc/mail/mail_domains}
virtuals=${VIRTUALS:-/etc/mail/virtuals}
mail_from=${MAIL_FROM:-/etc/mail/mail_from}
dkim_domains=${DKIM_DOMAINS:-/etc/mail/dkim_domains}
spamd_alloweddomains=${SPAMD_ALLOWEDDOMAINS:-/etc/mail/spamd.alloweddomains}
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
#
# The platform's own domain and everything under it are refused here too. It is
# the last line of defence: the drain refuses such a removal before this script
# runs, but a hand-run `remove-group.sh kyriakon.net` would delete the platform's
# mail table lines, vhosts and certificate. The platform's name is the first line
# of mail_domains, read the way provision-member.sh reads it.
domain_ok() {
	typeset name="$1" platform
	[ "${#name}" -le 253 ] || return 1
	case "$name" in
	*.*) ;;
	*) return 1 ;;
	esac
	printf '%s' "$name" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' || return 1
	# A table that is missing or empty refuses every name rather than guessing:
	# without its first line there is no way to tell the operator's domain from a
	# body's.
	platform=$(mail_domains_first "$mail_domains") || return 1
	[ -n "$platform" ] || return 1
	# kyriakon.com is the platform's defensive registration: the box serves it
	# with its own certificate and relayd keypair, which a removal would delete.
	case "$name" in
	"$platform" | *."$platform" | kyriakon.com | *.kyriakon.com) return 1 ;;
	esac
	return 0
}

# The restarts, as functions so the self-test can record them instead of running
# them.
reload_smtpd() { ksh "$script_dir/reload-smtpd.sh"; }
reload_spamd() { ksh "$script_dir/reload-spamd.sh"; }

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

# drop_table <table> <exact|prefix|suffix> <text> <message>
#
# One table_drop call and its report, with 2 (failure) kept apart from 1 (no
# match): a failed write must stop the removal, not read as nothing to do.
# Sets tables_changed when the table changed, and returns 1 on a failed write.
drop_table() {
	typeset table="$1" mode="$2" text="$3" message="$4" rc=0
	table_drop "$table" "$mode" "$text" || rc=$?
	case $rc in
	0)
		printf '%s\n' "$message"
		tables_changed=yes
		;;
	1) ;;
	*) return 1 ;;
	esac
	return 0
}

# remove_group: the whole job, in the order the transition's notes give.
# shellcheck disable=SC2154 # the three paths come from cert_paths in lib.sh
remove_group() {
	tables_changed=no

	# 1. The mail tables. mail_domains and dkim_domains carry the domain as a
	# whole line; virtuals carries one line per address on it, both mailboxes and
	# aliases. The allow list carries it at-prefixed. Every match is literal, so
	# a domain called parish-example.net is not the same line as parish.example.
	drop_table "$mail_domains" exact "$domain" \
		"removed $domain from $mail_domains" || return 1
	drop_table "$dkim_domains" exact "$domain" \
		"removed $domain from $dkim_domains" || return 1
	# spamd is a separate daemon with its own restart, so whether its line was
	# there is recorded before the drop: a second run restarts nothing.
	spamd_changed=no
	if [ -f "$spamd_alloweddomains" ] && grep -qxF "@$domain" "$spamd_alloweddomains"; then
		spamd_changed=yes
	fi
	drop_table "$spamd_alloweddomains" exact "@$domain" \
		"removed @$domain from $spamd_alloweddomains" || return 1
	drop_table "$virtuals" suffix "@$domain" \
		"removed the $domain entries from $virtuals" || return 1
	# The sender mapping carries the same addresses as values, keyed by the
	# account that may submit as them, so the domain is removed from every
	# account's list and a line left with no address goes. mail_from lives beside
	# virtuals and every match is literal.
	drop_table "$mail_from" value-suffix "@$domain" \
		"removed the $domain senders from $mail_from" || return 1

	# 2. The generated daemon blocks and the certificate material. The order
	# inside this step does not matter: cron-apply.sh --web runs after this
	# script and reads the directory as it finds it.
	remove_path "daemon block" "$httpd_d/$domain.conf"
	remove_path "daemon block" "$gmid_d/$domain.conf"
	remove_path "daemon block" "$acme_d/$domain.conf"
	cert_paths "$ssl_dir" "$ssl_private" "$domain"
	remove_path "certificate chain" "$cert_chain"
	remove_path "certificate key" "$cert_key"
	remove_path "relayd certificate link" "$cert_link"
	remove_path "capsule configuration" "$ssl_dir/capsule-$domain.cnf"
	remove_path "capsule certificate" "$ssl_dir/capsule-$domain.crt"
	remove_path "capsule key" "$ssl_private/capsule-$domain.key"
	remove_path "queued certificate request" "$acme_queue_dir/pending/$domain"

	# 3. The two daemons, once each, and only when their own files changed. The
	# files were already rewritten, so each restart makes what is on disk live.
	if [ "$tables_changed" = yes ]; then
		reload_smtpd
		printf 'restarted smtpd, which reads the tables at start\n'
	fi
	if [ "$spamd_changed" = yes ]; then
		reload_spamd
		printf 'restarted spamd, which reads the allow list at start\n'
	fi
	return 0
}

# --- the self-test ----------------------------------------------------------
#
# Rebind the paths to a throwaway tree and record the restart, so the logic runs
# anywhere: no root, no daemon, nothing outside TMPDIR. What it checks is this
# script's own decisions, not the tools'.

self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	mail_domains="$tree/etc/mail/mail_domains"
	virtuals="$tree/etc/mail/virtuals"
	mail_from="$tree/etc/mail/mail_from"
	dkim_domains="$tree/etc/mail/dkim_domains"
	spamd_alloweddomains="$tree/etc/mail/spamd.alloweddomains"
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
	reload_spamd() { printf 'reload-spamd\n' >>"$calls"; }

	domain=parish.example
	other=other.example
	# parish-example.net is the lookalike that a pattern match on the domain
	# would take with parish.example; every match below is literal.
	lookalike=parish-example.net
	{
		printf 'kyriakon.net\n'
		printf '%s\n' "$domain"
		printf '%s\n' "$other"
		printf '%s\n' "$lookalike"
	} >"$mail_domains"
	cp "$mail_domains" "$dkim_domains"
	# What provisioning leaves in the greylist pass-through list: the body's
	# at-prefixed line beside the platform's and the lookalike's, under the
	# tracked header. The removal must take exactly one of them.
	{
		printf '# greylist pass-through\n'
		printf '@kyriakon.net\n'
		printf '@%s\n' "$domain"
		printf '@%s\n' "$lookalike"
	} >"$spamd_alloweddomains"
	{
		printf 'secretary@%s: parish-secretary\n' "$domain"
		printf 'office@%s: parish-secretary\n' "$domain"
		printf 'alice@kyriakon.net: alice\n'
		printf 'secretary@%s: somebody\n' "$other"
		printf 'secretary@%s: somebody\n' "$lookalike"
	} >"$virtuals"
	# The sender mapping the listeners read. Provisioning adds each address to
	# the owning account's list, so the removal has to take the body's addresses
	# out of every list and keep the platform's, the other body's, the
	# lookalike's, and a line that had another address as well.
	{
		printf 'parish-secretary: secretary@%s,office@%s\n' "$domain" "$domain"
		printf 'alice: alice@kyriakon.net,secretary@%s\n' "$domain"
		printf 'somebody: secretary@%s\n' "$other"
		printf 'lookalike: secretary@%s\n' "$lookalike"
	} >"$mail_from"
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
	check "the allow list holds the line provisioning wrote" \
		"$(grep -cxF "@$domain" "$spamd_alloweddomains")" 1
	remove_group >"$tree/first.out" 2>"$tree/first.err"

	check "the mail domain table lost the domain" \
		"$(grep -cxF "$domain" "$mail_domains" || true)" 0
	check "and kept the platform and the other body" \
		"$(grep -cE '^(kyriakon\.net|other\.example)$' "$mail_domains")" 2
	check "and kept the domain that merely looks like it" \
		"$(grep -cxF "$lookalike" "$mail_domains")" 1
	check "the DKIM list lost the domain" \
		"$(grep -cxF "$domain" "$dkim_domains" || true)" 0
	check "and kept the other body" "$(grep -cxF "$other" "$dkim_domains")" 1
	check "and the lookalike" "$(grep -cxF "$lookalike" "$dkim_domains")" 1
	check "the allow list lost the at-prefixed line" \
		"$(grep -cxF "@$domain" "$spamd_alloweddomains" || true)" 0
	check "and kept the platform's line and the lookalike's" \
		"$(grep -cxF -e '@kyriakon.net' -e "@$lookalike" "$spamd_alloweddomains")" 2
	check "and the header that explains the file" \
		"$(grep -cxF '# greylist pass-through' "$spamd_alloweddomains")" 1
	check "the virtual table lost every address on the domain" \
		"$(grep -cF "@$domain" "$virtuals" || true)" 0
	check "and kept the platform's and the other body's" \
		"$(grep -cE '^(alice@kyriakon\.net|secretary@other\.example)' "$virtuals")" 2
	check "and the lookalike's address" \
		"$(grep -c "^secretary@$lookalike:" "$virtuals")" 1
	check "the sender mapping lost every address on the domain" \
		"$(grep -cF "@$domain" "$mail_from" || true)" 0
	check "and the list that also held another address kept it" \
		"$(grep -cxF 'alice: alice@kyriakon.net' "$mail_from")" 1
	check "and a line left with no address went" \
		"$(grep -c '^parish-secretary:' "$mail_from" || true)" 0
	check "and kept the platform's, the other body's and the lookalike's" \
		"$(grep -cE '^(alice: alice@kyriakon\.net|somebody: secretary@other\.example|lookalike: secretary@parish-example\.net)' "$mail_from")" 3
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
	check "and spamd, whose allow list lost the line" \
		"$(grep -c '^reload-spamd$' "$calls")" 1
	check "and the first run said what it did" \
		"$(grep -c '^removed ' "$tree/first.out")" 15

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
	# The platform's own domain is the first line of the table, and it and
	# everything under it belong to the operator: a removal would take the
	# platform's mail lines, vhosts and certificate with it.
	platform=$(mail_domains_first "$mail_domains")
	check "the platform's own domain is refused" \
		"$(domain_ok "$platform" && printf yes || printf no)" no
	check "and a name under it" \
		"$(domain_ok "mail.$platform" && printf yes || printf no)" no
	check "but a name that merely contains the same letters is accepted" \
		"$(domain_ok "not$platform" && printf yes || printf no)" yes

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
		printf 'invalid domain: %s (a lowercase FQDN of at least two labels, and not the platform'\''s own domain or a name under it)\n' "$domain" >&2
		exit 1
	}
	[ "$(id -u)" -eq 0 ] || {
		printf 'must run as root: doas ksh %s %s\n' "$0" "$domain" >&2
		exit 1
	}
	remove_group
	;;
esac
