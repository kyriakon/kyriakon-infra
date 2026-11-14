#!/bin/ksh
# filter-fromcheck — refuse a message whose From: header names an address the
# sender may not use.
#
# `senders <mail_from>` on the listeners binds the SMTP envelope sender and
# nothing else, and filter-dkimsign signs whatever domain the From: header names
# with the platform's one published key. So an authenticated member could submit
# MAIL FROM:<their own address> with `From: hello@kyriakon.net` (or another body's
# secretary@parish.example) and have it arrive SPF-passing, DKIM-passing and
# DMARC-aligned as that address. The socket listener has no `senders` at all, so
# any local enqueue could do the same. That is the hole this filter closes: the
# listener comment in openbsd/etc/smtpd.conf says the From check has to live in a
# filter, and this is it.
#
# Three policies, chosen per session from the report stream:
#
#   authenticated  every From address must be mapped to the account that
#                  authenticated in the -t table, which is the same
#                  /etc/mail/mail_from the listeners' `senders` reads. An alias
#                  the platform publishes but no account owns (hello@, abuse@)
#                  is therefore not sendable from an authenticated session.
#   local enqueue  every From address must be in one of the -a domains: the
#                  platform's own and the mail host's, which is what cron(8),
#                  mail(1) and the drain's notices write. A bare localpart is
#                  allowed because that is what those produce before smtpd
#                  appends the listener hostname downstream of this filter.
#   otherwise      internet mail is not looked at: its From is the
#                  correspondent's, and not this platform's to police.
#
# The decision is taken at the commit phase. The data-line phase can only rewrite
# the message, not refuse it, so the filter passes every line through unchanged
# and answers at the end of DATA, which is where the 5xx reaches the client. It
# buffers the header block only, never the body: a shell variable is no place for
# a 35M message, and filter-dkimsign, which runs after this in the chain, already
# buffers the whole message to sign it. A refused message is never signed,
# because the chain stops at this filter's reject before the signer is asked to
# commit.
#
# Usage (from smtpd.conf, as a filter or the head of a filter chain):
#
#   filter "fromcheck" proc-exec "filter-fromcheck -t /etc/mail/mail_from \
#       -a kyriakon.net -a mail.kyriakon.net"
#
# ksh filter-fromcheck.sh --self-test

# Deliberately no `set -e`: a filter is started once and may never terminate,
# and a failure anywhere below would otherwise take every submission down with
# it. The one condition that must not be papered over — no state directory, so no
# way to know whose session a message belongs to — exits loudly instead, and
# smtpd reports the dead filter.
set -u

# The mapping `senders` reads: account name to a comma-separated address list, one
# account per line, as scripts/lib.sh's mail_from_entries writes it.
mail_from_table=/etc/mail/mail_from

# Comma-separated -a values, the domains a local enqueue may write in From.
local_domains=

usage() {
	printf 'usage: %s -t <mail_from table> -a <domain> [-a <domain> ...]\n' "$0" >&2
	printf '       %s --self-test\n' "$0" >&2
	exit 64
}

state_dir=

# clean_transaction <sessid>: drop one message's header state. Called at commit,
# because a second message in the same SMTP session is a second message and must
# be checked from scratch.
clean_transaction() {
	rm -f "$state_dir/$1".from "$state_dir/$1".infrom "$state_dir/$1".count \
		"$state_dir/$1".body
}

# clean_session <sessid>: drop the whole connection's state. Called at
# disconnect, so a reconnect gets a fresh answer rather than the last one. The
# account and the connect source live for the connection, not the transaction:
# smtpd reports them once, and forgetting them at commit would leave every later
# message in the session looking like inbound mail.
clean_session() {
	rm -f "$state_dir/$1".user "$state_dir/$1".local
	clean_transaction "$1"
}

# add_domain <domain>
add_domain() {
	[ -n "$1" ] || return 0
	local_domains=${local_domains:-$1}
	[ "$local_domains" = "$1" ] || local_domains="$local_domains,$1"
}

# from_problem <sessid>: print the 5xx text the message must be refused with, or
# nothing when it may go on. Fails closed for a method it cannot see: an
# authenticated session whose account is absent from the table is refused rather
# than let through.
from_problem() {
	typeset sid="$1" user='' value='' count='' mode=''
	if [ -f "$state_dir/$sid.user" ]; then
		read -r user < "$state_dir/$sid.user" || true
	fi
	if [ -n "$user" ]; then
		mode=auth
	elif [ -f "$state_dir/$sid.local" ]; then
		mode=local
	else
		# Not authenticated and not the enqueuer: inbound mail, not ours.
		return 0
	fi
	if [ -f "$state_dir/$sid.count" ]; then
		read -r count < "$state_dir/$sid.count" || true
		if [ "${count:-0}" -gt 1 ]; then
			printf '5.7.1 the message has more than one From header'
			return 0
		fi
	fi
	if [ -f "$state_dir/$sid.from" ]; then
		read -r value < "$state_dir/$sid.from" || true
	fi
	# One awk pass for the whole decision: extract the addresses out of the
	# unfolded header value, then compare each against the account's mapping or
	# the local domains. The quoting, angle-bracket and comment forms of a From
	# header are why this is not string surgery in the shell.
	printf '%s\n' "$value" | awk -v mode="$mode" -v user="$user" \
		-v domains="$local_domains" -v table="$mail_from_table" '
	function trim(s) {
		sub(/^[ \t]+/, "", s)
		sub(/[ \t]+$/, "", s)
		return s
	}
	function problem(why) {
		printf "%s", why
		exit
	}
	function add(a,   d) {
		a = tolower(trim(a))
		if (a == "")
			return
		added++
		if (mode == "auth") {
			if (index(a, "@") == 0 ||
			    index(allowed[user] ",", "," a ",") == 0)
				problem("5.7.1 " a " is not an address this account may send as")
		} else {
			if (index(a, "@") == 0)
				return	# a bare localpart, as cron(8) and mail(1) write
			d = substr(a, index(a, "@") + 1)
			if (!(d in ok_domain))
				problem("5.7.1 " a " is not a domain this platform originates")
		}
	}
	BEGIN {
		if (mode == "auth") {
			while ((getline line < table) > 0) {
				p = index(line, ":")
				if (p == 0)
					continue
				n = split(substr(line, p + 1), part, ",")
				list = ""
				for (i = 1; i <= n; i++) {
					a = tolower(trim(part[i]))
					if (a != "")
						list = list "," a
				}
				allowed[tolower(trim(substr(line, 1, p - 1)))] = list ","
			}
			close(table)
		}
		n = split(domains, part, ",")
		for (i = 1; i <= n; i++)
			ok_domain[tolower(trim(part[i]))] = 1
	}
	{
		value = value $0 " "
	}
	END {
		value = trim(value)
		if (value == "") {
			if (mode == "auth")
				problem("5.7.1 the message has no From header")
			exit
		}
		# An RFC 5322 comment may itself contain an address, so comments are
		# removed before anything is read out of the header: otherwise the
		# address in "hello@kyriakon.net (x <alice@kyriakon.net>)" would be the
		# one in the comment, and the header own address never checked. To a
		# fixpoint, innermost first, because comments nest.
		while (match(value, /\([^()]*\)/)) {
			value = substr(value, 1, RSTART - 1) " " substr(value, RSTART + RLENGTH)
		}
		# One pass for every mailbox in the header. Quoted display-name
		# strings are blanked first, so the comma in `"A, Inc." <a@b>` is
		# not read as an address separator; quotes inside <...> belong to
		# the addr-spec and are left alone. A comma-separated part that has
		# brackets carries its addresses in them and the text beside them is
		# only a display name; a part without brackets is a bare addr-spec
		# and is checked too, or `hello@kyriakon.net, <alice@kyriakon.net>`
		# would pass by naming one usable address.
		clean = ""; inq = 0; esc = 0; inangle = 0; added = 0
		for (i = 1; i <= length(value); i++) {
			c = substr(value, i, 1)
			if (inq) {
				if (esc) {
					esc = 0
				} else if (c == "\\") {
					esc = 1
				} else if (c == "\"") {
					inq = 0
				}
				clean = clean " "
				continue
			}
			if (inangle) {
				if (c == ">")
					inangle = 0
				clean = clean c
				continue
			}
			if (c == "\"") {
				inq = 1
				clean = clean " "
				continue
			}
			if (c == "<")
				inangle = 1
			clean = clean c
		}
		# A quote or angle bracket that never closes leaves no address to
		# check, and an unchecked header must not pass: dkimsign would sign
		# whatever domain the unreadable header names.
		if (inq || inangle)
			problem("5.7.1 the From header has an unterminated " \
				(inq ? "quoted string" : "angle address"))
		n = split(clean, part, ",")
		for (i = 1; i <= n; i++) {
			p = part[i]
			if (index(p, "<") == 0) {
				add(p)
				continue
			}
			while (match(p, /<[^>]*>/)) {
				add(substr(p, RSTART + 1, RLENGTH - 2))
				p = substr(p, 1, RSTART - 1) substr(p, RSTART + RLENGTH)
			}
		}
		# A header that parsed to no address at all (a quoted string with no
		# mailbox beside it) has nothing to check, so it cannot pass.
		if (mode == "auth" && added == 0)
			problem("5.7.1 the From header names no address")
	}'
}

# handle_dataline <sessid> <token> <line>: echo the line back unchanged, and, in
# the header block, keep what the From check needs. Echoing is the whole contract
# of this phase: smtpd takes the message to be the filters' output, so a filter
# that buffered a line without answering it would stall the session.
handle_dataline() {
	typeset sid="$1" token="$2" line="$3" count
	printf 'filter-dataline|%s|%s|%s\n' "$sid" "$token" "$line"
	[ -f "$state_dir/$sid.body" ] && return 0
	if [ -z "$line" ]; then
		: > "$state_dir/$sid.body"
		return 0
	fi
	case "$line" in
	' '* | '	'*)
		# A folded continuation, and only a From's is worth keeping: an
		# unfolding of the header immediately above it.
		if [ -f "$state_dir/$sid.infrom" ]; then
			printf ' %s' "$line" >> "$state_dir/$sid.from"
		fi
		;;
	[Ff][Rr][Oo][Mm]:*)
		count=0
		[ -f "$state_dir/$sid.count" ] && read -r count < "$state_dir/$sid.count"
		count=$((count + 1))
		printf '%s' "$count" > "$state_dir/$sid.count"
		# Only the first From is kept; a second one is refused at commit.
		if [ "$count" -eq 1 ]; then
			: > "$state_dir/$sid.from"
			printf '%s' "${line#*:}" >> "$state_dir/$sid.from"
			: > "$state_dir/$sid.infrom"
		fi
		;;
	*)
		rm -f "$state_dir/$sid.infrom"
		;;
	esac
}

# handle_commit <sessid> <token>: answer, and forget the session's transaction.
handle_commit() {
	typeset sid="$1" token="$2" problem
	problem=$(from_problem "$sid")
	if [ -n "$problem" ]; then
		printf 'filter-result|%s|%s|reject|550 %s\n' "$sid" "$token" "$problem"
	else
		printf 'filter-result|%s|%s|proceed\n' "$sid" "$token"
	fi
	clean_transaction "$sid"
}

# handle_report <line>: the events the policies are read from — the source of the
# connection, and the account that authenticated.
handle_report() {
	typeset rest event sid params user p
	# report|<version>|<timestamp>|<subsystem>|<event>|<sessid>|<params>
	rest=${1#report\|}
	rest=${rest#*\|}
	rest=${rest#*\|}
	rest=${rest#*\|}
	event=${rest%%\|*}
	rest=${rest#*\|}
	sid=${rest%%\|*}
	rest=${rest#*\|}
	case "$event" in
	link-connect)
		params=$rest
		p=${params#*\|}
		p=${p#*\|}
		# src is the third field; the enqueuer is a UNIX socket, and the
		# version of this report that names it "local" is the connect request.
		case "${p%%\|*}" in
		local | unix:*) : > "$state_dir/$sid.local" ;;
		*) rm -f "$state_dir/$sid.local" ;;
		esac
		;;
	link-auth)
		case "$rest" in
		pass\|*)
			user=${rest#*\|}
			printf '%s' "$user" > "$state_dir/$sid.user"
			;;
		*)
			rm -f "$state_dir/$sid.user"
			;;
		esac
		;;
	link-disconnect)
		clean_session "$sid"
		;;
	esac
}

# handle_filter <line>: the two phases this filter answers.
handle_filter() {
	typeset rest phase sid token param
	# filter|<version>|<timestamp>|<subsystem>|<phase>|<sessid>|<token>|<param>
	rest=${1#filter\|}
	rest=${rest#*\|}
	rest=${rest#*\|}
	rest=${rest#*\|}
	phase=${rest%%\|*}
	rest=${rest#*\|}
	sid=${rest%%\|*}
	rest=${rest#*\|}
	token=${rest%%\|*}
	case "$rest" in
	*\|*) param=${rest#*\|} ;;
	*) param= ;;
	esac
	case "$sid" in
	'' | *[!0-9a-f]*) return 0 ;;	# not something smtpd sends
	esac
	case "$phase" in
	data-line)
		[ -n "$token" ] && handle_dataline "$sid" "$token" "$param"
		;;
	commit)
		[ -n "$token" ] && handle_commit "$sid" "$token"
		;;
	esac
}

# run_filter — the whole process: the handshake, then the protocol until smtpd
# closes the pipe.
run_filter() {
	typeset line
	state_dir=$(mktemp -d "${TMPDIR:-/tmp}/filter-fromcheck.XXXXXX") || {
		printf 'filter-fromcheck: cannot create a state directory\n' >&2
		exit 1
	}
	while IFS= read -r line; do
		case "$line" in
		config\|ready)
			# Reports first: the policies are read from them, and a filter
			# that registered for its requests only would answer every
			# message as unknown.
			printf 'register|report|smtp-in|link-connect\n'
			printf 'register|report|smtp-in|link-auth\n'
			printf 'register|report|smtp-in|link-disconnect\n'
			printf 'register|filter|smtp-in|data-line\n'
			printf 'register|filter|smtp-in|commit\n'
			printf 'register|ready\n'
			;;
		report\|*) handle_report "$line" ;;
		filter\|*) handle_filter "$line" ;;
		esac
	done
	rm -rf "$state_dir"
	state_dir=
}

self_test() {
	typeset work table
	work=$(mktemp -d "${TMPDIR:-/tmp}/filter-fromcheck-test.XXXXXX") || exit 1
	# shellcheck disable=SC2064 # expanded now: the local is gone at exit
	trap "rm -rf '$work'" EXIT
	fail=0
	check() { # <what> <got> <want>
		if [ "$2" = "$3" ]; then
			printf 'ok: %s\n' "$1"
		else
			printf 'FAIL: %s: expected [%s], got [%s]\n' "$1" "$3" "$2"
			fail=$((fail + 1))
		fi
	}
	# The shape mail_from_entries and table_map_add write.
	table="$work/mail_from"
	printf 'alice: alice@kyriakon.net,secretary@parish.example\n' > "$table"
	mail_from_table=$table
	local_domains=
	add_domain kyriakon.net
	add_domain mail.kyriakon.net

	# run_case <name> <transcript body> — the handshake and one session's
	# transaction, with the decisions pulled out.
	session=a000000000000001
	run_case() {
		typeset body="$1"
		{
			printf 'config|protocol|0.7\n'
			printf 'config|smtpd-version|7.9.0\n'
			printf 'config|ready\n'
			printf '%s\n' "$body"
		} > "$work/transcript"
		run_filter < "$work/transcript" > "$work/out" 2> "$work/err"
	}
	# connect <sha> — the enqueuer, or an authenticated remote session.
	connect_local() {
		printf 'report|0.7|1.1|smtp-in|link-connect|%s|localhost|pass|unix:/var/run/smtpd.sock|unix:/var/run/smtpd.sock\n' "$session"
	}
	connect_remote() {
		printf 'report|0.7|1.1|smtp-in|link-connect|%s|mail.example|pass|192.0.2.5:41000|192.0.2.1:465\n' "$session"
		echo "report|0.7|1.2|smtp-in|link-auth|$session|pass|alice"
	}
	# message <from-line> [<extra header>] — a header block, one body line and
	# the terminator.
	message() {
		printf 'filter|0.7|2.1|smtp-in|data-line|%s|t0|Received: from client\n' "$session"
		printf '%s\n' "$1"
		[ -n "${2:-}" ] && printf '%s\n' "$2"
		printf 'filter|0.7|2.2|smtp-in|data-line|%s|t1|Subject: hi\n' "$session"
		printf 'filter|0.7|2.3|smtp-in|data-line|%s|t2|\n' "$session"
		printf 'filter|0.7|2.4|smtp-in|data-line|%s|t3|body\n' "$session"
		printf 'filter|0.7|2.5|smtp-in|data-line|%s|t4|.\n' "$session"
		printf 'filter|0.7|2.6|smtp-in|commit|%s|t5\n' "$session"
	}
	# message_no_from — a header block with no From, then body and terminator.
	message_no_from() {
		printf 'filter|0.7|2.1|smtp-in|data-line|%s|t0|Received: from client\n' "$session"
		printf 'filter|0.7|2.2|smtp-in|data-line|%s|t1|Subject: hi\n' "$session"
		printf 'filter|0.7|2.3|smtp-in|data-line|%s|t2|\n' "$session"
		printf 'filter|0.7|2.4|smtp-in|data-line|%s|t3|body\n' "$session"
		printf 'filter|0.7|2.5|smtp-in|data-line|%s|t4|.\n' "$session"
		printf 'filter|0.7|2.6|smtp-in|commit|%s|t5\n' "$session"
	}
	# message_body_from <from-line> — the first body line looks like a header.
	message_body_from() {
		printf 'filter|0.7|2.1|smtp-in|data-line|%s|t0|Received: from client\n' "$session"
		printf '%s\n' "$1"
		printf 'filter|0.7|2.3|smtp-in|data-line|%s|t2|\n' "$session"
		printf 'filter|0.7|2.4|smtp-in|data-line|%s|t3|From: anyone@evil.example\n' "$session"
		printf 'filter|0.7|2.5|smtp-in|data-line|%s|t4|.\n' "$session"
		printf 'filter|0.7|2.6|smtp-in|commit|%s|t5\n' "$session"
	}
	# decision — what the last run answered at commit: "proceed", or the
	# "reject|<text>" it refused with.
	check_reject() { # <what> <prefix the rejection must start with>
		case "$(decision)" in
		reject\|"$2"*) printf 'ok: %s\n' "$1" ;;
		*)
			printf 'FAIL: %s: got [%s]\n' "$1" "$(decision)"
			fail=$((fail + 1))
			;;
		esac
	}
	decision() {
		typeset line
		line=$(grep '^filter-result|' "$work/out" | tail -1)
		case "$line" in
		*'|proceed') printf 'proceed' ;;
		*'|reject|'*) printf 'reject|%s' "${line#*\|reject\|}" ;;
		esac
	}

	# --- the authenticated policy ---
	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: hello@kyriakon.net")"
	check_reject "a member sending as another address is refused" \
		"550 5.7.1 hello@kyriakon.net"

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: Alice <alice@kyriakon.net>")"
	check "the account's own address, with a display name, is accepted" \
		"$(decision)" proceed

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: secretary@parish.example")"
	check "an address the account's mapping names is accepted" "$(decision)" proceed

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: ALICE@Kyriakon.Net")"
	check "the comparison is case-insensitive" "$(decision)" proceed

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: a@kyriakon.net, alice@kyriakon.net")"
	check_reject "any unlisted address in a list is refused" \
		"550 5.7.1 a@kyriakon.net"

	# A mailbox-list mixes the two address forms freely, and every one of them
	# is an address the header names: the bracketed one must not hide the bare
	# one beside it.
	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: hello@kyriakon.net, <alice@kyriakon.net>")"
	check_reject "a bare address beside a bracketed one is checked" \
		"550 5.7.1 hello@kyriakon.net"

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: <alice@kyriakon.net>, bob@kyriakon.net")"
	check_reject "a bare address after a bracketed one is checked" \
		"550 5.7.1 bob@kyriakon.net"

	# The comma in a quoted display name is not a separator, and an escaped
	# quote does not end the string at the wrong place.
	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: \"A, Inc.\" <alice@kyriakon.net>")"
	check "a quoted display name's comma is not an address separator" \
		"$(decision)" proceed

	quoted_from='From: "Alice \"Q\" Public, Inc." <alice@kyriakon.net>'
	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|$quoted_from")"
	check "an escaped quote does not split a display name" \
		"$(decision)" proceed

	# A header the parser cannot read must be refused, not pass unchecked.
	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: \" <hello@kyriakon.net>")"
	check_reject "an unterminated quoted string is refused" \
		"550 5.7.1 the From header has an unterminated quoted string"

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: alice@kyriakon.net, \" <hello@kyriakon.net>")"
	check_reject "an unterminated quote cannot blank the rest of the header" \
		"550 5.7.1 the From header has an unterminated quoted string"

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: <hello@kyriakon.net")"
	check_reject "an unterminated angle address is refused" \
		"550 5.7.1 the From header has an unterminated angle address"

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: \"hello@kyriakon.net\"")"
	check_reject "a quoted string with no mailbox is refused" \
		"550 5.7.1 the From header names no address"

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: \"\"")"
	check_reject "an empty quoted header is refused" \
		"550 5.7.1 the From header names no address"

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: alice")"
	check_reject "a bare localpart is not an authenticated identity" \
		"550 5.7.1 alice"

	# A second From: header is refused: dkimsign signs the first and receivers
	# disagree about which one DMARC aligns.
	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: alice@kyriakon.net" \
	"filter|0.7|2.0b|smtp-in|data-line|$session|t8|From: hello@kyriakon.net")"
	check_reject "two From headers are refused" \
		"550 5.7.1 the message has more than one"

	# A folded header is unfolded before the address is read.
	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: Alice" \
	"filter|0.7|2.0b|smtp-in|data-line|$session|t8| <alice@kyriakon.net>")"
	check "a folded From header is unfolded" "$(decision)" proceed

	# A comment can carry an address-looking string. The header's real address
	# is the one outside it, so the comment is dropped before the check.
	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: hello@kyriakon.net (x <alice@kyriakon.net>)")"
	check_reject "an address hidden in a comment is not the header's address" \
		"550 5.7.1 hello@kyriakon.net"

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: \"Alice\" (the platform) <alice@kyriakon.net>")"
	check "a comment beside a display name does not change the address" \
		"$(decision)" proceed

	# A message with no From at all has no address to check, and dkimsign has
	# nothing to sign either: refused rather than let through unsigned.
	run_case "$(connect_remote)
$(message_no_from)"
	check_reject "a message with no From header is refused" \
		"550 5.7.1 the message has no From header"

	# --- the account outlives a commit, the connection does not ---
	# smtpd reports link-auth and link-connect once per connection. Clearing
	# them at commit would make every later message in the session look like
	# inbound mail and skip the check entirely.
	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: alice@kyriakon.net")
$(message "filter|0.7|3.0|smtp-in|data-line|$session|u9|From: hello@kyriakon.net")"
	check "the first message in a session proceeds" \
		"$(grep -c 'filter-result|.*|t5|proceed' "$work/out")" 1
	check_reject "a second message in the same session is still checked" \
		"550 5.7.1 hello@kyriakon.net"

	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: alice@kyriakon.net")
report|0.7|4.0|smtp-in|link-disconnect|$session
report|0.7|5.0|smtp-in|link-connect|$session|mail.example|pass|192.0.2.5:41001|192.0.2.1:25
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: anyone@example.org")"
	check "a reconnect starts with no identity" "$(decision)" proceed

	# --- the local enqueuer's policy ---
	run_case "$(connect_local)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: kyriakon <hello@kyriakon.net>")"
	check "the enqueuer may send as a platform address" "$(decision)" proceed

	run_case "$(connect_local)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: root (Cron Daemon)")"
	check "cron's bare localpart is accepted" "$(decision)" proceed

	run_case "$(connect_local)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: root@mail.kyriakon.net")"
	check "the mail host's own domain is accepted" "$(decision)" proceed

	run_case "$(connect_local)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: secretary@parish.example")"
	check_reject "the enqueuer cannot write a body domain" \
		"550 5.7.1 secretary@parish.example"

	run_case "$(connect_local)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: x@evil.example (x <hello@kyriakon.net>)")"
	check_reject "the enqueuer cannot hide a foreign domain in a comment" \
		"550 5.7.1 x@evil.example"

	run_case "$(connect_local)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: hello@kyriakon.net, <anything@evil.example>")"
	check_reject "the enqueuer checks both addresses of a mixed header" \
		"550 5.7.1 anything@evil.example"

	run_case "$(connect_local)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: hello@kyriakon.net")
$(message "filter|0.7|3.0|smtp-in|data-line|$session|u9|From: x@evil.example")"
	check_reject "the enqueuer's second message in a session is still checked" \
		"550 5.7.1 x@evil.example"

	# A From: line in the body is body text, not a header: the header block
	# ended at the blank line.
	run_case "$(connect_local)
$(message_body_from "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: hello@kyriakon.net")"
	check "a From: line in the body is not a header" "$(decision)" proceed

	# --- inbound mail is untouched ---
	run_case "$(printf 'report|0.7|1.1|smtp-in|link-connect|%s|mail.example|pass|192.0.2.5:41000|192.0.2.1:25\n' "$session")
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: anyone@example.org")"
	check "an unauthenticated inbound message is not looked at" \
		"$(decision)" proceed

	# --- the passthrough contract ---
	run_case "$(connect_remote)
$(message "filter|0.7|2.0|smtp-in|data-line|$session|t9|From: Alice <alice@kyriakon.net>")"
	check "every data line is echoed back with its own token" \
		"$(grep -c "^filter-dataline|$session|t[0-9]" "$work/out")" 6
	check "and the terminating dot is echoed" \
		"$(grep -c "^filter-dataline|$session|t4|\.\$" "$work/out")" 1
	check "and the handshake registers before any request" \
		"$(sed -n '1p' "$work/out")" "register|report|smtp-in|link-connect"

	if [ "$fail" -ne 0 ]; then
		printf '\nself-test: %s check(s) failed\n' "$fail" >&2
		exit 1
	fi
	printf '\nself-test: every check passed\n'
}

case "${1:-}" in
--self-test)
	self_test
	exit 0
	;;
--help | -h) usage ;;
esac

while getopts t:a: opt; do
	case "$opt" in
	t) mail_from_table=$OPTARG ;;
	a) add_domain "$OPTARG" ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || usage
[ -n "$local_domains" ] || usage
[ -r "$mail_from_table" ] || {
	printf 'filter-fromcheck: cannot read %s\n' "$mail_from_table" >&2
	exit 1
}
# The state directory is this process's alone; smtpd restarts the filter rather
# than signalling it, but a stop does send TERM and the directory should not
# outlive the process.
trap '[ -z "$state_dir" ] || rm -rf "$state_dir"' EXIT TERM
run_filter
