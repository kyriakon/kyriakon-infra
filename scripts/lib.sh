#!/bin/ksh
# lib.sh: shared helpers for the scripts that run on the box (backup.sh,
# restore-test.sh, rehearsal.sh, abuse-monitor.sh, check-hygiene.sh,
# check-keyring-drift.sh, renew-acme.sh, restore-standup.sh, acme-queue.sh).
# Source it
# from the script's own directory:
#
#   . "$(dirname "$0")/lib.sh"
#
# Deployed alongside each script (install both into the same dir; the crontab
# examples assume /root/bin/<script> and /root/bin/lib.sh).

# cron(8) runs jobs with PATH=/usr/bin:/bin, and OpenBSD keeps packages under
# /usr/local. Without this the nightly run dies at its first restic call with
# "restic: not found" and nothing reaches the storage box. Set here rather than
# in each caller so backup.sh, restore-test.sh and rehearsal.sh cannot drift.
PATH="/usr/local/bin:$PATH"
export PATH

# ping_url <url> — best-effort GET that never fails the caller. A monitoring ping
# must not turn a transient curl failure into a script failure / cron mail storm.
ping_url() {
	curl -fsS -m 10 --retry 3 "$1" >/dev/null 2>&1 || true
}

# hc_fail <url> — ping Healthchecks /fail and exit 1. Wired to the ERR trap so a
# failed run reports failure before the shell dies.
hc_fail() {
	if [ -n "${1:-}" ]; then
		ping_url "$1/fail"
	fi
	exit 1
}

# Canary contract: backup.sh writes this file into the snapshot; restore-test.sh
# asserts it returns byte-identical. The two run on DIFFERENT boxes, so the path
# and content are single-sourced here rather than re-typed (and allowed to drift)
# per script. Exported (not just set) so shellcheck sees the cross-file use.
export CANARY_PATH='/home/.kyriakon-backup-canary'
export CANARY_TEXT='kyriakon backup canary v1'

# Per-box values, so nothing has to be retyped or passed on a command line:
# /root/.kyriakon-env, mode 0600, one 'export VAR=value' per line. The tracked
# template is openbsd/etc/kyriakon.env in the repo, which deploy-mail.sh installs.
# Sourced rather than parsed, which is also how the cron lines read it, so the two
# cannot disagree about the format. Override the path with KYRIAKON_ENV.
KYRIAKON_ENV="${KYRIAKON_ENV:-/root/.kyriakon-env}"
export KYRIAKON_ENV
if [ -r "$KYRIAKON_ENV" ]; then
	# shellcheck disable=SC1090 # the path is the operator's, not a fixed literal
	. "$KYRIAKON_ENV"
fi


# install_staged <src> <dst> [install flags...]: install one file without ever
# leaving a partial one at <dst>. install writes a sibling temp in <dst>'s own
# directory, so the rename cannot cross a filesystem, and mv puts it in place
# atomically with the mode and owner install gave it: a run killed mid-write
# leaves <dst> as it was, and a reader sees either the old file or the whole new
# one. A failure removes the temp and prints what it was doing, because the
# caller runs under `set -e` and would otherwise exit without a word.
install_staged() {
	typeset staging_src="$1" staging_dst="$2" staging_tmp
	shift 2
	staging_tmp="$staging_dst.new.$$"
	if ! install "$@" "$staging_src" "$staging_tmp"; then
		rm -f "$staging_tmp"
		printf 'could not stage %s; %s left as it was\n' "$staging_src" "$staging_dst" >&2
		return 1
	fi
	if ! mv "$staging_tmp" "$staging_dst"; then
		rm -f "$staging_tmp"
		printf 'could not rename %s into place; %s left as it was\n' \
			"$staging_tmp" "$staging_dst" >&2
		return 1
	fi
}


# install_rows <table> <destination>: the scripts the install-set table gives one
# destination, one per line. scripts/install-set.tsv names the destination every
# installed script lands in, and this is the one query its readers used to run
# over their own copy of the list. A table that cannot be read is an error rather
# than an empty set, so a caller cannot install nothing and call it success.
install_rows() {
	typeset rows_table="$1" rows_destination="$2"
	if [ ! -f "$rows_table" ]; then
		printf 'install_rows: no table at %s\n' "$rows_table" >&2
		return 1
	fi
	awk -F'\t' -v d="$rows_destination" '!/^#/ && $2 == d { print $1 }' "$rows_table"
}


# need_pkg <package>: install it unless it is already there. One copy, because
# two deploys carried their own and one of them asked with `pkg_info -q` (name
# and version, which never matched the name it was given, so every deploy
# reinstalled) and ran pkg_add without -I (which asks on a tty, and a dispatcher
# waiting at a prompt looks exactly like a hung fetch).
need_pkg() {
	if pkg_info -q -e "$1" >/dev/null 2>&1 || pkg_info -q -e "$1-*" >/dev/null 2>&1; then
		return 0
	fi
	printf 'installing %s (fetching; can take a minute)\n' "$1"
	pkg_add -I "$1"
}


# --- generated files -------------------------------------------------------
#
# write_generated <target> <body-fn> [<cert> <key>]: write <target> from the
# body function, atomically, and only when the bytes differ.
#
# The body goes to a sibling candidate, is compared with what is there, and only
# then is renamed into place at 0644; the candidate's own creation is the
# caller's umask 077, so a half-written file is never readable by a member. A run
# killed at any point leaves the file the daemon is reading as it was, and a run
# that would write the same bytes leaves its inode and mtime alone. Sets
# conf_changed to yes or no, which is what the callers' "next" lines and the
# --web pass key off.
#
# A <cert> with no <key> is a broken pair rather than a state to serve from:
# relayd would name a key that is not there, its config check would fail, and the
# reload would take every name on the box down rather than one. The pair is an
# argument so the refusal is made once, here, and a lane that writes a file
# naming the pair cannot forget it.
write_generated() {
	typeset gen_target="$1" gen_body="$2" gen_cert="${3:-}" gen_key="${4:-}" gen_candidate
	if [ -n "$gen_cert" ] && [ -f "$gen_cert" ] && [ ! -f "$gen_key" ]; then
		printf '%s is there and %s is not, so %s was left alone: the relay needs both halves of the pair\n' \
			"$gen_cert" "$gen_key" "$gen_target" >&2
		return 1
	fi
	gen_candidate="$gen_target.new.$$"
	if ! "$gen_body" >"$gen_candidate"; then
		rm -f "$gen_candidate"
		printf 'could not write %s for %s; %s left as it was\n' \
			"$gen_body" "$gen_target" "$gen_target" >&2
		return 1
	fi
	if [ -f "$gen_target" ] && cmp -s "$gen_candidate" "$gen_target"; then
		rm -f "$gen_candidate"
		# shellcheck disable=SC2034 # the caller reads it
		conf_changed=no
		return 0
	fi
	chmod 0644 "$gen_candidate"
	if ! mv "$gen_candidate" "$gen_target"; then
		rm -f "$gen_candidate"
		printf 'could not rename %s into place; %s left as it was\n' \
			"$gen_candidate" "$gen_target" >&2
		return 1
	fi
	# shellcheck disable=SC2034 # the caller reads it
	conf_changed=yes
	return 0
}


# cert_paths <ssl-dir> <private-dir> <name>: set cert_chain, cert_key and
# cert_link to the files relayd's keypair <name> is made of. One place, because
# a link made or removed under a different name than the pair is a keypair
# relayd cannot open, and the relay deploy, the member pass and the removal
# scripts all touch the same three.
cert_paths() {
	cert_chain="$1/$3.fullchain.pem"
	cert_key="$2/$3.key"
	cert_link="$1/$3.crt"
	# Exported so shellcheck sees the cross-file use, the same way CANARY_* is.
	export cert_chain cert_key cert_link
}

# link_cert <ssl-dir> <private-dir> <name>: make cert_link the symlink relayd
# reads <name>'s pair through, and never over a file that is not a link: a real
# file at that path is somebody else's certificate and deleting it would take a
# name down. Says what it did when it changed something, so a run that repairs a
# link removed by hand reads as one that changed something. A missing half of the
# pair is the caller's check: the deploy names what it needs, and the member pass
# skips a name that is not ready.
link_cert() {
	# Names of their own, because ksh93 binds a function's typeset to a local of
	# the same name in its caller: a plain `target` here became the caller's.
	typeset cert_target cert_now
	cert_paths "$1" "$2" "$3"
	cert_target="$3.fullchain.pem"
	if [ -L "$cert_link" ]; then
		cert_now=$(readlink "$cert_link")
		[ "$cert_now" = "$cert_target" ] && return 0
		ln -sfn "$cert_target" "$cert_link"
		printf '%s: relinked to %s (was %s)\n' "$cert_link" "$cert_target" "$cert_now"
		return 0
	fi
	if [ -e "$cert_link" ]; then
		printf '%s is not a symlink; refusing to replace a file that may be a certificate\n' \
			"$cert_link" >&2
		return 1
	fi
	ln -s "$cert_target" "$cert_link"
	printf 'linked %s -> %s\n' "$cert_link" "$cert_target"
}


# dnsbl_verdict <ip> — ask the blocklists what they make of an address, and print one
# line naming both the verdict and the list that gave it:
#
#   listed <zone> <answer>   that list has the address
#   clean <zone>             that list has no record of it
#   unchecked <why>          no list answered
#
# Always returns 0, so a caller running under `set -e` reads the verdict instead of
# trapping on it, and so nothing is tempted to treat a status as the finding.
#
# One zone was not enough, and a single zone is how this went wrong. zen.spamhaus.org
# is the list that matters for deliverability and it refuses to answer any resolver
# serving more than one machine, which is this box's system resolver, a workstation's
# and every public resolver tried on 2026-09-23. A refusal is 127.255.255.x and a
# listing is 127.0.0.x, so the old code reported "cannot check" and "clean" in the same
# breath, and mailed the first of those every cooldown. The zones below are ordered
# strongest first, the first to answer wins, and the verdict names it, because a
# listing on SpamCop is not a listing on Spamhaus and the reader needs to know which.
dnsbl_zones="${DNSBL_ZONES:-${DNSBL_ZONE:-zen.spamhaus.org bl.spamcop.net all.s5h.net dnsbl.dronebl.org}}"

dnsbl_verdict() {
	dnsbl_ip="$1"
	dnsbl_rev=$(printf '%s\n' "$dnsbl_ip" | awk -F. '{ print $4"."$3"."$2"."$1 }')
	# A resolver serving one machine is answered by everyone; a shared one is not.
	# Patient on purpose, three tries at five seconds. This probe is itself the first
	# query after a boot, so it is the one query that primes the root while the cache
	# is empty, and a two-second version gave up on a resolver with nothing wrong with
	# it. That is the 2026-10-05 alert: the box had just rebooted, the probe failed,
	# the check fell through to the system resolver, Spamhaus ignored it by design,
	# and the operator was told to go and look at a healthy unbound. A slow run here
	# costs nothing, and a week of runs is still one query a quarter hour.
	if dig +short +time=5 +tries=3 @127.0.0.1 . NS >/dev/null 2>&1; then
		dnsbl_at="@127.0.0.1"
	else
		dnsbl_at=""
	fi
	dnsbl_skipped=""
	for dnsbl_zone in $dnsbl_zones; do
		# Prove the zone answers at all before trusting its silence. Every DNSBL
		# publishes a test entry for this, 2.0.0.127, and the reason is exactly the
		# trap here: a zone with no record and a zone that does not exist both
		# answer NXDOMAIN, so without the control a typo in the list would read as
		# clean forever, and silence from a zone refusing this resolver would read
		# as clean too. A zone that fails its own control is skipped rather than
		# believed.
		# shellcheck disable=SC2086 # deliberately empty or one argument
		dnsbl_ctl=$(dig +short +time=10 +tries=3 $dnsbl_at "2.0.0.127.$dnsbl_zone" A 2>/dev/null | head -1 || true)
		case "$dnsbl_ctl" in
		127.0.0.*) ;;
		127.255.255.*)
			# Answered, and the answer is a refusal: the zone is up and will not
			# serve this resolver. Recording which happened separates it from a zone
			# that said nothing at all, and the two need different advice, because
			# one is a policy and the other is DNS on this box.
			dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=refused"
			continue
			;;
		*)
			dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=silent"
			continue
			;;
		esac
		# shellcheck disable=SC2086 # deliberately empty or one argument
		dnsbl_out=$(dig +time=10 +tries=3 $dnsbl_at "$dnsbl_rev.$dnsbl_zone" A 2>/dev/null || true)
		dnsbl_status=$(printf '%s\n' "$dnsbl_out" | awk '/status:/ { s=$6; sub(/,.*/, "", s); print s; exit }')
		dnsbl_answer=$(printf '%s\n' "$dnsbl_out" \
			| awk -F'[ \t]+' '/IN[ \t]+A[ \t]+/ && $1 !~ /^;/ { print $5; exit }')
		case "$dnsbl_status:$dnsbl_answer" in
		NOERROR:127.0.0.*)
			printf 'listed %s %s\n' "$dnsbl_zone" "$dnsbl_answer"
			return 0
			;;
		NOERROR:127.255.255.*)
			# The zone refusing the resolver after passing its own control, which a
			# proxy between here and there would explain. Not a verdict.
			dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=refused"
			continue
			;;
		NOERROR:|NXDOMAIN:)
			# Answered, and no record for this address: the verdict this whole
			# function exists to be able to give.
			printf 'clean %s%s\n' "$dnsbl_zone" "${dnsbl_skipped:+ [skipped:$dnsbl_skipped]}"
			return 0
			;;
		*)
			# The status says which kind of nothing this was. SERVFAIL is what
			# Spamhaus's zones look like through QNAME minimisation, because their
			# NS and SOA answers do not match RFC 1034 and minimisation needs them;
			# a bare timeout carries no status at all.
			case "$dnsbl_status" in
			SERVFAIL) dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=servfail" ;;
			REFUSED) dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=refused" ;;
			"") dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=no-answer" ;;
			*) dnsbl_skipped="$dnsbl_skipped $dnsbl_zone=$dnsbl_status" ;;
			esac
			continue
			;;
		esac
	done
	printf 'unchecked no zone answered%s\n' "${dnsbl_skipped:+ [skipped:$dnsbl_skipped]}"
	return 0
}

# --- operator mail ---------------------------------------------------------
#
# notify_operator <component> <event> <found> [<what to do>]
#
# The one way a scheduled script tells the operator something, so the shape
# cannot drift per script. The subject names the component and the event, both
# drawn from the vocabulary below, and the body says what ran, when, what it
# found and what to do about it. The subject is the part that has to hold: an
# operator triaging a crowded mailbox sorts and filters on it, and a mail whose
# subject says nothing is read last, if at all.
#
# The components, one word per thing the box runs, the same word in every mail
# about it. onboard/src/notice.rs builds the identical shape for the drain:
#
#   onboard  the signup service: the handler, the drain and the store
#   mail     smtpd, dovecot, and the accounts and allowances behind them
#   spamd    the greylisting and blocking layer in front of smtpd
#   ssh      sshd, and the keys and accounts it admits
#   acme     certificate issuance, renewal and the queue
#   backup   the nightly restic snapshot and the weekly restore test
#   keyring  the published mail keys the encrypting LMTP reads
#   host     the box itself: filesystems, snapshots and the hygiene checks
#
# Never fails the caller, for the reason ping_url gives: an alert that cannot be
# sent must not become a second failure stacked on the one being reported, and a
# script that dies on its own alert is silent about the failure it was
# reporting. Mail that could not be sent is printed instead, so cron's own mail
# still carries it, under cron's subject, which hides the component and is
# still better than silence.
notify_operator() {
	# Locals, so a caller's own variables of any name survive the call. The
	# scripts that source this one run under `set -u`, and a helper that left a
	# stray variable behind would be a bug in a script nowhere near it.
	typeset component="$1" event="$2" found="$3" todo="${4:-}" subject body
	subject="kyriakon: $component: $event"
	body="$found"
	if [ -n "$todo" ]; then
		body="$body

what to do: $todo"
	fi
	body="$body

run: $0 on $(hostname) at $(date '+%F %T')"
	# The enqueuer directly rather than mail(1): mail(1) supplies a From from the
	# account running it, which for every one of these scripts is root, so an
	# operator alert read "Charlie Root <root@mail.kyriakon.net>". Naming the
	# sender is the only way to keep the platform's own address on it.
	if [ -n "${ALERT_EMAIL:-}" ] &&
		{
			printf 'From: %s\n' "${ALERT_FROM:-kyriakon <hello@kyriakon.net>}"
			printf 'To: %s\nSubject: %s\n\n' "$ALERT_EMAIL" "$subject"
			printf '%s\n' "$body"
		} | ${SENDMAIL:-/usr/sbin/sendmail} -i -t >/dev/null 2>&1; then
		return 0
	fi
	printf '%s\n\n%s\n' "$subject" "$body" >&2
	return 0
}

# --- keys -------------------------------------------------------------------
#
# key_problems <file> — why a public key cannot serve this platform's mail, one
# line each, and nothing at all when it can. Two faults, both silent at delivery
# time: gpg encrypts with packet tag 20 whenever the key advertises AEAD, and a
# client that implements MDC alone cannot open that; an expired key makes the
# encryptor fail closed, and the drift check compares fingerprints only, so
# nothing reports it. deploy-mail.sh warns about the first at install and
# rekey-mail-key.sh fixes it, both on the side of the box; this is the gate the
# key has to pass before it is published at all.
key_problems() {
	typeset key_file="$1" packets feat expires
	packets=$(gpg --list-packets "$key_file" 2>/dev/null)
	if printf '%s\n' "$packets" | grep -q 'pref-aead-algos'; then
		printf 'it advertises AEAD, so delivery would use a packet a client with MDC alone cannot read (fix on the workstation holding it: scripts/rekey-mail-key.sh)\n'
	fi
	# One line per self-signature: a key re-signed beside an older signature
	# advertises both sets, and the feature bit is what a client reads.
	printf '%s\n' "$packets" |
		sed -n 's/.*(features: \([0-9a-fA-F]*\)).*/\1/p' |
		while read -r feat; do
			if [ $((0x$feat & 2)) -ne 0 ]; then
				printf 'its self-signature sets the AEAD feature bit (features: %s)\n' "$feat"
			fi
		done
	expires=$(gpg --batch --with-colons --show-keys "$key_file" 2>/dev/null |
		awk -F: '$1 == "pub" { print $7; exit }')
	if [ -n "$expires" ]; then
		printf 'it expires on %s, and delivery stops then without a word (a mail key must not expire)\n' \
			"$(date -r "$expires" +%Y-%m-%d)"
	fi
}

# --- self-tests ------------------------------------------------------------
#
# A --self-test is the one check a script can run without the box's own state, so
# most scripts carry one. These three pieces are the shape, kept here rather than
# copied into each: the scratch directory and its cleanup, the assertion, and the
# summary that makes the exit status mean something.
#
# A script that does not already source lib.sh for its live path sources it from
# inside self_test, so the live path takes no new dependency. The drain's copies do
# get lib.sh installed beside them, but only so one can answer --self-test there.
#
#   self_test_begin                     # sets $self_test_work, clears the count
#   check "what it proves" "$got" "$want"
#   self_test_end                       # prints the summary, exits 0 or 1

self_test_begin() {
	self_test_fails=0
	self_test_work=$(mktemp -d "${TMPDIR:-/tmp}/kyriakon-self-test.XXXXXX") || exit 1
	# Expanded now rather than at exit: the function's locals are gone by then.
	# shellcheck disable=SC2064
	trap "rm -rf '$self_test_work'" EXIT
}

check() {
	if [ "$2" = "$3" ]; then
		printf 'ok: %s\n' "$1"
	else
		printf 'FAIL: %s: expected [%s], got [%s]\n' "$1" "$3" "$2"
		self_test_fails=$((self_test_fails + 1))
	fi
}

self_test_end() {
	if [ "${self_test_fails:-0}" -ne 0 ]; then
		printf '\nself-test: %s check(s) failed\n' "$self_test_fails" >&2
		exit 1
	fi
	printf '\nself-test: every check passed\n'
	exit 0
}
