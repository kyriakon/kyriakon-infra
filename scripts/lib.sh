#!/bin/ksh
# lib.sh: shared helpers for the scripts that run on the box (backup.sh,
# restore-test.sh, rehearsal.sh, abuse-monitor.sh, check-hygiene.sh,
# check-keyring-drift.sh, renew-acme.sh, restore-standup.sh, acme-queue.sh,
# deploy-mail.sh, add-user.sh, provision-member.sh, delete-user.sh,
# remove-group.sh, publish-mail-key.sh, remove-upload-key.sh, the
# provision-member-* and provision-group-* lane scripts, and
# kyriakon-authcheck.sh). Source it from the script's own directory:
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

# Payload contract: the paths backup.sh hands restic, and the ones restore-test.sh
# asserts came back. Single-sourced for the canary's reason: the two run on
# different boxes and a list typed in both is how one side drifts. One path per
# line. backup.sh skips a path this box has not created, since restic exits on a
# missing one; restore-test.sh requires every path, because the snapshot it reads
# is of the mail box, which has them all.
BACKUP_PATHS='/home
/etc/mail
/var/db/onboard
/var/db/kyriakon-acme-queue
/etc/kyriakon
/etc/master.passwd
/etc/passwd
/etc/group
/etc/httpd.d
/etc/gmid.d
/etc/acme-client.d
/etc/ssh/authorized_keys'
export BACKUP_PATHS

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

# need_packages <file> <owner>: install every package the table assigns to owner.
# The owner is the script that needs it, so a deploy pulls its own rows, a
# package shared by two deploys is written once, and CI reads the same table.
need_packages() {
	typeset file=$1 owner=$2 pkg selected
	if [ ! -f "$file" ]; then
		printf '%s: no package table at %s\n' "$0" "$file" >&2
		return 1
	fi
	selected=$(awk -F'\t' -v owner="$owner" '
		/^[[:space:]]*#/ || NF < 3 { next }
		index("," $2 ",", "," owner ",") > 0 { print $1 }' "$file" | sort -u)
	if [ -z "$selected" ]; then
		printf '%s: no packages for %s in %s\n' "$0" "$owner" "$file" >&2
		return 1
	fi
	for pkg in $selected; do
		need_pkg "$pkg"
	done
}


# --- generated files -------------------------------------------------------
#
# write_generated <target> <body-fn> [<cert> <key>]: write <target> from the
# body function, atomically, and only when the bytes differ.
#
# Contract:
#   - <body-fn> prints the whole file on stdout and nothing else; a non-zero
#     status means nothing is written and <target> is left as it was.
#   - the body runs under umask 077, so the candidate it creates is never
#     readable by a member even before the chmod below.
#   - the candidate is compared with the existing file and only then renamed
#     into place, at 0644. A run killed at any point leaves the file the daemon
#     is reading as it was, and a run that would write the same bytes leaves its
#     inode and mtime alone.
#   - sets conf_changed to yes or no, the answer the callers print and the --web
#     pass keys off, and returns 1 with a message on stderr on any failure.
#
# <cert> and <key> are for a file that names a relayd pair. The guard trips when
# the certificate is present and not empty and the key is not, which is the half
# pair that passes `httpd -n` and fails `relayd -n`; an empty file is an
# interrupted write, not half a pair. Lanes whose pair is always generated
# together pass neither and are not guarded by a rule they cannot break.
write_generated() {
	typeset gen_target="$1" gen_body="$2" gen_cert="${3:-}" gen_key="${4:-}" gen_candidate
	if [ -n "$gen_cert" ] && [ -s "$gen_cert" ] && [ ! -s "$gen_key" ]; then
		printf '%s is there and %s is not, so %s was left alone: the relay needs both halves of the pair\n' \
			"$gen_cert" "$gen_key" "$gen_target" >&2
		return 1
	fi
	gen_candidate="$gen_target.new.$$"
	# The redirection is inside the subshell, because the shell that opens the
	# file is the one whose umask applies to it; the caller's is untouched.
	if ! ( umask 077; "$gen_body" >"$gen_candidate" ); then
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
# about it. control/crates/core/src/mail/notice.rs builds the identical shape for the drain:
#
#   control  the control plane: the handler, the drain and the store
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
# client that implements MDC alone cannot open that; an expiring key, on the
# primary or on its encryption subkey, makes the encryptor fail closed at the
# date, and the drift check compares fingerprints only, so nothing reports it.
# deploy-mail.sh warns about the first at install and rekey-mail-key.sh fixes it,
# both on the side of the box; this is the gate the key has to pass before it is
# published at all.
key_problems() {
	typeset key_file="$1" packets feat
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
	# The primary and every encryption-capable subkey carry the expiry that
	# stops delivery. A signing subkey's expiry does not (the crate checks
	# `encrypts` for the same reason), and reading it would refuse a key that
	# approval's own check reports clean. Field 12 is the capabilities column.
	gpg --batch --with-colons --show-keys "$key_file" 2>/dev/null |
		awk -F: '($1 == "pub" || ($1 == "sub" && $12 ~ /e/)) && $7 != "" { print $7 }' |
		sort -un |
		while read -r expires; do
			printf 'it expires on %s, and delivery stops then without a word (a mail key must not expire)\n' \
				"$(date -r "$expires" +%Y-%m-%d)"
		done
}

# uid_warnings <key-file> <localpart> — the User IDs the published
# keys/<localpart>.asc would carry beyond <localpart>@kyriakon.net, one line
# each, and nothing when the key is the platform identity alone. A display name
# or another address is allowed, because a member may want it, but the published
# set is public forever, so it is a warning rather than a refusal.
uid_warnings() {
	gpg --batch --with-colons --show-keys "$1" 2>/dev/null |
		awk -F: -v want="$2@kyriakon.net" \
			'$1 == "uid" && tolower($10) != want { print $10 }'
}

# --- tables ----------------------------------------------------------------
#
# The mail scripts' tables (/etc/mail/virtuals, mail_domains, mail_from,
# dkim_domains) are read whole by smtpd or by a filter, so a write that leaves
# half a line behind takes addresses offline until someone notices. These two
# helpers are the one write shape, and each takes the same lock for its whole
# read-modify-write: a signup and an operator deploy can overlap, and a rewrite
# that read before the other's append would move the old table back over it.

# table_lock <table> / table_unlock <table>
#
# mkdir(2) is the lock: it fails when the directory exists, and nothing else
# needs a base tool. The owner writes its pid inside, so a lock left by a killed
# writer can be told from one being held. A writer waits five seconds in whole
# seconds; a lock whose pid is gone, or that has been held for more than thirty
# seconds, is reaped once and the acquisition retried. The drain's Rust writer
# takes the same <table>.lock directory with the same pid file, so the two
# exclude each other.
table_lock() {
	typeset table="$1" lock="$1.lock" tries=0 reaped=no stale
	while [ "$tries" -lt 5 ]; do
		if mkdir "$lock" 2>/dev/null; then
			if ! printf '%s\n' "$$" > "$lock/pid"; then
				rm -rf "$lock"
				printf 'could not write the owner pid into %s\n' "$lock" >&2
				return 2
			fi
			return 0
		fi
		if [ ! -d "$lock" ]; then
			printf 'could not lock %s: cannot create %s\n' "$table" "$lock" >&2
			return 2
		fi
		if [ "$reaped" = no ]; then
			stale=$(table_lock_stale "$table")
			if [ -n "$stale" ]; then
				printf 'reaping stale lock %s: %s\n' "$lock" "$stale" >&2
				rm -rf "$lock"
				reaped=yes
				continue
			fi
		fi
		tries=$((tries + 1))
		[ "$tries" -ge 5 ] || sleep 1
	done
	printf 'could not lock %s: %s exists and did not clear; remove it if no writer is running\n' \
		"$table" "$lock" >&2
	return 2
}

# table_lock_stale <table>: why <table>.lock is not being held by a live writer,
# one line, or nothing when it is absent or looks live. Used by table_lock to
# decide whether to reap, and by check-hygiene.sh to report a wedged table.
table_lock_stale() {
	typeset table="$1" lock="$1.lock" pid mtime now age
	lock="$table.lock"
	[ -d "$lock" ] || return 0
	pid=$(cat "$lock/pid" 2>/dev/null || true)
	case "$pid" in
	'' | *[!0-9]*) ;;
	*)
		if kill -0 "$pid" 2>/dev/null; then
			# A live owner is holding it, however long the write is taking.
			return 0
		fi
		printf 'the owner pid %s is gone\n' "$pid"
		return 0
		;;
	esac
	# OpenBSD and macOS stat use -f, GNU stat uses -c.
	mtime=$(stat -c %Y "$lock" 2>/dev/null || stat -f %m "$lock" 2>/dev/null || printf '')
	[ -n "$mtime" ] || return 0
	now=$(date +%s)
	age=$((now - mtime))
	if [ "$age" -gt 30 ]; then
		printf 'it has been held for %s seconds\n' "$age"
	fi
	return 0
}

table_unlock() {
	typeset table="$1"
	rm -rf "$table.lock"
}

# valid_localpart <name> — the username and mailbox charset: 1-31 lowercase
# letters, digits and interior hyphens, starting and ending alphanumeric: a
# single DNS label. It is a filesystem path component, a subdomain label and a
# keyring filename, so every script that takes a member name checks it here.
valid_localpart() {
	printf '%s' "$1" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,29}[a-z0-9])?$'
}

# mail_domains_first <file>: the first line of mail_domains, the platform's own
# domain. One read, because deploy-mail.sh, check-hygiene.sh and
# provision-member.sh all depend on that line being the same one.
mail_domains_first() {
	awk 'NR == 1 { print; exit }' "$1"
}

# mail_domains_first_problem <file> <platform-domain>: why the first line is not
# the platform domain, one line, or nothing when it is. A restore or a hand edit
# that reorders the table is otherwise silent, and provision-member.sh addresses
# a new member on whatever line it finds first.
mail_domains_first_problem() {
	typeset first
	first=$(mail_domains_first "$1")
	[ "$first" = "$2" ] && return 0
	printf 'the first line is "%s", not %s; provision-member.sh reads it as the domain a new member is addressed on. Put %s first.\n' \
		"$first" "$2" "$2"
}

# table_set <table> <name> <entry>
#
# Replace the line whose key (the text before the first colon) is exactly <name>
# with <entry>, or append it when there is none. The key is compared literally,
# not as a pattern: a key is an address or a domain and contains a dot, and a
# pattern match would let a.b touch axb. On return table_set_how is "set" or
# "added". Returns 0 on success and 2 on failure, after naming the failure on
# stderr.
#
# The append is a write to the live table under the lock rather than a rewrite.
# A missing final newline is added first, which is the interrupted-append state
# this helper exists to survive. The replace path still goes through a candidate
# beside the table and a rename, so a reader never sees half a line.
table_set_how=''
table_set() {
	typeset table="$1" name="$2" entry="$3" candidate last
	table_set_how=''
	table_lock "$table" || return 2
	if [ -f "$table" ] &&
		awk -F: -v k="$name" '$1 == k { found = 1 } END { exit !found }' "$table"; then
		candidate=$(mktemp "$table.XXXXXX") || {
			printf 'could not create a candidate beside %s\n' "$table" >&2
			table_unlock "$table"
			return 2
		}
		if ! awk -F: -v k="$name" -v e="$entry" '{
			if ($1 == k) { print e; next }
			print
		}' "$table" > "$candidate"; then
			printf 'could not rewrite %s\n' "$table" >&2
			rm -f "$candidate"
			table_unlock "$table"
			return 2
		fi
		if ! chmod 0644 "$candidate" || ! mv "$candidate" "$table"; then
			printf 'could not replace %s\n' "$table" >&2
			rm -f "$candidate"
			table_unlock "$table"
			return 2
		fi
		table_set_how='set'
	else
		if [ -s "$table" ]; then
			if ! last=$(tail -c 1 "$table"); then
				printf 'could not read the end of %s\n' "$table" >&2
				table_unlock "$table"
				return 2
			fi
			if [ -n "$last" ] && ! printf '\n' >> "$table"; then
				printf 'could not finish the last line of %s\n' "$table" >&2
				table_unlock "$table"
				return 2
			fi
		fi
		if ! printf '%s\n' "$entry" >> "$table" || ! chmod 0644 "$table"; then
			printf 'could not append to %s\n' "$table" >&2
			table_unlock "$table"
			return 2
		fi
		table_set_how='added'
	fi
	table_unlock "$table"
	return 0
}

# table_drop <table> <exact|prefix|suffix> <text>
#
# Drop every line whose key matches <text> literally: equal to it, starting with
# it, or ending with it. Literal on purpose: the caller's value is an address
# or a domain and contains a dot, and an ERE would let a.b drop axb and let
# parish-example match parish.example. A table of bare domains, such as
# mail_domains, has the whole line as its key.
#
# Returns 0 when the table changed, 1 when it did not, and 2 on failure after
# naming it on stderr. Callers must not read 2 as "nothing to do". A changed
# table is copied to <table>.<timestamp>.bak, mode 0600, one per table: the
# previous backup is removed first so the directory does not accumulate copies
# that ride every restic snapshot.
table_drop() {
	typeset table="$1" how="$2" text="$3" candidate backup old
	if [ ! -f "$table" ]; then
		printf 'no table at %s\n' "$table" >&2
		return 2
	fi
	table_lock "$table" || return 2
	candidate=$(mktemp "$table.XXXXXX") || {
		printf 'could not create a candidate beside %s\n' "$table" >&2
		table_unlock "$table"
		return 2
	}
	if ! awk -F: -v how="$how" -v text="$text" '{
		key = $1
		gsub(/^[ \t]+|[ \t]+$/, "", key)
		drop = 0
		if (how == "exact") {
			drop = (key == text)
		} else if (how == "prefix") {
			drop = (length(key) >= length(text) &&
				substr(key, 1, length(text)) == text)
		} else if (how == "suffix") {
			drop = (length(key) >= length(text) &&
				substr(key, length(key) - length(text) + 1) == text)
		}
		if (!drop) print
	}' "$table" > "$candidate"; then
		printf 'could not rewrite %s\n' "$table" >&2
		rm -f "$candidate"
		table_unlock "$table"
		return 2
	fi
	if cmp -s "$table" "$candidate"; then
		rm -f "$candidate"
		table_unlock "$table"
		return 1
	fi
	for old in "$table".*.bak; do
		[ -f "$old" ] || continue
		if ! rm -f "$old"; then
			printf 'could not remove the old backup %s\n' "$old" >&2
			rm -f "$candidate"
			table_unlock "$table"
			return 2
		fi
	done
	backup="$table.$(date +%Y%m%d%H%M%S).bak"
	if ! cp -p "$table" "$backup" || ! chmod 0600 "$backup"; then
		printf 'could not keep a copy of %s at %s\n' "$table" "$backup" >&2
		rm -f "$candidate"
		table_unlock "$table"
		return 2
	fi
	if ! chmod 0644 "$candidate" || ! mv "$candidate" "$table"; then
		printf 'could not replace %s\n' "$table" >&2
		rm -f "$candidate"
		table_unlock "$table"
		return 2
	fi
	printf 'kept %s\n' "$backup" >&2
	table_unlock "$table"
	return 0
}

# --- the MTA configuration -------------------------------------------------
#
# smtpd.conf carries two placeholders that deploy-mail.sh fills in from the box's
# own state: the queue key and the DKIM filter's -d list. The list is a table the
# drain appends to when a body joins or leaves, so the substitution has to be
# repeatable outside a deploy, or the filter keeps signing a body's mail with the
# fallback domain. The template deploy-mail.sh installs beside the live file is
# what these two read, and every caller that restarts smtpd goes through them.

# dkim_domains_args <file>: print the "-d <domain>" arguments for the filter's
# proc-exec line, in file order, because the filter signs with the domain that
# matches the message's From header and falls back to the first one given. Each
# line is validated here rather than left to smtpd: the list is spliced into a
# command string, so a stray line would reach the configuration as part of that
# string, and smtpd's complaint would name the config file rather than the list.
dkim_domains_args() {
	dk_args=
	while IFS= read -r dk_domain; do
		[ -n "$dk_domain" ] || continue
		printf '%s\n' "$dk_domain" \
			| grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$' \
			|| { printf '%s holds a line that is not a domain: %s\n' "$1" "$dk_domain" >&2; return 1; }
		dk_args="$dk_args -d $dk_domain"
	done < "$1"
	[ -n "$dk_args" ] || { printf '%s holds no domains\n' "$1" >&2; return 1; }
	printf '%s\n' "${dk_args# }"
}

# install_smtpd_conf <template> <dkim-domains> <queue-key-file> <destination>
#
# The shipped config with the queue key and the filter's domain list substituted,
# staged beside <destination> and renamed onto it, 0600 because it carries the
# key. Both placeholders are substituted in the one pass, so the file is never
# left with the key and not the list, or the reverse. The redirect used to go
# straight onto the live file, which empties the MTA's only configuration before
# filling it, and the chmod landed two lines later: for that window the file
# carrying the substituted queue key existed under the caller's umask.
install_smtpd_conf() {
	typeset conf_template="$1" conf_domains="$2" conf_keyfile="$3" conf_dst="$4" \
		conf_key conf_args conf_candidate
	conf_args=$(dkim_domains_args "$conf_domains") || return 1
	conf_key=$(cat "$conf_keyfile" 2>/dev/null) \
		|| { printf 'could not read the queue key from %s\n' "$conf_keyfile" >&2; return 1; }
	[ -n "$conf_key" ] || { printf '%s holds no queue key\n' "$conf_keyfile" >&2; return 1; }
	# smtpd's crypto_setup() rejects anything but exactly 32 characters and
	# exits, so a restored or hand-edited key of another length is a daemon that
	# will not start. deploy-mail.sh regenerates one of the right length; this
	# refuses to install a config that would take the running MTA down.
	if [ "${#conf_key}" -ne 32 ]; then
		printf '%s holds a %s-character queue key, not 32; run scripts/deploy-mail.sh to regenerate it\n' \
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
	if ! chmod 0600 "$conf_candidate" || ! mv "$conf_candidate" "$conf_dst"; then
		printf 'could not replace %s\n' "$conf_dst" >&2
		rm -f "$conf_candidate"
		return 1
	fi
	return 0
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
	# A self-test must not mail the fixtures it runs. The cron line may have
	# sourced /root/.kyriakon-env before KYRIAKON_ENV=/dev/null was set, so the
	# operator's address can already be in the environment; drop it here rather
	# than relying on each test to remember.
	unset ALERT_EMAIL
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

# The helpers' own checks. lib.sh is a library, so the guard below runs this only
# when the file is executed itself; a script that sources it keeps its own
# --self-test, and its own self_test definition replaces this one.
self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin
	tree=$self_test_work

	check "a plain localpart is accepted" \
		"$(valid_localpart alice && printf yes || printf no)" yes
	check "an uppercase name is refused" \
		"$(valid_localpart Alice && printf yes || printf no)" no
	check "a leading dot is refused" \
		"$(valid_localpart .alice && printf yes || printf no)" no
	check "a leading hyphen is refused" \
		"$(valid_localpart -alice && printf yes || printf no)" no
	check "an interior hyphen is accepted" \
		"$(valid_localpart a-b && printf yes || printf no)" yes
	check "a dotted localpart is refused" \
		"$(valid_localpart a.b && printf yes || printf no)" no
	check "an underscore is refused" \
		"$(valid_localpart a_b && printf yes || printf no)" no
	check "a trailing hyphen is refused" \
		"$(valid_localpart a- && printf yes || printf no)" no
	check "a name of 31 characters is accepted" \
		"$(valid_localpart aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa && printf yes || printf no)" yes
	check "a name of 32 characters is refused" \
		"$(valid_localpart aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa && printf yes || printf no)" no

	# The fixture that motivated the helper: the last line has no newline, so a
	# plain append joins the new entry to it and both keys stop matching.
	printf 'hello: oliver\nsecretary@parish.example: parish' > "$tree/virtuals"
	table_set "$tree/virtuals" alice "alice@kyriakon.net: alice"
	check "table_set reports an append" "$table_set_how" added
	check "an append leaves a last line without a newline whole" \
		"$(grep -c '^secretary@parish.example: parish$' "$tree/virtuals")" 1
	check "and writes the new entry on its own line" \
		"$(grep -c '^alice@kyriakon.net: alice$' "$tree/virtuals")" 1
	check "with one line more than before" \
		"$(wc -l < "$tree/virtuals" | tr -d ' ')" 3
	check "at mode 0644" "$(stat -f '%Lp' "$tree/virtuals")" 644

	table_set "$tree/virtuals" hello "hello: alice"
	check "table_set reports a replacement" "$table_set_how" set
	check "an existing entry is replaced" \
		"$(grep -c '^hello: alice$' "$tree/virtuals")" 1
	check "and not duplicated" "$(grep -c '^hello:' "$tree/virtuals")" 1
	# The key is literal: a.b must not touch axb.
	printf 'a.b: one\naxb: two\n' > "$tree/literal"
	table_set "$tree/literal" a.b "a.b: changed"
	check "a dotted key is replaced" "$(grep -c '^a.b: changed$' "$tree/literal")" 1
	check "and the key it would match as a pattern is untouched" \
		"$(grep -c '^axb: two$' "$tree/literal")" 1

	# Drops are literal too, in all three shapes.
	printf 'a.b@kyriakon.net: a\naxb@kyriakon.net: b\nalice@parish.example: alice\nbob@parish-example.net: bob\n' \
		> "$tree/drop"
	check "table_drop reports no change when nothing matches" \
		"$(table_drop "$tree/drop" exact absent@example && printf yes || printf no)" no
	check "table_drop reports a change" \
		"$(table_drop "$tree/drop" prefix a.b@ && printf yes || printf no)" yes
	check "a dotted prefix drops only its own key" \
		"$(grep -c '^axb@kyriakon.net: b$' "$tree/drop")" 1
	check "and the dotted key is gone" "$(grep -cF 'a.b@' "$tree/drop" || true)" 0
	check "a suffix drop is literal" \
		"$(table_drop "$tree/drop" suffix @parish.example && printf yes || printf no)" yes
	check "parish.example is gone" "$(grep -cF '@parish.example' "$tree/drop" || true)" 0
	check "and parish-example.net stays" \
		"$(grep -c '@parish-example.net' "$tree/drop")" 1
	check "a backup was kept" \
		"$(find "$tree" -name 'drop.*.bak' | wc -l | tr -d ' ')" 1
	check "at mode 0600" "$(stat -f '%Lp' "$(find "$tree" -name 'drop.*.bak' | head -1)")" 600
	# A second change replaces that backup rather than adding another.
	printf 'carol@parish.example: carol\n' >> "$tree/drop"
	table_drop "$tree/drop" suffix @parish.example >/dev/null 2>&1
	check "only one backup per table is kept" \
		"$(find "$tree" -name 'drop.*.bak' | wc -l | tr -d ' ')" 1

	# Failures are 2, not 1, and name what went wrong.
	code=0
	table_drop "$tree/absent" exact x >/dev/null 2>"$tree/absent.err" || code=$?
	check "a missing table is a failure, not 'unchanged'" "$code" 2
	out=$(cat "$tree/absent.err")
	case "$out" in
	*"$tree/absent"*) ;;
	*) printf 'FAIL: a missing table names itself; got [%s]\n' "$out" >&2
	   self_test_fails=$((self_test_fails + 1)) ;;
	esac
	# A lock whose owner is gone is reaped and the write goes ahead, rather than
	# wedging every later writer.
	mkdir "$tree/stale.lock"
	printf '999999\n' > "$tree/stale.lock/pid"
	code=0
	table_set "$tree/stale" x "x: x" >/dev/null 2>"$tree/reap.err" || code=$?
	check "a stale lock is reaped" "$code" 0
	check "and the write lands" "$(grep -c '^x: x$' "$tree/stale")" 1
	out=$(cat "$tree/reap.err")
	case "$out" in
	*"reaping stale lock $tree/stale.lock"*) ;;
	*) printf 'FAIL: the reap names the lock; got [%s]\n' "$out" >&2
	   self_test_fails=$((self_test_fails + 1)) ;;
	esac

	# Three writers at once, the shape the lock exists for. The retry is in whole
	# seconds, so the count is kept under the five-second wait.
	touch "$tree/concurrent"
	i=0
	while [ "$i" -lt 3 ]; do
		table_set "$tree/concurrent" "user$i" "user$i: user$i" &
		i=$((i + 1))
	done
	wait
	check "concurrent appends all land" \
		"$(wc -l < "$tree/concurrent" | tr -d ' ')" 3
	check "and the lock is released" \
		"$([ -d "$tree/concurrent.lock" ] && printf held || printf free)" free

	self_test_end
}

case "${0##*/}:${1:-}" in
lib.sh:--self-test) self_test ;;
esac
