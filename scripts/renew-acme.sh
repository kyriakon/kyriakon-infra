#!/bin/ksh
# renew-acme.sh: renew every certificate this box has a domain block for,
# restarting only the daemons whose certificate changed, and making a renewal
# that does not happen visible.
#
# Runs ON the box as root (invoke under doas):
#
#   doas ksh renew-acme.sh
#
# crontab (root), daily, installed by scripts/cron-apply.sh rather than pasted in:
#
#   0 3 * * *  . /root/.kyriakon-env; /root/bin/renew-acme.sh
#
# The schedule, and what triggers a renewal. One daily run. acme-client asks the
# CA for a certificate only when less than a third of its lifetime is left, half
# of it when the lifetime is under 10 days, and exits 2 without asking for
# anything else (`man acme-client`, read on the box 2026-10-01). So a daily run
# renews within a day of a certificate becoming due and contacts the CA for
# nothing in between, which is why there is one line and no per-name timetable to
# keep in step with the certificates. This replaced two crontab one-liners that
# never ran: cron ends a command at the first unescaped '%', and their printf
# formats contained '%s', so every night handed /bin/sh a command cut in the
# middle of a quote. No '%' appears in this file.
#
# Exit codes carry the outcome. 0 means every certificate was renewed or was
# current; 1 means at least one was not, or was renewed into a daemon that did not
# come back. Output goes to stdout and stderr, which cron mails to root, and root
# is aliased to the operator. A clean run prints one line per certificate carrying
# its expiry date, so mail from this job means the schedule ran and the dates say
# how much margin is left; a failure prints a line beginning with the certificate
# name, the client's own words, and ends the run with a count.
#
# The issuance ceiling, and why renewals do not touch it. Let's Encrypt allows 50
# new certificates per registered domain per seven days, refilling one every 202
# minutes, and exempts an order that repeats the exact same set of identifiers as
# a renewal (docs/planning/research/cert-issuance-ceiling.md, section 2). Every
# block in the config renews with the set it was issued under, so this lane spends
# none of that budget and keeps running while the onboarding queue is waiting on
# it: a member who waits a day is an inconvenience, a certificate that lapses is
# an outage. Only a first issue for a new name spends budget, and that belongs to
# the queue (issue #166), along with ordering those requests oldest first, the
# wait, and the alert when the oldest one passes a stated age. None of that is
# duplicated here, and the queue's store (/var/db/kyriakon-acme-queue,
# scripts/acme-queue.sh) is never written from this lane: a renewal that queued
# would spend the slot a waiting first issue needs, which is the opposite of the
# exemption that keeps this lane running when the queue is backed up.
#
# The names come from /etc/acme-client.conf on every run, not from a list in this
# file. A list is how oliver.kyriakon.net went unrenewed while its domain block
# sat in the config and httpd and gmid both served it. A handle with no entry in
# services_for below stops the run instead of being renewed into no daemon, so a
# name cannot be added to the config without this script being told what holds it.
# Per-member certificates belong in a file the config includes (acme-client.conf(5)
# documents `include`), so that neither lane inherits the other's domain list.
#
# A Retry-After cannot be honoured here. acme-client 7.9 does not read that
# header, and it prints the ACME problem detail only for some replies, so a
# refused new-order reaches this script as "bad HTTP: 429" and nothing more:
# `strings /usr/sbin/acme-client | grep -i retry` on the box finds nothing. That
# case is reported as a rate limit rather than as a broken name, and the next
# attempt is the next daily run, which is longer than the 202-minute refill.
#
# Depends on: /etc/acme-client.conf, the challenge directory it names (or
# /home/www/acme, the one the web chroot can see), openssl from base, and lib.sh
# installed beside this file.

set -euo pipefail

# cron(8) hands jobs PATH=/usr/bin:/bin; packages live in /usr/local and the
# rcctl(8) and openssl(1) this script uses do not. Same line as the other box
# scripts, so the PATH needed on this box is written in one shape.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

[ "$(id -u)" -eq 0 ] || { printf 'run as root (doas ksh %s)\n' "$0" >&2; exit 1; }

script_dir="$(dirname "$0")"
if [ ! -f "$script_dir/lib.sh" ]; then
	printf '%s: lib.sh is not in %s. Install the two files together, as lib.sh describes.\n' \
		"$0" "$script_dir" >&2
	exit 1
fi

# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
. "$script_dir/lib.sh"

# ACME_CONF and EXPIRY_WARN_DAYS are overridable so the script can be pointed at
# a copy of the config, and so the warning threshold is a stated number rather
# than one buried in a comparison.
acme_conf="${ACME_CONF:-/etc/acme-client.conf}"
expiry_warn_days="${EXPIRY_WARN_DAYS:-14}"

# --- one run at a time ------------------------------------------------------
# mkdir is the atomic test-and-set available in base: this box has no shlock(1)
# and no flock(1), only the flock(2) syscall, which has no shell wrapper. Two
# acme-client processes on one name write the same key and certificate files, and
# a run stalled on the CA would otherwise overlap the next night's job. A lock
# left behind by a killed run is taken over once its pid is gone, so a reboot or a
# kill cannot wedge renewal.
lock=/var/run/renew-acme.lock
if ! mkdir -m 0700 "$lock" 2>/dev/null; then
	holder=$(cat "$lock/pid" 2>/dev/null || true)
	if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
		# Not a failure. The run holding the lock is doing today's work and
		# reports for itself, so this one says nothing and cron mails once.
		exit 0
	fi
	rm -f "$lock/pid"
	rmdir "$lock" 2>/dev/null || true
	if ! mkdir -m 0700 "$lock" 2>/dev/null; then
		printf '%s: could not take %s, and no live process holds it\n' "$0" "$lock" >&2
		exit 1
	fi
fi
printf '%s\n' "$$" > "$lock/pid"
trap 'rm -f "$lock/pid"; rmdir "$lock" 2>/dev/null || true' EXIT

# --- what needs renewing ----------------------------------------------------
[ -r "$acme_conf" ] || {
	printf '%s: %s is missing or unreadable, so nothing can be renewed\n' "$0" "$acme_conf" >&2
	exit 1
}

# One "<handle> <full chain path>" line per domain block. A block starts at
# column 0 and its settings are indented, so the two patterns cannot collide.
# Included files are deliberately not followed: those are the queue's names.
#
# Comment lines are skipped in this parse and in the challenge directory one
# below, because the config's prose names the settings it explains and a parser
# that reads prose finds settings that are not there. A comment reading
# '("duplicate challengedir" is an error within one block)' was parsed as a
# challenge directory called "duplicate", which stopped the run before a single
# certificate was asked for, every night. A setting is a line that is not a
# comment.
domains=$(awk '
	/^[ \t]*#/ { next }
	/^domain[ \t]/ { handle = $2; next }
	handle != "" && /domain full chain certificate/ {
		path = $5
		gsub(/"/, "", path)
		print handle, path
		handle = ""
	}
' "$acme_conf")

if [ -z "$domains" ]; then
	# A config this script cannot parse must not read as a clean run: that is a
	# certificate quietly stopping being renewed.
	printf '%s: no domain blocks found in %s\n' "$0" "$acme_conf" >&2
	exit 1
fi

# The HTTP-01 challenge file is written into the block's challengedir, or into
# /home/www/acme when a block names none. The fallback has to be inside httpd's
# chroot: a file written under /var/www is no longer served once httpd chroots to
# /home/www, so a challenge written there would never be read and every name
# would fail validation. One missing directory fails every name at
# once, and each failure spends one of the five authorization attempts allowed per
# identifier per hour, so the run stops before asking rather than spending them.
challenge_dirs=$(awk -F'"' '!/^[ \t]*#/ && /challengedir/ { print $2 }' "$acme_conf")
[ -n "$challenge_dirs" ] || challenge_dirs=/home/www/acme
for dir in $challenge_dirs; do
	if [ ! -d "$dir" ]; then
		printf '%s: the ACME challenge directory %s does not exist.\n' "$0" "$dir" >&2
		printf '  httpd serves it at /.well-known/acme-challenge/, and every domain in\n' >&2
		printf '  %s is validated through it. install -d -m 0755 %s\n' "$acme_conf" "$dir" >&2
		exit 1
	fi
done

# --- reporting --------------------------------------------------------------
# expiry_of <fullchain> : the date the certificate stops working, in openssl's own
# words, or an admission that the file is not there. Every line carries it, so a
# run that reads "still current" also says until when.
expiry_of() {
	if [ ! -f "$1" ]; then
		printf 'no certificate file at %s' "$1"
		return 0
	fi
	end=$(openssl x509 -noout -enddate -in "$1" 2>/dev/null | cut -d= -f2) || end=""
	if [ -n "$end" ]; then
		printf 'expires %s' "$end"
	else
		printf 'unreadable certificate at %s' "$1"
	fi
}

# inside_warn_window <fullchain> : true when the certificate expires within
# expiry_warn_days. -checkend does the comparison, so no date is parsed here.
inside_warn_window() {
	[ -f "$1" ] || return 1
	! openssl x509 -checkend "$(( expiry_warn_days * 86400 ))" -noout -in "$1" >/dev/null 2>&1
}

# services_for <handle> : the daemons holding that certificate, in restart order.
# Dovecot before smtpd on the mail host because smtpd delivers to Dovecot over
# LMTP, so bringing smtpd back first leaves it a window with no delivery target
# and bounces anything arriving inside it. gmid holds the apex and personal-site
# certificates as well as httpd (openbsd/etc/gmid.conf), and neither rc.d defines
# a reload action, so both are restarted rather than reloaded.
services_for() {
	case "$1" in
	mail.kyriakon.net) printf 'dovecot smtpd' ;;
	kyriakon.net | oliver.kyriakon.net) printf 'httpd gmid' ;;
	kyriakon.com) printf 'httpd' ;;
	*) return 1 ;;
	esac
}

total=0
failed=0

# renew <handle> <fullchain> <service>...
# The counter carries the outcome, not the return status: a failure on one
# certificate must not stop the others being attempted, and the run still exits
# non-zero so cron mails the result.
renew() {
	handle="$1"
	cert="$2"
	shift 2
	rc=0
	log=$(acme-client -v "$handle" 2>&1) || rc=$?
	case "$rc" in
	0)
		printf '%s: renewed, restarting %s (%s)\n' "$handle" "$*" "$(expiry_of "$cert")"
		if ! rcctl restart "$@"; then
			printf '%s: renewed, but restarting %s failed, so the daemon is still serving the old certificate\n' \
				"$handle" "$*" >&2
			failed=$(( failed + 1 ))
		fi
		;;
	2)
		printf '%s: still current, nothing restarted (%s)\n' "$handle" "$(expiry_of "$cert")"
		;;
	*)
		printf '%s: acme-client exited %s (%s)\n%s\n' \
			"$handle" "$rc" "$(expiry_of "$cert")" "$log" >&2
		case "$log" in
		*"bad HTTP: 429"*)
			printf '%s: the CA rate limited this order. A refusal spends no budget, and\n  acme-client 7.9 prints no Retry-After, so the next daily run is the retry.\n  Repeat occurrences: docs/planning/research/cert-issuance-ceiling.md\n' \
				"$handle" >&2
			;;
		esac
		if inside_warn_window "$cert"; then
			printf '%s: %s, inside the %s-day warning window, so this needs a human now\n' \
				"$handle" "$(expiry_of "$cert")" "$expiry_warn_days" >&2
		fi
		failed=$(( failed + 1 ))
		;;
	esac
	return 0
}

# Read from a here-document rather than a pipe: a piped loop runs in a subshell
# and the failure count would be lost with it, so a run where nothing renewed
# would exit 0.
while read -r handle cert; do
	total=$(( total + 1 ))
	if ! services=$(services_for "$handle"); then
		printf '%s: %s has no restart list in services_for, so it was not renewed.\n  A certificate renewed into no daemon is not a renewal; add the daemons that\n  serve it, then run this again.\n' \
			"$0" "$handle" >&2
		failed=$(( failed + 1 ))
		continue
	fi
	# shellcheck disable=SC2086 # services is a deliberate word list
	renew "$handle" "$cert" $services
done <<EOF
$domains
EOF

if [ "$failed" -ne 0 ]; then
	printf '%s: %s of %s certificates were not renewed, see above\n' "$0" "$failed" "$total" >&2
	exit 1
fi
printf '%s: %s certificates current or renewed\n' "$0" "$total"
