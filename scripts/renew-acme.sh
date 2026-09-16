#!/bin/ksh
# renew-acme.sh: renew the mail and landing-site certificates, restarting only
# the daemons whose certificate changed.
#
# Runs ON the box as root (invoke under doas).
#
# Usage:
#   doas ksh renew-acme.sh
#
# crontab (root), daily. acme-client renews only inside the 30 days before
# expiry and exits 2 when the certificate is still current, so a daily run
# issues nothing it does not have to:
#   0 3 * * *  /root/bin/renew-acme.sh
#
# Why this is a script and not two crontab one-liners: cron(8) ends the command
# at the first unescaped '%' and passes the remainder to the command on stdin.
# The one-liners needed printf format strings, so every run was handed a command
# cut in the middle of a quote and failed with "/bin/sh: no closing quote". The
# failure arrived as mail from the cron daemon, so a renewal that never happened
# looked like ordinary system mail. No '%' appears in this file's crontab line.

set -euo pipefail

PATH="/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

[ "$(id -u)" -eq 0 ] || { printf 'run as root (doas ksh %s)\n' "$0" >&2; exit 1; }

# renew <domain> <service>...: one certificate and the daemons that hold it.
# Dovecot restarts before smtpd on the mail host because smtpd delivers to
# Dovecot over LMTP, so bringing smtpd back first leaves it a window with no
# delivery target and bounces anything that arrives inside it.
#
# acme-client exit codes: 0 issued or renewed, 2 still current, anything else a
# failure. A failure on one certificate does not stop the other from being
# attempted, and the script still exits non-zero so the run reaches cron's mail.
failed=0
renew() {
	domain="$1"
	shift
	rc=0
	log=$(acme-client -v "$domain" 2>&1) || rc=$?
	case "$rc" in
	0) printf '%s: renewed, restarting %s\n' "$domain" "$*"
	   rcctl restart "$@" ;;
	2) printf '%s: still current, nothing restarted\n' "$domain" ;;
	*) printf '%s: acme-client exited %s\n%s\n' "$domain" "$rc" "$log" >&2
	   failed=1 ;;
	esac
}

renew mail.kyriakon.net dovecot smtpd
renew kyriakon.net httpd

if [ "$failed" -ne 0 ]; then
	exit 1
fi
printf 'certificates current or renewed\n'
