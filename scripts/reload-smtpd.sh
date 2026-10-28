#!/bin/ksh
# reload-smtpd.sh: make a virtual table line the drain just appended live.
#
# Usage:
#   doas ksh scripts/reload-smtpd.sh
#        ksh scripts/reload-smtpd.sh --self-test
#
# Runs ON the box as root. smtpd reads /etc/mail/virtuals when it starts and
# /etc/rc.d/smtpd defines no reload verb, so a line appended by the drain is not
# live until it restarts. provision-member.sh and delete-user.sh restart it
# inline for the same reason; a group's alias has no builder to do that, so the
# drain calls this instead.
#
# The configuration is checked first, so a table smtpd would refuse leaves the
# running daemon alone. A missing configuration is a note rather than an error: a
# box that has not run scripts/deploy-mail.sh has no table to reload, and the
# drain's own table write would already have refused.
#
# Idempotent in the sense that matters: a restart with the same table changes
# nothing a reader can see, so a retried intent pays one restart and no more.
#
# Env: none. The self-test rebinds the one path and replaces the two commands, so
# it needs no root and touches nothing outside TMPDIR.

set -euo pipefail

# doas and cron both hand over a minimal PATH, and smtpd and rcctl live outside
# the default one.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

smtpd_conf=${SMTPD_CONF:-/etc/mail/smtpd.conf}

usage() {
	cat >&2 <<'USAGE'
usage: doas ksh reload-smtpd.sh
       ksh reload-smtpd.sh --self-test
USAGE
	exit 2
}

# The two commands, as functions so the self-test can replace them. The check
# comes before the restart in every caller: a table smtpd would reject must not
# replace the running configuration.
smtpd_ok() { smtpd -n -f "$smtpd_conf"; }
restart_smtpd() { rcctl restart smtpd >/dev/null; }

reload_smtpd() {
	if [ ! -f "$smtpd_conf" ]; then
		printf 'note: no %s, so there is no smtpd table to reload\n' "$smtpd_conf" >&2
		return 0
	fi
	if smtpd_ok; then
		restart_smtpd
		printf 'restarted smtpd, which reads the table at start\n'
	else
		printf 'refusing: smtpd -n rejected %s, so the running daemon is left alone\n' \
			"$smtpd_conf" >&2
		return 1
	fi
}

# --- the self-test ----------------------------------------------------------
#
# The real function against a throwaway tree, with the config check and the
# restart recorded rather than run. What it proves is this script's own decision:
# reload only when the check passes.
self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$(dirname "$0")/lib.sh"
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	calls="$tree/calls"
	: >"$calls"
	smtpd_conf="$tree/smtpd.conf"
	: >"$smtpd_conf"
	smtpd_ok() { return 0; }
	restart_smtpd() { printf 'rcctl restart smtpd\n' >>"$calls"; }

	reload_smtpd >"$tree/first.out" 2>&1
	check "a good config restarts smtpd" \
		"$(wc -l <"$calls" | tr -d ' ')" 1
	check "and says so" "$(grep -c 'restarted smtpd' "$tree/first.out")" 1

	smtpd_ok() { return 1; }
	if reload_smtpd >"$tree/second.out" 2>&1; then
		code=0
	else
		code=$?
	fi
	check "a rejected config is refused" "$code" 1
	check "and the daemon is not restarted" \
		"$(wc -l <"$calls" | tr -d ' ')" 1
	check "and the refusal says why" "$(grep -c 'left alone' "$tree/second.out")" 1

	smtpd_conf="$tree/absent.conf"
	reload_smtpd >"$tree/third.out" 2>&1
	check "a missing config does not restart anything" \
		"$(wc -l <"$calls" | tr -d ' ')" 1
	check "and is a note naming the path" "$(grep -c 'no smtpd table' "$tree/third.out")" 1

	self_test_end
}

# --- the entry --------------------------------------------------------------

self_test_mode=no
case "${1:-}" in
--self-test) self_test_mode=yes ;;
"") ;;
*) usage ;;
esac

if [ "$self_test_mode" = yes ]; then
	self_test
fi

if [ "$#" -ne 0 ]; then
	usage
fi

if [ "$(id -u)" -ne 0 ]; then
	printf 'must run as root: doas ksh %s\n' "$0" >&2
	exit 1
fi

reload_smtpd
