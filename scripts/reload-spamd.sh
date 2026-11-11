#!/bin/ksh
# reload-spamd.sh: make a spamd allow list line the drain just wrote live.
#
# Usage:
#   doas ksh scripts/reload-spamd.sh
#        ksh scripts/reload-spamd.sh --self-test
#
# Runs ON the box as root. spamd reads /etc/mail/spamd.alloweddomains once, when
# it starts, and /etc/rc.d/spamd defines no reload verb, so a line the drain
# appends or remove-group.sh drops is not live until spamd restarts. A group
# provisioned between mail deploys would otherwise still have its mail trapped
# and its senders blocklisted.
#
# A missing allow list is a note rather than an error: a box that has not run
# scripts/deploy-mail.sh has no list to reload, and the drain's own table write
# would already have refused.
#
# Idempotent in the sense that matters: a restart with the same list changes
# nothing a reader can see, so a retried intent pays one restart and no more.
#
# Env: SPAMD_ALLOWEDDOMAINS rebinds the path. The self-test rebinds it and
# replaces the restart, so it needs no root and touches nothing outside TMPDIR.

set -euo pipefail

# doas and cron both hand over a minimal PATH, and rcctl lives outside the
# default one.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

spamd_allowed=${SPAMD_ALLOWEDDOMAINS:-/etc/mail/spamd.alloweddomains}

usage() {
	cat >&2 <<'USAGE'
usage: doas ksh reload-spamd.sh
       ksh reload-spamd.sh --self-test
USAGE
	exit 2
}

# The restart, as a function so the self-test can record it instead of running it.
restart_spamd() { rcctl restart spamd >/dev/null; }

reload_spamd() {
	if [ ! -f "$spamd_allowed" ]; then
		printf 'note: no %s, so there is no spamd allow list to reload\n' "$spamd_allowed" >&2
		return 0
	fi
	restart_spamd
	printf 'restarted spamd, which reads the allow list at start\n'
}

# --- the self-test ----------------------------------------------------------
#
# The real function against a throwaway tree, with the restart recorded rather
# than run. What it proves is this script's own decision: restart for a list that
# is there, and say why when it is not.

self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$(dirname "$0")/lib.sh"
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	calls="$tree/calls"
	: >"$calls"
	spamd_allowed="$tree/spamd.alloweddomains"
	printf '@kyriakon.net\n' >"$spamd_allowed"
	restart_spamd() { printf 'rcctl restart spamd\n' >>"$calls"; }

	reload_spamd >"$tree/first.out" 2>&1
	check "an allow list restarts spamd" "$(wc -l <"$calls" | tr -d ' ')" 1
	check "and says so" "$(grep -c 'restarted spamd' "$tree/first.out")" 1

	spamd_allowed="$tree/absent.alloweddomains"
	reload_spamd >"$tree/second.out" 2>&1
	check "a missing allow list does not restart anything" \
		"$(wc -l <"$calls" | tr -d ' ')" 1
	check "and is a note naming the path" \
		"$(grep -c 'no spamd allow list' "$tree/second.out")" 1

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

reload_spamd
