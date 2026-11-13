#!/bin/ksh
# reload-smtpd.sh: make a virtual table line the drain just appended live.
#
# Usage:
#   doas ksh scripts/reload-smtpd.sh
#        ksh scripts/reload-smtpd.sh --self-test
#
# Runs ON the box as root. smtpd reads /etc/mail/virtuals and its own
# configuration when it starts and /etc/rc.d/smtpd defines no reload verb, so a
# line appended by the drain is not live until it restarts. provision-member.sh,
# delete-user.sh and remove-group.sh restart it inline for the same reason; a
# group's alias has no builder to do that, so the drain calls this instead.
#
# The filter's -d list is spliced into the configuration at deploy time, and a
# body's domain appended to /etc/mail/dkim_domains is not signed until it is
# spliced again: the filter would fall back to the platform's domain for the
# body's mail and its d= would not align with its From. So the configuration is
# re-rendered from the template deploy-mail.sh installed before the check and
# restart, in this one place, because every path that adds or drops a body's
# domain ends here.
#
# The configuration is checked first, so a table smtpd would refuse leaves the
# running daemon alone. A missing configuration is a note rather than an error: a
# box that has not run scripts/deploy-mail.sh has no table to reload, and the
# drain's own table write would already have refused. A box deployed before the
# template was installed has the older configuration only; that is a note too,
# and the next deploy-mail.sh installs the template.
#
# Idempotent in the sense that matters: a restart with the same table changes
# nothing a reader can see, so a retried intent pays one restart and no more.
#
# Env: SMTPD_CONF, SMTPD_TEMPLATE, DKIM_DOMAINS and QUEUE_KEY rebind the paths,
# and SMTPD_CONF is passed through by remove-group.sh. The self-test rebinds all
# four and replaces the two commands, so it needs no root and touches nothing
# outside TMPDIR.

set -euo pipefail

# doas and cron both hand over a minimal PATH, and smtpd and rcctl live outside
# the default one.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

script_dir=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

smtpd_conf=${SMTPD_CONF:-/etc/mail/smtpd.conf}
smtpd_template=${SMTPD_TEMPLATE:-/etc/mail/smtpd.conf.template}
dkim_domains=${DKIM_DOMAINS:-/etc/mail/dkim_domains}
queue_key_file=${QUEUE_KEY:-/etc/mail/queue.key}

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
	# The template beside the live file is what makes the re-render possible. A
	# box that predates it keeps the configuration deploy-mail.sh installed, and
	# the next deploy installs the template.
	if [ -f "$smtpd_template" ]; then
		if ! install_smtpd_conf "$smtpd_template" "$dkim_domains" \
			"$queue_key_file" "$smtpd_conf" smtpd; then
			printf 'refusing: %s could not be re-expanded from %s, so the running daemon is left alone\n' \
				"$smtpd_conf" "$dkim_domains" >&2
			return 1
		fi
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
# restart recorded rather than run. What it proves is this script's own
# decisions: re-render from the template, and reload only when the check passes.
self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work
	# smtpd -n validates the live tree, which this fixture does not have; the
	# deploy self-test proves the parser check itself.
	export SMTPD_CONF_CHECK=no

	calls="$tree/calls"
	: >"$calls"
	smtpd_conf="$tree/smtpd.conf"
	smtpd_template="$tree/smtpd.conf.template"
	dkim_domains="$tree/dkim_domains"
	queue_key_file="$tree/queue.key"
	printf 'kyriakon.net\n' > "$dkim_domains"
	printf '0123456789abcdef0123456789abcdef\n' > "$queue_key_file"
	# The live configuration deploy-mail.sh leaves. The render replaces it.
	: > "$smtpd_conf"
	printf 'queue encryption "REPLACE_ME_QUEUE_KEY"\nfilter "d" proc-exec "filter-dkimsign REPLACE_ME_DKIM_DOMAINS -s mail"\n' \
		> "$smtpd_template"
	smtpd_ok() { return 0; }
	restart_smtpd() { printf 'rcctl restart smtpd\n' >>"$calls"; }

	reload_smtpd >"$tree/first.out" 2>&1
	check "a good config restarts smtpd" \
		"$(wc -l <"$calls" | tr -d ' ')" 1
	check "and says so" "$(grep -c 'restarted smtpd' "$tree/first.out")" 1
	check "the configuration is rendered from the template" \
		"$(grep -c -- '-d kyriakon.net' "$smtpd_conf")" 1
	check "with the queue key substituted too" \
		"$(grep -c REPLACE_ME "$smtpd_conf")" 0

	# The property the ticket exists for: a body's domain appended to the list is
	# in the -d arguments after the next reload, without a deploy.
	printf 'kyriakon.net\nparish.example\n' > "$dkim_domains"
	reload_smtpd >"$tree/body.out" 2>&1
	check "a body's domain reaches the filter's -d list" \
		"$(grep -c -- '-d kyriakon.net -d parish.example' "$smtpd_conf")" 1
	check "and the reload still restarts once" \
		"$(wc -l <"$calls" | tr -d ' ')" 2

	# A line the renderer refuses can be in the table from before the intake was
	# tightened. It is skipped with a warning naming it, so the rest of the table
	# still renders and the daemon still restarts: one old record must not stop
	# every body's mail being signed after the fix.
	: >"$calls"
	printf 'kyriakon.net\nparish.12\n' > "$dkim_domains"
	reload_smtpd >"$tree/badline.out" 2>&1
	check "a line the renderer refuses does not block the reload" \
		"$(wc -l <"$calls" | tr -d ' ')" 1
	check "and the good domain is in the rendered filter" \
		"$(grep -c -- '-d kyriakon.net' "$smtpd_conf")" 1
	check "and the refused domain is not" \
		"$(grep -c 'parish.12' "$smtpd_conf" || true)" 0
	check "and the warning names it" \
		"$(grep -c 'not signed: parish.12' "$tree/badline.out")" 1

	# A list with nothing acceptable is still refused before the daemon is
	# touched: there is no filter to render.
	: >"$calls"
	printf 'not a domain\n' > "$dkim_domains"
	if reload_smtpd >"$tree/badlist.out" 2>&1; then
		code=0
	else
		code=$?
	fi
	check "a list with no acceptable domain is refused" "$code" 1
	check "and the daemon is not restarted" \
		"$(wc -l <"$calls" | tr -d ' ')" 0
	check "and the refusal says what could not be expanded" \
		"$(grep -c 'could not be re-expanded' "$tree/badlist.out")" 1
	printf 'kyriakon.net\n' > "$dkim_domains"

	# The queue key is smtpd's crypto key and must be exactly 32 characters. A
	# restored or hand-edited file of another length would stop the daemon, so the
	# render refuses rather than installing a config built from it.
	printf '0123456789abcdef\n' > "$queue_key_file"
	if reload_smtpd >"$tree/badkey.out" 2>&1; then
		code=0
	else
		code=$?
	fi
	check "a wrong-length queue key is refused" "$code" 1
	check "and names the file and the deploy that regenerates it" \
		"$(grep -c 'queue key, not 32; run scripts/deploy-mail.sh' "$tree/badkey.out")" 1
	check "and a bad key restarts nothing" \
		"$(wc -l <"$calls" | tr -d ' ')" 0
	printf '0123456789abcdef0123456789abcdef\n' > "$queue_key_file"

	smtpd_ok() { return 1; }
	if reload_smtpd >"$tree/second.out" 2>&1; then
		code=0
	else
		code=$?
	fi
	check "a rejected config is refused" "$code" 1
	check "and the daemon is not restarted" \
		"$(wc -l <"$calls" | tr -d ' ')" 0
	check "and the refusal says why" "$(grep -c 'left alone' "$tree/second.out")" 1

	# A box deployed before the template existed still restarts on the
	# configuration it has.
	rm -f "$smtpd_template"
	smtpd_ok() { return 0; }
	reload_smtpd >"$tree/third.out" 2>&1
	check "a missing template does not stop the reload" \
		"$(wc -l <"$calls" | tr -d ' ')" 1

	smtpd_conf="$tree/absent.conf"
	reload_smtpd >"$tree/fourth.out" 2>&1
	check "a missing config does not restart anything" \
		"$(wc -l <"$calls" | tr -d ' ')" 1
	check "and is a note naming the path" "$(grep -c 'no smtpd table' "$tree/fourth.out")" 1

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
