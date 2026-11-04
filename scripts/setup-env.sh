#!/bin/ksh
# setup-env.sh — install and check the box's values file, /root/.kyriakon-env.
#
# A value here overrides the default inside the script that reads it, which is the
# point, and also a trap: when a threshold is re-baselined in the script, a box whose
# env file still pins the old value keeps the old value. The ssh attempt threshold sat
# at 10 on the box for three weeks after the code moved to 300, because the env file
# was written when 10 was the default, and the monitor mailed the operator about
# ordinary scanning every hour until someone read the number in the alert. When a
# default changes, either update the line here or delete it and let the script decide.
#
# Run this FIRST on a box, before deploy-nsd.sh and deploy-mail.sh:
#
#   doas ksh scripts/setup-env.sh                       # install the template, report what is unfilled
#   doas ksh scripts/setup-env.sh --ipv4 ... --ipv6 ... --tsig-secret ... \
#        --restic-repository ... --restic-password-file ... \
#        --alert-email ... --healthchecks-url ... --keyring-healthchecks-url ... \
#        --rehearsal-healthchecks-url ...
#
# With no arguments it installs the repo template if the file is absent and
# reports what still needs filling in. With arguments, and the file already
# present, it merges: only the values given change, and every other line keeps
# what it had, comments included. Giving one value to a box that knows the rest
# is an update, not a typo.
#
# With arguments and no file at all, it writes the whole file and insists on all
# thirteen, because there is nothing to merge into and a half-filled new file is
# more likely a mistake than an intention. Nothing is written until the values it
# was given have been checked.
#
# Why it is its own step rather than part of a deploy: more than one deploy script
# needs those values, and nsd runs before mail, so leaving the install to any one
# of them makes the others depend on running in a particular order. The deploys
# call this when the file is absent instead of each carrying its own copy.
#
# One value is chosen here rather than passed in: TUI_PORT, the port the
# applicant-facing sshd will listen on. The box walks 2200-2299 in order for the
# first port that is neither listening nor named in /etc/services and records it
# under that name, once. It is not an argument, and a later run keeps the value
# it finds rather than choosing again.
#
# It never overwrites the file without arguments: the real one holds the TSIG
# secret and the alert topic, and rewriting it from the repo template would
# replace them with placeholders.

set -euo pipefail

script_dir="$(dirname "$0")"
template="${KYRIAKON_ENV_TEMPLATE:-$script_dir/../openbsd/etc/kyriakon.env}"
env_dst="${KYRIAKON_ENV:-/root/.kyriakon-env}"

# install_staged: the file every cron job sources is written through a sibling
# and renamed, so a run killed mid-copy leaves the old one rather than a
# truncated one that takes PATH and ALERT_EMAIL with it. lib.sh sources
# $KYRIAKON_ENV when it can, and that file is the one this script exists to
# repair, so it is pointed at /dev/null for the source: a broken line in it must
# not abort the run that would replace the line.
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
KYRIAKON_ENV=/dev/null . "$script_dir/lib.sh"

# The onboarding TUI's port is a property of the box, not a value an operator
# can be expected to know, so the box picks it here instead of taking it as an
# argument. The reserved range is 2200-2299.
tui_port_first=2200
tui_port_last=2299

# True when a port is already listening on either address family. netstat's
# local-address column ends in the port, so a suffix match covers a wildcard
# (0.0.0.0.2200, *.2200) as well as a bound address (127.0.0.1.2200). The match
# runs in awk rather than `| grep -q` because grep -q exits at its first hit and
# the resulting SIGPIPE to netstat would trip `set -o pipefail`.
port_listening() {
	netstat -na -f inet 2>/dev/null | awk -v p="$1" '$4 ~ ("[.:]" p "$") { f = 1 } END { exit !f }' ||
		netstat -na -f inet6 2>/dev/null | awk -v p="$1" '$4 ~ ("[.:]" p "$") { f = 1 } END { exit !f }'
}

# True when /etc/services names the port. sshd takes any numeric port whether or
# not /etc/services names it, so this is not about the daemon rejecting the
# value: a name there marks a port a stock box already accounts for, and the
# range is walked to stay clear of those.
port_named_in_services() {
	awk -v p="$1" '$2 ~ ("^" p "/(tcp|udp)$") { f = 1 } END { exit !f }' /etc/services
}

# The first free port in the range. Returning nothing is a failure, not a
# fallback: an unreviewed listener on an arbitrary port is worse than a build
# that stops.
choose_tui_port() {
	p=$tui_port_first
	while [ "$p" -le "$tui_port_last" ]; do
		if ! port_listening "$p" && ! port_named_in_services "$p"; then
			printf '%s\n' "$p"
			return 0
		fi
		p=$((p + 1))
	done
	return 1
}

# merge_env <pairs>: rewrite $env_dst with each KEY=value line replaced by the
# given one, appended when the file has never had it, and every other line —
# comments and the PATH block included — passed through untouched. Written
# through install_staged, so the file the cron lines source is either the old one
# or the whole new one and never a partial copy.
merge_env() {
	typeset pairs="$1" tmp
	tmp=$(mktemp)
	# Through the environment rather than -v: awk reinterprets escape
	# sequences in a -v assignment, and these pairs are newline-separated,
	# which -v rejects outright.
	PAIRS="$pairs" awk -v q="'" '
		BEGIN { n = split(ENVIRON["PAIRS"], p, "\n")
			for (i = 1; i <= n; i++) {
				eq = index(p[i], "=")
				if (eq > 0) want[substr(p[i], 1, eq - 1)] = substr(p[i], eq + 1)
			} }
		{
			for (k in want) {
				if (index($0, "export " k "=") == 1) {
					print "export " k "=" q want[k] q
					delete want[k]
					next
				}
			}
			print
		}
		END { for (k in want) print "export " k "=" q want[k] q }
	' "$env_dst" > "$tmp"
	install_staged "$tmp" "$env_dst" -m 0600 || {
		rm -f "$tmp"
		return 1
	}
	rm -f "$tmp"
}

# append_env <block>: $env_dst with <block> appended, through the same staged
# write as the merge. These blocks are not a merge, but they land in the same
# file: a short append is a syntax error in the file every cron line sources.
append_env() {
	typeset block="$1" tmp
	tmp=$(mktemp)
	{
		cat "$env_dst"
		printf '%s\n' "$block"
	} > "$tmp"
	install_staged "$tmp" "$env_dst" -m 0600 || {
		rm -f "$tmp"
		return 1
	}
	rm -f "$tmp"
}

# --- self-test ---------------------------------------------------------------
#
# The merge is the path every later run takes, and it is where a lost comment or
# a lost PATH block would go unnoticed until a cron job failed at 02:30. The
# rename is the other half: this file must be the old one or the whole new one,
# because every cron line sources it. Runs as anyone, writes only under TMPDIR.

self_test() {
	typeset tree fixture before stub code
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work
	fixture=$tree/kyriakon.env
	cat > "$fixture" <<'EOF'
# a comment that has to survive the merge
export KYRIAKON_IPV4='203.0.113.9'
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH
export ALERT_EMAIL='old@example.invalid'
EOF
	env_dst=$fixture

	merge_env "ALERT_EMAIL=new@example.invalid
KYRIAKON_IPV6=2001:db8::10"

	check "the given value is replaced" \
		"$(grep -c "^export ALERT_EMAIL='new@example.invalid'" "$fixture")" 1
	check "a value the file had not seen is appended" \
		"$(grep -c "^export KYRIAKON_IPV6='2001:db8::10'" "$fixture")" 1
	check "a value not given keeps what it had" \
		"$(grep -c "^export KYRIAKON_IPV4='203.0.113.9'" "$fixture")" 1
	check "the comment survives" \
		"$(grep -c '^# a comment that has to survive the merge$' "$fixture")" 1
	check "the PATH block survives" "$(grep -c '^export PATH$' "$fixture")" 1
	# shellcheck disable=SC2016 # the literal text written to the file, not this script's PATH
	check "with its literal value" \
		"$(grep -cF 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"' "$fixture")" 1
	check "the file is mode 0600" "$(stat -f '%Lp' "$fixture")" 600

	# A write killed between the copy and the rename: the rename is stubbed to
	# fail, which is what a crash at that point looks like, and the file every
	# cron job sources has to be untouched rather than half written.
	before=$(cat "$fixture")
	stub=$tree/bin
	mkdir "$stub"
	printf '#!/bin/sh\nexit 1\n' > "$stub/mv"
	chmod +x "$stub/mv"
	code=0
	# shellcheck disable=SC2030,SC2031 # the stub PATH is for this call only
	( PATH="$stub:$PATH"; merge_env "ALERT_EMAIL=lost@example.invalid" ) \
		> "$tree/failed.out" 2>&1 || code=$?
	check "a rename that fails is a failure" "$code" 1
	check "and says the file was left as it was" \
		"$(grep -c 'left as it was' "$tree/failed.out")" 1
	check "and the file is untouched" "$(cat "$fixture")" "$before"
	set -- "$tree"/*.new.*
	check "and no candidate is left behind" \
		"$([ -e "$1" ] && printf yes || printf no)" no

	# The two blocks the script appends are the same file and the same hazard.
	append_env "
# an appended block
export TITAN_PORT='1966'"
	check "an appended block lands" "$(grep -c '^export TITAN_PORT=' "$fixture")" 1
	check "and the file it joined survives" \
		"$(grep -c '^# a comment that has to survive the merge$' "$fixture")" 1
	check "and it stays 0600" "$(stat -f '%Lp' "$fixture")" 600
	before=$(cat "$fixture")
	code=0
	# shellcheck disable=SC2030,SC2031 # the stub PATH is for this call only
	( PATH="$stub:$PATH"; append_env "export TUI_PORT='2299'" ) \
		> "$tree/append-failed.out" 2>&1 || code=$?
	check "an append that cannot be renamed is a failure" "$code" 1
	check "and leaves the file as it was" "$(cat "$fixture")" "$before"

	# The script itself, over a file it has to repair. The source at the top
	# points lib.sh at /dev/null, so an unterminated line here cannot abort the
	# run that replaces it; without that, the box's only env file could not be
	# fixed by the script that owns it.
	broken=$tree/broken.env
	cat > "$broken" <<'EOF'
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH
export KYRIAKON_IPV4='203.0.113.9'
export KYRIAKON_IPV6='2001:db8::9'
export KYRIAKON_TSIG_SECRET='not-a-secret'
export RESTIC_REPOSITORY='sftp://example.invalid/repo'
export RESTIC_PASSWORD_FILE='/root/.restic-pass'
export ALERT_EMAIL='unterminated
export HEALTHCHECKS_URL='https://hc-ping.com/example'
export KEYRING_HEALTHCHECKS_URL='https://hc-ping.com/example'
export REHEARSAL_HEALTHCHECKS_URL='https://hc-ping.com/example'
export HCLOUD_TOKEN='example'
export RESTORE_TEST_REPOSITORY='sftp://example.invalid/'
export RESTORE_TEST_HEALTHCHECKS_URL='https://hc-ping.com/example'
export POSTAL_ADDRESS='1 Example Street'
EOF
	code=0
	KYRIAKON_ENV="$broken" ksh "$script_dir/setup-env.sh" \
		--alert-email fixed@example.invalid > "$tree/broken.out" 2>&1 || code=$?
	check "a broken env file does not stop the run that repairs it" "$code" 0
	check "and the broken line is replaced" \
		"$(grep -c "^export ALERT_EMAIL='fixed@example.invalid'" "$broken")" 1
	check "and the PATH block is still there" "$(grep -c '^export PATH$' "$broken")" 1
	check "and TUI_PORT is appended where it was absent" \
		"$(grep -c '^export TUI_PORT=' "$broken")" 1
	check "and TITAN_PORT too" "$(grep -c '^export TITAN_PORT=' "$broken")" 1

	self_test_end
}

vars="KYRIAKON_IPV4 KYRIAKON_IPV6 KYRIAKON_TSIG_SECRET RESTIC_REPOSITORY RESTIC_PASSWORD_FILE ALERT_EMAIL HEALTHCHECKS_URL KEYRING_HEALTHCHECKS_URL REHEARSAL_HEALTHCHECKS_URL HCLOUD_TOKEN RESTORE_TEST_REPOSITORY RESTORE_TEST_HEALTHCHECKS_URL POSTAL_ADDRESS"

usage() {
	cat >&2 <<'EOF'
usage: doas ksh setup-env.sh [--ipv4 A --ipv6 B --tsig-secret C
                             --restic-repository D --restic-password-file E
                             --alert-email F --healthchecks-url G
                             --keyring-healthchecks-url H
                             --rehearsal-healthchecks-url I
                             --hcloud-token J --restore-test-repository K
                             --restore-test-healthchecks-url L
                             --postal-address M
                             [--ico-reference N --eu-representative O
                              --eu-representative-contact P]]
       ksh scripts/setup-env.sh --self-test

  No arguments: install the template if /root/.kyriakon-env is absent, then
  report which values are still missing or placeholders.

  The last three are optional. The site build's privacy notice needs them, and
  refuses to render until they are set. Set them here when those decisions are
  made.

  Some arguments, file present: update just those values. Everything else keeps
  what it had, comments and the PATH block included. This is how a box that is
  already deployed is given a value it did not have.

  All thirteen arguments, no file: write it from them, mode 0600. All or nothing
  when creating one, and each value is checked before anything is written.

    doas ksh scripts/setup-env.sh \
      --ipv4 203.0.113.10 --ipv6 2001:db8::10 \
      --tsig-secret "$(openssl rand -base64 32)" \
      --restic-repository 'sftp://user@host:23/kyriakon-backup' \
      --restic-password-file /root/.restic-pass \
      --alert-email you@example.invalid \
      --healthchecks-url https://hc-ping.com/<uuid> \
      --rehearsal-healthchecks-url https://hc-ping.com/<uuid> \
      --hcloud-token "$(pass kyriakon/hetzner-terraform-api-key)" \
      --restore-test-repository 'sftp://user-sub1@host:23/' \
      --restore-test-healthchecks-url https://hc-ping.com/<uuid> \
      --postal-address '1 Example Street, Example'
EOF
	exit 2
}

case "${1:-}" in
--self-test)
	[ "$#" -eq 1 ] || usage
	self_test
	;;
esac

a_ipv4=
a_ipv6=
a_tsig=
a_repo=
a_pass=
a_email=
a_hc=
a_keyring_hc=
a_reh=
a_hcloud=
a_restrepo=
a_resthc=
a_postal=
a_ico=
a_rep=
a_rep_contact=
while [ "$#" -gt 0 ]; do
	[ "$#" -ge 2 ] || usage
	case "$1" in
	--ipv4) a_ipv4="$2" ;;
	--ipv6) a_ipv6="$2" ;;
	--tsig-secret) a_tsig="$2" ;;
	--restic-repository) a_repo="$2" ;;
	--restic-password-file) a_pass="$2" ;;
	--alert-email) a_email="$2" ;;
	--healthchecks-url) a_hc="$2" ;;
	--keyring-healthchecks-url) a_keyring_hc="$2" ;;
	--rehearsal-healthchecks-url) a_reh="$2" ;;
	--hcloud-token) a_hcloud="$2" ;;
	--restore-test-repository) a_restrepo="$2" ;;
	--restore-test-healthchecks-url) a_resthc="$2" ;;
	--postal-address) a_postal="$2" ;;
	--ico-reference) a_ico="$2" ;;
	--eu-representative) a_rep="$2" ;;
	--eu-representative-contact) a_rep_contact="$2" ;;
	*) usage ;;
	esac
	shift 2
done

given=0
for v in "$a_ipv4" "$a_ipv6" "$a_tsig" "$a_repo" "$a_pass" "$a_email" "$a_hc" "$a_keyring_hc" "$a_reh" "$a_hcloud" "$a_restrepo" "$a_resthc" "$a_postal" "$a_ico" "$a_rep" "$a_rep_contact"; do
	if [ -n "$v" ]; then
		given=$((given + 1))
	fi
done

if [ "$given" -gt 0 ]; then
	# Both paths need every value present, and the merge path is the only one that
	# may arrive without them.
	if [ ! -f "$env_dst" ]; then
		missing=""
		if [ -z "$a_ipv4" ]; then missing="$missing KYRIAKON_IPV4"; fi
		if [ -z "$a_ipv6" ]; then missing="$missing KYRIAKON_IPV6"; fi
		if [ -z "$a_tsig" ]; then missing="$missing KYRIAKON_TSIG_SECRET"; fi
		if [ -z "$a_repo" ]; then missing="$missing RESTIC_REPOSITORY"; fi
		if [ -z "$a_pass" ]; then missing="$missing RESTIC_PASSWORD_FILE"; fi
		if [ -z "$a_email" ]; then missing="$missing ALERT_EMAIL"; fi
		if [ -z "$a_hc" ]; then missing="$missing HEALTHCHECKS_URL"; fi
		if [ -z "$a_keyring_hc" ]; then missing="$missing KEYRING_HEALTHCHECKS_URL"; fi
		if [ -z "$a_reh" ]; then missing="$missing REHEARSAL_HEALTHCHECKS_URL"; fi
		if [ -z "$a_hcloud" ]; then missing="$missing HCLOUD_TOKEN"; fi
		if [ -z "$a_restrepo" ]; then missing="$missing RESTORE_TEST_REPOSITORY"; fi
		if [ -z "$a_resthc" ]; then missing="$missing RESTORE_TEST_HEALTHCHECKS_URL"; fi
		if [ -z "$a_postal" ]; then missing="$missing POSTAL_ADDRESS"; fi
		if [ -n "$missing" ]; then
			printf 'setup-env: %s does not exist yet, so all thirteen arguments are needed; missing:%s\n\n' "$env_dst" "$missing" >&2
			usage
		fi
	fi

	# Check before writing anything, so a typo fails here and not in a deploy.
	# Only the values actually given are checked; the merge path has no others.
	if [ -n "$a_ipv4" ]; then
		printf '%s' "$a_ipv4" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
			|| { printf 'setup-env: not an IPv4 address: %s\n' "$a_ipv4" >&2; exit 2; }
	fi
	if [ -n "$a_ipv6" ]; then
		printf '%s' "$a_ipv6" | grep -q ':' \
			|| { printf 'setup-env: not an IPv6 address: %s\n' "$a_ipv6" >&2; exit 2; }
	fi
	if [ -n "$a_tsig" ]; then
		case "$a_tsig" in
		REPLACE_ME) printf 'setup-env: tsig-secret is a placeholder\n' >&2; exit 2 ;;
		esac
		printf '%s' "$a_tsig" | grep -Eq '^[A-Za-z0-9+/=]+$' \
			|| { printf 'setup-env: tsig-secret is not clean base64\n' >&2; exit 2; }
	fi
	for u in "$a_hc" "$a_keyring_hc" "$a_reh" "$a_resthc"; do
		[ -n "$u" ] || continue
		printf '%s' "$u" | grep -Eq '^https?://' \
			|| { printf 'setup-env: not a URL: %s\n' "$u" >&2; exit 2; }
	done
	if [ -n "$a_restrepo" ]; then
		printf '%s' "$a_restrepo" | grep -Eq '^sftp://' \
			|| { printf 'setup-env: not an sftp URL: %s\n' "$a_restrepo" >&2; exit 2; }
	fi
	# The restore test must hold read-only credentials, or a fault on a throwaway box
	# could damage the repository it is checking. Hetzner names a storage sub-account
	# after its parent, so the absence of -sub is worth saying out loud rather than
	# refusing on: it is a convention, not a guarantee.
	case "${a_restrepo:-sub}" in
	*sub*) ;;
	*) printf 'setup-env: warning: %s does not look like a sub-account URL. The restore test must not hold the backup account credentials.\n' "$a_restrepo" >&2 ;;
	esac
	# The file expresses values as single-quoted shell words, so a value
	# containing a quote cannot be represented in it.
	for v in "$a_ipv4" "$a_ipv6" "$a_tsig" "$a_repo" "$a_pass" "$a_email" "$a_hc" "$a_keyring_hc" "$a_reh" "$a_hcloud" "$a_restrepo" "$a_resthc" "$a_postal" "$a_ico" "$a_rep" "$a_rep_contact"; do
		case "$v" in
		*"'"*) printf 'setup-env: a value contains a single quote, which this file cannot express\n' >&2; exit 2 ;;
		esac
	done
	for v in "$a_ico" "$a_rep" "$a_rep_contact"; do
		[ -n "$v" ] || continue
		case "$v" in
		REPLACE_ME*) printf 'setup-env: %s is a placeholder\n' "$v" >&2; exit 2 ;;
		esac
	done

	if [ -f "$env_dst" ]; then
		# Merge. Each given value replaces its own line, or is appended if the
		# file has never had it. Everything else, comments and the PATH block
		# included, is passed through untouched.
		pairs=""
		for kv in "KYRIAKON_IPV4=$a_ipv4" "KYRIAKON_IPV6=$a_ipv6" "KYRIAKON_TSIG_SECRET=$a_tsig" \
			"RESTIC_REPOSITORY=$a_repo" "RESTIC_PASSWORD_FILE=$a_pass" "ALERT_EMAIL=$a_email" \
			"HEALTHCHECKS_URL=$a_hc" "KEYRING_HEALTHCHECKS_URL=$a_keyring_hc" \
			"REHEARSAL_HEALTHCHECKS_URL=$a_reh" "HCLOUD_TOKEN=$a_hcloud" \
			"RESTORE_TEST_REPOSITORY=$a_restrepo" "RESTORE_TEST_HEALTHCHECKS_URL=$a_resthc" \
			"POSTAL_ADDRESS=$a_postal" "ICO_REFERENCE=$a_ico" \
			"EU_REPRESENTATIVE=$a_rep" "EU_REPRESENTATIVE_CONTACT=$a_rep_contact"; do
			case "$kv" in
			*=) continue ;;
			esac
			pairs="$pairs
$kv"
		done
		merge_env "$pairs"
		printf 'updated %s with %s value(s); the rest kept what they had\n' "$env_dst" "$given"
	else
	tmp=$(mktemp)
	{
		printf '# Written by setup-env.sh. Mode 0600: this file holds secrets.\n'
		# Quoted heredoc: $PATH is the literal text to write, not this script's
		# value, which is what shellcheck's SC2016 would otherwise flag.
		cat <<-'EOF'
			# cron(8) jobs get PATH=/usr/bin:/bin, where curl, ifconfig and
			# acme-client are all absent; every cron line sources this file.
			PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
			export PATH
		EOF
		printf "export KYRIAKON_IPV4='%s'\n" "$a_ipv4"
		printf "export KYRIAKON_IPV6='%s'\n" "$a_ipv6"
		printf "export KYRIAKON_TSIG_SECRET='%s'\n" "$a_tsig"
		printf "export RESTIC_REPOSITORY='%s'\n" "$a_repo"
		printf "export RESTIC_PASSWORD_FILE='%s'\n" "$a_pass"
		printf "export ALERT_EMAIL='%s'\n" "$a_email"
		printf "export HEALTHCHECKS_URL='%s'\n" "$a_hc"
		printf "export KEYRING_HEALTHCHECKS_URL='%s'\n" "$a_keyring_hc"
		printf "export REHEARSAL_HEALTHCHECKS_URL='%s'\n" "$a_reh"
		printf "export HCLOUD_TOKEN='%s'\n" "$a_hcloud"
		printf "export RESTORE_TEST_REPOSITORY='%s'\n" "$a_restrepo"
		printf "export RESTORE_TEST_HEALTHCHECKS_URL='%s'\n" "$a_resthc"
		printf "export POSTAL_ADDRESS='%s'\n" "$a_postal"
		if [ -n "$a_ico" ]; then printf "export ICO_REFERENCE='%s'\n" "$a_ico"; fi
		if [ -n "$a_rep" ]; then printf "export EU_REPRESENTATIVE='%s'\n" "$a_rep"; fi
		if [ -n "$a_rep_contact" ]; then printf "export EU_REPRESENTATIVE_CONTACT='%s'\n" "$a_rep_contact"; fi
	} > "$tmp"
	if ! install_staged "$tmp" "$env_dst" -m 0600; then
		rm -f "$tmp"
		exit 1
	fi
	rm -f "$tmp"
	printf 'wrote %s from the arguments\n' "$env_dst"
	fi
elif [ ! -f "$env_dst" ]; then
	[ -r "$template" ] || {
		printf 'setup-env: no %s, and no template at %s\n' "$env_dst" "$template" >&2
		exit 1
	}
	install_staged "$template" "$env_dst" -m 0600
	printf 'installed %s from %s\n' "$env_dst" "$template"
fi

# TUI_PORT is the one value here the box chooses rather than the operator, so it
# is filled in whenever the line is absent: on the template install, on a fresh
# write from arguments, and on a re-run against a file written before this
# change. An existing value is kept untouched, which is what makes it recorded
# once: a later run must not move a port the firewall has already been told
# about.
if ! grep -q '^export TUI_PORT=' "$env_dst"; then
	if ! tui_port=$(choose_tui_port); then
		printf 'setup-env: nothing in %s-%s is free for the onboarding TUI sshd; not choosing a port\n' \
			"$tui_port_first" "$tui_port_last" >&2
		exit 1
	fi
	append_env "$(printf '
# The port the applicant-facing sshd listens on, chosen from the free
# ports in 2200-2299. The installed /etc/ssh/sshd_config.onboard carries
# it on its Port line. The firewall rule that opens it is a later ticket and
# is not built here; it will read this value rather than carry its own.
export TUI_PORT=%s' "'$tui_port'")"
	printf 'chose %s for the onboarding TUI (TUI_PORT)\n' "$tui_port"
fi

# TITAN_PORT is fixed rather than chosen: relayd's commented listener block names
# it, and scripts/pf-apply.sh opens the same value. It is appended only when the
# line is absent, so a re-run against a file written before this change gains it
# and a box that has already chosen a different one keeps what it has.
if ! grep -q '^export TITAN_PORT=' "$env_dst"; then
	append_env "
# The public port the Titan upload listener is reached on, behind relayd.
# scripts/pf-apply.sh proposes the firewall rule for it; the relayd block
# stays commented until an operator opens both by hand.
export TITAN_PORT='1966'"
	printf 'recorded 1966 for the Titan listener (TITAN_PORT)\n'
fi

missing=""
placeholder=""
for v in $vars; do
	if ! grep -q "^export $v=" "$env_dst"; then
		missing="$missing $v"
	elif grep -q "^export $v='.*REPLACE_ME" "$env_dst"; then
		placeholder="$placeholder $v"
	fi
done

if [ -n "$missing" ] || [ -n "$placeholder" ]; then
	if [ -n "$missing" ]; then
		printf 'not set in %s:%s\n' "$env_dst" "$missing"
	fi
	if [ -n "$placeholder" ]; then
		printf 'still a placeholder in %s:%s\n' "$env_dst" "$placeholder"
	fi
	printf '\nPass them as arguments, or fill them in and re-run this script.\n\n'
	printf 'Where the values already exist on this box:\n'
	printf '  KYRIAKON_IPV4, KYRIAKON_IPV6   terraform output ipv4_address ipv6_address\n'
	printf '  KYRIAKON_TSIG_SECRET           the kyriakon-he key in /var/nsd/etc/nsd.conf\n'
	printf '  RESTIC_REPOSITORY             the crontab line of a backup that works\n'
	printf '  RESTIC_PASSWORD_FILE          /root/.restic-pass\n'
	printf '  ALERT_EMAIL                   an address off this box, where alerts are mailed\n'
	printf '  HEALTHCHECKS_URL              this box'"'"'s own check, not another box'"'"'s\n'
	printf '  REHEARSAL_HEALTHCHECKS_URL    belongs on the rehearsal box, not this one\n'
	printf '  POSTAL_ADDRESS                the address the cash-by-post rail gives out\n'
	exit 1
fi

# Report the permissions rather than asserting them: a file that predates this
# script, or one edited by hand, may be readable by more than root, and it holds
# the TSIG secret and the alert topic.
printf '%s is complete (%s %s)\n' "$env_dst" "$(stat -f '%Su:%Sg' "$env_dst")" "$(stat -f '%Lp' "$env_dst")"
if [ "$(stat -f '%Lp' "$env_dst")" != 600 ]; then
	printf 'setup-env: mode is not 600, and this file holds secrets. Fix: chmod 600 %s\n' "$env_dst" >&2
	exit 1
fi
