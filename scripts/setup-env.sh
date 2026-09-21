#!/bin/ksh
# setup-env.sh — install and check the box's values file, /root/.kyriakon-env.
#
# Run this FIRST on a box, before deploy-nsd.sh and deploy-mail.sh:
#
#   doas ksh scripts/setup-env.sh                       # install the template, report what is unfilled
#   doas ksh scripts/setup-env.sh --ipv4 ... --ipv6 ... --tsig-secret ... \
#        --restic-repository ... --restic-password-file ... \
#        --alert-topic ... --healthchecks-url ... --rehearsal-healthchecks-url ...
#
# With no arguments it installs the repo template if the file is absent and
# reports what still needs filling in. With arguments it writes the file from
# them, and refuses unless every value is given: a partial set is a typo, not an
# intention, and the failure belongs here rather than halfway through a deploy.
# Nothing is written until every value has been checked.
#
# Why it is its own step rather than part of a deploy: more than one deploy script
# needs those values, and nsd runs before mail, so leaving the install to any one
# of them makes the others depend on running in a particular order. The deploys
# call this when the file is absent instead of each carrying its own copy.
#
# It never overwrites the file without arguments: the real one holds the TSIG
# secret and the alert topic, and rewriting it from the repo template would
# replace them with placeholders.

set -euo pipefail

script_dir="$(dirname "$0")"
template="${KYRIAKON_ENV_TEMPLATE:-$script_dir/../openbsd/etc/kyriakon.env}"
env_dst="${KYRIAKON_ENV:-/root/.kyriakon-env}"

vars="KYRIAKON_IPV4 KYRIAKON_IPV6 KYRIAKON_TSIG_SECRET RESTIC_REPOSITORY RESTIC_PASSWORD_FILE ALERT_TOPIC HEALTHCHECKS_URL REHEARSAL_HEALTHCHECKS_URL"

usage() {
	cat >&2 <<'EOF'
usage: doas ksh setup-env.sh [--ipv4 A --ipv6 B --tsig-secret C
                             --restic-repository D --restic-password-file E
                             --alert-topic F --healthchecks-url G
                             --rehearsal-healthchecks-url H]

  No arguments: install the template if /root/.kyriakon-env is absent, then
  report which values are still missing or placeholders.

  All eight arguments: write the file from them, mode 0600. All or nothing, and
  each value is checked before anything is written.

    doas ksh scripts/setup-env.sh \
      --ipv4 203.0.113.10 --ipv6 2001:db8::10 \
      --tsig-secret "$(openssl rand -base64 32)" \
      --restic-repository 'sftp://user@host:23/kyriakon-backup' \
      --restic-password-file /root/.restic-pass \
      --alert-topic kyriakon-alerts \
      --healthchecks-url https://hc-ping.com/<uuid> \
      --rehearsal-healthchecks-url https://hc-ping.com/<uuid>
EOF
	exit 2
}

a_ipv4=
a_ipv6=
a_tsig=
a_repo=
a_pass=
a_topic=
a_hc=
a_reh=
while [ "$#" -gt 0 ]; do
	[ "$#" -ge 2 ] || usage
	case "$1" in
	--ipv4) a_ipv4="$2" ;;
	--ipv6) a_ipv6="$2" ;;
	--tsig-secret) a_tsig="$2" ;;
	--restic-repository) a_repo="$2" ;;
	--restic-password-file) a_pass="$2" ;;
	--alert-topic) a_topic="$2" ;;
	--healthchecks-url) a_hc="$2" ;;
	--rehearsal-healthchecks-url) a_reh="$2" ;;
	*) usage ;;
	esac
	shift 2
done

given=0
for v in "$a_ipv4" "$a_ipv6" "$a_tsig" "$a_repo" "$a_pass" "$a_topic" "$a_hc" "$a_reh"; do
	if [ -n "$v" ]; then
		given=$((given + 1))
	fi
done

if [ "$given" -gt 0 ]; then
	missing=""
	if [ -z "$a_ipv4" ]; then missing="$missing KYRIAKON_IPV4"; fi
	if [ -z "$a_ipv6" ]; then missing="$missing KYRIAKON_IPV6"; fi
	if [ -z "$a_tsig" ]; then missing="$missing KYRIAKON_TSIG_SECRET"; fi
	if [ -z "$a_repo" ]; then missing="$missing RESTIC_REPOSITORY"; fi
	if [ -z "$a_pass" ]; then missing="$missing RESTIC_PASSWORD_FILE"; fi
	if [ -z "$a_topic" ]; then missing="$missing ALERT_TOPIC"; fi
	if [ -z "$a_hc" ]; then missing="$missing HEALTHCHECKS_URL"; fi
	if [ -z "$a_reh" ]; then missing="$missing REHEARSAL_HEALTHCHECKS_URL"; fi
	if [ -n "$missing" ]; then
		printf 'setup-env: missing an argument for:%s\n\n' "$missing" >&2
		usage
	fi

	# Check before writing anything, so a typo fails here and not in a deploy.
	printf '%s' "$a_ipv4" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
		|| { printf 'setup-env: not an IPv4 address: %s\n' "$a_ipv4" >&2; exit 2; }
	printf '%s' "$a_ipv6" | grep -q ':' \
		|| { printf 'setup-env: not an IPv6 address: %s\n' "$a_ipv6" >&2; exit 2; }
	case "$a_tsig" in
	REPLACE_ME|'') printf 'setup-env: tsig-secret is a placeholder\n' >&2; exit 2 ;;
	esac
	printf '%s' "$a_tsig" | grep -Eq '^[A-Za-z0-9+/=]+$' \
		|| { printf 'setup-env: tsig-secret is not clean base64\n' >&2; exit 2; }
	for u in "$a_hc" "$a_reh"; do
		printf '%s' "$u" | grep -Eq '^https?://' \
			|| { printf 'setup-env: not a URL: %s\n' "$u" >&2; exit 2; }
	done
	# The file expresses values as single-quoted shell words, so a value
	# containing a quote cannot be represented in it.
	for v in "$a_ipv4" "$a_ipv6" "$a_tsig" "$a_repo" "$a_pass" "$a_topic" "$a_hc" "$a_reh"; do
		case "$v" in
		*"'"*) printf 'setup-env: a value contains a single quote, which this file cannot express\n' >&2; exit 2 ;;
		esac
	done

	tmp=$(mktemp)
	{
		printf '# Written by setup-env.sh. Mode 0600: this file holds secrets.\n'
		printf "export KYRIAKON_IPV4='%s'\n" "$a_ipv4"
		printf "export KYRIAKON_IPV6='%s'\n" "$a_ipv6"
		printf "export KYRIAKON_TSIG_SECRET='%s'\n" "$a_tsig"
		printf "export RESTIC_REPOSITORY='%s'\n" "$a_repo"
		printf "export RESTIC_PASSWORD_FILE='%s'\n" "$a_pass"
		printf "export ALERT_TOPIC='%s'\n" "$a_topic"
		printf "export HEALTHCHECKS_URL='%s'\n" "$a_hc"
		printf "export REHEARSAL_HEALTHCHECKS_URL='%s'\n" "$a_reh"
	} > "$tmp"
	install -m 0600 "$tmp" "$env_dst"
	rm -f "$tmp"
	printf 'wrote %s from the arguments\n' "$env_dst"
elif [ ! -f "$env_dst" ]; then
	[ -r "$template" ] || {
		printf 'setup-env: no %s, and no template at %s\n' "$env_dst" "$template" >&2
		exit 1
	}
	install -m 0600 "$template" "$env_dst"
	printf 'installed %s from %s\n' "$env_dst" "$template"
fi

missing=""
placeholder=""
for v in $vars; do
	if ! grep -q "^export $v=" "$env_dst"; then
		missing="$missing $v"
	elif grep -q "^export $v='*REPLACE_ME" "$env_dst"; then
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
	printf '  ALERT_TOPIC                   an ntfy.sh topic you invent, and keep secret\n'
	printf '  HEALTHCHECKS_URL              this box'"'"'s own check, not another box'"'"'s\n'
	printf '  REHEARSAL_HEALTHCHECKS_URL    belongs on the rehearsal box, not this one\n'
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
