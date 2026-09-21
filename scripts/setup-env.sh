#!/bin/ksh
# setup-env.sh — install and check the box's values file, /root/.kyriakon-env.
#
# Run this FIRST on a box, before deploy-nsd.sh and deploy-mail.sh:
#
#   doas ksh scripts/setup-env.sh
#
# Why it is its own step rather than part of a deploy: more than one deploy script
# needs those values, and nsd runs before mail, so leaving the install to any one
# of them makes the others depend on running in a particular order. This is
# idempotent, and the deploys call it when the file is absent instead of each
# carrying their own copy of the install.
#
# It never overwrites the file: the real one holds the TSIG secret and the alert
# topic, and rewriting it from the repo template would replace them with
# placeholders. It reports what is unset or still a placeholder and exits
# non-zero, so a caller can use it as a pre-flight check.

set -euo pipefail

script_dir="$(dirname "$0")"
template="${KYRIAKON_ENV_TEMPLATE:-$script_dir/../openbsd/etc/kyriakon.env}"
env_dst="${KYRIAKON_ENV:-/root/.kyriakon-env}"

vars="KYRIAKON_IPV4 KYRIAKON_IPV6 KYRIAKON_TSIG_SECRET RESTIC_REPOSITORY RESTIC_PASSWORD_FILE ALERT_TOPIC HEALTHCHECKS_URL REHEARSAL_HEALTHCHECKS_URL"

if [ ! -f "$env_dst" ]; then
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
	printf '\nFill those in and re-run this script. Nothing else needs editing.\n\n'
	printf 'Where the values already exist on this box:\n'
	printf '  KYRIAKON_IPV4, KYRIAKON_IPV6   terraform output ipv4_address ipv6_address\n'
	printf '  KYRIAKON_TSIG_SECRET           the kyriakon-he key in /var/nsd/etc/nsd.conf\n'
	printf '  RESTIC_REPOSITORY             the crontab line of a backup that works\n'
	printf '  RESTIC_PASSWORD_FILE          /root/.restic-pass\n'
	printf '  ALERT_TOPIC                   the ntfy.sh topic alerts are pushed to\n'
	printf '  HEALTHCHECKS_URL              this box'"'"'s Healthchecks check\n'
	printf '  REHEARSAL_HEALTHCHECKS_URL    belongs on the rehearsal box, not this one\n'
	exit 1
fi

# Report the permissions rather than asserting them: if the file predates this
# script it may be 0644, and it holds the TSIG secret and the alert topic.
printf '%s is complete (%s %s)\n' "$env_dst" "$(stat -f '%Su:%Sg' "$env_dst")" "$(stat -f '%Lp' "$env_dst")"
if [ "$(stat -f '%Lp' "$env_dst")" != 600 ]; then
	printf 'setup-env: mode is not 600, and this file holds secrets. Fix: chmod 600 %s\n' "$env_dst" >&2
	exit 1
fi
