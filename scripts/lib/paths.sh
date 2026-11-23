#!/bin/ksh
# paths.sh: one registry for the box paths the shell scripts share. Sourced by
# lib.sh. A value only one script reads stays in that script rather than here.
#
# openbsd/etc/onboard/drain.toml is the drain's copy of the same values, read by
# the Rust side. Shell scripts cannot source TOML, so this is the shell copy and
# paths_match_drain_toml is the check that keeps the two from drifting.

KYRIAKON_STORE_ROOT=/var/db/onboard
KYRIAKON_MAIL_DOMAINS=/etc/mail/mail_domains
KYRIAKON_VIRTUALS=/etc/mail/virtuals
KYRIAKON_MAIL_FROM=/etc/mail/mail_from
KYRIAKON_DKIM_DOMAINS=/etc/mail/dkim_domains
KYRIAKON_SPAMD_ALLOWED=/etc/mail/spamd.alloweddomains
KYRIAKON_KEYRING_DIR=/etc/kyriakon/keys
export KYRIAKON_STORE_ROOT KYRIAKON_MAIL_DOMAINS KYRIAKON_VIRTUALS
export KYRIAKON_MAIL_FROM KYRIAKON_DKIM_DOMAINS KYRIAKON_SPAMD_ALLOWED
export KYRIAKON_KEYRING_DIR

# The values setup-env.sh exists to fill in. deploy-control.sh requires the
# subset it reads; env_keys_agree is what keeps the template, this list and
# that script from inventing different names.
KYRIAKON_ENV_KEYS='KYRIAKON_IPV4 KYRIAKON_IPV6 KYRIAKON_TSIG_SECRET RESTIC_REPOSITORY RESTIC_PASSWORD_FILE ALERT_EMAIL HEALTHCHECKS_URL KEYRING_HEALTHCHECKS_URL REHEARSAL_HEALTHCHECKS_URL HCLOUD_TOKEN RESTORE_TEST_REPOSITORY RESTORE_TEST_HEALTHCHECKS_URL POSTAL_ADDRESS STRIPE_PAYMENT_LINK STRIPE_GROUP_PAYMENT_LINK'
export KYRIAKON_ENV_KEYS

# paths_match_drain_toml <drain.toml>: one line per value the registry and the
# drain's config disagree about. Both are edited by hand, so this is the seam
# that would otherwise only show up as the drain reading a different store.
paths_match_drain_toml() {
	typeset file="$1" pair key want got rc=0
	[ -f "$file" ] || {
		printf 'paths: no drain config at %s\n' "$file" >&2
		return 1
	}
	for pair in \
		store_root="$KYRIAKON_STORE_ROOT" \
		mail_domains="$KYRIAKON_MAIL_DOMAINS" \
		virtuals="$KYRIAKON_VIRTUALS" \
		mail_from="$KYRIAKON_MAIL_FROM" \
		dkim_domains="$KYRIAKON_DKIM_DOMAINS" \
		spamd_alloweddomains="$KYRIAKON_SPAMD_ALLOWED" \
		keyring_dir="$KYRIAKON_KEYRING_DIR"; do
		key=${pair%%=*}
		want=${pair#*=}
		got=$(sed -n "s/^${key}[[:space:]]*=[[:space:]]*\"\(.*\)\"/\1/p" "$file" | head -1)
		if [ "$got" != "$want" ]; then
			printf 'paths: %s is %s in %s, registry says %s\n' \
				"$key" "${got:-missing}" "$file" "$want"
			rc=1
		fi
	done
	return "$rc"
}

# env_keys_agree <template> <deploy-control.sh>: the template defines every key
# and deploy-control does not read one the registry does not name.
env_keys_agree() {
	typeset template="$1" deploy="$2" v text rc=0
	[ -f "$template" ] || {
		printf 'paths: no env template at %s\n' "$template" >&2
		return 1
	}
	for v in $KYRIAKON_ENV_KEYS; do
		grep -q "^export $v=" "$template" \
			|| { printf 'paths: %s is not in %s\n' "$v" "$template"; rc=1; }
	done
	# Both `$KEY` and `${KEY...}` forms count. The exclusions are script state
	# and test fixtures, not values the box's env file supplies.
	# shellcheck disable=SC2016 # both tr sets are literal characters
	text=$(grep -oE '[$][A-Z][A-Z0-9_]+' "$deploy" | tr -d '${}' | sort -u)
	for v in $text; do
		case "$v" in
		KYRIAKON_ENV | KYRIAKON_ENV_KEYS | KYRIAKON_ENV_TEMPLATE | PATH | HOME | TMPDIR | PKG_ADD_LOG)
			continue
			;;
		esac
		case " $KYRIAKON_ENV_KEYS " in
		*" $v "*) ;;
		*) printf 'paths: deploy-control reads %s, which the registry does not name\n' "$v"; rc=1 ;;
		esac
	done
	return "$rc"
}
