#!/bin/ksh
# tls-acme.sh: certificate paths, relayd's keypair link, the capsule pair, the
# certificate-to-daemon map and the one cross-lane ACME lock. Sourced by
# scripts/lib.sh so every certificate writer derives the same paths.

# tls_dirs: set ssl_dir and ssl_private from the environment, defaulting to the
# box's /etc/ssl. Every provisioning lane calls this, so a self-test or a
# relocated tree rebinds one variable rather than six hardcoded paths.
tls_dirs() {
	ssl_dir=${SSL_DIR:-/etc/ssl}
	ssl_private=${SSL_PRIVATE_DIR:-${SSL_PRIVATE:-/etc/ssl/private}}
	# shellcheck disable=SC2034 # the callers read these globals
	export ssl_dir ssl_private
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
# name down.
link_cert() {
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

# capsule_pair_present <cert> <key> <openssl>: both halves non-empty, both
# parseable, and the key is the one the certificate carries. A truncated or
# mismatched pair left by an interrupted run is not a pair, so the next run
# regenerates it rather than serving it.
capsule_pair_present() {
	typeset cert_modulus key_modulus
	[ -s "$1" ] && [ -s "$2" ] || return 1
	"$3" x509 -in "$1" -noout >/dev/null 2>&1 || return 1
	"$3" rsa -in "$2" -noout >/dev/null 2>&1 || return 1
	cert_modulus=$("$3" x509 -in "$1" -noout -modulus 2>/dev/null) || return 1
	key_modulus=$("$3" rsa -in "$2" -noout -modulus 2>/dev/null) || return 1
	[ -n "$cert_modulus" ] && [ "$cert_modulus" = "$key_modulus" ]
}

# ensure_capsule_pair <cert> <key> <cnf> <openssl>: generate the self-signed
# capsule pair unless a complete, parseable pair is already there. Sets
# capsule_generated to yes or no. The candidates are written under umask 077 in
# their destination directories, checked, and renamed into place, so a killed
# run leaves either the old pair or no half pair, never a world-readable key.
#
# Two files cannot be renamed as one; the key is renamed first because a key
# with no certificate is harmless, while a certificate with no key is the pair
# `gmid -n` refuses.
tls_ensure_capsule_pair() {
	typeset cert="$1" key="$2" cnf="$3" openssl_cmd="$4"
	typeset cert_dir key_dir cert_candidate key_candidate
	capsule_generated=no
	if capsule_pair_present "$cert" "$key" "$openssl_cmd"; then
		return 0
	fi
	cert_dir=${cert%/*}
	key_dir=${key%/*}
	cert_candidate="$cert_dir/.capsule-${cert##*/}.tmp.$$"
	key_candidate="$key_dir/.capsule-${key##*/}.tmp.$$"
	rm -f "$cert_candidate" "$key_candidate"
	if ! ( umask 077; "$openssl_cmd" req -x509 -new -nodes -days 3650 -config "$cnf" \
		-keyout "$key_candidate" -out "$cert_candidate" ); then
		rm -f "$cert_candidate" "$key_candidate"
		printf 'openssl req failed; nothing was installed\n' >&2
		return 1
	fi
	if [ ! -s "$cert_candidate" ] || [ ! -s "$key_candidate" ]; then
		rm -f "$cert_candidate" "$key_candidate"
		printf 'openssl wrote an empty capsule half; nothing was installed\n' >&2
		return 1
	fi
	if ! "$openssl_cmd" x509 -in "$cert_candidate" -noout >/dev/null 2>&1; then
		rm -f "$cert_candidate" "$key_candidate"
		printf '%s does not parse as a certificate; nothing was installed\n' \
			"$cert_candidate" >&2
		return 1
	fi
	if ! chmod 0644 "$cert_candidate" || ! chmod 0600 "$key_candidate"; then
		rm -f "$cert_candidate" "$key_candidate"
		printf 'could not set the capsule pair mode; nothing was installed\n' >&2
		return 1
	fi
	if ! mv "$key_candidate" "$key"; then
		rm -f "$key_candidate" "$cert_candidate"
		printf 'could not rename the capsule key into place\n' >&2
		return 1
	fi
	if ! mv "$cert_candidate" "$cert"; then
		# The key is already installed beside the old certificate. Remove both
		# installed halves rather than leaving a mismatched pair that presence
		# would mistake for complete.
		rm -f "$cert_candidate" "$cert" "$key"
		printf 'could not rename the capsule certificate into place; both halves were removed\n' >&2
		return 1
	fi
	capsule_generated=yes
	# shellcheck disable=SC2034 # the caller reads it
	export capsule_generated
	return 0
}

# ensure_capsule_pair: the name callers use; a lane with its own messages wraps
# tls_ensure_capsule_pair instead of reimplementing the staging.
ensure_capsule_pair() {
	tls_ensure_capsule_pair "$@"
}

# cert_services <handle> <member-conf-dir>: the daemons holding that certificate,
# in restart order, one line of words, or non-zero when the handle has no list.
# Dovecot before smtpd because smtpd delivers over LMTP; relayd terminates TLS
# for the web names and holds the generated pairs. gmid and httpd are absent on
# purpose: capsules pin the long-lived capsule pair, and the 443 vhosts moved
# behind the relay.
cert_services() {
	case "$1" in
	mail.kyriakon.net) printf 'dovecot smtpd' ;;
	kyriakon.net | oliver.kyriakon.net | kyriakon.com) printf 'relayd' ;;
	*.kyriakon.net) printf 'relayd' ;;
	*)
		if [ -f "$2/$1.conf" ]; then
			printf 'relayd'
			return 0
		fi
		return 1
		;;
	esac
}

# acme_lock_path: the one lock both acme-queue.sh and renew-acme.sh take, so a
# first issue and a renewal cannot run acme-client for the same name at 03:00.
# ACME_LOCK_DIR rebinds it for a self-test.
acme_lock_path() {
	printf '%s' "${ACME_LOCK_DIR:-/var/run/kyriakon-acme.lock}"
}
