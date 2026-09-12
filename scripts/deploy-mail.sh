#!/bin/ksh
# deploy-mail.sh — bring the kyriakon.net mail stack up on the box.
#
# Runs ON the box as root (invoke under doas). It does NOT touch pf.conf: the
# mail port rules and the spamd divert-to greylisting stay propose-only human
# steps.
#
# Usage:
#   doas ksh deploy-mail.sh [repo_dir]
#
#   repo_dir   checkout to install from; defaults to /root/src/kyriakon-infra
#
# Idempotent. Re-running reinstalls the configs, rebuilds the two components,
# and restarts what is already running. It:
#   1. installs the packages the build and the daemons need
#   2. installs httpd.conf + acme-client.conf and issues the mail certificate
#   3. installs smtpd.conf (with the queue key) and dovecot.conf
#   4. generates the DKIM key if absent and checks the published record
#   5. builds and installs the Dovecot plugin and the kyriakon-encrypt daemon
#   6. syncs the published keyring, starts every service, creates oliver
#
# The queue-encryption key is generated once and persisted in
# /etc/mail/queue.key (0600 root). It must stay stable: changing it makes
# queued mail undecryptable.

set -euo pipefail

repo_dir="${1:-/root/src/kyriakon-infra}"

# Everything this installs lives under /usr/local, and doas, cron and rcctl all
# hand over a minimal PATH, so set it explicitly instead of trusting the caller.
PATH="/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

queue_key_file=/etc/mail/queue.key
# smtpd's crypto_setup() requires exactly this many characters (KEY_SIZE in
# usr.sbin/smtpd/crypto.c) and uses them verbatim as the AES-256 key.
queue_key_len=32
dkim_key=/etc/mail/dkim/private.rsa.key
keyring_dir=/etc/kyriakon/keys
encrypt_bin=/usr/local/sbin/kyriakon-encrypt

[ "$(id -u)" -eq 0 ] || { printf 'run as root (doas ksh %s)\n' "$0" >&2; exit 1; }
[ -d "$repo_dir" ] || { printf 'repo_dir not found: %s\n' "$repo_dir" >&2; exit 1; }

for f in openbsd/etc/smtpd.conf openbsd/etc/httpd.conf openbsd/etc/acme-client.conf \
	openbsd/etc/rc.d/kyriakon_encrypt openbsd/dovecot/dovecot.conf \
	dovecot-plugin/Makefile kyriakon-encrypt/Cargo.toml keys; do
	[ -e "$repo_dir/$f" ] || { printf 'missing from repo_dir: %s\n' "$f" >&2; exit 1; }
done

say() { printf '== %s\n' "$*"; }

need_pkg() {
	if pkg_info -q -e "$1" >/dev/null 2>&1 || pkg_info -q -e "$1-*" >/dev/null 2>&1; then
		printf 'ok: %s already installed\n' "$1"
	else
		# -I: no questions. Interactive is the default on a tty, and a deploy
		# that stops on a prompt (a same-version replacement of quirks, for
		# instance) looks exactly like a hung fetch.
		printf 'installing %s (fetching; can take a minute)\n' "$1"
		pkg_add -I "$1"
	fi
}

start_service() {
	rcctl enable "$1"
	if rcctl check "$1" >/dev/null 2>&1; then
		rcctl restart "$1"
	else
		rcctl start "$1"
	fi
	rcctl check "$1" >/dev/null 2>&1 \
		|| { printf '%s did not start; check /var/log/messages\n' "$1" >&2; exit 1; }
	printf 'running: %s\n' "$1"
}

# --- 1. packages ---------------------------------------------------------

say "packages"
need_pkg dovecot
need_pkg gnupg
need_pkg rust
need_pkg opensmtpd-filter-dkimsign

command -v cargo >/dev/null || { printf 'cargo missing after pkg_add rust\n' >&2; exit 1; }
command -v gpg >/dev/null || { printf 'gpg missing after pkg_add gnupg\n' >&2; exit 1; }

# The headers are the real prerequisite for the plugin build. There is nothing
# to run: OpenBSD ships dovecot-config as a 0644 shell variable file rather than
# an executable, so just report what it says.
[ -d /usr/local/include/dovecot ] \
	|| { printf 'dovecot headers missing (/usr/local/include/dovecot); is the dovecot package installed?\n' >&2; exit 1; }
if [ -r /usr/local/lib/dovecot/dovecot-config ]; then
	# shellcheck source=/dev/null
	. /usr/local/lib/dovecot/dovecot-config
	# shellcheck disable=SC2154  # both names come from the sourced file
	printf 'dovecot: include %s, modules %s\n' "$dovecot_pkgincludedir" "$dovecot_moduledir"
fi
command -v dovecot >/dev/null || { printf 'dovecot binary not found on PATH\n' >&2; exit 1; }

# --- 2. TLS --------------------------------------------------------------

say "TLS"
install -d -m 0755 /var/www/acme
install -d -m 0700 /etc/acme
install -m 0644 "$repo_dir/openbsd/etc/httpd.conf" /etc/httpd.conf
install -m 0644 "$repo_dir/openbsd/etc/acme-client.conf" /etc/acme-client.conf
httpd -n -f /etc/httpd.conf
start_service httpd

# acme-client exits 0 on change, 2 when the certificate is already current.
acme_rc=0
acme-client -v mail.kyriakon.net || acme_rc=$?
case "$acme_rc" in
	0) printf 'certificate issued or renewed\n' ;;
	2) printf 'certificate already current\n' ;;
	*) printf 'acme-client failed (exit %s); is port 80 reachable and\n' "$acme_rc" >&2
	   printf 'the challenge directory served? see /var/www/acme\n' >&2
	   exit 1 ;;
esac
for f in /etc/ssl/mail.kyriakon.net.fullchain.pem /etc/ssl/private/mail.kyriakon.net.key; do
	[ -s "$f" ] || { printf 'missing certificate file: %s\n' "$f" >&2; exit 1; }
done

# --- 3. smtpd + dovecot configs -----------------------------------------

say "configs"
queue_key=
if [ -s "$queue_key_file" ]; then
	queue_key=$(cat "$queue_key_file")
fi
if [ "${#queue_key}" -ne "$queue_key_len" ]; then
	if [ -n "$queue_key" ]; then
		printf 'warning: %s holds a %s-character key and smtpd requires %s; replacing it. Anything still queued under the old key becomes undecryptable.\n' \
			"$queue_key_file" "${#queue_key}" "$queue_key_len"
	fi
	# 32 hex characters, as smtpd's crypto_setup() comment suggests. base64 of
	# 32 bytes is 44 characters and is rejected at startup.
	queue_key=$(openssl rand -hex 16)
	(umask 077; printf '%s\n' "$queue_key" > "$queue_key_file")
	# umask only governs creation, so an existing file could carry looser bits.
	chmod 0600 "$queue_key_file"
	printf 'generated the queue-encryption key in %s (%s characters) - store it in your password manager.\n' \
		"$queue_key_file" "$queue_key_len"
fi

# '|' delimits the s/// because base64 keys contain '/'. The deployed file
# holds the key, hence 0600.
sed -e "s|REPLACE_ME_QUEUE_KEY|$queue_key|" "$repo_dir/openbsd/etc/smtpd.conf" > /etc/mail/smtpd.conf
chmod 0600 /etc/mail/smtpd.conf
grep -q 'REPLACE_ME_QUEUE_KEY' /etc/mail/smtpd.conf \
	&& { printf 'queue key substitution failed\n' >&2; exit 1; }
smtpd -n -f /etc/mail/smtpd.conf

install -m 0644 "$repo_dir/openbsd/dovecot/dovecot.conf" /etc/dovecot/dovecot.conf
doveconf -n >/dev/null

# --- 4. DKIM -------------------------------------------------------------

say "DKIM"
if [ ! -s "$dkim_key" ]; then
	install -d -o _dkimsign -g _dkimsign -m 0700 /etc/mail/dkim
	openssl genrsa -out "$dkim_key" 2048
	chown _dkimsign:_dkimsign "$dkim_key"
	chmod 0600 "$dkim_key"
	printf 'generated %s\n' "$dkim_key"
fi
dkim_pub=$(openssl rsa -in "$dkim_key" -pubout -outform DER | openssl base64 -A)
published=$(dig +short @ns1.he.net mail._domainkey.kyriakon.net TXT | tr -d '"')
case "$published" in
	*"$dkim_pub"*) printf 'zone record matches the on-box key\n' ;;
	*) printf 'zone record does NOT match. Publish this in\n'
	   printf 'openbsd/etc/nsd/kyriakon.net.zone (bump the SOA serial), then redeploy nsd:\n\n'
	   printf '\tmail._domainkey IN TXT "v=DKIM1; k=rsa; p=%s"\n\n' "$dkim_pub" ;;
esac

# --- 5. components ------------------------------------------------------

say "dovecot plugin"
# The Makefile sources dovecot-config for the include and module directories.
( cd "$repo_dir/dovecot-plugin" && make && make install )

say "kyriakon-encrypt"
( cd "$repo_dir/kyriakon-encrypt" && cargo build --release )
install -m 0755 "$repo_dir/kyriakon-encrypt/target/release/kyriakon-encrypt" "$encrypt_bin"

say "keyring"
install -d -m 0755 "$keyring_dir"
for k in "$repo_dir"/keys/*.asc; do
	[ -e "$k" ] || continue
	install -m 0644 "$k" "$keyring_dir/$(basename "$k")"
	printf 'installed %s\n' "$(basename "$k")"
done

# --- 6. services --------------------------------------------------------

say "services"
install -m 0755 "$repo_dir/openbsd/etc/rc.d/kyriakon_encrypt" /etc/rc.d/kyriakon_encrypt
start_service kyriakon_encrypt
[ -S /var/run/kyriakon/encrypt.sock ] \
	|| { printf 'encryptor socket missing; delivery would fail closed\n' >&2; exit 1; }

start_service dovecot
start_service smtpd

# --- 7. account ---------------------------------------------------------

# oliver is the operator account: it doubles as the admin login for the box,
# so it keeps an interactive shell. That is the deliberate difference from
# add-user.sh, which forces /sbin/nologin because standard-tier accounts must
# not have one. The Maildir is what the mail stack needs, and it is created
# either way.
say "account oliver"
if id oliver >/dev/null 2>&1; then
	printf 'account exists: oliver\n'
else
	useradd -m -d /home/oliver -s /bin/ksh -g =uid oliver
	printf 'created oliver with an interactive shell\n'
	printf 'set the password with: doas passwd oliver\n'
fi

home=$(awk -F: '$1 == "oliver" { print $6 }' /etc/passwd)
[ -n "$home" ] || { printf 'cannot read the home directory for oliver from /etc/passwd\n' >&2; exit 1; }
shell=$(awk -F: '$1 == "oliver" { print $7 }' /etc/passwd)
if [ "$shell" = /sbin/nologin ]; then
	chsh -s /bin/ksh oliver
	shell=/bin/ksh
	printf 'set oliver shell to /bin/ksh (operator account, not a standard-tier one)\n'
fi

# add-user.sh creates these for standard accounts; an account made by hand may
# not have them, and Dovecot's maildir:~/Maildir needs them.
for d in cur new tmp; do
	install -d -m 0700 -o oliver -g oliver "$home/Maildir/$d"
done
printf 'Maildir: %s/Maildir (shell %s)\n' "$home" "$shell"

# --- 8. verify ----------------------------------------------------------

say "verify"
for s in dovecot smtpd kyriakon_encrypt httpd; do
	printf '%-18s %s\n' "$s" "$(rcctl check "$s" 2>&1 || true)"
done
printf 'MX:   %s\n' "$(dig +short @ns1.he.net kyriakon.net MX)"
printf 'mail: %s %s\n' "$(dig +short @ns1.he.net mail.kyriakon.net A)" \
	"$(dig +short @ns1.he.net mail.kyriakon.net AAAA)"
printf 'PTR4: %s\n' "$(dig +short -x 95.216.152.17)"
printf 'PTR6: %s\n' "$(dig +short -x 2a01:4f9:c013:7888::1)"

printf '\nmail stack is up. Remaining manual steps:\n'
printf '  1. doas passwd oliver, then configure your client:\n'
printf '     IMAP mail.kyriakon.net:993 (TLS), submission :465 (auth)\n'
printf '  2. inbound test from an external mailbox, then check the Maildir:\n'
printf '     ls -t /home/oliver/Maildir/new/* | head -1\n'
printf '  3. outbound test, then SPF/DKIM/DMARC and inbox placement at a public checker\n'
