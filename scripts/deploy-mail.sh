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
#   2. installs httpd.conf + acme-client.conf and issues the mail and site
#      certificates
#   3. installs smtpd.conf (with the queue key), dovecot.conf and the mail
#      aliases the domain has to answer for
#   4. generates the DKIM key if absent, and checks the published DKIM and SPF
#      records
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
	openbsd/etc/spamd.alloweddomains openbsd/etc/spamd.conf \
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
# an executable, so source it for the two paths the plugin build needs.
dovecot_include_dir=/usr/local/include/dovecot
dovecot_module_dir=/usr/local/lib/dovecot
if [ -r /usr/local/lib/dovecot/dovecot-config ]; then
	# shellcheck source=/dev/null
	. /usr/local/lib/dovecot/dovecot-config
	# The sourced file defines dovecot_pkgincludedir and dovecot_moduledir, which
	# is why these locals carry different names: same-name assignment would be a
	# no-op.
	# shellcheck disable=SC2154
	dovecot_include_dir=${dovecot_pkgincludedir:-$dovecot_include_dir}
	# shellcheck disable=SC2154
	dovecot_module_dir=${dovecot_moduledir:-$dovecot_module_dir}
fi
[ -d "$dovecot_include_dir" ] \
	|| { printf 'dovecot headers missing (%s); is the dovecot package installed?\n' "$dovecot_include_dir" >&2; exit 1; }
command -v dovecot >/dev/null || { printf 'dovecot binary not found on PATH\n' >&2; exit 1; }
printf 'dovecot: include %s, modules %s\n' "$dovecot_include_dir" "$dovecot_module_dir"

# --- 2. TLS --------------------------------------------------------------

say "TLS"
install -d -m 0755 /var/www/acme
install -d -m 0700 /etc/acme
# Document root for the landing site. httpd serves it read-only; the content
# itself comes from a kyriakon-site checkout (see the tail of this script).
install -d -m 0755 /var/www/kyriakon.net
install -m 0644 "$repo_dir/openbsd/etc/httpd.conf" /etc/httpd.conf
install -m 0644 "$repo_dir/openbsd/etc/acme-client.conf" /etc/acme-client.conf
httpd -n -f /etc/httpd.conf
start_service httpd

# acme-client exits 0 on change, 2 when the certificate is already current.
# The mail certificate is fatal: smtpd and Dovecot do not start without it.
acme_rc=0
acme-client -v mail.kyriakon.net || acme_rc=$?
case "$acme_rc" in
	0) printf 'mail certificate issued or renewed\n' ;;
	2) printf 'mail certificate already current\n' ;;
	*) printf 'acme-client failed for mail.kyriakon.net (exit %s); is port 80\n' "$acme_rc" >&2
	   printf 'reachable and the challenge directory served? see /var/www/acme\n' >&2
	   exit 1 ;;
esac
for f in /etc/ssl/mail.kyriakon.net.fullchain.pem /etc/ssl/private/mail.kyriakon.net.key; do
	[ -s "$f" ] || { printf 'missing certificate file: %s\n' "$f" >&2; exit 1; }
done

# The landing site's certificate is issued here because this script is what
# installs httpd.conf, and the site's vhosts reference it. A failure warns
# instead of exiting: the mail stack does not depend on the site, and a broken
# challenge should not stop a mail deploy. Issue #55 covers serving it over TLS.
acme_rc=0
acme-client -v kyriakon.net || acme_rc=$?
case "$acme_rc" in
	0) printf 'site certificate issued or renewed\n' ;;
	2) printf 'site certificate already current\n' ;;
	*) printf 'warning: acme-client failed for kyriakon.net (exit %s); the landing\n' "$acme_rc" >&2
	   printf '  site has no certificate until that succeeds. Check that the\n' >&2
	   printf '  kyriakon.net and www.kyriakon.net vhosts serve the challenge.\n' >&2 ;;
esac

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

# spamd.conf holds no blacklists, and greylisting needs no list to run: it is
# spamd's default mode, and <spamd-white> is maintained by spamd itself from
# /var/db/spamd rather than by spamd-setup. The file is installed because
# /etc/rc.d/spamd runs spamd-setup(8) on every start and spamd-setup refuses to
# run without an `all` tag, which would make `rcctl start spamd` return nonzero
# and take this script down with it.
install -m 0644 "$repo_dir/openbsd/etc/spamd.conf" /etc/mail/spamd.conf

# The greytrap destination allowlist. spamd reads this fixed path itself, and it
# is not a spamd.conf(5) list: a greylisted host sending to a destination whose
# domain matches none of these suffixes is blacklisted for 24 hours, so mail to a
# kyriakon.net address must not be what teaches spamd that a new sender is a
# spammer.
install -m 0644 "$repo_dir/openbsd/etc/spamd.alloweddomains" /etc/mail/spamd.alloweddomains

# Addresses the domain has to answer for. RFC 2142 requires every mail domain
# to accept postmaster@ and abuse@; docs/aup.md sends abuse reports to
# abuse@kyriakon.net; the DMARC record points aggregate reports at
# dmarc@kyriakon.net. On a fresh box none of them land anywhere useful: abuse
# and dmarc have no entry at all, and postmaster resolves to root, whose
# mailbox nobody reads. Delivering them to the operator account means they
# arrive in a mailbox that is read, encrypted at rest like any other delivery.
#
# OpenBSD has no alias database and no newaliases, so smtpd reads this file
# directly and picks up the edit when the service step reloads it below.
# Rewritten rather than edited in place with sed -i: that flag takes its suffix
# differently on BSD and GNU sed, and this way the same code can be exercised
# off the box.
aliases=/etc/mail/aliases
aliases_tmp=$(mktemp "$aliases.XXXXXX")
trap 'rm -f "$aliases_tmp"' EXIT
# make sure an append starts on a line of its own
[ -n "$(tail -c 1 "$aliases")" ] && printf '\n' >> "$aliases"
# Every address the domain promises to answer, all landing in the operator's
# mailbox. One list drives the write and the check below, because they were two
# separate copies and an address added to only one of them would pass its own
# check. Read line by line rather than split on whitespace: each line is a
# "name: value" pair, and word splitting would tear the pair apart and write an
# alias with an empty right-hand side, which silently stops delivering mail to
# that address. security@ is absent on purpose, since the base aliases already
# point it at root, which resolves here to oliver. hello@ is here because the
# landing site publishes it as the contact address, so mail to the platform
# bounces without it.
alias_entries="root: oliver
postmaster: oliver
abuse: oliver
dmarc: oliver
admin: oliver
hello: oliver"
# Fed to each loop through a here-document rather than a here-string. OpenBSD's
# /bin/ksh is pdksh-derived and has no `<<<`, which fails at parse time with
# "syntax error: `< ' unexpected" and takes the whole deploy down with it. The
# delimiter is unquoted so the variable expands, one alias per line.
while IFS= read -r entry; do
	alias_name=${entry%%:*}
	if grep -q "^${alias_name}:" "$aliases"; then
		sed "s|^${alias_name}:.*|${entry}|" "$aliases" > "$aliases_tmp"
		# copied over the original rather than moved into place, so the file
		# keeps the ownership and mode the base system gave it
		cat "$aliases_tmp" > "$aliases"
		printf 'alias %s set\n' "$alias_name"
	else
		printf '%s\n' "$entry" >> "$aliases"
		printf 'alias %s added\n' "$alias_name"
	fi
done <<EOF
$alias_entries
EOF
while IFS= read -r entry; do
	alias_name=${entry%%:*}
	grep -q "^${alias_name}: oliver" "$aliases" \
		|| { printf 'alias %s did not land in %s\n' "$alias_name" "$aliases" >&2; exit 1; }
done <<EOF
$alias_entries
EOF

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
# A TXT value over 255 bytes is served as adjacent character-strings, and dig
# prints one space between them once the quoting is stripped, while the base64
# from openssl contains no spaces. Drop the whitespace before comparing, or a
# correct record reads as a mismatch on every run, which is exactly what
# happened the first time this record was published.
published=$(dig +short @ns1.he.net mail._domainkey.kyriakon.net TXT | tr -d '"' | tr -d '[:space:]')
case "$published" in
	*"$dkim_pub"*) printf 'zone record matches the on-box key\n' ;;
	*) printf 'zone record does NOT match. Publish this in\n'
	   printf 'openbsd/etc/nsd/kyriakon.net.zone (bump the SOA serial), then redeploy nsd:\n\n'
	   # split at 255 bytes including the "v=DKIM1; k=rsa; p=" prefix, because
	   # nsd rejects a single longer character-string and stops serving the
	   # zone entirely rather than complaining
	   printf '\tmail._domainkey\tIN\tTXT\t( "v=DKIM1; k=rsa; p=%s"\n' \
		   "$(printf '%s' "$dkim_pub" | cut -c1-$((255 - 18)))"
	   printf '\t\t\t\t"%s" )\n\n' "$(printf '%s' "$dkim_pub" | cut -c$((255 - 18 + 1))-)"
	   ;;
esac

say "SPF"
# The mail host is a sending identity of its own. Cron output, the daily
# security(8) mail and smtpd's own bounces leave here with mail.kyriakon.net as
# both their envelope and From domain, so SPF is checked against that name and
# not the apex. A missing record there returns "none" and gives those messages
# no SPF pass at all: Google's aggregate reports showed spf=fail on every row
# from this box, with DKIM the only thing carrying them.
mail_spf="v=spf1 a -all"
published_spf=$(dig +short @ns1.he.net mail.kyriakon.net TXT | tr -d '"')
case "$published_spf" in
	*"$mail_spf"*) printf 'mail SPF record published: %s\n' "$published_spf" ;;
	*) printf 'mail SPF record missing or different (want "%s", got "%s").\n' \
		   "$mail_spf" "$published_spf"
	   printf 'Publish it in openbsd/etc/nsd/kyriakon.net.zone (bump the SOA\n'
	   printf 'serial), then redeploy nsd:\n\n'
	   printf '\tmail\tIN\tTXT\t"%s"\n\n' "$mail_spf" ;;
esac

# --- 5. components ------------------------------------------------------

say "dovecot plugin"
# The Makefile defaults to the packaged layout; pass the values read from
# dovecot-config so a relocated layout still builds and installs correctly.
( cd "$repo_dir/dovecot-plugin" \
	&& make INCLUDEDIR="$dovecot_include_dir" MODULEDIR="$dovecot_module_dir" \
	&& make INCLUDEDIR="$dovecot_include_dir" MODULEDIR="$dovecot_module_dir" install )

say "kyriakon-encrypt"
( cd "$repo_dir/kyriakon-encrypt" && cargo build --release )
install -m 0755 "$repo_dir/kyriakon-encrypt/target/release/kyriakon-encrypt" "$encrypt_bin"

say "keyring"
install -d -m 0755 "$keyring_dir"
for k in "$repo_dir"/keys/*.asc; do
	[ -e "$k" ] || continue
	install -m 0644 "$k" "$keyring_dir/$(basename "$k")"
	printf 'installed %s\n' "$(basename "$k")"
	# gpg picks AEAD (packet tag 20) when the recipient key advertises it, and no
	# flag on the encrypt side overrides that: --rfc4880 does not stop it. That
	# leaves delivery depending on the reader's AEAD support, where SEIPD
	# (tag 18) is read by every implementation, and Thunderbird's feature check
	# (MDC alone) reports such a key as advertising an unsupported feature.
	# Dropping AEAD from the key's preferences (setpref) removes both the
	# pref-aead subpacket and the AEAD feature bit, which makes gpg emit SEIPD
	# instead. Warn here rather than let it surface as mail the client cannot
	# open. The fix itself runs on the workstation that holds the secret key, not
	# here: scripts/rekey-mail-key.sh.
	if gpg --list-packets "$k" 2>/dev/null | grep -q 'pref-aead-algos'; then
		printf 'warning: %s advertises AEAD, so delivery would use packet tag 20 rather than SEIPD\n' "$(basename "$k")" >&2
		printf '  fix on the workstation holding the key: scripts/rekey-mail-key.sh\n' >&2
	fi
done

# --- 6. services --------------------------------------------------------

say "services"
install -m 0755 "$repo_dir/openbsd/etc/rc.d/kyriakon_encrypt" /etc/rc.d/kyriakon_encrypt
start_service kyriakon_encrypt
[ -S /var/run/kyriakon/encrypt.sock ] \
	|| { printf 'encryptor socket missing; delivery would fail closed\n' >&2; exit 1; }

start_service dovecot
start_service smtpd

# -v logs each greylist decision, which is what makes the deploy's own check
# below and a first-contact test readable. spamd ships in base, so there is no
# package to add. It is inert until the pf divert is applied: with no divert,
# nothing reaches it and no mail is greylisted.
#
# enable first, then set flags: rcctl refuses to write variables for a daemon
# that is not enabled yet, and under "set -e" that aborts the deploy before the
# daemon is ever started. The first run of this script did exactly that.
rcctl enable spamd
rcctl set spamd flags -v
start_service spamd
# The config test for this half: the greytrap allowlist is read by the daemon,
# and the blacklist loader is what the rc.d start path runs. Dry run, so nothing
# is shipped to spamd.
/usr/libexec/spamd-setup -n

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

# Where the operator's cron scripts live. The crontab lines in backup.sh,
# abuse-monitor.sh, restore-test.sh and renew-acme.sh all call /root/bin/<script>,
# and nothing else creates the directory, so a fresh box fails on the first
# install with "install: /root/bin/INS@...: No such file or directory".
# 0755 inside /root, which is already 0700 root.
install -d -m 0755 /root/bin

home=$(awk -F: '$1 == "oliver" { print $6 }' /etc/passwd)
[ -n "$home" ] || { printf 'cannot read the home directory for oliver from /etc/passwd\n' >&2; exit 1; }
shell=$(awk -F: '$1 == "oliver" { print $7 }' /etc/passwd)
if [ "$shell" = /sbin/nologin ]; then
	chsh -s /bin/ksh oliver
	shell=/bin/ksh
	printf 'set oliver shell to /bin/ksh (operator account, not a standard-tier one)\n'
fi

# add-user.sh creates these for standard accounts; an account made by hand may
# not have them, and Dovecot's maildir:~/Maildir needs them. The root of the
# Maildir is in the list too, because Dovecot creates dovecot-uidlist and its
# index files there, not only in the subdirectories. install -d creates missing
# parents itself and leaves the owner of a directory it did not create alone, so
# a Maildir root left behind by an earlier run stays root-owned, every service
# still reports healthy, and then each IMAP session fails with
# "file_dotlock_create ... Permission denied". Hence the explicit chown and the
# ownership check below.
for d in "$home/Maildir" "$home/Maildir/cur" "$home/Maildir/new" "$home/Maildir/tmp"; do
	install -d -m 0700 -o oliver -g oliver "$d"
	chown oliver:oliver "$d"
done

owner=$(stat -f '%Su' "$home/Maildir")
[ "$owner" = oliver ] || { printf 'Maildir root is owned by %s, not oliver; Dovecot cannot open INBOX\n' "$owner" >&2; exit 1; }
printf 'Maildir: %s/Maildir (owner %s, shell %s)\n' "$home" "$owner" "$shell"

# --- 8. verify ----------------------------------------------------------

say "verify"
for s in dovecot smtpd kyriakon_encrypt httpd spamd; do
	printf '%-18s %s\n' "$s" "$(rcctl check "$s" 2>&1 || true)"
done
# The daemon being up says nothing about whether greylisting is on: the switch is
# the pf divert, which this script must not apply. Report which state the box is
# actually in rather than implying the enabled one.
if pfctl -sr 2>/dev/null | grep -q 'divert-to 127.0.0.1 port spamd'; then
	printf 'greylisting: on (%s greylisted host(s))\n' \
		"$(spamdb 2>/dev/null | grep -c '^GREY|' || true)"
else
	printf 'greylisting: OFF - inbound mail is not diverted to spamd.\n'
	printf '              Apply the pf fragment in step 6 below.\n'
fi
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
printf '  4. landing site: the vhosts serve it from /var/www/kyriakon.net, so a\n'
printf '     kyriakon-site checkout there is all it needs (git clone once, then\n'
printf '     git pull to update). No pf change is required for 443.\n'
printf '  5. personal site: same shape, at /var/www/oliver.kyriakon.net, from\n'
printf '     https://github.com/OliverBrotchie/oliver.kyriakon.net . The vhost\n'
printf '     blocks /.git, so keep it a checkout rather than a copy of the files:\n'
printf '     git clone once as root, then git pull to update. It carries both\n'
printf '     index.html for HTTP and index.gmi for the Gemini side.\n'
printf '  6. greylisting: append this to the END of /etc/pf.conf (pf is\n'
printf '     last-match-wins, so it must follow the stock pass rule), then\n'
printf '     "pfctl -nf" it and load it. Rationale and checks:\n'
printf '     docs/planning/research/spamd-greylisting.md\n'
printf '\n'
printf '\t\t table <spamd-white> persist\n'
printf '\t\t pass in on egress proto tcp to any port smtp \\\n'
printf '\t\t     divert-to 127.0.0.1 port spamd\n'
printf '\t\t pass in log on egress proto tcp from <spamd-white> to any port smtp\n'
printf '\n'
printf '  7. LMTP socket: leave it at the Dovecot default. smtpd mda runs as the\n'
printf '     recipient, not as root, so a root:wheel 0600 socket answers\n'
printf '     "mail.lmtp: connect: Permission denied" and mail queues.\n'
