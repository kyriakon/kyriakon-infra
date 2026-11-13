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
#   repo_dir   checkout to install from; defaults to /usr/local/src/kyriakon-infra
#
# The writes it makes into files the box reads are checked without a box:
#
#   ksh deploy-mail.sh --self-test [repo_root]
#
# Idempotent. Re-running reinstalls the configs, rebuilds the two components,
# and restarts what is already running. It:
#   1. installs the packages the build and the daemons need
#   2. installs httpd.conf + acme-client.conf and issues the mail and site
#      certificates
#   3. installs smtpd.conf (with the queue key and the DKIM filter's domain
#      list), dovecot.conf, and seeds the mail tables the domain has to answer
#      for
#   4. generates the DKIM key if absent, and checks the published DKIM and SPF
#      records
#   5. builds and installs the Dovecot plugin and the kyriakon-encrypt binary
#      it runs per save
#   6. syncs the published keyring, starts every service, creates oliver
#
# The queue-encryption key is generated once and persisted in
# /etc/mail/queue.key (0600 root). It must stay stable: changing it makes
# queued mail undecryptable.

set -euo pipefail

repo_dir="${1:-/usr/local/src/kyriakon-infra}"

# Everything this installs lives under /usr/local, and doas, cron and rcctl all
# hand over a minimal PATH, so set it explicitly instead of trusting the caller.
PATH="/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

script_dir=$(cd "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

queue_key_file=/etc/mail/queue.key
# smtpd's crypto_setup() requires exactly this many characters (KEY_SIZE in
# usr.sbin/smtpd/crypto.c) and uses them verbatim as the AES-256 key.
queue_key_len=32
dkim_key=/etc/mail/dkim/private.rsa.key
keyring_dir=/etc/kyriakon/keys
# The store root the drain owns, read here for the one fact the keyring install
# needs: which mail key an account record says the box is delivering with. A
# rotation changes it without changing the tracked key, and the install below
# leaves the rotated key alone.
store_root=/var/db/onboard
encrypt_bin=/usr/local/sbin/kyriakon-encrypt

say() { printf '== %s\n' "$*"; }

# The one list of which scripts the box runs, and where. scripts/install-set.tsv
# is its own explanation, and lib.sh's install_rows is how this reads it. This
# deploy installs the /root/bin rows and the one /usr/local/libexec row (the
# member session shell), cron-apply.sh schedules the former, check-hygiene.sh
# checks the copies, and deploy.sh routes a changed script by its row.
install_set="$script_dir/install-set.tsv"

# stale_copies <installed names>: the pre-split copies in /root/bin that this
# deploy still sweeps away, less every name the table installs. Before the
# control plane split out of this deploy, the drain's scripts were installed
# here too, and a box from that time keeps them; they are stale copies of scripts
# that now run from the drain's directory, and check-hygiene's section 9 reports
# every one of them for ever otherwise. The installed set is excluded so a row
# added later for one of these cannot be installed and removed in the same run.
stale_copies() {
	for s in add-user.sh check-hygiene.sh cron-apply.sh delete-user.sh deploy-mail.sh \
		deploy-onboard.sh deploy-relayd.sh onboard-store.sh provision-member.sh \
		provision-member-capsule.sh provision-member-web.sh quota-apply.sh restore-test.sh; do
		case " $(printf '%s\n' "$1" | tr '\n' ' ') " in
		*" $s "*) continue ;;
		esac
		printf '%s\n' "$s"
	done
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

# dkim_domains_add <file> <domain>: put <domain> in the DKIM filter's domain
# list, and print only when it was not already there, so a redeploy that changes
# nothing says nothing. The line is written by table_set, the same locked shape
# the virtual table below uses, which also compares the key literally rather than
# as a substring: parish.example and sub.parish.example are different domains and
# both belong in the list.
dkim_domains_add() {
	table_set "$1" "$2" "$2"
	# shellcheck disable=SC2154 # table_set_how is set by table_set in lib.sh
	[ "$table_set_how" = added ] || return 0
	printf 'dkim domain %s added\n' "$2"
}

# dkim_domains_args lives in lib.sh: the deploy is no longer the only caller, so
# reload-smtpd.sh and provision-member.sh re-expand the filter's -d list from the
# same table after a body joins or leaves.

# set_virtual <table> <name> <entry>
#
# Replace the line whose localpart is exactly <name> with <entry>, or append it
# when there is none, and print which happened. The write is lib.sh's table_set,
# which is also what the signup and removal scripts use: this file is the whole
# answer for local delivery, so an interrupted write that left a fragment would
# make addresses under it unreachable.
set_virtual() {
	typeset table="$1" name="$2" entry="$3"
	table_set "$table" "$name" "$entry"
	printf 'virtual %s %s\n' "$name" "$table_set_how"
}

# require_mail_domains <table> <platform-domain>: the deploy's refusal. Prints
# lib.sh's one-line problem and returns 1 when the first line is not the platform
# domain, so the caller exits rather than seeding over or keeping a table that
# would address a new member on a body's domain.
require_mail_domains() {
	typeset problem
	problem=$(mail_domains_first_problem "$1" "$2")
	[ -z "$problem" ] && return 0
	printf '%s: %s\n' "$1" "$problem" >&2
	return 1
}

# merge_spamd_allowed <seed> <mail-domains> <destination>
#
# The greylist pass-through list, as the mail domain table names it. A box with
# none is seeded from the tracked file, which carries the header and the
# platform's own domain; every domain in the table that has no `@domain` line is
# appended under the same table lock the drain takes, and a line already there is
# not added twice. Installing the tracked file over the live one, which this
# used to do, deleted each body's line on every deploy, and spamd(8) traps a
# destination that has no line here rather than greylisting it.
merge_spamd_allowed() {
	typeset seed="$1" domains="$2" dst="$3" domain
	[ -f "$dst" ] || install -m 0644 "$seed" "$dst"
	while IFS= read -r domain; do
		# The same normalisation check-hygiene.sh compares with: a comment and
		# the spaces around a hand-edited line would otherwise become part of the
		# line this appends, and the next hygiene run would call that drift.
		domain=$(printf '%s' "$domain" | sed -e 's/#.*//' -e 's/[[:space:]]//g')
		[ -n "$domain" ] || continue
		table_set "$dst" "@$domain" "@$domain" || return 1
	done <"$domains"
}

# mail_from_entries <passwd-file> <virtuals-file>: the mail-from table, mapped
# from account to the addresses that account may submit as. Every account whose
# home is under /home gets a line starting with its own identity,
# <user>@<platform-domain>, and every full-address virtuals entry whose target is
# one of those accounts is appended to that account's list, so a group mailbox
# that publishes secretary@parish.example can send as it. A bare localpart is not
# an identity and is left out, as is an address aimed at a service account, and
# an address already in the account's list is not repeated. smtpd's `senders`
# option reads this as a mapping, so one account's line never carries another
# account's address.
mail_from_entries() {
	awk -F: -v d="$platform_domain" '
		FILENAME == ARGV[1] {
			if ($6 ~ /^\/home\//) {
				account[++n] = $1
				own[$1] = $1 "@" d
				seen[$1 "@" d] = 1
			}
			next
		}
		{
			addr = $1
			if (addr !~ /@/) next
			target = $2
			sub(/^[ \t]+/, "", target)
			sub(/[ \t]+$/, "", target)
			sub(/\+.*$/, "", target)
			if ((target in own) && !(addr in seen)) {
				seen[addr] = 1
				extra[target] = (extra[target] == "") ? addr : extra[target] "," addr
			}
		}
		END {
			for (i = 1; i <= n; i++) {
				acct = account[i]
				line = own[acct]
				if (extra[acct] != "") line = line "," extra[acct]
				print acct ": " line
			}
		}
	' "$1" "$2"
}

# install_smtpd_conf lives in lib.sh: reload-smtpd.sh and provision-member.sh
# re-render the same template from the same two box files whenever they restart
# smtpd, so a body's domain is signed without waiting for the next deploy.

# install_indexes <root> — create the three generated index files and leave them
# 0644. `root` is /etc on the box and a fixture in the self-test, which is what
# lets the third lane's creation be checked without a box.
install_indexes() {
	typeset root="$1" i
	install -d -m 0755 "$root/httpd.d" "$root/gmid.d" "$root/acme-client.d"
	for i in "$root/httpd.d/index.conf" "$root/gmid.d/index.conf" \
		"$root/acme-client.d/index.conf"; do
		[ -e "$i" ] || : >"$i"
		chmod 0644 "$i"
	done
}

# fpr_of <file>: the primary fingerprint of the first key in a public key file,
# or nothing when it cannot be read. The same colon-output shape
# scripts/check-keyring-drift.sh compares.
fpr_of() {
	gpg --batch --no-tty --with-colons --import-options show-only --import "$1" 2>/dev/null \
		| awk -F: '$1 == "fpr" { print $10; exit }'
}

# install_keyring_key <key-file>: install one tracked key into the keyring, unless
# the account record names a different fingerprint. A member's rotation writes the
# new key into the keyring and the record together; installing the tracked key
# over it would silently revert delivery to a key the member no longer holds, and
# the published set is the operator's to update after a rotation.
install_keyring_key() {
	typeset name localpart account recorded tracked
	name=$(basename "$1")
	localpart=${name%.asc}
	account="$store_root/accounts/$localpart/account.json"
	if [ -f "$account" ] && command -v jq >/dev/null 2>&1; then
		recorded=$(jq -r '.mail_key // empty' "$account")
		tracked=$(fpr_of "$1")
		if [ -n "$recorded" ] && [ -n "$tracked" ] && [ "$recorded" != "$tracked" ]; then
			printf 'kept %s: the account record names %s and the tracked key is %s\n' \
				"$name" "$recorded" "$tracked" >&2
			printf '  the box keeps delivering with the rotated key; publish it to keys/%s.asc and deploy again\n' \
				"$localpart" >&2
			return 0
		fi
	fi
	install -m 0644 "$1" "$keyring_dir/$name"
	printf 'installed %s\n' "$name"
	warn_aead "$1"
}

# The AEAD warning for one installed key. gpg picks AEAD (packet tag 20) when the
# recipient key advertises it, and no flag on the encrypt side overrides that:
# --rfc4880 does not stop it. That leaves delivery depending on the reader's AEAD
# support, where SEIPD (tag 18) is read by every implementation, and
# Thunderbird's feature check (MDC alone) reports such a key as advertising an
# unsupported feature. Dropping AEAD from the key's preferences (setpref) removes
# both the pref-aead subpacket and the AEAD feature bit, which makes gpg emit
# SEIPD instead. The fix itself runs on the workstation that holds the secret
# key, not here: scripts/rekey-mail-key.sh.
warn_aead() {
	if gpg --list-packets "$1" 2>/dev/null | grep -q 'pref-aead-algos'; then
		printf 'warning: %s advertises AEAD, so delivery would use packet tag 20 rather than SEIPD\n' "$(basename "$1")" >&2
		printf '  fix on the workstation holding the key: scripts/rekey-mail-key.sh\n' >&2
	fi
}

# dkim_selector <smtpd.conf>: the selector the dkimsign filter signs under, read
# from the filter's own -s argument. The zone check and the repair record follow
# it, so a rotation that changes -s does not leave the comparison on the record
# the old selector published.
dkim_selector() {
	awk '/filter "dkimsign"/ { for (i = 1; i < NF; i++) if ($i == "-s") { print $(i + 1); exit } }' "$1"
}

# dkim_zone_check <smtpd.conf>: compare the on-box public key ($dkim_pub) with
# the TXT record the filter's selector names. A value over 255 bytes is served
# as adjacent character-strings, and dig prints one space between them once the
# quoting is stripped, while the base64 from openssl contains no spaces. Drop
# the whitespace before comparing, or a correct record reads as a mismatch on
# every run, which is exactly what happened the first time this record was
# published.
dkim_zone_check() {
	typeset selector published
	selector=$(dkim_selector "$1")
	if [ -z "$selector" ]; then
		printf 'no DKIM selector in %s: the signing filter has no -s argument\n' "$1" >&2
		return 1
	fi
	published=$(dig +short @ns1.he.net "$selector._domainkey.kyriakon.net" TXT | tr -d '"' | tr -d '[:space:]')
	case "$published" in
	*"$dkim_pub"*) printf 'zone record matches the on-box key\n' ;;
	*) printf 'zone record does NOT match. Publish this in\n'
	   printf 'openbsd/etc/nsd/kyriakon.net.zone (bump the SOA serial), then redeploy nsd:\n\n'
	   # split at 255 bytes including the "v=DKIM1; k=rsa; p=" prefix, because
	   # nsd rejects a single longer character-string and stops serving the
	   # zone entirely rather than complaining
	   printf '\t%s._domainkey\tIN\tTXT\t( "v=DKIM1; k=rsa; p=%s"\n' \
		   "$selector" "$(printf '%s' "$dkim_pub" | cut -c1-$((255 - 18)))"
	   printf '\t\t\t\t"%s" )\n\n' "$(printf '%s' "$dkim_pub" | cut -c$((255 - 18 + 1))-)"
	   ;;
	esac
}

# self_test — the writes this deploy makes into files the box reads, against
# fixtures and the shipped smtpd.conf, and not the box. Each install moves a
# candidate onto the live file, and that is what the checks are about: a write
# that is interrupted, or that cannot be made at all, leaves the file with what it
# had, never with half of a new one. The routing rules the installed config must
# carry are checked here too, because smtpd -n cannot be run off an OpenBSD box.
self_test() {
	typeset tree code before after i got
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work

	# --- the virtual table ---
	# As a previous run and the drain leave it: two platform entries, and one the
	# drain wrote for a body's own address. All three have to survive a redeploy.
	printf 'admin: oliver+Admin\nhello: oliver\nsecretary@parish.example: parish\n' \
		> "$tree/virtuals"
	before=$(stat -f %i "$tree/virtuals")
	set_virtual "$tree/virtuals" hello \
		"hello: hello@kyriakon.net" > "$tree/set.out" 2>&1
	after=$(stat -f %i "$tree/virtuals")
	check "an existing entry is replaced" \
		"$(grep -c '^hello: hello@kyriakon.net$' "$tree/virtuals")" 1
	check "and the lines around it are left alone" \
		"$(grep -c -e '^admin: oliver+Admin$' -e '^secretary@parish.example: parish$' "$tree/virtuals")" 2
	check "and the run says which happened" "$(grep -c '^virtual hello set$' "$tree/set.out")" 1
	# What the move buys: the table is replaced rather than rewritten in place, so
	# there is no moment at which it holds half an entry, with every address under
	# it unreachable until someone notices.
	check "the table is replaced, not rewritten" \
		"$([ "$before" != "$after" ] && printf yes || printf no)" yes
	check "at the mode the table had" "$(stat -f %Lp "$tree/virtuals")" 644

	before=$(stat -f %i "$tree/virtuals")
	set_virtual "$tree/virtuals" dmarc "dmarc: oliver" > "$tree/add.out" 2>&1
	after=$(stat -f %i "$tree/virtuals")
	check "an entry with no line of its own is appended" \
		"$(grep -c '^dmarc: oliver$' "$tree/virtuals")" 1
	# The append writes the live table under the helper's lock rather than
	# replacing it, so the inode stays and a concurrent append cannot be lost.
	check "and the table is appended to, not replaced" \
		"$([ "$before" = "$after" ] && printf yes || printf no)" yes

	# A write that cannot be made leaves the table exactly as it was. The table is
	# a directory here, which the append refuses as root as well as otherwise.
	cp "$tree/virtuals" "$tree/expected"
	mkdir "$tree/adirectory"
	set +e
	( set -e; set_virtual "$tree/adirectory" hello "hello: x" ) >/dev/null 2>&1
	code=$?
	set -e
	check "a write that fails leaves the table as it was" \
		"$(cmp -s "$tree/virtuals" "$tree/expected" && printf same || printf changed)" same
	check "and does not leave the lock behind" \
		"$([ -d "$tree/adirectory.lock" ] && printf held || printf free)" free
	check "and says that it failed" "$([ "$code" -ne 0 ] && printf yes || printf no)" yes

	# --- mail_domains ---
	# provision-member.sh reads the first line as the domain a new member is
	# addressed on, so the deploy refuses a table whose first line is anything
	# else rather than seeding over it or leaving it alone.
	platform_domain=kyriakon.net
	printf 'parish.example\nkyriakon.net\n' > "$tree/mail_domains"
	code=0
	out=$( ( require_mail_domains "$tree/mail_domains" "$platform_domain" ) 2>&1 ) || code=$?
	check "the deploy refuses a mail_domains not starting with the platform domain" \
		"$code" 1
	case "$out" in
	*parish.example*kyriakon.net*) ;;
	*) printf 'FAIL: the refusal names the line and the domain it wants; got [%s]\n' \
		"$out" >&2
	   self_test_fails=$((self_test_fails + 1)) ;;
	esac
	printf 'kyriakon.net\nparish.example\n' > "$tree/mail_domains"
	code=0
	( require_mail_domains "$tree/mail_domains" "$platform_domain" ) >/dev/null 2>&1 || code=$?
	check "and accepts one that starts with it" "$code" 0

	# --- the spamd greylist pass-through list ---
	# A destination domain with no line here is not greylisted: spamd treats the
	# sender as a spamtrap hit and blocklists it. So the file follows mail_domains
	# rather than being installed from the tracked copy, which is what used to
	# delete a body's line on every deploy.
	printf 'kyriakon.net\nparish.example\nparish-example.net\n' > "$tree/mail_domains"
	merge_spamd_allowed "$repo_dir/openbsd/etc/spamd.alloweddomains" \
		"$tree/mail_domains" "$tree/spamd.alloweddomains"
	check "the allow list is seeded from the tracked file" \
		"$(grep -c '^#' "$tree/spamd.alloweddomains")" \
		"$(grep -c '^#' "$repo_dir/openbsd/etc/spamd.alloweddomains")"
	check "and every mail domain gets one at-prefixed line" \
		"$(grep -cx -e '@kyriakon.net' -e '@parish.example' -e '@parish-example.net' \
			"$tree/spamd.alloweddomains")" 3
	check "a domain the seed already names is not added twice" \
		"$(grep -cxF '@kyriakon.net' "$tree/spamd.alloweddomains")" 1
	check "and the list is 0644" "$(stat -f %Lp "$tree/spamd.alloweddomains")" 644

	# A deploy after a group was provisioned leaves the body's line where the
	# drain put it, and a hand edit is not clobbered either.
	cp "$tree/spamd.alloweddomains" "$tree/allowed.expected"
	merge_spamd_allowed "$repo_dir/openbsd/etc/spamd.alloweddomains" \
		"$tree/mail_domains" "$tree/spamd.alloweddomains"
	check "a second merge leaves the list as it was" \
		"$(cmp -s "$tree/spamd.alloweddomains" "$tree/allowed.expected" \
			&& printf same || printf changed)" same
	printf '# a hand edit\n@manual.example\n' >> "$tree/spamd.alloweddomains"
	merge_spamd_allowed "$repo_dir/openbsd/etc/spamd.alloweddomains" \
		"$tree/mail_domains" "$tree/spamd.alloweddomains"
	check "a hand-written line and its comment survive a deploy" \
		"$(grep -cx -e '# a hand edit' -e '@manual.example' "$tree/spamd.alloweddomains")" 2

	# A hand edit in mail_domains can carry a comment or trailing spaces.
	# check-hygiene.sh compares the two files after stripping both, so the line
	# this appends must be the bare domain or the next hygiene run reports drift.
	printf 'kyriakon.net\n  parish.example  # the parish\n# a note, not a domain\n' \
		>"$tree/mail_domains"
	merge_spamd_allowed "$repo_dir/openbsd/etc/spamd.alloweddomains" \
		"$tree/mail_domains" "$tree/spamd.alloweddomains"
	check "a commented mail_domains line is appended as the bare domain" \
		"$(grep -cxF '@parish.example' "$tree/spamd.alloweddomains")" 1
	check "and nothing carrying the comment or the spaces is appended" \
		"$(grep -c -e '@parish.example ' -e '@parish.example#' "$tree/spamd.alloweddomains")" 0

	# --- the mail-from table ---
	# The submission check is only as good as this table: smtpd's `senders`
	# option looks the authenticated account up and refuses any other address, so
	# the line must be per-account. An account's own identity heads its list, and
	# a full-address virtuals line that delivers into it is appended, which is how
	# a group mailbox sends as the address it publishes. A bare alias and an
	# address aimed at a service account are not account identities.
	printf '%s\n' 'oliver:x:1000:1000::/home/oliver:/bin/ksh' \
		'alice:x:1001:1001::/home/alice:/bin/ksh' \
		'_onboard:x:800:800::/var/db/onboard:/sbin/nologin' > "$tree/passwd"
	printf '%s\n' 'oliver@kyriakon.net: oliver' \
		'secretary@parish.example: alice' \
		'admin@kyriakon.net: alice+Admin' \
		'hello: alice' \
		'apply@kyriakon.net: _onboard' > "$tree/virtuals_mail_from"
	mail_from_entries "$tree/passwd" "$tree/virtuals_mail_from" > "$tree/mail_from"
	check "each account under /home gets its own line" \
		"$(grep -c -e '^oliver: ' -e '^alice: ' "$tree/mail_from")" 2
	check "and the platform identity alone is on it" \
		"$(grep -c '^oliver: oliver@kyriakon.net$' "$tree/mail_from")" 1
	check "and the addresses that deliver into it are on that line" \
		"$(grep -c '^alice: alice@kyriakon.net,secretary@parish.example,admin@kyriakon.net$' "$tree/mail_from")" 1
	check "a delivery detail resolves to the account" \
		"$(grep -c 'admin@kyriakon.net' "$tree/mail_from")" 1
	check "but a bare alias and a service account's address are not" \
		"$(grep -c -e 'hello' -e 'apply@' -e '_onboard' "$tree/mail_from")" 0
	check "and no account's line carries another account's address" \
		"$(awk -F': ' '$1 == "alice" && $2 ~ /oliver@/ { found = 1 } END { exit !found }' "$tree/mail_from" \
			&& printf yes || printf no)" no
	check "an identity virtuals already carries is not repeated" \
		"$(grep -c 'alice@kyriakon.net' "$tree/mail_from")" 1
	check "and there is one line per account" \
		"$(wc -l < "$tree/mail_from" | tr -d ' ')" 2

	# --- the MTA configuration ---
	# Against the file that gets installed rather than a fixture: the substitution
	# below is what puts the queue key and the filter's domain list in place, and
	# reload-smtpd.sh runs the same function after a body joins or leaves.
	if [ ! -r "$repo_dir/openbsd/etc/smtpd.conf" ]; then
		printf 'self-test: no %s/openbsd/etc/smtpd.conf to read: run this from the checkout, or pass its root as the second argument\n' \
			"$repo_dir" >&2
		exit 1
	fi
	template="$repo_dir/openbsd/etc/smtpd.conf"
	queue_key=0123456789abcdef0123456789abcdef
	printf '%s\n' "$queue_key" > "$tree/queue.key"
	printf 'kyriakon.net\n' > "$tree/dkim_domains"
	# The umask an operator's shell is likely to have. The file holds the queue
	# key, so the mode it lands with must not depend on this.
	umask 022
	install_smtpd_conf "$template" "$tree/dkim_domains" "$tree/queue.key" "$tree/smtpd.conf"
	check "no placeholder is left in the installed configuration" \
		"$(grep -c REPLACE_ME "$tree/smtpd.conf")" 0
	# One substituted line for each placeholder in the shipped file, whatever shape
	# that file's filter declaration has. The key is checked by the line above.
	check "every placeholder line is given the domain list" \
		"$(grep -c -- '-d kyriakon.net' "$tree/smtpd.conf")" \
		"$(grep -c REPLACE_ME_DKIM_DOMAINS "$template")"
	check "the installed configuration is 0600 under a 022 umask" \
		"$(stat -f %Lp "$tree/smtpd.conf")" 600

	# A body's domain appended to the list is in the next render, in file order
	# behind the platform's: the filter falls back to the first -d, so the order
	# is the property, not decoration.
	printf 'kyriakon.net\nparish.example\n' > "$tree/dkim_domains"
	install_smtpd_conf "$template" "$tree/dkim_domains" "$tree/queue.key" "$tree/smtpd.conf"
	check "a body's domain reaches the filter's -d list on a re-render" \
		"$(grep -c '^filter \"dkimsign\" proc-exec \"filter-dkimsign -d kyriakon.net -d parish.example' "$tree/smtpd.conf")" 1
	printf 'kyriakon.net\n' > "$tree/dkim_domains"
	install_smtpd_conf "$template" "$tree/dkim_domains" "$tree/queue.key" "$tree/smtpd.conf"
	check "and a domain dropped from the list leaves the filter" \
		"$(grep -c '^filter.*-d parish.example' "$tree/smtpd.conf")" 0

	# The renderer's rule is the intake's: control/crates/core/src/flow/validate.rs's
	# domain() accepts these, and the same corpus is in its own test. A line the
	# rule refuses can still be in the table from before the rule, so it is
	# skipped with a warning rather than failing the render: one bad line must
	# not stop every body's mail being signed.
	printf 'kyriakon.net\nsub.parish.example\nparish-12.example\na.bb\n' > "$tree/dkim_domains"
	check "every domain the intake accepts renders" \
		"$(dkim_domains_args "$tree/dkim_domains")" \
		"-d kyriakon.net -d sub.parish.example -d parish-12.example -d a.bb"
	printf 'kyriakon.net\nparish.12\n' > "$tree/dkim_domains"
	if dkim_domains_args "$tree/dkim_domains" >"$tree/skipped.out" 2>&1; then
		code=0
	else
		code=$?
	fi
	check "a line the renderer refuses does not fail the render" "$code" 0
	check "and the good domain still renders" \
		"$(grep -cx -- '-d kyriakon.net' "$tree/skipped.out" || true)" 1
	check "and the refused line is named in the warning" \
		"$(grep -c 'not a domain, so it is not signed: parish.12' "$tree/skipped.out")" 1
	check "and it is not in the filter arguments" \
		"$(grep -c -- '-d parish.12' "$tree/skipped.out" || true)" 0
	printf 'kyriakon.net\n' > "$tree/dkim_domains"

	# The routing rules the mail cannot do without. The enqueuer's rule is what
	# carries cron's own failure copy and every operator alert off the box: with
	# it gone they are refused at RCPT and the alert path disappears silently.
	# The submission listener's `senders` option is what binds an authenticated
	# account to its own addresses, which filter-dkimsign would otherwise sign
	# for whatever domain the sender names.
	#
	# Each is an exact line of the installed file, so removing the line from the
	# shipped config makes this self-test fail rather than pass on a substring.
	relay_match=$(awk '/^match from local for any action "relay"$/ { print NR; exit }' \
		"$tree/smtpd.conf")
	mail_domains_local=$(awk '/^match from any for domain <mail_domains> action "local_mail"$/ { print NR; exit }' \
		"$tree/smtpd.conf")
	local_for_local=$(awk '/^match from local for local action "local_mail"$/ { print NR; exit }' \
		"$tree/smtpd.conf")
	check "off-box mail from the enqueuer reaches the relay" \
		"$([ -n "$relay_match" ] && printf yes || printf no)" yes
	check "and only after both local delivery rules" \
		"$([ -n "$relay_match" ] && [ -n "$mail_domains_local" ] && [ -n "$local_for_local" ] \
			&& [ "$relay_match" -gt "$mail_domains_local" ] && [ "$relay_match" -gt "$local_for_local" ] \
			&& printf yes || printf no)" yes
	check "authenticated submission is held to the sender mapping" \
		"$(grep -c '^match auth from any for any action "relay"$' "$tree/smtpd.conf")" 1
	check "and the submission listener reads it" \
		"$(grep -c '^listen on egress smtps pki mail.kyriakon.net auth filter "dkimsign" senders <mail_from>$' "$tree/smtpd.conf")" 1
	check "and so does the auth-optional port, so it is not a way around it" \
		"$(grep -c '^listen on egress tls pki mail.kyriakon.net auth-optional senders <mail_from>$' "$tree/smtpd.conf")" 1
	check "and the table the listeners name is installed" \
		"$(grep -c '^table mail_from file:/etc/mail/mail_from$' "$tree/smtpd.conf")" 1
	check "no unauthenticated TCP loopback listener is left" \
		"$(grep -c '^listen on lo0' "$tree/smtpd.conf" || true)" 0

	# The apply@ route: a plaintext Maildir for _onboard, matched before the
	# general local delivery. The order is the whole property: a match after it
	# would deliver the key through the encrypting LMTP path, where the drain
	# cannot read it.
	apply_match=$(awk '/^match from any for domain <mail_domains> rcpt-to apply@kyriakon.net action "onboard_mail"$/ { print NR; exit }' \
		"$tree/smtpd.conf")
	local_match=$(awk '/^match from any for domain <mail_domains> action "local_mail"$/ { print NR; exit }' \
		"$tree/smtpd.conf")
	check "apply@ is delivered to the plaintext _onboard Maildir" \
		"$(grep -c '^action "onboard_mail" maildir "/var/db/onboard/mail" user _onboard$' "$tree/smtpd.conf")" 1
	check "apply@ is matched before local delivery" \
		"$([ -n "$apply_match" ] && [ -n "$local_match" ] && [ "$apply_match" -lt "$local_match" ] && printf yes || printf no)" yes

	before=$(stat -f %i "$tree/smtpd.conf")
	install_smtpd_conf "$template" "$tree/dkim_domains" "$tree/queue.key" "$tree/smtpd.conf"
	after=$(stat -f %i "$tree/smtpd.conf")
	check "an installed configuration is replaced, not rewritten" \
		"$([ "$before" != "$after" ] && printf yes || printf no)" yes

	# A template that cannot be read fails after the candidate is staged, which is
	# the failure the redirect used to turn into an empty smtpd.conf, every mail
	# path on the box. The live file must be as it was and the staged candidate
	# gone rather than left beside it.
	cp "$tree/smtpd.conf" "$tree/expected"
	set +e
	( set -e; install_smtpd_conf "$tree/no-such-template" \
		"$tree/dkim_domains" "$tree/queue.key" "$tree/smtpd.conf" ) >/dev/null 2>&1
	code=$?
	set -e
	check "a substitution that fails leaves the configuration as it was" \
		"$(cmp -s "$tree/smtpd.conf" "$tree/expected" && printf same || printf changed)" same
	check "and says that it failed" "$([ "$code" -ne 0 ] && printf yes || printf no)" yes
	check "and leaves no candidate beside it" \
		"$(find "$tree" -maxdepth 1 -name 'smtpd.conf.*' | wc -l | tr -d ' ')" 0

	# The live callers name the parser, so a candidate smtpd refuses never lands.
	printf '#!/bin/sh\nexit 1\n' > "$tree/smtpd-refuses"
	chmod 0755 "$tree/smtpd-refuses"
	cp "$tree/smtpd.conf" "$tree/expected-smtpd"
	code=0
	( install_smtpd_conf "$template" "$tree/dkim_domains" "$tree/queue.key" \
		"$tree/smtpd.conf" "$tree/smtpd-refuses" ) >/dev/null 2>&1 || code=$?
	check "a parser that refuses fails the smtpd render" \
		"$([ "$code" -ne 0 ] && printf yes || printf no)" yes
	check "and leaves the live file alone" \
		"$(cmp -s "$tree/smtpd.conf" "$tree/expected-smtpd" && printf same || printf changed)" same
	check "and leaves no candidate behind it" \
		"$(find "$tree" -maxdepth 1 -name 'smtpd.conf.*' | wc -l | tr -d ' ')" 0

	# The shared staged install, which the other three configs use.
	printf 'new\n' > "$tree/staged.src"
	printf 'old\n' > "$tree/staged.live"
	printf '#!/bin/sh\nexit 0\n' > "$tree/check-ok"
	printf '#!/bin/sh\nexit 1\n' > "$tree/check-bad"
	chmod 0755 "$tree/check-ok" "$tree/check-bad"
	install_validated "$tree/staged.src" "$tree/staged.live" "$tree/check-ok"
	check "a validated config replaces the live file" "$(cat "$tree/staged.live")" new
	printf 'old\n' > "$tree/staged.live"
	code=0
	( install_validated "$tree/staged.src" "$tree/staged.live" "$tree/check-bad" ) \
		>/dev/null 2>&1 || code=$?
	check "a parser that refuses fails the install" \
		"$([ "$code" -ne 0 ] && printf yes || printf no)" yes
	check "and leaves the live file alone" "$(cat "$tree/staged.live")" old
	check "and leaves no candidate behind it" \
		"$([ -e "$tree/staged.live.new" ] && printf present || printf gone)" gone

	# --- the DKIM selector and the zone check ---
	# The zone check follows the filter's -s argument. A rotation changes that
	# argument, and a comparison hardcoded to "mail" would then report the new
	# record as missing on every deploy.
	check "the DKIM selector is read from the filter line" \
		"$(dkim_selector "$tree/smtpd.conf")" mail
	sed 's/-s mail/-s parish/' "$tree/smtpd.conf" > "$tree/rotated.conf"
	check "and a rotated selector is followed" \
		"$(dkim_selector "$tree/rotated.conf")" parish
	dkim_pub=AAAA
	dig() { printf '%s\n' "$*" > "$tree/dig.args"; printf '"AAAA"\n'; }
	dkim_zone_check "$tree/rotated.conf" > "$tree/zone.out"
	check "the zone check queries the selector the filter names" \
		"$(grep -c 'parish\._domainkey\.kyriakon\.net' "$tree/dig.args")" 1
	check "and reports the match" \
		"$(grep -c 'zone record matches the on-box key' "$tree/zone.out")" 1
	dig() { printf '"BBBB"\n'; }
	dkim_zone_check "$tree/rotated.conf" > "$tree/zone-miss.out"
	check "and the repair record names the same selector" \
		"$(grep -c 'parish\._domainkey' "$tree/zone-miss.out")" 1

	# --- the log retention config ---
	# docs/privacy.md promises a seven-day window on the logs that hold a member's
	# address or timestamp. That promise is only a property of the config while
	# these two lines say seven daily generations, so the shipped file is checked
	# here rather than left to a reader to notice.
	# shellcheck disable=SC2016 # $D0 is the literal newsyslog token
	check "the daemon log keeps seven daily generations" \
		"$(grep -E -c '^/var/log/daemon[[:space:]]+640[[:space:]]+7[[:space:]]+\*[[:space:]]+\$D0' \
			"$repo_dir/openbsd/etc/newsyslog.conf" || true)" 1
	# shellcheck disable=SC2016 # as above
	check "the access log keeps seven daily generations at root:wheel 600" \
		"$(grep -E -c '^/home/www/logs/access\.log[[:space:]]+root:wheel[[:space:]]+600[[:space:]]+7[[:space:]]+\*[[:space:]]+\$D0' \
			"$repo_dir/openbsd/etc/newsyslog.conf" || true)" 1

	# --- the generated indexes ---
	# The three include targets are created here, not by the config they are
	# included from. Dropping one again is what #339 did, and the deployed
	# acme-client then fails to parse a config whose include target is missing.
	install_indexes "$tree/etc"
	for i in httpd gmid acme-client; do
		check "the $i index is installed" \
			"$([ -f "$tree/etc/$i.d/index.conf" ] && printf yes || printf no)" yes
	done
	check "the index is 0644" "$(stat -f %Lp "$tree/etc/httpd.d/index.conf")" 644

	# --- the keyring install and a rotated key ---
	# A rotation writes a key the tracked set does not hold. The deploy leaves it
	# alone rather than putting the old key back, and names both fingerprints in
	# what it prints. gpg is stubbed: this checks the decision, not GnuPG.
	gpg() {
		case " $* " in
		*" --list-packets "*) return 0 ;;
		esac
		printf 'fpr:::::::::BBBB BBBB BBBB BBBB:\n'
	}
	keyring_dir="$tree/keyring"
	store_root="$tree/store"
	install -d -m 0755 "$keyring_dir" "$store_root/accounts/alice"
	printf 'tracked alice key\n' > "$tree/alice.asc"
	printf 'tracked bob key\n' > "$tree/bob.asc"
	printf '{"version": 1, "username": "alice", "mail_key": "AAAA AAAA AAAA AAAA"}\n' \
		> "$store_root/accounts/alice/account.json"
	install_keyring_key "$tree/alice.asc" > "$tree/rotated.out" 2>&1
	check "a rotated key is not overwritten" \
		"$([ -f "$keyring_dir/alice.asc" ] && printf yes || printf no)" no
	check "and the deploy names the account's fingerprint" \
		"$(grep -c 'AAAA AAAA AAAA AAAA' "$tree/rotated.out")" 1
	check "and the tracked one" \
		"$(grep -c 'BBBB BBBB BBBB BBBB' "$tree/rotated.out")" 1
	check "and says where to publish it" \
		"$(grep -c 'keys/alice.asc' "$tree/rotated.out")" 1

	# A key with no account record is the ordinary case and installs.
	install_keyring_key "$tree/bob.asc" > "$tree/new.out" 2>&1
	check "a key with no account record installs" \
		"$(cat "$keyring_dir/bob.asc")" 'tracked bob key'
	# The record names the tracked key, which is what a published rotation looks
	# like: the tracked file is the one to install.
	printf '{"mail_key": "BBBB BBBB BBBB BBBB"}\n' \
		> "$store_root/accounts/alice/account.json"
	install_keyring_key "$tree/alice.asc" > "$tree/published.out" 2>&1
	check "a published rotation installs the tracked key" \
		"$(cat "$keyring_dir/alice.asc")" 'tracked alice key'

	# --- the install-set reader ---
	# The /root/bin installs are the table's rows, so this reader decides what
	# reaches the box: it has to skip the comments and take only this
	# destination's rows, and a table it cannot read must not read as an empty
	# install.
	cat > "$tree/install-set.tsv" <<'EOF'
# a comment, not a row
lib.sh	/root/bin	-
keep.sh	/root/bin	30 2 * * *
drain-only.sh	drain	-
EOF
	check "the /root/bin rows are read from the table" \
		"$(install_rows "$tree/install-set.tsv" /root/bin)" "$(printf 'lib.sh\nkeep.sh')"
	got=0
	install_rows "$tree/no-such.tsv" /root/bin >/dev/null 2>&1 || got=$?
	check "a missing table is refused rather than read as no scripts" \
		"$([ "$got" -ne 0 ] && printf yes || printf no)" yes
	check "the checkout's table names lib.sh for /root/bin" \
		"$(install_rows "$script_dir/install-set.tsv" /root/bin | grep -c '^lib\.sh$')" 1
	# The sweep removes the pre-split copies, but never a name the table installs:
	# that would install a new row and delete it in the same run.
	check "a table row is not swept away" \
		"$(stale_copies 'add-user.sh' | grep -c '^add-user\.sh$')" 0
	check "and a script the table does not install still is" \
		"$(stale_copies 'add-user.sh' | grep -c '^restore-test\.sh$')" 1

	self_test_end
}

# --- how this run was asked for ------------------------------------------
# The live run defaults to the box's checkout. --self-test takes the repo root from
# this script's own location instead, and with no second argument, so a run from a
# checkout of either shape reads the tree it is being run from.
case "${1:-}" in
--self-test)
	[ "$#" -le 2 ] || { printf 'usage: ksh %s [repo_dir] | ksh %s --self-test [repo_root]\n' "$0" "$0" >&2; exit 2; }
	repo_dir="${2:-$(cd "$(dirname "$0")/.." && pwd)}"
	self_test
	;;
-*)
	printf 'usage: ksh %s [repo_dir] | ksh %s --self-test [repo_root]\n' "$0" "$0" >&2
	exit 2
	;;
esac

# --- the preconditions, for a live run -----------------------------------
[ "$(id -u)" -eq 0 ] || { printf 'run as root (doas ksh %s)\n' "$0" >&2; exit 1; }
[ -d "$repo_dir" ] || { printf 'repo_dir not found: %s\n' "$repo_dir" >&2; exit 1; }

for f in openbsd/etc/smtpd.conf openbsd/etc/httpd.conf openbsd/etc/gmid.conf \
	openbsd/etc/acme-client.conf \
	openbsd/dovecot/dovecot.conf \
	openbsd/etc/spamd.alloweddomains openbsd/etc/spamd.conf openbsd/etc/nospamd \
	openbsd/etc/kyriakon.env openbsd/etc/newsyslog.conf \
	dovecot-plugin/Makefile kyriakon-encrypt/Cargo.toml keys scripts/setup-env.sh; do
	[ -e "$repo_dir/$f" ] || { printf 'missing from repo_dir: %s\n' "$f" >&2; exit 1; }
done

# --- 1. packages ---------------------------------------------------------

say "packages"
# The rows for this deploy are in openbsd/packages.tsv. The table is also what
# CI reads, so a package this deploy needs has one place to be declared.
need_packages "$repo_dir/openbsd/packages.tsv" deploy-mail.sh

# The blocklist check asks Spamhaus, and Spamhaus refuses to answer any resolver
# serving more than one machine, which is every resolver a Hetzner box is handed.
# A resolver on the box is what lets the strongest list answer rather than the
# fallback zones carrying the verdict.
#
# unbound is part of the base system, not a package, so it is checked rather than
# installed. This used to call need_pkg, which could never succeed and printed
# "Can't find unbound" on every deploy: an error line that is not an error, in a
# script whose failures have to be readable at a glance.
[ -x /usr/sbin/unbound ] || {
	printf 'unbound is missing from the base system\n' >&2
	exit 1
}

# The resolver config is tracked for one setting in it: without
# `qname-minimisation: no` Spamhaus gives no verdict for a clean address, so the
# blocklist check reports coverage it does not have. The candidate is parsed
# before it is renamed onto the live path: a typo left there would take the
# next restart down, and this resolver is DNS for everything else on the box.
# The service's own rc_pre repeats the check, so a file that slips past here
# fails loudly at the restart instead of half-starting.
install_validated "$repo_dir/openbsd/etc/unbound.conf" \
	/var/unbound/etc/unbound.conf unbound-checkconf
start_service unbound

command -v cargo >/dev/null || { printf 'cargo missing after pkg_add rust\n' >&2; exit 1; }
command -v gpg >/dev/null || { printf 'gpg missing after pkg_add gnupg\n' >&2; exit 1; }
command -v hx >/dev/null || { printf 'hx missing after pkg_add helix\n' >&2; exit 1; }

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
# The web tree lives under /home/www and both daemons chroot there, so the
# platform's own sites and the ACME challenge directory sit beside the directory
# each member gets: /home/www/<host>/{www,gemini}. /home/www is root-owned 0755
# because sshd checks every component of a member's ChrootDirectory for root
# ownership and no group or other write bit, and members' directories sit under
# this one. Owner and group are given rather than defaulted, because
# deploy-control.sh now runs first and creates /home/www as a parent of the
# sockets' directories: the mode and owner this line states are the ones the
# chroot check needs whichever deploy made the directory.
install -d -m 0755 -o root -g wheel /home/www
# httpd derives its log directory from the chroot (the chroot plus /logs) and
# refuses to start without it, so it is created here owned the way /var/www/logs
# was: root:daemon 0755.
install -d -m 0755 -o root -g daemon /home/www/logs
# The access log can name a capability URL (/status/<token>, /password/…?sig=),
# so it is root's alone. newsyslog.conf keeps each new rotation at 600; this
# repairs the files already on the box, which a deploy reaches before the first
# rotation after the change.
# httpd creates a missing log 0644, so it must exist at 600 before httpd starts
# in this same deploy; an empty file does not disturb a live one.
[ -e /home/www/logs/access.log ] || : > /home/www/logs/access.log
for log in /home/www/logs/access.log /home/www/logs/access.log.*; do
	[ -f "$log" ] || continue
	chmod 600 "$log"
	chown root:wheel "$log"
done
# acme-client writes the HTTP-01 challenge here. The challenge is served by the
# httpd vhosts, so it has to be inside httpd's chroot, and the default of
# /var/www/acme is not any more. Every domain block in acme-client.conf names
# this directory rather than relying on the default.
install -d -m 0755 -o root -g daemon /home/www/acme
install -d -m 0700 /etc/acme
# The generated indexes the front-ends and acme-client include. include is an
# fopen of one path, so a missing index fails the whole configuration rather than
# being skipped: the file has to exist before httpd -n, gmid -n or acme-client
# parses the config, and an empty one is valid. acme-client.d is the third lane,
# added when member certificates arrived: each member's name gets its own domain
# block there, so the tracked config never gains a per-member line.
install_indexes /etc
# One root per hostname the box serves, each with the www and gemini halves, so
# httpd's root "/<host>/www" and gmid's root "/<host>/gemini" are relative to the
# same chroot and the whole public surface is one tree that the backup covers.
# www.kyriakon.net is absent because it only redirects. The signup hostname has
# no capsule, so it gets www only.
for host in kyriakon.net oliver.kyriakon.net kleio.kyriakon.net press.kyriakon.net; do
	install -d -m 0755 "/home/www/$host/www" "/home/www/$host/gemini"
done
install -d -m 0755 /home/www/signup.kyriakon.net/www
# The vhosts serve from /home/www now, and the directories above are created
# empty. If the old tree is still there, its content has not moved, and saying so
# here is cheaper than debugging a site that returns 404 with every service up.
if [ -d /var/www/kyriakon.net ] || [ -d /var/www/oliver.kyriakon.net ]; then
	printf 'note: /var/www still holds site content, and the vhosts serve /home/www.\n' >&2
	printf '      Move it before relying on the site; the exact commands are in the\n' >&2
	printf '      pull request that introduced /home/www.\n' >&2
fi
# Same move, different tree: httpd's logs follow its chroot, so the live files
# are /home/www/logs and the pre-move archives under /var/www/logs are inert.
# Nothing writes there now, and the newsyslog.conf installed below rotates the
# live path, so those archives are safe to remove by hand.
if [ -d /var/www/logs ]; then
	printf 'note: /var/www/logs holds the pre-move log archives and nothing writes to it.\n' >&2
	printf '      The live logs are /home/www/logs. Delete the stale tree when convenient:\n' >&2
	printf '      doas rm -rf /var/www/logs\n' >&2
fi
install_validated "$repo_dir/openbsd/etc/httpd.conf" /etc/httpd.conf httpd -n -f
install -m 0644 "$repo_dir/openbsd/etc/acme-client.conf" /etc/acme-client.conf

# The log-rotation and retention bound. Installed whole rather than merged: it
# carries the base system's entries as well as ours, because newsyslog has no
# include, so a file holding only our own lines would stop rotating every log
# that is not ours. See the file's header.
install -m 0644 "$repo_dir/openbsd/etc/newsyslog.conf" /etc/newsyslog.conf
start_service httpd

# acme-client exits 0 on change, 2 when the certificate is already current.
# The mail certificate is fatal: smtpd and Dovecot do not start without it.
acme_rc=0
acme-client -v mail.kyriakon.net || acme_rc=$?
case "$acme_rc" in
	0) printf 'mail certificate issued or renewed\n' ;;
	2) printf 'mail certificate already current\n' ;;
	*) printf 'acme-client failed for mail.kyriakon.net (exit %s); is port 80\n' "$acme_rc" >&2
	   printf 'reachable and the challenge directory served? see /home/www/acme\n' >&2
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

# oliver.kyriakon.net, which httpd.conf has a vhost for and relayd presents for
# it. It was not in this list, so its certificate was issued by hand and nothing
# renewed it: left that way it expires silently and takes the https side down for
# that hostname. The capsules are served from the capsule pair generated below,
# not from this one.
acme_rc=0
acme-client -v oliver.kyriakon.net || acme_rc=$?
case "$acme_rc" in
	0) printf 'oliver.kyriakon.net certificate issued or renewed\n' ;;
	2) printf 'oliver.kyriakon.net certificate already current\n' ;;
	*) printf 'warning: acme-client failed for oliver.kyriakon.net (exit %s); its\n' "$acme_rc" >&2
	   printf '  https vhost has no certificate until that succeeds.\n' >&2 ;;
esac

# kyriakon.com, the defensive registration. relayd.conf names its own keypair for
# it, and deploy-relayd.sh refuses to install without both halves of the pair, so
# a fresh box would come up with 443 down until the 03:00 renewal ran. Warns
# rather than exits, like the two above: the name only redirects to the apex, and
# the mail stack does not depend on it.
acme_rc=0
acme-client -v kyriakon.com || acme_rc=$?
case "$acme_rc" in
	0) printf 'kyriakon.com certificate issued or renewed\n' ;;
	2) printf 'kyriakon.com certificate already current\n' ;;
	*) printf 'warning: acme-client failed for kyriakon.com (exit %s); relayd has no\n' "$acme_rc" >&2
	   printf '  pair to present for the redirector until that succeeds, and\n' >&2
	   printf '  scripts/deploy-relayd.sh refuses to run without it.\n' >&2 ;;
esac

# --- Gemini --------------------------------------------------------------

# The same content tree httpd serves, to a second protocol (issue #95). gmid -n
# validates the config the way httpd -n does, before anything restarts.
#
# The capsule pair first, because the config below names it and gmid refuses to
# start on a certificate it cannot read. The pair step generates both halves when
# either is missing and leaves a complete pair alone: a rotated pair is a
# certificate every reader's client has to trust again, so this repairs a lost
# pair and never renews a live one. Refusing here rather than at gmid -n is what
# keeps an unstartable config off the disk, since that check runs after the
# install and a box that reboots in between would come up with no capsules at all.
if ! ksh "$repo_dir/scripts/provision-member-capsule.sh" --pair; then
	printf 'refusing to install %s: the capsules present the pair this step looks after,\n' \
		"/etc/gmid.conf" >&2
	printf '  and it is not there, so gmid would not start.\n' >&2
	exit 1
fi

install_validated "$repo_dir/openbsd/etc/gmid.conf" /etc/gmid.conf gmid -n -c
start_service gmid

# The capsule block needs one live request, because gmid accepts a mistyped
# FastCGI socket path at config time and fails only when a request arrives: the
# gmid -n above cannot tell the socket in the block from one that is not there.
#
# Both halves of the answer are checked, and both are read back from
# /var/log/daemon. Its line count is taken first, so an older deploy's line
# cannot be read as this request's. The reply has to be the handler's, and gmid
# can answer by itself: a connect it cannot make is answered by gmid with a
# status of its own, and gmid has no 20 to send, so a 20 is the capsule
# rendering and the handler's own line carries the same route and code. And
# gmid's log must hold no access line for the request, because that line carries
# the request URI, and a URI on this hostname carries a draft token and an
# applicant's answer, which is what `log off` in the block is for. The handler's
# line carries the route, the reply code and the client address, and never the
# query or the body.
#
# The responder is another script's, and the order is stated rather than assumed:
# scripts/deploy-control.sh creates the socket directory inside gmid's chroot,
# installs the unit and starts kyriakon_control, and this script does none of
# that. With no responder behind the block there is nothing to ask, so this stops
# here and names the script to run first. A version of this that skipped a
# missing responder would pass on the one box the check exists for.
if ! rcctl check kyriakon_control >/dev/null 2>&1; then
	printf 'the capsule: kyriakon_control is not running, so the block just installed\n' >&2
	printf '  answers nothing. Run scripts/deploy-control.sh first, which creates the\n' >&2
	printf '  socket directory and starts the responder.\n' >&2
	exit 1
fi

gemini_url='gemini://signup.kyriakon.net/'
log_before=$(wc -l < /var/log/daemon)

# 1965 is gmid's port, spelled in the block above and in the pf fragment that
# opens it. -quiet takes the handshake off the answer; it implies -ign_eof, and
# this ends where the handler closes the connection. timeout is the bound on a
# gmid that accepts and then waits on a socket that never answers.
#
# The retry is for gmid's own start rather than for the socket: gmid creates its
# listeners in the server processes, which start after the parent has written its
# pidfile, so rcctl check can pass a moment before the port is open. A socket
# nothing ever answers on is what is left after the retries, with no reply at all.
gemini_reply=
gemini_try=0
while [ "$gemini_try" -lt 5 ] && [ -z "$gemini_reply" ]; do
	gemini_reply=$(printf '%s\r\n' "$gemini_url" \
		| timeout 10 openssl s_client -quiet -connect 127.0.0.1:1965 \
			-servername signup.kyriakon.net 2>/dev/null \
		| tr -d '\r' | awk 'NR == 1 { first = $0 } END { print first }') || true
	[ -n "$gemini_reply" ] || sleep 1
	gemini_try=$((gemini_try + 1))
done
gemini_code=${gemini_reply%% *}

if [ "$gemini_code" != 20 ]; then
	printf 'the capsule: %s answered %s, wanted a 20 from the handler.\n' \
		"$gemini_url" "${gemini_reply:-nothing at all}" >&2
	printf '  A 4x here is gmid answering for a socket it could not reach, and gmid logs\n' >&2
	printf '  the path it tried. Check that the block in /etc/gmid.conf and gemini_socket\n' >&2
	printf '  in /etc/onboard/onboard.toml name the same socket.\n' >&2
	tail -n "+$((log_before + 1))" /var/log/daemon | grep -F gmid >&2 || true
	exit 1
fi

# The handler's line, waited for rather than assumed present, because rc.subr's
# daemon_logger is a second process and the line reaches syslog a moment after
# the reply does. The address is the one gmid saw, which for this request is
# loopback, and gmid sends the numeric address with no port on it.
gemini_line="kyriakon-control: gemini / $gemini_code 127.0.0.1"
gemini_log=
gemini_try=0
while [ "$gemini_try" -lt 5 ]; do
	gemini_log=$(tail -n "+$((log_before + 1))" /var/log/daemon)
	case "$gemini_log" in
	*"$gemini_line"*) break ;;
	esac
	sleep 1
	gemini_try=$((gemini_try + 1))
done

case "$gemini_log" in
*"$gemini_line"*) ;;
*)
	printf 'the capsule: %s answered %s and the handler wrote no line for it.\n' \
		"$gemini_url" "$gemini_reply" >&2
	gemini_seen=$(printf '%s\n' "$gemini_log" | grep -F kyriakon-control | tail -1)
	printf '  wanted %s, where this run holds: %s\n' \
		"$gemini_line" "${gemini_seen:-nothing from the handler}" >&2
	exit 1
	;;
esac

# The other half: no access line of gmid's for the request. The URI is what is
# looked for rather than the shape of the line, because the URI is what `log off`
# exists to keep out of the log and what gmid writes verbatim when the block logs.
case "$gemini_log" in
*"$gemini_url"*)
	printf 'the capsule: gmid logged a line carrying %s, so the block is not\n' \
		"$gemini_url" >&2
	printf '  keeping the request URI out of /var/log/daemon. See log off in the block.\n' >&2
	printf '%s\n' "$gemini_log" | grep -F "$gemini_url" >&2
	exit 1
	;;
esac

printf 'gemini: %s answered %s, so the block reaches the handler\n' "$gemini_url" "$gemini_reply"
printf '  handler log: %s\n' "$(printf '%s\n' "$gemini_log" | grep -F "$gemini_line" | tail -1)"
printf '  gmid log: no access line for the request, so its URI is not in the log\n'

# --- Finger --------------------------------------------------------------

# A static page on port 79, spawned per connection by inetd rather than run as a
# daemon, which is why there is no rc.d entry for it here. Everything it serves
# is already public: gen-finger-page.sh derives the endpoint list from the httpd
# and gmid configs installed above, so adding a vhost is the only edit needed for
# it to appear, and the page cannot advertise something the box does not serve.
#
# Deliberately not fingerd's default provider, which answers with login names,
# real names and .plan contents, and -p only removes part of that; -P replaces it
# outright. -s stops a query being forwarded to another host. -l is left off
# because it logs the requesting host and the query, which would make this the
# one service on the box keeping a record of who looked. This is a finger service
# for an easter egg, not a directory of the box's users.
say "finger"
install -d -m 0755 /etc/kyriakon
install -d -m 0755 /usr/local/libexec
finger_tmp=$(mktemp)
ksh "$repo_dir/scripts/gen-finger-page.sh" > "$finger_tmp"
install -m 0644 "$finger_tmp" /etc/kyriakon/finger.txt
rm -f "$finger_tmp"
install -m 0755 "$repo_dir/openbsd/etc/kyriakon-finger" /usr/local/libexec/kyriakon-finger

# The page and the provider are read by the _fingerd account, so both have to stay
# world-readable. The service is spawned by inetd, and OpenBSD's base install
# ships no /etc/inetd.conf at all, only a commented example under /etc/examples,
# so this creates the file.
#
# Two lines, not one. inetd takes the socket family from the protocol field, so a
# lone `tcp` entry listens on IPv4 only and the box refuses connections on its IPv6
# address: `finger @kyriakon.net` then works or not depending on which address the
# resolver returns first, which is how the first deploy looked healthy while being
# half-open. The shipped example carries both lines for this reason. Each family is
# guarded separately so that adding the missing one works on a box where the other
# is already installed, which is exactly the state the first deploy left behind.
inetd_conf=/etc/inetd.conf
for proto in tcp tcp6; do
	if grep -Eq "^[[:space:]]*finger[[:space:]]+stream[[:space:]]+${proto}[[:space:]]" "$inetd_conf" 2>/dev/null; then
		printf 'inetd: finger/%s already configured\n' "$proto"
	else
		printf '%s\n' "finger stream ${proto} nowait _fingerd /usr/libexec/fingerd fingerd -s -P /usr/local/libexec/kyriakon-finger" >> "$inetd_conf"
		printf 'inetd: finger/%s line added to %s\n' "$proto" "$inetd_conf"
	fi
done
start_service inetd

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

# The two tables smtpd.conf reads. Both are generated on the box: this deploy
# seeds only the platform's own entries and leaves the rest of each file alone,
# because the drain that provisions a body appends to these same files and a
# redeploy must not wipe what it wrote.
#
# Seeded before the reload below, not after: a file: table is opened when the LKA
# process starts rather than when the configuration is parsed, so smtpd -n passes
# on a config naming a table the box does not have and it is the running daemon
# that fails.
#
# The drain hooks in here. Its group-provision step appends one line to
# /etc/mail/mail_domains per body domain, a "full-address account" line to
# /etc/mail/virtuals per body address, and that address to the delivering
# mailbox's list in /etc/mail/mail_from, then runs reload-smtpd.sh, which
# re-expands the filter's -d list and restarts smtpd. The mail_from generation
# below is the same table's other writer, under the same lock.
# The platform's own domain. Every account under /home answers for it, and it is
# the one line this deploy owns in mail_domains.
platform_domain=kyriakon.net
mail_domains_table=/etc/mail/mail_domains
virtuals_table=/etc/mail/virtuals
if [ -s "$mail_domains_table" ]; then
	require_mail_domains "$mail_domains_table" "$platform_domain" || exit 1
	printf 'kept existing %s\n' "$mail_domains_table"
else
	printf '%s\n' "$platform_domain" > "$mail_domains_table"
	chmod 0644 "$mail_domains_table"
	printf 'seeded %s with the platform domain\n' "$mail_domains_table"
fi
[ -e "$virtuals_table" ] || : > "$virtuals_table"
chmod 0644 "$virtuals_table"

# The DKIM filter's domain list, one domain per line, generated on the box the way
# the two tables above are. The single filter process signs every domain in it
# with the one key, choosing the domain that matches the message's From header and
# falling back to the first domain given, so the platform's own domain is first: a
# list whose first line was a body's domain would sign every name the filter does
# not know with that body's domain, its d= would not match its From domain, and
# DMARC alignment would fail. This deploy writes only that first line; the drain
# that provisions a body appends the body's domain, and removing a body is
# removing its line.
#
# The first domain is asserted rather than rewritten, because reordering a list
# this deploy shares with the drain is how the fallback would move by accident.
# The list is not a secret, only the domains the box sends as.
#
# The drain writes the file too, and a line here is not enough on its own: the -d
# list is spliced into /etc/mail/smtpd.conf. Whoever appends a domain re-runs
# that splice, which is why this deploy installs the template beside the live
# file and scripts/reload-smtpd.sh renders it on every restart.
dkim_domains_table=/etc/mail/dkim_domains
if [ -s "$dkim_domains_table" ]; then
	dkim_first=$(awk 'NF { print; exit }' "$dkim_domains_table")
	[ "$dkim_first" = "$platform_domain" ] || {
		printf 'first line of %s is "%s", not "%s": the filter falls back to the first domain, which must be the platform domain\n' \
			"$dkim_domains_table" "$dkim_first" "$platform_domain" >&2
		exit 1
	}
else
	dkim_domains_add "$dkim_domains_table" "$platform_domain"
	chmod 0644 "$dkim_domains_table"
fi

# Addresses the domain has to answer for. RFC 2142 requires every mail domain to
# accept postmaster@ and abuse@; docs/aup.md sends abuse reports to
# abuse@kyriakon.net; the DMARC record points aggregate reports at
# dmarc@kyriakon.net. On a fresh box none of them land anywhere useful: abuse
# and dmarc have no entry at all, and postmaster resolves to root, whose mailbox
# nobody reads. Delivering them to the operator account means they arrive in a
# mailbox that is read like any other delivery.
#
# These move into /etc/mail/virtuals as bare localparts rather than into
# /etc/mail/aliases. The virtual lookup tries user@domain, then user, so a bare
# localpart answers for every domain in mail_domains; the full-address entry the
# drain writes for a body's own secretary@ is a different key and does not
# collide with it. A body keeps no catch-all, because the ten-address cap counts
# what the platform provisions and a catch-all would answer for any number of
# them. security@ is absent on purpose, since the base aliases point it at root,
# which resolves here to oliver. hello@ is here because the landing site
# publishes it as the contact address, so mail to the platform bounces without
# it.
#
# A table line is "name: value" (table(5) allows whitespace or an optional colon
# between the columns; the colon is what the platform aliases have always used).
# The write is matched on the leading localpart, so the platform's bare hello
# does not touch a body's hello@parish.example, and every line the drain has
# already added survives.
#
# admin@ uses Dovecot's recipient_delimiter (+ in dovecot.conf) so it lands in
# the .Admin folder rather than the INBOX. It was previously an INBOX delivery
# with a Thunderbird filter expected to move it, and that filter matches on the
# sender being root@, so it filed machine mail and could never have caught
# correspondence addressed to admin@. Filing it at delivery means it works on
# every client, not only the one somebody configured, and the folder name here
# has to match the existing .Admin exactly, since the detail part is used as
# written.
virtual_entries="root: oliver
postmaster: oliver
abuse: oliver
dmarc: oliver
admin: oliver+Admin
hello: oliver"
# Fed to each loop through a here-document rather than a here-string. OpenBSD's
# /bin/ksh is pdksh-derived and has no `<<<`, which fails at parse time with
# "syntax error: `< ' unexpected" and takes the whole deploy down with it. The
# delimiter is unquoted so the variable expands, one entry per line. Read line
# by line rather than split on whitespace: splitting would tear the "name: value"
# pair apart and write an entry with an empty value, which stops delivering mail
# to that address.
# One trap for every candidate in this section: a second `trap ... EXIT` would
# replace this one rather than add to it, and the earlier writes' candidates
# would be left behind. mail_from_tmp is set below; `:-` covers this trap running
# first. The virtual writes create their own candidate inside table_set, under
# the lock.
mail_from_tmp=''
trap 'rm -f "${mail_from_tmp:-}"' EXIT
while IFS= read -r entry; do
	set_virtual "$virtuals_table" "${entry%%:*}" "$entry"
done <<EOF
$virtual_entries
EOF
while IFS= read -r entry; do
	grep -qxF "$entry" "$virtuals_table" \
		|| { printf 'virtual entry did not land in %s: %s\n' "$virtuals_table" "$entry" >&2; exit 1; }
done <<EOF
$virtual_entries
EOF

# One entry per local account, because the virtual table is the whole answer for
# this domain: a lookup that finds neither <user>@<domain> nor <user> has nothing
# to expand to, so an account whose address is missing is an account mail cannot
# reach, and the rejection happens at RCPT time where only the sender sees it.
# Every account whose home is under /home is one of ours, since the service
# accounts live in /var, and each entry is an identity mapping: the account
# delivers its own mail.
#
# The aliases above and these lines are both written here, and the drain writes
# the same file's body addresses, because a box deployed today has accounts that
# predate any drain. Only an absent line is added: one that already maps the
# address somewhere else is left alone, so an address deliberately aimed at
# another mailbox survives a redeploy. Nothing is removed here either, since an
# address can still be wanted after the account stops being used, and removing it
# is the drain's act.
while IFS= read -r acct; do
	[ -n "$acct" ] || continue
	account_line="$acct@$platform_domain: $acct"
	if awk -F: -v k="$acct@$platform_domain" '$1 == k { found = 1 } END { exit !found }' "$virtuals_table"; then
		continue
	fi
	table_set "$virtuals_table" "$acct@$platform_domain" "$account_line"
	awk -F: -v k="$acct@$platform_domain" '$1 == k { found = 1 } END { exit !found }' "$virtuals_table" \
		|| { printf 'virtual entry did not land in %s: %s\n' "$virtuals_table" "$account_line" >&2; exit 1; }
	printf 'virtual %s added\n' "$acct@$platform_domain"
done <<EOF
$(awk -F: '$6 ~ /^\/home\// { print $1 }' /etc/passwd)
EOF

# The sender mapping the listeners' `senders` option reads. Generated rather
# than appended, so an account deleted from /etc/passwd loses its submission
# identity at the next deploy. It is written in the same pass as the tables
# above, before smtpd -n and the restart, because smtpd fails to start on a file
# table it cannot open.
#
# Each line maps an account to the addresses it may submit as: its login
# identity first, then every full-address virtuals line that delivers into an
# account with a home under /home. A bare alias and an address aimed at a service
# account are not account identities and stay out. The generation covers
# everything the box holds at that moment; provision-member.sh and the drain's
# group transition add an address to the owning account's line as they make it,
# so a member provisioned after this deploy submits without waiting for the next
# one. The read-modify-replace runs under the same table lock those writers take:
# an append landing between the virtuals read and the rename would otherwise be
# dropped.
mail_from_table=/etc/mail/mail_from
mail_from_tmp=$(mktemp "$mail_from_table.XXXXXX")
table_lock "$mail_from_table" || exit 1
mail_from_entries /etc/passwd "$virtuals_table" > "$mail_from_tmp"
chmod 0644 "$mail_from_tmp"
mv "$mail_from_tmp" "$mail_from_table"
table_unlock "$mail_from_table"
printf 'mail_from: %s entries\n' "$(grep -c . "$mail_from_table" || true)"

# The shipped template with both placeholders still in it, installed beside the
# live file. reload-smtpd.sh and provision-member.sh re-render from it whenever a
# body joins or leaves, so the filter's -d list follows /etc/mail/dkim_domains
# without waiting for a deploy.
install -m 0644 "$repo_dir/openbsd/etc/smtpd.conf" /etc/mail/smtpd.conf.template

# '|' delimits the s/// because base64 keys contain '/'. The deployed file holds
# the key, hence 0600. install_smtpd_conf stages beside the live file and parses
# the candidate with `smtpd -n -f` before the rename, so a failure leaves the
# running configuration whole and the live file untouched.
install_smtpd_conf /etc/mail/smtpd.conf.template "$dkim_domains_table" \
	"$queue_key_file" /etc/mail/smtpd.conf smtpd
for placeholder in REPLACE_ME_QUEUE_KEY REPLACE_ME_DKIM_DOMAINS; do
	grep -q "$placeholder" /etc/mail/smtpd.conf \
		&& { printf '%s was not substituted in /etc/mail/smtpd.conf\n' "$placeholder" >&2; exit 1; }
done

# The same order for Dovecot: the candidate is parsed before it takes the live
# path, so a typo costs a refused deploy rather than every IMAP session after
# the next restart.
install_validated "$repo_dir/openbsd/dovecot/dovecot.conf" \
	/etc/dovecot/dovecot.conf doveconf -n -c

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
# spammer. It follows /etc/mail/mail_domains rather than the tracked copy: a
# body's domain is appended by the drain when its group is provisioned, and
# installing the tracked file over the live one would delete every one of those
# lines on each deploy.
merge_spamd_allowed "$repo_dir/openbsd/etc/spamd.alloweddomains" \
	"$mail_domains_table" /etc/mail/spamd.alloweddomains
printf 'spamd.alloweddomains: %s domains\n' \
	"$(grep -c '^@' /etc/mail/spamd.alloweddomains || true)"

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
# The selector comes from the filter line, not a literal: after a rotation -s
# names the new selector and the old one is published only until its messages
# age out, so a fixed "mail" here would report a correct rotation as a mismatch
# and tell the operator to retire the old selector early.
dkim_zone_check /etc/mail/smtpd.conf || exit 1

say "SPF"
# The mail host is a sending identity of its own. Cron output, the daily
# security(8) mail and smtpd's own bounces leave here with mail.kyriakon.net as
# both their envelope and From domain, so SPF is checked against that name and
# not the apex. A missing record there returns "none" and gives those messages
# no SPF pass at all: Google's aggregate reports showed spf=fail on every row
# from this box, with DKIM the only thing carrying them.
#
# The record names the box's own IPv6 address. The mail host has no AAAA, so
# that address is not one the "a" mechanism can match, and an outbound message
# sent over IPv6 would find nothing authorizing it.
#
# Read from the env file, which is what deploy-nsd.sh substitutes into the zone,
# rather than from the interface. The interface is not that value: it is empty
# whenever the address is not up, so reading it here produced an expected record
# of "ip6:" with nothing after it, and reported a correct published record as
# wrong. Anchoring on the substitution's own source is what keeps the two in step,
# and the interface is one of the things the substitution changes.
env_file="${KYRIAKON_ENV:-/root/.kyriakon-env}"
# shellcheck disable=SC1090 # root's own env file, whose path resolves at runtime
box_v6=$(. "$env_file" 2>/dev/null; printf '%s' "${KYRIAKON_IPV6:-}")
if [ -z "$box_v6" ]; then
	printf 'mail SPF: no KYRIAKON_IPV6 in %s, so the zone would be published\n' "$env_file"
	printf 'with "ip6:" and no address after it. Set it in that file, then:\n'
	printf '  doas ksh %s/deploy-nsd.sh\n\n' "$(dirname "$0")"
else
	mail_spf="v=spf1 a ip6:${box_v6} -all"
	published_spf=$(dig +short @ns1.he.net mail.kyriakon.net TXT | tr -d '"')
	case "$published_spf" in
		*"$mail_spf"*) printf 'mail SPF record published: %s\n' "$published_spf" ;;
		*) printf 'mail SPF record missing or different (want "%s", got "%s").\n' \
			   "$mail_spf" "$published_spf"
		   printf 'That is what the zone template substitutes to. Redeploy it, which\n'
		   printf 'bumps the serial and derives the record from the same value:\n\n'
		   printf '  doas ksh %s/deploy-nsd.sh\n\n' "$(dirname "$0")" ;;
	esac
fi

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
	install_keyring_key "$k"
done

# --- 6. services --------------------------------------------------------

say "services"
# Nothing to start for the encryptor: the Dovecot plugin runs the binary
# installed above, as the mailbox user, once per save. A box deployed while the
# encryptor was still a daemon keeps it and its socket until it is retired here.
rcctl stop kyriakon_encrypt >/dev/null 2>&1 || true
rcctl disable kyriakon_encrypt >/dev/null 2>&1 || true
rm -f /etc/rc.d/kyriakon_encrypt

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
# spamlogd is not optional and is easy to miss. It reads the pflog interface and
# writes the whitelist entries in /var/db/spamd when it sees a connection pass to
# the real MTA on the SMTP port, which is the only way <spamd-white> ever gets
# populated. Without it greylisting never lets anyone through: the earlier deploy
# started only spamd, and three separate contacts from one host were all refused
# while the table stayed empty. The `log` keyword on the passthrough rule exists
# for this daemon to read.
start_service spamlogd
# The config test for this half: the greytrap allowlist is read by the daemon,
# and the blacklist loader is what the rc.d start path runs. Dry run, so nothing
# is shipped to spamd.
/usr/libexec/spamd-setup -n

# The list of senders that skip greylisting, read by pf as a table file. spamd
# promotes an address only when a retry arrives for the same tuple, and a tuple is
# keyed on the source IP, so a sender that rotates its outbound address between
# retries is never promoted and is deferred until it gives up. Outlook.com,
# Exchange Online and GitHub's own out-N.smtp.github.com pool do that; the pf
# rules that read this file are added by scripts/pf-apply.sh, and
# docs/planning/research/spamd-greylisting.md records each range and the SPF
# record it came from.
say "nospamd"
nospamd_src="$repo_dir/openbsd/etc/nospamd"
# A pf table file holds addresses only. A stray line here would fail the later
# load, which is a human-run step, so it is rejected at deploy time instead.
bad=$(grep -v -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^[0-9A-Fa-f:]+(/[0-9]{1,3})?$' "$nospamd_src" | head -3 || true)
[ -z "$bad" ] || {
	printf 'not an address or network in openbsd/etc/nospamd:\n%s\n' "$bad" >&2
	exit 1
}
install -m 0644 -o root -g wheel "$nospamd_src" /etc/mail/nospamd
printf 'installed /etc/mail/nospamd (%s networks)\n' "$(grep -c . /etc/mail/nospamd)"
# A persist file table is read only when the ruleset loads, so a fresh file
# changes nothing until the table is replaced. Done on every deploy rather than
# on a diff: a matching count is not a matching set, and a replace is cheap and
# idempotent. The check near the end still reports a table that disagrees.
/sbin/pfctl -t nospamd -T replace -f /etc/mail/nospamd \
	|| printf 'could not replace the nospamd table; the greylist exemption check at the end reports it\n' >&2

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

# The members group is what openbsd/etc/sshd_config matches, to give member
# sessions the chrooted sftp server on 22 and git-shell on 2222 and to give the
# operator account neither. sshd refuses a configuration naming a group that does
# not exist, so the group has to be here before that fragment can be applied.
# add-user.sh puts each member into it; anyone created before this ran needs
# "doas usermod -G members <username>" once.
if getent group members >/dev/null 2>&1; then
	printf 'group exists: members\n'
else
	groupadd members
	printf 'created the members group\n'
fi

# Where the operator's cron scripts live. The crontab lines in backup.sh,
# abuse-monitor.sh, check-keyring-drift.sh, restore-standup.sh, renew-acme.sh and
# acme-queue.sh all call /root/bin/<script>,
# and nothing else creates the directory, so a fresh box fails on the first
# install with "install: /root/bin/INS@...: No such file or directory".
# 0755 inside /root, which is already 0700 root.
install -d -m 0755 /root/bin
# The scripts themselves, from the table's /root/bin rows. Nothing used to put
# them there, so every box had them copied by hand from the repo and each crontab
# line pasted by hand too, which is how the monitor spent a week unscheduled.
# cron-apply.sh puts the lines in; it can only do that if the files it names are
# deployed first.
root_bin=$(install_rows "$install_set" /root/bin) \
	|| { printf 'cannot read %s\n' "$install_set" >&2; exit 1; }
[ -n "$root_bin" ] \
	|| { printf '%s names no /root/bin script\n' "$install_set" >&2; exit 1; }
for s in $root_bin; do
	install_staged "$repo_dir/scripts/$s" "/root/bin/$s" -m 0755
done
# The stale copies a box from before the onboarding split still holds; the list
# and why it excludes the installed set are stale_copies' own comment.
for s in $(stale_copies "$root_bin"); do
	[ -e "/root/bin/$s" ] || continue
	rm -f "/root/bin/$s"
	printf 'removed the stale copy /root/bin/%s\n' "$s"
done
printf 'cron scripts installed into /root/bin\n'

# The member session shell on 2222, from the table's /usr/local/libexec row. The
# member login class names this path, so the file is installed here even though
# the class itself is a hand step scripts/deploy.sh prints: applying the class
# before the file is there would refuse every member's push. root:wheel 0755 in
# /usr/local/libexec, which a member can read and execute and cannot write, and
# which is not in the PATH a member session is handed.
libexec_scripts=$(install_rows "$install_set" /usr/local/libexec) \
	|| { printf 'cannot read %s\n' "$install_set" >&2; exit 1; }
[ -n "$libexec_scripts" ] \
	|| { printf '%s names no /usr/local/libexec script\n' "$install_set" >&2; exit 1; }
install -d -m 0755 /usr/local/libexec
for s in $libexec_scripts; do
	install_staged "$repo_dir/scripts/$s" "/usr/local/libexec/$s" -m 0755 -o root -g wheel
done
printf 'member session shell installed into /usr/local/libexec\n'

# The root-owned key directory the member sessions are proposed to read
# (AuthorizedKeysFile /etc/ssh/authorized_keys/%u inside the members Match
# block). It is on every run so the directory exists before a member is
# provisioned, and it sits under /etc/ssh where nothing a member can write is on
# the path. provision-member.sh writes one file per account.
install -d -m 0755 -o root -g wheel /etc/ssh/authorized_keys
printf 'member key directory installed at /etc/ssh/authorized_keys\n'

# hcloud is installed at the top from openbsd/packages.tsv; restore-standup.sh
# needs it to create the weekly test box.

# The box's values. setup-env.sh owns the install and is called rather than
# duplicated here, so a box gets the file whichever deploy runs first: this one
# needs nothing from it, but nsd and cron-apply do, and nsd runs before mail.
say "env"
env_dst=/root/.kyriakon-env
if [ -f "$env_dst" ]; then
	printf 'kept existing %s\n' "$env_dst"
	# A box installed before the PATH line existed still has a file without it,
	# and cron would go on finding no curl: the Healthchecks ping fails into
	# `|| true`, so the box reads as monitored while nothing is sent. Append the
	# line rather than rewriting the file, which must never lose its values.
	if ! grep -q '^PATH=' "$env_dst"; then
		# Quoted heredoc: $PATH here is the literal text to write, not this
		# script's value, which is what shellcheck's SC2016 would flag.
		cat >> "$env_dst" <<-'EOF'

			# cron(8) runs jobs with PATH=/usr/bin:/bin; packages live in
			# /usr/local and ifconfig in /sbin. Every cron line sources this.
			PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
			export PATH
		EOF
		printf 'added the cron PATH line to %s\n' "$env_dst"
	fi
else
	ksh "$repo_dir/scripts/setup-env.sh" \
		|| printf 'WARNING: fill in %s before deploy-nsd or cron-apply\n' "$env_dst"
fi

# A placeholder is not a value, and the failure it causes is silent by design:
# mail to REPLACE_ME_OFF_BOX_ADDRESS fails, notify_operator falls back to
# printing, and cron sends it under its own subject, so every alert loses the
# component and the event in the field an operator triages on. The same applies
# to a healthcheck URL this box reads as a dead-man's switch it is not pinging.
# This is the deploy that installs the cron scripts, so it is the one that says
# so; check-hygiene.sh reports the live value afterwards.
if grep -q 'REPLACE_ME' "$env_dst"; then
	printf '%s still carries a placeholder:\n' "$env_dst" >&2
	grep -n 'REPLACE_ME' "$env_dst" | sed -e 's/^/  /' >&2
	printf 'set it with scripts/setup-env.sh before deploying, or every alert goes out under cron own subject\n' >&2
	exit 1
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
for s in dovecot smtpd httpd spamd inetd; do
	printf '%-18s %s\n' "$s" "$(rcctl check "$s" 2>&1 || true)"
done

# The save path runs the encryptor as the mailbox user, not as root, so prove
# the installed binary and keyring work for that identity. oliver is the
# account this deploy creates and the operator's mail account, so it is the
# one the LMTP process runs as for the first mailbox.
probe_key="$keyring_dir/oliver.asc"
probe_cmd="test -x '$encrypt_bin' &&
	test -x '$keyring_dir' &&
	test -r '$probe_key' || exit 1
	d=\$(mktemp -d) || exit 1
	printf 'From: deploy-check@example.invalid\n\nprobe\n' |
		'$encrypt_bin' encrypt --user oliver --keyring '$keyring_dir' --gpg-home \"\$d\" >/dev/null
	rc=\$?
	rm -rf \"\$d\"
	exit \$rc"
if id oliver >/dev/null 2>&1; then
	if su oliver -c "$probe_cmd"; then
		printf 'encryptor: runs as oliver and encrypted a probe message\n'
	else
		printf 'encryptor probe failed as oliver: every save would fail closed.\n' >&2
		printf 'Check that %s and %s are readable by a non-root account.\n' \
			"$encrypt_bin" "$probe_key" >&2
		exit 1
	fi
else
	printf 'encryptor probe skipped: no oliver account to run it as, so the first\n' >&2
	printf 'LMTP delivery is the first proof it runs as the mailbox user.\n' >&2
fi
# The daemon being up says nothing about whether greylisting is on: the switch is
# the pf divert, which this script must not apply. Report which state the box is
# actually in rather than implying the enabled one.
#
# Match on "divert-to 127.0.0.1" alone. pfctl -sr renders the service name "spamd"
# as its port number, so a pattern containing "port spamd" never matches a loaded
# ruleset and the check reports OFF on a box where greylisting is running.
if pfctl -sr 2>/dev/null | grep -q 'divert-to 127.0.0.1'; then
	printf 'greylisting: on (%s greylisted host(s))\n' \
		"$(spamdb 2>/dev/null | grep -c '^GREY|' || true)"
else
	printf 'greylisting: OFF - inbound mail is not diverted to spamd.\n'
	printf '             Apply it with: doas ksh scripts/pf-apply.sh\n'
fi
# The exemption is reported separately because its absence is not visible in the
# greylisting line above: with the divert on and no exempt list, everything looks
# healthy while senders on rotating addresses are deferred until they give up.
if pfctl -sr 2>/dev/null | grep -q 'from <nospamd>'; then
	# Count what the kernel holds, not what the file says: a `persist file` table is
	# read at load time, so a list that was replaced after the last load leaves the
	# old entries in place while the file looks right. The first run of this check
	# counted the file and reported 19 networks while the kernel held 11.
	kernel_n=$(pfctl -t nospamd -T show 2>/dev/null | grep -c . || true)
	file_n=$(grep -c . /etc/mail/nospamd 2>/dev/null || true)
	printf 'greylist exemption: on (%s network(s) loaded)\n' "$kernel_n"
	if [ "$kernel_n" != "$file_n" ]; then
		printf '                    but /etc/mail/nospamd holds %s: the table is stale.\n' "$file_n"
		# A `persist file` table is read only when the ruleset is loaded, so the
		# file and the kernel can disagree. This replaces just the table;
		# pf-apply.sh would also do it, by reloading /etc/pf.conf.
		printf '                    Run: doas pfctl -t nospamd -T replace -f /etc/mail/nospamd\n'
	fi
else
	printf 'greylist exemption: OFF - senders that rotate their IP will be deferred until they give up.\n'
	printf '                    Apply it with: doas ksh scripts/pf-apply.sh\n'
fi
printf 'MX:   %s\n' "$(dig +short @ns1.he.net kyriakon.net MX)"
printf 'mail: %s %s\n' "$(dig +short @ns1.he.net mail.kyriakon.net A)" \
	"$(dig +short @ns1.he.net mail.kyriakon.net AAAA)"
# The box's own addresses, read from the egress interface rather than written
# here: this repo is public and the addresses are host-specific, so the value
# belongs to the box. Same idiom as scripts/check-hygiene.sh.
ip4=$(ifconfig egress inet 2>/dev/null | awk '/inet / { print $2; exit }')
# The interface carries a link-local address too, and a PTR lookup for fe80::...
# is not the record the box publishes, so the first non-link-local one is the
# global address.
ip6=$(ifconfig egress inet6 2>/dev/null | awk '$1 == "inet6" && $2 !~ /^fe80/ { print $2; exit }')
printf 'PTR4: %s\n' "$(dig +short -x "$ip4")"
printf 'PTR6: %s\n' "$(dig +short -x "$ip6")"

printf '\nmail stack is up. Remaining manual steps:\n'
printf '  1. doas passwd oliver, then configure your client:\n'
printf '     IMAP mail.kyriakon.net:993 (TLS), submission :465 (auth)\n'
printf '  2. inbound test from an external mailbox, then check the Maildir:\n'
printf '     ls -t /home/oliver/Maildir/new/* | head -1\n'
printf '  3. outbound test, then SPF/DKIM/DMARC and inbox placement at a public checker\n'
printf '  4. landing site: the vhosts serve it from /home/www/kyriakon.net/www, so\n'
printf '     a kyriakon-site checkout there is all it needs (git clone once, then\n'
printf '     git pull to update). No pf change is required for 443.\n'
printf '  5. personal site: same shape, at /home/www/oliver.kyriakon.net/www, from\n'
printf '     https://github.com/OliverBrotchie/oliver.kyriakon.net . The vhost\n'
printf '     blocks /.git, so keep it a checkout rather than a copy of the files:\n'
printf '     git clone once as root, then git pull to update. index.html goes in\n'
printf '     www/ and index.gmi in gemini/, which gmid serves for the same name.\n'
printf '  6. pf: the fragments, appended at the END of /etc/pf.conf (pf is\n'
printf '     last-match-wins, so they must follow the stock pass rule). Review\n'
printf '     the diff, then apply:\n'
printf '\n'
printf '\t\t doas ksh scripts/pf-apply.sh --check\n'
printf '\t\t doas ksh scripts/pf-apply.sh\n'
printf '\n'
printf '     It appends only what is missing, checks the candidate with\n'
printf '     "pfctl -n" before touching the live file, keeps a timestamped copy\n'
printf '     of that file, and loads nothing pfctl rejects. The fragments:\n'
printf '\n'
printf '\t\t table <spamd-white> persist\n'
printf '\t\t pass in on egress proto tcp to any port smtp \\\n'
printf '\t\t     divert-to 127.0.0.1 port spamd\n'
printf '\t\t pass in log on egress proto tcp from <spamd-white> to any port smtp\n'
printf '\n'
printf '\t\t table <nospamd> persist file "/etc/mail/nospamd"\n'
printf '\t\t pass in on egress proto tcp from <nospamd> to any port smtp\n'
printf '\n'
printf '     Rationale, including why the second one exists, and checks:\n'
printf '     docs/planning/research/spamd-greylisting.md\n'
printf '  7. cron: the monitoring, backup and renewal lines:\n'
printf '\n'
printf '\t\t doas ksh scripts/cron-apply.sh --check\n'
printf '\t\t doas ksh scripts/cron-apply.sh\n'
printf '\n'
printf '     Values come from /root/.kyriakon-env (mode 0600), which the nsd\n'
printf '     deploy reads too, so nothing is retyped. On a fresh box that file is\n'
printf '     created by scripts/setup-env.sh, before the nsd deploy rather than\n'
printf '     after it.\n'
printf '     The same script applies the generated vhost indexes, which is what\n'
printf '     gives a signup its vhost, in one pass and one reload per daemon:\n'
printf '\n'
printf '\t\t doas ksh scripts/cron-apply.sh --web --check\n'
printf '\t\t doas ksh scripts/cron-apply.sh --web\n'
printf '\n'
printf '  8. quarterly rehearsal: create a Healthchecks check with a ~90-day\n'
printf '     period, then run scripts/rehearsal.sh on a throwaway box. The check is\n'
printf '     the reminder: a skipped quarter leaves it stale and it alerts, which no\n'
printf '     cron entry on this box could do for you if the box is the problem.\n'
printf '  9. LMTP socket: leave it at the Dovecot default. smtpd mda runs as the\n'
printf '     recipient, not as root, so a root:wheel 0600 socket answers\n'
printf '     "mail.lmtp: connect: Permission denied" and mail queues.\n'
