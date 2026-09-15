#!/bin/ksh
# rekey-mail-key.sh — republish a mail key without the AEAD adverts RNP cannot read.
#
# Runs on the WORKSTATION that holds the secret key. The box half is
# deploy-mail.sh, which installs keys/*.asc into the delivery keyring and warns
# about any published key still advertising AEAD.
#
# Why: gpg 2.4+ encrypts with AEAD (packet tag 20) whenever the recipient key
# advertises a pref-aead subpacket, and nothing on the encrypt side overrides
# that — not even --rfc4880. RNP, which is Thunderbird's OpenPGP, has no AEAD
# support, so mail encrypted that way arrives unreadable. Re-signing the
# self-signature with setpref drops both the pref-aead subpacket and the AEAD
# feature bit (features 07 -> 05), after which gpg emits SEIPD (tag 18, AES with
# MDC) instead.
#
# This is a replacement, not a rotation: setpref leaves the fingerprint alone,
# so the published file is rewritten in place and no key material on the box
# changes.
#
# Usage, from the repo root:
#   scripts/rekey-mail-key.sh [key] [published-file]
#
#   key              key id, fingerprint or uid; default oliver@kyriakon.net
#   published-file   tracked file to rewrite; default keys/oliver.asc
#
# Idempotent: an already AEAD-free key skips the edit (and its passphrase
# prompt) and only refreshes the published file. The change is reversible
# (setpref with AEAD:OCB puts the adverts back) and every earlier published
# state is in git history.
#
# It edits the keyring and one tracked file, then prints the git, deploy and
# client steps that follow. Deploying to the box stays a human step.

set -euo pipefail

key="${1:-oliver@kyriakon.net}"
published="${2:-keys/oliver.asc}"

say() { printf '== %s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

# pinentry-curses draws the passphrase prompt on GPG_TTY, and gpg under --batch
# does not hand that address to the agent itself. Without it, a shell that never
# exported GPG_TTY gets a prompt with nowhere to appear.
if [ -z "${GPG_TTY:-}" ] && [ -t 0 ]; then
	GPG_TTY=$(tty)
	export GPG_TTY
fi

# --- preflight ----------------------------------------------------------

command -v gpg >/dev/null || die 'gpg not on PATH'
[ -f "$published" ] || die "run this from the repo root: $published not found"
gpg --list-keys "$key" >/dev/null 2>&1 || die "no keyring key matches: $key"

# packets <key spec> — the subpacket dump of a keyring key, or of a key file.
# Both are read: the file is what ships, and a file left advertising AEAD is the
# failure this script exists to prevent.
packets() {
	if [ -f "$1" ]; then
		gpg --list-packets "$1" 2>/dev/null
	else
		gpg --export "$1" 2>/dev/null | gpg --list-packets 2>/dev/null
	fi
}

# aead_adverts <key spec> — one line per AEAD advert, empty when the key is
# clean. The two adverts fail differently, so both are named: pref-aead is what
# makes gpg choose tag 20, and the feature bit is what RNP reads as an
# unsupported feature.
aead_adverts() {
	if packets "$1" | grep -q 'pref-aead-algos'; then
		printf 'pref-aead-algos subpacket\n'
	fi
	# One line per self-signature: a key with an older signature alongside a
	# fresh one advertises both sets.
	packets "$1" | sed -n 's/.*(features: \([0-9a-fA-F]*\)).*/\1/p' \
		| while read -r feat; do
			if [ $(( 0x$feat & 2 )) -ne 0 ]; then
				printf 'AEAD feature bit (features: %s)\n' "$feat"
			fi
		done
}

# fingerprint <key spec> — primary fingerprint, from the keyring or a file.
# Empty for anything gpg cannot read, including a truncated or empty key file,
# and every caller treats empty as a failure.
fingerprint() {
	if [ -f "$1" ]; then
		gpg --with-colons --show-keys "$1" 2>/dev/null
	else
		gpg --with-colons --list-keys "$1" 2>/dev/null
	fi | awk -F: '$1 == "fpr" { print $10; exit }' || true
}

# --- 1. re-sign without AEAD --------------------------------------------

if [ -n "$(aead_adverts "$key")" ]; then
	say "re-signing $key without AEAD"
	printf '   setpref rewrites the self-signature, so gpg will ask for the passphrase\n'
	# The commands come in on fd 0, so the edit is scripted rather than typed.
	# The preference list has to be explicit because setpref writes only what it
	# is given, and AEAD is exactly what is being dropped. Nothing is written
	# until `save`, so a failure before that leaves the key as it was.
	if ! gpg --batch --yes --command-fd 0 --edit-key "$key" <<'EOF'
setpref AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed
y
save
EOF
	then
		die "gpg could not re-sign $key.
Run this in a terminal so pinentry can ask for the passphrase, then check that
the key is not on a card or in another GnuPG home."
	fi
fi

# --- 2. verify the keyring key ------------------------------------------

say 'verify'
adverts=$(aead_adverts "$key")
[ -z "$adverts" ] || die "$key still advertises AEAD:
$adverts
Do not publish it: gpg would keep emitting tag 20, which RNP cannot open. If the
setpref line above ran, check that it is not being shadowed by a second
self-signature (gpg --edit-key $key, then showpref)."

# --- 3. publish ---------------------------------------------------------

# The file being replaced has to be this key. A different fingerprint means that
# path now holds another key, and overwriting it would silently drop that key
# from the published set: a rotation belongs in a new file, not in this script.
key_fpr=$(fingerprint "$key")
published_fpr=$(fingerprint "$published")
[ -n "$published_fpr" ] || die "$published does not hold a key; refusing to overwrite it"
[ "$published_fpr" = "$key_fpr" ] || die "$published holds $published_fpr, but $key is $key_fpr.
Refusing to overwrite a file that does not hold this key."

# Exported to a temp file beside the target and moved into place, so a check
# that fails cannot leave a half-written key in a tracked path.
tmp=$(mktemp "$published.XXXXXX")
trap 'rm -f "$tmp"' EXIT

gpg --export --armor "$key" > "$tmp"
[ -n "$(fingerprint "$tmp")" ] || die "gpg exported no usable key into $tmp"

adverts=$(aead_adverts "$tmp")
[ -z "$adverts" ] || die "the exported key still advertises AEAD:
$adverts"

if cmp -s "$tmp" "$published"; then
	say "published file already current: $published"
else
	mv "$tmp" "$published"
	say "updated $published"
	git --no-pager diff --stat -- "$published"
fi

# --- 4. what is left ----------------------------------------------------

printf '\nremaining manual steps:\n'
printf '  1. commit the replacement key and push it:\n'
printf '       git add %s\n' "$published"
printf '       git commit -m "fix(mail): drop AEAD from the published key so clients can read delivery"\n'
printf '       git push\n'
printf '  2. on the box, deploy it:\n'
printf '       cd /root/src/kyriakon-infra && git pull --ff-only && doas ksh scripts/deploy-mail.sh\n'
printf '     the keyring section must install %s with no AEAD warning\n' "${published##*/}"
printf '  3. on the box, encrypt the way the daemon does and check the packet shape:\n'
printf '       echo test | doas gpg --batch --no-tty --no-options --encrypt --armor \\\n'
printf '         --no-encrypt-to --recipient-file /etc/kyriakon/keys/%s \\\n' "${published##*/}"
printf '         --homedir /var/run/kyriakon/gpg | doas gpg --list-packets | grep -E "tag=|mdc_method"\n'
printf '     kyriakon-encrypt encrypts with --recipient-file and imports no key, so this is\n'
printf '     the same path a delivery takes, with the deployed file as its only input\n'
printf '     tag=18 with mdc_method: 2 is the pass. tag=20 or an aead line means the old\n'
printf '     key is still deployed: doas gpg --list-packets /etc/kyriakon/keys/%s\n' "${published##*/}"
printf '     must show features: 05 and no pref-aead-algos\n'
printf '  4. in Thunderbird: Account Settings -> End-To-End Encryption -> OpenPGP Key\n'
printf '     Manager -> File -> Import Public Key(s) From File -> %s\n' "$published"
printf '     same fingerprint, so it updates in place\n'
printf '  5. round trip: deliver from an external mailbox and confirm the Maildir file is\n'
printf '     RFC 3156 PGP/MIME that Thunderbird opens, then send out and confirm the\n'
printf '     DKIM-Signature and Authentication-Results on the receiving side\n'
printf '\nanything the box encrypted before this change is AEAD, which Thunderbird cannot\n'
printf 'open; gpg itself still reads it (gpg --decrypt <file>)\n'
