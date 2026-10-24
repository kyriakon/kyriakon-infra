#!/bin/ksh
# render-docs.sh — the publishable copies of the governance documents, with the
# deployment values substituted.
#
# The tracked docs/terms.md, docs/aup.md and docs/privacy.md are the source the
# site serves, and they carry REPLACE_ME rather than the operator's own values
# because this repository is public. The site build runs this script over them and
# renders the output, so the published pages carry the values while the tracked
# files do not.
#
# The trading address is POSTAL_ADDRESS, the same value the drain reads for the
# cash-by-post rail: the operator decided the published trading address and the
# collection address are one value (#397), so there is one variable and the two
# cannot disagree. The ICO reference and the Union representative are separate
# decisions; their variables are read from the same file if the documents name
# them, and the script refuses rather than publish a placeholder.
#
# Usage:
#   ksh scripts/render-docs.sh --out DIR [--env FILE]
#        ksh scripts/render-docs.sh --self-test
#
# --out receives terms.md, privacy.md and aup.md. It is the site build's input,
# not HTML: presentation belongs to the site build, which is kyriakon-site #3.
#
# Refuses, and writes nothing, when a value the documents need is absent or still
# a placeholder, or when any REPLACE_ME remains in an output. A placeholder must
# not reach the public web.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_dir=$(cd "$script_dir/.." && pwd)

usage() {
	printf 'usage: ksh %s --out DIR [--env FILE]\n       ksh %s --self-test\n' \
		"$0" "$0" >&2
	exit 2
}

die() {
	printf '%s: %s\n' "$0" "$*" >&2
	exit 1
}

# render_one <src> <dst> — substitute the five placeholders, then refuse any that
# remain. Letting a placeholder through is the failure the whole script exists to
# prevent, so the check is over the output rather than the list of substitutions.
#
# The replacement is a literal string, so an address can carry & or \. awk's
# gsub treats & in the replacement as the match and leaves the escaping
# implementation-defined, so index and substr do the work instead.
render_one() {
	src=$1
	dst=$2
	awk -v addr="${POSTAL_ADDRESS:-}" -v ico="${ICO_REFERENCE:-}" \
		-v rep="${EU_REPRESENTATIVE:-}" \
		-v rep_contact="${EU_REPRESENTATIVE_CONTACT:-}" '
		function replace_all(s, needle, repl,    out, i) {
			out = ""
			while ((i = index(s, needle)) > 0) {
				out = out substr(s, 1, i - 1) repl
				s = substr(s, i + length(needle))
			}
			return out s
		}
		{
			line = $0
			line = replace_all(line, "REPLACE_ME_TRADING_ADDRESS", addr)
			line = replace_all(line, "REPLACE_ME_ICO_REFERENCE", ico)
			# The contact placeholder is the longer of the two, so it goes first:
			# the shorter pattern would otherwise consume its prefix.
			line = replace_all(line, "REPLACE_ME_REPRESENTATIVE_CONTACT", rep_contact)
			line = replace_all(line, "REPLACE_ME_REPRESENTATIVE", rep)
			print line
		}' "$src" > "$dst" || die "cannot write $dst"
	remaining=$(grep -o 'REPLACE_ME_[A-Z_0-9]*' "$dst" | sort -u || true)
	[ -z "$remaining" ] || die "$dst still carries a placeholder:$remaining"
}

# render_all <docs dir> <out dir> — the live path and the self-test's entry point.
# Values are required only when the documents name them, so a page without a
# placeholder does not demand a value it never uses.
render_all() {
	docs=$1
	out=$2
	terms="$docs/terms.md"
	privacy="$docs/privacy.md"
	aup="$docs/aup.md"
	for f in "$terms" "$privacy" "$aup"; do
		[ -r "$f" ] || die "cannot read $f"
	done

	if grep -q REPLACE_ME_TRADING_ADDRESS "$terms" "$privacy"; then
		case "${POSTAL_ADDRESS:-}" in
		'')
			die "POSTAL_ADDRESS is not set in $env_file; set it with: scripts/setup-env.sh --postal-address '...'"
			;;
		*REPLACE_ME*)
			die "POSTAL_ADDRESS in $env_file is still a placeholder; set it with: scripts/setup-env.sh --postal-address '...'"
			;;
		esac
	fi

	if grep -q REPLACE_ME_ICO_REFERENCE "$terms" "$privacy"; then
		case "${ICO_REFERENCE:-}" in
		'' | *REPLACE_ME*)
			die "ICO_REFERENCE is not set in $env_file; the privacy notice names the ICO registration, which is a separate decision"
			;;
		esac
	fi

	if grep -q REPLACE_ME_REPRESENTATIVE "$terms" "$privacy"; then
		case "${EU_REPRESENTATIVE:-}" in
		'' | *REPLACE_ME*)
			die "EU_REPRESENTATIVE is not set in $env_file; remove the Union representative paragraph if the service is not offered there, or set the value"
			;;
		esac
		case "${EU_REPRESENTATIVE_CONTACT:-}" in
		'' | *REPLACE_ME*)
			die "EU_REPRESENTATIVE_CONTACT is not set in $env_file; set the representative's contact route"
			;;
		esac
	fi

	mkdir -p "$out" || die "cannot create $out"
	render_one "$terms" "$out/terms.md"
	render_one "$privacy" "$out/privacy.md"
	render_one "$aup" "$out/aup.md"
	printf 'rendered terms.md, privacy.md and aup.md to %s\n' "$out"
}

self_test() {
	# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
	. "$script_dir/lib.sh"
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	work=$self_test_work

	# A passing set, with the address the drain would read and the two values
	# whose decisions are separate from the address. The & is there because it is
	# the character awk would otherwise read as the match.
	POSTAL_ADDRESS='1 Example & Co, Example Street, Example'
	ICO_REFERENCE='ZA000000'
	EU_REPRESENTATIVE='Example Representative Ltd'
	EU_REPRESENTATIVE_CONTACT='representative@example.invalid'
	export POSTAL_ADDRESS ICO_REFERENCE EU_REPRESENTATIVE EU_REPRESENTATIVE_CONTACT

	render_all "$repo_dir/docs" "$work/out" >/dev/null

	check 'the terms page carries the address' \
		"$(grep -c -F "$POSTAL_ADDRESS" "$work/out/terms.md")" 2
	check 'the privacy page carries the address' \
		"$(grep -c -F "$POSTAL_ADDRESS" "$work/out/privacy.md")" 1
	check 'no placeholder survives in the terms page' \
		"$(grep -c 'REPLACE_ME' "$work/out/terms.md" || true)" 0
	check 'no placeholder survives in the privacy page' \
		"$(grep -c 'REPLACE_ME' "$work/out/privacy.md" || true)" 0
	check 'the ICO reference is substituted' \
		"$(grep -c -F "$ICO_REFERENCE" "$work/out/privacy.md")" 1
	check 'the representative and its contact are substituted' \
		"$(grep -c -F "$EU_REPRESENTATIVE_CONTACT" "$work/out/privacy.md")" 1
	check 'the aup is copied unchanged' \
		"$(cmp -s "$repo_dir/docs/aup.md" "$work/out/aup.md" && printf yes)" yes
	check 'the tracked terms still carry the placeholder' \
		"$(grep -c -F 'REPLACE_ME_TRADING_ADDRESS' "$repo_dir/docs/terms.md")" 2
	check 'the tracked privacy still carries the placeholder' \
		"$(grep -c -F 'REPLACE_ME_TRADING_ADDRESS' "$repo_dir/docs/privacy.md")" 1

	# No address: fail, and do not leave a partial output directory behind.
	if ( POSTAL_ADDRESS=; render_all "$repo_dir/docs" "$work/no-address" ) >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'no address is refused' "$got" no
	check 'no address writes nothing' \
		"$(find "$work/no-address" -type f 2>/dev/null | wc -l | tr -d ' ')" 0

	# The address itself a placeholder: the same failure, because a placeholder is
	# not a value.
	if ( POSTAL_ADDRESS='REPLACE_ME'; render_all "$repo_dir/docs" "$work/still" ) >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'a placeholder address is refused' "$got" no

	# A missing value for another placeholder the page carries is refused, so the
	# page cannot be published with REPLACE_ME_ICO_REFERENCE on it.
	if ( ICO_REFERENCE=''; render_all "$repo_dir/docs" "$work/no-ico" ) >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'a missing ICO reference is refused' "$got" no

	self_test_end
}

out=''
env_override=''
env_file="${KYRIAKON_ENV:-/root/.kyriakon-env}"
while [ "$#" -gt 0 ]; do
	case "$1" in
	--out)
		[ "$#" -ge 2 ] || usage
		out=$2
		shift 2
		;;
	--env)
		[ "$#" -ge 2 ] || usage
		env_override=$2
		shift 2
		;;
	--self-test)
		self_test
		;;
	*)
		usage
		;;
	esac
done

[ -n "$out" ] || usage

if [ -n "$env_override" ]; then
	[ -r "$env_override" ] || die "cannot read $env_override"
	env_file=$env_override
fi
if [ -r "$env_file" ]; then
	# shellcheck disable=SC1090 # the operator's own file, whose path resolves at runtime
	. "$env_file"
fi

render_all "$repo_dir/docs" "$out"
