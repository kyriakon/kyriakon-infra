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
# The trading address is POSTAL_ADDRESS, the same value scripts/deploy-onboard.sh
# writes into the drain's postal_address for the cash-by-post rail: the operator
# decided the published trading address and the collection address are one value
# (#397), so there is one variable and the two cannot disagree. The ICO
# reference and the Union representative are separate decisions; set them with
# scripts/setup-env.sh --ico-reference and --eu-representative, and the script
# reads them from the same file. It refuses rather than publish a placeholder.
#
# The key walkthrough is the fourth source, docs/key-walkthrough.md. It is not a
# governance document, so the site build's --out does not receive it; the gemtext
# mode does, because the capsule has to serve the walkthrough as a page rather
# than link a browser page a gemini client cannot open.
#
# Usage:
#   ksh scripts/render-docs.sh --out DIR [--env FILE]
#   ksh scripts/render-docs.sh --gemini DIR [--env FILE]
#        ksh scripts/render-docs.sh --self-test
#
# --out receives terms.md, privacy.md and aup.md. It is the site build's input,
# not HTML: presentation belongs to the site build, which is kyriakon-site #3.
#
# --gemini receives terms.gmi, privacy.gmi, aup.gmi and key-walkthrough.gmi, the
# four pages the capsule mirrors. The converter handles what these documents
# use, and refuses the constructs it does not, so a sentence added with a table
# image or a fenced block fails the deploy rather than reaching a reader as
# half-converted text.
#
# Refuses, and writes nothing, when a value the documents need is absent or still
# a placeholder, or when any REPLACE_ME remains in an output. A placeholder must
# not reach the public web.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_dir=$(cd "$script_dir/.." && pwd)

usage() {
	printf 'usage: ksh %s --out DIR [--env FILE]\n       ksh %s --gemini DIR [--env FILE]\n       ksh %s --self-test\n' \
		"$0" "$0" "$0" >&2
	exit 2
}

die() {
	printf '%s: %s\n' "$0" "$*" >&2
	exit 1
}

# render_one <src> <dst> — substitute the four placeholders, then refuse any that
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
	remaining=$(grep -o 'REPLACE_ME[A-Z_0-9]*' "$dst" | sort -u || true)
	[ -z "$remaining" ] || die "$dst still carries a placeholder:$remaining"
}

# require_values <terms> <privacy> — the values the pages name, required only when
# they name them, so a page without a placeholder does not demand a value it
# never uses. Shared by the web and gemtext modes so the two cannot publish the
# same document under different refusal rules.
require_values() {
	terms=$1
	privacy=$2
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
			die "ICO_REFERENCE is not set in $env_file; the privacy notice names the ICO registration, a separate decision. Set it with: scripts/setup-env.sh --ico-reference '...'"
			;;
		esac
	fi

	if grep -q REPLACE_ME_REPRESENTATIVE "$terms" "$privacy"; then
		case "${EU_REPRESENTATIVE:-}" in
		'' | *REPLACE_ME*)
			die "EU_REPRESENTATIVE is not set in $env_file; set it with: scripts/setup-env.sh --eu-representative '...', or remove the Union representative paragraph if the service is not offered there"
			;;
		esac
		case "${EU_REPRESENTATIVE_CONTACT:-}" in
		'' | *REPLACE_ME*)
			die "EU_REPRESENTATIVE_CONTACT is not set in $env_file; set the representative's contact route with: scripts/setup-env.sh --eu-representative-contact '...'"
			;;
		esac
	fi
}

# render_all <docs dir> <out dir> — the live path and the self-test's entry point.
render_all() {
	docs=$1
	out=$2
	terms="$docs/terms.md"
	privacy="$docs/privacy.md"
	aup="$docs/aup.md"
	for f in "$terms" "$privacy" "$aup"; do
		[ -r "$f" ] || die "cannot read $f"
	done

	require_values "$terms" "$privacy"

	mkdir -p "$out" || die "cannot create $out"
	# A mistaken --out pointing at the source would put the operator's address into
	# the tracked files. -P resolves a symlinked --out, or the guard would miss a
	# link to docs and the render would truncate the source. The directory itself
	# is fine to create; the pages are not written until the check has passed.
	out_abs=$(cd -P "$out" && pwd)
	docs_abs=$(cd -P "$docs" && pwd)
	[ "$out_abs" != "$docs_abs" ] \
		|| die "refusing to write into the tracked source directory $docs; name the site build's output directory"

	# Stage every page before installing any of them: a page that fails its
	# placeholder check must not replace the good copy already in --out. The
	# subshell owns the stage's EXIT trap, so it does not replace the self-test's
	# own trap. mv is atomic within the directory, which is why the stage sits
	# inside --out.
	(
		stage=$(mktemp -d "$out/.render.XXXXXX") || exit 1
		trap 'rm -rf "$stage"' EXIT
		render_one "$terms" "$stage/terms.md"
		render_one "$privacy" "$stage/privacy.md"
		render_one "$aup" "$stage/aup.md"
		chmod 0644 "$stage/terms.md" "$stage/privacy.md" "$stage/aup.md" || exit 1
		mv "$stage/terms.md" "$out/terms.md" || exit 1
		mv "$stage/privacy.md" "$out/privacy.md" || exit 1
		mv "$stage/aup.md" "$out/aup.md" || exit 1
	) || exit 1
	printf 'rendered terms.md, privacy.md and aup.md to %s\n' "$out"
}

# gemini_one <src.md> <dst.gmi> — the conservative markdown to gemtext converter.
#
# It handles the constructs these documents use: headings of one to three
# levels, paragraphs, unordered lists, ordered lists as plain text, block quotes,
# pipe tables and inline code or emphasis. Everything else is refused, because
# half-converted markdown reaches a reader as literal asterisks, and a page that
# fails stops the deploy instead.
gemini_one() {
	src=$1
	dst=$2
	awk '
		function refuse(why) {
			printf "%s:%d: %s\n", FILENAME, FNR, why > "/dev/stderr"
			exit 1
		}
		function inline(s) {
			gsub(/`/, "", s)
			gsub(/\*\*/, "", s)
			gsub(/\*/, "", s)
			return s
		}
		{
			if ($0 ~ /\]\(/ || $0 ~ /!\[/) refuse("a markdown link or image")
			if ($0 ~ /^[ \t]*(```|~~~)/) refuse("a fenced code block")
			if ($0 ~ /^ {4,}/ || $0 ~ /^\t/) refuse("an indented block")
			if ($0 ~ /^[ \t]+[-*+][ \t]+/) refuse("a nested list")
			if ($0 ~ /^[ \t]+[0-9]+[.)][ \t]+/) refuse("a nested ordered list")
			if ($0 ~ /^[ \t]*\[[^]]+\]:/) refuse("a link definition")
			if ($0 ~ /^[ \t]*([-*_][ \t]*){3,}$/) refuse("a horizontal rule")
			if ($0 ~ /^[ \t]*=+[ \t]*$/) refuse("a setext heading")
			if ($0 ~ /^[ \t]*[-*+] \[[ xX]\]/) refuse("a task list")
			if ($0 ~ /^[ \t]*<[a-zA-Z\/!]/) refuse("raw html")
		}
		/^[ \t]*$/ { print ""; next }
		/^#+[ \t]/ {
			line = $0
			match(line, /^#+/)
			level = RLENGTH
			rest = substr(line, RLENGTH + 1)
			sub(/^[ \t]+/, "", rest)
			sub(/[ \t]+#+[ \t]*$/, "", rest)
			if (level > 3) level = 3
			print substr("###", 1, level) " " inline(rest)
			next
		}
		/^[ \t]*\|/ {
			line = $0
			sub(/^[ \t]*\|/, "", line)
			sub(/[ \t]*\|[ \t]*$/, "", line)
			n = split(line, cells, "[|]")
			separator = 1
			for (i = 1; i <= n; i++) {
				c = cells[i]
				gsub(/^[ \t]+|[ \t]+$/, "", c)
				if (c !~ /^:?-+:?$/) separator = 0
			}
			if (separator) next
			out = ""
			for (i = 1; i <= n; i++) {
				c = cells[i]
				gsub(/^[ \t]+|[ \t]+$/, "", c)
				if (i > 1) out = out " | "
				out = out inline(c)
			}
			print out
			next
		}
		/^>[ \t]?/ {
			line = $0
			sub(/^>[ \t]?/, "", line)
			line = inline(line)
			sub(/[ \t]+$/, "", line)
			if (line == "") print ">"
			else print "> " line
			next
		}
		/^[-*+][ \t]+/ {
			line = $0
			sub(/^[-*+][ \t]+/, "", line)
			print "* " inline(line)
			next
		}
		/^[0-9]+[.)][ \t]+/ {
			print inline($0)
			next
		}
		{ print inline($0) }
	' "$src" > "$dst" || die "cannot convert $src to gemtext: a construct it does not handle"
}

# gemini_all <docs dir> <out dir> — the capsule's four mirrored pages. It uses
# the same substitution and the same refusals as the web mode, then converts,
# so the two published forms cannot disagree about a value or a placeholder.
gemini_all() {
	docs=$1
	out=$2
	terms="$docs/terms.md"
	privacy="$docs/privacy.md"
	aup="$docs/aup.md"
	walkthrough="$docs/key-walkthrough.md"
	for f in "$terms" "$privacy" "$aup" "$walkthrough"; do
		[ -r "$f" ] || die "cannot read $f"
	done

	require_values "$terms" "$privacy"

	mkdir -p "$out" || die "cannot create $out"
	out_abs=$(cd -P "$out" && pwd)
	docs_abs=$(cd -P "$docs" && pwd)
	[ "$out_abs" != "$docs_abs" ] \
		|| die "refusing to write into the tracked source directory $docs; name the capsule's page directory"

	(
		stage=$(mktemp -d "$out/.render.XXXXXX") || exit 1
		trap 'rm -rf "$stage"' EXIT
		for pair in "terms.md:$terms" "privacy.md:$privacy" "aup.md:$aup" \
			"key-walkthrough.md:$walkthrough"; do
			name=${pair%%:*}
			src=${pair#*:}
			render_one "$src" "$stage/$name" || exit 1
		done
		gemini_one "$stage/terms.md" "$stage/terms.gmi" || exit 1
		gemini_one "$stage/privacy.md" "$stage/privacy.gmi" || exit 1
		gemini_one "$stage/aup.md" "$stage/aup.gmi" || exit 1
		gemini_one "$stage/key-walkthrough.md" "$stage/key-walkthrough.gmi" || exit 1
		chmod 0644 "$stage/terms.gmi" "$stage/privacy.gmi" "$stage/aup.gmi" \
			"$stage/key-walkthrough.gmi" || exit 1
		mv "$stage/terms.gmi" "$out/terms.gmi" || exit 1
		mv "$stage/privacy.gmi" "$out/privacy.gmi" || exit 1
		mv "$stage/aup.gmi" "$out/aup.gmi" || exit 1
		mv "$stage/key-walkthrough.gmi" "$out/key-walkthrough.gmi" || exit 1
	) || exit 1
	printf 'rendered terms.gmi, privacy.gmi, aup.gmi and key-walkthrough.gmi to %s\n' "$out"
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
	# The failure cases below shadow these values in a subshell. Keep the passing
	# set under names they do not touch, so the CLI test can still use it.
	cli_address=$POSTAL_ADDRESS
	cli_ico=$ICO_REFERENCE
	cli_rep=$EU_REPRESENTATIVE
	cli_rep_contact=$EU_REPRESENTATIVE_CONTACT

	render_all "$repo_dir/docs" "$work/out" >/dev/null

	check 'the terms page carries the address' \
		"$(grep -q -F "$POSTAL_ADDRESS" "$work/out/terms.md" && printf yes)" yes
	check 'the privacy page carries the address' \
		"$(grep -q -F "$POSTAL_ADDRESS" "$work/out/privacy.md" && printf yes)" yes
	check 'no placeholder survives in the terms page' \
		"$(if grep -q 'REPLACE_ME' "$work/out/terms.md"; then printf yes; else printf no; fi)" no
	check 'no placeholder survives in the privacy page' \
		"$(if grep -q 'REPLACE_ME' "$work/out/privacy.md"; then printf yes; else printf no; fi)" no
	check 'the ICO reference is substituted' \
		"$(grep -q -F "$ICO_REFERENCE" "$work/out/privacy.md" && printf yes)" yes
	check 'the representative and its contact are substituted' \
		"$(grep -q -F "$EU_REPRESENTATIVE_CONTACT" "$work/out/privacy.md" && printf yes)" yes
	check 'the aup is copied unchanged' \
		"$(cmp -s "$repo_dir/docs/aup.md" "$work/out/aup.md" && printf yes)" yes
	check 'the tracked terms still carry the placeholder' \
		"$(grep -q -F 'REPLACE_ME_TRADING_ADDRESS' "$repo_dir/docs/terms.md" && printf yes)" yes
	check 'the tracked privacy still carry the placeholder' \
		"$(grep -q -F 'REPLACE_ME_TRADING_ADDRESS' "$repo_dir/docs/privacy.md" && printf yes)" yes

	# The capsule's four gemtext pages, from the same sources and values.
	gemini_all "$repo_dir/docs" "$work/gemini" >/dev/null

	for page in terms.gmi privacy.gmi aup.gmi key-walkthrough.gmi; do
		check "the gemtext mode writes $page" \
			"$(test -s "$work/gemini/$page" && printf yes || printf no)" yes
	done
	check 'the gemtext terms page keeps its first heading' \
		"$(grep -q -F '# Terms of service' "$work/gemini/terms.gmi" && printf yes)" yes
	check 'the gemtext terms page keeps its second heading' \
		"$(grep -q -F '## Who you are dealing with' "$work/gemini/terms.gmi" && printf yes)" yes
	check 'a table becomes text rows' \
		"$(grep -q -F 'Individual | £20 a year |' "$work/gemini/terms.gmi" && printf yes)" yes
	check 'an unordered list becomes a gemtext list' \
		"$(grep -q -F '* your express request' "$work/gemini/terms.gmi" && printf yes)" yes
	check 'an ordered list stays readable text' \
		"$(grep -q -F '1. Detect.' "$work/gemini/aup.gmi" && printf yes)" yes
	check 'a block quote becomes a gemtext quote' \
		"$(grep -q -F '> To Oliver Brotchie' "$work/gemini/terms.gmi" && printf yes)" yes
	check 'inline emphasis and code are stripped' \
		"$(if grep -q -e '\*\*' -e '`' "$work/gemini/terms.gmi" "$work/gemini/aup.gmi"; then printf yes; else printf no; fi)" no
	check 'no placeholder survives in the gemtext pages' \
		"$(if grep -q 'REPLACE_ME' "$work/gemini/terms.gmi" "$work/gemini/privacy.gmi"; then printf yes; else printf no; fi)" no
	check 'the walkthrough names Thunderbird on a desktop' \
		"$(grep -q -F 'Thunderbird on a desktop' "$work/gemini/key-walkthrough.gmi" && printf yes)" yes
	check 'the walkthrough names sftp on 22' \
		"$(grep -q -F 'sftp on port 22' "$work/gemini/key-walkthrough.gmi" && printf yes)" yes
	check 'the walkthrough names git on 2222' \
		"$(grep -q -F 'git on port 2222' "$work/gemini/key-walkthrough.gmi" && printf yes)" yes
	check 'no mirrored page claims encryption at rest or end-to-end' \
		"$(if grep -E -qi 'encrypted at rest|end-to-end' "$work/gemini"/*.gmi; then printf yes; else printf no; fi)" no
	check 'the terms page states the zero-access metadata limit' \
		"$(grep -q -F 'addressing information' "$work/gemini/terms.gmi" && printf yes)" yes
	check 'the privacy page states the zero-access metadata limit' \
		"$(grep -E -q 'metadata|addressing information' "$work/gemini/privacy.gmi" && printf yes)" yes
	check 'the acceptable use policy states the zero-access metadata limit' \
		"$(grep -q -F 'addressing information' "$work/gemini/aup.gmi" && printf yes)" yes

	# A construct the converter does not handle stops the render rather than
	# reaching a reader as literal markdown.
	mkdir -p "$work/bad-docs"
	cp "$repo_dir/docs/terms.md" "$repo_dir/docs/privacy.md" "$repo_dir/docs/aup.md" \
		"$repo_dir/docs/key-walkthrough.md" "$work/bad-docs/"
	printf '\n![a diagram](https://example.invalid/diagram.png)\n' >>"$work/bad-docs/terms.md"
	if ( gemini_all "$work/bad-docs" "$work/bad-out" ) >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'an unsupported markdown construct is refused' "$got" no
	check 'a refused conversion writes no page' \
		"$(find "$work/bad-out" -type f 2>/dev/null | wc -l | tr -d ' ')" 0

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

	# A mistaken --out at the source would put the address into the tracked files.
	# The test uses a copy, so a broken refusal cannot rewrite the repository.
	mkdir -p "$work/source"
	cp "$repo_dir/docs/terms.md" "$repo_dir/docs/privacy.md" "$repo_dir/docs/aup.md" "$work/source/"
	if ( render_all "$work/source" "$work/source" ) >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'writing into the source directory is refused' "$got" no
	check 'the source copy is unchanged' \
		"$(grep -q -F 'REPLACE_ME_TRADING_ADDRESS' "$work/source/terms.md" && printf yes)" yes

	# A symlink to the source directory is the same mistake in another spelling.
	# The guard must resolve it, or the render truncates the tracked files before
	# the check can see them.
	ln -s "$work/source" "$work/source-link"
	if ( render_all "$work/source" "$work/source-link" ) >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'writing through a symlink to the source is refused' "$got" no
	check 'the symlinked source copy is unchanged' \
		"$(grep -q -F 'REPLACE_ME_TRADING_ADDRESS' "$work/source/terms.md" && printf yes)" yes

	# A page that fails its placeholder check must not replace the good page
	# already in --out.
	mkdir -p "$work/fail-source" "$work/fail-out"
	cp "$repo_dir/docs/terms.md" "$repo_dir/docs/privacy.md" "$repo_dir/docs/aup.md" "$work/fail-source/"
	printf '\nREPLACE_ME_VAT_NUMBER\n' >> "$work/fail-source/privacy.md"
	printf 'previous page\n' > "$work/fail-out/terms.md"
	if ( render_all "$work/fail-source" "$work/fail-out" ) >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'a failed render is refused' "$got" no
	check 'a failed render leaves the previous page' "$(cat "$work/fail-out/terms.md")" 'previous page'
	check 'a failed render leaves no privacy page' \
		"$(test -e "$work/fail-out/privacy.md" && printf yes || printf no)" no
	check 'a failed render leaves no staging directory' \
		"$(find "$work/fail-out" -maxdepth 1 -name '.render.*' | wc -l | tr -d ' ')" 0

	# The bare form is a placeholder too, not only the suffixed one.
	mkdir -p "$work/bare-source" "$work/bare-out"
	cp "$repo_dir/docs/terms.md" "$repo_dir/docs/privacy.md" "$repo_dir/docs/aup.md" "$work/bare-source/"
	printf '\nsee REPLACE_ME.\n' >> "$work/bare-source/privacy.md"
	if ( render_all "$work/bare-source" "$work/bare-out" ) >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'a bare placeholder is refused' "$got" no

	# The CLI's argument handling is a separate path from render_all.
	cat >"$work/cli-env" <<EOF
export POSTAL_ADDRESS='$cli_address'
export ICO_REFERENCE='$cli_ico'
export EU_REPRESENTATIVE='$cli_rep'
export EU_REPRESENTATIVE_CONTACT='$cli_rep_contact'
EOF
	if ksh "$0" --out "$work/cli" --env "$work/cli-env" >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'the CLI renders with --env' "$got" yes
	check 'the CLI wrote the terms page' \
		"$(grep -q -F "$cli_address" "$work/cli/terms.md" && printf yes)" yes
	if ksh "$0" --gemini "$work/cli-gemini" --env "$work/cli-env" >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'the CLI renders gemtext with --gemini' "$got" yes
	check 'the gemtext CLI wrote the walkthrough page' \
		"$(test -s "$work/cli-gemini/key-walkthrough.gmi" && printf yes || printf no)" yes
	if ksh "$0" >/dev/null 2>&1; then got=yes; else got=no; fi
	check 'a missing --out is refused' "$got" no
	if ksh "$0" --bogus >/dev/null 2>&1; then got=yes; else got=no; fi
	check 'an unknown argument is refused' "$got" no
	if ksh "$0" --out "$work/no-env" --env "$work/missing-env" >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'an unreadable --env is refused' "$got" no
	if KYRIAKON_ENV="$work/missing-default" ksh "$0" --out "$work/no-default" >/dev/null 2>&1; then
		got=yes
	else
		got=no
	fi
	check 'an unreadable default env file is refused' "$got" no

	self_test_end
}

out=''
gemini_out=''
env_override=''
env_file="${KYRIAKON_ENV:-/root/.kyriakon-env}"
while [ "$#" -gt 0 ]; do
	case "$1" in
	--out)
		[ "$#" -ge 2 ] || usage
		out=$2
		shift 2
		;;
	--gemini)
		[ "$#" -ge 2 ] || usage
		gemini_out=$2
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

[ -n "$out" ] || [ -n "$gemini_out" ] || usage
if [ -n "$out" ] && [ -n "$gemini_out" ]; then
	usage
fi

if [ -n "$env_override" ]; then
	[ -r "$env_override" ] || die "cannot read $env_override"
	env_file=$env_override
elif [ ! -r "$env_file" ]; then
	die "no $env_file; run scripts/setup-env.sh first, which installs it, or pass --env FILE"
fi
# shellcheck disable=SC1090 # the operator's own file, whose path resolves at runtime
. "$env_file"

if [ -n "$out" ]; then
	render_all "$repo_dir/docs" "$out"
else
	gemini_all "$repo_dir/docs" "$gemini_out"
fi
