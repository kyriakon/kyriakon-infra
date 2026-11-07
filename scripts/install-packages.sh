#!/bin/ksh
# install-packages.sh — install the packages the box runs, from openbsd/packages.tsv.
#
# Usage:
#   ksh scripts/install-packages.sh                 # every row, the box
#   ksh scripts/install-packages.sh --ci            # rows marked ci=yes
#   ksh scripts/install-packages.sh <owner>...      # rows assigned to an owner
#   ksh scripts/install-packages.sh --check         # direct need_pkg calls are listed
#   ksh scripts/install-packages.sh --self-test
#
# The table is the one list. The deploy scripts read it through need_packages in
# lib.sh, and the CI OpenBSD VM reads it here with --ci, so the VM installs the
# tools the scripts call rather than a hand-picked subset. --ci is not "the box
# has it": rust and dovecot stay out because the self-tests do not build or
# start them.
#
# --check reads every direct need_pkg call in the scripts and fails when one is
# not in the table. It is what keeps a new dependency from being installed only
# on the developer's machine.
#
# Run as root on the box; the CI VM's run step is root too.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_dir=$(cd "$script_dir/.." && pwd)
packages=${PACKAGES_FILE:-$repo_dir/openbsd/packages.tsv}
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

die() { printf '%s: %s\n' "$0" "$*" >&2; exit 1; }

# select_packages <all|ci|owner> [owner...]: print the unique package names.
select_packages() {
	typeset mode=$1
	shift
	[ -f "$packages" ] || die "no package table at $packages"
	awk -F'\t' -v mode="$mode" -v owners="$*" '
		/^[[:space:]]*#/ || NF < 3 { next }
		{
			keep = (mode == "all")
			if (mode == "ci") keep = ($3 == "yes")
			if (mode == "owner") {
				n = split(owners, want, " ")
				for (i = 1; i <= n; i++)
					if (index("," $2 ",", "," want[i] ",") > 0) { keep = 1; break }
			}
			if (keep) print $1
		}' "$packages" | sort -u
}

install_selected() {
	typeset selected pkg
	selected=$(select_packages "$@")
	[ -n "$selected" ] || die "no packages selected from $packages"
	for pkg in $selected; do
		need_pkg "$pkg"
	done
}

# check_calls: every direct need_pkg call is a row in the table. Lines that
# start with a hash are comments, and the self-test fixtures are named in the
# filter: they are not real packages.
check_calls() {
	typeset dir=${CHECK_SCRIPTS_DIR:-$script_dir} listed calls missing calls_file listed_file
	[ -f "$packages" ] || die "no package table at $packages"
	listed=$(awk -F'\t' '/^[[:space:]]*#/ || NF < 3 { next } { print $1 }' "$packages" | sort -u)
	calls=$(awk -v q="'" '
		/^[[:space:]]*#/ { next }
		{
			line = $0
			gsub(q "[^" q "]*" q, "", line)
			gsub(/"[^"]*"/, "", line)
			while (match(line, /(^|[^[:alnum:]_.-])need_pkg[[:space:]]+[A-Za-z0-9][A-Za-z0-9._-]*/)) {
				s = substr(line, RSTART, RLENGTH)
				sub(/^.*need_pkg[[:space:]]+/, "", s)
				print s
				line = substr(line, RSTART + RLENGTH)
			}
		}' "$dir"/*.sh 2>/dev/null | grep -v -E '^(present|absent)\.sh$|^versioned$' | sort -u)
	[ -n "$calls" ] || return 0
	calls_file=$(mktemp "${TMPDIR:-/tmp}/need-pkg-calls.XXXXXX") || return 1
	listed_file=$(mktemp "${TMPDIR:-/tmp}/listed-packages.XXXXXX") || {
		rm -f "$calls_file"
		return 1
	}
	printf '%s\n' "$calls" >"$calls_file"
	printf '%s\n' "$listed" >"$listed_file"
	missing=$(comm -23 "$calls_file" "$listed_file")
	rm -f "$calls_file" "$listed_file"
	if [ -n "$missing" ]; then
		printf 'packages missing from %s:\n%s\n' "$packages" "$missing" >&2
		return 1
	fi
	return 0
}

self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	work=$self_test_work
	mkdir -p "$work/bin" "$work/scripts"
	cat > "$work/bin/pkg_info" <<'STUB'
#!/bin/sh
for a in "$@"; do last=$a; done
case "$last" in
foo|foo-*) exit 0 ;;
esac
if [ -n "${PKG_INSTALLED:-}" ]; then
	grep -qx -- "$last" "$PKG_INSTALLED" 2>/dev/null && exit 0
	grep -qx -- "${last%-*}" "$PKG_INSTALLED" 2>/dev/null && exit 0
fi
exit 1
STUB
	cat > "$work/bin/pkg_add" <<'STUB'
#!/bin/sh
for a in "$@"; do pkg=$a; done
printf '%s\n' "$pkg" >> "$PKG_INSTALLED"
printf '%s\n' "$*" >> "$PKG_ADD_LOG"
STUB
	chmod 0700 "$work/bin/pkg_info" "$work/bin/pkg_add"
	: > "$work/add.log"
	: > "$work/installed"
	export PATH="$work/bin:$PATH" PKG_ADD_LOG="$work/add.log" PKG_INSTALLED="$work/installed"
	printf '# fixture\nfoo\tdeploy-a.sh\tyes\nbar\tdeploy-a.sh,deploy-b.sh\tno\nbaz\tbox\tyes\n' > "$work/packages.tsv"
	packages="$work/packages.tsv"

	install_selected ci >/dev/null
	check "the ci rows are installed" "$(tr '\n' ' ' < "$work/add.log")" "-I baz "
	: > "$work/add.log"
	install_selected owner deploy-b.sh >/dev/null
	check "an owner pulls its shared row" "$(tr '\n' ' ' < "$work/add.log")" "-I bar "
	: > "$work/add.log"
	install_selected ci >/dev/null
	check "an installed package is not reinstalled" "$(tr '\n' ' ' < "$work/add.log")" ""
	: > "$work/installed"
	: > "$work/add.log"
	need_packages "$work/packages.tsv" deploy-b.sh >/dev/null
	check "need_packages pulls the owner's rows" "$(tr '\n' ' ' < "$work/add.log")" "-I bar "

	printf 'need_pkg foo\n' > "$work/scripts/a.sh"
	printf 'if true; then need_pkg missing; fi\n' > "$work/scripts/b.sh"
	printf 'need_pkg fake.sh\n' > "$work/scripts/c.sh"
	if CHECK_SCRIPTS_DIR="$work/scripts" check_calls >"$work/check.out" 2>&1; then
		check "an unlisted direct need_pkg is a finding" "passed" "failed"
	else
		check "an unlisted direct need_pkg is a finding" "$(grep -c -E '^(missing|fake\.sh)$' "$work/check.out")" "2"
	fi
	self_test_end
}

case "${1:-}" in
--self-test) self_test ;;
--check)
	if check_calls; then exit 0; else exit 1; fi
	;;
esac

if [ "$#" -eq 0 ]; then
	install_selected all
elif [ "${1:-}" = "--ci" ]; then
	install_selected ci
else
	install_selected owner "$@"
fi
