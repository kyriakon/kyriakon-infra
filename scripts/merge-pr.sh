#!/bin/ksh
# merge-pr.sh <pr> — squash-merge only when every check is SUCCESS.
#
# `gh pr merge --admin` bypasses review, not the bar, but it will happily merge
# while a check is queued or cancelled. That is how a split that broke the
# deploy self-test reached main. A queued, running, cancelled or skipped check
# is not proof; this refuses it and says which ones are not green.
#
# Usage:
#   ksh scripts/merge-pr.sh <pr>
#   ksh scripts/merge-pr.sh --self-test

set -euo pipefail

self_test() {
	work=$(mktemp -d "${TMPDIR:-/tmp}/merge-pr.XXXXXX") || exit 1
	trap 'rm -rf "$work"' EXIT
	mkdir "$work/bin"
	cat > "$work/bin/gh" <<'STUB'
#!/bin/sh
case "$1 $2" in
"pr checks") cat "$GH_CHECKS" ;;
"pr merge") printf '%s\n' "$*" > "$GH_MERGED" ;;
*) exit 1 ;;
esac
STUB
	chmod +x "$work/bin/gh"
	GH="$work/bin/gh"
	GH_CHECKS="$work/checks"
	GH_MERGED="$work/merged"
	export GH GH_CHECKS GH_MERGED

	printf 'SUCCESS onboard crate\nSUCCESS shell scripts\n' > "$GH_CHECKS"
	"$0" 42 >/dev/null
	[ -f "$GH_MERGED" ] || {
		printf 'self-test: a green PR was not merged\n' >&2
		exit 1
	}

	rm -f "$GH_MERGED"
	printf 'IN_PROGRESS onboard crate\nSUCCESS shell scripts\n' > "$GH_CHECKS"
	if "$0" 42 >/dev/null 2>&1; then
		printf 'self-test: a running check was accepted\n' >&2
		exit 1
	fi
	[ ! -f "$GH_MERGED" ] || {
		printf 'self-test: a PR with a running check was merged\n' >&2
		exit 1
	}

	printf 'CANCELLED script self-tests\n' > "$GH_CHECKS"
	if "$0" 42 >/dev/null 2>&1; then
		printf 'self-test: a cancelled check was accepted\n' >&2
		exit 1
	fi

	printf 'self-test: ok\n'
}

if [ "${1:-}" = --self-test ]; then
	self_test
	exit 0
fi

pr=${1:-}
if [ -z "$pr" ]; then
	printf 'usage: ksh %s <pr-or---self-test>\n' "$0" >&2
	exit 2
fi

GH=${GH:-gh}
checks=$("$GH" pr checks "$pr" --json name,state --jq '.[] | "\(.state) \(.name)"')
if [ -z "$checks" ]; then
	printf 'merge-pr: #%s reports no checks; refusing to merge\n' "$pr" >&2
	exit 1
fi

not_green=$(printf '%s\n' "$checks" | awk '$1 != "SUCCESS"')
if [ -n "$not_green" ]; then
	printf 'merge-pr: #%s is not green:\n%s\n' "$pr" "$not_green" >&2
	exit 1
fi

"$GH" pr merge "$pr" --squash --admin
