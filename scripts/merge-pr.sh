#!/bin/ksh
# merge-pr.sh <pr> — squash-merge only when every check is SUCCESS.
#
# `gh pr merge --admin` bypasses review, not the bar, but it will happily merge
# while a check is queued or cancelled. That is how a split that broke the
# deploy self-test reached main. A queued, running, cancelled or skipped check
# is not proof; this refuses it and says which ones are not green.
#
# The checks belong to the head at the time they ran. A push while they run
# would let an unchecked commit merge, so the head is captured first, re-read
# just before merging, and pinned with --match-head-commit (which gh enforces
# server-side, closing the gap between the re-read and the merge).
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
"pr view")
	if [ -n "${GH_HEAD_AFTER:-}" ] && [ -f "$GH_VIEWED" ]; then
		printf '%s\n' "$GH_HEAD_AFTER"
	else
		: > "$GH_VIEWED"
		printf '%s\n' "$GH_HEAD"
	fi
	;;
"pr checks") cat "$GH_CHECKS" ;;
"pr merge") printf '%s\n' "$*" > "$GH_MERGED" ;;
*) exit 1 ;;
esac
STUB
	chmod +x "$work/bin/gh"
	GH="$work/bin/gh"
	GH_CHECKS="$work/checks"
	GH_MERGED="$work/merged"
	GH_VIEWED="$work/viewed"
	GH_HEAD=1111111111111111111111111111111111111111
	export GH GH_CHECKS GH_MERGED GH_VIEWED GH_HEAD

	printf 'SUCCESS onboard crate\nSUCCESS shell scripts\n' > "$GH_CHECKS"
	"$0" 42 >/dev/null
	[ -f "$GH_MERGED" ] || {
		printf 'self-test: a green PR was not merged\n' >&2
		exit 1
	}
	grep -q -- "--match-head-commit $GH_HEAD" "$GH_MERGED" || {
		printf 'self-test: the merge was not pinned to the reviewed head\n' >&2
		exit 1
	}

	rm -f "$GH_MERGED" "$GH_VIEWED"
	export GH_HEAD_AFTER=2222222222222222222222222222222222222222
	if "$0" 42 >/dev/null 2>&1; then
		printf 'self-test: a moved head was accepted\n' >&2
		exit 1
	fi
	[ ! -f "$GH_MERGED" ] || {
		printf 'self-test: a moved head was merged\n' >&2
		exit 1
	}
	unset GH_HEAD_AFTER

	rm -f "$GH_MERGED" "$GH_VIEWED"
	GH_HEAD=
	if "$0" 42 >/dev/null 2>&1; then
		printf 'self-test: an empty head was accepted\n' >&2
		exit 1
	fi
	[ ! -f "$GH_MERGED" ] || {
		printf 'self-test: a PR with no head commit was merged\n' >&2
		exit 1
	}
	GH_HEAD=1111111111111111111111111111111111111111

	rm -f "$GH_MERGED" "$GH_VIEWED"
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

pr_head() {
	"$GH" pr view "$pr" --json headRefOid --jq .headRefOid
}

head=$(pr_head)
if [ -z "$head" ]; then
	printf 'merge-pr: #%s reports no head commit; refusing to merge\n' "$pr" >&2
	exit 1
fi

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

head_now=$(pr_head)
if [ "$head_now" != "$head" ]; then
	printf 'merge-pr: #%s head moved from %s to %s while checks ran; refusing to merge\n' \
		"$pr" "$head" "$head_now" >&2
	exit 1
fi

"$GH" pr merge "$pr" --squash --admin --match-head-commit "$head"
