#!/bin/ksh
# self-test-all.sh — every script's --self-test, with the arguments each needs.
#
# The arguments are the trap: two of these read a shipped file from the checkout,
# and one wrong path reads as a broken self-test rather than as a wrong argument.
# The list is read from the scripts themselves, so a new --self-test is picked up
# without editing this file.
#
# Usage:
#   ksh self-test-all.sh            # the checkout this script is in
#   ksh self-test-all.sh <repo>     # another checkout, or a box's own
#
# One line per script, the failures' own output under each, and the exit status
# is 1 if any failed. That shape is what makes it safe in cron: a passing run
# prints nothing that reads as a failure, and a failing one carries the reason.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo="${1:-$(cd "$here/.." && pwd)}"
failed=0
ran=0

# A script is a self-test if it defines self_test(), not if it mentions the
# flag: every comment that says "--self-test" would otherwise match, including
# this one, which is how the first version of this file ran itself.
for file in "$here"/*.sh; do
	[ "$(basename "$file")" = self-test-all.sh ] && continue
	grep -q '^self_test()' "$file" || continue
	ran=$((ran + 1))
	name=$(basename "$file")
	case "$name" in
	deploy-mail.sh) args="$repo" ;;
	deploy-relayd.sh) args="$repo/openbsd/etc" ;;
	*) args='' ;;
	esac
	# A hanging self-test would hold the weekly run open forever on the box, where
	# timeout(1) exists; here it is absent and the check is skipped.
	limit=''
	if command -v timeout >/dev/null 2>&1; then
		limit='timeout 300'
	fi
	# shellcheck disable=SC2086 # args is a repo path or empty, and limit is a word or empty
	if out=$($limit ksh "$file" --self-test $args 2>&1); then
		printf 'ok   %s\n' "$name"
	else
		printf 'FAIL %s\n' "$name"
		printf '%s\n' "$out" | sed -e 's/^/     /'
		failed=$((failed + 1))
	fi
done

if [ "$ran" -eq 0 ]; then
	printf 'self-test-all: no script in %s answers --self-test\n' "$here" >&2
	exit 1
fi
if [ "$failed" -ne 0 ]; then
	printf '\nself-test-all: %s of %s failed\n' "$failed" "$ran" >&2
	exit 1
fi
printf '\nself-test-all: %s passed\n' "$ran"
