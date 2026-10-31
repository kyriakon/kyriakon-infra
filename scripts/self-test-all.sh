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

# A self-test is offline by design, and lib.sh sources /root/.kyriakon-env when it
# can read it. Under cron that file exists, so a test would pick up the operator's
# address and mail the fixtures it was given instead of printing them. Both the
# drift check's children and every other test get a path that does not exist.
export KYRIAKON_ENV=/dev/null

# Scripts that cannot answer --self-test. A library has no run to make, and the
# rest need a live box, root or a service this checkout does not have. A script
# not named here without a self_test() fails the run, so a new script either
# carries its test or its exemption is a deliberate edit.
self_test_optional="
lib.sh
add-user.sh
backup.sh
deploy-nsd.sh
gen-finger-page.sh
onboard-store.sh
provision-member.sh
rehearsal.sh
rekey-mail-key.sh
renew-acme.sh
restore-standup.sh
restore-test.sh
setup-env.sh
"

# SELF_TEST_ALL_DIR lets the self-test below run this loop over a fixture rather
# than over the checkout.
here=${SELF_TEST_ALL_DIR:-$(cd "$(dirname "$0")" && pwd)}
repo="${1:-$(cd "$here/.." && pwd)}"
# The box runs pdksh, and a self-test that passes under another ksh proves
# nothing about it. CI sets this to oksh, the portable OpenBSD shell; a
# developer's macOS /bin/ksh is ksh93.
ksh_bin=${SELF_TEST_KSH:-ksh}
failed=0
ran=0

# The discovery and its refusal are the one branch worth testing here: a script
# with no self-test must be named and failed, not skipped silently.
self_test() {
	work=$(mktemp -d "${TMPDIR:-/tmp}/self-test-all.XXXXXX") || exit 1
	trap 'rm -rf "$work"' EXIT
	printf '#!/bin/ksh\nself_test() { :; }\n' > "$work/good.sh"
	if ! SELF_TEST_ALL_DIR="$work" "$ksh_bin" "$0" >/dev/null 2>&1; then
		printf 'self-test: a script with a self_test() should pass\n' >&2
		exit 1
	fi
	printf '#!/bin/ksh\n: no self-test here\n' > "$work/missing.sh"
	if SELF_TEST_ALL_DIR="$work" "$ksh_bin" "$0" >/dev/null 2>&1; then
		printf 'self-test: a script with no self_test() should fail\n' >&2
		exit 1
	fi
	printf 'self-test: ok\n'
}

if [ "${1:-}" = --self-test ]; then
	self_test
	exit 0
fi

# A script is a self-test if it defines self_test(), not if it mentions the
# flag: every comment that says "--self-test" would otherwise match, including
# this one, which is how the first version of this file ran itself.
for file in "$here"/*.sh; do
	name=$(basename "$file")
	if ! grep -q '^self_test()' "$file"; then
		if printf '%s\n' "$self_test_optional" | grep -qx -- "$name"; then
			continue
		fi
		printf 'FAIL %s\n' "$name"
		printf '     no self_test(); add one, or list it in self_test_optional\n'
		failed=$((failed + 1))
		continue
	fi
	case "$name" in
	deploy-mail.sh) args="$repo" ;;
	deploy-onboard.sh) args="$repo" ;;
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
	if out=$($limit "$ksh_bin" "$file" --self-test $args 2>&1); then
		printf 'ok   %s\n' "$name"
		ran=$((ran + 1))
	else
		printf 'FAIL %s\n' "$name"
		printf '%s\n' "$out" | sed -e 's/^/     /'
		failed=$((failed + 1))
	fi
done

if [ "$ran" -eq 0 ] && [ "$failed" -eq 0 ]; then
	printf 'self-test-all: no script in %s answers --self-test\n' "$here" >&2
	exit 1
fi
if [ "$failed" -ne 0 ]; then
	printf '\nself-test-all: %s failed, %s passed\n' "$failed" "$ran" >&2
	exit 1
fi
printf '\nself-test-all: %s passed\n' "$ran"
