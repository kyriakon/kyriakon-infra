#!/bin/ksh
# stripe-api.sh: read one Stripe object, and nothing else.
#
# The drain settles a card payment only after retrieving the subscription and
# seeing it is active, because a paid invoice does not prove one. This is the
# only Stripe call the service makes, and it is a read: the webhook path marks no
# invoice paid, creates no session and cancels nothing.
#
# Usage:
#   doas ksh scripts/stripe-api.sh subscription <subscription-id> <key-file>
#   ksh scripts/stripe-api.sh --self-test
#
#   <subscription-id>  the `sub_...` id an invoice or checkout named
#   <key-file>         the root-only restricted API key, mode 0600
#
# The JSON object is written to stdout and nothing else is. The key goes into a
# curl config file, never an argument, so it is not in the process table and not
# in any error message. The key needs only read access to subscriptions; the
# script refuses to run without a 0600 file, and as root without a root-owned
# one.
#
# Exit: 0 the object is on stdout; 1 the API could not be read, so the drain
#       leaves the event for the next pass; 2 the arguments or the credential
#       are unusable, which is a configuration to fix.

set -euo pipefail
umask 077

api_base="${STRIPE_API:-https://api.stripe.com}"

usage() {
	cat <<'EOF'
usage: stripe-api.sh subscription <subscription-id> <key-file>
       stripe-api.sh --self-test

  <subscription-id>  the sub_... id to retrieve
  <key-file>         the root-only restricted Stripe API key

The header of this script documents the mechanism and the exit codes.
EOF
}

# die <message>: the arguments or the credential are unusable, so retrying the
# event changes nothing.
die() {
	printf '%s: %s\n' "$0" "$1" >&2
	exit 2
}

# fail <message>: the API could not be read. The event stays in place for the
# next pass rather than the date being extended on trust.
fail() {
	printf '%s: %s\n' "$0" "$1" >&2
	exit 1
}

# subscription <id> <key-file>: GET /v1/subscriptions/<id> and print the object.
subscription() {
	id=$1
	key_file=$2

	# The id is a path segment, so its charset is checked before it is used as
	# one.
	case "$id" in
	sub_*)
		case "$id" in
		*[!A-Za-z0-9_]*) die "the subscription id $id is not an id" ;;
		esac
		;;
	*) die "the subscription id $id is not a sub_ id" ;;
	esac

	[ -f "$key_file" ] || die "no key file at $key_file"
	if [ "$(stat -f '%Lp' "$key_file")" != 600 ]; then
		die "$key_file is not mode 600, and a key another user can read is a key that can read payments"
	fi
	if [ "$(id -u)" -eq 0 ] && [ "$(stat -f '%Su' "$key_file")" != root ]; then
		die "$key_file is not owned by root"
	fi
	key=$(cat "$key_file") || die "cannot read $key_file"
	printf '%s' "$key" | grep -Eq '^[A-Za-z0-9_-]{20,255}$' ||
		die "$key_file does not hold one API key; a pasted newline, a trailing comment or a Bearer prefix would all go into the request"

	{
		printf 'header = "Authorization: Bearer %s"\n' "$key"
		printf 'silent\nshow-error\nmax-time = 30\n'
	} >"$curlrc"
	unset key

	code=$(curl -K "$curlrc" -o "$resp" -w '%{http_code}' \
		"$api_base/v1/subscriptions/$id") ||
		fail "curl could not reach $api_base"
	case "$code" in
	200)
		[ -s "$resp" ] || fail "$api_base answered an empty subscription"
		cat "$resp"
		;;
	401 | 403)
		die "the key cannot read subscriptions (HTTP $code); it needs read access to subscriptions only"
		;;
	404)
		fail "Stripe has no subscription $id"
		;;
	*)
		fail "$api_base answered HTTP $code for subscription $id"
		;;
	esac
}

# --- self-test: the decisions, against a stub API -----------------------------
#
# curl is replaced on PATH by a stub that answers from SELFTEST_MODE, so what is
# exercised is this script's own decisions. The stub logs its argv, because "the
# key is never an argument" and "only the subscription URL is called" are claims
# about what did not happen.
self_test() {
	fix=$(mktemp -d "${TMPDIR:-/tmp}/kyriakon-stripe-selftest.XXXXXX")
	mkdir -p "$fix/bin"
	export SELFTEST_LOG="$fix/stub.log"
	export SELFTEST_MODE="${SELFTEST_MODE:-active}"

	cat >"$fix/bin/curl" <<'EOF'
#!/bin/ksh
mode="${SELFTEST_MODE:-active}"
argv="$*"
out=/dev/null
url=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	-K) shift ;;
	-o)
		out=$2
		shift
		;;
	-w) shift ;;
	*) url=$1 ;;
	esac
	shift
done
if [ "$mode" = "unreachable" ]; then
	printf '%s\n' "GET $url [curl could not connect]" >>"$SELFTEST_LOG"
	exit 7
fi
printf '%s\n' "GET $url [$argv]" >>"$SELFTEST_LOG"
case "$mode" in
active)
	code=200
	printf '%s\n' '{"id":"sub_123","status":"active","current_period_end":1790000000,"customer":"cus_1"}' >"$out"
	;;
past_due)
	code=200
	printf '%s\n' '{"id":"sub_123","status":"past_due","current_period_end":1790000000,"customer":"cus_1"}' >"$out"
	;;
missing)
	code=404
	: >"$out"
	;;
denied)
	code=401
	: >"$out"
	;;
*)
	code=500
	: >"$out"
	;;
esac
printf '%s' "$code"
EOF
	chmod 755 "$fix/bin/curl"

	[ "$(PATH="$fix/bin:$PATH" SELFTEST_MODE=missing curl https://stub.invalid)" = 404 ] ||
		die "the self-test's stub curl is not being used"

	printf '%s\n' 'not-a-real-stripe-key-000000' >"$fix/key"
	chmod 600 "$fix/key"

	fail=0
	assert_eq() {
		if [ "$2" = "$3" ]; then
			printf 'ok: %s\n' "$1"
		else
			printf 'FAIL: %s: expected [%s], got [%s]\n' "$1" "$2" "$3"
			fail=1
		fi
	}
	assert_has() {
		case "$3" in
		*"$2"*)
			printf 'ok: %s\n' "$1"
			;;
		*)
			printf 'FAIL: %s: does not contain [%s]:\n%s\n' "$1" "$2" "$3"
			fail=1
			;;
		esac
	}

	run() {
		: >"$SELFTEST_LOG"
		: >"$fix/out"
		if (PATH="$fix/bin:$PATH" subscription "$@" >"$fix/out" 2>&1); then
			rc=0
		else
			rc=$?
		fi
		out=$(cat "$fix/out")
	}

	printf '%s\n' '--- an active subscription is printed'
	SELFTEST_MODE=active
	run sub_123 "$fix/key"
	assert_eq 'active exit' 0 "$rc"
	assert_has 'the object is the API answer' '"status":"active"' "$out"
	assert_has 'only the subscription URL is read' 'GET https://api.stripe.com/v1/subscriptions/sub_123' "$(cat "$SELFTEST_LOG")"

	printf '%s\n' '--- a past_due subscription is still returned'
	SELFTEST_MODE=past_due
	run sub_123 "$fix/key"
	assert_eq 'past_due exit' 0 "$rc"
	assert_has 'the status is the API answer' '"status":"past_due"' "$out"

	printf '%s\n' '--- a missing subscription is a retryable failure'
	SELFTEST_MODE=missing
	run sub_123 "$fix/key"
	assert_eq 'missing exit' 1 "$rc"
	assert_has 'the failure names the subscription' 'sub_123' "$out"

	printf '%s\n' '--- a key that cannot read subscriptions is a configuration to fix'
	SELFTEST_MODE=denied
	run sub_123 "$fix/key"
	assert_eq 'denied exit' 2 "$rc"
	assert_has 'the failure names the scope' 'subscriptions' "$out"

	printf '%s\n' '--- an unreachable API is a retryable failure'
	SELFTEST_MODE=unreachable
	run sub_123 "$fix/key"
	assert_eq 'unreachable exit' 1 "$rc"
	assert_has 'the failure says it could not reach the API' 'could not reach' "$out"

	printf '%s\n' '--- the key is never an argument'
	SELFTEST_MODE=active
	run sub_123 "$fix/key"
	assert_eq 'key run exit' 0 "$rc"
	if grep -q 'not-a-real-stripe-key' "$SELFTEST_LOG"; then
		printf 'FAIL: the key reached an argument:\n%s\n' "$(cat "$SELFTEST_LOG")"
		fail=1
	else
		printf 'ok: the key is not in any argument\n'
	fi

	printf '%s\n' '--- a key another user can read is refused'
	chmod 644 "$fix/key"
	run sub_123 "$fix/key"
	assert_eq 'readable key exit' 2 "$rc"
	assert_has 'the refusal names the file' "$fix/key" "$out"
	chmod 600 "$fix/key"

	printf '%s\n' '--- an id that is not a subscription id is refused before any call'
	: >"$SELFTEST_LOG"
	run '../customers' "$fix/key"
	assert_eq 'bad id exit' 2 "$rc"
	assert_eq 'nothing was called' '' "$(cat "$SELFTEST_LOG")"

	rm -rf "$fix"
	if [ "$fail" -ne 0 ]; then
		printf '\nself-test: FAILED\n' >&2
		return 1
	fi
	printf '\nself-test: all cases passed\n'
	return 0
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/kyriakon-stripe.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
resp="$tmp/response"
curlrc="$tmp/curlrc"

case "${1:-}" in
--self-test)
	if self_test; then
		exit 0
	else
		exit 1
	fi
	;;
-h | --help)
	usage
	exit 0
	;;
subscription)
	[ "$#" -eq 3 ] || {
		usage >&2
		exit 2
	}
	command -v curl >/dev/null || die "curl is not on PATH"
	subscription "$2" "$3"
	;;
*)
	usage >&2
	exit 2
	;;
esac
