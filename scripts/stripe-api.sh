#!/bin/ksh
# stripe-api.sh: read one Stripe object, and nothing else.
#
# The drain settles a card payment only after retrieving the subscription and
# seeing it is active, because a paid invoice does not prove one. It also reads
# the Checkout Session a subscription came from, which is how a missed
# `checkout.session.completed` is repaired: the session carries the account's
# reference. Both calls are reads; the webhook path marks no invoice paid,
# creates no session and cancels nothing.
#
# Usage:
#   doas ksh scripts/stripe-api.sh subscription <subscription-id> <key-file>
#   doas ksh scripts/stripe-api.sh session <subscription-id> <key-file>
#   ksh scripts/stripe-api.sh --self-test
#
#   <subscription-id>  the `sub_...` id an invoice or checkout named
#   <key-file>         the root-only restricted API key, mode 0600
#
# The JSON object is written to stdout and nothing else is. The key goes into a
# curl config file, never an argument, so it is not in the process table and not
# in any error message. The key needs read access to subscriptions and checkout
# sessions; the script refuses to run without a 0600 file, and as root without a
# root-owned one.
#
# `session` prints the first Checkout Session for the subscription, which the
# list filter `?subscription=<id>&limit=1` returns. An empty list exits 1: the
# drain has nothing to repair from and leaves the event for a later delivery.
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
       stripe-api.sh session <subscription-id> <key-file>
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

# subscription_id <id>: the id is a path segment and a query value, so its
# charset is checked before either use.
subscription_id() {
	id=$1
	case "$id" in
	sub_*)
		case "$id" in
		*[!A-Za-z0-9_]*) die "the subscription id $id is not an id" ;;
		esac
		;;
	*) die "the subscription id $id is not a sub_ id" ;;
	esac
}

# credential <key-file>: the key file's shape and ownership, then the curl
# config that carries it. The key is never an argument.
credential() {
	key_file=$1
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
}

# subscription <id> <key-file>: GET /v1/subscriptions/<id> and print the object.
subscription() {
	id=$1
	subscription_id "$id"
	credential "$2"

	code=$(curl -K "$curlrc" -o "$resp" -w '%{http_code}' \
		"$api_base/v1/subscriptions/$id") ||
		fail "curl could not reach $api_base"
	case "$code" in
	200)
		[ -s "$resp" ] || fail "$api_base answered an empty subscription"
		cat "$resp"
		;;
	401 | 403)
		die "the key cannot read subscriptions and checkout sessions (HTTP $code); it needs read access to both"
		;;
	404)
		fail "Stripe has no subscription $id"
		;;
	*)
		fail "$api_base answered HTTP $code for subscription $id"
		;;
	esac
}

# session <id> <key-file>: the first Checkout Session for the subscription, by
# the documented list filter. An empty list is a retryable failure: there is
# nothing to repair from yet.
session() {
	id=$1
	subscription_id "$id"
	credential "$2"
	command -v jq >/dev/null || die "jq is not on PATH (pkg_add jq)"

	code=$(curl -K "$curlrc" -o "$resp" -w '%{http_code}' \
		"$api_base/v1/checkout/sessions?subscription=$id&limit=1") ||
		fail "curl could not reach $api_base"
	case "$code" in
	200)
		[ -s "$resp" ] || fail "$api_base answered an empty session list"
		one=$(jq -c '.data[0] // empty' "$resp" 2>/dev/null) ||
			die "the session list from $api_base is not JSON jq can read"
		[ -n "$one" ] || fail "Stripe has no checkout session for subscription $id"
		printf '%s\n' "$one"
		;;
	401 | 403)
		die "the key cannot read subscriptions and checkout sessions (HTTP $code); it needs read access to both"
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
session)
	code=200
	printf '%s\n' '{"object":"list","data":[{"id":"cs_123","subscription":"sub_123","client_reference_id":"KYR-AAAA-BBBB-CCCC"}]}' >"$out"
	;;
session_empty)
	code=200
	printf '%s\n' '{"object":"list","data":[]}' >"$out"
	;;
session_no_reference)
	code=200
	printf '%s\n' '{"object":"list","data":[{"id":"cs_123","subscription":"sub_123"}]}' >"$out"
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
		verb=$1
		shift
		: >"$SELFTEST_LOG"
		: >"$fix/out"
		if (PATH="$fix/bin:$PATH" "$verb" "$@" >"$fix/out" 2>&1); then
			rc=0
		else
			rc=$?
		fi
		out=$(cat "$fix/out")
	}

	printf '%s\n' '--- an active subscription is printed'
	SELFTEST_MODE=active
	run subscription sub_123 "$fix/key"
	assert_eq 'active exit' 0 "$rc"
	assert_has 'the object is the API answer' '"status":"active"' "$out"
	assert_has 'only the subscription URL is read' 'GET https://api.stripe.com/v1/subscriptions/sub_123' "$(cat "$SELFTEST_LOG")"

	printf '%s\n' '--- a past_due subscription is still returned'
	SELFTEST_MODE=past_due
	run subscription sub_123 "$fix/key"
	assert_eq 'past_due exit' 0 "$rc"
	assert_has 'the status is the API answer' '"status":"past_due"' "$out"

	printf '%s\n' '--- a missing subscription is a retryable failure'
	SELFTEST_MODE=missing
	run subscription sub_123 "$fix/key"
	assert_eq 'missing exit' 1 "$rc"
	assert_has 'the failure names the subscription' 'sub_123' "$out"

	printf '%s\n' '--- a key that cannot read subscriptions is a configuration to fix'
	SELFTEST_MODE=denied
	run subscription sub_123 "$fix/key"
	assert_eq 'denied exit' 2 "$rc"
	assert_has 'the failure names the scope' 'subscriptions' "$out"

	printf '%s\n' '--- an unreachable API is a retryable failure'
	SELFTEST_MODE=unreachable
	run subscription sub_123 "$fix/key"
	assert_eq 'unreachable exit' 1 "$rc"
	assert_has 'the failure says it could not reach the API' 'could not reach' "$out"

	printf '%s\n' '--- a checkout session is printed by the subscription filter'
	SELFTEST_MODE=session
	run session sub_123 "$fix/key"
	assert_eq 'session exit' 0 "$rc"
	assert_has 'the session is printed' '"client_reference_id":"KYR-AAAA-BBBB-CCCC"' "$out"
	assert_has 'the URL filters by subscription' '?subscription=sub_123' "$(cat "$SELFTEST_LOG")"
	assert_has 'the URL asks for one session' 'limit=1' "$(cat "$SELFTEST_LOG")"

	printf '%s\n' '--- a session with no reference is printed as it is'
	SELFTEST_MODE=session_no_reference
	run session sub_123 "$fix/key"
	assert_eq 'reference-less session exit' 0 "$rc"
	if printf '%s' "$out" | grep -q 'client_reference_id'; then
		printf 'FAIL: the reference-less session carries a reference: %s\n' "$out"
		fail=1
	else
		printf 'ok: the session carries no reference\n'
	fi

	printf '%s\n' '--- an empty session list is a retryable failure'
	SELFTEST_MODE=session_empty
	run session sub_123 "$fix/key"
	assert_eq 'empty session exit' 1 "$rc"
	assert_has 'the failure names the subscription' 'sub_123' "$out"

	printf '%s\n' '--- the key is never an argument'
	SELFTEST_MODE=active
	run subscription sub_123 "$fix/key"
	assert_eq 'key run exit' 0 "$rc"
	if grep -q 'not-a-real-stripe-key' "$SELFTEST_LOG"; then
		printf 'FAIL: the key reached an argument:\n%s\n' "$(cat "$SELFTEST_LOG")"
		fail=1
	else
		printf 'ok: the key is not in any argument\n'
	fi

	printf '%s\n' '--- a key another user can read is refused'
	chmod 644 "$fix/key"
	run subscription sub_123 "$fix/key"
	assert_eq 'readable key exit' 2 "$rc"
	assert_has 'the refusal names the file' "$fix/key" "$out"
	chmod 600 "$fix/key"

	printf '%s\n' '--- an id that is not a subscription id is refused before any call'
	: >"$SELFTEST_LOG"
	run subscription '../customers' "$fix/key"
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
subscription | session)
	[ "$#" -eq 3 ] || {
		usage >&2
		exit 2
	}
	command -v curl >/dev/null || die "curl is not on PATH"
	"$1" "$2" "$3"
	;;
*)
	usage >&2
	exit 2
	;;
esac
