#!/bin/ksh
# publish-mail-key.sh: open a change that publishes an approved member's mail key.
#
# The pull request does not wait for an operator: .github/workflows/auto-merge-key.yml
# merges it once the checks pass, because a key is not code and the approval has
# already made the decision. The branch is squashed and deleted, so the published
# set's history is one commit per key.
#
# Usage:
#   doas ksh scripts/publish-mail-key.sh <localpart> <key-file> <token-file>
#   ksh scripts/publish-mail-key.sh --self-test
#
# The drain runs the first form, as root, once per mail key, after the key is in
# the box keyring and the member is built and before the account record and the
# notice. This is the other half of scripts/check-keyring-drift.sh: that check's
# box rule alerts when a key is on the box and not in the merged published set,
# which is the right signal and, without this, a permanent one.
#
#   <localpart>   the member's account name, or the mailbox the key is for
#   <key-file>    the armored public key, the file the drain just wrote into the
#                 box keyring at /etc/kyriakon/keys/<localpart>.asc
#   <token-file>  the root-only file holding the forge token
#
# The mechanism, because it is the unusual part. The box has no Go and no node,
# and the authoritative record is a tracked file, so the client that opens the
# change is small enough to live here: curl and jq against the forge's REST API,
# with a fine-grained token whose only rights are this repository's contents and
# pull requests. The alternative the ticket names and rejects is a script a human
# copies from, which makes a promise the operator has to remember; this makes the
# approval itself the publisher.
#
# What it does, and why each call:
#
#   One branch per member, publish-key/<localpart>, holding one commit that adds
#   keys/<localpart>.asc. That is the change. A human merges it, and the seven
#   days check-keyring-drift.sh allows an unpublished key is that window: after
#   it the check alerts, and the repair is still to merge it.
#
#   The comparison is by primary fingerprint and not by file bytes, so that this
#   script's "nothing to do" is exactly the state that makes the drift check go
#   quiet. A key re-signed with the same fingerprint is the same key; only a
#   different fingerprint is a key the member would stop being able to read.
#
#   Idempotent by construction. A key already on the default branch with this
#   fingerprint is the second run: print nothing and exit 0. A branch that
#   already holds this key only gets its change ensured, and the forge's own "a
#   pull request already exists" answer counts as success here. So a retried
#   approval, or two passes over one intent, leave one commit and one change.
#
#   A DIFFERENT key already published for that localpart is refused rather than
#   overwritten. Replacing a published key is a rotation: #155 owns it, it
#   confirms with the member first, and the drift check's --publication rule
#   exists to catch a substitution nobody reviewed. This path must not be the
#   way one happens, so it stops and says so instead.
#
#   Failure is loud and named. Every refusal prints the localpart and the
#   fingerprint to stderr, which the drain mails to the operator, and exits
#   non-zero, which leaves the intent in place so a later pass tries again. The
#   failure mode is mail that delivers on the box while the repository never
#   hears about the key, so a silent failure is the one outcome not allowed, and
#   the seven-day window in check-keyring-drift.sh is the backstop for one that
#   never succeeds.
#
#   The credential is a file outside the tracked tree, root-owned and mode 0600,
#   which the drain's config names. It is written into a curl config file that is
#   itself mode 0600 in this script's scratch directory: the token is never an
#   argument, so it reaches neither the process table nor any output, and a token
#   file another user can read is refused rather than used.
#
# The three names this shares with check-keyring-drift.sh, fixed rather than
# configurable for that reason: the published directory keys/, the file
# <localpart>.asc, and the default branch main.
#
# Env:
#   KYRIAKON_REPO  owner/name of the repository to open the change against
#                  (default kyriakon/kyriakon-infra). Point it at a scratch fork
#                  to exercise this somewhere other than the real published set.
#   KYRIAKON_API   the API base (default https://api.github.com)
#
# Exit: 0 nothing to do, or the change is open; 1 the publish failed and the key
#       is not in the published set; 2 the arguments, the key or the credential
#       are unusable, which is a configuration to fix rather than a publish to
#       retry.

set -euo pipefail

# Everything here creates only its own scratch and the token-bearing curl config,
# so the mask is set once and never relaxed.
umask 077

# lib.sh holds key_problems, which is what decides whether a key can serve this
# platform's mail. deploy-onboard.sh installs the two files together, and the
# repo has them beside each other, so a missing one is a broken install rather
# than a key to publish.
script_dir=$(cd "$(dirname "$0")" && pwd)
if [ ! -f "$script_dir/lib.sh" ]; then
	printf '%s: lib.sh is not in %s. Install the two files together.\n' "$0" "$script_dir" >&2
	exit 2
fi
# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

repo="${KYRIAKON_REPO:-kyriakon/kyriakon-infra}"
api_base="${KYRIAKON_API:-https://api.github.com}"
api_version=2022-11-28
key_dir=keys
base_branch=main
accept_raw='application/vnd.github.raw+json'
accept_json='application/vnd.github+json'

usage() {
	cat <<'EOF'
usage: publish-mail-key.sh <localpart> <key-file> <token-file>
       publish-mail-key.sh --self-test

  <localpart>   the member's account name, or the mailbox the key is for
  <key-file>    the armored public key to publish
  <token-file>  the root-only file holding the forge token

The header of this script documents the mechanism, the environment it reads and
the exit codes.
EOF
}

# die <message>: the arguments, the key or the credential are not usable, so the
# run is a configuration to fix rather than a publish to retry.
die() {
	printf '%s: %s\n' "$0" "$1" >&2
	exit 2
}

# refuse <localpart> <fingerprint> <message>: a publish that must not happen. The
# member and the key are named in it because the person reading it is an operator
# answering a mail and needs to know which key to look at.
refuse() {
	printf '%s (%s): %s\n' "$1" "${2:-no fingerprint}" "$3" >&2
	exit 1
}

# unexpected <what>: a status this script has no use for. 401 and 403 are named
# apart because they are the token's scope, which a human fixes, rather than the
# forge having a bad day.
unexpected() {
	case "$code" in
	401 | 403)
		die "the token cannot read $repo (HTTP $code); it needs this repository's contents and pull requests"
		;;
	*)
		die "$repo answered HTTP $code for $1"
		;;
	esac
}

# fpr_of <file>: the primary fingerprint of the first key in a public key file,
# or empty when gpg cannot read it. The same call check-keyring-drift.sh makes,
# so the two agree about what "the same key" means, from a scratch keyring that
# keeps this out of root's own.
#
# The `|| true` is load-bearing under `set -o pipefail`: gpg exits non-zero on a
# file that is not a key, and without it the assignment would abort this script
# silently, which is the one thing a failed publish must not do. Empty is what
# every caller tests for.
fpr_of() {
	gpg --with-colons --show-keys "$1" 2>/dev/null |
		awk -F: '$1 == "fpr" { print $10; exit }' || true
}

# already_there: whether the last 422 is the forge saying the thing is already
# there, which is a previous run's own work rather than a refusal. Every other
# 422 is a publish that failed, and a failed publish is the one outcome this
# script must never leave quiet.
already_there() {
	grep -q 'already exists' "$resp"
}

# api <method> <accept> <url> [body-file]: one call, its status left in $code and
# its body in $resp. No answer at all is a failure to do the job rather than a
# finding about the key, so curl's own failure is fatal and named.
api() {
	method=$1
	accept=$2
	url=$3
	if [ "$#" -eq 4 ]; then
		code=$(curl -K "$curlrc" -X "$method" -H "Accept: $accept" \
			--data-binary "@$4" -o "$resp" -w '%{http_code}' "$url") ||
			die "curl could not reach $api_base"
	else
		code=$(curl -K "$curlrc" -X "$method" -H "Accept: $accept" \
			-o "$resp" -w '%{http_code}' "$url") ||
			die "curl could not reach $api_base"
	fi
}

# ensure_change <branch> <localpart> <fingerprint>: the change itself, opened
# once. GitHub answers 422 for a pull request that already exists for that head
# branch, which is what a second run of this finds and what "does not open a
# second change" means; anything else is a failure.
ensure_change() {
	branch=$1
	localpart=$2
	fingerprint=$3
	title="feat(keys): publish $localpart's mail key"
	body=$(
		printf '%s\n' \
			"Adds keys/$localpart.asc, the mail key the box is already delivering to" \
			"$localpart with. Opened by scripts/publish-mail-key.sh on the mail box when" \
			"the application was approved: the keyring the encrypting LMTP reads and the" \
			"published set have to agree, and this is the change that makes them." \
			"" \
			"Fingerprint: $fingerprint"
	)
	jq -n --arg title "$title" --arg head "$branch" --arg base "$base_branch" --arg body "$body" \
		'{title:$title, head:$head, base:$base, body:$body}' >"$tmp/change.json"
	api POST "$accept_json" "$api_base/repos/$repo/pulls" "$tmp/change.json"
	case "$code" in
	201) ;;
	422)
		already_there ||
			refuse "$localpart" "$fingerprint" "$repo refused the change for $branch (HTTP 422): $(cat "$resp")"
		;;
	*) refuse "$localpart" "$fingerprint" "$repo would not open the change for $branch (HTTP $code): $(cat "$resp")" ;;
	esac
}

# publish <localpart> <key-file> <token-file>: the whole job.
publish() {
	localpart=$1
	key_file=$2
	token_file=$3

	# The charset add-user.sh, acme-queue.sh and check-keyring-drift.sh already
	# carry, because the name is a filename here, a path in the API and half of a
	# branch name.
	printf '%s' "$localpart" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$' ||
		die "the localpart $localpart is not a name this platform uses"
	[ -f "$key_file" ] || die "no key file at $key_file"
	[ -s "$key_file" ] || die "the key file $key_file is empty"
	# The published file is a public key and nothing else. One grep against a
	# mistake that could not be taken back: a member's private key in a public
	# repository.
	if grep -q 'PRIVATE KEY' "$key_file"; then
		die "the key file $key_file holds a private key, and only the public half is published"
	fi

	[ -f "$token_file" ] ||
		die "no token file at $token_file; scripts/deploy-onboard.sh prints the line that installs one"
	if [ "$(stat -f '%Lp' "$token_file")" != 600 ]; then
		die "$token_file is not mode 600, and a token another user can read is a token that can write the published set"
	fi
	if [ "$(id -u)" -eq 0 ] && [ "$(stat -f '%Su' "$token_file")" != root ]; then
		die "$token_file is not owned by root"
	fi
	token=$(cat "$token_file") || die "cannot read $token_file"
	printf '%s' "$token" | grep -Eq '^[A-Za-z0-9_.-]{20,255}$' ||
		die "$token_file does not hold one token; a pasted newline, a trailing comment or a Bearer prefix would all go into the request"

	# The token goes into a curl config file rather than onto a command line: an
	# argument is readable in the process table for the life of the call, and this
	# box has several accounts. Nothing below prints it either.
	{
		printf 'header = "Authorization: Bearer %s"\n' "$token"
		printf 'header = "X-GitHub-Api-Version: %s"\n' "$api_version"
		printf 'header = "User-Agent: kyriakon-publish-mail-key"\n'
		printf 'silent\nshow-error\nmax-time = 30\nretry = 3\n'
	} >"$curlrc"
	unset token

	want=$(fpr_of "$key_file")
	[ -n "$want" ] ||
		refuse "$localpart" "" "the key file $key_file is not a public key gpg can read, so nothing was published"

	# The key's shape, before anything is opened: a key the platform cannot
	# deliver to is a refusal with the fix on the workstation that holds it, not
	# a published set entry that fails one member's mail quietly.
	problems=$(key_problems "$key_file")
	[ -z "$problems" ] ||
		refuse "$localpart" "$want" "the key cannot serve this platform's mail:
$problems"

	path="$key_dir/$localpart.asc"
	branch="publish-key/$localpart"

	# The published set, on the default branch. A key there under this
	# fingerprint is the second run, and a silent exit is what the box's rule for
	# a quiet job asks of any run that finds nothing to do.
	api GET "$accept_raw" "$api_base/repos/$repo/contents/$path?ref=$base_branch"
	case "$code" in
	200)
		have=$(fpr_of "$resp")
		if [ "$have" = "$want" ]; then
			return 0
		fi
		if [ -z "$have" ]; then
			refuse "$localpart" "$want" "$repo publishes $path and gpg cannot read it; refusing to replace a file nobody can interpret"
		fi
		refuse "$localpart" "$want" "$repo already publishes $have for this localpart; replacing a published key is the runbook's rotation path, not this one"
		;;
	404) ;;
	*) unexpected "$path" ;;
	esac

	# The branch, for a run that got as far as its own commit and failed later,
	# or that is being retried before the merge. The same fingerprint means the
	# work is done and only the change needs ensuring.
	api GET "$accept_raw" "$api_base/repos/$repo/contents/$path?ref=$branch"
	case "$code" in
	200)
		have=$(fpr_of "$resp")
		[ "$have" = "$want" ] ||
			refuse "$localpart" "$want" "the branch $branch already holds $have for this localpart; delete the branch to start again"
		ensure_change "$branch" "$localpart" "$want"
		return 0
		;;
	404) ;;
	*) unexpected "$path on $branch" ;;
	esac

	# The default branch's commit, which the new branch starts from. The Contents
	# API would make the branch itself, but that is an undocumented convenience
	# and one explicit call is cheaper than depending on it.
	api GET "$accept_json" "$api_base/repos/$repo/git/ref/heads/$base_branch"
	[ "$code" = 200 ] || unexpected "refs/heads/$base_branch"
	head=$(jq -r '.object.sha // empty' "$resp" 2>/dev/null) || head=""
	[ -n "$head" ] || refuse "$localpart" "$want" "$repo answered $base_branch with no commit; nothing was published"

	# The branch. 422 is the forge saying it is already there, which a previous
	# run that died between this and the write leaves behind, so it is not an
	# error here.
	jq -n --arg ref "refs/heads/$branch" --arg sha "$head" \
		'{ref:$ref, sha:$sha}' >"$tmp/branch.json"
	api POST "$accept_json" "$api_base/repos/$repo/git/refs" "$tmp/branch.json"
	case "$code" in
	201) ;;
	422)
		already_there ||
			refuse "$localpart" "$want" "$repo refused the branch $branch (HTTP 422): $(cat "$resp")"
		;;
	*) refuse "$localpart" "$want" "$repo would not create $branch (HTTP $code): $(cat "$resp")" ;;
	esac

	# The commit. jq's @base64 is what encodes the key, because this box has no
	# base64(1): OpenBSD ships none.
	jq -n --rawfile key "$key_file" --arg message "feat(keys): publish $localpart's mail key" \
		--arg branch "$branch" \
		'{message:$message, content:($key|@base64), branch:$branch}' >"$tmp/file.json"
	api PUT "$accept_json" "$api_base/repos/$repo/contents/$path" "$tmp/file.json"
	case "$code" in
	200 | 201) ;;
	*) refuse "$localpart" "$want" "$repo would not write $path on $branch (HTTP $code): $(cat "$resp")" ;;
	esac

	ensure_change "$branch" "$localpart" "$want"
	printf 'opened %s: %s\n' "$branch" "$want"
}

# --- self-test: the decisions, against a stub forge ----------------------------
#
# curl is replaced on PATH by a stub that answers the calls this script makes
# from fixture files, so what is exercised is this script's own decisions:
# already published, on the branch, a different key either side, and a credential
# it must refuse. Every case also reads the stub's log, because "a second publish
# opens no second change" and "the token is never an argument" are claims about
# what did not happen. gpg and jq are real; the keys are throwaway ones under
# TMPDIR.
self_test() {
	fix="$tmp/self"
	mkdir -p "$fix/bin" "$fix/state"
	export SELFTEST_STATE="$fix/state"
	export SELFTEST_LOG="$fix/stub.log"

	# The stub. It answers only the calls this script makes, from files a case
	# lays down: state/main and state/branch hold the key at that ref, and their
	# absence is the forge's 404. It logs its own argv, so a token on a command
	# line would show up in the assertions below.
	cat >"$fix/bin/curl" <<'EOF'
#!/bin/ksh
method=GET
accept=""
out=/dev/null
body=""
url=""
argv="$*"
while [ "$#" -gt 0 ]; do
	case "$1" in
	-K) shift ;;
	-X)
		method=$2
		shift
		;;
	-H)
		accept=$2
		shift
		;;
	--data-binary)
		body=${2#@}
		shift
		;;
	-o)
		out=$2
		shift
		;;
	-w) shift ;;
	*) url=$1 ;;
	esac
	shift
done
printf '%s\n' "$method $url [$argv]" >>"$SELFTEST_LOG"
case "$url" in
*"/contents/"*"?ref=main")
	if [ -f "$SELFTEST_STATE/main" ]; then
		code=200
		cp "$SELFTEST_STATE/main" "$out"
	else
		code=404
		: >"$out"
	fi
	;;
*"/contents/"*"?ref=publish-key/"*)
	if [ -f "$SELFTEST_STATE/branch" ]; then
		code=200
		cp "$SELFTEST_STATE/branch" "$out"
	else
		code=404
		: >"$out"
	fi
	;;
*"/git/ref/heads/"*)
	code=200
	printf '{"object":{"sha":"0000000000000000000000000000000000000000"}}\n' >"$out"
	;;
*"/git/refs")
	code=201
	: >"$out"
	;;
*"/contents/"*)
	code=201
	if [ -f "$body" ]; then
		jq -j '.content|@base64d' "$body" >"$SELFTEST_STATE/branch"
	fi
	: >"$out"
	;;
*"/pulls")
	code=${SELFTEST_PULL_CODE:-201}
	if [ "$code" = 422 ]; then
		printf '{"message":"Validation Failed","errors":[{"message":"%s"}]}\n' \
			"${SELFTEST_PULL_MESSAGE:-A pull request already exists for kyriakon:branch.}" >"$out"
	else
		: >"$out"
	fi
	;;
*)
	code=500
	: >"$out"
	;;
esac
printf '%s' "$code"
EOF
	chmod 755 "$fix/bin/curl"

	# The stub runs before anything depends on it: a real curl here would go to
	# the network, and the guesses it would get back are not the test.
	[ "$(PATH="$fix/bin:$PATH" curl https://stub.invalid)" = 500 ] ||
		die "the self-test's stub curl is not being used"

	make_key() {
		gpg --batch --pinentry-mode loopback --passphrase '' \
			--quick-generate-key "$1" ed25519 sign 0 >/dev/null 2>&1
		# gpg 2.4+ writes the AEAD preference into every self-signature, and the
		# publish gate refuses that: a fixture has to look like a key the platform
		# would publish, or every case below would test the refusal instead.
		gpg --batch --yes --pinentry-mode loopback --passphrase '' --command-fd 0 \
			--edit-key "$1" >/dev/null 2>&1 <<'SETPREF'
setpref AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed
y
save
SETPREF
		gpg --batch --armor --export "$1" >"$2" 2>/dev/null
	}
	make_key 'Alice Publish <alice@example.invalid>' "$fix/alice.asc"
	make_key 'Bob Publish <bob@example.invalid>' "$fix/bob.asc"
	alice=$(fpr_of "$fix/alice.asc")
	bob=$(fpr_of "$fix/bob.asc")
	if [ -z "$alice" ] || [ -z "$bob" ] || [ "$alice" = "$bob" ]; then
		die "the self-test could not generate its throwaway keys"
	fi

	printf '%s\n' 'not-a-real-token-0000000000' >"$fix/token"
	chmod 600 "$fix/token"

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
	assert_log() {
		case "$(cat "$fix/stub.log")" in
		*"$2"*)
			printf 'ok: %s\n' "$1"
			;;
		*)
			printf 'FAIL: %s: the calls do not include [%s]:\n%s\n' "$1" "$2" "$(cat "$fix/stub.log")"
			fail=1
			;;
		esac
	}
	assert_no_log() {
		case "$(cat "$fix/stub.log")" in
		*"$2"*)
			printf 'FAIL: %s: the calls should not include [%s]:\n%s\n' "$1" "$2" "$(cat "$fix/stub.log")"
			fail=1
			;;
		*)
			printf 'ok: %s\n' "$1"
			;;
		esac
	}

	# run <args...> runs publish under the stub, leaving its output in $out and
	# its status in $rc. The subshell is what keeps a refusal, which exits, from
	# ending the self-test, and the output goes through a file rather than a
	# command substitution: an exit inside one loses what it had written on at
	# least one ksh this repository has run under.
	run() {
		: >"$fix/stub.log"
		: >"$fix/out"
		if (PATH="$fix/bin:$PATH" publish "$@" >"$fix/out" 2>&1); then
			rc=0
		else
			rc=$?
		fi
		out=$(cat "$fix/out")
	}

	printf '%s\n' '--- the first publish opens the change'
	rm -f "$fix/state/main" "$fix/state/branch"
	run alice "$fix/alice.asc" "$fix/token"
	assert_eq 'first publish exit' 0 "$rc"
	assert_log 'the commit was written' 'PUT'
	assert_log 'the change was opened' '/pulls'
	assert_eq 'the branch holds the key' "$alice" "$(fpr_of "$fix/state/branch")"

	printf '%s\n' '--- the second publish changes nothing and opens no second change'
	rm -f "$fix/state/main"
	# The branch is there with this key, which is what a retry finds, and the
	# forge's own answer for a change that already exists is the 422 the stub
	# returns here rather than a second change.
	export SELFTEST_PULL_CODE=422
	run alice "$fix/alice.asc" "$fix/token"
	unset SELFTEST_PULL_CODE
	assert_eq 'second publish exit' 0 "$rc"
	assert_eq 'second publish output' '' "$out"
	assert_no_log 'no second commit' 'PUT'
	assert_log 'the change was ensured' '/pulls'

	printf '%s\n' '--- a 422 that is not an existing change is a failed publish'
	rm -f "$fix/state/main"
	export SELFTEST_PULL_CODE=422
	export SELFTEST_PULL_MESSAGE='Validation Failed'
	run alice "$fix/alice.asc" "$fix/token"
	unset SELFTEST_PULL_CODE SELFTEST_PULL_MESSAGE
	assert_eq 'refused change exit' 1 "$rc"
	assert_has 'the refusal names the member' 'alice' "$out"
	assert_has 'the refusal names the key' "$alice" "$out"
	assert_has 'the refusal carries what the forge said' 'Validation Failed' "$out"

	printf '%s\n' '--- a key already published is silent and changes nothing'
	cp "$fix/alice.asc" "$fix/state/main"
	run alice "$fix/alice.asc" "$fix/token"
	assert_eq 'published exit' 0 "$rc"
	assert_eq 'published output' '' "$out"
	assert_no_log 'no commit for a published key' 'PUT'
	assert_no_log 'no change for a published key' '/pulls'

	printf '%s\n' '--- a different published key is refused, and names both'
	cp "$fix/bob.asc" "$fix/state/main"
	run alice "$fix/alice.asc" "$fix/token"
	assert_eq 'substitution exit' 1 "$rc"
	assert_has 'the refusal names the member' 'alice' "$out"
	assert_has 'the refusal names the published key' "$bob" "$out"
	assert_has 'the refusal names the key on the box' "$alice" "$out"
	assert_no_log 'the published file was not written' 'PUT'

	printf '%s\n' '--- a key that advertises AEAD is refused before anything is opened'
	aead_key="$fix/carol.asc"
	gpg --batch --pinentry-mode loopback --passphrase '' \
		--quick-generate-key 'Carol Aead <carol@example.invalid>' ed25519 sign 0 >/dev/null 2>&1
	gpg --batch --armor --export 'carol@example.invalid' >"$aead_key" 2>/dev/null
	# gpg before 2.4 writes no AEAD advert, so there would be nothing to refuse.
	# Skipped by name rather than asserted, because the case would then fail for a
	# property of the tool rather than of this script.
	if gpg --list-packets "$aead_key" 2>/dev/null | grep -q 'pref-aead-algos'; then
		run carol "$aead_key" "$fix/token"
		assert_eq 'aead exit' 1 "$rc"
		assert_has 'the refusal names the fix' 'rekey-mail-key.sh' "$out"
		assert_no_log 'nothing was opened for an AEAD key' 'PUT'
	else
		printf 'skip: this gpg writes no AEAD advert, so %s has nothing to refuse\n' "$0"
	fi

	printf '%s\n' '--- a key that expires is refused'
	expiring_key="$fix/exp.asc"
	gpg --batch --pinentry-mode loopback --passphrase '' \
		--quick-generate-key 'Exp Soon <exp@example.invalid>' rsa2048 encr 1d >/dev/null 2>&1
	gpg --batch --armor --export 'exp@example.invalid' >"$expiring_key" 2>/dev/null
	run exp "$expiring_key" "$fix/token"
	assert_eq 'expiry exit' 1 "$rc"
	assert_has 'the refusal says when it expires' 'expires on' "$out"
	assert_no_log 'nothing was opened for an expiring key' 'PUT'

	printf '%s\n' '--- a different key on the branch is refused'
	rm -f "$fix/state/main"
	cp "$fix/bob.asc" "$fix/state/branch"
	run alice "$fix/alice.asc" "$fix/token"
	assert_eq 'branch collision exit' 1 "$rc"
	assert_has 'the refusal names the branch' 'publish-key/alice' "$out"
	assert_no_log 'the branch was not written' 'PUT'

	printf '%s\n' '--- a key file gpg cannot read is refused, and names the member'
	rm -f "$fix/state/main" "$fix/state/branch"
	printf '%s\n' 'not a public key' >"$fix/broken.asc"
	run alice "$fix/broken.asc" "$fix/token"
	assert_eq 'unreadable key exit' 1 "$rc"
	assert_has 'the refusal names the member' 'alice' "$out"
	assert_eq 'nothing was sent' '' "$(cat "$fix/stub.log")"

	printf '%s\n' '--- the token is never an argument'
	rm -f "$fix/state/main" "$fix/state/branch"
	run alice "$fix/alice.asc" "$fix/token"
	assert_eq 'token run exit' 0 "$rc"
	if grep -q 'not-a-real-token' "$fix/stub.log"; then
		printf 'FAIL: the token reached an argument:\n%s\n' "$(cat "$fix/stub.log")"
		fail=1
	else
		printf 'ok: the token is not in any argument\n'
	fi

	printf '%s\n' '--- a token another user can read is refused'
	chmod 644 "$fix/token"
	run alice "$fix/alice.asc" "$fix/token"
	assert_eq 'readable token exit' 2 "$rc"
	assert_has 'the refusal names the file' "$fix/token" "$out"
	chmod 600 "$fix/token"

	printf '%s\n' '--- a private key is refused before anything is sent'
	rm -f "$fix/state/main" "$fix/state/branch"
	printf '%s\n' '-----BEGIN PGP PRIVATE KEY BLOCK-----' >"$fix/secret.asc"
	run alice "$fix/secret.asc" "$fix/token"
	assert_eq 'private key exit' 2 "$rc"
	assert_has 'the refusal says why' 'private key' "$out"
	assert_eq 'nothing was sent' '' "$(cat "$fix/stub.log")"

	if [ "$fail" -ne 0 ]; then
		printf '\nself-test: FAILED\n' >&2
		return 1
	fi
	printf '\nself-test: all cases passed\n'
	return 0
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/kyriakon-publish.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
resp="$tmp/response"
curlrc="$tmp/curlrc"
# gpg reads the key files from the argument, but it still wants a home to exist,
# and a scratch one keeps the keyring lookup away from root's own.
export GNUPGHOME="$tmp/gnupg"
mkdir -m 700 "$GNUPGHOME"

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
esac

[ "$#" -eq 3 ] || {
	usage >&2
	exit 2
}

command -v curl >/dev/null || die "curl is not on PATH (pkg_add curl)"
command -v jq >/dev/null || die "jq is not on PATH (pkg_add jq)"
command -v gpg >/dev/null || die "gpg is not on PATH (pkg_add gnupg)"

publish "$1" "$2" "$3"
