#!/bin/ksh
# check-keyring-drift.sh: notice a member's mail key changing under the platform's feet.
#
# Two rules, one script, both comparing public fingerprints and never key bodies:
#
#   --box          runs on the mail box. Compares the fingerprints of
#                  /etc/kyriakon/keys/*.asc against the merged published set,
#                  keys/*.asc in kyriakon-infra. A key published but absent from
#                  the box alerts at once, because delivery for that member has
#                  stopped. A fingerprint that differs alerts at once, because the
#                  box is encrypting to a key nobody published. A key on the box
#                  and not yet published alerts only after UNPUBLISHED_DAYS days:
#                  a signup's pull request sitting unmerged is normal for a week,
#                  and a mistake after that. The age is the key file's modification
#                  time in the keyring, which is when the signup service wrote it,
#                  so the service must create the file rather than carry some older
#                  timestamp onto it.
#
#   --publication  runs off the box, wherever the recorded copy in the second
#                  repository (KEYRING_STORE) is readable. Compares the merged
#                  published set against that copy, which the mail box's publish
#                  token is not scoped to and cannot write. A fingerprint that
#                  changed for an already-published key alerts, however the commit
#                  reached main. This is the rule that survives the box itself
#                  being compromised, since the box holds a merge credential for
#                  the repository that the first rule reads.
#
#   --fingerprints print the published set in the recorded copy's format. This is
#                  how that copy is refreshed after a reviewed and expected change
#                  (a rotation, a member leaving). Additions are deliberately
#                  silent under --publication: a new key is a signup, and the box
#                  rule is what watches whether it ever reaches the published set.
#
#   --self-test    build throwaway keyrings under TMPDIR and check both rules
#                  against a known answer. Needs gpg and nothing else.
#
# The published set is fetched from the repository with a depth-1 clone rather than
# read from a checkout that may be days stale, so the comparison is against the
# merged state at the moment it runs. A stale checkout would show the old
# fingerprint for a rewritten key and miss the substitution entirely.
#
# Alerts go off the box by the route scripts/abuse-monitor.sh uses: mail to
# ALERT_EMAIL, and this check's own Healthchecks URL carrying the finding in its
# event log. A clean run pings that URL too, so silence means the check stopped
# running. The monitor's HEALTHCHECKS_URL is deliberately not reused: its period
# belongs to a fifteen-minute job, and a second, daily pinger would make its
# liveness say nothing.
#
# Nothing here changes delivery. The box keyring is what encrypts, a publication
# lag must never bounce a member's mail, and an alert is for a human to look at.
#
# Env:
#   ALERT_EMAIL              off-box address for findings (abuse-monitor.sh reads it too)
#   KEYRING_HEALTHCHECKS_URL this check's own check, daily period
#   KEYRING_DIR              on-box keyring (default /etc/kyriakon/keys)
#   KEYRING_STORE            recorded published fingerprints, one 'localpart
#                            fingerprint' line each, in the second repository
#   KYRIAKON_REPO_URL        repository to fetch the published set from (default
#                            https://github.com/kyriakon/kyriakon-infra.git)
#   KYRIAKON_PUBLISHED_DIR   a keys/ directory to read instead of cloning (used by
#                            the self-test; also useful against a local checkout)
#   UNPUBLISHED_DAYS         days a box key may sit unpublished before it alerts (default 7)
#
# Exit: 0 no findings, 1 drift found, 2 the check could not run.
#
# crontab (root), installed by scripts/cron-apply.sh:
#   0 4 * * * . /root/.kyriakon-env; /root/bin/check-keyring-drift.sh --box
# Off the box, on the host that holds the second repository's checkout:
#   0 5 * * * . /home/operator/.kyriakon-drift-env; /home/operator/bin/check-keyring-drift.sh --publication

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
if [ ! -f "$script_dir/lib.sh" ]; then
	printf '%s: lib.sh is not in %s. Install the two files together, as lib.sh describes.\n' \
		"$0" "$script_dir" >&2
	exit 2
fi

# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's directory
. "$script_dir/lib.sh"

usage() {
	cat <<'EOF'
usage: check-keyring-drift.sh [--box | --publication | --fingerprints | --self-test]

  --box           (default) the box keyring against the merged published set
  --publication   the merged published set against the recorded copy in the second repository
  --fingerprints  print the published set in the recorded copy's format
  --self-test     run the local fixtures (needs gpg, writes only under TMPDIR)

The header of this script documents the environment it reads, the exit codes and
the crontab lines.
EOF
}

mode=box
while [ $# -gt 0 ]; do
	case "$1" in
		--box) mode=box ;;
		--publication) mode=publication ;;
		--fingerprints) mode=fingerprints ;;
		--self-test) mode=self_test ;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			usage >&2
			exit 2
			;;
	esac
	shift
done

keyring_dir="${KEYRING_DIR:-/etc/kyriakon/keys}"
unpublished_days="${UNPUBLISHED_DAYS:-7}"
repo_url="${KYRIAKON_REPO_URL:-https://github.com/kyriakon/kyriakon-infra.git}"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/kyriakon-drift.XXXXXX")
findings="$tmp/findings"
pub_map="$tmp/published"

trap 'rm -rf "$tmp"' EXIT

# gpg reads the key files from the argument, not from a keyring, but it still wants
# a home to exist. A scratch one keeps the check from touching root's own keyring,
# and from being affected by whatever state that keyring is in.
export GNUPGHOME="$tmp/gnupg"
mkdir -m 700 "$GNUPGHOME"

# die <message>: the check could not do its job. An unattended run that cannot see
# the keyring is not the same as a clean one, so say so on the same off-box channel
# and leave a status that cron and a human can tell apart from drift.
die() {
	printf '%s: %s\n' "$0" "$1" >&2
	if [ -n "${KEYRING_HEALTHCHECKS_URL:-}" ]; then
		ping_url "$KEYRING_HEALTHCHECKS_URL/fail"
	fi
	exit 2
}

# alert <title> <body>: mail off the box, and carry the body into the check's
# event log. Never fails the caller: an alert that cannot be sent must not become a
# second failure stacked on the one being reported.
alert() {
	title="$1"
	body="$2"
	when=$(date '+%F %T')
	if [ -n "${ALERT_EMAIL:-}" ]; then
		printf '%s\n\n%s on %s\n' "$body" "$title" "$(hostname)" |
			mail -s "kyriakon: $title" "$ALERT_EMAIL" >/dev/null 2>&1 || true
	fi
	if [ -n "${KEYRING_HEALTHCHECKS_URL:-}" ]; then
		curl -fsS -m 10 --retry 3 --data "$when $title: $body" "$KEYRING_HEALTHCHECKS_URL" \
			>/dev/null 2>&1 || true
	fi
	printf '%s %s: %s\n%s\n' "$when" "$title" "$(hostname)" "$body" >&2
}

# fpr_of <file>: the primary fingerprint of the first key in a public key file, or
# empty if gpg cannot read it. --show-keys is the call rekey-mail-key.sh already
# uses, and it reads the file without importing anything.
fpr_of() {
	gpg --with-colons --show-keys "$1" 2>/dev/null |
		awk -F: '$1 == "fpr" { print $10; exit }'
}

# A finding names the localpart and the fingerprints involved, never the key body.
finding() {
	printf '%s\n' "$1" >>"$findings"
}

# pub_map holds 'localpart fingerprint' for every published key, in glob order. A
# key file gpg cannot read in the published set is a failure to run, not drift: half
# a comparison would report the box against a set nobody can interpret.
build_pub_map() {
	: >"$pub_map"
	for p in "$published_dir"/*.asc; do
		[ -e "$p" ] || continue
		lp=${p##*/}
		lp=${lp%.asc}
		fpr=$(fpr_of "$p")
		[ -n "$fpr" ] || die "cannot read the published key $p"
		printf '%s %s\n' "$lp" "$fpr" >>"$pub_map"
	done
	[ -s "$pub_map" ] || die "no *.asc files in the published set at $published_dir"
}

pub_fpr() {
	awk -v lp="$1" '$1 == lp { print $2; exit }' "$pub_map"
}

check_box() {
	[ -d "$keyring_dir" ] || die "no keyring directory to read: $keyring_dir"
	build_pub_map

	now=$(date +%s)

	# Every key the box serves, against the published set.
	for k in "$keyring_dir"/*.asc; do
		[ -e "$k" ] || continue
		lp=${k##*/}
		lp=${lp%.asc}
		fpr=$(fpr_of "$k")
		if [ -z "$fpr" ]; then
			finding "$lp: unreadable key file $k. Delivery to $lp fails closed until a key gpg can read is back in place."
			continue
		fi
		pf=$(pub_fpr "$lp")
		if [ -z "$pf" ]; then
			mtime=$(stat -f %m "$k")
			age=$(( (now - mtime) / 86400 ))
			if [ "$age" -gt "$unpublished_days" ]; then
				finding "$lp: on the box as $fpr, unpublished for $age days (limit $unpublished_days). An unmerged pull request or a mistake; delivery works either way, so nothing is broken yet."
			fi
			continue
		fi
		if [ "$fpr" != "$pf" ]; then
			finding "$lp: the box serves $fpr, the published set has $pf. The box is encrypting to a key nobody published."
		fi
	done

	# Every published key, against the box. Nothing waits here: publication is the
	# claim, and a member whose key is not being served has had their mail stopped.
	while read -r lp pf; do
		[ -e "$keyring_dir/$lp.asc" ] ||
			finding "$lp: published as $pf but absent from $keyring_dir. Delivery for $lp has stopped."
	done <"$pub_map"
}

check_publication() {
	[ -n "${KEYRING_STORE:-}" ] ||
		die "--publication needs KEYRING_STORE, the recorded copy in the second repository"
	[ -r "$KEYRING_STORE" ] || die "cannot read the recorded copy at $KEYRING_STORE"
	build_pub_map

	# The recorded copy, against the published set. Additions are not reported
	# here on purpose, and the header says why.
	while read -r lp recorded; do
		case "$lp" in
			'' | '#'*) continue ;;
		esac
		pf=$(pub_fpr "$lp")
		if [ -z "$pf" ]; then
			finding "$lp: recorded as $recorded, no longer in the published set. A published key was removed."
		elif [ "$pf" != "$recorded" ]; then
			finding "$lp: recorded as $recorded, now published as $pf. An already-published key was rewritten."
		fi
	done <"$KEYRING_STORE"
}

print_fingerprints() {
	build_pub_map
	cat "$pub_map"
}

# --- self-test: both rules against a known answer ------------------------------
#
# Builds three throwaway keys under TMPDIR, lays out a published set, a healthy
# keyring, a drifted one and a recorded copy, then runs this script against each and
# checks the exit code and what the output names. gpg is the only dependency.
self_test() {
	fixture="$tmp/fixture"
	pub="$fixture/published"
	box_ok="$fixture/box-ok"
	box_drift="$fixture/box-drift"
	store="$fixture/store"

	mkdir -p "$pub" "$box_ok" "$box_drift"

	make_key() {
		gpg --batch --pinentry-mode loopback --passphrase '' \
			--quick-generate-key "$1" ed25519 sign 0 >/dev/null 2>&1
		gpg --batch --armor --export "$1" >"$2" 2>/dev/null
	}
	make_key 'Alice Drift <alice@example.invalid>' "$fixture/alice.asc"
	make_key 'Bob Drift <bob@example.invalid>' "$fixture/bob.asc"
	make_key 'Carol Drift <carol@example.invalid>' "$fixture/carol.asc"

	alice=$(fpr_of "$fixture/alice.asc")
	bob=$(fpr_of "$fixture/bob.asc")
	carol=$(fpr_of "$fixture/carol.asc")
	if [ -z "$alice" ] || [ -z "$bob" ] || [ -z "$carol" ]; then
		die "the self-test could not generate its throwaway keys"
	fi

	# The published set: alice, bob, carol.
	cp "$fixture/alice.asc" "$pub/alice.asc"
	cp "$fixture/bob.asc" "$pub/bob.asc"
	cp "$fixture/carol.asc" "$pub/carol.asc"

	# The healthy box serves all three, each one matching its published file.
	cp "$fixture/alice.asc" "$box_ok/alice.asc"
	cp "$fixture/bob.asc" "$box_ok/bob.asc"
	cp "$fixture/carol.asc" "$box_ok/carol.asc"

	# The drifted box: bob's file holds a different key, carol is published and not
	# served at all, dave is unpublished and old, eve is unpublished and fresh. Eve
	# staying silent is the seven-day rule working.
	cp "$fixture/alice.asc" "$box_drift/alice.asc"
	cp "$fixture/carol.asc" "$box_drift/bob.asc"
	cp "$fixture/carol.asc" "$box_drift/dave.asc"
	cp "$fixture/carol.asc" "$box_drift/eve.asc"
	touch -t 202001010000 "$box_drift/dave.asc"

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
				printf 'FAIL: %s: output does not mention [%s]:\n%s\n' "$1" "$2" "$3"
				fail=1
				;;
		esac
	}
	assert_hasnt() {
		case "$3" in
			*"$2"*)
				printf 'FAIL: %s: output should not mention [%s]:\n%s\n' "$1" "$2" "$3"
				fail=1
				;;
			*)
				printf 'ok: %s\n' "$1"
				;;
		esac
	}

	# run <args...> runs this script with the fixture environment and no alerting,
	# leaving the exit status in $rc and the combined output in $out.
	export KEYRING_DIR KEYRING_STORE
	run() {
		if out=$(ALERT_EMAIL='' KEYRING_HEALTHCHECKS_URL='' KYRIAKON_PUBLISHED_DIR="$run_pub" \
			"$0" "$@" 2>&1); then
			rc=0
		else
			rc=$?
		fi
	}

	run_pub="$pub"

	printf '%s\n' '--- a healthy box is silent and exits 0'
	KEYRING_DIR="$box_ok"
	run --box
	assert_eq 'healthy exit' 0 "$rc"
	assert_eq 'healthy output' '' "$out"

	printf '%s\n' '--- a drifted box names each localpart and exits 1'
	KEYRING_DIR="$box_drift"
	run --box
	assert_eq 'drifted exit' 1 "$rc"
	assert_has 'bob: the key the box serves' "$carol" "$out"
	assert_has 'bob: the published fingerprint' "$bob" "$out"
	assert_has 'carol: published, not served' 'carol' "$out"
	assert_has 'dave: unpublished past the limit' 'dave' "$out"
	assert_hasnt 'eve: unpublished and fresh, silent' 'eve' "$out"
	assert_hasnt 'alice: matching, silent' 'alice' "$out"

	printf '%s\n' '--- a recorded copy that matches is silent, additions included'
	printf '%s %s\n%s %s\n' alice "$alice" bob "$bob" >"$store"
	KEYRING_STORE="$store"
	run --publication
	assert_eq 'recorded copy exit' 0 "$rc"
	assert_eq 'recorded copy output' '' "$out"

	printf '%s\n' '--- a rewritten key and a removed key both alert'
	rm -f "$pub/carol.asc"
	cp "$fixture/carol.asc" "$pub/bob.asc"
	cp "$fixture/carol.asc" "$pub/dave.asc"
	printf '%s %s\n%s %s\n%s %s\n' alice "$alice" bob "$bob" carol "$carol" >"$store"
	run --publication
	assert_eq 'rewrite exit' 1 "$rc"
	assert_has 'bob: the recorded fingerprint' "$bob" "$out"
	assert_has 'bob: the published fingerprint' "$carol" "$out"
	assert_has 'carol: removed from publication' 'carol' "$out"
	assert_hasnt 'dave: an addition, silent' 'dave' "$out"

	printf '%s\n' '--- --fingerprints prints the recorded copy format'
	run --fingerprints
	assert_eq 'fingerprints exit' 0 "$rc"
	assert_has 'bob: the published fingerprint' "bob $carol" "$out"

	if [ "$fail" -ne 0 ]; then
		printf '\nself-test: FAILED\n' >&2
		return 1
	fi
	printf '\nself-test: all cases passed\n'
	return 0
}

if [ "$mode" = self_test ]; then
	if self_test; then
		exit 0
	else
		exit 1
	fi
fi

command -v gpg >/dev/null || die "gpg is not on PATH (pkg_add gnupg)"

# The published set comes from a fresh clone of the repository, not from a local
# checkout, so the merged state is what both the box rule and the recorded-copy rule
# compare against at the moment they run.
published_dir=""
if [ -n "${KYRIAKON_PUBLISHED_DIR:-}" ]; then
	published_dir="$KYRIAKON_PUBLISHED_DIR"
	[ -d "$published_dir" ] || die "KYRIAKON_PUBLISHED_DIR is not a directory: $published_dir"
else
	command -v git >/dev/null || die "git is not on PATH and the published set is fetched with it"
	git clone --depth 1 --quiet --branch main "$repo_url" "$tmp/kyriakon-infra" ||
		die "cannot fetch the published set from $repo_url"
	published_dir="$tmp/kyriakon-infra/keys"
fi

if [ "$mode" = fingerprints ]; then
	print_fingerprints
	exit 0
fi

case "$mode" in
	box) check_box ;;
	publication) check_publication ;;
esac

if [ -s "$findings" ]; then
	alert "keyring drift" "$(cat "$findings")"
	exit 1
fi

if [ -n "${KEYRING_HEALTHCHECKS_URL:-}" ]; then
	ping_url "$KEYRING_HEALTHCHECKS_URL"
fi
exit 0
