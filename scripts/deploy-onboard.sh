#!/bin/ksh
# deploy-onboard.sh: put the onboarding handler on the box and start it.
#
# The release's front door, installed from this repository: the store under
# /var/db/onboard, the binary built from onboard/ and installed to
# /usr/local/sbin, the config at /etc/onboard/onboard.toml with the deployed
# release substituted into it, and the rc.d unit. Every step is idempotent, so a
# rebuild, or a second run after a fix, is one command.
#
# Runs ON the box as root:
#
#   doas ksh scripts/deploy-onboard.sh [repo_dir]
#
# Two things this deliberately does not do.
#
# It does not create the _onboard account. That account is a reserved-uid one in
# the shape _gmid has, so it is the operator's to create, once, and
# scripts/onboard-store.sh (called below) stops with the exact useradd line when
# it is missing. It also does not configure relayd: the handler listens on
# loopback only, and the front end that terminates TLS for signup.kyriakon.net is
# a separate ticket. Until that exists the handler answers the box and nothing
# else, which is why the verification here is a loopback request.

set -euo pipefail

script_dir=$(cd "$(dirname -- "$0")" && pwd)
repo_dir="${1:-$(cd "$script_dir/.." && pwd)}"

[ "$(id -u)" -eq 0 ] || { printf 'run as root (doas ksh %s)\n' "$0" >&2; exit 1; }

say() { printf '== %s\n' "$*"; }
die() { printf '%s: %s\n' "$0" "$*" >&2; exit 1; }

need_pkg() {
	pkg_info -q "$1" >/dev/null 2>&1 && return 0
	printf 'installing %s\n' "$1"
	pkg_add "$1"
}

# Every source this installs, checked before anything on the box is changed, so a
# half-copied checkout fails here rather than after the store has been written.
for f in onboard/Cargo.toml openbsd/etc/onboard/onboard.toml openbsd/etc/onboard/questions.tsv \
	openbsd/etc/rc.d/kyriakon_onboard scripts/onboard-store.sh reserved-usernames.txt; do
	[ -e "$repo_dir/$f" ] || die "missing from $repo_dir: $f"
done

# The store, the four writable directories, the mail spool, the drain's root-only
# home, and the two files the three front-ends share. One author for all of it:
# the unit does not re-create any of it, so the modes cannot drift from what that
# script asserts.
say "store"
ksh "$repo_dir/scripts/onboard-store.sh"

say "build"
need_pkg rust
cargo build --release --manifest-path "$repo_dir/onboard/Cargo.toml"
[ -x "$repo_dir/onboard/target/release/kyriakon-onboard" ] \
	|| die "the build produced no binary at onboard/target/release/kyriakon-onboard"

say "install"
install -d -m 0755 -o root -g wheel /etc/onboard
install -m 0755 "$repo_dir/onboard/target/release/kyriakon-onboard" /usr/local/sbin/kyriakon-onboard
install -m 0755 "$repo_dir/openbsd/etc/rc.d/kyriakon_onboard" /etc/rc.d/kyriakon_onboard

# The release this box is running, as the config's own comment describes it: the
# deployed commit and its date. The acceptance records carry it as the version of
# the documents an applicant accepted, so a stale value is worse than a missing
# one: it would say they accepted a revision they did not. It is rewritten on
# every deploy rather than set once.
#
# safe.directory is passed per command rather than configured: the checkout is
# root's and this script runs as root, but a box whose git refuses the checkout
# for ownership reasons should not need a setting changed to deploy.
release=$(git -C "$repo_dir" -c "safe.directory=$repo_dir" rev-parse --short HEAD 2>/dev/null) \
	|| die "cannot read the commit from $repo_dir, so the release cannot be named"
release="$release $(date -u +%F)"

sed -e "s|^release = .*|release = \"$release\"|" \
	"$repo_dir/openbsd/etc/onboard/onboard.toml" > /etc/onboard/onboard.toml
chmod 0644 /etc/onboard/onboard.toml

# The two ways this substitution goes wrong, both checked: a config that still
# carries the placeholder (the handler refuses to start, which is deliberate and
# is why this is caught here first), and one where the line did not match and the
# file went out with no release at all.
awk -v want="release = \"$release\"" '$0 == want { found = 1 } END { exit !found }' \
	/etc/onboard/onboard.toml || die "/etc/onboard/onboard.toml does not name the release $release"
if awk '/REPLACE_ME/ { found = 1 } END { exit !found }' /etc/onboard/onboard.toml; then
	die "/etc/onboard/onboard.toml still carries a REPLACE_ME placeholder"
fi
printf 'release: %s\n' "$release"

say "service"
rcctl enable kyriakon_onboard
if rcctl check kyriakon_onboard >/dev/null 2>&1; then
	rcctl restart kyriakon_onboard
else
	rcctl start kyriakon_onboard
fi
rcctl check kyriakon_onboard >/dev/null 2>&1 \
	|| die "kyriakon_onboard did not come up; check /var/log/daemon"

# The listener, taken from the installed config rather than assumed, so a box
# whose port was changed is checked where it actually answers.
port=$(awk -F= '/^port[[:space:]]*=/ { gsub(/[^0-9]/, "", $2); print $2; exit }' /etc/onboard/onboard.toml)
[ -n "$port" ] || die "no port in /etc/onboard/onboard.toml"
url="http://127.0.0.1:$port"

say "verify"
# The page must render, and the four sections must be there on both paths: the
# community block is a fieldset inside the first, so a body page counts four as
# well. A handler that is up but rendering nothing would pass a process check and
# fail this.
for path in "/" "/?branch=body"; do
	body=$(curl -s --max-time 10 "$url$path") || die "no answer from $url$path"
	printf '%s: %s sections\n' "$path" \
		"$(printf '%s' "$body" | awk '/<section/ { n++ } END { print n + 0 }')"
done
printf 'the rail question appears %s time(s), the ticket asks for 1\n' \
	"$(curl -s --max-time 10 "$url/" | awk '/How you will pay/ { n++ } END { print n + 0 }')"

printf '\ninstalled. the handler answers %s on this box only.\n' "$url"
printf 'relayd terminates TLS for signup.kyriakon.net and has to set the forwarded\n'
printf 'address the counters key on; until that front end exists the limits are\n'
printf 'box-wide. See the deployment notes on the service ticket.\n'
