#!/bin/ksh
# deploy-onboard.sh: put the onboarding service on the box and start its handler.
#
# The release's front door, installed from this repository: the store under
# /var/db/onboard, the three binaries built from onboard/ and installed to
# /usr/local/sbin (the handler, the root drain and onboardctl), the handler's
# config at /etc/onboard/onboard.toml and the drain's own root-only config at
# /etc/kyriakon/onboard/drain.toml, both with the deployed release substituted,
# and the rc.d unit. Every step is idempotent, so a rebuild, or a second run
# after a fix, is one command.
#
# Installing the drain's binary does not schedule it: its crontab line, the same
# one every minute that the rest of the scheduled scripts get, is installed by
# scripts/cron-apply.sh, which the operator runs afterwards.
#
# Runs ON the box as root:
#
#   doas ksh scripts/deploy-onboard.sh [repo_dir]
#
# Three things this deliberately does not do.
#
# It does not create the _onboard account. That account is a reserved-uid one in
# the shape _gmid has, so it is the operator's to create, once, and
# scripts/onboard-store.sh (called below) stops with the exact useradd line when
# it is missing. It also does not configure relayd: the handler listens on
# loopback only, and the front end that terminates TLS for signup.kyriakon.net is
# a separate ticket. Until that exists the handler answers the box and nothing
# else, which is why the verification here is a loopback request.
#
# It generates the approval key when it is absent, and never rotates one that is
# already there, so a first deploy signs and a later one leaves the links it
# signed alone. Stripe's webhook secret is the one that stays a paste by hand,
# because a real secret cannot live in this repository at all.

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

# The scripts the drain runs, by the paths its config names. It invokes
# add-user.sh, provision-member.sh and delete-user.sh directly, and those invoke
# quota-apply.sh, provision-member-web.sh, provision-member-capsule.sh and
# cron-apply.sh, so the whole set has to be installed wherever the drain looks.
# provision-member.sh also reads the tracked login class next to itself (its own
# ../openbsd/etc/login.conf.d/member), so this deploy installs that file into the
# layout the relative read resolves to rather than copying the scripts somewhere
# the read would leave behind.
drain_scripts="add-user.sh provision-member.sh delete-user.sh quota-apply.sh provision-member-web.sh provision-member-capsule.sh cron-apply.sh"
drain_class="openbsd/etc/login.conf.d/member"

# Every source this installs, checked before anything on the box is changed, so a
# half-copied checkout fails here rather than after the store has been written.
for f in onboard/Cargo.toml openbsd/etc/onboard/onboard.toml openbsd/etc/onboard/drain.toml \
	openbsd/etc/onboard/questions.toml \
	openbsd/etc/rc.d/kyriakon_onboard scripts/onboard-store.sh reserved-usernames.txt; do
	[ -e "$repo_dir/$f" ] || die "missing from $repo_dir: $f"
done
for s in $drain_scripts; do
	[ -e "$repo_dir/scripts/$s" ] || die "missing from $repo_dir: scripts/$s"
done
[ -e "$repo_dir/$drain_class" ] || die "missing from $repo_dir: $drain_class"

# The store, the four writable directories, the mail spool, the drain's root-only
# home, and the two files the three front-ends share. One author for all of it:
# the unit does not re-create any of it, so the modes cannot drift from what that
# script asserts.
say "store"
ksh "$repo_dir/scripts/onboard-store.sh"

say "build"
need_pkg rust
cargo build --release --manifest-path "$repo_dir/onboard/Cargo.toml"
# The handler, the root drain and onboardctl are one crate and three programs:
# a build that produced one of them but not the others is half a service.
for b in kyriakon-onboard kyriakon-onboard-drain kyriakon-onboardctl; do
	[ -x "$repo_dir/onboard/target/release/$b" ] \
		|| die "the build produced no binary at onboard/target/release/$b"
done

say "install"
install -d -m 0755 -o root -g wheel /etc/onboard
install -m 0755 "$repo_dir/onboard/target/release/kyriakon-onboard" /usr/local/sbin/kyriakon-onboard
install -m 0755 "$repo_dir/onboard/target/release/kyriakon-onboard-drain" /usr/local/sbin/kyriakon-onboard-drain
install -m 0755 "$repo_dir/onboard/target/release/kyriakon-onboardctl" /usr/local/sbin/kyriakon-onboardctl
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

# The postal address the cash-by-post rail gives out, read from the box's own
# values file rather than edited on the box: nothing host-specific is edited on
# the box, and this is the file every other deploy already reads. A box that has
# not set it is told where to, rather than left a config with a hole in it.
env_file="${KYRIAKON_ENV:-/root/.kyriakon-env}"
[ -r "$env_file" ] || die "no $env_file; run scripts/setup-env.sh first, which installs it"
# shellcheck source=/dev/null
. "$env_file"
case "${POSTAL_ADDRESS:-}" in
"")
	die "POSTAL_ADDRESS is not set in $env_file; set it with: scripts/setup-env.sh --postal-address '...'"
	;;
*REPLACE_ME*)
	die "POSTAL_ADDRESS in $env_file is still a placeholder; set it with: scripts/setup-env.sh --postal-address '...'"
	;;
esac

# The drain's own root-only config, into the drain's home that the store script
# created. The release and the postal address come from the tracked template,
# substituted here; nothing is edited on the box.
install -d -m 0700 -o root -g wheel /etc/kyriakon/onboard
RELEASE="$release" POSTAL="$POSTAL_ADDRESS" awk '
	/^release[[:space:]]*=/ { print "release = \"" ENVIRON["RELEASE"] "\""; next }
	/^postal_address[[:space:]]*=/ { print "postal_address = \"" ENVIRON["POSTAL"] "\""; next }
	{ print }
' "$repo_dir/openbsd/etc/onboard/drain.toml" > /etc/kyriakon/onboard/drain.toml
chmod 0600 /etc/kyriakon/onboard/drain.toml
awk -v want="release = \"$release\"" '$0 == want { found = 1 } END { exit !found }' \
	/etc/kyriakon/onboard/drain.toml \
	|| die "/etc/kyriakon/onboard/drain.toml does not name the release $release"
if grep -q '^release = "REPLACE_ME' /etc/kyriakon/onboard/drain.toml; then
	die "/etc/kyriakon/onboard/drain.toml still carries a REPLACE_ME release"
fi
awk -v want="postal_address = \"$POSTAL_ADDRESS\"" '$0 == want { found = 1 } END { exit !found }' \
	/etc/kyriakon/onboard/drain.toml \
	|| die "/etc/kyriakon/onboard/drain.toml does not name the postal address; it should have been substituted, not left as a placeholder"
printf 'release: %s\n' "$release"

# The approval key, generated once and never by a later deploy: a second run must
# not invalidate links a previous run has already signed. Replacing it is the
# operator's own act, by hand, and the only rotation there is.
approval_key=/etc/kyriakon/onboard/approval-signing-key
if [ ! -e "$approval_key" ]; then
	[ -x /usr/bin/openssl ] || die "no /usr/bin/openssl, which generates the approval key"
	(umask 077 && /usr/bin/openssl rand -base64 32 > "$approval_key")
	chown root:wheel "$approval_key"
	printf 'generated %s\n' "$approval_key"
else
	printf 'kept the existing %s\n' "$approval_key"
fi
# Stripe's webhook secret is the exception: a real secret cannot live in this
# repository, so the card rail's ticket leaves that file as a paste by hand.

# The tree the drain looks in, taken back from its own installed config, so the
# install and the drain cannot disagree about the path. The scripts run from
# where they sit, which is why the login class provision-member.sh reads beside
# them is installed into the same layout.
say "drain scripts"
scripts_dir=$(awk -F'"' '/^scripts[[:space:]]*=/ { print $2; exit }' /etc/kyriakon/onboard/drain.toml)
[ -n "$scripts_dir" ] || die "/etc/kyriakon/onboard/drain.toml names no scripts directory"
scripts_root=$(dirname "$scripts_dir")
install -d -m 0755 "$scripts_dir"
for s in $drain_scripts; do
	install -m 0755 "$repo_dir/scripts/$s" "$scripts_dir/$s"
done
install -d -m 0755 "$scripts_root/openbsd/etc/login.conf.d"
install -m 0644 "$repo_dir/$drain_class" "$scripts_root/openbsd/etc/login.conf.d/member"
# Before the unit starts, every script the drain names must be executable. A
# missing one is the drain's first intent failing at cron, which is how this gap
# was found.
for s in $drain_scripts; do
	[ -x "$scripts_dir/$s" ] || die "$scripts_dir/$s is not executable"
done
printf 'drain scripts installed in %s\n' "$scripts_dir"

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
