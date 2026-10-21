#!/bin/ksh
# deploy-onboard.sh: put the onboarding service on the box and start its handler.
#
# The release's front door, installed from this repository: the store under
# /var/db/onboard, the four binaries built from onboard/ and installed to
# /usr/local/sbin (the handler, the root drain, onboardctl and the portal), the
# handler's config at /etc/onboard/onboard.toml and the drain's own root-only
# config at /etc/kyriakon/onboard/drain.toml, both with the deployed release
# substituted, and the rc.d unit. Every step is idempotent, so a rebuild, or a
# second run after a fix, is one command.
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
# it is missing. It also does not configure the front-ends: httpd's vhost and
# gmid's block are installed by their own deploys, and relayd terminates TLS for
# every name ahead of them. What this script does is create the socket
# directories those two configs name, because the service binds the sockets and
# cannot create the directory inside another daemon's chroot itself; the
# verification at the end is then the sockets existing with the modes that keep
# every other local user out.
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
# add-user.sh, provision-member.sh, delete-user.sh and publish-mail-key.sh
# directly, and those invoke quota-apply.sh, provision-member-web.sh,
# provision-member-capsule.sh and cron-apply.sh, so the whole set has to be
# installed wherever the drain looks.
# provision-member.sh also reads the tracked login class next to itself (its own
# ../openbsd/etc/login.conf.d/member), so this deploy installs that file into the
# layout the relative read resolves to rather than copying the scripts somewhere
# the read would leave behind.
drain_scripts="add-user.sh provision-member.sh delete-user.sh quota-apply.sh provision-member-web.sh provision-member-capsule.sh cron-apply.sh publish-mail-key.sh set-mail-password.sh"
drain_class="openbsd/etc/login.conf.d/member"

# The service's own account, which scripts/onboard-store.sh refuses to create and
# names the useradd line for: the socket directories below are owned by it,
# because it is the account that binds the sockets inside them.
onboard_user='_onboard'

# Every source this installs, checked before anything on the box is changed, so a
# half-copied checkout fails here rather than after the store has been written.
for f in onboard/Cargo.toml openbsd/etc/onboard/onboard.toml openbsd/etc/onboard/drain.toml \
	onboard/questions.toml \
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
# The publish path is a shell client rather than the binary: publish-mail-key.sh
# opens the change with curl and encodes the key with jq, so the deploy that
# installs the drain is what installs them. jq is not a convenience here, it is
# the only base64 encoder on the box: OpenBSD ships no base64(1).
need_pkg curl
need_pkg jq
cargo build --release --manifest-path "$repo_dir/onboard/Cargo.toml"
# The handler, the root drain, onboardctl and the portal are one crate and four
# programs: a build that produced some of them but not the others is half a
# service. The portal is the one the applicant's ssh session runs, so a build
# without it would install nothing the login class names and every connection
# would land on a file that is not there.
for b in kyriakon-onboard kyriakon-onboard-drain kyriakon-onboardctl kyriakon-onboard-tui; do
	[ -x "$repo_dir/onboard/target/release/$b" ] \
		|| die "the build produced no binary at onboard/target/release/$b"
done

say "install"
install -d -m 0755 -o root -g wheel /etc/onboard
install -m 0755 "$repo_dir/onboard/target/release/kyriakon-onboard" /usr/local/sbin/kyriakon-onboard
install -m 0755 "$repo_dir/onboard/target/release/kyriakon-onboard-drain" /usr/local/sbin/kyriakon-onboard-drain
install -m 0755 "$repo_dir/onboard/target/release/kyriakon-onboardctl" /usr/local/sbin/kyriakon-onboardctl
# The portal, at the path openbsd/etc/login.conf.d/onboard names as the session's
# shell and openbsd/etc/sshd_config.onboard pins with ForceCommand. It also
# replaces the ksh program that path held, which left the repository in #373: the
# same path and one file, so no session can reach the retired program and no
# fallback runs it.
install -m 0755 "$repo_dir/onboard/target/release/kyriakon-onboard-tui" /usr/local/sbin/kyriakon-onboard-tui
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

# The keyring publish token, the other credential a deploy cannot generate: a
# fine-grained token for the public repository with contents and pull requests
# and nothing else, which publish-mail-key.sh opens an approved member's key
# with. Like the webhook secret it is a paste by hand, so a box without it is
# deployed rather than refused, and the publish path reports its own failure
# until it is there. What is checked here is the shape the entry has to keep: a
# token another local user could read is a token that can write the published
# set, which is the repository the whole audit trail rests on.
publish_token=/etc/kyriakon/onboard/keyring-publish-token
if [ -e "$publish_token" ]; then
	[ "$(stat -f '%Lp' "$publish_token")" = 600 ] \
		|| die "$publish_token is not mode 600"
	[ "$(stat -f '%Su' "$publish_token")" = root ] \
		|| die "$publish_token is not owned by root"
	printf 'kept the existing %s\n' "$publish_token"
else
	printf 'no %s yet, so an approval will report a failed publish until it is\n' "$publish_token"
	printf 'there and the drift check will alert seven days later. Install one as root:\n'
	printf '  doas install -m 600 -o root -g wheel <token-file> %s\n' "$publish_token"
fi

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
# The drain's scripts source lib.sh only from inside --self-test, so the live path
# keeps no dependency on it. It is installed here for the same reason the scripts
# are: so one of them can answer --self-test on the box, where the checkout may
# be older than this deploy.
install -m 0755 "$repo_dir/scripts/lib.sh" "$scripts_dir/lib.sh"
install -d -m 0755 "$scripts_root/openbsd/etc/login.conf.d"
install -m 0644 "$repo_dir/$drain_class" "$scripts_root/openbsd/etc/login.conf.d/member"
# Before the unit starts, every script the drain names must be executable. A
# missing one is the drain's first intent failing at cron, which is how this gap
# was found.
for s in $drain_scripts; do
	[ -x "$scripts_dir/$s" ] || die "$scripts_dir/$s is not executable"
done
printf 'drain scripts installed in %s\n' "$scripts_dir"

# The two socket paths, read from the installed config rather than written here,
# so the directories this script creates and the check at the end are the ones the
# service itself uses: a box whose paths were changed is deployed to where it
# answers.
socket_path() {
	awk -F'"' -v key="$1" '$1 ~ "^" key "[[:space:]]*=" { print $2; exit }' \
		/etc/onboard/onboard.toml
}
httpd_socket_path=$(socket_path httpd_socket)
gemini_socket_path=$(socket_path gemini_socket)
[ -n "$httpd_socket_path" ] || die "/etc/onboard/onboard.toml names no httpd_socket"
[ -n "$gemini_socket_path" ] || die "/etc/onboard/onboard.toml names no gemini_socket"

# The two socket directories, inside the chroot the two front-ends share. Both the
# paths and the chroot are the installed config's: this service borrows a
# directory inside httpd's and gmid's chroot because a FastCGI socket path is
# resolved inside it, and a layout that moves the chroot moves these with it.
#
# One directory per socket rather than one for both, because a socket file's group
# is what decides which daemon may connect and a directory's set-group-id bit can
# carry one group. Without the bit the socket would take _onboard's own group and
# neither www nor _gmid could reach it. Nothing else may connect: a local user who
# could would forge the request environment, REMOTE_ADDR among it.
say "sockets"
for pair in "www:$httpd_socket_path" "_gmid:$gemini_socket_path"; do
	group=${pair%%:*}
	dir=$(dirname "${pair#*:}")
	install -d -o "$onboard_user" -g "$group" -m 2770 "$dir"
	[ -g "$dir" ] || die "$dir is not set-group-id, so the socket in it would not carry $group"
	[ "$(stat -f '%Su %Sg' "$dir")" = "$onboard_user $group" ] \
		|| die "$dir is not $onboard_user:$group"
	printf '%s (%s, 2770)
' "$dir" "$group"
done

say "service"
rcctl enable kyriakon_onboard
if rcctl check kyriakon_onboard >/dev/null 2>&1; then
	rcctl restart kyriakon_onboard
else
	rcctl start kyriakon_onboard
fi
rcctl check kyriakon_onboard >/dev/null 2>&1 \
	|| die "kyriakon_onboard did not come up; check /var/log/daemon"

# The sockets, taken from the installed config rather than assumed, so a box whose
# paths were changed is checked where they are. A responder that came up but could
# not bind is a service no front-end can reach, and this is what says so without a
# front-end in the path: each file is a socket, and its mode is the one that keeps
# every other local user out. The pages themselves are checked by the front-ends'
# own deploys, which are the only things that can ask for one.
say "verify"
for pair in "httpd:$httpd_socket_path" "gemini:$gemini_socket_path"; do
	front=${pair%%:*}
	path=${pair#*:}
	[ -S "$path" ] || die "$path is not a socket: is kyriakon_onboard running, and is its directory there?"
	[ "$(stat -f '%Lp' "$path")" = "660" ] || die "$path is not mode 660"
	printf '%s: %s\n' "$front" "$path"
done

printf '\ninstalled. the responder answers %s and %s, and no other local user may connect.\n' \
	"$httpd_socket_path" "$gemini_socket_path"
printf 'httpd and gmid reach it from their own configs, which their own deploys install.\n'
printf 'relayd terminates TLS for signup.kyriakon.net and sets the forwarded address\n'
printf 'the counters key on.\n'
