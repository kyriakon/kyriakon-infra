#!/bin/ksh
# deploy-control.sh: put the control plane on the box and start its handler.
#
# The release's front door, installed from this repository: the store under
# /var/db/onboard, the four binaries built from control/ and installed to
# /usr/local/sbin (the handler, the root drain, kyriakon-admin and the portal), the
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
#   doas ksh scripts/deploy-control.sh [repo_dir]
#        ksh scripts/deploy-control.sh --self-test [repo_root]
#
# Three things this deliberately does not do.
#
# It does not create the _onboard account. That account is a reserved-uid one in
# the shape _gmid has, so it is the operator's to create, once, and
# scripts/control-store.sh (called below) stops with the exact useradd line when
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
install_set="$script_dir/install-set.tsv"

# shellcheck disable=SC1091 # resolves at runtime from this script's directory
. "$script_dir/lib.sh"

# --- self-test ---------------------------------------------------------------

# The script names the drain's Rust invokes with `run_script(cfg, "…")` and its
# two siblings, read from the source rather than a second list that can drift.
# The transition bodies live under crates/drain/src/transitions/, so the scan takes either
# that directory or one file (the self-test's fixture). A new `spawn_script` or
# `run_script` call needs a row in install-set.tsv, or this self-test fails.
drain_invoked() { # <src dir or .rs file>
	{
		if [ -d "$1" ]; then
			find "$1" -type f -name '*.rs' -exec cat {} +
		else
			cat "$1"
		fi
	} | tr '\n' ' ' \
		| grep -oE '(run_script|run_script_tolerating|spawn_script)\([[:space:]]*cfg,[[:space:]]*"[^"]+"' \
		| sed -E 's/.*"([^"]+)"/\1/' | sort -u
}

# The invoked names the drain's directory does not get. A missing one is a
# payment or an approval that fails on the box while every test here passes,
# which is how stripe-api.sh reached a merge.
missing_drain_scripts() { # <src dir or .rs file> <install-set table>
	invoked=$(drain_invoked "$1")
	# One line per row, which is what the table reader prints; the case below
	# compares space-separated words.
	installed=$(install_rows "$2" drain | tr '\n' ' ') || return 1
	for name in $invoked; do
		case " $installed " in
		*" $name "*) ;;
		*) printf '%s\n' "$name" ;;
		esac
	done
}

# The four names a box may still carry from before the control rename, each with
# the program that owns it now. Applied by hand are the login class's shell, the
# applicant sshd's ForceCommand and the crontab's drain line; until all three
# name the new paths these stay as symlinks.
old_names="kyriakon-onboard:kyriakon-control
kyriakon-onboard-drain:kyriakon-control-drain
kyriakon-onboardctl:kyriakon-admin
kyriakon-onboard-tui:kyriakon-control-tui"

# settle_old_names <bin dir> <yes|no>: with `no`, relink each old name that is
# present to its new program and print it, so the caller can say what is still
# pinned; with `yes`, remove every old name. A name absent already is left alone,
# so a fresh box gets no symlinks.
settle_old_names() { # <dir> <yes|no>
	for pair in $old_names; do
		old=${pair%%:*} new=${pair#*:}
		if [ "$2" = yes ]; then
			rm -f "$1/$old"
		elif [ -e "$1/$old" ]; then
			ln -sfn "$1/$new" "$1/$old"
			printf '%s\n' "$old"
		fi
	done
}

self_test() {
	repo=${1:-$(cd "$script_dir/.." && pwd)}
	src=$repo/control/crates/drain/src
	[ -d "$src" ] || {
		printf 'self-test: %s is missing\n' "$src" >&2
		exit 1
	}
	[ -f "$install_set" ] || {
		printf 'self-test: %s is missing\n' "$install_set" >&2
		exit 1
	}
	work=$(mktemp -d "${TMPDIR:-/tmp}/deploy-control.XXXXXX") || exit 1
	trap 'rm -rf "$work"' EXIT

	installed=$(install_rows "$install_set" drain)
	[ -n "$installed" ] || {
		printf 'self-test: %s names no drain scripts\n' "$install_set" >&2
		exit 1
	}

	if missing=$(missing_drain_scripts "$src" "$install_set") \
		&& [ -n "$missing" ]; then
		printf 'self-test: the drain invokes scripts this deploy does not install:\n%s\n' \
			"$missing" >&2
		exit 1
	fi

	# The check has to see a missing name, or it proves nothing: here the source
	# invokes one the table has no row for.
	printf 'fn fixture(cfg: &DrainConfig) { let _ = spawn_script(cfg, "not-installed.sh", &[]); }\n' \
		> "$work/fixture.rs"
	if ! missing_drain_scripts "$work/fixture.rs" "$install_set" \
		| grep -qx 'not-installed.sh'; then
		printf 'self-test: the check did not see a missing script\n' >&2
		exit 1
	fi

	# And a table with no drain rows installs nothing, so every invoked name is a
	# finding rather than a pass on an empty list.
	invoked_count=$(drain_invoked "$src" | grep -c .)
	: > "$work/empty.tsv"
	reported=$(missing_drain_scripts "$src" "$work/empty.tsv" | grep -c .)
	[ "$invoked_count" -gt 0 ] && [ "$reported" -eq "$invoked_count" ] || {
		printf 'self-test: a table with no drain rows reported %s of %s invoked scripts\n' \
			"$reported" "$invoked_count" >&2
		exit 1
	}

	# need_pkg asks with -e and installs with -I. Both matter: `pkg_info -q`
	# printed a version, matched nothing, and reinstalled every package on every
	# deploy, and plain pkg_add asks on a tty, so the dispatcher waited at a
	# prompt that reads as a hung fetch. The two binaries are stubbed.
	mkdir "$work/bin"
	cat > "$work/bin/pkg_info" <<'STUB'
#!/bin/sh
# Args are -q -e <pattern>. present.sh is installed under its own name;
# versioned is installed as versioned-1.2, which only the name-* query matches.
case "${3:-}" in
present.sh) exit 0 ;;
versioned-*) exit 0 ;;
esac
exit 1
STUB
	cat > "$work/bin/pkg_add" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$PKG_ADD_LOG"
STUB
	chmod +x "$work/bin/pkg_info" "$work/bin/pkg_add"
	PKG_ADD_LOG="$work/pkg_add.log"
	export PKG_ADD_LOG
	# shellcheck disable=SC2030,SC2031 # the stub PATH is for this call only
	if ! ( PATH="$work/bin:$PATH"; need_pkg present.sh ) >"$work/pkg.out" 2>&1; then
		printf 'self-test: need_pkg failed on an installed package\n' >&2
		exit 1
	fi
	[ ! -e "$work/pkg_add.log" ] || {
		printf 'self-test: need_pkg installed an installed package\n' >&2
		exit 1
	}
	# shellcheck disable=SC2030,SC2031 # as above
	if ! ( PATH="$work/bin:$PATH"; need_pkg absent.sh ) >"$work/pkg-absent.out" 2>&1; then
		printf 'self-test: need_pkg failed on a missing package\n' >&2
		exit 1
	fi
	grep -qx -- '-I absent.sh' "$work/pkg_add.log" || {
		printf 'self-test: need_pkg did not install without questions: %s\n' \
			"$(cat "$work/pkg_add.log" 2>/dev/null)" >&2
		exit 1
	}
	# A package installed under a versioned name is what the name-* query is
	# for: asking only for the bare name would reinstall it on every deploy.
	# Deleting that fallback fails this check.
	: >"$work/pkg_add.log"
	# shellcheck disable=SC2030,SC2031 # the stub PATH is for this call only
	if ! ( PATH="$work/bin:$PATH"; need_pkg versioned ) >"$work/pkg-version.out" 2>&1; then
		printf 'self-test: need_pkg failed on a versioned package\n' >&2
		exit 1
	fi
	[ ! -s "$work/pkg_add.log" ] || {
		printf 'self-test: need_pkg reinstalled a versioned package: %s\n' \
			"$(cat "$work/pkg_add.log")" >&2
		exit 1
	}

	# The rename's compatibility step. A box with the old names still linked must
	# keep them until the three hand-applied paths are updated, and a settled box
	# must lose them; getting the direction wrong takes the portal down for a live
	# session or leaves the old names forever.
	mkdir "$work/sbin"
	for new in kyriakon-control kyriakon-control-drain kyriakon-admin kyriakon-control-tui; do
		printf '#!/bin/sh\n' >"$work/sbin/$new"
	done
	for old in kyriakon-onboard kyriakon-onboard-drain kyriakon-onboardctl kyriakon-onboard-tui; do
		printf 'old\n' >"$work/sbin/$old"
	done
	kept=$(settle_old_names "$work/sbin" no)
	[ "$(printf '%s\n' "$kept" | grep -c .)" -eq 4 ] || {
		printf 'self-test: the unsettled deploy kept %s of 4 old names\n' \
			"$(printf '%s\n' "$kept" | grep -c .)" >&2
		exit 1
	}
	[ "$(readlink "$work/sbin/kyriakon-onboard-drain")" = "$work/sbin/kyriakon-control-drain" ] || {
		printf 'self-test: an old name does not point at its new program\n' >&2
		exit 1
	}
	settle_old_names "$work/sbin" yes >/dev/null
	for old in kyriakon-onboard kyriakon-onboard-drain kyriakon-onboardctl kyriakon-onboard-tui; do
		[ ! -e "$work/sbin/$old" ] && [ ! -L "$work/sbin/$old" ] || {
			printf 'self-test: a settled deploy left %s behind\n' "$old" >&2
			exit 1
		}
	done

	printf 'self-test: ok\n'
}

case "${1:-}" in
--self-test)
	[ "$#" -le 2 ] || {
		printf 'usage: ksh %s --self-test [repo_root]\n' "$0" >&2
		exit 2
	}
	self_test "${2:-}"
	exit 0
	;;
esac

repo_dir="${1:-$(cd "$script_dir/.." && pwd)}"

# The two configs below are written to a candidate and renamed. A write that
# fails part way leaves a truncated config, and a partial onboard.toml is a
# handler that refuses to start, which is the fault #423 fixed at the other
# write sites.
trap 'rm -f "${onboard_candidate:-}" "${drain_candidate:-}"' EXIT

[ "$(id -u)" -eq 0 ] || { printf 'run as root (doas ksh %s)\n' "$0" >&2; exit 1; }

say() { printf '== %s\n' "$*"; }
die() { printf '%s: %s\n' "$0" "$*" >&2; exit 1; }

# The scripts the drain runs, read from the install-set table's drain rows. The
# set has to cover everything the drain's Rust invokes and what those scripts in
# turn run, because they run from the drain's directory and nowhere else: it
# invokes add-user.sh, provision-member.sh, delete-user.sh, publish-mail-key.sh,
# remove-upload-key.sh, stripe-api.sh, provision-group-web.sh,
# provision-group-capsule.sh, provision-group-acme.sh, remove-group.sh and
# reload-smtpd.sh directly, and those invoke quota-apply.sh,
# provision-member-web.sh, provision-member-capsule.sh, provision-member-acme.sh
# and cron-apply.sh. relayd-members.sh is there because cron-apply.sh --web runs
# it to rewrite /etc/relayd.conf's member keypair region, from the directory
# cron-apply.sh sits in, and lib.sh because every one of them sources it.
# provision-member.sh and lapse-user.sh also read the tracked login classes next
# to themselves (their own ../openbsd/etc/login.conf.d/member and lapsed), so this
# deploy installs both files into the layout the relative read resolves to rather
# than copying the scripts somewhere the read would leave behind.
drain_scripts=$(install_rows "$install_set" drain) \
	|| die "cannot read $install_set"
[ -n "$drain_scripts" ] || die "$install_set names no drain scripts"
drain_class="openbsd/etc/login.conf.d/member"
drain_lapsed_class="openbsd/etc/login.conf.d/lapsed"

# The service's own account, which scripts/control-store.sh refuses to create and
# names the useradd line for: the socket directories below are owned by it,
# because it is the account that binds the sockets inside them.
onboard_user='_onboard'

# Every source this installs, checked before anything on the box is changed, so a
# half-copied checkout fails here rather than after the store has been written.
for f in control/Cargo.toml openbsd/etc/onboard/onboard.toml openbsd/etc/onboard/drain.toml \
	control/questions.toml \
	openbsd/etc/rc.d/kyriakon_control scripts/control-store.sh scripts/render-docs.sh \
	scripts/kyriakon-authcheck.sh openbsd/etc/doas.conf.control \
	docs/terms.md docs/privacy.md docs/aup.md docs/key-walkthrough.md \
	reserved-usernames.txt; do
	[ -e "$repo_dir/$f" ] || die "missing from $repo_dir: $f"
done
for s in $drain_scripts; do
	[ -e "$repo_dir/scripts/$s" ] || die "missing from $repo_dir: scripts/$s"
done
[ -e "$repo_dir/$drain_class" ] || die "missing from $repo_dir: $drain_class"
[ -e "$repo_dir/$drain_lapsed_class" ] || die "missing from $repo_dir: $drain_lapsed_class"

# The store, the four writable directories, the mail spool, the drain's root-only
# home, and the two files the three front-ends share. One author for all of it:
# the unit does not re-create any of it, so the modes cannot drift from what that
# script asserts.
say "store"
ksh "$repo_dir/scripts/control-store.sh"

# The portal's own state: one lock file per live session, created and removed by
# the program as `hello`. It is not under the store because `_onboard` owns that
# and the portal must not be able to read it. The account is the operator's to
# create, like `_onboard`. A box whose account is still named `onboard` gets the
# socket directory under `_onboard`'s group and a warning rather than a deploy that
# stops: the handler must still start for every other part of the service, and the
# rename plus a rerun moves the socket to the portal's group.
say "portal state"
if id hello >/dev/null 2>&1; then
	# The group is the account's own, not the word "hello": the live box reaches
	# it by renaming the old account, and a rename leaves the group's name behind.
	portal_group=$(id -gn hello)
	install -d -o hello -g "$portal_group" -m 0700 /var/db/kyriakon-onboard-tui
else
	portal_group=$onboard_user
	printf 'hello account missing; the portal cannot start until it exists, and this deploy must be rerun after the rename\n' >&2
fi

say "build"
# The rows for this deploy are in openbsd/packages.tsv, including rust, curl and
# jq for the publish path, and gmid for the capsule socket directory.
need_packages "$repo_dir/openbsd/packages.tsv" deploy-control.sh
cargo build --release --manifest-path "$repo_dir/control/Cargo.toml"
# The handler, the root drain, kyriakon-admin and the portal are one crate and four
# programs: a build that produced some of them but not the others is half a
# service. The portal is the one the applicant's ssh session runs, so a build
# without it would install nothing the login class names and every connection
# would land on a file that is not there.
for b in kyriakon-control kyriakon-control-drain kyriakon-admin kyriakon-control-tui; do
	[ -x "$repo_dir/control/target/release/$b" ] \
		|| die "the build produced no binary at control/target/release/$b"
done

say "install"
install -d -m 0755 -o root -g wheel /etc/onboard
install -m 0755 "$repo_dir/control/target/release/kyriakon-control" /usr/local/sbin/kyriakon-control
install -m 0755 "$repo_dir/control/target/release/kyriakon-control-drain" /usr/local/sbin/kyriakon-control-drain
install -m 0755 "$repo_dir/control/target/release/kyriakon-admin" /usr/local/sbin/kyriakon-admin
# The portal, at the path openbsd/etc/login.conf.d/hello names as the session's
# shell and openbsd/etc/sshd_config.onboard pins with ForceCommand. It also
# replaces the ksh program that path held, which left the repository in #373: the
# same path and one file, so no session can reach the retired program and no
# fallback runs it.
install -m 0755 "$repo_dir/control/target/release/kyriakon-control-tui" /usr/local/sbin/kyriakon-control-tui
install -m 0755 "$repo_dir/openbsd/etc/rc.d/kyriakon_control" /etc/rc.d/kyriakon_control

# Three paths applied by hand still name the old programs: the login class's
# shell, sshd_config.onboard's ForceCommand, and the crontab's drain line. The
# operator changes those a deploy or two after this one. Until every one of them
# names the new path, the old name stays a symlink, so an applicant's session
# does not die on a missing file and settlement keeps running. Once all three
# name it, the links go and the box holds one name per program.
settled=no
if grep -q kyriakon-control-tui /etc/login.conf.d/hello 2>/dev/null &&
	grep -q kyriakon-control-tui /etc/ssh/sshd_config.onboard 2>/dev/null &&
	crontab -l 2>/dev/null | grep -q kyriakon-control-drain; then
	settled=yes
fi
kept=$(settle_old_names /usr/local/sbin "$settled")
if [ -n "$kept" ]; then
	printf 'the old program names stay as symlinks until all three are done:\n'
	printf '  install openbsd/etc/login.conf.d/hello and run doas cap_mkdb /etc/login.conf\n'
	printf '  install the rendered sshd_config.onboard (scripts/deploy.sh prints the\n'
	printf '  install line) and reload kyriakon_onboard_sshd\n'
	printf '  run scripts/cron-apply.sh so cron runs kyriakon-control-drain\n'
	printf 'then run this deploy again to remove the links\n'
fi

# The old unit is the one running, and the new one binds the same sockets, so it
# is stopped and removed here rather than left for the operator: a deploy that
# enabled the new unit first would fail its own health check against a socket the
# old process still held. The file is this repository's, installed by hand from
# openbsd/etc/rc.d, so removing it is the same act as installing its replacement.
if [ -e /etc/rc.d/kyriakon_onboard ]; then
	rcctl stop kyriakon_onboard >/dev/null 2>&1 || true
	rcctl disable kyriakon_onboard >/dev/null 2>&1 || true
	rm -f /etc/rc.d/kyriakon_onboard
	say "the old unit kyriakon_onboard is removed; kyriakon_control takes over below"
fi

# The login check: the one fixed-argument program the account page may run as
# root. It takes a username and the proof directory, reads the password from
# stdin and runs only `doveadm auth test`. doas.conf cannot name the check's
# arguments (they are the username), so it names this program, and the program
# is what keeps the subcommand fixed and mints the login proof.
install -d -m 0755 -o root -g wheel /usr/local/libexec
# lib.sh sits beside it because the checker sources valid_localpart from there.
# It is a 0644 source file, not a program, so it adds nothing the doas rule can
# run: the rule still names only /usr/local/libexec/kyriakon-authcheck.
install_staged "$repo_dir/scripts/lib.sh" /usr/local/libexec/lib.sh -m 0644
install_staged "$repo_dir/scripts/kyriakon-authcheck.sh" /usr/local/libexec/kyriakon-authcheck -m 0755

# The login proofs: one file per admitted login, named by a random token, written
# by the checker as root and read back by the drain. Root-owned 0700 is the whole
# point: the handler writes its own session records, so a proof it could write
# or replace would prove nothing. install -d creates the missing parent too.
install -d -m 0755 -o root -g wheel /var/db/kyriakon
install -d -m 0700 -o root -g wheel /var/db/kyriakon/logins

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

# The values the recipe is generated from, read from the box's own values file
# and its tracked zone rather than restated in the repository. The postal address
# is the cash-by-post rail's; the rest are the public DNS values a body copies.
# Nothing host-specific is edited on the box.
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
case "${KYRIAKON_IPV4:-}" in
"" | *REPLACE_ME*)
	die "KYRIAKON_IPV4 is not set in $env_file; set the box's IPv4 there"
	;;
esac
# The card rail's Payment Link, created in the Stripe dashboard. It is a live
# object's URL, so it comes from the box's values file like the postal address
# and is never a literal in this repository.
case "${STRIPE_PAYMENT_LINK:-}" in
"")
	die "STRIPE_PAYMENT_LINK is not set in $env_file; add the Payment Link's URL from the Stripe dashboard"
	;;
*REPLACE_ME*)
	die "STRIPE_PAYMENT_LINK in $env_file is still a placeholder; replace it with the Payment Link's URL"
	;;
esac
# The URL is written into a TOML string, so its charset is bounded rather than
# trusted: a quote or a newline from a paste would break the config.
printf '%s' "$STRIPE_PAYMENT_LINK" | grep -Eq '^https://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+$' ||
	die "STRIPE_PAYMENT_LINK in $env_file is not a plain https URL"
# The group's own Payment Link, a separate Stripe object because a body's year
# is its own price. Same rules as the person's link.
case "${STRIPE_GROUP_PAYMENT_LINK:-}" in
"")
	die "STRIPE_GROUP_PAYMENT_LINK is not set in $env_file; add the group Payment Link's URL from the Stripe dashboard"
	;;
*REPLACE_ME*)
	die "STRIPE_GROUP_PAYMENT_LINK in $env_file is still a placeholder; replace it with the group Payment Link's URL"
	;;
esac
printf '%s' "$STRIPE_GROUP_PAYMENT_LINK" | grep -Eq '^https://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+$' ||
	die "STRIPE_GROUP_PAYMENT_LINK in $env_file is not a plain https URL"
case "${KYRIAKON_IPV6:-}" in
"" | *REPLACE_ME*)
	die "KYRIAKON_IPV6 is not set in $env_file; set the box's IPv6 there"
	;;
esac

# The DKIM selector and public key are the ones the tracked zone publishes, read
# here rather than copied into a config: a second copy would keep publishing
# after a rotation and nothing would fail. The record is two adjacent quoted
# strings, so the quoted parts are concatenated and the zone's own base64 is
# what lands.
dkim_selector=$(
	awk '
		/^[a-z0-9-]+\._domainkey[[:space:]]+IN[[:space:]]+TXT/ {
			sub(/\._domainkey.*/, "")
			print
			exit
		}
	' "$repo_dir/openbsd/etc/nsd/kyriakon.net.zone"
)
case "$dkim_selector" in
"" | *REPLACE_ME*)
	die "cannot read the DKIM selector from $repo_dir/openbsd/etc/nsd/kyriakon.net.zone"
	;;
esac
dkim_public_key=$(
	awk -v sel="$dkim_selector" '
		index($0, sel "._domainkey") == 1 { found = 1 }
		found {
			text = $0
			while (match(text, /"[^"]*"/)) {
				printf "%s", substr(text, RSTART + 1, RLENGTH - 2)
				text = substr(text, RSTART + RLENGTH)
			}
			if ($0 ~ /\)/) exit
		}
	' "$repo_dir/openbsd/etc/nsd/kyriakon.net.zone"
)
case "$dkim_public_key" in
v=DKIM1*)
	;;
*)
	die "cannot read the DKIM public key from $repo_dir/openbsd/etc/nsd/kyriakon.net.zone"
	;;
esac

# The price the pages show is read from the drain's own config rather than
# repeated here: the Stripe Price and the prepaid price have to agree, and two
# copies of the number can disagree.
price_gbp=$(
	awk -F'"' '/^price_gbp[[:space:]]*=/ { print $2; exit }' \
		"$repo_dir/openbsd/etc/onboard/drain.toml"
)
case "$price_gbp" in
"" | *REPLACE_ME*)
	die "cannot read price_gbp from $repo_dir/openbsd/etc/onboard/drain.toml"
	;;
esac

onboard_candidate=$(mktemp /etc/onboard/.onboard.toml.XXXXXX)
RELEASE="$release" PRICE="$price_gbp" POSTAL="$POSTAL_ADDRESS" LINK="$STRIPE_PAYMENT_LINK" GROUP_LINK="$STRIPE_GROUP_PAYMENT_LINK" IPV4="$KYRIAKON_IPV4" IPV6="$KYRIAKON_IPV6" SELECTOR="$dkim_selector" DKIM="$dkim_public_key" awk '
	/^release[[:space:]]*=/ { print "release = \"" ENVIRON["RELEASE"] "\""; next }
	/^price_gbp[[:space:]]*=/ { print "price_gbp = \"" ENVIRON["PRICE"] "\""; next }
	/^postal_address[[:space:]]*=/ { print "postal_address = \"" ENVIRON["POSTAL"] "\""; next }
	/^stripe_payment_link[[:space:]]*=/ { print "stripe_payment_link = \"" ENVIRON["LINK"] "\""; next }
	/^stripe_group_payment_link[[:space:]]*=/ { print "stripe_group_payment_link = \"" ENVIRON["GROUP_LINK"] "\""; next }
	/^ipv4[[:space:]]*=/ { print "ipv4 = \"" ENVIRON["IPV4"] "\""; next }
	/^ipv6[[:space:]]*=/ { print "ipv6 = \"" ENVIRON["IPV6"] "\""; next }
	/^dkim_selector[[:space:]]*=/ { print "dkim_selector = \"" ENVIRON["SELECTOR"] "\""; next }
	/^dkim_public_key[[:space:]]*=/ { print "dkim_public_key = \"" ENVIRON["DKIM"] "\""; next }
	{ print }
' "$repo_dir/openbsd/etc/onboard/onboard.toml" > "$onboard_candidate"
chmod 0644 "$onboard_candidate"

# The two ways this substitution goes wrong, both checked on the candidate: a
# config that still carries the placeholder (the handler refuses to start, which
# is deliberate and is why this is caught here first), and one where the line did
# not match and the file went out with no release at all.
awk -v want="release = \"$release\"" '$0 == want { found = 1 } END { exit !found }' \
	"$onboard_candidate" || die "/etc/onboard/onboard.toml does not name the release $release"
if awk '/REPLACE_ME/ { found = 1 } END { exit !found }' "$onboard_candidate"; then
	die "/etc/onboard/onboard.toml still carries a REPLACE_ME placeholder"
fi
mv "$onboard_candidate" /etc/onboard/onboard.toml

# The drain's own root-only config, into the drain's home that the store script
# created. The release, the postal address and the DNS values come from the
# tracked template, substituted here; nothing is edited on the box.
install -d -m 0700 -o root -g wheel /etc/kyriakon/onboard
drain_candidate=$(mktemp /etc/kyriakon/onboard/.drain.toml.XXXXXX)
RELEASE="$release" POSTAL="$POSTAL_ADDRESS" LINK="$STRIPE_PAYMENT_LINK" GROUP_LINK="$STRIPE_GROUP_PAYMENT_LINK" IPV4="$KYRIAKON_IPV4" IPV6="$KYRIAKON_IPV6" SELECTOR="$dkim_selector" DKIM="$dkim_public_key" awk '
	/^release[[:space:]]*=/ { print "release = \"" ENVIRON["RELEASE"] "\""; next }
	/^postal_address[[:space:]]*=/ { print "postal_address = \"" ENVIRON["POSTAL"] "\""; next }
	/^stripe_payment_link[[:space:]]*=/ { print "stripe_payment_link = \"" ENVIRON["LINK"] "\""; next }
	/^stripe_group_payment_link[[:space:]]*=/ { print "stripe_group_payment_link = \"" ENVIRON["GROUP_LINK"] "\""; next }
	/^ipv4[[:space:]]*=/ { print "ipv4 = \"" ENVIRON["IPV4"] "\""; next }
	/^ipv6[[:space:]]*=/ { print "ipv6 = \"" ENVIRON["IPV6"] "\""; next }
	/^dkim_selector[[:space:]]*=/ { print "dkim_selector = \"" ENVIRON["SELECTOR"] "\""; next }
	/^dkim_public_key[[:space:]]*=/ { print "dkim_public_key = \"" ENVIRON["DKIM"] "\""; next }
	{ print }
' "$repo_dir/openbsd/etc/onboard/drain.toml" > "$drain_candidate"
chmod 0600 "$drain_candidate"
awk -v want="release = \"$release\"" '$0 == want { found = 1 } END { exit !found }' \
	"$drain_candidate" \
	|| die "/etc/kyriakon/onboard/drain.toml does not name the release $release"
awk -v want="postal_address = \"$POSTAL_ADDRESS\"" '$0 == want { found = 1 } END { exit !found }' \
	"$drain_candidate" \
	|| die "/etc/kyriakon/onboard/drain.toml does not name the postal address; it should have been substituted, not left as a placeholder"
awk -v want="stripe_payment_link = \"$STRIPE_PAYMENT_LINK\"" '$0 == want { found = 1 } END { exit !found }' \
	"$drain_candidate" \
	|| die "/etc/kyriakon/onboard/drain.toml does not name the Payment Link; it should have been substituted, not left as a placeholder"
awk -v want="stripe_group_payment_link = \"$STRIPE_GROUP_PAYMENT_LINK\"" '$0 == want { found = 1 } END { exit !found }' \
	"$drain_candidate" \
	|| die "/etc/kyriakon/onboard/drain.toml does not name the group Payment Link; it should have been substituted, not left as a placeholder"
if grep -q 'REPLACE_ME' "$drain_candidate"; then
	die "/etc/kyriakon/onboard/drain.toml still carries a REPLACE_ME placeholder"
fi
mv "$drain_candidate" /etc/kyriakon/onboard/drain.toml
printf 'release: %s\n' "$release"

# The capsule's mirrored pages: the terms, the acceptable use policy, the privacy
# notice and the key walkthrough, rendered to gemtext from the same tracked
# sources the site publishes and staged where the installed config says the
# handler reads them. The renderer refuses a placeholder and an unsupported
# markdown construct, so a page that would reach a reader half-converted stops
# this deploy instead. The path comes from the config rather than being repeated
# here, for the reason that file gives for naming it at all.
say "pages"
pages_dir=$(awk -F'"' '/^pages[[:space:]]*=/ { print $2; exit }' /etc/onboard/onboard.toml)
[ -n "$pages_dir" ] || die "/etc/onboard/onboard.toml names no pages directory"
install -d -m 0755 -o root -g wheel "$pages_dir"
ksh "$repo_dir/scripts/render-docs.sh" --gemini "$pages_dir" --env "$env_file"
for page in terms.gmi aup.gmi privacy.gmi key-walkthrough.gmi; do
	[ -s "$pages_dir/$page" ] || die "$pages_dir/$page was not rendered"
done

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
	install_staged "$repo_dir/scripts/$s" "$scripts_dir/$s" -m 0755
done
# cron-apply.sh, installed above, reads this table to build the crontab, and it
# reads it from its own directory. Installing it here is what makes the deployed
# copy work; the checkout's copy is the one this run installs from.
install_staged "$repo_dir/scripts/install-set.tsv" "$scripts_dir/install-set.tsv" -m 0644
install -d -m 0755 "$scripts_root/openbsd/etc/login.conf.d"
install -m 0644 "$repo_dir/$drain_class" "$scripts_root/openbsd/etc/login.conf.d/member"
install -m 0644 "$repo_dir/$drain_lapsed_class" "$scripts_root/openbsd/etc/login.conf.d/lapsed"
# Before the unit starts, every script the drain names must be executable. A
# missing one is the drain's first intent failing at cron, which is how this gap
# was found.
for s in $drain_scripts; do
	[ -x "$scripts_dir/$s" ] || die "$scripts_dir/$s is not executable"
done
printf 'drain scripts installed in %s\n' "$scripts_dir"

# The socket paths and the Titan listener, read from the installed config rather
# than written here, so the directories this script creates and the check at the
# end are the ones the service itself uses: a box whose paths were changed is
# deployed to where it answers.
config_value() {
	awk -F'"' -v key="$1" '$1 ~ "^" key "[[:space:]]*=" { print $2; exit }' \
		/etc/onboard/onboard.toml
}
httpd_socket_path=$(config_value httpd_socket)
gemini_socket_path=$(config_value gemini_socket)
portal_socket_path=$(config_value portal_socket)
titan_listener=$(config_value titan_listener)
[ -n "$httpd_socket_path" ] || die "/etc/onboard/onboard.toml names no httpd_socket"
[ -n "$gemini_socket_path" ] || die "/etc/onboard/onboard.toml names no gemini_socket"
[ -n "$portal_socket_path" ] || die "/etc/onboard/onboard.toml names no portal_socket"
[ -n "$titan_listener" ] || die "/etc/onboard/onboard.toml names no titan_listener"

# The three socket directories. httpd's and gmid's are inside the chroot the two
# front-ends share; the portal's is the on-disk path its unchrooted program
# connects to. All three paths and the chroot are the installed config's: this
# service borrows a
# directory inside httpd's and gmid's chroot because a FastCGI socket path is
# resolved inside it, and a layout that moves the chroot moves these with it.
#
# One directory per socket rather than one for both, because a socket file's group
# is what decides which daemon may connect and a directory's set-group-id bit can
# carry one group. Without the bit the socket would take _onboard's own group and
# neither www nor _gmid could reach it. Nothing else may connect: a local user who
# could would forge the request environment, REMOTE_ADDR among it.
say "sockets"
for pair in "www:$httpd_socket_path" "_gmid:$gemini_socket_path" "$portal_group:$portal_socket_path"; do
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
rcctl enable kyriakon_control
if rcctl check kyriakon_control >/dev/null 2>&1; then
	rcctl restart kyriakon_control
else
	rcctl start kyriakon_control
fi
rcctl check kyriakon_control >/dev/null 2>&1 \
	|| die "kyriakon_control did not come up; check /var/log/daemon"

# The sockets, taken from the installed config rather than assumed, so a box whose
# paths were changed is checked where they are. A responder that came up but could
# not bind is a service no front-end can reach, and this is what says so without a
# front-end in the path: each file is a socket, and its mode is the one that keeps
# every other local user out. The pages themselves are checked by the front-ends'
# own deploys, which are the only things that can ask for one.
say "verify"
for pair in "httpd:$httpd_socket_path" "gemini:$gemini_socket_path" "portal:$portal_socket_path"; do
	front=${pair%%:*}
	path=${pair#*:}
	[ -S "$path" ] || die "$path is not a socket: is kyriakon_control running, and is its directory there?"
	[ "$(stat -f '%Lp' "$path")" = "660" ] || die "$path is not mode 660"
	printf '%s: %s\n' "$front" "$path"
done

# The Titan listener is a TCP socket on loopback, so it has no file to stat. Its
# address is the commented relayd forward target, and relayd is the only thing
# that reaches it from off the box. A process that came up without binding it is
# a service whose upload route is missing, and this is the check that says so.
titan_port=${titan_listener##*:}
case "$titan_port" in
"" | *[!0-9]*)
	die "/etc/onboard/onboard.toml has no port in titan_listener: '$titan_listener'"
	;;
esac
# sockstat names the process that holds the socket, which netstat cannot: a
# row ending in the port proves only that something listens there. The family
# follows the configured address so an IPv6 listener is not read as missing.
family=-4
case "${titan_listener%:*}" in
*:*) family=-6 ;;
esac
sockstat "$family" -ln | awk -v p=":$titan_port" '$2 == "kyriakon_control" && $6 ~ (p "$") { found = 1 } END { exit !found }' \
	|| die "kyriakon_control is not listening on titan_listener $titan_listener"
printf 'titan: %s\n' "$titan_listener"

printf '\ninstalled. the responder answers %s, %s and %s, and no other local user may connect.\n' \
	"$httpd_socket_path" "$gemini_socket_path" "$portal_socket_path"
# The command the drain's rate fetch runs. It is a package rather than a base
# tool, and nothing else on the pass needs it, so a box without it would open
# every Monero window with no quote and log a failure per attempt. The check is
# a warning like the doas one: this script does not install packages.
say "rate fetch"
rates_fetch=$(awk -F'"' '/^rates_fetch[[:space:]]*=/ { print $2; exit }' /etc/kyriakon/onboard/drain.toml)
[ -n "$rates_fetch" ] || die "/etc/kyriakon/onboard/drain.toml names no rates_fetch"
if [ -x "$rates_fetch" ]; then
	printf 'rates: %s\n' "$rates_fetch"
else
	printf 'the Monero quote cannot be fetched until %s exists:\n' "$rates_fetch"
	printf '  doas pkg_add curl\n'
fi

# The one doas rule the login needs. It is not written here: doas.conf is the
# box's privilege list, and a deploy that appended to it could lock the operator
# out of root. The tracked fragment is the line itself, so the manual step is a
# copy rather than a retyping.
say "login check"
authcheck_rule='permit nopass _onboard as root cmd /usr/local/libexec/kyriakon-authcheck'
if grep -qxF "$authcheck_rule" /etc/doas.conf 2>/dev/null; then
	printf 'doas: %s\n' "$authcheck_rule"
else
	printf 'the account page login will refuse everyone until this line is in /etc/doas.conf:\n'
	printf '  %s\n' "$authcheck_rule"
	printf 'append it and check the file with: doas -C /etc/doas.conf\n'
	printf 'the tracked copy is %s\n' "$repo_dir/openbsd/etc/doas.conf.control"
fi

printf 'the Titan upload listener is on %s behind the commented relayd block.\n' "$titan_listener"
printf 'httpd and gmid reach it from their own configs, which their own deploys install.\n'
printf 'relayd terminates TLS for signup.kyriakon.net and sets the forwarded address\n'
printf 'the counters key on.\n'
