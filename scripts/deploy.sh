#!/bin/ksh
# deploy.sh — run the deploy scripts a range of commits needs, in order.
#
# Runs ON the box as root, after the checkout has been updated:
#
#   doas ksh scripts/deploy.sh --check           # print the plan, run nothing
#   doas ksh scripts/deploy.sh                   # run the plan
#   doas ksh scripts/deploy.sh --since <commit>  # plan from a chosen commit
#   doas ksh scripts/deploy.sh --all             # every deploy script
#
# The base is /var/db/kyriakon/deployed, written as `<commit><tab><date>` after
# a run whose scripts all succeeded. The first run has no marker and plans every
# script; a later run diffs the marker's commit to HEAD and runs only what the
# changed paths need. `--check` prints the same plan and writes nothing.
#
# Two changes are never applied here. pf.conf is the operator's propose-only
# step, and sshd_config and its login class are installed by hand; the script
# prints the commands for both and does not advance the marker while one of
# them remains in the range. Apply the diff by hand, then run this again.
#
# A path this script does not recognise is an error, not a silent skip: a new
# directory has to choose its deploy, which is how a config file added under
# openbsd/etc/ cannot land without a rule.
#
# The mapping is read from the repository layout, not from a list per script:
# onboard/ goes with deploy-onboard, the mail and web configs with deploy-mail,
# relayd.conf with deploy-relayd, the nsd tree with deploy-nsd.

set -euo pipefail

script_dir=$(cd "$(dirname -- "$0")" && pwd)
repo_dir=$(cd "$script_dir/.." && pwd)
marker="${KYRIAKON_DEPLOY_MARKER:-/var/db/kyriakon/deployed}"

say() { printf '== %s\n' "$*"; }
die() { printf '%s: %s\n' "$0" "$*" >&2; exit 1; }

usage() {
	printf 'usage: doas ksh %s [--check] [--since <commit> | --all]\n' "$0" >&2
	exit 2
}

reset_plan() {
	needs_nsd=no
	needs_mail=no
	needs_relayd=no
	needs_onboard=no
	manual_pf=no
	manual_sshd=no
	manual_sshd_onboard=no
	manual_member_class=no
	manual_cron=no
	manual_env=no
	manual_terraform=no
}

# classify <path> — set the flags for one changed path. Returns 1 when the path
# has no rule, so `plan` can refuse the run and name every unclassified path.
classify() {
	case "$1" in
	onboard/*) needs_onboard=yes ;;
	kyriakon-encrypt/* | dovecot-plugin/*) needs_mail=yes ;;
	openbsd/dovecot/*) needs_mail=yes ;;
	openbsd/etc/onboard/*) needs_onboard=yes ;;
	openbsd/etc/rc.d/kyriakon_onboard) needs_onboard=yes ;;
	openbsd/etc/rc.d/kyriakon_onboard_sshd) manual_sshd_onboard=yes ;;
	openbsd/etc/rc.d/kyriakon_encrypt) needs_mail=yes ;;
	openbsd/etc/httpd.conf | openbsd/etc/gmid.conf | openbsd/etc/acme-client.conf | \
		openbsd/etc/smtpd.conf | openbsd/etc/unbound.conf | openbsd/etc/newsyslog.conf | \
		openbsd/etc/spamd.conf | openbsd/etc/spamd.alloweddomains | openbsd/etc/nospamd | \
		openbsd/etc/kyriakon-finger | openbsd/etc/finger.txt) needs_mail=yes ;;
	openbsd/etc/kyriakon.env)
		needs_mail=yes
		manual_env=yes
		;;
	openbsd/etc/relayd.conf) needs_relayd=yes ;;
	openbsd/etc/nsd/* | openbsd/etc/hostname.vio0) needs_nsd=yes ;;
	openbsd/etc/pf.conf) manual_pf=yes ;;
	openbsd/etc/sshd_config) manual_sshd=yes ;;
	openbsd/etc/sshd_config.onboard | openbsd/etc/login.conf.d/onboard) manual_sshd_onboard=yes ;;
	openbsd/etc/login.conf.d/member)
		needs_onboard=yes
		manual_member_class=yes
		;;
	reserved-usernames.txt | scripts/onboard-store.sh) needs_onboard=yes ;;
	scripts/lib.sh | scripts/abuse-monitor.sh | scripts/backup.sh | \
		scripts/renew-acme.sh | scripts/restore-standup.sh) needs_mail=yes ;;
	scripts/cron-apply.sh) manual_cron=yes ;;
	scripts/*) : ;;
	keys/*) needs_mail=yes ;;
	terraform/*) manual_terraform=yes ;;
	docs/* | .github/* | .githooks/* | openbsd/restore-template/*) : ;;
	*.md) : ;;
	*) return 1 ;;
	esac
	return 0
}

# plan <repo> <base> — set the flags from the diff `<base>..HEAD`, or every
# deploy script when <base> is empty. A base that is not in the checkout is an
# error rather than a diff against nothing.
plan() {
	plan_repo=$1
	plan_base=$2
	reset_plan
	if [ -z "$plan_base" ]; then
		needs_nsd=yes
		needs_mail=yes
		needs_relayd=yes
		needs_onboard=yes
		return 0
	fi
	if ! git -C "$plan_repo" cat-file -e "$plan_base^{commit}" 2>/dev/null; then
		die "no commit $plan_base in $plan_repo; pass a commit the checkout holds"
	fi
	changed=$(git -C "$plan_repo" diff --name-only "$plan_base..HEAD") ||
		die "cannot read the diff from $plan_base in $plan_repo"
	[ -n "$changed" ] || return 0
	unknown=''
	while IFS= read -r path; do
		[ -n "$path" ] || continue
		if ! classify "$path"; then
			unknown="$unknown $path"
		fi
	done <<EOF
$changed
EOF
	[ -z "$unknown" ] || die "no deploy rule for:$unknown"
}

# The fixed order: DNS before mail, mail before the relay, the service last.
# A second function so the self-test reads the same order the live run uses.
plan_order() {
	if [ "$needs_nsd" = yes ]; then printf 'deploy-nsd.sh\n'; fi
	if [ "$needs_mail" = yes ]; then printf 'deploy-mail.sh\n'; fi
	if [ "$needs_relayd" = yes ]; then printf 'deploy-relayd.sh\n'; fi
	if [ "$needs_onboard" = yes ]; then printf 'deploy-onboard.sh\n'; fi
	return 0
}

manual_any() {
	[ "$manual_pf" = yes ] || [ "$manual_sshd" = yes ] || [ "$manual_sshd_onboard" = yes ] ||
		[ "$manual_member_class" = yes ] || [ "$manual_cron" = yes ] ||
		[ "$manual_env" = yes ] || [ "$manual_terraform" = yes ]
}

print_manual() {
	if [ "$manual_pf" = yes ]; then
		printf 'propose-only: pf.conf changed. Review the diff, then apply it by hand:\n'
		printf '  doas ksh scripts/pf-apply.sh --check\n'
		printf '  doas ksh scripts/pf-apply.sh\n'
	fi
	if [ "$manual_sshd" = yes ]; then
		printf 'propose-only: sshd_config changed. Install it by hand, then:\n'
		printf '  doas sshd -t -f /etc/ssh/sshd_config\n'
		printf '  doas rcctl restart sshd\n'
	fi
	if [ "$manual_sshd_onboard" = yes ]; then
		printf 'propose-only: the portal sshd config or its login class changed:\n'
		printf '  doas sshd -t -f /etc/ssh/sshd_config.onboard\n'
		printf '  doas rcctl restart kyriakon_onboard_sshd\n'
		printf '  doas cap_mkdb /etc/login.conf   # when the class changed\n'
	fi
	if [ "$manual_member_class" = yes ]; then
		printf 'the member login class changed; existing accounts keep the old one until:\n'
		printf '  doas install -m 0644 openbsd/etc/login.conf.d/member /etc/login.conf.d/member\n'
		printf '  doas cap_mkdb /etc/login.conf   # only when /etc/login.conf.db exists\n'
		printf '  doas usermod -L member <username>\n'
	fi
	if [ "$manual_cron" = yes ]; then
		printf 'the crontab or its scripts changed:\n  doas ksh scripts/cron-apply.sh\n'
	fi
	if [ "$manual_env" = yes ]; then
		printf 'the environment template changed; merge it into /root/.kyriakon-env:\n'
		printf '  doas ksh scripts/setup-env.sh\n'
	fi
	if [ "$manual_terraform" = yes ]; then
		printf 'terraform changed; review the plan, then apply it by hand:\n'
		printf '  terraform -chdir=terraform plan\n'
	fi
	return 0
}

print_plan() {
	if [ "$all" = yes ]; then
		say 'the plan: every deploy script'
	else
		say 'the plan:'
	fi
	if [ -z "$(plan_order)" ]; then
		say 'no deploy script is needed'
	else
		plan_order | while IFS= read -r s; do
			printf '  ksh scripts/%s\n' "$s"
		done
	fi
	print_manual
}

run_scripts() {
	# shellcheck disable=SC2046 # plan_order writes one script name per line
	for s in $(plan_order); do
		say "running scripts/$s"
		ksh "$1/scripts/$s" || die "scripts/$s failed; the marker was not written"
	done
}

marker_base() {
	[ -f "$1" ] || return 0
	cut -f1 "$1" 2>/dev/null | head -1
}

write_marker() {
	mkdir -p "$(dirname "$1")"
	printf '%s\t%s\n' "$2" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$1.tmp"
	mv "$1.tmp" "$1"
}

main() {
	if [ "${1:-}" = --self-test ]; then
		self_test
	fi
	check_only=no
	all=no
	since=''
	while [ $# -gt 0 ]; do
		case "$1" in
		--check) check_only=yes ;;
		--all) all=yes ;;
		--since)
			[ $# -ge 2 ] || usage
			since=$2
			shift
			;;
		*) usage ;;
		esac
		shift
	done
	if [ "$all" = yes ] && [ -n "$since" ]; then
		die '--all and --since cannot be combined'
	fi
	[ "$(id -u)" -eq 0 ] || die "run as root (doas ksh $0)"
	[ -d "$repo_dir/.git" ] || die "$repo_dir is not a git checkout"
	if ! git -C "$repo_dir" diff --quiet || ! git -C "$repo_dir" diff --cached --quiet; then
		die "$repo_dir has uncommitted changes; commit or discard them first"
	fi

	base=$since
	if [ "$all" = no ] && [ -z "$base" ]; then
		base=$(marker_base "$marker")
		if [ -z "$base" ]; then
			all=yes
			say "no deploy marker at $marker: planning every deploy script"
		fi
	fi
	[ "$all" = no ] || base=''

	plan "$repo_dir" "$base"
	head=$(git -C "$repo_dir" rev-parse HEAD)
	if [ -n "$base" ]; then
		say "deploying $(printf '%.12s' "$head") from $(printf '%.12s' "$base")"
	else
		say "deploying $(printf '%.12s' "$head")"
	fi
	print_plan

	if [ "$check_only" = yes ]; then
		say '--check: nothing was run and the marker was not written'
		return 0
	fi
	run_scripts "$repo_dir"
	if manual_any; then
		say 'not recorded: the manual steps above are still to run'
		return 0
	fi
	write_marker "$marker" "$head"
	say "recorded $head in $marker"
}

self_test() {
	KYRIAKON_ENV=/dev/null
	export KYRIAKON_ENV
	# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
	. "$script_dir/lib.sh"
	self_test_begin

	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	repo="$self_test_work/repo"
	mkdir -p "$repo/scripts" "$repo/docs"
	git init -q "$repo"
	git -C "$repo" config user.email 'self-test@example.invalid'
	git -C "$repo" config user.name 'self test'
	git -C "$repo" config commit.gpgsign false
	printf 'one\n' >"$repo/docs/readme.md"
	git -C "$repo" add -A
	git -C "$repo" commit -qm one
	first=$(git -C "$repo" rev-parse HEAD)

	mkdir -p "$repo/onboard/src" "$repo/openbsd/etc/nsd" "$repo/openbsd/etc/onboard" \
		"$repo/terraform"
	printf 'x\n' >"$repo/onboard/src/lib.rs"
	printf 'x\n' >"$repo/openbsd/etc/nsd/nsd.conf"
	printf 'x\n' >"$repo/openbsd/etc/httpd.conf"
	printf 'x\n' >"$repo/openbsd/etc/pf.conf"
	printf 'x\n' >"$repo/openbsd/etc/sshd_config"
	printf 'x\n' >"$repo/openbsd/etc/onboard/drain.toml"
	printf 'x\n' >"$repo/terraform/main.tf"
	git -C "$repo" add -A
	git -C "$repo" commit -qm two
	second=$(git -C "$repo" rev-parse HEAD)

	plan "$repo" "$first"
	check 'the onboard change plans deploy-onboard' "$needs_onboard" yes
	check 'the mail change plans deploy-mail' "$needs_mail" yes
	check 'the nsd change plans deploy-nsd' "$needs_nsd" yes
	check 'the pf change is manual' "$manual_pf" yes
	check 'the sshd change is manual' "$manual_sshd" yes
	check 'the relayd change is not planned' "$needs_relayd" no
	check 'the plan order' "$(plan_order | paste -sd ' ' -)" \
		'deploy-nsd.sh deploy-mail.sh deploy-onboard.sh'
	check 'a manual step gates the marker' \
		"$(if manual_any; then printf yes; else printf no; fi)" yes

	printf 'more\n' >>"$repo/docs/readme.md"
	git -C "$repo" commit -qam three
	plan "$repo" "$second"
	check 'a docs-only range plans nothing' "$(plan_order)" ''
	check 'a docs-only range has no manual step' \
		"$(if manual_any; then printf yes; else printf no; fi)" no

	reset_plan
	got=0
	( classify 'mystery/file' ) || got=$?
	check 'an unrecognised path is refused' "$got" 1

	reset_plan
	classify 'scripts/backup.sh'
	check 'an installed cron script plans deploy-mail' "$needs_mail" yes
	reset_plan
	classify 'scripts/deploy.sh'
	check 'the deploy script plans nothing' "$(plan_order)" ''

	plan "$repo" ''
	check 'no base plans every script' "$(plan_order | paste -sd ' ' -)" \
		'deploy-nsd.sh deploy-mail.sh deploy-relayd.sh deploy-onboard.sh'

	printf 'abc123\t2026-10-22T00:00:00Z\n' >"$self_test_work/old-marker"
	check "the marker's commit is read" "$(marker_base "$self_test_work/old-marker")" abc123
	write_marker "$self_test_work/new-marker" deadbeef
	check 'the marker is written' "$(marker_base "$self_test_work/new-marker")" deadbeef

	self_test_end
}

main "$@"
