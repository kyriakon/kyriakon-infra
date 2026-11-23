#!/bin/ksh
# deploy.sh — run the deploy scripts a range of commits needs, in order.
#
# Runs ON the box as root, after the checkout has been updated:
#
#   doas ksh scripts/deploy.sh --check           # print the plan, run nothing
#   doas ksh scripts/deploy.sh                   # run the plan
#   doas ksh scripts/deploy.sh --since <commit>  # plan from a chosen commit
#   doas ksh scripts/deploy.sh --all             # every deploy script, no record
#   doas ksh scripts/deploy.sh --record          # record HEAD, run nothing
#
# The base is /var/db/kyriakon/deployed, written as `<commit><tab><date>` after
# a run whose scripts all succeeded and whose propose-only steps were applied.
# The first run has no marker: `--all` runs every script and does not record,
# because with no diff it cannot see a pf.conf or sshd_config change. After the
# manual checks, `--record` records HEAD. A later run diffs the marker's commit
# to HEAD and runs only what the changed paths need. `--check` prints the same
# plan and writes nothing.
#
# Three changes are never applied here. pf.conf is the operator's propose-only
# step, sshd_config and its login class are installed by hand, and the control
# doas rule is a fragment copied into /etc/doas.conf by hand; the script prints
# the commands for each and does not advance the marker while one of them
# remains in the range. Apply the diff by hand, then run `--record`.
#
# A path this script does not recognise is an error, not a silent skip: a new
# directory has to choose its deploy, which is how a config file added under
# openbsd/etc/ cannot land without a rule.
#
# The mapping follows the repository layout, plus scripts/install-set.tsv: the
# destination a script's row names is the deploy that installs it, so adding a
# script to the box is one row in that table rather than an arm here. A deploy
# script's own path needs the deploy it runs, so pulling a fix to deploy-mail.sh
# schedules deploy-mail.sh.

set -euo pipefail

script_dir=$(cd "$(dirname -- "$0")" && pwd)
repo_dir=$(cd "$script_dir/.." && pwd)
install_set="$script_dir/install-set.tsv"
marker="${KYRIAKON_DEPLOY_MARKER:-/var/db/kyriakon/deployed}"

say() { printf '== %s\n' "$*"; }
die() { printf '%s: %s\n' "$0" "$*" >&2; exit 1; }

usage() {
	printf 'usage: doas ksh %s [--check | --record] [--since <commit> | --all]\n' "$0" >&2
	exit 2
}

reset_plan() {
	needs_nsd=no
	needs_mail=no
	needs_relayd=no
	needs_control=no
	manual_pf=no
	manual_sshd=no
	manual_sshd_onboard=no
	manual_member_class=no
	manual_lapsed_class=no
	manual_cron=no
	manual_env=no
	manual_doas=no
	manual_terraform=no
	uninstall_list=''
}

# apply_routes <token>... — set the flags one manifest row's deploy_route names.
# The tokens are the deploys that install the file and the manual steps a change
# needs; an unknown one is refused rather than skipped.
apply_routes() {
	typeset route
	for route in "$@"; do
		case "$route" in
		mail) needs_mail=yes ;;
		control) needs_control=yes ;;
		relayd) needs_relayd=yes ;;
		nsd) needs_nsd=yes ;;
		cron) manual_cron=yes ;;
		env) manual_env=yes ;;
		pf) manual_pf=yes ;;
		doas) manual_doas=yes ;;
		none) ;;
		*) die "unknown deploy_route $route for a script in $install_set" ;;
		esac
	done
}

# classify_script <path> — a scripts/ path is routed by its manifest rows. The
# table is the manifest: a script nothing names returns 1 so the plan fails on
# it, and a retired row with no active one still routes the deploy that removes
# the installed copy.
classify_script() {
	typeset name="${1#scripts/}" routes
	case "$name" in
	# The table itself: a row added or removed is an install on one side or the
	# other, and a schedule changed is the crontab, so a change here is both
	# deploys and the manual cron step rather than nothing.
	install-set.tsv)
		needs_mail=yes
		needs_control=yes
		manual_cron=yes
		return 0
		;;
	esac
	manifest_has "$install_set" "$name" || return 1
	routes=$(manifest_routes "$install_set" "$name")
	if [ -z "$routes" ]; then
		routes=$(manifest_retired_routes "$install_set" "$name")
	fi
	[ -n "$routes" ] || return 0
	# Shell word splitting turns the newline-separated tokens into arguments.
	# shellcheck disable=SC2086 # one token per line, refusals on anything else
	apply_routes $routes
	return 0
}

# classify <path> — set the flags for one changed path. Returns 1 when the path
# has no rule, so `plan` can refuse the run and name every unclassified path.
classify() {
	case "$1" in
	# The filter is built by the control deploy and restarted by the mail
	# deploy: a new binary is not running until smtpd restarts the filter.
	control/crates/fromcheck/*) needs_control=yes; needs_mail=yes ;;
	control/*) needs_control=yes ;;
	# The filter reads mailparse too, so a parser change rebuilds and restarts
	# it as well as the encryptor.
	mailparse/*) needs_mail=yes; needs_control=yes ;;
	kyriakon-encrypt/* | dovecot-plugin/*) needs_mail=yes ;;
	openbsd/dovecot/*) needs_mail=yes ;;
	# Both deploys read the package table, and either side's rows can change.
	openbsd/packages.tsv) needs_mail=yes; needs_control=yes ;;
	openbsd/etc/onboard/*) needs_control=yes ;;
	openbsd/etc/rc.d/kyriakon_control) needs_control=yes ;;
	openbsd/etc/rc.d/kyriakon_onboard_sshd) manual_sshd_onboard=yes ;;
	openbsd/etc/httpd.conf | openbsd/etc/gmid.conf | openbsd/etc/acme-client.conf | \
		openbsd/etc/smtpd.conf | openbsd/etc/unbound.conf | openbsd/etc/newsyslog.conf | \
		openbsd/etc/spamd.conf | openbsd/etc/spamd.alloweddomains | openbsd/etc/nospamd | \
		openbsd/etc/kyriakon-finger | openbsd/etc/finger.txt) needs_mail=yes ;;
	openbsd/etc/kyriakon.env) manual_env=yes ;;
	openbsd/etc/relayd.conf) needs_relayd=yes ;;
	openbsd/etc/nsd/* | openbsd/etc/hostname.vio0) needs_nsd=yes ;;
	openbsd/etc/pf.conf) manual_pf=yes ;;
	openbsd/etc/sshd_config) manual_sshd=yes ;;
	openbsd/etc/sshd_config.onboard | openbsd/etc/login.conf.d/hello) manual_sshd_onboard=yes ;;
	# A hand-applied fragment, printed by the control deploy when the rule is
	# missing from /etc/doas.conf. It gates the marker like pf.conf does: the
	# deploy history must not say applied while the rule is still uninstalled.
	openbsd/etc/doas.conf.control)
		needs_control=yes
		manual_doas=yes
		;;

	openbsd/etc/login.conf.d/member)
		needs_control=yes
		manual_member_class=yes
		;;
	# deploy-control.sh installs the drain's copy, and lapse-user.sh installs
	# /etc/login.conf.d/lapsed when it next runs, so that copy is by hand.
	openbsd/etc/login.conf.d/lapsed)
		needs_control=yes
		manual_lapsed_class=yes
		;;
	reserved-usernames.txt | scripts/control-store.sh) needs_control=yes ;;
	# The installed set is the table's: a script's row names the deploy that
	# installs it, so adding one is a row there and not an arm here.
	scripts/*) classify_script "$1" || return 1 ;;
	keys/*) needs_mail=yes ;;
	terraform/*) manual_terraform=yes ;;
	# deploy-control.sh renders terms.md, privacy.md, aup.md and
	# key-walkthrough.md into the capsule and stamps the release, so a docs change
	# is that deploy; `*.md` below is the rest of the tree's markdown.
	docs/*) needs_control=yes ;;
	# The restore installer's response file is served from the landing site's
	# document root, which deploy-mail installs it into, so a change is that
	# deploy. The rest of the template is used at build time and never deployed.
	openbsd/restore-template/install.conf) needs_mail=yes ;;
	.github/* | .githooks/* | .omp/* | openbsd/restore-template/*) : ;;
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
		needs_control=yes
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
		# A deleted script is an uninstall, not a skip: the manifest must carry
		# it as retired, the deploy that owns the destination removes the
		# installed copy, and the plan says so. A deletion whose rows are still
		# active (or absent) is refused, because the box would keep invoking it.
		case "$path" in
		scripts/*)
			if [ ! -e "$plan_repo/$path" ]; then
				name=${path#scripts/}
				if ! manifest_has "$install_set" "$name"; then
					unknown="$unknown $path"
					continue
				fi
				if [ -n "$(manifest_routes "$install_set" "$name")" ]; then
					die "scripts/$name is deleted but its manifest row is active; mark the row retired"
				fi
				uninstall_list="$uninstall_list $name"
				routes=$(manifest_retired_routes "$install_set" "$name")
				# shellcheck disable=SC2086 # one token per line
				[ -z "$routes" ] || apply_routes $routes
				continue
			fi
			;;
		esac
		if ! classify "$path"; then
			unknown="$unknown $path"
		fi
	done <<EOF
$changed
EOF
	[ -z "$unknown" ] || die "no deploy rule for:$unknown"
}

# The fixed order. The control plane goes first because the two deploys
# after it check that it is up: deploy-mail refuses to finish unless
# kyriakon_control is running (it gates the capsule the handler answers on), and
# deploy-relayd requires the handler to answer signup.kyriakon.net with 200. The
# handler needs only the store and its socket directories, which deploy-control
# creates, so it can come up before either front-end. DNS next, then mail, then
# the relay that needs both. A second function so the self-test reads the same
# order the live run uses.
plan_order() {
	if [ "$needs_control" = yes ]; then printf 'deploy-control.sh\n'; fi
	if [ "$needs_nsd" = yes ]; then printf 'deploy-nsd.sh\n'; fi
	if [ "$needs_mail" = yes ]; then printf 'deploy-mail.sh\n'; fi
	if [ "$needs_relayd" = yes ]; then printf 'deploy-relayd.sh\n'; fi
	return 0
}

# render_onboard_sshd <template> <env-file> <out> — write the portal sshd config
# with its Port line taken from TUI_PORT.
#
# The tracked template carries `Port REPLACE_ME`, and sshd refuses that, so the
# file an operator checks and installs is the rendered one. setup-env.sh chooses
# the port once and records it in the box's values file; this reads the same file
# the deploy scripts and cron lines source rather than carrying a second copy of
# the rule. Returns 1 when the file holds no usable TUI_PORT.
render_onboard_sshd() {
	typeset template="$1" env_file="$2" out="$3" port
	# Sourced, not parsed, which is how the cron lines and deploy-mail.sh read it.
	# errexit is off for the read only: a values file that errors then names the
	# missing value below instead of ending the run here.
	set +e
	# shellcheck disable=SC1090 # root's own env file, whose path resolves at runtime
	port=$(. "$env_file" 2>/dev/null; printf '%s' "${TUI_PORT:-}")
	set -e
	case "$port" in
	'' | *[!0-9]*) return 1 ;;
	esac
	if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
		return 1
	fi
	sed "s/^Port REPLACE_ME$/Port $port/" "$template" >"$out"
	# The substitution must be the one line that changed. A template that lost the
	# placeholder would otherwise install a file nobody substituted.
	grep -qx "Port $port" "$out"
}

manual_any() {
	[ "$manual_pf" = yes ] || [ "$manual_sshd" = yes ] || [ "$manual_sshd_onboard" = yes ] ||
		[ "$manual_member_class" = yes ] || [ "$manual_lapsed_class" = yes ] ||
	[ "$manual_cron" = yes ] || [ "$manual_doas" = yes ] ||
	[ "$manual_env" = yes ] || [ "$manual_terraform" = yes ]
}

print_manual() {
	if [ "$manual_pf" = yes ]; then
		printf 'propose-only: pf.conf or scripts/pf-apply.sh changed. Review the diff, then apply it by hand:\n'
		printf '  doas ksh scripts/pf-apply.sh --check\n'
		printf '  doas ksh scripts/pf-apply.sh\n'
	fi
	if [ "$manual_sshd" = yes ]; then
		printf 'propose-only: sshd_config changed. Install it by hand, then:\n'
		printf '  doas install -m 0644 %s/openbsd/etc/sshd_config /etc/ssh/sshd_config\n' "$repo_dir"
		printf '  doas sshd -t -f /etc/ssh/sshd_config\n'
		printf '  doas rcctl restart sshd\n'
	fi
	if [ "$manual_sshd_onboard" = yes ]; then
		printf 'propose-only: the portal sshd config or its login class changed. Install by hand:\n'
		printf '  doas install -m 0644 %s/openbsd/etc/login.conf.d/hello /etc/login.conf.d/hello\n' "$repo_dir"
		printf '  doas cap_mkdb /etc/login.conf   # when the class changed\n'
		# The template ships Port REPLACE_ME, so this renders the file first and
		# checks that rendering, not the template: an install of the template is a
		# config sshd refuses to start.
		#
		# A stable path, not a temporary one: the plan is printed now and applied by
		# hand later, and /tmp is cleared on reboot. The file holds the port
		# substitution and nothing secret, and stays root-only like the values file.
		onboard_env="${KYRIAKON_ENV:-/root/.kyriakon-env}"
		onboard_src="${KYRIAKON_SSHD_RENDER:-/root/sshd_config.onboard.rendered}"
		if [ ! -d "$(dirname "$onboard_src")" ]; then
			die "the directory for $onboard_src does not exist; create it, then re-run this plan"
		fi
		if ! render_onboard_sshd "$repo_dir/openbsd/etc/sshd_config.onboard" "$onboard_env" "$onboard_src"; then
			die "no usable TUI_PORT in $onboard_env; run scripts/setup-env.sh, then re-run this plan"
		fi
		chmod 0600 "$onboard_src"
		if ! sshd -t -f "$onboard_src"; then
			die "$onboard_src does not pass sshd -t; the install step is not printed"
		fi
		printf '  # rendered with Port %s from TUI_PORT in %s\n' \
			"$(sed -n 's/^Port //p' "$onboard_src")" "$onboard_env"
		printf '  doas install -m 0644 %s /etc/ssh/sshd_config.onboard\n' "$onboard_src"
		printf '  doas sshd -t -f /etc/ssh/sshd_config.onboard\n'
		printf '  doas rcctl restart kyriakon_onboard_sshd\n'
	fi
	if [ "$manual_member_class" = yes ]; then
		printf 'the member login class changed; existing accounts keep the old one until:\n'
		printf '  doas install -m 0644 %s/openbsd/etc/login.conf.d/member /etc/login.conf.d/member\n' "$repo_dir"
		printf '  doas cap_mkdb /etc/login.conf   # only when /etc/login.conf.db exists\n'
		printf '  doas usermod -L member <username>\n'
	fi
	if [ "$manual_lapsed_class" = yes ]; then
		printf 'the lapsed login class changed; an already-lapsed account keeps the old one until:\n'
		printf '  doas install -m 0644 %s/openbsd/etc/login.conf.d/lapsed /etc/login.conf.d/lapsed\n' "$repo_dir"
		printf '  doas cap_mkdb /etc/login.conf   # only when /etc/login.conf.db exists\n'
	fi
	if [ "$manual_cron" = yes ]; then
		printf 'the crontab or its scripts changed:\n  doas ksh scripts/cron-apply.sh\n'
	fi
	if [ "$manual_doas" = yes ]; then
		printf 'the control doas rule changed; apply it by hand, then run --record:\n'
		printf '  doas ksh scripts/deploy-control.sh   # prints the rule when /etc/doas.conf lacks it\n'
	fi
	if [ -n "${uninstall_list:-}" ]; then
		printf 'retired scripts are removed by their deploy:\n'
		for s in $uninstall_list; do
			printf '  scripts/%s\n' "$s"
		done
	fi
	if [ "$manual_env" = yes ]; then
		printf 'the environment template changed; merge it into /root/.kyriakon-env:\n'
		printf '  doas ksh scripts/setup-env.sh\n'
	fi
	if [ "$manual_terraform" = yes ]; then
		printf 'terraform changed; review the plan from the workstation, then apply it by hand:\n'
		printf '  terraform -chdir=terraform plan\n'
	fi
	return 0
}

print_plan() {
	if [ "$all_scripts" = yes ]; then
		say 'the plan: every deploy script'
	else
		say 'the plan:'
	fi
	plan_scripts=$(plan_order)
	if [ -z "$plan_scripts" ]; then
		say 'no deploy script is needed'
	else
		printf '%s\n' "$plan_scripts" | while IFS= read -r s; do
			printf '  ksh scripts/%s\n' "$s"
		done
	fi
	print_manual
}

run_scripts() {
	# shellcheck disable=SC2086 # plan_scripts is one script name per line
	for s in $plan_scripts; do
		say "running scripts/$s"
		ksh "$1/scripts/$s" || die "scripts/$s failed; the marker was not written"
	done
}

# The marker is written when the range was checked (not --all) and held no
# manual step. `--record` is the operator's explicit confirmation after applying
# one, and is the only other writer.
gate() {
	[ "${all_scripts:-no}" = no ] && ! manual_any
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

record_now() {
	head=$(git -C "$1" rev-parse HEAD)
	write_marker "$2" "$head"
	say "recorded $head in $2"
}

main() {
	if [ "${1:-}" = --self-test ]; then
		self_test
	fi
	check_only=no
	record_only=no
	all_scripts=no
	since_commit=''
	while [ $# -gt 0 ]; do
		case "$1" in
		--check) check_only=yes ;;
		--record) record_only=yes ;;
		--all) all_scripts=yes ;;
		--since)
			[ $# -ge 2 ] || usage
			since_commit=$2
			shift
			;;
		*) usage ;;
		esac
		shift
	done
	if [ "$all_scripts" = yes ] && [ -n "$since_commit" ]; then
		die '--all and --since cannot be combined'
	fi
	if [ "$record_only" = yes ] && { [ "$check_only" = yes ] || [ "$all_scripts" = yes ] || [ -n "$since_commit" ]; }; then
		die '--record stands alone'
	fi
	[ "$(id -u)" -eq 0 ] || die "run as root (doas ksh $0)"
	# git is assigned to this script in packages.tsv: on a fresh box it is the
	# first command that needs it, before any deploy has run, so it installs
	# itself here rather than leaving the documented pull as the failure.
	if ! command -v git >/dev/null 2>&1; then
		say 'git is not installed; installing the bootstrap packages'
		ksh "$script_dir/install-packages.sh" deploy.sh \
			|| die "cannot install git; install it and re-run"
	fi
	[ -d "$repo_dir/.git" ] || die "$repo_dir is not a git checkout"
	if ! git -C "$repo_dir" diff --quiet || ! git -C "$repo_dir" diff --cached --quiet; then
		die "$repo_dir has uncommitted changes; commit or discard them first"
	fi

	if [ "$record_only" = yes ]; then
		record_now "$repo_dir" "$marker"
		return 0
	fi

	base=$since_commit
	if [ "$all_scripts" = no ] && [ -z "$base" ]; then
		base=$(marker_base "$marker")
		if [ -z "$base" ]; then
			all_scripts=yes
			say "no deploy marker at $marker: planning every deploy script"
		fi
	fi
	[ "$all_scripts" = no ] || base=''

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
	if ! gate; then
		if [ "$all_scripts" = yes ]; then
			say 'not recorded: --all has no diff, so pf.conf and sshd_config were not checked'
			say 'apply the propose-only steps, then: doas ksh scripts/deploy.sh --record'
		else
			say 'not recorded: the manual steps above are still to run'
			say 'apply them, then: doas ksh scripts/deploy.sh --record'
		fi
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

	mkdir -p "$repo/control/crates/core/src" "$repo/openbsd/etc/nsd" "$repo/openbsd/etc/onboard" \
		"$repo/terraform"
	printf 'x\n' >"$repo/control/Cargo.toml"
	printf 'x\n' >"$repo/control/crates/core/src/lib.rs"
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
	check 'the onboard change plans deploy-control' "$needs_control" yes
	check 'the mail change plans deploy-mail' "$needs_mail" yes
	check 'the nsd change plans deploy-nsd' "$needs_nsd" yes
	check 'the pf change is manual' "$manual_pf" yes
	check 'the sshd change is manual' "$manual_sshd" yes
	check 'the relayd change is not planned' "$needs_relayd" no
	check 'the plan order' "$(plan_order | paste -sd ' ' -)" \
		'deploy-control.sh deploy-nsd.sh deploy-mail.sh'
	check 'a manual step gates the marker' \
		"$(if manual_any; then printf yes; else printf no; fi)" yes

	# docs/ is rendered into the capsule by the control deploy, so a docs change
	# is that deploy; markdown elsewhere in the tree is not.
	printf 'more\n' >>"$repo/docs/readme.md"
	git -C "$repo" commit -qam three
	third=$(git -C "$repo" rev-parse HEAD)
	plan "$repo" "$second"
	check 'a docs range plans the control deploy' "$(plan_order)" 'deploy-control.sh'
	check 'a docs range has no manual step' \
		"$(if manual_any; then printf yes; else printf no; fi)" no

	printf 'more\n' >"$repo/NOTES.md"
	git -C "$repo" add -A
	git -C "$repo" commit -qm four
	plan "$repo" "$third"
	check 'markdown outside docs/ plans nothing' "$(plan_order)" ''

	reset_plan
	classify 'docs/terms.md'
	check 'the terms page plans the control deploy' "$needs_control" yes

	reset_plan
	got=0
	( classify 'mystery/file' ) || got=$?
	check 'an unrecognised path is refused' "$got" 1

	reset_plan
	got=0
	( classify 'scripts/no-such-helper.sh' ) || got=$?
	check 'an uninstalled script with no rule is refused' "$got" 1

	# Retiring an installed script deletes the script and marks its manifest row
	# retired in one commit. The deletion is an explicit uninstall step, and the
	# deploy that owns the destination is still planned.
	printf 'gone.sh\t/usr/local/bin\t-\t\tmail\t-\tretired\n' > "$self_test_work/table.tsv"
	install_set="$self_test_work/table.tsv"
	printf 'x\n' > "$repo/scripts/gone.sh"
	git -C "$repo" add -A
	git -C "$repo" commit -qm five
	fifth=$(git -C "$repo" rev-parse HEAD)
	rm "$repo/scripts/gone.sh"
	git -C "$repo" add -A
	git -C "$repo" commit -qm six
	got=0
	plan "$repo" "$fifth" || got=$?
	check 'a retired deletion plans its deploy' "$got" 0
	check 'and is surfaced as an uninstall' "$uninstall_list" ' gone.sh'
	check 'and the deploy removing it runs' "$(plan_order)" 'deploy-mail.sh'
	# A deletion whose row is still active would leave the box invoking a file
	# that no longer exists, so it is refused rather than recorded.
	printf 'gone.sh\t/usr/local/bin\t-\t\tmail\t-\tactive\n' > "$self_test_work/table.tsv"
	got=0
	( plan "$repo" "$fifth" ) >/dev/null 2>&1 || got=$?
	check 'a deletion with an active row is refused' "$got" 1
	install_set="$script_dir/install-set.tsv"

	reset_plan
	classify 'scripts/backup.sh'
	check 'an installed cron script plans deploy-mail' "$needs_mail" yes
	reset_plan
	classify 'scripts/check-keyring-drift.sh'
	check 'the drift check plans deploy-mail' "$needs_mail" yes
	reset_plan
	classify 'scripts/provision-member.sh'
	check 'a drain script plans deploy-control' "$needs_control" yes
	reset_plan
	classify 'scripts/provision-member-acme.sh'
	check 'the acme lane plans deploy-control' "$needs_control" yes
	reset_plan
	classify 'scripts/remove-upload-key.sh'
	check 'the upload-key removal plans deploy-control' "$needs_control" yes
	reset_plan
	classify 'scripts/provision-group-web.sh'
	check 'an own-domain hosting lane plans deploy-control' "$needs_control" yes
	reset_plan
	classify 'scripts/provision-group-acme.sh'
	check 'the own-domain acme lane plans deploy-control' "$needs_control" yes
	reset_plan
	classify 'scripts/check-hygiene.sh'
	check 'a checkout script plans no deploy' "$(plan_order)" ''
	check 'and no manual step' \
		"$(if manual_any; then printf yes; else printf no; fi)" no
	reset_plan
	classify 'scripts/relayd-members.sh'
	check 'the relayd member helper plans both deploys' \
		"$needs_relayd $needs_control" 'yes yes'
	reset_plan
	classify 'scripts/lib.sh'
	check 'lib.sh plans both deploys' "$needs_mail $needs_control" 'yes yes'
	reset_plan
	classify 'scripts/cron-apply.sh'
	check 'cron-apply plans onboard and a manual run' "$needs_control $manual_cron" 'yes yes'
	reset_plan
	classify 'openbsd/etc/kyriakon.env'
	check 'the env template does not plan a mail deploy' "$needs_mail" no
	check 'the env template is a manual step' "$manual_env" yes
	reset_plan
	classify 'openbsd/etc/login.conf.d/hello'
	check 'the portal login class is a manual step' "$manual_sshd_onboard" yes
	reset_plan
	classify 'openbsd/etc/login.conf.d/lapsed'
	check 'the lapsed login class plans deploy-control' "$needs_control" yes
	check 'the lapsed login class is a manual step' "$manual_lapsed_class" yes
	reset_plan
	classify 'scripts/deploy.sh'
	check 'the deploy script plans nothing' "$(plan_order)" ''
	for s in install-packages merge-pr rehearsal rekey-mail-key restore-test; do
		reset_plan
		classify "scripts/$s.sh"
		check "scripts/$s.sh plans nothing" "$(plan_order)" ''
	done
	reset_plan
	classify 'scripts/deploy-mail.sh'
	check 'the mail deploy plans itself' "$needs_mail" yes
	reset_plan
	classify 'mailparse/src/lib.rs'
	check 'a shared parser change rebuilds the filter too' \
		"$needs_control $needs_mail" 'yes yes'
	reset_plan
	classify 'scripts/deploy-relayd.sh'
	check 'the relay deploy plans itself' "$needs_relayd" yes
	reset_plan
	classify 'scripts/deploy-control.sh'
	check 'the onboard deploy plans itself' "$needs_control" yes
	reset_plan
	classify 'scripts/deploy-nsd.sh'
	check 'the nsd deploy plans itself' "$needs_nsd" yes
	reset_plan
	classify 'scripts/pf-apply.sh'
	check 'a pf script change is a manual step' "$manual_pf" yes
	reset_plan
	classify 'scripts/reload-smtpd.sh'
	check 'the smtpd reload script plans deploy-control' "$needs_control" yes
	reset_plan
	classify 'scripts/gen-finger-page.sh'
	check 'the finger page renderer plans deploy-mail' "$needs_mail" yes
	reset_plan
	classify 'scripts/setup-env.sh'
	check 'the setup script plans no deploy' "$(plan_order)" ''
	check 'the setup script is the manual env step' "$manual_env" yes

	# Every row of the install-set table has to plan the deploy that installs it,
	# or a fix to that script lands in the checkout and never reaches the box. The
	# rows are read from the table rather than retyped here, so the check cannot
	# agree with a stale copy of it. A retired row is not installed.
	drain_rows=$(awk -F'\t' '!/^#/ && $2 == "drain" && $7 == "active" { print $1 }' "$install_set")
	root_bin_rows=$(awk -F'\t' '!/^#/ && $2 == "/root/bin" && $7 == "active" { print $1 }' "$install_set")
	libexec_rows=$(awk -F'\t' '!/^#/ && $2 == "/usr/local/libexec" && $7 == "active" { print $1 }' "$install_set")
	libexec_mail_rows=$(awk -F'\t' '!/^#/ && $2 == "/usr/local/libexec" && $7 == "active" && $5 ~ /(^|,)mail(,|$)/ { print $1 }' "$install_set")
	docroot_rows=$(awk -F'\t' '!/^#/ && $2 ~ /^\/home\/www\// && $7 == "active" { print $1 }' "$install_set")
	check 'the table names drain scripts' \
		"$([ -n "$drain_rows" ] && printf yes || printf no)" yes
	check 'the table names /root/bin scripts' \
		"$([ -n "$root_bin_rows" ] && printf yes || printf no)" yes
	check 'the table names /usr/local/libexec scripts' \
		"$([ -n "$libexec_rows" ] && printf yes || printf no)" yes
	check 'the table names a document root file' \
		"$([ -n "$docroot_rows" ] && printf yes || printf no)" yes
	for installed in $drain_rows; do
		reset_plan
		classify "scripts/$installed"
		check "scripts/$installed plans deploy-control" "$needs_control" yes
	done
	for installed in $root_bin_rows; do
		reset_plan
		classify "scripts/$installed"
		check "scripts/$installed plans deploy-mail" "$needs_mail" yes
	done
	for installed in $libexec_mail_rows; do
		reset_plan
		classify "scripts/$installed"
		check "scripts/$installed plans deploy-mail" "$needs_mail" yes
	done
	# A document-root row names its source from the repo root, so it is classified
	# as that path. A row whose path has no arm fails here rather than planning
	# nothing and leaving a served file stale.
	for served in $docroot_rows; do
		reset_plan
		classify "$served"
		check "$served plans deploy-mail" "$needs_mail" yes
	done
	reset_plan
	classify 'scripts/install-set.tsv'
	check 'a table change plans both deploys and the cron step' \
		"$needs_mail $needs_control $manual_cron" 'yes yes yes'
	reset_plan
	classify 'openbsd/packages.tsv'
	check 'a package table change plans both deploys' \
		"$needs_mail $needs_control" 'yes yes'
	reset_plan
	classify 'control/crates/fromcheck/src/lib.rs'
	check 'a filter change rebuilds it and restarts smtpd' \
		"$needs_control $needs_mail" 'yes yes'
	reset_plan
	classify 'scripts/kyriakon-authcheck.sh'
	check 'the libexec install plans deploy-control' "$needs_control" yes
	reset_plan
	classify 'scripts/render-docs.sh'
	check 'the pages renderer plans deploy-control' "$needs_control" yes
	# A route token no deploy or manual step names is refused rather than
	# skipped: a typo would otherwise route a change nowhere.
	got=0
	( apply_routes somewhere-else ) >/dev/null 2>&1 || got=$?
	check 'an unknown deploy route is refused' "$got" 1
	got=0
	( manifest_has "$self_test_work/no-such-table.tsv" new.sh ) >/dev/null 2>&1 || got=$?
	check 'a missing manifest table is refused' "$got" 1
	# The doas rule is hand-applied, so its diff must gate the marker.
	reset_plan
	classify 'openbsd/etc/doas.conf.control'
	check 'the doas fragment plans deploy-control' "$needs_control" yes
	check 'and gates the marker' \
		"$(if manual_any; then printf yes; else printf no; fi)" yes
	reset_plan
	classify '.omp/lsp.json'
	check 'developer tooling plans nothing' "$(plan_order)" ''

	# The portal sshd step installs the rendered file, so the port substitution is
	# the thing to test: an unsubstituted install is a config sshd refuses.
	printf 'Port REPLACE_ME\nPidFile /var/run/sshd.onboard.pid\n' >"$self_test_work/onboard.tpl"
	printf "export TUI_PORT='2233'\n" >"$self_test_work/tui-env"
	if render_onboard_sshd "$self_test_work/onboard.tpl" "$self_test_work/tui-env" \
		"$self_test_work/onboard.rendered"; then
		check 'the portal sshd port comes from TUI_PORT' \
			"$(cat "$self_test_work/onboard.rendered")" \
			"$(printf 'Port 2233\nPidFile /var/run/sshd.onboard.pid')"
	else
		printf 'FAIL: a TUI_PORT in the values file did not render\n' >&2
		exit 1
	fi
	printf "export TUI_PORT='not-a-port'\n" >"$self_test_work/tui-bad"
	got=0
	render_onboard_sshd "$self_test_work/onboard.tpl" "$self_test_work/tui-bad" \
		"$self_test_work/onboard.bad" || got=$?
	check 'a non-numeric TUI_PORT is refused' "$got" 1
	: >"$self_test_work/tui-empty"
	got=0
	render_onboard_sshd "$self_test_work/onboard.tpl" "$self_test_work/tui-empty" \
		"$self_test_work/onboard.none" || got=$?
	check 'a missing TUI_PORT is refused' "$got" 1

	# The plan is printed now and applied by hand later, possibly after a reboot,
	# so the install must name a stable path rather than one under /tmp. The sshd
	# check is stubbed: the box runs it, this only asserts what is printed.
	mkdir -p "$self_test_work/sshd-bin"
	printf '#!/bin/sh\nexit 0\n' >"$self_test_work/sshd-bin/sshd"
	chmod 0755 "$self_test_work/sshd-bin/sshd"
	render_path="$self_test_work/sshd_config.onboard.rendered"
	KYRIAKON_ENV="$self_test_work/tui-env"
	KYRIAKON_SSHD_RENDER="$render_path"
	manual_sshd_onboard=yes
	old_path=$PATH
	PATH="$self_test_work/sshd-bin:$PATH"
	print_manual >"$self_test_work/plan.out"
	PATH=$old_path
	manual_sshd_onboard=no
	check 'the printed install uses the stable render path' \
		"$(grep -cF "doas install -m 0644 $render_path /etc/ssh/sshd_config.onboard" \
			"$self_test_work/plan.out")" 1
	check 'the plan names the rendered port' \
		"$(grep -cF "# rendered with Port 2233 from TUI_PORT" "$self_test_work/plan.out")" 1
	check 'the rendered file is root-only' \
		"$(find "$render_path" -perm 0600 | wc -l | tr -d ' ')" 1

	plan "$repo" ''
	check 'no base plans every script' "$(plan_order | paste -sd ' ' -)" \
		'deploy-control.sh deploy-nsd.sh deploy-mail.sh deploy-relayd.sh'

	all_scripts=no
	reset_plan
	check 'a clean range records' "$(if gate; then printf yes; else printf no; fi)" yes
	manual_pf=yes
	check 'a manual step blocks recording' "$(if gate; then printf yes; else printf no; fi)" no
	all_scripts=yes
	manual_pf=no
	check '--all does not record' "$(if gate; then printf yes; else printf no; fi)" no
	all_scripts=no

	printf 'abc123\t2026-10-22T00:00:00Z\n' >"$self_test_work/old-marker"
	check "the marker's commit is read" "$(marker_base "$self_test_work/old-marker")" abc123
	write_marker "$self_test_work/new-marker" deadbeef
	check 'the marker is written' "$(marker_base "$self_test_work/new-marker")" deadbeef
	head=$(git -C "$repo" rev-parse HEAD)
	record_now "$repo" "$self_test_work/recorded"
	check 'record_now writes HEAD' "$(marker_base "$self_test_work/recorded")" "$head"

	# A scripts/ path with no arm and no install row now fails the plan instead of
	# planning nothing, which is how a change to a script nothing installs was
	# skipped.
	printf 'x\n' >"$repo/scripts/unknown-helper.sh"
	git -C "$repo" add -A
	git -C "$repo" commit -qm five
	got=0
	( plan "$repo" "$head" ) >/dev/null 2>&1 || got=$?
	check 'an uninstalled script fails the plan' "$got" 1

	# A range that only changes the hand-applied doas fragment must not record:
	# the rule is copied into /etc/doas.conf by hand, and the marker says the
	# release is applied.
	doas_base=$(git -C "$repo" rev-parse HEAD)
	printf 'permit nopass _onboard as root cmd /usr/local/libexec/kyriakon-authcheck\n' \
		>"$repo/openbsd/etc/doas.conf.control"
	git -C "$repo" add -A
	git -C "$repo" commit -qm doas
	all_scripts=no
	plan "$repo" "$doas_base"
	check 'a doas-only range plans deploy-control' "$needs_control" yes
	check 'and marks the rule as manual' "$manual_doas" yes
	check 'and does not advance the marker' \
		"$(if gate; then printf yes; else printf no; fi)" no

	self_test_end
}

main "$@"
