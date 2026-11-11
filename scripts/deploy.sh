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
# Two changes are never applied here. pf.conf is the operator's propose-only
# step, and sshd_config and its login class are installed by hand; the script
# prints the commands for both and does not advance the marker while one of
# them remains in the range. Apply the diff by hand, then run `--record`.
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
	manual_cron=no
	manual_env=no
	manual_terraform=no
}

# install_dests <script name> <table> — set the deploy flags for one script's
# install-set rows. A table this cannot read, or a destination no deploy
# installs, is an error rather than a silent skip: the alternative is a script
# that never reaches the box.
install_dests() {
	typeset name="$1" table="$2" dest dests
	[ -f "$table" ] || die "no install-set table at $table"
	dests=$(awk -F'\t' -v n="$name" '!/^#/ && $1 == n { print $2 }' "$table") ||
		die "cannot read $table"
	for dest in $dests; do
		case "$dest" in
		/root/bin) needs_mail=yes ;;
		drain) needs_control=yes ;;
		# Run from the checkout, so a change to it is installed by nothing: the
		# pull that changes it is the whole deploy.
		checkout) ;;
		*) die "unknown destination $dest for $name in $table" ;;
		esac
	done
}

# classify_script <path> — the scripts/ arms. Most scripts are routed by their
# install-set row, through install_dests at the end. The arms above it are the
# ones whose deploy is not their install: the scripts nothing installs, and the
# deploy scripts themselves, which plan the deploy they are.
classify_script() {
	case "$1" in
	# A helper of both the relay deploy and the drain's web pass, so a change to
	# it is both. Its one install row is the drain's.
	scripts/relayd-members.sh) needs_relayd=yes ;;
	# Its install row is the drain's, and the crontab it writes is a manual step.
	scripts/cron-apply.sh) manual_cron=yes ;;
	# The table itself: a row added or removed is an install on one side or the
	# other, and a schedule changed is the crontab, so a change here is both
	# deploys and the manual cron step rather than nothing.
	scripts/install-set.tsv)
		needs_mail=yes
		needs_control=yes
		manual_cron=yes
		return 0
		;;
	# Installed by deploy-control.sh under a name its own row could not carry
	# (/usr/local/libexec/kyriakon-authcheck), so its install is that script's
	# explicit line and this is its route.
	scripts/kyriakon-authcheck.sh)
		needs_control=yes
		return 0
		;;
	# Rendered into the capsule by the deploy and run from the checkout, so there
	# is no install row: the pages the handler serves are written by a deploy.
	scripts/render-docs.sh)
		needs_control=yes
		return 0
		;;
	# A deploy script's own code changed, so run it. `deploy.sh` itself is the
	# dispatcher and deliberately plans nothing.
	scripts/deploy-mail.sh)
		needs_mail=yes
		return 0
		;;
	scripts/deploy-relayd.sh)
		needs_relayd=yes
		return 0
		;;
	scripts/deploy-control.sh)
		needs_control=yes
		return 0
		;;
	scripts/deploy-nsd.sh)
		needs_nsd=yes
		return 0
		;;
	# The pf fragments live in the script; a change to it is still the propose-only
	# step, not a deploy this dispatcher runs.
	scripts/pf-apply.sh)
		manual_pf=yes
		return 0
		;;
	esac
	install_dests "${1#scripts/}" "$install_set"
}

# classify <path> — set the flags for one changed path. Returns 1 when the path
# has no rule, so `plan` can refuse the run and name every unclassified path.
classify() {
	case "$1" in
	control/*) needs_control=yes ;;
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
	openbsd/etc/login.conf.d/member)
		needs_control=yes
		manual_member_class=yes
		;;
	reserved-usernames.txt | scripts/control-store.sh) needs_control=yes ;;
	# The installed set is the table's: a script's row names the deploy that
	# installs it, so adding one is a row there and not an arm here.
	scripts/*) classify_script "$1" ;;
	keys/*) needs_mail=yes ;;
	terraform/*) manual_terraform=yes ;;
	docs/* | .github/* | .githooks/* | .omp/* | openbsd/restore-template/*) : ;;
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
		[ "$manual_member_class" = yes ] || [ "$manual_cron" = yes ] ||
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
	if [ "$manual_cron" = yes ]; then
		printf 'the crontab or its scripts changed:\n  doas ksh scripts/cron-apply.sh\n'
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
	classify 'scripts/deploy.sh'
	check 'the deploy script plans nothing' "$(plan_order)" ''
	reset_plan
	classify 'scripts/deploy-mail.sh'
	check 'the mail deploy plans itself' "$needs_mail" yes
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

	# Every row of the install-set table has to plan the deploy that installs it,
	# or a fix to that script lands in the checkout and never reaches the box. The
	# rows are read from the table rather than retyped here, so the check cannot
	# agree with a stale copy of it. render-docs.sh and kyriakon-authcheck.sh are
	# not rows: the one runs from the checkout and the other is installed under a
	# name its row could not carry.
	drain_rows=$(awk -F'\t' '!/^#/ && $2 == "drain" { print $1 }' "$install_set")
	root_bin_rows=$(awk -F'\t' '!/^#/ && $2 == "/root/bin" { print $1 }' "$install_set")
	check 'the table names drain scripts' \
		"$([ -n "$drain_rows" ] && printf yes || printf no)" yes
	check 'the table names /root/bin scripts' \
		"$([ -n "$root_bin_rows" ] && printf yes || printf no)" yes
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
	reset_plan
	classify 'scripts/install-set.tsv'
	check 'a table change plans both deploys and the cron step' \
		"$needs_mail $needs_control $manual_cron" 'yes yes yes'
	reset_plan
	classify 'openbsd/packages.tsv'
	check 'a package table change plans both deploys' \
		"$needs_mail $needs_control" 'yes yes'
	reset_plan
	classify 'scripts/kyriakon-authcheck.sh'
	check 'the libexec install plans deploy-control' "$needs_control" yes
	reset_plan
	classify 'scripts/render-docs.sh'
	check 'the pages renderer plans deploy-control' "$needs_control" yes
	# A destination nothing installs is refused rather than skipped: a row with a
	# typo in it would otherwise be a script no deploy puts on the box.
	printf 'new.sh\tsomewhere-else\t-\n' >"$self_test_work/unknown-dest.tsv"
	got=0
	( install_dests new.sh "$self_test_work/unknown-dest.tsv" ) >/dev/null 2>&1 || got=$?
	check 'an unknown destination is refused' "$got" 1
	got=0
	( install_dests new.sh "$self_test_work/no-such-table.tsv" ) >/dev/null 2>&1 || got=$?
	check 'a missing install-set table is refused' "$got" 1
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

	self_test_end
}

main "$@"
