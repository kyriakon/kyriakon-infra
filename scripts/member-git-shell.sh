#!/bin/ksh
# member-git-shell.sh — the member login shell on port 2222, confined.
#
# Installed by scripts/deploy-mail.sh and scripts/provision-member.sh as
# /usr/local/libexec/member-git-shell.sh, and named as the shell capability of
# the member login class in openbsd/etc/login.conf.d/member. sshd runs a
# session's login shell as `shell -c '<client command>'` (session.c do_child()),
# so this program receives exactly what a `git push` or `git fetch` sends.
#
# Why not git-shell(1) itself. git-shell parses `-c` and re-execs
# git-receive-pack or git-upload-pack with the client's path verbatim, so a
# member can name any path the account can reach. The port 22 sftp session is
# chrooted to /home/www/<user>.kyriakon.net, but 2222 is not chrooted, and the
# upload tree inside the chroot is the same directory the account owns outside
# it: upload a repository with an executable hooks/pre-receive (or a config
# naming core.fsmonitor) at /home/www/<user>.kyriakon.net/www/repo.git, then
# push to it on 2222 and git runs the hook as the member. git-shell also runs
# executables from ~/git-shell-commands as custom commands. This wrapper closes
# both: it accepts the three git commands and nothing else, it refuses any
# repository outside ~/repos/<name>.git, and it turns hooks and the monitor
# command off on the command line before git reads the repository's config.
#
# Why the path rules are strict. The member owns ~/repos, so the name is the
# only part a client controls, and a symlinked directory or repository can
# point anywhere. The path is built from the passwd home, its parent directory
# must be exactly ~/repos, and both the repos directory and an existing
# repository are resolved and compared with their literal paths, so a symlink
# planted in either place is refused rather than followed.
#
# Why the global config is nulled. `-c` outranks the repository config, but git
# also reads ~/.gitconfig and $XDG_CONFIG_HOME/git/config first, and ~ is the
# member's. A `uploadpack.packObjectsHook` there runs a command served by git
# upload-pack, which a fetch reaches without any repository hook. The wrapper
# therefore exports GIT_CONFIG_GLOBAL=/dev/null before the exec, which replaces
# both files; the repository's own config still applies, under the two -c
# settings above it.
#
# Why packObjectsHook needs no -c of its own. The setting landed in git 2.10,
# but upload-pack has read it only from protected configuration (the system,
# global and command scopes) since 2.38, so a repository-local value never
# runs; nulling the global file closes the only scope the member can write.
# The box's `git --version` must therefore be 2.38 or later, and
# packages.tsv installs git unversioned. An empty override is not the answer:
# `-c uploadpack.packObjectsHook=` is an empty command, and every fetch then
# dies in "cannot run :".
# shortcut: nothing enforces that version floor; add the check when
# install-packages.sh is next changed.
#
# The known exec channel the allowlist leaves open. A format defined by
# tar.<format>.command runs through git-upload-archive, one of the three
# allowlisted verbs, when the repository also sets tar.<format>.remote=true;
# user-defined formats are not remote-enabled without it. That is an exec
# channel for an account with no shell, so dropping upload-archive from the
# allowlist is what closes it. It stays because the per-member hosting spec
# names the verb, and changing the allowlist is a spec change, not a fix here.
# Why the ForceCommand mode. sshd's port 2222 block names this wrapper as its
# ForceCommand. sshd runs an external subsystem request through the login shell
# too (session_subsystem_req -> do_exec -> do_child), so the login-class wrapper
# already refused an sftp request on 2222; the ForceCommand states the boundary
# at the port as well, and holds if the login class ever names another shell.
# sshd runs a forced command through that shell with `-c`, so the argument it
# receives is this script's own name followed by `--force`, and the client's
# command is in SSH_ORIGINAL_COMMAND. For an sftp subsystem request that value is
# /usr/libexec/sftp-server, which the allowlist below refuses. A git push arrives
# with its own command in SSH_ORIGINAL_COMMAND and passes the same checks.
#
# Usage (sshd does this; a human only runs --self-test):
#   member-git-shell.sh -c "git-receive-pack '/home/<user>/repos/<name>.git'"
#   member-git-shell.sh -c "/usr/local/libexec/member-git-shell.sh --force"
#   member-git-shell.sh --self-test

set -euo pipefail

# sshd hands a session a PATH from /etc/login.conf, which this script does not
# want to depend on: git and the tools below are found here or not at all.
PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

git=/usr/local/bin/git
home=''

script_dir=$(cd "$(dirname "$0")" && pwd)
# The path sshd's ForceCommand string names, used to recognise a forced session:
# sshd runs the forced command through the login shell, which is this script.
self="$script_dir/${0##*/}"

usage() {
	printf 'usage: %s -c "<git-receive-pack|git-upload-pack|git-upload-archive> <path>"\n' "$0" >&2
	printf '       %s --self-test\n' "$0" >&2
	exit 1
}

die() {
	printf 'kyriakon git shell: %s\n' "$*" >&2
	exit 1
}

# client_command <argv>: print the command the session asked to run. sshd runs
# this script two ways. As the login shell it is `-c <command>`. As the port 2222
# ForceCommand it is still `-c`, with the forced string as the argument, because
# sshd runs a forced command through the login shell (session.c do_child()); the
# argument then reads `<path>/member-git-shell.sh --force` and the client's own
# command is in SSH_ORIGINAL_COMMAND. Both forms end at run_command below, so an
# sftp subsystem request, whose SSH_ORIGINAL_COMMAND is the sftp-server command,
# is refused there like any other non-git command.
client_command() {
	case "${1:-}" in
	-c)
		[ "$#" -eq 2 ] || usage
		if [ "$2" = "$self --force" ]; then
			printf '%s\n' "${SSH_ORIGINAL_COMMAND:-}"
		else
			printf '%s\n' "$2"
		fi
		;;
	*) usage ;;
	esac
}

# canonical <path>: the path with every symlink resolved, printing it. `pwd -P`
# rather than realpath(1), which is not in every userland this runs under.
canonical() {
	(cd "$1" 2>/dev/null && pwd -P)
}

# resolve_repo <argument>: print the path of the repository the client named, or
# refuse. The only accepted shapes put the repository directly in ~/repos and
# name it <name>.git:
#
#   /home/<user>/repos/<name>.git
#   ~/repos/<name>.git
#   repos/<name>.git
#
# Everything else is refused, including `..`, another absolute path, a name with
# a slash in it, and a symlink anywhere in the path.
resolve_repo() {
	typeset arg path root name base canon
	arg=$1
	# shellcheck disable=SC2088 # the client's literal ~, not this shell's
	case "$arg" in
	/*) path=$arg ;;
	'~/'*) path=$home/${arg#'~/'} ;;
	*) path=$home/$arg ;;
	esac
	root=$home/repos
	if [ "${path%/*}" != "$root" ]; then
		die "refusing a path outside $root: $arg"
	fi
	name=${path##*/}
	case "$name" in
	*.git) ;;
	*) die "refusing a repository not named <name>.git: $arg" ;;
	esac
	base=${name%.git}
	case "$base" in
	'' | *[!A-Za-z0-9._-]* | [!A-Za-z0-9]*)
		die "refusing a repository name with anything but letters, digits, dot, dash and underscore, starting with a letter or digit: $arg"
		;;
	esac
	# ~/repos is the member's, so it can be renamed and replaced with a symlink.
	canon=$(canonical "$root") || die "refusing: $root is not a directory"
	if [ "$canon" != "$root" ]; then
		die "refusing a repository under a symlinked $root: $arg"
	fi
	if [ -e "$path" ]; then
		canon=$(canonical "$path") || die "refusing a repository that is not a directory: $arg"
		if [ "$canon" != "$path" ]; then
			die "refusing a repository reached through a symlink: $arg"
		fi
	fi
	printf '%s\n' "$path"
}

# run_command <client command>: check and exec. Everything the client can name
# is decided here, before git starts.
run_command() {
	typeset command sub rest repo cand verb
	command=$1
	sub=''
	for cand in git-receive-pack git-upload-pack git-upload-archive; do
		if [ "${command#"$cand "}" != "$command" ]; then
			sub=$cand
			break
		fi
	done
	[ -n "$sub" ] ||
		die "refusing a command that is not git-receive-pack, git-upload-pack or git-upload-archive"
	rest=${command#"$sub "}
	[ -n "$rest" ] || die "refusing $sub with no repository"
	# git's client sq-quotes the path; the characters a quote could protect are
	# all outside the name rule above, so stripping the outer pair is enough and
	# anything cunning is refused by that rule.
	case "$rest" in
	"'"*"'")
		rest=${rest#"'"}
		rest=${rest%"'"}
		;;
	esac
	repo=$(resolve_repo "$rest") || exit 1
	# git's client names the dashed program; `git` takes the subcommand without
	# the prefix (`git receive-pack`, not `git git-receive-pack`).
	verb=${sub#git-}
	# The repository's config is written by the member, so hooks and the monitor
	# command are turned off on the command line: -c outranks the repository's
	# own config. /dev/null is not a directory, so no hook is found there.
	#
	# GIT_CONFIG_GLOBAL replaces ~/.gitconfig and $XDG_CONFIG_HOME/git/config
	# with an empty file. Without it a packObjectsHook in the member's global
	# config runs a command on a fetch, which the repository cannot turn off.
	export GIT_CONFIG_GLOBAL=/dev/null
	exec "$git" -c core.hooksPath=/dev/null -c core.fsmonitor=false "$verb" "$repo"
}

self_test() {
	# lib.sh is not installed beside this script: the live path runs as a
	# member and needs nothing from it, so only the test reads the checkout's.
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$script_dir/lib.sh"
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin
	tree=$self_test_work
	mkdir -p "$tree/home/alice/repos/pass.git" "$tree/bin"
	home=$(canonical "$tree/home/alice") || die "self-test: cannot resolve $tree/home/alice"

	# The global config a member can plant. Real git reads packObjectsHook from
	# here on a fetch unless GIT_CONFIG_GLOBAL points elsewhere, and the stub
	# below models that one setting, so the marker is a real assertion that the
	# wrapper nulled the file rather than a check that always passes.
	printf '[uploadpack]\n\tpackObjectsHook = touch %s\n' "$tree/global-hook-ran" \
		>"$home/.gitconfig"

	# The stub stands in for git: it records the argv and the global config path
	# it was handed. Nothing here opens a network connection.
	cat >"$tree/bin/git" <<EOF
#!/bin/ksh
printf '%s\n' "\$*" >>'$tree/git.argv'
printf '%s\n' "\${GIT_CONFIG_GLOBAL:-unset}" >>'$tree/git.env'
if [ "\${GIT_CONFIG_GLOBAL:-unset}" != /dev/null ] && grep -q packObjectsHook '$home/.gitconfig'; then
	touch '$tree/global-hook-ran'
fi
EOF
	chmod 0755 "$tree/bin/git"
	git=$tree/bin/git

	# A push or fetch naming anything but ~/repos/<name>.git is refused before
	# git starts: the upload tree (outside this script's allowlist by design),
	# `..` climbing, and a command that is not git.
	for command in \
		"git-receive-pack '/home/www/alice.kyriakon.net/www/repo.git'" \
		"git-upload-pack '/home/www/alice.kyriakon.net/www/repo.git'" \
		"git-upload-archive '/home/www/alice.kyriakon.net/www/repo.git'" \
		"git-receive-pack 'repos/../pass.git'" \
		"git-upload-pack '$home/repos/../repos/pass.git'" \
		"git-receive-pack 'repos/pass.git/../../etc/passwd'" \
		"git-receive-pack 'repos/pass.git extra'" \
		"sh -c id" \
		"git-receive-pack"
	do
		rm -f "$tree/git.argv" "$tree/git.env"
		rc=0
		( run_command "$command" ) >/dev/null 2>&1 || rc=$?
		check "refused before git runs: $command" \
			"$rc/$([ -e "$tree/git.argv" ] && printf ran || printf stopped)" '1/stopped'
	done

	# ~/repos can be replaced with a symlink to the upload tree, so a symlinked
	# repos directory is refused even though its path looks right.
	mkdir -p "$tree/home/bob"
	ln -s "$home/repos" "$tree/home/bob/repos"
	mkdir -p "$tree/home/carol/repos"
	ln -s "$home/repos/pass.git" "$tree/home/carol/repos/pass.git"
	saved_home=$home
	rm -f "$tree/git.argv" "$tree/git.env"
	home=$tree/home/bob
	rc=0
	( run_command "git-receive-pack 'repos/pass.git'" ) >/dev/null 2>&1 || rc=$?
	check "refused through a symlinked repos directory" \
		"$rc/$([ -e "$tree/git.argv" ] && printf ran || printf stopped)" '1/stopped'
	home=$tree/home/carol
	rc=0
	( run_command "git-upload-pack 'repos/pass.git'" ) >/dev/null 2>&1 || rc=$?
	check "refused through a symlinked repository" \
		"$rc/$([ -e "$tree/git.argv" ] && printf ran || printf stopped)" '1/stopped'
	home=$saved_home

	# Every accepted spelling resolves to the same repository, and git is handed
	# the two -c settings that stop hooks and the monitor command from running.
	# shellcheck disable=SC2088 # the forms a client sends, ~ literal on purpose
	for arg in "repos/pass.git" "$home/repos/pass.git" "~/repos/pass.git"; do
		rm -f "$tree/git.argv" "$tree/git.env"
		rc=0
		( run_command "git-receive-pack '$arg'" ) >/dev/null 2>&1 || rc=$?
		check "accepts $arg" "$rc" 0
		check "and hands git the confined path for $arg" \
			"$(cat "$tree/git.argv" 2>/dev/null)" \
			"-c core.hooksPath=/dev/null -c core.fsmonitor=false receive-pack $home/repos/pass.git"
		check "and replaces the member's global config for $arg" \
			"$(cat "$tree/git.env" 2>/dev/null)" /dev/null
	done
	for arg in "repos/pass.git" "$home/repos/pass.git"; do
		rm -f "$tree/git.argv" "$tree/git.env"
		rc=0
		( run_command "git-upload-pack '$arg'" ) >/dev/null 2>&1 || rc=$?
		check "accepts a fetch of $arg" "$rc" 0
	done
	rm -f "$tree/git.argv" "$tree/git.env"
	( run_command "git-upload-archive '$home/repos/pass.git'" ) >/dev/null 2>&1 || true
	check "accepts an archive read" \
		"$(cat "$tree/git.argv" 2>/dev/null)" \
		"-c core.hooksPath=/dev/null -c core.fsmonitor=false upload-archive $home/repos/pass.git"

	# The member's global config defines a hook git runs on a fetch. The stub
	# runs it only when GIT_CONFIG_GLOBAL is not /dev/null, so a wrapper that
	# stopped exporting the null file fails here.
	check "the global config hook did not run" \
		"$([ -e "$tree/global-hook-ran" ] && printf yes || printf no)" no

	# sshd's port 2222 ForceCommand runs the login shell, which is this script,
	# with `-c` and the forced string as the argument, and leaves the client's
	# command in SSH_ORIGINAL_COMMAND. An sftp subsystem request puts
	# /usr/libexec/sftp-server in that variable, and the allowlist must refuse it
	# rather than let a server start; a git request must pass the same gate the
	# login shell does.
	forced="$self --force"
	SSH_ORIGINAL_COMMAND=/usr/libexec/sftp-server
	rc=0
	out=$( (run_command "$(client_command -c "$forced")") 2>&1) || rc=$?
	check "a forced sftp subsystem request is refused as a non-git command" \
		"$rc/$out" \
		'1/kyriakon git shell: refusing a command that is not git-receive-pack, git-upload-pack or git-upload-archive'
	SSH_ORIGINAL_COMMAND="git-upload-pack '$home/repos/pass.git'"
	rm -f "$tree/git.argv" "$tree/git.env"
	rc=0
	(run_command "$(client_command -c "$forced")") >/dev/null 2>&1 || rc=$?
	check "a forced upload-pack reaches the allowlist" "$rc" 0
	check "and hands git the confined path" \
		"$(cat "$tree/git.argv" 2>/dev/null)" \
		"-c core.hooksPath=/dev/null -c core.fsmonitor=false upload-pack $home/repos/pass.git"
	unset SSH_ORIGINAL_COMMAND

	self_test_end
}

case "${1:-}" in
--self-test)
	[ "$#" -eq 1 ] || usage
	self_test
	;;
esac

cmd=$(client_command "$@")

user=$(id -un) || die "cannot find the account name"
home=$(getent passwd "$user" 2>/dev/null | awk -F: 'NR == 1 { print $6 }')
[ -n "$home" ] || home=${HOME:-}
[ -n "$home" ] || die "cannot find the home directory of $user"
home=$(canonical "$home") || die "refusing: $home is not a directory"

[ -x "$git" ] || die "no git at $git"
run_command "$cmd"
