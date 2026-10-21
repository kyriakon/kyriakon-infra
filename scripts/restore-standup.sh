#!/bin/ksh
# restore-standup.sh — run the weekly restore test on a box that exists for the run.
#
# Runs ON the mail box, weekly from cron, installed into /root/bin by
# scripts/deploy-mail.sh.
#
# The test used to run on a second box that was always on, which cost more per month than
# the mail box itself. Nothing about it needs a permanent machine: it needs a box for the
# minutes the restore takes, and it needs that box to not be the mail box. So this applies
# the hcloud CLI to create one, runs restore-test.sh on it over ssh, and destroys it on
# every exit path.
#
# The API by CLI rather than terraform, because the hcloud provider publishes no OpenBSD
# build. `terraform init` on a root using it fails on this platform at every provider
# version, so terraform cannot drive this box from here at all. The CLI is packaged for
# OpenBSD, which the provider is not.
#
# What terraform was there for was the destroy being unable to reach the mail box, since
# destroy only removes what is in the state it runs against. The same property holds here
# by a narrower route: the server is created once, its id captured, and everything after
# that in this script refers to that id and never to a name or a list. A delete cannot
# resolve to anything but the box this run made. The mail box keeps its own protection
# besides, the live root's prevent_destroy and Hetzner's delete_protection, both unchanged.
#
# Requires, in /root/.kyriakon-env:
#   HCLOUD_TOKEN                    the Hetzner Cloud token the hcloud CLI reads
#   RESTORE_TEST_REPOSITORY         READ-ONLY sub-account url, not the backup one
#   RESTORE_TEST_HEALTHCHECKS_URL   the restore check, whose period is weekly
#
# Also requires the hcloud CLI and jq (doas pkg_add hcloud jq), a private key at
# /root/.ssh/kyriakon-standup whose public half is in the template's
# /root/.ssh/authorized_keys, and two files this box already has: the restic password at
# /root/.restic-pass, and the READ-ONLY storage sub-account's private key.
#
# The test script is not taken from the image as the source of truth: this copies the
# checkout's scripts/restore-test.sh and scripts/lib.sh over after every boot, so a fix
# to the test takes effect on the next weekly run without rebuilding a snapshot.
# RESTORE_TEST_SCRIPT_DIR overrides where that checkout is.
#
# The template is a plain box, and that is forced rather than chosen. A softraid crypto
# root stops at the passphrase prompt, and nobody is at the console at 03:45 on the
# morning the test runs, so a template built from an encrypted box never reaches ssh and
# the run dies on its own timeout every week without testing anything. The template
# therefore carries no softraid at all, and the credentials it needs arrive after every
# boot: this script copies the restic password and the read-only key over ssh before the
# test runs. Nothing secret is baked into the image, which is also the better
# arrangement, since an image outlives the box it was made from.
#
# The cost of that is the throwaway's disk, which is plaintext for the minutes the run
# takes and is not wiped when Hetzner frees it. The restored mail is PGP ciphertext and
# the read-only key cannot write to the repository, so what a future holder of that disk
# could read is the restored site and git content plus read access to the backups. An
# encrypted scratch volume would remove that, and is a follow-up rather than part of this:
# it needs a throwaway box to prove the unlock works on, and there is no spare box.
#
# The read-only sub-account is the point rather than a detail: the test restores from the
# repository and must not be able to write to it, so a fault on a throwaway box cannot
# damage the backup it is testing.
#
# Usage:
#   ksh restore-standup.sh             # apply, test, destroy
#   ksh restore-standup.sh --dry-run   # print what it would run, touch nothing
#
# The exit status is the test's, so cron and the healthcheck see a real failure. The
# destroy lives in an EXIT trap rather than at the end of the script, because a box
# created and not destroyed bills by the month, which is the cost this exists to avoid.

set -euo pipefail
umask 077

die() {
	printf 'restore-standup: %s\n' "$*" >&2
	exit 1
}

# Only --dry-run is recognised, and anything else stops the run before it reads
# the env file. The test was a single exact match, so every other word fell
# through to the live path: a hand run of `restore-standup.sh --dryrun` created a
# cx23 and pushed the restic password and the read-only key to it, which is the
# one thing the flag is there to prevent.
[ "$#" -le 1 ] || die "one argument at most: --dry-run (got: $*)"
dry_run=no
case "${1:-}" in
'') ;;
--dry-run) dry_run=yes ;;
*) die "unknown argument: $1 (known: --dry-run, or nothing for a live run)" ;;
esac

env_file="${KYRIAKON_ENV:-/root/.kyriakon-env}"
if [ ! -f "$env_file" ]; then
	printf '%s: no %s\n' "$0" "$env_file" >&2
	exit 1
fi
# shellcheck disable=SC1090 # the path is the box's, not this repo's
. "$env_file"

# lib.sh holds notify_operator, the one way a scheduled script mails the operator.
# Installed beside this script, as its header says.
script_dir="$(dirname "$0")"
if [ ! -f "$script_dir/lib.sh" ]; then
	printf '%s: lib.sh is not in %s. Install the two files together, as lib.sh describes.\n' \
		"$0" "$script_dir" >&2
	exit 1
fi
# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
. "$script_dir/lib.sh"

: "${HCLOUD_TOKEN:?HCLOUD_TOKEN is required, in $env_file}"
: "${RESTORE_TEST_REPOSITORY:?RESTORE_TEST_REPOSITORY is required, in $env_file}"

image_label="${RESTORE_TEST_IMAGE_LABEL:-kind=restore}"
server_name="${RESTORE_TEST_SERVER_NAME:-kyriakon-restore-test}"
server_type="${RESTORE_TEST_SERVER_TYPE:-cx23}"
location="${RESTORE_TEST_LOCATION:-fsn1}"
server_id=''
ssh_key="${RESTORE_TEST_SSH_KEY:-/root/.ssh/kyriakon-standup}"
known_hosts="${RESTORE_TEST_KNOWN_HOSTS:-/root/.ssh/known_hosts.standup}"
ro_key="${RESTORE_TEST_RO_KEY:-/root/.ssh/kyriakon-restore-readonly}"
ro_password="${RESTORE_TEST_PASSWORD_FILE:-/root/.restic-pass}"
test_script_dir="${RESTORE_TEST_SCRIPT_DIR:-/usr/local/src/kyriakon-infra/scripts}"
healthchecks="${RESTORE_TEST_HEALTHCHECKS_URL:-}"
server_ip=''

# The two values that travel to the far side inside a shell command line. A single quote
# would end that quoting early and run the rest as a command, so refuse them rather than
# escaping: setup-env.sh refuses them for the same reason.
case "${RESTORE_TEST_REPOSITORY}${healthchecks}" in
*"'"*) die "a repository url or healthcheck url contains a single quote" ;;
esac

[ -f "$ssh_key" ] || die "no ssh key at $ssh_key"
[ -f "$ro_key" ] || die "no read-only storage key at $ro_key"
[ -f "$ro_password" ] || die "no restic password file at $ro_password"
for s in restore-test.sh lib.sh; do
	[ -f "$test_script_dir/$s" ] \
		|| die "no $test_script_dir/$s: the weekly test runs the checkout's script, and the checkout is what this box deploys from"
done

# Nothing is mailed, cleaned up or redirected before this point: the checks above
# are the ones that stop a hand run before it touches anything, and they say so on
# the terminal. Everything after it is the run's report.
if [ "$dry_run" = yes ]; then
	printf 'dry-run: hcloud image list -t snapshot -l %s -o noheader -o columns=id\n' "$image_label"
	printf 'dry-run: hcloud server create --name %s --type %s --image <id> --location %s -o json\n' "$server_name" "$server_type" "$location"
	printf 'dry-run: hcloud server ip <id>\n'
	printf 'dry-run: mount_mfs -s 128M swap /root/scratch, with the credentials, the restore target and the cache inside it\n'
	printf 'dry-run: ssh -i %s root@<address> mkdir -p /root/.ssh\n' "$ssh_key"
	printf 'dry-run: scp-equivalent: %s -> root@<address>:/root/.ssh/id_ed25519\n' "$ro_key"
	printf 'dry-run: scp-equivalent: %s -> root@<address>:/root/scratch/restic-pass\n' "$ro_password"
	printf 'dry-run: copy %s/restore-test.sh and %s/lib.sh to root@<address>:/root/bin\n' "$test_script_dir" "$test_script_dir"
	printf 'dry-run: ssh -i %s root@<address> RESTIC_REPOSITORY=... /root/bin/restore-test.sh\n' "$ssh_key"
	printf 'dry-run: hcloud server delete <id>       # the id this run created, never a name\n'
	printf 'dry-run: nothing was created, nothing was destroyed\n'
	exit 0
fi

# --- the report, which is also the operator mail ----------------------------
# From here every line the run produces goes to a file, and the trap below mails it
# under a subject naming the component and the event. cron mails what a job prints
# under a subject of its own, so printing the same words would send the operator the
# good mail and the guff. Nothing is mailed for a run that succeeded: the weekly
# healthcheck is the signal for that, as the header says. The lines below carry on
# being written exactly as they were, and only their destination changes.
report=$(mktemp)
exec 3>&1 4>&2
exec >> "$report" 2>&1

# The EXIT trap below invokes this, which shellcheck cannot follow. Two codes name
# the same thing: SC2329 where shellcheck calls it unused, SC2317 where it calls
# the body unreachable. The runner image's shellcheck is older than a
# workstation's, and it emits the second, so both are named here.
# shellcheck disable=SC2317,SC2329
cleanup() {
	cleanup_status=$?
	# The report goes back out on the streams cron reads before the mail is sent, so
	# an alert that could not be mailed is printed rather than written into the file
	# this is about to delete: cron's copy is ugly and a silent failure is worse.
	exec 1>&3 2>&4
	if [ -n "$server_id" ]; then
		printf 'deleting server %s\n' "$server_id"
		if ! hcloud server delete "$server_id"; then
			printf 'restore-standup: the box is still there. It bills until it is gone.\n' >&2
			notify_operator backup "restore server left behind" \
				"the throwaway box $server_id was created and could not be deleted, and it bills until it is gone." \
				"delete it: hcloud server delete $server_id"
		fi
	fi
	if [ "$cleanup_status" -ne 0 ]; then
		# The box is only known to be gone when there was an id to delete. A create
		# whose reply never arrived leaves none, and this line asserted the box had
		# been destroyed either way, which is the one thing a stranded box must not
		# be told.
		if [ -n "$server_id" ]; then
			gone="and the box it ran on has been destroyed"
		else
			gone="and no box was created by this run, or one was created and this run cannot name it: check for one that bills with hcloud server list -o noheader -o columns=id,name"
		fi
		# Every line the run produced, which is what cron used to mail under its own
		# subject, and what the operator needs to see beside the failure.
		notify_operator backup "restore test failed" "$(cat "$report")" \
			"read the lines above: the test's own output is there, $gone. The weekly healthcheck stays unpinned for a run that never got this far, so it is the channel that covers a failure of this one."
	fi
	rm -f "$report"
	exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

command -v hcloud >/dev/null 2>&1 || die "no hcloud on this box, run: doas pkg_add hcloud"
command -v jq >/dev/null 2>&1 || die "no jq on this box, run: doas pkg_add jq"

# The image is looked up by label rather than pinned by id, so rebuilding the template is
# snapshot and label with nothing to edit here. An empty answer stops the run, because
# creating from a missing image gives a box that cannot boot and a waste of a month's
# billing to notice.
image_ids=$(hcloud image list -t snapshot -l "$image_label" -o noheader -o columns=id)
[ -n "$image_ids" ] || die "no snapshot labelled $image_label; build the template, or set RESTORE_TEST_IMAGE_LABEL"
# Exactly one. hcloud lists oldest first, so taking the first match would quietly
# boot the oldest of a set, and a repaired template sitting beside the one it
# replaced is the ordinary way to end up with two. Which of them runs the test is
# a decision for a person, not for the order of an API reply.
image_count=$(printf '%s\n' "$image_ids" | grep -c .)
[ "$image_count" -eq 1 ] \
	|| die "$image_count snapshots are labelled $image_label, so which one boots the test is a coin toss; remove or relabel all but one: $(printf '%s' "$image_ids" | tr '\n' ' ')"
image_id=$image_ids

# The id is captured here and used for every later reference. That is the whole safety
# argument: no name lookup, no list, nothing that could resolve to another server.
printf 'creating %s from image %s\n' "$server_name" "$image_id"
# The status is caught rather than left to set -e, because the API can accept a
# create and the reply be lost: a dropped connection or a timeout aborted here
# with no id captured, so the exit path had nothing to delete and the failure
# mail said the box had been destroyed. The id is what the whole safety argument
# rests on, so a create that did not report one is the case that has to be loud.
create_rc=0
create_out=$(hcloud server create --name "$server_name" --type "$server_type" \
	--image "$image_id" --location "$location" -o json) || create_rc=$?
[ "$create_rc" -eq 0 ] \
	|| die "hcloud server create exited $create_rc, so a server named $server_name \
may have been created with no id this run can delete. Check for it and remove it by hand: \
hcloud server list -o noheader -o columns=id,name, then hcloud server delete <id>. \
hcloud said: ${create_out:-<nothing>}"
# This reply has come back wrapped as {"server": {...}, "root_password": "..."}, and
# older hcloud reported a bare object or a one-element array. Accept all three, and keep
# the expression total: anything else yields an empty id rather than a jq error under
# set -e, so every unexpected shape reaches the message below instead of dying at the
# assignment.
server_id=$(printf '%s' "$create_out" \
	| jq -r '.server?.id? // .id? // .[0]?.id? // ""' 2>/dev/null || true)
case "${server_id:-}" in
''|null)
	# Blank it, so the exit path cannot fall back to a name: without an id there is no
	# way to be sure which server a delete would reach, and a name may be one that
	# already existed. The box created above is the operator's to find and remove.
	server_id=''
	# The reply carries root_password for the new box, and this message reaches both the
	# operator and the alert mail, so the password is removed from it here. It is not
	# rendered at all next to an id, since that path never prints the reply.
	said=$(printf '%s' "$create_out" | jq -c 'del(.root_password)' 2>/dev/null \
		|| printf '%s' "${create_out:-<nothing>}")
	die "hcloud reported no server id for $server_name, so this run may not delete it. \
That server now exists and bills until it is gone; remove it by hand. \
$(hcloud version) said: $said"
	;;
esac
printf 'server id %s\n' "$server_id"

server_ip=$(hcloud server ip "$server_id")
[ -n "$server_ip" ] || die "hcloud reported no ipv4_address for server $server_id"
printf 'box is at %s\n' "$server_ip"

# The box is new, so its host key is unknown by definition. accept-new pins it on this
# first connection, and the file is truncated at the start of every run, so the pin lasts
# exactly as long as the box: no growing file, and no second chance for a key that changes
# mid-run.
: >"$known_hosts"

remote() {
	ssh -i "$ssh_key" -o BatchMode=yes -o ConnectTimeout=10 \
		-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$known_hosts" \
		"root@$server_ip" "$@"
}

# Copy one local file to the box, for the credentials the template cannot carry. Written
# as a redirect rather than scp so it travels down the same ssh invocation as everything
# else, with the same key and the same host-key pin.
push() {
	remote "cat > $1 && chmod ${3:-600} $1" <"$2"
}

# hcloud server create returns once the API has the server, which is before it has
# finished booting, so this is a short wait for ssh rather than for the API.
attempt=0
until remote true 2>/dev/null; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 45 ]; then
		die "no ssh on $server_ip after $((attempt * 10))s"
	fi
	sleep 10
done
printf 'ssh answered after %ss\n' "$((attempt * 10))"

# The scratch everything sensitive lands in is a memory filesystem. Hetzner frees a
# deleted server's disk without wiping it, so anything written to that disk may be read by
# whoever gets the physical device next, and what a run writes is the restored /etc/mail
# with the DKIM keys in it and the backup repository's password. mount_mfs builds a file
# system in virtual memory, backed by swap when memory runs low, and OpenBSD encrypts swap
# with keys generated fresh at every boot and held only in memory, so its contents do not
# outlive the box that held them. One mount is enough: the restore target lives inside it,
# and the test's own wipe of that target cannot reach the password sitting beside it.
#
# It is mfs and not tmpfs. mount_tmpfs is still installed, but tmpfs was removed from the
# kernel years ago, so the binary existing proves nothing and the mount fails with
# "Operation not supported". On mount_mfs the -m flag is the minfree percentage rather than
# a mode, so the mount point's own mode is what the filesystem inherits, and it is set
# there. -s takes a size with a multiplier, or sectors.
remote 'mkdir -p -m 0700 /root/scratch && mount_mfs -s 128M swap /root/scratch' \
	|| die "could not mount the scratch memory filesystem on $server_ip"
remote 'mount | grep " /root/scratch "'
printf 'scratch is a memory filesystem\n'
# That the tmpfs is safe rests on one assumption: pages pushed out to swap are encrypted
# with a key the kernel made at boot and keeps only in memory. If encryption were off, the
# same pages would sit in the clear on a disk that outlives the box, which is precisely
# what putting them in memory was for, so it is checked rather than assumed.
remote 'sysctl vm.swapencrypt.enable' | grep -q '=1' \
	|| die "swap encryption is off on $server_ip, so the scratch memory filesystem would not keep the secrets off the disk"
printf 'swap is encrypted, so anything paged out is unreadable once this box is gone\n'

# The test's own exit status is the script's, so a failure is a failure for cron and for
# the healthcheck, which the test pings itself.
# The credentials, after the boot and before the test. The mailbox's own known_hosts
# comes along because restic's sftp backend shells out to sftp, which has none of the
# flags above and would otherwise refuse the storage host as unknown.
remote 'mkdir -p /root/.ssh'
push /root/.ssh/id_ed25519 "$ro_key"
push /root/.ssh/known_hosts /root/.ssh/known_hosts
# The key stays where ssh looks for it, because restic's sftp backend shells out to ssh
# and only a change to the test script could point it elsewhere. On its own that key is
# read-only against one sub-account and reveals ciphertext, since the repository is
# encrypted; the password is what makes it readable, which is why that one has to be
# somewhere the box does not keep.
push /root/scratch/restic-pass "$ro_password"
printf 'credentials in place\n'

# The test script itself comes from this box's checkout, not from the image. The
# template carries a copy so a box can be tested by hand, but a copy in an image
# drifts: the weekly run would test whatever the template was built from, which is
# how a fix to the test reaches nobody until someone rebuilds a snapshot. The
# checkout is the deploy's own source, so this is the file the deploy names.
remote 'mkdir -p /root/bin'
push /root/bin/restore-test.sh "$test_script_dir/restore-test.sh" 755
push /root/bin/lib.sh "$test_script_dir/lib.sh" 755
printf 'test scripts in place, from %s\n' "$test_script_dir"

set +e
remote "RESTIC_REPOSITORY='$RESTORE_TEST_REPOSITORY' \
RESTIC_PASSWORD_FILE=/root/scratch/restic-pass \
RESTORE_TARGET_ROOT=/root/scratch/restore \
RESTIC_CACHE_DIR=/root/scratch/restic-cache \
TMPDIR=/root/scratch \
HEALTHCHECKS_URL='$healthchecks' /root/bin/restore-test.sh"
test_status=$?
set -e

# The test announces its own success, so only the failure needs saying here. Saying it
# twice makes the log read as though two things passed.
if [ "$test_status" -ne 0 ]; then
	printf 'restore-standup: the restore test failed with status %s\n' "$test_status" >&2
fi
exit "$test_status"
