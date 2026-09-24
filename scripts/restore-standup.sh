#!/bin/ksh
# restore-standup.sh — run the weekly restore test on a box that exists for the run.
#
# Runs ON the mail box, weekly from cron, installed into /root/bin by
# scripts/deploy-mail.sh.
#
# The test used to run on a second box that was always on, which cost more per month than
# the mail box itself. Nothing about it needs a permanent machine: it needs a box for the
# minutes the restore takes, and it needs that box to not be the mail box. So this applies
# terraform to create one, runs restore-test.sh on it over ssh, and destroys it again on
# every exit path.
#
# Terraform rather than the API by hand because the box's definition belongs in code, in
# terraform/throwaway, with its own state file separate from the live root's. That
# separation is what makes an unattended destroy safe: terraform can only remove what is
# in the state it is run against, and the mail box is not in this one. See that root's
# providers.tf before changing anything about it.
#
# Requires, in /root/.kyriakon-env:
#   HCLOUD_TOKEN                    the Hetzner Cloud token terraform reads
#   RESTORE_TEST_REPOSITORY         READ-ONLY sub-account url, not the backup one
#   RESTORE_TEST_HEALTHCHECKS_URL   the restore check, whose period is weekly
#
# Also requires terraform (pkg_add terraform), a one-time init in the root, a private key
# at /root/.ssh/kyriakon-standup whose public half is in the template's
# /root/.ssh/authorized_keys, and two files this box already has: the restic password at
# /root/.restic-pass, and the READ-ONLY storage sub-account's private key.
#
# The template is a plain box, and that is forced rather than chosen. A softraid crypto
# root stops at the passphrase prompt, and nobody is at the console at 03:45 on a Sunday,
# so a template built from an encrypted box never reaches ssh and the run dies on its own
# timeout every week without testing anything. The template therefore carries no softraid
# at all, and the credentials it needs arrive after every boot: this script copies the
# restic password and the read-only key over ssh before the test runs. Nothing secret is
# baked into the image, which is also the better arrangement, since an image outlives the
# box it was made from.
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

dry_run=no
if [ "${1:-}" = "--dry-run" ]; then
	dry_run=yes
fi

env_file="${KYRIAKON_ENV:-/root/.kyriakon-env}"
if [ ! -f "$env_file" ]; then
	printf '%s: no %s\n' "$0" "$env_file" >&2
	exit 1
fi
# shellcheck disable=SC1090 # the path is the box's, not this repo's
. "$env_file"

die() {
	printf 'restore-standup: %s\n' "$*" >&2
	exit 1
}

# Alert off-box. cron mails root once and then silence looks exactly like health, which
# this job has already been bitten by. The healthcheck is the real dead-man's switch: a
# run that never reaches the test leaves its weekly check unpinned, and the check alerts
# on its own.
# Called from the trap path rather than inline, which shellcheck cannot follow.
# shellcheck disable=SC2329
alert() {
	[ -n "${ALERT_EMAIL:-}" ] || return 0
	printf '%s\n' "$*" | mail -s "restore standup failed" "$ALERT_EMAIL" 2>/dev/null || true
}

: "${HCLOUD_TOKEN:?HCLOUD_TOKEN is required, in $env_file}"
: "${RESTORE_TEST_REPOSITORY:?RESTORE_TEST_REPOSITORY is required, in $env_file}"

tf_root="${RESTORE_TEST_TF_ROOT:-/root/kyriakon-infra/terraform/throwaway}"
ssh_key="${RESTORE_TEST_SSH_KEY:-/root/.ssh/kyriakon-standup}"
known_hosts="${RESTORE_TEST_KNOWN_HOSTS:-/root/.ssh/known_hosts.standup}"
ro_key="${RESTORE_TEST_RO_KEY:-/root/.ssh/kyriakon-restore-readonly}"
ro_password="${RESTORE_TEST_PASSWORD_FILE:-/root/.restic-pass}"
healthchecks="${RESTORE_TEST_HEALTHCHECKS_URL:-}"
server_ip=''
applied=no

# The two values that travel to the far side inside a shell command line. A single quote
# would end that quoting early and run the rest as a command, so refuse them rather than
# escaping: setup-env.sh refuses them for the same reason.
case "${RESTORE_TEST_REPOSITORY}${healthchecks}" in
*"'"*) die "a repository url or healthcheck url contains a single quote" ;;
esac

[ -d "$tf_root" ] || die "no terraform root at $tf_root"
[ -d "$tf_root/.terraform" ] || die "$tf_root has never been initialised, run: terraform -chdir=$tf_root init"
[ -f "$ssh_key" ] || die "no ssh key at $ssh_key"
[ -f "$ro_key" ] || die "no read-only storage key at $ro_key"
[ -f "$ro_password" ] || die "no restic password file at $ro_password"

# The EXIT trap below invokes this, which shellcheck cannot follow.
# shellcheck disable=SC2329
cleanup() {
	cleanup_status=$?
	if [ "$applied" = yes ]; then
		printf 'destroying the box\n'
		if ! terraform -chdir="$tf_root" destroy -auto-approve -input=false -no-color; then
			printf 'restore-standup: the box is still there. It bills until it is gone.\n' >&2
			alert "terraform destroy failed in $tf_root, and the box bills until it is gone"$'\n'"run: terraform -chdir=$tf_root destroy -auto-approve"
		fi
	fi
	if [ "$cleanup_status" -ne 0 ]; then
		alert "the restore standup failed with status $cleanup_status"
	fi
	exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

if [ "$dry_run" = yes ]; then
	printf 'dry-run: terraform -chdir=%s init -input=false\n' "$tf_root"
	printf 'dry-run: terraform -chdir=%s state list   # must hold only the test box\n' "$tf_root"
	printf 'dry-run: terraform -chdir=%s apply -auto-approve -input=false -no-color\n' "$tf_root"
	printf 'dry-run: terraform -chdir=%s output -raw ipv4_address\n' "$tf_root"
	printf 'dry-run: ssh -i %s root@<address> mkdir -p /root/.ssh\n' "$ssh_key"
	printf 'dry-run: scp-equivalent: %s -> root@<address>:/root/.ssh/id_ed25519\n' "$ro_key"
	printf 'dry-run: scp-equivalent: %s -> root@<address>:/root/.restic-pass\n' "$ro_password"
	printf 'dry-run: ssh -i %s root@<address> RESTIC_REPOSITORY=... /root/bin/restore-test.sh\n' "$ssh_key"
	printf 'dry-run: terraform -chdir=%s destroy -auto-approve -input=false -no-color\n' "$tf_root"
	printf 'dry-run: nothing was created, nothing was destroyed\n'
	exit 0
fi

command -v terraform >/dev/null 2>&1 || die "no terraform on this box, run: doas pkg_add terraform"

# The one thing this script must never do is delete the box it is running on. State
# isolation is why that is structurally true, and this is the check that proves the
# separation has not quietly broken. Anything in this state beyond the throwaway box and
# its image lookup means the root has drifted, and the run stops before it touches
# anything rather than finding out inside a destroy. The three refusals in front of a
# mistaken destroy are, in order: this, the live root's prevent_destroy, and Hetzner's
# own delete_protection on the mail box.
# `|| true` because the first run has no state file, which is an error to terraform and
# an empty answer here.
state_list=$(terraform -chdir="$tf_root" state list 2>/dev/null || true)
if [ -n "$state_list" ]; then
	unexpected=$(printf '%s\n' "$state_list" | grep -Ev '^(data\.)?hcloud_(server|image)\.restore$' || true)
	if [ -n "$unexpected" ]; then
		die "the throwaway state holds something that is not the test box: $(printf '%s' "$unexpected" | tr '\n' ' ')"
	fi
fi

# Init is a no-op once the provider is installed, and it is what makes a lock file that
# arrived by git pull take effect without anyone remembering. A failure here is not fatal
# on its own: what matters is whether the apply below can run, and that says so plainly.
if ! terraform -chdir="$tf_root" init -input=false -no-color >/dev/null 2>&1; then
	printf 'restore-standup: terraform init failed, continuing with what is installed\n' >&2
fi

# Set before the apply rather than after, so an apply that half-succeeds still gets its
# destroy: the trap is the only thing standing between a failed run and a monthly bill.
applied=yes
printf 'applying %s\n' "$tf_root"
terraform -chdir="$tf_root" apply -auto-approve -input=false -no-color

server_ip=$(terraform -chdir="$tf_root" output -raw ipv4_address)
[ -n "$server_ip" ] || die "terraform reported no ipv4_address"
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
	remote "cat > $1 && chmod 600 $1" <"$2"
}

# terraform apply returns once the provider sees the box running, so this is a short wait
# for the boot to finish rather than for the API.
attempt=0
until remote true 2>/dev/null; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 45 ]; then
		die "no ssh on $server_ip after $((attempt * 10))s"
	fi
	sleep 10
done
printf 'ssh answered after %ss\n' "$((attempt * 10))"

# The test's own exit status is the script's, so a failure is a failure for cron and for
# the healthcheck, which the test pings itself.
# The credentials, after the boot and before the test. The mailbox's own known_hosts
# comes along because restic's sftp backend shells out to sftp, which has none of the
# flags above and would otherwise refuse the storage host as unknown.
remote 'mkdir -p /root/.ssh'
push /root/.ssh/id_ed25519 "$ro_key"
push /root/.ssh/known_hosts /root/.ssh/known_hosts
push /root/.restic-pass "$ro_password"
printf 'credentials in place\n'

set +e
remote "RESTIC_REPOSITORY='$RESTORE_TEST_REPOSITORY' RESTIC_PASSWORD_FILE=/root/.restic-pass HEALTHCHECKS_URL='$healthchecks' /root/bin/restore-test.sh"
test_status=$?
set -e

if [ "$test_status" -eq 0 ]; then
	printf 'restore test passed\n'
else
	printf 'restore-standup: the restore test failed with status %s\n' "$test_status" >&2
fi
exit "$test_status"
