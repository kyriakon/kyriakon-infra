#!/bin/ksh
# restore-standup.sh — stand up a throwaway restore-test box, run the test on it,
# tear it down again.
#
# Runs ON the mail box, weekly from cron, installed into /root/bin by
# scripts/deploy-mail.sh.
#
# The restore test used to run on a second box that was always on, which cost more
# per month than the mail box itself. Nothing about the test needs a permanent
# machine: it needs a box for the minutes the restore takes, and it needs that box
# to not be the mail box. So this creates one from a snapshot, runs restore-test.sh
# on it over ssh, and deletes it on every exit path.
#
# The snapshot carries everything the test needs, so no secret moves at run time and
# nothing is reinstalled:
#
#   /root/bin/restore-test.sh and lib.sh   the test
#   /root/.restic-pass                     the repository password
#   /root/.ssh/id_ed25519 and known_hosts  the read-only storage sub-account
#
# Requires, in /root/.kyriakon-env:
#   HCLOUD_TOKEN                    Hetzner Cloud API token, the one terraform uses
#   RESTORE_TEST_REPOSITORY         READ-ONLY sub-account url, not the backup one
#   RESTORE_TEST_HEALTHCHECKS_URL   the restore check, whose period is weekly
#
# Also requires `jq` on this box (pkg_add jq), a snapshot carrying a label that
# RESTORE_TEST_IMAGE_SELECTOR matches, and a private key at
# /root/.ssh/kyriakon-standup whose public half is in that snapshot's
# /root/.ssh/authorized_keys.
#
# The read-only sub-account is the point rather than a detail: the test restores
# from the repository and must not be able to write to it, so a fault on a
# throwaway box cannot damage the backup it is testing.
#
# Usage:
#   ksh restore-standup.sh             # create, test, delete
#   ksh restore-standup.sh --dry-run   # print the calls, create nothing
#
# The exit status is the test's, so cron and the healthcheck see a real failure. The
# deletion lives in an EXIT trap rather than at the end of the script, because a box
# created and not deleted bills by the month, which is the cost this exists to avoid.

set -euo pipefail
umask 077

api_base="${HETZNER_API:-https://api.hetzner.cloud/v1}"
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

# Alert off-box. cron mails root once and then silence looks exactly like health,
# which is the failure mode this box has already been bitten by. The healthcheck is
# the real dead-man's switch: a run that never reaches the test leaves its weekly
# check unpinned, and the check alerts on its own.
# Called from the trap path rather than inline, which shellcheck cannot follow.
# shellcheck disable=SC2329
alert() {
	[ -n "${ALERT_EMAIL:-}" ] || return 0
	printf '%s\n' "$*" | mail -s "restore standup failed" "$ALERT_EMAIL" 2>/dev/null || true
}

: "${HCLOUD_TOKEN:?HCLOUD_TOKEN is required, in $env_file}"
: "${RESTORE_TEST_REPOSITORY:?RESTORE_TEST_REPOSITORY is required, in $env_file}"

server_label='role=restore-test'
image_selector="${RESTORE_TEST_IMAGE_SELECTOR:-kind=restore}"
server_type="${RESTORE_TEST_SERVER_TYPE:-cx23}"
location="${RESTORE_TEST_LOCATION:-fsn1}"
ssh_key="${RESTORE_TEST_SSH_KEY:-/root/.ssh/kyriakon-standup}"
known_hosts="${RESTORE_TEST_KNOWN_HOSTS:-/root/.ssh/known_hosts.standup}"
healthchecks="${RESTORE_TEST_HEALTHCHECKS_URL:-}"
run_name="kyriakon-restore-test-$(date +%Y%m%dT%H%M%S)"
created_id=''
server_ip=''
test_status=0

# The two values that travel to the far side inside a shell command line. A single
# quote would end that quoting early and run the rest as a command, so refuse them
# rather than escaping: setup-env.sh refuses them for the same reason.
case "${RESTORE_TEST_REPOSITORY}${healthchecks}" in
*"'"*) die "a repository url or healthcheck url contains a single quote" ;;
esac

[ -f "$ssh_key" ] || die "no ssh key at $ssh_key"

api() {
	api_method="$1"
	api_path="$2"
	api_body="${3:-}"
	if [ "$dry_run" = yes ]; then
		printf 'dry-run: %s %s%s\n' "$api_method" "$api_base" "$api_path"
		if [ -n "$api_body" ]; then
			printf '         body %s\n' "$api_body"
		fi
		return 0
	fi
	if [ -n "$api_body" ]; then
		curl -fsS -X "$api_method" -H "Authorization: Bearer $HCLOUD_TOKEN" \
			-H 'Content-Type: application/json' -d "$api_body" "$api_base$api_path"
	else
		# -s with -S so a failure prints why, without a progress meter in cron mail.
		curl -fsS -X "$api_method" -H "Authorization: Bearer $HCLOUD_TOKEN" "$api_base$api_path"
	fi
}

# The server is created before the trap that knows how to delete it, so the id is
# checked inside the trap rather than there being two cleanup paths.
# The EXIT trap below invokes this, which shellcheck cannot follow.
# shellcheck disable=SC2329
cleanup() {
	cleanup_status=$?
	if [ -n "$created_id" ]; then
		printf 'deleting server %s\n' "$created_id"
		if ! api DELETE "/servers/$created_id" >/dev/null; then
			printf 'restore-standup: could not delete %s. It bills until it is gone.\n' \
				"$created_id" >&2
			alert "could not delete server $created_id, and it bills until it is gone"
		fi
	fi
	if [ "$cleanup_status" -ne 0 ]; then
		alert "the restore standup failed with status $cleanup_status"
	fi
	exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

# A box left behind by a run that was killed mid-flight bills every month, which is
# the cost this script exists to avoid. Only this script sets that label, so anything
# wearing it is ours to remove.
printf 'looking for boxes left by earlier runs\n'
stale_json=$(api GET "/servers?label_selector=$server_label")
if [ "$dry_run" = no ]; then
	stale_ids=$(printf '%s' "$stale_json" | jq -r '.servers[]?.id')
	stale_names=$(printf '%s' "$stale_json" | jq -r '.servers[]?.name' | tr '\n' ' ')
	if [ -n "$stale_names" ]; then
		printf 'removing %s\n' "$stale_names"
	fi
	for stale_id in $stale_ids; do
		api DELETE "/servers/$stale_id" >/dev/null \
			|| printf 'restore-standup: could not delete %s\n' "$stale_id" >&2
	done
fi

# The newest snapshot that matches, by id, rather than by a sort parameter: ids
# increase, and the label is the contract.
images_json=$(api GET "/images?type=snapshot&label_selector=$image_selector")
if [ "$dry_run" = yes ]; then
	image_id='<newest snapshot matching the selector>'
	printf 'dry-run: would use %s\n' "$image_selector"
else
	image_id=$(printf '%s' "$images_json" | jq -r '[.images[]?.id] | max // empty')
	[ -n "$image_id" ] || die "no snapshot matches label $image_selector"
	printf 'image: %s\n' "$image_id"
fi

create_body=$(printf '{"name":"%s","server_type":"%s","image":%s,"location":"%s","start_after_create":true,"labels":{"role":"restore-test"}}' \
	"$run_name" "$server_type" "$image_id" "$location")
create_json=$(api POST /servers "$create_body")

if [ "$dry_run" = yes ]; then
	server_ip='the address the API returns'
	printf 'dry-run: nothing was created, nothing was deleted\n'
	exit 0
fi

created_id=$(printf '%s' "$create_json" | jq -r '.server.id // empty')
server_ip=$(printf '%s' "$create_json" | jq -r '.server.public_net.ipv4.ip // empty')
[ -n "$created_id" ] || die "the create call returned no server id"
[ -n "$server_ip" ] || die "the create call returned no address"
printf 'created %s as %s\n' "$created_id" "$server_ip"

# The box is new, so its host key is unknown by definition. accept-new pins it on
# this first connection and the file is truncated at the start of every run, so the
# pin lasts exactly as long as the box: no growing file, and no second chance for a
# key that changes mid-run.
: >"$known_hosts"

remote() {
	ssh -i "$ssh_key" -o BatchMode=yes -o ConnectTimeout=10 \
		-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$known_hosts" \
		"root@$server_ip" "$@"
}

attempt=0
until remote true 2>/dev/null; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 45 ]; then
		die "no ssh on $server_ip after $((attempt * 10))s"
	fi
	sleep 10
done
printf 'ssh answered after %ss\n' "$((attempt * 10))"

# The test's own exit status is the script's, so a failure is a failure for cron and
# for the healthcheck, which the test pings itself.
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
