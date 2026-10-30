#!/bin/ksh
# acme-queue.sh - the certificate request queue: one request per name, worked
# oldest first, spaced against Let's Encrypt's refill rate.
#
# Usage:
#   doas ksh acme-queue.sh --add <name> [<site-owner>]
#                                          file one request (the signup path does this)
#   doas ksh acme-queue.sh --status        pending requests, oldest first, with ages; no attempt
#   doas ksh acme-queue.sh --run           attempt at most one name this pass
#        ksh acme-queue.sh --self-test     exercise the ordering and spacing unprivileged
#
# Runs ON the box. --add and --run need root (they write the store, and --run runs
# acme-client and touches /etc/ssl); --status only reads.
#
# Why a queue. A member's name is issued its own certificate by HTTP-01, and a new
# certificate spends the registered domain's budget of 50 per seven days, which
# refills at one certificate every 202 minutes (docs/planning/research/
# cert-issuance-ceiling.md, section 2). So issuance is not immediate and signup has
# to tolerate a pending state. The queue is the platform's own: nothing on the CA
# side waits, a rate-limited request is simply refused, and acme-client 7.9 does
# not read the Retry-After header that would say when to come back (its strings
# carry no "retry"; renew-acme.sh records the same finding). The spacing therefore
# lives here.
#
# How it spaces. --run makes at most one attempt per pass and records the time of
# every attempt in the store. A later pass will not attempt until 202 minutes have
# passed since the last one, whatever the outcome, so two names can never be
# attempted in the same pass and no two attempts are closer than one refill. The
# attempt is recorded even when it fails: the point of the spacing is to protect
# the CA's refill and the five-authorization-failures-per-identifier-per-hour
# limit, and neither of those cares whether the last attempt succeeded. A failed
# name is left pending, so its age keeps showing in --status.
#
# The budget, stated plainly because an own-domain body changes what a slot is
# spent from. The queue has one global slot: at most one attempt every 202
# minutes for the whole box, not one slot per name and not one per registered
# domain. A member name spends one of kyriakon.net's fifty. A group's domain
# order spends one of that domain's own fifty, because Let's Encrypt counts the
# registered domain (the eTLD+1) and the body's domain is its own; the platform's
# fifty is untouched. Either order occupies the queue's one slot for the pass
# that makes it, so it waits behind earlier requests.
#
# Why a name that does not resolve is held, not attempted. An HTTP-01 attempt
# against a name the world cannot resolve spends one of the five authorization
# failures allowed per identifier per hour, and 1,152 consecutive failures pause
# the identifier for the account until a human clears it (the same research
# section). So resolution is checked first, a name that does not resolve is left
# pending (held) and the next name that does resolve is attempted instead, so one
# member's missing record does not wedge the whole queue. If no pending name
# resolves, nothing is attempted and nothing is recorded.
#
# Renewals are exempt and never queue. An order that repeats the exact set of
# identifiers is a renewal and spends none of the 50, so scripts/renew-acme.sh
# renews on its own daily lane and never writes this store: a renewal does not wait
# behind the queue, and a lapsed certificate is worse than a slow signup. This
# script is first issues only.
#
# Values the spec leaves to the build, chosen boring, stated once here and once
# where each is read:
#   store          /var/db/kyriakon-acme-queue      (beside kyriakon-onboard and
#                                                    kyriakon-monitor under /var/db)
#   request file   <store>/pending/<name>           one per name; the mtime is when
#                                                    the request was filed and so its age
#   last attempt   <store>/last-attempt             the epoch seconds of the last attempt
#   run lock       <store>/run.lock                 one pass at a time
#   spacing        202 minutes                      the CA's published refill
#   alert age      1440 minutes (24 hours)          read by scripts/abuse-monitor.sh
# The store and the client and resolver commands are overridable (ACME_QUEUE_DIR,
# ACME_CLIENT, ACME_RESOLVER, ACME_SSL_DIR) so the queue can be exercised against
# a copy or a stub without touching the live store or the CA.
#
# What a successful attempt triggers. A certificate on disk is the member's site
# half becoming due: scripts/provision-member-web.sh writes the block behind the
# relay, and scripts/cron-apply.sh --web rewrites the indexes and the relayd
# member keypair region, checks the configs and reloads what changed. The pass
# runs both after it closes the request, from the directory scripts/deploy-onboard.sh
# installs the drain's scripts in. That path is read from the `scripts` key of
# /etc/kyriakon/onboard/drain.toml, with the compiled-in default and a
# DRAIN_SCRIPTS override (which the self-test uses). A failure there is mailed and
# exits 1 while leaving the certificate and the closed request as they are, since
# those are the state and the apply is the step left undone.
#
# acme-queue.sh notes its schedule here, as each scheduled script does, for
# scripts/cron-apply.sh to install rather than for an operator to paste in. Every
# fifteen minutes, so a slot that opens is used inside the quarter hour; a pass
# with the slot still closed exits without asking the CA. No '%' appears, because
# cron ends a command at the first unescaped one and renew-acme.sh records how that
# went:
#
#   */15 * * * *  . /root/.kyriakon-env; /root/bin/acme-queue.sh --run
#
# --run prints nothing on a pass that attempts nothing, because cron mails a job's
# output: read the queue with --status, and a request that has waited too long
# arrives as an age alert rather than as a line every fifteen minutes.
#
# Depends on: /etc/acme-client.conf including /etc/acme-client.d/index.conf (the
# generated index scripts/cron-apply.sh --web rewrites), the acme-client binary,
# a resolver command (host(1) from base), and lib.sh installed beside this file,
# which is where notify_operator comes from. The apply step above needs the drain
# scripts, installed by scripts/deploy-onboard.sh.

set -euo pipefail

# cron(8) hands jobs PATH=/usr/bin:/bin; acme-client and the resolver live in
# /usr/local and base. The same line the other box scripts carry, so the PATH
# needed here is written in one shape.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

script_dir="$(dirname "$0")"
if [ ! -f "$script_dir/lib.sh" ]; then
	printf '%s: lib.sh is not in %s. Install the two files together, as lib.sh describes.\n' \
		"$0" "$script_dir" >&2
	exit 1
fi
# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
. "$script_dir/lib.sh"

queue_dir="${ACME_QUEUE_DIR:-/var/db/kyriakon-acme-queue}"
pending_dir="$queue_dir/pending"
last_attempt_file="$queue_dir/last-attempt"
client="${ACME_CLIENT:-acme-client}"
resolver="${ACME_RESOLVER:-host}"
# Where the certificate lands. A variable so the self-test can point attempt() at
# a throwaway directory: the success path below checks the file is there.
ssl_dir="${ACME_SSL_DIR:-/etc/ssl}"

# The directory the drain's privileged scripts are installed in. The apply hook
# below runs the web lane and scripts/cron-apply.sh --web from there, because
# they are the drain's copies rather than /root/bin ones and this script runs
# both from cron and, now, on behalf of the drain's own script directory. The
# path is read from the drain's configuration rather than typed twice, with the
# compiled-in default for a box whose config cannot be read. DRAIN_SCRIPTS
# overrides it, which is what the self-test points at its stubs.
drain_toml="${DRAIN_TOML:-/etc/kyriakon/onboard/drain.toml}"
if [ -n "${DRAIN_SCRIPTS:-}" ]; then
	drain_scripts=$DRAIN_SCRIPTS
else
	drain_scripts=/usr/local/libexec/kyriakon/scripts
	if [ -r "$drain_toml" ]; then
		configured_scripts=$(awk -F'"' '/^scripts[[:space:]]*=/ { print $2; exit }' "$drain_toml")
		[ -z "$configured_scripts" ] || drain_scripts=$configured_scripts
	fi
fi

# The published refill: 50 new certificates per registered domain per seven days is
# one every 202 minutes. A constant rather than a tunable, because it is the CA's
# number and not ours to set.
REFILL_MINUTES=202

usage() {
	printf 'usage: doas ksh %s --add <name> [<site-owner>] | --status | --run\n       ksh %s --self-test\n' \
		"$0" "$0" >&2
	exit 2
}

die() {
	# A run that stops before it can ask for a certificate has no report of its
	# own, so it is mailed like any other failure. --add and --status are runs by
	# hand, where the message on the terminal is the report, and cron is not
	# involved.
	if [ "${mode:-}" = run ]; then
		notify_operator acme "queue failed" "$*" \
			"nothing is attempted until this is fixed, and the queue's age alert is what says so after 24 hours. --status reads it by hand."
	else
		printf 'acme-queue: %s\n' "$*" >&2
	fi
	exit 1
}

# name_ok <name> : true when the request can be named <name>. Two shapes reach
# the queue: a member's <localpart>.kyriakon.net, and an own-domain body's
# domain, which is any validated FQDN. Both become a filename here, so the check
# is also what keeps a request from being a path: lowercase labels of letters,
# digits and hyphens, at least two labels, no label starting or ending with a
# hyphen, and at most 253 characters.
name_ok() {
	[ "${#1}" -le 253 ] || return 1
	case "$1" in
	*.*) ;;
	*) return 1 ;;
	esac
	printf '%s' "$1" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
}

# owner_ok <name> : a site owner is a member account, the string add-user.sh
# accepted as a username, and it becomes the account named in the 443 vhost the
# queue writes when an own-domain certificate lands.
owner_ok() {
	printf '%s' "$1" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'
}

# minutes_until_slot <now> <last_attempt> : 0 when a slot is open, else the whole
# minutes still to wait. Rounded up, so the wait reported is never shorter than the
# real one.
minutes_until_slot() {
	now="$1"; last="$2"
	if [ "$last" -le 0 ]; then
		printf '0'
		return 0
	fi
	left=$(( REFILL_MINUTES * 60 - (now - last) ))
	if [ "$left" -le 0 ]; then
		printf '0'
	else
		printf '%s' "$(( (left + 59) / 60 ))"
	fi
}

# pending_oldest_first : the request files as "<mtime> <path>" lines, oldest first.
# mtime is the queue time, so ordering by it is ordering by how long a name has
# waited. stat -f '%m %N' prints the mtime and the path; a validated name holds no
# space, so the caller can split the two on the last field.
pending_oldest_first() {
	[ -d "$pending_dir" ] || return 0
	find "$pending_dir" -type f -exec stat -f '%m %N' {} + 2>/dev/null | sort -n
}

# resolve_ok <name> : true when the name has an A record. See the header for why a
# name that does not resolve is held rather than attempted.
resolve_ok() {
	"$resolver" -t A "$1" >/dev/null 2>&1
}

# next_attempt <list> : the oldest name in the "<mtime> <path>" list whose records
# resolve, or nothing when none resolve. A name that does not resolve is skipped
# and the queue moves past one member's missing record rather than stopping on it
# (see the header). Skipped silently, not announced: a pass that attempts nothing
# prints nothing, and a name that never resolves is reported by its age through
# the monitor. Returns 0 either way; the caller reads the printed name.
next_attempt() {
	while read -r mtime path; do
		[ -n "$path" ] || continue
		name=${path##*/}
		if resolve_ok "$name"; then
			printf '%s' "$name"
			return 0
		fi
	done <<EOF
$1
EOF
	return 0
}

# apply_member <name> : the two steps a new certificate makes due, run from the
# drain's script directory. The web lane is what writes the member's block behind
# the relay, and cron-apply.sh --web is what regenerates the indexes and the
# relayd keypair region, checks the three configs and reloads what changed. Until
# both have run the name still answers with the relay's default certificate, so a
# failure here is mailed rather than swallowed: the certificate and the closed
# request are the state, and this is the step left undone.
#
# Silent on success, because cron mails a job's output and the queue's own notice
# is the report. On failure the failing step's output is printed, which is what
# the operator needs and the notice cannot carry.
apply_member() {
	typeset apply_name="$1" apply_owner="${2:-}" apply_web_lane="" apply_apply step step_out
	case "$apply_name" in
	*.kyriakon.net)
		apply_web_lane="$drain_scripts/provision-member-web.sh"
		set -- "${apply_name%.kyriakon.net}"
		;;
	*)
		# An own-domain name's 443 vhost names the site owner's tree, and the
		# account was recorded with the request because this lane runs after the
		# provisioning pass that knew it.
		if [ -n "$apply_owner" ]; then
			apply_web_lane="$drain_scripts/provision-group-web.sh"
			set -- "$apply_name" "$apply_owner"
		fi
		;;
	esac
	apply_apply="$drain_scripts/cron-apply.sh"
	if [ -z "${apply_web_lane:-}" ]; then
		printf 'acme-queue: %s has no site owner recorded, so its 443 vhost cannot be written: file it again with --add %s <account>\n' \
			"$apply_name" "$apply_name" >&2
		return 1
	fi
	for step in "$apply_web_lane" "$apply_apply"; do
		if [ ! -f "$step" ]; then
			printf 'acme-queue: no %s, so %s has a certificate and still no site: scripts/deploy-onboard.sh installs the drain scripts\n' \
				"$step" "$apply_name" >&2
			return 1
		fi
	done
	if ! step_out=$(ksh "$apply_web_lane" "$@" 2>&1); then
		printf '%s\n' "$step_out" >&2
		return 1
	fi
	if ! step_out=$(ksh "$apply_apply" --web 2>&1); then
		printf '%s\n' "$step_out" >&2
		return 1
	fi
	return 0
}

# attempt <name> : the one attempt of a pass. Records the attempt whatever happens,
# closes the request on success, and mails the outcome on every path: cron mails a
# job's output under a subject of its own, so the report is the mail and nothing is
# printed. On any outcome but success the request is left pending and the run exits
# 1, because a swallowed refusal is a member who waits for nothing.
attempt() {
	typeset request_owner apply_command
	name="$1"
	# The request file carries the site owner for an own-domain name, so the web
	# lane can be run again when the certificate lands. A member's file is empty.
	request_owner=$(cat "$pending_dir/$name" 2>/dev/null || true)
	cert="$ssl_dir/$name.fullchain.pem"
	rc=0
	log=$("$client" "$name" 2>&1) || rc=$?
	printf '%s\n' "$(date +%s)" > "$last_attempt_file"
	case "$rc" in
	0 | 2)
		# 0 issued or renewed; 2 still current. Either way the request is met.
		[ -f "$cert" ] || die "$name: acme-client exited $rc but $cert is not there"
		rm -f "$pending_dir/$name"
		[ ! -e "$pending_dir/$name" ] || die "$name: the request file is still there"
		# The certificate is the trigger for the name's two remaining pieces: the
		# vhost behind the relay and the relayd keypair line. Both are applied
		# here rather than left for a human, because nothing else runs on a new
		# certificate and the page would otherwise promise a padlock that never
		# arrives.
		if ! apply_member "$name" "$request_owner"; then
			found=$(printf '%s: issued or current, and %s is in place, so the request is closed.\nThe web lane or the web apply then failed, so %s still answers with the default certificate.' \
				"$name" "$cert" "$name")
			case "$name" in
			*.kyriakon.net) apply_command="provision-member-web.sh ${name%.kyriakon.net}" ;;
			*) apply_command="provision-group-web.sh $name $request_owner" ;;
			esac
			notify_operator acme "apply failed" "$found" \
				"run doas ksh scripts/$apply_command, then doas ksh scripts/cron-apply.sh --web, on the box: the first writes the vhost and the second the indexes, the relayd keypair and the reload"
			exit 1
		fi
		# The two outcomes get different events, so a list of subjects says which
		# one happened: a first issue spends one of the five per registered
		# domain, and a renewal that was already current spends none.
		if [ "$rc" -eq 0 ]; then
			notify_operator acme issued "$(printf '%s: issued, and %s is in place, so the request is closed.\nThe vhost and keypair are applied. The next attempt can be %s minutes from now at the earliest, and this one spent a slot of the registered domain refill.' \
				"$name" "$cert" "$REFILL_MINUTES")"
		else
			notify_operator acme current "$(printf '%s: already had a valid certificate, so the request is closed (%s).\nThe vhost and keypair are applied. The next attempt can be %s minutes from now at the earliest.' \
				"$name" "$cert" "$REFILL_MINUTES")"
		fi
		;;
	*)
		# The client's own words are the finding, and they are what has to arrive.
		found=$(printf '%s: acme-client exited %s\n%s' "$name" "$rc" "$log")
		case "$log" in
		*"bad HTTP: 429"*)
			found="$found$(printf '\n%s: the CA rate limited this order. A refusal spends no budget, but\n  acme-client 7.9 prints no Retry-After, so the %s-minute spacing stands as the retry.\n  Repeat occurrences: docs/planning/research/cert-issuance-ceiling.md' \
				"$name" "$REFILL_MINUTES")"
			;;
		esac
		notify_operator acme "attempt failed" "$found" \
			"$name is left pending, so its age keeps saying how long the wait is, and the next pass tries it in $REFILL_MINUTES minutes at the earliest. --status reads the queue by hand."
		exit 1
		;;
	esac
	return 0
}

add_request() {
	name="$1"
	owner="${2:-}"
	name_ok "$name" || die "not a certificate name: $name (expect an FQDN, such as <name>.kyriakon.net or <domain>)"
	case "$name" in
	*.kyriakon.net) ;;
	*)
		# An own-domain name needs the account the 443 vhost will root, and the
		# queue is where it is kept between provisioning and issuance.
		[ -n "$owner" ] || die "the own-domain name $name needs its site owner account, so the 443 vhost can be written when the certificate lands"
		owner_ok "$owner" || die "not an account name: $owner"
		;;
	esac
	install -d -m 0700 "$queue_dir" "$pending_dir"
	req="$pending_dir/$name"
	if [ -e "$req" ]; then
		printf 'already queued: %s (age %s minutes)\n' \
			"$name" "$(( ( $(date +%s) - $(stat -f '%m' "$req") ) / 60 ))"
		return 0
	fi
	# The file is written once and never rewritten: its mtime is the queue time,
	# and rewriting it would reset the age and let a name that had waited jump back
	# to the head of the queue. Its content is the site owner for an own-domain
	# name and empty for a member's.
	printf '%s\n' "$owner" > "$req"
	[ -f "$req" ] || die "could not file a request for $name"
	printf 'queued: %s\n' "$name"
}

status() {
	[ -d "$pending_dir" ] || { printf 'no pending certificate requests\n'; return 0; }
	list=$(pending_oldest_first)
	if [ -z "$list" ]; then
		printf 'no pending certificate requests\n'
		return 0
	fi
	now=$(date +%s)
	printf 'pending certificate requests, oldest first:\n'
	printf '%s\n' "$list" | while read -r mtime path; do
		printf '%6s minutes  %s\n' "$(( (now - mtime) / 60 ))" "${path##*/}"
	done
	last=0
	if [ -f "$last_attempt_file" ]; then
		last=$(cat "$last_attempt_file")
	fi
	printf 'next attempt in %s minutes (%s-minute spacing)\n' \
		"$(minutes_until_slot "$now" "$last")" "$REFILL_MINUTES"
}

run() {
	install -d -m 0700 "$queue_dir" "$pending_dir"

	# One pass at a time. mkdir is the atomic test-and-set available in base (no
	# shlock(1), no flock(1) wrapper), and two passes could otherwise both read the
	# same open slot and attempt in the same moment. A lock left by a killed run is
	# taken over once its pid is gone, so a reboot cannot wedge the queue.
	lock="$queue_dir/run.lock"
	if ! mkdir -m 0700 "$lock" 2>/dev/null; then
		holder=$(cat "$lock/pid" 2>/dev/null || true)
		if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
			# A pass that attempts nothing prints nothing, like every other such
			# pass: the run holding the lock reports its own outcome, and the age
			# alert is what covers one that never finishes.
			return 0
		fi
		rm -f "$lock/pid"
		rmdir "$lock" 2>/dev/null || true
		if ! mkdir -m 0700 "$lock" 2>/dev/null; then
			die "could not take $lock, and no live process holds it"
		fi
	fi
	printf '%s\n' "$$" > "$lock/pid"
	trap 'rm -f "$lock/pid"; rmdir "$lock" 2>/dev/null || true' EXIT

	now=$(date +%s)
	last=0
	if [ -f "$last_attempt_file" ]; then
		last=$(cat "$last_attempt_file")
	fi
	# A pass with nothing to do prints nothing. cron mails the output of a job, so
	# a line here is a line in the operator's inbox every fifteen minutes: this
	# queue is empty or inside its refill window for almost every pass it makes.
	# --status is the reading for a human, and a request that has waited too long
	# is reported by its age through the monitor, which is a signal rather than a
	# running commentary.
	wait=$(minutes_until_slot "$now" "$last")
	if [ "$wait" -gt 0 ]; then
		return 0
	fi

	list=$(pending_oldest_first)
	if [ -z "$list" ]; then
		return 0
	fi

	# The one attempt this pass makes: the oldest pending name that resolves. Two
	# attempts in a pass are impossible by construction, and attempt() records the
	# time so the next pass cannot come back before the refill.
	# Silent for the same reason: a name that does not resolve yet is held, and that
	# is a normal state for a name whose records were asked for minutes ago. The age
	# alert is what reports one that stays that way.
	candidate=$(next_attempt "$list")
	if [ -z "$candidate" ]; then
		return 0
	fi
	attempt "$candidate"
	return 0
}

# --self-test runs the ordering and spacing checks in a temporary store and leaves
# before any mode reads the live store or runs as root, so it is safe unprivileged
# on any machine (the same shape as scripts/abuse-monitor.sh --self-test).
self_test() {
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	work=$self_test_work

	check "a member name is accepted" "$(name_ok foo.kyriakon.net && printf yes)" "yes"
	check "an own-domain FQDN is accepted" "$(name_ok parish.example && printf yes || printf no)" "yes"
	check "a name with a bad character is refused" "$(name_ok Foo.kyriakon.net && printf yes || printf no)" "no"
	check "a bare localpart is refused" "$(name_ok foo && printf yes || printf no)" "no"
	check "a single-label domain is refused" "$(name_ok localhost && printf yes || printf no)" "no"
	check "a leading hyphen is refused" "$(name_ok -parish.example && printf yes || printf no)" "no"
	check "a path is refused" "$(name_ok ../etc/passwd.kyriakon.net && printf yes || printf no)" "no"
	check "a site owner is a member account name" "$(owner_ok parish-secretary && printf yes || printf no)" "yes"
	check "and a path is not a site owner" "$(owner_ok ../parish && printf yes || printf no)" "no"

	base=2000000000
	check "no attempt yet means an open slot" "$(minutes_until_slot "$base" 0)" "0"
	check "a just-made attempt waits the full refill" "$(minutes_until_slot "$base" $(( base - 1 )))" "202"
	check "a full refill past is open" "$(minutes_until_slot "$base" $(( base - 202 * 60 )))" "0"
	check "a partly waited refill reports the remainder" "$(minutes_until_slot "$base" $(( base - 101 * 60 )))" "101"

	# Three requests filed 30, 20 and 10 minutes ago must list oldest first, which
	# is the order the queue works them in.
	pending_dir="$work/pending"
	mkdir -p "$pending_dir"
	now=$(date +%s)
	age=30
	for n in c.kyriakon.net b.kyriakon.net a.kyriakon.net; do
		: > "$pending_dir/$n"
		touch -t "$(date -r $(( now - age * 60 )) '+%Y%m%d%H%M.%S')" "$pending_dir/$n"
		age=$(( age - 10 ))
	done
	check "requests list oldest first" \
		"$(pending_oldest_first | awk '{ n = $2; sub(".*/", "", n); print n }' | tr '\n' ' ')" \
		"c.kyriakon.net b.kyriakon.net a.kyriakon.net "

	# The resolver is stubbed so the selection rule is checkable without DNS: a
	# name without an A record is held and the next oldest name that resolves is
	# the one attempted, so one member's missing record does not stop the queue.
	mkdir -p "$work/bin"
	cat > "$work/bin/host" <<'STUB'
#!/bin/sh
# args: -t A <name>
case "$3" in
ok.kyriakon.net | a.kyriakon.net) exit 0 ;;
*) exit 1 ;;
esac
STUB
	chmod 0700 "$work/bin/host"
	resolver="$work/bin/host"
	check "the oldest name that resolves is chosen" \
		"$(next_attempt "10 $pending_dir/c.kyriakon.net
20 $pending_dir/ok.kyriakon.net" 2>/dev/null)" "ok.kyriakon.net"
	check "the oldest of two that resolve wins" \
		"$(next_attempt "10 $pending_dir/ok.kyriakon.net
20 $pending_dir/a.kyriakon.net" 2>/dev/null)" "ok.kyriakon.net"
	check "nothing is chosen when no pending name resolves" \
		"$(next_attempt "10 $pending_dir/c.kyriakon.net
20 $pending_dir/b.kyriakon.net" 2>/dev/null)" ""

	# The apply hook, exercised through attempt() rather than through its own
	# function: what has to hold is that a pass which issues a certificate runs the
	# web lane and then the web apply, so removing the call from attempt() or either
	# step from the hook fails here. The client and both drain scripts are stubs,
	# and the certificate lands in a throwaway ssl directory.
	ssl_dir="$work/ssl"
	last_attempt_file="$work/last-attempt"
	pending_dir="$work/apply-pending"
	drain_scripts="$work/drain"
	mkdir -p "$ssl_dir" "$pending_dir" "$drain_scripts"
	cat > "$work/bin/acme-client" <<STUB
#!/bin/sh
: > "$ssl_dir/\$1.fullchain.pem"
STUB
	cat > "$drain_scripts/provision-member-web.sh" <<STUB
#!/bin/sh
printf 'web %s\n' "\$*" >> '$work/calls'
STUB
	cat > "$drain_scripts/provision-group-web.sh" <<STUB
#!/bin/sh
printf 'web %s\n' "\$*" >> '$work/calls'
STUB
	cat > "$drain_scripts/cron-apply.sh" <<STUB
#!/bin/sh
printf 'apply %s\n' "\$1" >> '$work/calls'
STUB
	chmod 0700 "$work/bin/acme-client" "$drain_scripts/provision-member-web.sh" \
		"$drain_scripts/provision-group-web.sh" "$drain_scripts/cron-apply.sh"
	client="$work/bin/acme-client"
	: > "$pending_dir/alice.kyriakon.net"
	mode=run
	attempt alice.kyriakon.net > "$work/attempt.out" 2>&1
	check "an issued certificate closes its request" \
		"$([ -e "$pending_dir/alice.kyriakon.net" ] && printf yes || printf no)" no
	check "and runs the web lane then the web apply, in that order" \
		"$(cat "$work/calls")" "web alice
apply --web"

	# An own-domain request carries its site owner, and the web lane is run with
	# the domain and that account, because the 443 vhost roots the owner's tree.
	rm -f "$work/calls"
	printf 'parish-secretary\n' > "$pending_dir/parish.example"
	attempt parish.example > "$work/domain.out" 2>&1
	check "an issued own-domain certificate closes its request" \
		"$([ -e "$pending_dir/parish.example" ] && printf yes || printf no)" no
	check "and runs the domain's web lane with its owner, then the web apply" \
		"$(cat "$work/calls")" "web parish.example parish-secretary
apply --web"

	# An own-domain request with no owner cannot name a document root, so the hook
	# refuses rather than writing a vhost it would have to guess.
	code=0
	( apply_member parish.example ) > "$work/noowner.out" 2>&1 || code=$?
	check "an own-domain name with no owner is refused" "$code" 1
	check "and the refusal names the account that must be filed with it" \
		"$(grep -c 'file it again with --add parish.example <account>' "$work/noowner.out")" 1

	# A web lane that fails stops the hook, and the notice names the command an
	# operator runs to finish the job by hand.
	rm -f "$work/calls"
	printf '#!/bin/sh\necho "the vhost did not write" >&2\nexit 1\n' \
		> "$drain_scripts/provision-member-web.sh"
	chmod 0700 "$drain_scripts/provision-member-web.sh"
	: > "$pending_dir/bob.kyriakon.net"
	code=0
	( attempt bob.kyriakon.net ) > "$work/attempt-failed.out" 2>&1 || code=$?
	check "a failed web lane fails the attempt" "$([ "$code" -ne 0 ] && printf yes || printf no)" yes
	check "and the web apply is not reached" \
		"$([ -e "$work/calls" ] && printf yes || printf no)" no
	check "and the notice names both commands that finish it" \
		"$(grep -c 'provision-member-web.sh bob' "$work/attempt-failed.out")" 1
	check "and the web apply after it" \
		"$(grep -c 'doas ksh scripts/cron-apply.sh --web' "$work/attempt-failed.out")" 1
	check "and carries the lane's own words" \
		"$(grep -c 'the vhost did not write' "$work/attempt-failed.out")" 1

	# A request filed through the parser records the site owner, and a second
	# filing leaves the age alone.
	queue_dir="$work/add-queue"
	pending_dir="$queue_dir/pending"
	add_request parish.example parish-secretary > "$work/add.out"
	check "an own-domain request is queued" "$(grep -c '^queued: parish.example$' "$work/add.out")" 1
	check "and records the site owner for the later apply" \
		"$(cat "$pending_dir/parish.example")" "parish-secretary"
	before=$(stat -f '%i %m' "$pending_dir/parish.example")
	add_request parish.example parish-secretary > "$work/add-again.out"
	check "a second filing says it is already queued" \
		"$(grep -c '^already queued: parish.example' "$work/add-again.out")" 1
	check "and leaves the request alone" "$(stat -f '%i %m' "$pending_dir/parish.example")" "$before"
	code=0
	( add_request other.example ) > "$work/add-noowner.out" 2>&1 || code=$?
	check "an own-domain request with no owner is refused at filing" "$code" 1
	check "and nothing was filed for it" \
		"$([ -e "$pending_dir/other.example" ] && printf yes || printf no)" no

	# A hook whose scripts the deploy never installed fails rather than reporting a
	# vhost it did not write.
	rm -f "$drain_scripts/cron-apply.sh"
	code=0
	( apply_member alice.kyriakon.net ) > "$work/attempt-missing.out" 2>&1 || code=$?
	check "a missing drain script fails the hook" "$code" 1
	check "and the refusal names the deploy that installs it" \
		"$(grep -c 'scripts/deploy-onboard.sh' "$work/attempt-missing.out")" 1

	self_test_end
}

mode=""
name=""
owner=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	--add)
		mode=add
		[ "$#" -ge 2 ] || usage
		name="$2"
		shift 2
		# The site owner is optional and follows the name, for an own-domain
		# order. A member name needs none.
		if [ "$#" -gt 0 ] && [ "${1#-}" = "$1" ]; then
			owner="$1"
			shift
		fi
		;;
	--status) mode=status; shift ;;
	--run) mode=run; shift ;;
	--self-test) mode=self-test; shift ;;
	*) usage ;;
	esac
done
[ -n "$mode" ] || usage

if [ "$mode" = self-test ]; then
	self_test
fi

if [ "$mode" = add ] || [ "$mode" = run ]; then
	[ "$(id -u)" -eq 0 ] || die "run --add and --run as root (doas ksh $0)"
fi

case "$mode" in
add) add_request "$name" "$owner" ;;
status) status ;;
run) run ;;
esac
