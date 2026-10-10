#!/bin/ksh
# acme-queue.sh - the certificate request queue: one request per member name,
# worked oldest first, spaced against Let's Encrypt's refill rate.
#
# Usage:
#   doas ksh acme-queue.sh --add <name>    file one request (the signup path does this)
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
# ACME_CLIENT, ACME_RESOLVER) so the queue can be exercised against a copy or a
# stub without touching the live store or the CA.
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
# Depends on: /etc/acme-client.conf including /etc/acme-client.d/index.conf (the
# generated index scripts/cron-apply.sh --web rewrites), the acme-client binary,
# and a resolver command (host(1) from base).

set -euo pipefail

# cron(8) hands jobs PATH=/usr/bin:/bin; acme-client and the resolver live in
# /usr/local and base. The same line the other box scripts carry, so the PATH
# needed here is written in one shape.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
export PATH

queue_dir="${ACME_QUEUE_DIR:-/var/db/kyriakon-acme-queue}"
pending_dir="$queue_dir/pending"
last_attempt_file="$queue_dir/last-attempt"
client="${ACME_CLIENT:-acme-client}"
resolver="${ACME_RESOLVER:-host}"

# The published refill: 50 new certificates per registered domain per seven days is
# one every 202 minutes. A constant rather than a tunable, because it is the CA's
# number and not ours to set.
REFILL_MINUTES=202

usage() {
	printf 'usage: doas ksh %s --add <name> | --status | --run\n       ksh %s --self-test\n' \
		"$0" "$0" >&2
	exit 2
}

die() {
	printf 'acme-queue: %s\n' "$*" >&2
	exit 1
}

# name_ok <name> : true when the request can be named <name>. A member name is
# <localpart>.kyriakon.net, and the localpart is the string add-user.sh already
# accepted as a username, a home directory and a keyring filename, so it is that
# same set: lowercase [a-z0-9._-], first character alphanumeric, at most 32
# characters. The name becomes a filename here, so the check is also what keeps a
# request from being a path.
name_ok() {
	case "$1" in
	*.kyriakon.net) label=${1%.kyriakon.net} ;;
	*) return 1 ;;
	esac
	printf '%s' "$label" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'
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
# resolve, or nothing when none resolve. A name that does not resolve is announced
# on stderr and skipped, so the queue moves past one member's missing record rather
# than stopping on it (see the header). Returns 0 either way; the caller reads the
# printed name.
next_attempt() {
	while read -r mtime path; do
		[ -n "$path" ] || continue
		name=${path##*/}
		if resolve_ok "$name"; then
			printf '%s' "$name"
			return 0
		fi
		printf 'held: %s does not resolve yet, so it is left pending and not attempted\n' "$name" >&2
	done <<EOF
$1
EOF
	return 0
}

# attempt <name> : the one attempt of a pass. Records the attempt whatever happens,
# closes the request on success, and on any other outcome leaves it pending and
# exits 1 so cron mails root, because a swallowed refusal is a member who waits for
# nothing.
attempt() {
	name="$1"
	cert="/etc/ssl/$name.fullchain.pem"
	rc=0
	log=$("$client" "$name" 2>&1) || rc=$?
	printf '%s\n' "$(date +%s)" > "$last_attempt_file"
	case "$rc" in
	0 | 2)
		# 0 issued or renewed; 2 still current. Either way the request is met.
		[ -f "$cert" ] || die "$name: acme-client exited $rc but $cert is not there"
		rm -f "$pending_dir/$name"
		[ ! -e "$pending_dir/$name" ] || die "$name: the request file is still there"
		if [ "$rc" -eq 0 ]; then
			printf 'issued: %s (%s)\n' "$name" "$cert"
		else
			printf 'current: %s already had a valid certificate, so the request is closed (%s)\n' \
				"$name" "$cert"
		fi
		printf 'the next attempt can be %s minutes from now at the earliest\n' "$REFILL_MINUTES"
		;;
	*)
		printf 'failed: %s: acme-client exited %s\n%s\n' "$name" "$rc" "$log" >&2
		case "$log" in
		*"bad HTTP: 429"*)
			printf '%s: the CA rate limited this order. A refusal spends no budget, but\n  acme-client 7.9 prints no Retry-After, so the %s-minute spacing stands as the retry.\n  Repeat occurrences: docs/planning/research/cert-issuance-ceiling.md\n' \
				"$name" "$REFILL_MINUTES" >&2
			;;
		esac
		printf 'held: %s, left pending so its age stays visible in --status\n' "$name" >&2
		exit 1
		;;
	esac
	return 0
}

add_request() {
	name="$1"
	name_ok "$name" || die "not a member name: $name (expect <name>.kyriakon.net)"
	install -d -m 0700 "$queue_dir" "$pending_dir"
	req="$pending_dir/$name"
	if [ -e "$req" ]; then
		printf 'already queued: %s (age %s minutes)\n' \
			"$name" "$(( ( $(date +%s) - $(stat -f '%m' "$req") ) / 60 ))"
		return 0
	fi
	# The file is created empty and never rewritten: its mtime is the queue time,
	# and rewriting it would reset the age and let a name that had waited jump back
	# to the head of the queue.
	: > "$req"
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
			printf 'another pass is running (pid %s); nothing attempted\n' "$holder"
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
	wait=$(minutes_until_slot "$now" "$last")
	if [ "$wait" -gt 0 ]; then
		printf 'nothing attempted: the refill allows the next attempt in %s minutes (%s-minute spacing)\n' \
			"$wait" "$REFILL_MINUTES"
		return 0
	fi

	list=$(pending_oldest_first)
	if [ -z "$list" ]; then
		printf 'no pending certificate requests\n'
		return 0
	fi

	# The one attempt this pass makes: the oldest pending name that resolves. Two
	# attempts in a pass are impossible by construction, and attempt() records the
	# time so the next pass cannot come back before the refill.
	candidate=$(next_attempt "$list")
	if [ -z "$candidate" ]; then
		printf 'nothing attempted: no pending name resolves yet\n' >&2
		return 0
	fi
	attempt "$candidate"
	return 0
}

# --self-test runs the ordering and spacing checks in a temporary store and leaves
# before any mode reads the live store or runs as root, so it is safe unprivileged
# on any machine (the same shape as scripts/abuse-monitor.sh --self-test).
self_test() {
	typeset fails=0
	work=$(mktemp -d "${TMPDIR:-/tmp}/kyriakon-acme-queue-test.XXXXXX")
	trap 'rm -rf "$work"' EXIT
	check() {
		if [ "$2" = "$3" ]; then
			printf '  ok   %s\n' "$1"
		else
			printf '  FAIL %s: expected [%s], got [%s]\n' "$1" "$3" "$2"
			fails=$(( fails + 1 ))
		fi
	}

	check "a member name is accepted" "$(name_ok foo.kyriakon.net && printf yes)" "yes"
	check "a name with a bad character is refused" "$(name_ok Foo.kyriakon.net && printf yes || printf no)" "no"
	check "a bare localpart is refused" "$(name_ok foo && printf yes || printf no)" "no"
	check "another domain is refused" "$(name_ok foo.example.invalid && printf yes || printf no)" "no"
	check "a path is refused" "$(name_ok ../etc/passwd.kyriakon.net && printf yes || printf no)" "no"

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

	if [ "$fails" -eq 0 ]; then
		printf 'self-test: all checks passed\n'
	else
		printf 'self-test: %s failed\n' "$fails" >&2
		exit 1
	fi
}

mode=""
name=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	--add)
		mode=add
		[ "$#" -ge 2 ] || usage
		name="$2"
		shift 2
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
	exit 0
fi

if [ "$mode" = add ] || [ "$mode" = run ]; then
	[ "$(id -u)" -eq 0 ] || die "run --add and --run as root (doas ksh $0)"
fi

case "$mode" in
add) add_request "$name" ;;
status) status ;;
run) run ;;
esac
