#!/bin/ksh
# pf-apply.sh — put the pf fragments this repo documents into /etc/pf.conf.
#
# Runs ON the box as root:
#
#   doas ksh scripts/pf-apply.sh --check     # show the change, touch nothing
#   doas ksh scripts/pf-apply.sh             # append, check, back up, load
#
# The fragments live in this repo rather than in a shell history, so the pull
# request that changes them is the review of the firewall change, and every box
# ends up with the same rules.
#
# Every block is additive and goes at the END of the file: pf is last-match-wins,
# so a divert placed before the stock pass rule would never match.
#
# Safety properties:
#   - it only appends, and it skips a block whose opening marker is already
#     present, so it is safe to run repeatedly. It rewrites nothing outside its
#     own marker pairs, with two exceptions it makes on purpose: it drops a
#     byte-identical second copy of one of its own blocks, and it drops the
#     greylisting block when the file already diverts SMTP to spamd without it;
#   - the candidate is built in a temp file and checked with pfctl -n before
#     anything live is touched, and the installed file is checked again;
#   - the file it replaces is kept beside the original, timestamped;
#   - pf loads a ruleset atomically, so a load pfctl rejects leaves the running
#     ruleset in place;
#   - it does not touch sshd, disable pf, or flush anything.
#
# What it cannot check is whether these are the rules you want. Read the diff
# from --check, and the rationale in docs/planning/research/spamd-greylisting.md.
#
# This is a human step. Nothing in the repo runs it automatically.

set -euo pipefail

pf_conf=/etc/pf.conf
nospamd=/etc/mail/nospamd
check_only=no

case "${1:-}" in
--check) check_only=yes ;;
--self-test) self_test_mode=yes ;;
"") ;;
*) printf 'usage: doas ksh %s [--check | --self-test]\n' "$0" >&2; exit 2 ;;
esac

die() {
	printf 'pf-apply: %s\n' "$*" >&2
	exit 1
}

# A fragment is present iff its opening marker is. Keying on the rule text is what
# broke finger: that check looked for a line ending "port 79", the rule grew a
# keep-state suffix, and from then on every run appended the block again. The
# marker is the stable key. The one fragment that cannot use this alone is
# greylisting, whose rules a stock pf.conf already carries without our marker; its
# test adds the effect as well, and says why there.
has_block_in() { grep -q "^# --- kyriakon: $2" "$1"; }
has_block() { has_block_in "$pf_conf" "$1"; }

# The port a fragment already carries, read from its rule line. A marker-only
# test cannot tell a block for this port from one for the port it was proposed
# with last month, and a firewall rule on the wrong port is not a no-op.
block_port() {
	awk -v marker="# --- kyriakon: $2" '
		index($0, marker) == 1 { inside = 1; next }
		inside && /^# --- end kyriakon: / { exit }
		inside && match($0, /port [0-9]+/) {
			print substr($0, RSTART + 5, RLENGTH - 5)
			exit
		}' "$1"
}

# One value from the box's values file, or the empty string. Sourced in a
# subshell so a file that errors cannot end this run, which is the same reason
# the onboarding TUI's read below disables errexit for its own read.
env_value() {
	if [ -r "$env_file" ]; then
		# shellcheck disable=SC1090 # root's own env file, whose path resolves at runtime
		( set +e; . "$env_file" 2>/dev/null; eval "printf '%s' \"\${$1:-}\"" )
	fi
}

# The Titan fragment's rule. The public port is the relay's, not the handler's:
# relayd terminates TLS on it and forwards to the loopback listener with PROXY
# protocol v1, so the handler keeps seeing the client's address.
append_titan() {
	# $1 candidate file, $2 public port. Returns 1 when the marker is already
	# there, so the caller can leave the file byte-identical.
	if has_block_in "$1" "titan upload"; then
		return 1
	fi
	cat >>"$1" <<EOF

# --- kyriakon: titan upload (openbsd/etc/relayd.conf) ---
pass in log on egress proto tcp to any port $2
# --- end kyriakon: titan upload ---
EOF
}

self_test() {
	# shellcheck disable=SC1091 # resolves at runtime from this script's directory
	. "$(dirname "$0")/lib.sh"
	typeset tree first second env
	self_test_begin
	# shellcheck disable=SC2154 # set by self_test_begin in lib.sh
	tree=$self_test_work
	first="$tree/pf.conf"
	: > "$first"

	# The fragment reads its port from the values file, beside the onboarding
	# TUI's, and a box with no TITAN_PORT is skipped rather than guessed at.
	env="$tree/kyriakon.env"
	printf "export TITAN_PORT='1966'\n" > "$env"
	env_file=$env
	check "the values file is read" "$(env_value TITAN_PORT)" "1966"
	env_file="$tree/missing"
	check "a missing values file is empty" "$(env_value TITAN_PORT)" ""

	# The quiet path: the first run writes the block, and the second finds its
	# own marker and leaves the file byte-identical.
	append_titan "$first" 1966
	check "the fragment carries the port" "$(grep -c 'to any port 1966' "$first")" "1"
	check "the marker is present" "$(has_block_in "$first" 'titan upload' && printf yes)" "yes"
	before=$(cksum "$first")
	if append_titan "$first" 1966; then
		second=added
	else
		second=quiet
	fi
	check "a second run changes nothing" "$second" "quiet"
	check "and the file is byte-identical" "$(cksum "$first")" "$before"
	check "the block's port is readable" "$(block_port "$first" 'titan upload')" "1966"

	self_test_end
}

if [ "${self_test_mode:-no}" = yes ]; then
	self_test
fi

[ "$(id -u)" -eq 0 ] || die "run this with doas: it writes ${pf_conf}"
[ -f "$pf_conf" ] || die "no ${pf_conf}"
command -v pfctl >/dev/null 2>&1 || die "pfctl is not in PATH"

# The table file has to be there before the ruleset that reads it is loaded, and
# pf reports an unreadable table file at load time rather than at parse time, so
# a missing one would not be caught by the -n below. The mail deploy installs it.
if [ ! -s "$nospamd" ]; then
	die "${nospamd} is missing or empty: run the mail deploy first, it installs openbsd/etc/nospamd"
fi

work=$(mktemp)
bak=${pf_conf}.bak.$(date +%Y%m%d%H%M%S)

# The candidate starts as the live file with the copies of our own blocks that are
# no longer needed removed. Two things make a block redundant. One is a
# byte-identical repeat: a check that keyed on a rule's text appended finger twice,
# and only this script can repair a root-only file the operator will not hand-edit.
# The other is our greylisting block when the file already diverts SMTP to spamd
# outside it, because a stock pf.conf carries those same rules in its own words and
# our copy is then dead weight. A block is its two marker lines and everything
# between them; a line outside them is copied through untouched, and two copies
# that differ (a block appended twice around a changed value) are both kept and
# left to the diff, because guessing which is wanted is not this script's call.
dropped=$(mktemp)
collapsed=0
# Whether the diverts are already there is decided with our own marker pairs
# stripped out first. A scan that saw our block's own divert line would call a box
# whose only divert is our block a box that does not need it, and drop it, sending
# SMTP to smtpd instead of spamd: a mail change made by a firewall script for no
# reason. So a box with the stock rules drops our block, and a box whose only
# divert is our block keeps it.
outdivert=$(awk '
/^# --- kyriakon: / { inblk = 1; next }
inblk && /^# --- end kyriakon: / { inblk = 0; next }
inblk { next }
/divert-to 127\.0\.0\.1 port spamd/ { found = 1 }
END { print found + 0 }
' "$pf_conf")
awk -v dropped="$dropped" -v dropgrey="$outdivert" '
/^# --- kyriakon: / { inblk = 1; buf = $0 ORS; open = $0; next }
inblk && /^# --- end kyriakon: / {
	buf = buf $0 ORS
	if (dropgrey == 1 && open ~ /^# --- kyriakon: greylisting /) {
		print "greylisting, superseded by the divert rules already in the file: " open >> dropped
	} else if (buf in seen) {
		print "byte-identical duplicate: " open >> dropped
	} else {
		seen[buf] = 1
		printf "%s", buf
	}
	inblk = 0
	next
}
inblk { buf = buf $0 ORS; next }
{ print }
END { if (inblk) printf "%s", buf }
' "$pf_conf" > "$work"
if [ -s "$dropped" ]; then
	collapsed=$(awk 'END { print NR + 0 }' "$dropped")
	printf 'removing %s kyriakon block(s):\n' "$collapsed"
	while read -r why; do
		printf '\t%s\n' "$why"
	done < "$dropped"
fi
rm -f "$dropped"
added=0

# --- greylisting ------------------------------------------------------------
# The divert sends every inbound SMTP connection to spamd. The second rule is
# what lets a whitelisted host through instead, and its log keyword is what
# spamlogd reads to keep <spamd-white> current.
# The greylisting fragment tests differently from the other five, and it has to. A
# stock OpenBSD pf.conf already carries these diverts in its own words, without our
# marker, so a marker-only test would append a second copy of rules the box already
# runs. The test is therefore for the effect, a divert to spamd, as well as for our
# marker. The other five open services a stock file has nothing for, so there their
# marker is the whole story. Removing our block once the stock rules are doing the
# work is the candidate builder's job below, not this test's.
if has_block greylisting || grep -q 'divert-to 127.0.0.1 port spamd' "$pf_conf"; then
	printf 'greylisting:  already in %s\n' "$pf_conf"
else
	cat >>"$work" <<'EOF'

# --- kyriakon: greylisting (docs/planning/research/spamd-greylisting.md) ---
table <spamd-white> persist
pass in on egress proto tcp to any port smtp divert-to 127.0.0.1 port spamd
pass in log on egress proto tcp from <spamd-white> to any port smtp
# --- end kyriakon: greylisting ---
EOF
	added=$((added + 1))
	printf 'greylisting:  to be added\n'
fi

# --- senders that skip greylisting -----------------------------------------
# spamd promotes an address only when a retry arrives for the same tuple, and a
# tuple is keyed on the source IP as well as the envelope. A sender that rotates
# its outbound addresses between retries is never promoted, so it is deferred
# until it gives up. Exchange Online and Outlook.com do exactly that. This table
# is the documented way to exempt them, and the list is in openbsd/etc/nospamd.
if has_block 'senders that skip greylisting'; then
	printf 'nospamd:      already in %s\n' "$pf_conf"
else
	cat >>"$work" <<'EOF'

# --- kyriakon: senders that skip greylisting (openbsd/etc/nospamd) ---
table <nospamd> persist file "/etc/mail/nospamd"
pass in on egress proto tcp from <nospamd> to any port smtp
# --- end kyriakon: senders that skip greylisting ---
EOF
	added=$((added + 1))
	printf 'nospamd:      to be added\n'
fi

# --- gemini -----------------------------------------------------------------
# gmid has no proxy layer, so the capsule is reached on 1965 directly and needs
# its own inbound pass rather than riding on 443. Logged, like the greylisting
# rules, so that a scrape or a probe is attributable in pflog instead of
# invisible. Note that this opens the port; gmid itself only serves hostnames
# named in its config, and answers anything else with a 59.
if has_block gemini; then
	printf 'gemini:       already in %s\n' "$pf_conf"
else
	cat >>"$work" <<'EOF'

# --- kyriakon: gemini (openbsd/etc/gmid.conf) ---
pass in log on egress proto tcp to any port 1965
# --- end kyriakon: gemini ---
EOF
	added=$((added + 1))
	printf 'gemini:       to be added\n'
fi

# --- git over ssh -----------------------------------------------------------
# Members push to their pass repositories over ssh on 2222. The chroot on the
# sftp path is what forces the split (see openbsd/etc/sshd_config), so this is a
# new inbound service rather than more of the ssh already allowed on 22, and it
# needs its own rule. Logged, like the rest, so a probe is attributable in pflog
# instead of invisible. No max-src-conn: sshd's own MaxStartups bounds what a
# source can open before authentication.
if has_block 'git over ssh'; then
	printf 'git:          already in %s\n' "$pf_conf"
else
	cat >>"$work" <<'EOF'

# --- kyriakon: git over ssh (openbsd/etc/sshd_config) ---
pass in log on egress proto tcp to any port 2222
# --- end kyriakon: git over ssh ---
EOF
	added=$((added + 1))
	printf 'git:          to be added\n'
fi

# --- onboarding TUI ---------------------------------------------------------
# The applicant sshd listens on a port the box chose when it was built, recorded
# once as TUI_PORT in the values file rather than carried here, so this candidate
# reads it at run time and expands it into the rule. On a box with no TUI yet the
# file has no such line, and the block is skipped with a note instead of stopping
# the run, so every other fragment still applies. A value that is not a port
# number stops the run: the alternative is handing pfctl an unexpanded or
# out-of-range port and reporting a parse failure that names nowhere near the bad
# value, and nothing is written before this point anyway.
#
# No inet qualifier, deliberately: signup.kyriakon.net resolves through the zone
# wildcard, which carries both an A and an AAAA, so a client that prefers IPv6
# reaches this port too, and an inet-only rule would drop it.
env_file="${KYRIAKON_ENV:-/root/.kyriakon-env}"
tui_port=""
if [ -r "$env_file" ]; then
	# Sourced, not parsed, which is how the cron lines and deploy-mail.sh read it,
	# so the two cannot disagree about the format. A value file that errors ends
	# the shell `.` runs in, which under errexit would end this run before the
	# skip note below could say the file did not hold TUI_PORT: a silent exit is
	# worse than a named skip, so errexit is off for the read only.
	set +e
	# shellcheck disable=SC1090 # root's own env file, whose path resolves at runtime
	tui_port=$(. "$env_file" 2>/dev/null; printf '%s' "${TUI_PORT:-}")
	set -e
fi
case "$tui_port" in
"")
	;;
*[!0-9]*)
	die "TUI_PORT in ${env_file} is not a port number: '${tui_port}'"
	;;
*)
	if [ "$tui_port" -lt 1 ] || [ "$tui_port" -gt 65535 ]; then
		die "TUI_PORT in ${env_file} is outside 1-65535: '${tui_port}'"
	fi
	;;
esac

# The port is a deploy value, so the rule text is not a stable key to test for:
# check the block marker instead, which also stops a re-run appending a second
# block under the same heading.
if [ -z "$tui_port" ]; then
	printf 'onboard TUI:  skipped, no TUI_PORT in %s\n' "$env_file"
elif has_block 'onboarding TUI'; then
	printf 'onboard TUI:  already in %s\n' "$pf_conf"
else
	cat >>"$work" <<EOF

# --- kyriakon: onboarding TUI (openbsd/etc/sshd_config.onboard) ---
pass in log on egress proto tcp to any port ${tui_port} keep state (max-src-conn 4)
# --- end kyriakon: onboarding TUI ---
EOF
	added=$((added + 1))
	printf 'onboard TUI:  to be added on port %s\n' "$tui_port"
fi

# --- titan upload -----------------------------------------------------------
# The Titan listener is the one public port the handler needs of its own. gmid
# holds 1965 and a Titan request cannot reach a FastCGI front-end, so relayd
# terminates TLS for it and forwards to the handler on loopback. This opens the
# public port only; the relayd block stays commented in the repository until the
# operator turns it on, and no agent applies either change. The port is read from
# TITAN_PORT in the values file, the way the onboarding TUI's is, and a box with
# none is skipped with a note rather than stopping every other fragment.
titan_port=$(env_value TITAN_PORT)
case "$titan_port" in
"")
	;;
*[!0-9]*)
	die "TITAN_PORT in ${env_file} is not a port number: '${titan_port}'"
	;;
*)
	if [ "$titan_port" -lt 1 ] || [ "$titan_port" -gt 65535 ]; then
		die "TITAN_PORT in ${env_file} is outside 1-65535: '${titan_port}'"
	fi
	;;
esac

if [ -z "$titan_port" ]; then
	printf 'titan upload: skipped, no TITAN_PORT in %s\n' "$env_file"
elif has_block 'titan upload'; then
	existing=$(block_port "$pf_conf" 'titan upload')
	if [ "$existing" = "$titan_port" ]; then
		# Nothing changes, so say nothing: a quiet run is one the operator can
		# ignore, and the port is already the one the values file names.
		:
	else
		printf 'titan upload: %s already opens port %s, not TITAN_PORT %s; leaving it and the rest of the run alone\n' \
			"$pf_conf" "${existing:-unknown}" "$titan_port" >&2
	fi
else
	append_titan "$work" "$titan_port"
	added=$((added + 1))
	printf 'titan upload: to be added on port %s\n' "$titan_port"
fi

# --- finger -----------------------------------------------------------------
# fingerd is spawned by inetd rather than listening on its own, so the port has
# to be opened here before the deploy's inetd line is reachable at all. Logged,
# like the rest, so that a probe is attributable in pflog. max-src-conn bounds a
# single source: inetd forks per connection and the protocol is one line of
# input, which would otherwise make this the cheapest port on the box to flood.
if has_block finger; then
	printf 'finger:       already in %s\n' "$pf_conf"
else
	cat >>"$work" <<'EOF'

# --- kyriakon: finger (openbsd/etc/kyriakon-finger) ---
pass in log on egress proto tcp to any port 79 keep state (max-src-conn 5)
# --- end kyriakon: finger ---
EOF
	added=$((added + 1))
	printf 'finger:       to be added\n'
fi

if [ "$added" -eq 0 ] && [ "$collapsed" -eq 0 ]; then
	# A `persist file` table is read when the ruleset loads, so replacing the list
	# file leaves the kernel holding the old one until something reloads. Compare
	# them, ignoring order, and reload when they differ: that is what makes this
	# idempotent after the deploy installs an updated list. Two temp files rather
	# than process substitution, which OpenBSD's ksh does not have.
	known=$(mktemp)
	want=$(mktemp)
	# A table that does not exist yet returns non-zero, which under `set -e` with
	# pipefail would end the script before it could reload and create it.
	{ pfctl -t nospamd -T show 2>/dev/null || true; } | tr -d ' ' | sort > "$known"
	sort "$nospamd" > "$want"
	same=no
	if cmp -s "$known" "$want"; then
		same=yes
	fi
	rm -f "$known" "$want"
	if [ "$same" = yes ]; then
		rm -f "$work"
		printf '\nnothing to do: %s carries every fragment and <nospamd> matches %s\n' \
			"$pf_conf" "$nospamd"
		exit 0
	fi
	printf '\nthe fragments are in place, but <nospamd> in the kernel does not match %s\n' "$nospamd"
	printf 'reloading %s to pick the list up\n' "$pf_conf"
	if [ "$check_only" = yes ]; then
		rm -f "$work"
		printf '\n--check: a reload is what is needed. Nothing was written.\n'
		exit 0
	fi
	cp -p "$pf_conf" "$bak"
	pfctl -f "$pf_conf" || die "reload failed; the running ruleset is unchanged"
	rm -f "$work"
	printf '\nbacked up as %s\n' "$bak"
	printf 'reloaded %s\n\n' "$pf_conf"
	printf '<nospamd> now holds %s entries\n' "$(pfctl -t nospamd -T show 2>/dev/null | grep -c .)"
	exit 0
fi

pfctl -nf "$work" || {
	rm -f "$work"
	die "the candidate does not parse; ${pf_conf} is untouched"
}

if [ "$check_only" = yes ]; then
	printf '\n--- the change that would be made ---\n'
	diff -u "$pf_conf" "$work" || true
	rm -f "$work"
	printf '\n--check: the candidate parses. Nothing was written.\n'
	printf 'Re-run without --check to back up %s and load it.\n' "$pf_conf"
	exit 0
fi

cp -p "$pf_conf" "$bak"
install -m "$(stat -f %Lp "$pf_conf")" "$work" "$pf_conf"
rm -f "$work"
pfctl -nf "$pf_conf" || die "${pf_conf} does not re-check; restore ${bak}"
pfctl -f "$pf_conf"

printf '\nbacked up as %s\n' "$bak"
printf 'loaded %s\n\n' "$pf_conf"
printf 'rules now loaded from these fragments:\n'
pfctl -sr | grep -E 'divert-to 127\.0\.0\.1|spamd-white|nospamd|port = 1965|port = 2222|port = 79|max-src-conn 4' | awk '{print "\t" $0}'
printf '\nrevert with: pfctl -f %s\n' "$bak"
