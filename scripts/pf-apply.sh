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
#   - it only appends. It never removes or rewrites a rule, and it skips a block
#     whose rules are already present, so it is safe to run repeatedly;
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
"") ;;
*) printf 'usage: doas ksh %s [--check]\n' "$0" >&2; exit 2 ;;
esac

die() {
	printf 'pf-apply: %s\n' "$*" >&2
	exit 1
}

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
cp -p "$pf_conf" "$work"
added=0

# --- greylisting ------------------------------------------------------------
# The divert sends every inbound SMTP connection to spamd. The second rule is
# what lets a whitelisted host through instead, and its log keyword is what
# spamlogd reads to keep <spamd-white> current.
if grep -q 'divert-to 127.0.0.1 port spamd' "$pf_conf"; then
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
if grep -q 'table <nospamd>' "$pf_conf"; then
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
if grep -q 'port 1965' "$pf_conf"; then
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

if [ "$added" -eq 0 ]; then
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
pfctl -sr | grep -E 'divert-to 127\.0\.0\.1|spamd-white|nospamd' | awk '{print "\t" $0}'
printf '\nrevert with: pfctl -f %s\n' "$bak"
