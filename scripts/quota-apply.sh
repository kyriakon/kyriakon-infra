#!/bin/ksh
# quota-apply.sh: the 5 GB allowance, applied and checked.
#
# The platform publishes 5 GB per account across mail, web and git, all of it on
# /home, and nothing enforces it until a quota is set on the account. This script
# is that enforcement, in one place, so provisioning does not depend on somebody
# remembering to run edquota.
#
# Usage:
#   doas ksh scripts/quota-apply.sh --enable        turn quotas on for the mount
#   doas ksh scripts/quota-apply.sh <username>      set the standard allowance
#   doas ksh scripts/quota-apply.sh --all           set it on every member
#   doas ksh scripts/quota-apply.sh --clear <name>  remove one account's allowance
#   doas ksh scripts/quota-apply.sh --show          report the state, change nothing
#   ksh scripts/quota-apply.sh --self-test          check the logic against stubs
#
# The numbers, and why they are these:
#   soft 5242880 KB (5 GiB)   what the site promises, so what the monitor watches
#   hard 5767168 KB (5.5 GiB) headroom for a mailbox that fills while its owner is
#                             asleep, so a member is warned before anything bounces
#   inodes 0, 0               no limit: this platform counts bytes, and a limit on
#                             file count would fail mail delivery in ways nobody
#                             could explain from the published page
# edquota(8) counts kilobytes, and "setting a quota to zero indicates that no quota
# should be imposed", which is why an account with no limits set is unaffected by
# quotas being switched on.
#
# Clearing an account is setting both of its limits to zero on this same path, so the
# account keeps every file and nothing is enforced against it. That is for exempting
# one account from the published 5 GB, not for stopping one: an account that must stop
# using disk is the lifecycle's suspension, not a quota.
#
# The grace period is one week, the default from MAX_DQ_TIME; `edquota -t` shows it
# and writes it explicitly. A member past the soft limit has that week to delete
# something before writes fail, which is the same window the copy describes.
#
# edquota is an editor, so the allowance is applied by pointing $EDITOR at a small
# filter that rewrites the limits on the mount's line of the file edquota hands it.
# The filter is checked by reading the limits back with quota(1) afterwards: if the
# file format ever changes under us, the run fails loudly instead of reporting a
# limit that was never written.
#
# Env:
#   QUOTA_SOFT_KB   soft block limit (default 5242880)
#   QUOTA_HARD_KB   hard block limit (default 5767168)
#   FSTAB           fstab to read and patch (default /etc/fstab)
#   PASSWD          passwd file to read accounts from (default /etc/passwd)
#   QUOTA_MOUNT     the filesystem carrying member homes (default /home)
# The last three are the seams the self-test uses; leave them unset on the box.
#
# Exit: 0 done; 1 refused, or set and not read back; 2 usage; 3 quotas are not on.
#
# Not this script's job: the fstab line cannot take effect without a remount, so
# --enable patches the file, runs the live path, and says plainly that a reboot is
# the clean one. Quotas stay enforced across a reboot through check_quotas=YES.

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)

fstab=${FSTAB:-/etc/fstab}
passwd_file=${PASSWD:-/etc/passwd}
mount=${QUOTA_MOUNT:-/home}
soft_kb=${QUOTA_SOFT_KB:-5242880}
hard_kb=${QUOTA_HARD_KB:-5767168}
quota_file="$mount/quota.user"

usage() {
	cat >&2 <<'USAGE'
usage: quota-apply.sh --enable | <username> | --all | --show | --self-test

  --enable      add userquota to the mount's fstab line, run quotacheck and
                quotaon, and report what the box will do at the next boot
  <username>    set the standard allowance on one account and read it back
  --all         the same for every member account (no shell, home on the mount)
  --clear <name>  set that account's limits back to zero, which is no quota at all
  --show        report quotas and per-account limits, change nothing
  --self-test   exercise the fstab, filter and read-back logic against stubs
USAGE
	exit 2
}

die() {
	printf '%s: %s\n' "$0" "$*" >&2
	exit 1
}

# --- the fstab line -------------------------------------------------------
# quotaon(8) and edquota(8) both read the list of quota'd filesystems from fstab,
# so the option has to be there before anything else works. Only the mount's line
# is touched, and only its options field.

fstab_line() {
	awk -v m="$mount" '$1 !~ /^#/ && $2 == m { print; exit }' "$fstab"
}

fstab_has_userquota() {
	fstab_line | awk '{ print $4 }' | grep -qw userquota
}

fstab_patch() {
	typeset tmp
	[ -f "$fstab" ] || die "no $fstab to patch"
	if [ ! -f "$fstab.kyriakon.bak" ]; then
		cp -p "$fstab" "$fstab.kyriakon.bak" ||
			die "cannot write $fstab.kyriakon.bak"
	fi
	tmp="$fstab.kyriakon.new"
	awk -v m="$mount" '
		$1 !~ /^#/ && $2 == m && $4 !~ /(^|,)userquota(,|$)/ { $4 = $4 ",userquota" }
		{ print }
	' "$fstab" > "$tmp" || die "cannot write $tmp"
	mv "$tmp" "$fstab" || die "cannot replace $fstab"
	printf 'added userquota to the %s line in %s (backup at %s.kyriakon.bak)\n' \
		"$mount" "$fstab" "$fstab"
}

# --- state ----------------------------------------------------------------

# OpenBSD's quotaon has no -p flag to ask whether quotas are on, so the question is put
# to quota(1): with no quota file for the filesystem it prints a single line ending
# "none", and with one it prints the per-filesystem table.
#
# What that cannot tell you is whether the kernel is enforcing right now, because
# quota(1) reads the same file the kernel does. A quota file that quotacheck has just
# created reads as "on" before any quotaon has run, which is why --enable attempts
# quotaon whatever this says rather than using it to skip the step. Treat "on" as "the
# file is in place", not as "enforcement is live": a reboot makes enforcement certain,
# through check_quotas=YES.
quotas_state() {
	out=$(quota -v -u "$(first_account)" 2>&1) || { printf 'unknown'; return; }
	case "$out" in
	*none*) printf 'off' ;;
	*"$mount"*) printf 'on' ;;
	*) printf 'unknown' ;;
	esac
}

# The first account that can carry a quota, member or operator: the probe for
# quotas_state, which needs somebody to ask about.
first_account() {
	awk -F: -v min=1000 '$3 >= min { print $1; exit }' "$passwd_file"
}

account_home() {
	awk -F: -v u="$1" '$1 == u { print $6; exit }' "$passwd_file"
}

member_accounts() {
	awk -F: -v m="$mount/" -v min=1000 '
		$3 >= min && index($6, m) == 1 && $7 == "/sbin/nologin" { print $1 }
	' "$passwd_file"
}

# --- setting the limits ---------------------------------------------------

# edquota invokes $EDITOR on its temporary file. This filter rewrites the block
# limits on the mount's line and leaves everything else, including the inode line,
# exactly as edquota wrote it.
editor_filter() {
	cat <<'FILTER'
#!/bin/ksh
# edquota hands the editor its temporary file and writes back whatever is left
# there. This filter rewrites the limits, and keeps a copy of what it was given and
# what it left, because that is the only way to tell a write that did not take from
# a kernel that has not noticed a write that did.
file="$1"
[ -n "${EDITOR_DUMP_DIR:-}" ] || { printf 'EDITOR_DUMP_DIR is not set\n' >&2; exit 1; }
cp -p "$file" "$EDITOR_DUMP_DIR/received" 2>/dev/null || true
grep -q "^$EDITOR_MOUNT:" "$file" ||
	{ printf 'no line for %s in %s\n' "$EDITOR_MOUNT" "$file" >&2; exit 1; }
tmp="$file.kyriakon"
awk -v m="$EDITOR_MOUNT" -v soft="$QUOTA_SOFT_KB" -v hard="$QUOTA_HARD_KB" '
	$0 ~ ("^" m ":") { sub(/limits.*/, "limits (soft = " soft ", hard = " hard ")") }
	{ print }
' "$file" > "$tmp" && mv "$tmp" "$file"
cp -p "$file" "$EDITOR_DUMP_DIR/after" 2>/dev/null || true
FILTER
}

# The limits as they stand in a dump of edquota's file. One field at a time, so a
# caller can compare each against what it asked for.
dump_limit() {
	awk -v m="$mount" -v want="$2" '
		$0 ~ ("^" m ":") {
			if (match($0, /soft = [0-9]+/)) s = substr($0, RSTART + 7, RLENGTH - 7)
			if (match($0, /hard = [0-9]+/)) h = substr($0, RSTART + 7, RLENGTH - 7)
			print (want == 1 ? s : h)
			exit
		}' "$1"
}

read_limits() {
	quota -v -u "$1" 2>/dev/null | awk -v m="$mount" '$1 == m { print $3, $4; exit }'
}

set_limits() {
	typeset user home diag filter soft_read hard_read read
	user="$1"
	home=$(account_home "$user")
	[ -n "$home" ] || die "$user is not in $passwd_file"
	case "$home" in
	"$mount"/*) : ;;
	*) die "$user's home is $home, which is not on $mount, so no allowance applies" ;;
	esac

	[ -f "$quota_file" ] || {
		printf 'quotas are not on for %s, so there is nothing to set yet.\n' "$mount" >&2
		printf 'Run: doas ksh %s/quota-apply.sh --enable\n' "$script_dir" >&2
		exit 3
	}

	# The dump directory holds what the editor was given and what it left, so a run
	# that goes wrong can be read afterwards rather than guessed at. It is removed on
	# success and kept on failure, where the message names it.
	diag=$(mktemp -d "${TMPDIR:-/tmp}/kyriakon-quota-diag.XXXXXX")
	chmod 0700 "$diag"
	filter="$diag/editor"
	editor_filter > "$filter"
	chmod 0700 "$filter"
	# The trap reads a script-scope name, not the local one. A ksh function's
	# `typeset` variables have no scope left by the time an EXIT trap runs, and with
	# `set -u` that makes every run end in `filter: parameter not set`, the runs that
	# worked included, which is noise on a line an operator has to be able to trust.
	# Only the editor script goes: on the failure path the directory it sits in is
	# what the message tells the operator to read, so that outlives the run.
	trap_diag="$diag"
	trap 'rm -f "$trap_diag/editor"' EXIT

	QUOTA_SOFT_KB="$soft_kb" QUOTA_HARD_KB="$hard_kb" EDITOR_MOUNT="$mount" \
		EDITOR_DUMP_DIR="$diag" EDITOR="$filter" edquota -u "$user" ||
		die "edquota failed for $user, so nothing was written"

	# What the editor left is what edquota writes back, which makes it the thing to
	# check. quota(1) reads through the kernel, and the kernel caches limits per user
	# without noticing a write made in userland, so it can report the old figures for
	# a write that worked. Checking the dump first keeps that from reading as failure.
	[ -f "$diag/after" ] ||
		die "edquota never ran the editor: there is no $diag/after, so nothing was written. Keep $diag and report it"
	soft_read=$(dump_limit "$diag/after" 1)
	hard_read=$(dump_limit "$diag/after" 2)
	if [ "$soft_read" != "$soft_kb" ] || [ "$hard_read" != "$hard_kb" ]; then
		die "the editor left soft $soft_read hard $hard_read for $mount, not soft $soft_kb hard $hard_kb. What it was given and what it left are both in $diag"
	fi
	printf '%s: soft %s KB, hard %s KB written to the quota file\n' "$user" "$soft_read" "$hard_read"

	# Secondary, and a difference here is expected rather than a failure. The kernel
	# caches limits per user and does not notice a write made in userland, so quota(1)
	# can report the old figures for a write that worked, and the note says so rather
	# than pretending the write failed.
	#
	# The order in the advice is the safe one, and the obvious order is not. Turning
	# quotas off flushes the kernel's in-core figures back to the quota file, so
	# running quotaoff *after* a write can put those cached figures straight back over
	# it and undo the write. Turning them off before the write leaves nothing cached
	# to overwrite with, and the quotaon that follows loads the file the write made.
	# That is the refresh without the reboot. The 2026-10-05 run on the box is what
	# turned this up: the advice here was the other order, the operator followed it,
	# and the allowance it had just applied read back as no allowance at all.
	read=$(read_limits "$user")
	if [ "$read" != "$soft_kb $hard_kb" ]; then
		printf 'note: quota -v -u %s reports "%s" until the kernel re-reads the quota file.\n' \
			"$user" "$(if [ -n "$read" ]; then printf '%s' "$read"; else printf 'nothing'; fi)"
		printf 'To have the kernel read it without a reboot, turn quotas off first, then apply, then on:\n'
		printf '  doas quotaoff -v %s\n  doas ksh %s/quota-apply.sh %s\n  doas quotaon -u -v %s\n' \
			"$mount" "$script_dir" "$user" "$mount"
	fi
	rm -rf "$diag"
}

# Clearing is the same write with zeroes, so it goes through the same filter and the
# same read-back: a clear that did not take must fail as loudly as a set that did not.
clear_limits() {
	typeset soft_save hard_save
	[ "$#" -eq 1 ] || die "usage: $0 --clear <username>"
	soft_save=$soft_kb
	hard_save=$hard_kb
	soft_kb=0
	hard_kb=0
	set_limits "$1"
	soft_kb=$soft_save
	hard_kb=$hard_save
}

# --- modes ----------------------------------------------------------------

cmd_enable() {
	if fstab_has_userquota; then
		printf '%s already carries userquota in %s\n' "$mount" "$fstab"
	else
		fstab_patch
		printf '\nThe fstab change takes effect at the next boot; the live path below\n'
		printf 'turns quotas on now without one.\n\n'
	fi

	if [ -f "$quota_file" ]; then
		printf '%s already exists, so quotacheck is skipped\n' "$quota_file"
	else
		printf 'running quotacheck on %s (it wants the filesystem quiet)\n' "$mount"
		quotacheck -v "$mount" || die "quotacheck failed"
	fi

	# quotaon is attempted whenever the state is not already on. It exits non-zero
	# when the filesystem is already enabled, which is not a failure, so the state is
	# what decides rather than the exit code.
	# Always attempted. Skipping it when the probe said "on" was wrong: the probe goes
	# on seeing the quota file, which quotacheck has just created, so the enable would
	# report success while doing nothing.
	if [ "$(quotas_state)" = on ]; then
		printf 'the quota file for %s is in place; running quotaon anyway\n' "$mount"
	fi
	# -u: user quotas only. The fstab line carries userquota and no groupquota, because
	# every account already has its own group of the same name (add-user.sh passes
	# -g =uid), so a group quota would be a second mechanism measuring the same thing.
	# Without -u, quotaon asks for both and prints "group quotas using
	# /home/quota.group: No such file or directory" before turning user quotas on.
	# /etc/rc runs `quotaon -a` the same way at boot, so that one line in the boot log
	# is expected and harmless: the same call still reports user quotas turned on.
	printf 'running quotaon on %s\n' "$mount"
	if quotaon -u -v "$mount"; then
		printf 'quotaon reported success\n'
	else
		printf 'quotaon exited non-zero. It does that when quotas are already enabled,\n'
		printf 'which is not a failure here, so the state is checked below.\n'
	fi

	[ -f "$quota_file" ] || die "$quota_file still does not exist, so quotas are not on"
	case "$(quotas_state)" in
	on) printf 'the quota file exists and quota(1) lists %s. If quotaon succeeded above,\n' "$mount"
	    printf 'enforcement is live now; the next boot makes it certain either way.\n' ;;
	off) die "quotaon ran but quota -v -u $(first_account) still reports none. Check by hand: doas quota -v -u $(first_account)" ;;
	*) printf 'could not read the state from quota(1); check by hand: doas repquota -u %s\n' "$mount" ;;
	esac
	printf '\nquotas are on. Two things left:\n'
	printf '  doas edquota -t              # confirm the grace period, one week by default\n'
	printf '  doas reboot                  # the clean path, since rc.conf has check_quotas=YES\n'
	printf '\nWith no limit set an account is unlimited, so nothing changes for existing\n'
	printf 'accounts until you run: doas ksh %s/quota-apply.sh --all\n' "$script_dir"
}

cmd_show() {
	typeset read
	printf 'mount:   %s\n' "$mount"
	printf 'fstab:   %s\n' "$fstab"
	if fstab_has_userquota; then
		printf 'fstab:   the %s line carries userquota\n' "$mount"
	else
		printf 'fstab:   the %s line does NOT carry userquota, so quotas cannot be on\n' "$mount"
	fi
	printf 'quotafile: %s\n' "$(if [ -f "$quota_file" ]; then echo present; else echo missing; fi)"
	printf 'quota file on the mount: %s (quota -v -u %s says %s; this cannot show\n' "$(if [ -f "$quota_file" ]; then echo present; else echo missing; fi)" "$(first_account)" "$(quotas_state)"
	printf 'whether the kernel is enforcing, which a reboot settles)\n'
	printf 'repquota -u %s:\n' "$mount"
	repquota -u "$mount" 2>&1 | sed 's/^/  /' || true
	printf 'member accounts on %s:\n' "$mount"
	for user in $(member_accounts); do
		read=$(read_limits "$user")
		printf '  %-20s %s\n' "$user" "$(if [ -n "$read" ]; then echo "soft $read"; else echo no limits read; fi)"
	done
}

cmd_all() {
	typeset found user
	found=no
	for user in $(member_accounts); do
		found=yes
		set_limits "$user"
	done
	[ "$found" = yes ] || die "no member accounts found on $mount (shell /sbin/nologin, home under it)"
}

self_test() {
	typeset work fails filter rc out
	work=$(mktemp -d "${TMPDIR:-/tmp}/kyriakon-quota-test.XXXXXX")
	# Script scope, for the reason set_limits gives: a function's `typeset` names are
	# gone by the time an EXIT trap runs, and `set -u` turns that into a line on stderr
	# and a non-zero exit on a run where every check passed. Seen on the box on
	# 2026-10-05, where the self-test printed "all checks passed" and exited 1.
	self_test_work="$work"
	trap 'rm -rf "$self_test_work"' EXIT
	fails=0
	check() {
		if [ "$2" = "$3" ]; then
			printf '  ok   %s\n' "$1"
		else
			printf '  FAIL %s: expected [%s], got [%s]\n' "$1" "$3" "$2"
			fails=$((fails + 1))
		fi
	}
	limits_of() {
		awk -v m="$1" '$0 ~ ("^" m ":")' "$2" 2>/dev/null | sed 's/.*limits/limits/'
	}
	sample() {
		cat > "$1" <<EOF
Quotas for user member:
$test_mount: KBytes in use: 412980, limits (soft = $2, hard = $3)
		inodes in use: 1234, limits (soft = 0, hard = 0)
EOF
	}

	test_mount="$work/home"
	mkdir -p "$test_mount"
	: > "$test_mount/quota.user"

	cat > "$work/fstab" <<EOF
aaa.a / ffs rw 1 1
bbb.b $test_mount ffs rw,nodev,nosuid 1 2
EOF
	cat > "$work/passwd" <<EOF
root:*:0:0:daemon:/root:/bin/ksh
oliver:*:1000:1000:operator:/home/oliver:/bin/ksh
member:*:1001:1001:member:$test_mount/member:/sbin/nologin
EOF
	# Point the script's own variables at the fixtures, so no check can touch the
	# real fstab, passwd or mount.
	fstab="$work/fstab"
	passwd_file="$work/passwd"
	mount="$test_mount"
	quota_file="$mount/quota.user"

	# 1. fstab detection and patching
	check "fstab starts without userquota" "$(fstab_has_userquota && echo yes || echo no)" "no"
	fstab_patch >/dev/null
	check "fstab gains userquota" "$(fstab_has_userquota && echo yes || echo no)" "yes"
	cp "$work/fstab" "$work/fstab.once"
	fstab_patch >/dev/null
	check "patching twice changes nothing" "$(cmp -s "$work/fstab" "$work/fstab.once" && echo same || echo differs)" "same"
	check "the backup holds the original" "$(grep -c userquota "$work/fstab.kyriakon.bak")" "0"

	# 2. the editor filter, driven the way edquota drives it, and the dumps it leaves
	filter="$work/filter"
	editor_filter > "$filter"
	chmod 0700 "$filter"
	mkdir -p "$work/d1"
	sample "$work/sample1" 0 0
	QUOTA_SOFT_KB=5242880 QUOTA_HARD_KB=5767168 EDITOR_MOUNT="$test_mount" \
		EDITOR_DUMP_DIR="$work/d1" "$filter" "$work/sample1"
	check "the file edquota gets back carries the limits" \
		"$(limits_of "$test_mount" "$work/d1/after")" "limits (soft = 5242880, hard = 5767168)"
	check "what the editor received is kept" \
		"$(limits_of "$test_mount" "$work/d1/received")" "limits (soft = 0, hard = 0)"
	check "the inode line is left alone" \
		"$(sed -n '3p' "$work/d1/after" | sed 's/.*limits/limits/')" "limits (soft = 0, hard = 0)"

	mkdir -p "$work/d2"
	sample "$work/sample2" 5242880 5767168
	QUOTA_SOFT_KB=0 QUOTA_HARD_KB=0 EDITOR_MOUNT="$test_mount" \
		EDITOR_DUMP_DIR="$work/d2" "$filter" "$work/sample2"
	check "clearing writes zero limits" \
		"$(limits_of "$test_mount" "$work/d2/after")" "limits (soft = 0, hard = 0)"

	check "the soft limit is read from a dump" "$(dump_limit "$work/d1/after" 1)" "5242880"
	check "the hard limit is read from a dump" "$(dump_limit "$work/d1/after" 2)" "5767168"

	# 3. the stubs, and quota(1) reporting the kernel's view
	mkdir -p "$work/bin"
	cat > "$work/bin/quota" <<EOF
#!/bin/ksh
if [ -n "\${STUB_NONE:-}" ]; then
	printf 'Disk quotas for user member (uid 1001): none\n'
	exit 0
fi
printf 'Disk quotas for user member (uid 1001):\n'
printf 'Filesystem   blocks   quota   limit   grace   files   quota   limit   grace\n'
printf '%s       412980  %s %s             1234       0       0\n' "$test_mount" "\${STUB_SOFT:-5242880}" "\${STUB_HARD:-5767168}"
EOF
	chmod 0700 "$work/bin/quota"
	PATH="$work/bin:$PATH"
	check "the kernel's view parses" "$(read_limits member)" "5242880 5767168"

	# 4. the whole path, through an edquota stub that behaves like the real one
	cat > "$work/bin/edquota" <<EOF
#!/bin/ksh
tmp="$work/edquota.tmp"
cat > "\$tmp" <<'SAMPLE'
Quotas for user member:
$test_mount: KBytes in use: 412980, limits (soft = 0, hard = 0)
		inodes in use: 1234, limits (soft = 0, hard = 0)
SAMPLE
"\$EDITOR" "\$tmp" || exit 1
cp "\$tmp" "$work/applied"
EOF
	chmod 0700 "$work/bin/edquota"
	set +e
	( set_limits member ) >/dev/null 2>&1
	rc=$?
	set -e
	check "setting an allowance succeeds" "$rc" "0"
	check "and edquota applied the new limits" \
		"$(limits_of "$test_mount" "$work/applied")" "limits (soft = 5242880, hard = 5767168)"

	# 4b. an edquota that never runs the editor says so instead of passing
	cat > "$work/bin/edquota" <<'EOF'
#!/bin/ksh
exit 0
EOF
	chmod 0700 "$work/bin/edquota"
	set +e
	( set_limits member ) > "$work/err.txt" 2>&1
	rc=$?
	set -e
	out=$(cat "$work/err.txt")
	check "an editor that never ran exits 1" "$rc" "1"
	check "and the message names it" "$(printf '%s' "$out" | grep -c 'never ran the editor')" "1"
	check "and says nothing was written" "$(printf '%s' "$out" | grep -c 'so nothing was written')" "1"

	# 5. quotas off is exit 3, a state rather than a failure
	rm -f "$mount/quota.user"
	set +e
	( set_limits member ) >/dev/null 2>&1
	rc=$?
	set -e
	check "quotas off exits 3" "$rc" "3"
	: > "$mount/quota.user"

	# 6. the state probe
	STUB_NONE=1
	export STUB_NONE
	check "quota reporting none reads as off" "$(quotas_state)" "off"
	unset STUB_NONE
	check "quota listing the mount reads as on" "$(quotas_state)" "on"

	if [ "$fails" -eq 0 ]; then
		printf 'self-test: all checks passed\n'
	else
		printf 'self-test: %s failed\n' "$fails" >&2
		exit 1
	fi
}

case "${1:-}" in
--enable) cmd_enable ;;
--all) cmd_all ;;
--clear) [ "$#" -eq 2 ] || usage; clear_limits "$2" ;;
--show) cmd_show ;;
--self-test) self_test ;;
"") usage ;;
-*) usage ;;
*) set_limits "$1" ;;
esac
