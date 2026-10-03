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
file="$1"
grep -q "^$EDITOR_MOUNT:" "$file" ||
	{ printf 'no line for %s in %s\n' "$EDITOR_MOUNT" "$file" >&2; exit 1; }
tmp="$file.kyriakon"
awk -v m="$EDITOR_MOUNT" -v soft="$QUOTA_SOFT_KB" -v hard="$QUOTA_HARD_KB" '
	$0 ~ ("^" m ":") {
		sub(/limits \(soft = [0-9]+, hard = [0-9]+\)/,
		    "limits (soft = " soft ", hard = " hard ")")
	}
	{ print }
' "$file" > "$tmp" && mv "$tmp" "$file"
FILTER
}

# quota(1), verbose, in the classic BSD layout:
#   Filesystem  blocks  quota  limit  grace  files  quota  limit  grace
#   /home       412980  5242880 5767168       1234   0      0
read_limits() {
	quota -v -u "$1" 2>/dev/null | awk -v m="$mount" '$1 == m { print $3, $4; exit }'
}

set_limits() {
	typeset user home filter read soft_read hard_read
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

	filter=$(mktemp "${TMPDIR:-/tmp}/kyriakon-quota-editor.XXXXXX")
	editor_filter > "$filter"
	chmod 0700 "$filter"
	trap 'rm -f "$filter"' EXIT

	# The filter reads these from the environment, which edquota passes through.
	QUOTA_SOFT_KB="$soft_kb" QUOTA_HARD_KB="$hard_kb" EDITOR_MOUNT="$mount" \
		EDITOR="$filter" edquota -u "$user" ||
		die "edquota failed for $user"

	read=$(read_limits "$user")
	[ -n "$read" ] ||
		die "set the allowance for $user but quota -v -u $user does not list $mount, so nothing can be confirmed"
	soft_read=$(printf '%s' "$read" | awk '{ print $1 }')
	hard_read=$(printf '%s' "$read" | awk '{ print $2 }')
	if [ "$soft_read" != "$soft_kb" ] || [ "$hard_read" != "$hard_kb" ]; then
		die "$user reads back as soft $soft_read hard $hard_read, not soft $soft_kb hard $hard_kb. The edquota file format may have changed; check by hand with: doas edquota $user"
	fi
	printf '%s: soft %s KB, hard %s KB (read back from quota)\n' "$user" "$soft_read" "$hard_read"
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
	# /etc/rc does exactly that at boot, so that one line in the boot log is expected
	# and harmless: the same call still reports "user quotas turned on".
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
	typeset work fails
	work=$(mktemp -d "${TMPDIR:-/tmp}/kyriakon-quota-test.XXXXXX")
	trap 'rm -rf "$work"' EXIT
	fails=0
	check() {
		if [ "$2" = "$3" ]; then
			printf '  ok   %s\n' "$1"
		else
			printf '  FAIL %s: expected [%s], got [%s]\n' "$1" "$3" "$2"
			fails=$((fails + 1))
		fi
	}

	test_mount="$work/home"
	mkdir -p "$test_mount"
	: > "$test_mount/quota.user"

	# A fixture fstab without the option, and a fixture passwd with one member.
	cat > "$work/fstab" <<EOF
aaa.a / ffs rw 1 1
bbb.b $test_mount ffs rw,nodev,nosuid 1 2
EOF
	cat > "$work/passwd" <<EOF
root:*:0:0:daemon:/root:/bin/ksh
oliver:*:1000:1000:operator:/home/oliver:/bin/ksh
member:*:1001:1001:member:$test_mount/member:/sbin/nologin
EOF
	# Point the script's own variables at the fixtures. These are the same names
	# the env supplies at startup, reassigned here so no test can touch the real
	# /etc/fstab, /etc/passwd or /home.
	fstab="$work/fstab"
	passwd_file="$work/passwd"
	mount="$test_mount"
	quota_file="$mount/quota.user"

	# 1. detection and patching
	check "fstab starts without userquota" "$(fstab_has_userquota && echo yes || echo no)" "no"
	fstab_patch >/dev/null
	check "fstab gains userquota" "$(fstab_has_userquota && echo yes || echo no)" "yes"
	cp "$work/fstab" "$work/fstab.once"
	fstab_patch >/dev/null
	check "patching twice changes nothing" "$(cmp -s "$work/fstab" "$work/fstab.once" && echo same || echo differs)" "same"
	check "the backup holds the original" "$(grep -c userquota "$work/fstab.kyriakon.bak")" "0"

	# 2. the editor filter, driven the way edquota drives it
	cat > "$work/sample" <<EOF
Quotas for user member:
$test_mount: KBytes in use: 412980, limits (soft = 0, hard = 0)
		inodes in use: 1234, limits (soft = 0, hard = 0)
EOF
	filter="$work/filter"
	editor_filter > "$filter"
	chmod 0700 "$filter"
	QUOTA_SOFT_KB=5242880 QUOTA_HARD_KB=5767168 EDITOR_MOUNT="$test_mount" \
		"$filter" "$work/sample"
	check "block limits rewritten" \
		"$(awk -v m="$test_mount" '$0 ~ "^" m ":" { print $0 }' "$work/sample" | sed 's/.*limits/limits/')" \
		"limits (soft = 5242880, hard = 5767168)"
	check "inode line left alone" \
		"$(sed -n '3p' "$work/sample" | sed 's/.*limits/limits/')" \
		"limits (soft = 0, hard = 0)"

	# 3. the read-back, both ways round
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
	check "read-back parses the limits" "$(read_limits member)" "5242880 5767168"

	# 4. a read-back that disagrees must fail the run, not pass quietly
	cat > "$work/bin/edquota" <<'EOF'
#!/bin/ksh
exit 0
EOF
	chmod 0700 "$work/bin/edquota"
	STUB_SOFT=0
	STUB_HARD=0
	export STUB_SOFT STUB_HARD
	set +e
	( set_limits member ) > "$work/err.txt" 2>&1
	rc=$?
	set -e
	out=$(cat "$work/err.txt")
	check "a limit that did not take exits 1" "$rc" "1"
	check "and says what it read" "$(printf '%s' "$out" | grep -c 'reads back as soft 0 hard 0')" "1"

	# 5. the contract add-user.sh branches on: quotas off is exit 3, a state, and
	#    not the same thing as a failed run.
	rm -f "$mount/quota.user"
	set +e
	( set_limits member ) >/dev/null 2>&1
	rc=$?
	set -e
	check "quotas off exits 3" "$rc" "3"
	: > "$mount/quota.user"

	# 5b. clearing: the same filter with zeroes, and the read-back agreeing.
	cat > "$work/sample2" <<EOF
Quotas for user member:
$test_mount: KBytes in use: 412980, limits (soft = 5242880, hard = 5767168)
		inodes in use: 1234, limits (soft = 0, hard = 0)
EOF
	QUOTA_SOFT_KB=0 QUOTA_HARD_KB=0 EDITOR_MOUNT="$test_mount" "$work/filter" "$work/sample2"
	check "clearing writes zero limits" \
		"$(awk -v m="$test_mount" '$0 ~ "^" m ":" { print $0 }' "$work/sample2" | sed 's/.*limits/limits/')" \
		"limits (soft = 0, hard = 0)"

	STUB_SOFT=0
	STUB_HARD=0
	export STUB_SOFT STUB_HARD
	set +e
	( clear_limits member ) >/dev/null 2>&1
	rc=$?
	set -e
	check "clearing an account exits 0 when read back as zero" "$rc" "0"

	# 6. the state probe, which is how --enable and --show ask the question that
	#    OpenBSD's quotaon cannot answer for them.
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
