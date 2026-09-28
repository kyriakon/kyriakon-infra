#!/bin/bash
# prepare-disk.sh - write the install media to the target disk, and give OpenBSD
# the whole disk to install into.
#
# Runs ON THE HETZNER RESCUE HOST. Not on the box being built, and not on the
# mail box. The rescue is Debian-based, hence bash rather than the ksh the rest
# of this repo assumes: Linux can write a disk image and a partition table, and
# cannot mount the filesystem that results.
#
# Why the partition must be extended. miniroot79.img is a whole-disk image whose
# MBR declares an OpenBSD partition of 10,368 sectors, about 5 MB, holding the
# installer kernel. The interactive installer asks "Use (W)hole disk MBR, whole
# disk (G)PT" and a person answers it, which is how the live box came out with a
# 38 GB root. That question belongs to fdisk, not to the installer, so a response
# file cannot answer it, and with the partition left as it is disklabel -A
# allocates "all the disk space in the OpenBSD portion", which is 5 MB. The
# result was a 1.27 MB root, no room for the installer to prefetch and verify the
# sets, and a run that stopped before installing anything.
#
# Usage: bash prepare-disk.sh [expected-sha256]
#
# The default hash was verified on the mail box with signify against
# /etc/signify/openbsd-79-base.pub. Linux has no signify, so comparing against
# that verified value is the most this side can do, and the script refuses to
# write anything if it does not match.
set -euo pipefail

IMG_URL=https://cdn.openbsd.org/pub/OpenBSD/7.9/amd64/miniroot79.img
EXPECTED=${1:-7f0ba80ce491008cce01bbefe34f1ecf820b93eb32565c3c708f5c50ea619b75}
DISK=${DISK:-/dev/sda}

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -b "$DISK" ] || { echo "$DISK is not a block device" >&2; exit 1; }
if mount | grep -q "^$DISK"; then
	echo "$DISK has mounted filesystems, refusing" >&2
	exit 1
fi

total=$(blockdev --getsz "$DISK")
printf 'disk: %s sectors (%.1f GiB)\n' "$total" "$(echo "$total * 512 / 1073741824" | bc -l)"

cd /tmp
rm -f miniroot79.img
wget -q -O miniroot79.img "$IMG_URL"
got=$(sha256sum miniroot79.img | cut -d' ' -f1)
echo "sha256: $got"
if [ "$got" != "$EXPECTED" ]; then
	echo "does not match the signature-verified value, refusing to write" >&2
	exit 1
fi

echo "writing the installer to $DISK"
dd if=/tmp/miniroot79.img of="$DISK" bs=4M conv=fsync status=none
sync

# Find the OpenBSD partition rather than assuming its slot. The image happens to
# put it fourth, but that is not something worth trusting.
entry=''
for slot in 0 1 2 3; do
	base=$((446 + slot * 16))
	t=$(dd if="$DISK" bs=1 skip=$((base + 4)) count=1 status=none | od -An -tu1 | tr -d ' ')
	if [ "$t" = "166" ]; then entry=$base; break; fi
done
[ -n "$entry" ] || { echo "no 0xA6 partition in the MBR, refusing" >&2; exit 1; }

start=$(od -An -tu4 -j $((entry + 8)) -N4 "$DISK" | tr -d ' ')
count=$(( total - start ))
printf 'openbsd entry at %s: start %s, extending the count from %s to %s sectors\n' \
	"$entry" "$start" "$(od -An -tu4 -j $((entry + 12)) -N4 "$DISK" | tr -d ' ')" "$count"

printf '%b' "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
	$((count & 255)) $(((count >> 8) & 255)) $(((count >> 16) & 255)) $(((count >> 24) & 255)))" \
	| dd of="$DISK" bs=1 seek=$((entry + 12)) conv=notrunc status=none
sync

fdisk -l "$DISK" | tail -3
echo
echo "done. Reboot to boot the installer; it still needs someone to press A at its menu."
