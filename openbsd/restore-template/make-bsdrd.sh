#!/bin/ksh
# make-bsdrd.sh - build a miniroot image whose installer answers itself.
#
# Runs as ROOT ON THE MAIL BOX, never on the rescue host: it mounts filesystem
# images, and mounting is the only thing root is needed for. The box is OpenBSD,
# so it has rdsetroot, vnconfig and mount_ffs; Hetzner's rescue is Linux and has
# none of them.
#
# Output: /tmp/miniroot79-patched.img, a whole bootable disk image with the
# response file inside the installer's ramdisk. The rescue host writes that to
# the disk instead of the stock miniroot.
#
# Why: autoinstall finds /auto_install.conf in the ramdisk without asking
# anything, so the install needs no console input at all. The alternative is
# choosing (A)utoinstall at the boot menu and pasting a URL, which is two things
# to get right on a VNC console.
#
# The stock image is signature-verified here before it is modified. Modifying it
# breaks its own signature, which is fine: the installer still verifies the sets
# it downloads against the release key inside the ramdisk, and that key is
# untouched. Only an answer file is added.
set -euo pipefail

conf="${1:-/root/src/kyriakon-infra/openbsd/restore-template/install.conf}"
work=/tmp/bsdrd-build
out=/tmp/miniroot79-patched.img

[ -f "$conf" ] || { echo "no response file at $conf" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "this needs root: it mounts filesystem images" >&2; exit 1; }

cleanup() {
	umount /mnt/ram 2>/dev/null || true
	umount /mnt/miniroot 2>/dev/null || true
	vnconfig -u vnd1 2>/dev/null || true
	vnconfig -u vnd0 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP

rm -rf "$work"
mkdir -p "$work" /mnt/miniroot /mnt/ram
cd "$work"

echo "fetching and verifying the stock image"
ftp -o miniroot79.img https://cdn.openbsd.org/pub/OpenBSD/7.9/amd64/miniroot79.img
ftp -o SHA256.sig https://cdn.openbsd.org/pub/OpenBSD/7.9/amd64/SHA256.sig
signify -Cp /etc/signify/openbsd-79-base.pub -x SHA256.sig miniroot79.img

echo "extracting the installer kernel the miniroot carries"
mkdir extract
cp miniroot79.img outer.img
vnconfig vnd0 outer.img
# The image is a whole disk, so it usually carries a label; fall back to the raw
# partition if it does not.
mount /dev/vnd0a /mnt/miniroot 2>/dev/null || mount_ffs /dev/vnd0c /mnt/miniroot
[ -f /mnt/miniroot/bsd.rd ] || { echo "no bsd.rd inside the miniroot" >&2; exit 1; }
cp /mnt/miniroot/bsd.rd extract/bsd.rd
umount /mnt/miniroot
vnconfig -u vnd0

echo "adding the response file to that kernel's ramdisk"
gunzip -c extract/bsd.rd > extract/bsd.rd.raw
rdsetroot -x extract/bsd.rd.raw extract/ram.fs
vnconfig vnd1 extract/ram.fs
mount /dev/vnd1a /mnt/ram 2>/dev/null || mount_ffs /dev/vnd1c /mnt/ram
install -m 0644 "$conf" /mnt/ram/auto_install.conf
ls -l /mnt/ram/auto_install.conf
umount /mnt/ram
vnconfig -u vnd1
rdsetroot extract/bsd.rd.raw extract/ram.fs
gzip -9 -c extract/bsd.rd.raw > extract/bsd.rd.new

echo "putting the patched kernel back into the image"
vnconfig vnd0 outer.img
mount /dev/vnd0a /mnt/miniroot 2>/dev/null || mount_ffs /dev/vnd0c /mnt/miniroot
install -m 0644 extract/bsd.rd.new /mnt/miniroot/bsd.rd
ls -l /mnt/miniroot/bsd.rd
umount /mnt/miniroot
vnconfig -u vnd0

cp outer.img "$out"
echo
echo "ready: $out"
echo "write it to the target disk in place of the stock miniroot."
echo "The boot menu will still appear; do not touch the console and autoinstall starts on its own."
sha256 -q "$out"
