#!/bin/ksh
# make-bsdrd.sh - build a bsd.rd whose ramdisk carries the response file.
#
# Runs as ROOT ON THE MAIL BOX, never on the rescue host: it mounts the ramdisk
# image, and mounting is the one thing root is needed for. Everything else here
# happens on the box because the box is OpenBSD and has rdsetroot, vnconfig and
# mount_ffs; Hetzner's rescue is Linux and has none of them.
#
# Output: /tmp/bsd.rd.autoinstall, to be written to the target disk's first
# sectors by the rescue host in place of the stock image.
#
# Why bother: autoinstall discovers its response file over DHCP, and Hetzner's
# DHCP does not carry next-server or filename. The installer then asks for the
# location, which is one prompt a human has to answer at the console. Putting
# /auto_install.conf inside the ramdisk answers that too, and the install runs
# with no console input at all.
#
# The image is signed by OpenBSD and this modifies it. The chain still holds
# where it matters: the installer verifies the sets it downloads against the
# release key already inside the ramdisk, and that key is untouched.
set -euo pipefail

conf="${1:-/root/kyriakon-infra/openbsd/restore-template/install.conf}"
work=/tmp/bsdrd-build
out=/tmp/bsd.rd.autoinstall

[ -f "$conf" ] || { echo "no response file at $conf" >&2; exit 1; }
rm -rf "$work"
mkdir -p "$work" /mnt

cd "$work"
echo "fetching the release image"
ftp -o bsd.rd https://cdn.openbsd.org/pub/OpenBSD/7.9/amd64/bsd.rd
ftp -o SHA256.sig https://cdn.openbsd.org/pub/OpenBSD/7.9/amd64/SHA256.sig
signify -Cp /etc/signify/openbsd-79-base.pub -x SHA256.sig bsd.rd
echo "signature verified against the installed release key"

gunzip -c bsd.rd > bsd.rd.raw
rdsetroot -x bsd.rd.raw ram.fs

vnconfig vnd0 ram.fs
trap 'umount /mnt 2>/dev/null || true; vnconfig -u vnd0 2>/dev/null || true' EXIT
# The extracted image may be a bare filesystem or a labelled disk; the two forms
# mount differently. Neither was testable without root, so try both.
mount /dev/vnd0a /mnt 2>/dev/null || mount_ffs /dev/vnd0c /mnt
install -m 0644 "$conf" /mnt/auto_install.conf
echo "response file installed as /auto_install.conf"
ls -l /mnt/auto_install.conf
umount /mnt
vnconfig -u vnd0

rdsetroot bsd.rd.raw ram.fs
gzip -9 -c bsd.rd.raw > "$out"
ls -l "$out"
echo "ready: write $out to the target disk's first sectors, not bsd.rd"
