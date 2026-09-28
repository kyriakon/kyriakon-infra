# Terraform + snapshot procedure

One Hetzner Cloud server for the kyriakon.net mail box, provisioned from an
OpenBSD snapshot (proposal section 6.1, snapshot-first). The snapshot is the gold
image; Terraform only describes the box. Research: `docs/planning/research/openbsd-hetzner-snapshot.md`
(ticket #4).

## Prerequisites

- `HCLOUD_TOKEN` - Hetzner Cloud API token, environment variable only, never committed.
- `hcloud` CLI (snapshot procedure).
- `terraform` >= 1.5.

## 1. Create the snapshot (manual, one-time - ticket #21)

Hetzner has no native OpenBSD image, so install once by hand and snapshot it:

1. Provision a throwaway Cloud VPS (any Linux type, e.g. `cx22`/`cx32`). Its disk
   **must be <= the production `server_type` disk**, or the snapshot won't fit.
2. Enable rescue and reboot into it:
   ```sh
   hcloud server enable-rescue --type linux64 <server>
   hcloud server reset <server>
   ```
3. In the rescue shell (SSH as root), download the install image and **verify it
   with `signify` before trusting it** - a substituted image is a compromised
   platform from first boot:
   ```sh
   wget https://cdn.openbsd.org/pub/OpenBSD/7.9/amd64/miniroot79.img
   signify -Cp /etc/signify/openbsd-7X-base.pub -x SHA256.sig miniroot79.img
   ```
   (`miniroot` pulls file sets over the network; `install79.img` bundles them.
   Substitute the current 7.x release. `signify` catches tampering, `SHA256`
   only corruption.)
4. Write it to disk and reboot:
   ```sh
   dd if=miniroot79.img of=/dev/sda bs=4M && sync && reboot
   ```
5. Complete the **interactive** installer over the VNC console. Choose **full-disk
   `softraid` encryption** when prompted - now-or-never, and required by the
   threat model (proposal section 2). Answer **no** at that prompt only when
   building the restore template, for the reason in "The restore template" below.
6. Post-install, before snapshotting:
   ```sh
   syspatch
   pkg_add dovecot rspamd restic
   pkg_add -u
   ```
7. Shut down cleanly (`shutdown -h now`), then snapshot with a label:
   ```sh
   hcloud server create-image --type snapshot \
     --description "kyriakon-openbsd-79-$(date +%Y%m%d)" \
     --label os=openbsd \
     <server>
   ```
8. Record the returned numeric image ID (operational reference only - Terraform
   selects by the `os=openbsd` label, not the ID).

## 2. Provision with Terraform (ticket #22 - apply is human-only)

```sh
cp terraform.tfvars.example terraform.tfvars   # set server_name
export HCLOUD_TOKEN=...
terraform init
terraform plan      # read the diff
terraform apply     # human-run propose-only step - never by an agent
```

**Patch-on-provision** - after `apply`, before the box serves traffic:

```sh
doas syspatch && doas pkg_add -u
```

This bounds the window where a fresh box boots stale binaries if the snapshot is
slightly behind (proposal section 6.10). Then re-snapshot (section 3).

## 3. Re-snapshot after every patch cycle

A snapshot freezes base + packages. After each `syspatch`/`pkg_add -u` cycle on
the live box, shut down cleanly and re-snapshot with the same `os=openbsd`
label. `most_recent` makes Terraform pick up the newest matching snapshot
automatically - never reprovision from a stale one, or a rebuilt box boots
vulnerable rspamd (section 6.10).

## Variables

| Variable            | Default        | Notes |
| ------------------- | -------------- | ----- |
| `server_name`       | -              | host-identifying; set in `terraform.tfvars` |
| `server_type`       | `cx23`         | disk >= snapshot's source disk |
| `location`          | `hel1`         | region the storage box is NOT in |
| `snapshot_selector` | `os=openbsd`   | set at `create-image` time |

## The restore template

The weekly test box comes from a snapshot labelled `kind=restore`, and that snapshot is
built by section 1 with **one answer changed**: no disk encryption.

This is forced rather than preferred. A softraid crypto root stops at the passphrase
prompt, ssh never answers while it waits, and cron at 03:45 has nobody to type it. The
snapshot research already recorded the shape of that failure: a box in that state reports
as running in the API and silently accepts no connections. Building the template from the
gold image in section 1 therefore produces a box that boots, waits, and is deleted again
by the standup's own timeout, every week, without ever testing a restore.

Declining encryption costs nothing here, because the template holds nothing worth
protecting: a base install, `restic jq git`, the two test scripts, and a public key. It
carries no user data, no repository password, and no storage key. Those two secrets are
copied to the throwaway after each boot by `scripts/restore-standup.sh`. What the
throwaway does hold, in plaintext for the minutes it runs, is the restored data, and that
residue is the open follow-up recorded in #111 rather than a property of this image.

So the template is section 1 with these differences:

- Answer **no** to disk encryption at the installer's prompt.
- Install `restic jq git` rather than `dovecot rspamd restic`.
- `mkdir -p /root/bin`, and put `lib.sh` and `restore-test.sh` in it, mode 0755. They are
  in this repo at `scripts/`, and the box can fetch them from the public repository.
- Append the mail box's `/root/.ssh/kyriakon-standup.pub` to `/root/.ssh/authorized_keys`.
  The standup reaches the throwaway with it after every boot, since the template carries
  it into the snapshot.
- Snapshot with `--label kind=restore`, not the `os=openbsd` label section 1 uses, so a
  test run can never pick up a provisioning image and provisioning can never pick up the
  template.

The installer's answers live in `openbsd/restore-template/install.conf`, written against the
question text 7.9 actually uses, read out of the release's own `bsd.rd` ramdisk. This
matters: autoinstall matches questions by their text and silently falls back to the
installer's default when it cannot match an answer, so a response file taken from an older
write-up installs something other than what it says. The prompts that bit are `Password for
root account?` and `Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout?`,
neither of which appears in older guides in that form.

Two ways to put that file in front of the installer.

Straightforward, and what the four differences above assume: choose **(A)utoinstall** at the
ramdisk's prompt. Hetzner's DHCP carries no `next-server`, so it then asks `Response file
location?`, and the answer is that file's URL. One prompt at the console instead of twenty.

Fully unattended is not built yet, and the image's shape is why.

`miniroot79.img` has no disklabel and no OpenBSD filesystem. It is an MBR with x86 boot
code at sector 0, then a FAT partition starting at sector 64 whose OEM name is `BSD  4.4`,
holding the installer kernel under the name `bsd` rather than `bsd.rd`. The first attempt at
a patch script mounted `/dev/vnd0a` and `/dev/vnd0c` looking for an FFS, found neither, and
reported the kernel as missing when the truth was that nothing had mounted at all. That
script is deleted rather than left to be run.

The unattended route is worth having and needs the kernel patched rather than a filesystem
mounted: the response file has to reach `/auto_install.conf` inside the kernel's ramdisk, so
the work is to lift `/bsd` out of the FAT partition, `gunzip` it, `rdsetroot -x` the ramdisk,
add the file, put both back, and write the result where the FAT expects the kernel. The
signature-verified `bsd.rd` from the release directory is the same kernel under its release
name, which is where the ramdisk can be built from without touching the FAT at all, if the
kernel can be put back afterwards.

Until that exists, the URL route is the one to use, and the URL is kept short deliberately:
`https://kyriakon.net/install.conf`, served from the site's document root, which is a git
checkout. The canonical copy is in this repo at `openbsd/restore-template/install.conf`.

## The weekly restore box

`scripts/restore-standup.sh` creates the box the weekly restore test runs on, runs the test over ssh, and deletes the box in an exit trap. It uses the `hcloud` CLI rather than terraform, because the hcloud provider publishes no OpenBSD build: `terraform init` against any provider version fails on this platform, so terraform cannot drive a box from the mail box at all.

What terraform was there for was that a destroy could not reach the mail box, since destroy only removes what is in the state it runs against. The CLI version keeps that property by a narrower route: the script creates the server once, captures its id, and uses only that id for every later reference. The delete cannot resolve to anything but the box that run made. The mail box keeps its own protection besides, the live root's `prevent_destroy` and Hetzner's `delete_protection`.

The box comes from a snapshot labelled `kind=restore`, a third label beside `kind=gold` for provisioning images and `kind=dr` for point-in-time copies, so neither of those can be picked up by a test run. The template is a plain box without softraid, because a crypto root stops at a passphrase prompt and nobody is at the console when cron runs. It holds the test scripts and the standup's public key; the repository password and the read-only storage sub-account key are copied in after each boot.

## Discipline

- `terraform apply`/`destroy` against the live root are human-run, never by an agent and
  never unattended. The one automated path is `scripts/restore-standup.sh`, which creates
  and deletes the weekly test box with the `hcloud` CLI from cron on the mail box, and
  refers to that box only by the id it captured when creating it.
- The mail box has three refusals in front of a mistaken destroy: the standup's id
  discipline, which means it can only ask for the box it made this run; the live root's
  `prevent_destroy`, which stops a plan from proposing the removal at all; and Hetzner's
  `delete_protection`, which refuses the request even if it gets through.
- Terraform is never run automatically off the boxes: no cron, no launchd agent, nothing
  on a workstation that applies without someone at the keyboard.
- No secrets or host-identifying values in tracked files: `terraform.tfvars`,
  state, and `.terraform/` are gitignored.
