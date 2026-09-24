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
   threat model (proposal section 2).
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
