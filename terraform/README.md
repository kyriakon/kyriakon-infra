# Terraform + snapshot procedure

One Hetzner Cloud server for the kyriakon.net mail box, provisioned from an
OpenBSD snapshot (proposal §6.1, snapshot-first). The snapshot is the gold
image; Terraform only describes the box. Research: `docs/planning/research/openbsd-hetzner-snapshot.md`
(ticket #4).

## Prerequisites

- `HCLOUD_TOKEN` — Hetzner Cloud API token, environment variable only, never committed.
- `hcloud` CLI (snapshot procedure).
- `terraform` ≥ 1.5.

## 1. Create the snapshot (manual, one-time — ticket #21)

Hetzner has no native OpenBSD image, so install once by hand and snapshot it:

1. Provision a throwaway Cloud VPS (any Linux type, e.g. `cx22`/`cx32`). Its disk
   **must be ≤ the production `server_type` disk**, or the snapshot won't fit.
2. Enable rescue and reboot into it:
   ```sh
   hcloud server enable-rescue --type linux64 <server>
   hcloud server reset <server>
   ```
3. In the rescue shell (SSH as root), download the install image and **verify it
   with `signify` before trusting it** — a substituted image is a compromised
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
   `softraid` encryption** when prompted — now-or-never, and required by the
   threat model (proposal §2).
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
8. Record the returned numeric image ID (operational reference only — Terraform
   selects by the `os=openbsd` label, not the ID).

## 2. Provision with Terraform (ticket #22 — apply is human-only)

```sh
cp terraform.tfvars.example terraform.tfvars   # set server_name
export HCLOUD_TOKEN=...
terraform init
terraform plan      # read the diff
terraform apply     # human-run propose-only step — never by an agent
```

**Patch-on-provision** — after `apply`, before the box serves traffic:

```sh
doas syspatch && doas pkg_add -u
```

This bounds the window where a fresh box boots stale binaries if the snapshot is
slightly behind (proposal §6.10). Then re-snapshot (§3).

## 3. Re-snapshot after every patch cycle

A snapshot freezes base + packages. After each `syspatch`/`pkg_add -u` cycle on
the live box, shut down cleanly and re-snapshot with the same `os=openbsd`
label. `most_recent` makes Terraform pick up the newest matching snapshot
automatically — never reprovision from a stale one, or a rebuilt box boots
vulnerable rspamd (§6.10).

## Variables

| Variable            | Default        | Notes |
| ------------------- | -------------- | ----- |
| `server_name`       | —              | host-identifying; set in `terraform.tfvars` |
| `server_type`       | `cx23`         | disk ≥ snapshot's source disk |
| `location`          | `hel1`         | region the storage box is NOT in |
| `snapshot_selector` | `os=openbsd`   | set at `create-image` time |

## Discipline

- `terraform apply`/`destroy` are human-run, never by an agent (propose-only).
- No secrets or host-identifying values in tracked files: `terraform.tfvars`,
  state, and `.terraform/` are gitignored.
