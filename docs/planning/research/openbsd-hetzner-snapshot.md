# OpenBSD 7.x on Hetzner VPS — rescue-mode install & snapshot

Ticket: install OpenBSD 7.x on a Hetzner Cloud VPS via rescue mode, snapshot it through the Hetzner API, and use that snapshot as the Terraform `hcloud` image source (proposal §6.1, snapshot-first). Answers four questions: manual install steps, exact snapshot API/CLI calls, what Terraform `hcloud_server` needs, and the §6.10 package-patch-cadence caveat.

## Recommended shape (short answer)

1. Provision one throwaway Hetzner Cloud VPS (any Linux type, e.g. `cx22`/`cx32`).
2. Boot it into the Hetzner **rescue system** (`linux64`), download the OpenBSD `install7X.img`/`miniroot7X.img`, `dd` it onto the primary disk, reboot.
3. Run the **interactive** installer over the VNC console (no autoinstall response file — §6.1 deferred that spike). Choose full-disk `softraid` encryption when prompted.
4. Post-install: `syspatch`, `pkg_add` Dovecot/rspamd, configure mail/git/web. Then **shut down cleanly**.
5. Snapshot: `hcloud server create-image --type snapshot --description "kyriakon-openbsd-<rev>" <server>`.
6. Terraform references the snapshot by **numeric image ID** (snapshots have no `name`), via `data "hcloud_image"`.
7. Patch cadence: a snapshot freezes base + packages; never reprovision from a stale snapshot — re-snapshot after every `syspatch`/`pkg_add -u` cycle, and run the patch step in provisioning before the box serves traffic.

---

## 1. Manual install steps

Hetzner has no native OpenBSD image (proposal §4, "Host" row). The install path is: boot the Hetzner rescue system, write the OpenBSD ramdisk image to the disk, reboot into the installer.

### 1.1 Enter the rescue system

The Hetzner Cloud rescue system is a Debian-based Linux live environment booted over the network, not from local disk ([Hetzner: Using Rescue](https://docs.hetzner.com/cloud/servers/getting-started/rescue-system/)). Activate it either in the Hetzner Console ("Rescue" → "Enable rescue & power cycle") or via CLI:

```sh
hcloud server enable-rescue --type linux64 <server>
hcloud server reset <server>
```

Facts from primary sources:

- Rescue OS choices are `linux64` (and a legacy `linux32` that the CLI now rejects) ([hcloud CLI `enable-rescue` source](https://github.com/hetznercloud/cli/blob/main/internal/cmd/server/enable_rescue.go): default `--type linux64`; `linux32` returns "rescue type not supported anymore").
- `enable-rescue` injects an SSH key (`--ssh-key`) and/or returns a root password for the rescue session ([Hetzner: Using Rescue](https://docs.hetzner.com/cloud/servers/getting-started/rescue-system/), step 4).
- Plain "Enable rescue" stays armed for 60 minutes; "Enable rescue & power cycle" restarts immediately and stays armed until the next restart ([Hetzner: Using Rescue](https://docs.hetzner.com/cloud/servers/getting-started/rescue-system/), step 3).

### 1.2 Write the OpenBSD ramdisk image to disk

In the rescue shell (SSH in as `root`):

```sh
wget https://cdn.openbsd.org/pub/OpenBSD/7.9/amd64/miniroot79.img
# verify first (see 1.4)
dd if=miniroot79.img of=/dev/sda bs=4M
sync
reboot
```

This is the exact method Frederic Cambus (OpenBSD developer) documents for Hetzner Cloud: "provision a Linux instance to fetch the installation media and write it to the root disk," then "the installer will start after reboot, allowing us to perform an interactive installation using the console" ([Cambus, "OpenBSD/arm64 on Hetzner Cloud"](https://www.cambus.net/openbsd-arm64-on-hetzner-cloud/)). The same `dd`-the-ramdisk-to-disk pattern is the core of the OpenBSD installer's own design — `bsd.rd`/the install image boots into a live in-memory environment ([OpenBSD FAQ 4, "Overview of the Installation Procedure"](https://www.openbsd.org/faq/faq4.html)).

- Image choice: `install7X.img` **includes the file sets**; `miniroot7X.img` is smaller and pulls sets over the network ([OpenBSD FAQ 4, "Downloading OpenBSD"](https://www.openbsd.org/faq/faq4.html)). Either works; `install7X.img` removes a network dependency during set install but is ~10× larger. Version suffix tracks the release (`…79.img` for 7.9; the FAQ I cite is at 7.9, so substitute the current 7.x number).
- Hetzner Cloud primary disk is `/dev/sda` in the rescue system (confirmed by Cambus's `of=/dev/sda`).

### 1.3 Run the interactive installer

After reboot the OpenBSD ramdisk installer starts; complete it over the Hetzner Cloud VNC console (Hetzner Cloud KVM instances expose a VNC console in the Console — no serial/`qemu` dance needed, unlike Hetzner *dedicated* boxes, see §5). Follow [OpenBSD FAQ 4, "Performing a Simple Install"](https://www.openbsd.org/faq/faq4.html): `(I)nstall`, accept the defaults, set hostname, network (Hetzner Cloud serves DHCP — accept `dhcp`), and the root password.

**Full-disk encryption is a now-or-never install-time choice.** The installer asks "Do you want disk encryption?" ([OpenBSD FAQ 4, "Pre-Installation Checklist"](https://www.openbsd.org/faq/faq4.html)). Kyriakon's threat model requires full-disk `softraid` (§2: "Full-disk softraid + encrypted backup … a second, weaker layer"), and FDE cannot be cleanly retrofitted after install — the snapshot must already contain an encrypted disk. Choose `softraid` encryption at this prompt; the disk-layout mechanics are in the [OpenBSD softraid FAQ](https://www.openbsd.org/faq/faq14.html#softraid) (same guide the [grosu.nl](https://grosu.nl/openbsd-hetzner.html) Hetzner writeup points at).

Networking: Hetzner Cloud uses virtio NICs, so the installed system gets `vio0`/DHCP (see Cambus's dmesg: `vio0 at virtio1`). No `hostname.em0`→`hostname.re0` rename is needed on Cloud — that rename in the [grosu.nl](https://grosu.nl/openbsd-hetzner.html) guide is for a *dedicated* server's different NIC model.

### 1.4 Verify the image before trusting it

The FAQ requires cryptographic verification, not just checksums: `signify -Cp /etc/signify/openbsd-7X-base.pub -x SHA256.sig miniroot*.img` (SHA256 only catches accidental corruption; `signify` catches tampering) ([OpenBSD FAQ 4, "Downloading OpenBSD"](https://www.openbsd.org/faq/faq4.html)). This matters here because the snapshot later becomes the source of every real user's mail and keys — a substituted install image is a compromised platform from the first boot.

### 1.5 Post-install before snapshotting

The snapshot is the frozen gold image, so everything below must be done **before** the snapshot, on the throwaway box:

1. `syspatch` (base-system patches) — apply to current.
2. `pkg_add` Dovecot + rspamd (and any other packages), then `pkg_add -u`.
3. Install the provisioned config (mail/git/web/DNS), keys, `provision.sh`, etc.
4. **Shut down cleanly** (`shutdown -h now` from inside, or `hcloud server shutdown`) so the snapshot captures a consistent FFS filesystem — a snapshot of a running server can capture a mid-write filesystem.

Then snapshot (§2), and optionally keep the throwaway box or delete it.

---

## 2. Snapshot via the Hetzner API/CLI

### CLI

```sh
hcloud server create-image --type snapshot \
  --description "kyriakon-openbsd-79-<YYYYMMDD>" \
  --label os=openbsd --label rev=<n> \
  <server>
```

Exact syntax and flags from the [hcloud CLI `create-image` source](https://github.com/hetznercloud/cli/blob/main/internal/cmd/server/create_image.go):

- `Use: "create-image [options] --type <snapshot|backup> <server>"`
- `--type` — required, one of `snapshot` or `backup`.
- `--description` — string, the human label for the image.
- `--label key=value` — repeatable, sets image labels (used later for label-selector lookup in Terraform).
- Output: `Image <id> created from Server <id>` — i.e. the result is a **numeric image ID**.

### API

The CLI/Go client wrap a single REST call ([hcloud-go `server.go`, `ServerClient.CreateImage`](https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/server.go)):

```
POST /servers/{id}/actions/create_image
{ "description": "…", "type": "snapshot", "labels": { … } }
→ { "image": { "id": … , "type": "snapshot", … }, "action": { … } }
```

- `type` is an enum: `snapshot` | `backup` | (`system` only for Hetzner's stock images) ([hcloud-go `image.go`](https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/image.go)).
- The call returns an `Action` — creating a snapshot is asynchronous; poll the action until done (the CLI does this via `WaitForActions`).
- **Snapshot images have a `description`, not a `name`.** The image `name` field only exists for `type=system` images ([Terraform `hcloud_image` data source](https://registry.terraform.io/providers/hetznercloud/hcloud/latest/docs/data-sources/image): "`name` … only present when the type is `system`"). This is why Terraform must use the numeric ID (§3).

### Consistency

Shut the server down before `create-image` (§1.5). Hetzner's API does not force a shutdown (the CLI only validates `--type`), and a snapshot is a point-in-time disk copy — a running FFS filesystem can be captured mid-write. This is operational practice, not an API guarantee.

---

## 3. Terraform image requirement: ID, not name

`hcloud_server` takes the image via its `image` argument — "Name or ID of the image the server is created from" ([Terraform `hcloud_server`](https://registry.terraform.io/providers/hetznercloud/hcloud/latest/docs/resources/server)). But because a **snapshot has no `name`** (§2), the "name" half of that contract doesn't apply to our image — you must reference the snapshot by its **numeric ID**.

The provider's own "Server creation from snapshot" example does exactly this ([Terraform `hcloud_server`, "Server creation from snapshot"](https://registry.terraform.io/providers/hetznercloud/hcloud/latest/docs/resources/server)):

```hcl
# Look up the snapshot by label selector (or by id), get its numeric id
data "hcloud_image" "snapshot" {
  with_selector = "os=openbsd"
  most_recent   = true
}

resource "hcloud_server" "kyriakon" {
  name        = "kyriakon"
  image       = data.hcloud_image.snapshot.id   # ← numeric id, NOT the description
  server_type = "cx32"
  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }
}
```

`data "hcloud_image"` lookup filters ([Terraform `hcloud_image` data source](https://registry.terraform.io/providers/hetznercloud/hcloud/latest/docs/data-sources/image)):

- `id` — the numeric ID returned by `create-image`.
- `with_selector` + `most_recent` — label-selector lookup (pair with the `--label` you set at snapshot time, §2); `most_recent` picks the newest matching image, which is the natural way to always grab the freshest snapshot.
- `with_architecture` — recommended (`x86`/`arm`); the data source doc explicitly says to always provide it.
- Read-only `type` reports `snapshot`/`backup`/`system`, and `description` carries the text you set.

Practical consequence for the repo: pin by label selector + `most_recent` (auto-tracks re-snapshots) or by explicit ID (auditable, deterministic); avoid hardcoding a `description` string, since descriptions aren't a lookup key.

**Disk-size constraint:** a server must not be created from a snapshot with a primary disk larger than the target `server_type`'s disk. Keep the throwaway VPS's disk ≤ the production type's disk, or provision the snapshot source at the production size (`primary_disk_size` is an exported attribute of `hcloud_server`).

---

## 4. Patch-cadence caveat (§6.10)

§6.10 is explicit: Dovecot **and rspamd** ship as OpenBSD *packages*, whose patch cadence is independent of `syspatch` (base), and rspamd "parses untrusted inbound email at scale and is the box's largest mail attack surface." The snapshot approach interacts with this in one dangerous way:

> **Reprovisioning from an old snapshot silently reintroduces a vulnerable package version.** A snapshot is a frozen disk image; it captures whatever `pkg_add` version of Dovecot/rspamd and whatever base revision existed at snapshot time. A server rebuilt from a six-month-old snapshot boots with six-month-old packages, including any CVE patched in the interim — with no warning.

Mitigations to bake into the runbook/`provision.sh` (this is the "worth a line in `provision.sh`" §6.10 asks for):

1. **Re-snapshot after every patch cycle.** Treat the snapshot as mutable gold: `syspatch` + `pkg_add -u` on a live box, verify, cleanly shut down, `create-image` a new snapshot, rotate the label selector/Terraform reference to it. Never leave the snapshot to drift.
2. **Patch-on-provision.** When Terraform creates a server from a snapshot, the first provisioning step must be `syspatch` and `pkg_add -u` *before* the box serves mail (ideally before it's reachable — the [privacy-fish](https://github.com/privacy-fish/hetzner-cloud-automated-openbsd-x86-installation) script does exactly this by patching `sshd` inside QEMU before exposing the box). This bounds the window where a fresh box runs stale binaries even if the snapshot is slightly behind.
3. **Track package versions separately from base.** Base updates come from `syspatch`/`sysupgrade`; package updates from `pkg_add -u`. §6.10 (resolved) also fixes the base cadence: OpenBSD releases every 6 months, each supported ~1 year, `sysupgrade` on a stated cadence. Record both in the runbook so a snapshot's age can be audited against both cadences.

The concrete failure mode to design against: a warm-standby VPS (§6.11 layer 4) built from the snapshot and started during an incident must not come up with vulnerable rspamd parsing live mail. The "tested restore" discipline in §5.5 is the same discipline applied to the image: prove the snapshot boots *and* is current before it's needed.

---

## 5. Community "openbsd-hetzner" scripts — audit notes

Per §6.1, "audit before writing anything from scratch … not trusted uncritically." Three primary sources found:

| Source | Method | Verdict for kyriakon |
|---|---|---|
| [Cambus, "OpenBSD/arm64 on Hetzner Cloud"](https://www.cambus.net/openbsd-arm64-on-hetzner-cloud/) | Rescue → `dd` miniroot → reboot → interactive install | **Trust.** OpenBSD developer; method is just the official installer applied to Hetzner. This is the manual-install baseline (§1). |
| [grosu.nl, "Running OpenBSD on a Hetzner.de server"](https://grosu.nl/openbsd-hetzner.html) | `qemu-system-x86_64` with `/dev/sda` as `-hda`, serial console, custom `boot.conf` (`set tty com0`) | **Legacy / dedicated-only.** Needed because Hetzner *dedicated* (robot) boxes have no VNC console. Unnecessary for Cloud VPS (which has a VNC console); the serial-console and `hostname.em0`→`re0` bits don't apply to Cloud virtio. Skip for kyriakon. |
| [privacy-fish, "hetzner-cloud-automated-openbsd-x86-installation"](https://github.com/privacy-fish/hetzner-cloud-automated-openbsd-x86-installation) | Rescue → flash miniroot → boot installer **inside QEMU**, drive it with an **autoinstall response file** (`install.conf`) + `expect` over serial; `site/install.site` + `post-install.sh` do post-install (incl. `syspatch` ×2 before exposure) | **Well-built but the wrong tool for this ticket.** It's a full autoinstall-response-file pipeline — exactly the spike §6.1 explicitly deferred ("snapshot-first, no autoinstall spike"). Two techniques worth stealing regardless: (a) patching (`syspatch`) before the box is network-exposed, and (b) verifying downloads with `signify` (it does both). Audit it when/if the autoinstall route is ever revisited. |

Net: no community script is needed for the chosen manual path. The Cambus method (§1) is the manual install; the community scripts are either legacy (grosu) or solve the deferred autoinstall problem (privacy-fish).

---

## Sources

- [OpenBSD FAQ 4 — Installation Guide](https://www.openbsd.org/faq/faq4.html) (ramdisk boot model, install/miniroot image variants, `signify` verification, interactive install, "Do you want disk encryption?").
- [OpenBSD FAQ 14 — softraid / disk encryption](https://www.openbsd.org/faq/faq14.html#softraid) (referenced for FDE at install time).
- [Hetzner Docs — Using Rescue (Cloud)](https://docs.hetzner.com/cloud/servers/getting-started/rescue-system/) (rescue activation, `linux64`, 60-minute window, SSH-key/password login).
- [hcloud CLI — `server enable_rescue.go`](https://github.com/hetznercloud/cli/blob/main/internal/cmd/server/enable_rescue.go) and [`server create_image.go`](https://github.com/hetznercloud/cli/blob/main/internal/cmd/server/create_image.go) (exact command syntax and flags).
- [hcloud-go — `server.go` (`CreateImage`)](https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/server.go) and [`image.go` (ImageType enum)](https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/image.go) (`POST /servers/{id}/actions/create_image`, `{description, type, labels}`).
- [Terraform `hcloud_server` resource](https://registry.terraform.io/providers/hetznercloud/hcloud/latest/docs/resources/server) (`image` = name **or** ID; "Server creation from snapshot" example).
- [Terraform `hcloud_image` data source](https://registry.terraform.io/providers/hetznercloud/hcloud/latest/docs/data-sources/image) (`name` only for `system` images; `id`/`with_selector`/`most_recent`/`with_architecture` filters; `type` values).
- [Frederic Cambus — OpenBSD/arm64 on Hetzner Cloud](https://www.cambus.net/openbsd-arm64-on-hetzner-cloud/) (rescue → `dd` miniroot → reboot → interactive install; virtio `vio0`/DHCP).
- [grosu.nl — Running OpenBSD on a Hetzner.de server](https://grosu.nl/openbsd-hetzner.html) (legacy qemu+serial method, dedicated servers).
- [privacy-fish — hetzner-cloud-automated-openbsd-x86-installation](https://github.com/privacy-fish/hetzner-cloud-automated-openbsd-x86-installation) (autoinstall-response-file pipeline; `signify` verification; patch-before-expose).
- Kyriakon project proposal `../kyriakon/docs/decisions/kyriakon-net-project-proposal.md` — §4 (no native OpenBSD image), §2 (FDE via softraid), §6.1 (snapshot-first decision), §6.10 (package vs. base patch cadence).
