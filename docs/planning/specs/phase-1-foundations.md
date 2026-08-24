# Phase 1 — Foundations

> Spec synthesised from the [Phase 1 wayfinder map](https://github.com/kyriakon/kyriakon-infra/issues/1) (tickets #2–#10) and the project proposal (`../kyriakon/docs/decisions/kyriakon-net-project-proposal.md`). Working material — this file lives in `docs/planning/specs/` until its tickets close.

## Problem Statement

Kyriakon.net has no running infrastructure yet. Oliver needs to stand up the first box — his own email running on OpenBSD, stored so the platform itself cannot read it, backed up and provably restorable, and monitored — before any other user's mail touches it. The entire non-secret configuration must be published publicly from the start, so the platform's "audit us" promise is verifiable rather than asserted.

## Solution

A single OpenBSD VPS on Hetzner, provisioned from a snapshot, running the zero-access mail stack (OpenSMTPD + Dovecot + Maildir, PGP-encrypted on ingress to client-held keys), authoritative DNS via `nsd` + Hurricane Electric secondary, nightly encrypted restic backups with a tested restore procedure, and automated abuse + health monitoring. A drafted acceptable-use policy and the public `kyriakon-infra` repo complete the phase. Everything is dogfooded on Oliver's own address first.

## User Stories

### Provisioning

1. As an operator, I want to install OpenBSD on a Hetzner VPS through the rescue system, so that the box runs the platform's chosen OS despite Hetzner lacking a native OpenBSD image.
2. As an operator, I want full-disk `softraid` encryption chosen at install time, so that a walked-away disk reveals no data.
3. As an operator, I want to verify the OpenBSD install image with `signify` before trusting it, so that a substituted image can't silently compromise the box from first boot.
4. As an operator, I want to snapshot the configured box via the Hetzner API, so that future boxes are reproducibly provisioned from that image.
5. As an operator, I want Terraform to describe the box, so that provisioning is auditable and repeatable rather than hand-typed.
6. As an operator, I want the box patched (`syspatch` + `pkg_add -u`) on provision before it serves traffic, so that a slightly stale snapshot never boots a vulnerable package.
7. As an operator, I want the snapshot re-taken after each patch cycle, so that reprovisioning can't silently reintroduce a patched-out vulnerability.

### Zero-access mail

8. As a dogfooding mail user, I want incoming mail delivered to my mailbox, so that I can receive email on `oliver@kyriakon.net`.
9. As a dogfooding mail user, I want my incoming mail encrypted on delivery to my PGP public key, so that the server stores only ciphertext it cannot decrypt.
10. As a dogfooding mail user, I want mail I upload or draft (IMAP APPEND) encrypted the same way, so that every stored message — not just delivered ones — is ciphertext.
11. As a dogfooding mail user, I want to read my mail with a PGP-capable client that decrypts with my client-held key, so that mail is usable end-to-end without the server ever holding the private key.
12. As a dogfooding mail user, I want plus-addressing (`oliver+tag@kyriakon.net`) to work, so that I can filter mail by tag without breaking encryption.
13. As a dogfooding mail user, I want a recovery phrase that restores my mail key if I lose a device, so that key loss is not silently permanent.
14. As an auditor, I want the server's public keyring to be the git-tracked published set, so that key substitution is detectable by reviewing the repo.
15. As an operator, I want delivery to fail closed when a recipient has no key, so that plaintext mail is never written to disk.
16. As an operator, I want the transient SMTP spool encrypted, so that the one residual plaintext window is defense-in-depth closed and documented.
17. As a dogfooding mail user, I want obvious spam classified away from my inbox, so that raw spam volume doesn't drown real mail.

### DNS

18. As an operator, I want `nsd` to serve the `kyriakon.net` zone as a hidden primary, so that the zone is git-auditable and the answering service isn't a direct probe target.
19. As an operator, I want Hurricane Electric to serve as the public secondary via AXFR/NOTIFY, so that DNS resolution survives a box outage.
20. As an operator, I want MX, SPF, DKIM, and DMARC records published before mail goes live, so that mail is deliverable from the first send.
21. As an operator, I want a wildcard `*.kyriakon.net` record, so that per-user subdomains resolve without a DNS write per signup.
22. As an operator, I want the mail IP's PTR record set to match its forward name, so that mail isn't flagged for a missing reverse record.
23. As an operator, I want the assigned IP checked against reputation lists before the first send, so that I don't commit to a pre-blocked address.

### Backup & restore

24. As an operator, I want nightly encrypted backups of mail, git repos, and web roots to a separate Hetzner storage box, so that a primary loss doesn't lose user data.
25. As an operator, I want the backup decryption key held offline, so that a dead primary doesn't make its own backups undecryptable.
26. As an operator, I want a weekly automated restore test that actually restores and verifies data, so that a green backup job isn't mistaken for a working recovery.
27. As an operator, I want the restore test to assert the restored Maildir is still PGP ciphertext, so that a plaintext-mail regression is caught in the backup path too.
28. As an operator, I want a quarterly full-dress rehearsal that rebuilds a working mail server from backup, so that "restorable" is proven against a real incident, not assumed.
29. As an operator, I want the quarterly rehearsal reminder-scheduled and scripted as far as possible, so that it actually happens on schedule with minimal manual effort.

### Monitoring

30. As an operator, I want automated alerts for sudden outbound mail-volume spikes, so that a compromised account relaying spam is caught early.
31. As an operator, I want alerts for repeated SMTP/IMAP/SSH authentication failures, so that credential-stuffing attempts are visible.
32. As an operator, I want alerts when a user approaches their storage quota, so that disk exhaustion is caught before it takes the box down.
33. As an operator, I want alerts when the box's IP appears on a reputation blocklist, so that deliverability problems are caught early.
34. As an operator, I want a dead-man's-switch heartbeat on an external service, so that the box going silent alerts me even when the box itself is compromised.
35. As an operator, I want content-rich alerts on a channel that doesn't depend on the box, so that "the box is compromised and relaying" is still reported reliably.

### Governance

36. As an operator, I want a drafted acceptable-use policy covering mail abuse, published content, resource use, account security, and enforcement, so that the governance stance exists before the first real user.
37. As an operator, I want the AUP to state a graduated, uniformly-applied enforcement ladder, so that abuse is acted on consistently even against known contacts.
38. As an operator, I want account sharing permitted via a shared `pass` repo, so that legitimate shared accounts don't need to share raw credentials.

### Public repo

39. As an auditor, I want the entire non-secret configuration published on GitHub, so that I can verify how the platform is run rather than trusting its claims.
40. As an auditor, I want no secrets, key material, or user data in any tracked file, so that the published repo can't leak a real key.
41. As an operator, I want host-specific values behind variables rather than hardcoded, so that nothing host-identifying leaks into the public repo.

## Implementation Decisions

- **Provisioning** is snapshot-first (§6.1): rescue-mode `dd` of the OpenBSD ramdisk, interactive install over the VNC console with `softraid` FDE, then `create-image --type snapshot`. Terraform references the snapshot by numeric image ID (snapshots have no `name`); `data.hcloud_image` with `most_recent` tracks re-snapshots. No autoinstall-response-file spike.
- **Zero-access mail** is one encryption point: a custom Dovecot lib-storage save-path plugin, covering both LMTP delivery and IMAP APPEND. SMTP stays plaintext across the local LMTP hop. The ciphertext format is whole-message RFC 3156 PGP/MIME (headers + body encrypted).
- **Account model**: mail authentication is via real OpenBSD system accounts — `useradd` with the shell forced to `/sbin/nologin`, home holding the Maildir; Dovecot and OpenSMTPD authenticate against them via PAM (the nologin shell blocks interactive sessions without affecting PAM, since PAM doesn't consult the shell field). This is the shell-less-user property — no standard account gets an interactive shell. The dogfood account is created manually or via `add-user.sh`; the onboarding service that automates this is Phase 3, not here.
- **Language split**: the Dovecot plugin is a minimal C shim (~100 lines — hook registration + `save_begin`/`save_finish` override + pipe), because Dovecot's plugin ABI is C and has no Rust interface. All authored logic lives in a Rust encryptor daemon; the OpenPGP engine is GnuPG. This encodes the standing preference "always prefer Rust over C for code authored in this project." From the prototype (`docs/planning/zero-access-mail-pipeline.md`):

  ```
  SMTP (smtpd) ──LMTP unix socket──▶ Dovecot ──save path──▶ [C shim → kyriakon-encrypt → gpg] ──▶ Maildir (ciphertext)
                                     ▲
                         IMAP APPEND ┘  (same save path, same shim + encryptor)
  ```

- **Encryptor process model**: `kyriakon-encrypt` runs as a long-lived daemon on a unix socket; the C shim talks to it over the socket (no subprocess per save).
- **Keyring**: the git-tracked published key set in `kyriakon-infra` is the single source of truth (auditable per §5.6); the on-box keyring is a read-only sync of it, refreshed on the provisioning/reload step. Resolution strips `+tag` and maps base-localpart → public cert.
- **Invariants**: no private key ever on the server; no plaintext at rest (transient spool closed by `queue encryption`, residual window documented in `threat-model.md`); fail-closed on missing key (never write plaintext); one encryption point (no double-encryption).
- **DNS**: `nsd` hidden primary (`notify:`/`provide-xfr:` to Hurricane Electric's transfer IPs, NOKEY/IP-ACL — HE's AXFR source IPs are pinned at signup, never `0.0.0.0/0`), HE free secondary via AXFR/NOTIFY, TCP/53 from HE allowed in `pf`. Record set: MX 10, SPF `v=spf1 mx -all`, DKIM at `mail._domainkey` (private key on-box, excluded from repo), DMARC `p=none` + `rua=`, wildcard `*` A/AAAA (a record, not a cert). PTR set at Hetzner, not in the zone.
- **Backup**: restic over the SFTP backend to the Hetzner storage box, a single offline repository password (password = key, no keyfile). Retention via `forget --keep-*` (the retention window is the purge mechanism — targeted purge isn't possible in a content-addressed repo).
- **Restore testing**: a weekly automated full `restore` on a separate read-only machine (snapshot-recency → `check` → `restore` → verify canary byte-identical + Maildir-is-PGP-ciphertext + `git fsck` + `stats` count → Healthchecks ping), plus a quarterly full-dress rehearsal (reminder-scheduled, scripted as far as possible) that rebuilds a working mail server.
- **Abuse & health monitoring**: cron scripts watching outbound-mail spikes, auth-failure counts, quota approach, spamd greylist/blocklist changes, and the IP's blocklist status. Healthchecks.io carries the heartbeat/dead-man's switch only; content-rich alerts go to Oliver's personal external channel.
- **AUP**: five sections (mail abuse · published content · resource use with the 5 GB quota · account security with `pass`-repo sharing · enforcement), with a graduated, uniformly-applied ladder (detect → warn → suspend → 40-day-grace admin-mediated delete). Content floor = illegal/pornographic/gambling. The content-philosophy fork (open vs Orthodox-purpose hosting) is explicitly **not** decided here — it's a Phase 3 decision (see Out of Scope).
- **Dogfood exit condition**: 2 weeks of real use as primary mail, the zero-access checklist passing, SPF/DKIM/DMARC passing with inbox placement to an external mailbox, and zero open P1/P2 mail-path issues.

## Testing Decisions

**Seam.** The one place with authored logic is the `kyriakon-encrypt` daemon — its stdin→stdout interface (RFC 5322 message in, RFC 3156 PGP/MIME ciphertext out) plus its keyring directory is the single test seam. Shell scripts are tested at their CLI; config files are syntax-checked on an OpenBSD host only (not CI).

- **What makes a good test here**: exercise observable behavior only — given a message and a keyring, the daemon emits RFC 3156 ciphertext; given a missing key, it fails closed; given a `+tag` recipient, it resolves the base localpart. Never test internal parse steps or gpg invocation flags.
- **Modules tested**: the `kyriakon-encrypt` daemon (encryption, keyring resolution, tag stripping, fail-closed), and the shell scripts via their CLI (`provision`, `add-user`, `del-user`, `backup`, `abuse-monitor`).
- **Prior art**: none — this repo has no test suite yet; these are the first tests. OpenBSD config syntax checks (`httpd -n`, `smtpd -n`, `nsd-checkconf`, `doveconf -n`) are manual, run on a real OpenBSD host, not in CI.

## Out of Scope

- **Phase 2** — static/Gemini/git hosting.
- **Phase 3** — the onboarding service + account portal, reserved-name enforcement, AUP finalization, and the **hosting content-philosophy fork** (open vs Orthodox-purpose membership), which is gated on external guidance and re-charted as a Phase 3 decision.
- SSH TUI signup, CGI, own-domain tier, secondary MX, warm-standby VPS — all fast-follow or deferred.
- The guardrails "propose-only" tier for host changes — lives in the `omp-extensions` marketplace repo, not here.

## Further Notes

- **Propose-only discipline**: anything touching `pf.conf`, `sshd_config`, or running `terraform apply`/`destroy` is drafted as a diff with the live-affecting command left as a documented manual step — never run by an agent.
- **Secrets**: no DKIM private key, TLS key, API token, or user data in any tracked file, even as a placeholder example; fake values use `REPLACE_ME`/`example.invalid`.
- **Package cadence**: Dovecot and rspamd are OpenBSD packages with a patch cadence independent of base; snapshot re-taking and patch-on-provision are the controls.
- **Abuse-monitor thresholds** are deliberately not fixed here — they are tuned during dogfood, before real users generate false-positive noise.
- **Standing preference**: always prefer Rust over C for authored code (also to be recorded in `AGENTS.md`).
