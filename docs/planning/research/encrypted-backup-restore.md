# Encrypted nightly backup + tested restore (Phase 1, §5.5)

**Question:** pick the encryption layer for nightly backups (Maildir + git repos + web roots)
from the OpenBSD box to a separate Hetzner storage box, with the backup-decryption key held
offline (§5.5), and a schedulable restore-test that runs against the storage box *without*
touching the live box.

**Answer:** **restic**, writing over the **SFTP backend** to the storage box, with a single
repository password held offline. Restore-test is a weekly cron job on a *separate* machine
that does a real `restic restore` from the storage box and verifies the output, plus a
quarterly full-dress rebuild.

---

## 1. What the backup must actually protect

The payload is not uniformly sensitive. Per §2/§5.1, Maildir is already **zero-access** —
whole-message PGP/MIME ciphertext the platform cannot decrypt — and `pass` git stores are
GPG-encrypted client-side. So the backup-encryption layer's *marginal* job is protecting:

- **web roots** (`www/` + `gemini/`) — plaintext user content (§5.2);
- **git repo structure** — commit messages, `authorized_keys`, repo names, even though
  `pass` store *contents* are already ciphertext (§5.3);
- **mail metadata** — envelope sender/recipient, timestamps, sizes, Dovecot indexes — which
  §2 explicitly says zero-access does **not** protect.

So encrypted backup is not redundant with zero-access; it is the layer that turns a
walked-away storage box into "ciphertext + no key," exactly the second, weaker layer §2
describes.

## 2. Primary sources consulted

- OpenBSD ports tree (official GitHub mirror): `sysutils/restic`
  [Makefile](https://raw.githubusercontent.com/openbsd/ports/master/sysutils/restic/Makefile)
  (v0.19.1); `sysutils/borgbackup`
  [1.4](https://raw.githubusercontent.com/openbsd/ports/master/sysutils/borgbackup/1.4/Makefile)
  (1.4.5) and
  [2.0](https://raw.githubusercontent.com/openbsd/ports/master/sysutils/borgbackup/2.0/Makefile)
  (2.0.0b23, beta); `sysutils/duplicity`
  [Makefile](https://raw.githubusercontent.com/openbsd/ports/master/sysutils/duplicity/Makefile)
  (3.0.6).
- restic docs (source of truth in-tree): [design.rst](https://github.com/restic/restic/blob/master/doc/design.rst)
  (encryption, pack/repo format), [030_preparing_a_new_repo.rst](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst)
  (password-as-key, SFTP backend), [050_restore.rst](https://github.com/restic/restic/blob/master/doc/050_restore.rst)
  (`restore`, `--target`, `--include`/`--exclude`, `--dry-run`).
- borg docs: [borg init](https://borgbackup.readthedocs.io/en/stable/usage/init.html)
  (encryption modes), [security internals](https://borgbackup.readthedocs.io/en/stable/internals/security.html)
  (AES-256-CTR + HMAC-SHA256, encrypt-then-MAC, TAM manifest auth).
- Hetzner: [Storage Box — SSH/rsync/BorgBackup access](https://docs.hetzner.com/storage/storage-box/access/access-ssh-rsync-borg/)
  (port 23 SSH service, borg versions, restic SFTP support, rsync caveat).

## 3. Tool comparison

| Axis | **restic** | **borg** | **duplicity** | softraid/encrypted-loop |
|---|---|---|---|---|
| OpenBSD 7.x ports | yes, v0.19.1 (Go, BSD) | yes, 1.4.5 stable / 2.0b23 beta (Python + zstd + xxhash) | yes, 3.0.6 (Python + gnupg + librsync + py-paramiko) | base (FDE only) |
| Encryption | AES-256-CTR + Poly1305-AES, per-file IV | AES-256-CTR + HMAC-SHA256 (or BLAKE2b), encrypt-then-MAC | GnuPG (asymmetric) | AES-XTS FDE |
| Offline key custody | **one password = the key** (KDF); no keyfile | repokey (passphrase; key blob in repo) or keyfile (key + passphrase, key must be exported) | GPG private key (decrypt-only) + public key on box (encrypt-only) | passphrase |
| Write key == read key | **yes (symmetric)** | yes (symmetric) | **no (asymmetric)** | n/a |
| Incremental model | content-defined dedup + zstd (repo v2) | content-defined dedup | full + incremental **chains** | block device (no per-file dedup) |
| Storage-box support | SFTP backend (Hetzner: "natively supported") | native `borg serve` via port 23 (`--remote-path=borg-1.4`) | rsync target | no (local block device only) |
| Restore from any machine | `restic restore` + password | `borg extract` + keyfile + passphrase | walk GPG+incremental chain | mount loop + rsync out |

### Encryption-layer notes, from source

- **restic** encrypts every file `IV || CIPHERTEXT || MAC` with AES-256-CTR and a
  Poly1305-AES MAC, a fresh random IV per file (design.rst). Access is gated by "a password
  (also called a key)"; the docs are explicit that "knowledge of your password is required
  to access the repository. Losing your password means that your data is irrecoverably
  lost" (030_preparing_a_new_repo.rst). There is **no separate keyfile** — offline custody
  is *just* one secret.
- **borg** uses AES-256-CTR in an encrypt-then-MAC construction (HMAC-SHA256, or keyed
  BLAKE2b in `*-blake2` modes) and anchors the manifest with a TAM key derived via
  HKDF-SHA-512 (security internals). It has two custody models: `repokey` (key blob stored
  in the repo, encrypted by passphrase — passphrase is the offline secret) and `keyfile`
  (key in `~/.config/borg/keys`; you **must** `borg key export` an offsite copy or lose
  the data). borg always needs *both* key and passphrase.
- **duplicity** encrypts via GnuPG, so the box holds only a **public** key (encrypt-only)
  and the **private** key stays fully offline — the only option here with true
  write/read key separation.

### The custody nuance worth being explicit about

§5.5's literal wording — the decrypt key "not resident on the primary" — is *only* fully
satisfied by the asymmetric (GnuPG/duplicity) model. restic and borg are symmetric: the
credential that writes a backup is the same one that decrypts it, so an automated nightly
job necessarily has the key material present on the primary. However, the stated *reason*
for the rule — "a key stored **only** on the primary makes the backup undecryptable exactly
when the primary dies" — is satisfied by **keeping an offline copy** of the password
(which is what §5.5 actually resolves to). The storage box holds only ciphertext and no
key in every option. Given zero-access mail and the acknowledged "determined state actor"
ceiling (§5.6), a compromised primary already sees live mail; the symmetric write-key is
not a *new* exposure, and it is the price of restic/borg's far stronger incremental +
snapshot model. If Oliver later wants strict encrypt-only-on-primary, the fallback is
duplicity — flagged, not recommended, because its chain restore is fragile.

## 4. Recommendation: restic (SFTP backend)

Reasons, in order of weight:

1. **One offline secret.** restic's entire key material is a single repository password
   (030_preparing_a_new_repo.rst). §5.5's "offline copy held by Oliver" is a long random
   password in Oliver's offline store — no keyfile to export and re-verify (unlike borg
   keyfile), no GPG keyring (unlike duplicity). Simplicity *is* the security property here:
   fewer secrets to lose or get wrong.
2. **Smallest footprint on the box.** `pkg_add restic` is one Go binary with no runtime
   deps. borg pulls a Python stack + OpenSSL + zstd + xxhash; duplicity pulls Python +
   GnuPG + librsync + py-paramiko + ncftp. §6.10 already frets about *package* patch
   cadence for Dovecot/rspamd — a single static binary is the least new surface to track.
3. **Incremental efficiency.** Content-defined chunking with dedup + zstd compression
   (repo format v2 is the default, design.rst/030) is exactly right for nightly Maildir
   runs: unchanged messages dedup to zero transfer; only changed/added files move.
4. **Restore is trivial from any machine.** `restic -r sftp:… restore latest --target …`
   reads the repo straight off the storage box and needs nothing from the live box — the
   exact property the restore-test needs (§5 below). borg can do the same but needs the
   keyfile + passphrase; restic needs just the password.
5. **First-class Hetzner support.** Hetzner documents restic as "natively supported with
   the SFTP backend" (access-ssh-rsync-borg). No server-side binary to pin the way borg
   needs `--remote-path=borg-1.4`.

One caveat to record: restic's FUSE `mount` is documented as Linux/macOS/FreeBSD only
(050_restore.rst) — irrelevant here because we use `restic restore`, not `mount`.

### Backup job shape (for the record)

```
pkg_add restic
restic -r sftp:uXXXXX@uXXXXX.your-storagebox.de:./kyriakon-backup init   # once; password from offline store
# nightly (cron), key read from a mode-0600 file on the box:
restic -r sftp:… backup /home /var/www /var/gemini /var/git --password-file /root/.restic-pass
restic -r sftp:… forget --keep-daily 30 --keep-weekly 8 --keep-monthly 6 --prune
```

Retention via `forget --keep-*` bounds how long a deleted account's data survives in
backups, matching §5.5's "erased once retention lapses" (targeted purge is not surgically
possible in a content-addressed repo; the retention window *is* the purge mechanism).

## 5. Restore-test runbook (the "green backup ≠ proof" answer)

The test must prove three things a green `restic backup` does **not**: the repo is readable,
the data is **decryptable**, and the files are actually **restorable** to a working state.

**Where it runs:** a *separate* machine — cheapest is a disposable Hetzner VPS (or Oliver's
workstation) running OpenBSD + `restic`, holding **read-only** storage-box credentials (a
sub-account restricted to the repo path) and a copy of the repository password. It never
connects to the live box; the only path is test-machine ↔ storage-box over SFTP. The live
box's only role is as the backup *source*.

**Automated weekly job (cron on the test machine):**

1. `restic -r sftp:… snapshots` → assert `latest` is within the retention window (else the
   *backup* itself has silently stopped — fail loudly).
2. `restic -r sftp:… check` → verify repo structure and pack integrity (cheap).
3. `restic -r sftp:… restore latest --target /var/restore-test/$(date +%F)` → **full**
   restore to a scratch dir. This is the actual proof: it reads and decrypts every restored
   object. (Periodically replace/augment with `check --read-data-subset=…` to re-read all
   data over time.)
4. Verify the output, not just the exit code:
   - file/size count matches `restic stats latest`;
   - a known **canary file** written by the backup job restores byte-identical;
   - **zero-access assertion:** the restored Maildir must be PGP ciphertext — a script
     asserts restored `cur/` files are ASCII-armored PGP blocks, not plaintext (guards
     against a future regression that starts writing plaintext mail into the backup);
   - spot-check a web root and a git bare repo (`git fsck` on a restored repo) render.
5. `rm -rf /var/restore-test/*` and ping **Healthchecks.io** (already the platform's
   dead-man's switch, §5.8/§6.11). Success = ping; failure/silence = Healthchecks alerts.

**Quarterly full-dress rehearsal (manual, ~1h):** the weekly job proves the *repo* is
restorable, but not that a restored copy *becomes a working platform*. Rehearse it:
provision a throwaway box from the §6.1 snapshot, run the same `restic restore` into its
mail/git/web paths, start `smtpd`/Dovecot/`httpd`/`gmid`/`git-shell`, and confirm a test
message round-trips and a test `pass` repo clones. This is the step that actually discharges
"unforgivable mail loss" — the rest is detection.

**What to skip for now:** `restic check --read-data` in full every night (expensive; the
weekly `restore` already reads all restored data, so nightly full re-read is redundant),
and any multi-client concurrent-write setup (single writer = live box; the test machine is
read-only).
