# kyriakon-infra

The public infrastructure for [kyriakon.net](https://kyriakon.net): zero-access mail, static web hosting, gemini capsules, and `pass`-compatible git repositories. Principled hosting, run by Orthodox Christians.

Every non-secret piece of infrastructure config is published here on GitHub. Audit us.

Built on OpenBSD via Hetzner, with Terraform describing the box.

## Stack

| Layer | Choice |
|---|---|
| Host | Hetzner Cloud, OpenBSD |
| Mail transport | OpenSMTPD, DKIM-signed by `filter-dkimsign` |
| Mail retrieval | Dovecot over IMAP, BSD auth against the system accounts |
| Mail storage | Maildir, encrypted at ingest by `kyriakon-encrypt` |
| Anti-spam | `spamd` greylisting, with an exemption table for mail that must pass |
| Static sites | OpenBSD `httpd` |
| Site upload | `sftp` in a chroot |
| Gemini | `gmid` |
| Git and `pass` hosting | `git-shell` |
| DNS | `nsd` as a hidden primary, Hurricane Electric as secondary |
| TLS | `acme-client`, with `relayd` terminating 443 |
| Firewall | `pf` |
| Provisioning | Terraform (`hcloud`) and the `hcloud` CLI for throwaways |
| Signup service | `onboard`, a Rust FastCGI responder and a root-side drain |

## Layout

```
terraform/            hcloud provider, the live root and the restore template recipe
openbsd/              every config the box runs, plus the restore template's files
scripts/              deploys, the drain's scripts, certificates, backups, checks
onboard/              the signup service: handler, drain, store, pages
kyriakon-encrypt/     the LMTP that encrypts mail as it is delivered
dovecot-plugin/       the Dovecot storage hook that hands mail to kyriakon-encrypt
keys/                 published member mail keys
docs/                 threat model, terms, privacy, runbook; planning under docs/planning/
CONTEXT.md            the words this project uses, and what they mean here
```

## Checking a change

```sh
cd onboard && cargo test && cargo clippy --all-targets -- -D warnings
ksh scripts/self-test-all.sh          # every script's --self-test, one line each
shellcheck scripts/*.sh
```

CI runs the same checks on the crates, the scripts and the terraform, plus `cargo fmt --check`. `scripts/check-hygiene.sh` runs on the box and reports its live state: permissions, the installed scripts against the checkout, the store's ownership, the greylist pair, and the address alerts go to.

## Deploying

`docs/runbook.md` has the order. The deploys are `deploy-onboard.sh`, then `deploy-mail.sh`, then `deploy-relayd.sh`, all run by a human as root. A subset of changes is propose-only: `pf.conf` and `sshd_config` edits, and `terraform apply` or `destroy`, are drafted as a PR diff and run by hand.

## For agents

`AGENTS.md` has the orientation, the build and test commands, the code style and the never list. `CODING_STANDARDS.md` is what a reviewer enforces beyond the tooling. The repository's hooks in `.githooks/` check the commit shape, `shellcheck` and `ksh -n` on staged scripts, and refuse a push from a branch that is behind `main`.
