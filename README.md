# kyriakon-infra

The public infrastructure for [kyriakon.net](https://kyriakon.net) - secure email, static web hosting, and `pass` repositories. Principled hosting, run by Orthodox Christians.

Every non-secret piece of infrastructure config is published here on GitHub. **Audit us.**

Built on OpenBSD via Hetzner + Terraform.

## Stack

| Layer | Choice |
|-------|--------|
| Host | Hetzner VPS, OpenBSD |
| Mail transport | OpenSMTPD |
| Mail retrieval | Dovecot (IMAP) |
| Mail storage | Maildir, zero-access |
| Anti-spam | `spamd` + rspamd |
| Static sites | OpenBSD `httpd` |
| Site upload | `sftp` chroot |
| Gemini | `gmid` |
| Git / `pass` hosting | `git-shell` |
| DNS | `nsd` (hidden primary) + Hurricane Electric secondary |
| Firewall | `pf` |
| Provisioning | Terraform (`hcloud`) |

## Layout

```
terraform/              hcloud provider - provisions the VPS
openbsd/etc/            pf.conf, httpd.conf, smtpd.conf, sshd_config
openbsd/dovecot/        Dovecot config
scripts/                provisioning, add/del user, backup, abuse monitoring
docs/                   threat-model, AUP; planning under docs/planning/
dovecot-plugin/         zero-access mail encryption at ingress
kyriakon-encrypt/       mail encryption tooling
reserved-usernames.txt  reserved signup names
```

## For agents

See [`AGENTS.md`](AGENTS.md) for orientation, build/test, code style, and the "Never"
list. This repo touches live infrastructure, so a subset of changes are **propose-only**:
any `pf.conf`/`sshd_config` edit or `terraform apply`/`destroy` is drafted as a PR diff and
deployed manually by a human - never run by an agent.
