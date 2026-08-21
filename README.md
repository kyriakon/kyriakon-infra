# kyriakon-infra

Public infrastructure for [kyriakon.net](https://kyriakon.net) — a low-extraction, no-shell hosting
platform (mail, static/Gemini sites, `pass`-compatible git repos) running on OpenBSD via Hetzner +
Terraform.

This repo holds implementation: Terraform, OpenBSD config, and operational scripts. Decisions and
shared vocabulary that cut across repos live in the meta repo, not here — read
`../kyriakon/docs/decisions/kyriakon-net-project-proposal.md` and `../kyriakon/docs/CONTEXT.md` first.

## Layout

- `terraform/` — hcloud provider; provisions the VPS
- `openbsd/` — base-system config (`pf.conf`, `httpd.conf`, `smtpd.conf`, Dovecot, `gmid`, `nsd`)
- `scripts/` — provisioning, user add/delete, backups, abuse monitoring
- `docs/` — architecture, security, threat model; planning docs in `docs/planning/`

## For agents

See `AGENTS.md` for orientation, build/test, code style, and the "Never" list. This repo touches
live infrastructure, so a subset of changes are **propose-only**: any `pf.conf`/`sshd_config` edit
or `terraform apply`/`destroy` is drafted as a PR diff and deployed manually by a human, never run by
an agent.
