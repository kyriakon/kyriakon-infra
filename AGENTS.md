# AGENTS.md

kyriakon-infra is the public infrastructure repo for kyriakon.net — a low-extraction,
no-shell hosting platform (mail, static/Gemini sites, `pass`-compatible git repos) for
the Orthodox Christian community, running on OpenBSD via Hetzner + Terraform.

## Orientation

**This repo is one of several `kyriakon-*` repos, cloned as siblings.** The founding
project proposal and cross-cutting shared vocabulary live in the meta repo, not here:
read `../kyriakon/docs/decisions/kyriakon-net-project-proposal.md` and
`../kyriakon/docs/CONTEXT.md` first for anything beyond a small, well-scoped change.
If `../kyriakon` isn't present alongside this repo, say so rather than proceeding
without that context — don't guess at proposal content from memory.

Any research/spec working docs specific to this repo live under `docs/planning/`. Read
`docs/planning/README.md` for infra-repo-local planning context.

Finalized decisions specific to this repo (not cross-cutting ones — those are ADRs in
the meta repo) live under `docs/decisions/` — check there before assuming you're
missing context; it may already be written down.

## Shared vocabulary

Cross-cutting glossary: `../kyriakon/docs/CONTEXT.md` (shell-less user, pricing tiers,
dogfooding, audit us). Repo-local terms specific to infra work: `CONTEXT.md` at this
repo's own root. Two terms most likely to matter while working in this repo:

- **Shell-less user**: the standard account tier. No interactive shell — mail via
  IMAP/SMTP, static/Gemini hosting via `ftpd` upload, `pass` repos via `git-shell`.
  This is the whole platform's core safety property; don't propose or scaffold
  anything that grants a standard-tier user an interactive shell.
- **Propose-only change**: any change that touches `pf.conf`, `sshd_config`, or would
  run `terraform apply`/`terraform destroy` against the live box. These are drafted as
  a PR diff with the actual live-affecting command left as a documented manual step —
  never run by an agent, even inside an otherwise-trusted session.

## Build & test

- Terraform: `terraform fmt -check -recursive` / `terraform validate` — run from
  `terraform/`. **`terraform plan` is fine to run; `terraform apply` and
  `terraform destroy` are never run by an agent** (see "Never" below).
- Shell scripts (`scripts/`): `shellcheck scripts/*.sh`
- OpenBSD config syntax checks require an actual OpenBSD host and are not run in CI —
  e.g. `httpd -n -f openbsd/etc/httpd.conf`, `smtpd -n -f openbsd/etc/smtpd.conf`. If
  you don't have access to a test OpenBSD instance, say so rather than claiming a
  config is valid.
- No build step for `docs/` — markdown only.

## Code style

- Terraform: `terraform fmt` is the source of truth for formatting. Resource and
  variable names in `snake_case`. Every variable needs a `description`.
- Shell scripts: `set -euo pipefail` at the top of every script; `shellcheck`-clean is
  the bar, not a suggestion.
- Config files (`openbsd/etc/*`, Dovecot, `gmid.conf`): every non-obvious setting gets
  a comment explaining *why*, not just what — this repo is public specifically so
  people can audit it, and an unexplained setting defeats that purpose.
- **No secrets, ever, in any tracked file** — not real, not as a "realistic example."
  Use obviously-fake placeholders (`REPLACE_ME`, `example.invalid`) if a sample value
  is needed for illustration.
- Push anything host-specific (real hostnames, real IPs, real domain-validation
  tokens) behind a Terraform variable rather than hardcoding it, even though this
  repo currently serves one box — it costs nothing now and avoids a leak later.

## Tickets

Tickets live in GitHub Issues. **Work only on the ticket explicitly given to you for
the current session — do not browse the issue tracker, list open issues, or self-select
work.** If a task doesn't map to an existing ticket, ask before creating one; don't
create tickets speculatively.

```
gh issue view <number>
gh issue create --title "..." --body-file <path> --label <label>   # only when asked
```

Issues generated from a spec include a `Spec:` line pointing to the corresponding file
in `docs/planning/specs/`. Read that file before starting non-trivial ticket work — the
issue body alone is a summary, not the full context.

## Git

- Conventional commits, with scope: `type(scope): description` — e.g.
  `feat(mail): add DKIM key rotation script`, `fix(terraform): correct hcloud image
  reference`. Types: `feat`, `fix`, `chore`, `docs`, `test`. Scope is the area touched
  (`terraform`, `mail`, `static`, `gemini`, `git-hosting`, `ci`, `docs`).
- Never force-push to `main`. Never rewrite shared history without explicit human
  sign-off.
- Squash merge only.

## Never

- **Never run `terraform apply` or `terraform destroy` against the live workspace.**
  These are human-run steps, executed only as the final approved step of an
  already-reviewed PR — see "Propose-only change" above.
- **Never write real secrets, key material, or user data into any tracked file** —
  DKIM private keys, TLS keys, API tokens, real user mailboxes/paths. This applies
  even to files meant to stay gitignored; don't write real values there either.
- **Never modify `pf.conf` or `sshd_config` directly.** Propose a diff in a PR; the
  human reviews it line-by-line and deploys it manually. These files are also
  blocked at the tool level via the `guardrails` extension — if a block fires here,
  that's working as intended, not a bug to route around.
- **Never `scp`, `rsync`, or otherwise push a config file to the live box.** All
  deployment to the live host is a manual, human-run step.
- Never edit `docs/decisions/*.md` (ADRs) as a side effect of an unrelated task —
  these record decisions, not implementation notes, and changes need explicit human
  review.

## Agent skills

### Issue tracker

Issues live in GitHub Issues, driven via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage labels, strings equal to their names: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context. ADRs live in `docs/decisions/`, shared vocabulary in `CONTEXT.md`. See `docs/agents/domain.md`.
