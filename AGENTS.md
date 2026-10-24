# AGENTS.md

kyriakon-infra is the public infrastructure repo for kyriakon.net — a low-extraction,
no-shell hosting platform (mail, static/gemini sites, `pass`-compatible git repos) for
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

Finalized decisions live in the meta repo, `../kyriakon/docs/decisions/`, beside the
project proposal. Check there before assuming you're missing context; it may already be
written down. This repo has no decisions directory of its own.

## Where things are

Pointers, so a search starts where the thing is.

- `onboard/`: the Rust service. `src/responder.rs` serves the web form and its pages;
  `src/capsule.rs` renders the same pages as gemtext, so a page has two renderers and a
  change to one is a change to both; `templates/*.html` are the web renderings;
  `src/transitions.rs` holds the drain's decisions; `src/bin/` holds the three
  binaries (`kyriakon-onboard-drain`, `kyriakon-onboard-tui`, `kyriakon-onboardctl`);
  `questions.toml` is the application's question list; `tests/drain.rs` is the drain's
  acceptance suite.
- `kyriakon-encrypt/`: the daemon that encrypts every saved message to the recipient's
  key; `src/lib.rs` builds the PGP/MIME wrapper.
- `dovecot-plugin/`: the C plugin that calls the encryptor on the save path.
- `keys/`: the published public keys, one `<localpart>.asc` per member: the audit
  surface. `scripts/publish-mail-key.sh` writes one, `scripts/rekey-mail-key.sh`
  rewrites one without the AEAD advert.
- `scripts/`: every deploy and operator script, each with a `--self-test`; `lib.sh`
  holds the shared helpers and the self-test harness.
- `openbsd/`: what the box runs: `etc/` (smtpd, httpd, relayd, gmid, unbound, nsd,
  spamd, sshd, `login.conf.d/`, `rc.d/`, `kyriakon.env`, and the three onboarding
  configs (`catalogue.toml`, `drain.toml`, `onboard.toml`) under `etc/onboard/`), `dovecot/`, and `restore-template/` for the throwaway box.
- `terraform/`: the box itself, and the throwaway's stack.
- `docs/`: `runbook.md` (every operator procedure, including the repository settings
  the automation depends on), `operations/`, `threat-model.md`, `terms.md`,
  `privacy.md`, `aup.md`, `transparency.md`, `refusals.md`, `planning/` (specs,
  research, prototypes), `agents/` (issue tracker, triage labels, domain docs).
- `.github/workflows/`: `checks.yml` (the four CI jobs) and `auto-merge-key.yml` (a
  green key publication merges itself, as the machine account).
- `.githooks/`: commit shape, pre-commit, pre-push.
- Root: `reserved-usernames.txt` (the held-back names), `CONTEXT.md` (repo vocabulary),
  `CODING_STANDARDS.md` (what a review enforces), `README.md`.

## Shared vocabulary

Cross-cutting glossary: `../kyriakon/docs/CONTEXT.md` (shell-less user, pricing tiers,
dogfooding, audit us). Repo-local terms specific to infra work: `CONTEXT.md` at this
repo's own root. Two terms most likely to matter while working in this repo:

- **Shell-less user**: the standard account tier. No interactive shell — mail via
  IMAP/SMTP, static/gemini hosting via `sftp` upload, `pass` repos via `git-shell`.
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
- Rust: `cargo test --manifest-path onboard/Cargo.toml` and
  `cargo clippy --manifest-path onboard/Cargo.toml --all-targets -- -D warnings`; the
  same for `kyriakon-encrypt/`. There is no workspace root, so a command without
  `--manifest-path`, run from the repository root, does not find `Cargo.toml` at all.
  `cargo fmt --check` runs in CI.
- Shell scripts (`scripts/`): `shellcheck scripts/*.sh`, and
  `ksh scripts/self-test-all.sh` runs every script's `--self-test` with the arguments
  each one needs. On the box, `ksh scripts/check-hygiene.sh` reports its live state.
- OpenBSD config syntax checks require an actual OpenBSD host and are not run in CI —
  e.g. `httpd -n -f openbsd/etc/httpd.conf`, `smtpd -n -f openbsd/etc/smtpd.conf`. If
  you don't have access to a test OpenBSD instance, say so rather than claiming a
  config is valid.
- No build step for `docs/` — markdown only.

## Code style

- `CODING_STANDARDS.md` is what a reviewer enforces beyond the tooling: tests that
  assert behaviour, the drain's transitions, and the shell-script failure shapes.
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

Tickets live in GitHub Issues. Work only on the ticket you were given for the
current session. **When the user asks you to pick the next task, use the Ready
queue query in `docs/agents/issue-tracker.md` and take one unblocked ticket;
otherwise do not browse the issue tracker, list open issues, or self-select
work.** If a task doesn't map to an existing ticket, ask before creating one;
don't create tickets speculatively.

When a PR is the last code change a ticket needs, its body says `Closes #<n>` so
the merge closes the issue. If the ticket also has a manual deploy, name that
step in the PR body; it is the operator's, and the merge still closes the issue.

```
gh issue view <number>
gh issue create --title "..." --body-file <path> --label <label>   # only when asked
```

Issues generated from a spec include a `Spec:` line pointing to the corresponding file
in `docs/planning/specs/`. Read that file before starting non-trivial ticket work — the
issue body alone is a summary, not the full context.

## Git

- Conventional commits, with scope: `type(scope): description`, for example
  `feat(mail): add DKIM key rotation script` or `fix(terraform): correct hcloud image
  reference`. Types: `feat`, `fix`, `chore`, `docs`, `test`. The scope is the area
  touched; in use are `onboard`, `web`, `scripts`, `mail`, `ssh`, `pf`, `relayd`,
  `hosting`, `gemini`, `terraform`, `ci`, `docs`, `specs`, `research`. The shape is
  enforced by `.githooks/commit-msg`; the scope is a judgement call.
- Enable the repository's hooks once per clone: `git config core.hooksPath .githooks`.
  They check the commit shape, run `shellcheck` and `ksh -n` on staged scripts and
  `cargo fmt --check` when Rust is staged, and refuse a push from a branch that is
  behind `main`, because a branch cut before a merge squashes to a commit that silently
  reverts it.
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
- Never edit the meta repo's ADRs (`../kyriakon/docs/decisions/*.md`) as a side effect
  of an unrelated task. They record decisions, not implementation notes, and changes
  need explicit human review.

## Agent skills

### Issue tracker

Issues live in GitHub Issues, driven via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage labels, strings equal to their names: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context. ADRs live in the meta repo at `../kyriakon/docs/decisions/`, shared vocabulary in `CONTEXT.md`. See `docs/agents/domain.md`.
