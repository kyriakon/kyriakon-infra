# kyriakon-infra

Repo-local vocabulary for `kyriakon-infra` only. **Read `../kyriakon/docs/CONTEXT.md`
first** — that's the shared glossary across all `kyriakon-*` repos (shell-less user,
pricing tiers, dogfooding, audit us). This file adds only the terms specific to
infra work that don't mean anything outside this repo.

## Language

**Propose-only change**:
Any change touching `pf.conf`, `sshd_config`, or that would run `terraform
apply`/`terraform destroy` against the live box. Drafted as a PR diff only; the actual
live-affecting command is a documented manual step, run by a human, never by an agent.
_Avoid_: direct change, auto-apply

**Snapshot approach**:
The recommended OpenBSD install-automation path: install and configure the box
manually once, snapshot it via the Hetzner API, then use that snapshot as the
Terraform image source for all future provisioning. Contrasted with the
autoinstall-response-file approach, which is unproven against Hetzner's rescue
environment.
_Avoid_: golden image (implies a broader image-management practice than exists here)
