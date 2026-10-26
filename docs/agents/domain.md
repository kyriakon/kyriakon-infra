# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- `../kyriakon/docs/CONTEXT.md` for the vocabulary shared across the kyriakon repos: shell-less user, the pricing tiers, dogfooding, audit us. This repo is one of several siblings, and that file is the glossary for all of them.
- `CONTEXT.md` at this repo's root for the terms specific to infrastructure work: propose-only change, snapshot approach, log minimization, capsule certificate, the portal.
- `../kyriakon/docs/decisions/` for the ADRs and the project proposal. This repo has no decisions directory of its own. Read the decisions that touch the area you are about to work in.

If `../kyriakon` is not cloned beside this repo, say so rather than guessing at the proposal or the glossary. Do not create a decisions directory here, and do not copy the ADRs into this repo.

The `/domain-modeling` skill creates terms lazily when a concept is actually resolved. A term that is in neither glossary is either language the project does not use, or a real gap worth noting.

## File structure

There is no single source root. Each Rust crate has its own `Cargo.toml`, and there is no workspace root:

```
/
├── CONTEXT.md            repo-local glossary
├── AGENTS.md             agent orientation, build commands, never list
├── CODING_STANDARDS.md   what a review enforces beyond the tooling
├── onboard/              Rust signup service: handler, drain, portal, store
├── kyriakon-encrypt/     Rust LMTP that encrypts mail at delivery
├── dovecot-plugin/       C hook that hands saved mail to kyriakon-encrypt
├── scripts/              deploys, drain scripts, operator checks, self-tests
├── openbsd/              every config the box runs, plus the restore template
├── terraform/            hcloud stack for the live box and the throwaway
├── keys/                 published member mail keys
└── docs/                 runbook, policies, threat model, agents/, planning/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in the two glossaries. Don't drift to synonyms they explicitly avoid.

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-NNNN (its title) but is worth reopening because…_
