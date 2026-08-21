# docs/planning

Planning and AI-assisted working documents for Kyriakon. Kept in its own folder, separate
from `docs/decisions/`, so it's obvious at a glance which docs are settled (reviewed,
durable) and which are working material (in progress, expect it to be messier).

## Layout

- `proposal/` — the current project proposal (architecture, MVP scope, team & schedule).
- `research/` — raw investigation notes and `grill with docs` session output. Reference
  material, not authoritative — don't treat it as settled just because it's written
  down.
- `specs/` — output of `to spec`, one file per feature, while its tickets are still
  open.
- `archive/` — specs whose tickets are all closed. Kept for history; not read by
  default.

## Workflow

1. **`/grill-with-docs`** or **`/wayfinder`** → notes land in `research/`.
2. **`/to-spec`** → a spec lands in `specs/`.
3. **`/to-tickets`** → creates GitHub issues directly via `gh issue create`, each with a
   `Spec:` line pointing back to the relevant file in `specs/`. Tickets are not
   mirrored here as markdown — GitHub Issues is the single source of truth for ticket
   status.
4. **`/implement`** → work only proceeds on a ticket that's been explicitly assigned for
   the session (see `AGENTS.md`). As tickets close, move the corresponding spec to
   `archive/` once every ticket it spawned is closed.
  
## Promoting to a decision record

When something in here captures a decision future contributors — human or agent — will
need to understand in order to know *why* the code looks the way it does, condense it
into a short ADR in `docs/decisions/` as part of a normal PR. Everything else here can
stay as working material and is fine to prune periodically.
