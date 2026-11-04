# onboard

The signup service: a FastCGI handler, a gemini capsule, an ssh portal, a root
drain, and the operator console. One crate, three binaries under `src/bin/`:
`kyriakon-onboard-drain`, `kyriakon-onboard-tui`, `kyriakon-onboardctl`.

## Front ends

- `src/responder.rs` — the web form and the shared applicant flow; one route
  table drives both the HTTP and gemini fronts.
- `src/page.rs` — the page models both fronts render.
- `src/capsule.rs` — the gemtext renderings.
- `src/portal.rs` — the terminal library (menu, sessions, applicant flow);
  `src/portal_ipc.rs` is its one request to the handler.
- `templates/*.html` — the web renderings.

## Drain

- `src/transitions.rs` — the settlement seam: `Envelope`, `Settlement`, `settle`,
  `Disposition`, `AfterLine`, `RefusalFile`, and the retry/backoff surface. Every
  root verb returns a `Settlement` and `settle` owns the dedup, line, remove and
  after-line work.
- `src/transitions/` — the verb bodies by job: `payments`, `groups`, `lifecycle`,
  `review`, `stripe`, `boxrun` (scripts, keys, addresses).
- `src/intents.rs` — the intent enum, its payloads, and parse/verify/apply.
- `src/journal.rs` — loads and indexes the journal once per pass.

## Records

- `src/store.rs` — paths, locks, atomic record writes, typed account/group/
  application reads.
- `src/ledger.rs` — the typed payment ledger and its locked sequence.

## Tests

`tests/drain.rs` is the acceptance suite; the areas live under `tests/areas/`
and their map is `tests/README.md`. Run one area with
`cargo test --manifest-path onboard/Cargo.toml --test drain -- <area>`.
