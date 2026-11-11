# onboard

The signup service: a FastCGI handler, a gemini capsule, an ssh portal, a root
drain, and the operator console. One Cargo workspace under `crates/`, four
binaries: `kyriakon-onboard`, `kyriakon-onboard-drain`,
`kyriakon-onboard-tui`, `kyriakon-onboardctl`.

## Packages

- `crates/core/` — the store, configuration, intent contract, IPC request, the
  shared flow, and the account, money and mail sections. Every other package
  depends on it.
- `crates/handler/` — the FastCGI wire, the responder and the page and capsule
  renderings; the `kyriakon-onboard` binary.
- `crates/drain/` — the intent loop, the transition verbs, the mailbox and the
  prepaid view; the `kyriakon-onboard-drain` binary.
- `crates/tui/` — the terminal library and its `kyriakon-onboard-tui` binary.
- `crates/ctl/` — the operator console, `kyriakon-onboardctl`.
- `crates/tests/` — the acceptance suite, `tests/drain.rs` and `tests/areas/`.

## Handler

- `crates/handler/src/responder/` — the web form; one route table drives both
  the HTTP and gemini fronts.
- `crates/handler/src/page.rs` — the page models both fronts render.
- `crates/handler/src/capsule.rs` — the gemtext renderings.
- `crates/handler/src/fastcgi.rs` — the request and reply wire.
- `crates/handler/templates/*.html` — the web renderings.
- `crates/core/src/flow/applicant.rs` — the applicant flow the handler and the
  terminal share.
- `crates/tui/src/lib.rs` — the terminal library; `crates/core/src/ipc.rs` is
  its one request to the handler.

## Drain

- `crates/drain/src/transitions.rs` — the settlement seam: `Envelope`,
  `Settlement`, `settle`, `Disposition`, `AfterLine`, `RefusalFile`, and the
  retry/backoff surface. Every root verb returns a `Settlement` and `settle`
  owns the dedup, line, remove and after-line work.
- `crates/drain/src/transitions/` — the verb bodies by job: `payments`, `groups`,
  `lifecycle`, `review`, `stripe`, `boxrun` (scripts, keys, addresses).
- `crates/core/src/intent.rs` — the intent enum, its payloads, and parse/file.
- `crates/drain/src/lib.rs` — verify, apply and the pass.
- `crates/core/src/store/journal.rs` — loads and indexes the journal once per
  pass.

## Records

- `crates/core/src/store/mod.rs` — paths, locks, atomic record writes, typed
  account/group/application reads.
- `crates/core/src/payments/ledger.rs` — the typed payment ledger and its locked
  sequence.

## Tests

`crates/tests/tests/drain.rs` is the acceptance suite; the areas live under
`crates/tests/tests/areas/` and their map is `crates/tests/tests/README.md`. Run
one area with
`cargo test --manifest-path onboard/Cargo.toml --test drain -- <area>`.
