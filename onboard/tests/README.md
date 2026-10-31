# Onboarding integration tests

The suite is one test binary, `drain.rs`, with the cases split into modules under
`areas/`:

| Module | What it drives |
|---|---|
| `card` | the Stripe rail: checkout, invoices, subscriptions and card ledger lines |
| `export` | `onboardctl ledger export` |
| `group` | the own-domain tier: groups, addresses, aliases and DNS |
| `lifecycle` | applications, decisions, mail, keys, passwords, purges and free accounts |
| `prepaid` | credits, windows, tokens, reconcile and `payment show` |
| `refund` | refunds and settlements |

Modules rather than separate files at the test root: Cargo runs one test
binary's tests in parallel, so a file per area would run the areas one after
another and make the full suite slower. The filter still gives the fast loop.

`common/mod.rs` holds the fixture and the helpers. It rebinds every path the
service touches to a temporary store, exactly as the production config does on
the box.

## Fast loop while iterating

```sh
cargo test --manifest-path onboard/Cargo.toml --lib
cargo test --manifest-path onboard/Cargo.toml --test drain -- prepaid   # or the area you touched
```

`cargo test --manifest-path onboard/Cargo.toml` remains the pre-push and CI gate.

## Binary or in-process

`Fix::drain()` runs the same `intents::run` pass in the test process. It is the
default because most tests are about the transition, not the process. It uses
`Store::new_for_test`, which writes the same bytes and appends in the same order
but skips the per-line `fsync`: the suite writes thousands of lines and APFS
fsync is a large part of that disk work. The production `Store::new` keeps the
barrier.

Use `Fix::drain_binary()` when the subject is the installed binary itself: a
printed alert, an exit status, or the pass lock. `Fix::ctl()` always drives the
console binary, because its argument parsing and exit status are the subject.
