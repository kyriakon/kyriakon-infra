# Proposed AGENTS.md changes

The rest of AGENTS.md is unchanged. These are the lines that the keygen
promotion makes stale.

## Where things are

Add after the `dovecot-plugin/` entry:

- `keygen/`: the member key tools, a separate build root. `src/lib.rs` generates
  and checks a mail key; `src/bin/check.rs` is `keygen-check`, the check-only
  helper the control plane runs as a process so it does not link `pgp`;
  `web/` is the browser page and `fuzz/` is its libFuzzer target. The helper is
  installed as `/usr/local/libexec/keygen-check`.

Change the binary list in the `control/` entry:

> The six binaries are `kyriakon-control`, `kyriakon-control-static`,
> `kyriakon-control-drain`, `kyriakon-control-tui`, `kyriakon-admin` and
> `kyriakon-fromcheck` (installed as `/usr/local/libexec/filter-fromcheck`).

to:

> The six control binaries are `kyriakon-control`, `kyriakon-control-static`,
> `kyriakon-control-drain`, `kyriakon-control-tui`, `kyriakon-admin` and
> `kyriakon-fromcheck` (installed as `/usr/local/libexec/filter-fromcheck`);
> `keygen-check` is built from `keygen/` and installed as
> `/usr/local/libexec/keygen-check`.

## CI

Change:

> `checks.yml` (the seven CI jobs: control, encrypt plugin, shared mail parser,
> shell scripts, script self-tests on the OpenBSD 8.0 VM, terraform, and the
> dependency advisories), `fuzz.yml` (the seven libFuzzer targets, weekly)

to:

> `checks.yml` (the eight CI jobs: control, keygen, encrypt plugin, shared mail
> parser, shell scripts, script self-tests on the OpenBSD 8.0 VM, terraform, and
> the dependency advisories), `fuzz.yml` (the eight libFuzzer targets, weekly)

## Build & test

Change the Rust bullet to include `keygen/`:

> Rust: `cargo test --manifest-path control/Cargo.toml` and
> `cargo clippy --manifest-path control/Cargo.toml --all-targets -- -D warnings`;
> the same for `keygen/`, `kyriakon-encrypt/` and `mailparse/`.

Change the dependency bullet:

> over every committed lockfile and `cargo deny` over the three shipping trees

to:

> over every committed lockfile and `cargo deny` over the four shipping trees
> (`control`, `keygen`, `kyriakon-encrypt`, `mailparse`)

Change the fuzz bullet:

> `kyriakon-encrypt/fuzz/`, `control/fuzz/` and `mailparse/fuzz/` hold one per
> parser: the encryptor's message and envelope, the shared mail parser's headers,
> addresses and MIME walk, the FastCGI reader and form decoder, the From-header
> filter, and the member path resolver, which asserts that a served file is
> always one inside the member's own root.

to:

> `kyriakon-encrypt/fuzz/`, `control/fuzz/`, `mailparse/fuzz/` and `keygen/fuzz/`
> hold one per parser: the encryptor's message and envelope, the shared mail
> parser's headers, addresses and MIME walk, the FastCGI reader and form decoder,
> the From-header filter, the member path resolver, which asserts that a served
> file is always one inside the member's own root, and the key check's armour,
> packet and subkey walk.
