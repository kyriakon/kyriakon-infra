# keygen

The member key tools. One library serves three callers:

- the `keygen` generator CLI;
- the `keygen-check` helper, which the control plane runs as a process so it
  does not link `pgp`;
- the browser page under `web/`, which builds the same library to WebAssembly.

The check reports the three conditions that break mail delivery: no
encryption-capable subkey, an advertised AEAD preference, and any expiry or
revocation on the primary key or its encryption subkey. The generator makes a
key that passes it.

## Layout

| Path | What |
|---|---|
| `src/lib.rs` | `generate_key` (feature `generate`) and `check_public_key` |
| `src/main.rs` | the generator CLI |
| `src/bin/check.rs` | the check-only helper |
| `web/` | the browser page and its harness |
| `fixtures/` | the keys the tests and the control suite share |
| `fuzz/` | the libFuzzer target for the check |

## Build

The helper the deploy installs, without the generator's `rand` or `smallvec`:

```sh
cargo build --release --no-default-features --bin keygen-check
```

The generator:

```sh
cargo run --release --bin keygen -- ed25519 /tmp/keygen-out
```

The page:

```sh
cargo build --target wasm32-unknown-unknown --release --lib --features wasm
wasm-bindgen --target web --out-dir web/pkg \
  target/wasm32-unknown-unknown/release/keygen.wasm
python3 -m http.server 8899 --bind 127.0.0.1 --directory web
```

## The `keygen-check` protocol

The helper reads one armoured public key block on stdin and takes the clock as
`--now-secs <seconds>`, because the library never reads a clock itself and the
browser supplies its own. It prints one of:

```text
ok
<finding>
<finding>
```

or `uninspected` when the block does not parse. Both are exit 0; a non-zero exit
is a usage or I/O failure. `control/crates/core/src/mail/pgp.rs` runs the helper
with a ten-second deadline and treats every spawn, timeout, exit or protocol
failure as the existing uninspected advisory, never as a refusal.

## Tests and fuzzing

```sh
cargo test
cd fuzz && cargo +nightly fuzz run key
```

The fixtures are the generator's clean key and the gpg keys that isolate each
condition. `docs/planning/research/key-generator-capability.md` records how they
were made and what the original spike measured; the page and fixture provenance
are unchanged.
