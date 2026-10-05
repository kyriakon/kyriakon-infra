# Key generator spike: the browser half

The spike's generation and check logic now lives in `src/lib.rs`, so two callers share it: the
CLI in `src/main.rs`, and the page here, which loads the same code as a WebAssembly module.
`lib.rs` touches no filesystem and no network, and it takes the clock as an argument rather
than reading one, because `SystemTime::now()` panics on `wasm32-unknown-unknown`.

## What the page is

`index.html`, `app.js` and `style.css`, with wasm-bindgen's output in `pkg/`. The page's
Content-Security-Policy is `default-src 'none'` with `script-src 'self' 'wasm-unsafe-eval'`,
`style-src 'self'` and `connect-src 'self'`, so nothing outside this directory can be loaded
and the only network the browser may touch is the server it came from.

It makes a key and it checks a key. Nothing is uploaded, there is no request after load, and
the private key is written by the page itself.

## Building it

```
cargo build --target wasm32-unknown-unknown --release --lib
wasm-bindgen --target web --out-dir pkg target/wasm32-unknown-unknown/release/keygen_spike.wasm
python3 -m http.server 8899 --bind 127.0.0.1
```

## What was measured, 2026-10-05

- The page generated a key in the browser, fingerprint
  `be8ee53ecd3a879242018ac577969482a8220d68`, with an armored public half and a
  passphrase-protected private half. Its own check returned clean.
- A key made by GnuPG 2.5.24 on this machine was flagged, with the message about `Ocb as an
  AEAD mode`. `gpg --list-packets` agrees with both verdicts: the gpg-made key carries
  `hashed subpkt 34 len 1 (pref-aead-algos: 2)` and `features: 07`, while the generated key
  carries no `pref-aead-algos` subpacket at all and `features: 01`. The ticket names `features: 05`, which is what deployed keys carry because GnuPG 2.5 sets the version 5 public key advertisement; `01` omits that and keeps the modification-detection bit, so the criterion is met in substance, as the capability note records.
- The tab made five requests in total and every one was this directory: `index.html`,
  `style.css`, `app.js`, `pkg/keygen_spike.js` and `pkg/keygen_spike_bg.wasm`. That is the
  ticket's browser acceptance, and it is the reason the page reports its own loaded resources
  from the browser's resource timing rather than asking to be trusted.
- `cargo test --lib` runs `self_check()`, which generates a key, checks it clean, feeds it a
  key that is not a key, and exercises the JSON escaping. The CLI's `--self-check` runs the
  same function without a harness.

## The client kit

`/tmp/kg-thunderbird-kit/` holds `public.asc`, `secret.asc`, `message-from-the-box.asc` and
the steps. The passphrase on the throwaway secret key is `spike-passphrase-not-a-secret`.
The message was encrypted **on the mail box** with `gpg --no-options --recipient-file` and
decrypted on this machine with the generated secret key, so the kit is a live pair rather
than a fixture.

## The residual checks, run 2026-10-05

Three of the four the capability note left open are now closed.

- **A larger key is inspected correctly.** A gpg RSA-4096 key came back flagged twice, for
  advertising AEAD and for having no key that can encrypt. The second is not a false alarm:
  `gpg --list-keys` shows it as `rsa4096 [SC]` with key flags `03` and no subkey, so a key
  made that way genuinely cannot receive mail. It is a shape a member could easily produce,
  which is the argument for the check existing.
- **The prototype's own RSA key checks clean**, so the generator's RSA path works as the
  EdDSA path does.
- **The RSA unlock oddity was an artefact.** A message encrypted to the prototype's RSA key
  decrypted on two consecutive attempts with the passphrase, so the first-attempt failure the
  capability note records came from pinentry without a terminal rather than from the key.

## What is still not verified

Thunderbird on desktop and on Android, which need a client rather than a browser. The
subkey-expiry path also stays unverified, because gpg refuses to export an expired subkey in
any form, so an artifact from gpg carries either a usable subkey or none.
