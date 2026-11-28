#![no_main]

use libfuzzer_sys::fuzz_target;

/// One submitted public key block, the same call `keygen-check` makes. The
/// armour framing, the base64 body, the packet walk and the rpgp parse all run
/// on data the box does not control, so none of them may panic or hang.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = keygen::check_public_key(&text, 1_800_000_000);
});
