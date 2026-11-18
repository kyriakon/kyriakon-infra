#![no_main]

use libfuzzer_sys::fuzz_target;

/// The save path's pure parses: header split, header spans, payload rewrite,
/// envelope gate, recipient guard. A panic here is a save that fails closed; a
/// mis-parse is the confidentiality class the property tests cover.
fuzz_target!(|data: &[u8]| {
    kyriakon_encrypt::fuzz::message(data);
});
