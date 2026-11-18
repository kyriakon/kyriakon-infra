#![no_main]

use libfuzzer_sys::fuzz_target;

/// The form decoder and the path decoder behind the public signup page. Both
/// read what a browser sent, so neither may panic on it.
fuzz_target!(|data: &[u8]| {
    kyriakon_control_handler::responder::fuzz_decode(&String::from_utf8_lossy(data));
});
